//! Device-bound vault key: a random 32-byte secret held in the OS keyring.
//!
//! `crypto-core`'s vault v2 mixes this key into the wrapping-key derivation
//! (`seal_bound` / `unlock_bound`), so a stolen vault blob can no longer be brute-forced
//! offline on the password alone — the attacker also needs the key that never leaves the
//! device's keyring. Fetching that key is the only OS-specific part, so it lives here
//! behind a small trait; the crypto stays in `crypto-core`.
//!
//! Backends:
//! * [`OsKeyring`] (feature `os-keyring`) — Linux Secret Service (GNOME Keyring/KWallet)
//!   and Windows Credential Manager, via the `keyring` crate.
//! * `AndroidKeystore` (compiled on `target_os = "android"`) — the device key is
//!   wrapped by a **non-exportable AES-GCM key inside the Android Keystore** (TEE /
//!   StrongBox where the hardware has one) and the wrapped blob sits in the app's
//!   private files dir. Even a root attacker can only *use* the wrapping key while
//!   resident — it cannot be copied off the device, so a stolen disk image or backup
//!   cannot open the vault.
//!
//! A client that cannot reach any keyring should fall back to a portable v1 vault
//! (password-only) rather than refuse to work — binding is hardening, not a gate.

use crypto_core::DEVICE_KEY_LEN;

#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError {
    #[error("OS keyring unavailable: {0}")]
    Unavailable(String),
    #[error("stored device key is malformed")]
    Malformed,
}

/// Source of the device-binding key.
///
/// The split between [`get`](Self::get) and [`get_or_create`](Self::get_or_create) is
/// load-bearing for data safety: minting a *new* device key destroys any existing
/// device-bound (v2) vault, so an unlock path must never do it. A transiently locked or
/// not-yet-ready keyring must surface as `get() -> Err`/`Ok(None)` and fail the unlock
/// *recoverably*, not be mistaken for "first run" and silently regenerate the key.
pub trait DeviceKeyProvider {
    /// Read the stored device key **without ever creating one**. `Ok(Some)` = present;
    /// `Ok(None)` = the store is reachable and genuinely empty (a true first run); `Err` =
    /// the store exists but is unreadable right now (e.g. a locked keyring). Every unlock /
    /// re-seal / availability path uses this.
    fn get(&self) -> Result<Option<[u8; DEVICE_KEY_LEN]>, DeviceKeyError>;

    /// Read the device key, minting + storing a fresh one **only** when [`get`](Self::get)
    /// returns `Ok(None)` (reachable and empty). Call this only when creating an account or
    /// linking a new device — never on an unlock path.
    fn get_or_create(&self) -> Result<[u8; DEVICE_KEY_LEN], DeviceKeyError>;
}

#[cfg(all(feature = "os-keyring", not(target_os = "android")))]
pub use os::OsKeyring;

#[cfg(all(feature = "os-keyring", not(target_os = "android")))]
mod os {
    use super::{DeviceKeyError, DeviceKeyProvider, DEVICE_KEY_LEN};
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use rand::RngCore;

    /// Device key stored in the platform keyring (Linux Secret Service / Windows
    /// Credential Manager) under a fixed service/entry name. One key per device, shared
    /// by all accounts on it — it is a second unlock *factor*, not an identity.
    pub struct OsKeyring {
        service: String,
    }

    const ENTRY_NAME: &str = "vault-device-key";

    impl OsKeyring {
        pub fn new(service: impl Into<String>) -> Self {
            OsKeyring {
                service: service.into(),
            }
        }
    }

    impl Default for OsKeyring {
        fn default() -> Self {
            OsKeyring::new("sona-messenger")
        }
    }

    impl DeviceKeyProvider for OsKeyring {
        fn get(&self) -> Result<Option<[u8; DEVICE_KEY_LEN]>, DeviceKeyError> {
            let entry = keyring::Entry::new(&self.service, ENTRY_NAME)
                .map_err(|e| DeviceKeyError::Unavailable(e.to_string()))?;
            match entry.get_password() {
                Ok(encoded) => {
                    let bytes = STANDARD_NO_PAD
                        .decode(encoded)
                        .map_err(|_| DeviceKeyError::Malformed)?;
                    let key: [u8; DEVICE_KEY_LEN] =
                        bytes.try_into().map_err(|_| DeviceKeyError::Malformed)?;
                    Ok(Some(key))
                }
                // Only a genuinely-absent entry is "first run". A locked/errored keyring is
                // NOT — surface it as an error so callers fail closed instead of minting a
                // new key over the one that seals an existing vault.
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(DeviceKeyError::Unavailable(e.to_string())),
            }
        }

        fn get_or_create(&self) -> Result<[u8; DEVICE_KEY_LEN], DeviceKeyError> {
            if let Some(key) = self.get()? {
                return Ok(key);
            }
            let entry = keyring::Entry::new(&self.service, ENTRY_NAME)
                .map_err(|e| DeviceKeyError::Unavailable(e.to_string()))?;
            let mut key = [0u8; DEVICE_KEY_LEN];
            rand::rngs::OsRng.fill_bytes(&mut key);
            entry
                .set_password(&STANDARD_NO_PAD.encode(key))
                .map_err(|e| DeviceKeyError::Unavailable(e.to_string()))?;
            Ok(key)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Needs a live, unlocked keyring (Secret Service daemon on Linux), so it does
        /// not run in headless CI: `cargo test -p client-core --features os-keyring -- --ignored`
        #[test]
        #[ignore = "requires an unlocked OS keyring"]
        fn os_keyring_round_trip_is_stable() {
            let kr = OsKeyring::new("sona-messenger-test");
            let a = kr.get_or_create().unwrap();
            let b = kr.get_or_create().unwrap();
            assert_eq!(a, b, "second fetch must return the key minted by the first");
            // Read-only get() returns the same key and never mints a different one.
            assert_eq!(
                kr.get().unwrap(),
                Some(a),
                "get() must return the stored key"
            );
            assert_eq!(
                kr.get().unwrap(),
                Some(a),
                "get() must be stable, not regenerate"
            );
        }
    }
}

#[cfg(target_os = "android")]
pub use android::AndroidKeystore;

/// Android Keystore backend. The 32-byte device key is generated once from OS
/// randomness, encrypted (AES-256-GCM) under a Keystore key that Android will never
/// export, and the `iv || ciphertext` blob is written to the app's private files dir.
/// Every later call unwraps the same key. All Keystore/Cipher work goes through JNI —
/// there is no NDK C API for the Keystore.
#[cfg(target_os = "android")]
mod android {
    use super::{DeviceKeyError, DeviceKeyProvider, DEVICE_KEY_LEN};
    use jni::objects::{JByteArray, JObject, JValue};
    use jni::JNIEnv;
    use rand::RngCore;

    /// Alias of the wrapping key inside AndroidKeyStore.
    const KEY_ALIAS: &str = "sona-vault-device-key";
    /// Wrapped-blob file (inside `Context.getFilesDir()`): `iv_len(1) || iv || ct`.
    const WRAPPED_FILE: &str = "sona-device-key.wrapped";
    /// KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT.
    const PURPOSES: i32 = 1 | 2;
    /// Cipher.ENCRYPT_MODE / DECRYPT_MODE.
    const ENCRYPT_MODE: i32 = 1;
    const DECRYPT_MODE: i32 = 2;

    pub struct AndroidKeystore;

    /// Run a JNI call; on failure clear any pending Java exception (it would poison
    /// every later JNI call on the thread) and surface a labeled error.
    macro_rules! jni_try {
        ($env:expr, $what:expr, $call:expr) => {{
            let result = $call;
            match result {
                Ok(v) => v,
                Err(e) => {
                    let _ = $env.exception_clear();
                    return Err(DeviceKeyError::Unavailable(format!("{}: {e}", $what)));
                }
            }
        }};
    }

    impl AndroidKeystore {
        /// `Context.getFilesDir().getAbsolutePath()` + our blob name.
        fn wrapped_path(env: &mut JNIEnv, context: &JObject) -> Result<String, DeviceKeyError> {
            let files_dir = {
                let r = env.call_method(context, "getFilesDir", "()Ljava/io/File;", &[]);
                jni_try!(env, "getFilesDir", r)
            };
            let files_dir = jni_try!(env, "getFilesDir obj", files_dir.l());
            let path = {
                let r = env.call_method(&files_dir, "getAbsolutePath", "()Ljava/lang/String;", &[]);
                jni_try!(env, "getAbsolutePath", r)
            };
            let path = jni_try!(env, "path obj", path.l());
            let path: String = {
                let r = env.get_string((&path).into());
                jni_try!(env, "path string", r).into()
            };
            Ok(format!("{path}/{WRAPPED_FILE}"))
        }

        /// `KeyStore.getInstance("AndroidKeyStore")`, loaded.
        fn keystore<'l>(env: &mut JNIEnv<'l>) -> Result<JObject<'l>, DeviceKeyError> {
            let name = jni_try!(env, "new_string", env.new_string("AndroidKeyStore"));
            let ks = {
                let r = env.call_static_method(
                    "java/security/KeyStore",
                    "getInstance",
                    "(Ljava/lang/String;)Ljava/security/KeyStore;",
                    &[JValue::Object(&name)],
                );
                jni_try!(env, "KeyStore.getInstance", r)
            };
            let ks = jni_try!(env, "keystore obj", ks.l());
            {
                let r = env.call_method(
                    &ks,
                    "load",
                    "(Ljava/security/KeyStore$LoadStoreParameter;)V",
                    &[JValue::Object(&JObject::null())],
                );
                jni_try!(env, "KeyStore.load", r);
            }
            Ok(ks)
        }

        /// Fetch the wrapping key, generating it inside the Keystore on first use.
        fn wrapping_key<'l>(
            env: &mut JNIEnv<'l>,
            keystore: &JObject,
        ) -> Result<JObject<'l>, DeviceKeyError> {
            let alias = jni_try!(env, "alias", env.new_string(KEY_ALIAS));
            let has = {
                let r = env.call_method(
                    keystore,
                    "containsAlias",
                    "(Ljava/lang/String;)Z",
                    &[JValue::Object(&alias)],
                );
                jni_try!(env, "containsAlias", r)
            };
            if !jni_try!(env, "containsAlias bool", has.z()) {
                // StrongBox first: on devices with a discrete secure element (all Pixels,
                // hence every GrapheneOS device) the wrapping key lives there instead of
                // the TEE. Any failure — StrongBoxUnavailableException, ProviderException
                // wrapping it, or NoSuchMethodError on API < 28 — falls back to the plain
                // TEE spec. A failed attempt stores nothing under the alias, so the
                // retry is safe.
                if Self::generate_key(env, true).is_err() {
                    Self::generate_key(env, false)?;
                }
            }
            let key = {
                let r = env.call_method(
                    keystore,
                    "getKey",
                    "(Ljava/lang/String;[C)Ljava/security/Key;",
                    &[JValue::Object(&alias), JValue::Object(&JObject::null())],
                );
                jni_try!(env, "getKey", r)
            };
            Ok(jni_try!(env, "key obj", key.l()))
        }

        /// Generate the AES-256-GCM wrapping key inside the Keystore under
        /// [`KEY_ALIAS`], optionally requesting StrongBox backing.
        fn generate_key(env: &mut JNIEnv, strongbox: bool) -> Result<(), DeviceKeyError> {
            let alias = jni_try!(env, "alias", env.new_string(KEY_ALIAS));
            {
                // KeyGenParameterSpec.Builder(alias, ENCRYPT|DECRYPT)
                //   .setBlockModes("GCM").setEncryptionPaddings("NoPadding")
                //   .setKeySize(256)[.setIsStrongBoxBacked(true)].build()
                let builder = {
                    let r = env.new_object(
                        "android/security/keystore/KeyGenParameterSpec$Builder",
                        "(Ljava/lang/String;I)V",
                        &[JValue::Object(&alias), JValue::Int(PURPOSES)],
                    );
                    jni_try!(env, "Builder.new", r)
                };
                let gcm = jni_try!(env, "gcm str", env.new_string("GCM"));
                let modes = {
                    let r = env.new_object_array(1, "java/lang/String", &gcm);
                    jni_try!(env, "modes arr", r)
                };
                let builder = {
                    let r = env.call_method(
                        &builder,
                        "setBlockModes",
                        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                        &[JValue::Object(&modes)],
                    );
                    let v = jni_try!(env, "setBlockModes", r);
                    jni_try!(env, "setBlockModes obj", v.l())
                };
                let nopad = jni_try!(env, "nopad str", env.new_string("NoPadding"));
                let pads = {
                    let r = env.new_object_array(1, "java/lang/String", &nopad);
                    jni_try!(env, "pads arr", r)
                };
                let builder = {
                    let r = env.call_method(
                        &builder,
                        "setEncryptionPaddings",
                        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                        &[JValue::Object(&pads)],
                    );
                    let v = jni_try!(env, "setEncryptionPaddings", r);
                    jni_try!(env, "setEncryptionPaddings obj", v.l())
                };
                let builder = {
                    let r = env.call_method(
                        &builder,
                        "setKeySize",
                        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                        &[JValue::Int(256)],
                    );
                    let v = jni_try!(env, "setKeySize", r);
                    jni_try!(env, "setKeySize obj", v.l())
                };
                let builder = if strongbox {
                    // API 28+ only — on older devices the missing method raises
                    // NoSuchMethodError, which jni_try! converts into the Err that
                    // triggers the caller's TEE fallback.
                    let r = env.call_method(
                        &builder,
                        "setIsStrongBoxBacked",
                        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                        &[JValue::Bool(1)],
                    );
                    let v = jni_try!(env, "setIsStrongBoxBacked", r);
                    jni_try!(env, "setIsStrongBoxBacked obj", v.l())
                } else {
                    builder
                };
                let spec = {
                    let r = env.call_method(
                        &builder,
                        "build",
                        "()Landroid/security/keystore/KeyGenParameterSpec;",
                        &[],
                    );
                    let v = jni_try!(env, "build", r);
                    jni_try!(env, "build obj", v.l())
                };

                let aes = jni_try!(env, "aes str", env.new_string("AES"));
                let provider = jni_try!(env, "prov str", env.new_string("AndroidKeyStore"));
                let kg = {
                    let r = env.call_static_method(
                        "javax/crypto/KeyGenerator",
                        "getInstance",
                        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                        &[JValue::Object(&aes), JValue::Object(&provider)],
                    );
                    let v = jni_try!(env, "KeyGenerator.getInstance", r);
                    jni_try!(env, "KeyGenerator obj", v.l())
                };
                {
                    let r = env.call_method(
                        &kg,
                        "init",
                        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
                        &[JValue::Object(&spec)],
                    );
                    jni_try!(env, "KeyGenerator.init", r);
                }
                {
                    let r = env.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[]);
                    jni_try!(env, "generateKey", r);
                }
            }
            Ok(())
        }

        /// `Cipher.getInstance("AES/GCM/NoPadding")`.
        fn cipher<'l>(env: &mut JNIEnv<'l>) -> Result<JObject<'l>, DeviceKeyError> {
            let transform = jni_try!(env, "transform", env.new_string("AES/GCM/NoPadding"));
            let c = {
                let r = env.call_static_method(
                    "javax/crypto/Cipher",
                    "getInstance",
                    "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                    &[JValue::Object(&transform)],
                );
                jni_try!(env, "Cipher.getInstance", r)
            };
            Ok(jni_try!(env, "cipher obj", c.l()))
        }

        fn wrap(
            env: &mut JNIEnv,
            key: &JObject,
            plain: &[u8; DEVICE_KEY_LEN],
        ) -> Result<Vec<u8>, DeviceKeyError> {
            let cipher = Self::cipher(env)?;
            {
                let r = env.call_method(
                    &cipher,
                    "init",
                    "(ILjava/security/Key;)V",
                    &[JValue::Int(ENCRYPT_MODE), JValue::Object(key)],
                );
                jni_try!(env, "Cipher.init(encrypt)", r);
            }
            let iv = {
                let r = env.call_method(&cipher, "getIV", "()[B", &[]);
                jni_try!(env, "getIV", r)
            };
            let iv: JByteArray = jni_try!(env, "iv obj", iv.l()).into();
            let iv = {
                let r = env.convert_byte_array(&iv);
                jni_try!(env, "iv bytes", r)
            };
            let input = {
                let r = env.byte_array_from_slice(plain);
                jni_try!(env, "input arr", r)
            };
            let ct = {
                let r = env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&input)]);
                jni_try!(env, "doFinal", r)
            };
            let ct: JByteArray = jni_try!(env, "ct obj", ct.l()).into();
            let ct = {
                let r = env.convert_byte_array(&ct);
                jni_try!(env, "ct bytes", r)
            };

            let mut blob = Vec::with_capacity(1 + iv.len() + ct.len());
            blob.push(iv.len() as u8);
            blob.extend_from_slice(&iv);
            blob.extend_from_slice(&ct);
            Ok(blob)
        }

        fn unwrap(
            env: &mut JNIEnv,
            key: &JObject,
            blob: &[u8],
        ) -> Result<[u8; DEVICE_KEY_LEN], DeviceKeyError> {
            let iv_len = *blob.first().ok_or(DeviceKeyError::Malformed)? as usize;
            if blob.len() < 1 + iv_len {
                return Err(DeviceKeyError::Malformed);
            }
            let (iv, ct) = blob[1..].split_at(iv_len);

            let cipher = Self::cipher(env)?;
            let iv_arr = {
                let r = env.byte_array_from_slice(iv);
                jni_try!(env, "iv arr", r)
            };
            // new GCMParameterSpec(128, iv)
            let spec = {
                let r = env.new_object(
                    "javax/crypto/spec/GCMParameterSpec",
                    "(I[B)V",
                    &[JValue::Int(128), JValue::Object(&iv_arr)],
                );
                jni_try!(env, "GCMParameterSpec.new", r)
            };
            {
                let r = env.call_method(
                    &cipher,
                    "init",
                    "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                    &[
                        JValue::Int(DECRYPT_MODE),
                        JValue::Object(key),
                        JValue::Object(&spec),
                    ],
                );
                jni_try!(env, "Cipher.init(decrypt)", r);
            }
            let ct_arr = {
                let r = env.byte_array_from_slice(ct);
                jni_try!(env, "ct arr", r)
            };
            let plain = {
                let r = env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&ct_arr)]);
                jni_try!(env, "doFinal(decrypt)", r)
            };
            let plain: JByteArray = jni_try!(env, "plain obj", plain.l()).into();
            let plain = {
                let r = env.convert_byte_array(&plain);
                jni_try!(env, "plain bytes", r)
            };
            plain.try_into().map_err(|_| DeviceKeyError::Malformed)
        }
    }

    impl DeviceKeyProvider for AndroidKeystore {
        fn get(&self) -> Result<Option<[u8; DEVICE_KEY_LEN]>, DeviceKeyError> {
            // Tauri initializes ndk-context with the app's JavaVM + Activity context.
            let ctx = ndk_context::android_context();
            let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
                .map_err(|e| DeviceKeyError::Unavailable(format!("JavaVM: {e}")))?;
            let mut env = vm
                .attach_current_thread()
                .map_err(|e| DeviceKeyError::Unavailable(format!("attach: {e}")))?;
            let context = unsafe { JObject::from_raw(ctx.context().cast()) };
            let path = Self::wrapped_path(&mut env, &context)?;
            // Read-only: only touch the Keystore when a wrapped blob exists. A missing blob
            // is a genuine first run (`Ok(None)`); we never mint a key on this path.
            match std::fs::read(&path) {
                Ok(blob) => {
                    let keystore = Self::keystore(&mut env)?;
                    let key = Self::wrapping_key(&mut env, &keystore)?;
                    Ok(Some(Self::unwrap(&mut env, &key, &blob)?))
                }
                Err(_) => Ok(None),
            }
        }

        fn get_or_create(&self) -> Result<[u8; DEVICE_KEY_LEN], DeviceKeyError> {
            if let Some(existing) = self.get()? {
                return Ok(existing);
            }
            let ctx = ndk_context::android_context();
            let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
                .map_err(|e| DeviceKeyError::Unavailable(format!("JavaVM: {e}")))?;
            let mut env = vm
                .attach_current_thread()
                .map_err(|e| DeviceKeyError::Unavailable(format!("attach: {e}")))?;
            let context = unsafe { JObject::from_raw(ctx.context().cast()) };
            let path = Self::wrapped_path(&mut env, &context)?;
            let keystore = Self::keystore(&mut env)?;
            let key = Self::wrapping_key(&mut env, &keystore)?;
            let mut fresh = [0u8; DEVICE_KEY_LEN];
            rand::rngs::OsRng.fill_bytes(&mut fresh);
            let blob = Self::wrap(&mut env, &key, &fresh)?;
            std::fs::write(&path, blob)
                .map_err(|e| DeviceKeyError::Unavailable(format!("write: {e}")))?;
            Ok(fresh)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::{
        create_account_with_username_bound, unlock, unlock_bound, AccountError, VaultError,
    };

    /// Deterministic provider standing in for an OS keyring.
    struct FixedKey([u8; DEVICE_KEY_LEN]);
    impl DeviceKeyProvider for FixedKey {
        fn get(&self) -> Result<Option<[u8; DEVICE_KEY_LEN]>, DeviceKeyError> {
            Ok(Some(self.0))
        }
        fn get_or_create(&self) -> Result<[u8; DEVICE_KEY_LEN], DeviceKeyError> {
            Ok(self.0)
        }
    }

    #[test]
    fn provider_key_binds_and_unlocks_the_vault() {
        let provider = FixedKey([9u8; DEVICE_KEY_LEN]);
        let dk = provider.get_or_create().unwrap();
        let pw = "Correct-Horse-Battery-9";
        let (acct, blob) = create_account_with_username_bound("carol", pw, Some(&dk)).unwrap();

        // Blob alone + password: refused, names the missing factor.
        assert!(matches!(
            unlock(pw, &blob),
            Err(AccountError::Vault(VaultError::DeviceKeyRequired))
        ));
        // With the provider's key: opens, same identity.
        let again = unlock_bound(pw, Some(&provider.get_or_create().unwrap()), &blob).unwrap();
        assert_eq!(again.account_id(), acct.account_id());
    }
}
