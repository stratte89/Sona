//! `crypto-core` — the single home for every Sona secret.
//!
//! Everything that touches key material lives here so it can be audited as one unit
//! and compiled once for every platform (native mobile via UniFFI, desktop via Tauri).
//! The platform clients are dumb shells around this crate.
//!
//! Phase 1 (current): the at-rest [`vault`] + account creation + password policy.
//! Phase 2 will add the Double Ratchet (libsignal) and the Key Transparency client
//! inside this same crate.

pub mod callkey;
pub mod kt;
pub mod localbox;
pub mod quick;
pub mod ratchet;
pub mod sync;
pub mod vault;

use rand::RngCore;
use ratchet::{RatchetEngine, RatchetError};
use vault::VaultPayload;

pub use callkey::{CallKey, CallKeyError};
pub use vault::{VaultError, DEVICE_KEY_LEN};

/// Result of checking a vault password against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordStrength {
    pub acceptable: bool,
    /// Human-readable reasons the password was rejected (empty when acceptable).
    pub problems: Vec<String>,
}

/// Enforce a minimum vault-password policy. The vault password is the *only* thing
/// standing between a stolen device and the identity key, so we refuse weak ones up
/// front rather than relying on Argon2id alone to save a `password123`.
pub fn check_password(password: &str) -> PasswordStrength {
    let mut problems = Vec::new();
    if password.chars().count() < 12 {
        problems.push("at least 12 characters".into());
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        problems.push("an uppercase letter".into());
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        problems.push("a lowercase letter".into());
    }
    if !password.chars().any(|c| c.is_numeric()) {
        problems.push("a number".into());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        problems.push("a symbol".into());
    }
    // Composition rules alone pass `Password123!`. For portable v1 vaults the password is
    // the ONLY factor, so also reject the common weak *bases* — a keyboard walk or a
    // dictionary word with the usual decorations. Not a full breach list (that needs a
    // large wordlist / zxcvbn), but it catches the obvious compliant-but-guessable ones (L-2).
    if is_common_base(password) {
        problems.push("not to be based on a common word or keyboard pattern".into());
    }
    PasswordStrength {
        acceptable: problems.is_empty(),
        problems,
    }
}

/// Does the password reduce to a well-known weak base once the usual leet/decoration is
/// undone? Case-folds, maps common symbol/digit→letter substitutions (`@`→a, `0`→o, `1`→i,
/// …), drops the remaining non-letters, then compares against a small blocklist. Letters
/// are never remapped, so real words survive intact.
fn is_common_base(password: &str) -> bool {
    const COMMON: &[&str] = &[
        "password",
        "letmein",
        "welcome",
        "qwerty",
        "qwertyuiop",
        "asdfgh",
        "zxcvbn",
        "iloveyou",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "trustno",
        "changeme",
        "secret",
        "login",
        "abcdef",
        "abcabc",
        "admin",
        "test",
        "root",
        "sona",
    ];
    let normalized: String = password
        .chars()
        .filter_map(|c| match c.to_ascii_lowercase() {
            '0' => Some('o'),
            '1' => Some('i'),
            '3' => Some('e'),
            '4' | '@' => Some('a'),
            '5' | '$' => Some('s'),
            '7' => Some('t'),
            '8' => Some('b'),
            c if c.is_ascii_alphabetic() => Some(c),
            _ => None, // drop un-leeted digits, symbols, spacing
        })
        .collect();
    // Short bases must match exactly (a 4-char prefix would reject too many real passwords);
    // longer bases also match as a prefix to catch the `password2024!` decoration.
    COMMON
        .iter()
        .any(|w| normalized == *w || (w.len() >= 6 && normalized.starts_with(w)))
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("password too weak: needs {0}")]
    WeakPassword(String),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Ratchet(#[from] RatchetError),
    #[error("vault predates the stored data key and cannot be opened safely")]
    LegacyVault,
}

/// An unlocked identity: the live ratchet engine plus the account id. Created by
/// [`create_account`] or [`unlock`]. Re-seal it with [`Account::seal`] after the
/// ratchet advances so the new state is persisted.
pub struct Account {
    engine: RatchetEngine,
    account_id: String,
    /// Stable 32-byte key for encrypting local bulk data (history/contacts). Sealed in
    /// the vault; available in memory only while unlocked.
    data_key: [u8; 32],
    /// The vault wrapping key, derived once (Argon2id) at create/unlock and cached so
    /// [`Account::reseal`] after every ratchet advance is cheap. Means the *password*
    /// never has to be kept in memory. Zeroized on drop.
    seal_key: Option<vault::SealKey>,
}

impl Account {
    /// SHA-256(account_id) — the only address the server ever sees.
    pub fn identity_hash(&self) -> protocol_types::IdentityHash {
        protocol_types::IdentityHash::from_identifier(&self.account_id)
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Mutable access to the ratchet engine for session/encrypt/decrypt operations.
    pub fn ratchet(&mut self) -> &mut RatchetEngine {
        &mut self.engine
    }

    /// Read-only access to the ratchet engine (identity keys, signing, etc.).
    pub fn ratchet_ref(&self) -> &RatchetEngine {
        &self.engine
    }

    /// The stable local-data key (for `localbox`-encrypting chat history / contacts).
    pub fn data_key(&self) -> [u8; 32] {
        self.data_key
    }

    /// Re-encrypt the current ratchet state under the password into a vault blob.
    /// Call after any operation that advances the ratchet (encrypt/decrypt/new session).
    pub fn seal(&self, password: &str) -> Result<Vec<u8>, AccountError> {
        self.seal_bound(password, None)
    }

    /// Like [`Account::seal`], but with `Some(device_key)` the blob is **device-bound**
    /// (vault v2): opening it again needs the password *and* the OS-keyring device key,
    /// so a stolen blob cannot be brute-forced offline on the password alone. With
    /// `None` this is the portable v1 seal.
    pub fn seal_bound(
        &self,
        password: &str,
        device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    ) -> Result<Vec<u8>, AccountError> {
        Ok(vault::seal_with(password, device_key, &self.payload()?)?)
    }

    /// Re-seal the current state under the wrapping key cached at create/unlock — **no
    /// Argon2 run**, so this is cheap enough to call after every single message. This is
    /// what interactive clients should use; [`Account::seal_bound`] (full KDF) remains
    /// for exports/password changes.
    pub fn reseal(&self) -> Result<Vec<u8>, AccountError> {
        let key = self
            .seal_key
            .as_ref()
            .expect("Account always carries a seal key from create/unlock");
        Ok(vault::seal_with_key(key, &self.payload()?)?)
    }

    fn payload(&self) -> Result<VaultPayload, AccountError> {
        Ok(VaultPayload {
            account_id: self.account_id.clone(),
            secret_state: self.engine.export_state()?,
            data_key: self.data_key.to_vec(),
        })
    }

    /// Export the cached seal key as bytes, for quick-unlock wrapping (see the [`quick`]
    /// module). These bytes ARE the vault key: store them only encrypted (PIN- or
    /// Keystore-wrapped); the returned buffer zeroizes on drop.
    pub fn seal_key_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        self.seal_key
            .as_ref()
            .expect("Account always carries a seal key from create/unlock")
            .to_bytes()
    }

    /// Rotate the vault password: enforce policy on the new one, derive a fresh seal key
    /// (one Argon2 run), cache it, and return the re-sealed blob. Every quick-unlock blob
    /// wrapped around the old seal key is invalidated by this — the caller re-wraps or
    /// deletes them. The caller is responsible for having verified the *current* password
    /// first (by opening the on-disk vault with it).
    pub fn rekey(
        &mut self,
        new_password: &str,
        device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    ) -> Result<Vec<u8>, AccountError> {
        let strength = check_password(new_password);
        if !strength.acceptable {
            return Err(AccountError::WeakPassword(strength.problems.join(", ")));
        }
        self.seal_key = Some(vault::derive_seal_key(new_password, device_key)?);
        self.reseal()
    }

    /// Change the account's username (= account id). Local only: the caller must publish
    /// the new Key Transparency claim / registration and revert on failure — this just
    /// validates and swaps the id, which changes [`Account::identity_hash`] and what
    /// [`Account::kt_claim_entry`](crate::kt) signs.
    pub fn rename(&mut self, new_username: &str) -> Result<(), AccountError> {
        let new_username = new_username.trim();
        if new_username.is_empty() || new_username.len() > 64 {
            return Err(AccountError::WeakPassword(
                "username must be 1..=64 characters".into(),
            ));
        }
        self.account_id = new_username.to_string();
        Ok(())
    }
}

/// Unlock a vault blob with exported seal-key bytes (the quick-unlock path — PIN,
/// biometric, or auto-unlock blobs all resolve to these bytes). No KDF runs; a key that
/// does not match the blob fails like a wrong password.
pub fn unlock_with_seal_key(
    seal_key_bytes: &[u8],
    vault_blob: &[u8],
) -> Result<Account, AccountError> {
    let seal_key = vault::SealKey::from_bytes(seal_key_bytes)?;
    let payload = vault::open_with_seal_key(&seal_key, vault_blob)?;
    let engine = RatchetEngine::import_state(&payload.secret_state)?;
    // Fail closed on a legacy vault with no stored data key (L-8) — see `unlock_bound`.
    let data_key: [u8; 32] = payload
        .data_key
        .clone()
        .try_into()
        .map_err(|_| AccountError::LegacyVault)?;
    Ok(Account {
        engine,
        account_id: payload.account_id.clone(),
        data_key,
        seal_key: Some(seal_key),
    })
}

/// Create a brand-new account with a fully random id (no human-chosen handle).
/// Contacts add each other by exchanging this id out-of-band.
pub fn create_account(password: &str) -> Result<(Account, Vec<u8>), AccountError> {
    build_account(password, random_uuid(), None)
}

/// Create an account whose discovery handle is a chosen `username` (login by username +
/// password). The username becomes the account id; its hash is the routing/Key
/// Transparency address. Usernames are first-come: the KT log refuses a second claim of
/// one already taken, so an attacker cannot overwrite an existing user's keys.
pub fn create_account_with_username(
    username: &str,
    password: &str,
) -> Result<(Account, Vec<u8>), AccountError> {
    create_account_with_username_bound(username, password, None)
}

/// Like [`create_account_with_username`], but with `Some(device_key)` the returned vault
/// blob is **device-bound** (v2 — see [`Account::seal_bound`]).
pub fn create_account_with_username_bound(
    username: &str,
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
) -> Result<(Account, Vec<u8>), AccountError> {
    let username = username.trim();
    if username.is_empty() || username.len() > 64 {
        return Err(AccountError::WeakPassword(
            "username must be 1..=64 characters".into(),
        ));
    }
    build_account(password, username.to_string(), device_key)
}

/// Shared account builder: enforce password policy, mint an Olm identity, seal the vault.
fn build_account(
    password: &str,
    account_id: String,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
) -> Result<(Account, Vec<u8>), AccountError> {
    let strength = check_password(password);
    if !strength.acceptable {
        return Err(AccountError::WeakPassword(strength.problems.join(", ")));
    }
    let mut data_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut data_key);
    // One Argon2 run here, at creation; every later re-seal reuses the cached key.
    let seal_key = vault::derive_seal_key(password, device_key)?;
    let account = Account {
        engine: RatchetEngine::new(),
        account_id,
        data_key,
        seal_key: Some(seal_key),
    };
    let vault_blob = account.reseal()?;
    Ok((account, vault_blob))
}

/// Unlock an existing account from its vault blob. Returns [`VaultError::Decryption`]
/// (wrapped) on a wrong password — the AEAD makes wrong-password and tampering
/// indistinguishable, so there is no oracle for an attacker.
pub fn unlock(password: &str, vault_blob: &[u8]) -> Result<Account, AccountError> {
    unlock_bound(password, None, vault_blob)
}

/// Like [`unlock`], but able to open device-bound (v2) vaults when the OS-keyring
/// device key is supplied. Opens portable v1 vaults too (the device key is ignored for
/// those, which is what allows a seamless v1→v2 re-seal on first unlock).
pub fn unlock_bound(
    password: &str,
    device_key: Option<&[u8; DEVICE_KEY_LEN]>,
    vault_blob: &[u8],
) -> Result<Account, AccountError> {
    let (payload, opened_key) = vault::open_keeping_key(password, device_key, vault_blob)?;
    let engine = RatchetEngine::import_state(&payload.secret_state)?;
    // New accounts always carry a random 32-byte data key. A vault that lacks one predates
    // the field; rather than derive a *predictable* key from the (semi-public) account id,
    // fail closed — a deterministic history key would be guessable from the username (L-8).
    let data_key: [u8; 32] = payload
        .data_key
        .clone()
        .try_into()
        .map_err(|_| AccountError::LegacyVault)?;
    // v1→v2 migration: a portable blob opened on a device that HAS a keyring key gets a
    // fresh device-bound seal key, so the next re-seal upgrades it. One extra KDF run,
    // once, at unlock. Otherwise reuse the key we already derived to open the blob.
    let seal_key = if vault_blob.get(4) == Some(&1) {
        if let Some(_dk) = device_key {
            vault::derive_seal_key(password, device_key)?
        } else {
            opened_key
        }
    } else {
        opened_key
    };
    Ok(Account {
        engine,
        account_id: payload.account_id.clone(),
        data_key,
        seal_key: Some(seal_key),
    })
}

/// Minimal RFC-4122-shaped v4 UUID from OS randomness (no extra dependency).
fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_weak_passwords() {
        assert!(!check_password("short").acceptable);
        assert!(!check_password("alllowercase123!").acceptable); // no uppercase
        assert!(!check_password("NoNumbersHere!").acceptable);
        assert!(!check_password("NoSymbol1234").acceptable);
    }

    #[test]
    fn rejects_policy_compliant_but_common_passwords() {
        // All satisfy the composition rules yet reduce to a common weak base (L-2).
        assert!(!check_password("Password123!").acceptable);
        assert!(!check_password("P@ssw0rd2024!").acceptable); // leet + decoration
        assert!(!check_password("Qwerty12345!").acceptable);
        assert!(!check_password("Letmein-2024!").acceptable);
        assert!(!check_password("Iloveyou-9000!").acceptable);
    }

    #[test]
    fn accepts_strong_password() {
        assert!(check_password("Correct-Horse-Battery-9").acceptable);
        // A real word that merely *contains* a blocklisted substring mid-string is fine.
        assert!(check_password("Brass-Compass-Word-7!").acceptable);
    }

    #[test]
    fn create_unlock_round_trip() {
        let pw = "Correct-Horse-Battery-9";
        let (acct, blob) = create_account(pw).unwrap();
        let id = acct.account_id().to_string();
        let hash = acct.identity_hash();
        // Re-open the sealed vault with the same password.
        let reopened = unlock(pw, &blob).unwrap();
        assert_eq!(reopened.account_id(), id);
        assert_eq!(reopened.identity_hash(), hash);
        // The routing hash is the SHA-256 of the account id, nothing else.
        assert_eq!(hash, protocol_types::IdentityHash::from_identifier(&id));
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let (_, blob) = create_account("Correct-Horse-Battery-9").unwrap();
        assert!(matches!(
            unlock("Wrong-Password-12345", &blob),
            Err(AccountError::Vault(VaultError::Decryption))
        ));
    }

    #[test]
    fn device_bound_account_round_trip() {
        let pw = "Correct-Horse-Battery-9";
        let dk = [5u8; DEVICE_KEY_LEN];
        let (acct, blob) = create_account_with_username_bound("alice", pw, Some(&dk)).unwrap();
        // Password alone is no longer enough…
        assert!(matches!(
            unlock(pw, &blob),
            Err(AccountError::Vault(VaultError::DeviceKeyRequired))
        ));
        // …password + device key is.
        let reopened = unlock_bound(pw, Some(&dk), &blob).unwrap();
        assert_eq!(reopened.account_id(), acct.account_id());
    }

    #[test]
    fn reseal_is_cheap_and_round_trips() {
        let pw = "Correct-Horse-Battery-9";
        let (acct, _) = create_account(pw).unwrap();
        // reseal (no KDF) must be drastically faster than the Argon2 path and produce a
        // blob the password still opens.
        let t = std::time::Instant::now();
        let blob = acct.reseal().unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_millis(50),
            "reseal must not run Argon2 (took {:?})",
            t.elapsed()
        );
        let reopened = unlock(pw, &blob).unwrap();
        assert_eq!(reopened.account_id(), acct.account_id());
    }

    #[test]
    fn unlock_migrates_v1_vault_to_device_bound_on_reseal() {
        let pw = "Correct-Horse-Battery-9";
        let (acct, v1_blob) = create_account(pw).unwrap(); // portable v1
        let dk = [9u8; DEVICE_KEY_LEN];
        // Unlock on a device with a keyring key: reseal must upgrade to v2.
        let unlocked = unlock_bound(pw, Some(&dk), &v1_blob).unwrap();
        let resealed = unlocked.reseal().unwrap();
        assert!(matches!(
            unlock(pw, &resealed),
            Err(AccountError::Vault(VaultError::DeviceKeyRequired))
        ));
        assert_eq!(
            unlock_bound(pw, Some(&dk), &resealed).unwrap().account_id(),
            acct.account_id()
        );
    }

    #[test]
    fn seal_key_bytes_quick_unlock_round_trip() {
        let pw = "Correct-Horse-Battery-9";
        let dk = [8u8; DEVICE_KEY_LEN];
        let (acct, blob) = create_account_with_username_bound("dave", pw, Some(&dk)).unwrap();
        // Exported seal-key bytes open the vault with no password and no KDF.
        let bytes = acct.seal_key_bytes();
        let t = std::time::Instant::now();
        let reopened = unlock_with_seal_key(&bytes, &blob).unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_millis(50),
            "quick unlock must not run Argon2 (took {:?})",
            t.elapsed()
        );
        assert_eq!(reopened.account_id(), acct.account_id());
        // And the reopened account re-seals blobs the original password still opens.
        let resealed = reopened.reseal().unwrap();
        assert!(unlock_bound(pw, Some(&dk), &resealed).is_ok());
        // Garbage bytes fail cleanly.
        assert!(unlock_with_seal_key(&[0u8; 10], &blob).is_err());
    }

    #[test]
    fn rekey_rotates_password_and_invalidates_old_seal_key() {
        let old_pw = "Correct-Horse-Battery-9";
        let new_pw = "Different-Stable-Pw-42!";
        let dk = [6u8; DEVICE_KEY_LEN];
        let (mut acct, _) = create_account_with_username_bound("erin", old_pw, Some(&dk)).unwrap();
        let old_seal_bytes = acct.seal_key_bytes();

        // Weak new password refused, account unchanged.
        assert!(matches!(
            acct.rekey("weak", Some(&dk)),
            Err(AccountError::WeakPassword(_))
        ));

        let new_blob = acct.rekey(new_pw, Some(&dk)).unwrap();
        // New password opens; old password and the old seal key do not.
        assert!(unlock_bound(new_pw, Some(&dk), &new_blob).is_ok());
        assert!(matches!(
            unlock_bound(old_pw, Some(&dk), &new_blob),
            Err(AccountError::Vault(VaultError::Decryption))
        ));
        assert!(unlock_with_seal_key(&old_seal_bytes, &new_blob).is_err());
        // The account's newly cached key still quick-unlocks the new blob.
        assert!(unlock_with_seal_key(&acct.seal_key_bytes(), &new_blob).is_ok());
    }

    #[test]
    fn rename_changes_identity_hash_but_not_keys() {
        let (mut acct, _) =
            create_account_with_username_bound("frank", "Correct-Horse-Battery-9", None).unwrap();
        let old_hash = acct.identity_hash();
        let key_before = acct.ratchet_ref().identity_key();
        assert!(acct.rename("").is_err());
        assert!(acct.rename(&"x".repeat(65)).is_err());
        acct.rename("franklin").unwrap();
        assert_eq!(acct.account_id(), "franklin");
        assert_ne!(acct.identity_hash(), old_hash);
        assert_eq!(acct.ratchet_ref().identity_key(), key_before);
        assert_eq!(
            acct.identity_hash(),
            protocol_types::IdentityHash::from_identifier("franklin")
        );
    }

    #[test]
    fn weak_password_blocks_account_creation() {
        assert!(matches!(
            create_account("weak"),
            Err(AccountError::WeakPassword(_))
        ));
    }

    #[test]
    fn account_ids_are_unique() {
        let (a, _) = create_account("Correct-Horse-Battery-9").unwrap();
        let (b, _) = create_account("Correct-Horse-Battery-9").unwrap();
        assert_ne!(a.account_id(), b.account_id());
    }

    #[test]
    fn end_to_end_through_account_api() {
        // Two accounts, full vault→ratchet→message flow, including a re-seal/unlock cycle.
        let pw_a = "Alice-Password-123!";
        let pw_b = "Bob-Password-456!";
        let (mut alice, _) = create_account(pw_a).unwrap();
        let (mut bob, _) = create_account(pw_b).unwrap();
        let bob_id = bob.ratchet().identity_key();
        let alice_id = alice.ratchet().identity_key();

        let bundle = bob.ratchet().create_bundle();
        alice.ratchet().establish_outbound(&bundle).unwrap();
        let c1 = alice
            .ratchet()
            .encrypt(&bob_id, "hello over the account api")
            .unwrap();

        // Persist Bob, reload from vault, then decrypt — proves ratchet state survives storage.
        let bob_blob = bob.seal(pw_b).unwrap();
        let mut bob = unlock(pw_b, &bob_blob).unwrap();
        assert_eq!(
            bob.ratchet().decrypt(&alice_id, &c1).unwrap(),
            "hello over the account api"
        );
    }
}
