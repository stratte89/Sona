package app.sona.messenger

// SONA-HARDENED — installed by scripts/harden-android.sh; re-run the script after
// regenerating gen/android. The Rust side (src-tauri/src/bio.rs) drives this class over
// JNI and polls the @Volatile result fields; keep names/signatures in sync.
//
// Fingerprint-first by design: BIOMETRIC_STRONG is Android biometric class 3, which the
// common camera-based face unlocks do not meet. (A device with class-3 face hardware
// would satisfy it too — the platform offers no way to allow fingerprints but refuse a
// class-3 face, and refusing class 3 outright would break fingerprints on some devices.)

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object BiometricGate {
  // Result protocol polled from Rust: PENDING while a prompt is up, then OK/CANCELLED/
  // ERROR; resultBlob carries the payload on OK (empty for a presence check).
  const val PENDING = -1
  const val OK = 0
  const val CANCELLED = 1
  const val ERROR = 2

  @JvmField @Volatile var resultCode: Int = ERROR
  @JvmField @Volatile var resultBlob: ByteArray? = null

  /** Alias of the seal-key wrapping key inside AndroidKeyStore. */
  private const val KEY_ALIAS = "sona-bio-unlock-key"

  /** 0 = strong biometric enrolled, 1 = device credential only, 2 = neither. */
  @JvmStatic
  fun availability(activity: Activity): Int {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      val bm = activity.getSystemService(BiometricManager::class.java)
      if (bm != null &&
        bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
          BiometricManager.BIOMETRIC_SUCCESS
      ) return 0
    }
    val kg = activity.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
    return if (kg?.isDeviceSecure == true) 1 else 2
  }

  /**
   * Presence check: fingerprint, falling back to the device credential. No key material —
   * this is the "OS vouches a legitimate user is present" step of a change ceremony.
   */
  @JvmStatic
  fun beginPresenceCheck(activity: Activity) {
    resultCode = PENDING
    resultBlob = null
    activity.runOnUiThread {
      try {
        val builder = BiometricPrompt.Builder(activity)
          .setTitle("Verify it's you")
          .setDescription("Confirm to authorize this account change")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          builder.setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
              BiometricManager.Authenticators.DEVICE_CREDENTIAL
          )
        } else {
          @Suppress("DEPRECATION")
          builder.setDeviceCredentialAllowed(true)
        }
        builder.build().authenticate(
          CancellationSignal(),
          activity.mainExecutor,
          callback { OK.also { resultBlob = ByteArray(0) } }
        )
      } catch (e: Exception) {
        resultCode = ERROR
      }
    }
  }

  /**
   * Wrap [plain] (the vault seal key) under a fresh Keystore AES-GCM key that requires a
   * BIOMETRIC_STRONG auth per use and dies when a new fingerprint is enrolled. The wrap
   * itself is auth-gated, so enabling prompts for a touch. Result blob: iv_len(1)||iv||ct.
   */
  @JvmStatic
  fun beginEnroll(activity: Activity, plain: ByteArray) {
    resultCode = PENDING
    resultBlob = null
    activity.runOnUiThread {
      try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, freshKey())
        prompt(activity, "Enable fingerprint unlock").authenticate(
          BiometricPrompt.CryptoObject(cipher),
          CancellationSignal(),
          activity.mainExecutor,
          cryptoCallback { c ->
            val iv = c.iv
            val ct = c.doFinal(plain)
            plain.fill(0)
            byteArrayOf(iv.size.toByte()) + iv + ct
          }
        )
      } catch (e: Exception) {
        resultCode = ERROR
      }
    }
  }

  /** Unwrap a blob produced by [beginEnroll]; prompts for a fingerprint. */
  @JvmStatic
  fun beginUnwrap(activity: Activity, blob: ByteArray) {
    resultCode = PENDING
    resultBlob = null
    activity.runOnUiThread {
      try {
        val ivLen = blob[0].toInt() and 0xff
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(KEY_ALIAS, null) as? SecretKey
          ?: throw IllegalStateException("no bio key")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        prompt(activity, "Unlock Sona").authenticate(
          BiometricPrompt.CryptoObject(cipher),
          CancellationSignal(),
          activity.mainExecutor,
          cryptoCallback { c -> c.doFinal(ct) }
        )
      } catch (e: Exception) {
        // Includes KeyPermanentlyInvalidatedException after a new fingerprint enrollment:
        // the wrap is dead by design; the app falls back to PIN/password.
        resultCode = ERROR
      }
    }
  }

  /** Delete the wrapping key (called when the user disables biometric unlock). */
  @JvmStatic
  fun dropKey() {
    try {
      KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KEY_ALIAS)
    } catch (_: Exception) {}
  }

  // ------------------------------------------------------------------ internals

  /** Replace any previous wrapping key with a fresh auth-per-use, enrollment-bound one. */
  private fun freshKey(): SecretKey {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    try { ks.deleteEntry(KEY_ALIAS) } catch (_: Exception) {}
    // StrongBox first (API 28+): on devices with a discrete secure element (all Pixels,
    // hence every GrapheneOS device) the wrapping key lives there instead of the TEE.
    // StrongBoxUnavailableException sometimes arrives wrapped in a ProviderException,
    // so any failure falls back to the TEE spec; a failed generateKey stores nothing
    // under the alias, so the retry is safe.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        return generateKey(strongBox = true)
      } catch (_: Exception) {}
    }
    return generateKey(strongBox = false)
  }

  private fun generateKey(strongBox: Boolean): SecretKey {
    val spec = KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .apply {
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
          @Suppress("DEPRECATION")
          setUserAuthenticationValidityDurationSeconds(-1) // auth per use
        }
      }
      .build()
    val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    kg.init(spec)
    return kg.generateKey()
  }

  private fun prompt(activity: Activity, title: String): BiometricPrompt {
    val builder = BiometricPrompt.Builder(activity)
      .setTitle(title)
      .setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> resultCode = CANCELLED }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
    }
    return builder.build()
  }

  /** Presence callback: no crypto object involved. */
  private fun callback(onOk: () -> Int) = object : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
      resultCode = onOk()
    }
    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
      resultCode =
        if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
          errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
        ) CANCELLED else ERROR
    }
  }

  /** Crypto callback: run [use] with the auth-released cipher, publish the blob. */
  private fun cryptoCallback(use: (Cipher) -> ByteArray) =
    object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
        try {
          val cipher = result?.cryptoObject?.cipher
            ?: throw IllegalStateException("no cipher")
          resultBlob = use(cipher)
          resultCode = OK
        } catch (e: Exception) {
          resultCode = ERROR
        }
      }
      override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
        resultCode =
          if (errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
          ) CANCELLED else ERROR
      }
    }
}
