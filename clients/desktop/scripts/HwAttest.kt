package app.sona.messenger

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import org.json.JSONArray

// SONA-ATTEST — device-link hardware attestation (docs/MULTI_DEVICE.md), installed by
// scripts/harden-android.sh. Driven from Rust over JNI while a link request is built.
//
// Mints an EPHEMERAL Keystore EC P-256 key whose attestation challenge binds it to this
// exact link request, exports the certificate chain the secure hardware signed for it,
// and deletes the key — only the chain matters. The primary verifies the chain against
// the pinned Google attestation roots (client-core attest.rs) and shows the verdict
// before authorizing: proof the linking device is genuine Android hardware, not an
// emulator or a scripted client. StrongBox is preferred (attestation then carries
// security level 2); TEE is the fallback; devices with no attestation support at all
// (or a Keystore in a bad state) return "[]" and the link proceeds without a chain.
object HwAttest {
  private const val ALIAS = "sona-link-attest"

  /** Certificate chain (leaf first) as a JSON array of base64 DER, or "[]". */
  @JvmStatic
  fun chainJson(challenge: ByteArray): String {
    return try {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        try {
          return generate(challenge, strongBox = true)
        } catch (_: Exception) {}
      }
      generate(challenge, strongBox = false)
    } catch (_: Exception) {
      "[]"
    } finally {
      dropKey()
    }
  }

  private fun generate(challenge: ByteArray, strongBox: Boolean): String {
    dropKey()
    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setAttestationChallenge(challenge)
      .apply {
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(true)
        }
      }
      .build()
    kpg.initialize(spec)
    kpg.generateKeyPair()
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val chain = ks.getCertificateChain(ALIAS) ?: return "[]"
    val arr = JSONArray()
    for (c in chain) arr.put(Base64.encodeToString(c.encoded, Base64.NO_WRAP))
    return arr.toString()
  }

  private fun dropKey() {
    try {
      KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS)
    } catch (_: Exception) {}
  }
}
