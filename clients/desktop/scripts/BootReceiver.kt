package app.sona.messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import org.json.JSONObject
import java.io.File

// SONA-NOTIFY — start background delivery after a reboot (docs/NOTIFICATIONS.md §4.6), injected by
// scripts/harden-android.sh. Gated on:
//  * the user having unlocked the device once (Keystore keys are unavailable before
//    the first unlock — nothing useful can start earlier),
//  * a configured account existing (vault.bin), and
//  * a connection delivery mode ("c"/"cp" — push-only needs no service; the next
//    message wakes the app via FCM, which works from boot on its own).
// prefs.json is deliberately plaintext (it must be readable before unlock); reading
// the mode here leaks nothing.
class BootReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
    val um = context.getSystemService(Context.USER_SERVICE) as UserManager
    if (!um.isUserUnlocked) return
    val dataDir = context.dataDir
    if (!File(dataDir, "vault.bin").exists()) return
    val mode = try {
      val prefs = File(dataDir, "prefs.json")
      if (prefs.exists()) JSONObject(prefs.readText()).optString("delivery_mode", "c") else "c"
    } catch (_: Exception) {
      "c"
    }
    if (mode == "p") return
    DeliveryService.start(context)
  }
}
