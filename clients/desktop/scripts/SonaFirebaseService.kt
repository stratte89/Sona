package app.sona.messenger

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

// SONA-NOTIFY — the FCM receiver (docs/NOTIFICATIONS.md §6.4), injected by scripts/harden-android.sh.
//
// The payload is CONTENT-FREE by construction: the relay sends data-only messages
// whose entire body is {"t":"m"}, {"t":"c"}, or {"t":"x"} (message / call-ring /
// silent call-control wake class). No
// plaintext, sender, or identity ever rides through Google — display happens locally
// after the authenticated mailbox drain decrypts. A high-priority data message grants
// ~10 s of network in Doze plus the exemption to start a foreground service from the
// background; DrainService (shortService) holds the process for the drain.
class SonaFirebaseService : FirebaseMessagingService() {
  override fun onMessageReceived(message: RemoteMessage) {
    val wakeClass = when (message.data["t"]) {
      "c" -> 1
      "x" -> 2
      else -> 0
    }
    DrainService.start(applicationContext, wakeClass)
  }

  /// Token rotation / reinstall / restore: hand the fresh token to Rust, which
  /// re-registers the endpoint with the relay (idempotent upsert).
  override fun onNewToken(token: String) {
    try {
      NotificationBridge.nativeSetPushToken(token)
    } catch (_: Throwable) {
      // Native lib not loaded (impossible after SonaApp.onCreate) — next unlock
      // re-fetches the token anyway.
    }
  }
}
