package app.sona.messenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings

// SONA-DELIVERY — foreground service that keeps the app process (and with it the Rust
// delivery engine's authenticated WebSocket) alive while the app is backgrounded.
//
// v2 (docs/NOTIFICATIONS.md §4.5): the service no longer merely idles — every onStartCommand calls
// nativeStartHeadless, so a START_STICKY restart after an OEM kill actually BOOTS the
// Rust engine (auto-unlock → reconnect) instead of posting a "Connected" notification
// over a dead runtime (RC-1: the lying notification). The status text is bound to the
// engine's real connection state via setStatus and can no longer lie:
//   0 Connected · 1 Reconnecting… · 2 Delivery paused (locked) · 3 stopping.
//
// Started when a session unlocks (mode C/C+P), by the boot receiver, and by Android's
// sticky restart; stopped on lock and in push-only mode.
class DeliveryService : Service() {
  companion object {
    private const val CHANNEL = "delivery"
    private const val NOTIF_ID = 7001

    /// Engine-reported status code; re-posted into the notification on change.
    @Volatile private var status = 1 // starts as "Reconnecting…" until Rust reports

    // Ask for the Doze exemption at most once per process: Doze parks the network even
    // under a foreground service, which would silently break background delivery. The
    // system remembers a grant; a decline re-prompts only after an app restart.
    @Volatile private var askedBattery = false

    @JvmStatic
    fun start(ctx: Context) {
      val i = Intent(ctx, DeliveryService::class.java)
      if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
      if (!askedBattery) {
        askedBattery = true
        requestUnrestrictedBattery(ctx)
      }
    }

    @JvmStatic
    fun stop(ctx: Context) {
      status = 3
      ctx.stopService(Intent(ctx, DeliveryService::class.java))
    }

    /// Rust → truthful status text. Re-posts the persistent notification only while
    /// the service is running (notify with the same id is a cheap in-place update).
    @JvmStatic
    fun setStatus(ctx: Context, code: Int) {
      if (status == code) return
      status = code
      if (code == 3) return // stopping — no repost
      if (running) {
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(ctx))
      }
    }

    @Volatile private var running = false

    /// Connectivity changed (NetworkMonitor): re-render the status text — the same
    /// engine code reads "Reconnecting…" with a network and "No network" without one.
    @JvmStatic
    fun refreshStatus(ctx: Context) {
      if (!running || status == 3) return
      val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
      nm.notify(NOTIF_ID, buildNotification(ctx))
    }

    private fun statusText(): String = when {
      status == 0 -> "Connected — receiving messages"
      status == 2 -> "Delivery paused — unlock Sona to receive messages"
      // Locked, but a wake transport is registered and the process hold was kept (E-2), so
      // an incoming call still reaches this device. Said explicitly rather than folded into
      // the line above: the difference between these two states is whether the phone rings,
      // and §4.5 forbids being vague about exactly that.
      status == 4 -> "Locked — unlock for messages. Incoming calls will still ring."
      // Honest offline text: the OS presents no network (airplane mode, or the app's
      // Network permission revoked on GrapheneOS) — "Reconnecting…" would imply a
      // fixable fault. Reconnect resumes the instant a network appears (onAvailable
      // nudge), so no user action is suggested.
      !NetworkMonitor.online -> "No network — delivery resumes automatically"
      else -> "Reconnecting…"
    }

    private fun buildNotification(ctx: Context): Notification {
      val open = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
      )
      val builder =
        if (Build.VERSION.SDK_INT >= 26) Notification.Builder(ctx, CHANNEL)
        else @Suppress("DEPRECATION") Notification.Builder(ctx)
      return builder
        .setSmallIcon(R.drawable.ic_stat_sona)
        .setContentTitle("Sona")
        .setContentText(statusText())
        .setOngoing(true)
        .setContentIntent(open)
        .build()
    }

    private fun requestUnrestrictedBattery(ctx: Context) {
      val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
      if (pm.isIgnoringBatteryOptimizations(ctx.packageName)) return
      try {
        val i = Intent(
          Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
          Uri.parse("package:" + ctx.packageName)
        )
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i)
      } catch (_: Exception) {
        // Some OEM builds hide this screen; delivery still works, just Doze-throttled.
      }
    }
  }

  /// Boot the Rust engine headless: auto-unlock (when enabled) and resume delivery.
  /// The engine drives the status text back through setStatus.
  private external fun nativeStartHeadless(dataDir: String)

  override fun onCreate() {
    super.onCreate()
    if (Build.VERSION.SDK_INT >= 26) {
      val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
      if (nm.getNotificationChannel(CHANNEL) == null) {
        nm.createNotificationChannel(
          NotificationChannel(
            CHANNEL,
            "Background delivery",
            // MIN: no sound, no status-bar icon on most builds — as quiet as a
            // foreground-service notification is allowed to be.
            NotificationManager.IMPORTANCE_MIN
          ).apply {
            description = "Keeps the encrypted connection open to receive messages and calls"
            setShowBadge(false)
          }
        )
      }
    }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    running = true
    val n = buildNotification(this)
    if (Build.VERSION.SDK_INT >= 34) {
      // targetSdk 34+: the type must be declared at startForeground time too.
      // specialUse (declared in the manifest with a PROPERTY_SPECIAL_USE_FGS_SUBTYPE
      // explanation) is the only type without a runtime time limit that fits
      // "hold a message-delivery socket without a push service" — and it is NOT in
      // Android 15's boot-time-restricted list (dataSync is).
      startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
    } else {
      startForeground(NOTIF_ID, n)
    }
    // The whole point of v2: a (re)start actually starts delivery. On a normal unlock
    // the engine is already running and this is a cheap no-op; after a sticky restart
    // it boots the engine, auto-unlocks, and reconnects (RC-1 fixed).
    Thread {
      try {
        nativeStartHeadless(dataDir.absolutePath)
      } catch (t: Throwable) {
        android.util.Log.e("SonaDelivery", "nativeStartHeadless failed", t)
      }
    }.start()
    return START_STICKY
  }

  // Swiping the task away must NOT stop the service — surviving that is its job.
  override fun onTaskRemoved(rootIntent: Intent?) {}

  override fun onDestroy() {
    running = false
    super.onDestroy()
  }

  override fun onBind(intent: Intent?): IBinder? = null
}
