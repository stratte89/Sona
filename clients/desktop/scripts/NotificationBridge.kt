package app.sona.messenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.RemoteInput
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.media.session.MediaSession
import android.media.session.PlaybackState
import android.net.ConnectivityManager
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.view.KeyEvent
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject

// SONA-NOTIFY — the native notification pipeline (docs/NOTIFICATIONS.md Pillar B), injected by
// scripts/harden-android.sh. Every OS notification posts through here using the
// APPLICATION context — never the activity, never the tauri plugin — so messages and
// calls keep working with the task removed, the process restarted headless, or the
// app never opened since boot (RC-2). Driven from Rust over JNI (notifier.rs);
// the `native*` externals below are the reverse direction (jni_entry.rs).
object NotificationBridge {
  const val CHANNEL_MESSAGES = "messages"
  const val CHANNEL_CALLS = "calls"
  const val CHANNEL_DELIVERY = "delivery" // owned by DeliveryService (IMPORTANCE_MIN)
  const val CHANNEL_STATUS = "status"

  private const val SUMMARY_ID = 7100
  private const val GENERIC_ID = 7101
  private const val CALL_ID_BASE = 7200
  private const val GROUP_KEY = "sona_msgs"

  // ── Rust → Kotlin entry points (called via JNI reflection; keep signatures) ──

  @JvmStatic external fun nativeWake(dataDir: String, callClass: Boolean)
  @JvmStatic external fun nativeNetworkChanged()
  @JvmStatic external fun nativeActivityState(resumed: Boolean)
  @JvmStatic external fun nativeNotifAction(json: String)
  @JvmStatic external fun nativeSetPushToken(token: String)
  @JvmStatic external fun nativeSetUpEndpoint(endpoint: String)
  @JvmStatic external fun nativeOpenIntent(json: String)

  private fun app(): Context = SonaApp.instance
  private fun nm(ctx: Context): NotificationManager =
    ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

  /// Stable 31-bit id per chat (message notifications are per-chat, MessagingStyle).
  private fun chatNotifId(chatKey: String): Int = 7300 + (chatKey.hashCode() and 0x0fffffff) % 100000
  private fun callNotifId(callId: String): Int = CALL_ID_BASE + (callId.hashCode() and 0x0fffffff) % 1000

  // ── Channels (created once from SonaApp.onCreate) ──

  @JvmStatic
  fun createChannels(ctx: Context) {
    val nm = nm(ctx)
    if (nm.getNotificationChannel(CHANNEL_MESSAGES) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CHANNEL_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
          description = "New messages"
          lockscreenVisibility = Notification.VISIBILITY_PRIVATE
          enableVibration(true)
          setShowBadge(true)
        }
      )
    }
    if (nm.getNotificationChannel(CHANNEL_CALLS) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CHANNEL_CALLS, "Incoming calls", NotificationManager.IMPORTANCE_HIGH).apply {
          description = "Incoming call rings"
          lockscreenVisibility = Notification.VISIBILITY_PRIVATE
          setSound(
            RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
            AudioAttributes.Builder()
              .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
              .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
              .build()
          )
          enableVibration(true)
          vibrationPattern = longArrayOf(0, 1000, 800, 1000, 800, 1000)
          setShowBadge(false)
        }
      )
    }
    if (nm.getNotificationChannel(CHANNEL_STATUS) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CHANNEL_STATUS, "Missed calls & alerts", NotificationManager.IMPORTANCE_DEFAULT).apply {
          description = "Missed calls and delivery alerts"
          lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
      )
    }
    // CHANNEL_DELIVERY (IMPORTANCE_MIN) is created by DeliveryService.
  }

  /// Activity PendingIntent (Android 12+ trampoline rules: launches must never go
  /// through a broadcast/service trampoline). Extras carry routing keys only.
  private fun openAppIntent(ctx: Context, extras: Map<String, String>, requestCode: Int): PendingIntent {
    val i = Intent(ctx, MainActivity::class.java).apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      for ((k, v) in extras) putExtra(k, v)
    }
    return PendingIntent.getActivity(
      ctx, requestCode, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
  }

  // ── Messages (MessagingStyle, per chat, grouped) ──

  /// `linesJson`: [{"title":…, "body":…, "when":…ms}] — already privacy-leveled by the
  /// Rust engine (never more than the user's chosen level reaches this process
  /// boundary). The engine replays the last ≤8 lines per chat on every post.
  @JvmStatic
  fun showMessage(chatKey: String, linesJson: String) {
    val ctx = app()
    val lines = JSONArray(linesJson)
    if (lines.length() == 0) return
    val me = android.app.Person.Builder().setName("You").build()
    val style = Notification.MessagingStyle(me)
    var latest = System.currentTimeMillis()
    for (i in 0 until lines.length()) {
      val l = lines.getJSONObject(i)
      val who = android.app.Person.Builder().setName(l.optString("title", "Sona")).build()
      val whenMs = l.optLong("when", System.currentTimeMillis())
      latest = whenMs
      style.addMessage(l.optString("body", ""), whenMs, who)
    }
    // Shade actions ride ONLY on real (decrypted) message notifications — the
    // locked-state generics never get them: there is nothing known to mark read or
    // reply to. Reply needs FLAG_MUTABLE (RemoteInput fills the result in); the
    // mark-read broadcast stays immutable. Distinct actions keep the PendingIntents
    // distinct despite shared request codes (filterEquals compares the action).
    val markRead = PendingIntent.getBroadcast(
      ctx, chatNotifId(chatKey),
      Intent(ctx, NotifActionReceiver::class.java).apply {
        action = NotifActionReceiver.ACTION_MARK_READ
        putExtra("chat", chatKey)
      },
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val replyPi = PendingIntent.getBroadcast(
      ctx, chatNotifId(chatKey),
      Intent(ctx, NotifActionReceiver::class.java).apply {
        action = NotifActionReceiver.ACTION_REPLY
        putExtra("chat", chatKey)
      },
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val n = Notification.Builder(ctx, CHANNEL_MESSAGES)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setStyle(style)
      .setWhen(latest)
      .setShowWhen(true)
      .setAutoCancel(true)
      .setGroup(GROUP_KEY)
      .setContentIntent(openAppIntent(ctx, mapOf("open_chat" to chatKey), chatNotifId(chatKey)))
      .setCategory(Notification.CATEGORY_MESSAGE)
      .setVisibility(Notification.VISIBILITY_PRIVATE)
      .addAction(Notification.Action.Builder(null, "Mark read", markRead).build())
      .addAction(
        Notification.Action.Builder(null, "Reply", replyPi)
          .addRemoteInput(RemoteInput.Builder(NotifActionReceiver.KEY_REPLY).setLabel("Reply").build())
          .build()
      )
      .build()
    val nm = nm(ctx)
    nm.notify(chatNotifId(chatKey), n)
    // Summary when >1 chat is active, so the shade collapses cleanly.
    val active = nm.activeNotifications.count { it.notification.group == GROUP_KEY && it.id != SUMMARY_ID }
    if (active > 1) {
      nm.notify(
        SUMMARY_ID,
        Notification.Builder(ctx, CHANNEL_MESSAGES)
          .setSmallIcon(R.drawable.ic_stat_sona)
          .setGroup(GROUP_KEY)
          .setGroupSummary(true)
          .setAutoCancel(true)
          .setContentIntent(openAppIntent(ctx, emptyMap(), SUMMARY_ID))
          .setCategory(Notification.CATEGORY_MESSAGE)
          .setVisibility(Notification.VISIBILITY_PRIVATE)
          .build()
      )
    }
  }

  /// The chat was opened, or its content expired (disappearing messages must never
  /// outlive their timer in the shade).
  @JvmStatic
  fun cancelChat(chatKey: String) {
    val nm = nm(app())
    nm.cancel(chatNotifId(chatKey))
    val left = nm.activeNotifications.count { it.notification.group == GROUP_KEY && it.id != SUMMARY_ID }
    if (left == 0) nm.cancel(SUMMARY_ID)
  }

  // ── Calls: the ring (RC-4 fix) ──

  /// CallStyle (API 31+) / high-priority actions (26–30), full-screen intent over the
  /// lock screen, FLAG_INSISTENT so the system loops the channel ringtone until the
  /// notification is cancelled, and a timeout aligned with the Rust ring window.
  @JvmStatic
  fun showCall(callId: String, title: String, isGroup: Boolean) {
    val ctx = app()
    val answer = openAppIntent(
      ctx, mapOf("call" to callId, "call_action" to "answer"), callNotifId(callId)
    )
    val declineIntent = Intent(ctx, NotifActionReceiver::class.java).apply {
      action = NotifActionReceiver.ACTION_DECLINE
      putExtra("call_id", callId)
    }
    val decline = PendingIntent.getBroadcast(
      ctx, callNotifId(callId) + 1, declineIntent,
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val builder = Notification.Builder(ctx, CHANNEL_CALLS)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setContentTitle(title)
      .setContentText(if (isGroup) "Incoming group call" else "Incoming call")
      .setCategory(Notification.CATEGORY_CALL)
      .setOngoing(true)
      .setVisibility(Notification.VISIBILITY_PRIVATE)
      .setFullScreenIntent(answer, true)
      .setTimeoutAfter(45_000) // RING_TIMEOUT_SECS — the Rust timer also cancels
    if (Build.VERSION.SDK_INT >= 31) {
      val caller = android.app.Person.Builder().setName(title).setImportant(true).build()
      builder.setStyle(Notification.CallStyle.forIncomingCall(caller, decline, answer))
    } else {
      builder
        .addAction(Notification.Action.Builder(null, "Decline", decline).build())
        .addAction(Notification.Action.Builder(null, "Answer", answer).build())
    }
    val n = builder.build()
    n.flags = n.flags or Notification.FLAG_INSISTENT
    nm(ctx).notify(callNotifId(callId), n)
  }

  /// Stop the ring. `missedTitle` non-empty ⇒ post a missed-call entry (status channel).
  @JvmStatic
  fun cancelCall(callId: String, missedTitle: String) {
    val ctx = app()
    nm(ctx).cancel(callNotifId(callId))
    if (missedTitle.isNotEmpty()) {
      nm(ctx).notify(
        callNotifId(callId) + 2,
        Notification.Builder(ctx, CHANNEL_STATUS)
          .setSmallIcon(R.drawable.ic_stat_sona)
          .setContentTitle(missedTitle)
          .setContentText("Missed call")
          .setAutoCancel(true)
          .setContentIntent(openAppIntent(ctx, emptyMap(), callNotifId(callId) + 2))
          .setCategory(Notification.CATEGORY_MISSED_CALL)
          .setVisibility(Notification.VISIBILITY_PRIVATE)
          .build()
      )
    }
  }

  // ── Bluetooth/headset button answer (ring window only) ──
  //
  // Without a Telecom ConnectionService the HFP call button never reaches us, but
  // virtually every headset's tap arrives as a media-button KeyEvent — IF an active
  // MediaSession claims it. One is held exactly for the ring window (started with the
  // ring, released with it): tap answers, double-function keys (stop/end) decline.
  // The engine validates the call id against the live ring, so a stale event is a
  // no-op. Outside the ring window no session exists — music apps keep their buttons.

  private var btSession: MediaSession? = null
  @Volatile private var btCallId: String? = null

  @JvmStatic
  fun callButtonsStart(callId: String) {
    synchronized(this) {
      callButtonsStopLocked()
      btCallId = callId
      try {
        val s = MediaSession(app(), "sona-call")
        s.setCallback(object : MediaSession.Callback() {
          override fun onMediaButtonEvent(mediaButtonIntent: Intent): Boolean {
            val ke: KeyEvent? = if (Build.VERSION.SDK_INT >= 33) {
              mediaButtonIntent.getParcelableExtra(Intent.EXTRA_KEY_EVENT, KeyEvent::class.java)
            } else {
              @Suppress("DEPRECATION") mediaButtonIntent.getParcelableExtra(Intent.EXTRA_KEY_EVENT)
            }
            val id = btCallId ?: return true
            if (ke == null || ke.action != KeyEvent.ACTION_UP) return true // eat downs/repeats
            when (ke.keyCode) {
              KeyEvent.KEYCODE_HEADSETHOOK, KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE,
              KeyEvent.KEYCODE_MEDIA_PLAY, KeyEvent.KEYCODE_CALL ->
                try {
                  nativeNotifAction(
                    JSONObject().put("action", "accept_call").put("call_id", id).toString()
                  )
                } catch (_: Throwable) {}
              KeyEvent.KEYCODE_MEDIA_STOP, KeyEvent.KEYCODE_ENDCALL -> {
                cancelCall(id, "")
                try {
                  nativeNotifAction(
                    JSONObject().put("action", "decline_call").put("call_id", id).toString()
                  )
                } catch (_: Throwable) {}
              }
              else -> return false
            }
            return true
          }
        }, Handler(Looper.getMainLooper()))
        // STATE_PLAYING is what makes the system route media buttons here.
        s.setPlaybackState(
          PlaybackState.Builder()
            .setActions(
              PlaybackState.ACTION_PLAY or PlaybackState.ACTION_PAUSE or
                PlaybackState.ACTION_PLAY_PAUSE or PlaybackState.ACTION_STOP
            )
            .setState(PlaybackState.STATE_PLAYING, 0, 1f)
            .build()
        )
        s.isActive = true
        btSession = s
      } catch (_: Exception) {
        // No session = no button answer; the ring itself is unaffected.
      }
    }
  }

  @JvmStatic
  fun callButtonsStop() = synchronized(this) { callButtonsStopLocked() }

  private fun callButtonsStopLocked() {
    btCallId = null
    btSession?.let {
      try {
        it.isActive = false
        it.release()
      } catch (_: Exception) {}
    }
    btSession = null
  }

  // ── Locked-vault degradation (docs/NOTIFICATIONS.md §7.4) ──

  /// kind 0 = "you may have new messages"; 1 = generic call ring (insistent, the
  /// answer intent lands on the lock screen → unlock → drain → real call UI).
  @JvmStatic
  fun showGeneric(kind: Int) {
    val ctx = app()
    if (kind == 1) {
      showCall("locked-call", "Sona", false)
      return
    }
    nm(ctx).notify(
      GENERIC_ID,
      Notification.Builder(ctx, CHANNEL_STATUS)
        .setSmallIcon(R.drawable.ic_stat_sona)
        .setContentTitle("Sona")
        .setContentText("You may have new messages — unlock to receive them")
        .setAutoCancel(true)
        .setContentIntent(openAppIntent(ctx, emptyMap(), GENERIC_ID))
        .setVisibility(Notification.VISIBILITY_PRIVATE)
        .build()
    )
  }

  /// The vault just unlocked: the locked-state generics are superseded — the drain
  /// or live socket now produces real (leveled) notifications, and a lingering
  /// generic ring must not keep "ringing" a call the user is already handling.
  @JvmStatic
  fun clearGenerics() {
    val nm = nm(app())
    nm.cancel(GENERIC_ID)
    nm.cancel(callNotifId("locked-call"))
  }

  // ── Foreground-service status / drain bookkeeping ──

  @JvmStatic
  fun setServiceStatus(code: Int) {
    DeliveryService.setStatus(app(), code)
  }

  @JvmStatic
  fun drainFinished() {
    DrainService.finish()
  }

  // ── Push token ──

  /// Async FCM token fetch; the token lands back in Rust via nativeSetPushToken.
  /// Silently unavailable without Firebase config / Play Services (mode P then stays
  /// gated off in the UI).
  @JvmStatic
  fun requestFcmToken() {
    try {
      if (!SonaApp.firebaseReady) return
      com.google.firebase.messaging.FirebaseMessaging.getInstance().token
        .addOnSuccessListener { token -> if (token != null) nativeSetPushToken(token) }
    } catch (_: Throwable) {
      // Play Services absent or Firebase not initialized — reported via healthJson.
    }
  }

  // ── Native clipboard image (paste fallback) ──
  //
  // Android's WebView never exposes clipboard images to JS in a plain textarea (no
  // files on the paste event, clipboard.read() denied), so the paste handler falls
  // back to this: read the system clipboard's content-URI item directly. Covers
  // "copy image/GIF anywhere → paste in Sona", including keyboards that put their
  // GIFs on the clipboard. Called only from an explicit paste gesture — never
  // polled — so Android's clipboard-access indicator matches user intent.
  @JvmStatic
  fun clipboardImageJson(): String {
    return try {
      val ctx = app()
      val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
      val clip = cm.primaryClip ?: return ""
      for (i in 0 until clip.itemCount) {
        val uri = clip.getItemAt(i).uri ?: continue
        val mime = ctx.contentResolver.getType(uri) ?: continue
        if (!mime.startsWith("image/")) continue
        val bytes = ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: continue
        if (bytes.isEmpty() || bytes.size > 10 * 1024 * 1024) continue
        val ext = mime.substringAfter('/').substringBefore('+')
        return JSONObject()
          .put("name", "pasted.$ext")
          .put("mime", mime)
          .put("b64", android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
          .toString()
      }
      ""
    } catch (_: Exception) {
      "" // no permission for that URI / clipboard empty — the paste just no-ops
    }
  }

  // ── UnifiedPush (docs/NOTIFICATIONS.md §6.7) — thin JNI-facing shims ──

  @JvmStatic fun upDistributors(): String = UnifiedPushMgr.distributorsJson(app())
  @JvmStatic fun upRegister(pkg: String) = UnifiedPushMgr.register(app(), pkg)
  @JvmStatic fun upUnregister() = UnifiedPushMgr.unregister(app())

  // ── Health panel (docs/NOTIFICATIONS.md §7.1) ──

  @JvmStatic
  fun healthJson(): String {
    val ctx = app()
    val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
    val nm = nm(ctx)
    val fsi = if (Build.VERSION.SDK_INT >= 34) nm.canUseFullScreenIntent() else true
    val msgsChannel = nm.getNotificationChannel(CHANNEL_MESSAGES)
    val callsChannel = nm.getNotificationChannel(CHANNEL_CALLS)
    return JSONObject().apply {
      put("battery_exempt", pm.isIgnoringBatteryOptimizations(ctx.packageName))
      // false = the OS presents no network to the app (airplane mode, or the app's
      // Network permission revoked on GrapheneOS) — lets the panel say "offline"
      // instead of implying a delivery fault.
      put("network", NetworkMonitor.online)
      put("notifications_enabled", nm.areNotificationsEnabled())
      put("full_screen_intent", fsi)
      put("play_services", SonaApp.firebaseReady)
      run {
        val up = JSONObject(UnifiedPushMgr.currentJson(ctx))
        put("up_distributor", up.optString("distributor", ""))
        put("up_endpoint", up.optBoolean("endpoint", false))
        put("up_available", JSONArray(UnifiedPushMgr.distributorsJson(ctx)).length() > 0)
      }
      put("messages_channel_muted",
        msgsChannel != null && msgsChannel.importance == NotificationManager.IMPORTANCE_NONE)
      put("calls_channel_muted",
        callsChannel != null && callsChannel.importance == NotificationManager.IMPORTANCE_NONE)
      put("manufacturer", Build.MANUFACTURER)
    }.toString()
  }

  /// Fix-it deep links: 0 battery exemption, 1 notification settings, 2 full-screen
  /// intent settings (API 34+), 3 the dontkillmyapp.com guide for this phone's maker
  /// (OEM background-killers have no API — only the user can flip their switches).
  @JvmStatic
  fun openFixit(what: Int) {
    val ctx = app()
    try {
      val i = when (what) {
        0 -> Intent(
          Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
          Uri.parse("package:" + ctx.packageName)
        )
        1 -> Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
          .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
        2 -> if (Build.VERSION.SDK_INT >= 34) {
          Intent(
            Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
            Uri.parse("package:" + ctx.packageName)
          )
        } else return
        3 -> Intent(Intent.ACTION_VIEW, Uri.parse("https://dontkillmyapp.com/" + dkmaSlug()))
        else -> return
      }
      i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      ctx.startActivity(i)
    } catch (_: Exception) {
      // Some OEM builds hide these screens; the health panel still shows the state.
    }
  }

  /// dontkillmyapp.com page slug for this device. Sub-brands map to their parent's
  /// page; makers without a page get the general one (the site 404s on unknowns).
  private fun dkmaSlug(): String {
    val m = Build.MANUFACTURER.lowercase().trim()
    val mapped = when (m) {
      "redmi", "poco" -> "xiaomi"
      "hmd global" -> "nokia"
      else -> m
    }
    val known = setOf(
      "samsung", "xiaomi", "huawei", "honor", "oneplus", "oppo", "realme", "vivo",
      "meizu", "asus", "sony", "lenovo", "nokia", "unihertz", "tecno", "infinix",
      "blackview", "google"
    )
    return if (mapped in known) mapped else "general"
  }
}

// SONA-NOTIFY — notification actions (decline / mark read / inline reply).
// exported=false; every payload is validated in Rust against live state (unknown
// call_id or chat = no-op, reply/mark-read require the unlocked vault), so a stale or
// spoofed broadcast cannot decline, read, or send anything real. Reply and mark-read
// exist only on real message notifications — the locked-state generics carry no
// actions, because there is nothing known to act on.
class NotifActionReceiver : BroadcastReceiver() {
  companion object {
    const val ACTION_DECLINE = "app.sona.messenger.DECLINE_CALL"
    const val ACTION_MARK_READ = "app.sona.messenger.MARK_READ"
    const val ACTION_REPLY = "app.sona.messenger.REPLY"
    const val KEY_REPLY = "sona_reply"
  }

  private fun action(json: JSONObject) {
    try {
      NotificationBridge.nativeNotifAction(json.toString())
    } catch (_: Throwable) {
      // Native lib not loaded (should not happen — SonaApp loads it) — drop.
    }
  }

  override fun onReceive(context: Context, intent: Intent) {
    when (intent.action) {
      ACTION_DECLINE -> {
        val callId = intent.getStringExtra("call_id") ?: return
        NotificationBridge.cancelCall(callId, "")
        action(JSONObject().put("action", "decline_call").put("call_id", callId))
      }
      ACTION_MARK_READ -> {
        val chat = intent.getStringExtra("chat") ?: return
        action(JSONObject().put("action", "mark_read").put("chat", chat))
      }
      ACTION_REPLY -> {
        val chat = intent.getStringExtra("chat") ?: return
        val text = RemoteInput.getResultsFromIntent(intent)
          ?.getCharSequence(KEY_REPLY)?.toString()?.trim() ?: return
        if (text.isEmpty()) return
        // Rust confirms by re-posting the notification (with the sent line appended,
        // or an error entry) — that repost is what clears the action's spinner.
        action(JSONObject().put("action", "reply").put("chat", chat).put("text", text))
      }
    }
  }
}

// SONA-NOTIFY — the push-drain shortService: a high-priority FCM wake grants the
// background-start exemption; this service keeps the process visible-alive for the
// few seconds the drain needs (3-minute hard cap type). Released from Rust through
// NotificationBridge.drainFinished() when the last drain loop ends.
class DrainService : Service() {
  companion object {
    @Volatile private var live: DrainService? = null

    fun start(ctx: Context, callClass: Boolean) {
      val i = Intent(ctx, DrainService::class.java).putExtra("call", callClass)
      try {
        ctx.startForegroundService(i)
      } catch (_: Exception) {
        // Exemption window missed (rare): drain inline on the FCM thread's budget.
        NotificationBridge.nativeWake(ctx.dataDir.absolutePath, callClass)
      }
    }

    fun finish() {
      live?.let { svc ->
        svc.stopForeground(STOP_FOREGROUND_REMOVE)
        svc.stopSelf()
      }
    }
  }

  override fun onCreate() {
    super.onCreate()
    live = this
  }

  override fun onDestroy() {
    live = null
    super.onDestroy()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (nm.getNotificationChannel(NotificationBridge.CHANNEL_DELIVERY) == null) {
      nm.createNotificationChannel(
        NotificationChannel(
          NotificationBridge.CHANNEL_DELIVERY,
          "Background delivery",
          NotificationManager.IMPORTANCE_MIN
        ).apply { setShowBadge(false) }
      )
    }
    val n = Notification.Builder(this, NotificationBridge.CHANNEL_DELIVERY)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setContentTitle("Sona")
      .setContentText("Checking for new messages…")
      .setOngoing(true)
      .build()
    if (Build.VERSION.SDK_INT >= 34) {
      startForeground(7002, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE)
    } else {
      startForeground(7002, n)
    }
    val call = intent?.getBooleanExtra("call", false) ?: false
    Thread {
      try {
        NotificationBridge.nativeWake(dataDir.absolutePath, call)
      } catch (t: Throwable) {
        android.util.Log.e("SonaDrain", "nativeWake failed", t)
        finish()
      }
    }.start()
    return START_NOT_STICKY
  }

  override fun onTimeout(startId: Int, fgsType: Int) {
    // shortService hard cap reached — stop cleanly; the mailbox keeps the rest.
    finish()
  }

  override fun onBind(intent: Intent?): IBinder? = null
}

// SONA-NOTIFY — connectivity callback: any network change nudges the Rust reconnect
// backoff so delivery recovers the moment a network exists (wifi↔cell, VPN toggles).
// Also tracks whether a default network exists at all, so the delivery notification
// can say "No network" instead of an eternal "Reconnecting…" — the visible state when
// the OS keeps the app offline (airplane mode, or GrapheneOS's per-app Network
// permission revoked, which simply presents no network to the app).
object NetworkMonitor {
  private var registered = false

  /** Is there a default network right now? Volatile: written from CM callbacks. */
  @JvmStatic @Volatile var online = true

  @JvmStatic
  fun register(ctx: Context) {
    if (registered) return
    registered = true
    val app = ctx.applicationContext
    val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    online = try { cm.activeNetwork != null } catch (_: Exception) { true }
    try {
      cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
          online = true
          try { NotificationBridge.nativeNetworkChanged() } catch (_: Throwable) {}
          DeliveryService.refreshStatus(app)
        }
        override fun onLost(network: Network) {
          // Another default network may replace this one (onAvailable follows);
          // re-query instead of assuming offline.
          online = try { cm.activeNetwork != null } catch (_: Exception) { false }
          DeliveryService.refreshStatus(app)
        }
      })
    } catch (_: Exception) {
      registered = false // too many callbacks registered (rare); watchdog still covers
    }
  }
}
