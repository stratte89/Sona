package app.sona.messenger

import android.app.KeyguardManager
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
import android.net.ConnectivityManager
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
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
  /// The "unlock to answer" prompt. IMPORTANCE_HIGH, because a full-screen intent needs it
  /// — that is how the prompt gets over the keyguard — but silent and still: it stands in
  /// for a ring the user just answered, so alerting again is the phone arguing with them.
  /// A channel of its own because channels are immutable once created (silencing
  /// CHANNEL_CALLS would do nothing on an installed device, and would silence the ring).
  const val CHANNEL_CALL_UNLOCK = "call_unlock"
  const val CHANNEL_DELIVERY = "delivery" // owned by DeliveryService (IMPORTANCE_MIN)
  const val CHANNEL_STATUS = "status"

  private const val SUMMARY_ID = 7100
  private const val GENERIC_ID = 7101
  /// The "unlock to answer" prompt: one at a time, and its own id so cancelling it never
  /// touches the ring it stands beside.
  private const val UNLOCK_ID = 7102
  /// "A call is happening and this device cannot take it" (E-1). Its own id so clearing it
  /// never touches the message generic beside it, and so the unlock can revoke it.
  private const val CALL_GENERIC_ID = 7103
  private const val CALL_ID_BASE = 7200
  private const val GROUP_KEY = "sona_msgs"

  // ── Rust → Kotlin entry points (called via JNI reflection; keep signatures) ──

  @JvmStatic external fun nativeWake(dataDir: String, wakeClass: Int)
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
  /// Not private: `CallRingService` posts the ring as its own foreground notification and
  /// has to post it under the very same id, or cancelling one would leave the other.
  @JvmStatic
  fun callNotifId(callId: String): Int = CALL_ID_BASE + (callId.hashCode() and 0x0fffffff) % 1000

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
    // Must exist before the prompt is ever posted: a notification aimed at a channel that
    // does not exist is dropped SILENTLY on API 26+, which would take unlock-to-answer out
    // altogether — a far worse fault than the double ring this channel removes.
    if (nm.getNotificationChannel(CHANNEL_CALL_UNLOCK) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CHANNEL_CALL_UNLOCK, "Unlock to answer", NotificationManager.IMPORTANCE_HIGH).apply {
          description = "Prompt to unlock this device to finish answering a call"
          lockscreenVisibility = Notification.VISIBILITY_PRIVATE
          setSound(null, null)
          enableVibration(false)
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

  /// SONA-TELECOM — the user answered a call on a locked phone (from the lock screen, a
  /// watch, a headset). Telecom already shows the call as connecting; Sona still needs the
  /// vault before it may claim the call, so bring the app forward on top of the lock
  /// screen and let its ordinary unlock surface (biometric / PIN / password) do the rest.
  ///
  /// No credential path of its own: this only opens the app the user already has.
  ///
  /// Two ways in, because `startActivity` alone is not one. Reached from a notification
  /// action it works: the broadcast carries a background-activity-start grant. Reached
  /// from Core-Telecom's own answer callback — a headset, a watch, the lock screen, which
  /// is the case this whole feature exists for — there is no grant on Android 10+, and the
  /// call is not refused so much as silently ignored: nothing appears, nothing throws, and
  /// the attempt just times out with no explanation.
  ///
  /// So a full-screen intent goes up as well. That is the sanctioned way to put a call UI
  /// over the keyguard and needs no grant. On a phone that is awake and unlocked it
  /// degrades to a heads-up notification, which is why the direct start is still tried
  /// first — when it is allowed, it is the better experience.
  ///
  /// **What that intent may point at is the whole of E-4.** It pointed at `MainActivity`,
  /// which has no `showWhenLocked` — the very defect D-2 diagnosed for the ring and fixed
  /// by building `CallActivity`. Over a keyguard the launch landed behind it: nothing
  /// appeared, and the answer the user had just given led to the home screen with the call
  /// ringing somewhere they could not see. The full-screen intent now targets
  /// `CallActivity` in unlock mode, which can show there and which brings `MainActivity`
  /// forward itself once the dismissal succeeds — from a foreground activity, with the
  /// background-activity-start grant this function does not have.
  ///
  /// The *tap* still goes to `MainActivity`, because a tap happens on a screen that is
  /// already unlocked and going straight there is right.
  @JvmStatic
  fun openAppForUnlock() {
    val ctx = app()
    val i = Intent(ctx, MainActivity::class.java).apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
    try {
      ctx.startActivity(i)
    } catch (_: Throwable) {
      // Refused outright (rare — the usual failure is silent); the full-screen intent
      // below is the path that does not depend on a grant.
    }
    // The notification's TAP still goes to MainActivity — a tap happens on an unlocked
    // screen, where that is exactly right.
    val pi = PendingIntent.getActivity(
      ctx, UNLOCK_ID, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    // The FULL-SCREEN intent does not (E-4). It fires over a keyguard, and `MainActivity`
    // has no `showWhenLocked` — which is the entire reason D-2 had to build `CallActivity`
    // in the first place. Aimed here it landed behind the keyguard, so the answer the user
    // had just given led to the home screen with the call ringing out of sight.
    //
    // `CallActivity` already has every attribute this needs, and from there `MainActivity`
    // is launched by a foreground activity — which carries a background-activity-start
    // grant — instead of by Rust's runtime thread, which does not.
    val fsi = PendingIntent.getActivity(
      ctx,
      UNLOCK_ID + 1,
      CallActivity.unlockIntent(ctx),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    // CHANNEL_CALL_UNLOCK, not CHANNEL_CALLS: that channel's sound IS the ringtone, and
    // this is a fresh id on it, so the flagship flow went "press Answer → the insistent
    // ring stops → the phone immediately rings and buzzes again". Still IMPORTANCE_HIGH,
    // which is what keeps the full-screen intent — the whole mechanism for getting over
    // the keyguard — allowed.
    val n = Notification.Builder(ctx, CHANNEL_CALL_UNLOCK)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setContentTitle("Sona")
      .setContentText("Unlock to answer")
      .setCategory(Notification.CATEGORY_CALL)
      .setOngoing(true)
      .setOnlyAlertOnce(true) // backstop: a re-post must never alert either
      // PUBLIC, unlike the ring: this notification's entire content is the word "Sona" and
      // the instruction "Unlock to answer", which reveals nothing a locked device may not
      // say — and it is *for* a locked screen, where PRIVATE would have the system replace
      // it with a redacted stand-in the user cannot act on. The prompt has to be legible
      // exactly where it is least allowed to say anything.
      .setVisibility(Notification.VISIBILITY_PUBLIC)
      // Suppressed while the ring screen is driving its own dismissal: it is resumed and
      // visible, so its request is the one that can succeed, and firing a full-screen
      // intent at the same `singleInstance` activity would replace it mid-flight and
      // cancel exactly that request.
      .apply { if (!CallActivity.isHandlingUnlock()) setFullScreenIntent(fsi, true) }
      .setContentIntent(pi)
      // UNLOCK_TO_ANSWER_SECS — the engine's own deadline clears it too; this is the
      // backstop for a process that dies holding it. A notification-level timeout, so the
      // channel change above leaves it exactly as it was.
      .setTimeoutAfter(45_000)
      .build()
    nm(ctx).notify(UNLOCK_ID, n)
  }

  /// The unlock attempt resolved (answered, expired, or the call ended): take its prompt
  /// down. A prompt that outlives the call it belongs to is an invitation to answer
  /// something that is no longer ringing.
  @JvmStatic
  fun clearUnlockPrompt() {
    val ctx = app()
    nm(ctx).cancel(UNLOCK_ID)
    // The prompt and its full-screen surface are one thing and end as one thing, exactly
    // as the ring and `CallActivity` do (E-4). A window left in front of the keyguard for
    // an unlock attempt that has already resolved is the same class of leftover.
    CallActivity.dismissUnlock()
    // …and so is the process hold the answer handed over (E-5). Every path that resolves an
    // unlock attempt — the vault opening, the deadline, the call ending — comes through
    // here, so this is where the hold is given back rather than waiting out its backstop.
    CallRingService.releaseHold(ctx)
  }

  /// SONA-TELECOM — is the OS keyguard up right now?
  ///
  /// "Require app unlock to answer calls" promises that a call is never answered by
  /// whoever is holding the phone. That threat is the **device** being locked, and Sona's
  /// vault is a different state: auto-lock defaults to off, so the vault normally stays
  /// open from the user's last unlock while the phone sits at the keyguard. Gating the
  /// answer on the vault therefore gated on nothing in the default configuration; this is
  /// the state that has to be read instead.
  ///
  /// `isKeyguardLocked` alone, deliberately — not `&& isDeviceSecure`. A phone with no
  /// credential enrolled must not read as "free to answer": the Rust side asks for Sona's
  /// own password/PIN there instead. Anything unanswerable is treated as locked, so the
  /// cost of a broken probe is a human check, never a call answered without one.
  @JvmStatic
  fun deviceLocked(): Boolean =
    try {
      val kg = app().getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
      kg?.isKeyguardLocked ?: true
    } catch (_: Throwable) {
      true
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

  /// The ring's Answer action. SONA-TELECOM — it goes through the SAME path as a headset,
  /// a watch, or the lock screen: Rust decides (unlock gating, the caller's winner
  /// acknowledgement) and drives Telecom. It deliberately does not "open the app and hope
  /// the UI answers" — that was the second answer path internal/CALL_PLAN.md §7.3 removes. Rust
  /// brings the app forward itself when the vault has to be opened first.
  private fun answerAction(ctx: Context, callId: String): PendingIntent =
    PendingIntent.getBroadcast(
      ctx, callNotifId(callId),
      Intent(ctx, NotifActionReceiver::class.java).apply {
        action = NotifActionReceiver.ACTION_ANSWER
        putExtra("call_id", callId)
      },
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

  private fun declineAction(ctx: Context, callId: String): PendingIntent =
    PendingIntent.getBroadcast(
      ctx, callNotifId(callId) + 1,
      Intent(ctx, NotifActionReceiver::class.java).apply {
        action = NotifActionReceiver.ACTION_DECLINE
        putExtra("call_id", callId)
      },
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

  /// The ring notification. CallStyle (API 31+) / high-priority actions (26–30),
  /// full-screen intent onto [`CallActivity`], FLAG_INSISTENT so the system loops the
  /// channel ringtone until the notification is cancelled, and a timeout aligned with the
  /// Rust ring window.
  ///
  /// Two things here are what a lock screen actually needs, and neither was true before.
  ///
  /// **The full-screen intent aims at a screen that can show over the keyguard.** It used
  /// to aim at `MainActivity`, which has no `showWhenLocked` — so the launch landed behind
  /// the keyguard, nothing appeared, and the ring degraded to a notification. `CallActivity`
  /// is a bare Answer/Decline screen with no app state on it, for exactly this.
  ///
  /// **A public version, so the lock screen has something to press.** `VISIBILITY_PRIVATE`
  /// does not mean "show less"; it means the system substitutes its own redacted stand-in
  /// on a secure lock screen, and that stand-in carries no `CallStyle` and no actions. The
  /// user got a bare "Sona" line with no Answer and no Decline — the notification was
  /// technically there and the call was unanswerable. The public version is the sanctioned
  /// way to say what a *locked* device may show, and here that is the two actions with no
  /// name at all: withholding *who* is calling is what PRIVATE was asked for, withholding
  /// the ability to stop the ring was never part of the bargain.
  ///
  /// The name still reaches [`CallActivity`] — the full-screen call screen shows it the way
  /// every phone's incoming-call screen does, because deciding whether to answer is the
  /// whole point of it. `notif_level` is the control for that: at `"generic"` the engine
  /// resolves the title to "Sona" before it ever crosses into this process, so a user who
  /// asked never to be told who is calling is not told here either.
  @JvmStatic
  fun showCall(callId: String, title: String, isGroup: Boolean) {
    // Held by a phoneCall foreground service for the ring window: that is what keeps this
    // process out of the cached-and-frozen state while a call is ringing, so the terminal
    // that stops the ring can be *received* rather than waited on. Falls back to posting
    // the notification directly if the platform refuses the service.
    if (!CallRingService.start(app(), callId, title, isGroup)) {
      nm(app()).notify(callNotifId(callId), buildCallNotification(app(), callId, title, isGroup))
    }
  }

  /// Shared by [showCall] and by [CallRingService], which posts the very same notification
  /// as its foreground notification — one ring, one id, one lifetime.
  @JvmStatic
  fun buildCallNotification(
    ctx: Context,
    callId: String,
    title: String,
    isGroup: Boolean,
  ): Notification {
    val answer = answerAction(ctx, callId)
    val decline = declineAction(ctx, callId)
    // The full-screen intent fires AUTOMATICALLY over the lock screen — that is its whole
    // job. It must therefore only SHOW the ring UI (Answer/Decline), never carry the answer
    // action, or a locked phone silently auto-answers with no screen to decline from (the
    // caller then hears nothing until the callee unlocks).
    val showUi = PendingIntent.getActivity(
      ctx, callNotifId(callId) + 3, CallActivity.intent(ctx, callId, title, isGroup),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val text = if (isGroup) "Incoming group call" else "Incoming call"
    val builder = Notification.Builder(ctx, CHANNEL_CALLS)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setContentTitle(title)
      .setContentText(text)
      .setCategory(Notification.CATEGORY_CALL)
      .setOngoing(true)
      .setVisibility(Notification.VISIBILITY_PRIVATE)
      .setPublicVersion(publicCallNotification(ctx, callId, text, answer, decline))
      .setFullScreenIntent(showUi, true) // show the ring UI — NOT auto-answer (see above)
      .setContentIntent(showUi)
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
    return n
  }

  /// What a **secure lock screen** is allowed to render: the two actions, and no name.
  ///
  /// Names are deliberately dropped rather than passed through. `VISIBILITY_PRIVATE` is the
  /// user asking for sensitive content to be withheld there, and who is calling is exactly
  /// that; the full name is one unlock away, on the notification's own private form and on
  /// [`CallActivity`]. What must not be one unlock away is the ability to *stop the ring* —
  /// that is what the old redacted stand-in took away.
  private fun publicCallNotification(
    ctx: Context,
    callId: String,
    text: String,
    answer: PendingIntent,
    decline: PendingIntent,
  ): Notification {
    val showUi = PendingIntent.getActivity(
      ctx, callNotifId(callId) + 4, CallActivity.intent(ctx, callId, "Sona", false),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val builder = Notification.Builder(ctx, CHANNEL_CALLS)
      .setSmallIcon(R.drawable.ic_stat_sona)
      .setContentTitle("Sona")
      .setContentText(text)
      .setCategory(Notification.CATEGORY_CALL)
      .setOngoing(true)
      .setVisibility(Notification.VISIBILITY_PUBLIC)
      .setContentIntent(showUi)
      .setTimeoutAfter(45_000)
    if (Build.VERSION.SDK_INT >= 31) {
      val caller = android.app.Person.Builder().setName("Sona").setImportant(true).build()
      builder.setStyle(Notification.CallStyle.forIncomingCall(caller, decline, answer))
    } else {
      builder
        .addAction(Notification.Action.Builder(null, "Decline", decline).build())
        .addAction(Notification.Action.Builder(null, "Answer", answer).build())
    }
    return builder.build()
  }

  /// Stop the ring. `missedTitle` non-empty ⇒ post a missed-call entry (status channel).
  ///
  /// Every surface the ring occupies comes down together: the notification, the foreground
  /// service holding the process for it, and the call screen. They are posted as one thing
  /// and they end as one thing — a leftover on any of them is a call that looks live after
  /// it is over.
  /// The ring was **answered** here (E-5). Stops the ringtone and the call screen exactly
  /// as [cancelCall] does, but hands the process hold to the unlock window instead of
  /// ending it — Rust may be about to wait up to `UNLOCK_TO_ANSWER_SECS` for a vault, and
  /// on the locked path it has no socket either.
  ///
  /// Falls back to a plain cancel when no service is holding this ring: the fallback path
  /// posts the notification directly, and a ring whose process has since died has nothing
  /// behind it at all. Either way the insistent ringtone stops — that part is unconditional
  /// (D-1).
  /// Give back a process hold taken by [acceptCall] (E-5). No-op unless one is held, so
  /// every path that ends an answer's waiting period can call it blindly.
  @JvmStatic
  fun releaseCallHold() {
    CallRingService.releaseHold(app())
  }

  @JvmStatic
  fun acceptCall(callId: String) {
    val ctx = app()
    CallActivity.dismiss(callId)
    if (!CallRingService.holdForAnswer(ctx, callId)) {
      CallRingService.stop(ctx, callId)
      nm(ctx).cancel(callNotifId(callId))
    }
    // Answering must show the user the call they just joined.
    //
    // The lock-screen path already does this — `CallActivity.answer` finishes into
    // `openAppAndFinish`. Answering from the notification's own Accept action did not, so a
    // call answered with the app merely minimised connected silently: no call screen, no
    // timer, nothing but the "Answering…" notification, and the only way to see it was to
    // open Sona by hand. Reported 2026-08-01.
    //
    // Best effort: a background activity start can be refused, and the call is already
    // answered either way — the notification stays as the way back in.
    try {
      ctx.startActivity(
        Intent(ctx, MainActivity::class.java).apply {
          addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
      )
    } catch (_: Throwable) {
    }
  }

  @JvmStatic
  fun cancelCall(callId: String, missedTitle: String) {
    val ctx = app()
    CallRingService.stop(ctx, callId)
    CallActivity.dismiss(callId)
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

  // ── Headset / watch / car answer ──
  //
  // Core-Telecom delivers these now: a self-managed call registered with CallsManager
  // gets the HFP call button, the watch's answer, and the car's, as real answer and
  // disconnect callbacks (TelecomBridge.kt). The ring-window MediaSession that used to
  // approximate that is gone — two answer paths for one ring is exactly the duplicate
  // lifecycle internal/CALL_PLAN.md §7.3 removes.

  // ── Locked-vault degradation (docs/NOTIFICATIONS.md §7.4) ──

  /// kind 0 = "you may have new messages"; 1 = generic call ring (insistent, the
  /// answer intent lands on the lock screen → unlock → drain → real call UI);
  /// 2 = a call this device cannot act on.
  @JvmStatic
  fun showGeneric(kind: Int) {
    val ctx = app()
    if (kind == 1) {
      showCall("locked-call", "Sona", false)
      return
    }
    // SONA-TELECOM — a call is happening and this device cannot take it (`internal/CALL_PLAN.md`
    // §3.1, E-1): no capsule survived the drain, no call-control identity, a mailbox that
    // may not be screened, or credential-encrypted storage still locked after a reboot.
    //
    // Everything about this notification is the opposite of the ring, on purpose. The ring
    // is ONGOING|INSISTENT|NO_CLEAR|NO_DISMISS with a repeating ringtone and two actions;
    // its Answer resolves to `AnswerPlan::Nothing` and its Decline has no capsule to aim
    // at when there is no call state, so the user is left with a phone they cannot answer,
    // decline, or silence. This one is dismissible, silent, carries no actions it cannot
    // honour, and does nothing but open the app. CHANNEL_STATUS, not CHANNEL_CALLS —
    // that channel's sound *is* the ringtone.
    if (kind == 2) {
      nm(ctx).notify(
        CALL_GENERIC_ID,
        Notification.Builder(ctx, CHANNEL_STATUS)
          .setSmallIcon(R.drawable.ic_stat_sona)
          .setContentTitle("Sona")
          .setContentText("Incoming call — open Sona to answer")
          .setCategory(Notification.CATEGORY_CALL)
          .setAutoCancel(true)
          .setContentIntent(openAppIntent(ctx, emptyMap(), CALL_GENERIC_ID))
          .setVisibility(Notification.VISIBILITY_PRIVATE)
          // The ring window, so it does not outlive the call it stands for. A plain
          // notification honours setTimeoutAfter — unlike a foreground-service one, which
          // is why CallRingService needs its own backstop.
          .setTimeoutAfter(45_000)
          .build()
      )
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
    // The unactionable-call notice is superseded the moment the vault opens: the drain and
    // the live socket now produce a real, answerable ring, and an "open Sona to answer"
    // line for a call that is already on screen (or already over) is noise.
    nm.cancel(CALL_GENERIC_ID)
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
      // A usable FCM transport: Play services installed in THIS profile AND Firebase
      // initialized against it. `play_installed` separates "no Google here at all"
      // (de-Googled / GrapheneOS without sandboxed Play — UnifiedPush is the answer)
      // from "Play is here but has not produced a token yet", which on GrapheneOS is
      // usually its battery restriction and has different advice.
      put("play_services", SonaApp.firebaseReady)
      put("play_installed", SonaApp.playInstalled)
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
    const val ACTION_ANSWER = "app.sona.messenger.ANSWER_CALL"
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
      ACTION_ANSWER -> {
        val callId = intent.getStringExtra("call_id") ?: return
        // Stop the ringtone here, in Kotlin, for the same reason ACTION_DECLINE does: this
        // process always knows the id, and the Rust engine may not — after a locked wake the
        // notification outlives the process that posted it, so its in-memory "which ring is
        // showing" is empty while FLAG_INSISTENT keeps looping the channel ringtone.
        //
        // `acceptCall`, not `cancelCall`: a disconnect here would hang up the call being
        // answered, and ending the foreground service here would drop the process hold
        // exactly when the unlock wait needs it (E-5).
        NotificationBridge.acceptCall(callId)
        action(JSONObject().put("action", "answer_call").put("call_id", callId))
      }
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

    fun start(ctx: Context, wakeClass: Int) {
      val i = Intent(ctx, DrainService::class.java).putExtra("wakeClass", wakeClass)
      try {
        ctx.startForegroundService(i)
      } catch (_: Exception) {
        // Exemption window missed (rare): drain inline on the FCM thread's budget.
        NotificationBridge.nativeWake(ctx.dataDir.absolutePath, wakeClass)
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
    val wakeClass = intent?.getIntExtra("wakeClass", 0) ?: 0
    Thread {
      try {
        NotificationBridge.nativeWake(dataDir.absolutePath, wakeClass)
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

// SONA-TELECOM — the ring window's foreground service (`phoneCall`).
//
// The bug it exists for. A push-woken ring is posted from inside `DrainService`, a
// `shortService` that ends the moment the drain burst does — seconds later. After that the
// app owns no foreground component, so Android moves it to cached and freezes it (or kills
// it outright, cached-empty being first in line). Meanwhile the *notification* is in
// `system_server`, carrying `FLAG_INSISTENT`, and it keeps the ringtone looping for the
// full 45-second window no matter what the app is doing.
//
// So the app spent the ring frozen: its ring-timeout timer never fired, its socket was
// down, and the only thing that could still stop the ring was a second FCM wake landing on
// a process that had to boot from nothing. That is why "your friend hung up" and "you
// answered on the laptop" both ended with a phone that rang all the way out.
//
// A `phoneCall` foreground service is the sanctioned answer, and the permission for it was
// already declared and never used. Prerequisites are met unconditionally: the type needs
// `FOREGROUND_SERVICE_PHONE_CALL` plus either the dialer role or `MANAGE_OWN_CALLS`, and
// Sona holds the latter as a self-managed calling app.
//
// It also posts the ring notification *as* its foreground notification: on API 31+ a
// `CallStyle` notification is only accepted with a foreground service or a full-screen
// intent behind it, and tying it to the service means the ring no longer depends on the
// full-screen-intent permission being granted to keep its Answer and Decline buttons.
class CallRingService : Service() {
  companion object {
    private const val EXTRA_ID = "call_id"
    private const val EXTRA_TITLE = "title"
    private const val EXTRA_GROUP = "group"
    private const val NOTIF_PLACEHOLDER = 7003

    /// Hard stop for the ring window: CALL_RING_TIMEOUT_SECS (45 s) plus a little slack, so
    /// every ordinary ending — Rust's own ring-expiry timer, a terminal, either button —
    /// gets there first and this is only ever the backstop.
    ///
    /// It is not optional. `setTimeoutAfter` on the notification used to be the last line
    /// of defence, and a **foreground-service** notification cannot be timed out or
    /// cancelled by it while the service holds it. Without this the locked-vault ring — the
    /// one posted with no live call state behind it and therefore no Rust timer of its own —
    /// would ring until something killed the process.
    private const val RING_WINDOW_MS = 48_000L

    @Volatile private var live: CallRingService? = null
    /// The ring this service is holding, so a stale cancel for a different call cannot
    /// take down the one that is actually up.
    @Volatile private var current: String = ""

    /// The ring the service has been *asked* for, set before the start request and cleared
    /// by [stop].
    ///
    /// `startForegroundService` is asynchronous: the service does not exist yet when it
    /// returns. A terminal arriving in that window — an answer on the laptop lands within
    /// milliseconds — would find `live == null`, cancel a notification that has not been
    /// posted, and then watch the service start and ring for a call that is already over.
    /// `onStartCommand` compares against this and refuses to post a ring nobody wants.
    @Volatile private var wanted: String = ""

    /// The service is held for an **answer** rather than for a ring (E-5): the ringtone is
    /// already gone and what is left is the process hold the unlock wait needs. Read by
    /// [releaseHold], so that releasing can never take down a ring that is genuinely
    /// sounding for some other call.
    @Volatile private var holding = false

    /// Which call the hold above is for.
    ///
    /// Kept separately from [current], which only `onStartCommand` sets: a ring whose process
    /// died and restarted before the user answered reaches [holdForAnswer] with `current`
    /// empty, and then both the release and the backstop — each keyed on `current` — matched
    /// nothing and the "Answering…" notification stayed up for good.
    @Volatile private var heldFor: String = ""

    /// Returns false if the platform refused, and then the caller posts the notification
    /// directly — a ring that rings without the process being held is still better than no
    /// ring, and it is exactly the behaviour this replaced.
    @JvmStatic
    fun start(ctx: Context, callId: String, title: String, isGroup: Boolean): Boolean =
      try {
        wanted = callId
        ctx.startForegroundService(
          Intent(ctx, CallRingService::class.java)
            .putExtra(EXTRA_ID, callId)
            .putExtra(EXTRA_TITLE, title)
            .putExtra(EXTRA_GROUP, isGroup)
        )
        true
      } catch (_: Throwable) {
        // Background-start window missed, or the type refused on this build.
        wanted = ""
        false
      }

    /// How long the hold survives an **answer** (E-5). Covers `UNLOCK_TO_ANSWER_SECS`
    /// (45 s) with the same slack [RING_WINDOW_MS] gives the ring, so every ordinary
    /// ending — the vault opening, the deadline, the user cancelling — gets there first.
    private const val HOLD_WINDOW_MS = 48_000L

    /// The ring was **answered**: keep the process hold for the unlock window instead of
    /// dropping it (E-5).
    ///
    /// Both answer surfaces used to call `cancelCall`, which stops this service — right
    /// when Rust is about to arm a 45-second `pending_unlock` during which, on the locked
    /// path, there is no socket either. The hold has to survive the answer, not end with it.
    ///
    /// The ring notification is replaced **in place** (same id, through
    /// `NotificationManager.notify`) rather than by restarting the foreground with a new
    /// one. That is the documented way to update a foreground-service notification, it
    /// keeps the service and its `phoneCall` type exactly as they were, and it means the
    /// insistent ringtone stops the instant this runs — the new notification simply does
    /// not carry `FLAG_INSISTENT`.
    ///
    /// Returns false when this service is not the one holding `callId`, and then the caller
    /// cancels the notification outright: a ring posted on the fallback path, or by a
    /// process that has since died, has no service behind it and must still come down (D-1).
    @JvmStatic
    fun holdForAnswer(ctx: Context, callId: String): Boolean {
      if (callId.isEmpty()) return false
      if (current.isNotEmpty() && current != callId) return false
      if (current.isEmpty() && wanted.isNotEmpty() && wanted != callId) return false
      val svc = live ?: return false
      Handler(Looper.getMainLooper()).post {
        // Re-read on the main thread, where `onStartCommand` also runs: a different ring
        // may have taken this service over between the request and here.
        if (current.isNotEmpty() && current != callId) return@post
        try {
          val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
          nm.notify(NotificationBridge.callNotifId(callId), answeringNotification(ctx))
          holding = true
          // The call this hold is for, recorded separately from `current`.
          //
          // Both the release and the backstop below used to key off `current`, which is set
          // by `onStartCommand` — so a ring whose process died and restarted before it was
          // answered reached here with `current` empty. The hold was taken, and then nothing
          // could give it back: `releaseHold` returned early on the empty id and the backstop's
          // `current == callId` never matched either. The result was an "Answering…"
          // notification that never went away, sitting over the lock screen clock for the rest
          // of the call. Reported 2026-08-01.
          heldFor = callId
          svc.handler.removeCallbacksAndMessages(null)
          svc.handler.postDelayed({
            if (heldFor == callId) NotificationBridge.cancelCall(callId, "")
          }, HOLD_WINDOW_MS)
        } catch (_: Throwable) {
          // Could not swap it: stopping is safer than leaving an insistent ring up for a
          // call the user has already answered.
          NotificationBridge.cancelCall(callId, "")
        }
      }
      return true
    }

    /// Give back a hold taken by [holdForAnswer].
    ///
    /// Deliberately **not** `stop(ctx, "")`. The empty id stops whatever is held, and by the
    /// time an unlock attempt resolves a *different* call may be ringing — a redial, or a
    /// second caller. Killing that ring is exactly the mistake D-4's `wanted`/`current`
    /// guards exist to prevent, so this releases only a service that is actually holding
    /// for an answer, and only the call it is holding for.
    @JvmStatic
    fun releaseHold(ctx: Context) {
      if (!holding) return
      // `heldFor`, not `current`: the hold names its own call precisely so a restarted
      // service (empty `current`) can still give it back. See `holdForAnswer`.
      val held = heldFor.ifEmpty { current }
      if (held.isEmpty()) return
      NotificationBridge.cancelCall(held, "")
    }

    /// What stands in for the ring while the answer is being completed. Silent and
    /// alert-once — it replaces a ring the user has just answered, so alerting again is
    /// the phone arguing with them (the same rule A-20 established for the unlock prompt).
    private fun answeringNotification(ctx: Context): Notification =
      Notification.Builder(ctx, NotificationBridge.CHANNEL_CALLS)
        .setSmallIcon(R.drawable.ic_stat_sona)
        .setContentTitle("Sona")
        .setContentText("Answering…")
        .setCategory(Notification.CATEGORY_CALL)
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setVisibility(Notification.VISIBILITY_PRIVATE)
        .build()

    /// The ring is over. Empty `callId` stops whatever is held.
    @JvmStatic
    fun stop(ctx: Context, callId: String) {
      if (callId.isNotEmpty() && current.isNotEmpty() && current != callId) return
      if (callId.isNotEmpty() && current.isEmpty() && wanted.isNotEmpty() && wanted != callId) {
        return
      }
      wanted = ""
      current = ""
      holding = false
      heldFor = ""
      val svc = live ?: return // not started yet — `onStartCommand` will now refuse it
      // Onto the main thread, where `onStartCommand` also runs. This is reached from Rust's
      // JNI thread, and the two must not interleave: a ring ending while the next one is
      // starting (a redial, or a second caller) would otherwise let this tear-down land
      // *after* the new ring's `startForeground` and demote a call that just began.
      // Re-reading `wanted` inside the post is what makes that safe — if a new ring has
      // been asked for by the time this runs, it is not ours to stop.
      Handler(Looper.getMainLooper()).post {
        if (wanted.isNotEmpty()) return@post
        // STOP_FOREGROUND_REMOVE takes the notification with it; the caller cancels the id
        // as well, because the notification also exists on the fallback path where no
        // service was ever started.
        try {
          svc.stopForeground(STOP_FOREGROUND_REMOVE)
          svc.stopSelf()
        } catch (_: Throwable) {
          // Already gone.
        }
      }
    }

    /// A notification that says nothing and makes no sound, on the delivery channel
    /// (IMPORTANCE_MIN). Used only to answer `startForegroundService`'s five-second
    /// deadline on a start that must not become a ring — the service removes it and stops
    /// in the same breath, so it is never really on screen.
    private fun placeholder(svc: Service): Notification =
      Notification.Builder(svc, NotificationBridge.CHANNEL_DELIVERY)
        .setSmallIcon(R.drawable.ic_stat_sona)
        .setContentTitle("Sona")
        .build()
  }

  override fun onCreate() {
    super.onCreate()
    live = this
    // The placeholder rides CHANNEL_DELIVERY, and a notification aimed at a channel that
    // does not exist is dropped SILENTLY on API 26+ — which would make `startForeground`
    // throw and take the deadline escape with it. This service can be the first thing in
    // the process to need that channel, so it does not assume anyone else made it.
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
  }

  override fun onDestroy() {
    handler.removeCallbacksAndMessages(null)
    if (live === this) live = null
    super.onDestroy()
  }

  private val handler = Handler(Looper.getMainLooper())

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val callId = intent?.getStringExtra(EXTRA_ID) ?: ""
    val title = intent?.getStringExtra(EXTRA_TITLE) ?: "Sona"
    val isGroup = intent?.getBooleanExtra(EXTRA_GROUP, false) ?: false
    // The ring was cancelled between the start request and this callback (an answer on
    // another device is that fast), or this is a restart carrying no intent. Either way it
    // must not become a ring — but the `startForegroundService` deadline still has to be
    // answered, or the system kills the process for missing it.
    if (callId.isEmpty() || wanted != callId) {
      try {
        startForeground(NOTIF_PLACEHOLDER, placeholder(this))
        stopForeground(STOP_FOREGROUND_REMOVE)
      } catch (_: Throwable) {
        // Never reached the foreground; stopping below cancels the deadline anyway.
      }
      stopSelf()
      return START_NOT_STICKY
    }
    // A different ring already held here: take its notification down first, or replacing
    // the service's foreground notification would leave the old one stranded on screen.
    val previous = current
    if (previous.isNotEmpty() && previous != callId) {
      try {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
          .cancel(NotificationBridge.callNotifId(previous))
      } catch (_: Throwable) {
      }
    }
    current = callId
    // A real ring is taking this service over, so it is no longer held for an answer —
    // whatever it was holding for is finished with. Without this, `releaseHold` from the
    // *previous* call's unlock resolving would take down the ring that just started.
    holding = false
    heldFor = ""
    val id = NotificationBridge.callNotifId(callId)
    val n = NotificationBridge.buildCallNotification(this, callId, title, isGroup)
    // `startForegroundService` must be answered by `startForeground` within ~5 s or the
    // system kills the process with a "did not then call startForeground" exception.
    // Stopping the service cancels that deadline, so every failure path ends in stopSelf —
    // and the notification still goes up, because a refused service must not cost the ring.
    try {
      if (Build.VERSION.SDK_INT >= 34) {
        startForeground(id, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL)
      } else {
        startForeground(id, n)
      }
    } catch (_: Throwable) {
      try {
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(id, n)
      } catch (_: Throwable) {
      }
      current = ""
      stopSelf()
      return START_NOT_STICKY
    }
    // The backstop. Nothing else in this process is guaranteed to end a locked-vault ring:
    // it is posted with no call state behind it, so it has no Rust timer of its own, and a
    // foreground-service notification ignores `setTimeoutAfter`.
    handler.removeCallbacksAndMessages(null)
    handler.postDelayed({
      if (current == callId) {
        NotificationBridge.cancelCall(callId, "")
      }
    }, RING_WINDOW_MS)
    // NOT sticky: a restart with no intent would re-post a ring for a call that is over.
    return START_NOT_STICKY
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
