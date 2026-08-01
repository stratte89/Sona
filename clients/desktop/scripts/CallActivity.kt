package app.sona.messenger

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

/// SONA-TELECOM — the incoming-call screen, over the lock screen.
///
/// Why this exists at all. A **self-managed** Telecom call (`MANAGE_OWN_CALLS`, which is
/// the only kind an app without the dialer role may have) gets no system call UI: the
/// platform draws the in-call screen for *managed* connection services only, and the
/// contract for self-managed apps is explicitly that they show their own. Sona had none,
/// so everything the ring had to offer arrived as a notification — and on a secure lock
/// screen a notification is exactly where a call UI stops working:
///
///   * `VISIBILITY_PRIVATE` (the ring's, and the calls channel's) means the lock screen
///     shows the system's **redacted** stand-in, which carries no `CallStyle` and no
///     actions. No Answer button, no Decline button — the thing the user tested first.
///   * The full-screen intent aimed at `MainActivity` could not help: that activity has no
///     `showWhenLocked`, so the launch lands *behind* the keyguard and the user sees the
///     heads-up notification and nothing else.
///   * With no way to press anything, the only thing that stopped the ring was pulling
///     down the shade — `onPanelRevealed` clears a `FLAG_INSISTENT` sound. That is the
///     system silencing a notification, not the user answering a call.
///
/// So the ring gets a real screen: a plain Android activity, `showWhenLocked` +
/// `turnScreenOn`, that shows one already-privacy-leveled name and two buttons.
///
/// Deliberately **not** the app. No WebView, no vault, no chat state — it is a task of its
/// own (`taskAffinity=""`, `excludeFromRecents`), so putting a call over the keyguard can
/// never put a conversation there with it. The only thing it can say is what the ring
/// notification was already allowed to say, and the only things it can do are the two the
/// notification's own actions do.
///
/// Both buttons go through `nativeNotifAction` — the same entry point the shade's actions,
/// a headset, a watch, and Core-Telecom's own answer callback use. Rust decides what an
/// answer means here (unlock gating, the caller's winner acknowledgement); this screen
/// decides nothing (`internal/CALL_PLAN.md` §7.3: one answer path).
class CallActivity : Activity() {
  companion object {
    const val EXTRA_CALL_ID = "sona_call_id"
    const val EXTRA_TITLE = "sona_call_title"
    const val EXTRA_GROUP = "sona_call_group"
    /// `true` ⇒ the **unlock** screen rather than the ring screen (E-4). Same activity
    /// because the only thing that matters here is `showWhenLocked`, and this is the one
    /// component that has it.
    const val EXTRA_UNLOCK = "sona_call_unlock"

    /// The screen currently up, if any, so the ring ending anywhere else takes it down.
    /// A call screen that outlives its ring is an Answer button for a call that is over.
    @Volatile private var live: CallActivity? = null

    /// When the ring screen last took responsibility for the keyguard dismissal itself.
    ///
    /// The answer surfaces are mutually exclusive and this is how they stay that way. When
    /// the user presses Answer on the ring screen, that activity is resumed and visible, so
    /// it can ask for the credential prompt and act on the result. Rust does not know that
    /// and posts its unlock prompt regardless — and because this activity is
    /// `singleInstance`, that prompt's full-screen intent arrives as `onNewIntent` on the
    /// *same* activity, replacing the ring screen mid-dismissal and cancelling the very
    /// request it was waiting on. That is the flash-then-lock-screen the tester saw.
    @Volatile private var unlockHandledAt = 0L

    /// Is the ring screen currently driving an unlock of its own? Bounded by the same
    /// window Rust gives the answer (`UNLOCK_TO_ANSWER_SECS`, plus slack), so a stale flag
    /// can never suppress a later prompt that really is needed.
    @JvmStatic
    fun isHandlingUnlock(): Boolean =
      unlockHandledAt != 0L &&
        android.os.SystemClock.elapsedRealtime() - unlockHandledAt < 50_000L

    /// The full-screen intent's target, and the same intent the notification's tap uses.
    /// `SINGLE_TOP`, not a new task each time: a re-post of the same ring must reuse the
    /// screen that is already up (`onNewIntent`) rather than stack a second one.
    @JvmStatic
    fun intent(ctx: Context, callId: String, title: String, isGroup: Boolean): Intent =
      Intent(ctx, CallActivity::class.java).apply {
        addFlags(
          Intent.FLAG_ACTIVITY_NEW_TASK or
            Intent.FLAG_ACTIVITY_SINGLE_TOP or
            Intent.FLAG_ACTIVITY_NO_USER_ACTION
        )
        putExtra(EXTRA_CALL_ID, callId)
        putExtra(EXTRA_TITLE, title)
        putExtra(EXTRA_GROUP, isGroup)
      }

    /// The **unlock** surface for an answer already taken (E-4, `internal/CALL_PLAN.md` §8).
    ///
    /// `NotificationBridge.openAppForUnlock` used to aim both its direct `startActivity`
    /// and its full-screen intent at `MainActivity`. That activity has no `showWhenLocked`
    /// — which is the whole reason D-2 had to build this one — so over a keyguard the
    /// launch landed *behind* it and the user was left on the home screen with the call
    /// still ringing somewhere they could not see.
    ///
    /// Aiming the full-screen intent here instead is the sanctioned way to put a call
    /// surface over the keyguard, and this activity already has every attribute for it.
    /// From here `MainActivity` is launched by a **foreground activity** — which carries a
    /// background-activity-start grant — rather than by Rust's runtime thread, which does
    /// not.
    @JvmStatic
    fun unlockIntent(ctx: Context): Intent =
      Intent(ctx, CallActivity::class.java).apply {
        addFlags(
          Intent.FLAG_ACTIVITY_NEW_TASK or
            Intent.FLAG_ACTIVITY_SINGLE_TOP or
            Intent.FLAG_ACTIVITY_NO_USER_ACTION
        )
        putExtra(EXTRA_UNLOCK, true)
      }

    /// The ring for `callId` is over (answered here or elsewhere, declined, cancelled by
    /// the caller, timed out). Empty `callId` closes whatever is up.
    ///
    /// Called from `NotificationBridge.cancelCall`, so every path that takes the
    /// notification down takes this with it and there is no second lifetime to get wrong.
    @JvmStatic
    fun dismiss(callId: String) {
      val a = live ?: return
      if (callId.isNotEmpty() && a.callId != callId) return
      // Only a screen still waiting for a decision. A screen whose button was already
      // pressed finishes on its own terms — and it reaches here re-entrantly, because
      // pressing a button cancels the ring notification, which is what calls this. Closing
      // it from underneath would kill the keyguard-dismissal request Answer is mid-way
      // through making.
      if (!a.ringing) return
      a.runOnUiThread {
        a.ringing = false
        a.finishAndRemoveTask()
      }
    }

    /// The unlock attempt resolved somewhere else — the vault opened, the deadline expired,
    /// or the call ended. Paired with `NotificationBridge.clearUnlockPrompt` for the same
    /// reason [dismiss] is paired with `cancelCall`: one thing goes up, one thing comes
    /// down, and there is no second lifetime to get wrong.
    @JvmStatic
    fun dismissUnlock() {
      val a = live ?: return
      if (!a.unlockMode || a.unlockResolved) return
      a.runOnUiThread { a.finishUnlock(open = false) }
    }
  }

  private var callId: String = ""
  /// Still an unresolved ring? Cleared by both buttons and by [dismiss], and read by
  /// `onStop`: a screen the user swiped away without choosing is a ring they walked away
  /// from, and it must not stay parked in front of the keyguard forever.
  private var ringing = true
  /// This instance is the **unlock** surface (E-4), not the ring screen.
  private var unlockMode = false
  /// The dismissal has been asked for once; `onResume` can fire again (the bouncer covering
  /// and uncovering this window) and must not stack a second request.
  private var unlockRequested = false
  /// The unlock attempt has been decided (dismissed, cancelled, or refused), so the
  /// teardown has already run and must not run twice.
  private var unlockResolved = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Over the keyguard, and wake the screen for it. The manifest attributes cover a cold
    // launch; these cover the case the attributes cannot (a recycled instance), and they
    // are what makes the failure mode loud if the manifest ever regresses.
    if (Build.VERSION.SDK_INT >= 27) {
      setShowWhenLocked(true)
      setTurnScreenOn(true)
    } else {
      @Suppress("DEPRECATION")
      window.addFlags(
        WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
          WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
      )
    }
    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    // Same capture policy as the rest of the app: a caller's name is exactly the kind of
    // thing the screen-capture channel exists to harvest.
    window.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE
    )
    live = this
    bind(intent)
  }

  /// The keyguard dismissal is requested **here**, not in `onCreate`.
  ///
  /// `requestDismissKeyguard` needs a resumed activity. Asked from `onCreate` the platform
  /// cancels it immediately, the callback fires `onDismissCancelled`, this window closes,
  /// and the user is left on the lock screen having to unlock by hand — which is exactly
  /// what the first version of this did.
  override fun onResume() {
    super.onResume()
    if (!unlockMode || unlockResolved || unlockRequested) return
    unlockRequested = true
    requestUnlock()
  }

  /// A re-post of the same ring, or a different call arriving while this one is up.
  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    ringing = true
    bind(intent)
  }

  private fun bind(intent: Intent?) {
    unlockMode = intent?.getBooleanExtra(EXTRA_UNLOCK, false) ?: false
    if (unlockMode) {
      // Not a ring: the user has already pressed Answer and Rust has already stopped the
      // ringtone. `ringing` gates the ring screen's own teardown paths, and none of them
      // apply here.
      ringing = false
      callId = ""
      // **Nothing is drawn.** This exists only to be an activity the platform will accept a
      // keyguard-dismissal request from; the bouncer it raises is the native prompt and the
      // only thing the user should see. It previously drew a dark screen with an "Unlock"
      // button, which flashed up, asked at the wrong moment, was cancelled, and closed —
      // leaving the user to unlock by hand. A surface with nothing on it cannot do that.
      window.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(Color.TRANSPARENT))
      window.setDimAmount(0f)
      // The request itself waits for `onResume` (see below).
      return
    }
    callId = intent?.getStringExtra(EXTRA_CALL_ID) ?: ""
    val title = intent?.getStringExtra(EXTRA_TITLE)?.takeIf { it.isNotEmpty() } ?: "Sona"
    val isGroup = intent?.getBooleanExtra(EXTRA_GROUP, false) ?: false
    setContentView(view(title, isGroup))
  }

  // ── the screen ──

  private fun dp(v: Int): Int = TypedValue.applyDimension(
    TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics
  ).toInt()

  private fun view(title: String, isGroup: Boolean): View {
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER_HORIZONTAL
      // Fixed dark surface rather than the app theme: this window is drawn over the
      // keyguard, where the app's theme is not necessarily legible, and a call screen that
      // renders as black-on-black is a call the user cannot answer.
      setBackgroundColor(Color.parseColor("#0B0F14"))
      setPadding(dp(28), dp(72), dp(28), dp(56))
    }
    root.addView(
      TextView(this).apply {
        text = "Sona"
        setTextColor(Color.parseColor("#7C8798"))
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        letterSpacing = 0.18f
        gravity = Gravity.CENTER
      }
    )
    root.addView(
      TextView(this).apply {
        // Already privacy-leveled upstream (`ring_title`): "generic" never reaches here as
        // a name. Nothing on this screen may reveal more than the notification would.
        text = title
        setTextColor(Color.WHITE)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 32f)
        gravity = Gravity.CENTER
        setPadding(0, dp(24), 0, dp(8))
      }
    )
    root.addView(
      TextView(this).apply {
        text = if (isGroup) "Incoming group call" else "Incoming call"
        setTextColor(Color.parseColor("#A9B4C4"))
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
        gravity = Gravity.CENTER
      }
    )
    // Spacer: the buttons sit at the bottom, where a phone's call screen puts them and
    // where a thumb reaches them without looking.
    root.addView(
      View(this),
      LinearLayout.LayoutParams(0, 0, 1f)
    )
    val row = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER
    }
    row.addView(button("Decline", "#D2323C") { decline() })
    row.addView(View(this), LinearLayout.LayoutParams(dp(56), dp(1)))
    row.addView(button("Answer", "#1F9D55") { answer() })
    root.addView(row, LinearLayout.LayoutParams(
      LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
    ))
    return root
  }

  /// The unlock surface (E-4). Says only what the unlock notification is allowed to say —
  /// "Sona / Unlock to answer" — because it stands in front of a locked screen and the
  /// caller's name is exactly what `VISIBILITY_PRIVATE` withholds there.
  private fun unlockView(): View {
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER
      setBackgroundColor(Color.parseColor("#0B0F14"))
      setPadding(dp(28), dp(72), dp(28), dp(56))
    }
    root.addView(
      TextView(this).apply {
        text = "Sona"
        setTextColor(Color.parseColor("#7C8798"))
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        letterSpacing = 0.18f
        gravity = Gravity.CENTER
      }
    )
    root.addView(
      TextView(this).apply {
        text = "Unlock to answer"
        setTextColor(Color.WHITE)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 26f)
        gravity = Gravity.CENTER
        setPadding(0, dp(20), 0, dp(28))
      }
    )
    // The dismissal is requested on create; this is the way back if the user dismissed the
    // credential prompt by accident and the window is still up.
    root.addView(button("Unlock", "#1F9D55") { requestUnlock() })
    return root
  }

  /// Ask the platform to take the keyguard down, then bring the app forward **from here**.
  ///
  /// The launch has to originate in a foreground activity. `open_unlock_surface()` runs on
  /// Rust's runtime thread, which on Android 10+ has no background-activity-start grant:
  /// the call is not refused so much as silently ignored, which is exactly how the user
  /// ended up on the home screen with a call ringing out of sight.
  private fun requestUnlock() {
    val kg = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
    if (Build.VERSION.SDK_INT >= 26 && kg?.isKeyguardLocked == true) {
      try {
        kg.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
          override fun onDismissSucceeded() = finishUnlock(open = true)
          // Cancelled or refused: the vault never opens and Rust's own deadline expires on
          // its own terms. Nothing is opened — bringing the app forward against a user who
          // just backed out of the credential prompt would be arguing with them.
          override fun onDismissCancelled() = finishUnlock(open = false)
          override fun onDismissError() = finishUnlock(open = false)
        })
      } catch (_: Throwable) {
        finishUnlock(open = false)
      }
      return
    }
    // No keyguard (or too old to ask): the device is already usable, so the only thing
    // between the user and the call is Sona's own vault screen.
    finishUnlock(open = true)
  }

  private fun finishUnlock(open: Boolean) {
    if (unlockResolved) return
    unlockResolved = true
    if (open) {
      try {
        startActivity(
          Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
          }
        )
      } catch (_: Throwable) {
        // Nothing else to try: the notification's own content intent is still there.
      }
    }
    finishAndRemoveTask()
  }

  private fun button(label: String, color: String, onTap: () -> Unit): View =
    Button(this).apply {
      text = label
      isAllCaps = false
      setTextColor(Color.WHITE)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
      background = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(32).toFloat()
        setColor(Color.parseColor(color))
      }
      minimumWidth = dp(136)
      setPadding(dp(24), dp(18), dp(24), dp(18))
      setOnClickListener { onTap() }
    }

  // ── the two things it can do ──

  /// Hand the answer to Rust and get out of the way.
  ///
  /// What happens next is not this screen's to decide. On an unlocked device Rust claims
  /// the call and starts media; on a locked one it stops the ring, arms the unlock
  /// deadline, and raises the unlock surface.
  ///
  /// D-2 had this method request the keyguard dismissal itself, so the credential prompt
  /// would be the next thing the user saw. That goal is right and is now met by the unlock
  /// surface, which requests the dismissal on create — and, crucially, knows what to do
  /// *after* it succeeds. Doing it here as well would be two competing dismissal requests
  /// against one `singleInstance` activity, one of them from an instance that is finishing,
  /// and the one that "won" was the one that could only close itself: the user unlocked and
  /// landed on the home screen (E-4).
  private fun answer() {
    if (!ringing) return
    ringing = false
    send("answer_call")
    // Ask for the credential prompt from **here**, and nowhere else.
    //
    // This activity is resumed and visible — the user just tapped a button on it — which is
    // the state `requestDismissKeyguard` requires. Asking from a freshly created activity
    // instead (which is what the unlock-mode full-screen intent did) is too early: the
    // system cancels the request outright, and the surface that asked closes again, leaving
    // the user back on the lock screen having to unlock by hand.
    //
    // There is no Sona UI in this: the bouncer is the platform's own prompt. Nothing of
    // ours is drawn over it, and nothing needs to be.
    unlockHandledAt = android.os.SystemClock.elapsedRealtime()
    val kg = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
    if (Build.VERSION.SDK_INT >= 26 && kg?.isKeyguardLocked == true) {
      try {
        kg.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
          // Unlocked. Bring the app forward from this activity, which still has a
          // background-activity-start grant; Rust's runtime thread does not (E-4).
          override fun onDismissSucceeded() = openAppAndFinish()
          // Backed out of: the vault never opens, Rust's own deadline expires on its terms,
          // and this window must not sit in front of the keyguard meanwhile.
          override fun onDismissCancelled() = finishAndRemoveTask()
          override fun onDismissError() = finishAndRemoveTask()
        })
      } catch (_: Throwable) {
        openAppAndFinish()
      }
      return
    }
    // No keyguard: only Sona's own vault screen stands between the user and the call.
    openAppAndFinish()
  }

  private fun openAppAndFinish() {
    try {
      startActivity(
        Intent(this, MainActivity::class.java).apply {
          addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
      )
    } catch (_: Throwable) {
      // The unlock notification's own tap target is still there as the way in.
    }
    finishAndRemoveTask()
  }

  /// Decline needs no unlock, by design: a locked device signs it with the call-control
  /// key alone (`internal/CALL_PLAN.md` §3.4), so the caller learns they were declined instead of
  /// being left to ring out.
  private fun decline() {
    if (!ringing) return
    ringing = false
    send("decline_call")
    finishAndRemoveTask()
  }

  private fun send(action: String) {
    if (callId.isEmpty()) return
    // The ringtone stops now, from this process, for the same reason the shade's own
    // actions stop it here: after a locked wake the notification outlives the process that
    // posted it, and `FLAG_INSISTENT` keeps looping until something takes it down. Rust
    // does it too — both paths are idempotent and unconditional.
    //
    // Answer and Decline part company on what happens to the *process hold*. A decline is
    // the end of the call, so the foreground service goes with it. An answer is the
    // beginning of an unlock wait of up to `UNLOCK_TO_ANSWER_SECS`, during which the locked
    // path has no socket either — so the hold is handed over, not dropped (E-5).
    if (action == "answer_call") {
      NotificationBridge.acceptCall(callId)
    } else {
      NotificationBridge.cancelCall(callId, "")
    }
    try {
      NotificationBridge.nativeNotifAction(
        JSONObject().put("action", action).put("call_id", callId).toString()
      )
    } catch (_: Throwable) {
      // Native library not loaded (the process is going down): the notification is already
      // cancelled, and the caller finds out at their own ring timeout.
    }
  }

  /// Backed out of, or covered by something else, with the ring still unresolved: treat it
  /// as walking away. The ring notification stays up — that is the surface that is allowed
  /// to persist — but this window does not park itself in front of the keyguard.
  ///
  /// The unlock surface is deliberately exempt. It is *expected* to be covered — by the
  /// credential bouncer it just asked for — and tearing itself down there would kill the
  /// keyguard-dismissal request mid-flight, which is the same mistake in a new place.
  /// Its lifetime is owned by the dismissal callback and by [dismissUnlock].
  override fun onStop() {
    super.onStop()
    if (unlockMode) return
    if (ringing && !isChangingConfigurations) finishAndRemoveTask()
  }

  override fun onDestroy() {
    if (live === this) live = null
    super.onDestroy()
  }
}
