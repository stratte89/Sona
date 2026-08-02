package app.sona.messenger

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONArray
import org.json.JSONObject

// SONA-NOTIFY — UnifiedPush wake transport (docs/NOTIFICATIONS.md §6.7), injected by
// scripts/harden-android.sh.
//
// UnifiedPush is the Google-free push path: the user installs a *distributor* app of
// their choice (ntfy, NextPush, Sunup, …) which keeps one battery-cheap connection for
// every app on the phone. Sona asks it for an endpoint URL and registers that URL with
// the relay — whose webhook wake path is already UnifiedPush-shaped (constant body
// "wake"/"wake-call", SSRF-filtered, challenge-signed registration). No server work,
// no Play Services, and the user picks (or self-hosts) the broker.
//
// Implemented against the raw UnifiedPush broadcast spec (v2 extras, v3 bytesMessage
// tolerated) instead of the connector library: it is four broadcasts, and staying
// dependency-free keeps the reproducible build byte-identical without new inputs.
object UnifiedPushMgr {
  private const val ACTION_REGISTER = "org.unifiedpush.android.distributor.REGISTER"
  private const val ACTION_UNREGISTER = "org.unifiedpush.android.distributor.UNREGISTER"
  private const val PREFS = "sona_up"

  private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  /// Installed distributor apps: [{pkg, label}]. Empty array = none installed.
  @JvmStatic
  fun distributorsJson(ctx: Context): String {
    val pm = ctx.packageManager
    val out = JSONArray()
    val seen = HashSet<String>()
    for (ri in pm.queryBroadcastReceivers(Intent(ACTION_REGISTER), 0)) {
      val pkg = ri.activityInfo?.packageName ?: continue
      if (!seen.add(pkg)) continue
      val label = try {
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
      } catch (_: Exception) { pkg }
      out.put(JSONObject().put("pkg", pkg).put("label", label))
    }
    return out.toString()
  }

  /// Ask `distributor` for an endpoint. The reply (NEW_ENDPOINT) lands async in
  /// UnifiedPushReceiver, which hands the URL to Rust for relay registration.
  @JvmStatic
  fun register(ctx: Context, distributor: String) {
    val p = prefs(ctx)
    var token = p.getString("token", null)
    if (token == null || p.getString("distributor", null) != distributor) {
      token = java.util.UUID.randomUUID().toString()
    }
    p.edit().putString("distributor", distributor).putString("token", token).apply()
    ctx.sendBroadcast(
      Intent(ACTION_REGISTER).apply {
        `package` = distributor
        putExtra("token", token)
        putExtra("application", ctx.packageName)
      }
    )
  }

  /// Called at every process start (SonaApp): distributors expect re-registration
  /// after boot/app update, and it is an idempotent upsert on their side.
  ///
  /// **Does nothing until the user has unlocked the device once (E-15).** These
  /// preferences live in credential-encrypted storage, and reading them before the first
  /// unlock does not return a default — it *throws*
  /// `IllegalStateException: SharedPreferences in credential encrypted storage are not
  /// available until after user (id 0) is unlocked`. Thrown out of `Application.onCreate`
  /// that took the whole process down every time anything started Sona after a reboot,
  /// which is a crash loop on the one path where the app most needs to come up quietly.
  ///
  /// Nothing is lost by skipping it: a distributor registration is an idempotent upsert,
  /// and the next process start after the unlock re-runs this.
  @JvmStatic
  fun reRegister(ctx: Context) {
    if (!userUnlocked(ctx)) return
    prefs(ctx).getString("distributor", null)?.let { register(ctx, it) }
  }

  /// Has the user unlocked the device since boot? Credential-encrypted storage — which is
  /// where this object's preferences and the whole Sona data directory live — is simply
  /// not readable before that.
  private fun userUnlocked(ctx: Context): Boolean =
    try {
      val um = ctx.getSystemService(Context.USER_SERVICE) as? android.os.UserManager
      um?.isUserUnlocked ?: false
    } catch (_: Throwable) {
      false // unanswerable ⇒ treat as locked; the cost is one skipped idempotent upsert
    }

  /// Drop the distributor registration and tell Rust the endpoint is gone (Rust then
  /// falls back to the system push token, or unregisters from the relay).
  @JvmStatic
  fun unregister(ctx: Context) {
    val p = prefs(ctx)
    val distributor = p.getString("distributor", null)
    val token = p.getString("token", null)
    if (distributor != null && token != null) {
      ctx.sendBroadcast(
        Intent(ACTION_UNREGISTER).apply {
          `package` = distributor
          putExtra("token", token)
        }
      )
    }
    p.edit().clear().apply()
    try { NotificationBridge.nativeSetUpEndpoint("") } catch (_: Throwable) {}
  }

  /// {"distributor": pkg|"", "endpoint": bool} for the health/settings surfaces.
  @JvmStatic
  fun currentJson(ctx: Context): String {
    val p = prefs(ctx)
    return JSONObject()
      .put("distributor", p.getString("distributor", "") ?: "")
      .put("endpoint", !(p.getString("endpoint", null).isNullOrEmpty()))
      .toString()
  }

  internal fun onNewEndpoint(ctx: Context, token: String?, endpoint: String?) {
    val p = prefs(ctx)
    if (token == null || token != p.getString("token", null)) return // spoofed/stale
    if (endpoint.isNullOrEmpty()) return
    p.edit().putString("endpoint", endpoint).apply()
    try { NotificationBridge.nativeSetUpEndpoint(endpoint) } catch (_: Throwable) {}
  }

  // SP-18: this guard used to fail OPEN on a null token (`token != null && …`), unlike
  // its two siblings. The receiver must be exported — the distributor is a separate app —
  // and carries no permission guard, so ANY app on the device could broadcast
  // UNREGISTERED with no extras, pass the guard, drop the stored endpoint, and unregister
  // push at the relay. The victim then silently stops receiving message and call wakes
  // whenever the socket is down. `tokenMatches` is false for null, which is the correct
  // behaviour here; reuse it so all three paths share one fail-closed rule. A real
  // distributor always includes the token, so this does not break real unregistration.
  internal fun onGone(ctx: Context, token: String?) {
    if (!tokenMatches(ctx, token)) return
    prefs(ctx).edit().remove("endpoint").apply()
    try { NotificationBridge.nativeSetUpEndpoint("") } catch (_: Throwable) {}
  }

  internal fun tokenMatches(ctx: Context, token: String?): Boolean =
    token != null && token == prefs(ctx).getString("token", null)
}

// SONA-NOTIFY — the UnifiedPush receiver: the distributor's mirror image of
// SonaFirebaseService. Exported (the distributor is another app), so every broadcast
// is validated against our stored random token — a spoofed MESSAGE can at worst drain
// an empty mailbox, and even that only with the unguessable token. The payload is the
// relay's constant wake body ("wake"/"wake-call"/"wake-call-control"): content-free,
// display happens locally after the authenticated drain decrypts.
class UnifiedPushReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    val token = intent.getStringExtra("token")
    when (intent.action) {
      "org.unifiedpush.android.connector.MESSAGE" -> {
        if (!UnifiedPushMgr.tokenMatches(context, token)) return
        val body = intent.getStringExtra("message")
          ?: intent.getByteArrayExtra("bytesMessage")?.toString(Charsets.UTF_8)
          ?: ""
        val wakeClass = when (body.trim()) {
          "wake-call" -> 1
          "wake-call-control" -> 2
          else -> 0
        }
        DrainService.start(context.applicationContext, wakeClass)
      }
      "org.unifiedpush.android.connector.NEW_ENDPOINT" ->
        UnifiedPushMgr.onNewEndpoint(context, token, intent.getStringExtra("endpoint"))
      "org.unifiedpush.android.connector.UNREGISTERED",
      "org.unifiedpush.android.connector.REGISTRATION_FAILED" ->
        UnifiedPushMgr.onGone(context, token)
    }
  }
}
