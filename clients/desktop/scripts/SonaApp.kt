package app.sona.messenger

import android.app.Application

// SONA-NOTIFY — process-wide bootstrap (docs/NOTIFICATIONS.md §4.3 context split), injected by
// scripts/harden-android.sh and named in the manifest (android:name=".SonaApp").
//
// Application.onCreate runs before ANY component — the activity, the sticky-restarted
// DeliveryService shell, the boot receiver, and the FCM receiver alike — so this is
// the one place that can guarantee the native library is loaded and ndk-context holds
// the APPLICATION context (never the activity) for every headless start. This is what
// turns the RC-1 "Kotlin shell without Rust" restart into a real delivery restart.
class SonaApp : Application() {
  companion object {
    @Volatile lateinit var instance: SonaApp
      private set

    /// Google Play services is installed in THIS profile. On GrapheneOS that means
    /// sandboxed Play was installed here (it is per-profile); everywhere de-Googled it
    /// is false, and no Firebase class is ever loaded.
    @Volatile var playInstalled: Boolean = false
      private set

    /// FirebaseApp.initializeApp succeeded (Play services present + build config).
    /// Gates the push modes in the UI and the auto-resolved delivery default.
    @Volatile var firebaseReady: Boolean = false
      private set
  }

  private external fun nativeInitAppContext(ctx: android.content.Context)

  override fun onCreate() {
    super.onCreate()
    instance = this
    // Tauri's generated code loads this lazily from the activity; a headless start
    // has no activity, so load it here. Idempotent.
    System.loadLibrary("sona_desktop_lib")
    nativeInitAppContext(applicationContext)
    NotificationBridge.createChannels(this)
    NetworkMonitor.register(this)
    // SONA-TELECOM — register with Telecom before any component can ring: a call added
    // by a headless wake must find the app already registered. Idempotent, and a refusal
    // (no telecom service, permission missing) is reported rather than thrown.
    TelecomBridge.register()
    initFirebase()
    // UnifiedPush distributors expect re-registration after boot/app update; it is an
    // idempotent upsert on their side and a no-op when none was ever chosen.
    //
    // Wrapped, and every optional step below should be (E-15). An exception escaping
    // `Application.onCreate` kills the process before a single component runs — no
    // delivery, no ring, no notification — and this one really did: reading these
    // preferences before the first unlock after a reboot throws rather than returning a
    // default, so *anything* that started Sona in that window crash-looped it. A push
    // re-registration is worth exactly nothing compared to the app existing.
    try {
      UnifiedPushMgr.reRegister(this)
    } catch (t: Throwable) {
      android.util.Log.e("SonaApp", "UnifiedPush re-registration skipped", t)
    }
  }

  // Google Play services present in this profile? Package visibility for it is declared
  // in the manifest <queries> (harden-android.sh 15c3) — without that this returns false
  // on Android 11+ even where Play IS installed.
  private fun playServicesInstalled(): Boolean = try {
    packageManager.getPackageInfo("com.google.android.gms", 0)
    true
  } catch (_: Throwable) {
    false
  }

  // Manual Firebase init — no google-services.json, no gradle plugin (reproducible
  // builds stay deterministic; see docs/REPRODUCIBLE_BUILDS.md). Values come from
  // buildConfigFields injected by harden-android.sh; absent values → the push modes are
  // simply unavailable and the settings UI explains why.
  //
  // Gated on Play services actually being installed (internal/CALL_PLAN.md §10.1: no FCM class
  // may be loaded unconditionally when Play is absent). It is not only hygiene —
  // FirebaseApp.initializeApp SUCCEEDS on a de-Googled phone, and only the token fetch
  // later fails, so initializing unconditionally made `firebaseReady` claim a wake
  // transport GrapheneOS does not have. The delivery default is resolved from that flag.
  private fun initFirebase() {
    try {
      playInstalled = playServicesInstalled()
      if (!playInstalled) return
      if (BuildConfig.FCM_PROJECT.isEmpty() || BuildConfig.FCM_APP_ID.isEmpty()) return
      val options = com.google.firebase.FirebaseOptions.Builder()
        .setProjectId(BuildConfig.FCM_PROJECT)
        .setApplicationId(BuildConfig.FCM_APP_ID)
        .setApiKey(BuildConfig.FCM_API_KEY)
        .setGcmSenderId(BuildConfig.FCM_SENDER)
        .build()
      com.google.firebase.FirebaseApp.initializeApp(this, options)
      firebaseReady = true
    } catch (_: Throwable) {
      // Missing Play Services (Graphene etc.) or bad config: the push modes stay gated
      // off and the delivery default resolves to the connection; delivery is unaffected.
      firebaseReady = false
    }
  }
}
