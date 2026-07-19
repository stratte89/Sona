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

    /// FirebaseApp.initializeApp succeeded (build config present + Play Services
    /// answered). Gates the push-only delivery mode in the UI.
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
    initFirebase()
    // UnifiedPush distributors expect re-registration after boot/app update; it is an
    // idempotent upsert on their side and a no-op when none was ever chosen.
    UnifiedPushMgr.reRegister(this)
  }

  // Manual Firebase init — no google-services.json, no gradle plugin (reproducible
  // builds stay deterministic; see docs/REPRODUCIBLE_BUILDS.md). Values come from
  // buildConfigFields injected by harden-android.sh; absent values → mode P (FCM) is
  // simply unavailable and the settings UI explains why.
  private fun initFirebase() {
    try {
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
      // Missing Play Services (Graphene etc.) or bad config: push-only mode stays
      // gated off; connection mode is unaffected.
      firebaseReady = false
    }
  }
}
