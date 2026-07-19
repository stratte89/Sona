package app.sona.messenger

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

/**
 * In-app update installer. The Rust side (update.rs) downloads the APK and verifies its
 * minisign signature into app cache, then hands the path here. From that point the
 * platform package installer owns the transaction — it enforces same-signer +
 * higher-versionCode before touching the installed app, so app data survives and a
 * foreign APK can't replace us regardless of what was downloaded.
 */
object UpdateBridge {

  /** Android 8+ gates sideload installs behind a per-app "install unknown apps" toggle. */
  @JvmStatic
  fun canRequestInstalls(activity: Activity): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
      activity.packageManager.canRequestPackageInstalls()
    else true

  /** Bounce to the system "install unknown apps" screen for this app. */
  @JvmStatic
  fun openInstallSettings(activity: Activity) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    activity.runOnUiThread {
      try {
        activity.startActivity(
          Intent(
            Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
            Uri.parse("package:" + activity.packageName)
          )
        )
      } catch (e: Exception) {
        android.util.Log.w("SonaUpdate", "install settings: $e")
      }
    }
  }

  /** Hand a verified APK (app-cache path) to the platform installer. */
  @JvmStatic
  fun installApk(activity: Activity, path: String) {
    activity.runOnUiThread {
      try {
        val uri =
          FileProvider.getUriForFile(activity, activity.packageName + ".updates", File(path))
        val i = Intent(Intent.ACTION_VIEW)
          .setDataAndType(uri, "application/vnd.android.package-archive")
          .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        activity.startActivity(i)
      } catch (e: Exception) {
        android.util.Log.w("SonaUpdate", "installApk: $e")
      }
    }
  }
}
