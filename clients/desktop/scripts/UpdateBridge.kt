package app.sona.messenger

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import java.io.File

/**
 * In-app update installer. The Rust side (update.rs) downloads the APK and verifies its
 * minisign signature into app cache, then hands the path here. The bytes are STREAMED
 * into a [PackageInstaller] session — not passed as a FileProvider content URI, which
 * several ROMs mangle into "There was a problem while parsing the package". From the
 * session commit on, the platform installer owns the transaction: it enforces
 * same-signer + higher-versionCode before touching the installed app, so app data
 * survives and a foreign APK can't replace us regardless of what was downloaded.
 */
object UpdateBridge {

  const val ACTION_RESULT = "app.sona.messenger.UPDATE_RESULT"

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

  /** Stream a verified APK (app-cache path) into a PackageInstaller session. */
  @JvmStatic
  fun installApk(activity: Activity, path: String) {
    Thread({
      try {
        val file = File(path)
        val pi = activity.packageManager.packageInstaller
        val params =
          PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setSize(file.length())
        val sessionId = pi.createSession(params)
        pi.openSession(sessionId).use { session ->
          file.inputStream().use { input ->
            session.openWrite("sona.apk", 0, file.length()).use { out ->
              input.copyTo(out)
              session.fsync(out)
            }
          }
          val intent = Intent(activity, ResultReceiver::class.java)
            .setAction(ACTION_RESULT)
            .setPackage(activity.packageName)
          val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
          val pending = PendingIntent.getBroadcast(activity, sessionId, intent, flags)
          session.commit(pending.intentSender)
        }
      } catch (e: Exception) {
        android.util.Log.w("SonaUpdate", "installApk: $e")
        activity.runOnUiThread {
          Toast.makeText(activity, "Update failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
      }
    }, "sona-update").start()
  }

  /** Session outcome. PENDING_USER_ACTION carries the system confirm dialog to show;
   *  SUCCESS means the process is about to be replaced; anything else is a failure the
   *  user should actually see (the old flow failed silently into a stuck version). */
  class ResultReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
      when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)) {
        PackageInstaller.STATUS_PENDING_USER_ACTION -> {
          val confirm: Intent? =
            if (Build.VERSION.SDK_INT >= 33)
              intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            else
              @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT)
          try {
            confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (confirm != null) ctx.startActivity(confirm)
          } catch (e: Exception) {
            android.util.Log.w("SonaUpdate", "confirm dialog: $e")
          }
        }
        PackageInstaller.STATUS_SUCCESS -> {
          android.util.Log.i("SonaUpdate", "update installed")
        }
        else -> {
          val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "code $status"
          android.util.Log.w("SonaUpdate", "install failed: $msg")
          Toast.makeText(ctx, "Update failed: $msg", Toast.LENGTH_LONG).show()
        }
      }
    }
  }
}
