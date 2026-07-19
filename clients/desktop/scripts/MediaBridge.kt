package app.sona.messenger

// SONA-MEDIA — installed by scripts/harden-android.sh; re-run the script after
// regenerating gen/android. The Rust side (src-tauri/src/android_media.rs) drives this
// object over JNI; keep names/signatures in sync.
//
// Camera and screen frames are pushed into Rust (`nativeVideoFrame`) where the
// client-core engine encodes, pads, and end-to-end encrypts them — nothing here
// touches the network. Capture runs only between explicit start/stop calls, which the
// Rust side issues when the user toggles a track.
//
// Screen share uses MediaProjection, which on Android 10+ must run inside a foreground
// service with type `mediaProjection` (declared by harden-android.sh). System-audio
// share uses AudioPlaybackCapture (Android 10+), which rides the same projection.
//
// Note on FLAG_SECURE: Sona's own window carries FLAG_SECURE, so in a shared screen
// the Sona app itself appears black. That is deliberate — screen share can never leak
// your own chats.

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.PixelFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.AudioAttributes
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioPlaybackCaptureConfiguration
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.Image
import android.media.ImageReader
import android.media.MediaRecorder
import android.media.Ringtone
import android.media.RingtoneManager
import android.media.ToneGenerator
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.util.DisplayMetrics

object MediaBridge {
  private const val REQ_SCREEN = 44071
  private const val REQ_CAMERA_PERM = 44072
  private const val REQ_MIC_PERM = 44073
  /// Track ids — must match client-core's `media::Track`.
  private const val TRACK_CAMERA = 1
  private const val TRACK_SCREEN = 2

  // Frames/PCM into Rust. `rgba=true` → packed RGBA (Rust converts + decimates);
  // `rgba=false` → already-packed planar I420. `rot` = degrees CLOCKWISE Rust must
  // rotate the frame so it displays upright (camera sensors are landscape-mounted;
  // screen frames pass 0).
  @JvmStatic external fun nativeVideoFrame(track: Int, width: Int, height: Int, rgba: Boolean, rot: Int, data: ByteArray)
  // 48 kHz stereo interleaved PCM16, little-endian bytes, any length.
  @JvmStatic external fun nativeSystemAudio(pcm: ByteArray)
  // 48 kHz MONO PCM16 little-endian from the voice-call mic (VOICE_COMMUNICATION
  // source, hardware AEC/NS/AGC attached) — exact 20 ms frames (1920 bytes).
  @JvmStatic external fun nativeVoiceAudio(pcm: ByteArray)
  // Pulls one 20 ms playout frame (1920 bytes, mono PCM16 LE) from Rust into `out`;
  // returns the bytes written, or 0 when nothing is buffered (write silence instead).
  @JvmStatic external fun nativeVoicePlayoutFrame(out: ByteArray): Int

  /** Call-audio route changed (device plugged/unplugged, auto-switch): JSON of
   *  audioRoutesJson, pushed so the in-call UI adapts live. */
  @JvmStatic external fun nativeAudioRoute(json: String)
  // Hands the JavaVM + activity to Rust's ndk-context (tao/wry no longer do this;
  // the Keystore device-key binding and the biometric gate depend on it). Called
  // from MainActivity.onCreate right after the native library is loaded.
  @JvmStatic external fun nativeInitAndroidContext(activity: Activity)

  // SONA-CONTEXT-SPLIT — the live-activity slot (docs/NOTIFICATIONS.md §4.3): onCreate/onResume pass
  // the activity, onDestroy passes null. ndk-context itself holds the APPLICATION
  // context (installed by SonaApp) so headless flows keep working.
  @JvmStatic external fun nativeSetActivity(activity: Activity?)

  private fun ui(f: () -> Unit) = Handler(Looper.getMainLooper()).post { f() }

  /**
   * Native (cpal) mic capture for calls bypasses the WebView, so nothing ever raises the
   * RECORD_AUDIO runtime prompt for it. Rust calls this before opening the mic: no-op
   * when already granted, otherwise the system dialog appears and the user retries.
   */
  @JvmStatic
  fun ensureMic(activity: Activity) {
    ui {
      if (activity.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
        != PackageManager.PERMISSION_GRANTED
      ) {
        activity.requestPermissions(
          arrayOf(android.Manifest.permission.RECORD_AUDIO), REQ_MIC_PERM
        )
      }
    }
  }

  // ── Camera (Camera2, front lens, ~VGA YUV) ────────────────────────────────────

  private var camDevice: CameraDevice? = null
  private var camSession: CameraCaptureSession? = null
  private var camReader: ImageReader? = null
  private var camThread: HandlerThread? = null
  @Volatile private var camWanted = false
  private var camRetries = 0
  private const val CAM_RETRIES = 8
  private const val CAM_RETRY_MS = 500L

  @JvmStatic
  fun startCamera(activity: Activity) {
    camWanted = true
    camRetries = 0
    ui {
      if (activity.checkSelfPermission(android.Manifest.permission.CAMERA)
        != PackageManager.PERMISSION_GRANTED
      ) {
        // First use: ask. The user re-taps the camera button after granting (the
        // Rust side keeps the toggle state; frames simply start flowing then).
        activity.requestPermissions(arrayOf(android.Manifest.permission.CAMERA), REQ_CAMERA_PERM)
        return@ui
      }
      if (camDevice != null || !camWanted) return@ui
      try {
        openCamera(activity)
      } catch (e: Exception) {
        android.util.Log.w("SonaMedia", "camera start failed: $e")
        retryCamera(activity)
      }
    }
  }

  /**
   * The camera HAL refuses transiently (another app releasing it, thermal, coming back
   * from background mid-call) — without a retry the toggle silently never starts and
   * the user waits forever. Bounded ladder; success resets it.
   */
  private fun retryCamera(activity: Activity) {
    if (!camWanted || camRetries >= CAM_RETRIES) return
    camRetries++
    Handler(Looper.getMainLooper()).postDelayed({
      if (camWanted && camDevice == null) {
        try {
          openCamera(activity)
        } catch (e: Exception) {
          android.util.Log.w("SonaMedia", "camera retry $camRetries failed: $e")
          retryCamera(activity)
        }
      }
    }, CAM_RETRY_MS)
  }

  @JvmStatic
  fun stopCamera() {
    camWanted = false
    ui {
      camSession?.close(); camSession = null
      camDevice?.close(); camDevice = null
      camReader?.close(); camReader = null
      camThread?.quitSafely(); camThread = null
    }
  }

  private fun openCamera(activity: Activity) {
    val mgr = activity.getSystemService(CameraManager::class.java) ?: return
    val id = mgr.cameraIdList.firstOrNull { cid ->
      mgr.getCameraCharacteristics(cid)
        .get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT
    } ?: mgr.cameraIdList.firstOrNull() ?: return

    // Camera sensors are landscape-mounted: compute the clockwise rotation that makes
    // the frame upright for the current display orientation (Camera2's JPEG-orientation
    // formula, which applies to the raw buffer). Do NOT use the preview-transform
    // variant that inverts for front lenses — that compensates for a mirroring the
    // display pipeline adds, which raw frames don't get (found on-device: front camera
    // came out 180° off). Front video stays mirrored, the selfie convention.
    // Rust rotates the I420 planes.
    val chars = mgr.getCameraCharacteristics(id)
    val sensor = chars.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
    val front =
      chars.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_FRONT
    @Suppress("DEPRECATION")
    val dispRot = when (activity.windowManager.defaultDisplay.rotation) {
      android.view.Surface.ROTATION_90 -> 90
      android.view.Surface.ROTATION_180 -> 180
      android.view.Surface.ROTATION_270 -> 270
      else -> 0
    }
    val rot = if (front) (sensor + dispRot) % 360
              else (sensor - dispRot + 360) % 360

    val thread = HandlerThread("sona-camera").apply { start() }
    camThread = thread
    val handler = Handler(thread.looper)
    // 640x480 YUV_420_888 is universally supported; the engine's encoder target.
    val reader = ImageReader.newInstance(640, 480, android.graphics.ImageFormat.YUV_420_888, 3)
    camReader = reader
    reader.setOnImageAvailableListener({ r ->
      val img = r.acquireLatestImage() ?: return@setOnImageAvailableListener
      try {
        if (camWanted) nativeVideoFrame(TRACK_CAMERA, img.width, img.height, false, rot, yuv420ToI420(img))
      } finally {
        img.close()
      }
    }, handler)

    @Suppress("MissingPermission")
    mgr.openCamera(id, object : CameraDevice.StateCallback() {
      override fun onOpened(device: CameraDevice) {
        if (!camWanted) { device.close(); return }
        camRetries = 0
        camDevice = device
        val req = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
        req.addTarget(reader.surface)
        @Suppress("DEPRECATION")
        device.createCaptureSession(listOf(reader.surface),
          object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(session: CameraCaptureSession) {
              if (!camWanted) { session.close(); return }
              camSession = session
              session.setRepeatingRequest(req.build(), null, handler)
            }
            override fun onConfigureFailed(session: CameraCaptureSession) {
              ui { retryCamera(activity) }
            }
          }, handler)
      }
      override fun onDisconnected(device: CameraDevice) {
        device.close()
        ui { if (camDevice === device) camDevice = null; retryCamera(activity) }
      }
      override fun onError(device: CameraDevice, error: Int) {
        device.close()
        ui { if (camDevice === device) camDevice = null; retryCamera(activity) }
      }
    }, handler)
  }

  /** Repack YUV_420_888 (any row/pixel stride, planar or semi-planar) to tight I420. */
  private fun yuv420ToI420(img: Image): ByteArray {
    val w = img.width; val h = img.height
    val out = ByteArray(w * h * 3 / 2)
    var o = 0
    val y = img.planes[0]
    for (row in 0 until h) {
      y.buffer.position(row * y.rowStride)
      y.buffer.get(out, o, w); o += w
    }
    for (p in intArrayOf(1, 2)) {
      val pl = img.planes[p]
      val cw = w / 2; val ch = h / 2
      val rowBuf = ByteArray(pl.rowStride)
      for (row in 0 until ch) {
        pl.buffer.position(row * pl.rowStride)
        val len = minOf(pl.rowStride, pl.buffer.remaining())
        pl.buffer.get(rowBuf, 0, len)
        for (col in 0 until cw) out[o++] = rowBuf[col * pl.pixelStride]
      }
    }
    return out
  }

  // ── Screen share (MediaProjection + VirtualDisplay) ───────────────────────────

  @Volatile private var projection: MediaProjection? = null
  private var vDisplay: VirtualDisplay? = null
  private var screenReader: ImageReader? = null
  private var screenThread: HandlerThread? = null
  @Volatile private var screenWanted = false
  @Volatile private var audioWanted = false
  private var audioRecord: AudioRecord? = null
  private var audioThread: Thread? = null

  /** User toggled screen share on: ask the OS for consent (system dialog). */
  @JvmStatic
  fun startScreen(activity: Activity) {
    screenWanted = true
    ui {
      if (projection != null) return@ui
      val mpm = activity.getSystemService(MediaProjectionManager::class.java) ?: return@ui
      @Suppress("DEPRECATION")
      activity.startActivityForResult(mpm.createScreenCaptureIntent(), REQ_SCREEN)
    }
  }

  @JvmStatic
  fun stopScreen(activity: Activity) {
    screenWanted = false
    audioWanted = false
    ui {
      stopAudioCapture()
      vDisplay?.release(); vDisplay = null
      screenReader?.close(); screenReader = null
      projection?.stop(); projection = null
      screenThread?.quitSafely(); screenThread = null
      activity.stopService(Intent(activity, MediaProjectionService::class.java))
    }
  }

  /** MainActivity forwards its onActivityResult here (injected by harden-android.sh). */
  @JvmStatic
  fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode != REQ_SCREEN) return
    if (resultCode != Activity.RESULT_OK || data == null || !screenWanted) return
    // Android 10+: the projection may only be created from a foreground service of
    // type mediaProjection — start it and continue there.
    MediaProjectionService.consent = Pair(resultCode, data)
    val svc = Intent(activity, MediaProjectionService::class.java)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) activity.startForegroundService(svc)
    else activity.startService(svc)
  }

  /** Called by the service once it is in the foreground. */
  internal fun beginProjection(service: Service, resultCode: Int, data: Intent) {
    if (!screenWanted) return
    val mpm = service.getSystemService(MediaProjectionManager::class.java) ?: return
    val mp = mpm.getMediaProjection(resultCode, data) ?: return
    projection = mp
    mp.registerCallback(object : MediaProjection.Callback() {
      override fun onStop() { screenWanted = false; audioWanted = false }
    }, null)

    val dm: DisplayMetrics = service.resources.displayMetrics
    // Cap the virtual display at 1280 wide: keeps RGBA copies + encode tractable on
    // phones (the desktop peer sees a crisp-enough 720p-class share).
    var w = dm.widthPixels; var h = dm.heightPixels
    while (w > 1280) { w /= 2; h /= 2 }
    w = w and 1.inv(); h = h and 1.inv()

    val thread = HandlerThread("sona-screen").apply { start() }
    screenThread = thread
    val handler = Handler(thread.looper)
    val reader = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 3)
    screenReader = reader
    var last = 0L
    reader.setOnImageAvailableListener({ r ->
      val img = r.acquireLatestImage() ?: return@setOnImageAvailableListener
      try {
        val now = android.os.SystemClock.uptimeMillis()
        if (screenWanted && now - last >= 90) { // ≈10 fps toward the encoder
          last = now
          val plane = img.planes[0]
          val rowStride = plane.rowStride
          val tight = ByteArray(img.width * img.height * 4)
          if (rowStride == img.width * 4) {
            plane.buffer.get(tight, 0, tight.size.coerceAtMost(plane.buffer.remaining()))
          } else {
            for (row in 0 until img.height) {
              plane.buffer.position(row * rowStride)
              plane.buffer.get(tight, row * img.width * 4, img.width * 4)
            }
          }
          nativeVideoFrame(TRACK_SCREEN, img.width, img.height, true, 0, tight)
        }
      } finally {
        img.close()
      }
    }, handler)
    vDisplay = mp.createVirtualDisplay(
      "sona-share", w, h, dm.densityDpi,
      DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, reader.surface, null, handler
    )
    if (audioWanted) startAudioCapture()
  }

  // ── System audio (AudioPlaybackCapture, rides the projection) ─────────────────

  @JvmStatic
  fun startScreenAudio() {
    audioWanted = true
    ui { if (projection != null) startAudioCapture() }
  }

  @JvmStatic
  fun stopScreenAudio() {
    audioWanted = false
    ui { stopAudioCapture() }
  }

  private fun startAudioCapture() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
    val mp = projection ?: return
    if (audioRecord != null) return
    try {
      val cfg = AudioPlaybackCaptureConfiguration.Builder(mp)
        .addMatchingUsage(AudioAttributes.USAGE_MEDIA)
        .addMatchingUsage(AudioAttributes.USAGE_GAME)
        .addMatchingUsage(AudioAttributes.USAGE_UNKNOWN)
        .build()
      val fmt = AudioFormat.Builder()
        .setSampleRate(48_000)
        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
        .setChannelMask(AudioFormat.CHANNEL_IN_STEREO)
        .build()
      val rec = AudioRecord.Builder()
        .setAudioFormat(fmt)
        .setAudioPlaybackCaptureConfig(cfg)
        .setBufferSizeInBytes(48_000 / 5 * 4) // 200 ms of stereo PCM16
        .build()
      audioRecord = rec
      rec.startRecording()
      audioThread = Thread({
        val buf = ByteArray(1920 * 2) // one 20 ms stereo frame
        while (audioWanted && audioRecord === rec) {
          val n = rec.read(buf, 0, buf.size)
          if (n > 0) nativeSystemAudio(buf.copyOf(n))
        }
      }, "sona-sysaudio").apply { start() }
    } catch (e: Exception) {
      android.util.Log.w("SonaMedia", "playback capture failed: $e")
    }
  }

  private fun stopAudioCapture() {
    val rec = audioRecord ?: return
    audioRecord = null
    try { rec.stop() } catch (_: Exception) {}
    rec.release()
    audioThread = null
  }

  // ── Voice-call microphone (VOICE_COMMUNICATION + hardware AEC/NS/AGC) ──────────
  //
  // cpal's AAudio input opens the mic with the generic preset, which BYPASSES the
  // platform acoustic echo canceller — loudspeaker → mic feedback then builds into
  // static within seconds of a phone↔phone call (found on-device). Capturing with the
  // VOICE_COMMUNICATION source plus the platform audio effects is how every telephony
  // app gets echo-free audio: the AEC is tuned per device by the OEM against its own
  // speaker/mic pair. Frames go to Rust (`nativeVoiceAudio`) and replace the cpal
  // input on Android (audio.rs). MODE_IN_COMMUNICATION additionally switches routing
  // to the earpiece (echo-safe) — the speakerphone toggle below opts back into the
  // loudspeaker, against which the AEC still runs.
  //
  // startVoiceMic / startVoicePlayout are "ensure alive", not plain starts: they are
  // safe (and cheap) to re-issue on a live call. The Rust pump re-kicks them when the
  // mic goes quiet, which recovers every observed one-way-silence mode:
  //  * RECORD_AUDIO granted mid-call → onPermissionResult restarts the mic;
  //  * AudioRecord/AudioTrack killed by a routing change (ERROR_DEAD_OBJECT on some
  //    ROMs when toggling earpiece↔speaker) → detected and rebuilt in place;
  //  * transient HAL refusal right after the MODE_IN_COMMUNICATION switch → bounded
  //    retries with a short backoff.

  private var voiceRecord: AudioRecord? = null
  private var voiceThread: Thread? = null
  @Volatile private var voiceWanted = false
  private var voiceCtx: Context? = null
  /** One permission prompt per call — re-kicks must not spam the dialog. */
  private var micPromptShown = false
  private var voiceAec: AcousticEchoCanceler? = null
  private var voiceNs: NoiseSuppressor? = null
  private var voiceAgc: AutomaticGainControl? = null
  /** Desired platform NoiseSuppressor state (UI toggle; default on). */
  @Volatile private var voiceNsWanted = true
  private const val VOICE_RETRIES = 3
  private const val VOICE_RETRY_MS = 200L

  /** Live + persisted-for-next-call noise-suppression toggle (Rust bridges the UI). */
  @JvmStatic
  fun setVoiceNoiseSuppression(on: Boolean) {
    voiceNsWanted = on
    ui { voiceNs?.enabled = on }
  }

  /** MainActivity forwards onRequestPermissionsResult here (injected by harden-android.sh). */
  @JvmStatic
  fun onPermissionResult(activity: Activity, requestCode: Int) {
    if (requestCode != REQ_MIC_PERM) return
    if (voiceWanted &&
      activity.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
      == PackageManager.PERMISSION_GRANTED
    ) {
      // Granted mid-call: the mic starts now instead of staying dead until re-dial.
      ui { ensureVoiceMic(0) }
    }
  }

  @JvmStatic
  fun startVoiceMic(activity: Activity) {
    voiceWanted = true
    voiceCtx = activity.applicationContext
    ui {
      if (activity.checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
        != PackageManager.PERMISSION_GRANTED
      ) {
        if (!micPromptShown) {
          micPromptShown = true
          activity.requestPermissions(
            arrayOf(android.Manifest.permission.RECORD_AUDIO), REQ_MIC_PERM
          )
        }
        beginRouteSession(activity) // routing matters even before the mic permission
        return@ui // resumed from onPermissionResult if granted
      }
      ensureVoiceMic(0)
      beginRouteSession(activity)
    }
  }

  /** Main thread only. No-op while a record is healthily recording; rebuilds otherwise. */
  private fun ensureVoiceMic(attempt: Int) {
    if (!voiceWanted) return
    val ctx = voiceCtx ?: return
    voiceRecord?.let {
      if (it.recordingState == AudioRecord.RECORDSTATE_RECORDING) return
      releaseVoiceMic() // died (route change / HAL restart) — rebuild below
    }
    val am = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    am.mode = AudioManager.MODE_IN_COMMUNICATION
    try {
      val fmt = AudioFormat.Builder()
        .setSampleRate(48_000)
        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
        .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
        .build()
      val rec = AudioRecord.Builder()
        .setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
        .setAudioFormat(fmt)
        .setBufferSizeInBytes(48_000 / 5 * 2) // 200 ms of mono PCM16
        .build()
      if (rec.state != AudioRecord.STATE_INITIALIZED) {
        rec.release()
        throw IllegalStateException("AudioRecord not initialized")
      }
      // VOICE_COMMUNICATION implies the effects on most devices; attach them
      // explicitly anyway — some OEM builds only enable what is asked for.
      if (AcousticEchoCanceler.isAvailable())
        voiceAec = AcousticEchoCanceler.create(rec.audioSessionId)?.apply { enabled = true }
      if (NoiseSuppressor.isAvailable())
        voiceNs = NoiseSuppressor.create(rec.audioSessionId)?.apply { enabled = voiceNsWanted }
      if (AutomaticGainControl.isAvailable())
        voiceAgc = AutomaticGainControl.create(rec.audioSessionId)?.apply { enabled = true }
      rec.startRecording()
      if (rec.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
        releaseVoiceMicEffects()
        rec.release()
        throw IllegalStateException("startRecording did not stick")
      }
      voiceRecord = rec
      voiceThread = Thread({
        val buf = ByteArray(1920) // one 20 ms mono frame
        var errs = 0
        while (voiceWanted && voiceRecord === rec) {
          // Read a FULL frame per push — keeps the Rust framing trivial.
          var off = 0
          while (off < buf.size) {
            val n = rec.read(buf, off, buf.size - off)
            if (n <= 0) break
            off += n
          }
          if (off == buf.size) {
            errs = 0
            nativeVoiceAudio(buf.copyOf())
          } else {
            // ERROR_DEAD_OBJECT after a route change, or a stalled HAL: back off,
            // and after repeated failures rebuild the record instead of spinning.
            if (++errs >= 5) {
              ui { if (voiceWanted && voiceRecord === rec) { releaseVoiceMic(); ensureVoiceMic(0) } }
              break
            }
            Thread.sleep(20)
          }
        }
      }, "sona-voicemic").apply { start() }
    } catch (e: Exception) {
      android.util.Log.w("SonaMedia", "voice mic start (attempt $attempt): $e")
      // The HAL can refuse briefly right after the mode switch — retry, bounded.
      if (attempt < VOICE_RETRIES)
        Handler(Looper.getMainLooper()).postDelayed({ ensureVoiceMic(attempt + 1) }, VOICE_RETRY_MS)
    }
  }

  private fun releaseVoiceMicEffects() {
    voiceAec?.release(); voiceAec = null
    voiceNs?.release(); voiceNs = null
    voiceAgc?.release(); voiceAgc = null
  }

  /** Main thread only. Releases the record + effects; keeps mode/routing untouched. */
  private fun releaseVoiceMic() {
    val rec = voiceRecord
    voiceRecord = null
    if (rec != null) {
      try { rec.stop() } catch (_: Exception) {}
      rec.release()
    }
    releaseVoiceMicEffects()
    voiceThread = null
  }

  @JvmStatic
  fun stopVoiceMic(activity: Activity) {
    voiceWanted = false
    micPromptShown = false
    voiceCtx = null
    ui {
      val am = activity.getSystemService(Context.AUDIO_SERVICE) as AudioManager
      releaseVoiceMic()
      endRouteSession()
      // Leave in-call routing/mode with the call.
      if (Build.VERSION.SDK_INT >= 31) am.clearCommunicationDevice()
      else @Suppress("DEPRECATION") {
        if (am.isBluetoothScoOn) { am.stopBluetoothSco(); am.isBluetoothScoOn = false }
        am.isSpeakerphoneOn = false
      }
      am.mode = AudioManager.MODE_NORMAL
    }
  }

  // ── Voice-call playout (USAGE_VOICE_COMMUNICATION AudioTrack) ──────────────────
  //
  // The far end must NOT play through a MEDIA-usage stream (cpal/AAudio's default)
  // while the device sits in MODE_IN_COMMUNICATION: many OEM ROMs mute or heavily
  // duck media in call mode (observed as a completely silent call), media ignores
  // the earpiece↔speaker communication routing (so the loudspeaker toggle does
  // nothing), and the platform AEC never sees the far end as its cancellation
  // reference. A VOICE_COMMUNICATION AudioTrack is correct on all three counts.
  // Frames are pulled from Rust; the blocking `write` paces the loop at 20 ms.

  private var voiceTrack: AudioTrack? = null
  private var voicePlayThread: Thread? = null
  @Volatile private var voicePlayWanted = false

  @JvmStatic
  fun startVoicePlayout() {
    voicePlayWanted = true
    ui { ensureVoicePlayout(0) }
  }

  /** Main thread only. No-op while a track is healthily playing; rebuilds otherwise. */
  private fun ensureVoicePlayout(attempt: Int) {
    if (!voicePlayWanted) return
    voiceTrack?.let {
      if (it.playState == AudioTrack.PLAYSTATE_PLAYING) return
      releaseVoicePlayout() // died (route change) — rebuild below
    }
    try {
      val track = AudioTrack.Builder()
        .setAudioAttributes(
          AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
            .build()
        )
        .setAudioFormat(
          AudioFormat.Builder()
            .setSampleRate(48_000)
            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
            .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
            .build()
        )
        .setTransferMode(AudioTrack.MODE_STREAM)
        .setBufferSizeInBytes(48_000 / 5 * 2) // 200 ms of mono PCM16
        .build()
      if (track.state != AudioTrack.STATE_INITIALIZED) {
        track.release()
        throw IllegalStateException("AudioTrack not initialized")
      }
      voiceTrack = track
      track.play()
      voicePlayThread = Thread({
        val buf = ByteArray(1920) // one 20 ms mono frame
        while (voicePlayWanted && voiceTrack === track) {
          if (nativeVoicePlayoutFrame(buf) > 0) {
            // Blocking write paces the loop at 20 ms. A negative result is
            // ERROR_DEAD_OBJECT (route change killed the track on some ROMs) —
            // rebuild in place instead of silently eating every later frame.
            if (track.write(buf, 0, buf.size) < 0) {
              ui { if (voicePlayWanted && voiceTrack === track) { releaseVoicePlayout(); ensureVoicePlayout(0) } }
              break
            }
          } else {
            // Underrun: let the track drain (brief silence) instead of stuffing
            // zero frames — writing silence would keep the 200 ms track buffer
            // permanently full, freezing that much extra latency into the call.
            Thread.sleep(5)
          }
        }
      }, "sona-voiceplay").apply { start() }
    } catch (e: Exception) {
      android.util.Log.w("SonaMedia", "voice playout start (attempt $attempt): $e")
      if (attempt < VOICE_RETRIES)
        Handler(Looper.getMainLooper()).postDelayed({ ensureVoicePlayout(attempt + 1) }, VOICE_RETRY_MS)
    }
  }

  /** Main thread only. */
  private fun releaseVoicePlayout() {
    val track = voiceTrack
    voiceTrack = null
    if (track != null) {
      try { track.pause(); track.flush() } catch (_: Exception) {}
      track.release()
    }
    voicePlayThread = null
  }

  @JvmStatic
  fun stopVoicePlayout() {
    voicePlayWanted = false
    ui {
      releaseVoicePlayout()
      endRouteSession()
    }
  }

  // ── Call-audio routing: earpiece / loudspeaker / Bluetooth headset ─────────────
  //
  // One route model for the whole call. `chosenRoute` is the user's explicit pick
  // for THIS call (null = automatic). Automatic policy: a connected SCO headset wins
  // — someone who answers on their earbuds expects to hear the call there, not on a
  // phone pressed to nothing. An AudioDeviceCallback keeps it live mid-call: headset
  // appears → auto-route to it (unless the user chose otherwise); headset vanishes →
  // fall back to the earpiece and tell the UI. All calls run synchronously on the
  // JNI thread (AudioManager is thread-safe) so read-backs see the new route.

  @Volatile private var chosenRoute: String? = null
  private var routeCb: AudioDeviceCallback? = null
  private var routeCtx: Context? = null

  private fun scoDevice(am: AudioManager): AudioDeviceInfo? =
    am.getDevices(AudioManager.GET_DEVICES_OUTPUTS)
      .firstOrNull { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO }

  private fun currentRoute(am: AudioManager): String {
    if (Build.VERSION.SDK_INT >= 31) {
      return when (am.communicationDevice?.type) {
        AudioDeviceInfo.TYPE_BLUETOOTH_SCO -> "bluetooth"
        AudioDeviceInfo.TYPE_BUILTIN_SPEAKER -> "speaker"
        AudioDeviceInfo.TYPE_WIRED_HEADSET, AudioDeviceInfo.TYPE_WIRED_HEADPHONES,
        AudioDeviceInfo.TYPE_USB_HEADSET -> "wired"
        else -> "earpiece"
      }
    }
    @Suppress("DEPRECATION")
    return when {
      am.isBluetoothScoOn -> "bluetooth"
      am.isSpeakerphoneOn -> "speaker"
      else -> "earpiece"
    }
  }

  /** {"bt": headset present, "bt_name": product name, "route": current} */
  @JvmStatic
  fun audioRoutesJson(ctx: Context): String {
    val am = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    val sco = scoDevice(am)
    return org.json.JSONObject()
      .put("bt", sco != null)
      .put("bt_name", sco?.productName?.toString() ?: "")
      .put("route", currentRoute(am))
      .toString()
  }

  /** Explicit user pick for this call; returns the fresh routes JSON. */
  @JvmStatic
  fun setAudioRoute(ctx: Context, route: String): String {
    val am = ctx.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    chosenRoute = route
    applyRoute(am, route)
    return audioRoutesJson(ctx)
  }

  private fun applyRoute(am: AudioManager, route: String) {
    try {
      if (Build.VERSION.SDK_INT >= 31) {
        when (route) {
          "bluetooth" -> am.availableCommunicationDevices
            .firstOrNull { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO }
            ?.let { am.setCommunicationDevice(it) }
          "speaker" -> am.availableCommunicationDevices
            .firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER }
            ?.let { am.setCommunicationDevice(it) }
          // Earpiece must be an EXPLICIT device pick: clearCommunicationDevice() means
          // "system default", and with a Bluetooth headset connected the default IS the
          // headset — the user's earpiece choice silently did nothing.
          else -> am.availableCommunicationDevices
            .firstOrNull { it.type == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE }
            ?.let { am.setCommunicationDevice(it) }
            ?: am.clearCommunicationDevice()
        }
      } else @Suppress("DEPRECATION") {
        when (route) {
          "bluetooth" -> {
            am.isSpeakerphoneOn = false
            am.startBluetoothSco() // async; SCO comes up moments later
            am.isBluetoothScoOn = true
          }
          "speaker" -> {
            if (am.isBluetoothScoOn) { am.stopBluetoothSco(); am.isBluetoothScoOn = false }
            am.isSpeakerphoneOn = true
          }
          else -> {
            if (am.isBluetoothScoOn) { am.stopBluetoothSco(); am.isBluetoothScoOn = false }
            am.isSpeakerphoneOn = false
          }
        }
      }
    } catch (_: Exception) {
      // A refused route keeps the previous one; the UI re-reads actual state.
    }
  }

  private fun notifyRoute(ctx: Context) {
    try { nativeAudioRoute(audioRoutesJson(ctx)) } catch (_: Throwable) {}
  }

  /** Voice session came up: default to the headset when one is connected (unless the
   *  user already picked a route this call) and start watching for plug/unplug. */
  private fun beginRouteSession(ctx: Context) {
    val app = ctx.applicationContext
    val am = app.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    if (routeCb == null) {
      routeCtx = app
      val cb = object : AudioDeviceCallback() {
        override fun onAudioDevicesAdded(added: Array<out AudioDeviceInfo>) {
          if (added.any { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO } && chosenRoute == null) {
            applyRoute(am, "bluetooth")
          }
          notifyRoute(app)
        }
        override fun onAudioDevicesRemoved(removed: Array<out AudioDeviceInfo>) {
          if (removed.any { it.type == AudioDeviceInfo.TYPE_BLUETOOTH_SCO }) {
            if (chosenRoute == "bluetooth" || currentRoute(am) == "bluetooth") {
              chosenRoute = null // headset gone: automatic again, safe default
              applyRoute(am, "earpiece")
            }
          }
          notifyRoute(app)
        }
      }
      routeCb = cb
      am.registerAudioDeviceCallback(cb, null) // main-looper callbacks
    }
    if (chosenRoute == null && scoDevice(am) != null && currentRoute(am) != "bluetooth") {
      applyRoute(am, "bluetooth")
      notifyRoute(app)
    }
  }

  // ── Call progress tones (JS-driven): outgoing ringback + end-of-call beep. ──────
  // ToneGenerator on STREAM_VOICE_CALL follows the call's audio route (earpiece / BT /
  // speaker) and stays audible in MODE_IN_COMMUNICATION, where MEDIA-stream playout is
  // silenced — the reason the webview can't play these itself on Android.
  private var ringbackGen: ToneGenerator? = null
  private var inAppRing: Ringtone? = null

  @JvmStatic
  fun callTone(ctx: Context, kind: String) {
    try {
      when (kind) {
        "ringback" -> {
          if (ringbackGen == null) {
            val tg = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 70)
            tg.startTone(ToneGenerator.TONE_SUP_RINGTONE) // continuous; repeats until stopped
            ringbackGen = tg
          }
        }
        // Incoming ring while the app is on screen: the native CallStyle notification
        // (and its insistent ringtone) is deliberately skipped when focused, so the
        // in-app overlay plays the user's system ringtone itself. Same stream/usage as
        // the notification ring — silent mode and ring volume behave identically.
        "ring" -> startInAppRing(ctx)
        "end" -> {
          stopInAppRing()
          stopRingback()
          // One-shot: beep, then release once it has played out.
          val tg = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 80)
          tg.startTone(ToneGenerator.TONE_PROP_BEEP2, 400)
          Handler(Looper.getMainLooper()).postDelayed({
            try { tg.release() } catch (_: Exception) {}
          }, 700)
        }
        else -> { stopRingback(); stopInAppRing() } // "stop"
      }
    } catch (_: Exception) {
      // A missing tone must never break the call.
    }
  }

  private fun startInAppRing(ctx: Context) {
    if (inAppRing != null) return
    val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE) ?: return
    val rt = RingtoneManager.getRingtone(ctx, uri) ?: return
    rt.audioAttributes = AudioAttributes.Builder()
      .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
      .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
      .build()
    if (Build.VERSION.SDK_INT >= 28) rt.isLooping = true
    rt.play()
    inAppRing = rt
    if (Build.VERSION.SDK_INT < 28) loopInAppRing(rt) // no isLooping before P: re-play by hand
  }

  private fun loopInAppRing(rt: Ringtone) {
    Handler(Looper.getMainLooper()).postDelayed({
      if (inAppRing === rt) {
        try { if (!rt.isPlaying) rt.play() } catch (_: Exception) {}
        loopInAppRing(rt)
      }
    }, 1000)
  }

  private fun stopInAppRing() {
    inAppRing?.let { try { it.stop() } catch (_: Exception) {} }
    inAppRing = null
  }

  private fun stopRingback() {
    ringbackGen?.let { try { it.stopTone(); it.release() } catch (_: Exception) {} }
    ringbackGen = null
  }

  private fun endRouteSession() {
    if (voiceWanted || voicePlayWanted) return // other half of the call still live
    stopRingback() // audio session is over; stray tones must not outlive it
    stopInAppRing()
    routeCtx?.let { c ->
      routeCb?.let {
        try {
          (c.getSystemService(Context.AUDIO_SERVICE) as AudioManager)
            .unregisterAudioDeviceCallback(it)
        } catch (_: Exception) {}
      }
    }
    routeCb = null
    routeCtx = null
    chosenRoute = null
  }

  /**
   * Loudspeaker toggle for calls (mobile UI, no-headset path); the platform AEC keeps
   * running. Synchronous on the JNI thread so the read that follows sees the new
   * route immediately.
   */
  @JvmStatic
  fun setSpeakerphone(activity: Activity, on: Boolean) {
    val am = activity.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    chosenRoute = if (on) "speaker" else "earpiece"
    applyRoute(am, chosenRoute!!)
  }

  @JvmStatic
  fun isSpeakerphoneOn(activity: Activity): Boolean {
    val am = activity.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    return currentRoute(am) == "speaker"
  }
}

/**
 * Foreground service that hosts the MediaProjection (mandatory on Android 10+). Shows
 * a persistent "sharing your screen" notification — which is exactly the user-facing
 * signal we want anyway.
 */
class MediaProjectionService : Service() {
  companion object {
    /** Consent handed over from onActivityResult; consumed once. */
    @Volatile var consent: Pair<Int, Intent>? = null
    private const val CHANNEL = "sona-screenshare"
    private const val NOTE_ID = 4407
  }

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val nm = getSystemService(NotificationManager::class.java)
      nm?.createNotificationChannel(
        NotificationChannel(CHANNEL, "Screen sharing", NotificationManager.IMPORTANCE_LOW)
      )
    }
    val note: Notification =
      (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
        Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this))
        .setContentTitle("Sona is sharing your screen")
        .setSmallIcon(android.R.drawable.ic_menu_share)
        .setOngoing(true)
        .build()
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      startForeground(NOTE_ID, note,
        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
    } else {
      startForeground(NOTE_ID, note)
    }
    consent?.let { (code, data) ->
      consent = null
      MediaBridge.beginProjection(this, code, data)
    }
    return START_NOT_STICKY
  }

  override fun onDestroy() {
    stopForeground(STOP_FOREGROUND_REMOVE)
    super.onDestroy()
  }
}
