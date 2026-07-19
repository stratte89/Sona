#!/usr/bin/env bash
# harden-android.sh — apply Sona's Android hardening to the Tauri-generated project.
#
# Tauri 2 generates the Android project (`src-tauri/gen/android`) on a machine with the
# Android toolchain (`cargo tauri android init`), and that directory is gitignored. This
# script patches the generated project and is safe to re-run (idempotent). Run it after
# `android init` and after any re-generation:
#
#     cargo tauri android init
#     ./scripts/harden-android.sh
#
# What it applies (see ../../docs/ANDROID_HARDENING.md for the full rationale):
#
#   1. FLAG_SECURE on the activity window — blocks screenshots, screen recording, and
#      screen-sharing capture of the app, and blanks the preview in the recents switcher.
#      This defeats the screen-capture channel used by most non-root spyware.
#   2. An accessibility-service warning — on resume, if any accessibility service is
#      enabled, the user is warned that it may be able to read the screen. (Warning only:
#      legitimate users of screen readers can ignore it.)
#   3. allowBackup="false" + fullBackupContent="false" + dataExtractionRules — the vault
#      and local state never leave the device via ADB backup, cloud backup, or
#      device-to-device transfer.
#   4. BiometricGate.kt — the Keystore/BiometricPrompt helper behind fingerprint unlock
#      and the change-ceremony presence check (driven from Rust over JNI), plus the
#      USE_BIOMETRIC permission it needs.
#   5. MediaBridge.kt — camera (Camera2) and screen-share (MediaProjection + foreground
#      service + AudioPlaybackCapture) capture for video calls, driven from Rust over
#      JNI, plus the CAMERA / FOREGROUND_SERVICE permissions, the mediaProjection
#      service declaration, and the MainActivity onActivityResult forwarder the
#      consent dialog needs. The CAMERA permission also backs the in-webview QR
#      link-code scanner: wry's generated RustWebChromeClient answers the webview's
#      VIDEO_CAPTURE request by runtime-requesting CAMERA, which (like the mic, #6)
#      is auto-denied with no dialog unless declared in the manifest.
#   6. Microphone permissions (RECORD_AUDIO + MODIFY_AUDIO_SETTINGS) — wry's webview
#      permission handler requests both; either missing from the manifest silently
#      denies getUserMedia (voice messages).
#   7. proguard-sona.pro — keep rules so R8 doesn't strip the JNI-reflection-only
#      bridge classes (MediaBridge controls, BiometricGate) from release builds.
#
# Modes:
#   ./harden-android.sh          apply (default)
#   ./harden-android.sh --check  report status, exit 0 if hardened, 1 if not
#
# The generated-project path can be overridden as the last argument.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="apply"
GEN_DIR="$SCRIPT_DIR/../src-tauri/gen/android"

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --help|-h)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) GEN_DIR="$arg" ;;
  esac
done

MARKER="SONA-HARDENED"
fail() { echo "error: $*" >&2; exit 1; }
note() { echo "  $*"; }

[ -d "$GEN_DIR" ] || fail "generated Android project not found at $GEN_DIR
run 'cargo tauri android init' first (needs the Android toolchain), or pass the path explicitly."

MAIN_DIR="$GEN_DIR/app/src/main"
MANIFEST="$MAIN_DIR/AndroidManifest.xml"
[ -f "$MANIFEST" ] || fail "AndroidManifest.xml not found at $MANIFEST — is this a Tauri gen/android directory?"

# The template puts MainActivity.kt under java/<reverse.domain.path>/MainActivity.kt.
ACTIVITY="$(find "$MAIN_DIR/java" -name MainActivity.kt 2>/dev/null | head -n1 || true)"
[ -n "$ACTIVITY" ] || fail "MainActivity.kt not found under $MAIN_DIR/java"

XML_RULES="$MAIN_DIR/res/xml/data_extraction_rules.xml"

GATE_SRC="$SCRIPT_DIR/BiometricGate.kt"
GATE_DST="$(dirname "$ACTIVITY")/BiometricGate.kt"

MEDIA_SRC="$SCRIPT_DIR/MediaBridge.kt"
MEDIA_DST="$(dirname "$ACTIVITY")/MediaBridge.kt"
MEDIA_MARKER="SONA-MEDIA"

DELIVERY_SRC="$SCRIPT_DIR/DeliveryService.kt"
DELIVERY_DST="$(dirname "$ACTIVITY")/DeliveryService.kt"

# Notification pipeline + headless delivery (docs/NOTIFICATIONS.md): SonaApp bootstrap, the
# NotificationBridge (channels, MessagingStyle messages, CallStyle ring, drain
# shortService, network monitor), boot receiver, FCM receiver.
NOTIFY_MARKER="SONA-NOTIFY"
SONAAPP_SRC="$SCRIPT_DIR/SonaApp.kt";           SONAAPP_DST="$(dirname "$ACTIVITY")/SonaApp.kt"
BRIDGE_SRC="$SCRIPT_DIR/NotificationBridge.kt"; BRIDGE_DST="$(dirname "$ACTIVITY")/NotificationBridge.kt"
BOOT_SRC="$SCRIPT_DIR/BootReceiver.kt";         BOOT_DST="$(dirname "$ACTIVITY")/BootReceiver.kt"
FCM_SRC="$SCRIPT_DIR/SonaFirebaseService.kt";   FCM_DST="$(dirname "$ACTIVITY")/SonaFirebaseService.kt"
UP_SRC="$SCRIPT_DIR/UnifiedPush.kt";            UP_DST="$(dirname "$ACTIVITY")/UnifiedPush.kt"
HWATTEST_SRC="$SCRIPT_DIR/HwAttest.kt";         HWATTEST_DST="$(dirname "$ACTIVITY")/HwAttest.kt"
UPDATE_SRC="$SCRIPT_DIR/UpdateBridge.kt";       UPDATE_DST="$(dirname "$ACTIVITY")/UpdateBridge.kt"
STAT_ICON="$MAIN_DIR/res/drawable/ic_stat_sona.xml"
UPDATE_PATHS_XML="$MAIN_DIR/res/xml/sona_update_paths.xml"

# ---------------------------------------------------------------- check mode
activity_hardened() { grep -q "$MARKER" "$ACTIVITY"; }
manifest_hardened() {
  grep -q 'android:allowBackup="false"' "$MANIFEST" \
    && grep -q 'android:dataExtractionRules="@xml/data_extraction_rules"' "$MANIFEST"
}
gate_installed() { [ -f "$GATE_DST" ] && cmp -s "$GATE_SRC" "$GATE_DST"; }
biometric_permitted() { grep -q 'android.permission.USE_BIOMETRIC' "$MANIFEST"; }
mic_permitted() {
  grep -q 'android.permission.RECORD_AUDIO' "$MANIFEST" \
    && grep -q 'android.permission.MODIFY_AUDIO_SETTINGS' "$MANIFEST"
}
PRO_FILE="$GEN_DIR/app/proguard-sona.pro"
proguard_kept() { [ -f "$PRO_FILE" ] && grep -q 'MediaBridge' "$PRO_FILE"; }
NETSEC_XML="$MAIN_DIR/res/xml/network_security_config.xml"
netsec_configured() {
  [ -f "$NETSEC_XML" ] \
    && grep -q 'android:networkSecurityConfig="@xml/network_security_config"' "$MANIFEST" \
    && grep -q 'android:usesCleartextTraffic="false"' "$MANIFEST"
}
media_installed() { [ -f "$MEDIA_DST" ] && cmp -s "$MEDIA_SRC" "$MEDIA_DST"; }
delivery_installed() { [ -f "$DELIVERY_DST" ] && cmp -s "$DELIVERY_SRC" "$DELIVERY_DST"; }
delivery_permitted() {
  grep -q 'android.permission.FOREGROUND_SERVICE_SPECIAL_USE' "$MANIFEST" \
    && grep -q 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' "$MANIFEST" \
    && grep -q 'android.permission.POST_NOTIFICATIONS' "$MANIFEST" \
    && grep -q '"\.DeliveryService"' "$MANIFEST"
}
delivery_kept() { [ -f "$PRO_FILE" ] && grep -q 'DeliveryService' "$PRO_FILE"; }
update_installed() { [ -f "$UPDATE_DST" ] && cmp -s "$UPDATE_SRC" "$UPDATE_DST"; }
update_wired() {
  grep -q 'android.permission.REQUEST_INSTALL_PACKAGES' "$MANIFEST" \
    && grep -q '\.updates"' "$MANIFEST" \
    && [ -f "$UPDATE_PATHS_XML" ]
}
update_kept() { [ -f "$PRO_FILE" ] && grep -q 'UpdateBridge' "$PRO_FILE"; }
media_activity_wired() { grep -q "$MEDIA_MARKER" "$ACTIVITY"; }
notify_installed() {
  [ -f "$SONAAPP_DST" ] && cmp -s "$SONAAPP_SRC" "$SONAAPP_DST"     && [ -f "$BRIDGE_DST" ] && cmp -s "$BRIDGE_SRC" "$BRIDGE_DST"     && [ -f "$BOOT_DST" ] && cmp -s "$BOOT_SRC" "$BOOT_DST"     && [ -f "$FCM_DST" ] && cmp -s "$FCM_SRC" "$FCM_DST"     && [ -f "$UP_DST" ] && cmp -s "$UP_SRC" "$UP_DST"
}
notify_manifest_wired() {
  grep -q 'android:name=".SonaApp"' "$MANIFEST"     && grep -q 'android.permission.RECEIVE_BOOT_COMPLETED' "$MANIFEST"     && grep -q 'android.permission.USE_FULL_SCREEN_INTENT' "$MANIFEST"     && grep -q '"\.BootReceiver"' "$MANIFEST"     && grep -q '"\.DrainService"' "$MANIFEST"     && grep -q '"\.SonaFirebaseService"' "$MANIFEST"     && grep -q '"\.NotifActionReceiver"' "$MANIFEST"     && grep -q '"\.UnifiedPushReceiver"' "$MANIFEST"     && grep -q 'android:launchMode="singleTask"' "$MANIFEST"
}
up_queries_wired() { grep -q 'org.unifiedpush.android.distributor.REGISTER' "$MANIFEST"; }
memtag_wired() { grep -q 'android:memtagMode=' "$MANIFEST"; }
attest_installed() { [ -f "$HWATTEST_DST" ] && cmp -s "$HWATTEST_SRC" "$HWATTEST_DST"; }
attest_kept() { [ -f "$PRO_FILE" ] && grep -q 'HwAttest' "$PRO_FILE"; }
lifecycle_wired() { grep -q "SONA-LIFECYCLE" "$ACTIVITY"; }
back_wired() { grep -q "SONA-BACK" "$ACTIVITY"; }
firebase_gradle_wired() { grep -q 'firebase-messaging' "$GRADLE" && grep -q 'FCM_PROJECT' "$GRADLE"; }
stat_icon_present() { [ -f "$STAT_ICON" ]; }
notify_kept() { [ -f "$PRO_FILE" ] && grep -q 'NotificationBridge' "$PRO_FILE" && grep -q 'UnifiedPushReceiver' "$PRO_FILE"; }
perm_forwarder_wired() { grep -q "SONA-PERM" "$ACTIVITY"; }
context_wired() { grep -q "SONA-CONTEXT" "$ACTIVITY"; }
GRADLE="$GEN_DIR/app/build.gradle.kts"
signing_wired() { grep -q 'signingConfigs' "$GRADLE" 2>/dev/null; }
media_permitted() {
  grep -q 'android.permission.CAMERA' "$MANIFEST" \
    && grep -q 'android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION' "$MANIFEST" \
    && grep -q 'MediaProjectionService' "$MANIFEST"
}

if [ "$MODE" = "check" ]; then
  ok=0
  if activity_hardened; then note "MainActivity: hardened (FLAG_SECURE + accessibility warning)"; else note "MainActivity: NOT hardened"; ok=1; fi
  if manifest_hardened; then note "AndroidManifest: hardened (backups disabled)"; else note "AndroidManifest: NOT hardened"; ok=1; fi
  if netsec_configured; then note "network security config: cleartext disabled (except loopback)"; else note "network security config: MISSING (cleartext allowed)"; ok=1; fi
  if [ -f "$XML_RULES" ]; then note "data_extraction_rules.xml: present"; else note "data_extraction_rules.xml: MISSING"; ok=1; fi
  if gate_installed; then note "BiometricGate.kt: installed (current)"; else note "BiometricGate.kt: MISSING or stale"; ok=1; fi
  if biometric_permitted; then note "USE_BIOMETRIC permission: present"; else note "USE_BIOMETRIC permission: MISSING"; ok=1; fi
  if mic_permitted; then note "mic permissions (RECORD_AUDIO + MODIFY_AUDIO_SETTINGS): present"; else note "mic permissions: MISSING or incomplete"; ok=1; fi
  if proguard_kept; then note "proguard keep rules (JNI bridges): present"; else note "proguard keep rules: MISSING (release builds strip the bridges)"; ok=1; fi
  if media_installed; then note "MediaBridge.kt: installed (current)"; else note "MediaBridge.kt: MISSING or stale"; ok=1; fi
  if media_activity_wired; then note "MainActivity: media consent forwarder wired"; else note "MainActivity: media forwarder NOT wired"; ok=1; fi
  if perm_forwarder_wired; then note "MainActivity: permission-result forwarder wired"; else note "MainActivity: permission forwarder NOT wired"; ok=1; fi
  if media_permitted; then note "media permissions + service: present"; else note "media permissions + service: MISSING"; ok=1; fi
  if delivery_installed; then note "DeliveryService.kt: installed (current)"; else note "DeliveryService.kt: MISSING or stale"; ok=1; fi
  if delivery_permitted; then note "delivery permissions + service: present"; else note "delivery permissions + service: MISSING"; ok=1; fi
  if delivery_kept; then note "proguard keep rule (DeliveryService): present"; else note "proguard keep rule (DeliveryService): MISSING"; ok=1; fi
  if context_wired; then note "MainActivity: ndk-context init wired"; else note "MainActivity: ndk-context init NOT wired"; ok=1; fi
  if notify_installed; then note "notification pipeline (SonaApp/NotificationBridge/Boot/FCM): installed"; else note "notification pipeline: MISSING or stale"; ok=1; fi
  if notify_manifest_wired; then note "notification manifest wiring: present"; else note "notification manifest wiring: MISSING"; ok=1; fi
  if up_queries_wired; then note "UnifiedPush distributor <queries>: present"; else note "UnifiedPush distributor <queries>: MISSING (distributor discovery empty on Android 11+)"; ok=1; fi
  if memtag_wired; then note "memtagMode (MTE opt-in): present"; else note "memtagMode (MTE opt-in): MISSING"; ok=1; fi
  if attest_installed; then note "HwAttest.kt: installed (current)"; else note "HwAttest.kt: MISSING or stale"; ok=1; fi
  if attest_kept; then note "proguard keep rule (HwAttest): present"; else note "proguard keep rule (HwAttest): MISSING"; ok=1; fi
  if lifecycle_wired; then note "MainActivity: engine lifecycle forwarders wired"; else note "MainActivity: engine lifecycle NOT wired"; ok=1; fi
  if back_wired; then note "MainActivity: JS-routed back navigation wired"; else note "MainActivity: back navigation NOT wired (WebView-history back races the JS router)"; ok=1; fi
  if firebase_gradle_wired; then note "gradle: firebase-messaging + FCM build fields wired"; else note "gradle: firebase NOT wired"; ok=1; fi
  if stat_icon_present; then note "ic_stat_sona: present"; else note "ic_stat_sona: MISSING"; ok=1; fi
  if notify_kept; then note "proguard keep rules (notification pipeline): present"; else note "proguard keep rules (notification pipeline): MISSING"; ok=1; fi
  if signing_wired; then note "release signing: wired"; else note "release signing: NOT wired"; ok=1; fi
  if update_installed; then note "UpdateBridge.kt: installed (current)"; else note "UpdateBridge.kt: MISSING or stale"; ok=1; fi
  if update_wired; then note "update install wiring (permission + FileProvider): present"; else note "update install wiring: MISSING"; ok=1; fi
  if update_kept; then note "proguard keep rule (UpdateBridge): present"; else note "proguard keep rule (UpdateBridge): MISSING"; ok=1; fi
  exit "$ok"
fi

# ------------------------------------------------------- 1+2. MainActivity.kt
# Tauri's template has shipped in two shapes: a body-less one-liner
# (`class MainActivity : TauriActivity()`) and, newer, a class whose onCreate calls
# enableEdgeToEdge(). Handle both; refuse anything else (then patch by hand).
if activity_hardened; then
  note "MainActivity.kt already hardened — skipping"
else
  if grep -qE '^class MainActivity : TauriActivity\(\)[[:space:]]*$' "$ACTIVITY"; then
    # Old one-liner: give the class a hardened body.
    awk '
      /^class MainActivity : TauriActivity\(\)[[:space:]]*$/ {
        print "class MainActivity : TauriActivity() {"
        print "  override fun onCreate(savedInstanceState: Bundle?) {"
        print "    super.onCreate(savedInstanceState)"
        print "  }"
        print "}"
        next
      }
      { print }
    ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  fi

  grep -qE '^class MainActivity : TauriActivity\(\) \{' "$ACTIVITY" \
    && grep -q 'override fun onCreate(savedInstanceState: Bundle?) {' "$ACTIVITY" \
    || fail "MainActivity.kt does not match any known Tauri template.
Apply the hardening manually (see docs/ANDROID_HARDENING.md) or restore the template first."

  awk -v marker="$MARKER" '
    # Imports (deduped) + marker, right after the package line.
    /^package / {
      print
      print ""
      print "// " marker " — applied by scripts/harden-android.sh; re-run the script after regenerating."
      print "import android.os.Bundle"
      print "import android.provider.Settings"
      print "import android.view.WindowManager"
      print "import android.widget.Toast"
      next
    }
    # FLAG_SECURE as the FIRST statements of onCreate — before super.onCreate and
    # anything else, so no frame is ever capturable.
    /override fun onCreate\(savedInstanceState: Bundle\?\) \{/ {
      print
      print "    // Block screenshots, screen recording, and screen-share capture of this"
      print "    // window, and blank the app preview in the recent-apps switcher. Defeats"
      print "    // the screen-capture channel used by most non-root spyware/stalkerware."
      print "    window.setFlags("
      print "      WindowManager.LayoutParams.FLAG_SECURE,"
      print "      WindowManager.LayoutParams.FLAG_SECURE"
      print "    )"
      next
    }
    { print }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"

  # Drop a duplicate Bundle import if the template already had one (we always add ours).
  awk '/^import android\.os\.Bundle$/ { if (seen++) next } { print }' \
    "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"

  # Append onResume + the accessibility warning before the class-closing brace
  # (last line of the file).
  awk '
    { lines[NR] = $0 }
    END {
      for (i = 1; i < NR; i++) print lines[i]
      print ""
      print "  override fun onResume() {"
      print "    super.onResume()"
      print "    warnIfAccessibilityServicesEnabled()"
      print "  }"
      print ""
      print "  // Non-root spyware commonly reads the screen through the accessibility API"
      print "  // (which FLAG_SECURE does not block). We cannot prevent that without also"
      print "  // breaking screen readers for blind users, so we warn instead: the user"
      print "  // decides whether the enabled service is one they trust."
      print "  private fun warnIfAccessibilityServicesEnabled() {"
      print "    val enabled = Settings.Secure.getString("
      print "      contentResolver,"
      print "      Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES"
      print "    )"
      print "    if (!enabled.isNullOrBlank()) {"
      print "      Toast.makeText("
      print "        this,"
      print "        \"An accessibility service is enabled — it may be able to read this screen.\","
      print "        Toast.LENGTH_LONG"
      print "      ).show()"
      print "    }"
      print "  }"
      print lines[NR]
    }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: FLAG_SECURE + accessibility warning applied"
fi

# ---------------------------------------------------- 3. AndroidManifest.xml
if manifest_hardened; then
  note "AndroidManifest.xml already hardened — skipping"
else
  grep -q '<application' "$MANIFEST" || fail "no <application> element in $MANIFEST"

  # Flip an explicit allowBackup="true" to false; drop stale attributes so the
  # insert below is the single source of truth.
  sed -i \
    -e 's/android:allowBackup="true"/android:allowBackup="false"/' \
    "$MANIFEST"

  # Insert the backup-hardening attributes right after the <application tag opens,
  # skipping any that are already present.
  attrs=""
  grep -q 'android:allowBackup=' "$MANIFEST" \
    || attrs="$attrs        android:allowBackup=\"false\"\n"
  grep -q 'android:fullBackupContent=' "$MANIFEST" \
    || attrs="$attrs        android:fullBackupContent=\"false\"\n"
  grep -q 'android:dataExtractionRules=' "$MANIFEST" \
    || attrs="$attrs        android:dataExtractionRules=\"@xml/data_extraction_rules\"\n"

  if [ -n "$attrs" ]; then
    sed -i "s|<application|<application\n${attrs%\\n}|" "$MANIFEST"
  fi
  note "AndroidManifest.xml: backups + extraction disabled"
fi

# ------------------------------------------- 4. data_extraction_rules.xml
if [ -f "$XML_RULES" ]; then
  note "data_extraction_rules.xml already present — skipping"
else
  mkdir -p "$(dirname "$XML_RULES")"
  cat > "$XML_RULES" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- SONA-HARDENED: belt-and-suspenders for Android 12+. allowBackup="false" already
     disables backups entirely; these rules exclude everything even if that attribute
     is ever lost in a manifest merge. -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="root" path="." />
        <exclude domain="file" path="." />
        <exclude domain="database" path="." />
        <exclude domain="sharedpref" path="." />
        <exclude domain="external" path="." />
    </cloud-backup>
    <device-transfer>
        <exclude domain="root" path="." />
        <exclude domain="file" path="." />
        <exclude domain="database" path="." />
        <exclude domain="sharedpref" path="." />
        <exclude domain="external" path="." />
    </device-transfer>
</data-extraction-rules>
EOF
  note "data_extraction_rules.xml written"
fi

# ------------------------------------------- 4b. network security config (no cleartext)
# With minSdkVersion 26, cleartext (http/ws) is allowed by default, so an accidental
# http:// / ws:// relay URL would connect in the clear — leaking connection metadata (the
# E2E content stays encrypted, but the transport wrapper should be too). Forbid cleartext
# everywhere except local-dev loopback.
if netsec_configured; then
  note "network security config already present — skipping"
else
  if [ ! -f "$NETSEC_XML" ]; then
    mkdir -p "$(dirname "$NETSEC_XML")"
    cat > "$NETSEC_XML" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- SONA-HARDENED: forbid cleartext (http/ws) so an accidental plaintext relay URL cannot
     connect in the clear. Loopback is allowed for local development against a dev relay. -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">10.0.2.2</domain>
    </domain-config>
</network-security-config>
EOF
    note "network_security_config.xml written"
  fi
  attrs=""
  grep -q 'android:usesCleartextTraffic=' "$MANIFEST" \
    || attrs="$attrs        android:usesCleartextTraffic=\"false\"\n"
  grep -q 'android:networkSecurityConfig=' "$MANIFEST" \
    || attrs="$attrs        android:networkSecurityConfig=\"@xml/network_security_config\"\n"
  if [ -n "$attrs" ]; then
    sed -i "s|<application|<application\n${attrs%\\n}|" "$MANIFEST"
  fi
  note "AndroidManifest.xml: cleartext disabled + network security config wired"
fi

# ---------------------------------------------- 4b. Memory Tagging Extension opt-in
# android:memtagMode="sync" (API 31+ attr, ignored where unsupported): on MTE-capable
# hardware (Pixel 8+, hence current GrapheneOS devices) the kernel tags every heap
# allocation and faults precisely on use-after-free / out-of-bounds in native code —
# covering the Rust unsafe/JNI surface and the C deps (opus etc.). "sync" over "async":
# precise faulting addresses, and a messenger's UI load makes the overhead irrelevant.
if memtag_wired; then
  note "memtagMode already present — skipping"
else
  sed -i 's|<application|<application\n        android:memtagMode="sync"|' "$MANIFEST"
  note "AndroidManifest.xml: memtagMode=sync (MTE opt-in)"
fi

# ---------------------------------------------- 5. BiometricGate.kt (fingerprint gate)
if gate_installed; then
  note "BiometricGate.kt already current — skipping"
else
  cp "$GATE_SRC" "$GATE_DST"
  note "BiometricGate.kt installed"
fi

# --------------------------------------------- 6. USE_BIOMETRIC permission
if biometric_permitted; then
  note "USE_BIOMETRIC permission already present — skipping"
else
  # The framework BiometricPrompt requires it; insert before <application>.
  sed -i 's|<application|<uses-permission android:name="android.permission.USE_BIOMETRIC" />\n    <application|' "$MANIFEST"
  note "USE_BIOMETRIC permission added"
fi

# --------------------------------------------- 7. microphone permissions
# Voice messages: wry's WebChromeClient answers the webview's AUDIO_CAPTURE request by
# runtime-requesting BOTH RECORD_AUDIO and MODIFY_AUDIO_SETTINGS. A permission that is
# not declared in the manifest is auto-denied with NO dialog, which fails the whole
# grant — getUserMedia then reports "Permission denied" even when the user granted the
# mic by hand (found on-device). Both must be declared.
if mic_permitted; then
  note "mic permissions already present — skipping"
else
  grep -q 'android.permission.RECORD_AUDIO' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.RECORD_AUDIO" />\n    <application|' "$MANIFEST"
  grep -q 'android.permission.MODIFY_AUDIO_SETTINGS' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />\n    <application|' "$MANIFEST"
  note "mic permissions added (RECORD_AUDIO + MODIFY_AUDIO_SETTINGS)"
fi

# --------------------------------------------- 8. MediaBridge.kt (video calls / share)
if media_installed; then
  note "MediaBridge.kt already current — skipping"
else
  cp "$MEDIA_SRC" "$MEDIA_DST"
  note "MediaBridge.kt installed"
fi

# ------------------------------- 9. MainActivity: forward the projection consent
# MediaProjection's consent dialog answers through onActivityResult; forward it to the
# bridge. Appended before the class-closing brace, like the onResume block above.
if media_activity_wired; then
  note "MainActivity media forwarder already wired — skipping"
else
  # The forwarder needs the Intent import.
  grep -q '^import android.content.Intent$' "$ACTIVITY" || sed -i \
    's|^import android.os.Bundle$|import android.content.Intent\nimport android.os.Bundle|' "$ACTIVITY"
  awk -v marker="$MEDIA_MARKER" '
    { lines[NR] = $0 }
    END {
      for (i = 1; i < NR; i++) print lines[i]
      print ""
      print "  // " marker " — screen-share consent flows back through onActivityResult;"
      print "  // MediaBridge turns it into the projection + foreground service."
      print "  @Suppress(\"DEPRECATION\")"
      print "  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {"
      print "    super.onActivityResult(requestCode, resultCode, data)"
      print "    MediaBridge.onActivityResult(this, requestCode, resultCode, data)"
      print "  }"
      print lines[NR]
    }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: media consent forwarder wired"
fi

# --------------------- 9b. MainActivity: forward runtime-permission results
# A call started before RECORD_AUDIO was granted leaves the mic dead for the whole
# call unless the grant restarts it — MediaBridge.onPermissionResult does exactly that.
if perm_forwarder_wired; then
  note "MainActivity permission forwarder already wired — skipping"
else
  awk '
    { lines[NR] = $0 }
    END {
      for (i = 1; i < NR; i++) print lines[i]
      print ""
      print "  // SONA-PERM — mic permission granted mid-call restarts the voice mic."
      print "  override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {"
      print "    super.onRequestPermissionsResult(requestCode, permissions, grantResults)"
      print "    MediaBridge.onPermissionResult(this, requestCode)"
      print "  }"
      print lines[NR]
    }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: permission-result forwarder wired"
fi

# ---------------------- 10. media permissions + the mediaProjection service
if media_permitted; then
  note "media permissions + service already present — skipping"
else
  grep -q 'android.permission.CAMERA' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.CAMERA" />\n    <application|' "$MANIFEST"
  grep -q '"android.permission.FOREGROUND_SERVICE"' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />\n    <application|' "$MANIFEST"
  grep -q 'android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION" />\n    <application|' "$MANIFEST"
  grep -q 'MediaProjectionService' "$MANIFEST" || sed -i \
    's|</application>|    <service\n        android:name=".MediaProjectionService"\n        android:exported="false"\n        android:foregroundServiceType="mediaProjection" />\n    </application>|' "$MANIFEST"
  note "media permissions + MediaProjectionService declared"
fi

# ---------------------- 11. ndk-context initialization (Rust JNI plumbing)
# tao/wry stopped initializing the ndk-context crate; Rust's Keystore + biometric
# code reads it. Hand over the activity right after super.onCreate (the native
# library is loaded by then).
if context_wired; then
  note "ndk-context init already wired — skipping"
else
  awk '
    /super.onCreate\(savedInstanceState\)/ {
      print
      print "    // SONA-CONTEXT — hand the JavaVM + activity to Rust ndk-context (Keystore/biometrics)."
      print "    MediaBridge.nativeInitAndroidContext(this)"
      next
    }
    { print }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: ndk-context init wired"
fi

# ---------------------- 11b. JS-routed system back navigation
# WryActivity's default back handling asks WebView history (canGoBack()/goBack()).
# That races the JS router's history re-arm: a fast back press can observe a
# transiently drained stack and finish the activity from inside a chat. Route every
# system back press to the JS router instead (window.__sonaBack in 00-core.js); when
# JS is not loaded yet, background the task — the process (and delivery) stays alive.
if back_wired; then
  note "JS-routed back navigation already wired — skipping"
else
  awk '
    /^class MainActivity : TauriActivity\(\) \{/ {
      print
      print "  // SONA-BACK — system back is routed to the app'"'"'s JS back router, never through"
      print "  // WebView history. WryActivity'"'"'s default (canGoBack()/goBack()) races the JS"
      print "  // router'"'"'s history re-arm: a fast back press can observe a transiently drained"
      print "  // stack and finish the activity from inside a chat. JS owns the decision; when"
      print "  // it is not loaded yet, the press backgrounds the task (process stays alive,"
      print "  // delivery keeps running) instead of killing the activity."
      print "  override val handleBackNavigation: Boolean = false"
      print "  private var sonaWebView: android.webkit.WebView? = null"
      print "  override fun onWebViewCreate(webView: android.webkit.WebView) { sonaWebView = webView }"
      print ""
      next
    }
    /super.onCreate\(savedInstanceState\)/ {
      print
      print "    // SONA-BACK — see the class-level note: back presses go straight to JS."
      print "    onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {"
      print "      override fun handleOnBackPressed() {"
      print "        val wv = sonaWebView"
      print "        if (wv == null) { moveTaskToBack(true); return }"
      print "        wv.evaluateJavascript(\"window.__sonaBack ? window.__sonaBack() : '"'"'exit'"'"'\") { result ->"
      print "          if (result != null && result.contains(\"exit\")) moveTaskToBack(true)"
      print "        }"
      print "      }"
      print "    })"
      next
    }
    { print }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: JS-routed back navigation wired"
fi

# ---------------------- 12. release signing (reads keystore.properties)
# The generated project ships without a release signingConfig, producing unsigned
# (uninstallable) APKs. Wire one that reads gen/android/keystore.properties — which
# is NOT committed (it holds the keystore password); create it once per machine:
#
#   keytool -genkey -keystore ~/.sona-keys/sona.keystore -alias sona ...
#   printf 'storeFile=...\nstorePassword=...\nkeyAlias=sona\nkeyPassword=...\n' \
#     > gen/android/keystore.properties
#
# Absent the file, the config resolves empty and gradle falls back to unsigned.
if signing_wired; then
  note "release signing already wired — skipping"
else
  grep -q '^import java.util.Properties' "$GRADLE" || sed -i \
    '1i import java.util.Properties\n' "$GRADLE"
  python3 - "$GRADLE" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('''    buildTypes {''', '''    signingConfigs {
        create("release") {
            val props = Properties()
            val f = rootProject.file("keystore.properties")
            if (f.exists()) {
                f.inputStream().use { props.load(it) }
                storeFile = file(props.getProperty("storeFile"))
                storePassword = props.getProperty("storePassword")
                keyAlias = props.getProperty("keyAlias")
                keyPassword = props.getProperty("keyPassword")
            }
        }
    }
    buildTypes {''', 1)
s = s.replace('''        getByName("release") {
            isMinifyEnabled = true''', '''        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true''', 1)
open(p, 'w').write(s)
PYEOF
  note "release signing wired (create gen/android/keystore.properties per machine)"
fi

# ---------------------- 13. R8/proguard keep rules for the JNI-driven bridges
# Release builds minify (isMinifyEnabled = true in the generated build.gradle.kts).
# MediaBridge's control methods (startCamera/startScreen/…) and the whole BiometricGate
# class are reached ONLY via JNI reflection from Rust — no Kotlin caller — so R8 strips
# them. Found on-device: camera/screen-share buttons dead and the fingerprint-unlock
# option missing, while the JNI-native methods survived (default rules keep `native`
# members, which is why frames/init still worked). The template's proguardFiles picks
# up every *.pro under app/, so dropping this file is enough.
if proguard_kept; then
  note "proguard keep rules already present — skipping"
else
  cat > "$PRO_FILE" <<'EOF'
# SONA-HARDENED — keep the classes Rust drives over JNI reflection; R8 cannot see
# those call sites and would strip or rename them in release builds.
-keep class app.sona.messenger.MediaBridge { *; }
-keep class app.sona.messenger.BiometricGate { *; }
-keep class app.sona.messenger.MediaProjectionService { *; }
-keep class app.sona.messenger.MediaProjectionService$* { *; }
EOF
  note "proguard keep rules written ($PRO_FILE)"
fi

# ---------------------- 14. DeliveryService (background message delivery)
# Foreground service that keeps the process — and the Rust delivery WebSocket — alive
# while the app is backgrounded. Google-free push: no FCM, the socket IS the transport.
# Driven from Rust (delivery_service.rs) on session unlock/lock.
if delivery_installed; then
  note "DeliveryService.kt already current — skipping"
else
  cp "$DELIVERY_SRC" "$DELIVERY_DST"
  note "DeliveryService.kt installed"
fi

if delivery_permitted; then
  note "delivery permissions + service already present — skipping"
else
  # specialUse: the only foreground-service type without a runtime time limit that
  # fits "hold a message-delivery socket without a push service" (targetSdk 34+).
  grep -q 'android.permission.FOREGROUND_SERVICE_SPECIAL_USE' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />\n    <application|' "$MANIFEST"
  # Doze parks the network even under a foreground service; a messenger needs the
  # exemption (the service fires the system consent dialog once).
  grep -q 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />\n    <application|' "$MANIFEST"
  # Android 13+: message notifications (and the service chip) need the runtime grant;
  # the plugin requests it, but the permission must be declared to be grantable.
  grep -q 'android.permission.POST_NOTIFICATIONS' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />\n    <application|' "$MANIFEST"
  grep -q '"\.DeliveryService"' "$MANIFEST" || sed -i \
    's|</application>|    <service\n        android:name=".DeliveryService"\n        android:exported="false"\n        android:foregroundServiceType="specialUse">\n        <property\n            android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"\n            android:value="Keeps the user\x27s end-to-end-encrypted message delivery connection open; no third-party push service is used, for privacy." />\n    </service>\n    </application>|' "$MANIFEST"
  note "delivery permissions + DeliveryService declared"
fi

if delivery_kept; then
  note "proguard keep rule (DeliveryService) already present — skipping"
else
  cat >> "$PRO_FILE" <<'EOF'
# DeliveryService is started over JNI reflection from Rust — keep it too.
-keep class app.sona.messenger.DeliveryService { *; }
-keep class app.sona.messenger.DeliveryService$* { *; }
EOF
  note "proguard keep rule (DeliveryService) appended"
fi

# ---------------------- 15. Notification pipeline + headless delivery (docs/NOTIFICATIONS.md)
# SonaApp (process bootstrap: native lib load, app-context handover, channels,
# network monitor, manual Firebase init), NotificationBridge (MessagingStyle
# messages, CallStyle+FSI ring, drain shortService), BootReceiver, FCM receiver.
if notify_installed; then
  note "notification pipeline already current — skipping"
else
  cp "$SONAAPP_SRC" "$SONAAPP_DST"
  cp "$BRIDGE_SRC" "$BRIDGE_DST"
  cp "$BOOT_SRC" "$BOOT_DST"
  cp "$FCM_SRC" "$FCM_DST"
  cp "$UP_SRC" "$UP_DST"
  note "notification pipeline installed (SonaApp, NotificationBridge, BootReceiver, SonaFirebaseService, UnifiedPush)"
fi

# ---------------------- 15b. MainActivity: engine lifecycle forwarders
# The delivery engine needs the authoritative activity state (focus for
# notification suppression; the activity slot for prompts) and notification-tap
# routing (onNewIntent). tao's window-focus events die with the activity, so the
# lifecycle is forwarded explicitly.
if lifecycle_wired; then
  note "MainActivity lifecycle forwarders already wired — skipping"
else
  # Feed the activity slot + focus into the engine from the existing onResume.
  awk '
    /super.onResume\(\)/ {
      print
      print "    // SONA-LIFECYCLE — authoritative focus + activity slot for the delivery engine."
      print "    MediaBridge.nativeSetActivity(this)"
      print "    NotificationBridge.nativeActivityState(true)"
      next
    }
    { print }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  # Cold-start notification routing: forward launch-intent extras once the webview
  # is up; onNewIntent covers the warm (singleTask) path.
  awk '
    /super.onCreate\(savedInstanceState\)/ {
      print
      print "    // SONA-LIFECYCLE — route a notification-tap launch to the right chat/call."
      print "    forwardIntentExtras(intent)"
      next
    }
    { print }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  # onPause / onDestroy / onNewIntent + the extras forwarder, before the class brace.
  awk '
    { lines[NR] = $0 }
    END {
      for (i = 1; i < NR; i++) print lines[i]
      print ""
      print "  // SONA-LIFECYCLE — engine focus + notification-intent routing."
      print "  override fun onPause() {"
      print "    NotificationBridge.nativeActivityState(false)"
      print "    super.onPause()"
      print "  }"
      print ""
      print "  override fun onDestroy() {"
      print "    MediaBridge.nativeSetActivity(null)"
      print "    NotificationBridge.nativeActivityState(false)"
      print "    super.onDestroy()"
      print "  }"
      print ""
      print "  override fun onNewIntent(intent: Intent) {"
      print "    super.onNewIntent(intent)"
      print "    setIntent(intent)"
      print "    forwardIntentExtras(intent)"
      print "  }"
      print ""
      print "  private fun forwardIntentExtras(intent: Intent?) {"
      print "    intent ?: return"
      print "    val json = org.json.JSONObject()"
      print "    intent.getStringExtra(\"open_chat\")?.let { json.put(\"open_chat\", it) }"
      print "    intent.getStringExtra(\"call\")?.let { json.put(\"call\", it) }"
      print "    intent.getStringExtra(\"call_action\")?.let { json.put(\"call_action\", it) }"
      print "    if (json.length() > 0) {"
      print "      try { NotificationBridge.nativeOpenIntent(json.toString()) } catch (_: Throwable) {}"
      print "    }"
      print "  }"
      print lines[NR]
    }
  ' "$ACTIVITY" > "$ACTIVITY.tmp" && mv "$ACTIVITY.tmp" "$ACTIVITY"
  note "MainActivity.kt: engine lifecycle forwarders wired"
fi

# ---------------------- 15c. Manifest: application/activity attrs, permissions,
#                              receivers + services for the pipeline
if notify_manifest_wired; then
  note "notification manifest wiring already present — skipping"
else
  # Application class (headless bootstrap).
  grep -q 'android:name=".SonaApp"' "$MANIFEST" || sed -i \
    's|<application|<application\n        android:name=".SonaApp"|' "$MANIFEST"
  # Notification taps route through onNewIntent — one live task.
  grep -q 'android:launchMode=' "$MANIFEST" || sed -i \
    's|<activity|<activity\n            android:launchMode="singleTask"|' "$MANIFEST"
  grep -q 'android.permission.RECEIVE_BOOT_COMPLETED' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />\n    <application|' "$MANIFEST"
  grep -q 'android.permission.USE_FULL_SCREEN_INTENT' "$MANIFEST" || sed -i \
    's|<application|<uses-permission android:name="android.permission.USE_FULL_SCREEN_INTENT" />\n    <application|' "$MANIFEST"
  # shortService FGS type needs only the base FOREGROUND_SERVICE permission (present).
  grep -q '"\.DrainService"' "$MANIFEST" || sed -i \
    's|</application>|    <service\n        android:name=".DrainService"\n        android:exported="false"\n        android:foregroundServiceType="shortService" />\n    </application>|' "$MANIFEST"
  grep -q '"\.NotifActionReceiver"' "$MANIFEST" || sed -i \
    's|</application>|    <receiver\n        android:name=".NotifActionReceiver"\n        android:exported="false" />\n    </application>|' "$MANIFEST"
  grep -q '"\.BootReceiver"' "$MANIFEST" || sed -i \
    's|</application>|    <receiver\n        android:name=".BootReceiver"\n        android:exported="true">\n        <intent-filter>\n            <action android:name="android.intent.action.BOOT_COMPLETED" />\n        </intent-filter>\n    </receiver>\n    </application>|' "$MANIFEST"
  grep -q '"\.SonaFirebaseService"' "$MANIFEST" || sed -i \
    's|</application>|    <service\n        android:name=".SonaFirebaseService"\n        android:exported="false">\n        <intent-filter>\n            <action android:name="com.google.firebase.MESSAGING_EVENT" />\n        </intent-filter>\n    </service>\n    </application>|' "$MANIFEST"
  # UnifiedPush receiver MUST be exported: the distributor is a separate app sending
  # explicit broadcasts. Each one is validated inside the receiver against the
  # app-private random registration token (spoof = no-op).
  grep -q '"\.UnifiedPushReceiver"' "$MANIFEST" || sed -i \
    's|</application>|    <receiver\n        android:name=".UnifiedPushReceiver"\n        android:exported="true">\n        <intent-filter>\n            <action android:name="org.unifiedpush.android.connector.MESSAGE" />\n            <action android:name="org.unifiedpush.android.connector.NEW_ENDPOINT" />\n            <action android:name="org.unifiedpush.android.connector.REGISTRATION_FAILED" />\n            <action android:name="org.unifiedpush.android.connector.UNREGISTERED" />\n        </intent-filter>\n    </receiver>\n    </application>|' "$MANIFEST"
  note "notification manifest wiring applied"
fi

# ---------------------- 15c2. Manifest: UnifiedPush distributor package visibility
# Android 11+ package-visibility filtering (targetSdk >= 30) hides other apps'
# receivers from queryBroadcastReceivers unless the querying intent is declared in
# <queries>. Without this, UnifiedPushMgr.distributorsJson() returns [] even with a
# distributor (ntfy, NextPush, …) installed — the settings picker then claims no
# distributor exists. Separate step from 15c: already-wired manifests (which pass
# notify_manifest_wired and skip 15c) still need the element retrofitted.
if up_queries_wired; then
  note "UnifiedPush distributor <queries> already present — skipping"
else
  sed -i 's|<application|<queries>\n        <intent>\n            <action android:name="org.unifiedpush.android.distributor.REGISTER" />\n        </intent>\n    </queries>\n    <application|' "$MANIFEST"
  note "UnifiedPush distributor <queries> declared"
fi

# ---------------------- 15c3. HwAttest.kt (device-link hardware attestation)
# Ephemeral Keystore attestation chain for link requests, driven from Rust over JNI
# reflection (hw_attest.rs) — needs an install + a proguard keep like the other bridges.
if attest_installed; then
  note "HwAttest.kt already current — skipping"
else
  cp "$HWATTEST_SRC" "$HWATTEST_DST"
  note "HwAttest.kt installed"
fi
if attest_kept; then
  note "proguard keep rule (HwAttest) already present — skipping"
else
  cat >> "$PRO_FILE" <<'EOF'
# HwAttest is reached from Rust over JNI reflection only — keep it.
-keep class app.sona.messenger.HwAttest { *; }
EOF
  note "proguard keep rule (HwAttest) appended"
fi

# ---------------------- 15d. Gradle: firebase-messaging + FCM build fields
# No google-services.json, no com.google.gms plugin (reproducible builds stay
# deterministic): the Kotlin dependency alone, plus buildConfigFields SonaApp reads
# for the manual FirebaseOptions init. Values come from env (SONA_FCM_*) or gradle
# -P properties; absent = empty = FCM mode simply unavailable (UI explains).
if firebase_gradle_wired; then
  note "gradle firebase wiring already present — skipping"
else
  python3 "$SCRIPT_DIR/patch-gradle-fcm.py" "$GRADLE"
  note "gradle: firebase-messaging + FCM build fields wired"
fi

# ---------------------- 15e. Monochrome status-bar icon (ic_stat_sona)
# The launcher mipmap renders as a grey blob in the status bar on most ROMs; small
# icons must be monochrome-with-alpha. Simple chat-bubble glyph.
if stat_icon_present; then
  note "ic_stat_sona already present — skipping"
else
  mkdir -p "$(dirname "$STAT_ICON")"
  cat > "$STAT_ICON" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- SONA-NOTIFY: monochrome small icon for all notifications (white + alpha only). -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FFFFFFFF"
        android:pathData="M12,2C6.48,2 2,5.9 2,10.7c0,2.75 1.46,5.2 3.75,6.8L5,22l4.13,-2.48c0.92,0.2 1.88,0.31 2.87,0.31 5.52,0 10,-3.9 10,-8.7C22,5.9 17.52,2 12,2zM7.5,11.9c-0.69,0 -1.25,-0.56 -1.25,-1.25S6.81,9.4 7.5,9.4s1.25,0.56 1.25,1.25S8.19,11.9 7.5,11.9zM12,11.9c-0.69,0 -1.25,-0.56 -1.25,-1.25S11.31,9.4 12,9.4s1.25,0.56 1.25,1.25S12.69,11.9 12,11.9zM16.5,11.9c-0.69,0 -1.25,-0.56 -1.25,-1.25s0.56,-1.25 1.25,-1.25 1.25,0.56 1.25,1.25 -0.56,1.25 -1.25,1.25z"/>
</vector>
EOF
  note "ic_stat_sona written"
fi

# ---------------------- 15f. Proguard keeps for the pipeline classes
# NotificationBridge and DrainService are reached from Rust over JNI reflection;
# SonaApp/BootReceiver/SonaFirebaseService are manifest components (kept by default,
# but keeping them explicit is free insurance against aggressive shrinker configs).
if notify_kept; then
  note "proguard keep rules (notification pipeline) already present — skipping"
else
  cat >> "$PRO_FILE" <<'EOF'
# Notification pipeline: NotificationBridge/DrainService/NetworkMonitor are driven
# over JNI reflection from Rust; the rest are manifest components.
-keep class app.sona.messenger.NotificationBridge { *; }
-keep class app.sona.messenger.DrainService { *; }
-keep class app.sona.messenger.DrainService$* { *; }
-keep class app.sona.messenger.NetworkMonitor { *; }
-keep class app.sona.messenger.NotifActionReceiver { *; }
-keep class app.sona.messenger.SonaApp { *; }
-keep class app.sona.messenger.BootReceiver { *; }
-keep class app.sona.messenger.SonaFirebaseService { *; }
-keep class app.sona.messenger.UnifiedPushReceiver { *; }
-keep class app.sona.messenger.UnifiedPushMgr { *; }
EOF
  note "proguard keep rules (notification pipeline) appended"
fi

# ---------------------- 16. UpdateBridge.kt (in-app APK updates, update.rs)
# Rust downloads + minisign-verifies the APK into app cache; the bridge hands it to the
# platform installer via a FileProvider URI. The OS enforces same-signer + monotonic
# versionCode, so data survives and a foreign APK can never replace the app.
if update_installed; then
  note "UpdateBridge.kt already current — skipping"
else
  cp "$UPDATE_SRC" "$UPDATE_DST"
  note "UpdateBridge.kt installed"
fi
if grep -q 'android.permission.REQUEST_INSTALL_PACKAGES' "$MANIFEST"; then
  note "REQUEST_INSTALL_PACKAGES already present — skipping"
else
  sed -i \
    's|<application|<uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />\n    <application|' "$MANIFEST"
  note "AndroidManifest.xml: REQUEST_INSTALL_PACKAGES added"
fi
if [ -f "$UPDATE_PATHS_XML" ]; then
  note "sona_update_paths.xml already present — skipping"
else
  cat > "$UPDATE_PATHS_XML" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- FileProvider scope for in-app updates: ONLY the cache updates/ dir is exposed,
     read-only, to the platform package installer. Nothing else leaves the sandbox. -->
<paths>
    <cache-path name="updates" path="updates/" />
</paths>
EOF
  note "sona_update_paths.xml written"
fi
if grep -q '\.updates"' "$MANIFEST"; then
  note "update FileProvider already present — skipping"
else
  sed -i \
    's|</application>|    <provider\n        android:name="androidx.core.content.FileProvider"\n        android:authorities="${applicationId}.updates"\n        android:exported="false"\n        android:grantUriPermissions="true">\n        <meta-data\n            android:name="android.support.FILE_PROVIDER_PATHS"\n            android:resource="@xml/sona_update_paths" />\n    </provider>\n    </application>|' "$MANIFEST"
  note "AndroidManifest.xml: update FileProvider added"
fi
if update_kept; then
  note "proguard keep rule (UpdateBridge) already present — skipping"
else
  cat >> "$PRO_FILE" <<'EOF'
# In-app updates: UpdateBridge is driven over JNI reflection from Rust (update.rs).
-keep class app.sona.messenger.UpdateBridge { *; }
EOF
  note "proguard keep rule (UpdateBridge) appended"
fi

echo "done. verify with: $0 --check"
