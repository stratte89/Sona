#!/usr/bin/env python3
"""Wire firebase-messaging + FCM buildConfigFields into the generated
app/build.gradle.kts (called by harden-android.sh step 15d). Idempotent.

Deliberately NO google-services gradle plugin: SonaApp initializes Firebase
manually from these buildConfigFields, keeping the reproducible-build pipeline
free of a Google build-time dependency (docs/REPRODUCIBLE_BUILDS.md)."""
import sys

p = sys.argv[1]
s = open(p).read()

DEP = (
    "dependencies {\n"
    "    // SONA-NOTIFY: FCM data-only wake transport. Deliberately WITHOUT the\n"
    "    // google-services gradle plugin -- SonaApp initializes Firebase manually from\n"
    "    // the buildConfigFields below (docs/REPRODUCIBLE_BUILDS.md constraint).\n"
    "    implementation(\"com.google.firebase:firebase-messaging:24.1.0\")"
)
if "firebase-messaging" not in s:
    s = s.replace("dependencies {", DEP, 1)

VN = 'versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")'
FIELDS = (
    '\n        buildConfigField("String", "FCM_PROJECT", "\\"${System.getenv("SONA_FCM_PROJECT") ?: (project.findProperty("sonaFcmProject") ?: "")}\\"")'
    '\n        buildConfigField("String", "FCM_APP_ID", "\\"${System.getenv("SONA_FCM_APP_ID") ?: (project.findProperty("sonaFcmAppId") ?: "")}\\"")'
    '\n        buildConfigField("String", "FCM_API_KEY", "\\"${System.getenv("SONA_FCM_API_KEY") ?: (project.findProperty("sonaFcmApiKey") ?: "")}\\"")'
    '\n        buildConfigField("String", "FCM_SENDER", "\\"${System.getenv("SONA_FCM_SENDER") ?: (project.findProperty("sonaFcmSender") ?: "")}\\"")'
)
if "FCM_PROJECT" not in s:
    if VN in s:
        s = s.replace(VN, VN + FIELDS, 1)
    else:
        sys.exit("patch-gradle-fcm: versionName anchor not found in " + p)

if "buildConfig = true" not in s:
    if "buildFeatures {" in s:
        s = s.replace("buildFeatures {", "buildFeatures {\n        buildConfig = true", 1)
    else:
        s = s.replace(
            "    buildTypes {",
            "    buildFeatures {\n        buildConfig = true\n    }\n    buildTypes {",
            1,
        )

open(p, "w").write(s)
print("  gradle FCM wiring applied")
