#!/usr/bin/env python3
"""Wire androidx.core:core-telecom (+ the coroutines runtime it needs) into the
generated app/build.gradle.kts (called by harden-android.sh step 16). Idempotent.

The version is pinned exactly, never a dynamic range: a call stack is not something
to let a build resolve differently on two machines, and the pin is re-evaluated by an
explicit dependency commit plus an Android smoke pass (see internal/NOTES.md)."""
import sys

TELECOM = "1.1.0-alpha06"
COROUTINES = "1.8.1"

p = sys.argv[1]
s = open(p).read()

DEP = (
    "dependencies {\n"
    "    // SONA-TELECOM: Core-Telecom owns the call lifecycle and audio route\n"
    "    // (internal/CALL_PLAN.md §7). Pinned exactly -- re-evaluate only with a build + smoke pass.\n"
    f'    implementation("androidx.core:core-telecom:{TELECOM}")\n'
    f'    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:{COROUTINES}")'
)
if "core-telecom" not in s:
    if "dependencies {" not in s:
        sys.exit("patch-gradle-telecom: no dependencies block in " + p)
    s = s.replace("dependencies {", DEP, 1)

open(p, "w").write(s)
print("  gradle Core-Telecom wiring applied")
