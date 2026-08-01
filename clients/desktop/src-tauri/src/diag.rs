//! Diagnostics that survive not having a terminal.
//!
//! Every hard bug in the call stack has been cracked by one printed line — which encoder
//! refused and why, whether the echo canceller found a delay, whether a frame path was
//! keeping up. On Linux that is free: run the binary and read stderr.
//!
//! On Windows it is not. Release builds are `windows_subsystem = "windows"`, so the
//! process has no console, and getting the lines out means asking someone to run a
//! redirect incantation with the exact install path — which failed twice, once because
//! the path in the instructions was wrong and once for reasons nobody could see. Two
//! rounds of testing produced no Windows diagnostics at all while the machine in question
//! was the one crashing.
//!
//! So the app writes its own. [`diag!`] goes to stderr *and* to a file next to the vault,
//! which can be asked for by name and pasted back. It is deliberately dumb: no levels, no
//! filtering, no dependency — the lines that matter already know they matter, and this
//! only has to make them retrievable.
//!
//! **Off unless asked for.** These lines name devices, sinks and call state, and an
//! ordinary user has no reason to generate a file of them on every run. Turn them on with
//! `--debug` on the command line, or `SONA_DEBUG=1` in the environment for a test run or a
//! service where argv is awkward to reach:
//!
//! ```text
//! sona --debug
//! SONA_DEBUG=1 cargo test --release --lib -- --ignored --nocapture echo_loopback
//! ```
//!
//! Read once, lazily, from the real process arguments — so it needs no wiring in `main`,
//! it works in test binaries that never call [`init`], and it cannot drift out of sync
//! with a startup order that changes.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Cap on the log. Diagnostics here are a handful of lines a minute at worst, so this is
/// hours of a call; past it the file restarts rather than growing without bound on a
/// machine nobody is watching.
const MAX_BYTES: u64 = 1 << 20;

static SINK: Mutex<Option<std::fs::File>> = Mutex::new(None);
static PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Are diagnostics turned on for this process? `--debug`, or `SONA_DEBUG=1` — and on
/// Android, the `debug.sona.diag` system property.
///
/// The argv/env pair is computed once and cached: it is consulted on every logged line, and
/// re-walking argv each time would make the "off" case cost more than the "on" one.
///
/// **Android needs a third switch**, because neither of the first two is reachable there.
/// A release APK is launched by the system with no argv of ours and no environment we can
/// set, so on the one platform whose failures need a log most, diagnostics could not be
/// turned on at all. `adb shell setprop debug.sona.diag 1` needs no root and no rebuild.
///
/// It is re-read rather than cached, with a short memo, and that is deliberate: `debug.*`
/// properties do not survive a reboot, so "set it and restart the app" is not a workflow —
/// and a *force-stop* to restart the process would stop FCM waking the app at all, which is
/// the very path being debugged. Re-reading means `setprop` then place a call.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    let fixed = *ON.get_or_init(|| {
        std::env::args().any(|a| a == "--debug")
            || std::env::var("SONA_DEBUG").is_ok_and(|v| v != "0" && !v.is_empty())
    });
    #[cfg(target_os = "android")]
    {
        fixed || android_prop_enabled()
    }
    #[cfg(not(target_os = "android"))]
    {
        fixed
    }
}

/// `debug.sona.diag`, memoized for a second so a hot path cannot turn logging into the
/// bottleneck. `__system_property_get` is a shared-memory read, so the memo is politeness
/// rather than necessity.
#[cfg(target_os = "android")]
fn android_prop_enabled() -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    static VALUE: AtomicBool = AtomicBool::new(false);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let last = LAST_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 1000 && last != 0 {
        return VALUE.load(Ordering::Relaxed);
    }
    unsafe extern "C" {
        fn __system_property_get(name: *const u8, value: *mut u8) -> i32;
    }
    // PROP_VALUE_MAX is 92; the property is written by `adb shell setprop`.
    let mut buf = [0u8; 92];
    let n = unsafe { __system_property_get(c"debug.sona.diag".as_ptr().cast(), buf.as_mut_ptr()) };
    let on = n > 0 && buf[0] != b'0';
    VALUE.store(on, Ordering::Relaxed);
    LAST_MS.store(now_ms, Ordering::Relaxed);
    on
}

/// Point the log at the app's data directory. Called once, as soon as that is known.
///
/// Before this the macro still prints to stderr, so nothing is lost on a platform where
/// stderr is readable — the file is the fallback, not the mechanism. Without `--debug`
/// this does nothing at all: no file is created, so a user who never asked for
/// diagnostics never accumulates any.
pub fn init(data_dir: &std::path::Path) {
    if !enabled() {
        return;
    }
    let path = data_dir.join("sona-diag.log");
    let _ = std::fs::create_dir_all(data_dir);
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_BYTES {
        let _ = std::fs::remove_file(&path);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();
    if let Ok(mut slot) = SINK.lock() {
        *slot = file;
    }
    if let Ok(mut slot) = PATH.lock() {
        *slot = Some(path.clone());
    }
    write(&format!(
        "--- sona {} starting, {} ---",
        env!("CARGO_PKG_VERSION"),
        path.display()
    ));
}

/// One line, to stderr and to the file. Never panics and never blocks on anything but its
/// own mutex — a diagnostic that can take the process down is worse than no diagnostic.
pub fn write(line: &str) {
    if !enabled() {
        return;
    }
    eprintln!("{line}");
    if let Ok(mut slot) = SINK.lock() {
        if let Some(f) = slot.as_mut() {
            let _ = writeln!(f, "[{}] {line}", stamp());
            let _ = f.flush();
        }
    }
}

/// Seconds since the epoch. Not a date: this is for ordering lines and measuring gaps
/// between them, and pulling in a formatting dependency for that would be silly.
fn stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `eprintln!` that also lands in the log file. Same formatting rules.
#[macro_export]
macro_rules! diag {
    ($($arg:tt)*) => {
        $crate::diag::write(&format!($($arg)*))
    };
}
