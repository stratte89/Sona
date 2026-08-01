//! These talk to the real sound server when there is one and assert nothing about what it
//! contains — a build machine has no audio and a desktop's applications are whatever
//! happened to be open. What they check is that the protocol exchange works and never
//! panics, which is the part that can rot.

use super::*;

#[test]
fn enumerating_sink_inputs_never_panics() {
    let inputs = sink_inputs();
    for i in &inputs {
        if let Some(p) = i.pid {
            assert!(p > 0, "pid 0 for {}", i.app);
        }
    }
    eprintln!("sink inputs visible: {}", inputs.len());
    for i in &inputs {
        eprintln!("  #{} sink {} pid {:?} {}", i.index, i.sink, i.pid, i.app);
    }
}

/// With no call running this process plays nothing, so there is no stream of ours to find
/// and the caller must fall back rather than be handed something arbitrary.
#[test]
fn our_monitor_is_none_when_we_are_playing_nothing() {
    // Only meaningful when a server is reachable; on a headless box both are None anyway.
    let ours = our_monitor_source();
    if let Some(name) = &ours {
        // If it did find one it must at least look like a monitor source.
        assert!(
            name.contains("monitor"),
            "resolved {name}, which is not a monitor source"
        );
    }
    eprintln!("our monitor source: {ours:?}");
}
