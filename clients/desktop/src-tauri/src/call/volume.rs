//! Per-listener volume: how loud *this* device plays somebody's voice, and the shared
//! audio that comes with a screen share.
//!
//! All of it is local. Nothing here touches the wire, so the other side cannot tell they
//! have been turned down or muted — which is the point. A person whose microphone is
//! quiet, or whose desktop audio is drowning the conversation, is fixed at the listening
//! end without a negotiation.
//!
//! Two controls with deliberately different lifetimes:
//!
//! * **Voice gain is remembered per contact.** A voice that is too quiet is a property
//!   of someone's microphone and room, not of one call, so it lives in the encrypted
//!   history next to the other local contact preferences ([`ContactPin::voice_gain`])
//!   and applies to every future call with them — group calls included.
//! * **Everything else is per-call.** Mute, and the shared-audio level, reset when the
//!   call ends. A share is a thing that happens *during* a call; a level left over from
//!   the last one would be a surprise the next time somebody shares.
//!
//! Mute is kept separate from the level rather than being "level 0", so that un-muting
//! returns to wherever the slider was rather than to the default.
//!
//! [`ContactPin::voice_gain`]: client_core::history::ContactPin::voice_gain

use std::collections::HashSet;
use std::sync::Mutex;

use client_core::call::GAIN_MAX;
use serde::Serialize;
use tauri::State;

use crate::state::AppState;

/// Contacts this listener has muted, by username. In memory only: mute is per-call.
static MUTED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn muted_set<T>(f: impl FnOnce(&mut HashSet<String>) -> T) -> T {
    let mut g = match MUTED.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    f(g.get_or_insert_with(HashSet::default))
}

fn is_muted(username: &str) -> bool {
    muted_set(|m| m.contains(username))
}

/// Forget every per-call volume control. Called when a call ends, from both the 1:1 and
/// the group path — the saved per-contact levels are untouched.
pub(crate) fn reset_for_new_call() {
    muted_set(|m| m.clear());
    crate::audio::reset_share_audio();
}

/// What the UI needs to draw one person's volume row.
#[derive(Serialize)]
pub struct VoiceVolume {
    /// Saved level in percent — what the slider shows, unaffected by mute.
    pub gain: u32,
    pub muted: bool,
    /// The top of the slider, so the UI never has to hardcode it.
    pub max: u32,
}

/// The same, for the peer's shared system audio.
#[derive(Serialize)]
pub struct ShareVolume {
    pub gain: u32,
    pub muted: bool,
    pub max: u32,
}

/// The gain the engines should actually be applying to this contact right now.
fn effective(gain: u32, username: &str) -> u32 {
    if is_muted(username) {
        0
    } else {
        gain
    }
}

/// Push a contact's effective gain into whichever call engine is live.
///
/// Both are handled because a saved level has to mean the same thing in a 1:1 call and
/// in a group call — "remembered for future calls with this person" would be a lie if it
/// only worked in one of them.
async fn push_to_engine(state: &State<'_, AppState>, username: &str, effective: u32) {
    let s = state.inner.lock().await;
    if let Some(c) = s.call.as_ref() {
        if c.peer_username == username {
            c.toggles
                .voice_gain
                .store(effective, std::sync::atomic::Ordering::Relaxed);
        }
    }
    if let Some(g) = s.group_call.as_ref() {
        // The group engine keys legs by identity key, since a leg exists before its
        // username has been resolved out of history.
        if let Some(key) = s.history.pinned_contact_key(username) {
            g.gains.set(key, effective);
        }
    }
}

/// This contact's saved voice level, and whether they are muted for this call.
#[tauri::command]
pub async fn call_voice_volume(
    state: State<'_, AppState>,
    username: String,
) -> Result<VoiceVolume, String> {
    let gain = {
        let s = state.inner.lock().await;
        s.history.voice_gain(&username)
    };
    Ok(VoiceVolume {
        gain,
        muted: is_muted(&username),
        max: GAIN_MAX,
    })
}

/// Set — and remember — how loud to play this contact.
#[tauri::command]
pub async fn call_set_voice_gain(
    state: State<'_, AppState>,
    username: String,
    percent: u32,
) -> Result<(), String> {
    let percent = percent.min(GAIN_MAX);
    {
        let mut s = state.inner.lock().await;
        // A volume for someone who is not a pinned contact has nowhere durable to live.
        // It still applies to the call in progress — refusing to turn a stranger down
        // would be worse than not remembering it — but say so rather than pretending.
        if s.history.set_voice_gain(&username, percent) {
            s.persist()?;
        } else {
            crate::diag!(
                "[call] voice level for {username} applies to this call only \
                 (not a saved contact, so there is nowhere to remember it)"
            );
        }
    }
    push_to_engine(&state, &username, effective(percent, &username)).await;
    Ok(())
}

/// Mute or un-mute this contact for the rest of the call. Not remembered.
#[tauri::command]
pub async fn call_set_voice_muted(
    state: State<'_, AppState>,
    username: String,
    muted: bool,
) -> Result<(), String> {
    muted_set(|m| {
        if muted {
            m.insert(username.clone());
        } else {
            m.remove(&username);
        }
    });
    let gain = {
        let s = state.inner.lock().await;
        s.history.voice_gain(&username)
    };
    push_to_engine(&state, &username, effective(gain, &username)).await;
    Ok(())
}

/// The peer's shared-audio level for this call.
#[tauri::command]
pub fn call_share_volume() -> ShareVolume {
    use std::sync::atomic::Ordering;
    ShareVolume {
        gain: crate::audio::SHARE_AUDIO_GAIN.load(Ordering::Relaxed),
        muted: crate::audio::SHARE_AUDIO_MUTED.load(Ordering::Relaxed),
        max: GAIN_MAX,
    }
}

/// Set the shared-audio level. Per-call: it resets with the call.
#[tauri::command]
pub fn call_set_share_gain(percent: u32) {
    crate::audio::SHARE_AUDIO_GAIN
        .store(percent.min(GAIN_MAX), std::sync::atomic::Ordering::Relaxed);
}

/// Mute or un-mute the peer's shared audio without losing the slider position.
#[tauri::command]
pub fn call_set_share_muted(muted: bool) {
    crate::audio::SHARE_AUDIO_MUTED.store(muted, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mute and level are independent: un-muting has to come back to the slider, not to
    /// the default, or every mute silently throws the setting away.
    #[test]
    fn muting_does_not_disturb_the_saved_level() {
        muted_set(|m| m.clear());
        assert_eq!(effective(140, "bob"), 140);
        muted_set(|m| {
            m.insert("bob".into());
        });
        assert_eq!(effective(140, "bob"), 0, "muted plays nothing");
        assert_eq!(effective(140, "carol"), 140, "and only for that person");
        muted_set(|m| {
            m.remove("bob");
        });
        assert_eq!(effective(140, "bob"), 140, "un-mute returns to the slider");
    }

    /// Ending a call clears mute but must not touch anything saved.
    #[test]
    fn a_new_call_starts_unmuted_with_share_audio_back_at_the_default() {
        muted_set(|m| {
            m.insert("dave".into());
        });
        crate::audio::SHARE_AUDIO_GAIN.store(93, std::sync::atomic::Ordering::Relaxed);
        crate::audio::SHARE_AUDIO_MUTED.store(true, std::sync::atomic::Ordering::Relaxed);

        reset_for_new_call();

        assert!(!is_muted("dave"));
        assert_eq!(
            crate::audio::share_audio_gain(),
            crate::audio::SHARE_AUDIO_DEFAULT
        );
    }
}
