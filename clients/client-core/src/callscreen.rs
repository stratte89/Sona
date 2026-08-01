//! The **approved-caller screening index**: who may make this device ring while its
//! chat vault is locked.
//!
//! A capsule is only as safe as the answer to "may this caller ring me?", and a locked
//! device cannot ask the vault — contacts, blocks, and message-request state all live in
//! it. So at unlock the device distils the minimum needed to screen a call and seals it
//! under the call-only store key ([`crypto_core::callkey::call_store_key`]), where the
//! locked call subsystem can read it.
//!
//! Minimum means minimum (`internal/CALL_PLAN.md` §4.4):
//!
//! * callers appear under a **keyed hash** of their username, so the file is not a
//!   readable — or cross-device linkable — list of who may call this device;
//! * each entry holds only the device ids and Ed25519 roster keys needed to verify a
//!   capsule signature. No identity keys, no display names, no message content, no
//!   conversation state;
//! * blocked contacts, pending message requests, and contacts whose roster we have not
//!   KT-verified are simply **absent** — screening fails closed, and an absent caller
//!   still rings normally once the vault is open.
//!
//! Our **own** account is indexed first and unconditionally. It is not a contact, so
//! nothing else would put it here, and it is the one entry that must never be missing: a
//! sibling device's `answered_elsewhere` capsule is what stops this phone ringing for a
//! call already answered on the desktop, and a capsule whose signer cannot be placed is
//! refused before it is even read.

use serde::{Deserialize, Serialize};

use crate::history::History;

/// Upper bound on indexed callers. Bounds the sealed file and the work a locked device
/// does per capsule; a device with more contacts than this screens the first
/// [`MAX_SCREEN_CALLERS`] and the rest ring after unlock, which is the safe direction.
pub const MAX_SCREEN_CALLERS: usize = 1024;
/// Upper bound on devices recorded per caller — the roster cap, mirrored here so a
/// hostile or corrupted index cannot make lookups unbounded.
pub const MAX_SCREEN_DEVICES: usize = 8;

/// One caller's screening entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenEntry {
    /// Keyed hash of the caller's username (see
    /// [`crypto_core::callkey::screen_hash`]).
    pub caller: String,
    /// `(device_id, Ed25519 roster signing key)` for that caller's verified devices.
    pub devices: Vec<(String, String)>,
}

/// The sealed-at-rest approved-caller index.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenIndex {
    pub entries: Vec<ScreenEntry>,
}

impl ScreenIndex {
    /// Build the index from verified state: our own account, then every pinned contact
    /// that is not blocked, is not a pending message request, and whose KT-verified
    /// roster we hold.
    ///
    /// `me` is this account's username. It is indexed **first**, so that the entry which
    /// stops a ring can never be the one `MAX_SCREEN_CALLERS` truncates away, and it is
    /// not subject to the block/request rules — those are about who may *start* a call,
    /// and a self-sync terminal ends one.
    ///
    /// An account without a pinned roster contributes nothing — we would have no key to
    /// check a capsule signature against, and guessing one is exactly what fail-closed
    /// forbids.
    pub fn build(store_key: &[u8; 32], history: &History, me: Option<&str>) -> Self {
        let mut entries = Vec::new();
        // Our own devices, minus this one: `prepare_capsules` never addresses a capsule
        // to the device that minted it, so an entry for ourselves would only ever match
        // something we do not send.
        let self_device = history.self_device_id();
        if let Some(me) = me {
            if let Some(entry) = Self::entry_for(store_key, history, me, Some(&self_device)) {
                entries.push(entry);
            }
        }
        for (username, pin) in history.contacts() {
            if entries.len() >= MAX_SCREEN_CALLERS {
                break;
            }
            if pin.blocked || pin.request.is_some() || Some(username.as_str()) == me {
                continue;
            }
            if let Some(entry) = Self::entry_for(store_key, history, &username, None) {
                entries.push(entry);
            }
        }
        ScreenIndex { entries }
    }

    /// One account's entry, or `None` when there is no KT-verified roster to take
    /// signing keys from.
    fn entry_for(
        store_key: &[u8; 32],
        history: &History,
        username: &str,
        skip_device: Option<&str>,
    ) -> Option<ScreenEntry> {
        let roster = history.pinned_roster(username)?;
        let devices: Vec<(String, String)> = roster
            .devices
            .iter()
            .filter(|device| {
                !device.signing_key.is_empty() && Some(device.device_id.as_str()) != skip_device
            })
            .take(MAX_SCREEN_DEVICES)
            .map(|device| (device.device_id.clone(), device.signing_key.clone()))
            .collect();
        (!devices.is_empty()).then(|| ScreenEntry {
            caller: crypto_core::callkey::screen_hash(store_key, username),
            devices,
        })
    }

    /// The signing key a capsule from `(username, device_id)` must carry, or `None` when
    /// that caller may not ring this device while it is locked.
    pub fn signing_key(
        &self,
        store_key: &[u8; 32],
        username: &str,
        device_id: &str,
    ) -> Option<String> {
        let caller = crypto_core::callkey::screen_hash(store_key, username);
        self.entries
            .iter()
            .find(|entry| entry.caller == caller)?
            .devices
            .iter()
            .find(|(id, _)| id == device_id)
            .map(|(_, key)| key.clone())
    }

    /// Seal for storage under the call-only store key.
    pub fn seal(&self, store_key: &[u8; 32]) -> Vec<u8> {
        let plain = serde_json::to_vec(self).unwrap_or_default();
        crypto_core::callkey::seal_screen_index(store_key, &plain)
    }

    /// Open a sealed index. `None` on a wrong device key, tampering, or a shape that
    /// exceeds the bounds — the caller rebuilds from verified state at the next unlock
    /// and screens nothing until then.
    pub fn open(store_key: &[u8; 32], blob: &[u8]) -> Option<Self> {
        let plain = crypto_core::callkey::open_screen_index(store_key, blob)?;
        let index: ScreenIndex = serde_json::from_slice(&plain).ok()?;
        (index.entries.len() <= MAX_SCREEN_CALLERS
            && index
                .entries
                .iter()
                .all(|entry| entry.devices.len() <= MAX_SCREEN_DEVICES))
        .then_some(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::RosterDevice;

    fn store_key() -> [u8; 32] {
        *crypto_core::callkey::call_store_key(&[4u8; crypto_core::DEVICE_KEY_LEN])
    }

    fn device(id: &str, signing_key: &str) -> RosterDevice {
        RosterDevice {
            device_id: id.to_string(),
            identity_key: format!("{id}-identity"),
            signing_key: signing_key.to_string(),
        }
    }

    fn history_with_contact(username: &str, blocked: bool, roster: bool) -> History {
        let mut history = History::new();
        history.pin_contact(username, &format!("{username}-key"), true);
        if blocked {
            history.with_contact_mut(username, |pin| pin.blocked = true);
        }
        if roster {
            history
                .pin_roster(
                    username,
                    0,
                    0,
                    &format!("{username}-key"),
                    vec![
                        device("0", "primary-signing-key"),
                        device(&"a".repeat(32), "linked-signing-key"),
                    ],
                )
                .unwrap();
        }
        history
    }

    /// The entry a locked device needs most: our **own** siblings. Answering on the
    /// desktop sends this phone an `answered_elsewhere` capsule signed by that sibling's
    /// roster key, and a signer the index cannot place is refused — so without this the
    /// phone rings for the full timeout at a call that is already answered.
    #[test]
    fn our_own_siblings_can_stop_this_devices_ring() {
        let key = store_key();
        let mut history = History::new();
        // This device is the phone; the primary and the laptop are the siblings whose
        // terminals have to reach it.
        history.set_self_device(&"f".repeat(32), false);
        history
            .pin_roster(
                "me",
                0,
                0,
                "my-key",
                vec![
                    device("0", "my-primary-signing-key"),
                    device(&"a".repeat(32), "my-laptop-signing-key"),
                    device(&"f".repeat(32), "this-phones-signing-key"),
                ],
            )
            .unwrap();
        let index = ScreenIndex::build(&key, &history, Some("me"));
        assert_eq!(
            index.signing_key(&key, "me", "0").as_deref(),
            Some("my-primary-signing-key"),
            "a sibling's terminal capsule must verify while the vault is locked"
        );
        assert_eq!(
            index.signing_key(&key, "me", &"a".repeat(32)).as_deref(),
            Some("my-laptop-signing-key")
        );
        // Our own account is not a contact, so nothing else would have indexed it.
        assert!(ScreenIndex::build(&key, &history, None)
            .signing_key(&key, "me", "0")
            .is_none());
        // Still keyed, like every other entry.
        let blob = index.seal(&key);
        assert!(!blob.windows(2).any(|w| w == b"me"));
    }

    /// This device is skipped: `prepare_capsules` never addresses a capsule to the device
    /// that minted it, so an entry for ourselves could only match something we never send.
    #[test]
    fn this_device_is_not_indexed_as_a_caller() {
        let key = store_key();
        let mut history = History::new();
        history.set_self_device(&"a".repeat(32), false);
        history
            .pin_roster(
                "me",
                0,
                0,
                "my-key",
                vec![
                    device("0", "my-primary-signing-key"),
                    device(&"a".repeat(32), "linked-signing-key"),
                ],
            )
            .unwrap();
        let index = ScreenIndex::build(&key, &history, Some("me"));
        assert_eq!(
            index.signing_key(&key, "me", "0").as_deref(),
            Some("my-primary-signing-key")
        );
        assert!(index.signing_key(&key, "me", &"a".repeat(32)).is_none());
    }

    /// Our own account is indexed even when the contact list is at the cap, because the
    /// truncation must never drop the entry that stops a ring.
    #[test]
    fn the_caller_cap_never_costs_us_our_own_entry() {
        let key = store_key();
        let mut history = History::new();
        history.set_self_device(&"f".repeat(32), false);
        history
            .pin_roster("me", 0, 0, "my-key", vec![device("0", "my-signing-key")])
            .unwrap();
        for n in 0..MAX_SCREEN_CALLERS + 8 {
            let name = format!("contact{n}");
            history.pin_contact(&name, &format!("{name}-key"), true);
            history
                .pin_roster(&name, 0, 0, &format!("{name}-key"), vec![device("0", "k")])
                .unwrap();
        }
        let index = ScreenIndex::build(&key, &history, Some("me"));
        assert_eq!(index.entries.len(), MAX_SCREEN_CALLERS);
        assert_eq!(
            index.signing_key(&key, "me", "0").as_deref(),
            Some("my-signing-key")
        );
    }

    #[test]
    fn an_approved_contact_is_screenable_by_device() {
        let key = store_key();
        let index = ScreenIndex::build(&key, &history_with_contact("alice", false, true), None);
        assert_eq!(
            index.signing_key(&key, "alice", "0").as_deref(),
            Some("primary-signing-key")
        );
        assert_eq!(
            index.signing_key(&key, "alice", &"a".repeat(32)).as_deref(),
            Some("linked-signing-key")
        );
        // A device that is not on the pinned roster cannot ring us.
        assert!(index.signing_key(&key, "alice", &"b".repeat(32)).is_none());
        // Nor can an account we never indexed.
        assert!(index.signing_key(&key, "mallory", "0").is_none());
    }

    #[test]
    fn blocked_and_unverified_callers_are_absent() {
        let key = store_key();
        // Blocked: no entry at all.
        let blocked = ScreenIndex::build(&key, &history_with_contact("alice", true, true), None);
        assert!(blocked.entries.is_empty());
        // Pinned contact with no verified roster: nothing to check a signature against.
        let unverified =
            ScreenIndex::build(&key, &history_with_contact("alice", false, false), None);
        assert!(unverified.entries.is_empty());
    }

    #[test]
    fn the_sealed_index_names_nobody_in_the_clear() {
        let key = store_key();
        let index = ScreenIndex::build(&key, &history_with_contact("alice", false, true), None);
        let blob = index.seal(&key);
        assert!(!blob.windows(5).any(|w| w == b"alice"));
        assert_eq!(ScreenIndex::open(&key, &blob).unwrap(), index);
        // A different device key opens nothing…
        let other = *crypto_core::callkey::call_store_key(&[9u8; crypto_core::DEVICE_KEY_LEN]);
        assert!(ScreenIndex::open(&other, &blob).is_none());
        // …and tampering is refused rather than half-trusted.
        let mut broken = blob.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xff;
        assert!(ScreenIndex::open(&key, &broken).is_none());
    }

    #[test]
    fn an_oversized_index_is_refused_on_open() {
        let key = store_key();
        let bloated = ScreenIndex {
            entries: (0..MAX_SCREEN_CALLERS + 1)
                .map(|i| ScreenEntry {
                    caller: format!("{i:032x}"),
                    devices: vec![("0".into(), "key".into())],
                })
                .collect(),
        };
        assert!(ScreenIndex::open(&key, &bloated.seal(&key)).is_none());
        let wide = ScreenIndex {
            entries: vec![ScreenEntry {
                caller: "aa".into(),
                devices: (0..MAX_SCREEN_DEVICES + 1)
                    .map(|i| (format!("{i}"), "key".into()))
                    .collect(),
            }],
        };
        assert!(ScreenIndex::open(&key, &wide.seal(&key)).is_none());
    }
}
