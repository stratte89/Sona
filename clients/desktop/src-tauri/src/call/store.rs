//! Persistence for the call-control store: where it lives, how it is written, and what a
//! restart does with what it finds there.
//!
//! The state itself is [`client_core::callstore::CallStore`]. This module is the shell's
//! half: the file next to the vault, sealed under the **device** key (so it opens while
//! the chat vault is locked and nowhere else), written atomically so a process killed
//! mid-write leaves the previous store intact rather than a truncated one, and reconciled
//! on every unlock so a ring this device died holding is either restored or taken down.
//!
//! This is the store with the vault **open**. Everything it can do while the vault is
//! locked — the screened mailbox drain, the generic ring, the decline — is
//! [`super::store_locked`], which is a separate module because it is a separate set of
//! rules: no roster, no account, and a different answer to what "fail closed" means.

use crate::*;
use client_core::callstore::CallStore;
use crypto_core::callkey;

/// The retention choices offered for internal call-control records (`internal/CALL_PLAN.md` §6.3):
/// terminal-immediate, 24 hours, 7 days (default), 30 days. There is no indefinite option.
///
/// "Immediate" cannot mean zero: the registry keeps a tombstone for `MIN_TOMBSTONE_SECS`
/// regardless, because a still-valid offer that arrives after a restart would otherwise
/// ring for a call that already ended. It means no *historical* retention beyond that
/// mandatory anti-replay window.
pub(crate) const CALL_RETENTION_CHOICES: [u64; 4] = [0, 24 * 3600, 7 * 24 * 3600, 30 * 24 * 3600];

/// The retention this device applies to terminal tombstones.
pub(crate) fn call_retention_secs(s: &Session) -> u64 {
    let chosen = s.prefs.call_retention_secs;
    if CALL_RETENTION_CHOICES.contains(&chosen) {
        chosen
    } else {
        CALL_RETENTION_CHOICES[2]
    }
}

/// Record a terminal outcome in this device's call registry, under **the retention the
/// user chose**.
///
/// It exists because the obvious thing did not work: nineteen call sites wrote
/// `s.calls().registry.record_terminal(…, 0)` — a literal zero, because `s.calls()`
/// borrows the session mutably and the retention has to be read before it. So every
/// tombstone the encrypted signalling path wrote lived `MIN_TOMBSTONE_SECS`, whatever
/// "Keep call records: 30 days" said in the settings. The direction was privacy-safe and
/// the label was a lie, which is the kind of dishonest UI this project refuses elsewhere.
///
/// A free function taking the session is what makes that unforgettable: there is no
/// parameter left for a new call site to get wrong.
pub(crate) fn record_call_terminal(
    s: &mut Session,
    call_instance_id: &str,
    offer_id: &str,
    reason: client_core::callstate::CallTerminalReason,
) -> client_core::callstate::TerminalDecision {
    let retention = call_retention_secs(s);
    s.calls()
        .registry
        .record_terminal(call_instance_id, offer_id, reason, now_secs(), retention)
}

/// How often the periodic sweep runs (`internal/CALL_PLAN.md` §6.3). Cleanup is already driven by
/// every event that can change the answer — store open, terminal transition, retention
/// change — so this is the belt-and-braces pass for a device that simply stays up: a
/// phone left unlocked for a week must not keep tombstones past the window the user
/// chose merely because no call happened to trigger a sweep.
pub(crate) const CALL_CLEANUP_TICK_SECS: u64 = 3600;

/// Expire what has aged out, writing only if something actually changed — a sweep over a
/// store with nothing to expire costs no re-seal and no disk write.
pub(crate) fn cleanup_call_store(s: &mut Session) {
    if s.account.is_none() {
        return;
    }
    let retention = call_retention_secs(s);
    if s.call_store.cleanup(now_secs(), retention) {
        s.mark_calls_dirty();
        save_call_store(s);
    }
}

/// Apply a retention change immediately: a *shorter* window must take effect now, not
/// whenever the next call happens to clean up (`internal/CALL_PLAN.md` §6.3).
pub(crate) fn apply_call_retention(s: &mut Session) {
    let retention = call_retention_secs(s);
    with_call_store(s, |store| store.cleanup(now_secs(), retention));
}

/// Load (or start) this device's call-control store and reconcile it with reality.
///
/// A store belonging to another account or another device id is discarded rather than
/// adopted: a relink or a primary transfer re-ids this device, and the previous store's
/// rings are not ours to put back on screen. Returns the rings a restart owes the
/// platform — presentation is the Core-Telecom work, so today's shell only takes down
/// what it must and keeps the ordering state.
pub(crate) fn load_call_store(s: &mut Session) {
    let Some(account) = s.account.as_ref() else {
        return;
    };
    let account_hash = account.identity_hash().as_str().to_string();
    let device_id = s.history.self_device_id();
    let stored = device_key()
        .map(|key| callkey::call_store_key(&key))
        .and_then(|store_key| {
            std::fs::read(s.call_store_path())
                .ok()
                .and_then(|blob| CallStore::open(&store_key, &blob))
        })
        .filter(|store| store.belongs_to(&account_hash, &device_id));
    s.call_store = stored.unwrap_or_else(|| CallStore::new(&account_hash, &device_id));
    // Carried so a decline sent while locked can name its own signer (see `decline_locked`).
    s.call_store.username = account.account_id().to_string();
    let reconciliation = s.call_store.reconcile(now_secs(), call_retention_secs(s));
    // A ring this process was showing when it died, for a call that has since ended or
    // expired: take the presentation down. Nothing here can ring — a pending ring holds no
    // media capability, and `reconcile` never returns an expired or tombstoned one.
    for ring_handle in &reconciliation.cancel {
        eng().cancel_ring(ring_handle, "");
    }
    reconcile_system_calls(s, &reconciliation);
    s.mark_calls_dirty();
    save_call_store(s);
}

/// The name a **restored** ring may show on the lock screen.
///
/// Every live ring goes through `ring_title`, which returns "Sona" when the user has set
/// `notif_level: "generic"`. Reconciliation did not, and put `ring.display_name` on screen
/// raw — so a process death was all it took for the lock screen to name a caller the user
/// had asked never to be named. A restart is not a reason to reveal less carefully.
fn restored_ring_title(s: &Session, ring: &client_core::callstore::PendingRing) -> String {
    if ring.display_name.is_empty() {
        return "Sona".to_string();
    }
    ring_title(s, &ring.display_name)
}

/// Make the platform's idea of our calls match ours (`internal/CALL_PLAN.md` §6.4).
///
/// Two directions, both of which a process death can leave wrong:
///
/// * a ring the store still considers live that Telecom no longer holds — put it back,
///   but only because a **non-terminal, unexpired** record says so, never because a row
///   exists;
/// * a Telecom call nothing here knows about — the previous process died holding it, and
///   leaving it up would show the user a call that cannot be answered or ended.
fn reconcile_system_calls(
    s: &mut Session,
    reconciliation: &client_core::callstore::Reconciliation,
) {
    let live = crate::telecom::active_calls();
    let mut restored = Vec::new();
    for ring in &reconciliation.present {
        if !live.contains(&ring.ring_handle) {
            let name = restored_ring_title(s, ring);
            eng().start_system_call(&ring.ring_handle, &name, ring.video, true);
            restored.push((ring.call_instance_id.clone(), ring.ring_handle.clone()));
        }
    }
    // A restored ring is now on screen under its **handle**, not under the generic locked
    // id it may have carried from before. Record that, or the next terminal cancels the
    // notification this process no longer has and leaves the one it does.
    if !restored.is_empty() {
        with_call_store(s, |store| {
            for (call_instance_id, ring_handle) in &restored {
                store.mark_presented(call_instance_id, ring_handle);
            }
        });
    }
    for handle in live {
        let ours = s.call.as_ref().is_some_and(|c| c.ring_handle == handle)
            || s.group_call
                .as_ref()
                .is_some_and(|c| c.ring_handle == handle)
            || s.call_store
                .rings
                .iter()
                .any(|ring| ring.ring_handle == handle);
        if !ours {
            eng().end_system_call(&handle, crate::telecom::cause::LOCAL);
        }
    }
}

/// Seal the store to disk if it changed and this device has a key store.
///
/// Best effort and honest about it: without a device key there is nothing to seal under,
/// and the store stays in memory only — the same degraded-but-working state the
/// call-control identity has on such a device.
/// `&Session`, not `&mut`: [`Session::persist`] holds only a shared borrow and has to be able
/// to clear the flag too, or it re-seals the store on every message for the rest of the
/// process' life (A-24). Both callers come through here so neither can drift on who owns the
/// flag.
pub(crate) fn save_call_store(s: &Session) {
    use std::sync::atomic::Ordering::SeqCst;
    // No data dir means no session has been installed yet (tests, early startup): there is
    // nowhere to write, and writing relative to the process' cwd would be wrong.
    if !s.call_store_dirty.load(SeqCst) || s.data_dir.as_os_str().is_empty() {
        return;
    }
    let Some(device_key) = device_key() else {
        return;
    };
    let blob = s.call_store.seal(&callkey::call_store_key(&device_key));
    // Cleared only on a successful write. Clearing after a failure would silently drop a
    // tombstone — the one piece of call state that must outlive the process.
    if write_atomic(&s.call_store_path(), &blob).is_ok() {
        s.call_store_dirty.store(false, SeqCst);
    }
}

/// Mutate the store and persist the result.
pub(crate) fn with_call_store<R>(s: &mut Session, f: impl FnOnce(&mut CallStore) -> R) -> R {
    let out = f(&mut s.call_store);
    s.mark_calls_dirty();
    save_call_store(s);
    out
}

/// Destroy the store: the file, and the state it mirrors.
///
/// Honest about what deletion means, exactly as with the identity: the file is unlinked
/// and its contents are cryptographically useless without the device key, but flash
/// storage cannot promise the ciphertext bytes are physically overwritten.
pub(crate) fn wipe_call_store(s: &mut Session) {
    let _ = std::fs::remove_file(s.call_store_path());
    s.call_store = CallStore::default();
    s.call_store_dirty
        .store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Write via a temporary file and rename, so a process killed mid-write leaves the
/// previous store intact instead of a truncated one that opens as nothing.
pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_core::callcapsule::CapsuleSigner;
    use client_core::callstate::{random_call_id, CallTerminalReason};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sona-callstore-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A killed process must leave the previous store readable, never a half-written one.
    #[test]
    fn the_store_is_written_atomically_and_leaves_no_partial_file() {
        let dir = temp_dir("atomic");
        let path = dir.join("call_store.bin");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second and longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second and longer");
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tombstones outlive the process: a terminal recorded before a restart still
    /// suppresses the offer that arrives after it.
    #[test]
    fn a_tombstone_survives_a_reload_of_the_sealed_store() {
        let dir = temp_dir("reload");
        let store_key = *callkey::call_store_key(&[5u8; crypto_core::DEVICE_KEY_LEN]);
        let device = "a".repeat(32);
        let mut store = CallStore::new("account-hash", &device);
        let (call, offer) = (random_call_id(), random_call_id());
        store.record_terminal(
            &call,
            &offer,
            CallTerminalReason::AnsweredElsewhere,
            now_secs(),
            call_retention_secs(&Session::default()),
        );
        let path = dir.join("call_store.bin");
        write_atomic(&path, &store.seal(&store_key)).unwrap();

        let reloaded = CallStore::open(&store_key, &std::fs::read(&path).unwrap()).unwrap();
        assert!(reloaded.belongs_to("account-hash", &device));
        assert_eq!(
            reloaded.registry.terminal_reason(&call),
            Some(CallTerminalReason::AnsweredElsewhere)
        );
        // …and it is not adopted by a device that is not the one that wrote it.
        assert!(!reloaded.belongs_to("account-hash", &"b".repeat(32)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restoration is driven by the record, never by the row's existence: a ring whose
    /// call ended is cancelled, and only a live one is offered back to the platform.
    #[test]
    fn reconciliation_only_restores_rings_that_are_still_live() {
        use client_core::callcapsule::{CallCapsule, CapsuleKind, CapsulePlan};
        use client_core::callstate::{CALL_RING_TIMEOUT_SECS, CALL_SIGNAL_TTL_SECS};

        let account = crypto_core::create_account_with_username("bob", "Bob-Password-123!")
            .unwrap()
            .0;
        let now = now_secs();
        let capsule = |call: &str, offer: &str| {
            CallCapsule::new(
                CapsulePlan {
                    kind: CapsuleKind::Offer,
                    call_instance_id: call.to_string(),
                    offer_id: offer.to_string(),
                    from: "bob".into(),
                    caller_identity_key: account.ratchet_ref().identity_key(),
                    caller_device_id: "0".into(),
                    to_device_id: "a".repeat(32),
                    video: false,
                    group: false,
                    display_name: "bob".into(),
                    created_at: now,
                    ring_expires_at: now + CALL_RING_TIMEOUT_SECS,
                    expires_at: now + CALL_SIGNAL_TTL_SECS,
                    reply_to_mailbox: "b".repeat(64),
                    reply_call_mailbox: "c".repeat(64),
                    reply_call_key: String::new(),
                    signer: CapsuleSigner::Roster,
                    reason: None,
                },
                |payload| account.ratchet_ref().sign(payload),
            )
        };
        let mut store = CallStore::new("account-hash", &"a".repeat(32));
        let live = (random_call_id(), random_call_id());
        let ended = (random_call_id(), random_call_id());
        store.record_offer(&capsule(&live.0, &live.1), now, CALL_RETENTION_CHOICES[2]);
        store.record_offer(&capsule(&ended.0, &ended.1), now, CALL_RETENTION_CHOICES[2]);
        store.record_terminal(
            &ended.0,
            &ended.1,
            CallTerminalReason::AnsweredElsewhere,
            now,
            CALL_RETENTION_CHOICES[2],
        );

        let out = store.reconcile(now + 1, CALL_RETENTION_CHOICES[2]);
        assert_eq!(out.present.len(), 1);
        assert_eq!(out.present[0].call_instance_id, live.0);
        // The ended call is gone from the store entirely — nothing left to re-present.
        assert!(store.ring(&ended.0).is_none());
    }

    /// A-24: `persist` must clear the dirty flag it just wrote for.
    ///
    /// `Session::persist(&self)` sealed the store whenever the flag was set but could not
    /// clear it — only `save_call_store` could, and nothing on the message path calls that.
    /// So after a single call, **every** later persist (one per message, per receipt, per
    /// state-mutating command) performed an extra `write_atomic` plus `sync_all` of the
    /// store: flash wear, and a synchronous fsync on the message path, for nothing.
    ///
    /// Asserted as a biconditional rather than "the flag is clear", because the seal needs a
    /// device key and a headless CI runner may have no key store: cleared **exactly** when
    /// the write happened. That is also the other half of the rule — clearing after a failed
    /// write would silently drop a tombstone, the one piece of call state that has to outlive
    /// the process.
    #[test]
    fn persist_clears_the_call_store_flag_exactly_when_it_wrote_the_store() {
        use std::sync::atomic::Ordering::SeqCst;

        let mut session = Session {
            data_dir: temp_dir("persist-dirty"),
            account: Some(
                crypto_core::create_account_with_username("alice", "Alice-Password-123!")
                    .unwrap()
                    .0,
            ),
            ..Default::default()
        };
        session.calls(); // any registry transition marks the store for sealing
        assert!(session.call_store_dirty.load(SeqCst));

        session.persist().unwrap();

        let wrote = session.call_store_path().exists();
        assert_eq!(
            !session.call_store_dirty.load(SeqCst),
            wrote,
            "the flag must be cleared exactly when the store reached disk — left set after a \
             successful write, every later persist re-seals and re-fsyncs it forever"
        );

        // And a second persist with nothing new must not write again.
        let before = std::fs::metadata(session.call_store_path())
            .ok()
            .and_then(|m| m.modified().ok());
        session.persist().unwrap();
        if wrote {
            assert_eq!(
                std::fs::metadata(session.call_store_path())
                    .ok()
                    .and_then(|m| m.modified().ok()),
                before,
                "an unchanged store must not be re-sealed by the next message's persist"
            );
        }
        let _ = std::fs::remove_dir_all(&session.data_dir);
    }

    /// A-9: the retention the user chose has to reach the tombstone the **signalling**
    /// path writes, not only the capsule one.
    ///
    /// Nineteen call sites passed a literal `0`, because `s.calls()` borrows the session
    /// and the setting has to be read before it — so "Keep call records: 30 days" described
    /// a 65-second window. The helper is what makes that unforgettable, and this is what
    /// says so out loud.
    #[test]
    fn a_terminal_is_tombstoned_for_the_retention_the_user_chose() {
        use client_core::callstate::{CallRecordState, MIN_TOMBSTONE_SECS};

        let kept = |chosen: u64| {
            let mut session = Session::default();
            session.prefs.call_retention_secs = chosen;
            let (call, offer) = (random_call_id(), random_call_id());
            record_call_terminal(
                &mut session,
                &call,
                &offer,
                CallTerminalReason::CallerCancelled,
            );
            match &session.call_store.registry.records()[0].state {
                CallRecordState::Terminal { retain_until, .. } => {
                    retain_until.saturating_sub(now_secs())
                }
                other => panic!("expected a tombstone, got {other:?}"),
            }
        };
        // Thirty days means thirty days…
        assert!(kept(CALL_RETENTION_CHOICES[3]) >= CALL_RETENTION_CHOICES[3] - 1);
        assert!(kept(CALL_RETENTION_CHOICES[1]) >= CALL_RETENTION_CHOICES[1] - 1);
        // …and "until the call ends" still keeps the mandatory anti-replay window, or a
        // still-valid offer arriving after a restart would ring for a call that is over.
        let immediate = kept(CALL_RETENTION_CHOICES[0]);
        assert!(immediate >= MIN_TOMBSTONE_SECS - 1 && immediate < CALL_RETENTION_CHOICES[1]);
    }

    /// A-10: a restart is not a reason to reveal a caller the user asked to hide.
    ///
    /// Every live ring is named through `ring_title`; reconciliation used
    /// `ring.display_name` raw, so a process death was all it took for the lock screen to
    /// name the caller under `notif_level: "generic"`.
    #[test]
    fn a_restored_ring_honors_the_notification_privacy_level() {
        use client_core::callstore::PendingRing;

        let ring = |display_name: &str| PendingRing {
            call_instance_id: random_call_id(),
            offer_id: random_call_id(),
            ring_handle: random_call_id(),
            from: "alice".into(),
            display_name: display_name.to_string(),
            video: false,
            group: false,
            caller_device_id: "0".into(),
            reply_to_mailbox: "b".repeat(64),
            reply_call_mailbox: String::new(),
            reply_call_key: String::new(),
            created_at: now_secs(),
            ring_expires_at: now_secs() + 45,
            presented_as: None,
        };
        let mut session = Session::default();
        assert_eq!(restored_ring_title(&session, &ring("Alice")), "Alice");
        session.prefs.notif_level = "generic".into();
        assert_eq!(restored_ring_title(&session, &ring("Alice")), "Sona");
        // A capsule that carried no name at all still gets an honest placeholder.
        assert_eq!(restored_ring_title(&session, &ring("")), "Sona");
    }

    /// Wiping removes the file, not just the in-memory copy.
    #[test]
    fn wiping_removes_the_store_file() {
        let dir = temp_dir("wipe");
        let mut session = Session {
            data_dir: dir.clone(),
            ..Session::default()
        };
        std::fs::write(session.call_store_path(), b"sealed store").unwrap();
        session.call_store.device_id = "a".repeat(32);
        wipe_call_store(&mut session);
        assert!(!session.call_store_path().exists());
        assert_eq!(session.call_store, CallStore::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
