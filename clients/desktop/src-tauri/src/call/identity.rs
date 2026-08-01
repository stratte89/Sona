//! This device's **call-control identity**: minting it, keeping it on disk under the
//! device key, publishing it, and destroying it.
//!
//! The identity is what lets an incoming-call capsule reach this device while the chat
//! vault is locked, so its secret deliberately does **not** live in the vault: it is
//! sealed under `crypto_core::callkey::call_store_key(device_key)` — the OS keyring on
//! desktop, a non-exportable Keystore/StrongBox key on Android. Without a device key
//! there is no call-control identity at all (and calls simply keep working the ordinary
//! way, after unlock); we never fall back to storing it in the clear.
//!
//! Publishing, by contrast, happens only while unlocked: it needs the account's roster
//! signing key. `History::call_key_published` remembers what went out, so an unlock does
//! not republish for nothing and a fresh publication always carries a `created_at` the
//! relay's monotonic shelf will accept.

use crate::*;
use crypto_core::callkey::{self, CallKey};

/// Load this device's call-control secret, minting and persisting one when there is
/// none (or when the stored blob no longer opens — a rotated device key, a truncated
/// file). `None` means this device has no key store, so it gets no call-control
/// identity; that is a degraded-but-honest state, not an error to retry.
pub(crate) fn load_or_mint_call_key(path: &std::path::Path) -> Option<(CallKey, bool)> {
    let store_key = callkey::call_store_key(&device_key()?);
    load_or_mint_under(path, &store_key)
}

/// [`load_or_mint_call_key`] with the store key supplied, so the on-disk behavior is
/// testable without a key store.
fn load_or_mint_under(path: &std::path::Path, store_key: &[u8; 32]) -> Option<(CallKey, bool)> {
    if let Some(existing) = std::fs::read(path)
        .ok()
        .and_then(|blob| callkey::open_call_secret(store_key, &blob))
    {
        return Some((existing, false));
    }
    let minted = CallKey::generate();
    let blob = callkey::seal_call_secret(store_key, &minted);
    // Atomically, like the store: a process killed mid-write would otherwise leave a
    // truncated secret, and the next unlock would mint a *new* identity — silently
    // dropping every capsule sealed to the published one until it republished.
    write_atomic(path, &blob).ok()?;
    Some((minted, true))
}

/// Make sure this device has a call-control identity and that the relay's shelf carries
/// its current key.
///
/// Runs off the session lock for the publication (a relay round trip), taking the lock
/// only to read what is needed and to record the result. Best effort throughout: a
/// missing key store, a locked vault, or an unreachable relay leaves calls working
/// exactly as they do today — capsules are an addition to the encrypted offer, never a
/// replacement for it.
pub(crate) async fn ensure_call_identity(inner: &Arc<Mutex<Session>>, client: &Arc<Client>) {
    let (path, device_id, mailbox, published) = {
        let s = inner.lock().await;
        if !is_current(&s, client) || s.history.revoked() {
            return;
        }
        let Some(account) = s.account.as_ref() else {
            return;
        };
        let device_id = s.history.self_device_id();
        let Ok(mailbox) = client.device_mailbox(account.account_id(), &device_id) else {
            return;
        };
        (
            s.call_key_path(),
            device_id,
            mailbox,
            s.history.call_key_published().cloned(),
        )
    };
    let Some((call_key, minted)) = load_or_mint_call_key(&path) else {
        return; // no device key store on this platform/profile
    };
    let public = call_key.public_b64();
    {
        let mut s = inner.lock().await;
        if !is_current(&s, client) {
            return;
        }
        s.call_key = Some(Arc::new(call_key));
        if minted {
            // A fresh secret invalidates whatever the shelf holds for us.
            s.history.clear_call_key_published();
            let _ = s.persist();
        }
    }
    let already_published = !minted
        && published
            .as_ref()
            .is_some_and(|p| p.public_key == public && p.device_id == device_id);
    if already_published {
        return;
    }
    // Strictly newer than our last publication: the relay's shelf is monotonic, so a
    // clock that went backwards must not lock this device out of republishing.
    let created_at = published
        .map(|p| p.created_at.saturating_add(1).max(now_secs()))
        .unwrap_or_else(now_secs);
    if publish(inner, client, &mailbox, &device_id, created_at).await {
        let mut s = inner.lock().await;
        if is_current(&s, client) {
            s.history
                .set_call_key_published(&public, created_at, &device_id);
            let _ = s.persist();
        }
    }
}

/// Publish with the session lock released across the relay round trip. The account is
/// borrowed only to sign, which is why signing happens inside a short critical section
/// and the HTTP call does not.
async fn publish(
    inner: &Arc<Mutex<Session>>,
    client: &Arc<Client>,
    mailbox: &str,
    device_id: &str,
    created_at: u64,
) -> bool {
    let Ok(nonce) = client.call_key_nonce(mailbox).await else {
        return false;
    };
    // Sign under the lock; post with it released.
    let (account_hash, binding, signature) = {
        let s = inner.lock().await;
        if !is_current(&s, client) {
            return false;
        }
        let (Some(account), Some(call_key)) = (s.account.as_ref(), s.call_key.as_ref()) else {
            return false;
        };
        let (binding, signature) = client.prepare_call_key_publication(
            account, mailbox, device_id, call_key, created_at, &nonce,
        );
        (
            account.identity_hash().as_str().to_string(),
            binding,
            signature,
        )
    };
    client
        .post_call_key_publication(&account_hash, mailbox, &nonce, &binding, &signature)
        .await
        .is_ok()
}

/// Rebuild and reseal the approved-caller screening index from currently verified state.
///
/// This is what a **locked** device screens capsules with, so it must be refreshed
/// wherever the answer to "may this caller ring me?" changes: at unlock, when a contact
/// is blocked or unblocked, when a message request is accepted or declined, and when a
/// roster is re-verified. Cheap (a few hundred bytes of keyed hashes) and idempotent, so
/// over-calling it costs nothing; missing a call would leave a stale answer, which is why
/// every one of those sites calls it rather than a timer.
///
/// No device key ⇒ no index, exactly as with the identity itself: screening then has
/// nothing to say and capsules simply do not ring until the vault is open.
pub(crate) fn refresh_call_screen(s: &mut Session) {
    let Some(device_key) = device_key() else {
        return;
    };
    if s.account.is_none() || s.history.revoked() {
        return;
    }
    let store_key = callkey::call_store_key(&device_key);
    // Our own account goes in too: a sibling's `answered_elsewhere` capsule is the one
    // this device must be able to verify while locked, and it is never a contact.
    let me = s.account.as_ref().map(|account| account.account_id());
    let index = client_core::callscreen::ScreenIndex::build(&store_key, &s.history, me);
    // Atomically: a truncated index opens as nothing, and screening that falls back to
    // "nobody" leaves a locked phone unable to verify the sibling terminal that stops it
    // ringing (A-1) until the next unlock rebuilds it.
    let _ = write_atomic(&s.call_screen_path(), &index.seal(&store_key));
}

/// Destroy this device's call-control identity: the sealed secret on disk, the in-memory
/// copy, and the local record of what was published.
///
/// Honest about what deletion means: the file is unlinked and the key it held is
/// cryptographically useless without the device key, but flash storage (journaling, wear
/// levelling) cannot promise the ciphertext bytes are physically overwritten.
pub(crate) fn wipe_call_identity(s: &mut Session) {
    let _ = std::fs::remove_file(s.call_key_path());
    let _ = std::fs::remove_file(s.call_screen_path());
    wipe_call_store(s);
    s.call_key = None;
    s.history.clear_call_key_published();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("sona-callkey-{name}-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn the_identity_is_minted_once_and_reloaded_after_that() {
        let path = temp_path("stable");
        let store_key = callkey::call_store_key(&[1u8; crypto_core::DEVICE_KEY_LEN]);
        let (first, minted) = load_or_mint_under(&path, &store_key).unwrap();
        assert!(minted, "first call mints");
        let (again, minted_again) = load_or_mint_under(&path, &store_key).unwrap();
        assert!(!minted_again, "a stored identity is reused, not replaced");
        assert_eq!(first.public_b64(), again.public_b64());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_blob_that_no_longer_opens_yields_a_fresh_identity() {
        let path = temp_path("rotated");
        let store_key = callkey::call_store_key(&[1u8; crypto_core::DEVICE_KEY_LEN]);
        let (original, _) = load_or_mint_under(&path, &store_key).unwrap();
        // The device key rotated (or the file was corrupted): mint again rather than
        // leaving the device with an identity it cannot use.
        let rotated = callkey::call_store_key(&[2u8; crypto_core::DEVICE_KEY_LEN]);
        let (fresh, minted) = load_or_mint_under(&path, &rotated).unwrap();
        assert!(minted);
        assert_ne!(fresh.public_b64(), original.public_b64());
        // …and the new one is what persists.
        let (reloaded, minted_again) = load_or_mint_under(&path, &rotated).unwrap();
        assert!(!minted_again);
        assert_eq!(reloaded.public_b64(), fresh.public_b64());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_screening_index_is_rebuilt_and_wiped_with_the_identity() {
        let dir = std::env::temp_dir().join(format!("sona-screen-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut session = Session {
            data_dir: dir.clone(),
            ..Session::default()
        };
        // A sealed index written by an earlier unlock must not survive the wipe.
        std::fs::write(session.call_screen_path(), b"sealed index").unwrap();
        wipe_call_identity(&mut session);
        assert!(!session.call_screen_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wiping_removes_the_secret_and_the_publication_record() {
        let path = temp_path("wipe");
        let store_key = callkey::call_store_key(&[3u8; crypto_core::DEVICE_KEY_LEN]);
        let (key, _) = load_or_mint_under(&path, &store_key).unwrap();
        let mut session = Session {
            data_dir: path.parent().unwrap().to_path_buf(),
            ..Session::default()
        };
        // Point the session at this test's file by writing it where the session looks.
        std::fs::copy(&path, session.call_key_path()).unwrap();
        session.call_key = Some(Arc::new(key));
        session.history.set_call_key_published("pub", 5, "0");
        wipe_call_identity(&mut session);
        assert!(session.call_key.is_none());
        assert!(session.history.call_key_published().is_none());
        assert!(!session.call_key_path().exists());
        let _ = std::fs::remove_file(&path);
    }
}
