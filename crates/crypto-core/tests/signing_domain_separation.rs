//! The signing-context disjointness invariant (SP-01).
//!
//! Every context that the account's long-term Ed25519 identity key signs is prefixed
//! with its own domain separator, so a signature minted for one purpose can never be
//! valid for another. The WebSocket login challenge used to be the one exception — it
//! signed the relay's raw nonce — which made it a **blind signing oracle**: a hostile
//! relay could serve, say, a `KtRosterEntry::signing_payload()` as the "nonce" and get
//! the victim's client to sign it unattended on the next reconnect.
//!
//! This test locks the property down structurally rather than by inspection. The
//! argument is:
//!
//! 1. Every signing context's payload **starts with its own domain prefix**.
//! 2. No domain prefix is a **prefix of** any other.
//!
//! Together those imply no two contexts can ever produce the same bytes — for *any*
//! inputs, including attacker-chosen ones. The failure mode this guards against is not
//! "today's code is wrong", it is "someone adds a new signing context next year whose
//! prefix happens to collide", which is why (2) is asserted over a registry that a new
//! context has to be added to.
//!
//! This crate is the test's home because it is the one that depends on both
//! `protocol-types` and `kt-log`.

use kt_log::{DeviceRecord, GroupEpoch, GroupMemberEntry, KtEntry, KtRosterEntry};
use protocol_types::{
    account_delete_signing_message, call_key_publish_signing_message, kt_leaves_signing_message,
    one_time_keys_signing_message, push_register_signing_message, push_unregister_signing_message,
    ws_auth_signing_message,
};

/// The domain separator of the WebSocket login challenge. Any change here is a breaking
/// wire change; the constant is duplicated on purpose so an accidental edit to
/// `ws_auth_signing_message` fails this test instead of silently shipping.
const WS_AUTH_DOMAIN: &str = "sona-ws-auth-v1|";

/// Every domain-separator prefix under which something is **signed** in this tree.
///
/// Add a new entry here whenever a new signing context is introduced — the pairwise
/// test below is what makes the prefixes safe to concatenate with attacker-influenced
/// data. (Non-signing tags — ALPN strings, AEAD `info` labels, mailbox-derivation
/// prefixes — are deliberately out of scope: nothing verifies a signature over them.)
const SIGNING_DOMAINS: &[&str] = &[
    "sona-ws-auth-v1|",          // WebSocket / mailbox login challenge  (this file)
    "sona-register-v1|",         // server::auth::registration_message
    "sona-otk-upload-v1|",       // protocol_types::one_time_keys_signing_message
    "sona-push-register-v1|",    // protocol_types::push_register_signing_message
    "sona-push-unregister-v1|",  // protocol_types::push_unregister_signing_message
    "sona-call-key-publish-v1|", // protocol_types::call_key_publish_signing_message
    "sona-account-delete-v1|",   // protocol_types::account_delete_signing_message
    "sona-kt-leaves-v1|",        // protocol_types::kt_leaves_signing_message
    "sona-kt-entry-v1",          // kt_log::KtEntry::signing_payload
    "sona-kt-roster-v1",         // kt_log::KtRosterEntry::signing_payload
    "sona-kt-device-v1",         // kt_log::DeviceRecord::signing_payload
    "sona-kt-leaf-roster-v1|",   // kt_log::KtRosterEntry::leaf_bytes
    "sona-kt-sth-v1",            // kt_log::SignedTreeHead
    "sona-call-key-v1",          // kt_log::CallKeyBinding::signing_payload
    "sona-group-epoch-v1",       // kt_log::GroupEpoch::signing_payload
    "sona-call-capsule-v1",      // client_core::CallCapsule::signing_payload
];

/// (2) above: no prefix is a prefix of another. This is the property that makes the
/// whole scheme work, and the one that regresses silently when a context is added.
#[test]
fn signing_domains_are_pairwise_prefix_free() {
    for (i, a) in SIGNING_DOMAINS.iter().enumerate() {
        for (j, b) in SIGNING_DOMAINS.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !a.starts_with(b),
                "signing domain {a:?} starts with {b:?} — a payload in one context could \
                 be mistaken for the other; give it a distinct prefix",
            );
        }
    }
}

#[test]
fn ws_auth_message_is_domain_separated_and_binds_the_mailbox() {
    let m = ws_auth_signing_message("aa".repeat(32).as_str(), "bm9uY2U");
    assert!(m.starts_with(WS_AUTH_DOMAIN.as_bytes()));

    // The mailbox hash must be bound in: without it, a signature harvested from one
    // mailbox authenticates any other mailbox the relay controls.
    let a = ws_auth_signing_message("aa".repeat(32).as_str(), "bm9uY2U");
    let b = ws_auth_signing_message("bb".repeat(32).as_str(), "bm9uY2U");
    assert_ne!(a, b);
    // And the nonce must be bound in, or every login for one mailbox signs the same bytes.
    let c = ws_auth_signing_message("aa".repeat(32).as_str(), "b3RoZXI");
    assert_ne!(a, c);
}

/// (1) above, for every context reachable from this crate's dependencies: the payload
/// really does start with the registered prefix.
#[test]
fn every_signing_context_starts_with_its_registered_domain() {
    let hash = "aa".repeat(32);
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let unsigned = |_: &[u8]| String::new();

    let device = DeviceRecord::new(
        &hash,
        "0".into(),
        key.into(),
        key.into(),
        1_700_000_000,
        unsigned,
    );
    let roster = KtRosterEntry::new(
        0,
        hash.clone(),
        vec![device.clone()],
        1_700_000_000,
        unsigned,
    );
    let entry = KtEntry::new_claim(
        hash.clone(),
        key.into(),
        key.into(),
        1_700_000_000,
        unsigned,
    );
    let epoch = GroupEpoch::genesis(
        "group".into(),
        vec![GroupMemberEntry {
            username: "alice".into(),
            identity_key: key.into(),
        }],
        key.into(),
        key.into(),
        1_700_000_000,
        unsigned,
    );

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "sona-ws-auth-v1|",
            ws_auth_signing_message(&hash, "bm9uY2U"),
        ),
        (
            "sona-otk-upload-v1|",
            one_time_keys_signing_message(&hash, &[key.to_string()]),
        ),
        (
            "sona-push-register-v1|",
            push_register_signing_message(&hash, "https://push.example/x", "bm9uY2U"),
        ),
        (
            "sona-push-unregister-v1|",
            push_unregister_signing_message(&hash, "bm9uY2U"),
        ),
        (
            "sona-call-key-publish-v1|",
            call_key_publish_signing_message(&hash, key, 1_700_000_000, "bm9uY2U"),
        ),
        (
            "sona-account-delete-v1|",
            account_delete_signing_message(&hash, std::slice::from_ref(&hash), "bm9uY2U"),
        ),
        (
            "sona-kt-leaves-v1|",
            kt_leaves_signing_message(&hash, "bm9uY2U"),
        ),
        ("sona-kt-entry-v1", entry.signing_payload()),
        ("sona-kt-roster-v1", roster.signing_payload()),
        ("sona-kt-device-v1", device.signing_payload(&hash)),
        ("sona-kt-leaf-roster-v1|", roster.leaf_bytes()),
        ("sona-group-epoch-v1", epoch.signing_payload()),
    ];

    for (domain, payload) in &cases {
        assert!(
            SIGNING_DOMAINS.contains(domain),
            "{domain:?} is not in the SIGNING_DOMAINS registry",
        );
        assert!(
            payload.starts_with(domain.as_bytes()),
            "payload for {domain:?} does not start with its domain separator",
        );
    }

    // The conclusion (1)+(2) buys us, stated directly for the context that matters: no
    // other signing payload can ever be handed to the client as a login "nonce" and come
    // back as a valid signature for that other context.
    for (domain, payload) in &cases {
        if *domain == WS_AUTH_DOMAIN {
            continue;
        }
        assert!(
            !payload.starts_with(WS_AUTH_DOMAIN.as_bytes()),
            "{domain:?} payload collides with the login challenge domain",
        );
    }
}

/// Attacker-chosen inputs: the relay picks the nonce and (via a squatted username) can
/// influence the hash, so feed both the exact bytes it would most like to forge.
#[test]
fn attacker_controlled_fields_cannot_forge_a_login_message() {
    let hash = "aa".repeat(32);
    let unsigned = |_: &[u8]| String::new();

    // A username hash and device id that literally spell the login domain still cannot
    // move the roster payload's first bytes — the prefix is emitted before any field.
    let hostile = format!("{WS_AUTH_DOMAIN}{hash}");
    let device = DeviceRecord::new(
        &hostile,
        WS_AUTH_DOMAIN.into(),
        "k".into(),
        "k".into(),
        0,
        unsigned,
    );
    let roster = KtRosterEntry::new(0, hostile.clone(), vec![device.clone()], 0, unsigned);
    for payload in [
        roster.signing_payload(),
        roster.leaf_bytes(),
        device.signing_payload(&hostile),
    ] {
        assert!(!payload.starts_with(WS_AUTH_DOMAIN.as_bytes()));
    }

    // And the reverse direction: a nonce that spells another context's domain cannot
    // make the login message *be* that context's payload, because the login prefix
    // comes first.
    let m = ws_auth_signing_message(&hash, "sona-kt-roster-v1");
    for d in SIGNING_DOMAINS {
        if *d == WS_AUTH_DOMAIN {
            continue;
        }
        assert!(!m.starts_with(d.as_bytes()));
    }
}
