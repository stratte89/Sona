//! Android hardware key attestation for device linking (docs/MULTI_DEVICE.md §"Hardware
//! attestation").
//!
//! When a new Android device builds its [`LinkRequest`](crate::LinkRequest), it can mint
//! an **ephemeral Keystore key** whose attestation challenge is bound to the request
//! (`link_attest_challenge`) and attach the resulting certificate chain. The primary
//! verifies the chain here before the user confirms the link:
//!
//! * the chain's signatures are valid and terminate at a **pinned Google hardware
//!   attestation root** (the two published roots, fetched 2026-07-18 from
//!   `https://android.googleapis.com/attestation/root`);
//! * the leaf's attestation extension carries **our exact challenge** — so the chain was
//!   minted for THIS link request and this device key, not replayed from anywhere else;
//! * the attestation **security level is TEE or StrongBox** — the statement itself was
//!   produced inside secure hardware, which an emulator or a software keystore cannot do.
//!
//! What this proves: the linking device is *genuine Android hardware with a secure
//! element/TEE*, not an emulator or a scripted client replaying extracted key material.
//! What it does NOT prove: that the hardware is friendly (malware on a real phone can
//! attest fine), or anything at all on iOS/desktop linkers — absence of attestation is
//! normal there, so the verdict is advisory UI, never a hard gate.
//!
//! Verified-boot policy: the root-of-trust boot state is *surfaced*, not enforced.
//! GrapheneOS (locked bootloader, own AVB key) reports `SelfSigned` — treating that as a
//! failure would punish exactly the devices with the strongest posture. The UI shows the
//! state and the boot key hash; the user decides.
//!
//! No CRL fetch: Google's attestation status list lives at a Google URL, and hitting it
//! from the primary at scan time would leak the linking ceremony (and defeat a Tor
//! routing) to a third party. Pinned roots + challenge freshness bound the risk.

use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// OID of the Android key attestation extension.
const ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Pinned SubjectPublicKeyInfo (DER) of the Google hardware attestation roots.
/// RSA-4096 root (serial f92009e853b6b045, in use since 2016) and the P-384 "Key
/// Attestation CA1" root (active from 2026-02).
const GOOGLE_ROOT_SPKI_B64: [&str; 2] = [
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==",
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr",
];

/// The challenge a linking device must bake into its attestation: bound to the device id
/// and the device's identity key, so a chain minted for one link request proves nothing
/// about any other. Domain-separated; both sides compute it from the [`LinkRequest`]
/// fields alone.
pub fn link_attest_challenge(device_id: &str, identity_key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sona-link-attest-v1\0");
    h.update(device_id.as_bytes());
    h.update(b"\0");
    h.update(identity_key.as_bytes());
    h.finalize().into()
}

/// Where the attestation statement was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Software keymaster — no hardware claim at all. Surfaced as a failure by policy.
    Software,
    /// Trusted Execution Environment (every certified Android device).
    Tee,
    /// Discrete secure element (Pixel Titan M/M2 and similar).
    StrongBox,
}

/// Root-of-trust verified-boot state from the attestation extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootState {
    /// Stock OS, locked bootloader, OEM key.
    Verified,
    /// Locked bootloader with a user-set AVB key — GrapheneOS and friends land here.
    SelfSigned,
    /// Unlocked bootloader.
    Unverified,
    Failed,
}

/// A successfully verified attestation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwAttestation {
    pub security_level: SecurityLevel,
    /// Boot state / bootloader-lock / verified-boot-key from the hardware-enforced
    /// root of trust; absent when the extension omits it.
    pub boot_state: Option<BootState>,
    pub device_locked: Option<bool>,
    /// SHA-256 of the verified boot key, hex — lets a user recognize e.g. the
    /// GrapheneOS signing key out-of-band.
    pub verified_boot_key_sha256: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("empty or undecodable certificate chain")]
    BadChain,
    #[error("certificate signature verification failed")]
    BadSignature,
    #[error("chain does not terminate at a pinned attestation root")]
    UntrustedRoot,
    #[error("certificate outside its validity window")]
    Expired,
    #[error("leaf carries no attestation extension")]
    NoExtension,
    #[error("attestation extension is malformed")]
    BadExtension,
    #[error("attestation challenge does not match this link request")]
    ChallengeMismatch,
    #[error("attestation was produced by a software keymaster, not hardware")]
    SoftwareLevel,
    #[error("issuing certificate is not a CA")]
    NotCa,
}

/// Verify an attestation chain (base64 DER certificates, leaf first) against the pinned
/// Google roots. See the module docs for exactly what a success does and does not prove.
pub fn verify_hw_attestation(
    chain_b64: &[String],
    expected_challenge: &[u8],
) -> Result<HwAttestation, AttestError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let roots: Vec<Vec<u8>> = GOOGLE_ROOT_SPKI_B64
        .iter()
        .map(|b| STANDARD.decode(b).expect("pinned root spki decodes"))
        .collect();
    let root_refs: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    verify_hw_attestation_with_roots(chain_b64, expected_challenge, &root_refs)
}

/// [`verify_hw_attestation`] with caller-supplied root SPKIs (DER) — exposed for tests.
pub fn verify_hw_attestation_with_roots(
    chain_b64: &[String],
    expected_challenge: &[u8],
    roots_spki_der: &[&[u8]],
) -> Result<HwAttestation, AttestError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    if chain_b64.is_empty() || chain_b64.len() > 8 {
        return Err(AttestError::BadChain);
    }
    let ders: Vec<Vec<u8>> = chain_b64
        .iter()
        .map(|b| STANDARD.decode(b.trim()).map_err(|_| AttestError::BadChain))
        .collect::<Result<_, _>>()?;
    let certs: Vec<X509Certificate> = ders
        .iter()
        .map(|d| {
            X509Certificate::from_der(d)
                .map(|(_, c)| c)
                .map_err(|_| AttestError::BadChain)
        })
        .collect::<Result<_, _>>()?;

    // Each certificate must be inside its validity window (batch attestation certs are
    // long-lived; remotely-provisioned leaves are short-lived by design)…
    let now = x509_parser::time::ASN1Time::now();
    if certs.iter().any(|c| !c.validity().is_valid_at(now)) {
        return Err(AttestError::Expired);
    }
    // …and signed by the next one up. The last cert must be the (self-signed) root.
    // Every ISSUING certificate (everything above the leaf) must also assert CA=true in
    // BasicConstraints. Without this check, an attested leaf key — which its owner can
    // sign arbitrary bytes with through the ordinary Keystore API — could itself "issue"
    // a forged leaf claiming any challenge and security level, and the forged chain
    // [fake_leaf, real_leaf, …, root] would verify all the way to the pinned root.
    // Real Android chains always mark the intermediates and root as CAs.
    for i in 0..certs.len() {
        let issuer = if i + 1 < certs.len() {
            &certs[i + 1]
        } else {
            &certs[i]
        };
        match issuer.basic_constraints() {
            Ok(Some(bc)) if bc.value.ca => {}
            _ => return Err(AttestError::NotCa),
        }
        certs[i]
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| AttestError::BadSignature)?;
    }
    // Pin: the terminating cert's SubjectPublicKeyInfo must be a known root. (Comparing
    // the SPKI rather than the whole certificate tolerates root re-issuance.)
    let last_spki = certs.last().expect("nonempty").public_key().raw;
    if !roots_spki_der.contains(&last_spki) {
        return Err(AttestError::UntrustedRoot);
    }

    // Attestation extension lives in the LEAF.
    let ext = certs[0]
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == ATTESTATION_OID)
        .ok_or(AttestError::NoExtension)?;
    let kd = parse_key_description(ext.value)?;
    if kd.challenge != expected_challenge {
        return Err(AttestError::ChallengeMismatch);
    }
    let security_level = match kd.security_level {
        1 => SecurityLevel::Tee,
        2 => SecurityLevel::StrongBox,
        _ => return Err(AttestError::SoftwareLevel),
    };
    Ok(HwAttestation {
        security_level,
        boot_state: kd.boot_state.map(|s| match s {
            0 => BootState::Verified,
            1 => BootState::SelfSigned,
            2 => BootState::Unverified,
            _ => BootState::Failed,
        }),
        device_locked: kd.device_locked,
        verified_boot_key_sha256: kd.verified_boot_key.map(|k| hex_lower(&Sha256::digest(&k))),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Minimal DER walk of the KeyDescription extension ─────────────────────────────────
//
// KeyDescription ::= SEQUENCE {
//   attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
//   keymasterVersion INTEGER,   keymasterSecurityLevel ENUMERATED,
//   attestationChallenge OCTET_STRING, uniqueId OCTET_STRING,
//   softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
//
// AuthorizationList is a SEQUENCE of EXPLICIT context-tagged fields; rootOfTrust is
// tag [704]: SEQUENCE { verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN,
// verifiedBootState ENUMERATED, verifiedBootHash OCTET_STRING OPTIONAL }.
//
// A tiny hand-rolled reader keeps this parse exact and dependency-free: it reads only
// the fields above and ignores everything else by length.

struct KeyDescription {
    security_level: u64,
    challenge: Vec<u8>,
    boot_state: Option<u64>,
    device_locked: Option<bool>,
    verified_boot_key: Option<Vec<u8>>,
}

/// One decoded DER TLV: (tag_class_and_number, constructed, value, rest).
type DerTlv<'a> = (u32, bool, &'a [u8], &'a [u8]);

/// One DER TLV.
fn der_tlv(input: &[u8]) -> Result<DerTlv<'_>, AttestError> {
    let e = AttestError::BadExtension;
    if input.len() < 2 {
        return Err(e);
    }
    let first = input[0];
    let constructed = first & 0x20 != 0;
    let mut idx = 1;
    let mut tag_num: u32 = (first & 0x1f) as u32;
    if tag_num == 0x1f {
        // High-tag-number form (rootOfTrust's 704 needs it).
        tag_num = 0;
        loop {
            let b = *input.get(idx).ok_or(AttestError::BadExtension)?;
            idx += 1;
            tag_num =
                tag_num.checked_mul(128).ok_or(AttestError::BadExtension)? + (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let mut len_byte = *input.get(idx).ok_or(AttestError::BadExtension)? as usize;
    idx += 1;
    if len_byte & 0x80 != 0 {
        let n = len_byte & 0x7f;
        if n == 0 || n > 4 {
            return Err(AttestError::BadExtension);
        }
        len_byte = 0;
        for _ in 0..n {
            len_byte = len_byte << 8 | *input.get(idx).ok_or(AttestError::BadExtension)? as usize;
            idx += 1;
        }
    }
    let end = idx.checked_add(len_byte).ok_or(AttestError::BadExtension)?;
    if end > input.len() {
        return Err(AttestError::BadExtension);
    }
    // Tag class in the top 2 bits keeps context tags distinct from universal ones.
    let class = (first >> 6) as u32;
    Ok((
        class << 24 | tag_num,
        constructed,
        &input[idx..end],
        &input[end..],
    ))
}

/// Split a constructed value into its child TLVs (tag, value) in order.
fn der_children(mut v: &[u8]) -> Result<Vec<(u32, &[u8])>, AttestError> {
    let mut out = Vec::new();
    while !v.is_empty() {
        let (tag, _, val, rest) = der_tlv(v)?;
        out.push((tag, val));
        v = rest;
    }
    Ok(out)
}

fn der_uint(v: &[u8]) -> Result<u64, AttestError> {
    if v.is_empty() || v.len() > 8 {
        return Err(AttestError::BadExtension);
    }
    Ok(v.iter().fold(0u64, |a, b| a << 8 | *b as u64))
}

const CTX: u32 = 2 << 24; // context class marker from der_tlv

fn parse_key_description(ext: &[u8]) -> Result<KeyDescription, AttestError> {
    let (tag, _, seq, _) = der_tlv(ext)?;
    if tag != 0x10 {
        return Err(AttestError::BadExtension); // not a SEQUENCE
    }
    let fields = der_children(seq)?;
    if fields.len() < 8 {
        return Err(AttestError::BadExtension);
    }
    // fields: 0 ver, 1 secLevel, 2 kmVer, 3 kmSecLevel, 4 challenge, 5 uniqueId,
    //         6 softwareEnforced, 7 hardwareEnforced
    let security_level = der_uint(fields[1].1)?;
    let challenge = fields[4].1.to_vec();
    let mut boot_state = None;
    let mut device_locked = None;
    let mut verified_boot_key = None;
    // rootOfTrust ([704]) is hardware-enforced; an entry in softwareEnforced instead
    // would be a software keymaster's claim, which the security-level check already
    // rejects — only field 7 is read.
    for (tag, val) in der_children(fields[7].1)? {
        if tag == CTX | 704 {
            let (stag, _, rot, _) = der_tlv(val)?;
            if stag != 0x10 {
                return Err(AttestError::BadExtension);
            }
            let rot = der_children(rot)?;
            if rot.len() < 3 {
                return Err(AttestError::BadExtension);
            }
            verified_boot_key = Some(rot[0].1.to_vec());
            device_locked = Some(!matches!(rot[1].1, [0]));
            boot_state = Some(der_uint(rot[2].1)?);
        }
    }
    Ok(KeyDescription {
        security_level,
        challenge,
        boot_state,
        device_locked,
        verified_boot_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    /// DER-encode one TLV with a small tag.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            let l = content.len();
            out.push(0x82);
            out.push((l >> 8) as u8);
            out.push(l as u8);
        }
        out.extend_from_slice(content);
        out
    }

    /// Context tag 704, high-tag-number form (0xBF 0x85 0x40).
    fn tag704(content: &[u8]) -> Vec<u8> {
        let mut out = vec![0xbf, 0x85, 0x40, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    /// Build a KeyDescription extension: given security level, challenge, boot state.
    fn key_description(level: u8, challenge: &[u8], boot: Option<(u8, bool)>) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend(tlv(0x02, &[4])); // attestationVersion
        inner.extend(tlv(0x0a, &[level])); // attestationSecurityLevel
        inner.extend(tlv(0x02, &[41])); // keymasterVersion
        inner.extend(tlv(0x0a, &[level])); // keymasterSecurityLevel
        inner.extend(tlv(0x04, challenge)); // attestationChallenge
        inner.extend(tlv(0x04, &[])); // uniqueId
        inner.extend(tlv(0x30, &[])); // softwareEnforced (empty)
        let hw = match boot {
            None => tlv(0x30, &[]),
            Some((state, locked)) => {
                let mut rot = Vec::new();
                rot.extend(tlv(0x04, &[0xab; 32])); // verifiedBootKey
                rot.extend(tlv(0x01, &[if locked { 0xff } else { 0 }])); // deviceLocked
                rot.extend(tlv(0x0a, &[state])); // verifiedBootState
                let rot_seq = tlv(0x30, &rot);
                tlv(0x30, &tag704(&rot_seq))
            }
        };
        inner.extend(hw);
        tlv(0x30, &inner)
    }

    /// Mint a (root, leaf-with-extension) chain; returns (chain_b64 leaf-first, root SPKI).
    fn chain(ext_der: &[u8]) -> (Vec<String>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec![]).unwrap();
        leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            ext_der.to_vec(),
        )];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();
        (
            vec![
                STANDARD.encode(leaf_cert.der()),
                STANDARD.encode(root_cert.der()),
            ],
            root_key.public_key_der(),
        )
    }

    // The leaf-as-issuer forgery: an attested key's owner CAN sign arbitrary bytes with
    // it (PURPOSE_SIGN through the Keystore API), so a real leaf must never be accepted
    // as the issuer of a forged leaf claiming a different challenge/security level. The
    // CA basic-constraints check is what stops it.
    #[test]
    fn leaf_signed_forgery_is_rejected() {
        use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
        let target_challenge = link_attest_challenge("victim-device", "victim-key");

        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // The attacker's OWN legitimately-attested leaf (some other challenge, NOT a CA
        // — exactly how real attestation leaves look).
        let real_leaf_key = KeyPair::generate().unwrap();
        let mut real_leaf_params = CertificateParams::new(vec![]).unwrap();
        real_leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(1, &[0x55; 32], None),
        )];
        let real_leaf = real_leaf_params
            .signed_by(&real_leaf_key, &root_cert, &root_key)
            .unwrap();

        // Forged leaf: claims the victim's challenge at StrongBox level, "issued" by the
        // attacker's real leaf key.
        let mut fake_params = CertificateParams::new(vec![]).unwrap();
        fake_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(2, &target_challenge, Some((0, true))),
        )];
        let fake_key = KeyPair::generate().unwrap();
        let fake_leaf = fake_params
            .signed_by(&fake_key, &real_leaf, &real_leaf_key)
            .unwrap();

        let forged = vec![
            STANDARD.encode(fake_leaf.der()),
            STANDARD.encode(real_leaf.der()),
            STANDARD.encode(root_cert.der()),
        ];
        assert_eq!(
            verify_hw_attestation_with_roots(
                &forged,
                &target_challenge,
                &[&root_key.public_key_der()]
            ),
            Err(AttestError::NotCa),
            "a non-CA issuer must be rejected even when every signature verifies"
        );
    }

    #[test]
    fn tee_chain_with_matching_challenge_verifies() {
        let challenge = link_attest_challenge("aabb", "key1");
        let ext = key_description(1, &challenge, Some((1, true)));
        let (chain_b64, root_spki) = chain(&ext);
        let a = verify_hw_attestation_with_roots(&chain_b64, &challenge, &[&root_spki]).unwrap();
        assert_eq!(a.security_level, SecurityLevel::Tee);
        assert_eq!(a.boot_state, Some(BootState::SelfSigned));
        assert_eq!(a.device_locked, Some(true));
        assert!(a.verified_boot_key_sha256.is_some());
    }

    #[test]
    fn strongbox_level_and_missing_root_of_trust_survive() {
        let challenge = [7u8; 32];
        let ext = key_description(2, &challenge, None);
        let (chain_b64, root_spki) = chain(&ext);
        let a = verify_hw_attestation_with_roots(&chain_b64, &challenge, &[&root_spki]).unwrap();
        assert_eq!(a.security_level, SecurityLevel::StrongBox);
        assert_eq!(a.boot_state, None);
    }

    #[test]
    fn wrong_challenge_software_level_and_bad_root_are_rejected() {
        let challenge = [1u8; 32];
        let ext = key_description(1, &challenge, None);
        let (chain_b64, root_spki) = chain(&ext);
        assert_eq!(
            verify_hw_attestation_with_roots(&chain_b64, &[2u8; 32], &[&root_spki]),
            Err(AttestError::ChallengeMismatch)
        );
        // Software keymaster (level 0) must not pass.
        let ext_sw = key_description(0, &challenge, None);
        let (chain_sw, root_sw) = chain(&ext_sw);
        assert_eq!(
            verify_hw_attestation_with_roots(&chain_sw, &challenge, &[&root_sw]),
            Err(AttestError::SoftwareLevel)
        );
        // A chain rooted anywhere but the pins is untrusted — root from a DIFFERENT
        // chain, so signatures still verify but the pin does not match.
        let (_, other_root) = chain(&ext);
        assert_eq!(
            verify_hw_attestation_with_roots(&chain_b64, &challenge, &[&other_root]),
            Err(AttestError::UntrustedRoot)
        );
        // Tampered chain: leaf signed by nobody in the list.
        let mut broken = chain_b64.clone();
        broken.swap(0, 1);
        assert!(verify_hw_attestation_with_roots(&broken, &challenge, &[&root_spki]).is_err());
        // The real-pin entry point rejects a synthetic chain outright.
        assert_eq!(
            verify_hw_attestation(&chain_b64, &challenge),
            Err(AttestError::UntrustedRoot)
        );
    }

    #[test]
    fn challenge_is_domain_separated_and_stable() {
        let a = link_attest_challenge("dev1", "k1");
        assert_eq!(a, link_attest_challenge("dev1", "k1"));
        assert_ne!(a, link_attest_challenge("dev2", "k1"));
        assert_ne!(a, link_attest_challenge("dev1", "k2"));
        // The separator prevents ("ab","c") colliding with ("a","bc").
        assert_ne!(
            link_attest_challenge("ab", "c"),
            link_attest_challenge("a", "bc")
        );
    }
}
