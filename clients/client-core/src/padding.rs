//! Length padding for end-to-end payloads.
//!
//! A ratchet ciphertext is roughly as long as its plaintext, so an observer (the server,
//! or the network) can infer message length — "ok" vs a paragraph — even though the
//! content is encrypted. Padding buckets every payload up to a fixed size before
//! encryption, so all short messages look identical on the wire and longer ones only
//! reveal a coarse bucket.
//!
//! Format: `[u32 be real_len][payload][zero padding]`, sized to the next bucket. The
//! recipient reads `real_len` and slices the payload back out. Buckets start at 256 bytes
//! and grow ~1.25× (the scheme Signal uses), so length leaks at most log-scale coarseness.

const MIN_BUCKET: usize = 256;
const PREFIX: usize = 4;

/// The bucket size (>= `n`) a payload of `n` bytes is padded to.
fn bucket_size(n: usize) -> usize {
    let mut b = MIN_BUCKET;
    while b < n {
        b += b / 4; // grow ~1.25×
    }
    b
}

/// Pad `data` to its bucket, prefixed with its real length.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let bucket = bucket_size(PREFIX + data.len());
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(bucket, 0);
    out
}

/// Recover the original bytes from a padded buffer. `None` if malformed.
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < PREFIX {
        return None;
    }
    let len = u32::from_be_bytes(padded[0..PREFIX].try_into().ok()?) as usize;
    let end = PREFIX.checked_add(len)?;
    if end > padded.len() {
        return None;
    }
    Some(padded[PREFIX..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for data in [
            &b""[..],
            b"hi",
            b"a longer message but still small",
            &[7u8; 1000][..],
        ] {
            assert_eq!(unpad(&pad(data)).unwrap(), data);
        }
    }

    #[test]
    fn short_messages_share_one_bucket() {
        // Two very different short messages must be indistinguishable by length.
        let a = pad(b"ok");
        let b = pad(b"this is a considerably longer sentence, still under the bucket");
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), MIN_BUCKET);
    }

    #[test]
    fn buckets_grow_coarsely_and_cover_input() {
        // Every bucket must fit its input, and lengths quantize (few distinct sizes).
        let mut sizes = std::collections::BTreeSet::new();
        for n in 0..2000 {
            let p = pad(&vec![0u8; n]);
            assert!(p.len() >= PREFIX + n);
            sizes.insert(p.len());
        }
        assert!(
            sizes.len() < 20,
            "too many distinct padded lengths: {}",
            sizes.len()
        );
    }

    #[test]
    fn malformed_is_rejected() {
        assert!(unpad(&[0, 0]).is_none()); // too short for prefix
        assert!(unpad(&[0, 0, 0, 255, 1, 2]).is_none()); // claims 255 bytes, has 2
    }
}
