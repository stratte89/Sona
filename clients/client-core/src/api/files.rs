use crate::*;

impl Client {
    /// Send a file to a contact. The file is encrypted client-side with a fresh random
    /// key; only the ciphertext is uploaded to the relay (opaque, the server can't read
    /// it), and the key + reference are sent inside the ratchet so only the recipient
    /// learns them. Returns the message id, timestamp, and blob id.
    pub async fn send_file(
        &self,
        account: &mut Account,
        contact: &Contact,
        filename: &str,
        data: &[u8],
    ) -> Result<SentAttachment> {
        let attachment = self.upload_attachment(filename, data).await?;
        let blob_id = attachment.blob_id.clone();
        let prepared = self.prepare_attachment(account, contact, attachment, None, false)?;
        self.post_envelope(&prepared.envelope).await?;
        Ok(SentAttachment {
            msg_id: prepared.msg_id,
            sent_at: prepared.sent_at,
            blob_id,
        })
    }
    /// Encrypt + pad + upload a file as an opaque relay blob. Needs **no account state**
    /// (fresh random key), so a caller can run the slow upload outside any account lock.
    /// Returns the [`AttachmentRef`] to send end-to-end with
    /// [`prepare_attachment`](Self::prepare_attachment).
    pub async fn upload_attachment(&self, filename: &str, data: &[u8]) -> Result<AttachmentRef> {
        use sha2::{Digest, Sha256};

        // Encrypt the file with a random per-attachment key, then pad to a size bucket so
        // the blob length reveals only a coarse bucket. The hash covers what is stored.
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let padded = padding::pad(&crypto_core::localbox::seal(&key, data));
        let content_hash = STANDARD_NO_PAD.encode(Sha256::digest(&padded));

        let resp = self
            .http
            .post(format!("{}/v1/blobs", self.base_url))
            .body(padded)
            .send()
            .await?
            .error_for_status()?;
        let blob: Value = resp.json().await?;
        let blob_id = blob["blob_id"]
            .as_str()
            .ok_or_else(|| ClientError::Protocol("missing blob_id".into()))?
            .to_string();

        Ok(AttachmentRef {
            blob_id,
            key: STANDARD_NO_PAD.encode(key),
            filename: filename.to_string(),
            size: data.len(),
            content_hash,
            ts: now(),
            voice: false,
            duration_secs: 0,
            caption: None,
            peaks: Vec::new(),
        })
    }
    /// Encrypt an attachment reference (key + blob id) into an envelope for a contact —
    /// fast, no network. Post with [`Client::post_envelope`].
    /// `forwarded` marks it as forwarded from another conversation ("Forwarded" tag).
    pub fn prepare_attachment(
        &self,
        account: &mut Account,
        contact: &Contact,
        attachment: AttachmentRef,
        expire_secs: Option<u64>,
        forwarded: bool,
    ) -> Result<PreparedMessage> {
        let sent_at = attachment.ts;
        let payload = ChatPayload::File {
            fwd: forwarded,
            attachment,
            from: account.account_id().to_string(),
            expire_secs,
        };
        let envelope = build_envelope(account, contact, &payload)?;
        let msg_id = envelope.msg_id.clone();
        Ok(PreparedMessage {
            envelope,
            msg_id,
            sent_at,
        })
    }
    /// Download and decrypt an attachment referenced by an [`AttachmentRef`]. Verifies the
    /// ciphertext hash before decrypting, so a swapped/corrupt blob is rejected.
    pub async fn download_attachment(&self, attachment: &AttachmentRef) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        // A malicious relay could serve an unbounded body; buffer the download under a hard
        // ceiling so a bad blob can't exhaust memory. The server caps uploads at 10 MiB —
        // we don't trust that, but the ceiling stays generously above any legitimate blob.
        const MAX_ATTACHMENT_DOWNLOAD_BYTES: usize = 12 * 1024 * 1024;
        let mut resp = self
            .http
            .get(format!("{}/v1/blobs/{}", self.base_url, attachment.blob_id))
            .send()
            .await?
            .error_for_status()?;
        let mut padded: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if padded.len() + chunk.len() > MAX_ATTACHMENT_DOWNLOAD_BYTES {
                return Err(ClientError::Protocol("attachment blob too large".into()));
            }
            padded.extend_from_slice(&chunk);
        }
        // Integrity: the blob must be exactly the one the sender referenced.
        if STANDARD_NO_PAD.encode(Sha256::digest(&padded)) != attachment.content_hash {
            return Err(ClientError::Protocol("attachment hash mismatch".into()));
        }
        // Strip the length padding to recover the ciphertext, then decrypt.
        let ciphertext = padding::unpad(&padded)
            .ok_or_else(|| ClientError::Protocol("bad attachment padding".into()))?;
        let key: [u8; 32] = STANDARD_NO_PAD
            .decode(&attachment.key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ClientError::Protocol("bad attachment key".into()))?;
        crypto_core::localbox::open(&key, &ciphertext)
            .ok_or_else(|| ClientError::Crypto("attachment decryption failed".into()))
    }
}
