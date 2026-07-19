use crate::*;

impl Client {
    /// The optional protocol surfaces the relay supports. Empty on an old relay (404).
    pub async fn server_capabilities(&self) -> Result<Vec<String>> {
        let resp = self
            .http
            .get(format!("{}/v1/capabilities", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }
        let v: Value = resp.error_for_status()?.json().await?;
        Ok(v["capabilities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }
    /// Search GIFs through the relay's privacy proxy (`CAP_GIF_SEARCH`): the provider
    /// only ever sees the relay, never this client. Returns the relay's slimmed JSON
    /// (`{results: [{url, preview, width, height}], next}`).
    pub async fn gif_search(&self, query: &str, pos: Option<&str>) -> Result<Value> {
        let mut req = self
            .http
            .get(format!("{}/v1/gif/search", self.base_url))
            .query(&[("q", query)]);
        if let Some(pos) = pos.filter(|p| !p.is_empty()) {
            req = req.query(&[("pos", pos)]);
        }
        let resp = req.send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }
    /// Trending GIFs from the relay's pre-loaded cache (`CAP_GIF_SEARCH`): the default
    /// suggestions the GIF tab shows before the user types. Same slimmed shape as
    /// [`Self::gif_search`].
    pub async fn gif_trending(&self) -> Result<Value> {
        let resp = self
            .http
            .get(format!("{}/v1/gif/trending", self.base_url))
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }
    /// Fetch GIF media bytes through the relay proxy (never directly from the
    /// provider). The result is sent on as an ordinary E2E-encrypted attachment.
    pub async fn gif_fetch(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/v1/gif/proxy", self.base_url))
            .query(&[("url", url)])
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.bytes().await?.to_vec())
    }
    /// Publish a device-roster epoch (minted with [`Account::kt_roster_entry`] on the
    /// primary device). The relay appends it to the transparency log — a roster it (or
    /// anyone) tampered with is refused by the log and unverifiable by peers.
    pub async fn publish_roster(&self, roster: &KtRosterEntry) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/v1/kt/roster", self.base_url))
            .json(roster)
            .send()
            .await?;
        ensure_ok(resp).await
    }
    /// Fetch and fully verify a contact's device roster: pinned tree head, Merkle
    /// inclusion of the roster leaf, and semantic validation against the contact's
    /// KT-verified current binding (account signature, per-device proofs of
    /// possession, primary keys matching the logged account keys).
    ///
    /// `Ok(None)` = the account has never published a roster (single-device — encrypt
    /// to the KT entry's key exactly as today). Any verification failure is an error:
    /// treat the roster as untrusted and **fall back to single-device delivery**, never
    /// to an unverified device list.
    pub async fn fetch_verified_roster(&self, username: &str) -> Result<Option<KtRosterEntry>> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        let entry = self.fetch_verified_entry(&hash).await?;

        let resp = self
            .http
            .get(format!("{}/v1/kt/roster/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let v: Value = resp.error_for_status()?.json().await?;
        let roster: KtRosterEntry = serde_json::from_value(v["roster"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let sth: SignedTreeHead = serde_json::from_value(v["sth"].clone())
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let index = v["index"]
            .as_u64()
            .ok_or_else(|| ClientError::Protocol("missing index".into()))?;
        let proof_b64 = v["proof_b64"]
            .as_str()
            .ok_or_else(|| ClientError::Protocol("missing proof".into()))?;

        if !verify_sth_b64(&self.pinned_kt_key, &sth) {
            return Err(ClientError::KtVerification(KtCheck::BadTreeHead));
        }
        if !verify_roster_inclusion_b64(&sth, &roster, index, proof_b64) {
            return Err(ClientError::KtVerification(KtCheck::NotInLog));
        }
        if roster.validate_against(&entry).is_err() {
            return Err(ClientError::KtVerification(KtCheck::KeyMismatch));
        }
        Ok(Some(roster))
    }
    /// Upload an opaque history-sync blob (sealed with [`crypto_core::sync`] — the
    /// relay can read neither the history nor the key). Returns the capability id to
    /// hand to the new device over the linking channel.
    pub async fn upload_sync_blob(&self, blob: Vec<u8>) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/v1/sync", self.base_url))
            .body(blob)
            .send()
            .await?
            .error_for_status()?;
        let v: Value = resp.json().await?;
        v["sync_id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ClientError::Protocol("missing sync_id".into()))
    }
    /// Download a history-sync blob by capability id. Decrypt with
    /// [`crypto_core::sync::open_history`] after the user enters the account
    /// password/PIN (plus the link secret from the linking channel).
    pub async fn download_sync_blob(&self, sync_id: &str) -> Result<Vec<u8>> {
        Ok(self
            .http
            .get(format!("{}/v1/sync/{sync_id}", self.base_url))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }
}
