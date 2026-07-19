use crate::*;

impl Client {
    /// Discover a contact by username: fetch their bundle, **prove via Key Transparency**
    /// that the offered key is the one published for that name, and compute the safety
    /// number — but do NOT start a session yet. Lets the caller check the key against a
    /// previously-pinned one before trusting it.
    pub async fn discover(&self, account: &Account, username: &str) -> Result<Discovered> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();

        let resp = self
            .http
            .get(format!("{}/v1/bundle/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::UserNotFound);
        }
        let bundle: PreKeyBundle = resp.error_for_status()?.json().await?;

        let resp = self
            .http
            .get(format!("{}/v1/kt/proof/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ClientError::UserNotFound);
        }
        let proof: KtProofResponse = resp.error_for_status()?.json().await?;

        // The gate: trust nothing the server said, verify the proof against the pinned key.
        let check = verify_contact_binding(
            &self.pinned_kt_key,
            &hash,
            &bundle.identity_key,
            &proof.entry,
            proof.index,
            &proof.proof_b64,
            &proof.sth,
        );
        if check != KtCheck::Verified {
            return Err(ClientError::KtVerification(check));
        }

        let safety = safety_number(&account.ratchet_ref().identity_key(), &bundle.identity_key);
        Ok(Discovered {
            username: username.to_string(),
            identity_hash: hash,
            identity_key: bundle.identity_key.clone(),
            safety_number: safety,
            bundle,
        })
    }

    /// Establish an outbound session from a [`Discovered`] contact.
    pub fn start_session(&self, account: &mut Account, d: &Discovered) -> Result<Contact> {
        account
            .ratchet()
            .establish_outbound(&d.bundle)
            .map_err(|e| ClientError::Crypto(e.to_string()))?;
        Ok(Contact {
            username: d.username.clone(),
            identity_hash: d.identity_hash.clone(),
            identity_key: d.identity_key.clone(),
            safety_number: d.safety_number.clone(),
        })
    }

    /// Discover a contact and start a session (KT-verified). Convenience for the common
    /// first-contact path; use [`add_contact_checked`](Self::add_contact_checked) when you
    /// have a previously-pinned key to guard against a silent key change.
    pub async fn add_contact(&self, account: &mut Account, username: &str) -> Result<Contact> {
        let d = self.discover(account, username).await?;
        self.start_session(account, &d)
    }

    /// KT-verified discovery that also guards against a **key change**. Pass the key you
    /// previously pinned for this contact (or `None` for first contact):
    ///
    /// * first contact → [`ContactOutcome::New`] (session started; caller should pin the key),
    /// * key unchanged → [`ContactOutcome::Unchanged`] (session started),
    /// * key differs → [`ContactOutcome::KeyChanged`] — **no session is started**; the
    ///   caller must have the user compare the new safety number and explicitly accept
    ///   before calling [`add_contact`](Self::add_contact) to proceed.
    pub async fn add_contact_checked(
        &self,
        account: &mut Account,
        username: &str,
        known_key: Option<&str>,
    ) -> Result<ContactOutcome> {
        // First check the KT log alone — the proof endpoint is enough to detect a key
        // change and to confirm an unchanged binding. Fetching the *bundle* consumes one
        // of the contact's one-time keys, so we only do that when we actually need to
        // establish a session (first contact, or a session that went missing).
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        let logged = self.fetch_verified_entry(&hash).await?;
        match known_key {
            Some(k) if k != logged.identity_key => Ok(ContactOutcome::KeyChanged {
                username: username.to_string(),
                previous_identity_key: k.to_string(),
                new_identity_key: logged.identity_key.clone(),
                new_safety_number: safety_number(
                    &account.ratchet_ref().identity_key(),
                    &logged.identity_key,
                ),
            }),
            Some(k) if account.ratchet_ref().has_session(k) => {
                // Known key, live session: nothing to fetch, no one-time key to burn.
                Ok(ContactOutcome::Unchanged(Contact {
                    username: username.to_string(),
                    identity_hash: hash,
                    identity_key: k.to_string(),
                    safety_number: safety_number(&account.ratchet_ref().identity_key(), k),
                }))
            }
            Some(_) => {
                let d = self.discover(account, username).await?;
                Ok(ContactOutcome::Unchanged(self.start_session(account, &d)?))
            }
            None => {
                let d = self.discover(account, username).await?;
                Ok(ContactOutcome::New(self.start_session(account, &d)?))
            }
        }
    }
}
