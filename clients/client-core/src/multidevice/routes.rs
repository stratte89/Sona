use super::*;

/// One device of an account and the mailbox its sealed copies are posted to.
#[derive(Debug, Clone)]
pub struct DeviceRoute {
    pub device_id: String,
    pub identity_key: String,
    /// Mailbox hash — `device_mailbox_hash(account_hash, device_id)`.
    pub mailbox: String,
}

/// What a fresh, KT-verified roster fetch asks the local pin to become.
///
/// Splitting the *fetch* from the *pin* is what lets a shell resolve a roster without
/// holding its session mutex: the network half needs nothing local, and the anti-rollback
/// decision is taken against live [`History`] state at apply time (never against a stale
/// snapshot taken before the fetch).
#[derive(Debug, Clone)]
pub enum RosterUpdate {
    /// The account publishes no roster. Legitimate for a single-device account, and a
    /// **downgrade attempt** when we already pinned one — unless the KT binding advanced
    /// to a different primary key, which is an ownership change the old pin cannot survive.
    Absent {
        primary_key: String,
        binding_seq: u64,
    },
    /// A roster was served and KT-verified (STH + inclusion + binding validation).
    Verified {
        binding_seq: u64,
        seq: u64,
        primary_key: String,
        devices: Vec<RosterDevice>,
    },
    /// A roster was served and proved, but does not validate against the current binding
    /// (e.g. it predates an account-key rotation). Ignored: delivery falls back to the
    /// single KT-bound key, and the existing pin is left untouched.
    Stale,
}

impl History {
    /// Apply a [`RosterUpdate`] to the local pin, fail-closed on rollback.
    pub fn apply_roster_update(
        &mut self,
        username: &str,
        update: &RosterUpdate,
    ) -> std::result::Result<(), RosterRollback> {
        match update {
            RosterUpdate::Stale => Ok(()),
            RosterUpdate::Absent {
                primary_key,
                binding_seq,
            } => {
                let Some(pinned) = self.pinned_roster(username) else {
                    return Ok(());
                };
                // Ownership moved: the (verified) binding advanced past our pin to a new
                // key — a released name taken over by an owner who has not published a
                // roster yet. The old owner's pin no longer applies.
                if &pinned.primary_key != primary_key && *binding_seq > pinned.binding_seq {
                    self.clear_pinned_roster(username);
                    return Ok(());
                }
                // Same owner: an append-only roster is never deleted; a 404 after we
                // pinned one is a downgrade attempt.
                Err(RosterRollback {
                    username: username.to_string(),
                    pinned_seq: pinned.seq,
                    served_seq: 0,
                })
            }
            RosterUpdate::Verified {
                binding_seq,
                seq,
                primary_key,
                devices,
            } => self.pin_roster(username, *binding_seq, *seq, primary_key, devices.clone()),
        }
    }
}

impl Client {
    /// The network half of [`resolve_account_devices`](Client::resolve_account_devices):
    /// fetch and verify the binding and roster, and report what the local pin should
    /// become. Touches no local state, so a shell may call it with every lock released.
    pub async fn fetch_account_devices(
        &self,
        username: &str,
    ) -> Result<(ResolvedDevices, RosterUpdate)> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        let entry = self.fetch_verified_entry(&hash).await?;
        let primary_key = entry.identity_key.clone();
        let single = |primary_key: String, signing_key: String| ResolvedDevices {
            devices: vec![RosterDevice {
                device_id: PRIMARY_DEVICE_ID.to_string(),
                identity_key: primary_key.clone(),
                signing_key,
            }],
            primary_key,
            roster_seq: None,
        };

        let resp = self
            .http
            .get(format!("{}/v1/kt/roster/{hash}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok((
                single(primary_key.clone(), entry.signing_key.clone()),
                RosterUpdate::Absent {
                    primary_key,
                    binding_seq: entry.seq,
                },
            ));
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
            return Err(ClientError::KtVerification(
                crypto_core::kt::KtCheck::BadTreeHead,
            ));
        }
        if !verify_roster_inclusion_b64(&sth, &roster, index, proof_b64) {
            return Err(ClientError::KtVerification(
                crypto_core::kt::KtCheck::NotInLog,
            ));
        }
        if roster.validate_against(&entry).is_err() {
            return Ok((single(primary_key, entry.signing_key), RosterUpdate::Stale));
        }

        let devices: Vec<RosterDevice> = roster
            .devices
            .iter()
            .map(|d| RosterDevice {
                device_id: d.device_id.clone(),
                identity_key: d.identity_key.clone(),
                signing_key: d.signing_key.clone(),
            })
            .collect();
        Ok((
            ResolvedDevices {
                primary_key: primary_key.clone(),
                roster_seq: Some(roster.seq),
                devices: devices.clone(),
            },
            RosterUpdate::Verified {
                binding_seq: entry.seq,
                seq: roster.seq,
                primary_key,
                devices,
            },
        ))
    }

    /// Which of `resolved`'s devices we cannot seal to yet, because no ratchet session
    /// with that device exists. Network-free.
    pub fn missing_device_sessions(
        &self,
        account: &Account,
        username: &str,
        resolved: &ResolvedDevices,
    ) -> Vec<DeviceRoute> {
        let hash = IdentityHash::from_identifier(username).as_str().to_string();
        resolved
            .devices
            .iter()
            .filter(|d| !account.ratchet_ref().has_session(&d.identity_key))
            .filter_map(|d| {
                Some(DeviceRoute {
                    device_id: d.device_id.clone(),
                    identity_key: d.identity_key.clone(),
                    mailbox: self.device_mailbox_from_hash(&hash, &d.device_id).ok()?,
                })
            })
            .collect()
    }

    /// Fetch the prekey bundle of every route, concurrently and bounded. Network only.
    ///
    /// Best effort: a route whose bundle is unreachable — or whose served identity key is
    /// not the roster-verified one — is dropped, so the caller simply cannot address that
    /// device yet. It is never substituted with an unverified key.
    pub async fn fetch_device_bundles(
        &self,
        routes: &[DeviceRoute],
    ) -> Vec<(DeviceRoute, protocol_types::PreKeyBundle)> {
        use futures_util::{stream, StreamExt};
        stream::iter(routes.iter().cloned())
            .map(|route| async move {
                let bundle = self
                    .fetch_device_bundle(&route.mailbox, &route.identity_key)
                    .await
                    .ok()?;
                Some((route, bundle))
            })
            .buffer_unordered(8)
            .filter_map(|fetched| async move { fetched })
            .collect()
            .await
    }

    /// Install the sessions for already-fetched bundles. Network-free; returns how many
    /// new sessions were established.
    pub fn install_device_sessions(
        &self,
        account: &mut Account,
        fetched: &[(DeviceRoute, protocol_types::PreKeyBundle)],
    ) -> usize {
        fetched
            .iter()
            .filter(|(route, bundle)| {
                bundle.identity_key == route.identity_key
                    && !account.ratchet_ref().has_session(&route.identity_key)
                    && account.ratchet().establish_outbound(bundle).is_ok()
            })
            .count()
    }

    /// Refresh `username`'s verified roster pin and open every missing device session, so
    /// later fan-outs for that account can be prepared without any network wait.
    ///
    /// A shell that must not hold its session lock across the network calls the four
    /// steps ([`fetch_account_devices`](Self::fetch_account_devices),
    /// [`History::apply_roster_update`], [`missing_device_sessions`](Self::missing_device_sessions),
    /// [`fetch_device_bundles`](Self::fetch_device_bundles) +
    /// [`install_device_sessions`](Self::install_device_sessions)) itself, taking the lock
    /// only around the two local ones.
    pub async fn warm_account_routes(
        &self,
        account: &mut Account,
        history: &mut History,
        username: &str,
    ) -> Result<ResolvedDevices> {
        let (resolved, update) = self.fetch_account_devices(username).await?;
        history.apply_roster_update(username, &update)?;
        if account.account_id() == username {
            history.set_self_primary_key(&resolved.primary_key);
        }
        let missing = self.missing_device_sessions(account, username, &resolved);
        if !missing.is_empty() {
            let fetched = self.fetch_device_bundles(&missing).await;
            self.install_device_sessions(account, &fetched);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, key: &str) -> RosterDevice {
        RosterDevice {
            device_id: id.to_string(),
            identity_key: key.to_string(),
            signing_key: format!("{key}-sig"),
        }
    }

    fn verified(binding_seq: u64, seq: u64, primary_key: &str) -> RosterUpdate {
        RosterUpdate::Verified {
            binding_seq,
            seq,
            primary_key: primary_key.to_string(),
            devices: vec![device(PRIMARY_DEVICE_ID, primary_key), device("d2", "kb")],
        }
    }

    #[test]
    fn a_verified_update_pins_and_a_lower_epoch_is_refused() {
        let mut history = History::new();
        history
            .apply_roster_update("alice", &verified(4, 7, "ka"))
            .unwrap();
        assert_eq!(history.pinned_roster("alice").unwrap().seq, 7);
        // Rollback to an older epoch of the same owner: fail closed, pin untouched.
        assert!(history
            .apply_roster_update("alice", &verified(4, 6, "ka"))
            .is_err());
        assert_eq!(history.pinned_roster("alice").unwrap().seq, 7);
    }

    #[test]
    fn a_vanished_roster_is_a_downgrade_unless_ownership_moved() {
        let mut history = History::new();
        history
            .apply_roster_update("alice", &verified(4, 7, "ka"))
            .unwrap();
        // Same owner, no roster served: an append-only roster is never deleted.
        let same_owner = RosterUpdate::Absent {
            primary_key: "ka".into(),
            binding_seq: 9,
        };
        assert!(history.apply_roster_update("alice", &same_owner).is_err());
        assert!(history.pinned_roster("alice").is_some());
        // A new owner whose binding advanced past ours legitimately has no roster yet.
        let taken_over = RosterUpdate::Absent {
            primary_key: "kz".into(),
            binding_seq: 9,
        };
        history.apply_roster_update("alice", &taken_over).unwrap();
        assert!(history.pinned_roster("alice").is_none());
    }

    #[test]
    fn a_stale_roster_leaves_the_pin_alone() {
        let mut history = History::new();
        history
            .apply_roster_update("alice", &verified(4, 7, "ka"))
            .unwrap();
        history
            .apply_roster_update("alice", &RosterUpdate::Stale)
            .unwrap();
        assert_eq!(history.pinned_roster("alice").unwrap().seq, 7);
        // And on an unpinned account it is simply a no-op.
        let mut fresh = History::new();
        fresh
            .apply_roster_update("bob", &RosterUpdate::Stale)
            .unwrap();
        assert!(fresh.pinned_roster("bob").is_none());
    }

    #[test]
    fn an_absent_roster_without_a_pin_is_ordinary_single_device() {
        let mut history = History::new();
        history
            .apply_roster_update(
                "bob",
                &RosterUpdate::Absent {
                    primary_key: "kb".into(),
                    binding_seq: 1,
                },
            )
            .unwrap();
        assert!(history.pinned_roster("bob").is_none());
    }
}
