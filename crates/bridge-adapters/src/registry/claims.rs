//! Exclusive native evidence claims held across the authoritative custody commit.
//! This module contains no producer authorization, job logic or durable store.

use super::*;

/// One caller source captured by an unresolved registration, never wire authority.
/// Dropping this value deliberately does not release its reservation: only a
/// proven no-commit result permits release; ambiguity must remain fenced.
#[derive(Debug)]
pub(crate) struct EvidenceClaim {
    /// Original globally unique observation-use identity, also the claim handle.
    pub(crate) use_key: String,
    /// Exact native caller fixed when qualified evidence was reserved.
    pub(crate) caller: VerifiedCaller,
    /// Native per-call identifier, distinct from producer request identity.
    pub(crate) native_call_id: String,
    /// Actual kernel harness PID/start-time incarnation.
    pub(crate) harness: (u32, u64),
    /// Absolute finite validity bound checked again by the custody transaction.
    pub(crate) expires_at_ms: u64,
}

/// The source whose future use is fenced by a registration claim.
#[derive(Debug, Clone)]
pub(super) enum ClaimSource {
    /// A direct protected hook observation; it remains in the call registry.
    Native {
        /// Protected per-invocation call identifier.
        call: String,
        /// Actual owning harness process incarnation.
        harness: (u32, u64),
    },
    /// A legacy frontend proof retaining the original observation-use identity.
    Sealed {
        /// SHA-256 lookup of the proof, never the raw secret.
        digest: String,
    },
}

/// Internal reservation ownership; contains no credential or raw proof value.
#[derive(Debug)]
pub(super) struct ClaimRecord {
    /// Authenticated producer fixed before reservation.
    pub(super) producer: String,
    /// Stable producer registration identity used for reconciliation.
    pub(super) request_id: String,
    /// Canonical requested intent, supplied by the one protocol fingerprint helper.
    pub(super) fingerprint: String,
    /// Exact record/proof to settle only after a proven custody outcome.
    pub(super) source: ClaimSource,
}

impl Registry {
    /// Derives a boot-qualified use key from an exact protected native source.
    /// Fields are fixed-order JSON, so arbitrary native strings cannot collide
    /// through delimiters; repeated observations of the same invocation keep
    /// the same key. Observation time bounds validity, not identity. The value
    /// contains no credential or proof secret.
    pub(super) fn source_use_key(
        &self,
        call: &str,
        harness: (u32, u64),
        epoch: u64,
        _observed_ms: u64,
    ) -> String {
        let bytes = serde_json::to_vec(&(&self.issuer_boot, call, harness, epoch))
            .expect("native source tuple serializes");
        crate::server::sha256_hex(&bytes)
    }

    /// Reports an existing unresolved authenticated request without releasing it.
    /// Changed requested intent conflicts; identical intent is in progress.
    pub(crate) fn claimed_request(
        &self,
        producer: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<Option<String>, CorrelationError> {
        let claim = self
            .claims
            .iter()
            .find(|(_, claim)| claim.producer == producer && claim.request_id == request_id);
        match claim {
            Some((key, claim)) if claim.fingerprint == fingerprint => Ok(Some(key.clone())),
            Some(_) => Err(CorrelationError::Conflicting(
                "registration intention changed".into(),
            )),
            None => Ok(None),
        }
    }

    /// Reserves actual qualified direct/sealed native evidence for one producer
    /// request. The caller authenticated and validated semantics before this call.
    /// Legacy and v1 consumers cannot spend the source until explicit settlement.
    /// Capacity, invalid classification and unqualified evidence refuse before
    /// use. Returned snapshot never authorizes a product mutation by itself.
    pub(crate) fn reserve_caller(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
        producer: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<EvidenceClaim, CorrelationError> {
        if self
            .claimed_request(producer, request_id, fingerprint)?
            .is_some()
        {
            return Err(CorrelationError::Unavailable(
                "registration is in progress".into(),
            ));
        }
        let (caller, harness, call, expires_at_ms, use_key, source, tool_name) = match meta {
            PresentedMeta::Sealed { proof } => {
                self.verify_relay(peer)?;
                let digest = crate::server::sha256_hex(proof.as_str().as_bytes());
                let sealed = self
                    .sealed
                    .get(&digest)
                    .ok_or_else(|| CorrelationError::Missing("sealed proof".into()))?;
                let source_expiry = sealed.source_expires_at_ms(self.config.max_call_age_ms);
                if source_expiry <= now_ms || !self.sealed_current(sealed) {
                    return Err(CorrelationError::Stale(
                        "sealed proof is not current".into(),
                    ));
                }
                (
                    sealed.caller.clone().into_relayed(),
                    sealed.harness,
                    sealed.native_call_id.clone(),
                    source_expiry,
                    sealed.source_use_key.clone(),
                    ClaimSource::Sealed { digest },
                    sealed.tool_name.clone(),
                )
            }
            _ => {
                let (caller, harness, call, tool_name) =
                    self.inspect_native(peer, meta, now_ms, false)?;
                let key =
                    self.source_use_key(&call, harness, caller.epoch(), caller.observed_at_ms());
                let expires = caller
                    .observed_at_ms()
                    .saturating_add(self.config.max_call_age_ms);
                (
                    caller,
                    harness,
                    call.clone(),
                    expires,
                    key,
                    ClaimSource::Native { call, harness },
                    tool_name,
                )
            }
        };
        if !tool_name.as_deref().is_some_and(native_mcp_tool) {
            return Err(CorrelationError::NotEvidence(
                "unsupported_host_path".into(),
            ));
        }
        if self.claims.contains_key(&use_key) {
            return Err(CorrelationError::Unavailable(
                "native evidence reserved".into(),
            ));
        }
        if self.claims.len() >= self.max_calls {
            return Err(CorrelationError::Unavailable(
                "native claim capacity exhausted".into(),
            ));
        }
        if let ClaimSource::Native { call, harness } = &source {
            self.calls
                .get_mut(call)
                .expect("verified call")
                .iter_mut()
                .find(|record| record.harness == *harness)
                .expect("verified incarnation")
                .claimed = true;
        }
        self.claims.insert(
            use_key.clone(),
            ClaimRecord {
                producer: producer.into(),
                request_id: request_id.into(),
                fingerprint: fingerprint.into(),
                source,
            },
        );
        Ok(EvidenceClaim {
            use_key,
            caller,
            native_call_id: call,
            harness,
            expires_at_ms,
        })
    }

    /// Completes an exclusive source only after proven durable commitment.
    /// A missing handle is harmless reconciliation; it never recreates evidence.
    pub(crate) fn finalize_claim(&mut self, use_key: &str) {
        if let Some(claim) = self.claims.remove(use_key) {
            match claim.source {
                ClaimSource::Native { call, harness } => {
                    if let Some(record) = self.calls.get_mut(&call).and_then(|records| {
                        records.iter_mut().find(|record| record.harness == harness)
                    }) {
                        record.claimed = false;
                        record.consumed = true;
                    }
                }
                ClaimSource::Sealed { digest } => {
                    self.sealed.remove(&digest);
                }
            }
        }
    }

    /// Releases only a proven uncommitted claim. Callers must never invoke this
    /// merely because a response was lost or a reconciliation row was absent.
    pub(crate) fn release_claim(&mut self, use_key: &str) {
        if let Some(claim) = self.claims.remove(use_key)
            && let ClaimSource::Native { call, harness } = claim.source
            && let Some(record) = self
                .calls
                .get_mut(&call)
                .and_then(|records| records.iter_mut().find(|record| record.harness == harness))
        {
            record.claimed = false;
        }
    }

    /// Inspects a positively verifiable replay origin without spending evidence
    /// or asserting freshness. Missing/lost/expired evidence is no origin fact.
    pub(crate) fn replay_origin(
        &mut self,
        peer: PeerIdentity,
        meta: &PresentedMeta,
        now_ms: u64,
    ) -> Option<(VerifiedCaller, (u32, u64), String, u64)> {
        match meta {
            PresentedMeta::Sealed { proof } => {
                self.verify_relay(peer).ok()?;
                let sealed = self
                    .sealed
                    .get(&crate::server::sha256_hex(proof.as_str().as_bytes()))?;
                let source_expiry = sealed.source_expires_at_ms(self.config.max_call_age_ms);
                (source_expiry > now_ms && self.sealed_current(sealed)).then(|| {
                    (
                        sealed.caller.clone().into_relayed(),
                        sealed.harness,
                        sealed.source_use_key.clone(),
                        source_expiry,
                    )
                })
            }
            _ => self.inspect_native(peer, meta, now_ms, true).ok().map(
                |(caller, harness, call, _)| {
                    let use_key = self.source_use_key(
                        &call,
                        harness,
                        caller.epoch(),
                        caller.observed_at_ms(),
                    );
                    let expiry = caller
                        .observed_at_ms()
                        .saturating_add(self.config.max_call_age_ms);
                    (caller, harness, use_key, expiry)
                },
            ),
        }
    }

    /// Verifies a relay's kernel identity and warmed exact loaded build, without
    /// reading, removing or spending a proof. No PID or path alone qualifies.
    pub(super) fn verify_relay(&mut self, peer: PeerIdentity) -> Result<(), CorrelationError> {
        if peer.uid != self.owner_uid {
            return Err(CorrelationError::NotEvidence(
                "relay runs as another user".into(),
            ));
        }
        let facts = os::process_facts(peer.pid)
            .ok_or_else(|| CorrelationError::NotEvidence("relay process is gone".into()))?;
        let exe = facts
            .exe
            .ok_or_else(|| CorrelationError::NotEvidence("relay executable unreadable".into()))?;
        let digest = self
            .config
            .relays
            .iter()
            .find(|relay| relay.path == exe)
            .map(|relay| relay.sha256.clone())
            .ok_or_else(|| {
                CorrelationError::NotEvidence("peer is not a configured relay".into())
            })?;
        self.verify_loaded(&exe, facts.start_time, &digest)
    }

    /// Whether an issued source still belongs to the same live endpoint.
    pub(super) fn sealed_current(&self, sealed: &Sealed) -> bool {
        self.bindings.get(&sealed.binding).is_some_and(|binding| {
            !binding.retired
                && binding.harness == sealed.harness
                && binding.epoch == sealed.caller.epoch()
                && os::incarnation_alive(binding.harness.0, binding.harness.1)
        })
    }
}

/// Recognizes supported native host MCP grammar only. It never extracts or
/// authorizes a producer/tool identity. Outer wrappers, non-MCP and missing
/// observations have no positive classification and cannot substitute for calls.
fn native_mcp_tool(name: &str) -> bool {
    name.strip_prefix("mcp__")
        .and_then(|tail| tail.split_once("__"))
        .is_some_and(|(server, tool)| {
            !server.is_empty()
                && !tool.is_empty()
                && name.len() <= MAX_NATIVE_ID_BYTES
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    //! Local source-fence controls; native ingress qualification is separate.
    use super::*;

    /// Constructs a registry without harness qualification or executable reads.
    fn registry() -> Registry {
        Registry::new(
            RegistryConfig {
                host_id: "lab".into(),
                profiles: Vec::new(),
                intermediates: Vec::new(),
                max_call_age_ms: 10_000,
                relays: Vec::new(),
                audiences: Vec::new(),
            },
            0,
        )
        .unwrap()
    }

    /// Installs an explicitly synthetic native observation for eviction controls.
    fn record(claimed: bool) -> CallRecord {
        CallRecord {
            harness: (42, 7),
            address: "lab/claude-code/store/session".into(),
            role: ActorRole::Root,
            native_id: "session".into(),
            epoch: 2,
            observed_ms: 100,
            consumed: false,
            claimed,
            tool_name: Some("mcp__new_producer__make_report".into()),
        }
    }

    /// Host grammar is generic while outer wrappers and incomplete names refuse.
    #[test]
    fn mcp_classification_refuses_outer_and_non_mcp_names() {
        assert!(native_mcp_tool("mcp__unknown_producer__unseen_operation"));
        assert!(native_mcp_tool("mcp__a-b__call_4"));
        for name in [
            "functions.exec",
            "shell",
            "mcp__",
            "mcp__a",
            "mcp____b",
            "mcp__a__",
            "mcp__a__b c",
        ] {
            assert!(!native_mcp_tool(name), "unexpected host classification");
        }
    }

    /// A capacity/eviction gate cannot discard a reserved native observation;
    /// proven commitment spends it, whereas proven noncommit only releases it.
    #[test]
    fn claimed_records_survive_capacity_and_settle_explicitly() {
        let mut registry = registry();
        registry.max_calls = 2;
        registry.record_call("old".into(), record(true));
        registry.record_call("middle".into(), record(false));
        assert!(registry.ensure_call_capacity().is_ok());
        registry.record_call("new".into(), record(false));
        assert!(registry.calls.contains_key("old"));
        assert!(!registry.calls.contains_key("middle"));
        assert!(registry.calls.contains_key("new"));
        registry.calls.get_mut("new").unwrap()[0].claimed = true;
        assert!(registry.ensure_call_capacity().is_err());
        registry.claims.insert(
            "claim".into(),
            ClaimRecord {
                producer: "p".into(),
                request_id: "r".into(),
                fingerprint: "f".into(),
                source: ClaimSource::Native {
                    call: "old".into(),
                    harness: (42, 7),
                },
            },
        );
        assert_eq!(
            registry.claimed_request("p", "r", "f").unwrap(),
            Some("claim".into())
        );
        assert!(registry.claimed_request("p", "r", "changed").is_err());
        registry.release_claim("claim");
        assert!(!registry.calls["old"][0].claimed);
        assert!(!registry.calls["old"][0].consumed);
        registry.calls.get_mut("old").unwrap()[0].claimed = true;
        registry.claims.insert(
            "claim".into(),
            ClaimRecord {
                producer: "p".into(),
                request_id: "r".into(),
                fingerprint: "f".into(),
                source: ClaimSource::Native {
                    call: "old".into(),
                    harness: (42, 7),
                },
            },
        );
        registry.finalize_claim("claim");
        assert!(!registry.calls["old"][0].claimed);
        assert!(registry.calls["old"][0].consumed);
        assert!(registry.claims.is_empty());
    }

    /// Source identity is unambiguous and unique across issuer boots, epoch and
    /// native call while remaining stable for exact direct/sealed derivatives.
    #[test]
    fn source_use_identity_is_boot_qualified_and_unambiguous() {
        let registry = registry();
        let key = registry.source_use_key("call", (42, 7), 2, 100);
        assert_eq!(key, registry.source_use_key("call", (42, 7), 2, 100));
        assert_eq!(key, registry.source_use_key("call", (42, 7), 2, 101));
        assert_ne!(key, registry.source_use_key("call", (42, 7), 3, 100));
        assert_ne!(key, registry.source_use_key("other", (42, 7), 2, 100));
        let second = self::registry();
        assert_ne!(key, second.source_use_key("call", (42, 7), 2, 100));
    }
}
