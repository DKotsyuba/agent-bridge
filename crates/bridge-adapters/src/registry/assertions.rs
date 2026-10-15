//! Bounded generic detached invocation assertions; durable routes are never
//! reconstructed into fresh authority. The issuer cache is intentionally per boot.

use super::*;
use bridge_protocol::{
    ConsumeResult, ConsumptionReceipt, FreshAssertion, InvocationContext, InvocationValidity,
    RegistrationReceipt, Secret,
};

/// Cache entry fixed at issuance, including actual caller revocation evidence.
#[derive(Debug, Clone)]
pub(super) struct AssertionRecord {
    /// Authenticated owner, not a bearer identity supplied in RPC arguments.
    producer: String,
    /// Frozen verified native invocation; no credential or assertion key.
    context: InvocationContext,
    /// Actual source snapshot used for current endpoint/epoch checks.
    caller: VerifiedCaller,
    /// Actual source harness incarnation.
    harness: (u32, u64),
    /// First consumption and positively qualified backend incarnation.
    consumed: Option<(ConsumptionReceipt, (u32, u64))>,
}

impl Registry {
    /// Reserves bounded assertion capacity before claiming native evidence.
    /// Name/producer must have explicit deployment audience configuration.
    /// Exhaustion refuses instead of evicting immutable consumed receipts.
    pub(crate) fn reserve_assertion_slot(
        &mut self,
        producer: &str,
        request_id: &str,
        audience: &str,
        now_ms: u64,
    ) -> Result<(), CorrelationError> {
        if !self
            .config
            .audiences
            .iter()
            .any(|entry| entry.producer == producer && entry.name == audience)
        {
            return Err(CorrelationError::NotEvidence(
                "assertion_audience_mismatch".into(),
            ));
        }
        // Expired unused random issuer keys can never be reissued; consumed facts
        // remain immutable until issuer boot ends, under the same hard bound.
        self.assertions
            .retain(|_, entry| entry.consumed.is_some() || entry.context.expires_at_ms > now_ms);
        let owner = (producer.to_string(), request_id.to_string());
        if self.assertion_slots.contains(&owner) {
            return Ok(());
        }
        if self.assertions.len() + self.assertion_slots.len() >= MAX_SEALED {
            return Err(CorrelationError::Unavailable(
                "assertion capacity exhausted".into(),
            ));
        }
        self.assertion_slots.insert(owner);
        Ok(())
    }

    /// Releases an unactivated slot after historical recovery or refusal; it
    /// never releases native evidence claims or recalls an issued assertion.
    pub(crate) fn release_assertion_slot(&mut self, producer: &str, request_id: &str) {
        self.assertion_slots
            .remove(&(producer.to_string(), request_id.to_string()));
    }

    /// Activates a real reserved assertion only after durable registration and
    /// positive source-current recheck. Failure leaves the committed route intact.
    /// Exact registration replay never calls this method or renews its expiry.
    pub(crate) fn issue_assertion(
        &mut self,
        receipt: &RegistrationReceipt,
        claim: &EvidenceClaim,
        audience: &str,
        invocation_key: &str,
        now_ms: u64,
    ) -> Option<FreshAssertion> {
        if !self
            .assertion_slots
            .remove(&(receipt.producer.clone(), receipt.request_id.clone()))
            || !self.caller_current(&claim.caller, claim.harness)
            || claim.expires_at_ms <= now_ms
        {
            return None;
        }
        let key: String = os::random_bytes()
            .ok()?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let expiry = now_ms
            .saturating_add(SEALED_PROOF_TTL_MS)
            .min(claim.expires_at_ms);
        let incarnation = self.source_use_key(
            &claim.native_call_id,
            claim.harness,
            claim.caller.epoch(),
            claim.caller.observed_at_ms(),
        );
        let context = InvocationContext {
            audience: audience.into(),
            caller_scope: receipt.caller_scope.clone(),
            destination_scope: receipt.destination_scope.clone(),
            caller_address: claim.caller.address().to_canonical_string(),
            destination_address: claim.caller.address().to_canonical_string(),
            role: match claim.caller.role() {
                ActorRole::Root => bridge_protocol::ActorRole::Root,
                ActorRole::Child => bridge_protocol::ActorRole::Child,
            },
            native_actor_id: claim.caller.native_id().into(),
            native_call_id: claim.native_call_id.clone(),
            invocation_key: invocation_key.into(),
            observed_at_ms: claim.caller.observed_at_ms(),
            expires_at_ms: expiry,
            issuer_boot: self.issuer_boot.clone(),
            endpoint_incarnation: incarnation.clone(),
        };
        self.assertions.insert(
            crate::server::sha256_hex(key.as_bytes()),
            AssertionRecord {
                producer: receipt.producer.clone(),
                context,
                caller: claim.caller.clone(),
                harness: claim.harness,
                consumed: None,
            },
        );
        Some(FreshAssertion {
            assertion_key: Secret::new(key),
            invocation_key: invocation_key.into(),
            audience: audience.into(),
            observed_at_ms: claim.caller.observed_at_ms(),
            expires_at_ms: expiry,
            issuer_boot: self.issuer_boot.clone(),
            endpoint_incarnation: incarnation,
        })
    }

    /// Consumes once for the authenticated configured backend and exact forwarded
    /// invocation. Exact consumer/request retry preserves context/expiry; after
    /// expiry/revocation it is explicitly historical. New uses cannot spend it.
    pub(crate) fn consume_assertion(
        &mut self,
        peer: PeerIdentity,
        producer: &str,
        request_id: &str,
        params: &bridge_protocol::ConsumeAssertionParams,
        allowed_audiences: &[String],
        now_ms: u64,
    ) -> Result<ConsumeResult, CorrelationError> {
        let invocation_key = params.invocation_key.as_str();
        let digest = crate::server::sha256_hex(params.assertion_key.expose().as_bytes());
        if self.assertions.iter().any(|(key, entry)| {
            entry.producer == producer
                && entry
                    .consumed
                    .as_ref()
                    .is_some_and(|(receipt, _)| receipt.request_id == request_id)
                && (key != &digest || entry.context.invocation_key != invocation_key)
        }) {
            return Err(CorrelationError::Conflicting(
                "assertion consume intention changed".into(),
            ));
        }
        let entry = self
            .assertions
            .get(&digest)
            .filter(|entry| entry.producer == producer)
            .cloned()
            .ok_or_else(|| CorrelationError::Missing("needs_new_attestation".into()))?;
        if !allowed_audiences.contains(&entry.context.audience) {
            return Err(CorrelationError::NotEvidence(
                "assertion_audience_mismatch".into(),
            ));
        }
        let consumer = self.verify_audience(peer, producer, &entry.context.audience)?;
        if entry.context.invocation_key != invocation_key {
            return Err(CorrelationError::Conflicting(
                "assertion_invocation_mismatch".into(),
            ));
        }
        let current = entry.context.expires_at_ms > now_ms
            && self.caller_current(&entry.caller, entry.harness);
        if let Some((receipt, original_consumer)) = entry.consumed {
            if receipt.request_id != request_id || original_consumer != consumer {
                return Err(CorrelationError::Duplicate("assertion_consumed".into()));
            }
            return Ok(ConsumeResult {
                receipt,
                state: if current {
                    InvocationValidity::Current
                } else {
                    InvocationValidity::Historical
                },
            });
        }
        if !current {
            return Err(CorrelationError::Stale("assertion_expired".into()));
        }
        let receipt = ConsumptionReceipt {
            producer: producer.into(),
            request_id: request_id.into(),
            context: entry.context,
            consumed_at_ms: now_ms,
        };
        self.assertions
            .get_mut(&digest)
            .expect("verified entry")
            .consumed = Some((receipt.clone(), consumer));
        Ok(ConsumeResult {
            receipt,
            state: InvocationValidity::Current,
        })
    }

    /// Verifies the current own-UID backend executable and exact loaded build.
    /// Configuration names do not grant authority without core authentication.
    fn verify_audience(
        &mut self,
        peer: PeerIdentity,
        producer: &str,
        audience: &str,
    ) -> Result<(u32, u64), CorrelationError> {
        if peer.uid != self.owner_uid {
            return Err(CorrelationError::NotEvidence(
                "assertion_audience_mismatch".into(),
            ));
        }
        let executable = self
            .config
            .audiences
            .iter()
            .find(|entry| entry.producer == producer && entry.name == audience)
            .map(|entry| entry.executable.clone())
            .ok_or_else(|| CorrelationError::NotEvidence("assertion_audience_mismatch".into()))?;
        let facts = os::process_facts(peer.pid)
            .ok_or_else(|| CorrelationError::NotEvidence("assertion_audience_mismatch".into()))?;
        if facts.uid != Some(self.owner_uid) || facts.exe.as_ref() != Some(&executable.path) {
            return Err(CorrelationError::NotEvidence(
                "assertion_audience_mismatch".into(),
            ));
        }
        self.verify_loaded(&executable.path, facts.start_time, &executable.sha256)?;
        Ok((facts.pid, facts.start_time))
    }

    /// Current endpoint incarnation check; stable scope equality is irrelevant.
    pub(super) fn caller_current(&mut self, caller: &VerifiedCaller, harness: (u32, u64)) -> bool {
        let Some(binding) = self
            .bindings
            .get(&caller.address().to_canonical_string())
            .cloned()
        else {
            return false;
        };
        !binding.retired
            && binding.harness == harness
            && binding.epoch == caller.epoch()
            && os::process_facts(harness.0).is_some_and(|facts| {
                facts.start_time == harness.1
                    && facts.exe.as_ref() == Some(&binding.executable)
                    && executable_current(&binding.executable, &facts, self.owner_uid).is_ok()
            })
    }
}

impl Registry {
    /// Native host/build facts advertised to authenticated producers: none. Native
    /// recipients are not predeclared by build, so there is no configured
    /// host/build/path fact to disclose and nothing fake is advertised; the
    /// harness-level policy is operator configuration, not a capability to
    /// advertise. No session, address, foreign producer or executable path is
    /// disclosed.
    pub(crate) fn native_contracts(&mut self) -> Vec<bridge_protocol::NativeContract> {
        Vec::new()
    }

    /// Whether this producer's current allowed audience list intersects explicit
    /// native backend configuration. This discloses feature support, not authority.
    pub(crate) fn has_audience(&mut self, producer: &str, allowed: &[String]) -> bool {
        let candidates: Vec<_> = self
            .config
            .audiences
            .iter()
            .filter(|entry| entry.producer == producer && allowed.contains(&entry.name))
            .map(|entry| entry.executable.clone())
            .collect();
        candidates.iter().any(|executable| {
            self.verify_loaded(&executable.path, u64::MAX, &executable.sha256)
                .is_ok()
        })
    }
}
