//! Closed typed managed-owner v2 and authenticated actor-lookup wire objects.
//!
//! Reject duplicate object keys recursively at the frame boundary before serde.
//! These declarations do not enable or advertise managed delivery.

use crate::{
    Secret,
    attempt::{ActorV1, IncarnationV1, nullable},
};
use serde::{Deserialize, Serialize};

/// Defines a documented, closed managed wire object.
macro_rules! dto {
    ($name:ident, $doc:literal, { $($field:ident : $ty:ty => $field_doc:literal),* $(,)? }) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(#[doc = $field_doc] pub $field: $ty,)* }
    };
}

dto!(AttemptRefV1, "Exact durable Run attempt and launch.", {
    run_store_id: String => "Pinned opaque Run store identity.",
    lineage_root_id: String => "Immutable lineage root identity.",
    execution_id: String => "Exact execution identity.",
    sequence: u32 => "Positive attempt sequence within the lineage.",
    attempt_id: String => "Durable attempt identity.",
    launch_id: String => "Run launch UUID."
});
dto!(RouteV1, "Exact component store, route and worker UID.", {
    component_store_id: String => "Pinned opaque component store identity.",
    route_id: String => "Exact component route identity.",
    worker_uid: u32 => "Kernel worker UID."
});
dto!(BindingV1, "Frozen Pool member binding for a target attempt.", {
    pool_store_id: String => "Pinned Pool store identity.",
    pool_id: String => "Pool identity.",
    member_id: String => "Member identity.",
    binding_generation: u64 => "Pool-owned binding generation.",
    attempt: AttemptRefV1 => "Exact target attempt and launch.",
    actor: ActorV1 => "Exact target root actor.",
    run_route: RouteV1 => "Pinned Run route.",
    bridge_route: RouteV1 => "Pinned Bridge route."
});

/// The only delivery mode of the managed owner contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedModeV1 {
    /// Deliver exactly one message to the already-live owner.
    Message,
}

/// The only retention policy of the managed owner contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRetentionV1 {
    /// Preserve every distinct effect independently.
    KeepAll,
}

dto!(OutboxIntentV1, "Immutable one-effect managed outbox projection.", {
    effect_id: String => "Durable producer effect identity.",
    producer_scope: String => "Durable effect namespace.",
    event_key: String => "Original domain event identity.",
    payload_sha256: String => "SHA-256 of the exact UTF-8 message.",
    payload_length: u64 => "Length of the exact UTF-8 message in bytes.",
    target_binding: BindingV1 => "Complete immutable target binding.",
    expected_incarnation: IncarnationV1 => "Expected full kernel incarnation.",
    bridge_route: RouteV1 => "Exact Bridge route, equal to the binding route.",
    mode: ManagedModeV1 => "Managed message mode.",
    retention: ManagedRetentionV1 => "Noncoalescing keep-all policy."
});
dto!(OwnerRequestV2, "One private length-prefixed managed owner request.", {
    version: u16 => "Must be 2.",
    thread_id: String => "Exact target native session.",
    call_id: String => "Per-dispatch correlation, excluded from effect identity.",
    outbox_intent: OutboxIntentV1 => "Complete immutable target and effect intent.",
    effect_digest: String => "Canonical egress-intent digest.",
    text: Secret => "Exact UTF-8 message, redacted in diagnostics.",
    wake_only: bool => "Must be true; recipient must be idle."
});

/// Authoritative Run owner effect result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerStateV2 {
    /// Exact native handoff was durably accepted.
    Accepted,
    /// No native effect occurred and no late writer remains.
    KnownUnsent,
    /// Native effect may have occurred and cannot be resent.
    Unknown,
}

/// Correlated owner reply; nullable fields are still required on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerReplyV2 {
    /// Must be 2.
    pub version: u16,
    /// Echo of this dispatch's call identity.
    pub call_id: String,
    /// Echo of the original effect identity.
    pub effect_id: String,
    /// Echo of the immutable egress-intent digest.
    pub effect_digest: String,
    /// Durable outcome state.
    pub state: OwnerStateV2,
    /// Native protocol when accepted, otherwise null.
    #[serde(deserialize_with = "nullable")]
    pub protocol: Option<String>,
    /// Native receipt when accepted, otherwise null.
    #[serde(deserialize_with = "nullable")]
    pub native_id: Option<String>,
    /// Finite refusal or uncertainty code, otherwise null.
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
}

dto!(PublishManagedOwnerParamsV1, "One authenticated managed-owner custody request.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    audience: String => "Configured producer backend audience.",
    run_receipt_id: String => "Opaque selector for a Run-owned current receipt.",
    outbox_intent: OutboxIntentV1 => "Complete immutable effect and target.",
    effect_digest: String => "Canonical egress-intent digest.",
    text: Secret => "Exact redacted UTF-8 payload."
});
dto!(LookupManagedOwnerParamsV1, "Recover one exact managed-owner effect.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    audience: String => "Original configured backend audience.",
    producer_scope: String => "Original effect namespace.",
    effect_id: String => "Original effect identity.",
    effect_digest: String => "Original canonical egress-intent digest."
});
dto!(CompactManagedOwnerScopeParamsV1, "Compact settled owner receipts after scope retirement.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    audience: String => "Configured original backend audience.",
    producer_scope: String => "Already retired producer effect namespace."
});
dto!(CompactManagedOwnerScopeResultV1, "Outcome of one scoped compaction pass.", {
    version: u16 => "Must be 1.",
    store_id: String => "Durable Bridge store UUID.",
    producer: String => "Authenticated original producer.",
    producer_scope: String => "Already retired producer effect namespace.",
    compacted: u64 => "Number of terminal rows removed during this pass.",
    remaining: u64 => "Rows still retained for this audience and scope."
});

/// Abort uses the same complete frozen intent as publication so an absent
/// effect can be durably fenced before a delayed publish arrives.
pub type AbortManagedOwnerParamsV1 = PublishManagedOwnerParamsV1;

/// Bridge's durable managed-owner outcome, including a permanent abort fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOwnerStateV1 {
    /// Exact native handoff was durably accepted.
    Accepted,
    /// No native effect occurred and a same-effect retry may be allowed.
    KnownUnsent,
    /// A native effect may have occurred and must not be resent.
    Unknown,
    /// Run and Bridge durably fenced any current and late native write.
    Aborted,
}

/// Durable managed-owner outcome. Nullable fields must appear on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedOwnerResultV1 {
    /// Selected operation version, 1.
    pub version: u16,
    /// Durable Bridge store UUID.
    pub store_id: String,
    /// Authenticated original producer.
    pub producer: String,
    /// Original effect namespace.
    pub producer_scope: String,
    /// Original effect identity.
    pub effect_id: String,
    /// Original canonical egress-intent digest.
    pub effect_digest: String,
    /// Accepted, definitively unsent, or uncertain native handoff.
    pub state: ManagedOwnerStateV1,
    /// Native protocol only for an acceptance, else null.
    #[serde(deserialize_with = "nullable")]
    pub protocol: Option<String>,
    /// Native receipt only for an acceptance, else null.
    #[serde(deserialize_with = "nullable")]
    pub native_id: Option<String>,
    /// Finite reason only for an unsent or unknown result, else null.
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
}

dto!(RunActorLookupParamsV1, "Authenticated Run reader's exact actor query.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    producer: String => "Producer whose observation is queried.",
    incarnation: IncarnationV1 => "Exact claimed kernel incarnation.",
    launch_id: String => "Exact originally observed Run launch UUID."
});

/// Bridge's live classification of an originally observed launch actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunActorStateV1 {
    /// One current original observation and live kernel incarnation are proven.
    Current,
    /// Original observation is available only as historical evidence.
    Historical,
    /// Current or historical association cannot be proven.
    Unavailable,
}

/// Exact actor lookup result; nullable fields remain mandatory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunActorLookupResultV1 {
    /// Selected operation version, 1.
    pub version: u16,
    /// Durable Bridge store UUID.
    pub store_id: String,
    /// Echo of the original producer.
    pub producer: String,
    /// Echo of the exact requested process incarnation.
    pub incarnation: IncarnationV1,
    /// Echo of the exact original launch UUID.
    pub launch_id: String,
    /// Current, historical or unavailable classification.
    pub state: RunActorStateV1,
    /// Original actor, required for current and otherwise nullable.
    #[serde(deserialize_with = "nullable")]
    pub actor: Option<ActorV1>,
    /// Original issuer, required for current and otherwise nullable.
    #[serde(deserialize_with = "nullable")]
    pub issuer_epoch: Option<String>,
}

/// Recovery readiness of one exact managed root after Bridge restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunActorRecoveryStateV1 {
    /// A fresh root hook has re-armed the original exact actor.
    Current,
    /// A matching original capture exists but needs a fresh root hook.
    AwaitingRootHook,
    /// Original capture cannot be restored for this incarnation.
    RelaunchRequired,
    /// The process or protected journal cannot currently be checked.
    Unavailable,
}

/// Same exact process and launch selector as the actor lookup.
pub type RunActorRecoveryStatusParamsV1 = RunActorLookupParamsV1;
dto!(RunActorRecoveryStatusResultV1, "Exact actor recovery readiness.", {
    version: u16 => "Must be 1.",
    store_id: String => "Durable Bridge store UUID.",
    producer: String => "Configured original producer.",
    incarnation: IncarnationV1 => "Exact queried kernel incarnation.",
    launch_id: String => "Exact original launch UUID.",
    state: RunActorRecoveryStateV1 => "Current readiness or refusal."
});

/// Encodes one JSON value using the typed canonical tree in the attempt-binding
/// contract. Objects sort by Unicode scalar key order; floats retain their IEEE
/// 754 category and normalize negative zero. This is not legacy canonical JSON.
///
/// # Errors
///
/// The input is not a finite JSON value or canonical serialization fails.
pub fn canonical_value(value: &serde_json::Value) -> Result<Vec<u8>, crate::ProtocolError> {
    use serde_json::{Value, json};
    /// Recursively constructs the unambiguous type-tagged JSON tree.
    fn tree(value: &Value) -> Result<Value, crate::ProtocolError> {
        Ok(match value {
            Value::Null => json!(["n"]),
            Value::Bool(value) => json!(["b", value]),
            Value::String(value) => json!(["s", value]),
            Value::Number(value) => {
                if let Some(integer) = value.as_i64() {
                    json!(["i", integer.to_string()])
                } else if let Some(integer) = value.as_u64() {
                    json!(["i", integer.to_string()])
                } else {
                    let float = value
                        .as_f64()
                        .filter(|v| v.is_finite())
                        .ok_or(crate::ProtocolError::new("canonical", "nonfinite number"))?;
                    let bits = if float == 0.0 { 0 } else { float.to_bits() };
                    json!(["f", format!("{bits:016x}")])
                }
            }
            Value::Array(values) => {
                json!(["a", values.iter().map(tree).collect::<Result<Vec<_>, _>>()?])
            }
            Value::Object(values) => {
                let mut sorted: Vec<_> = values.iter().collect();
                sorted.sort_by_key(|(left, _)| *left);
                let entries = sorted
                    .into_iter()
                    .map(|(key, value)| Ok(json!([key, tree(value)?])))
                    .collect::<Result<Vec<Value>, crate::ProtocolError>>()?;
                json!(["o", entries])
            }
        })
    }
    serde_json::to_vec(&tree(value)?)
        .map_err(|_| crate::ProtocolError::new("canonical", "encoding failed"))
}

/// Computes the managed egress digest of the complete immutable outbox intent.
/// This excludes per-dispatch correlation and includes the exact payload hash.
///
/// # Errors
///
/// The intent cannot be converted to canonical typed JSON.
pub fn egress_intent_digest(intent: &OutboxIntentV1) -> Result<String, crate::ProtocolError> {
    use sha2::{Digest, Sha256};
    let value = serde_json::to_value(intent)
        .map_err(|_| crate::ProtocolError::new("outbox", "encoding failed"))?;
    let mut hash = Sha256::new();
    hash.update(b"agent-mcp/attempt-binding/egress-intent/v1\0");
    hash.update(canonical_value(&value)?);
    Ok(format!("{:x}", hash.finalize()))
}

/// Rejects integer tokens outside the serde JSON integer range before raw-byte
/// parsing. String contents and fractional/exponent number categories are not
/// reinterpreted. Full JSON syntax and duplicate keys must be checked separately.
///
/// # Errors
///
/// An integer token is outside `[-2^63, 2^64-1]`.
pub fn validate_raw_integer_tokens(bytes: &[u8]) -> Result<(), crate::ProtocolError> {
    let invalid = || crate::ProtocolError::new("integer", "raw integer outside supported range");
    let mut cursor = 0;
    let mut string = false;
    let mut escaped = false;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
            cursor += 1;
            continue;
        }
        if byte == b'"' {
            string = true;
            cursor += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && matches!(
                    bytes[cursor],
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                )
            {
                cursor += 1;
            }
            let token = &bytes[start..cursor];
            if !token.iter().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                let token = std::str::from_utf8(token).map_err(|_| invalid())?;
                if token.starts_with('-') {
                    token.parse::<i64>().map_err(|_| invalid())?;
                } else {
                    token.parse::<u64>().map_err(|_| invalid())?;
                }
            }
            continue;
        }
        cursor += 1;
    }
    Ok(())
}

/// Largest UTF-8 text accepted by the native owner frame.
pub const MAX_OWNER_TEXT_BYTES: usize = 98_304;

/// Validates a bounded identifier without exposing its contents.
fn valid_id(value: &str) -> bool {
    crate::validate_id("identity", value, crate::MAX_ID_BYTES).is_ok()
}

/// Validates a canonical lowercase UUID.
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// Validates lowercase SHA-256 spelling.
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl OutboxIntentV1 {
    /// Validates all frozen identity associations and the exact message bytes.
    /// This is structural validation, not proof of a Run receipt or live owner.
    ///
    /// # Errors
    ///
    /// A field, route, address, process identity, content hash or size mismatches.
    pub fn validate(&self, text: &str) -> Result<(), crate::ProtocolError> {
        use sha2::{Digest, Sha256};
        let invalid = || crate::ProtocolError::new("outbox", "invalid managed intent");
        let binding = &self.target_binding;
        let attempt = &binding.attempt;
        let process = &self.expected_incarnation;
        let address = crate::NativeAddress::parse(&binding.actor.address).map_err(|_| invalid())?;
        if ![
            &self.effect_id,
            &self.producer_scope,
            &self.event_key,
            &binding.pool_store_id,
            &binding.pool_id,
            &binding.member_id,
            &attempt.run_store_id,
            &attempt.lineage_root_id,
            &attempt.execution_id,
            &attempt.attempt_id,
            &binding.actor.address,
            &binding.actor.native_id,
            &binding.run_route.component_store_id,
            &binding.run_route.route_id,
            &binding.bridge_route.component_store_id,
            &binding.bridge_route.route_id,
            &process.host_id,
        ]
        .iter()
        .all(|value| valid_id(value))
            || !uuid(&attempt.launch_id)
            || !uuid(&process.boot_id)
            || !uuid(&binding.bridge_route.component_store_id)
            || attempt.sequence == 0
            || binding.binding_generation == 0
            || binding.actor.epoch == 0
            || process.pid <= 1
            || process.start_ticks == 0
            || process.pid_namespace_inode == 0
            || binding.run_route.component_store_id != attempt.run_store_id
            || binding.bridge_route != self.bridge_route
            || binding.run_route.worker_uid != process.uid
            || binding.bridge_route.worker_uid != process.uid
            || !matches!(address.harness.as_str(), "codex" | "claude-code")
            || address.host != process.host_id
            || address.session != binding.actor.native_id
            || address.canonical() != binding.actor.address
            || !hash(&self.payload_sha256)
            || text.len() > MAX_OWNER_TEXT_BYTES
            || self.payload_length != text.len() as u64
            || self.payload_sha256 != format!("{:x}", Sha256::digest(text.as_bytes()))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl OwnerRequestV2 {
    /// Validates the exact target, payload, version and recomputed intent digest.
    ///
    /// # Errors
    ///
    /// A field is malformed or differs from the immutable target or content.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        let invalid = || crate::ProtocolError::new("owner_request", "invalid managed request");
        self.outbox_intent.validate(self.text.expose())?;
        if self.version != 2
            || !self.wake_only
            || !valid_id(&self.thread_id)
            || !valid_id(&self.call_id)
            || self.thread_id != self.outbox_intent.target_binding.actor.native_id
            || !hash(&self.effect_digest)
            || self.effect_digest != egress_intent_digest(&self.outbox_intent)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl OwnerReplyV2 {
    /// Validates the exact dispatch/effect echoes and closed receipt semantics.
    /// A malformed reply after writing must be classified as outcome unknown.
    ///
    /// # Errors
    ///
    /// Correlation, native protocol or the finite state-specific shape is wrong.
    pub fn validate_for(
        &self,
        request: &OwnerRequestV2,
        protocol: &str,
    ) -> Result<(), crate::ProtocolError> {
        let invalid = || crate::ProtocolError::new("owner_reply", "invalid correlated receipt");
        if self.version != 2
            || self.call_id != request.call_id
            || self.effect_id != request.outbox_intent.effect_id
            || self.effect_digest != request.effect_digest
        {
            return Err(invalid());
        }
        match (
            self.state,
            self.protocol.as_deref(),
            self.native_id.as_deref(),
            self.reason.as_deref(),
        ) {
            (OwnerStateV2::Accepted, Some(actual), Some(native), None)
                if matches!(protocol, "codex_turn" | "claude_input")
                    && actual == protocol
                    && valid_id(native) =>
            {
                Ok(())
            }
            (
                OwnerStateV2::KnownUnsent,
                None,
                None,
                Some(
                    "actor_mismatch"
                    | "not_idle"
                    | "awaiting_input"
                    | "finished"
                    | "budget"
                    | "cancelled"
                    | "unavailable"
                    | "invalid_request"
                    | "capacity"
                    | "conflict"
                    | "attempt_not_ready"
                    | "attempt_mismatch"
                    | "qualification_pending",
                ),
            ) => Ok(()),
            (OwnerStateV2::Unknown, None, None, Some("native_uncertain" | "channel_failed")) => {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Frozen codec vectors and explicit effect/dispatch identity separation.
    use super::*;
    use crate::attempt::ActorRoleV1;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    /// The shared settlement vector proves canonical tags and domain framing.
    #[test]
    fn frozen_settlement_canonical_vector_and_integer_boundaries() {
        let value = json!({"version":1,"pool_store_id":"pool-store-uuid","intent_id":"intent-1","security_digest":"a".repeat(64),"state":"committed"});
        let canonical = canonical_value(&value).unwrap();
        assert_eq!(canonical.len(), 223);
        let mut hash = Sha256::new();
        hash.update(b"agent-mcp/attempt-binding/settlement/v1\0");
        hash.update(canonical);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "10a5159c5c085fd018534a640862ed8600fdf334cbfac41be9964659d72de8eb"
        );
        assert_eq!(
            canonical_value(&json!(0.0)).unwrap(),
            canonical_value(&json!(-0.0)).unwrap()
        );
        assert_ne!(
            canonical_value(&json!(1)).unwrap(),
            canonical_value(&json!(1.0)).unwrap()
        );
        for raw in [
            r#"{"n":18446744073709551615}"#,
            r#"{"n":-9223372036854775808}"#,
            r#"{"n":"18446744073709551616"}"#,
            r#"{"n":1e100}"#,
        ] {
            assert!(validate_raw_integer_tokens(raw.as_bytes()).is_ok());
        }
        for raw in [
            r#"{"n":18446744073709551616}"#,
            r#"{"n":-9223372036854775809}"#,
        ] {
            assert!(validate_raw_integer_tokens(raw.as_bytes()).is_err());
        }
        // Cross-checked against the frozen Python reference: Unicode scalar
        // sorting, required escapes, signed/unsigned boundaries and f64 tags.
        let unicode = json!({"é":"猫\n\t\u{0008}\u{000c}\r\u{0001}\"\\", "z":[0.0,-0.0,1.0,u64::MAX,i64::MIN]});
        let encoded = canonical_value(&unicode).unwrap();
        assert_eq!(encoded.len(), 193);
        let mut hash = Sha256::new();
        hash.update(b"agent-mcp/attempt-binding/egress-intent/v1\0");
        hash.update(encoded);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "e19e8b1c4187b9224c6495788c6ac2651f2dcaf8cf36a96a7eb6faba0fdac3f5"
        );
    }

    /// The same immutable effect retains one digest across dispatch IDs;
    /// changing payload or any target field invalidates the original request.
    #[test]
    fn outbox_digest_binds_intent_but_not_dispatch_id() {
        let store = "01234567-89ab-4cde-8fab-0123456789ab";
        let route = RouteV1 {
            component_store_id: store.into(),
            route_id: "bridge-route".into(),
            worker_uid: 1000,
        };
        let intent = OutboxIntentV1 {
            effect_id: "effect".into(),
            producer_scope: "scope".into(),
            event_key: "event".into(),
            payload_sha256: format!("{:x}", Sha256::digest(b"text")),
            payload_length: 4,
            target_binding: BindingV1 {
                pool_store_id: "pool-store".into(),
                pool_id: "pool".into(),
                member_id: "member".into(),
                binding_generation: 1,
                attempt: AttemptRefV1 {
                    run_store_id: "store_run".into(),
                    lineage_root_id: "root".into(),
                    execution_id: "exec".into(),
                    sequence: 1,
                    attempt_id: "attempt".into(),
                    launch_id: store.into(),
                },
                actor: ActorV1 {
                    address: "lab/codex/store/session".into(),
                    role: ActorRoleV1::Root,
                    native_id: "session".into(),
                    epoch: 1,
                },
                run_route: RouteV1 {
                    component_store_id: "store_run".into(),
                    route_id: "run-route".into(),
                    worker_uid: 1000,
                },
                bridge_route: route.clone(),
            },
            expected_incarnation: IncarnationV1 {
                host_id: "lab".into(),
                boot_id: store.into(),
                pid_namespace_inode: 2,
                uid: 1000,
                pid: 42,
                start_ticks: 7,
            },
            bridge_route: route,
            mode: ManagedModeV1::Message,
            retention: ManagedRetentionV1::KeepAll,
        };
        let digest = egress_intent_digest(&intent).unwrap();
        assert_eq!(
            digest,
            "72518e5ded118c2d5922aabd377f6f85fd4a906a6cd2775512daaadf7d77a6e9"
        );
        let mut request = OwnerRequestV2 {
            version: 2,
            thread_id: "session".into(),
            call_id: "dispatch-a".into(),
            outbox_intent: intent,
            effect_digest: digest.clone(),
            text: Secret::new("text"),
            wake_only: true,
        };
        request.validate().unwrap();
        request.call_id = "dispatch-b".into();
        request.validate().unwrap();
        assert_eq!(request.effect_digest, digest);
        for reason in [
            "attempt_not_ready",
            "attempt_mismatch",
            "qualification_pending",
        ] {
            let reply = OwnerReplyV2 {
                version: 2,
                call_id: request.call_id.clone(),
                effect_id: request.outbox_intent.effect_id.clone(),
                effect_digest: digest.clone(),
                state: OwnerStateV2::KnownUnsent,
                protocol: None,
                native_id: None,
                reason: Some(reason.into()),
            };
            reply.validate_for(&request, "codex_turn").unwrap();
        }
        // The reason list is closed: a near miss is still malformed.
        let unknown_reason = OwnerReplyV2 {
            version: 2,
            call_id: request.call_id.clone(),
            effect_id: request.outbox_intent.effect_id.clone(),
            effect_digest: digest.clone(),
            state: OwnerStateV2::KnownUnsent,
            protocol: None,
            native_id: None,
            reason: Some("attempt_mismatched".into()),
        };
        assert!(unknown_reason.validate_for(&request, "codex_turn").is_err());
        request.outbox_intent.target_binding.binding_generation += 1;
        assert!(request.validate().is_err());
        assert!(!format!("{request:?}").contains("text\""));
    }
}
