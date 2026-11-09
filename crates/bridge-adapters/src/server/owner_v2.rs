//! Separate managed owner v2 custody channel and pinned Run receipt verifier.
//!
//! All I/O is bounded and outside registry/custody locks. The adapter never
//! accepts a caller-supplied receipt as authority or selects an alternate route.

use super::*;
use crate::registry::{AttemptError, ManagedOwnerRoute};
use bridge_core::owner_v2::{
    OwnerEffect, OwnerEffectResult, OwnerRecoveryIdentity, OwnerReservation,
};
use bridge_protocol::{
    Secret,
    attempt::{ActorV1, IncarnationV1},
    managed_owner::{
        AttemptRefV1, CompactManagedOwnerScopeParamsV1 as Compact,
        LookupManagedOwnerParamsV1 as Lookup, ManagedOwnerStateV1, OutboxIntentV1, OwnerRequestV2,
        PublishManagedOwnerParamsV1 as Publish, validate_raw_integer_tokens,
    },
};
use std::io::Read;

/// Exact additive envelope, decoded independently from legacy operation DTOs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Existing producer envelope version.
    api_version: u16,
    /// Per-dispatch correlation.
    request_id: String,
    /// Protected producer credential.
    credential: Secret,
    /// Explicit managed operation name.
    op: String,
    /// Strict operation-specific parameters.
    params: serde_json::Value,
}

/// Run's durable lineage step; a root parent may explicitly be null.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainNode {
    /// Execution at this lineage step.
    execution_id: String,
    /// Parent execution, explicitly null only at the root.
    #[serde(deserialize_with = "nullable")]
    parent_execution_id: Option<String>,
    /// Positive attempt sequence.
    sequence: u32,
}

/// Run-proven same-lineage path to the frozen target.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorProof {
    /// Immutable lineage root.
    lineage_root_id: String,
    /// Original bound execution.
    bound_execution_id: String,
    /// Latest current execution.
    current_execution_id: String,
    /// Nonempty ordered chain.
    chain: Vec<ChainNode>,
}

/// The immutable Run receipt returned only by the authenticated endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentReceipt {
    /// Durable receipt identity.
    receipt_id: String,
    /// This read is valid only for `egress`.
    purpose: String,
    /// Original lineage root.
    lineage_root_id: String,
    /// Bound execution used to request the observation.
    bound_execution_id: String,
    /// Exact current attempt.
    attempt: AttemptRefV1,
    /// Full original process identity.
    incarnation: IncarnationV1,
    /// Exact current native root actor.
    actor: ActorV1,
    /// Durable same-lineage proof.
    successor_proof: SuccessorProof,
}

/// Exact successful Run result.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptResult {
    /// Must be 1.
    version: u16,
    /// Exact pinned Run store.
    store_id: String,
    /// Durable Run receipt.
    receipt: CurrentReceipt,
}

/// Strict Run JSON-RPC-like successful envelope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunEnvelope {
    /// Exact request correlation.
    id: String,
    /// Exact successful result.
    result: serde_json::Value,
}

/// Run R3's authenticated effect-recovery boundary. Implementations must use
/// the original pinned route and return only validated durable observations.
trait RunOwnerRecovery {
    /// Looks up the original effect without sending or retargeting it.
    fn lookup(
        &self,
        route: &ManagedOwnerRoute,
        effect: &OwnerRecoveryIdentity,
    ) -> Option<RunEffectResult>;
    /// Requests the original effect's Run-side permanent writer fence.
    fn abort(
        &self,
        route: &ManagedOwnerRoute,
        effect: &OwnerRecoveryIdentity,
    ) -> Option<RunEffectResult>;
}

/// Authenticated Run effect lookup/abort on the pinned receipt endpoint.
struct PinnedRunOwnerRecovery<'a> {
    /// Existing protected adapter-channel state.
    state: &'a ChannelState,
}
impl RunOwnerRecovery for PinnedRunOwnerRecovery<'_> {
    /// Retrieves an exact original effect without mutating it.
    fn lookup(
        &self,
        route: &ManagedOwnerRoute,
        effect: &OwnerRecoveryIdentity,
    ) -> Option<RunEffectResult> {
        run_effect(self.state, route, effect, "_owner_effect_lookup_v2")
    }
    /// Installs or reads the exact original effect's Run writer fence.
    fn abort(
        &self,
        route: &ManagedOwnerRoute,
        effect: &OwnerRecoveryIdentity,
    ) -> Option<RunEffectResult> {
        run_effect(self.state, route, effect, "_owner_effect_abort_v2")
    }
}

/// R3's durable effect state, including absence that is not a fence.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RunEffectState {
    /// Snapshot absence, never proof that a late writer cannot arrive.
    Absent,
    /// Permanent Run writer tombstone.
    Aborted,
    /// Positive pre-effect result, not by itself a Bridge late-writer fence.
    KnownUnsent,
    /// The original native effect may have happened.
    Unknown,
    /// Original exact-host native receipt was durably recorded.
    Accepted,
}

/// Closed correlated effect result from the authenticated Run store.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunEffectResult {
    /// Must be 2.
    version: u16,
    /// Exact pinned Run store.
    store_id: String,
    /// Original producer namespace.
    producer_scope: String,
    /// Original effect identity.
    effect_id: String,
    /// Original immutable digest.
    effect_digest: String,
    /// Durable Run state.
    state: RunEffectState,
    /// Native protocol on acceptance, otherwise null.
    #[serde(deserialize_with = "nullable")]
    protocol: Option<String>,
    /// Native receipt on acceptance, otherwise null.
    #[serde(deserialize_with = "nullable")]
    native_id: Option<String>,
    /// Finite refusal or uncertainty reason, where applicable.
    #[serde(deserialize_with = "nullable")]
    reason: Option<String>,
}

/// Requires a nullable field to be present rather than implicitly absent.
fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

/// Bounded opaque identity validation with no rejected values in diagnostics.
fn id(value: &str) -> bool {
    bridge_protocol::validate_id("id", value, bridge_protocol::MAX_ID_BYTES).is_ok()
}

/// Validates a normalized SHA-256 spelling.
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Checks the exact lineage segment and all immutable target associations.
fn receipt_matches(receipt: &CurrentReceipt, receipt_id: &str, intent: &OutboxIntentV1) -> bool {
    let binding = &intent.target_binding;
    let proof = &receipt.successor_proof;
    let chain = &proof.chain;
    let mut unique = std::collections::HashSet::new();
    receipt.receipt_id == receipt_id
        && receipt.purpose == "egress"
        && receipt.attempt == binding.attempt
        && receipt.actor == binding.actor
        && receipt.incarnation == intent.expected_incarnation
        && receipt.lineage_root_id == binding.attempt.lineage_root_id
        && proof.lineage_root_id == receipt.lineage_root_id
        && proof.bound_execution_id == receipt.bound_execution_id
        && proof.current_execution_id == binding.attempt.execution_id
        && !chain.is_empty()
        && chain.len() <= 4096
        && chain
            .first()
            .is_some_and(|node| node.execution_id == receipt.bound_execution_id)
        && chain.last().is_some_and(|node| {
            node.execution_id == binding.attempt.execution_id
                && node.sequence == binding.attempt.sequence
        })
        && chain.iter().all(|node| {
            id(&node.execution_id)
                && node.sequence > 0
                && node
                    .parent_execution_id
                    .as_ref()
                    .is_none_or(|parent| id(parent))
                && unique.insert(&node.execution_id)
        })
        && chain.windows(2).all(|pair| {
            pair[1].parent_execution_id.as_deref() == Some(&pair[0].execution_id)
                && pair[0].sequence.checked_add(1) == Some(pair[1].sequence)
        })
}

/// Reads a single bounded NDJSON response under one absolute deadline.
fn response_line(stream: &mut UnixStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        stream
            .set_read_timeout(Some(crate::desktop::remaining(deadline).ok()?))
            .ok()?;
        let count = match stream.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if let Some(end) = buf[..count].iter().position(|byte| *byte == b'\n') {
            if end + 1 != count || bytes.len().checked_add(end)? > 1_048_575 {
                return None;
            }
            bytes.extend_from_slice(&buf[..end]);
            return Some(bytes);
        }
        if bytes.len().checked_add(count)? > 1_048_575 {
            return None;
        }
        bytes.extend_from_slice(&buf[..count]);
    }
}

/// Writes a complete frame without extending its original absolute deadline.
fn write_deadline(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        let Ok(remaining) = crate::desktop::remaining(deadline) else {
            return false;
        };
        if stream.set_write_timeout(Some(remaining)).is_err() {
            return false;
        }
        match stream.write(bytes) {
            Ok(0) => return false,
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => return false,
        }
    }
    true
}

/// Sends one closed request to the exact pinned Run server, authenticating the
/// same connected peer before and after the exchange. Never exposes responses.
#[cfg(target_os = "linux")]
fn run_exchange(
    state: &ChannelState,
    route: &ManagedOwnerRoute,
    uid: u32,
    request_id: &str,
    method: &str,
    params: serde_json::Value,
) -> Option<serde_json::Value> {
    let socket = route.run_home.join("attempt-receipts.sock");
    if crate::owner::check_socket(&socket, uid).is_err() {
        return None;
    }
    // Run verifies the Bridge executable build before reading the request;
    // include that bounded authentication work in the exchange budget.
    let deadline = Instant::now() + Duration::from_secs(15);
    let before_connect_ticks = os::attempt::sample_start_ticks().ok()?;
    let mut stream = match os::connect_unix(&socket, deadline) {
        Ok(stream) => stream,
        Err(_) => return None,
    };
    let peer = match os::peer_identity(&stream) {
        Ok(peer) => peer,
        Err(_) => return None,
    };
    let before = match os::attempt::kernel_incarnation(peer.pid, peer.uid) {
        Ok(identity) => identity,
        Err(_) => return None,
    };
    if before.start_ticks > before_connect_ticks {
        return None;
    }
    if lock_registry(&state.registry)
        .verify_owner_v2_run_peer(peer, route)
        .is_err()
        || crate::owner::check_socket(&socket, uid).is_err()
    {
        return None;
    }
    let request = serde_json::json!({"id":request_id,"method":method,"params":params});
    let mut bytes = match serde_json::to_vec(&request) {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    bytes.push(b'\n');
    if !write_deadline(&mut stream, &bytes, deadline) {
        return None;
    }
    let frame = response_line(&mut stream, deadline)?;
    if validate_raw_integer_tokens(&frame).is_err()
        || os::attempt::kernel_incarnation(peer.pid, peer.uid)
            .ok()
            .as_ref()
            != Some(&before)
        || lock_registry(&state.registry)
            .verify_owner_v2_run_peer(peer, route)
            .is_err()
        || crate::owner::check_socket(&socket, uid).is_err()
    {
        return None;
    }
    let response: RunEnvelope = bridge_protocol::decode_strict_object(&frame, 1_048_575)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())?;
    (response.id == request_id).then_some(response.result)
}

/// Retrieves and verifies Run's original egress currentness receipt.
fn run_receipt(
    state: &ChannelState,
    route: &ManagedOwnerRoute,
    intent: &OutboxIntentV1,
    receipt_id: &str,
    request_id: &str,
) -> bool {
    let params = serde_json::json!({"version":1,"expected_store_id":intent.target_binding.attempt.run_store_id,"receipt_id":receipt_id});
    let result = run_exchange(
        state,
        route,
        intent.expected_incarnation.uid,
        request_id,
        "_attempt_current_receipt_v1",
        params,
    )
    .and_then(|value| serde_json::from_value::<ReceiptResult>(value).ok());
    result.is_some_and(|result| {
        result.version == 1
            && result.store_id == intent.target_binding.attempt.run_store_id
            && receipt_matches(&result.receipt, receipt_id, intent)
    })
}

/// Reads or aborts one exact effect under the distinct configured Run grant.
fn run_effect(
    state: &ChannelState,
    route: &ManagedOwnerRoute,
    effect: &OwnerRecoveryIdentity,
    method: &str,
) -> Option<RunEffectResult> {
    let intent = &effect.intent;
    let digest = bridge_protocol::managed_owner::egress_intent_digest(intent).ok()?;
    let params = serde_json::json!({"version":2,"expected_store_id":intent.target_binding.attempt.run_store_id,
        "producer_scope":intent.producer_scope,"effect_id":intent.effect_id,"effect_digest":digest});
    let response: RunEffectResult = serde_json::from_value(run_exchange(
        state,
        route,
        intent.expected_incarnation.uid,
        &intent.effect_id,
        method,
        params,
    )?)
    .ok()?;
    if response.version != 2
        || response.store_id != intent.target_binding.attempt.run_store_id
        || response.producer_scope != intent.producer_scope
        || response.effect_id != intent.effect_id
        || response.effect_digest != digest
    {
        return None;
    }
    let expected_protocol =
        bridge_protocol::NativeAddress::parse(&intent.target_binding.actor.address)
            .ok()
            .and_then(|address| match address.harness.as_str() {
                "codex" => Some("codex_turn"),
                "claude-code" => Some("claude_input"),
                _ => None,
            })?;
    let valid = match (
        response.state,
        response.protocol.as_deref(),
        response.native_id.as_deref(),
        response.reason.as_deref(),
    ) {
        (RunEffectState::Absent | RunEffectState::Aborted, None, None, None) => true,
        (RunEffectState::Accepted, Some(protocol), Some(native), None) => {
            protocol == expected_protocol && id(native)
        }
        (RunEffectState::Unknown, None, None, Some("native_uncertain" | "channel_failed")) => true,
        (
            RunEffectState::KnownUnsent,
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
                | "qualification_pending",
            ),
        ) => true,
        _ => false,
    };
    valid.then_some(response)
}

/// Converts only authoritative Run states; absence and bare known-unsent
/// cannot fence a delayed Bridge writer.
fn run_authoritative(result: RunEffectResult) -> Option<OwnerEffectResult> {
    let state = match result.state {
        RunEffectState::Accepted => ManagedOwnerStateV1::Accepted,
        RunEffectState::Aborted => ManagedOwnerStateV1::Aborted,
        RunEffectState::Unknown => ManagedOwnerStateV1::Unknown,
        RunEffectState::Absent | RunEffectState::KnownUnsent => return None,
    };
    Some(OwnerEffectResult {
        state,
        protocol: result.protocol,
        native_id: result.native_id,
        reason: result.reason,
    })
}

/// Durably reconciles only an authenticated, exact original Run outcome.
fn commit_run_result(
    state: &ChannelState,
    identity: &OwnerRecoveryIdentity,
    digest: &str,
    result: &OwnerEffectResult,
) -> Result<OwnerEffectResult, AttemptError> {
    with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_apply_run_result(
            &identity.intent.producer_scope,
            &identity.intent.effect_id,
            digest,
            result,
        )
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|error| match error {
        bridge_core::CoreError::Integrity(_) => AttemptError {
            code: "recovery_required",
            recovery: "operator",
        },
        _ => AttemptError {
            code: "recovery_required",
            recovery: "same_key_lookup",
        },
    })
}

/// Hashes only the immutable target; executable build pins are rotated in the
/// current configuration and are checked independently on each connection.
fn route_fingerprint(route: &ManagedOwnerRoute) -> Result<String, AttemptError> {
    let target = serde_json::to_value((
        &route.producer,
        &route.audience,
        &route.run_home,
        &route.run_route,
        &route.pool_route,
        &route.bridge_route,
    ))
    .map_err(|_| AttemptError {
        code: "recovery_required",
        recovery: "operator",
    })?;
    let mut bytes = b"agent-mcp/bridge/owner-route/v1\0".to_vec();
    bytes.extend(
        bridge_protocol::managed_owner::canonical_value(&target).map_err(|_| AttemptError {
            code: "recovery_required",
            recovery: "operator",
        })?,
    );
    Ok(sha256_hex(&bytes))
}

/// Both publishing and aborting require the same producer policy authority.
fn require_publish_grant(
    grant: &bridge_core::ProducerPolicyGrant,
    intent: &OutboxIntentV1,
) -> Result<(), AttemptError> {
    if !grant.policy().is_some_and(|policy| policy.delivery_scopes) {
        return Err(AttemptError {
            code: "capability_missing",
            recovery: "none",
        });
    }
    if !grant.allows_recipient(&intent.target_binding.actor.address)
        || !grant.modes().iter().any(|mode| mode == "message")
        || !grant.policies().iter().any(|policy| policy == "keep_all")
    {
        return Err(AttemptError {
            code: "peer_not_authorized",
            recovery: "none",
        });
    }
    Ok(())
}

/// Resolves a new target normally; an already-retained effect whose original
/// target no longer has a route needs explicit operator recovery.
fn publication_route(
    state: &ChannelState,
    peer: os::PeerIdentity,
    principal: &str,
    grant: &bridge_core::ProducerPolicyGrant,
    target: (&str, &str),
    request: &OwnerRequestV2,
) -> Result<ManagedOwnerRoute, AttemptError> {
    let (expected_store, audience) = target;
    let intent = &request.outbox_intent;
    let route = lock_registry(&state.registry).owner_v2_route(
        expected_store,
        peer,
        principal,
        audience,
        grant.assertion_audiences(),
        intent,
    );
    match route {
        Ok(route) => Ok(route),
        Err(error) if matches!(error.code, "capability_missing" | "route_mismatch") => {
            lock_registry(&state.registry).owner_v2_access(
                expected_store,
                peer,
                principal,
                audience,
                grant.assertion_audiences(),
                &intent.producer_scope,
            )?;
            let existing = with_custody(state.custody.as_ref(), |storage| {
                storage.owner_v2_lookup(
                    principal,
                    audience,
                    &intent.producer_scope,
                    &intent.effect_id,
                    &request.effect_digest,
                )
            })
            .ok_or(AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            })?
            .map_err(|error| storage_error(&error))?;
            if existing.is_some() {
                Err(AttemptError {
                    code: "recovery_required",
                    recovery: "operator",
                })
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

/// Recognizes only the separate additive managed owner operation names.
pub(super) fn is_owner_operation(name: &str) -> bool {
    matches!(
        name,
        "publish_managed_owner_v1"
            | "lookup_managed_owner_v1"
            | "abort_managed_owner_v1"
            | "compact_managed_owner_scope_v1"
    )
}

/// Fences Bridge dispatch locally, then authenticates Run's permanent
/// same-effect abort. A lost Run ACK leaves the local intention unresolved.
fn abort(
    state: &ChannelState,
    peer: os::PeerIdentity,
    principal: &str,
    grant: &bridge_core::ProducerPolicyGrant,
    request_id: &str,
    params: Publish,
) -> Result<serde_json::Value, AttemptError> {
    let invalid = || AttemptError {
        code: "capability_missing",
        recovery: "none",
    };
    if !id(&params.expected_store_id)
        || !id(&params.audience)
        || !id(&params.run_receipt_id)
        || !hash(&params.effect_digest)
    {
        return Err(invalid());
    }
    require_publish_grant(grant, &params.outbox_intent)?;
    let request = OwnerRequestV2 {
        version: 2,
        thread_id: params.outbox_intent.target_binding.actor.native_id.clone(),
        call_id: request_id.into(),
        outbox_intent: params.outbox_intent,
        effect_digest: params.effect_digest,
        text: params.text,
        wake_only: true,
    };
    request.validate().map_err(|_| invalid())?;
    let route = publication_route(
        state,
        peer,
        principal,
        grant,
        (&params.expected_store_id, &params.audience),
        &request,
    )?;
    let route_fingerprint = route_fingerprint(&route)?;
    let effect = OwnerEffect {
        producer: principal,
        audience: &params.audience,
        intent: &request.outbox_intent,
        digest: &request.effect_digest,
        run_receipt_id: &params.run_receipt_id,
        route_fingerprint: &route_fingerprint,
        call_id: request_id,
        text: request.text.expose(),
    };
    let reservation = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_begin_abort(&effect)
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|error| storage_error(&error))?;
    let result = match reservation {
        OwnerReservation::Existing(result) => result,
        OwnerReservation::Invoke => {
            let identity = with_custody(state.custody.as_ref(), |storage| {
                storage.owner_v2_recovery_identity(
                    principal,
                    &params.audience,
                    &request.outbox_intent.producer_scope,
                    &request.outbox_intent.effect_id,
                    &request.effect_digest,
                )
            })
            .ok_or(AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            })?
            .map_err(|_| AttemptError {
                code: "recovery_required",
                recovery: "operator",
            })?
            .ok_or(AttemptError {
                code: "recovery_required",
                recovery: "operator",
            })?;
            let recovery = PinnedRunOwnerRecovery { state };
            if let Some(remote) = recovery.abort(&route, &identity)
                && let Some(authoritative) = run_authoritative(remote)
            {
                commit_run_result(state, &identity, &request.effect_digest, &authoritative)?
            } else {
                // No authenticated fence arrived. Keep abort_pending durable so
                // exact replay can retry and no late Bridge dispatch can start.
                with_custody(state.custody.as_ref(), |storage| {
                    storage.owner_v2_lookup(
                        principal,
                        &params.audience,
                        &request.outbox_intent.producer_scope,
                        &request.outbox_intent.effect_id,
                        &request.effect_digest,
                    )
                })
                .ok_or(AttemptError {
                    code: "recovery_required",
                    recovery: "same_key_lookup",
                })?
                .map_err(|_| AttemptError {
                    code: "recovery_required",
                    recovery: "same_key_lookup",
                })?
                .ok_or(AttemptError {
                    code: "recovery_required",
                    recovery: "operator",
                })?
            }
        }
    };
    Ok(result_value(
        &params.expected_store_id,
        principal,
        &request.outbox_intent.producer_scope,
        &request.outbox_intent.effect_id,
        &request.effect_digest,
        &result,
    ))
}

/// Maps storage failures to finite, content-free managed recovery classes.
fn storage_error(error: &bridge_core::CoreError) -> AttemptError {
    match error {
        bridge_core::CoreError::Capacity { .. } => AttemptError {
            code: "capacity_exhausted",
            recovery: "operator",
        },
        bridge_core::CoreError::Fence(reason) if reason == "managed owner scope retired" => {
            AttemptError {
                code: "aborted",
                recovery: "none",
            }
        }
        bridge_core::CoreError::Fence(reason) if reason == "managed owner target route changed" => {
            AttemptError {
                code: "recovery_required",
                recovery: "operator",
            }
        }
        bridge_core::CoreError::Fence(reason) if reason == "managed owner scope not retired" => {
            AttemptError {
                code: "binding_unavailable",
                recovery: "none",
            }
        }
        bridge_core::CoreError::Fence(_) => AttemptError {
            code: "intent_conflict",
            recovery: "none",
        },
        bridge_core::CoreError::InvalidEnvelope(_) => AttemptError {
            code: "capability_missing",
            recovery: "none",
        },
        _ => AttemptError {
            code: "recovery_required",
            recovery: "same_key_lookup",
        },
    }
}

/// Retained success shape; no native payload, route path or receipt contents.
fn result_value(
    store: &str,
    producer: &str,
    scope: &str,
    effect: &str,
    digest: &str,
    result: &OwnerEffectResult,
) -> serde_json::Value {
    serde_json::json!({"version":1,"store_id":store,"producer":producer,"producer_scope":scope,
        "effect_id":effect,"effect_digest":digest,"state":result.state,"protocol":result.protocol,
        "native_id":result.native_id,"reason":result.reason})
}

/// A positive pre-write refusal, after the durable effect fence exists.
fn unsent(reason: &'static str) -> OwnerEffectResult {
    OwnerEffectResult {
        state: ManagedOwnerStateV1::KnownUnsent,
        protocol: None,
        native_id: None,
        reason: Some(reason.into()),
    }
}

/// Publishes one immutable effect without sharing a legacy manifest or route.
fn publish(
    state: &ChannelState,
    peer: os::PeerIdentity,
    principal: &str,
    grant: &bridge_core::ProducerPolicyGrant,
    request_id: &str,
    params: Publish,
) -> Result<serde_json::Value, AttemptError> {
    let invalid = || AttemptError {
        code: "capability_missing",
        recovery: "none",
    };
    if !id(&params.expected_store_id)
        || !id(&params.audience)
        || !id(&params.run_receipt_id)
        || !hash(&params.effect_digest)
    {
        return Err(invalid());
    }
    require_publish_grant(grant, &params.outbox_intent)?;
    let request = OwnerRequestV2 {
        version: 2,
        thread_id: params.outbox_intent.target_binding.actor.native_id.clone(),
        call_id: request_id.into(),
        outbox_intent: params.outbox_intent,
        effect_digest: params.effect_digest,
        text: params.text,
        wake_only: true,
    };
    request.validate().map_err(|_| invalid())?;
    let route = publication_route(
        state,
        peer,
        principal,
        grant,
        (&params.expected_store_id, &params.audience),
        &request,
    )?;
    let route_fingerprint = route_fingerprint(&route)?;
    let effect = OwnerEffect {
        producer: principal,
        audience: &params.audience,
        intent: &request.outbox_intent,
        digest: &request.effect_digest,
        run_receipt_id: &params.run_receipt_id,
        route_fingerprint: &route_fingerprint,
        call_id: request_id,
        text: request.text.expose(),
    };
    let reservation = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_reserve(&effect)
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|error| storage_error(&error))?;
    let result = match reservation {
        OwnerReservation::Existing(result) => result,
        OwnerReservation::Invoke => {
            let mut cancelled = false;
            let process = &request.outbox_intent.expected_incarnation;
            let identity = os::attempt::KernelIncarnation {
                boot_id: process.boot_id.clone(),
                pid_namespace_inode: process.pid_namespace_inode,
                uid: process.uid,
                pid: process.pid,
                start_ticks: process.start_ticks,
            };
            let result = if let Some(socket) = crate::owner::preflight_v2(&identity) {
                if !lock_registry(&state.registry).owner_v2_target_current(&request.outbox_intent) {
                    unsent("actor_mismatch")
                } else if !run_receipt(
                    state,
                    &route,
                    &request.outbox_intent,
                    &params.run_receipt_id,
                    request_id,
                ) {
                    unsent("unavailable")
                } else {
                    crate::owner::deliver_v2(
                        &state.registry,
                        &route,
                        &identity,
                        &socket,
                        &request,
                        &mut || {
                            let invoking = with_custody(state.custody.as_ref(), |storage| {
                                storage.owner_v2_invoking(
                                    &request.outbox_intent.producer_scope,
                                    &request.outbox_intent.effect_id,
                                    request_id,
                                )
                            })
                            .is_some_and(|result| result.unwrap_or(false));
                            cancelled = !invoking;
                            invoking
                        },
                    )
                }
            } else {
                unsent("capability_missing")
            };
            if !cancelled {
                with_custody(state.custody.as_ref(), |storage| {
                    storage.owner_v2_finish(
                        &request.outbox_intent.producer_scope,
                        &request.outbox_intent.effect_id,
                        request_id,
                        &result,
                    )
                })
                .ok_or(AttemptError {
                    code: "recovery_required",
                    recovery: "same_key_lookup",
                })?
                .map_err(|_| AttemptError {
                    code: "recovery_required",
                    recovery: "same_key_lookup",
                })?;
            }
            result
        }
    };
    Ok(result_value(
        &params.expected_store_id,
        principal,
        &request.outbox_intent.producer_scope,
        &request.outbox_intent.effect_id,
        &request.effect_digest,
        &result,
    ))
}

/// Recovers the original durable effect state without any native I/O.
fn lookup(
    state: &ChannelState,
    peer: os::PeerIdentity,
    principal: &str,
    grant: &bridge_core::ProducerPolicyGrant,
    params: Lookup,
) -> Result<serde_json::Value, AttemptError> {
    if ![
        params.expected_store_id.as_str(),
        params.audience.as_str(),
        params.producer_scope.as_str(),
        params.effect_id.as_str(),
    ]
    .iter()
    .all(|value| id(value))
        || !hash(&params.effect_digest)
    {
        return Err(AttemptError {
            code: "capability_missing",
            recovery: "none",
        });
    }
    lock_registry(&state.registry).owner_v2_access(
        &params.expected_store_id,
        peer,
        principal,
        &params.audience,
        grant.assertion_audiences(),
        &params.producer_scope,
    )?;
    let found = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_lookup(
            principal,
            &params.audience,
            &params.producer_scope,
            &params.effect_id,
            &params.effect_digest,
        )
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|error| storage_error(&error))?;
    let mut result = match found {
        Some(result) => result,
        None => {
            let retired = with_custody(state.custody.as_ref(), |storage| {
                storage.owner_v2_scope_retired(principal, &params.producer_scope)
            })
            .ok_or(AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            })?
            .map_err(|_| AttemptError {
                code: "recovery_required",
                recovery: "same_key_lookup",
            })?;
            return Err(if retired {
                AttemptError {
                    code: "recovery_required",
                    recovery: "operator",
                }
            } else {
                AttemptError {
                    code: "binding_unavailable",
                    recovery: "same_key_lookup",
                }
            });
        }
    };
    let identity = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_recovery_identity(
            principal,
            &params.audience,
            &params.producer_scope,
            &params.effect_id,
            &params.effect_digest,
        )
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|_| AttemptError {
        code: "recovery_required",
        recovery: "operator",
    })?
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "operator",
    })?;
    let route = lock_registry(&state.registry)
        .owner_v2_route(
            &params.expected_store_id,
            peer,
            principal,
            &params.audience,
            grant.assertion_audiences(),
            &identity.intent,
        )
        .map_err(|_| AttemptError {
            code: "recovery_required",
            recovery: "operator",
        })?;
    if route_fingerprint(&route)? != identity.route_fingerprint {
        return Err(AttemptError {
            code: "recovery_required",
            recovery: "operator",
        });
    }
    if result.state == ManagedOwnerStateV1::Unknown {
        let recovery = PinnedRunOwnerRecovery { state };
        if let Some(remote) = recovery.lookup(&route, &identity)
            && matches!(
                remote.state,
                RunEffectState::Accepted | RunEffectState::Aborted
            )
            && let Some(authoritative) = run_authoritative(remote)
        {
            result = commit_run_result(state, &identity, &params.effect_digest, &authoritative)?;
        }
    }
    Ok(result_value(
        &params.expected_store_id,
        principal,
        &params.producer_scope,
        &params.effect_id,
        &params.effect_digest,
        &result,
    ))
}

/// Reclaims only closed-scope terminal rows, with a fresh Run confirmation
/// before deleting every accepted or aborted receipt.
fn compact(
    state: &ChannelState,
    peer: os::PeerIdentity,
    principal: &str,
    grant: &bridge_core::ProducerPolicyGrant,
    params: Compact,
) -> Result<serde_json::Value, AttemptError> {
    if ![
        &params.expected_store_id,
        &params.audience,
        &params.producer_scope,
    ]
    .iter()
    .all(|value| id(value))
        || !grant.policy().is_some_and(|policy| policy.delivery_scopes)
    {
        return Err(AttemptError {
            code: "capability_missing",
            recovery: "none",
        });
    }
    lock_registry(&state.registry).owner_v2_access(
        &params.expected_store_id,
        peer,
        principal,
        &params.audience,
        grant.assertion_audiences(),
        &params.producer_scope,
    )?;
    let mut candidates = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_compaction_candidates(principal, &params.audience, &params.producer_scope)
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|error| storage_error(&error))?;
    if !candidates.is_empty() {
        let offset = state
            .owner_compaction_cursor
            .fetch_add(1, Ordering::Relaxed)
            % candidates.len();
        candidates.rotate_left(offset);
    }
    let recovery = PinnedRunOwnerRecovery { state };
    let mut compacted = 0_u64;
    let mut checked_run = false;
    for candidate in candidates {
        if compacted >= 32 {
            break;
        }
        if candidate.result.state != ManagedOwnerStateV1::KnownUnsent {
            // One bounded Run exchange per pass keeps a stalled endpoint from
            // multiplying the request deadline by the number of receipts.
            if checked_run {
                continue;
            }
            checked_run = true;
            let route = lock_registry(&state.registry)
                .owner_v2_route(
                    &params.expected_store_id,
                    peer,
                    principal,
                    &params.audience,
                    grant.assertion_audiences(),
                    &candidate.identity.intent,
                )
                .map_err(|_| AttemptError {
                    code: "recovery_required",
                    recovery: "operator",
                })?;
            if route_fingerprint(&route)? != candidate.identity.route_fingerprint {
                return Err(AttemptError {
                    code: "recovery_required",
                    recovery: "operator",
                });
            }
            if recovery
                .lookup(&route, &candidate.identity)
                .and_then(run_authoritative)
                .as_ref()
                != Some(&candidate.result)
            {
                continue;
            }
        }
        let removed = with_custody(state.custody.as_ref(), |storage| {
            storage.owner_v2_compact_candidate(
                principal,
                &params.audience,
                &params.producer_scope,
                &candidate.identity.intent.effect_id,
                &candidate.digest,
                &candidate.result,
            )
        })
        .ok_or(AttemptError {
            code: "recovery_required",
            recovery: "same_key_lookup",
        })?
        .map_err(|_| AttemptError {
            code: "recovery_required",
            recovery: "same_key_lookup",
        })?;
        compacted += u64::from(removed);
    }
    let remaining = with_custody(state.custody.as_ref(), |storage| {
        storage.owner_v2_scope_count(principal, &params.audience, &params.producer_scope)
    })
    .ok_or(AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?
    .map_err(|_| AttemptError {
        code: "recovery_required",
        recovery: "same_key_lookup",
    })?;
    Ok(
        serde_json::json!({"version":1,"store_id":params.expected_store_id,"producer":principal,
        "producer_scope":params.producer_scope,"compacted":compacted,"remaining":remaining}),
    )
}

/// Authenticates and serves one strict owner v2 producer request.
pub(super) fn serve(
    line: &str,
    peer: os::PeerIdentity,
    state: &ChannelState,
    writer: &mut UnixStream,
) {
    if validate_raw_integer_tokens(line.as_bytes()).is_err() {
        producer::serve_v1(line, peer, state, writer);
        return;
    }
    let raw = bridge_protocol::decode_strict_object(
        line.trim_end_matches('\n').as_bytes(),
        MAX_REQUEST_BYTES,
    )
    .ok()
    .and_then(|value| serde_json::from_value::<Request>(value).ok());
    let Some(request) = raw.filter(|request| {
        request.api_version == 1
            && id(&request.request_id)
            && id(request.credential.expose())
            && is_owner_operation(&request.op)
    }) else {
        producer::serve_v1(line, peer, state, writer);
        return;
    };
    let unavailable = || bridge_protocol::ApiError {
        class: bridge_protocol::ErrorClass::Unavailable,
        reason: "producer_unavailable".into(),
        retry_hint: bridge_protocol::RetryHint::Never,
        effect: None,
        reconciliation: None,
        detail: "Producer service unavailable".into(),
    };
    let authorizer = with_custody(state.custody.as_ref(), |storage| {
        storage.producer_authorizer()
    })
    .unwrap_or_else(|| Err(unavailable()));
    let authorizer = match authorizer {
        Ok(value) => value,
        Err(error) => {
            attempt::write_outer_error(writer, &request.request_id, error);
            return;
        }
    };
    let grant = match authorizer.authenticate(request.credential.expose()) {
        Ok(grant) => grant,
        Err(error) => {
            attempt::write_outer_error(writer, &request.request_id, error);
            return;
        }
    };
    crate::registry::refresh_stale(&state.registry);
    let producer = grant.producer();
    let store_id = lock_registry(&state.registry).attempt_store_id();
    let invalid = || AttemptError {
        code: "capability_missing",
        recovery: "none",
    };
    let unsupported = || AttemptError {
        code: "unsupported_version",
        recovery: "none",
    };
    let result = match request.op.as_str() {
        "publish_managed_owner_v1" => match serde_json::from_value::<Publish>(request.params) {
            Ok(params) if params.version != 1 => Err(unsupported()),
            Ok(params) => publish(state, peer, producer, grant, &request.request_id, params),
            Err(_) => Err(invalid()),
        },
        "lookup_managed_owner_v1" => match serde_json::from_value::<Lookup>(request.params) {
            Ok(params) if params.version != 1 => Err(unsupported()),
            Ok(params) => lookup(state, peer, producer, grant, params),
            Err(_) => Err(invalid()),
        },
        "abort_managed_owner_v1" => match serde_json::from_value::<Publish>(request.params) {
            Ok(params) if params.version != 1 => Err(unsupported()),
            Ok(params) => abort(state, peer, producer, grant, &request.request_id, params),
            Err(_) => Err(invalid()),
        },
        "compact_managed_owner_scope_v1" => match serde_json::from_value::<Compact>(request.params)
        {
            Ok(params) if params.version != 1 => Err(unsupported()),
            Ok(params) => compact(state, peer, producer, grant, params),
            Err(_) => Err(invalid()),
        },
        _ => Err(invalid()),
    };
    let value = match result {
        Ok(value) => serde_json::json!({"status":"ok","value":value}),
        Err(error) => {
            serde_json::json!({"status":"error","error":{"version":1,"store_id":store_id,"code":error.code,"recovery":error.recovery}})
        }
    };
    if let Ok(mut bytes) = serde_json::to_vec(
        &serde_json::json!({"api_version":1,"request_id":request.request_id,"success":true,"result":{"op":request.op,"value":value}}),
    ) {
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes);
    }
}
