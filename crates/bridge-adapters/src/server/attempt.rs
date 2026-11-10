//! Separate additive B1 operations on the protected producer channel.
//! Existing producer DTOs and their strict parsers remain unchanged.

use super::*;
use bridge_protocol::{CallEvidence, Secret};
use serde::Deserialize;

/// Strict envelope shared with producer v1, decoded separately for B1 methods.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// Existing envelope version.
    api_version: u16,
    /// Caller-chosen exchange identity.
    request_id: String,
    /// Existing producer credential, always redacted.
    credential: Secret,
    /// Explicit B1 operation name.
    op: String,
    /// Strict typed operation parameters.
    params: serde_json::Value,
}

/// Version-only discovery input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discovery {
    /// B1 operation version.
    version: u16,
}
/// Native call reservation input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Current issuer epoch obtained from capability discovery.
    expected_issuer_epoch: String,
    /// Unique invocation identity.
    invocation_key: String,
    /// Exact configured command.
    command_name: String,
    /// Original native proof metadata.
    native_proof: CallEvidence,
}
/// Reserved context lookup input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextLookup {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Producer that owns the invocation.
    producer: String,
    /// Opaque protected context reference.
    bridge_context_ref: Secret,
    /// Unique invocation identity.
    invocation_key: String,
}
/// Final digest association input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Original context reference.
    bridge_context_ref: Secret,
    /// Unique invocation identity.
    invocation_key: String,
    /// Exact configured command.
    command_name: String,
    /// Full normalized command security digest.
    security_digest: String,
    /// Configured consumer audience.
    audience: String,
    /// Exact frontend nonce.
    nonce: String,
    /// Re-presented original native proof.
    native_proof: CallEvidence,
}
/// Assertion consumption input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consume {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Protected registered assertion key.
    assertion_key: Secret,
    /// Unique invocation identity.
    invocation_key: String,
    /// Full security digest.
    security_digest: String,
}
/// Exact committed observation lookup input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Producer that owns the invocation.
    producer: String,
    /// Original consume request identity.
    consume_request_id: String,
    /// Unique invocation identity.
    invocation_key: String,
    /// Full security digest.
    security_digest: String,
}
/// Consumer abort/tombstone input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Abort {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Producer that owns the invocation.
    producer: String,
    /// Original consume request identity.
    consume_request_id: String,
    /// Unique invocation identity.
    invocation_key: String,
    /// Full security digest.
    security_digest: String,
    /// Original configured consumer audience.
    audience: String,
}

/// Run-attested retirement of one old managed issuer namespace.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retire {
    /// B1 operation version.
    version: u16,
    /// Pre-pinned durable Bridge store.
    expected_store_id: String,
    /// Producer that owns the old namespace.
    producer: String,
    /// Old issuer epoch for which recovery is complete.
    issuer_epoch: String,
    /// Stable idempotent Run retirement intention.
    retirement_key: String,
}

/// Recognizes only the separate explicit B1 operation names.
pub(super) fn is_attempt_operation(name: &str) -> bool {
    matches!(
        name,
        "attempt_binding_capabilities_v1"
            | "prepare_native_context_v1"
            | "context_lookup_v1"
            | "register_launch_assertion_v1"
            | "consume_launch_assertion_v1"
            | "observation_lookup_v1"
            | "consume_launch_assertion_abort_v1"
            | "retire_attempt_namespace_v1"
            | "run_actor_lookup_v1"
            | "run_actor_recovery_status_v1"
    )
}

/// Validates a bounded opaque identifier without echoing it.
fn id(value: &str) -> bool {
    bridge_protocol::validate_id("id", value, bridge_protocol::MAX_ID_BYTES).is_ok()
}
/// Validates a normalized digest without accepting alternate spelling.
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
/// Decodes a known exact DTO after duplicate-key rejection.
fn params<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

/// Writes an existing content-free producer error without echoing the request.
pub(super) fn write_outer_error(
    writer: &mut UnixStream,
    request_id: &str,
    error: bridge_protocol::ApiError,
) {
    let response = bridge_protocol::Response::error(request_id, error);
    if let Ok(mut bytes) = bridge_protocol::encode_response(&response) {
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes);
    }
}

/// Refuses a not-yet-decoded B1 frame because the channel is at capacity: the
/// versioned `capacity_exhausted` outcome with the `same_key_lookup` recovery
/// class, correlated by the request's own id and operation. Nothing was
/// decoded or executed, so the identical request (same id and keys) may simply
/// be repeated. A frame without a usable id or operation gets the producer
/// protocol's outer busy error instead.
pub(super) fn busy(line: &str, store_id: &str, writer: &mut UnixStream) {
    let value = serde_json::from_str::<serde_json::Value>(line).ok();
    let field = |name: &str| {
        value
            .as_ref()
            .and_then(|value| value.get(name))
            .and_then(serde_json::Value::as_str)
            .filter(|text| id(text))
            .map(str::to_string)
    };
    let (Some(request_id), Some(op)) = (field("request_id"), field("op")) else {
        producer::busy_v1(line, writer);
        return;
    };
    let response = serde_json::json!({
        "api_version": 1,
        "request_id": request_id,
        "success": true,
        "result": {"op": op, "value": {"status": "error", "error": {
            "version": 1,
            "store_id": store_id,
            "code": super::BUSY_CODE,
            "recovery": "same_key_lookup",
        }}},
    });
    if let Ok(mut bytes) = serde_json::to_vec(&response) {
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes);
    }
}

/// Serves one strict B1 frame; malformed/authentication errors use the existing
/// outer error shape and managed operation refusals use the versioned outcome.
pub(super) fn serve(
    line: &str,
    peer: os::PeerIdentity,
    state: &ChannelState,
    writer: &mut UnixStream,
) {
    // This versioned managed operation receives raw bytes: do not let an
    // overflowing integer token silently become an f64 during JSON parsing.
    if bridge_protocol::managed_owner::validate_raw_integer_tokens(line.as_bytes()).is_err() {
        producer::serve_v1(line, peer, state, writer);
        return;
    }
    let raw = bridge_protocol::decode_strict_object(
        line.trim_end_matches('\n').as_bytes(),
        MAX_REQUEST_BYTES,
    )
    .ok()
    .and_then(|value| serde_json::from_value::<Request>(value).ok());
    let Some(request) = raw.filter(|r| {
        r.api_version == 1
            && id(&r.request_id)
            && id(r.credential.expose())
            && is_attempt_operation(&r.op)
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
            write_outer_error(writer, &request.request_id, error);
            return;
        }
    };
    let grant = match authorizer.authenticate(request.credential.expose()) {
        Ok(grant) => grant,
        Err(error) => {
            write_outer_error(writer, &request.request_id, error);
            return;
        }
    };
    crate::registry::refresh_stale(&state.registry);
    let producer = grant.producer();
    let mut registry = lock_registry(&state.registry);
    let now = current_unix_millis();
    let store_id = registry.attempt_store_id();
    let invalid = || crate::registry::AttemptError {
        code: "capability_missing",
        recovery: "none",
    };
    let unsupported = || crate::registry::AttemptError {
        code: "unsupported_version",
        recovery: "none",
    };
    let result = match request.op.as_str() {
        "attempt_binding_capabilities_v1" => match params::<Discovery>(request.params) {
            Some(p) if p.version == 1 => registry.attempt_capabilities(peer, producer),
            Some(_) => Err(unsupported()),
            None => Err(invalid()),
        },
        "prepare_native_context_v1" => match params::<Prepare>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(&p.expected_issuer_epoch)
                    && id(&p.invocation_key)
                    && id(&p.command_name) =>
            {
                match producer::evidence(&p.native_proof) {
                    Ok(meta) => registry.prepare_attempt(
                        &p.expected_store_id,
                        &p.expected_issuer_epoch,
                        peer,
                        &meta,
                        now,
                        producer,
                        &p.invocation_key,
                        &p.command_name,
                        grant,
                    ),
                    Err(_) => Err(invalid()),
                }
            }
            _ => Err(invalid()),
        },
        "context_lookup_v1" => match params::<ContextLookup>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(&p.producer)
                    && id(p.bridge_context_ref.expose())
                    && id(&p.invocation_key) =>
            {
                registry.lookup_attempt_context(
                    &p.expected_store_id,
                    peer,
                    producer,
                    &p.producer,
                    p.bridge_context_ref.expose(),
                    &p.invocation_key,
                    now,
                )
            }
            _ => Err(invalid()),
        },
        "register_launch_assertion_v1" => match params::<Register>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(p.bridge_context_ref.expose())
                    && id(&p.invocation_key)
                    && id(&p.command_name)
                    && hash(&p.security_digest)
                    && id(&p.audience)
                    && id(&p.nonce) =>
            {
                match producer::evidence(&p.native_proof) {
                    Ok(meta) => registry.register_attempt(
                        &p.expected_store_id,
                        peer,
                        &meta,
                        now,
                        producer,
                        p.bridge_context_ref.expose(),
                        &p.invocation_key,
                        &p.command_name,
                        &p.security_digest,
                        &p.audience,
                        &p.nonce,
                        grant.assertion_audiences(),
                        grant,
                    ),
                    Err(_) => Err(invalid()),
                }
            }
            _ => Err(invalid()),
        },
        "consume_launch_assertion_v1" => match params::<Consume>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(p.assertion_key.expose())
                    && id(&p.invocation_key)
                    && hash(&p.security_digest) =>
            {
                registry.consume_attempt(
                    &p.expected_store_id,
                    peer,
                    producer,
                    &request.request_id,
                    p.assertion_key.expose(),
                    &p.invocation_key,
                    &p.security_digest,
                    grant.assertion_audiences(),
                    now,
                )
            }
            _ => Err(invalid()),
        },
        "observation_lookup_v1" => match params::<Lookup>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(&p.producer)
                    && id(&p.consume_request_id)
                    && id(&p.invocation_key)
                    && hash(&p.security_digest) =>
            {
                registry.lookup_attempt(
                    &p.expected_store_id,
                    peer,
                    producer,
                    &p.producer,
                    &p.consume_request_id,
                    &p.invocation_key,
                    &p.security_digest,
                    grant.assertion_audiences(),
                    now,
                )
            }
            _ => Err(invalid()),
        },
        "consume_launch_assertion_abort_v1" => match params::<Abort>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(&p.producer)
                    && id(&p.consume_request_id)
                    && id(&p.invocation_key)
                    && hash(&p.security_digest)
                    && id(&p.audience) =>
            {
                registry.abort_attempt(
                    &p.expected_store_id,
                    peer,
                    producer,
                    &p.producer,
                    &p.consume_request_id,
                    &p.invocation_key,
                    &p.security_digest,
                    &p.audience,
                    grant.assertion_audiences(),
                )
            }
            _ => Err(invalid()),
        },
        "retire_attempt_namespace_v1" => match params::<Retire>(request.params) {
            Some(p) if p.version != 1 => Err(unsupported()),
            Some(p)
                if id(&p.expected_store_id)
                    && id(&p.producer)
                    && id(&p.issuer_epoch)
                    && id(&p.retirement_key) =>
            {
                registry.retire_attempt_namespace(
                    &p.expected_store_id,
                    peer,
                    producer,
                    &p.producer,
                    &p.issuer_epoch,
                    &p.retirement_key,
                )
            }
            _ => Err(invalid()),
        },
        "run_actor_lookup_v1" | "run_actor_recovery_status_v1" => {
            match params::<bridge_protocol::managed_owner::RunActorLookupParamsV1>(request.params) {
                Some(p) if p.version != 1 => Err(unsupported()),
                Some(p)
                    if id(&p.expected_store_id)
                        && id(&p.producer)
                        && id(&p.incarnation.host_id)
                        && os::attempt::canonical_uuid(&p.incarnation.boot_id)
                        && os::attempt::canonical_uuid(&p.launch_id)
                        && p.incarnation.pid_namespace_inode != 0
                        && p.incarnation.pid != 0
                        && p.incarnation.start_ticks != 0 =>
                {
                    if request.op == "run_actor_lookup_v1" {
                        registry.run_actor_lookup(peer, producer, &p)
                    } else {
                        registry.run_actor_recovery_status(peer, producer, &p)
                    }
                }
                _ => Err(invalid()),
            }
        }
        _ => Err(invalid()),
    };
    let value = match result {
        Ok(value) => serde_json::json!({"status":"ok","value":value}),
        Err(error) => {
            serde_json::json!({"status":"error","error":{"version":1,"store_id":store_id,"code":error.code,"recovery":error.recovery}})
        }
    };
    let response = serde_json::json!({"api_version":1,"request_id":request.request_id,"success":true,"result":{"op":request.op,"value":value}});
    if let Ok(mut bytes) = serde_json::to_vec(&response) {
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes);
    }
}
