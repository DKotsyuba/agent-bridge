//! Typed, single-exchange clients for the additive managed-attempt operations.
//!
//! An uncertain write is never automatically retried. Callers retain their
//! original IDs and follow the operation's recovery protocol.

use crate::{Client, TransportOutcome, transport};
use bridge_protocol::managed_owner::{
    AbortManagedOwnerParamsV1, CompactManagedOwnerScopeParamsV1, CompactManagedOwnerScopeResultV1,
    LookupManagedOwnerParamsV1, ManagedOwnerResultV1, ManagedOwnerStateV1, OutboxIntentV1,
    PublishManagedOwnerParamsV1, RunActorLookupParamsV1, RunActorLookupResultV1,
    RunActorRecoveryStatusParamsV1, RunActorRecoveryStatusResultV1, RunActorStateV1,
    egress_intent_digest,
};
use bridge_protocol::{
    API_VERSION, ApiError, MAX_ID_BYTES, MAX_REGISTRATION_BYTES, ProtocolError, Secret, attempt::*,
    decode_strict_object, validate_id,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Out-of-band pinned Bridge server executable and exact SHA-256 build.
/// Every managed operation requires this value and validates the same connected
/// socket's kernel peer before transmitting any request or credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptServerPin {
    /// Absolute canonical server executable path.
    pub executable: std::path::PathBuf,
    /// Exact lowercase SHA-256 of that executable's loaded file.
    pub sha256: String,
}

impl AttemptServerPin {
    /// Creates an explicit pin; this performs no filesystem access or I/O.
    ///
    /// # Errors
    ///
    /// The executable path is not absolute or the digest is not lowercase SHA-256.
    pub fn new(
        executable: impl Into<std::path::PathBuf>,
        sha256: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let pin = Self {
            executable: executable.into(),
            sha256: sha256.into(),
        };
        pin.validate()?;
        Ok(pin)
    }

    /// Rechecks the caller-supplied pin before connecting.
    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if !self.executable.is_absolute() || !hash(&self.sha256) {
            return Err(ProtocolError::new(
                "server_pin",
                "invalid executable path or digest",
            ));
        }
        Ok(())
    }
}

/// Failure of a managed-attempt operation without request or payload details.
#[derive(Clone, PartialEq)]
pub enum AttemptClientError {
    /// Local request validation or encoding failed before any connection.
    InvalidRequest(ProtocolError),
    /// The authenticated server returned a structured outer producer error.
    Service(ApiError),
    /// The managed operation returned a correlated versioned refusal.
    Refused(AttemptErrorV1),
    /// Same-connection UID, PID, executable or loaded-build proof failed before write.
    PeerNotAuthorized,
    /// The responding store differs from the caller's pinned store.
    StoreMismatch {
        /// A mutation may have reached the unexpected store; recover the same key.
        outcome: TransportOutcome,
    },
    /// A bounded transport failure. Uncertain writes require same-key recovery.
    Transport {
        /// Observed request-write outcome.
        outcome: TransportOutcome,
        /// Static explanation with no request, response, socket or secret data.
        reason: &'static str,
    },
}

impl std::fmt::Debug for AttemptClientError {
    /// Never formats credentials, native evidence or untrusted response detail.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => f.debug_tuple("InvalidRequest").field(error).finish(),
            Self::Service(error) => f
                .debug_struct("Service")
                .field("class", &error.class)
                .finish(),
            Self::Refused(error) => f
                .debug_struct("Refused")
                .field("code", &error.code)
                .field("recovery", &error.recovery)
                .finish(),
            Self::PeerNotAuthorized => f.write_str("PeerNotAuthorized"),
            Self::StoreMismatch { outcome } => f
                .debug_struct("StoreMismatch")
                .field("outcome", outcome)
                .finish(),
            Self::Transport { outcome, reason } => f
                .debug_struct("Transport")
                .field("outcome", outcome)
                .field("reason", reason)
                .finish(),
        }
    }
}
impl std::fmt::Display for AttemptClientError {
    /// Reports only the safe diagnostic class.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AttemptClientError {}

/// Exact additive request envelope; no legacy operation enum is extended.
#[derive(Serialize)]
struct Request<'a, P> {
    /// Existing producer envelope version.
    api_version: u16,
    /// Exact caller-persisted correlation ID.
    request_id: &'a str,
    /// Configured protected producer credential.
    credential: &'a Secret,
    /// Explicit versioned managed operation.
    op: &'static str,
    /// Closed operation-specific parameters.
    params: &'a P,
}

/// Strict response branches enforce result/error exclusivity, including nulls.
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Envelope {
    /// Exactly one successful operation result.
    Success {
        /// Producer envelope version.
        api_version: u16,
        /// Exact caller correlation ID.
        request_id: String,
        /// True only for this success branch.
        success: bool,
        /// Matched managed operation result.
        result: ResultBody,
    },
    /// Exactly one authenticated outer service error.
    Failure {
        /// Producer envelope version.
        api_version: u16,
        /// Exact caller correlation ID.
        request_id: String,
        /// False only for this failure branch.
        success: bool,
        /// Content-free producer service error.
        error: ApiError,
    },
}

/// Managed result identified by the exact requested operation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    /// Echoed operation name.
    op: String,
    /// Tagged managed result.
    value: Outcome,
}

/// Closed success/refusal status; success value is decoded per operation.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Outcome {
    /// Successful operation-specific result.
    Ok {
        /// Strictly decoded per-operation value.
        value: serde_json::Value,
    },
    /// Structured managed refusal.
    Error {
        /// Finite content-free managed error.
        error: AttemptErrorV1,
    },
}

/// Validates a bounded opaque identifier without including it in diagnostics.
fn id(value: &str) -> bool {
    validate_id("id", value, MAX_ID_BYTES).is_ok()
}

/// Validates canonical lowercase UUID text without normalizing it.
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// Validates canonical lowercase SHA-256 text.
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validates original observation fields without claiming external authority.
fn observation(value: &ObservationV1) -> bool {
    let process = &value.incarnation;
    let actor_address = bridge_protocol::NativeAddress::parse(&value.actor.address).ok();
    id(&process.host_id)
        && uuid(&process.boot_id)
        && process.pid_namespace_inode != 0
        && process.pid != 0
        && process.start_ticks != 0
        && uuid(&value.launch_id)
        && id(&value.actor.address)
        && id(&value.actor.native_id)
        && value.actor.epoch != 0
        && actor_address.is_some_and(|address| {
            address.host == process.host_id
                && address.session == value.actor.native_id
                && address.canonical() == value.actor.address
        })
        && id(&value.native_call_id)
        && id(&value.tool_name)
        && value.observed_at_ms != 0
        && value.expires_at_ms > value.observed_at_ms
}

/// Validates a receipt's immutable shape and exact intention association.
fn receipt(
    value: &ConsumeReceiptV1,
    producer: Option<&str>,
    request: &str,
    invocation: &str,
    digest: &str,
) -> bool {
    id(&value.producer)
        && producer.is_none_or(|p| value.producer == p)
        && value.consume_request_id == request
        && value.invocation_key == invocation
        && value.security_digest == digest
        && hash(&value.security_digest)
        && id(&value.issuer_epoch)
        && value.consumed_at_ms != 0
        && observation(&value.observation)
}

/// Validates the exact effect association and state-specific receipt shape.
fn owner_result(value: &ManagedOwnerResultV1, scope: &str, effect: &str, digest: &str) -> bool {
    if !id(&value.producer)
        || value.producer_scope != scope
        || value.effect_id != effect
        || value.effect_digest != digest
        || !hash(&value.effect_digest)
    {
        return false;
    }
    match (
        value.state,
        value.protocol.as_deref(),
        value.native_id.as_deref(),
        value.reason.as_deref(),
    ) {
        (
            ManagedOwnerStateV1::Accepted,
            Some("codex_turn" | "claude_input"),
            Some(native),
            None,
        ) => id(native),
        (
            ManagedOwnerStateV1::KnownUnsent,
            None,
            None,
            Some(
                "capability_missing"
                | "actor_mismatch"
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
        (ManagedOwnerStateV1::Unknown, None, None, Some("native_uncertain" | "channel_failed")) => {
            true
        }
        (ManagedOwnerStateV1::Aborted, None, None, None) => true,
        _ => false,
    }
}

/// Correlates an accepted receipt to the intended harness's native protocol.
fn owner_result_for_intent(
    value: &ManagedOwnerResultV1,
    intent: &OutboxIntentV1,
    digest: &str,
) -> bool {
    let protocol = bridge_protocol::NativeAddress::parse(&intent.target_binding.actor.address)
        .ok()
        .and_then(|address| match address.harness.as_str() {
            "codex" => Some("codex_turn"),
            "claude-code" => Some("claude_input"),
            _ => None,
        });
    owner_result(value, &intent.producer_scope, &intent.effect_id, digest)
        && (value.state != ManagedOwnerStateV1::Accepted || value.protocol.as_deref() == protocol)
}

/// Fixed refusal vocabulary prevents server text from entering diagnostics.
fn refusal(error: &AttemptErrorV1) -> bool {
    error.version == 1
        && uuid(&error.store_id)
        && matches!(
            error.code.as_str(),
            "unsupported_version"
                | "capability_missing"
                | "transport_unsupported"
                | "role_unqualified"
                | "relaunch_required"
                | "peer_not_authorized"
                | "audience_mismatch"
                | "binding_unavailable"
                | "attempt_not_ready"
                | "attempt_mismatch"
                | "actor_mismatch"
                | "route_mismatch"
                | "assertion_stale"
                | "assertion_historical"
                | "invocation_spent"
                | "intent_conflict"
                | "request_in_progress"
                | "capacity_exhausted"
                | "aborted"
                | "recovery_required"
        )
}

/// Maps a transport/protocol failure to read failure or uncertain mutation.
fn failed(wrote: bool, mutation: bool, reason: &'static str) -> AttemptClientError {
    AttemptClientError::Transport {
        outcome: if !wrote {
            TransportOutcome::NotSent
        } else if mutation {
            TransportOutcome::OutcomeUnknown
        } else {
            TransportOutcome::ReadFailed
        },
        reason,
    }
}

impl Client {
    /// Runs one strictly correlated, same-UID, non-retrying managed exchange.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit pinned request and correlated response contract"
    )]
    fn managed_exchange<P: Serialize, R: DeserializeOwned>(
        &self,
        server: &AttemptServerPin,
        request_id: &str,
        op: &'static str,
        params: &P,
        expected_store: Option<&str>,
        mutation: bool,
        validate: impl FnOnce(&R) -> bool,
    ) -> Result<R, AttemptClientError> {
        server
            .validate()
            .map_err(AttemptClientError::InvalidRequest)?;
        validate_id("request_id", request_id, MAX_ID_BYTES)
            .map_err(AttemptClientError::InvalidRequest)?;
        let request = Request {
            api_version: API_VERSION,
            request_id,
            credential: &self.config.credential,
            op,
            params,
        };
        let mut bytes = serde_json::to_vec(&request).map_err(|_| {
            AttemptClientError::InvalidRequest(ProtocolError::new("request", "encoding failed"))
        })?;
        if bytes.len() > MAX_REGISTRATION_BYTES {
            return Err(AttemptClientError::InvalidRequest(ProtocolError::new(
                "request",
                "frame too large",
            )));
        }
        bytes.push(b'\n');
        let frame = transport::exchange_attempt(
            &self.config.registration_socket,
            &bytes,
            self.config.timeout,
            server,
        )
        .map_err(|error| match error {
            transport::AttemptFailure::PeerNotAuthorized => AttemptClientError::PeerNotAuthorized,
            transport::AttemptFailure::Transport(wrote, reason) => failed(wrote, mutation, reason),
        })?;
        let invalid = || failed(true, mutation, "invalid correlated response");
        let raw = decode_strict_object(&frame, bridge_protocol::MAX_RESPONSE_BYTES)
            .map_err(|_| invalid())?;
        let response: Envelope = serde_json::from_value(raw).map_err(|_| invalid())?;
        let result = match response {
            Envelope::Success {
                api_version,
                request_id: got,
                success: true,
                result,
            } if api_version == API_VERSION && got == request_id && result.op == op => result.value,
            Envelope::Failure {
                api_version,
                request_id: got,
                success: false,
                error,
            } if api_version == API_VERSION
                && got == request_id
                && error.validate().is_ok()
                && error.effect.is_none()
                && error.reconciliation.is_none() =>
            {
                return Err(AttemptClientError::Service(error));
            }
            _ => return Err(invalid()),
        };
        let result = match result {
            Outcome::Error { error } => {
                if !refusal(&error) {
                    return Err(invalid());
                }
                if expected_store.is_some_and(|store| store != error.store_id) {
                    return Err(AttemptClientError::StoreMismatch {
                        outcome: if mutation {
                            TransportOutcome::OutcomeUnknown
                        } else {
                            TransportOutcome::ReadFailed
                        },
                    });
                }
                return Err(AttemptClientError::Refused(error));
            }
            Outcome::Ok { value } => value,
        };
        let version = result.get("version").and_then(serde_json::Value::as_u64);
        let store = result.get("store_id").and_then(serde_json::Value::as_str);
        if version != Some(1) || !store.is_some_and(uuid) {
            return Err(invalid());
        }
        if expected_store.is_some_and(|expected| Some(expected) != store) {
            return Err(AttemptClientError::StoreMismatch {
                outcome: if mutation {
                    TransportOutcome::OutcomeUnknown
                } else {
                    TransportOutcome::ReadFailed
                },
            });
        }
        let result: R = serde_json::from_value(result).map_err(|_| invalid())?;
        if !validate(&result) {
            return Err(invalid());
        }
        Ok(result)
    }

    /// Discovers supported managed operations and current issuer; store identity
    /// must still be independently pinned before subsequent operations.
    pub fn attempt_binding_capabilities_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: AttemptCapabilitiesParamsV1,
    ) -> Result<AttemptCapabilitiesV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "attempt_binding_capabilities_v1",
            &params,
            None,
            false,
            |r: &AttemptCapabilitiesV1| {
                id(&r.issuer_epoch)
                    && !r.capabilities.is_empty()
                    && r.capabilities.iter().all(|s| id(s))
            },
        )
    }

    /// Reserves one original observation under the discovered issuer epoch.
    pub fn prepare_native_context_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: PrepareNativeContextParamsV1,
    ) -> Result<PreparedNativeContextV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "prepare_native_context_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |r: &PreparedNativeContextV1| {
                r.invocation_key == params.invocation_key
                    && id(r.bridge_context_ref.expose())
                    && r.expires_at_ms != 0
            },
        )
    }

    /// Looks up one original context, with currentness evaluated by Bridge.
    pub fn context_lookup_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: ContextLookupParamsV1,
    ) -> Result<ContextLookupResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "context_lookup_v1",
            &params,
            Some(&params.expected_store_id),
            false,
            |r: &ContextLookupResultV1| {
                r.invocation_key == params.invocation_key
                    && r.bridge_context_ref == params.bridge_context_ref
                    && id(&r.issuer_epoch)
                    && observation(&r.observation)
            },
        )
    }

    /// Binds an assertion to the original invocation, digest and audience.
    pub fn register_launch_assertion_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: RegisterLaunchAssertionParamsV1,
    ) -> Result<RegisteredLaunchAssertionV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "register_launch_assertion_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |r: &RegisteredLaunchAssertionV1| {
                r.invocation_key == params.invocation_key
                    && id(r.assertion_key.expose())
                    && id(&r.issuer_epoch)
                    && r.expires_at_ms != 0
            },
        )
    }

    /// Consumes a single assertion. Preserve `request_id` for exact recovery.
    pub fn consume_launch_assertion_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: ConsumeLaunchAssertionParamsV1,
    ) -> Result<ConsumeOutcomeV1, AttemptClientError> {
        let request_id = request_id.as_ref();
        self.managed_exchange(
            server,
            request_id,
            "consume_launch_assertion_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |r: &ConsumeOutcomeV1| {
                receipt(
                    &r.receipt,
                    None,
                    request_id,
                    &params.invocation_key,
                    &params.security_digest,
                )
            },
        )
    }

    /// Recovers one exact consumed observation; a missing result is not a fence.
    pub fn observation_lookup_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: ObservationLookupParamsV1,
    ) -> Result<ConsumeOutcomeV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "observation_lookup_v1",
            &params,
            Some(&params.expected_store_id),
            false,
            |r: &ConsumeOutcomeV1| {
                receipt(
                    &r.receipt,
                    Some(&params.producer),
                    &params.consume_request_id,
                    &params.invocation_key,
                    &params.security_digest,
                )
            },
        )
    }

    /// Durably aborts or seals the original consume intention.
    pub fn consume_launch_assertion_abort_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: ConsumeAbortParamsV1,
    ) -> Result<ConsumeAbortResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "consume_launch_assertion_abort_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |r: &ConsumeAbortResultV1| {
                r.aborted
                    && r.receipt.as_ref().is_none_or(|value| {
                        receipt(
                            value,
                            Some(&params.producer),
                            &params.consume_request_id,
                            &params.invocation_key,
                            &params.security_digest,
                        )
                    })
            },
        )
    }

    /// Retires one old issuer namespace only after all recovery has settled.
    pub fn retire_attempt_namespace_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: RetireAttemptNamespaceParamsV1,
    ) -> Result<RetireAttemptNamespaceResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "retire_attempt_namespace_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |r: &RetireAttemptNamespaceResultV1| {
                r.producer == params.producer
                    && r.issuer_epoch == params.issuer_epoch
                    && r.retirement_key == params.retirement_key
            },
        )
    }

    /// Retires one producer delivery scope using the existing core operation,
    /// after proving the same connected server's pinned executable and kernel
    /// incarnation. The exact request identity must be retained for recovery;
    /// this method never automatically retries an uncertain mutation.
    pub fn retire_delivery_scope_pinned(
        &self,
        request_id: impl Into<String>,
        server: &AttemptServerPin,
        params: bridge_protocol::RetireDeliveryScopeParams,
    ) -> Result<bridge_protocol::RetireResult, AttemptClientError> {
        server
            .validate()
            .map_err(AttemptClientError::InvalidRequest)?;
        let request = bridge_protocol::Request::new(
            request_id,
            self.config.credential.clone(),
            bridge_protocol::Operation::RetireDeliveryScope(params),
        )
        .map_err(AttemptClientError::InvalidRequest)?;
        let mut bytes = bridge_protocol::encode_request(&request)
            .map_err(AttemptClientError::InvalidRequest)?;
        bytes.push(b'\n');
        let frame = transport::exchange_attempt(
            &self.config.core_socket,
            &bytes,
            self.config.timeout,
            server,
        )
        .map_err(|error| match error {
            transport::AttemptFailure::PeerNotAuthorized => AttemptClientError::PeerNotAuthorized,
            transport::AttemptFailure::Transport(wrote, reason) => failed(wrote, true, reason),
        })?;
        let invalid = || failed(true, true, "invalid correlated response");
        bridge_protocol::managed_owner::validate_raw_integer_tokens(&frame)
            .map_err(|_| invalid())?;
        let response = bridge_protocol::decode_response(&frame, &request).map_err(|_| invalid())?;
        if let Some(error) = response.error {
            return Err(AttemptClientError::Service(error));
        }
        match response.result {
            Some(bridge_protocol::OperationResult::RetireDeliveryScope(result))
                if result.receipt.request_id == request.request_id =>
            {
                Ok(result)
            }
            _ => Err(invalid()),
        }
    }

    /// Queries the authenticated Run-reader view of an exact root launch.
    /// A current observation is a snapshot, not an atomic Run admission.
    pub fn run_actor_lookup_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: RunActorLookupParamsV1,
    ) -> Result<RunActorLookupResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "run_actor_lookup_v1",
            &params,
            Some(&params.expected_store_id),
            false,
            |result: &RunActorLookupResultV1| {
                result.producer == params.producer
                    && result.incarnation == params.incarnation
                    && result.launch_id == params.launch_id
                    && result.actor.as_ref().is_none_or(|actor| {
                        id(&actor.address) && id(&actor.native_id) && actor.epoch != 0
                    })
                    && result.issuer_epoch.as_deref().is_none_or(id)
                    && (result.state != RunActorStateV1::Current
                        || (result.actor.is_some() && result.issuer_epoch.is_some()))
            },
        )
    }

    /// Reads whether the original actor needs a fresh hook or a new launch.
    pub fn run_actor_recovery_status_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: RunActorRecoveryStatusParamsV1,
    ) -> Result<RunActorRecoveryStatusResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "run_actor_recovery_status_v1",
            &params,
            Some(&params.expected_store_id),
            false,
            |result: &RunActorRecoveryStatusResultV1| {
                result.producer == params.producer
                    && result.incarnation == params.incarnation
                    && result.launch_id == params.launch_id
            },
        )
    }

    /// Publishes one frozen managed owner effect. An uncertain result requires
    /// lookup of the original effect; it never authorizes an automatic resend.
    pub fn publish_managed_owner_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: PublishManagedOwnerParamsV1,
    ) -> Result<ManagedOwnerResultV1, AttemptClientError> {
        params
            .outbox_intent
            .validate(params.text.expose())
            .map_err(AttemptClientError::InvalidRequest)?;
        if egress_intent_digest(&params.outbox_intent)
            .map_err(AttemptClientError::InvalidRequest)?
            != params.effect_digest
        {
            return Err(AttemptClientError::InvalidRequest(ProtocolError::new(
                "outbox",
                "digest mismatch",
            )));
        }
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "publish_managed_owner_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |result: &ManagedOwnerResultV1| {
                owner_result_for_intent(result, &params.outbox_intent, &params.effect_digest)
            },
        )
    }

    /// Reads the retained original managed owner outcome without native I/O.
    pub fn lookup_managed_owner_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: LookupManagedOwnerParamsV1,
    ) -> Result<ManagedOwnerResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "lookup_managed_owner_v1",
            &params,
            Some(&params.expected_store_id),
            false,
            |result: &ManagedOwnerResultV1| {
                owner_result(
                    result,
                    &params.producer_scope,
                    &params.effect_id,
                    &params.effect_digest,
                )
            },
        )
    }

    /// Compacts settled receipts after durable scope retirement. Unknown and
    /// abort-pending effects remain retained. A lost ACK may be retried only
    /// for this same scope; counts report this particular pass.
    pub fn compact_managed_owner_scope_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: CompactManagedOwnerScopeParamsV1,
    ) -> Result<CompactManagedOwnerScopeResultV1, AttemptClientError> {
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "compact_managed_owner_scope_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |result: &CompactManagedOwnerScopeResultV1| {
                id(&result.producer) && result.producer_scope == params.producer_scope
            },
        )
    }

    /// Installs a local and Run-side permanent abort fence for the original
    /// frozen effect. An unknown result remains unresolved and is never resent.
    pub fn abort_managed_owner_v1(
        &self,
        request_id: impl AsRef<str>,
        server: &AttemptServerPin,
        params: AbortManagedOwnerParamsV1,
    ) -> Result<ManagedOwnerResultV1, AttemptClientError> {
        params
            .outbox_intent
            .validate(params.text.expose())
            .map_err(AttemptClientError::InvalidRequest)?;
        if egress_intent_digest(&params.outbox_intent)
            .map_err(AttemptClientError::InvalidRequest)?
            != params.effect_digest
        {
            return Err(AttemptClientError::InvalidRequest(ProtocolError::new(
                "outbox",
                "digest mismatch",
            )));
        }
        self.managed_exchange(
            server,
            request_id.as_ref(),
            "abort_managed_owner_v1",
            &params,
            Some(&params.expected_store_id),
            true,
            |result: &ManagedOwnerResultV1| {
                result.state != ManagedOwnerStateV1::KnownUnsent
                    && owner_result_for_intent(result, &params.outbox_intent, &params.effect_digest)
            },
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Synthetic same-UID endpoints exercise framing, correlation and uncertainty.
    use super::*;
    use crate::Config;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    /// Unique per-process synthetic socket number.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    /// Stable synthetic store UUID, never a credential.
    const STORE: &str = "01234567-89ab-4cde-8fab-0123456789ab";

    /// A copied, private executable is the real server peer in these tests.
    struct MockServer {
        /// Owned child, killed/reaped on every test exit.
        child: std::process::Child,
        /// Private synthetic fixture directory.
        directory: PathBuf,
        /// Exact connected server executable/build pin.
        pin: AttemptServerPin,
    }

    impl Drop for MockServer {
        /// Reaps only the owned helper and removes only its synthetic files.
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    /// Starts one same-UID server child from a distinct trusted executable copy.
    fn mock(answer: Option<String>) -> (Client, MockServer) {
        mock_case(answer, false)
    }

    /// Optionally expects the connected client to refuse before its first byte.
    fn mock_case(answer: Option<String>, expect_no_bytes: bool) -> (Client, MockServer) {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let directory =
            PathBuf::from(std::env::var_os("TMPDIR").expect("private TMPDIR")).join(format!(
                "sdk-b1-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let executable = directory.join("server");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let digest =
            bridge_protocol::sha256_reader(&mut std::fs::File::open(&executable).unwrap()).unwrap();
        let pin = AttemptServerPin::new(&executable, digest).unwrap();
        let socket = directory.join("s.sock");
        let mut command = std::process::Command::new(&executable);
        command
            .args([
                "--exact",
                "attempt::tests::mock_server_child",
                "--nocapture",
            ])
            .env("BRIDGE_SDK_MOCK_SOCKET", &socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(answer) = answer {
            command.env("BRIDGE_SDK_MOCK_ANSWER", answer);
        } else {
            command.env_remove("BRIDGE_SDK_MOCK_ANSWER");
        }
        if expect_no_bytes {
            command.env("BRIDGE_SDK_MOCK_REFUSAL", "1");
        } else {
            command.env_remove("BRIDGE_SDK_MOCK_REFUSAL");
        }
        let child = command.spawn().unwrap();
        let mut server = MockServer {
            child,
            directory,
            pin,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "mock server exited early"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "mock server startup timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let client = Client::new(
            Config::new(
                &socket,
                &socket,
                Secret::new("synthetic-test-credential"),
                Duration::from_secs(30),
            )
            .unwrap(),
        )
        .unwrap();
        (client, server)
    }

    /// Child-only private socket server; never an installed Bridge service.
    #[test]
    fn mock_server_child() {
        let Some(path) = std::env::var_os("BRIDGE_SDK_MOCK_SOCKET") else {
            return;
        };
        let listener = UnixListener::bind(path).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        if std::env::var_os("BRIDGE_SDK_MOCK_REFUSAL").is_some() {
            assert!(request.is_empty(), "request bytes reached a refused peer");
            return;
        }
        assert!(!request.is_empty());
        if let Ok(answer) = std::env::var("BRIDGE_SDK_MOCK_ANSWER") {
            stream.write_all(answer.as_bytes()).unwrap();
            stream.write_all(b"\n").unwrap();
        }
        listener.set_nonblocking(true).unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    /// Waits for and validates the owned one-request helper.
    fn cleanup(mut server: MockServer) {
        assert!(server.child.wait().unwrap().success());
    }

    /// A genuine frame preserves typed version, store, issuer and capabilities.
    #[test]
    fn discovery_is_strict_and_correlated() {
        let answer = format!(
            r#"{{"api_version":1,"request_id":"req","success":true,"result":{{"op":"attempt_binding_capabilities_v1","value":{{"status":"ok","value":{{"version":1,"store_id":"{STORE}","capabilities":["attempt_launch_v1"],"issuer_epoch":"{STORE}"}}}}}}}}"#
        );
        let (client, server) = mock(Some(answer));
        let result = client
            .attempt_binding_capabilities_v1(
                "req",
                &server.pin,
                AttemptCapabilitiesParamsV1 { version: 1 },
            )
            .unwrap();
        assert_eq!(result.store_id, STORE);
        assert_eq!(result.capabilities, ["attempt_launch_v1"]);
        cleanup(server);
    }

    /// A managed-role bootstrap refusal reaches callers as a typed refusal,
    /// not as an uncertain transport outcome.
    #[test]
    fn relaunch_required_is_a_typed_refusal() {
        let answer = format!(
            r#"{{"api_version":1,"request_id":"req","success":true,"result":{{"op":"observation_lookup_v1","value":{{"status":"error","error":{{"version":1,"store_id":"{STORE}","code":"relaunch_required","recovery":"none"}}}}}}}}"#
        );
        let (client, server) = mock(Some(answer));
        let error = client
            .observation_lookup_v1(
                "req",
                &server.pin,
                ObservationLookupParamsV1 {
                    version: 1,
                    expected_store_id: STORE.into(),
                    producer: "pool".into(),
                    consume_request_id: "consume".into(),
                    invocation_key: "invocation".into(),
                    security_digest: "a".repeat(64),
                },
            )
            .unwrap_err();
        assert!(
            matches!(error, AttemptClientError::Refused(AttemptErrorV1 { code, .. }) if code == "relaunch_required")
        );
        cleanup(server);
    }

    /// Pinned scope retirement uses the core endpoint and correlates the exact
    /// immutable scope, action and request ID in the returned receipt.
    #[test]
    fn pinned_scope_retirement_checks_core_peer_and_receipt() {
        use bridge_protocol::{
            OperationResult, Response, RetireDeliveryScopeParams, RetireReceipt, RetireResult,
            RetirementAction,
        };
        let params = RetireDeliveryScopeParams {
            scope_key: "pool/store/member".into(),
            action: RetirementAction::RetireUnhanded,
        };
        let receipt = RetireReceipt {
            producer: "pool".into(),
            request_id: "retire".into(),
            scope_key: params.scope_key.clone(),
            action: params.action,
            retired_at_ms: 1,
            disposed: 0,
            already_terminal: 0,
            preserved_possible_effect: 1,
            preserved_unhanded: 0,
        };
        let answer = Response::ok(
            "retire",
            OperationResult::RetireDeliveryScope(RetireResult {
                receipt: receipt.clone(),
                replayed: false,
            }),
        );
        let encoded =
            String::from_utf8(bridge_protocol::encode_response(&answer).unwrap()).unwrap();
        let (mut client, server) = mock(Some(encoded));
        client.config.registration_socket = server.directory.join("unused-registration.sock");
        let result = client
            .retire_delivery_scope_pinned("retire", &server.pin, params.clone())
            .unwrap();
        assert_eq!(result.receipt, receipt);
        assert!(!result.replayed);
        cleanup(server);

        let mut wrong = receipt;
        wrong.scope_key = "pool/other".into();
        let answer = Response::ok(
            "retire",
            OperationResult::RetireDeliveryScope(RetireResult {
                receipt: wrong,
                replayed: false,
            }),
        );
        let encoded =
            String::from_utf8(bridge_protocol::encode_response(&answer).unwrap()).unwrap();
        let (client, server) = mock(Some(encoded));
        assert!(matches!(
            client.retire_delivery_scope_pinned("retire", &server.pin, params),
            Err(AttemptClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                ..
            })
        ));
        cleanup(server);
    }

    /// A mismatched executable receives no producer credential or request.
    #[test]
    fn pinned_scope_retirement_refuses_untrusted_peer_before_write() {
        let (client, server) = mock_case(None, true);
        let path = std::fs::canonicalize("/usr/bin/true").unwrap();
        let digest =
            bridge_protocol::sha256_reader(&mut std::fs::File::open(&path).unwrap()).unwrap();
        let pin = AttemptServerPin::new(path, digest).unwrap();
        let params = bridge_protocol::RetireDeliveryScopeParams {
            scope_key: "pool/store/member".into(),
            action: bridge_protocol::RetirementAction::Preserve,
        };
        assert!(matches!(
            client.retire_delivery_scope_pinned("retire", &pin, params),
            Err(AttemptClientError::PeerNotAuthorized)
        ));
        cleanup(server);
    }

    /// A lost retirement acknowledgement is uncertain and never reconnected.
    #[test]
    fn pinned_scope_retirement_lost_ack_is_not_retried() {
        let (client, server) = mock(None);
        let params = bridge_protocol::RetireDeliveryScopeParams {
            scope_key: "pool/store/member".into(),
            action: bridge_protocol::RetirementAction::Preserve,
        };
        assert!(matches!(
            client.retire_delivery_scope_pinned("retire", &server.pin, params),
            Err(AttemptClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                ..
            })
        ));
        cleanup(server);
    }

    /// Duplicated nested keys and an incorrect operation name are not results.
    #[test]
    fn malformed_correlations_are_rejected() {
        for body in [
            format!(
                r#"{{"api_version":1,"request_id":"req","success":true,"result":{{"op":"attempt_binding_capabilities_v1","value":{{"status":"ok","value":{{"version":1,"store_id":"{STORE}","store_id":"{STORE}","capabilities":[],"issuer_epoch":"{STORE}"}}}}}}}}"#
            ),
            format!(
                r#"{{"api_version":1,"request_id":"req","success":true,"result":{{"op":"other","value":{{"status":"ok","value":{{"version":1,"store_id":"{STORE}","capabilities":["v1"],"issuer_epoch":"{STORE}"}}}}}}}}"#
            ),
        ] {
            let (client, server) = mock(Some(body));
            assert!(matches!(
                client.attempt_binding_capabilities_v1(
                    "req",
                    &server.pin,
                    AttemptCapabilitiesParamsV1 { version: 1 }
                ),
                Err(AttemptClientError::Transport {
                    outcome: TransportOutcome::ReadFailed,
                    ..
                })
            ));
            cleanup(server);
        }
    }

    /// Dropping an ACK after receiving a mutation never causes a second write,
    /// even when the unchanged legacy configuration permits reconnects.
    #[test]
    fn uncertain_mutation_is_not_retried() {
        let (client, server) = mock(None);
        let error = client
            .consume_launch_assertion_v1(
                "consume",
                &server.pin,
                ConsumeLaunchAssertionParamsV1 {
                    version: 1,
                    expected_store_id: STORE.into(),
                    assertion_key: Secret::new("fixture-assertion-secret"),
                    invocation_key: "invocation".into(),
                    security_digest: "a".repeat(64),
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            AttemptClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                ..
            }
        ));
        assert!(!format!("{error:?}").contains("fixture-assertion-secret"));
        cleanup(server);
    }

    /// A different same-UID executable is refused after connection before any
    /// credential byte; a mismatched digest refuses before connection.
    #[test]
    fn managed_server_pin_refuses_wrong_executable_or_digest_before_write() {
        let (client, server) = mock_case(None, true);
        let wrong_path = std::fs::canonicalize("/usr/bin/true").unwrap();
        let wrong_digest =
            bridge_protocol::sha256_reader(&mut std::fs::File::open(&wrong_path).unwrap()).unwrap();
        let wrong = AttemptServerPin::new(wrong_path, wrong_digest).unwrap();
        assert!(matches!(
            client.attempt_binding_capabilities_v1(
                "req",
                &wrong,
                AttemptCapabilitiesParamsV1 { version: 1 }
            ),
            Err(AttemptClientError::PeerNotAuthorized)
        ));
        cleanup(server);

        let (client, mut server) = mock(None);
        let mut wrong = server.pin.clone();
        wrong.sha256 = "0".repeat(64);
        assert!(matches!(
            client.attempt_binding_capabilities_v1(
                "req",
                &wrong,
                AttemptCapabilitiesParamsV1 { version: 1 }
            ),
            Err(AttemptClientError::PeerNotAuthorized)
        ));
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "mismatched digest connected"
        );
    }

    /// Owner lookup returns only a correlated typed durable effect result.
    #[test]
    fn managed_owner_lookup_checks_effect_identity() {
        let digest = "a".repeat(64);
        let answer = serde_json::json!({"api_version":1,"request_id":"owner-read","success":true,
            "result":{"op":"lookup_managed_owner_v1","value":{"status":"ok","value":{
                "version":1,"store_id":STORE,"producer":"pool","producer_scope":"scope",
                "effect_id":"effect","effect_digest":digest,"state":"unknown",
                "protocol":null,"native_id":null,"reason":"native_uncertain"}}}})
        .to_string();
        let (client, server) = mock(Some(answer));
        let result = client
            .lookup_managed_owner_v1(
                "owner-read",
                &server.pin,
                LookupManagedOwnerParamsV1 {
                    version: 1,
                    expected_store_id: STORE.into(),
                    audience: "backend".into(),
                    producer_scope: "scope".into(),
                    effect_id: "effect".into(),
                    effect_digest: digest,
                },
            )
            .unwrap();
        assert_eq!(result.state, ManagedOwnerStateV1::Unknown);
        cleanup(server);
    }

    /// A typed abort recognizes only the exact correlated permanent fence.
    #[test]
    fn managed_owner_abort_accepts_correlated_fence() {
        use bridge_protocol::managed_owner::{OutboxIntentV1, egress_intent_digest};
        let route =
            serde_json::json!({"component_store_id":STORE,"route_id":"bridge","worker_uid":1000});
        let intent: OutboxIntentV1 = serde_json::from_value(serde_json::json!({
            "effect_id":"effect", "producer_scope":"scope", "event_key":"event",
            "payload_sha256":"982d9e3eb996f559e633f4d194def3761d909f5a3b647d1a851fead67c32c9d1", "payload_length":4,
            "target_binding":{"pool_store_id":"pool-store","pool_id":"pool","member_id":"member","binding_generation":1,
                "attempt":{"run_store_id":"store_run","lineage_root_id":"root","execution_id":"exec","sequence":1,"attempt_id":"attempt","launch_id":STORE},
                "actor":{"address":"lab/codex/store/session","role":"root","native_id":"session","epoch":1},
                "run_route":{"component_store_id":"store_run","route_id":"run","worker_uid":1000},"bridge_route":route},
            "expected_incarnation":{"host_id":"lab","boot_id":STORE,"pid_namespace_inode":2,"uid":1000,"pid":42,"start_ticks":7},
            "bridge_route":route,"mode":"message","retention":"keep_all"
        })).unwrap();
        let digest = egress_intent_digest(&intent).unwrap();
        let answer = serde_json::json!({"api_version":1,"request_id":"owner-abort","success":true,
            "result":{"op":"abort_managed_owner_v1","value":{"status":"ok","value":{
                "version":1,"store_id":STORE,"producer":"pool","producer_scope":"scope",
                "effect_id":"effect","effect_digest":digest,"state":"aborted",
                "protocol":null,"native_id":null,"reason":null}}}})
        .to_string();
        let params = AbortManagedOwnerParamsV1 {
            version: 1,
            expected_store_id: STORE.into(),
            audience: "backend".into(),
            run_receipt_id: "receipt".into(),
            outbox_intent: intent,
            effect_digest: digest.clone(),
            text: Secret::new("text"),
        };
        let (client, server) = mock(Some(answer));
        let result = client
            .abort_managed_owner_v1("owner-abort", &server.pin, params.clone())
            .unwrap();
        assert_eq!(result.state, ManagedOwnerStateV1::Aborted);
        cleanup(server);
        let wrong_protocol =
            serde_json::json!({"api_version":1,"request_id":"owner-abort","success":true,
            "result":{"op":"abort_managed_owner_v1","value":{"status":"ok","value":{
                "version":1,"store_id":STORE,"producer":"pool","producer_scope":"scope",
                "effect_id":"effect","effect_digest":digest,"state":"accepted",
                "protocol":"claude_input","native_id":"native","reason":null}}}})
            .to_string();
        let (client, server) = mock(Some(wrong_protocol));
        assert!(matches!(
            client.abort_managed_owner_v1("owner-abort", &server.pin, params),
            Err(AttemptClientError::Transport {
                outcome: TransportOutcome::OutcomeUnknown,
                ..
            })
        ));
        cleanup(server);
    }
}
