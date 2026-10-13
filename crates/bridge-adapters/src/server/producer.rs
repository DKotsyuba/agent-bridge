//! Additive authenticated producer registration/consumption on the native channel.
//! Core owns authorization and durable facts; the registry owns ephemeral evidence.

use super::*;
use bridge_core::{RegistrationClaimState, VerifiedRegistration};
use bridge_protocol::*;

/// Serves one strictly decoded v1 request. Errors are static bounded categories;
/// neither original frame nor evidence/credential text is echoed or logged.
pub(super) fn serve_v1(
    line: &str,
    peer: os::PeerIdentity,
    state: &ChannelState,
    writer: &mut UnixStream,
) {
    let request = match decode_request(line.strip_suffix('\n').unwrap_or(line).as_bytes()) {
        Ok(request) => request,
        Err(cause) => {
            let unsupported = cause.field == "api_version";
            let id = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| {
                    value
                        .get("request_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .filter(|value| {
                    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
                })
                .unwrap_or_else(|| "invalid-request".into());
            let response = Response::error(
                id,
                ApiError {
                    class: if unsupported {
                        ErrorClass::Unsupported
                    } else {
                        ErrorClass::Invalid
                    },
                    reason: if unsupported {
                        "unsupported_api_version"
                    } else {
                        "malformed_v1_request"
                    }
                    .into(),
                    retry_hint: RetryHint::Never,
                    effect: None,
                    reconciliation: None,
                    detail: "Invalid producer request".into(),
                },
            );
            if let Ok(mut bytes) = encode_response(&response) {
                bytes.push(b'\n');
                let _ = writer.write_all(&bytes);
            }
            return;
        }
    };
    let outcome = handle(&request, peer, state);
    let response = match outcome {
        Ok(result) => Response::ok(&request.request_id, result),
        Err(error) => Response::error(&request.request_id, error),
    };
    if let Ok(mut bytes) = encode_response(&response) {
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes);
    }
}

/// Dispatches only native ingress operations through the same authoritative
/// producer authorizer already installed in custody. No duplicate policy exists.
fn handle(
    request: &Request,
    peer: os::PeerIdentity,
    state: &ChannelState,
) -> Result<OperationResult, ApiError> {
    let authorizer = with_custody(state.custody.as_ref(), |storage| {
        storage.producer_authorizer()
    })
    .ok_or_else(|| unavailable(request, false))??;
    let grant = authorizer.authenticate(request.credential.expose())?;
    let producer = grant.producer().to_string();
    match &request.operation {
        Operation::Capabilities(_) => {
            let mut capabilities = with_custody(state.custody.as_ref(), |storage| {
                storage.capabilities_v1(request.credential.expose())
            })
            .ok_or_else(|| unavailable(request, false))??;
            let mut registry = lock_registry(&state.registry);
            capabilities.native_contracts = registry.native_contracts();
            capabilities.evidence_variants = vec!["native".into(), "sealed".into()];
            capabilities.limits.registration_request_bytes = super::MAX_REQUEST_BYTES as u64;
            capabilities.limits.assertions = 1024;
            capabilities.features.host_observations = false;
            capabilities.features.consume_assertion =
                registry.has_audience(&producer, grant.assertion_audiences());
            Ok(OperationResult::Capabilities(capabilities))
        }
        Operation::RegisterCall(params) => register(request, params, peer, state, &producer),
        Operation::ConsumeAssertion(params) => {
            if grant.assertion_audiences().is_empty() {
                return Err(error(
                    request,
                    ErrorClass::Forbidden,
                    "assertion_audience_mismatch",
                    RetryHint::Never,
                    false,
                ));
            }
            let result = lock_registry(&state.registry)
                .consume_assertion(
                    peer,
                    &producer,
                    &request.request_id,
                    params,
                    grant.assertion_audiences(),
                    current_unix_millis(),
                )
                .map_err(|cause| correlation(request, cause))?;
            Ok(OperationResult::ConsumeAssertion(result))
        }
        _ => Err(error(
            request,
            ErrorClass::Unsupported,
            "unsupported_endpoint_operation",
            RetryHint::Never,
            false,
        )),
    }
}

/// Recovers historical custody before native claims; new registration reserves,
/// atomically commits through core, then finalizes or conservatively reconciles.
/// No registry lock overlaps custody; no lock spans socket I/O.
fn register(
    request: &Request,
    params: &RegisterCallParams,
    peer: os::PeerIdentity,
    state: &ChannelState,
    producer: &str,
) -> Result<OperationResult, ApiError> {
    let credential = request.credential.expose();
    let fingerprint = registration_request_fingerprint(params).map_err(|_| {
        error(
            request,
            ErrorClass::Invalid,
            "invalid_registration",
            RetryHint::Never,
            false,
        )
    })?;
    let prior = with_custody(state.custody.as_ref(), |storage| {
        storage.registration_replay(credential, &request.request_id, params)
    })
    .ok_or_else(|| unavailable(request, false))??;
    if let Some(receipt) = prior {
        if let Some(meta) = params
            .evidence
            .as_ref()
            .and_then(|value| evidence(value).ok())
        {
            let origin =
                lock_registry(&state.registry).replay_origin(peer, &meta, current_unix_millis());
            if let Some((origin, harness, use_key, expiry)) = origin {
                let verified = native_fact(&origin, harness, &use_key, expiry);
                with_custody(state.custody.as_ref(), |storage| {
                    storage.register_call(
                        credential,
                        &request.request_id,
                        params,
                        Some(&verified),
                        &current_unix_millis,
                    )
                })
                .ok_or_else(|| unavailable(request, true))??;
            }
        }
        let claim = lock_registry(&state.registry)
            .claimed_request(producer, &request.request_id, &fingerprint)
            .map_err(|cause| correlation(request, cause))?;
        if let Some(key) = claim {
            let reconciled = with_custody(state.custody.as_ref(), |storage| {
                storage.registration_evidence_committed(credential, &request.request_id, &key)
            })
            .ok_or_else(|| unavailable(request, true))??;
            if reconciled.claim == RegistrationClaimState::CommittedToRequest {
                lock_registry(&state.registry).finalize_claim(&key);
            }
        }
        lock_registry(&state.registry).release_assertion_slot(producer, &request.request_id);
        return Ok(OperationResult::RegisterCall(RegistrationResult {
            receipt,
            evidence_state: CallerEvidenceState::Historical,
            assertion: None,
        }));
    }
    {
        let mut registry = lock_registry(&state.registry);
        if registry
            .claimed_request(producer, &request.request_id, &fingerprint)
            .map_err(|cause| correlation(request, cause))?
            .is_some()
        {
            return Err(error(
                request,
                ErrorClass::Busy,
                "registration_in_progress",
                RetryHint::ObserveSameIdentity,
                true,
            ));
        }
        if let Some(audience) = &params.assertion_audience {
            registry
                .reserve_assertion_slot(
                    producer,
                    &request.request_id,
                    audience,
                    current_unix_millis(),
                )
                .map_err(|cause| correlation(request, cause))?;
        }
    }
    let reserved = params
        .evidence
        .as_ref()
        .ok_or_else(|| {
            error(
                request,
                ErrorClass::Unavailable,
                "needs_new_attestation",
                RetryHint::FreshEvidenceSameIdentity,
                false,
            )
        })
        .and_then(|value| evidence(value).map_err(|cause| correlation(request, cause)))
        .and_then(|meta| {
            lock_registry(&state.registry)
                .reserve_caller(
                    peer,
                    &meta,
                    current_unix_millis(),
                    producer,
                    &request.request_id,
                    &fingerprint,
                )
                .map_err(|cause| correlation(request, cause))
        });
    let claim = match reserved {
        Ok(claim) => claim,
        Err(cause) => {
            lock_registry(&state.registry).release_assertion_slot(producer, &request.request_id);
            return Err(cause);
        }
    };
    if params.reply_policy == ReplyPolicy::SelfActor && !claim.caller.may_act_as_address() {
        let mut registry = lock_registry(&state.registry);
        registry.release_claim(&claim.use_key);
        registry.release_assertion_slot(producer, &request.request_id);
        return Err(error(
            request,
            ErrorClass::Forbidden,
            "shared_session_policy_required",
            RetryHint::Never,
            false,
        ));
    }
    let verified = native_fact(
        &claim.caller,
        claim.harness,
        &claim.use_key,
        claim.expires_at_ms,
    );
    let committed = with_custody(state.custody.as_ref(), |storage| {
        storage.register_call(
            credential,
            &request.request_id,
            params,
            Some(&verified),
            &current_unix_millis,
        )
    });
    let receipt = match committed {
        Some(Ok(receipt)) => receipt,
        Some(Err(cause)) if cause.effect == Some(MutationEffect::NotCommitted) => {
            let mut registry = lock_registry(&state.registry);
            registry.release_claim(&claim.use_key);
            registry.release_assertion_slot(producer, &request.request_id);
            return Err(cause);
        }
        None => {
            let mut registry = lock_registry(&state.registry);
            registry.release_claim(&claim.use_key);
            registry.release_assertion_slot(producer, &request.request_id);
            return Err(unavailable(request, false));
        }
        Some(Err(_)) => {
            let reconciled = with_custody(state.custody.as_ref(), |storage| {
                storage.registration_evidence_committed(
                    credential,
                    &request.request_id,
                    &claim.use_key,
                )
            });
            match reconciled {
                Some(Ok(result)) if result.claim == RegistrationClaimState::CommittedToRequest => {
                    result.receipt.ok_or_else(|| unavailable(request, true))?
                }
                Some(Ok(result)) if result.claim == RegistrationClaimState::CommittedElsewhere => {
                    let mut registry = lock_registry(&state.registry);
                    registry.finalize_claim(&claim.use_key);
                    registry.release_assertion_slot(producer, &request.request_id);
                    return Err(error(
                        request,
                        ErrorClass::Conflict,
                        "duplicate_evidence",
                        RetryHint::Never,
                        false,
                    ));
                }
                _ => return Err(unavailable(request, true)),
            }
        }
    };
    let mut registry = lock_registry(&state.registry);
    registry.finalize_claim(&claim.use_key);
    let assertion = params
        .assertion_audience
        .as_deref()
        .zip(params.invocation_key.as_deref())
        .and_then(|(audience, invocation)| {
            registry.issue_assertion(
                &receipt,
                &claim,
                audience,
                invocation,
                current_unix_millis(),
            )
        });
    Ok(OperationResult::RegisterCall(RegistrationResult {
        receipt,
        evidence_state: if assertion.is_some() {
            CallerEvidenceState::FreshAssertionAvailable
        } else {
            CallerEvidenceState::VerifiedAtRegistration
        },
        assertion,
    }))
}

/// Converts original framework evidence using existing native parsing; explicit
/// host tag must agree. Sealed values carry no caller-authored origin facts.
fn evidence(candidate: &CallEvidence) -> Result<PresentedMeta, CorrelationError> {
    match candidate {
        CallEvidence::Native { host, metadata } => {
            let meta = PresentedMeta::from_mcp_meta(metadata)?;
            if !matches!(
                (host, &meta),
                (Host::Codex, PresentedMeta::Codex { .. })
                    | (Host::ClaudeCode, PresentedMeta::Claude { .. })
            ) {
                return Err(CorrelationError::NotEvidence("mixed host evidence".into()));
            }
            Ok(meta)
        }
        CallEvidence::Sealed { proof } => Ok(PresentedMeta::sealed(
            crate::registry::SealedProof::from_wire(proof.expose()),
        )),
    }
}

/// Builds the trusted core input from registry-only facts, never wire arguments.
fn native_fact(
    caller: &crate::VerifiedCaller,
    harness: (u32, u64),
    use_key: &str,
    expires_at_ms: u64,
) -> VerifiedRegistration {
    VerifiedRegistration {
        caller_address: caller.address().clone(),
        native_actor_id: caller.native_id().into(),
        actor_role: match caller.role() {
            crate::registry::ActorRole::Root => bridge_protocol::ActorRole::Root,
            crate::registry::ActorRole::Child => bridge_protocol::ActorRole::Child,
        },
        destination: caller.address().clone(),
        observed_at_ms: caller.observed_at_ms(),
        endpoint_epoch: caller.epoch(),
        harness_pid: harness.0,
        harness_start_time: harness.1,
        evidence_use_key: use_key.into(),
        evidence_expires_at_ms: expires_at_ms,
    }
}

/// Produces bounded safe errors with exact mutation reconciliation identity.
fn error(
    request: &Request,
    class: ErrorClass,
    reason: &str,
    hint: RetryHint,
    unknown: bool,
) -> ApiError {
    ApiError {
        class,
        reason: reason.into(),
        retry_hint: hint,
        effect: request.reconciliation().map(|_| {
            if unknown {
                MutationEffect::Unknown
            } else {
                MutationEffect::NotCommitted
            }
        }),
        reconciliation: request.reconciliation(),
        detail: "Producer operation refused; use the stated identity and retry hint".into(),
    }
}

/// Missing custody versus unresolved possible commit have distinct effect facts.
fn unavailable(request: &Request, unknown: bool) -> ApiError {
    error(
        request,
        if unknown {
            ErrorClass::OutcomeUnknown
        } else {
            ErrorClass::Unavailable
        },
        if unknown {
            "registration_outcome_unknown"
        } else {
            "custody_unavailable"
        },
        if unknown {
            RetryHint::ObserveSameIdentity
        } else {
            RetryHint::SameIdentity
        },
        unknown,
    )
}

/// Maps only locally generated correlation classes; details never echo native
/// identifiers or arbitrary underlying error text into a producer response.
fn correlation(request: &Request, cause: CorrelationError) -> ApiError {
    let (class, reason, hint, unknown) = match cause {
        CorrelationError::NotEvidence(detail) if detail == "unsupported_host_path" => (
            ErrorClass::Unsupported,
            "unsupported_host_path",
            RetryHint::Never,
            false,
        ),
        CorrelationError::NotEvidence(detail) if detail == "assertion_audience_mismatch" => (
            ErrorClass::Forbidden,
            "assertion_audience_mismatch",
            RetryHint::Never,
            false,
        ),
        CorrelationError::NotEvidence(_) => (
            ErrorClass::Forbidden,
            "caller_not_evidence",
            RetryHint::Never,
            false,
        ),
        CorrelationError::Conflicting(detail) if detail == "assertion_invocation_mismatch" => (
            ErrorClass::Conflict,
            "assertion_invocation_mismatch",
            RetryHint::Never,
            false,
        ),
        CorrelationError::Conflicting(detail)
            if detail == "registration intention changed"
                || detail == "assertion consume intention changed" =>
        {
            (
                ErrorClass::Conflict,
                "intent_conflict",
                RetryHint::Never,
                false,
            )
        }
        CorrelationError::Conflicting(_) => (
            ErrorClass::Conflict,
            "caller_scope_conflict",
            RetryHint::Never,
            false,
        ),
        CorrelationError::Duplicate(detail) if detail == "assertion_consumed" => (
            ErrorClass::Conflict,
            "assertion_consumed",
            RetryHint::Never,
            false,
        ),
        CorrelationError::Duplicate(_) => (
            ErrorClass::Conflict,
            "duplicate_evidence",
            RetryHint::Never,
            false,
        ),
        CorrelationError::Unavailable(detail) if detail == "registration is in progress" => (
            ErrorClass::Busy,
            "registration_in_progress",
            RetryHint::ObserveSameIdentity,
            true,
        ),
        CorrelationError::Unavailable(detail)
            if matches!(
                detail.as_str(),
                "native claim capacity exhausted" | "assertion capacity exhausted"
            ) =>
        {
            (
                ErrorClass::Capacity,
                "claim_capacity_exhausted",
                RetryHint::ObserveSameIdentity,
                false,
            )
        }
        CorrelationError::Unavailable(_) => (
            ErrorClass::Busy,
            "evidence_reserved",
            RetryHint::ObserveSameIdentity,
            false,
        ),
        CorrelationError::Stale(detail) if detail == "assertion_expired" => (
            ErrorClass::Unavailable,
            "assertion_expired",
            RetryHint::FreshEvidenceSameIdentity,
            false,
        ),
        _ => (
            ErrorClass::Unavailable,
            "needs_new_attestation",
            RetryHint::FreshEvidenceSameIdentity,
            false,
        ),
    };
    error(request, class, reason, hint, unknown)
}
