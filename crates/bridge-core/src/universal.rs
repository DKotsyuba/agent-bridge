//! Product-independent durable call registration, publication and lifetime.
//! Shared per-boot grants authenticate every operation. One immediate SQLite
//! transaction owns each immutable request/evidence/route or intent/custody
//! commit. Native proof algorithms and domain job idempotency live elsewhere.

use crate::producer::{allowed, failure, opaque};
use crate::storage::{publish_in, to_sql};
use crate::{CoreError, Storage};
use bridge_protocol::*;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Trusted native-provider input, never a deserializable producer claim. The
/// provider owns kernel/host qualification, exclusive proof reservation and
/// destination derivation; core checks domains, freshness and durable use.
#[derive(Debug)]
pub struct VerifiedRegistration {
    /// Actual qualified logical address, not a claimed model argument.
    pub caller_address: crate::NativeAddress,
    /// Exact native root/child actor identity, including shared-session children.
    pub native_actor_id: String,
    /// Actual root/child distinction, independent of destination equivalence.
    pub actor_role: ActorRole,
    /// Adapter-derived self/shared-session logical return destination.
    pub destination: crate::NativeAddress,
    /// Original native observation time in Unix milliseconds.
    pub observed_at_ms: u64,
    /// Original qualified endpoint epoch, excluded from logical identity.
    pub endpoint_epoch: u64,
    /// Actual live native process PID, excluded from logical identity.
    pub harness_pid: u32,
    /// Actual OS process start identity, excluded from logical identity.
    pub harness_start_time: u64,
    /// Single globally unique native observation key, shared by sealed derivation.
    pub evidence_use_key: String,
    /// Finite native observation validity, Unix milliseconds, never renewed.
    pub evidence_expires_at_ms: u64,
}
impl VerifiedRegistration {
    /// Validates trusted fact domains and commit-time freshness; this check
    /// does not itself authenticate a native process or protected hook.
    fn validate(&self, now: u64) -> Result<(), ApiError> {
        self.caller_address
            .validate()
            .map_err(|_| failure(ErrorClass::Invalid, "invalid_verified_origin"))?;
        self.destination
            .validate()
            .map_err(|_| failure(ErrorClass::Invalid, "invalid_verified_destination"))?;
        if !opaque(&self.native_actor_id)
            || !opaque(&self.evidence_use_key)
            || self.harness_pid == 0
            || self.harness_start_time == 0
            || self.endpoint_epoch == 0
            || self.observed_at_ms == 0
            || self.observed_at_ms > now
            || self.evidence_expires_at_ms <= now
            || self.evidence_expires_at_ms > crate::MAX_SQLITE_INT
        {
            return Err(failure(ErrorClass::Unavailable, "needs_new_attestation"));
        }
        Ok(())
    }
    /// Stable canonical logical actor material; endpoint/call/boot never joins.
    fn caller_json(&self) -> Result<String, ApiError> {
        encode(&(
            self.caller_address.to_canonical_string(),
            &self.native_actor_id,
            self.actor_role,
        ))
    }
}
/// Internal durable native-use observation; not an exposed cross-producer record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationClaimState {
    /// No committed fact visible now; not proof that no in-flight commit exists.
    NotVisible,
    /// Exact requested native use and own registration committed together.
    CommittedToRequest,
    /// This native observation was durably claimed under another request/owner.
    CommittedElsewhere,
}
/// Internal coordinator reconciliation; absent facts never authorize releasing
/// an uncertain claim or reconstructing a fresh assertion.
#[derive(Debug)]
pub struct RegistrationReconciliation {
    /// Historical own request receipt, if one was actually committed.
    pub receipt: Option<RegistrationReceipt>,
    /// Global native-use result without disclosing another owner's record.
    pub claim: RegistrationClaimState,
}
/// Exact route database column tuple; order follows load_route SELECT.
/// Only the constraints field is JSON, and the final field pins immutable facts.
type RawRoute = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    u64,
    Option<u64>,
    Option<u64>,
    String,
);
/// Frozen route row plus effective closure; typed receipts remain immutable.
struct Route {
    /// Producer identity authenticated by caller, never taken from params.
    producer: String,
    /// Immutable producer operation incarnation.
    operation: String,
    /// Issuer route reference.
    key: String,
    /// Normalized original request constraints, excluding transient assertions.
    requested: String,
    /// Frozen actual actor material, excluding endpoint incarnation.
    caller: String,
    /// Canonical logical return address.
    destination: String,
    /// First effective route limits; new publications also check current grants.
    constraints: RouteConstraints,
    /// Stable opaque caller mapping.
    caller_scope: String,
    /// Stable opaque destination mapping.
    destination_scope: String,
    /// First route creation time, Unix milliseconds.
    created: u64,
    /// Optional absolute route expiry, no implicit job TTL.
    expires: Option<u64>,
    /// First close time, if explicitly closed before expiry.
    closed: Option<u64>,
}
impl Route {
    /// Hashes every immutable route fact; closure is separate mutable lifecycle.
    /// Reads recheck this digest before using destinations or actor scopes.
    fn binding_hash(&self) -> Result<String, ApiError> {
        hash_json(&(
            &self.producer,
            &self.operation,
            &self.key,
            &self.requested,
            &self.caller,
            &self.destination,
            &self.constraints,
            &self.caller_scope,
            &self.destination_scope,
            self.created,
            self.expires,
        ))
    }
    /// Effective state at observation; closed is never reopened by later expiry.
    fn state(&self, now: u64) -> RouteState {
        if self.closed.is_some() {
            RouteState::Closed
        } else if self.expires.is_some_and(|v| v <= now) {
            RouteState::Expired
        } else {
            RouteState::Open
        }
    }
    /// Original immutable route association under one registration request ID.
    fn receipt(&self, request: &str) -> RegistrationReceipt {
        RegistrationReceipt {
            producer: self.producer.clone(),
            request_id: request.into(),
            operation_key: self.operation.clone(),
            route_key: self.key.clone(),
            caller_scope: self.caller_scope.clone(),
            destination_scope: self.destination_scope.clone(),
            reply_policy: self.constraints.reply_policy,
            constraints: self.constraints.clone(),
            state: RouteState::Open,
            created_at_ms: self.created,
            route_expires_at_ms: self.expires,
        }
    }
}

impl Storage {
    /// Authenticated exact registration replay before spending native evidence.
    /// Changed requested semantics conflict; absent means no visible receipt,
    /// not absence of an in-flight commit. The result is always historical.
    pub fn registration_replay(
        &self,
        credential: &str,
        request_id: &str,
        params: &RegisterCallParams,
    ) -> Result<Option<RegistrationReceipt>, ApiError> {
        validate_id("request_id", request_id, MAX_ID_BYTES).map_err(protocol_error)?;
        let hash = registration_request_fingerprint(params).map_err(protocol_error)?;
        let auth = self.producer_authorizer()?;
        let grant = auth.authenticate(credential)?;
        replay_registration(&self.connection, grant.producer(), request_id, &hash)
    }
    /// Commits an immutable producer return route, request receipt and global
    /// native-use claim together. Credential identifies the configured producer;
    /// request_id is its stable nonempty, control-free <=256-byte retry identity.
    /// Changed request/operation semantics conflict rather than replacing origin.
    ///
    /// Params are validated protocol intentions, not native authority. Missing
    /// modes means message; missing kinds inherit the first grant snapshot;
    /// missing payload ceiling means 64 KiB; missing route expiry imposes no TTL.
    /// Verified must be genuinely reserved provider facts for a new request.
    /// None is allowed only to recover an already committed exact request;
    /// Some on replay compares origin without spending a new proof or granting
    /// freshness. Shared-address children require explicit SharedSession policy.
    ///
    /// Clock returns absolute Unix milliseconds in 1..=MAX_SQLITE_INT and is
    /// sampled after acquiring BEGIN IMMEDIATE, so queued time cannot renew
    /// evidence. A new registration checks the original observation/expiry.
    /// Success is durable or historical receipt only, never job permission or
    /// fresh assertion. Validation/auth/capacity/conflict errors report
    /// NotCommitted; COMMIT failure is conservatively Unknown with the original
    /// registration reconciliation key, even if no receipt is visible yet.
    /// Reconcile that request/use before releasing an uncertain native claim;
    /// retry only the same identity and never synthesize a replacement operation.
    pub fn register_call(
        &mut self,
        credential: &str,
        request_id: &str,
        params: &RegisterCallParams,
        verified: Option<&VerifiedRegistration>,
        clock: &dyn Fn() -> u64,
    ) -> Result<RegistrationReceipt, ApiError> {
        let reconciliation = ReconciliationKey::Registration {
            request_id: request_id.into(),
        };
        let mut action = || -> Result<RegistrationReceipt, ApiError> {
            validate_id("request_id", request_id, MAX_ID_BYTES).map_err(protocol_error)?;
            let hash = registration_request_fingerprint(params).map_err(protocol_error)?;
            let auth = self.producer_authorizer()?;
            let grant = auth.authenticate(credential)?;
            let limits = self.universal_limits;
            let tx = self.begin().map_err(storage_error)?;
            let now = clock();
            positive_time(now)?;
            if let Some(receipt) = replay_registration(&tx, grant.producer(), request_id, &hash)? {
                if let Some(origin) = verified {
                    let route = load_route(&tx, grant.producer(), &receipt.route_key)?
                        .ok_or_else(integrity)?;
                    if route.caller != origin.caller_json()?
                        || route.destination != origin.destination.to_canonical_string()
                    {
                        return Err(failure(ErrorClass::Conflict, "caller_scope_conflict"));
                    }
                }
                return Ok(receipt);
            }
            let policy = grant
                .policy()
                .filter(|p| p.registration)
                .ok_or_else(|| failure(ErrorClass::Forbidden, "registration_not_allowed"))?;
            let origin = verified
                .ok_or_else(|| failure(ErrorClass::Unavailable, "needs_new_attestation"))?;
            origin.validate(now)?;
            if params.reply_policy == ReplyPolicy::SelfActor
                && origin.actor_role == ActorRole::Child
                && origin.native_actor_id != origin.caller_address.native_session_id
            {
                return Err(failure(
                    ErrorClass::Forbidden,
                    "shared_session_policy_required",
                ));
            }
            if !grant.allows_native_scope(&origin.caller_address)
                || !grant.allows_recipient(&origin.destination.to_canonical_string())
                || !policy
                    .reply_policies
                    .contains(&wire_name(&params.reply_policy)?)
            {
                return Err(failure(
                    ErrorClass::Forbidden,
                    "registration_scope_not_allowed",
                ));
            }
            if params
                .assertion_audience
                .as_ref()
                .is_some_and(|a| !policy.assertion_audiences.contains(a))
            {
                return Err(failure(
                    ErrorClass::Forbidden,
                    "assertion_audience_not_allowed",
                ));
            }
            capacity(
                &tx,
                "registration_requests",
                limits.max_registration_requests,
            )?;
            if tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM evidence_uses WHERE use_key=?1)",
                    params![origin.evidence_use_key],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(storage_error)?
            {
                return Err(failure(ErrorClass::Conflict, "duplicate_caller_evidence"));
            }
            let mut binding = params.clone();
            binding.evidence = None;
            binding.assertion_audience = None;
            binding.invocation_key = None;
            let requested = registration_request_fingerprint(&binding).map_err(protocol_error)?;
            let caller = origin.caller_json()?;
            let destination = origin.destination.to_canonical_string();
            let route_key: Option<String> = tx
                .query_row(
                    "SELECT route_key FROM return_routes WHERE producer=?1 AND operation_key=?2",
                    params![grant.producer(), params.operation_key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage_error)?;
            let route = if let Some(key) = route_key {
                let route = load_route(&tx, grant.producer(), &key)?.ok_or_else(integrity)?;
                if route.caller != caller
                    || route.destination != destination
                    || route.requested != requested
                {
                    return Err(failure(
                        ErrorClass::Conflict,
                        "immutable_operation_conflict",
                    ));
                }
                check_open(&route, now)?;
                route
            } else {
                capacity(&tx, "return_routes", limits.max_retained_routes)?;
                let open:u64=tx.query_row("SELECT COUNT(*) FROM return_routes WHERE closed_ms IS NULL AND (expires_ms IS NULL OR expires_ms>?1)",params![sql(now)?],|r|r.get(0)).map_err(storage_error)?;
                if open >= limits.max_open_routes as u64 {
                    return Err(failure(ErrorClass::Capacity, "open_route_capacity"));
                }
                if params.route_expires_at_ms.is_some_and(|v| v <= now) {
                    return Err(failure(ErrorClass::Invalid, "route_expired"));
                }
                let modes = params
                    .allowed_modes
                    .clone()
                    .unwrap_or_else(|| vec![Mode::Message]);
                for mode in &modes {
                    if !allowed(grant.modes(), &wire_name(mode)?) {
                        return Err(failure(ErrorClass::Forbidden, "route_mode_not_allowed"));
                    }
                }
                let kinds = params
                    .allowed_kinds
                    .clone()
                    .unwrap_or_else(|| grant.kinds().to_vec());
                if kinds.is_empty() || kinds.iter().any(|v| !allowed(grant.kinds(), v)) {
                    return Err(failure(ErrorClass::Forbidden, "route_kind_not_allowed"));
                }
                let constraints = RouteConstraints {
                    allowed_modes: modes,
                    allowed_kinds: kinds,
                    max_payload_bytes: params
                        .max_payload_bytes
                        .unwrap_or(crate::MAX_PAYLOAD_BYTES as u32),
                    reply_policy: params.reply_policy,
                };
                let caller_scope = scope(&tx, grant.producer(), "caller", &caller)?;
                let destination_scope = scope(&tx, grant.producer(), "destination", &destination)?;
                let route = Route {
                    producer: grant.producer().into(),
                    operation: params.operation_key.clone(),
                    key: random_key("route")?,
                    requested,
                    caller,
                    destination,
                    constraints,
                    caller_scope,
                    destination_scope,
                    created: now,
                    expires: params.route_expires_at_ms,
                    closed: None,
                };
                let binding_hash = route.binding_hash()?;
                tx.execute("INSERT INTO return_routes (producer,operation_key,route_key,binding_hash,requested_json,caller_json,destination,constraints_json,caller_scope,destination_scope,created_ms,expires_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![route.producer,route.operation,route.key,binding_hash,route.requested,route.caller,route.destination,encode(&route.constraints)?,route.caller_scope,route.destination_scope,sql(now)?,route.expires.map(sql).transpose()?]).map_err(storage_error)?;
                route
            };
            let receipt = route.receipt(request_id);
            tx.execute(
                "INSERT INTO evidence_uses(use_key,producer,request_id) VALUES(?1,?2,?3)",
                params![origin.evidence_use_key, grant.producer(), request_id],
            )
            .map_err(storage_error)?;
            tx.execute("INSERT INTO registration_requests(producer,request_id,request_hash,operation_key,receipt_json,use_key) VALUES(?1,?2,?3,?4,?5,?6)",params![grant.producer(),request_id,hash,params.operation_key,encode(&receipt)?,origin.evidence_use_key]).map_err(storage_error)?;
            commit(tx, reconciliation.clone())?;
            Ok(receipt)
        };
        action().map_err(|e| mutation_error(e, reconciliation))
    }
    /// Reconciles an uncertain native claim without disclosing another owner.
    /// NotVisible never establishes definite noncommit or fresh authority.
    pub fn registration_evidence_committed(
        &self,
        credential: &str,
        request_id: &str,
        use_key: &str,
    ) -> Result<RegistrationReconciliation, ApiError> {
        if !opaque(request_id) || !opaque(use_key) {
            return Err(failure(ErrorClass::Invalid, "invalid_reconciliation_key"));
        }
        let auth = self.producer_authorizer()?;
        let grant = auth.authenticate(credential)?;
        let receipt = read_json::<RegistrationReceipt>(
            &self.connection,
            "registration_requests",
            grant.producer(),
            "request_id",
            request_id,
        )?;
        let owner: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT producer,request_id FROM evidence_uses WHERE use_key=?1",
                params![use_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let claim = match owner {
            None => RegistrationClaimState::NotVisible,
            Some((producer, request)) if producer == grant.producer() && request == request_id => {
                RegistrationClaimState::CommittedToRequest
            }
            _ => RegistrationClaimState::CommittedElsewhere,
        };
        if claim == RegistrationClaimState::CommittedToRequest && receipt.is_none() {
            return Err(integrity());
        }
        Ok(RegistrationReconciliation { receipt, claim })
    }
    /// Commits authenticated normalized event intent and canonical custody in
    /// one immediate transaction. Credential determines producer; params contain
    /// immutable event_id, tagged own route/authorized address, opaque content,
    /// mode/policy/metadata, absolute expiry and optional producer lifetime.
    /// Message/keep_all/empty metadata/no expiry are protocol defaults.
    ///
    /// Existing exact intent recovers its original receipt before new
    /// route/expiry/current-policy admission. Changed intent or legacy-only
    /// identity conflicts; a route key is a scoped reference, never authority.
    /// Clock returns Unix milliseconds in 1..=MAX_SQLITE_INT, sampled after
    /// BEGIN IMMEDIATE acquisition. Current grants, route and lifetime fences
    /// serialize with new custody; success proves custody only and never
    /// requests another native handoff on replay.
    ///
    /// Precommit validation/auth/admission errors report NotCommitted. Failure
    /// at COMMIT reports Unknown with the original event reconciliation key;
    /// absent status is not proof that another same-key commit cannot exist.
    /// Preserve/reconcile the immutable event intent and exact-retry that ID,
    /// never replace it or directly resend an uncertain native effect.
    pub fn publish_v1(
        &mut self,
        credential: &str,
        params: &PublishParams,
        clock: &dyn Fn() -> u64,
    ) -> Result<PublishResult, ApiError> {
        let reconciliation = ReconciliationKey::Event {
            event_id: params.event_id.clone(),
        };
        let mut action = || -> Result<PublishResult, ApiError> {
            let intent = publication_intent_fingerprint(params).map_err(protocol_error)?;
            let auth = self.producer_authorizer()?;
            let grant = auth.authenticate(credential)?;
            let limits = self.limits();
            let universal = self.universal_limits;
            let tx = self.begin().map_err(storage_error)?;
            let now = clock();
            positive_time(now)?;
            if let Some((hash, receipt)) = read_intent(&tx, grant.producer(), &params.event_id)? {
                if hash != intent {
                    return Err(failure(ErrorClass::Conflict, "intent_conflict"));
                }
                return Ok(PublishResult {
                    receipt,
                    replayed: true,
                });
            }
            if tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE publisher_id=?1 AND event_id=?2)",
                    params![grant.producer(), params.event_id],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(storage_error)?
            {
                return Err(failure(ErrorClass::Conflict, "legacy_event_identity"));
            }
            let policy = grant
                .policy()
                .ok_or_else(|| failure(ErrorClass::Forbidden, "producer_v1_disabled"))?;
            let frozen = match &params.destination {
                Destination::Route { route_key } => {
                    let route = load_route(&tx, grant.producer(), route_key)?
                        .ok_or_else(|| failure(ErrorClass::Forbidden, "route_not_accessible"))?;
                    check_open(&route, now)?;
                    if !route.constraints.allowed_modes.contains(&params.mode)
                        || !allowed(&route.constraints.allowed_kinds, &params.kind)
                        || params.payload.as_str().len()
                            > route.constraints.max_payload_bytes as usize
                    {
                        return Err(failure(ErrorClass::Forbidden, "route_constraints"));
                    }
                    FrozenDestination {
                        address: route.destination,
                        route_key: Some(route.key),
                        caller_scope: Some(route.caller_scope),
                        destination_scope: Some(route.destination_scope),
                    }
                }
                Destination::Address { address } => {
                    if !policy.direct_address {
                        return Err(failure(ErrorClass::Forbidden, "direct_address_not_allowed"));
                    }
                    let address = crate::NativeAddress::parse(address)
                        .map_err(|_| failure(ErrorClass::Invalid, "invalid_address"))?
                        .to_canonical_string();
                    FrozenDestination {
                        address,
                        route_key: None,
                        caller_scope: None,
                        destination_scope: None,
                    }
                }
            };
            if !grant.allows_recipient(&frozen.address)
                || !allowed(grant.kinds(), &params.kind)
                || !allowed(grant.modes(), &wire_name(&params.mode)?)
                || !allowed(grant.policies(), &policy_name(&params.policy))
            {
                return Err(failure(ErrorClass::Forbidden, "publication_not_allowed"));
            }
            let lifetime = params.delivery_scope_key.as_deref().unwrap_or("");
            if !lifetime.is_empty() {
                if !policy.delivery_scopes {
                    return Err(failure(ErrorClass::Unsupported, "delivery_scopes_disabled"));
                }
                let closed: Option<Option<i64>> = tx
                    .query_row(
                        "SELECT closed_ms FROM delivery_scopes WHERE producer=?1 AND scope_key=?2",
                        params![grant.producer(), lifetime],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(storage_error)?;
                match closed {
                    Some(Some(_)) => {
                        return Err(failure(ErrorClass::Conflict, "delivery_scope_closed"));
                    }
                    None => {
                        capacity(&tx, "delivery_scopes", universal.max_delivery_scopes)?;
                        tx.execute(
                            "INSERT INTO delivery_scopes(producer,scope_key) VALUES(?1,?2)",
                            params![grant.producer(), lifetime],
                        )
                        .map_err(storage_error)?;
                    }
                    _ => {}
                }
            }
            let envelope = crate::Envelope::new(
                crate::PublisherId::new(grant.producer()).map_err(storage_error)?,
                crate::EventId::new(&params.event_id).map_err(storage_error)?,
                crate::NativeAddress::parse(&frozen.address).map_err(storage_error)?,
                crate::Kind::new(&params.kind).map_err(storage_error)?,
                core_mode(params.mode),
                core_policy(&params.policy)?,
                crate::Payload::new(params.payload.as_str()).map_err(storage_error)?,
                params.metadata.clone(),
                params
                    .expires_at_ms
                    .map(crate::ExpiresAt::from_unix_millis)
                    .transpose()
                    .map_err(storage_error)?,
            )
            .map_err(storage_error)?;
            crate::framing::check_renderable(&envelope).map_err(storage_error)?;
            let custody = publish_in(&tx, &envelope, now, limits, lifetime)
                .map_err(storage_error)?
                .receipt;
            let receipt = EventReceipt {
                producer: grant.producer().into(),
                event_id: params.event_id.clone(),
                intent_hash: intent.clone(),
                envelope_hash: custody.envelope_hash.as_str().into(),
                accepted_at_ms: custody.accepted_at_ms,
                acceptance_seq: custody.acceptance_seq,
                destination: frozen,
            };
            tx.execute("INSERT INTO publication_intents(producer,event_id,intent_hash,receipt_json) VALUES(?1,?2,?3,?4)",params![grant.producer(),params.event_id,intent,encode(&receipt)?]).map_err(storage_error)?;
            commit(tx, reconciliation.clone())?;
            Ok(PublishResult {
                receipt,
                replayed: false,
            })
        };
        action().map_err(|e| mutation_error(e, reconciliation))
    }
}

/// Validates positive SQLite-safe commit time; tests supply a controlled clock.
fn positive_time(now: u64) -> Result<(), ApiError> {
    validate_positive("commit_time", now).map_err(protocol_error)
}
/// SQLite-safe signed conversion without wrapping timestamps/counters.
fn sql(value: u64) -> Result<i64, ApiError> {
    to_sql(value).map_err(storage_error)
}
/// Encodes trusted bounded records without exposing encoding diagnostics.
fn encode<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(|_| integrity())
}
/// Decodes one trusted record, refusing integrity loss without body disclosure.
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, ApiError> {
    serde_json::from_str(value).map_err(|_| integrity())
}
/// Static storage-integrity error; no database bytes are disclosed.
fn integrity() -> ApiError {
    failure(ErrorClass::Unavailable, "stored_integrity")
}
/// Maps pure protocol validation to a static refusal with no rejected values.
fn protocol_error(_: ProtocolError) -> ApiError {
    failure(ErrorClass::Invalid, "invalid_request")
}
/// Maps precommit storage failure classes without native/SQLite diagnostics.
fn storage_error(error: impl Into<CoreError>) -> ApiError {
    match error.into() {
        CoreError::Capacity { .. } => failure(ErrorClass::Capacity, "capacity"),
        CoreError::Busy(_) => failure(ErrorClass::Busy, "storage_busy"),
        CoreError::Conflict { .. } => failure(ErrorClass::Conflict, "custody_conflict"),
        CoreError::Unsupported(_) => failure(ErrorClass::Unsupported, "native_mode_unsupported"),
        CoreError::InvalidEnvelope(_) => failure(ErrorClass::Invalid, "invalid_envelope"),
        _ => failure(ErrorClass::Unavailable, "storage_unavailable"),
    }
}
/// Adds definite precommit effect unless an owning commit already marked unknown.
fn mutation_error(mut error: ApiError, key: ReconciliationKey) -> ApiError {
    if error.effect.is_none() {
        error.effect = Some(MutationEffect::NotCommitted);
    }
    if error.reconciliation.is_none() {
        error.reconciliation = Some(key);
    }
    error
}
/// Commits before acknowledgement; any failure at COMMIT is conservatively
/// unknown, regardless of the raw SQLite class, and reconciles the same identity.
fn commit(tx: Transaction<'_>, key: ReconciliationKey) -> Result<(), ApiError> {
    tx.commit().map_err(|_| ApiError {
        class: ErrorClass::OutcomeUnknown,
        reason: "commit_outcome_unknown".into(),
        retry_hint: RetryHint::ObserveSameIdentity,
        effect: Some(MutationEffect::Unknown),
        reconciliation: Some(key),
        detail: "Reconcile the original identity.".into(),
    })
}
/// Canonical finite enum wire spelling, reused for generic policy matching.
fn wire_name<T: Serialize>(value: &T) -> Result<String, ApiError> {
    serde_json::to_value(value)
        .map_err(|_| integrity())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(integrity)
}
/// Canonical trusted binding digest; public request hashing stays protocol-owned.
fn hash_json<T: Serialize>(value: &T) -> Result<String, ApiError> {
    Ok(format!("{:x}", Sha256::digest(encode(value)?.as_bytes())))
}
/// Refuses hard identity capacity without evicting active rows or tombstones.
fn capacity(tx: &Connection, table: &str, limit: usize) -> Result<(), ApiError> {
    let count: u64 = tx
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .map_err(storage_error)?;
    if count >= limit as u64 {
        Err(failure(ErrorClass::Capacity, "identity_capacity"))
    } else {
        Ok(())
    }
}
/// Random issuer reference from operating-system entropy, never PID/time/random
/// heuristics; failure refuses before commit rather than weakening identity.
fn random_key(kind: &str) -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| failure(ErrorClass::Unavailable, "randomness_unavailable"))?;
    Ok(format!(
        "{kind}-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
/// Finds/creates a separate random durable logical actor/destination mapping.
fn scope(tx: &Connection, producer: &str, kind: &str, identity: &str) -> Result<String, ApiError> {
    if let Some(key)=tx.query_row("SELECT scope_key FROM producer_scopes WHERE producer=?1 AND kind=?2 AND identity_key=?3",params![producer,kind,identity],|r|r.get(0)).optional().map_err(storage_error)?{return Ok(key);}
    let key = random_key(kind)?;
    tx.execute(
        "INSERT INTO producer_scopes(producer,kind,identity_key,scope_key) VALUES(?1,?2,?3,?4)",
        params![producer, kind, identity, key],
    )
    .map_err(storage_error)?;
    Ok(key)
}
/// Reads an owned fixed-table receipt; table/column arguments are crate literals.
fn read_json<T: DeserializeOwned>(
    tx: &Connection,
    table: &str,
    producer: &str,
    column: &str,
    key: &str,
) -> Result<Option<T>, ApiError> {
    let raw: Option<String> = tx
        .query_row(
            &format!("SELECT receipt_json FROM {table} WHERE producer=?1 AND {column}=?2"),
            params![producer, key],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    raw.map(|s| decode(&s)).transpose()
}
/// Exact request replay compares immutable semantics before returning history.
fn replay_registration(
    tx: &Connection,
    producer: &str,
    request: &str,
    hash: &str,
) -> Result<Option<RegistrationReceipt>, ApiError> {
    let raw:Option<(String,String)>=tx.query_row("SELECT request_hash,receipt_json FROM registration_requests WHERE producer=?1 AND request_id=?2",params![producer,request],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage_error)?;
    match raw {
        Some((stored, raw)) if stored == hash => Ok(Some(decode(&raw)?)),
        Some(_) => Err(failure(
            ErrorClass::Conflict,
            "registration_request_conflict",
        )),
        None => Ok(None),
    }
}
/// Loads one producer-owned route; foreign and missing route are indistinguishable.
fn load_route(tx: &Connection, producer: &str, key: &str) -> Result<Option<Route>, ApiError> {
    let raw:Option<RawRoute>=tx.query_row("SELECT operation_key,requested_json,caller_json,destination,constraints_json,caller_scope,destination_scope,created_ms,expires_ms,closed_ms,binding_hash FROM return_routes WHERE producer=?1 AND route_key=?2",params![producer,key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional().map_err(storage_error)?;
    raw.map(
        |(
            operation,
            requested,
            caller,
            destination,
            constraints,
            caller_scope,
            destination_scope,
            created,
            expires,
            closed,
            hash,
        )| {
            let route = Route {
                producer: producer.into(),
                operation,
                key: key.into(),
                requested,
                caller,
                destination,
                constraints: decode(&constraints)?,
                caller_scope,
                destination_scope,
                created,
                expires,
                closed,
            };
            route.constraints.validate().map_err(|_| integrity())?;
            if route.binding_hash()? != hash {
                return Err(integrity());
            }
            Ok(route)
        },
    )
    .transpose()
}
/// Reads immutable v1 custody intent/receipt before new-event authorization.
fn read_intent(
    tx: &Connection,
    producer: &str,
    event: &str,
) -> Result<Option<(String, EventReceipt)>, ApiError> {
    let raw:Option<(String,String)>=tx.query_row("SELECT intent_hash,receipt_json FROM publication_intents WHERE producer=?1 AND event_id=?2",params![producer,event],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage_error)?;
    raw.map(|(hash, raw)| Ok((hash, decode(&raw)?))).transpose()
}
/// Fences only new route operations; exact request/event history recovers first.
fn check_open(route: &Route, now: u64) -> Result<(), ApiError> {
    match route.state(now) {
        RouteState::Open => Ok(()),
        RouteState::Closed => Err(failure(ErrorClass::Conflict, "route_closed")),
        RouteState::Expired => Err(failure(ErrorClass::Conflict, "route_expired")),
    }
}
/// Converts only generic protocol selector values, never product names.
fn core_mode(mode: Mode) -> crate::Mode {
    match mode {
        Mode::Message => crate::Mode::Message,
        Mode::Inject => crate::Mode::Inject,
        Mode::Auto => crate::Mode::Auto,
    }
}
/// Generic policy name for current allowlist admission.
fn policy_name(policy: &Policy) -> String {
    match policy {
        Policy::KeepAll => "keep_all",
        Policy::Latest { .. } => "latest",
        Policy::Batch { .. } => "batch",
    }
    .into()
}
/// Converts generic compaction fields into unchanged canonical core policy.
fn core_policy(policy: &Policy) -> Result<crate::Policy, ApiError> {
    Ok(match policy {
        Policy::KeepAll => crate::Policy::KeepAll,
        Policy::Latest { stream, revision } => crate::Policy::Latest {
            stream: crate::StreamId::new(stream).map_err(storage_error)?,
            revision: *revision,
        },
        Policy::Batch { group } => crate::Policy::Batch {
            group: group.clone(),
        },
    })
}

impl Storage {
    /// Reads only authenticated producer records, separating historical custody
    /// from delivery and current route state. Reads cannot create authority or
    /// restart native delivery; absent records are not proof of noncommit.
    pub fn status_v1(
        &self,
        credential: &str,
        selector: &StatusSelector,
        now_ms: u64,
    ) -> Result<StatusResult, ApiError> {
        selector.validate().map_err(protocol_error)?;
        positive_time(now_ms)?;
        let auth = self.producer_authorizer()?;
        let grant = auth.authenticate(credential)?;
        Ok(match selector {
            StatusSelector::Registration { request_id } => StatusResult::Registration {
                receipt: read_json(
                    &self.connection,
                    "registration_requests",
                    grant.producer(),
                    "request_id",
                    request_id,
                )?,
            },
            StatusSelector::Route { route_key } => {
                let route = load_route(&self.connection, grant.producer(), route_key)?;
                let route=route.map(|route|->Result<RouteStatus,ApiError>{
                    let raw:String=self.connection.query_row("SELECT receipt_json FROM registration_requests WHERE producer=?1 AND operation_key=?2 ORDER BY rowid LIMIT 1",params![grant.producer(),route.operation],|r|r.get(0)).map_err(storage_error)?;
                    Ok(RouteStatus{receipt:decode(&raw)?,state:route.state(now_ms),closed_at_ms:route.closed})
                }).transpose()?;
                StatusResult::Route { route }
            }
            StatusSelector::Event { event_id } => {
                let event = read_intent(&self.connection, grant.producer(), event_id)?
                    .map(|(_, receipt)| -> Result<EventStatus, ApiError> {
                        let custody = self
                            .lookup(
                                &crate::PublisherId::new(grant.producer())
                                    .map_err(storage_error)?,
                                &crate::EventId::new(event_id).map_err(storage_error)?,
                            )
                            .map_err(storage_error)?
                            .ok_or_else(integrity)?;
                        let delivery = delivery_status(
                            self.delivery_evidence(grant.producer(), event_id)
                                .map_err(storage_error)?,
                        )?;
                        Ok(EventStatus {
                            receipt,
                            custody_state: decode(&encode(&custody.state)?)?,
                            delivery,
                        })
                    })
                    .transpose()?;
                StatusResult::Event { event }
            }
        })
    }
    /// Fences only new custody against an authenticated own return route.
    /// Request_id is the producer's stable <=256-byte close retry identity;
    /// params bind its route_key and optional bounded reason (default None).
    /// Changed same-request semantics conflict. Existing events retain ordinary
    /// delivery/expiry, accepted intent retry and their frozen destination.
    ///
    /// Clock returns Unix milliseconds in 1..=MAX_SQLITE_INT, sampled after
    /// BEGIN IMMEDIATE; closure and new publication serialize at commit.
    /// Success returns an immutable close receipt or exact replay. First close
    /// time stays fixed; already-expired routes stay expired and never reopen.
    /// Precommit failures report NotCommitted, while COMMIT failure is Unknown
    /// with this original close reconciliation key. Query/reconcile or retry
    /// the same request and route; absence does not cancel an in-flight commit.
    /// Closing neither recalls a native effect nor authorizes delivery replay.
    pub fn close_route(
        &mut self,
        credential: &str,
        request_id: &str,
        params: &CloseRouteParams,
        clock: &dyn Fn() -> u64,
    ) -> Result<CloseResult, ApiError> {
        let reconciliation = ReconciliationKey::Close {
            request_id: request_id.into(),
        };
        let mut action = || -> Result<CloseResult, ApiError> {
            validate_id("request_id", request_id, MAX_ID_BYTES).map_err(protocol_error)?;
            params.validate().map_err(protocol_error)?;
            let hash = hash_json(params)?;
            let auth = self.producer_authorizer()?;
            let grant = auth.authenticate(credential)?;
            let limits = self.universal_limits;
            let tx = self.begin().map_err(storage_error)?;
            let now = clock();
            positive_time(now)?;
            if let Some(raw) = replay_lifecycle::<CloseReceipt>(
                &tx,
                "close_requests",
                grant.producer(),
                request_id,
                &hash,
            )? {
                return Ok(CloseResult {
                    receipt: raw,
                    replayed: true,
                });
            }
            if grant.policy().is_none() {
                return Err(failure(ErrorClass::Forbidden, "producer_v1_disabled"));
            }
            lifecycle_capacity(&tx, limits.max_lifecycle_requests)?;
            let mut route = load_route(&tx, grant.producer(), &params.route_key)?
                .ok_or_else(|| failure(ErrorClass::Forbidden, "route_not_accessible"))?;
            if route.state(now) == RouteState::Open {
                tx.execute("UPDATE return_routes SET closed_ms=?1 WHERE producer=?2 AND route_key=?3 AND closed_ms IS NULL",params![sql(now)?,grant.producer(),params.route_key]).map_err(storage_error)?;
                route.closed = Some(now);
            }
            let receipt = CloseReceipt {
                producer: grant.producer().into(),
                request_id: request_id.into(),
                route_key: params.route_key.clone(),
                state: route.state(now),
                closed_at_ms: route.closed,
            };
            tx.execute("INSERT INTO close_requests(producer,request_id,request_hash,receipt_json) VALUES(?1,?2,?3,?4)",params![grant.producer(),request_id,hash,encode(&receipt)?]).map_err(storage_error)?;
            commit(tx, reconciliation.clone())?;
            Ok(CloseResult {
                receipt,
                replayed: false,
            })
        };
        action().map_err(|e| mutation_error(e, reconciliation))
    }
    /// Permanently fences an authenticated producer-owned opaque lifetime,
    /// including before first publication. Request_id is a stable <=256-byte
    /// retry identity; params fix scope_key and explicit immutable action.
    /// Preserve fences new custody only and keeps existing dispatch eligible.
    /// RetireUnhanded also fences every new invoking transition and safely
    /// disposes only proved zero-effect work, including uninvoked reservations.
    /// Invoking/held/written/unknown/accepted history remains retained.
    ///
    /// Clock returns Unix milliseconds in 1..=MAX_SQLITE_INT after acquiring
    /// BEGIN IMMEDIATE. Custody, retirement and invoking permission serialize
    /// durably; no accepted native effect is recalled. Success returns the
    /// original four disjoint first-snapshot counts/time/action. Exact retry
    /// returns its original receipt; a later same-action request changes only
    /// request_id, and changed action conflicts. No retired scope key reopens.
    ///
    /// Precommit auth/validation/capacity/conflict failures report NotCommitted.
    /// COMMIT failure reports Unknown with the original retirement key;
    /// reconcile or exact-retry that request/scope without replacing identity.
    /// Missing visible status is not cancellation or definite noncommit.
    pub fn retire_delivery_scope(
        &mut self,
        credential: &str,
        request_id: &str,
        params: &RetireDeliveryScopeParams,
        clock: &dyn Fn() -> u64,
    ) -> Result<RetireResult, ApiError> {
        let reconciliation = ReconciliationKey::Retire {
            request_id: request_id.into(),
        };
        let mut action = || -> Result<RetireResult, ApiError> {
            validate_id("request_id", request_id, MAX_ID_BYTES).map_err(protocol_error)?;
            params.validate().map_err(protocol_error)?;
            let hash = hash_json(params)?;
            let auth = self.producer_authorizer()?;
            let grant = auth.authenticate(credential)?;
            let limits = self.universal_limits;
            let tx = self.begin().map_err(storage_error)?;
            let now = clock();
            positive_time(now)?;
            if let Some(receipt) = replay_lifecycle::<RetireReceipt>(
                &tx,
                "retire_requests",
                grant.producer(),
                request_id,
                &hash,
            )? {
                return Ok(RetireResult {
                    receipt,
                    replayed: true,
                });
            }
            if !grant.policy().is_some_and(|p| p.delivery_scopes) {
                return Err(failure(ErrorClass::Unsupported, "delivery_scopes_disabled"));
            }
            lifecycle_capacity(&tx, limits.max_lifecycle_requests)?;
            let previous:Option<(Option<String>,Option<String>)>=tx.query_row("SELECT action,receipt_json FROM delivery_scopes WHERE producer=?1 AND scope_key=?2",params![grant.producer(),params.scope_key],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage_error)?;
            let first = if let Some((Some(previous_action), Some(raw))) = &previous {
                if previous_action != &wire_name(&params.action)? {
                    return Err(failure(ErrorClass::Conflict, "retirement_action_conflict"));
                }
                decode::<RetireReceipt>(raw)?
            } else {
                if previous.is_none() {
                    capacity(&tx, "delivery_scopes", limits.max_delivery_scopes)?;
                }
                tx.execute("INSERT INTO delivery_scopes(producer,scope_key,closed_ms,action) VALUES(?1,?2,?3,?4) ON CONFLICT(producer,scope_key) DO UPDATE SET closed_ms=excluded.closed_ms,action=excluded.action",params![grant.producer(),params.scope_key,sql(now)?,wire_name(&params.action)?]).map_err(storage_error)?;
                // ponytail: set-based retirement under the single SQLite writer;
                // partition scopes only if measured transaction latency requires it.
                let (possible,terminal,unhanded):(u64,u64,u64)=tx.query_row(
                    &format!("SELECT COALESCE(SUM(CASE WHEN possible THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN NOT possible AND (state!='pending' OR delivery IN('accepted','hook_submitted','refused','disposed')) THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN NOT possible AND state='pending' AND delivery NOT IN('accepted','hook_submitted','refused','disposed') THEN 1 ELSE 0 END),0) FROM (SELECT e.state,e.delivery,{POSSIBLE_EFFECT} AS possible FROM events e WHERE e.publisher_id=?1 AND e.delivery_scope_key=?2)") ,
                    params![grant.producer(),params.scope_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))
                ).map_err(storage_error)?;
                let retire = params.action == RetirementAction::RetireUnhanded;
                let receipt = RetireReceipt {
                    producer: grant.producer().into(),
                    request_id: request_id.into(),
                    scope_key: params.scope_key.clone(),
                    action: params.action,
                    retired_at_ms: now,
                    disposed: if retire { unhanded } else { 0 },
                    already_terminal: terminal,
                    preserved_possible_effect: possible,
                    preserved_unhanded: if retire { 0 } else { unhanded },
                };
                if retire {
                    tx.execute("UPDATE attempts SET state='closed',note='producer lifetime retired before invocation',updated_ms=?1,lease_expires_ms=NULL WHERE state='reserved' AND EXISTS(SELECT 1 FROM attempt_members m JOIN events e ON e.publisher_id=m.publisher_id AND e.event_id=m.event_id WHERE m.attempt_seq=attempts.attempt_seq AND e.publisher_id=?2 AND e.delivery_scope_key=?3)",params![sql(now)?,grant.producer(),params.scope_key]).map_err(storage_error)?;
                    tx.execute("UPDATE events SET delivery='unhanded',attempt_seq=NULL,attempts_made=MAX(attempts_made-1,0) WHERE publisher_id=?1 AND delivery_scope_key=?2 AND delivery='reserved'",params![grant.producer(),params.scope_key]).map_err(storage_error)?;
                    tx.execute(&format!("UPDATE events AS e SET delivery='disposed',attempt_seq=NULL WHERE e.publisher_id=?1 AND e.delivery_scope_key=?2 AND e.state='pending' AND e.delivery='unhanded' AND NOT {POSSIBLE_EFFECT}"),params![grant.producer(),params.scope_key]).map_err(storage_error)?;
                    tx.execute(&format!("UPDATE events AS e SET delivery='review' WHERE e.publisher_id=?1 AND e.delivery_scope_key=?2 AND e.delivery='unhanded' AND {POSSIBLE_EFFECT}"),params![grant.producer(),params.scope_key]).map_err(storage_error)?;
                    tx.execute("UPDATE incidents SET state='disposed',resolution='producer lifetime retired before handoff',updated_ms=?1,resolved_ms=?1 WHERE publisher_id=?2 AND state='open' AND EXISTS(SELECT 1 FROM events e WHERE e.publisher_id=incidents.publisher_id AND e.event_id=incidents.event_id AND e.delivery_scope_key=?3 AND e.delivery='disposed')",params![sql(now)?,grant.producer(),params.scope_key]).map_err(storage_error)?;
                }
                tx.execute(
                    "UPDATE delivery_scopes SET receipt_json=?1 WHERE producer=?2 AND scope_key=?3",
                    params![encode(&receipt)?, grant.producer(), params.scope_key],
                )
                .map_err(storage_error)?;
                receipt
            };
            let receipt = RetireReceipt {
                request_id: request_id.into(),
                ..first
            };
            tx.execute("INSERT INTO retire_requests(producer,request_id,request_hash,receipt_json) VALUES(?1,?2,?3,?4)",params![grant.producer(),request_id,hash,encode(&receipt)?]).map_err(storage_error)?;
            commit(tx, reconciliation.clone())?;
            Ok(RetireResult {
                receipt,
                replayed: false,
            })
        };
        action().map_err(|e| mutation_error(e, reconciliation))
    }
    /// Authenticated policy-only core capabilities. Native ingress augments host
    /// contracts, acceptance and assertion cache capacity independently (it
    /// advertises no native build contract); this core response never claims a
    /// configured harness policy was live-verified.
    pub fn capabilities_v1(&self, credential: &str) -> Result<Capabilities, ApiError> {
        let auth = self.producer_authorizer()?;
        let grant = auth.authenticate(credential)?;
        let modes = public_set(
            grant
                .modes()
                .iter()
                .map(|m| decode(&encode(m)?))
                .collect::<Result<Vec<Mode>, _>>()?,
        );
        let policies = public_set(
            grant
                .policies()
                .iter()
                .map(|p| decode(&encode(p)?))
                .collect::<Result<Vec<PolicyKind>, _>>()?,
        );
        let replies = public_set(
            grant
                .reply_policies()
                .iter()
                .map(|p| decode(&encode(p)?))
                .collect::<Result<Vec<ReplyPolicy>, _>>()?,
        );
        let scope = grant.policy().is_some_and(|p| p.delivery_scopes);
        let mut operations = vec!["capabilities".into(), "status".into()];
        if let Some(policy) = grant.policy() {
            operations.extend(["publish".into(), "close_route".into()]);
            if policy.registration {
                operations.push("register_call".into());
            }
            if scope {
                operations.push("retire_delivery_scope".into());
            }
        }
        Ok(Capabilities {
            api_version: API_VERSION,
            supported_versions: vec![API_VERSION],
            operations,
            evidence_variants: Vec::new(),
            native_contracts: Vec::new(),
            modes: modes.clone(),
            policies: policies.clone(),
            reply_policies: replies.clone(),
            limits: Limits {
                registration_request_bytes: MAX_REGISTRATION_BYTES as u64,
                core_request_bytes: MAX_REQUEST_BYTES as u64,
                response_bytes: MAX_RESPONSE_BYTES as u64,
                payload_bytes: crate::MAX_PAYLOAD_BYTES as u64,
                metadata_entries: crate::MAX_METADATA_ENTRIES as u64,
                rendered_manifest_bytes: crate::framing::MAX_FRAMED_BYTES as u64,
                open_routes: self.universal_limits.max_open_routes as u64,
                assertions: 0,
            },
            grant: ProducerConstraints {
                allowed_modes: modes,
                allowed_policies: policies,
                allowed_kinds: public_set(grant.kinds().to_vec()),
                reply_policies: replies,
                direct_address: grant.policy().is_some_and(|p| p.direct_address),
                native_scopes: public_set(grant.native_scopes().to_vec()),
            },
            features: Features {
                consume_assertion: false,
                delivery_scopes: scope,
                host_observations: false,
            },
            retention: Retention {
                durable_keys: true,
                closed_tombstones: true,
                credential_independent_identity: true,
            },
        })
    }
}
/// Conservative historical-effect predicate: operator-retried unknowns remain
/// possible even after their current reservation was proven uninvoked. Held
/// states are retained conservatively; producer retirement never uses operator
/// disposal authority to erase uncertainty or accepted handoff history.
const POSSIBLE_EFFECT: &str = "(e.duplicate_risk != 0 OR e.delivery IN('invoking','held','review','accepted','hook_submitted') OR EXISTS(SELECT 1 FROM attempt_members m JOIN attempts a ON a.attempt_seq=m.attempt_seq WHERE m.publisher_id=e.publisher_id AND m.event_id=e.event_id AND a.state IN('invoking','native_held','written_no_receipt','outcome_unknown','native_accepted','hook_submitted')) OR EXISTS(SELECT 1 FROM evidence v WHERE v.publisher_id=e.publisher_id AND v.event_id=e.event_id AND v.tier IN('unknown','native_held','written_no_receipt','native_accepted','hook_emitted','context_observed','application_processed')))";
/// Reads exact lifecycle request identity; changed target/action/reason conflicts.
fn replay_lifecycle<T: DeserializeOwned>(
    tx: &Connection,
    table: &str,
    producer: &str,
    request: &str,
    hash: &str,
) -> Result<Option<T>, ApiError> {
    let raw: Option<(String, String)> = tx
        .query_row(
            &format!(
                "SELECT request_hash,receipt_json FROM {table} WHERE producer=?1 AND request_id=?2"
            ),
            params![producer, request],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage_error)?;
    match raw {
        Some((stored, raw)) if stored == hash => Ok(Some(decode(&raw)?)),
        Some(_) => Err(failure(ErrorClass::Conflict, "lifecycle_request_conflict")),
        None => Ok(None),
    }
}
/// Bounds both lifecycle ledgers together without removing retained request IDs.
fn lifecycle_capacity(tx: &Connection, limit: usize) -> Result<(), ApiError> {
    let count: u64 = tx
        .query_row(
            "SELECT (SELECT COUNT(*) FROM close_requests)+(SELECT COUNT(*) FROM retire_requests)",
            [],
            |r| r.get(0),
        )
        .map_err(storage_error)?;
    if count >= limit as u64 {
        Err(failure(ErrorClass::Capacity, "lifecycle_capacity"))
    } else {
        Ok(())
    }
}

/// Converts retained native facts into the content-free public status shape.
/// Core's None delivery means the existing event is positively unhanded with
/// no attempts/evidence/hold; it does not mean absence of custody.
fn delivery_status(delivery: Option<crate::DeliveryEvidence>) -> Result<DeliveryStatus, ApiError> {
    let Some(delivery) = delivery else {
        return Ok(DeliveryStatus {
            delivery: DeliveryState::Unhanded,
            attempt_state: None,
            effective_mode: None,
            note: None,
            attempts_made: 0,
            attempt: None,
            tiers: Vec::new(),
            incident: None,
            hold_reason: None,
            blocked_by: None,
        });
    };
    let mut tiers = Vec::new();
    for entry in &delivery.tiers {
        let tier = decode(&encode(&entry.tier)?)?;
        if !tiers.contains(&tier) {
            tiers.push(tier);
        }
    }
    Ok(DeliveryStatus {
        delivery: decode(&encode(&delivery.delivery)?)?,
        attempt_state: delivery
            .attempt
            .as_ref()
            .map(|a| decode(&encode(&a.state)?))
            .transpose()?,
        effective_mode: delivery
            .attempt
            .as_ref()
            .map(|a| decode(&encode(&a.effective_mode)?))
            .transpose()?,
        note: delivery.note.as_deref().map(public_diagnostic),
        attempts_made: u64::from(delivery.attempts_made),
        attempt: delivery.attempt.as_ref().map(|a| a.attempt_seq),
        tiers,
        incident: delivery
            .incident
            .as_ref()
            .map(|i| format!("incident-{}", i.incident_seq)),
        hold_reason: delivery.hold_reason.as_deref().map(public_diagnostic),
        blocked_by: delivery.blocked_by,
    })
}

/// Projects stored diagnostics to the public no-controls, 512-byte domain.
/// Replaces each control code point with one space, then bounds UTF-8 at a
/// character boundary. Stored/legacy evidence and semantic states are untouched.
fn public_diagnostic(text: &str) -> String {
    crate::recovery::bound_text(
        &text
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>(),
    )
}

/// Projects configured declaration lists into unique public sets, preserving
/// first occurrence order without mutating legacy configuration acceptance.
fn public_set<T: Eq>(values: Vec<T>) -> Vec<T> {
    // ponytail: small configured sets use linear dedup; use a keyed set only
    // if measured legacy configuration sizes make this projection expensive.
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    //! Actual SQLite commit-failure control on private in-memory fixture state.
    use super::*;
    use std::sync::Arc;
    /// A deferred foreign-key failure happens at COMMIT after event/intent writes;
    /// the API must report unknown with original event key, never safe no-effect.
    /// Exact retry after removing the fault recovers without a replacement ID.
    #[test]
    fn commit_failure_reports_unknown_and_exact_retry_is_safe() {
        let token = "fixture-commit-fault-token";
        let mut storage = Storage::open_in_memory(crate::Limits::new(10)).unwrap();
        let grant = crate::GrantConfig {
            token: token.into(),
            publisher: "opaque-producer".into(),
            recipients: vec!["*".into()],
            kinds: vec!["done".into()],
            modes: vec!["message".into()],
            policies: vec!["keep_all".into()],
            admin: false,
            producer_v1: Some(crate::ProducerPolicy {
                direct_address: true,
                ..crate::ProducerPolicy::default()
            }),
        };
        storage
            .install_producer_authorizer(Arc::new(
                crate::ProducerAuthorizer::new(&[grant]).unwrap(),
            ))
            .unwrap();
        storage
            .register_source_tag("opaque-producer", "opaque-producer")
            .unwrap();
        storage.connection.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE fault_parent(id INTEGER PRIMARY KEY); CREATE TABLE fault_child(id INTEGER REFERENCES fault_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER deferred_fault AFTER INSERT ON publication_intents BEGIN INSERT INTO fault_child VALUES(1); END;").unwrap();
        let request = PublishParams {
            destination: Destination::Address {
                address: "fixture/codex/store/session".into(),
            },
            event_id: "event".into(),
            kind: "done".into(),
            payload: Payload::new("opaque result").unwrap(),
            mode: Mode::Message,
            policy: Policy::KeepAll,
            metadata: Metadata::new(),
            expires_at_ms: None,
            delivery_scope_key: None,
        };
        let error = storage.publish_v1(token, &request, &|| 1000).unwrap_err();
        assert_eq!(error.effect, Some(MutationEffect::Unknown));
        assert_eq!(
            error.reconciliation,
            Some(ReconciliationKey::Event {
                event_id: "event".into()
            })
        );
        assert!(matches!(
            storage
                .status_v1(
                    token,
                    &StatusSelector::Event {
                        event_id: "event".into()
                    },
                    1001
                )
                .unwrap(),
            StatusResult::Event { event: None }
        ));
        storage
            .connection
            .execute_batch("DROP TRIGGER deferred_fault;")
            .unwrap();
        let accepted = storage.publish_v1(token, &request, &|| 1002).unwrap();
        assert_eq!(accepted.receipt.acceptance_seq, 1);
        assert!(
            storage
                .publish_v1(token, &request, &|| 1003)
                .unwrap()
                .replayed
        );
        assert_eq!(
            storage
                .connection
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}
