//! Restricted root relay: the only process that turns an attested root
//! caller's `bridge_me` / `bridge_send` / `bridge_status` into core
//! requests.
//!
//! Composition (see the crate docs): the harness-launched MCP frontend
//! ([`crate::mcp`]) attests each `tools/call` through the adapter registry
//! and receives a sealed single-use proof; it forwards `{proof, tool,
//! arguments}` here. The relay redeems the proof itself
//! ([`bridge_adapters::registry::PresentedMeta::Sealed`]) — the registry
//! admits redemption only from a configured relay executable, once, within
//! the proof lifetime, while the caller's binding epoch is unchanged — and
//! learns exactly the caller facts the registry stored. Nothing the
//! frontend or the model asserts (arguments, labels, cwd, environment) is
//! caller evidence.
//!
//! Rules enforced for every request, in order: authenticate (redeem the
//! proof; missing, stale, duplicate, conflicting or unavailable evidence
//! refuses), require a *root* actor acting as its own address (a Claude
//! subagent sharing its root's session, or any child, is refused), require
//! a configured caller scope, then validate the closed arguments. `send`
//! always publishes `keep_all` within the configured address policy through the
//! relay's own core *publisher* grant; `status` reads only events this
//! caller published. Event ids are derived from the caller address, actor
//! and `request_id`, so callers cannot collide with, conflict with or read
//! each other's events (even with equal native ids in different stores),
//! and a repeated `request_id` is an idempotent replay. The caller's
//! harness and session are attached as audit metadata only: core never
//! renders metadata and it is not provenance (the rendered source is the
//! relay grant's publisher tag).
//! There is no other operation: no enumeration, retry, reset, admin,
//! drain, acknowledgement or raw passthrough.
//!
//! The optional `bridge.ack` receipt capability is deliberately absent:
//! core records receipt-token possession only as an annotation with no
//! issued token and no predeclared release tier, and no producer has
//! declared one (see the crate README).

use std::io::BufReader;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use bridge_adapters::registry::{
    ActorRole, CallerAttestor, CorrelationError, PresentedMeta, SealedProof, VerifiedCaller,
};
use bridge_client::{
    BridgeClient, DeliveryEvidence, EventId, EvidenceTier, ExpiresAt, Harness, Kind, Mode,
    NativeAddress, Payload, Policy, ProtocolError, PublishRequest,
};
use bridge_core::recovery::DeliveryState;
use bridge_core::wire::{read_bounded_line, write_line};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{CallerPolicy, RootConfig};

/// The closed root tool set, by MCP tool name.
pub const TOOLS: [&str; 3] = ["bridge_me", "bridge_send", "bridge_status"];

/// Largest relay request line, in bytes (a maximal body JSON-escaped fits).
pub const MAX_RELAY_REQUEST_BYTES: usize = 512 * 1024;

/// Largest relay response line, in bytes.
pub const MAX_RELAY_RESPONSE_BYTES: usize = 64 * 1024;

/// Per-connection read/write deadline.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-operation timeout of the relay's caller attestation with the adapter
/// registry (used by `bridge-root-relay`). The registry client applies it to
/// the request write and to each read separately (not to the whole exchange).
pub const ATTEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The relay's expected time budget for one request, in seconds, from the
/// per-operation timeouts it is built from: reading the request line and
/// writing the answer ([`IO_TIMEOUT`] each), attestation (one stalled write
/// and one stalled read, [`ATTEST_TIMEOUT`] each) and the core client's two
/// repeatable attempts of a 10 s request write plus a 30 s first-byte wait
/// (`bridge-client`). It is a budget, not a hard bound: a peer that trickles
/// bytes into the attestation read and waiting for the shared core
/// connection behind other requests are not counted. An expired replay also
/// performs a custody lookup before publication; that additional exchange is
/// outside this ordinary one-operation budget and can outlast the finite
/// frontend wait without justifying a new request identity.
const RELAY_BUDGET_SECS: u64 =
    2 * IO_TIMEOUT.as_secs() + 2 * ATTEST_TIMEOUT.as_secs() + 2 * (10 + 30);

/// How long the frontend waits for the relay's answer: the relay's expected
/// budget plus a margin. The wait is finite by design, so a request that the
/// relay is slower than this to publish can still be published after the
/// frontend gave up; that is why a failure after the request was written is
/// always reported as an unknown outcome (reuse the same `request_id`).
pub const RELAY_ANSWER_TIMEOUT: Duration = Duration::from_secs(RELAY_BUDGET_SECS + 5);

/// Most connections served at once.
const MAX_CONNECTIONS: usize = 16;

/// Largest accepted `request_id`, in bytes.
const MAX_REQUEST_ID_BYTES: usize = 128;

/// Prefix of every relay-derived core event id.
const EVENT_PREFIX: &str = "root-";

/// One request from the frontend.
///
/// `proof` is the registry-sealed caller proof; it is the only caller
/// evidence the relay accepts and its `Debug` is redacted. Unknown fields
/// refuse.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRequest {
    /// Sealed single-use caller proof.
    pub proof: SealedProof,
    /// One of [`TOOLS`].
    pub tool: String,
    /// The tool's closed argument object.
    pub arguments: Value,
}

/// One relay answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RelayResponse {
    /// The tool succeeded with this structured value.
    Ok {
        /// Tool result.
        value: Value,
    },
    /// A refusal or an uncertain outcome, classified by `class`.
    /// Pre-effect validation/authorization and unavailable-connection refusals
    /// publish nothing. `custody_unknown` and `relay_outcome_unknown` may follow
    /// publication: reconcile or repeat the same `request_id`, never invent a
    /// new identity for that message. Detail discloses no token or proof.
    Error {
        /// Machine-readable class (see [`RootRelay::handle`]).
        class: String,
        /// Safe human-readable detail (never a token or proof).
        detail: String,
    },
}

impl RelayResponse {
    /// Builds an error response.
    pub fn error(class: impl Into<String>, detail: impl Into<String>) -> Self {
        RelayResponse::Error {
            class: class.into(),
            detail: detail.into(),
        }
    }
}

/// `bridge_me` arguments: none.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeArgs {}

/// `bridge_send` arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendArgs {
    /// Caller-chosen stable request id (idempotency key).
    request_id: String,
    /// Canonical address string or legacy structured recipient.
    #[serde(alias = "address")]
    recipient: RecipientArg,
    /// Allowlisted kind; defaults to the root message kind.
    #[serde(default = "default_kind")]
    kind: String,
    /// Requested delivery mode; defaults to visible native message delivery.
    #[serde(default = "default_mode")]
    mode: String,
    /// Plain-text body (`message` is the concise public spelling).
    #[serde(alias = "message")]
    body: String,
    /// Optional absolute expiry (Unix epoch ms); must be in the future.
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

/// A validated target address, accepting the concise native address or the
/// original closed structured form. Neither variant identifies the sender.
#[derive(Deserialize)]
#[serde(untagged)]
enum RecipientArg {
    /// Canonical `host/harness/store/session` address; parsed at admission.
    Canonical(String),
    /// Backward-compatible explicit components, still closed to extra fields.
    Structured(StructuredRecipientArg),
}

/// Default root event kind when a concise send omits it.
fn default_kind() -> String {
    "bridge.message".to_string()
}

/// Default mode for visible application messages rather than quiet context injection.
fn default_mode() -> String {
    "message".to_string()
}

/// Original structured recipient argument (closed).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredRecipientArg {
    /// Host id.
    host_id: String,
    /// Harness wire name.
    harness: String,
    /// Native store namespace.
    native_store_namespace: String,
    /// Native session id.
    native_session_id: String,
}

/// `bridge_status` arguments.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    /// The request id given to `bridge_send`.
    request_id: String,
}

/// The relay's request handler: attestation, policy and core client.
///
/// Thread-safe: one core connection is shared under a mutex and
/// re-established after a transport failure.
pub struct RootRelay {
    /// Core service socket.
    core_socket: PathBuf,
    /// Root policy.
    config: RootConfig,
    /// The relay's core publisher grant token (never logged).
    token: String,
    /// Caller attestation provider (production: the adapter registry).
    attestor: Box<dyn CallerAttestor>,
    /// Lazily connected core client.
    client: Mutex<Option<BridgeClient>>,
}

impl std::fmt::Debug for RootRelay {
    /// Prints the socket only; never the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootRelay")
            .field("core_socket", &self.core_socket)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RootRelay {
    /// Builds a relay for `config` (validated by
    /// [`crate::config::InterfacesConfig::validate`]) over the core socket,
    /// with the publisher `token` and the caller `attestor`.
    pub fn new(
        core_socket: PathBuf,
        config: RootConfig,
        token: String,
        attestor: Box<dyn CallerAttestor>,
    ) -> Self {
        RootRelay {
            core_socket,
            config,
            token,
            attestor,
            client: Mutex::new(None),
        }
    }

    /// Handles one request at `now_ms`.
    ///
    /// Refusal classes: `caller_unattested`, `caller_missing`,
    /// `caller_duplicate`, `caller_stale`, `caller_conflicting`,
    /// `caller_not_evidence`, `caller_unavailable` (attestation);
    /// `forbidden` (not a root acting as itself, unconfigured caller,
    /// recipient/mode/kind outside the allowlist); `unknown_tool`;
    /// `invalid` (closed-schema or field rules); `oversize`; `expired`;
    /// `core_unavailable` (no connection: nothing was sent); `custody_unknown`
    /// (the core may have accepted: repeat the same `request_id`); and the
    /// core's own classes (`conflict`, `capacity`, `unsupported`, …).
    pub fn handle(&self, mut request: RelayRequest, now_ms: u64) -> RelayResponse {
        let compatibility_id = format!(
            "call-{:x}",
            Sha256::digest(request.proof.as_str().as_bytes())
        );
        let caller = match self
            .attestor
            .attest(&PresentedMeta::sealed(request.proof), now_ms)
        {
            Ok(caller) => caller,
            Err(error) => return caller_refusal(&error),
        };
        if !caller.relayed() {
            return RelayResponse::error(
                "caller_not_evidence",
                "the caller was not obtained by redeeming a sealed proof",
            );
        }
        if caller.role() != ActorRole::Root || !caller.may_act_as_address() {
            return RelayResponse::error(
                "forbidden",
                "only a root actor acting as its own session may use the root surface",
            );
        }
        let Some(policy) = self.policy_for(caller.address()) else {
            return RelayResponse::error("forbidden", "caller is not a configured root");
        };
        // Older live frontends do not normalize an omitted request id. The
        // proof was redeemed above, so this fallback is an authenticated,
        // one-call identity; it is never a claimed caller or a retry instruction.
        if request.tool == "bridge_send"
            && request.arguments.is_object()
            && request.arguments.get("request_id").is_none()
        {
            request.arguments["request_id"] = Value::String(compatibility_id);
        }
        let outcome = match request.tool.as_str() {
            "bridge_me" => parse::<MeArgs>(request.arguments).map(|_| self.me(&caller, policy)),
            "bridge_send" => parse::<SendArgs>(request.arguments)
                .and_then(|args| self.send(&caller, policy, args, now_ms)),
            "bridge_status" => {
                parse::<StatusArgs>(request.arguments).and_then(|args| self.status(&caller, &args))
            }
            _ => Err(RelayResponse::error("unknown_tool", "no such root tool")),
        };
        outcome.unwrap_or_else(|refusal| refusal)
    }

    /// The most specific configured scope for `address`: an exact-session
    /// entry before a whole-store entry.
    fn policy_for(&self, address: &NativeAddress) -> Option<&CallerPolicy> {
        let mut matching = self
            .config
            .callers
            .iter()
            .filter(|policy| policy.matches(address));
        let first = matching.next()?;
        Some(
            std::iter::once(first)
                .chain(matching)
                .find(|policy| policy.native_session_id.is_some())
                .unwrap_or(first),
        )
    }

    /// `bridge_me`: the attested caller and its permitted capabilities.
    fn me(&self, caller: &VerifiedCaller, policy: &CallerPolicy) -> RelayResponse {
        RelayResponse::Ok {
            value: json!({
                "caller": caller_view(caller),
                "permitted": {
                    "recipients": policy.canonical_recipients().unwrap_or_default(),
                    "modes": policy.modes,
                    "kinds": policy.kinds,
                    "policy": "keep_all",
                    "max_body_bytes": self.config.max_body_bytes,
                },
            }),
        }
    }

    /// Validates and publishes one exact-grant keep_all event at Unix epoch
    /// milliseconds `now_ms`, for the already verified root `caller` and its
    /// configured `policy`. Consumes the closed arguments; returns custody
    /// identity or the explicit validation/core/uncertainty refusal.
    /// New expired events refuse; an expired identity already in custody is
    /// submitted to the core's immutable-hash replay check, returning the
    /// original receipt or a conflict. No retry extends the original expiry.
    fn send(
        &self,
        caller: &VerifiedCaller,
        policy: &CallerPolicy,
        args: SendArgs,
        now_ms: u64,
    ) -> Result<RelayResponse, RelayResponse> {
        check_request_id(&args.request_id)?;
        let recipient = match args.recipient {
            RecipientArg::Canonical(address) => NativeAddress::parse(&address).map_err(invalid)?,
            RecipientArg::Structured(args) => NativeAddress::new(
                args.host_id,
                Harness::parse(&args.harness).map_err(invalid)?,
                args.native_store_namespace,
                args.native_session_id,
            )
            .map_err(invalid)?,
        };
        if !policy
            .canonical_recipients()
            .unwrap_or_default()
            .iter()
            .any(|entry| entry == "*" || entry == &recipient.to_canonical_string())
        {
            return Err(RelayResponse::error(
                "forbidden",
                "recipient is not in this caller's exact allowlist",
            ));
        }
        let mode = Mode::parse(&args.mode).map_err(invalid)?;
        if !policy.modes.contains(&args.mode) {
            return Err(RelayResponse::error("forbidden", "mode is not allowed"));
        }
        if !policy.kinds.contains(&args.kind) {
            return Err(RelayResponse::error("forbidden", "kind is not allowed"));
        }
        if args.body.len() > self.config.max_body_bytes {
            return Err(RelayResponse::error(
                "oversize",
                format!(
                    "body is {} bytes; the limit is {} bytes (nothing was truncated or sent)",
                    args.body.len(),
                    self.config.max_body_bytes
                ),
            ));
        }
        let mut request = PublishRequest::new(
            event_id(caller, &args.request_id)?,
            recipient,
            Kind::new(args.kind).map_err(invalid)?,
            mode,
            Policy::KeepAll,
            Payload::new(args.body).map_err(invalid)?,
        )
        .with_metadata("request_id", args.request_id.clone())
        .with_metadata("sender_harness", caller.address().harness.as_str())
        .with_metadata("sender_session", caller.address().native_session_id.clone());
        if let Some(expires) = args.expires_at_ms {
            request =
                request.with_expires_at(ExpiresAt::from_unix_millis(expires).map_err(invalid)?);
        }
        let body = request.into_body().map_err(invalid)?;
        let receipt = self.with_client(|client, token| {
            if args.expires_at_ms.is_some_and(|expires| expires <= now_ms)
                && client.status(token, &body.event_id)?.0.is_none()
            {
                return Err(ProtocolError {
                    class: "expired".into(),
                    detail: "expires_at_ms is not in the future; nothing was sent".into(),
                });
            }
            client.publish(token, &body)
        })?;
        Ok(RelayResponse::Ok {
            value: json!({
                "request_id": args.request_id,
                "custody": custody_view(&receipt),
            }),
        })
    }

    /// `bridge_status`: this caller's own event, tiers kept distinct.
    fn status(
        &self,
        caller: &VerifiedCaller,
        args: &StatusArgs,
    ) -> Result<RelayResponse, RelayResponse> {
        check_request_id(&args.request_id)?;
        let event = event_id(caller, &args.request_id)?;
        let (receipt, delivery) =
            self.with_client(|client, token| client.status(token, event.as_str()))?;
        let value = match receipt {
            None => json!({
                "request_id": args.request_id,
                "custody": {"state": "not_found"},
            }),
            Some(receipt) => {
                let mut value = status_view(delivery.as_ref());
                value["request_id"] = json!(args.request_id);
                value["custody"] = custody_view(&receipt);
                value
            }
        };
        Ok(RelayResponse::Ok { value })
    }

    /// Runs one core request on the shared connection.
    ///
    /// Connection failure before any request maps to `core_unavailable`;
    /// a transport failure after the request may have been written maps to
    /// `custody_unknown` (repeat the same `request_id`) and drops the
    /// connection; other core refusals keep their class.
    fn with_client<T>(
        &self,
        action: impl FnOnce(&mut BridgeClient, &str) -> Result<T, ProtocolError>,
    ) -> Result<T, RelayResponse> {
        let mut slot = self
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_none() {
            *slot = Some(BridgeClient::connect(&self.core_socket).map_err(|_| {
                RelayResponse::error(
                    "core_unavailable",
                    "the core service is not reachable; nothing was sent",
                )
            })?);
        }
        let client = slot.as_mut().expect("connected above");
        match action(client, &self.token) {
            Ok(value) => Ok(value),
            Err(error) if error.class == "transport" => {
                *slot = None;
                Err(RelayResponse::error(
                    "custody_unknown",
                    "the core did not answer; repeat the same request_id (idempotent)",
                ))
            }
            Err(error) => Err(RelayResponse::error(error.class, error.detail)),
        }
    }
}

/// Maps an attestation refusal to its `caller_*` class.
fn caller_refusal(error: &CorrelationError) -> RelayResponse {
    let class = error.class();
    let class = if class.starts_with("caller_") {
        class.to_string()
    } else {
        format!("caller_{class}")
    };
    RelayResponse::error(class, error.detail())
}

/// Parses a closed argument object.
fn parse<T: for<'de> Deserialize<'de>>(arguments: Value) -> Result<T, RelayResponse> {
    serde_json::from_value(arguments)
        .map_err(|error| RelayResponse::error("invalid", format!("arguments: {error}")))
}

/// Maps a core validation error to `invalid`.
fn invalid(error: bridge_client::CoreError) -> RelayResponse {
    RelayResponse::error("invalid", error.to_string())
}

/// Checks a `request_id`: 1–128 bytes of `[A-Za-z0-9._:-]`.
fn check_request_id(request_id: &str) -> Result<(), RelayResponse> {
    let valid = !request_id.is_empty()
        && request_id.len() <= MAX_REQUEST_ID_BYTES
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(RelayResponse::error(
            "invalid",
            "request_id must be 1-128 characters of A-Z a-z 0-9 . _ : -",
        ))
    }
}

/// Derives the core event id of `request_id` for this caller.
///
/// `root-` plus the first 40 hex digits of SHA-256 over the caller's
/// canonical address, its native actor id and the request id (each
/// newline-terminated). Stable across endpoint epochs, so a retry after a
/// reconnect replays rather than conflicts; distinct per caller, so two
/// callers never share an event.
pub fn event_id(caller: &VerifiedCaller, request_id: &str) -> Result<EventId, RelayResponse> {
    let mut hasher = Sha256::new();
    for part in [
        caller.address().to_canonical_string().as_str(),
        caller.native_id(),
        request_id,
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    EventId::new(format!("{EVENT_PREFIX}{}", &digest[..40])).map_err(invalid)
}

/// Structured view of a verified caller (no proof, no evidence internals).
fn caller_view(caller: &VerifiedCaller) -> Value {
    let address = caller.address();
    json!({
        "address": {
            "host_id": address.host_id,
            "harness": address.harness.as_str(),
            "native_store_namespace": address.native_store_namespace,
            "native_session_id": address.native_session_id,
        },
        "canonical": address.to_canonical_string(),
        "role": "root",
        "native_id": caller.native_id(),
        "endpoint_epoch": caller.epoch(),
        "observed_at_ms": caller.observed_at_ms(),
        "channel": serde_json::to_value(caller.channel()).unwrap_or(Value::Null),
        "evidence": "registry-attested caller redeemed from a sealed single-use proof",
    })
}

/// Custody part of a status or send answer.
fn custody_view(receipt: &bridge_client::CustodyReceipt) -> Value {
    json!({
        "state": "accepted",
        "disposition": serde_json::to_value(receipt.state).unwrap_or(Value::Null),
        "envelope_hash": receipt.envelope_hash.as_str(),
        "accepted_at_ms": receipt.accepted_at_ms,
        "replayed": receipt.replayed,
    })
}

/// Whether `tiers` holds `tier`.
fn has_tier(delivery: &DeliveryEvidence, tier: EvidenceTier) -> bool {
    delivery.tiers.iter().any(|entry| entry.tier == tier)
}

/// Evidence rows the core returns per event (the newest ones); a full list
/// may have dropped older rows, so it cannot prove an absence.
const TIER_WINDOW: usize = 64;

/// Sentence appended to an open incident's reason when an earlier hand-off is
/// still unresolved behind it, so the incident cannot mask it.
const EARLIER_HAND_OFF: &str =
    "An earlier attempt may also have reached the recipient and its outcome was never established.";

/// What the surviving evidence says about an earlier hand-off that is not
/// positively ruled out, as the `native` name; `None` when every visible
/// attempt is proven unsent (or nothing was ever recorded) and the record is
/// complete.
///
/// The newest evidence tier alone proves nothing: each attempt is judged by
/// its own last tier, and one that is not known-unsent or refused (an
/// unknown, held, written or positive tier) keeps the possible effect alive
/// even if a later attempt was known-unsent. The record is not trusted as
/// complete when the evidence window is full, when the newest attempt repeats
/// a possible hand-off by manual decision (`duplicate_risk`, which also
/// covers evidence rows older than the window and an attempt counter the
/// retry reset), when the newest attempt itself may have handed off, or when
/// the counter shows attempts but no attempt is visible.
fn unresolved_hand_off(delivery: &DeliveryEvidence) -> Option<&'static str> {
    let mut last = std::collections::BTreeMap::new();
    for entry in &delivery.tiers {
        last.insert(entry.attempt_seq, entry.tier);
    }
    let open: Vec<EvidenceTier> = last
        .into_values()
        .filter(|tier| !matches!(tier, EvidenceTier::KnownUnsent | EvidenceTier::Refused))
        .collect();
    if open.contains(&EvidenceTier::WrittenNoReceipt) {
        return Some("written_no_receipt");
    }
    if open.contains(&EvidenceTier::NativeHeld) {
        return Some("native_held");
    }
    let incomplete = delivery.tiers.len() >= TIER_WINDOW
        || delivery
            .attempt
            .as_ref()
            .map_or(delivery.attempts_made > 0, |attempt| {
                attempt.duplicate_risk || attempt.state.possibly_handed_off()
            });
    (!open.is_empty() || incomplete).then_some("unknown")
}

/// `native` of an event closed by an audited disposition, from the evidence
/// that outlives it.
///
/// A disposition decides what happens next; it proves neither delivery nor
/// non-delivery. An unresolved earlier hand-off ([`unresolved_hand_off`])
/// is kept. Without one, `not_handed` or `refused` is claimed only when the
/// record holds positive no-effect evidence (an attempt or a tier); a
/// disposed event with no record at all is `unknown`, because the core does
/// not expose closed incidents and a legacy possible hand-off without any
/// attempt looks the same after its disposition.
fn disposed_native(delivery: &DeliveryEvidence) -> &'static str {
    if let Some(unresolved) = unresolved_hand_off(delivery) {
        return unresolved;
    }
    match delivery.tiers.last().map(|entry| entry.tier) {
        Some(EvidenceTier::Refused) => "refused",
        Some(_) => "not_handed",
        None if delivery.attempt.is_some() => "not_handed",
        None => "unknown",
    }
}

/// Delivery part of a status answer for an event in custody, with the
/// evidence tiers kept apart.
///
/// `delivery` is the core's evidence; `None` is the core's answer for an
/// accepted event that was never handed to any path and has no attempt,
/// hold, incident or evidence, reported as `unhanded` / `not_handed`.
/// `native` summarizes the handoff tier from the delivery state, except that
/// an unhanded or reserved event is `not_handed`, and a refused one `refused`,
/// only when the surviving evidence leaves no earlier hand-off unresolved (an
/// audited duplicate-risk retry followed by exhausted retries or a permanent
/// refusal, for example, keeps the earlier attempt's possible effect, and an
/// open incident's reason then also states it), and a
/// disposition (`delivery.state` = `disposed`)
/// never claims non-delivery: `native` keeps what the surviving evidence
/// shows, a later known-unsent attempt never erases an earlier unresolved
/// one, and a disposed event with no record at all is `unknown`. Whenever the
/// hand-off stays open after a retry or disposition `uncertainty` is set
/// (`disposed: true` after a disposition; no manual resolution left to do)
/// while the earlier outcome remains unknown. `context` and `processed` are
/// `observed` only when that exact tier was recorded; `uncertainty` is set
/// for a possible handoff with an unknown result or any open incident
/// (manual resolution, never an automatic resend). Tier details are
/// withheld; names and times only.
pub fn status_view(delivery: Option<&DeliveryEvidence>) -> Value {
    let Some(delivery) = delivery else {
        return json!({
            "delivery": {"state": "unhanded"},
            "native": "not_handed",
            "context": "not_available",
            "processed": "not_available",
            "uncertainty": Value::Null,
        });
    };
    let native = match delivery.delivery {
        DeliveryState::Unhanded | DeliveryState::Reserved => {
            unresolved_hand_off(delivery).unwrap_or("not_handed")
        }
        DeliveryState::Invoking => "in_flight",
        DeliveryState::Held if has_tier(delivery, EvidenceTier::WrittenNoReceipt) => {
            "written_no_receipt"
        }
        DeliveryState::Held => "native_held",
        DeliveryState::Review => "unknown",
        DeliveryState::Accepted => "native_accepted",
        DeliveryState::HookSubmitted => "hook_emitted",
        DeliveryState::Refused => unresolved_hand_off(delivery).unwrap_or("refused"),
        DeliveryState::Disposed => disposed_native(delivery),
    };
    let observed = |tier| {
        if has_tier(delivery, tier) {
            "observed"
        } else {
            "not_available"
        }
    };
    let earlier = EARLIER_HAND_OFF;
    let uncertainty = if delivery.delivery == DeliveryState::Review || delivery.incident.is_some() {
        // An open incident (for example retries exhausted or a permanent refusal
        // after a duplicate-risk retry) must not hide an earlier unresolved
        // hand-off: its reason then also states it.
        let masked =
            delivery.delivery != DeliveryState::Review && unresolved_hand_off(delivery).is_some();
        json!({
            "incident_kind": delivery.incident.as_ref().map(|incident| incident.kind.clone()),
            "reason": delivery.incident.as_ref().map(|incident| {
                if masked {
                    format!("{} {earlier}", incident.reason)
                } else {
                    incident.reason.clone()
                }
            }),
            "manual_resolution_required": true,
            "automatic_resend": false,
        })
    } else if matches!(
        delivery.delivery,
        DeliveryState::Unhanded
            | DeliveryState::Reserved
            | DeliveryState::Refused
            | DeliveryState::Disposed
    ) && !matches!(native, "not_handed" | "refused")
    {
        let disposed = delivery.delivery == DeliveryState::Disposed;
        let reason = if delivery.delivery == DeliveryState::Refused {
            "the event was refused, but an earlier attempt may have reached the recipient and its outcome was never established"
        } else if !disposed {
            "an earlier attempt may have reached the recipient and its outcome was never established; a manually authorized duplicate-risk retry may follow"
        } else if unresolved_hand_off(delivery).is_some() {
            "closed by an operator disposition; whether an earlier hand-off reached the recipient was never established"
        } else {
            "closed by an operator disposition; no hand-off is recorded, but the core does not retain whether an older possible hand-off was closed by it"
        };
        json!({
            "incident_kind": Value::Null,
            "reason": reason,
            "manual_resolution_required": false,
            "automatic_resend": false,
            "disposed": disposed,
        })
    } else {
        Value::Null
    };
    json!({
        "delivery": {
            "state": serde_json::to_value(delivery.delivery).unwrap_or(Value::Null),
            "effective_mode": delivery.effective_mode,
            "attempts_made": delivery.attempts_made,
            "hold_reason": delivery.hold_reason,
            "blocked_by": delivery.blocked_by,
        },
        "native": native,
        "context": observed(EvidenceTier::ContextObserved),
        "processed": observed(EvidenceTier::ApplicationProcessed),
        "uncertainty": uncertainty,
        "tiers": delivery.tiers.iter().map(|entry| json!({
            "tier": entry.tier.as_str(),
            "attempt": entry.attempt_seq,
            "at_ms": entry.at_ms,
        })).collect::<Vec<_>>(),
    })
}

/// A running relay socket server.
pub struct RelayServer {
    /// Socket path.
    socket: PathBuf,
    /// Inode identity of the bound socket.
    identity: (u64, u64),
    /// Stop flag.
    running: Arc<AtomicBool>,
    /// Accept loop.
    accept: Option<JoinHandle<()>>,
}

impl RelayServer {
    /// Binds the relay socket and serves `relay` until stopped.
    ///
    /// The socket's directory must be private
    /// ([`bridge_adapters::server::private_directory`]); the socket is
    /// `0600`. A stale socket (connection positively refused) is replaced;
    /// a live endpoint or any non-socket path is refused untouched. Each
    /// connection carries one request: the peer must run as this user; the
    /// line is bounded before allocation; the answer is one line.
    pub fn start(socket: &Path, relay: Arc<RootRelay>) -> std::io::Result<RelayServer> {
        let directory = socket
            .parent()
            .ok_or_else(|| std::io::Error::other("relay socket has no directory"))?;
        let owner = bridge_adapters::server::private_directory(directory)?;
        claim_stale(socket)?;
        let listener = UnixListener::bind(socket)?;
        let metadata = std::fs::symlink_metadata(socket)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let accept = std::thread::Builder::new()
            .name("bridge-root-relay".into())
            .spawn(move || accept_loop(&listener, &relay, &flag, owner))?;
        Ok(RelayServer {
            socket: socket.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
            running,
            accept: Some(accept),
        })
    }

    /// Stops accepting, waits for the accept loop and removes the socket
    /// only if it is still this server's inode.
    pub fn stop(mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if std::fs::symlink_metadata(&self.socket)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
        {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

/// Removes a stale socket at `path`: only a socket whose connection is
/// positively refused. Anything else present is refused untouched.
fn claim_stale(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    if !crate::config::is_socket(path) {
        return Err(std::io::Error::other(
            "relay socket path exists and is not a socket",
        ));
    }
    match UnixStream::connect(path) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
        }
        Ok(_) => Err(std::io::Error::other(
            "a live relay already serves this socket",
        )),
        Err(error) => Err(error),
    }
}

/// Accept loop: polls the non-blocking listener while running and serves
/// each connection on its own thread up to [`MAX_CONNECTIONS`].
fn accept_loop(listener: &UnixListener, relay: &Arc<RootRelay>, running: &AtomicBool, owner: u32) {
    let active = Arc::new(AtomicUsize::new(0));
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let relay = Arc::clone(relay);
                let slot = Arc::clone(&active);
                let spawned = std::thread::Builder::new()
                    .name("bridge-root-request".into())
                    .spawn(move || {
                        serve(stream, &relay, owner);
                        slot.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Serves one connection: peer check, one bounded request, one answer.
fn serve(stream: UnixStream, relay: &RootRelay, owner: u32) {
    let answer = match bridge_adapters::os::peer_identity(&stream) {
        Ok(peer) if peer.uid == owner => read_request(&stream).map_or_else(
            |refusal| refusal,
            |request| relay.handle(request, bridge_core::service::current_unix_millis()),
        ),
        _ => RelayResponse::error("forbidden", "relay peer runs as another user"),
    };
    let Ok(mut line) = serde_json::to_vec(&answer) else {
        return;
    };
    if line.len() > MAX_RELAY_RESPONSE_BYTES {
        line = serde_json::to_vec(&RelayResponse::error("internal", "answer too large"))
            .unwrap_or_default();
    }
    if let Ok(mut writer) = stream.try_clone() {
        let _ = write_line(&mut writer, &line, IO_TIMEOUT);
    }
}

/// Reads and parses one bounded request line.
fn read_request(stream: &UnixStream) -> Result<RelayRequest, RelayResponse> {
    let reader = stream
        .try_clone()
        .map_err(|_| RelayResponse::error("internal", "connection unusable"))?;
    let mut reader = BufReader::new(reader);
    let line = read_bounded_line(&mut reader, MAX_RELAY_REQUEST_BYTES, IO_TIMEOUT, IO_TIMEOUT)
        .map_err(|error| RelayResponse::error("invalid", format!("request line: {error}")))?
        .ok_or_else(|| RelayResponse::error("invalid", "empty request"))?;
    serde_json::from_str(&line).map_err(|error| RelayResponse::error("invalid", error.to_string()))
}

/// Sends one request to a relay and reads its answer (the frontend side).
///
/// The relay directory must be private to this user and the listening
/// peer must run as this user. The answer is awaited for the finite
/// [`RELAY_ANSWER_TIMEOUT`] (the relay's expected budget plus a margin); the
/// relay may still publish after the frontend gave up. Failures are
/// split by whether the request line may have reached the relay:
/// `relay_unavailable` before the write began (nothing was sent; re-running
/// the tool seals a fresh proof), `relay_outcome_unknown` once it began (the
/// request may have been redeemed and published; the caller repeats the same
/// `request_id` or asks `bridge_status`, never a new id).
pub fn call_relay(socket: &Path, request: &RelayRequest) -> RelayResponse {
    let mut write_began = false;
    let result = (|| -> std::io::Result<RelayResponse> {
        let own = crate::config::own_uid().map_err(std::io::Error::other)?;
        let directory = socket
            .parent()
            .ok_or_else(|| std::io::Error::other("relay socket has no directory"))?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != own || metadata.mode() & 0o077 != 0 {
            return Err(std::io::Error::other("relay directory is not private"));
        }
        let mut stream = UnixStream::connect(socket)?;
        if bridge_adapters::os::peer_identity(&stream)?.uid != own {
            return Err(std::io::Error::other("relay runs as another user"));
        }
        let line = serde_json::to_vec(request).map_err(std::io::Error::other)?;
        write_began = true;
        write_line(&mut stream, &line, IO_TIMEOUT)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let answer = read_bounded_line(
            &mut reader,
            MAX_RELAY_RESPONSE_BYTES,
            RELAY_ANSWER_TIMEOUT,
            RELAY_ANSWER_TIMEOUT,
        )?
        .ok_or_else(|| std::io::Error::other("relay closed without an answer"))?;
        serde_json::from_str(&answer).map_err(std::io::Error::other)
    })();
    result.unwrap_or_else(|error| {
        if write_began {
            RelayResponse::error(
                "relay_outcome_unknown",
                format!(
                    "root relay did not answer ({error}); outcome unknown: a bridge_send may have been published. Repeat the same request_id (idempotent) or ask bridge_status with it; never use a new request_id for the same message"
                ),
            )
        } else {
            RelayResponse::error(
                "relay_unavailable",
                format!("root relay unreachable ({error}); nothing was sent"),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    //! Pure policy helpers; the composed relay is exercised by
    //! `tests/root_composition.rs` over real processes.

    use super::*;

    /// Request ids must be non-empty, plain and at most 128 bytes.
    #[test]
    fn request_ids_are_bounded_and_plain() {
        assert!(check_request_id("req-1.a:b_c").is_ok());
        assert!(check_request_id("").is_err());
        assert!(check_request_id("has space").is_err());
        assert!(check_request_id(&"x".repeat(129)).is_err());
    }

    /// An event never handed to a native carrier reports `not_handed` and
    /// `not_available` with no uncertainty.
    #[test]
    fn unhanded_events_report_no_native_or_context_tier() {
        let view = status_view(None);
        assert_eq!(view["native"], "not_handed");
        assert_eq!(view["context"], "not_available");
        assert!(view["uncertainty"].is_null());
    }

    /// Caller attestation failures map to a single `caller_` class carrying the
    /// detail.
    #[test]
    fn refusal_classes_are_prefixed_once() {
        assert_eq!(
            caller_refusal(&CorrelationError::Unattested),
            RelayResponse::error("caller_unattested", "")
        );
        assert_eq!(
            caller_refusal(&CorrelationError::Duplicate("x".into())),
            RelayResponse::error("caller_duplicate", "x")
        );
    }

    /// Evidence of an event in `state` with the `attempts_made` counter, an
    /// optional newest attempt (`(attempt state, duplicate_risk)`) and
    /// evidence rows `(attempt_seq, tier)`.
    fn evidence(
        state: &str,
        attempts_made: u32,
        attempt: Option<(&str, bool)>,
        tiers: &[(u64, &str)],
    ) -> DeliveryEvidence {
        let attempt = attempt.map(|(attempt_state, duplicate_risk)| {
            json!({"attempt_seq": 2, "state": attempt_state, "requested_mode": "Message",
                   "effective_mode": "message", "actor": "a", "endpoint_epoch": 1,
                   "manifest_hash": "00", "deadline_ms": 9, "duplicate_risk": duplicate_risk})
        });
        let tiers: Vec<Value> = tiers
            .iter()
            .map(|(seq, tier)| json!({"attempt_seq": seq, "tier": tier, "detail": "d", "at_ms": 5}))
            .collect();
        serde_json::from_value(json!({
            "attempt_state": "none", "effective_mode": "none", "note": null,
            "delivery": state, "attempts_made": attempts_made, "attempt": attempt,
            "tiers": tiers, "incident": null, "hold_reason": null, "blocked_by": null
        }))
        .unwrap()
    }

    /// `evidence` with an open incident of `kind` and `reason`.
    fn with_incident(mut evidence: DeliveryEvidence, kind: &str, reason: &str) -> DeliveryEvidence {
        evidence.incident = Some(
            serde_json::from_value(json!({
                "incident_seq": 3, "kind": kind, "reason": reason, "review_deadline_ms": null
            }))
            .unwrap(),
        );
        evidence
    }

    /// A refused event never proves an earlier attempt unsent: after an unknown
    /// attempt A and a duplicate-risk retry whose attempt B ended known-unsent
    /// (retries exhausted) or permanently refused, `native` stays `unknown`
    /// and the open incident's reason also states the earlier hand-off; a
    /// plain refusal keeps `refused` and its own reason.
    #[test]
    fn a_refusal_after_a_duplicate_risk_retry_keeps_the_earlier_unknown() {
        let exhausted = with_incident(
            evidence(
                "refused",
                5,
                Some(("known_unsent", true)),
                &[(1, "unknown"), (2, "known_unsent")],
            ),
            "retries_exhausted",
            "5 automatic attempts ended known-unsent",
        );
        let refused = with_incident(
            evidence(
                "refused",
                0,
                Some(("permanent_refusal", true)),
                &[(1, "unknown"), (2, "refused")],
            ),
            "permanent_refusal",
            "carrier refused",
        );
        for case in [exhausted, refused] {
            let (native, uncertain, view) = judged(case);
            assert_eq!(view["delivery"]["state"], "refused");
            assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
            let reason = view["uncertainty"]["reason"].as_str().unwrap();
            assert!(reason.contains("earlier attempt may also"), "{view}");
            assert_eq!(view["uncertainty"]["manual_resolution_required"], true);
            assert_eq!(view["uncertainty"]["automatic_resend"], false);
        }
        // The same chain with the incident already gone is still not `refused`.
        let (native, uncertain, view) = judged(evidence(
            "refused",
            0,
            Some(("permanent_refusal", true)),
            &[(1, "unknown"), (2, "refused")],
        ));
        assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        assert!(
            view["uncertainty"]["reason"]
                .as_str()
                .unwrap()
                .contains("was refused")
        );
        // A plain refusal and exhausted automatic known-unsent attempts only.
        for plain in [
            evidence(
                "refused",
                0,
                Some(("permanent_refusal", false)),
                &[(1, "refused")],
            ),
            evidence(
                "refused",
                5,
                Some(("known_unsent", false)),
                &[(1, "known_unsent"), (2, "known_unsent")],
            ),
        ] {
            let (native, uncertain, view) = judged(with_incident(
                plain,
                "retries_exhausted",
                "5 automatic attempts ended known-unsent",
            ));
            assert_eq!(native, "refused", "{view}");
            assert!(
                uncertain,
                "the incident itself is still uncertainty: {view}"
            );
            assert!(
                !view["uncertainty"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("earlier attempt may also")
            );
        }
    }

    /// The `native` name and whether `uncertainty` is set for `evidence`.
    fn judged(evidence: DeliveryEvidence) -> (String, bool, Value) {
        let view = status_view(Some(&evidence));
        (
            view["native"].as_str().unwrap().to_string(),
            !view["uncertainty"].is_null(),
            view,
        )
    }

    /// A disposition never claims non-delivery: an earlier possible hand-off
    /// stays unknown with its uncertainty.
    #[test]
    fn a_disposition_keeps_the_native_uncertainty_and_never_claims_non_delivery() {
        let (native, uncertain, view) = judged(evidence("disposed", 1, None, &[(1, "unknown")]));
        assert_eq!(view["delivery"]["state"], "disposed");
        assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        assert_eq!(view["uncertainty"]["automatic_resend"], false);
        assert_eq!(view["uncertainty"]["disposed"], true);
        assert!(
            view["uncertainty"]["reason"]
                .as_str()
                .unwrap()
                .contains("never established")
        );
        assert!(!view.to_string().contains("not_delivered"));
    }

    /// An unknown first attempt, an audited duplicate-risk retry and a
    /// known-unsent second attempt: the later no-effect never erases the
    /// earlier possible effect, before (unhanded) and after the disposition.
    #[test]
    fn a_later_known_unsent_attempt_never_erases_an_earlier_unknown() {
        let tiers = [(1, "unknown"), (2, "known_unsent")];
        for state in ["unhanded", "disposed"] {
            let (native, uncertain, view) =
                judged(evidence(state, 1, Some(("known_unsent", true)), &tiers));
            assert_eq!(
                (native.as_str(), uncertain),
                ("unknown", true),
                "{state}: {view}"
            );
        }
        // The retry just authorized: no second attempt yet.
        let (native, uncertain, view) = judged(evidence(
            "unhanded",
            0,
            Some(("outcome_unknown", false)),
            &[(1, "unknown")],
        ));
        assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        // Each attempt is judged by its own last tier, not only the newest
        // tier overall (no duplicate-risk mark here).
        let (native, uncertain, view) = judged(evidence(
            "disposed",
            1,
            Some(("known_unsent", false)),
            &tiers,
        ));
        assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        // Positive context evidence of the earlier attempt stays reported.
        let (_, _, view) = judged(evidence(
            "disposed",
            1,
            Some(("known_unsent", true)),
            &[(1, "unknown"), (1, "context_observed"), (2, "known_unsent")],
        ));
        assert_eq!(view["context"], "observed", "{view}");
    }

    /// Evidence rows older than the window, or an attempt counter the retry
    /// reset, are not proof of absence: the duplicate-risk mark on the newest
    /// attempt (or a full window) keeps the hand-off unknown; sparse legacy
    /// records are `unknown`, never a guessed non-delivery.
    #[test]
    fn missing_history_is_unknown_not_a_guess() {
        // Attempt A's rows fell out of the visible record; B carries the mark.
        let (native, uncertain, view) = judged(evidence(
            "disposed",
            1,
            Some(("known_unsent", true)),
            &[(2, "known_unsent")],
        ));
        assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        // A full evidence window may have dropped older rows.
        let full: Vec<(u64, &str)> = (0..TIER_WINDOW).map(|_| (2, "known_unsent")).collect();
        let (native, _, view) = judged(evidence(
            "disposed",
            1,
            Some(("known_unsent", false)),
            &full,
        ));
        assert_eq!(native, "unknown", "{view}");
        let (native, uncertain, view) = judged(evidence(
            "disposed",
            1,
            Some(("known_unsent", false)),
            &full[1..],
        ));
        assert_eq!(
            (native.as_str(), uncertain),
            ("not_handed", false),
            "{view}"
        );
        // A counter without a visible attempt, a newest attempt that may have
        // handed off, and a disposed event with no record at all (it may be a
        // closed legacy possible hand-off with no attempt).
        for sparse in [
            evidence("disposed", 2, None, &[]),
            evidence("unhanded", 2, None, &[]),
            evidence("disposed", 0, Some(("invoking", false)), &[]),
            evidence("disposed", 0, None, &[]),
        ] {
            let (native, uncertain, view) = judged(sparse);
            assert_eq!((native.as_str(), uncertain), ("unknown", true), "{view}");
        }
        let (_, _, view) = judged(evidence("disposed", 0, None, &[]));
        assert!(
            view["uncertainty"]["reason"]
                .as_str()
                .unwrap()
                .contains("does not retain")
        );
    }

    /// Provably unsent history is still reported truthfully: automatic
    /// known-unsent retries, a never-handed unhanded event and a disposition
    /// after only known-unsent attempts are `not_handed` without uncertainty.
    #[test]
    fn provably_unsent_history_stays_not_handed() {
        for (state, attempts, attempt, tiers) in [
            (
                "unhanded",
                1,
                Some(("known_unsent", false)),
                vec![(1, "known_unsent")],
            ),
            ("unhanded", 0, None, vec![]),
            (
                "reserved",
                1,
                Some(("reserved", false)),
                vec![(1, "known_unsent")],
            ),
            (
                "disposed",
                2,
                Some(("known_unsent", false)),
                vec![(1, "known_unsent"), (2, "known_unsent")],
            ),
            ("disposed", 0, Some(("closed", false)), vec![]),
        ] {
            let (native, uncertain, view) = judged(evidence(state, attempts, attempt, &tiers));
            assert_eq!(
                (native.as_str(), uncertain),
                ("not_handed", false),
                "{state}: {view}"
            );
        }
        let (native, uncertain, view) = judged(evidence(
            "disposed",
            1,
            Some(("permanent_refusal", false)),
            &[(1, "refused")],
        ));
        assert_eq!((native.as_str(), uncertain), ("refused", false), "{view}");
        // A held or written attempt keeps its own name.
        for (tier, name) in [
            ("written_no_receipt", "written_no_receipt"),
            ("native_held", "native_held"),
        ] {
            let (native, uncertain, view) = judged(evidence("disposed", 0, None, &[(1, tier)]));
            assert_eq!((native.as_str(), uncertain), (name, true), "{view}");
        }
    }

    /// A private scratch directory and a relay request with a placeholder proof.
    fn relay_fixture(tag: &str) -> (crate::testdir::TestDir, RelayRequest) {
        (
            crate::testdir::TestDir::new(tag),
            RelayRequest {
                proof: SealedProof::from_wire("00".repeat(32)),
                tool: "bridge_me".into(),
                arguments: json!({}),
            },
        )
    }

    /// Serves one connection of a stub relay: reads the request line, waits
    /// `delay`, then writes `answer` (nothing when `None`) and closes.
    fn stub_relay(socket: &Path, delay: Duration, answer: Option<RelayResponse>) -> JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            std::thread::sleep(delay);
            if let Some(answer) = answer {
                let mut stream = stream;
                let _ = write_line(
                    &mut stream,
                    &serde_json::to_vec(&answer).unwrap(),
                    IO_TIMEOUT,
                );
            }
        })
    }

    /// The frontend waits for the relay's expected budget (about 115 s), not the
    /// old 40 s: an answer after 41 s is still delivered.
    #[test]
    fn a_relay_answer_slower_than_forty_seconds_is_still_awaited() {
        let (dir, request) = relay_fixture("slow");
        let socket = dir.path().join("r.sock");
        let answer = RelayResponse::Ok {
            value: json!({"late": true}),
        };
        let stub = stub_relay(&socket, Duration::from_secs(41), Some(answer.clone()));
        assert_eq!(call_relay(&socket, &request), answer);
        stub.join().unwrap();
    }

    /// Failures before the request line is written say nothing was sent; a
    /// relay that took the request but never answered is an unknown outcome
    /// that tells the caller to reuse the same `request_id`.
    #[test]
    fn relay_failures_separate_nothing_sent_from_outcome_unknown() {
        let (dir, request) = relay_fixture("split");
        let missing = call_relay(&dir.path().join("absent.sock"), &request);
        let RelayResponse::Error { class, detail } = missing else {
            panic!("an absent relay cannot answer");
        };
        assert_eq!(class, "relay_unavailable");
        assert!(detail.contains("nothing was sent"), "{detail}");
        let socket = dir.path().join("r.sock");
        let stub = stub_relay(&socket, Duration::ZERO, None);
        let RelayResponse::Error { class, detail } = call_relay(&socket, &request) else {
            panic!("a closed relay cannot answer");
        };
        stub.join().unwrap();
        assert_eq!(class, "relay_outcome_unknown");
        assert!(detail.contains("outcome unknown"), "{detail}");
        assert!(detail.contains("same request_id"), "{detail}");
    }
}
