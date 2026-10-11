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
//! always publishes `keep_all` to an exact allowlisted recipient through the
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
    /// The tool refused; nothing was published or disclosed beyond the
    /// refusal itself.
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
    /// Exact structured recipient.
    recipient: RecipientArg,
    /// Allowlisted kind.
    kind: String,
    /// Requested delivery mode.
    mode: String,
    /// Plain-text body.
    body: String,
    /// Optional absolute expiry (Unix epoch ms); must be in the future.
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

/// Structured recipient argument (closed).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientArg {
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
    pub fn handle(&self, request: RelayRequest, now_ms: u64) -> RelayResponse {
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

    /// `bridge_send`: validates and publishes one keep_all event.
    fn send(
        &self,
        caller: &VerifiedCaller,
        policy: &CallerPolicy,
        args: SendArgs,
        now_ms: u64,
    ) -> Result<RelayResponse, RelayResponse> {
        check_request_id(&args.request_id)?;
        let harness = Harness::parse(&args.recipient.harness).map_err(invalid)?;
        let recipient = NativeAddress::new(
            args.recipient.host_id,
            harness,
            args.recipient.native_store_namespace,
            args.recipient.native_session_id,
        )
        .map_err(invalid)?;
        if !policy
            .canonical_recipients()
            .unwrap_or_default()
            .contains(&recipient.to_canonical_string())
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
            if expires <= now_ms {
                return Err(RelayResponse::error(
                    "expired",
                    "expires_at_ms is not in the future; nothing was sent",
                ));
            }
            request =
                request.with_expires_at(ExpiresAt::from_unix_millis(expires).map_err(invalid)?);
        }
        let body = request.into_body().map_err(invalid)?;
        let receipt = self.with_client(|client, token| client.publish(token, &body))?;
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

/// Delivery part of a status answer for an event in custody, with the
/// evidence tiers kept apart.
///
/// `delivery` is the core's evidence; `None` is the core's answer for an
/// accepted event that was never handed to any path and has no attempt,
/// hold, incident or evidence, reported as `unhanded` / `not_handed`.
/// `native` summarizes the handoff tier from the delivery state;
/// `context` and `processed` are `observed` only when that exact tier was
/// recorded; `uncertainty` is set for a possible handoff with an unknown
/// result or any open incident (manual resolution, never an automatic
/// resend). Tier details are withheld; names and times only.
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
        DeliveryState::Unhanded | DeliveryState::Reserved => "not_handed",
        DeliveryState::Invoking => "in_flight",
        DeliveryState::Held if has_tier(delivery, EvidenceTier::WrittenNoReceipt) => {
            "written_no_receipt"
        }
        DeliveryState::Held => "native_held",
        DeliveryState::Review => "unknown",
        DeliveryState::Accepted => "native_accepted",
        DeliveryState::HookSubmitted => "hook_emitted",
        DeliveryState::Refused => "refused",
        DeliveryState::Disposed => "disposed_not_delivered",
    };
    let observed = |tier| {
        if has_tier(delivery, tier) {
            "observed"
        } else {
            "not_available"
        }
    };
    let uncertainty = if delivery.delivery == DeliveryState::Review || delivery.incident.is_some() {
        json!({
            "incident_kind": delivery.incident.as_ref().map(|incident| incident.kind.clone()),
            "reason": delivery.incident.as_ref().map(|incident| incident.reason.clone()),
            "manual_resolution_required": true,
            "automatic_resend": false,
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
/// peer must run as this user; any failure is `relay_unavailable` (the
/// sealed proof was not redeemed, or its outcome is unknown — the caller
/// re-runs the tool, which seals a fresh proof).
pub fn call_relay(socket: &Path, request: &RelayRequest) -> RelayResponse {
    let exchange = || -> std::io::Result<RelayResponse> {
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
        write_line(&mut stream, &line, IO_TIMEOUT)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let answer = read_bounded_line(
            &mut reader,
            MAX_RELAY_RESPONSE_BYTES,
            Duration::from_secs(40),
            Duration::from_secs(40),
        )?
        .ok_or_else(|| std::io::Error::other("relay closed without an answer"))?;
        serde_json::from_str(&answer).map_err(std::io::Error::other)
    };
    exchange().unwrap_or_else(|error| {
        RelayResponse::error("relay_unavailable", format!("root relay: {error}"))
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
}
