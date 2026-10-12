//! Authenticated typed local service: publisher and operator surfaces.
//!
//! A local Unix-stream socket speaking one JSON object per line (ndjson).
//! Every ingress is authenticated by a grant token before anything else
//! happens. Two disjoint credential realms exist:
//!
//! - **publisher grants** bind one publisher identity and the recipients,
//!   kinds, modes and policies it may use; they can only `publish` and read
//!   the `status` of their own events. The restricted root orchestrator
//!   surface consumes this same protocol through its own backend grant whose
//!   policy forces `keep_all` and its configured exact or any-address scope;
//!   external root credentials are never core credentials.
//! - **operator grants** (`admin = true`) carry empty allowlists, can never
//!   publish or read publisher status, and alone can list incidents, record
//!   audited recovery decisions, pause recipients and stop the daemon.
//!
//! There is deliberately no generic RPC surface. Bridge stamps the publisher
//! identity from the authenticated grant — a request never asserts its own
//! publisher or operator identity.
//!
//! Lifecycle: bounded connection admission and per-connection timeouts, a
//! maintenance thread that reconciles leases and rechecks and drives
//! registered carriers, and a stop that fences new work under the storage
//! lock, drains in-flight requests and removes only this instance's socket.
//! Structured logging is JSON lines on stderr; token values are never
//! logged.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dispatch::{
    DispatchCarrier, DispatchReport, DispatchTiming, attest_guarded, dispatch_message, lock_storage,
};
use crate::recovery::{
    DeliveryState, EvidenceTier, HoldView, IncidentPage, IncidentView, LineageScope, RetentionView,
};
use crate::storage::{CustodyReceipt, Limits, Storage};
use crate::types::{
    CoreError, Envelope, EventId, ExpiresAt, Kind, Metadata, Mode, NativeAddress, Payload, Policy,
    PublisherId,
};
use crate::wire::{MAX_REQUEST_BYTES, read_bounded_line, write_line};

pub use crate::recovery::DeliveryEvidence;

/// How long a stop waits for in-flight connections before giving up.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between reconciliation and dispatch passes.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);

/// Shortest accepted grant token, in bytes (tokens must be unguessable).
const MIN_TOKEN_BYTES: usize = 16;

/// Largest listing an operator request may ask for.
const MAX_LISTING: usize = 200;

/// Recipients dispatched per maintenance pass.
const RECIPIENTS_PER_PASS: usize = 16;

/// Attempts driven per recipient per maintenance pass.
const ATTEMPTS_PER_RECIPIENT: usize = 4;

/// Longest part of one carrier's attestation refusal, in characters, kept in
/// a recipient hold; the joined hold text is bounded again by the store.
const REFUSAL_REASON_CHARS: usize = 120;

/// Daemon and service configuration, usually loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Filesystem path of the SQLite custody database.
    pub database: PathBuf,
    /// Filesystem path of the Unix stream socket to listen on.
    pub socket: PathBuf,
    /// Admission limits handed to storage.
    pub limits: crate::storage::Limits,
    /// Integration grants; at least one is required to serve anything.
    #[serde(default, alias = "grant")]
    pub grants: Vec<GrantConfig>,
    /// Separate bounded v1 identities; never an implicit producer job timeout.
    #[serde(default)]
    pub universal_limits: crate::UniversalLimits,
}

/// One authenticated grant.
///
/// A publisher grant binds a secret token to exactly one publisher identity
/// and to the recipients, kinds, modes and policies that publisher may use;
/// its `publisher` identity is also the source tag Bridge renders around its
/// events. An operator grant (`admin = true`) must carry empty allowlists.
/// The token is supplied out-of-band; possession of the token plus socket
/// access is the caller's authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct GrantConfig {
    /// Secret bearer token (unguessable, at least 16 bytes, unique).
    pub token: String,
    /// The single publisher (or operator) identity this grant authenticates.
    pub publisher: String,
    /// Canonical recipient addresses this grant may publish to; `"*"` permits
    /// any well-formed address without a per-session admission change.
    pub recipients: Vec<String>,
    /// Event kinds this grant may publish.
    pub kinds: Vec<String>,
    /// Requested delivery modes this grant may use.
    pub modes: Vec<String>,
    /// Coalescing policy names this grant may use.
    pub policies: Vec<String>,
    /// Whether this is an operator grant: recovery, pause and shutdown
    /// operations, never publishing.
    #[serde(default)]
    pub admin: bool,
    /// Opt-in v1 permissions; absence preserves all legacy grant behavior.
    #[serde(default)]
    pub producer_v1: Option<crate::ProducerPolicy>,
}

impl std::fmt::Debug for GrantConfig {
    /// Prints the identity and allowlist sizes, never the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantConfig")
            .field("token", &"<redacted>")
            .field("publisher", &self.publisher)
            .field("recipients", &self.recipients.len())
            .field("kinds", &self.kinds)
            .field("modes", &self.modes)
            .field("policies", &self.policies)
            .field("admin", &self.admin)
            .field("producer_v1", &self.producer_v1)
            .finish()
    }
}

impl GrantConfig {
    /// Parses and validates everything the runtime will check against.
    ///
    /// Publisher identity, recipient addresses, kinds, modes and policies
    /// must be well-formed at load time so authorization decisions never
    /// run on malformed allowlist entries; a publisher identity must also be
    /// usable as a source tag; the token must be at least 16 bytes; an
    /// operator grant must have empty allowlists. Returns the first
    /// problem as [`CoreError::InvalidEnvelope`].
    pub fn validate(&self) -> Result<(), CoreError> {
        if let Some(policy) = &self.producer_v1 {
            if self.admin {
                return Err(CoreError::InvalidEnvelope(
                    "operator grants cannot enable producer v1".into(),
                ));
            }
            policy
                .validate()
                .map_err(|_| CoreError::InvalidEnvelope("invalid producer v1 policy".into()))?;
            for values in [&self.kinds, &self.modes, &self.policies] {
                if values.len() > 64
                    || values
                        .iter()
                        .enumerate()
                        .any(|(index, value)| values[..index].contains(value))
                {
                    return Err(CoreError::InvalidEnvelope(
                        "producer v1 allowlists must be bounded unique sets".into(),
                    ));
                }
            }
        }
        PublisherId::new(self.publisher.clone())?;
        if self.token.len() < MIN_TOKEN_BYTES {
            return Err(CoreError::InvalidEnvelope(format!(
                "grant token for {} is shorter than {MIN_TOKEN_BYTES} bytes",
                self.publisher
            )));
        }
        if self.admin {
            if !(self.recipients.is_empty()
                && self.kinds.is_empty()
                && self.modes.is_empty()
                && self.policies.is_empty())
            {
                return Err(CoreError::InvalidEnvelope(format!(
                    "operator grant {} must not carry publisher allowlists",
                    self.publisher
                )));
            }
        } else {
            crate::framing::validate_tag(&self.publisher)?;
        }
        for recipient in &self.recipients {
            if recipient != "*" {
                NativeAddress::parse(recipient)?;
            }
        }
        for kind in &self.kinds {
            Kind::new(kind.clone())?;
        }
        for mode in &self.modes {
            Mode::parse(mode)?;
        }
        for policy in &self.policies {
            match policy.as_str() {
                "keep_all" | "latest" | "batch" => {}
                other => {
                    return Err(CoreError::InvalidEnvelope(format!(
                        "unknown policy {other:?} in grant allowlist"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// A publish request body: everything an envelope carries except the
/// publisher identity and schema version, which Bridge stamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishBody {
    /// Producer-stable event id (unique per publisher).
    pub event_id: String,
    /// Exact native logical recipient address.
    pub recipient: NativeAddress,
    /// Event kind.
    pub kind: String,
    /// Requested delivery mode.
    pub mode: Mode,
    /// Coalescing policy.
    pub policy: Policy,
    /// Bounded payload text.
    pub payload: String,
    /// Project/task metadata (validated with the envelope).
    #[serde(default)]
    pub metadata: Metadata,
    /// Absolute expiry, if any.
    pub expires_at: Option<ExpiresAt>,
}

/// Bounded delivery counts for the operator surface.
///
/// Counts only: no event payloads, recipients or foreign detail are
/// enumerated. Routine losses stay countable (`held` covers native holds
/// and written-no-receipt; `review` covers possible hand-offs) so they
/// cannot be buried under routine unknowns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryCounts {
    /// Events never handed to any path.
    pub unhanded: u64,
    /// Events frozen into a reserved attempt that has not invoked.
    pub reserved: u64,
    /// Events with an invoking attempt (a hand-off may exist).
    pub invoking: u64,
    /// Events held by the native side or written without a receipt.
    pub held: u64,
    /// Events with a possible hand-off awaiting manual resolution.
    pub review: u64,
    /// Events accepted by a native queue or inbox.
    pub accepted: u64,
    /// Events whose hook payload was handed out.
    pub hook_submitted: u64,
    /// Events permanently refused before acceptance.
    pub refused: u64,
    /// Events closed by an audited disposition.
    pub disposed: u64,
    /// Currently open incidents.
    pub open_incidents: u64,
}

/// A bearer token that never appears in `Debug` output.
///
/// On the wire it is a plain JSON string (the early wire format is
/// unchanged); in memory it dereferences to `&str` for comparison. Request
/// and grant types hold it, so logging or panicking with one of them cannot
/// disclose a credential.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Token(String);

impl Token {
    /// Wraps a bearer token string.
    pub fn new(value: impl Into<String>) -> Self {
        Token(value.into())
    }
}

impl std::ops::Deref for Token {
    type Target = str;

    /// The token text, for comparison only; never log it.
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Token {
    /// Prints a fixed placeholder instead of the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// One bounded request line received on the local socket.
///
/// New operator page/retention reads remain separate from legacy listings,
/// publisher status and all mutations; each operation authenticates its realm.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Publish (or idempotently replay) one event under custody.
    Publish {
        /// Publisher-grant bearer token.
        token: Token,
        /// The event body; publisher is stamped from the grant.
        event: Box<PublishBody>,
    },
    /// Look up the caller's own publication status.
    Status {
        /// Publisher-grant bearer token.
        token: Token,
        /// The caller's event id.
        event_id: String,
    },
    /// Stop the daemon: refuse new work, drain, exit.
    Shutdown {
        /// Operator-grant bearer token.
        token: Token,
    },
    /// List retained incidents with age, deadlines and blocked dependents.
    Incidents {
        /// Operator-grant bearer token.
        token: Token,
        /// Include settled incidents too.
        #[serde(default)]
        include_closed: bool,
        /// Maximum rows (default 100, at most 200).
        limit: Option<usize>,
    },
    /// Read a stable-number incident page without modifying recovery state.
    IncidentsPage {
        /// Operator-grant bearer token; authenticated before cursor validation.
        token: Token,
        /// Include positively closed rows too; defaults to open rows only.
        #[serde(default)]
        include_closed: bool,
        /// Row bound: default 100, clamped to 1..200.
        limit: Option<usize>,
        /// Exclusive lower incident number; defaults to zero for a first page.
        #[serde(default)]
        after_seq: u64,
        /// Fixed high-water number; absent only when starting at zero.
        through_seq: Option<u64>,
    },
    /// Inspect exact retained storage facts without reading payload bytes.
    Retention {
        /// Operator-grant bearer token; publisher/root grants are refused.
        token: Token,
        /// Exact validated publisher identity.
        publisher: String,
        /// Exact validated event identity; unaccepted keys return no view.
        event_id: String,
    },
    /// List visible recipient holds.
    Holds {
        /// Operator-grant bearer token.
        token: Token,
        /// Maximum rows (default 100, at most 200).
        limit: Option<usize>,
    },
    /// Bounded delivery counts: how many events/attempt states sit in each
    /// tier, so routine losses (held, written-no-receipt, unknown) are
    /// countable without enumerating any event payload or foreign detail.
    Counts {
        /// Operator-grant bearer token.
        token: Token,
    },
    /// Authorize one more attempt of the same event after an unresolved
    /// possible hand-off; the duplicate risk is recorded permanently.
    AuthorizeRetry {
        /// Operator-grant bearer token.
        token: Token,
        /// Publisher of the event.
        publisher: String,
        /// The event to retry.
        event_id: String,
        /// Audit note (why the retry is acceptable).
        note: String,
    },
    /// Close an event with an audited disposition (never claims delivery).
    Dispose {
        /// Operator-grant bearer token.
        token: Token,
        /// Publisher of the event.
        publisher: String,
        /// The event to dispose.
        event_id: String,
        /// Audit note.
        note: String,
    },
    /// Waive a missing or expired predecessor of a dependent event.
    WaivePredecessor {
        /// Operator-grant bearer token.
        token: Token,
        /// Publisher of the dependent event.
        publisher: String,
        /// The dependent event.
        event_id: String,
        /// Audit note.
        note: String,
    },
    /// Record positive late evidence that settles an uncertain attempt.
    Evidence {
        /// Operator-grant bearer token.
        token: Token,
        /// Publisher of the event.
        publisher: String,
        /// The event the evidence concerns.
        event_id: String,
        /// The attempt the evidence concerns.
        attempt_seq: u64,
        /// The evidence tier.
        tier: EvidenceTier,
        /// The observed fact.
        detail: String,
    },
    /// Transfer a stream lineage's authoritative producer (audited).
    ///
    /// Operator grants only. The lineage is the coalescing scope without
    /// the publisher (exact recipient, kind, mode, declared project/task,
    /// stream); the previous owner is fenced from further `latest`
    /// publications into it, and neither producer's watermarks, event ids,
    /// attempts nor evidence are rewritten. Refused while another
    /// producer's event in the lineage has a possible or unknown native
    /// effect (invoking, review or natively held): resolve it first.
    TransferLineage {
        /// Operator-grant bearer token.
        token: Token,
        /// Exact recipient address of the lineage.
        recipient: NativeAddress,
        /// Event kind of the lineage.
        kind: String,
        /// Requested delivery mode of the lineage.
        mode: String,
        /// Declared project scope (empty string when none).
        project: String,
        /// Declared task scope (empty string when none).
        task: String,
        /// The authoritative stream.
        stream: String,
        /// The publisher taking authority (validated, Bridge-stamped
        /// thereafter; never taken from event metadata).
        new_publisher: String,
        /// Audit note: why the handover is acceptable.
        note: String,
    },
    /// Set the durable no-wake policy for a recipient.
    Pause {
        /// Operator-grant bearer token.
        token: Token,
        /// The recipient to pause.
        recipient: NativeAddress,
        /// Why it is paused.
        reason: String,
    },
    /// Clear the durable no-wake policy for a recipient.
    Resume {
        /// Operator-grant bearer token.
        token: Token,
        /// The recipient to resume.
        recipient: NativeAddress,
    },
}

/// One bounded response line written to the local client.
///
/// Operator pages and nullable retention facts are distinct additive variants;
/// existing response shapes keep their meaning and never establish native recall.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// Custody accepted (freshly or as an identical replay).
    Published {
        /// The durable custody receipt.
        receipt: CustodyReceipt,
    },
    /// Status of the caller's own event.
    Status {
        /// The custody receipt, or `None` when never accepted.
        receipt: Option<CustodyReceipt>,
        /// Delivery evidence tiers, distinct from custody; `None` when the
        /// event was never accepted. Callers must treat absent tiers as
        /// not_available, never as delivered.
        delivery: Option<Box<DeliveryEvidence>>,
    },
    /// Retained incidents.
    Incidents {
        /// The incidents, bounded by the request limit.
        incidents: Vec<IncidentView>,
    },
    /// Finite operator scan page; all rows retain their live incident meaning.
    IncidentsPage {
        /// At most 200 ascending rows and the fixed scan/continuation bounds.
        page: IncidentPage,
    },
    /// Exact operator storage facts, never payload content or a recall claim.
    Retention {
        /// Absent only for an unaccepted exact identity.
        retention: Option<Box<RetentionView>>,
    },
    /// Visible recipient holds.
    Holds {
        /// The holds, bounded by the request limit.
        holds: Vec<HoldView>,
    },
    /// Bounded delivery counts (no payloads, no enumeration).
    Counts {
        /// Count of events per delivery tier.
        counts: DeliveryCounts,
    },
    /// An operator action was applied (and audited).
    Done,
    /// Shutdown acknowledged; the daemon exits after draining.
    ShuttingDown,
    /// Structured refusal; nothing was accepted or disclosed.
    Error {
        /// Machine-readable class: auth, forbidden, unsupported, invalid,
        /// conflict, capacity, held, fence, busy or internal.
        class: String,
        /// Human-readable detail without secrets.
        detail: String,
    },
}

impl Response {
    /// Revalidates the parts of a decoded response that are not validated
    /// by their own types: operator listings (identifiers, ranges, bounds).
    ///
    /// Receipts, hashes, addresses and delivery evidence already revalidate
    /// during deserialization. Clients call this on every decoded response
    /// so a damaged or hostile line is never trusted for its numbers.
    pub fn validate(&self) -> Result<(), CoreError> {
        match self {
            Response::Incidents { incidents } => {
                incidents.iter().try_for_each(IncidentView::validate)
            }
            Response::IncidentsPage { page } => page.validate(),
            Response::Retention { retention } => {
                retention.as_ref().map_or(Ok(()), |view| view.validate())
            }
            Response::Holds { holds } => holds.iter().try_for_each(HoldView::validate),
            _ => Ok(()),
        }
    }
}

/// A structured refusal; small enough to travel in `Result` errors.
struct Refusal {
    /// Machine-readable class (see [`Response::Error`]).
    class: &'static str,
    /// Human-readable detail without secrets.
    detail: String,
}

impl Refusal {
    /// Builds a refusal.
    fn new(class: &'static str, detail: impl Into<String>) -> Self {
        Refusal {
            class,
            detail: detail.into(),
        }
    }
}

impl From<Refusal> for Response {
    /// Converts the refusal to its wire form.
    fn from(refusal: Refusal) -> Self {
        Response::Error {
            class: refusal.class.to_string(),
            detail: refusal.detail,
        }
    }
}

impl From<CoreError> for Refusal {
    /// Maps a [`CoreError`] to its wire refusal class.
    fn from(error: CoreError) -> Self {
        let class = match &error {
            CoreError::InvalidEnvelope(_) => "invalid",
            CoreError::Conflict { .. } => "conflict",
            CoreError::Capacity { .. } => "capacity",
            CoreError::PolicyHold { .. } => "held",
            CoreError::Fence(_) => "fence",
            CoreError::Busy(_) => "busy",
            CoreError::Unsupported(_) => "unsupported",
            CoreError::Storage(_) | CoreError::Integrity(_) => "internal",
        };
        Refusal::new(class, error.to_string())
    }
}

/// A running service bound to its socket.
///
/// Dropping the handle does not stop the service; call [`Running::shutdown`]
/// and [`Running::join`] for a bounded, drained stop.
pub struct Running {
    /// The bound socket path.
    socket_path: PathBuf,
    /// State shared with the worker threads.
    state: Arc<ServiceState>,
    /// The accept loop.
    accept_thread: JoinHandle<()>,
    /// The reconciliation and dispatch loop.
    maintenance_thread: JoinHandle<()>,
}

/// A carrier owned by the dispatch loop.
type BoxedCarrier = Box<dyn DispatchCarrier + Send>;

/// Shared server state behind the worker threads.
struct ServiceState {
    /// The custody store; its lock also fences shutdown against publishes.
    storage: Mutex<Storage>,
    /// Validated grants.
    authorizer: Arc<crate::ProducerAuthorizer>,
    /// Connection and timeout bounds (see [`Limits`]).
    limits: Limits,
    /// `false` once a stop was requested; new work is refused under the
    /// storage lock after that.
    running: AtomicBool,
    /// The configured socket path.
    socket_path: PathBuf,
    /// Identity (device, inode) of the socket file this instance bound, so
    /// shutdown only ever unlinks its own endpoint.
    socket_identity: (u64, u64),
    /// Currently served connections, bounded by `limits.max_connections`.
    active_connections: AtomicUsize,
    /// Read-half handles of served connections, to wake them at a stop.
    streams: Mutex<HashMap<u64, UnixStream>>,
    /// Source of connection registry keys.
    next_stream_id: AtomicU64,
    /// Carriers driven by the maintenance loop.
    carriers: Mutex<Vec<BoxedCarrier>>,
    /// Last recipient of the previous dispatch window, so the next pass
    /// continues after it; `None` starts a new rotation. Touched only by
    /// the maintenance thread.
    dispatch_cursor: Mutex<Option<NativeAddress>>,
    /// The advisory lock that proves exclusive ownership of the endpoint;
    /// held until the service state is dropped, i.e. past the socket's
    /// removal.
    _endpoint_lock: std::fs::File,
}

impl ServiceState {
    /// Requests a stop and fences new work.
    ///
    /// The flag is flipped while holding the storage lock, so any publish
    /// that is already inside its critical section finishes first and every
    /// later one observes the flag before touching custody: once this
    /// returns, no further publish can be accepted.
    fn stop(&self) {
        let _fence = lock_storage(&self.storage);
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Starts the service without carriers: custody and operator surfaces only.
///
/// Events stay pending (visibly) until a qualified adapter drives them. See
/// [`start_with_carriers`] for the full contract.
pub fn start(config: Config) -> Result<Running, CoreError> {
    start_with_carriers(config, Vec::new())
}

/// Starts the service: validates grants, opens storage, claims and binds the
/// socket and spawns the accept and maintenance loops.
///
/// Fails if a grant is malformed or duplicated, the database cannot be
/// opened, a source tag conflicts, or the socket cannot be bound — never
/// serves with partial authentication state. A path held by a live listener
/// is refused; a stale socket is claimed only when a connection attempt is
/// positively refused; any other existing path is preserved untouched.
/// `carriers` are driven by the maintenance loop for the message path.
pub fn start_with_carriers(
    config: Config,
    carriers: Vec<BoxedCarrier>,
) -> Result<Running, CoreError> {
    let mut tokens: Vec<&str> = Vec::new();
    for grant in &config.grants {
        grant.validate()?;
        if tokens.contains(&grant.token.as_str()) {
            return Err(CoreError::InvalidEnvelope(
                "two grants share one token".into(),
            ));
        }
        tokens.push(&grant.token);
    }
    config.limits.validate()?;
    config
        .universal_limits
        .validate()
        .map_err(|_| CoreError::InvalidEnvelope("invalid universal limits".into()))?;
    let authorizer = Arc::new(
        crate::ProducerAuthorizer::new(&config.grants)
            .map_err(|_| CoreError::InvalidEnvelope("invalid boot producer authority".into()))?,
    );
    if let Some(parent) = config.socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| io_failure(format!("cannot create socket directory: {error}")))?;
    }
    // Serializes every daemon that wants this endpoint, before the database
    // is touched: a loser changes nothing.
    let endpoint_lock = acquire_endpoint_lock(&config.socket)?;
    let mut storage = Storage::open(&config.database, config.limits)?;
    storage.universal_limits = config.universal_limits;
    storage
        .install_producer_authorizer(Arc::clone(&authorizer))
        .map_err(|_| CoreError::InvalidEnvelope("cannot install producer authority".into()))?;
    for grant in config.grants.iter().filter(|grant| !grant.admin) {
        storage.register_source_tag(&grant.publisher, &grant.publisher)?;
    }
    claim_socket(&config.socket)?;
    let listener = UnixListener::bind(&config.socket).map_err(|error| {
        io_failure(format!(
            "cannot bind socket {}: {error}",
            config.socket.display()
        ))
    })?;
    let identity = socket_identity(&config.socket)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600));
    listener
        .set_nonblocking(true)
        .map_err(|error| io_failure(format!("cannot set socket non-blocking: {error}")))?;
    let state = Arc::new(ServiceState {
        storage: Mutex::new(storage),
        authorizer,
        limits: config.limits,
        running: AtomicBool::new(true),
        socket_path: config.socket.clone(),
        socket_identity: identity,
        active_connections: AtomicUsize::new(0),
        streams: Mutex::new(HashMap::new()),
        next_stream_id: AtomicU64::new(0),
        carriers: Mutex::new(carriers),
        dispatch_cursor: Mutex::new(None),
        _endpoint_lock: endpoint_lock,
    });
    log_event(
        "info",
        "service_starting",
        &[
            ("socket", &state.socket_path.display().to_string()),
            ("grants", &config.grants.len().to_string()),
        ],
    );
    let accept_state = Arc::clone(&state);
    let accept_thread = std::thread::Builder::new()
        .name("bridge-accept".into())
        .spawn(move || accept_loop(listener, accept_state))
        .map_err(|error| io_failure(format!("cannot spawn accept thread: {error}")))?;
    let maintenance_state = Arc::clone(&state);
    let maintenance_thread = std::thread::Builder::new()
        .name("bridge-maintenance".into())
        .spawn(move || maintenance_loop(&maintenance_state))
        .map_err(|error| {
            state.stop();
            io_failure(format!("cannot spawn maintenance thread: {error}"))
        })?;
    Ok(Running {
        socket_path: config.socket,
        state,
        accept_thread,
        maintenance_thread,
    })
}

/// Wraps an operating-system failure as a storage-class core error.
fn io_failure(detail: String) -> CoreError {
    CoreError::Storage(rusqlite::Error::InvalidParameterName(detail))
}

impl Running {
    /// The bound socket path for clients.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Whether the service still accepts work (no stop was requested by
    /// [`Running::shutdown`] or an operator over the socket).
    pub fn is_running(&self) -> bool {
        self.state.running.load(Ordering::SeqCst)
    }

    /// Requests a drained stop (idempotent).
    ///
    /// Fences new work under the storage lock: when this returns, no
    /// further publish or operator mutation can be accepted.
    pub fn shutdown(&self) {
        self.state.stop();
    }

    /// Waits for the loops to finish and in-flight connections to drain,
    /// each bounded by a drain timeout; the caller requests the stop first.
    ///
    /// A carrier that hangs inside a hand-off cannot make the stop
    /// unbounded: the maintenance thread is then left to finish on its own
    /// (its attempt stays `invoking` and becomes a retained unknown outcome
    /// at its deadline, never a replay), and the timeout is logged.
    pub fn join(self) {
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        for (name, handle) in [
            ("accept", self.accept_thread),
            ("maintenance", self.maintenance_thread),
        ] {
            while !handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                log_event("warn", "drain_timeout", &[("thread", name)]);
            }
        }
        while self.state.active_connections.load(Ordering::SeqCst) > 0 {
            if Instant::now() >= deadline {
                log_event(
                    "warn",
                    "drain_timeout",
                    &[(
                        "active",
                        &self
                            .state
                            .active_connections
                            .load(Ordering::SeqCst)
                            .to_string(),
                    )],
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Runs `action` with exclusive access to the custody store.
    ///
    /// For in-process adapters (a qualified hook calling
    /// [`Storage::drain_inject`], evidence reporting) that must act on the
    /// same store the service uses. The lock is the same one that fences
    /// shutdown, so do not hold it across slow work.
    pub fn with_storage<T>(&self, action: impl FnOnce(&mut Storage) -> T) -> T {
        action(&mut lock_storage(&self.state.storage))
    }
}

/// Takes the exclusive advisory lock that serializes daemons contending for
/// one socket path.
///
/// The lock file is `<socket>.lock`; it is created if absent and left in
/// place afterwards (removing it would reopen the race it closes). A
/// non-regular file at that path is foreign and refused. A holder that is
/// still running refuses every later start before it can inspect, remove or
/// bind anything, so two daemons can never both decide that the same stale
/// socket is theirs.
fn acquire_endpoint_lock(socket: &Path) -> Result<std::fs::File, CoreError> {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    let path = PathBuf::from(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(io_failure(format!(
                "refusing endpoint lock path {}: not a regular file",
                path.display()
            )));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(io_failure(format!(
                "cannot inspect endpoint lock path {}: {error}",
                path.display()
            )));
        }
        _ => {}
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|error| {
            io_failure(format!(
                "cannot open endpoint lock {}: {error}",
                path.display()
            ))
        })?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(io_failure(format!(
            "another daemon owns the endpoint {}; refusing to start",
            socket.display()
        ))),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(io_failure(format!("cannot lock the endpoint: {error}")))
        }
    }
}

/// Reads the (device, inode) identity of the socket file at `path`.
fn socket_identity(path: &Path) -> Result<(u64, u64), CoreError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| io_failure(format!("cannot inspect bound socket: {error}")))?;
    if !metadata.file_type().is_socket() {
        return Err(io_failure(format!(
            "bound path {} is not a socket",
            path.display()
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Claims the socket path for binding, proving staleness positively.
///
/// Ownership rules: a path with a live listener is refused (a second
/// instance must never replace a working endpoint or get unlinked by the
/// first instance's shutdown); a socket is removed only when a connection
/// attempt is *refused* (nothing is listening) and the file is still the
/// very inode that was inspected; any other connect error is not positive
/// proof and refuses; any other existing path (regular file, directory,
/// symlink) is preserved untouched and startup refuses rather than deleting
/// foreign data.
fn claim_socket(path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io_failure(format!(
                "cannot inspect socket path {}: {error}",
                path.display()
            )));
        }
        Ok(metadata) => metadata,
    };
    if !metadata.file_type().is_socket() {
        return Err(io_failure(format!(
            "refusing to remove non-socket path {}",
            path.display()
        )));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(io_failure(format!(
            "a live daemon already owns socket {}; refusing to replace it",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let again = std::fs::symlink_metadata(path)
                .map_err(|error| io_failure(format!("socket path changed: {error}")))?;
            if again.dev() != metadata.dev() || again.ino() != metadata.ino() {
                return Err(io_failure(format!(
                    "socket {} was replaced while it was inspected; refusing",
                    path.display()
                )));
            }
            std::fs::remove_file(path).map_err(|error| {
                io_failure(format!(
                    "cannot remove stale socket {}: {error}",
                    path.display()
                ))
            })
        }
        Err(error) => Err(io_failure(format!(
            "cannot prove socket {} is stale ({error}); refusing to remove it",
            path.display()
        ))),
    }
}

/// Removes the socket file only if this instance still owns it.
///
/// Compares the file's (device, inode) identity with the one recorded at
/// bind time; a replacement endpoint bound by another daemon after this one
/// stopped is never unlinked.
fn release_socket(state: &ServiceState) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(metadata) = std::fs::symlink_metadata(&state.socket_path) {
        if (metadata.dev(), metadata.ino()) == state.socket_identity {
            let _ = std::fs::remove_file(&state.socket_path);
        } else {
            log_event("warn", "socket_replaced_before_stop", &[]);
        }
    }
}

/// Accept loop: non-blocking accept polled while running; each admitted
/// connection runs on its own thread up to `limits.max_connections`.
///
/// A stop ends the loop within one poll interval, wakes every served
/// connection (their read halves are shut down, so idle ones end at once
/// while a request in flight still finishes and answers) and removes only
/// this instance's socket. Spawn failure releases the admission slot.
fn accept_loop(listener: UnixListener, state: Arc<ServiceState>) {
    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => admit(&state, stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                log_event("error", "accept_failed", &[("error", &error.to_string())]);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    for stream in state
        .streams
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .values()
    {
        let _ = stream.shutdown(std::net::Shutdown::Read);
    }
    release_socket(&state);
    log_event("info", "service_stopped", &[]);
}

/// Admits one accepted connection under the connection cap.
fn admit(state: &Arc<ServiceState>, stream: UnixStream) {
    let active = state.active_connections.fetch_add(1, Ordering::SeqCst) + 1;
    if active > state.limits.max_connections {
        state.active_connections.fetch_sub(1, Ordering::SeqCst);
        log_event(
            "warn",
            "connection_refused_admission",
            &[("active", &active.to_string())],
        );
        return;
    }
    let id = state.next_stream_id.fetch_add(1, Ordering::SeqCst);
    if let Ok(clone) = stream.try_clone() {
        state
            .streams
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(id, clone);
    }
    let connection_state = Arc::clone(state);
    let spawned = std::thread::Builder::new()
        .name("bridge-connection".into())
        .spawn(move || {
            let _guard = ConnectionGuard {
                state: Arc::clone(&connection_state),
                id,
            };
            handle_connection(stream, &connection_state);
        });
    if let Err(error) = spawned {
        log_event(
            "error",
            "connection_spawn_failed",
            &[("error", &error.to_string())],
        );
        state
            .streams
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&id);
        state.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Releases a connection's admission slot and registry entry on exit, also
/// when the handler panics.
struct ConnectionGuard {
    /// Shared state owning the counters.
    state: Arc<ServiceState>,
    /// Registry key of this connection.
    id: u64,
}

impl Drop for ConnectionGuard {
    /// Releases the admission slot and the registry entry; never panics.
    fn drop(&mut self) {
        self.state
            .streams
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
        self.state.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves one connection with bounded framing, timeouts and a shutdown
/// fence.
///
/// Reads at most one newline-terminated request at a time without ever
/// allocating more than the request cap for a line; a silent connection is
/// closed after the idle timeout, a stalled partial line after the request
/// timeout, and a peer that stops reading after the write timeout. Every
/// parsed request is fenced against the stop flag (and mutations re-check it
/// under the storage lock). The connection ends at EOF, refusal, timeout or
/// shutdown.
fn handle_connection(stream: UnixStream, state: &Arc<ServiceState>) {
    let _ = stream.set_nonblocking(false);
    let Ok(reader_stream) = stream.try_clone() else {
        log_event("error", "connection_clone_failed", &[]);
        return;
    };
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    loop {
        let line = match read_bounded_line(
            &mut reader,
            MAX_REQUEST_BYTES,
            Duration::from_millis(state.limits.idle_timeout_ms),
            Duration::from_millis(state.limits.request_timeout_ms),
        ) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                // An idle connection or a peer that vanished mid-line is
                // closed silently: an unsolicited line would be mistaken
                // for the answer to the peer's next request.
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::WouldBlock
                ) {
                    let _ = respond(
                        state,
                        &mut writer,
                        &Refusal::new("invalid", error.to_string()).into(),
                    );
                }
                break; // framing cannot be trusted past a violation
            }
        };
        if !state.running.load(Ordering::SeqCst) {
            let _ = respond(state, &mut writer, &stopping().into());
            break;
        }
        // Additive v1 is strict and cannot fall through to legacy mutation.
        if let Some(bytes) = serve_v1_line(state, &line) {
            // A failed response codec closes without falsely acknowledging a
            // potentially committed mutation; the client reconciles its key.
            if bytes.is_empty() {
                break;
            }
            if write_line(
                &mut writer,
                &bytes,
                Duration::from_millis(state.limits.write_timeout_ms),
            )
            .is_err()
            {
                break;
            }
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => serve(state, request).unwrap_or_else(Response::from),
            Err(error) => {
                // The request text is never echoed: it may carry a token.
                Refusal::new(
                    "unsupported",
                    format!(
                        "unparseable request ({:?} error at column {})",
                        error.classify(),
                        error.column()
                    ),
                )
                .into()
            }
        };
        let stopping_now = matches!(response, Response::ShuttingDown);
        if respond(state, &mut writer, &response).is_err() || stopping_now {
            break;
        }
    }
}

/// Dispatches only additive versioned producer frames on the existing socket.
/// Protocol owns strict decoding/correlation; this function never echoes a
/// request/credential/body and native registration/consumption stay on adapter
/// ingress. All mutations share the custody/shutdown critical section.
fn serve_v1_line(state: &ServiceState, line: &str) -> Option<Vec<u8>> {
    use bridge_protocol::{Operation as Op, OperationResult as Out};
    let candidate: serde_json::Value = serde_json::from_str(line).ok()?;
    candidate.get("api_version")?;
    let request_id = candidate
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .filter(|v| crate::producer::opaque(v))
        .unwrap_or("invalid-request");
    let response = match bridge_protocol::decode_request(line.as_bytes()) {
        Err(error) => bridge_protocol::Response::error(
            request_id,
            crate::producer::failure(
                if error.field == "api_version" {
                    bridge_protocol::ErrorClass::Unsupported
                } else {
                    bridge_protocol::ErrorClass::Invalid
                },
                "invalid_v1_request",
            ),
        ),
        Ok(request) => {
            let mut storage = lock_storage(&state.storage);
            let result = if !state.running.load(Ordering::SeqCst) {
                Err(crate::producer::failure(
                    bridge_protocol::ErrorClass::Unavailable,
                    "service_stopping",
                ))
            } else {
                let credential = request.credential.expose();
                match &request.operation {
                    Op::Capabilities(_) => {
                        storage.capabilities_v1(credential).map(Out::Capabilities)
                    }
                    Op::Publish(body) => storage
                        .publish_v1(credential, body, &current_unix_millis)
                        .map(Out::Publish),
                    Op::Status(body) => storage
                        .status_v1(credential, &body.selector, current_unix_millis())
                        .map(Out::Status),
                    Op::CloseRoute(body) => storage
                        .close_route(credential, &request.request_id, body, &current_unix_millis)
                        .map(Out::CloseRoute),
                    Op::RetireDeliveryScope(body) => storage
                        .retire_delivery_scope(
                            credential,
                            &request.request_id,
                            body,
                            &current_unix_millis,
                        )
                        .map(Out::RetireDeliveryScope),
                    _ => storage
                        .producer_authorizer()
                        .and_then(|auth| auth.authenticate(credential).map(|_| ()))
                        .and_then(|_| {
                            Err(crate::producer::failure(
                                bridge_protocol::ErrorClass::Unsupported,
                                "native_ingress_required",
                            ))
                        }),
                }
            };
            match result {
                Ok(value) => bridge_protocol::Response::ok(&request.request_id, value),
                Err(mut error) => {
                    if let Some(key) = request.reconciliation() {
                        if error.effect.is_none() {
                            error.effect = Some(bridge_protocol::MutationEffect::NotCommitted);
                        }
                        error.reconciliation = Some(key);
                    }
                    bridge_protocol::Response::error(&request.request_id, error)
                }
            }
        }
    };
    Some(bridge_protocol::encode_response(&response).unwrap_or_default())
}

/// The refusal returned for work that arrives after a stop.
fn stopping() -> Refusal {
    Refusal::new("held", "service is shutting down; no new work is accepted")
}

/// Writes one response line with the write timeout.
fn respond(
    state: &ServiceState,
    stream: &mut UnixStream,
    response: &Response,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    write_line(
        stream,
        &bytes,
        Duration::from_millis(state.limits.write_timeout_ms),
    )
}

/// Authenticates each parsed request before reading or changing shared state.
///
/// Publisher operations stay scoped to their grant. New operator pages and exact
/// retention reads cannot mutate recovery state or disclose payload bytes;
/// invalid input/storage failures become structured refusals.
fn serve(state: &ServiceState, request: Request) -> Result<Response, Refusal> {
    match request {
        Request::Publish { token, event } => serve_publish(state, &token, &event),
        Request::Status { token, event_id } => serve_status(state, &token, &event_id),
        Request::Shutdown { token } => {
            let grant = operator(state, &token)?;
            state.stop();
            log_event(
                "info",
                "shutdown_requested",
                &[("operator", &grant.publisher)],
            );
            Ok(Response::ShuttingDown)
        }
        Request::Incidents {
            token,
            include_closed,
            limit,
        } => {
            operator(state, &token)?;
            let storage = lock_storage(&state.storage);
            Ok(Response::Incidents {
                incidents: storage.incidents(
                    include_closed,
                    current_unix_millis(),
                    listing(limit),
                )?,
            })
        }
        Request::IncidentsPage {
            token,
            include_closed,
            limit,
            after_seq,
            through_seq,
        } => {
            operator(state, &token)?;
            let storage = lock_storage(&state.storage);
            Ok(Response::IncidentsPage {
                page: storage.incidents_page(
                    include_closed,
                    current_unix_millis(),
                    listing(limit),
                    after_seq,
                    through_seq,
                )?,
            })
        }
        Request::Retention {
            token,
            publisher,
            event_id,
        } => {
            operator(state, &token)?;
            let storage = lock_storage(&state.storage);
            Ok(Response::Retention {
                retention: storage.retention(&publisher, &event_id)?.map(Box::new),
            })
        }
        Request::Holds { token, limit } => {
            operator(state, &token)?;
            let storage = lock_storage(&state.storage);
            Ok(Response::Holds {
                holds: storage.holds(listing(limit))?,
            })
        }
        Request::Counts { token } => {
            operator(state, &token)?;
            let storage = lock_storage(&state.storage);
            let count = |state: DeliveryState| storage.count_delivery(state);
            Ok(Response::Counts {
                counts: DeliveryCounts {
                    unhanded: count(DeliveryState::Unhanded)?,
                    reserved: count(DeliveryState::Reserved)?,
                    invoking: count(DeliveryState::Invoking)?,
                    held: count(DeliveryState::Held)?,
                    review: count(DeliveryState::Review)?,
                    accepted: count(DeliveryState::Accepted)?,
                    hook_submitted: count(DeliveryState::HookSubmitted)?,
                    refused: count(DeliveryState::Refused)?,
                    disposed: count(DeliveryState::Disposed)?,
                    open_incidents: storage.open_incident_count()?,
                },
            })
        }
        Request::AuthorizeRetry {
            token,
            publisher,
            event_id,
            note,
        } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.authorize_manual_retry(
                    &publisher,
                    &event_id,
                    &grant.publisher,
                    &note,
                    current_unix_millis(),
                )
            })
        }
        Request::Dispose {
            token,
            publisher,
            event_id,
            note,
        } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.dispose_event(
                    &publisher,
                    &event_id,
                    &grant.publisher,
                    &note,
                    current_unix_millis(),
                )
            })
        }
        Request::WaivePredecessor {
            token,
            publisher,
            event_id,
            note,
        } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.waive_predecessor(
                    &publisher,
                    &event_id,
                    &grant.publisher,
                    &note,
                    current_unix_millis(),
                )
            })
        }
        Request::Evidence {
            token,
            publisher,
            event_id,
            attempt_seq,
            tier,
            detail,
        } => {
            operator(state, &token)?;
            mutate(state, |storage| {
                storage
                    .record_evidence(
                        &publisher,
                        &event_id,
                        attempt_seq,
                        tier,
                        &detail,
                        current_unix_millis(),
                    )
                    .map(|_| ())
            })
        }
        Request::TransferLineage {
            token,
            recipient,
            kind,
            mode,
            project,
            task,
            stream,
            new_publisher,
            note,
        } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.transfer_lineage(
                    &LineageScope {
                        recipient: recipient.to_canonical_string(),
                        kind,
                        mode,
                        project,
                        task,
                        stream,
                    },
                    &new_publisher,
                    &note,
                    &grant.publisher,
                    current_unix_millis(),
                )?;
                Ok(())
            })
        }
        Request::Pause {
            token,
            recipient,
            reason,
        } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.set_no_wake(
                    &recipient.to_canonical_string(),
                    true,
                    Some(&reason),
                    &grant.publisher,
                    current_unix_millis(),
                )
            })
        }
        Request::Resume { token, recipient } => {
            let grant = operator(state, &token)?;
            mutate(state, |storage| {
                storage.set_no_wake(
                    &recipient.to_canonical_string(),
                    false,
                    None,
                    &grant.publisher,
                    current_unix_millis(),
                )
            })
        }
    }
}

/// Bounds a requested listing size.
fn listing(limit: Option<usize>) -> usize {
    limit.unwrap_or(100).clamp(1, MAX_LISTING)
}

/// Runs a storage mutation under the lock after re-checking the stop flag.
fn mutate(
    state: &ServiceState,
    action: impl FnOnce(&mut Storage) -> Result<(), CoreError>,
) -> Result<Response, Refusal> {
    let mut storage = lock_storage(&state.storage);
    if !state.running.load(Ordering::SeqCst) {
        return Err(stopping());
    }
    action(&mut storage)?;
    Ok(Response::Done)
}

/// Authenticates a token to its grant; the single entry gate for every
/// operation, before validation, dedup or any status disclosure.
///
/// Every grant is compared in constant time (no early exit on the first
/// match), so timing reveals neither which grant matched nor how much of a
/// token was right.
fn authenticate<'a>(state: &'a ServiceState, token: &str) -> Result<&'a GrantConfig, Refusal> {
    state.authorizer.authenticate_legacy(token).ok_or_else(|| {
        log_event("warn", "auth_failed", &[]);
        Refusal::new("auth", "unknown or invalid grant token")
    })
}

/// Authenticates a token and requires an operator grant.
fn operator<'a>(state: &'a ServiceState, token: &str) -> Result<&'a GrantConfig, Refusal> {
    let grant = authenticate(state, token)?;
    if grant.admin {
        Ok(grant)
    } else {
        Err(Refusal::new(
            "forbidden",
            "this operation requires an operator grant",
        ))
    }
}

/// Authenticates a token and requires a publisher grant.
fn publisher<'a>(state: &'a ServiceState, token: &str) -> Result<&'a GrantConfig, Refusal> {
    let grant = authenticate(state, token)?;
    if grant.admin {
        Err(Refusal::new(
            "forbidden",
            "operator grants cannot publish or read publisher status",
        ))
    } else {
        Ok(grant)
    }
}

/// Publish flow: authenticate, authorize, stamp, validate, admit.
fn serve_publish(
    state: &ServiceState,
    token: &str,
    body: &PublishBody,
) -> Result<Response, Refusal> {
    let grant = publisher(state, token)?;

    let recipient_text = body.recipient.to_canonical_string();
    let authorize = |allowed: bool, what: &str| -> Result<(), Refusal> {
        if allowed {
            Ok(())
        } else {
            Err(Refusal::new(
                "forbidden",
                format!("grant does not allow {what}"),
            ))
        }
    };
    authorize(
        grant
            .recipients
            .iter()
            .any(|entry| entry == "*" || entry == &recipient_text),
        "this recipient",
    )?;
    authorize(
        grant.kinds.iter().any(|allowed| allowed == &body.kind),
        "this kind",
    )?;
    authorize(
        grant
            .modes
            .iter()
            .any(|allowed| allowed == body.mode.as_str()),
        "this mode",
    )?;
    authorize(
        grant
            .policies
            .iter()
            .any(|allowed| *allowed == body.policy.as_str()),
        "this policy",
    )?;

    // Bridge stamps the authenticated publisher; the body never carries one.
    let envelope = Envelope::new(
        PublisherId::new(grant.publisher.clone())?,
        EventId::new(body.event_id.clone())?,
        body.recipient.clone(),
        Kind::new(body.kind.clone())?,
        body.mode,
        body.policy.clone(),
        Payload::new(body.payload.clone())?,
        body.metadata.clone(),
        body.expires_at,
    )?;

    let mut storage = lock_storage(&state.storage);
    // The stop flag is read under the storage lock: `stop` flips it under
    // the same lock, so nothing is accepted after a stop has returned.
    if !state.running.load(Ordering::SeqCst) {
        return Err(stopping());
    }
    let outcome = storage.publish(&envelope, current_unix_millis())?;
    log_event(
        "info",
        "publish",
        &[
            ("publisher", grant.publisher.as_str()),
            ("event_id", envelope.event_id.as_str()),
            (
                "replayed",
                if outcome.receipt.replayed {
                    "true"
                } else {
                    "false"
                },
            ),
        ],
    );
    Ok(Response::Published {
        receipt: outcome.receipt,
    })
}

/// Status flow: authenticate, then disclose only the caller's own event.
fn serve_status(state: &ServiceState, token: &str, event_id: &str) -> Result<Response, Refusal> {
    let grant = publisher(state, token)?;
    let publisher_id = PublisherId::new(grant.publisher.clone())?;
    let event = EventId::new(event_id.to_string())?;
    let storage = lock_storage(&state.storage);
    let receipt = storage.lookup(&publisher_id, &event)?;
    let delivery = storage.delivery_evidence(publisher_id.as_str(), event.as_str())?;
    Ok(Response::Status {
        receipt,
        delivery: delivery.map(Box::new),
    })
}

/// The reconciliation and dispatch loop.
///
/// Once per interval (checked at a fine grain so a stop is prompt): one
/// bounded maintenance pass, then — when carriers are registered — a
/// bounded dispatch pass over a rotating window of the recipients with
/// eligible work (see [`Storage::recipients_with_work`] for what the rotation
/// does and does not promise). Failures are logged and retried next pass;
/// nothing here replays an uncertain hand-off.
fn maintenance_loop(state: &ServiceState) {
    let mut next_pass = Instant::now();
    while state.running.load(Ordering::SeqCst) {
        if Instant::now() < next_pass {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        next_pass = Instant::now() + MAINTENANCE_INTERVAL;
        // A panic in maintenance or in a carrier must not end the recovery
        // loop: it is logged and the next pass retries.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| maintenance_pass(state)))
            .is_err()
        {
            log_event("error", "maintenance_panicked", &[]);
        }
    }
}

/// One reconciliation pass followed by one dispatch pass.
fn maintenance_pass(state: &ServiceState) {
    let report = lock_storage(&state.storage).run_maintenance(current_unix_millis());
    match report {
        Ok(report) => {
            if report.unknown_handoffs + report.overdue_rechecks + report.escalated_holds > 0 {
                log_event(
                    "warn",
                    "maintenance_incidents",
                    &[
                        ("unknown_handoffs", &report.unknown_handoffs.to_string()),
                        ("overdue_rechecks", &report.overdue_rechecks.to_string()),
                        ("escalated_holds", &report.escalated_holds.to_string()),
                    ],
                );
            }
        }
        Err(error) => log_event(
            "error",
            "maintenance_failed",
            &[("error", &error.to_string())],
        ),
    }
    dispatch_pass(state);
}

/// Drives the registered carriers over one window of recipients with
/// eligible work.
///
/// The window continues after the previous pass's last recipient
/// (`dispatch_cursor`) and wraps, so recipients that stay idle (inject-only
/// work, an active auto recipient, a blocked predecessor) cannot keep a
/// younger recipient out of every window while their work stays unchanged. A carrier that panics while
/// attesting is treated as a failed attestation for that recipient only: a
/// visible hold, never an acceptance, and the remaining recipients are
/// still served.
///
/// When no carrier attests, the hold text lists every carrier's refusal
/// (each bounded, in carrier order) rather than only the last one. Nothing is
/// attempted for that recipient and nothing is guessed about what a refusal
/// means.
fn dispatch_pass(state: &ServiceState) {
    let mut carriers = state
        .carriers
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if carriers.is_empty() {
        return;
    }
    let mut cursor = state
        .dispatch_cursor
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let recipients = match lock_storage(&state.storage).recipients_with_work(
        current_unix_millis(),
        RECIPIENTS_PER_PASS,
        cursor.as_ref(),
    ) {
        Ok(recipients) => recipients,
        Err(error) => {
            log_event(
                "error",
                "dispatch_listing_failed",
                &[("error", &error.to_string())],
            );
            return;
        }
    };
    // A full window means more recipients may follow it; a short one has
    // reached the end of the order, so the next pass starts over.
    *cursor = if recipients.len() == RECIPIENTS_PER_PASS {
        recipients.last().cloned()
    } else {
        None
    };
    let timing = DispatchTiming::default();
    for recipient in recipients {
        if !state.running.load(Ordering::SeqCst) {
            return;
        }
        // Every refusing carrier's reason is kept (each bounded), in carrier
        // order, so a matching carrier's specific refusal is not hidden by a
        // later unrelated carrier's answer.
        let mut reasons: Vec<String> = Vec::new();
        let serving = carriers.iter_mut().find_map(|carrier| {
            match attest_guarded(carrier.as_mut(), &recipient) {
                Ok(_) => Some(carrier),
                Err(reason) => {
                    reasons.push(reason.chars().take(REFUSAL_REASON_CHARS).collect());
                    None
                }
            }
        });
        let Some(carrier) = serving else {
            let reason = format!("no carrier attests this endpoint: {}", reasons.join("; "));
            if let Err(error) =
                lock_storage(&state.storage).record_hold(&recipient, &reason, current_unix_millis())
            {
                log_event("error", "hold_failed", &[("error", &error.to_string())]);
            }
            continue;
        };
        for _ in 0..ATTEMPTS_PER_RECIPIENT {
            match dispatch_message(
                &state.storage,
                carrier.as_mut(),
                &recipient,
                &current_unix_millis,
                &timing,
            ) {
                Ok(DispatchReport::Sent { .. }) => {}
                Ok(DispatchReport::Idle | DispatchReport::Held(_)) => break,
                Err(error) => {
                    log_event("error", "dispatch_failed", &[("error", &error.to_string())]);
                    break;
                }
            }
        }
    }
}

/// Constant-time byte-slice equality for token comparison.
///
/// Compares every byte of both slices regardless of where they differ, so
/// timing does not leak how much of a token matched.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference: u8 = 0;
    for (l, r) in left.iter().zip(right.iter()) {
        difference |= l ^ r;
    }
    difference == 0
}

/// Current wall clock in Unix epoch milliseconds.
///
/// Single clock source for the service edge; falls back to 0 only before
/// the Unix epoch and saturates instead of wrapping far in the future.
pub fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Writes one structured JSON log line to stderr.
///
/// Fields are ordered: timestamp, level, event, then the caller's pairs.
/// Values are `&str`; secrets and token values must never be passed. A
/// write failure (closed stderr) is ignored — logging never takes the
/// service down.
pub fn log_event(level: &str, event: &str, fields: &[(&str, &str)]) {
    let mut object = serde_json::Map::new();
    object.insert("ts_ms".into(), serde_json::json!(current_unix_millis()));
    object.insert("level".into(), serde_json::json!(level));
    object.insert("event".into(), serde_json::json!(event));
    for (key, value) in fields {
        object.insert((*key).into(), serde_json::json!(value));
    }
    let mut line = serde_json::to_vec(&serde_json::Value::Object(object))
        .unwrap_or_else(|_| b"{\"level\":\"error\",\"event\":\"log_serialize_failed\"}".to_vec());
    line.push(b'\n');
    let _ = std::io::stderr().write_all(&line);
}
