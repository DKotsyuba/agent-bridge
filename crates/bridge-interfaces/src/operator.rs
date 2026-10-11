//! Retained incidents and explicit manual recovery for Bridge operators.
//!
//! The operator channel: a durable store of delivery/recovery incidents
//! (reason, age, next action, responsible source, blocked dependents,
//! positive resolution) plus protected interfaces to read it and to act on
//! it. Acting on an incident is always explicit and always audited:
//! authorizing another attempt of the SAME event records the possible
//! duplicate risk, and disposing of an incident records who decided what.
//!
//! There is no automatic replay anywhere in this module. Nothing here sends
//! a message, retries a handoff or re-publicates an event; the recovery
//! records this store produces are consumed by the core dispatch layer
//! when it exists, and reporting an incident never resends the original
//! uncertain event.
//!
//! Incidents survive restarts in their own SQLite database, separate from
//! the core custody database: an incident may reference an event whose
//! custody lives in the core store, but the operator record of what was
//! seen and decided is owned here.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

/// Operator store schema version fenced by [`IncidentStore::open`].
///
/// A database whose version differs is refused rather than migrated
/// implicitly; migration is a deliberate later-task operation.
const OPERATOR_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted request line length in bytes on the operator socket.
const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// Configuration for the operator interface, usually loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Filesystem path of the operator SQLite incident database.
    pub database: PathBuf,
    /// Filesystem path of the operator Unix stream socket.
    ///
    /// Must differ from every publisher/root socket; operator tokens are a
    /// separate credential universe.
    pub socket: PathBuf,
    /// Operator bearer tokens; at least one is required to serve anything.
    #[serde(default)]
    pub tokens: Vec<String>,
}

/// One retained incident over a delivery or notification failure.
///
/// Mirrors the owner-approved recovery policy fields: what happened, why,
/// how old it is, what should happen next, who is responsible, what is
/// blocked behind it and how (if ever) it was positively resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// Monotonic incident id within this store.
    pub id: i64,
    /// Publisher of the referenced event (root interface, producer...).
    pub publisher: String,
    /// Event id within that publisher whose delivery is uncertain/failed.
    pub event_id: String,
    /// Frozen identity-content hash of the referenced envelope, if known.
    pub envelope_hash: String,
    /// Responsible source/interface that reported the incident.
    pub source: String,
    /// Classified reason (for example `possible_send` or `known_refusal`).
    pub reason: String,
    /// Human-readable detail without secrets.
    pub detail: String,
    /// Wall clock when the incident was first recorded, epoch milliseconds.
    pub created_at_ms: u64,
    /// Wall clock of the last update, epoch milliseconds.
    pub updated_at_ms: u64,
    /// The next action an operator should take.
    pub next_action: String,
    /// Optional review deadline, epoch milliseconds.
    pub review_deadline_ms: Option<u64>,
    /// References of dependent streams blocked behind this incident.
    pub blocked_dependents: Vec<String>,
    /// Lifecycle state of the incident.
    pub state: IncidentState,
}

/// Lifecycle state of an incident.
///
/// Only explicit operator actions (or new positive evidence recorded by an
/// operator) move an incident out of [`IncidentState::Open`]; time alone
/// never resolves anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    /// Retained, unresolved, visible.
    Open,
    /// Positively resolved at a declared evidence tier.
    Resolved,
    /// Audited disposition/cancellation without positive resolution.
    Disposed,
}

impl IncidentState {
    /// Storage text form.
    const fn as_str(self) -> &'static str {
        match self {
            IncidentState::Open => "open",
            IncidentState::Resolved => "resolved",
            IncidentState::Disposed => "disposed",
        }
    }

    /// Parses the storage text form; anything else is an error naming it.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "open" => Ok(IncidentState::Open),
            "resolved" => Ok(IncidentState::Resolved),
            "disposed" => Ok(IncidentState::Disposed),
            other => Err(format!("unknown incident state {other:?}")),
        }
    }
}

/// One audited recovery decision.
///
/// Every operator action on an incident produces one of these rows; the
/// audit trail is append-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    /// Monotonic audit id.
    pub id: i64,
    /// The incident this decision concerns.
    pub incident_id: i64,
    /// What was decided.
    pub action: RecoveryAction,
    /// Who decided (operator identity, from the operator token's label).
    pub actor: String,
    /// `true` whenever the decision was to attempt the same event again.
    pub possible_duplicate_risk: bool,
    /// Human-readable decision detail.
    pub detail: String,
    /// Wall clock of the decision, epoch milliseconds.
    pub created_at_ms: u64,
}

/// The audited actions an operator can take on an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Authorize another attempt of the SAME event (duplicate risk).
    AuthorizeRetry,
    /// Record positive resolution at a declared evidence tier.
    Resolve,
    /// Audited disposition/cancellation without resolution.
    Dispose,
    /// Free-form annotation, no state change.
    Note,
}

impl RecoveryAction {
    /// Storage text form.
    const fn as_str(self) -> &'static str {
        match self {
            RecoveryAction::AuthorizeRetry => "authorize_retry",
            RecoveryAction::Resolve => "resolve",
            RecoveryAction::Dispose => "dispose",
            RecoveryAction::Note => "note",
        }
    }

    /// Parses the storage/wire text form; anything else is an error.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "authorize_retry" => Ok(RecoveryAction::AuthorizeRetry),
            "resolve" => Ok(RecoveryAction::Resolve),
            "dispose" => Ok(RecoveryAction::Dispose),
            "note" => Ok(RecoveryAction::Note),
            other => Err(format!("unknown recovery action {other:?}")),
        }
    }

    /// Whether this action asks for another attempt of the same event.
    pub const fn risks_duplicate(self) -> bool {
        matches!(self, RecoveryAction::AuthorizeRetry)
    }
}

/// Input for recording (or idempotently updating) an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentInput {
    /// Publisher of the referenced event.
    pub publisher: String,
    /// Event id whose delivery is uncertain/failed.
    pub event_id: String,
    /// Frozen envelope hash, if known; empty when not.
    pub envelope_hash: String,
    /// Responsible source/interface reporting the incident.
    pub source: String,
    /// Classified reason.
    pub reason: String,
    /// Human-readable detail without secrets.
    pub detail: String,
    /// Next action for an operator.
    pub next_action: String,
    /// Optional review deadline, epoch milliseconds.
    pub review_deadline_ms: Option<u64>,
    /// Dependent stream references blocked behind this incident.
    pub blocked_dependents: Vec<String>,
}

/// The durable incident/audit store.
///
/// Owns one SQLite connection; callers coordinate threading at the
/// service layer (a `Mutex<IncidentStore>` behind the operator socket).
pub struct IncidentStore {
    connection: Connection,
}

impl IncidentStore {
    /// Opens (creating if necessary) the incident database and applies the
    /// schema fence.
    ///
    /// WAL journaling with full synchronous writes: recorded incidents and
    /// the recovery audit survive process crash and host restart. Refuses a
    /// database whose schema version differs; no implicit migration.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| error.to_string())?;
        IncidentStore { connection }.init_schema()
    }

    /// Applies the schema fence and creates tables on a fresh database.
    fn init_schema(self) -> Result<Self, String> {
        let version: u32 = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        if version != OPERATOR_SCHEMA_VERSION {
            return Err(format!(
                "operator database schema version {version} != {OPERATOR_SCHEMA_VERSION}; refusing"
            ));
        }
        Ok(self)
    }

    /// Creates a fresh incident database file with the current schema.
    ///
    /// Separated from [`IncidentStore::open`] so the fence (open) and the
    /// bootstrap (create) stay explicit; `open` refuses an empty-but-new
    /// file until this has run.
    pub fn create(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "BEGIN;
                 CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);
                 CREATE TABLE incidents (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     publisher TEXT NOT NULL,
                     event_id TEXT NOT NULL,
                     envelope_hash TEXT NOT NULL DEFAULT '',
                     source TEXT NOT NULL,
                     reason TEXT NOT NULL,
                     detail TEXT NOT NULL DEFAULT '',
                     created_at_ms INTEGER NOT NULL,
                     updated_at_ms INTEGER NOT NULL,
                     next_action TEXT NOT NULL,
                     review_deadline_ms INTEGER,
                     blocked_dependents TEXT NOT NULL DEFAULT '[]',
                     state TEXT NOT NULL
                 );
                 CREATE UNIQUE INDEX incidents_key ON incidents (publisher, event_id, reason);
                 CREATE TABLE recovery_audit (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     incident_id INTEGER NOT NULL REFERENCES incidents(id),
                     action TEXT NOT NULL,
                     actor TEXT NOT NULL,
                     possible_duplicate_risk INTEGER NOT NULL,
                     detail TEXT NOT NULL DEFAULT '',
                     created_at_ms INTEGER NOT NULL
                 );
                 COMMIT;",
            )
            .map_err(|error| error.to_string())?;
        IncidentStore { connection }.init_schema()
    }

    /// Records an incident, or idempotently refreshes the existing one.
    ///
    /// Keyed by `(publisher, event_id, reason)`: re-recording the same
    /// failure updates detail/next action/deadline/dependents and bumps
    /// `updated_at_ms` without creating a duplicate visible incident.
    /// Returns the retained incident as stored.
    pub fn record(
        &mut self,
        input: &IncidentInput,
        now_ms: u64,
    ) -> Result<Incident, String> {
        let dependents = serde_json::to_string(&input.blocked_dependents)
            .map_err(|error| error.to_string())?;
        self.connection
            .execute(
                "INSERT INTO incidents (publisher, event_id, envelope_hash, source, reason,
                                        detail, created_at_ms, updated_at_ms, next_action,
                                        review_deadline_ms, blocked_dependents, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10, 'open')
                 ON CONFLICT (publisher, event_id, reason) DO UPDATE SET
                     detail = excluded.detail,
                     updated_at_ms = excluded.updated_at_ms,
                     next_action = excluded.next_action,
                     review_deadline_ms = excluded.review_deadline_ms,
                     blocked_dependents = excluded.blocked_dependents",
                params![
                    input.publisher,
                    input.event_id,
                    input.envelope_hash,
                    input.source,
                    input.reason,
                    input.detail,
                    now_ms as i64,
                    input.next_action,
                    input.review_deadline_ms.map(|value| value as i64),
                    dependents,
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get(&input.publisher, &input.event_id, &input.reason)?
            .ok_or_else(|| "incident vanished after upsert".to_string())
    }

    /// Fetches one incident by its natural key, if present.
    fn get(
        &self,
        publisher: &str,
        event_id: &str,
        reason: &str,
    ) -> Result<Option<Incident>, String> {
        self.connection
            .query_row(
                "SELECT id, publisher, event_id, envelope_hash, source, reason, detail,
                        created_at_ms, updated_at_ms, next_action, review_deadline_ms,
                        blocked_dependents, state
                 FROM incidents WHERE publisher = ?1 AND event_id = ?2 AND reason = ?3",
                params![publisher, event_id, reason],
                incident_from_row,
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.to_string()),
            })
    }

    /// Fetches one incident by its monotonic id, if present.
    pub fn by_id(&self, id: i64) -> Result<Option<Incident>, String> {
        self.connection
            .query_row(
                "SELECT id, publisher, event_id, envelope_hash, source, reason, detail,
                        created_at_ms, updated_at_ms, next_action, review_deadline_ms,
                        blocked_dependents, state
                 FROM incidents WHERE id = ?1",
                params![id],
                incident_from_row,
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.to_string()),
            })
    }

    /// Lists incidents, newest update first, optionally filtered by state.
    pub fn list(&self, state: Option<IncidentState>) -> Result<Vec<Incident>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, publisher, event_id, envelope_hash, source, reason, detail,
                        created_at_ms, updated_at_ms, next_action, review_deadline_ms,
                        blocked_dependents, state
                 FROM incidents
                 WHERE (?1 IS NULL OR state = ?1)
                 ORDER BY updated_at_ms DESC, id DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![state.map(|value| value.as_str())], incident_from_row)
            .map_err(|error| error.to_string())?;
        let mut incidents = Vec::new();
        for row in rows {
            incidents.push(row.map_err(|error| error.to_string())?);
        }
        Ok(incidents)
    }

    /// Appends one audited decision and applies its state transition.
    ///
    /// `authorize_retry` records `possible_duplicate_risk = true` and keeps
    /// the incident open (the duplicate risk must stay visible until
    /// positively resolved). `resolve`/`dispose` close the incident; `note`
    /// annotates without changing state. Returns the audit row and the
    /// updated incident. This method never sends anything.
    pub fn decide(
        &mut self,
        incident_id: i64,
        action: RecoveryAction,
        actor: &str,
        detail: &str,
        now_ms: u64,
    ) -> Result<(RecoveryRecord, Incident), String> {
        let incident = self
            .by_id(incident_id)?
            .ok_or_else(|| format!("incident {incident_id} not found"))?;
        let new_state = match action {
            RecoveryAction::AuthorizeRetry => incident.state,
            RecoveryAction::Resolve => IncidentState::Resolved,
            RecoveryAction::Dispose => IncidentState::Disposed,
            RecoveryAction::Note => incident.state,
        };
        self.connection
            .execute(
                "UPDATE incidents SET state = ?2, updated_at_ms = ?3 WHERE id = ?1",
                params![incident_id, new_state.as_str(), now_ms as i64],
            )
            .map_err(|error| error.to_string())?;
        self.connection
            .execute(
                "INSERT INTO recovery_audit
                     (incident_id, action, actor, possible_duplicate_risk, detail, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    incident_id,
                    action.as_str(),
                    actor,
                    action.risks_duplicate(),
                    detail,
                    now_ms as i64,
                ],
            )
            .map_err(|error| error.to_string())?;
        let record_id = self.connection.last_insert_rowid();
        let record = RecoveryRecord {
            id: record_id,
            incident_id,
            action,
            actor: actor.to_string(),
            possible_duplicate_risk: action.risks_duplicate(),
            detail: detail.to_string(),
            created_at_ms: now_ms,
        };
        let updated = self
            .by_id(incident_id)?
            .ok_or_else(|| "incident vanished during decide".to_string())?;
        Ok((record, updated))
    }

    /// Lists the audit trail of one incident, oldest first.
    pub fn audit(&self, incident_id: i64) -> Result<Vec<RecoveryRecord>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, incident_id, action, actor, possible_duplicate_risk, detail,
                        created_at_ms
                 FROM recovery_audit WHERE incident_id = ?1 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![incident_id], |row| {
                Ok(RecoveryRecord {
                    id: row.get(0)?,
                    incident_id: row.get(1)?,
                    action: RecoveryAction::parse(&row.get::<_, String>(2)?)
                        .unwrap_or(RecoveryAction::Note),
                    actor: row.get(3)?,
                    possible_duplicate_risk: row.get::<_, i64>(4)? != 0,
                    detail: row.get(5)?,
                    created_at_ms: row.get::<_, i64>(6)? as u64,
                })
            })
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|error| error.to_string())?);
        }
        Ok(records)
    }
}

/// Builds an [`Incident`] from one storage row.
fn incident_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Incident> {
    let dependents: String = row.get(11)?;
    let state: String = row.get(12)?;
    Ok(Incident {
        id: row.get(0)?,
        publisher: row.get(1)?,
        event_id: row.get(2)?,
        envelope_hash: row.get(3)?,
        source: row.get(4)?,
        reason: row.get(5)?,
        detail: row.get(6)?,
        created_at_ms: row.get::<_, i64>(7)? as u64,
        updated_at_ms: row.get::<_, i64>(8)? as u64,
        next_action: row.get(9)?,
        review_deadline_ms: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
        blocked_dependents: serde_json::from_str(&dependents).unwrap_or_default(),
        state: IncidentState::parse(&state).unwrap_or(IncidentState::Open),
    })
}

/// One request line as it arrives on the operator socket.
///
/// Closed key sets are enforced per operation in [`parse_operator_request`];
/// this enum carries only already-validated shapes.
enum OperatorRequest {
    /// Record or refresh one incident.
    Record { token: String, input: IncidentInput },
    /// List incidents, optionally filtered by state.
    List { token: String, state: Option<IncidentState> },
    /// Fetch one incident with its audit trail.
    Get { token: String, incident_id: i64 },
    /// Take one audited recovery action on an incident.
    Decide {
        token: String,
        incident_id: i64,
        action: RecoveryAction,
        actor: String,
        detail: String,
    },
}

/// One response line from the operator interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorResponse {
    /// The retained incident after a record/refresh.
    Recorded { incident: Incident },
    /// The current incident list.
    Listed { incidents: Vec<Incident> },
    /// One incident with its append-only audit trail.
    Fetched {
        incident: Incident,
        audit: Vec<RecoveryRecord>,
    },
    /// The audited decision and the updated incident.
    Decided {
        record: RecoveryRecord,
        incident: Incident,
        /// Always `recorded_only` in this build: authorizations are
        /// durable records, not sends. The dispatch layer consumes them.
        execution: String,
    },
    /// Structured refusal; nothing was recorded, disclosed or decided.
    Error { class: String, detail: String },
}

/// A running operator interface bound to its socket.
///
/// Dropping the handle does not stop it; call [`OperatorRunning::shutdown`]
/// and [`OperatorRunning::join`] for a bounded, drained stop.
pub struct OperatorRunning {
    socket_path: PathBuf,
    state: Arc<OperatorState>,
    accept_thread: JoinHandle<()>,
}

/// Shared operator state behind the accept loop.
struct OperatorState {
    store: Mutex<IncidentStore>,
    tokens: Vec<String>,
    running: AtomicBool,
    socket_path: PathBuf,
}

/// Starts the operator interface on its own socket.
///
/// Fails with a human-named error string when the database cannot be
/// opened, the socket cannot be bound or no token is configured.
pub fn start(config: OperatorConfig) -> Result<OperatorRunning, String> {
    if config.tokens.is_empty() {
        return Err("operator interface requires at least one token".to_string());
    }
    let store = IncidentStore::open(&config.database)?;
    let _ = std::fs::remove_file(&config.socket);
    if let Some(parent) = config.socket.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("socket directory: {error}"))?;
    }
    let listener =
        UnixListener::bind(&config.socket).map_err(|error| format!("bind socket: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("socket non-blocking: {error}"))?;
    let state = Arc::new(OperatorState {
        store: Mutex::new(store),
        tokens: config.tokens,
        running: AtomicBool::new(true),
        socket_path: config.socket.clone(),
    });
    bridge_core::service::log_event(
        "info",
        "operator_starting",
        &[("socket", &state.socket_path.display().to_string())],
    );
    let accept_state = Arc::clone(&state);
    let accept_thread = std::thread::Builder::new()
        .name("bridge-operator-accept".into())
        .spawn(move || operator_accept_loop(listener, accept_state))
        .map_err(|error| format!("spawn accept thread: {error}"))?;
    Ok(OperatorRunning {
        socket_path: config.socket,
        state,
        accept_thread,
    })
}

impl OperatorRunning {
    /// The bound socket path for clients.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Requests a drained stop (idempotent).
    pub fn shutdown(&self) {
        self.state.running.store(false, Ordering::SeqCst);
    }

    /// Waits for the accept loop to finish; bounded by the caller.
    pub fn join(self) {
        let _ = self.accept_thread.join();
    }
}

/// Accept loop: same shape and trade-offs as the root ingress loop.
fn operator_accept_loop(listener: UnixListener, state: Arc<OperatorState>) {
    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let connection_state = Arc::clone(&state);
                let _ = std::thread::Builder::new()
                    .name("bridge-operator-connection".into())
                    .spawn(move || handle_operator_connection(stream, connection_state));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                bridge_core::service::log_event(
                    "error",
                    "operator_accept_failed",
                    &[("error", &error.to_string())],
                );
            }
        }
    }
    let _ = std::fs::remove_file(&state.socket_path);
    bridge_core::service::log_event("info", "operator_stopped", &[]);
}

/// Serves one operator connection line by line.
fn handle_operator_connection(stream: UnixStream, state: Arc<OperatorState>) {
    let _ = stream.set_nonblocking(false);
    let cloned = match stream.try_clone() {
        Ok(cloned) => cloned,
        Err(error) => {
            bridge_core::service::log_event(
                "error",
                "operator_connection_clone_failed",
                &[("error", &error.to_string())],
            );
            return;
        }
    };
    let reader = BufReader::new(cloned);
    let mut writer = stream;
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.len() > MAX_REQUEST_BYTES {
            let _ = write_operator_response(
                &mut writer,
                &operator_error("invalid", &format!("request exceeds {MAX_REQUEST_BYTES} bytes")),
            );
            continue;
        }
        let response = match parse_operator_request(&line) {
            Ok(request) => serve_operator(&state, request),
            Err(response) => Err(response),
        };
        let response = response.unwrap_or_else(|response| response);
        if write_operator_response(&mut writer, &response).is_err() {
            break;
        }
    }
}

/// Parses and closed-key-validates one operator request line.
///
/// Exact key sets per operation: unknown operations, unknown keys and
/// missing keys are refused before any typed field is read.
fn parse_operator_request(line: &str) -> Result<OperatorRequest, OperatorResponse> {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(error) => {
            return Err(operator_error(
                "unsupported",
                &format!("unparseable request: {error}"),
            ))
        }
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return Err(operator_error("unsupported", "request must be a JSON object"))
        }
    };
    let op = match object.get("op").and_then(|op| op.as_str()) {
        Some(op) => op,
        None => return Err(operator_error("unsupported", "request must carry an op")),
    };
    let base_keys = ["op", "token"];
    let allowed: &[&str] = match op {
        "record_incident" => &[
            "op",
            "token",
            "publisher",
            "event_id",
            "envelope_hash",
            "source",
            "reason",
            "detail",
            "next_action",
            "review_deadline_ms",
            "blocked_dependents",
        ],
        "list_incidents" => &["op", "token", "state"],
        "get_incident" => &["op", "token", "incident_id"],
        "decide" => &["op", "token", "incident_id", "action", "actor", "detail"],
        other => {
            return Err(operator_error(
                "unsupported",
                &format!("unknown op {other:?}"),
            ))
        }
    };
    if !base_keys.iter().all(|key| object.contains_key(key)) {
        return Err(operator_error("unsupported", &format!("op {op:?} requires a token")));
    }
    let unexpected: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unexpected.is_empty() {
        return Err(operator_error(
            "unsupported",
            &format!("closed schema: unknown keys {unexpected:?} for op {op:?}"),
        ));
    }
    let token = object
        .get("token")
        .and_then(|token| token.as_str())
        .ok_or_else(|| operator_error("invalid", "token must be a string"))?
        .to_string();
    let missing = |field: &str| operator_error("invalid", &format!("{field} is required"));
    match op {
        "record_incident" => {
            let input = IncidentInput {
                publisher: string_field(object, "publisher").ok_or_else(|| missing("publisher"))?,
                event_id: string_field(object, "event_id").ok_or_else(|| missing("event_id"))?,
                envelope_hash: string_field(object, "envelope_hash")
                    .unwrap_or_default(),
                source: string_field(object, "source").ok_or_else(|| missing("source"))?,
                reason: string_field(object, "reason").ok_or_else(|| missing("reason"))?,
                detail: string_field(object, "detail").unwrap_or_default(),
                next_action: string_field(object, "next_action")
                    .ok_or_else(|| missing("next_action"))?,
                review_deadline_ms: object
                    .get("review_deadline_ms")
                    .and_then(|value| value.as_u64()),
                blocked_dependents: object
                    .get("blocked_dependents")
                    .and_then(|value| value.as_array())
                    .map(|entries| {
                        entries
                            .iter()
                            .filter_map(|entry| entry.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            Ok(OperatorRequest::Record { token, input })
        }
        "list_incidents" => {
            let state = match object.get("state") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => {
                    let text = value
                        .as_str()
                        .ok_or_else(|| operator_error("invalid", "state must be a string"))?;
                    Some(IncidentState::parse(text).map_err(|error| operator_error("invalid", &error))?)
                }
            };
            Ok(OperatorRequest::List { token, state })
        }
        "get_incident" => {
            let incident_id = object
                .get("incident_id")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| missing("incident_id"))?;
            Ok(OperatorRequest::Get { token, incident_id })
        }
        "decide" => {
            let incident_id = object
                .get("incident_id")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| missing("incident_id"))?;
            let action = object
                .get("action")
                .and_then(|value| value.as_str())
                .and_then(|text| RecoveryAction::parse(text).map_err(|error| error).ok())
                .ok_or_else(|| {
                    operator_error(
                        "invalid",
                        "action must be one of authorize_retry/resolve/dispose/note",
                    )
                })?;
            let actor = string_field(object, "actor").unwrap_or_else(|| "operator".to_string());
            let detail = string_field(object, "detail").unwrap_or_default();
            Ok(OperatorRequest::Decide {
                token,
                incident_id,
                action,
                actor,
                detail,
            })
        }
        _ => unreachable!("op validated above"),
    }
}

/// Reads one required non-empty string field from a request object.
fn string_field(object: &serde_json::Map<String, serde_json::Value>, field: &str) -> Option<String> {
    match object.get(field) {
        Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
        _ => None,
    }
}

/// Authenticates and serves one parsed operator request.
fn serve_operator(
    state: &OperatorState,
    request: OperatorRequest,
) -> Result<OperatorResponse, OperatorResponse> {
    let token = match &request {
        OperatorRequest::Record { token, .. }
        | OperatorRequest::List { token, .. }
        | OperatorRequest::Get { token, .. }
        | OperatorRequest::Decide { token, .. } => token.as_str(),
    };
    if !state
        .tokens
        .iter()
        .any(|candidate| constant_time_eq(token.as_bytes(), candidate.as_bytes()))
    {
        bridge_core::service::log_event("warn", "operator_auth_failed", &[]);
        return Err(operator_error("auth", "unknown or invalid operator token"));
    }
    let mut store = state
        .store
        .lock()
        .map_err(|_| operator_error("internal", "store mutex poisoned"))?;
    let now_ms = current_unix_millis();
    match request {
        OperatorRequest::Record { token: _, input } => {
            let incident = store.record(&input, now_ms).map_err(|error| {
                operator_error("invalid", &format!("record incident: {error}"))
            })?;
            Ok(OperatorResponse::Recorded { incident })
        }
        OperatorRequest::List { token: _, state } => {
            let incidents = store
                .list(state)
                .map_err(|error| operator_error("internal", &format!("list incidents: {error}")))?;
            Ok(OperatorResponse::Listed { incidents })
        }
        OperatorRequest::Get { token: _, incident_id } => {
            let incident = store.by_id(incident_id).map_err(|error| {
                operator_error("internal", &format!("get incident: {error}"))
            })?;
            match incident {
                Some(incident) => {
                    let audit = store.audit(incident_id).map_err(|error| {
                        operator_error("internal", &format!("audit trail: {error}"))
                    })?;
                    Ok(OperatorResponse::Fetched { incident, audit })
                }
                None => Err(operator_error(
                    "invalid",
                    &format!("incident {incident_id} not found"),
                )),
            }
        }
        OperatorRequest::Decide {
            token: _,
            incident_id,
            action,
            actor,
            detail,
        } => {
            if action.risks_duplicate() && detail.is_empty() {
                return Err(operator_error(
                    "invalid",
                    "authorize_retry requires an explicit decision detail for the audit",
                ));
            }
            let (record, incident) = store
                .decide(incident_id, action, &actor, &detail, now_ms)
                .map_err(|error| operator_error("invalid", &format!("decide: {error}")))?;
            bridge_core::service::log_event(
                "info",
                "operator_decide",
                &[
                    ("incident_id", &incident_id.to_string()),
                    ("action", action.as_str()),
                    ("actor", &actor),
                ],
            );
            Ok(OperatorResponse::Decided {
                record,
                incident,
                execution: "recorded_only".to_string(),
            })
        }
    }
}

/// Builds the `Err` operator wire refusal.
pub(crate) fn operator_error(class: &str, detail: &str) -> OperatorResponse {
    OperatorResponse::Error {
        class: class.to_string(),
        detail: detail.to_string(),
    }
}

/// Writes one ndjson response line.
fn write_operator_response(
    stream: &mut UnixStream,
    response: &OperatorResponse,
) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

/// Current wall clock in Unix epoch milliseconds.
fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// Constant-time byte-slice equality for token comparison.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference: u8 = 0;
    for (l, r) in left.iter().zip(right) {
        difference |= l ^ r;
    }
    difference == 0
}

/// A minimal typed client for the operator interface socket.
///
/// One connection, sequential requests; used by the product CLI and tests.
#[derive(Debug)]
pub struct OperatorClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl OperatorClient {
    /// Connects to the operator interface socket.
    pub fn connect(socket: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(OperatorClient { stream, reader })
    }

    /// Performs one raw round trip with a request line already serialized.
    pub fn raw(&mut self, request_json: &str) -> std::io::Result<OperatorResponse> {
        self.stream.write_all(request_json.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        serde_json::from_str(&line)
            .map_err(|error| std::io::Error::other(format!("unparseable response: {error}")))
    }

    /// Records or refreshes one incident.
    pub fn record(&mut self, token: &str, input: &IncidentInput) -> std::io::Result<OperatorResponse> {
        let mut request = serde_json::json!({
            "op": "record_incident",
            "token": token,
            "publisher": input.publisher,
            "event_id": input.event_id,
            "envelope_hash": input.envelope_hash,
            "source": input.source,
            "reason": input.reason,
            "detail": input.detail,
            "next_action": input.next_action,
            "blocked_dependents": input.blocked_dependents,
        });
        if let Some(deadline) = input.review_deadline_ms {
            request["review_deadline_ms"] = serde_json::json!(deadline);
        }
        self.raw(&request.to_string())
    }

    /// Lists incidents, optionally filtered by state name.
    pub fn list(&mut self, token: &str, state: Option<&str>) -> std::io::Result<OperatorResponse> {
        let mut request = serde_json::json!({"op": "list_incidents", "token": token});
        if let Some(state) = state {
            request["state"] = serde_json::json!(state);
        }
        self.raw(&request.to_string())
    }

    /// Fetches one incident with its audit trail.
    pub fn get(&mut self, token: &str, incident_id: i64) -> std::io::Result<OperatorResponse> {
        self.raw(&format!(
            r#"{{"op":"get_incident","token":"{token}","incident_id":{incident_id}}}"#
        ))
    }

    /// Takes one audited recovery action on an incident.
    pub fn decide(
        &mut self,
        token: &str,
        incident_id: i64,
        action: &str,
        actor: &str,
        detail: &str,
    ) -> std::io::Result<OperatorResponse> {
        let request = serde_json::json!({
            "op": "decide",
            "token": token,
            "incident_id": incident_id,
            "action": action,
            "actor": actor,
            "detail": detail,
        });
        self.raw(&request.to_string())
    }
}
