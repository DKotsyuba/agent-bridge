//! Diagnostics-only observations over retained metadata. Reads never run
//! maintenance, acquire delivery custody, attest a caller or expose content.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::recovery::{DeliveryState, EvidenceTier, IncidentState};
use crate::service::DeliveryCounts;
use crate::storage::{EventState, Storage, from_sql, to_sql};
use crate::{CoreError, EventId, Harness, Mode, NativeAddress, PublisherId};

/// Maximum complete encoded observer frame, including newline and envelopes.
pub const MAX_OBSERVATION_BYTES: usize = 1024 * 1024;
/// Encoded row budget per page, leaving ample room for both protocol envelopes.
pub const PAGE_ROW_BYTES: usize = 64 * 1024;
/// Maximum decoded rows per page, independent of the byte budget.
pub const MAX_PAGE_ROWS: usize = 200;

/// Empty parameters; unknown fields fail closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

/// Finite scan window. Continue only with the returned high-water and cursor.
/// Rows retain live state within each read transaction, not a scan-wide snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageParams {
    /// Row bound, default 100, accepted only in 1..=200.
    pub limit: Option<usize>,
    /// Exclusive sequence lower bound, zero for the initial page.
    #[serde(default)]
    pub after_seq: u64,
    /// Inclusive fixed high-water; required when after_seq is nonzero.
    pub through_seq: Option<u64>,
}

/// Incident scan parameters; free-text incident detail is never included.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentParams {
    /// Row bound, default 100, accepted only in 1..=200.
    pub limit: Option<usize>,
    /// Exclusive incident sequence lower bound, initially zero.
    #[serde(default)]
    pub after_seq: u64,
    /// Fixed inclusive high-water returned by the initial page.
    pub through_seq: Option<u64>,
    /// Include closed incidents, default false.
    #[serde(default)]
    pub include_closed: bool,
}

/// Closed diagnostics operation set; carries no arbitrary method or credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservationQuery {
    /// Product version and the four fixed diagnostic capabilities.
    Identity(EmptyParams),
    /// Global retained counts and storage coverage.
    Overview(EmptyParams),
    /// Content-free delivery rows in ascending acceptance order.
    Deliveries(PageParams),
    /// Content-free incidents in ascending immutable incident order.
    Incidents(IncidentParams),
}

impl ObservationQuery {
    /// Stable result kind, including when the operation fails.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Identity(_) => "identity",
            Self::Overview(_) => "bridge_overview",
            Self::Deliveries(_) => "delivery_page",
            Self::Incidents(_) => "incident_page",
        }
    }
}

/// Product identity only; no installation path, host, session or grant details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Fixed product name, agent-bridge.
    pub product: String,
    /// Compiled Bridge version.
    pub version: String,
    /// Core storage schema version.
    pub core_schema: u32,
    /// Supported fixed observer operation names.
    pub capabilities: Vec<String>,
}

/// Aggregate retention facts; does not imply native recall or full history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCounts {
    /// Retained dedup identities, including compacted rows.
    pub events: u64,
    /// Retained identities whose envelope has been compacted.
    pub payload_compacted: u64,
    /// Total stored envelope bytes, excluding SQLite/index overhead.
    pub envelope_bytes: u64,
    /// Earliest retained acceptance time in Unix ms, absent for an empty store.
    pub oldest_accepted_at_ms: Option<u64>,
    /// Latest retained acceptance time in Unix ms, absent for an empty store.
    pub newest_accepted_at_ms: Option<u64>,
}

/// Global counts observed together in one read transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overview {
    /// Existing exact per-state global counts.
    pub counts: DeliveryCounts,
    /// Envelope retention and acceptance coverage.
    pub retention: RetainedCounts,
    /// Always retained_history: no claim of complete native or product history.
    pub coverage: String,
}

/// Content-free event/delivery identity and separately retained evidence facts.
/// Acceptance and receipt possession never imply comprehension or processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryRow {
    /// Stable monotonic custody order; also the delivery page cursor.
    pub acceptance_seq: u64,
    /// Authenticated source name, never a native host or session identifier.
    pub publisher: String,
    /// Stable producer-assigned event identity, unique within publisher.
    pub event_id: String,
    /// Harness product only, stripped of native host/store/session metadata.
    pub route_name: Harness,
    /// Custody disposition, separate from native delivery.
    pub custody_state: EventState,
    /// Current delivery state, never a claim of comprehension.
    pub delivery_state: DeliveryState,
    /// Originally requested mode; not proof that any path was invoked.
    pub requested_mode: Mode,
    /// Most recent attempt identity, absent when no attempt exists.
    pub attempt_seq: Option<u64>,
    /// Consumed automatic attempt budget, not immutable attempt-history count.
    pub attempts_made: u64,
    /// Explicit retained duplicate-risk flag.
    pub duplicate_risk: bool,
    /// Earliest next automatic attempt time in Unix ms; zero means no delay.
    pub not_before_ms: u64,
    /// Original acceptance time in Unix ms.
    pub accepted_at_ms: u64,
    /// Absolute expiry in Unix ms, absent when none was declared.
    pub expires_at_ms: Option<u64>,
    /// Retained serialized envelope bytes, without its content.
    pub envelope_bytes: u64,
    /// Whether the retained envelope bytes have been compacted.
    pub payload_compacted: bool,
    /// Distinct retained evidence tiers, without notes or receipt tokens.
    pub evidence_tiers: Vec<EvidenceTier>,
}

/// Safe incident projection; deliberately excludes reasons, notes, responsible
/// text, resolutions and dependent identifiers that may contain private detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentRow {
    /// Immutable incident sequence, also the page cursor.
    pub incident_seq: u64,
    /// Authenticated event source name.
    pub publisher: String,
    /// Stable affected event identity within the publisher.
    pub event_id: String,
    /// Related attempt identity, when known.
    pub attempt_seq: Option<u64>,
    /// Current incident state; may change between scan pages.
    pub state: IncidentState,
    /// Creation time in Unix ms.
    pub created_ms: u64,
    /// Last update time in Unix ms.
    pub updated_ms: u64,
    /// Scheduled check time in Unix ms, if any.
    pub next_check_ms: Option<u64>,
    /// Review deadline in Unix ms, if any.
    pub review_deadline_ms: Option<u64>,
    /// Whether a recorded duplicate risk remains associated with this row.
    pub duplicate_risk: bool,
}

/// Delivery scan page, bounded independently by encoded bytes and row count.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryPage {
    /// Ascending acceptance sequence rows; no row is skipped by continuation.
    pub deliveries: Vec<DeliveryRow>,
    /// Fixed inclusive high-water acceptance sequence.
    pub through_seq: u64,
    /// Last emitted sequence when more rows remain, otherwise absent.
    pub next_after_seq: Option<u64>,
    /// Retained history only, including compacted identities.
    pub coverage: String,
}

/// Incident scan page with the same finite-window and byte-budget guarantees.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticIncidentPage {
    /// Ascending incident sequence rows, filtered by include_closed.
    pub incidents: Vec<IncidentRow>,
    /// Fixed inclusive high-water incident sequence.
    pub through_seq: u64,
    /// Last emitted sequence when more matching rows remain, otherwise absent.
    pub next_after_seq: Option<u64>,
    /// Retained history only; current state is live at each page read.
    pub coverage: String,
}

/// Closed, typed result. Exactly one kind and its matching data are encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub enum Observation {
    /// Product identity and fixed capabilities.
    #[serde(rename = "identity")]
    Identity(Identity),
    /// Global delivery and retention counts.
    #[serde(rename = "bridge_overview")]
    Overview(Overview),
    /// Bounded content-free delivery metadata page.
    #[serde(rename = "delivery_page")]
    Deliveries(DeliveryPage),
    /// Bounded content-free incident metadata page.
    #[serde(rename = "incident_page")]
    Incidents(DiagnosticIncidentPage),
}

impl Observation {
    /// Revalidates decoded identity, finite ranges, page order/continuation and
    /// encoded size. Remote or stored corruption returns only generic text.
    pub fn validate(&self) -> Result<(), CoreError> {
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() + 128 > MAX_OBSERVATION_BYTES {
            return Err(invalid());
        }
        match self {
            Self::Identity(view) => {
                if view.product != "agent-bridge"
                    || view.version.is_empty()
                    || view.version.len() > 64
                    || view.version.chars().any(char::is_control)
                    || view.capabilities != ["identity", "overview", "deliveries", "incidents"]
                {
                    return Err(invalid());
                }
            }
            Self::Overview(view) => {
                if view.coverage != "retained_history"
                    || view.retention.payload_compacted > view.retention.events
                {
                    return Err(invalid());
                }
                for value in [
                    view.counts.unhanded,
                    view.counts.reserved,
                    view.counts.invoking,
                    view.counts.held,
                    view.counts.review,
                    view.counts.accepted,
                    view.counts.hook_submitted,
                    view.counts.refused,
                    view.counts.disposed,
                    view.counts.open_incidents,
                    view.retention.events,
                    view.retention.payload_compacted,
                    view.retention.envelope_bytes,
                ]
                .into_iter()
                .chain(view.retention.oldest_accepted_at_ms)
                .chain(view.retention.newest_accepted_at_ms)
                {
                    to_sql(value).map_err(|_| invalid())?;
                }
            }
            Self::Deliveries(page) => {
                validate_page(
                    &page
                        .deliveries
                        .iter()
                        .map(|r| r.acceptance_seq)
                        .collect::<Vec<_>>(),
                    page.through_seq,
                    page.next_after_seq,
                    &page.coverage,
                )?;
                for row in &page.deliveries {
                    identity(&row.publisher, &row.event_id)?;
                    for value in [
                        row.attempts_made,
                        row.not_before_ms,
                        row.accepted_at_ms,
                        row.envelope_bytes,
                    ]
                    .into_iter()
                    .chain(row.attempt_seq)
                    .chain(row.expires_at_ms)
                    {
                        to_sql(value).map_err(|_| invalid())?;
                    }
                    if row.payload_compacted != (row.envelope_bytes == 0)
                        || row.evidence_tiers.len() > 10
                    {
                        return Err(invalid());
                    }
                }
            }
            Self::Incidents(page) => {
                validate_page(
                    &page
                        .incidents
                        .iter()
                        .map(|r| r.incident_seq)
                        .collect::<Vec<_>>(),
                    page.through_seq,
                    page.next_after_seq,
                    &page.coverage,
                )?;
                for row in &page.incidents {
                    identity(&row.publisher, &row.event_id)?;
                    for value in [row.created_ms, row.updated_ms]
                        .into_iter()
                        .chain(row.attempt_seq)
                        .chain(row.next_check_ms)
                        .chain(row.review_deadline_ms)
                    {
                        to_sql(value).map_err(|_| invalid())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Requires result kind and page bounds/filter/row count to match the exact
    /// query after structural validation. Credentials are never inspected.
    pub fn validate_for(&self, query: &ObservationQuery) -> Result<(), CoreError> {
        self.validate()?;
        match (self, query) {
            (Self::Identity(_), ObservationQuery::Identity(_))
            | (Self::Overview(_), ObservationQuery::Overview(_)) => Ok(()),
            (Self::Deliveries(page), ObservationQuery::Deliveries(params)) => bind_page(
                &page
                    .deliveries
                    .iter()
                    .map(|r| r.acceptance_seq)
                    .collect::<Vec<_>>(),
                page.through_seq,
                params,
            ),
            (Self::Incidents(page), ObservationQuery::Incidents(params)) => {
                if !params.include_closed
                    && page
                        .incidents
                        .iter()
                        .any(|r| r.state != IncidentState::Open)
                {
                    return Err(invalid());
                }
                bind_page(
                    &page
                        .incidents
                        .iter()
                        .map(|r| r.incident_seq)
                        .collect::<Vec<_>>(),
                    page.through_seq,
                    &PageParams {
                        limit: params.limit,
                        after_seq: params.after_seq,
                        through_seq: params.through_seq,
                    },
                )
            }
            _ => Err(invalid()),
        }
    }
}

/// Checks strict ascending positive row numbers and honest continuation shape.
fn validate_page(
    sequences: &[u64],
    through: u64,
    next: Option<u64>,
    coverage: &str,
) -> Result<(), CoreError> {
    to_sql(through).map_err(|_| invalid())?;
    if coverage != "retained_history"
        || sequences.len() > MAX_PAGE_ROWS
        || sequences.iter().any(|&seq| seq == 0 || seq > through)
        || sequences.windows(2).any(|pair| pair[0] >= pair[1])
        || next.is_some_and(|next| sequences.last() != Some(&next) || next >= through)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Binds a finite page to its requested exclusive lower and fixed upper bounds.
fn bind_page(sequences: &[u64], through: u64, params: &PageParams) -> Result<(), CoreError> {
    if sequences.len() > params.limit.unwrap_or(100)
        || through < params.after_seq
        || params
            .through_seq
            .is_some_and(|expected| expected != through)
        || sequences.iter().any(|seq| *seq <= params.after_seq)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Generic rejection text prevents corrupt store values or parser input leaks.
fn invalid() -> CoreError {
    CoreError::InvalidEnvelope("invalid diagnostic observation".into())
}

/// Parses a stored finite enum through its public wire spelling, without text
/// from the store appearing in a returned error.
fn stored<T: serde::de::DeserializeOwned>(value: String) -> Result<T, CoreError> {
    serde_json::from_value(serde_json::Value::String(value)).map_err(|_| invalid())
}

/// Validates source and event domains without exposing invalid stored text.
fn identity(publisher: &str, event: &str) -> Result<(), CoreError> {
    PublisherId::new(publisher).map_err(|_| invalid())?;
    EventId::new(event).map_err(|_| invalid())?;
    Ok(())
}

/// Validates a finite window against current retained high-water. Performs
/// only a SELECT; nonzero continuation without a high-water is refused.
fn window(
    connection: &Connection,
    sql: &str,
    params: &PageParams,
) -> Result<(u64, usize), CoreError> {
    to_sql(params.after_seq)?;
    let limit = params.limit.unwrap_or(100);
    if !(1..=MAX_PAGE_ROWS).contains(&limit)
        || (params.after_seq != 0 && params.through_seq.is_none())
    {
        return Err(invalid());
    }
    let high = from_sql(connection.query_row(sql, [], |r| r.get(0))?)?;
    let through = params.through_seq.unwrap_or(high);
    to_sql(through)?;
    if params.after_seq > through || through > high {
        return Err(invalid());
    }
    Ok((through, limit))
}

/// Adds only rows that fit the encoded row budget. Returns false without
/// consuming the row's cursor, so a following page can emit it honestly.
fn fits<T: Serialize>(row: &T, bytes: &mut usize) -> Result<bool, CoreError> {
    let size = serde_json::to_vec(row).map_err(|_| invalid())?.len() + 1;
    if *bytes + size > PAGE_ROW_BYTES {
        return Ok(false);
    }
    *bytes += size;
    Ok(true)
}

impl Storage {
    /// Runs one closed observation within a read transaction, without reading
    /// envelope content, notes, native assertions or secrets. Invalid cursors,
    /// corrupt metadata or SQL failures return errors, never partial pages.
    /// No last-seen update, settlement, incident creation or native I/O occurs.
    pub fn observe(&self, query: &ObservationQuery) -> Result<Observation, CoreError> {
        let tx = self.connection.unchecked_transaction()?;
        let result = match query {
            ObservationQuery::Identity(_) => Observation::Identity(Identity {
                product: "agent-bridge".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                core_schema: crate::schema::SCHEMA_VERSION,
                capabilities: ["identity", "overview", "deliveries", "incidents"]
                    .map(String::from)
                    .to_vec(),
            }),
            ObservationQuery::Overview(_) => Observation::Overview(self.observation_overview()?),
            ObservationQuery::Deliveries(params) => {
                Observation::Deliveries(self.observation_deliveries(params)?)
            }
            ObservationQuery::Incidents(params) => {
                Observation::Incidents(self.observation_incidents(params)?)
            }
        };
        result.validate_for(query)?;
        tx.commit()?;
        Ok(result)
    }

    /// Reads existing exact state counts and aggregate retained envelope sizes;
    /// the caller owns the read transaction and no retention work is run.
    fn observation_overview(&self) -> Result<Overview, CoreError> {
        let count = |state| self.count_delivery(state);
        let counts = DeliveryCounts {
            unhanded: count(DeliveryState::Unhanded)?,
            reserved: count(DeliveryState::Reserved)?,
            invoking: count(DeliveryState::Invoking)?,
            held: count(DeliveryState::Held)?,
            review: count(DeliveryState::Review)?,
            accepted: count(DeliveryState::Accepted)?,
            hook_submitted: count(DeliveryState::HookSubmitted)?,
            refused: count(DeliveryState::Refused)?,
            disposed: count(DeliveryState::Disposed)?,
            open_incidents: self.open_incident_count()?,
        };
        let retention = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(envelope_json)=0),0), COALESCE(SUM(length(envelope_json)),0), MIN(accepted_at_ms), MAX(accepted_at_ms) FROM events", [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?)),
        )?;
        Ok(Overview {
            counts,
            retention: RetainedCounts {
                events: from_sql(retention.0)?,
                payload_compacted: from_sql(retention.1)?,
                envelope_bytes: from_sql(retention.2)?,
                oldest_accepted_at_ms: retention.3.map(from_sql).transpose()?,
                newest_accepted_at_ms: retention.4.map(from_sql).transpose()?,
            },
            coverage: "retained_history".into(),
        })
    }

    /// Selects only event metadata and finite evidence tier names. One lookahead
    /// row detects continuation; an un-emitted row never advances the cursor.
    fn observation_deliveries(&self, page: &PageParams) -> Result<DeliveryPage, CoreError> {
        let (through_seq, limit) = window(
            &self.connection,
            "SELECT COALESCE(MAX(acceptance_seq),0) FROM events",
            page,
        )?;
        let mut statement = self.connection.prepare(
            "SELECT acceptance_seq,publisher_id,event_id,recipient,state,delivery,mode,attempt_seq,attempts_made,duplicate_risk,not_before_ms,accepted_at_ms,expires_at_ms,length(envelope_json) FROM events WHERE acceptance_seq>?1 AND acceptance_seq<=?2 ORDER BY acceptance_seq LIMIT ?3",
        )?;
        let mut rows = statement.query(params![
            to_sql(page.after_seq)?,
            to_sql(through_seq)?,
            (limit + 1) as i64
        ])?;
        let mut deliveries = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        while let Some(r) = rows.next()? {
            if deliveries.len() == limit {
                more = true;
                break;
            }
            let publisher: String = r.get(1)?;
            let event_id: String = r.get(2)?;
            identity(&publisher, &event_id)?;
            let mut evidence = self.connection.prepare("SELECT DISTINCT tier FROM evidence WHERE publisher_id=?1 AND event_id=?2 ORDER BY tier LIMIT 11")?;
            let tiers = evidence
                .query_map(params![publisher, event_id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            if tiers.len() > 10 {
                return Err(invalid());
            }
            let envelope_bytes = from_sql(r.get(13)?)?;
            let row = DeliveryRow {
                acceptance_seq: from_sql(r.get(0)?)?,
                publisher,
                event_id,
                route_name: NativeAddress::parse(&r.get::<_, String>(3)?)
                    .map_err(|_| invalid())?
                    .harness,
                custody_state: stored(r.get(4)?)?,
                delivery_state: stored(r.get(5)?)?,
                requested_mode: Mode::parse(&r.get::<_, String>(6)?).map_err(|_| invalid())?,
                attempt_seq: r.get::<_, Option<i64>>(7)?.map(from_sql).transpose()?,
                attempts_made: from_sql(r.get(8)?)?,
                duplicate_risk: r.get::<_, i64>(9)? != 0,
                not_before_ms: from_sql(r.get(10)?)?,
                accepted_at_ms: from_sql(r.get(11)?)?,
                expires_at_ms: r.get::<_, Option<i64>>(12)?.map(from_sql).transpose()?,
                envelope_bytes,
                payload_compacted: envelope_bytes == 0,
                evidence_tiers: tiers.into_iter().map(stored).collect::<Result<_, _>>()?,
            };
            if !fits(&row, &mut bytes)? {
                more = true;
                break;
            }
            deliveries.push(row);
        }
        if more && deliveries.is_empty() {
            return Err(invalid());
        }
        let next_after_seq = more.then(|| {
            deliveries
                .last()
                .expect("nonempty bounded page")
                .acceptance_seq
        });
        Ok(DeliveryPage {
            deliveries,
            through_seq,
            next_after_seq,
            coverage: "retained_history".into(),
        })
    }

    /// Selects incident identity/state/times only, never free-text diagnostic
    /// fields, and applies the same honest byte and row continuation budgets.
    fn observation_incidents(
        &self,
        page: &IncidentParams,
    ) -> Result<DiagnosticIncidentPage, CoreError> {
        let bounds = PageParams {
            limit: page.limit,
            after_seq: page.after_seq,
            through_seq: page.through_seq,
        };
        let (through_seq, limit) = window(
            &self.connection,
            "SELECT COALESCE(MAX(incident_seq),0) FROM incidents",
            &bounds,
        )?;
        let mut statement = self.connection.prepare("SELECT incident_seq,publisher_id,event_id,attempt_seq,state,created_ms,updated_ms,next_check_ms,review_deadline_ms,duplicate_risk FROM incidents WHERE incident_seq>?1 AND incident_seq<=?2 AND (?3 OR state='open') ORDER BY incident_seq LIMIT ?4")?;
        let mut rows = statement.query(params![
            to_sql(page.after_seq)?,
            to_sql(through_seq)?,
            page.include_closed,
            (limit + 1) as i64
        ])?;
        let mut incidents = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        while let Some(r) = rows.next()? {
            if incidents.len() == limit {
                more = true;
                break;
            }
            let publisher: String = r.get(1)?;
            let event_id: String = r.get(2)?;
            identity(&publisher, &event_id)?;
            let row = IncidentRow {
                incident_seq: from_sql(r.get(0)?)?,
                publisher,
                event_id,
                attempt_seq: r.get::<_, Option<i64>>(3)?.map(from_sql).transpose()?,
                state: stored(r.get(4)?)?,
                created_ms: from_sql(r.get(5)?)?,
                updated_ms: from_sql(r.get(6)?)?,
                next_check_ms: r.get::<_, Option<i64>>(7)?.map(from_sql).transpose()?,
                review_deadline_ms: r.get::<_, Option<i64>>(8)?.map(from_sql).transpose()?,
                duplicate_risk: r.get::<_, i64>(9)? != 0,
            };
            if !fits(&row, &mut bytes)? {
                more = true;
                break;
            }
            incidents.push(row);
        }
        if more && incidents.is_empty() {
            return Err(invalid());
        }
        let next_after_seq = more.then(|| {
            incidents
                .last()
                .expect("nonempty bounded page")
                .incident_seq
        });
        Ok(DiagnosticIncidentPage {
            incidents,
            through_seq,
            next_after_seq,
            coverage: "retained_history".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic in-memory projection, byte-boundary and no-write controls.
    use super::*;

    /// Exact encoded byte edges count escaping and multibyte UTF-8, and a
    /// rejected row leaves the consumed-byte total unchanged.
    #[test]
    fn encoded_byte_budget_counts_unicode_and_json_escaping() {
        let mut bytes = PAGE_ROW_BYTES - 6;
        assert!(fits(&"界", &mut bytes).unwrap());
        assert_eq!(bytes, PAGE_ROW_BYTES);
        assert!(!fits(&"", &mut bytes).unwrap());
        assert_eq!(bytes, PAGE_ROW_BYTES);
        let mut bytes = PAGE_ROW_BYTES - 4;
        assert!(!fits(&"\"", &mut bytes).unwrap());
        assert_eq!(bytes, PAGE_ROW_BYTES - 4);
    }

    /// Builds synthetic retained rows with maximal Unicode/escaped IDs and
    /// secret sentinels exclusively in fields the projection must not read.
    fn fixture() -> Storage {
        let store = Storage::open_in_memory(crate::Limits::new(1000)).unwrap();
        let source = "界".repeat(crate::MAX_FIELD_BYTES / 3);
        for seq in 1..=260_u64 {
            let event = format!(
                "{seq:04}{}",
                "\"界".repeat((crate::MAX_FIELD_BYTES - 4) / 4)
            );
            store.connection.execute("INSERT INTO events(publisher_id,event_id,envelope_hash,envelope_json,state,acceptance_seq,accepted_at_ms,recipient,mode) VALUES(?1,?2,'hash',?3,'pending',?4,1000,?5,'message')",params![source,event,b"PRIVATE_BODY_TOKEN".as_slice(),to_sql(seq).unwrap(),NativeAddress::new("PRIVATE_HOST",Harness::CODEX,"PRIVATE_STORE","PRIVATE_SESSION").unwrap().to_canonical_string()]).unwrap();
            store.connection.execute("INSERT INTO incidents(incident_seq,publisher_id,event_id,kind,reason,created_ms,updated_ms,responsible,resolution) VALUES(?1,?2,?3,'unknown_handoff','PRIVATE_REASON',1000,1000,'PRIVATE_RESPONSIBLE','PRIVATE_RESOLUTION')",params![to_sql(seq).unwrap(),source,event]).unwrap();
        }
        store
    }

    /// Both scans stop on encoded-byte boundaries before 200 rows, retain
    /// ascending identities across every page and perform no durable write.
    #[test]
    fn unicode_byte_pages_are_complete_bounded_and_read_only() {
        let store = fixture();
        let changes = store.connection.total_changes();
        for incidents in [false, true] {
            let mut after_seq = 0;
            let mut through_seq = None;
            let mut sequences = Vec::new();
            loop {
                let query = if incidents {
                    ObservationQuery::Incidents(IncidentParams {
                        limit: Some(200),
                        after_seq,
                        through_seq,
                        include_closed: true,
                    })
                } else {
                    ObservationQuery::Deliveries(PageParams {
                        limit: Some(200),
                        after_seq,
                        through_seq,
                    })
                };
                let result = store.observe(&query).unwrap();
                let encoded = serde_json::to_string(&result).unwrap();
                assert!(encoded.len() + 128 <= MAX_OBSERVATION_BYTES);
                assert!(
                    !encoded.contains("PRIVATE_"),
                    "no content, native metadata or free text"
                );
                let (seqs, high, next) = match result {
                    Observation::Deliveries(page) => (
                        page.deliveries
                            .iter()
                            .map(|r| r.acceptance_seq)
                            .collect::<Vec<_>>(),
                        page.through_seq,
                        page.next_after_seq,
                    ),
                    Observation::Incidents(page) => (
                        page.incidents
                            .iter()
                            .map(|r| r.incident_seq)
                            .collect::<Vec<_>>(),
                        page.through_seq,
                        page.next_after_seq,
                    ),
                    _ => panic!("page required"),
                };
                assert!(!seqs.is_empty());
                assert!(seqs.len() < 200, "byte budget must bind before row budget");
                assert_eq!(high, 260);
                sequences.extend(seqs);
                let Some(next) = next else { break };
                assert!(next > after_seq);
                after_seq = next;
                through_seq = Some(high);
            }
            assert_eq!(sequences, (1..=260).collect::<Vec<_>>());
        }
        let Observation::Overview(overview) = store
            .observe(&ObservationQuery::Overview(EmptyParams {}))
            .unwrap()
        else {
            panic!("overview")
        };
        assert_eq!(overview.retention.events, 260);
        assert_eq!(overview.counts.unhanded, 260);
        assert_eq!(overview.counts.open_incidents, 260);
        assert_eq!(store.connection.total_changes(), changes);
    }

    /// Empty scans end cleanly; row limits, range overflow and misbound cursors
    /// fail closed without writes. A finite high-water excludes new rows.
    #[test]
    fn scan_windows_and_row_limits_are_enforced() {
        let store = fixture();
        for page in [
            PageParams {
                limit: Some(0),
                ..Default::default()
            },
            PageParams {
                limit: Some(201),
                ..Default::default()
            },
            PageParams {
                after_seq: 1,
                ..Default::default()
            },
            PageParams {
                after_seq: 5,
                through_seq: Some(4),
                ..Default::default()
            },
            PageParams {
                through_seq: Some(261),
                ..Default::default()
            },
            PageParams {
                through_seq: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            assert!(store.observe(&ObservationQuery::Deliveries(page)).is_err());
        }
        let Observation::Deliveries(page) = store
            .observe(&ObservationQuery::Deliveries(PageParams {
                limit: Some(1),
                through_seq: Some(2),
                ..Default::default()
            }))
            .unwrap()
        else {
            panic!("page")
        };
        assert_eq!(page.deliveries.len(), 1);
        assert_eq!(page.next_after_seq, Some(1));
        assert_eq!(page.through_seq, 2);
        let empty = Storage::open_in_memory(crate::Limits::new(1)).unwrap();
        let Observation::Deliveries(page) = empty
            .observe(&ObservationQuery::Deliveries(PageParams::default()))
            .unwrap()
        else {
            panic!("page")
        };
        assert!(page.deliveries.is_empty());
        assert_eq!(page.through_seq, 0);
        assert_eq!(page.next_after_seq, None);
    }
}
