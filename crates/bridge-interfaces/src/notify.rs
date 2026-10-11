//! Owner notification of retained incidents, with a durable ledger.
//!
//! One run reads the core's open incidents (operator grant) and reports
//! each one to the owner channel ([`crate::telegram`]) at most as the
//! ledger allows. The ledger is what keeps notifications honest:
//!
//! - a *sending* intent is written and synced **before** the request, so a
//!   crash during a send leaves `sending`, which every later run treats as
//!   a possible send — never resent automatically;
//! - `possible_send` is final for automation (the owner may have received
//!   it); `provider_accepted` is final and still not proof of reading;
//! - only known non-acceptance (`known_unsent`, including an unconfigured
//!   channel) is retried, up to `max_attempts` and after any provider
//!   rate-limit hint; then `gave_up`, visibly;
//! - an unconfigured channel never reports the owner as notified.
//!
//! Identity: the ledger is bound to one core (its socket path) and refuses
//! another; each entry records the incident's publisher, event, kind and
//! creation time, so an incident number reused by a different incident is
//! never mistaken for the one already reported (its stale entry is
//! replaced, and the run says so). An entry is pruned only on the core's own
//! closed row of the same incident, never because an incident is merely absent
//! from a (possibly capped or racing) listing.
//!
//! The CLI scans one sequence-ordered include-closed page of at most 200 rows
//! per pass with a durable finite high-water cursor ([`run_paged`]); completing
//! a scan resets it to reach new or reopened incidents next time. State is
//! live, not a snapshot. Closure is observed positively even beyond the first
//! 200 rows. Operating ceiling: there is no maximum entry count or byte bound;
//! a large/open backlog needs multiple passes and retains its entries.
//! [`Ledger::load`] reads the whole file, rewritten as pretty JSON with a
//! file and directory sync before every send and once at the end of every
//! pass. Never bound growth by forgetting a possibly sent report.
//!
//! Reporting an incident never touches the original event: no resend, no
//! retry, no permission answer. Runs are serialized by an exclusive lock
//! on `<ledger>.lock`. Ledger and lock must be private regular files of
//! this user (never links); the ledger is replaced atomically through an
//! exclusively created, unpredictable temporary file in the same
//! directory (synced, renamed, directory synced).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use bridge_client::IncidentView;
use bridge_core::recovery::IncidentState;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{NotifyConfig, TelegramConfig, open_private, private_file, random_hex};
use crate::telegram::{SendOutcome, Transport};

/// Notification state of one incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteState {
    /// A send was started and its outcome not yet recorded.
    Sending,
    /// The provider accepted the report (not proof of reading).
    ProviderAccepted,
    /// The report provably was not delivered to the provider (retryable).
    KnownUnsent,
    /// The report may have reached the provider; never resent automatically.
    PossibleSend,
    /// Known-unsent attempts are exhausted.
    GaveUp,
}

/// Ledger entry of one incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The incident this entry reports ([`incident_identity`]).
    pub identity: String,
    /// Current state.
    pub state: NoteState,
    /// Requests made so far.
    pub attempts: u32,
    /// Last change (Unix epoch ms).
    pub updated_ms: u64,
    /// Redacted detail of the last outcome.
    pub detail: String,
    /// Earliest next attempt after a rate-limit hint (Unix epoch ms).
    pub not_before_ms: Option<u64>,
}

/// The durable ledger of one core, keyed by incident number.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    /// The core this ledger belongs to (its socket path); empty until the
    /// first run binds it.
    pub backend: String,
    /// Entries by incident sequence.
    pub entries: BTreeMap<u64, Entry>,
    /// Last sequence consumed in the finite scan; zero starts a new scan.
    /// Default permits upgrading an existing ledger without forgetting sends.
    #[serde(default)]
    pub after_seq: u64,
    /// Captured inclusive high-water mark, or absent for the next fresh scan.
    #[serde(default)]
    pub through_seq: Option<u64>,
}

/// The identity of an incident beyond its number: publisher, event, kind
/// and creation time.
pub fn incident_identity(incident: &IncidentView) -> String {
    format!(
        "{}/{}/{}/{}",
        incident.publisher, incident.event_id, incident.kind, incident.created_ms
    )
}

impl Ledger {
    /// Loads the ledger; an absent file is empty. A link, foreign or
    /// group/other-accessible file, or an unreadable or corrupt one is an
    /// error (nothing may be sent without knowing past sends).
    pub fn load(path: &Path) -> Result<Ledger, String> {
        if !private_file(path)? {
            return Ok(Ledger::default());
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("notification ledger unreadable: {error}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("notification ledger is corrupt: {error}"))
    }

    /// Atomically replaces the ledger file.
    ///
    /// Writes `.<name>.<random>.tmp` in the same directory, created
    /// exclusively with mode `0600` (an existing path is never reused or
    /// followed), syncs it, renames it over `path` and syncs the directory.
    /// On failure only that temporary file is removed.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let directory = path
            .parent()
            .ok_or_else(|| "ledger path has no directory".to_string())?;
        let name = path
            .file_name()
            .ok_or_else(|| "ledger path has no file name".to_string())?
            .to_string_lossy();
        let temporary = directory.join(format!(".{name}.{}.tmp", random_hex(12)?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("cannot create ledger temporary: {error}"))?;
        let mut write = || -> std::io::Result<()> {
            file.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            File::open(directory)?.sync_all()
        };
        write().map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("cannot write notification ledger: {error}")
        })
    }
}

/// Plain-text report of one incident (bounded; never the original payload).
pub fn report_text(incident: &IncidentView) -> String {
    let (category, next_action) = crate::operator::classify(&incident.kind);
    let reason: String = incident.reason.chars().take(800).collect();
    format!(
        "Agent Bridge incident #{seq} [{category}] {kind}\nevent: {publisher}/{event}{attempt}\nreason: {reason}\nage: {age}s; blocked dependents: {blocked}\nnext: {next_action}\nThis report does not resend the original event.",
        seq = incident.incident_seq,
        kind = incident.kind,
        publisher = incident.publisher,
        event = incident.event_id,
        attempt = incident
            .attempt_seq
            .map(|attempt| format!(" attempt {attempt}"))
            .unwrap_or_default(),
        age = incident.age_ms / 1000,
        blocked = incident.blocked_dependents.len(),
    )
}

/// Runs one notification pass over `incidents` (the open incidents of
/// the core identified by `backend`).
///
/// Refuses before any send when `notify` fails [`NotifyConfig::check`], the
/// lock or ledger cannot be used, or the ledger belongs to another core.
/// `incidents` may be a capped or racing listing, so absence from it never
/// forgets a ledger entry: a possible or accepted send is pruned only on
/// positive proof that its incident is closed — a row of `closed` (incidents
/// the core reports in a state other than open) with the same incident
/// number *and* identity ([`incident_identity`]) as the entry, which is not
/// also in `incidents`. Entries without such proof are kept, so a displaced
/// open incident is never reported again. Returns one line per incident:
/// its notification state, whether a request was made in this run,
/// whether a stale entry for a reused number was replaced, and
/// `owner_read: "unknown"` (never claimed).
pub fn run(
    notify: &NotifyConfig,
    backend: &str,
    telegram: Option<&TelegramConfig>,
    transport: &dyn Transport,
    incidents: &[IncidentView],
    closed: &[IncidentView],
    now_ms: u64,
) -> Result<Vec<Value>, String> {
    let (_lock, mut ledger) = locked_ledger(notify, backend)?;
    report_page(
        notify,
        telegram,
        transport,
        incidents,
        closed,
        now_ms,
        &mut ledger,
    )
}

/// Acquires the private exclusive ledger lock and loads/binds `backend`.
/// The returned file must stay alive for the complete read/report/save pass.
/// Invalid configuration, unreadable ledger or a different core refuses
/// before any send. No caller may use an unlocked cursor or ledger snapshot.
fn locked_ledger(notify: &NotifyConfig, backend: &str) -> Result<(File, Ledger), String> {
    notify.check()?;
    let lock_path = PathBuf::from(format!("{}.lock", notify.ledger.display()));
    let lock = open_private(&lock_path).map_err(|error| format!("ledger lock: {error}"))?;
    lock.lock()
        .map_err(|error| format!("cannot lock ledger: {error}"))?;
    let mut ledger = Ledger::load(&notify.ledger)?;
    if ledger.backend.is_empty() {
        ledger.backend = backend.to_string();
    } else if ledger.backend != backend {
        return Err(
            "the notification ledger belongs to another core; use a separate ledger".into(),
        );
    }
    Ok((lock, ledger))
}

/// Consumes one protected include-closed incident page via `fetch`, invoked
/// once under the ledger lock with its durable `(after_seq, through_seq)`.
/// `fetch` must return the validated operator-client page as `(rows,
/// high_water, next_cursor)`, at most 200 rows; a provider/auth/read failure
/// is an error. The callback permits contract-faithful fixture pages while
/// production uses the typed Core client, without duplicating Core logic.
/// `backend` is the core socket identity bound to this private ledger;
/// `now_ms` is Unix epoch milliseconds for timestamps and retry scheduling.
/// `notify` supplies the protected ledger and bounded known-unsent attempts;
/// absent `telegram` reports unconfigured without calling `transport`.
/// Current rows are split into open reports and positive closed identities.
/// Only after report outcomes are durable is the next cursor saved; a crash
/// can repeat this page but never repeats a sending/possible/accepted report.
/// The final page resets the finite scan for newer/reopened rows. Returns the
/// current page's reports and cursor coverage, never a complete snapshot.
/// Read/auth/cursor/ledger failures abort; no unsafe absence pruning or send
/// occurs on a failed page read. No original event is changed by this pass.
pub fn run_paged(
    notify: &NotifyConfig,
    backend: &str,
    telegram: Option<&TelegramConfig>,
    transport: &dyn Transport,
    fetch: impl FnOnce(u64, Option<u64>) -> Result<(Vec<IncidentView>, u64, Option<u64>), String>,
    now_ms: u64,
) -> Result<Value, String> {
    let (_lock, mut ledger) = locked_ledger(notify, backend)?;
    let after_seq = ledger.after_seq;
    let (rows, through_seq, next_after_seq) = fetch(after_seq, ledger.through_seq)?;
    let (incidents, closed): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|incident| incident.state == IncidentState::Open);
    let lines = report_page(
        notify,
        telegram,
        transport,
        &incidents,
        &closed,
        now_ms,
        &mut ledger,
    )?;
    ledger.after_seq = next_after_seq.unwrap_or(0);
    ledger.through_seq = next_after_seq.map(|_| through_seq);
    ledger.save(&notify.ledger)?;
    Ok(json!({"incidents": lines, "coverage": {
        "after_seq": after_seq, "through_seq": through_seq,
        "next_after_seq": next_after_seq, "rows": incidents.len() + closed.len(),
        "limit": 200, "snapshot": false, "scan_complete": next_after_seq.is_none(),
    }}))
}

/// Updates `ledger` for the supplied authoritative open/closed rows while its
/// caller holds the exclusive lock. Preserves uncertain/accepted sends and
/// prunes only positively matching closed identities not also observed open.
/// Writes intent before any transport call and outcomes before returning.
/// Returns one honest notification status per open incident; save failures
/// stop processing and never justify a resend of a possibly sent report.
fn report_page(
    notify: &NotifyConfig,
    telegram: Option<&TelegramConfig>,
    transport: &dyn Transport,
    incidents: &[IncidentView],
    closed: &[IncidentView],
    now_ms: u64,
    ledger: &mut Ledger,
) -> Result<Vec<Value>, String> {
    for entry in ledger.entries.values_mut() {
        if entry.state == NoteState::Sending {
            entry.state = NoteState::PossibleSend;
            entry.detail = "a previous run stopped during the send".into();
        }
    }
    ledger.entries.retain(|seq, entry| {
        incidents
            .iter()
            .any(|incident| incident.incident_seq == *seq)
            || !closed.iter().any(|incident| {
                incident.incident_seq == *seq
                    && incident.state != IncidentState::Open
                    && incident_identity(incident) == entry.identity
            })
    });
    let mut lines = Vec::new();
    for incident in incidents {
        let seq = incident.incident_seq;
        let identity = incident_identity(incident);
        let mut replaced = false;
        if ledger
            .entries
            .get(&seq)
            .is_some_and(|entry| entry.identity != identity)
        {
            // The number now names a different incident: the old entry is
            // stale and must not suppress this report.
            ledger.entries.remove(&seq);
            replaced = true;
        }
        let previous = ledger.entries.get(&seq).cloned();
        let eligible = match &previous {
            None => true,
            Some(entry) => {
                entry.state == NoteState::KnownUnsent
                    && entry.attempts < notify.max_attempts
                    && entry.not_before_ms.is_none_or(|at| at <= now_ms)
            }
        };
        let mut sent_now = false;
        if eligible {
            let attempts = previous.as_ref().map_or(0, |entry| entry.attempts);
            if telegram.is_none() {
                ledger.entries.insert(
                    seq,
                    Entry {
                        identity: identity.clone(),
                        state: NoteState::KnownUnsent,
                        attempts,
                        updated_ms: now_ms,
                        detail: "owner channel unconfigured: owner not notified".into(),
                        not_before_ms: None,
                    },
                );
            } else {
                ledger.entries.insert(
                    seq,
                    Entry {
                        identity: identity.clone(),
                        state: NoteState::Sending,
                        attempts: attempts + 1,
                        updated_ms: now_ms,
                        detail: "send started".into(),
                        not_before_ms: None,
                    },
                );
                ledger.save(&notify.ledger)?;
                sent_now = true;
                let outcome = crate::telegram::send(telegram, transport, &report_text(incident));
                let (state, detail, not_before_ms) = match outcome {
                    SendOutcome::ProviderAccepted { message_id } => (
                        NoteState::ProviderAccepted,
                        format!("provider accepted (message {message_id:?}); not proof of reading"),
                        None,
                    ),
                    SendOutcome::KnownRefusal {
                        detail,
                        retry_after_ms,
                    } => (
                        NoteState::KnownUnsent,
                        detail,
                        retry_after_ms.map(|delay| now_ms.saturating_add(delay)),
                    ),
                    SendOutcome::KnownUnsent { detail } => (NoteState::KnownUnsent, detail, None),
                    SendOutcome::PossibleSend { detail } => (NoteState::PossibleSend, detail, None),
                };
                let entry = ledger.entries.get_mut(&seq).expect("inserted above");
                entry.state =
                    if state == NoteState::KnownUnsent && entry.attempts >= notify.max_attempts {
                        NoteState::GaveUp
                    } else {
                        state
                    };
                entry.detail = detail;
                entry.not_before_ms = not_before_ms;
                entry.updated_ms = now_ms;
            }
        }
        let entry = ledger.entries.get(&seq).cloned();
        lines.push(json!({
            "incident_seq": seq,
            "kind": incident.kind,
            "notification": entry.as_ref().map(|entry| entry.state),
            "attempts": entry.as_ref().map_or(0, |entry| entry.attempts),
            "detail": entry.as_ref().map(|entry| entry.detail.clone()),
            "requested_now": sent_now,
            "replaced_stale_entry": replaced,
            "owner_read": "unknown",
        }));
    }
    ledger.save(&notify.ledger)?;
    Ok(lines)
}

#[cfg(test)]
mod tests {
    //! Ledger policy with a scripted transport (no curl, no network).

    use super::*;
    use crate::telegram::TransportReply;
    use bridge_client::IncidentView;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    /// Scripted transport that counts calls.
    struct Script(RefCell<Vec<TransportReply>>, RefCell<usize>);

    impl Transport for Script {
        /// Pops the next scripted reply.
        fn post(&self, _url: &str, _body: &str, _timeout: Duration) -> TransportReply {
            *self.1.borrow_mut() += 1;
            self.0.borrow_mut().remove(0)
        }
    }

    /// A transport with replies in order.
    fn script(replies: Vec<TransportReply>) -> Script {
        Script(RefCell::new(replies), RefCell::new(0))
    }

    /// One open unknown-handoff incident.
    fn incident(seq: u64) -> IncidentView {
        serde_json::from_value(json!({
            "incident_seq": seq, "publisher": "p", "event_id": "e", "attempt_seq": 1,
            "kind": "unknown_handoff", "state": "open", "reason": "lost reply",
            "created_ms": 1, "updated_ms": 1, "age_ms": 5000, "next_check_ms": null,
            "review_deadline_ms": null, "responsible": "p/operator",
            "blocked_dependents": [], "duplicate_risk": false, "resolution": null
        }))
        .unwrap()
    }

    /// An isolated ledger directory and a protected fake token.
    struct Setup {
        /// Owned scratch directory (removed on drop).
        dir: crate::testdir::TestDir,
        /// Ledger configuration.
        notify: NotifyConfig,
        /// Channel configuration (fixed official origin; never contacted:
        /// these tests use scripted transports).
        telegram: TelegramConfig,
    }

    /// Builds a [`Setup`].
    fn setup(tag: &str) -> Setup {
        let dir = crate::testdir::TestDir::new(tag);
        let token = dir.path().join("token");
        std::fs::write(&token, "1:fake").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        Setup {
            notify: NotifyConfig {
                ledger: dir.path().join("ledger.json"),
                max_attempts: 2,
            },
            telegram: TelegramConfig {
                token_file: token,
                chat_id: "1".into(),
                api_base: crate::config::TELEGRAM_API.into(),
                timeout_ms: 1000,
            },
            dir,
        }
    }

    impl Setup {
        /// One pass for the core `core-a` with the channel configured.
        fn pass(&self, transport: &Script, incidents: &[IncidentView], now: u64) -> Vec<Value> {
            run(
                &self.notify,
                "core-a",
                Some(&self.telegram),
                transport,
                incidents,
                &[],
                now,
            )
            .unwrap()
        }
    }

    /// After an uncertain send the incident is marked `possible_send` and no
    /// second request is ever made.
    #[test]
    fn possible_send_is_never_repeated() {
        let setup = setup("possible");
        let transport = script(vec![TransportReply::Uncertain("timeout".into())]);
        let first = setup.pass(&transport, &[incident(1)], 10);
        assert_eq!(first[0]["notification"], "possible_send");
        let second = setup.pass(&transport, &[incident(1)], 20);
        assert_eq!(second[0]["requested_now"], false);
        assert_eq!(*transport.1.borrow(), 1, "exactly one request ever");
    }

    /// Faithful predeclared provider pages prove the M6 lock/cursor/outcome
    /// contract across restarts, a new high-water scan and positive closure.
    /// No Core state machine, network or native session is reimplemented.
    #[test]
    fn paged_passes_reach_new_rows_without_repeating_terminal_reports() {
        let setup = setup("pages");
        let mut ledger = Ledger {
            backend: "core-a".into(),
            ..Ledger::default()
        };
        for seq in 1..=200 {
            ledger.entries.insert(
                seq,
                Entry {
                    identity: incident_identity(&incident(seq)),
                    state: match seq % 3 {
                        0 => NoteState::Sending,
                        1 => NoteState::ProviderAccepted,
                        _ => NoteState::PossibleSend,
                    },
                    attempts: 1,
                    updated_ms: 1,
                    detail: "prior report".into(),
                    not_before_ms: None,
                },
            );
        }
        ledger.save(&setup.notify.ledger).unwrap();
        let accepted = || TransportReply::Responded {
            status: 200,
            body: r#"{"ok":true,"result":{"message_id":1}}"#.into(),
        };
        let transport = script(vec![accepted(), accepted()]);
        let first = run_paged(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            |after, through| {
                assert_eq!((after, through), (0, None));
                Ok(((1..=200).map(incident).collect(), 201, Some(200)))
            },
            10,
        )
        .unwrap();
        assert_eq!(first["coverage"]["scan_complete"], false);
        assert_eq!(*transport.1.borrow(), 0);
        let saved = Ledger::load(&setup.notify.ledger).unwrap();
        assert_eq!((saved.after_seq, saved.through_seq), (200, Some(201)));
        let second = run_paged(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            |after, through| {
                assert_eq!((after, through), (200, Some(201)));
                Ok((vec![incident(201)], 201, None))
            },
            20,
        )
        .unwrap();
        assert_eq!(second["incidents"][0]["incident_seq"], 201);
        assert_eq!(second["incidents"][0]["notification"], "provider_accepted");
        assert_eq!(*transport.1.borrow(), 1);
        let mut next_rows: Vec<_> = (1..=200).map(incident).collect();
        next_rows[0].state = IncidentState::Disposed;
        run_paged(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            |after, through| {
                assert_eq!((after, through), (0, None));
                Ok((next_rows, 202, Some(200)))
            },
            30,
        )
        .unwrap();
        let saved = Ledger::load(&setup.notify.ledger).unwrap();
        assert!(!saved.entries.contains_key(&1));
        assert!(
            saved.entries.contains_key(&201),
            "absence from this page cannot forget an accepted report"
        );
        let fourth = run_paged(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            |after, through| {
                assert_eq!((after, through), (200, Some(202)));
                Ok((vec![incident(201), incident(202)], 202, None))
            },
            40,
        )
        .unwrap();
        assert_eq!(fourth["incidents"][0]["requested_now"], false);
        assert_eq!(
            *transport.1.borrow(),
            2,
            "only new identities 201 and 202 were reported"
        );
        let saved = Ledger::load(&setup.notify.ledger).unwrap();
        assert_eq!((saved.after_seq, saved.through_seq), (0, None));
        assert_eq!(
            saved.entries[&3].state,
            NoteState::PossibleSend,
            "crash intent is never resent"
        );
        let before = std::fs::read(&setup.notify.ledger).unwrap();
        let failed = run_paged(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            |_, _| Err("operator auth/cursor/read refused".into()),
            50,
        );
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read(&setup.notify.ledger).unwrap(),
            before,
            "failed reads neither advance nor prune"
        );
        assert_eq!(*transport.1.borrow(), 2);
    }

    /// A ledger entry left in `Sending` by a crash is reported as `possible_send`
    /// without a request.
    #[test]
    fn interrupted_send_counts_as_possible_send() {
        let setup = setup("crash");
        let mut ledger = Ledger {
            backend: "core-a".into(),
            ..Ledger::default()
        };
        ledger.entries.insert(
            1,
            Entry {
                identity: incident_identity(&incident(1)),
                state: NoteState::Sending,
                attempts: 1,
                updated_ms: 1,
                detail: String::new(),
                not_before_ms: None,
            },
        );
        ledger.save(&setup.notify.ledger).unwrap();
        let transport = script(vec![]);
        let lines = setup.pass(&transport, &[incident(1)], 5);
        assert_eq!(lines[0]["notification"], "possible_send");
        assert_eq!(*transport.1.borrow(), 0);
    }

    /// Known-unsent failures are retried only up to the attempt bound and then
    /// give up; without Telegram configuration nothing is sent.
    #[test]
    fn known_unsent_retries_are_bounded_and_unconfigured_never_notifies() {
        let setup = setup("bounded");
        let unconfigured = run(
            &setup.notify,
            "core-a",
            None,
            &script(vec![]),
            &[incident(3)],
            &[],
            1,
        )
        .unwrap();
        assert_eq!(unconfigured[0]["notification"], "known_unsent");
        assert!(
            unconfigured[0]["detail"]
                .as_str()
                .unwrap()
                .contains("not notified")
        );
        let transport = script(vec![
            TransportReply::NotSent("connect refused".into()),
            TransportReply::NotSent("connect refused".into()),
        ]);
        setup.pass(&transport, &[incident(3)], 2);
        let last = setup.pass(&transport, &[incident(3)], 3);
        assert_eq!(last[0]["notification"], "gave_up");
        let after = setup.pass(&transport, &[incident(3)], 4);
        assert_eq!(after[0]["requested_now"], false);
        assert_eq!(*transport.1.borrow(), 2);
    }

    /// A provider rate-limit hint delays the retry until its deadline, after
    /// which acceptance is recorded with the owner read state unknown.
    #[test]
    fn rate_limit_hint_delays_the_retry() {
        let setup = setup("rate");
        let transport = script(vec![
            TransportReply::Responded {
                status: 429,
                body: r#"{"ok":false,"parameters":{"retry_after":10}}"#.into(),
            },
            TransportReply::Responded {
                status: 200,
                body: r#"{"ok":true,"result":{"message_id":1}}"#.into(),
            },
        ]);
        setup.pass(&transport, &[incident(4)], 1_000);
        let early = setup.pass(&transport, &[incident(4)], 5_000);
        assert_eq!(early[0]["requested_now"], false);
        let later = setup.pass(&transport, &[incident(4)], 11_000);
        assert_eq!(later[0]["notification"], "provider_accepted");
        assert_eq!(later[0]["owner_read"], "unknown");
    }

    /// A capped or racing listing that no longer shows an open incident never
    /// prunes its possible send (the incident is not resent when it shows
    /// again); only a positive closed row of the same incident does.
    #[test]
    fn absence_from_a_listing_never_prunes_a_send_but_a_closed_row_does() {
        let setup = setup("absent");
        let transport = script(vec![
            TransportReply::Uncertain("timeout".into()),
            TransportReply::Responded {
                status: 200,
                body: r#"{"ok":true,"result":{"message_id":1}}"#.into(),
            },
        ]);
        setup.pass(&transport, &[incident(7)], 100);
        let closed = |seq: u64, event: &str, state: IncidentState| {
            let mut view = incident(seq);
            view.event_id = event.into();
            view.state = state;
            view
        };
        let keeps = |closed: &[IncidentView], now: u64| {
            run(
                &setup.notify,
                "core-a",
                Some(&setup.telegram),
                &transport,
                &[],
                closed,
                now,
            )
            .unwrap();
            Ledger::load(&setup.notify.ledger)
                .unwrap()
                .entries
                .contains_key(&7)
        };
        // Incident 7 is open but displaced from a capped, racing list.
        assert!(keeps(&[], 150), "absence pruned a possible send");
        // A closed row of another incident, or of a reused number with a
        // different identity, or one that is still open, proves nothing.
        assert!(keeps(&[closed(8, "e", IncidentState::Disposed)], 160));
        assert!(keeps(&[closed(7, "other", IncidentState::Disposed)], 170));
        assert!(keeps(&[closed(7, "e", IncidentState::Open)], 180));
        let again = setup.pass(&transport, &[incident(7)], 200);
        assert_eq!(again[0]["requested_now"], false);
        assert_eq!(*transport.1.borrow(), 1, "a possible send is never resent");
        // A closed row of the very incident that is also in the open list is
        // a race, not proof.
        run(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            &[incident(7)],
            &[closed(7, "e", IncidentState::Resolved)],
            210,
        )
        .unwrap();
        assert_eq!(
            *transport.1.borrow(),
            1,
            "a raced closed row caused a resend"
        );
        assert!(keeps(&[], 220));
        // Positive proof: the same incident, closed.
        for state in [
            IncidentState::Resolved,
            IncidentState::Authorized,
            IncidentState::Disposed,
        ] {
            let mut ledger = Ledger::load(&setup.notify.ledger).unwrap();
            ledger.entries.entry(7).or_insert_with(|| Entry {
                identity: incident_identity(&incident(7)),
                state: NoteState::PossibleSend,
                attempts: 1,
                updated_ms: 1,
                detail: String::new(),
                not_before_ms: None,
            });
            ledger.save(&setup.notify.ledger).unwrap();
            assert!(!keeps(&[closed(7, "e", state)], 300), "{state:?} kept");
        }
    }

    /// A reused incident number with a different identity replaces the stale
    /// entry and is reported again, and a ledger bound to one core refuses
    /// another.
    #[test]
    fn a_reused_incident_number_is_reported_again_and_cores_are_fenced() {
        let setup = setup("identity");
        let transport = script(vec![
            TransportReply::Uncertain("timeout".into()),
            TransportReply::Uncertain("timeout".into()),
        ]);
        setup.pass(&transport, &[incident(5)], 1);
        let mut other = incident(5);
        other.event_id = "another-event".into();
        let lines = setup.pass(&transport, &[other], 2);
        assert_eq!(lines[0]["requested_now"], true, "{lines:?}");
        assert_eq!(lines[0]["replaced_stale_entry"], true);
        assert_eq!(*transport.1.borrow(), 2);
        let foreign = run(
            &setup.notify,
            "core-b",
            Some(&setup.telegram),
            &script(vec![]),
            &[incident(5)],
            &[],
            3,
        );
        assert!(foreign.is_err(), "a ledger is never shared between cores");
    }

    /// A valid ledger with no entries and no bound core.
    const EMPTY_LEDGER: &str = r#"{"backend":"","entries":{}}"#;

    /// A symlinked or shared ledger file and out-of-range attempt bounds are
    /// refused without any request.
    #[test]
    fn linked_or_shared_ledger_files_and_bad_attempt_bounds_are_refused() {
        let setup = setup("links");
        let target = setup.dir.path().join("elsewhere.json");
        // A valid empty ledger, so only the link rule can refuse it.
        std::fs::write(&target, EMPTY_LEDGER).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &setup.notify.ledger).unwrap();
        // Give the link itself private permission bits, so only the
        // file-type rule can refuse it.
        let chmod = std::process::Command::new("/bin/chmod")
            .args(["-h", "600"])
            .arg(&setup.notify.ledger)
            .status()
            .unwrap();
        assert!(chmod.success());
        let transport = script(vec![]);
        let linked = run(
            &setup.notify,
            "core-a",
            Some(&setup.telegram),
            &transport,
            &[incident(1)],
            &[],
            1,
        );
        assert!(linked.is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            EMPTY_LEDGER,
            "link target untouched"
        );
        std::fs::remove_file(&setup.notify.ledger).unwrap();
        std::fs::write(&setup.notify.ledger, EMPTY_LEDGER).unwrap();
        std::fs::set_permissions(&setup.notify.ledger, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(run(&setup.notify, "core-a", None, &transport, &[], &[], 1).is_err());
        let unbounded = NotifyConfig {
            max_attempts: 0,
            ..setup.notify.clone()
        };
        assert!(run(&unbounded, "core-a", None, &transport, &[], &[], 1).is_err());
        assert_eq!(*transport.1.borrow(), 0);
    }
}
