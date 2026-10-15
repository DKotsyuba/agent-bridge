//! `bridge`: the operator and product CLI.
//!
//! ```text
//! bridge version
//! bridge operator <config> incidents [--all] [--limit N]
//! bridge operator <config> holds [--limit N]
//! bridge operator <config> counts
//! bridge operator <config> retention <publisher> <event>
//! bridge operator <config> transfer-lineage --recipient ADDR --kind K --mode M --project P --task T
//!     --stream S --new-publisher ID --note TEXT     (project/task "" when undeclared)
//! bridge operator <config> retry <publisher> <event> --note TEXT --accept-duplicate-risk
//! bridge operator <config> dispose|waive <publisher> <event> --note TEXT
//! bridge operator <config> evidence <publisher> <event> <attempt> <tier> --detail TEXT
//! bridge operator <config> pause <recipient> --reason TEXT
//! bridge operator <config> resume <recipient>
//! bridge operator <config> shutdown
//! bridge notify <config>
//! bridge package --from DIR --out DIR [--plugin-dir DIR]   (OpenCode plugin source: index.js + package.json)
//! bridge verify <bundle> [--sums-sha256 HEX]   (attested only with the digest)
//! bridge self-install --bundle DIR --home DIR --bin-dir DIR --sums-sha256 HEX
//! bridge rollback --home DIR
//! bridge service start <core|relay> --home DIR --state DIR --config FILE
//! bridge service stop <core|relay> --home DIR --state DIR
//! bridge doctor [--home DIR] [--bin-dir DIR] [--state DIR] [--config FILE] [--daemon-config FILE]
//! ```
//!
//! Results are JSON on stdout. Exit codes: 0 success, 2 the operation or
//! a required check failed (detail on stderr), 3 invalid invocation (including
//! an option the command does not accept or a wrong number of positional
//! arguments, refused before any connection).
//! Secrets are read only from protected files named by the configuration;
//! none is accepted as an argument or printed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use bridge_client::{BridgeClient, LineageScope, NativeAddress};
use bridge_interfaces::config::{InterfacesConfig, read_secret};
use bridge_interfaces::operator::{
    Decision, apply, check, check_scope, failure_text, parse_tier, read_failure_text, report,
};
use bridge_interfaces::{doctor, install, lifecycle, notify, telegram};
use serde_json::{Value, json};

/// Boolean flags (no value).
const SWITCHES: [&str; 2] = ["--all", "--accept-duplicate-risk"];

/// Parsed arguments: positionals and `--flag [value]` pairs.
struct Args {
    /// Positional arguments in order.
    positional: Vec<String>,
    /// Flags; switches map to `None`.
    flags: HashMap<String, Option<String>>,
}

impl Args {
    /// Splits argv (without the program name).
    fn parse(raw: Vec<String>) -> Result<Args, String> {
        let mut positional = Vec::new();
        let mut flags = HashMap::new();
        let mut iter = raw.into_iter();
        while let Some(arg) = iter.next() {
            if arg.starts_with("--") {
                let value = if SWITCHES.contains(&arg.as_str()) {
                    None
                } else {
                    Some(iter.next().ok_or_else(|| format!("{arg} needs a value"))?)
                };
                if flags.insert(arg.clone(), value).is_some() {
                    return Err(format!("{arg} given twice"));
                }
            } else {
                positional.push(arg);
            }
        }
        Ok(Args { positional, flags })
    }

    /// A required flag value.
    fn value(&self, name: &str) -> Result<String, String> {
        self.optional(name)
            .ok_or_else(|| format!("{name} is required"))
    }

    /// An optional flag value.
    fn optional(&self, name: &str) -> Option<String> {
        self.flags.get(name).cloned().flatten()
    }

    /// An optional path flag.
    fn path(&self, name: &str) -> Option<PathBuf> {
        self.optional(name).map(PathBuf::from)
    }

    /// Whether a switch is present.
    fn switch(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    /// Requires exactly `positionals` positional arguments (command words
    /// included) and no flag outside `allowed`; a usage failure otherwise.
    /// Runs before anything is read, written or connected.
    fn closed(&self, positionals: usize, allowed: &[&str]) -> Result<(), Failure> {
        if self.positional.len() != positionals {
            return Err(Failure::Usage(format!(
                "expected {positionals} positional arguments, got {}",
                self.positional.len()
            )));
        }
        let mut unknown: Vec<&str> = self
            .flags
            .keys()
            .map(String::as_str)
            .filter(|flag| !allowed.contains(flag))
            .collect();
        unknown.sort_unstable();
        match unknown.first() {
            Some(flag) => Err(Failure::Usage(format!("unknown option {flag}"))),
            None => Ok(()),
        }
    }

    /// Positional `index`, required.
    fn at(&self, index: usize, what: &str) -> Result<String, String> {
        self.positional
            .get(index)
            .cloned()
            .ok_or_else(|| format!("missing {what}"))
    }
}

/// A command failure: usage (3) or operation (2).
enum Failure {
    /// Invalid invocation.
    Usage(String),
    /// The operation failed.
    Failed(String),
}

impl From<String> for Failure {
    /// Operation failures carry their message.
    fn from(message: String) -> Self {
        Failure::Failed(message)
    }
}

/// Entry point.
fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let outcome = Args::parse(raw)
        .map_err(Failure::Usage)
        .and_then(|args| dispatch(&args));
    match outcome {
        Ok((value, code)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
            ExitCode::from(code)
        }
        Err(Failure::Usage(message)) => {
            eprintln!("{}", json!({"error": "usage", "detail": message}));
            ExitCode::from(3)
        }
        Err(Failure::Failed(message)) => {
            eprintln!("{}", json!({"error": "failed", "detail": message}));
            ExitCode::from(2)
        }
    }
}

/// Runs one command; returns its JSON result and exit code.
fn dispatch(args: &Args) -> Result<(Value, u8), Failure> {
    let command = args.at(0, "command").map_err(Failure::Usage)?;
    match command.as_str() {
        "version" => {
            args.closed(1, &[])?;
            Ok((
                json!({"product": install::PRODUCT, "version": env!("CARGO_PKG_VERSION"),
                       "build_label": install::BUILD_LABEL, "target": install::target(),
                       "core_schema": bridge_core::schema::SCHEMA_VERSION}),
                0,
            ))
        }
        "operator" => operator(args).map(|value| (value, 0)),
        "notify" => notify_command(args).map(|value| (value, 0)),
        "package" => {
            args.closed(1, &["--from", "--out", "--plugin-dir"])?;
            let (manifest, sums) = install::package(
                &args
                    .path("--from")
                    .ok_or(Failure::Usage("--from is required".into()))?,
                &args
                    .path("--out")
                    .ok_or(Failure::Usage("--out is required".into()))?,
                args.path("--plugin-dir").as_deref(),
            )?;
            Ok((json!({"manifest": manifest, "sums_sha256": sums}), 0))
        }
        "verify" => {
            args.closed(2, &["--sums-sha256"])?;
            let bundle = PathBuf::from(args.at(1, "bundle").map_err(Failure::Usage)?);
            let manifest =
                install::verify_bundle(&bundle, args.optional("--sums-sha256").as_deref())?;
            let attested = args.optional("--sums-sha256").is_some();
            Ok((
                json!({"consistent": true, "attested": attested, "manifest": manifest}),
                0,
            ))
        }
        "self-install" => {
            args.closed(1, &["--bundle", "--home", "--bin-dir", "--sums-sha256"])?;
            let activation = install::self_install(
                &args
                    .path("--bundle")
                    .ok_or(Failure::Usage("--bundle is required".into()))?,
                &args
                    .path("--home")
                    .ok_or(Failure::Usage("--home is required".into()))?,
                &args
                    .path("--bin-dir")
                    .ok_or(Failure::Usage("--bin-dir is required".into()))?,
                &args.value("--sums-sha256").map_err(Failure::Usage)?,
            )?;
            Ok((json!(activation), 0))
        }
        "rollback" => {
            args.closed(1, &["--home"])?;
            let home = args
                .path("--home")
                .ok_or(Failure::Usage("--home is required".into()))?;
            Ok((json!(install::rollback(&home)?), 0))
        }
        "service" => service(args),
        "doctor" => {
            args.closed(
                1,
                &[
                    "--home",
                    "--bin-dir",
                    "--state",
                    "--config",
                    "--daemon-config",
                ],
            )?;
            let checks = doctor::run(&doctor::DoctorInput {
                home: args.path("--home"),
                bin_dir: args.path("--bin-dir"),
                state: args.path("--state"),
                config: args.path("--config"),
                daemon_config: args.path("--daemon-config"),
            });
            let code = doctor::exit_code(&checks);
            Ok((json!({"checks": checks}), code))
        }
        other => Err(Failure::Usage(format!("unknown command {other:?}"))),
    }
}

/// A read-only operator query.
enum Query {
    /// Retained incidents (optionally including closed ones).
    Incidents,
    /// Visible recipient holds.
    Holds,
    /// The core's complete delivery counts.
    Counts,
    /// Protected exact custody/expiry/tombstone/GC/watermark facts; no mutation.
    Retention {
        /// Exact publisher identity whose retained event is read.
        publisher: String,
        /// Immutable event id; an absent exact identity yields a null view.
        event_id: String,
    },
}

/// One parsed operator action.
enum Action {
    /// A read-only query.
    Query(Query),
    /// An audited decision.
    Decision(Decision),
}

/// The exact positional count (`operator`, the configuration, the action and
/// its operands) and the only flags `bridge operator` accepts for `action`;
/// `None` for an unknown action.
fn operator_shape(action: &str) -> Option<(usize, &'static [&'static str])> {
    Some(match action {
        "incidents" => (3, &["--all", "--limit"]),
        "holds" => (3, &["--limit"]),
        "counts" | "shutdown" => (3, &[]),
        "retention" => (5, &[]),
        "retry" => (5, &["--note", "--accept-duplicate-risk"]),
        "dispose" | "waive" => (5, &["--note"]),
        "evidence" => (7, &["--detail"]),
        "pause" => (4, &["--reason"]),
        "resume" => (4, &[]),
        "transfer-lineage" => (
            3,
            &[
                "--recipient",
                "--kind",
                "--mode",
                "--project",
                "--task",
                "--stream",
                "--new-publisher",
                "--note",
            ],
        ),
        _ => return None,
    })
}

/// `bridge operator <config> <action> …`.
///
/// The action must be known and its positional count and flags exact
/// ([`operator_shape`]), else exit 3 before anything else happens.
/// Arguments are parsed first; a decision then passes [`check`] (blank
/// notes and reasons, retry risk acceptance, lineage scope validators)
/// *before* the connection is opened, and [`apply`] repeats that check
/// before anything is written to the wire. The core validates the final
/// operator text itself before any mutation. Each decision is sent once;
/// a lost answer is reported as an unknown outcome ([`failure_text`]),
/// never resent. A failed read-only query reports unknown current data
/// ([`read_failure_text`]).
fn operator(args: &Args) -> Result<Value, Failure> {
    let config_path = PathBuf::from(args.at(1, "configuration").map_err(Failure::Usage)?);
    let action = args.at(2, "operator action").map_err(Failure::Usage)?;
    let (positionals, flags) = operator_shape(&action)
        .ok_or_else(|| Failure::Usage(format!("unknown operator action {action:?}")))?;
    args.closed(positionals, flags)?;
    let limit = args
        .optional("--limit")
        .map(|limit| limit.parse::<usize>())
        .transpose()
        .map_err(|_| Failure::Usage("--limit must be a number".into()))?;
    let note = || args.value("--note").map_err(Failure::Usage);
    let event = || -> Result<(String, String), Failure> {
        Ok((
            args.at(3, "publisher").map_err(Failure::Usage)?,
            args.at(4, "event id").map_err(Failure::Usage)?,
        ))
    };
    let recipient = || -> Result<NativeAddress, Failure> {
        NativeAddress::parse(&args.at(3, "recipient").map_err(Failure::Usage)?)
            .map_err(|error| Failure::Usage(error.to_string()))
    };
    let request = match action.as_str() {
        "incidents" => Action::Query(Query::Incidents),
        "holds" => Action::Query(Query::Holds),
        "counts" => Action::Query(Query::Counts),
        "retention" => {
            let (publisher, event_id) = event()?;
            bridge_client::PublisherId::new(publisher.clone())
                .map_err(|error| Failure::Usage(error.to_string()))?;
            bridge_client::EventId::new(event_id.clone())
                .map_err(|error| Failure::Usage(error.to_string()))?;
            Action::Query(Query::Retention {
                publisher,
                event_id,
            })
        }
        "retry" => {
            let (publisher, event_id) = event()?;
            Action::Decision(Decision::Retry {
                publisher,
                event_id,
                note: note()?,
                accept_duplicate_risk: args.switch("--accept-duplicate-risk"),
            })
        }
        "dispose" => {
            let (publisher, event_id) = event()?;
            Action::Decision(Decision::Dispose {
                publisher,
                event_id,
                note: note()?,
            })
        }
        "waive" => {
            let (publisher, event_id) = event()?;
            Action::Decision(Decision::Waive {
                publisher,
                event_id,
                note: note()?,
            })
        }
        "evidence" => {
            let (publisher, event_id) = event()?;
            Action::Decision(Decision::Evidence {
                publisher,
                event_id,
                attempt_seq: args
                    .at(5, "attempt")
                    .map_err(Failure::Usage)?
                    .parse()
                    .map_err(|_| Failure::Usage("attempt must be a number".into()))?,
                tier: parse_tier(&args.at(6, "tier").map_err(Failure::Usage)?)
                    .ok_or_else(|| Failure::Usage("unknown evidence tier".into()))?,
                detail: args.value("--detail").map_err(Failure::Usage)?,
            })
        }
        "pause" => Action::Decision(Decision::Pause {
            recipient: recipient()?,
            reason: args.value("--reason").map_err(Failure::Usage)?,
        }),
        "resume" => Action::Decision(Decision::Resume {
            recipient: recipient()?,
        }),
        "shutdown" => Action::Decision(Decision::Shutdown),
        "transfer-lineage" => {
            let flag = |name: &str| args.value(name).map_err(Failure::Usage);
            let scope = LineageScope {
                recipient: flag("--recipient")?,
                kind: flag("--kind")?,
                mode: flag("--mode")?,
                project: flag("--project")?,
                task: flag("--task")?,
                stream: flag("--stream")?,
            };
            let new_publisher = flag("--new-publisher")?;
            check_scope(&scope, &new_publisher).map_err(Failure::Usage)?;
            Action::Decision(Decision::TransferLineage {
                scope,
                new_publisher,
                note: note()?,
            })
        }
        other => return Err(Failure::Usage(format!("unknown operator action {other:?}"))),
    };
    let config = InterfacesConfig::load(&config_path)?;
    let operator = config
        .operator
        .as_ref()
        .ok_or_else(|| "the configuration has no [operator] section".to_string())?;
    let token = read_secret(&operator.token_file)?;
    let failed = |error: bridge_client::ProtocolError| Failure::Failed(failure_text(&error));
    let decision = match request {
        Action::Decision(decision) => decision,
        Action::Query(query) => {
            let read_failed =
                |error: bridge_client::ProtocolError| Failure::Failed(read_failure_text(&error));
            let mut client = BridgeClient::connect(&config.core_socket)
                .map_err(|error| format!("core unreachable: {error}"))?;
            return Ok(match query {
                Query::Incidents => json!({
                    "incidents": report(client.incidents(&token, args.switch("--all"), limit).map_err(read_failed)?),
                    "note": "a listing bounded by --limit (default 100, at most 200); use counts for totals. Routine written_no_receipt hand-offs within their deadline are not incidents.",
                }),
                Query::Holds => json!({"holds": client.holds(&token, limit).map_err(read_failed)?}),
                Query::Counts => json!({
                    "counts": client.counts(&token).map_err(read_failed)?,
                    "coverage": "complete totals computed by the core at one instant; not a sample",
                }),
                Query::Retention {
                    publisher,
                    event_id,
                } => json!({
                    "retention": client.retention(&token, &publisher, &event_id).map_err(read_failed)?,
                    "note": "exact current custody/storage facts, not native recall; expiry and compaction do not undo possible effects. GC eligibility is the storage guard, not a promise of compaction; keep-newest policy may retain bytes. Unknown identity is null.",
                }),
            });
        }
    };
    // Local rules run before the connection is opened, so a refused
    // decision never contacts the core at all.
    check(&decision).map_err(failed)?;
    let mut client = BridgeClient::connect(&config.core_socket)
        .map_err(|error| format!("core unreachable: {error}"))?;
    apply(&mut client, &token, &decision).map_err(failed)?;
    Ok(json!({"applied": action, "audited_by": "core operator grant"}))
}

/// `bridge notify <config>`: one owner-notification pass.
///
/// Consumes one include-closed page (at most 200 sequence-ordered rows) under
/// the ledger lock with a durable finite high-water cursor. Repeated passes
/// reach the rest of the scan and then new/reopened rows. Only matching
/// positive closed identities prune; missing rows never justify replay.
/// Outputs partial/live page coverage, never an immutable/complete snapshot.
fn notify_command(args: &Args) -> Result<Value, Failure> {
    args.closed(2, &[])?;
    let config = InterfacesConfig::load(&PathBuf::from(
        args.at(1, "configuration").map_err(Failure::Usage)?,
    ))?;
    let notify_config = config
        .notify
        .as_ref()
        .ok_or_else(|| "the configuration has no [notify] section".to_string())?;
    let operator = config
        .operator
        .as_ref()
        .ok_or_else(|| "the configuration has no [operator] section".to_string())?;
    let token = read_secret(&operator.token_file)?;
    let now_ms = bridge_core::service::current_unix_millis();
    let mut client = BridgeClient::connect(&config.core_socket)
        .map_err(|error| format!("core unreachable: {error}"))?;
    let mut output = notify::run_paged(
        notify_config,
        &config.core_socket.display().to_string(),
        config.telegram.as_ref(),
        &telegram::CurlTransport::default(),
        |after_seq, through_seq| {
            let page = client
                .incidents_page(&token, true, Some(200), after_seq, through_seq)
                .map_err(|error| error.to_string())?;
            Ok((page.incidents, page.through_seq, page.next_after_seq))
        },
        now_ms,
    )?;
    output["channel"] = json!(if config.telegram.is_some() {
        "telegram"
    } else {
        "unconfigured"
    });
    Ok(output)
}

/// `bridge service start|stop <component> …`.
fn service(args: &Args) -> Result<(Value, u8), Failure> {
    let verb = args.at(1, "start or stop").map_err(Failure::Usage)?;
    let allowed: &[&str] = match verb.as_str() {
        "start" => &["--home", "--state", "--config"],
        "stop" => &["--home", "--state"],
        other => return Err(Failure::Usage(format!("unknown service verb {other:?}"))),
    };
    args.closed(3, allowed)?;
    let component = lifecycle::Component::parse(&args.at(2, "component").map_err(Failure::Usage)?)
        .ok_or_else(|| Failure::Usage("component must be core or relay".into()))?;
    let state = args
        .path("--state")
        .ok_or(Failure::Usage("--state is required".into()))?;
    let home = args
        .path("--home")
        .ok_or(Failure::Usage("--home is required".into()))?;
    match verb.as_str() {
        "start" => {
            let config = args
                .path("--config")
                .ok_or(Failure::Usage("--config is required".into()))?;
            let record = lifecycle::start(&home, &state, component, &config)?;
            Ok((json!({"started": component.name(), "record": record}), 0))
        }
        "stop" => {
            let stopped = lifecycle::stop(&home, &state, component)?;
            Ok((
                json!({"component": component.name(), "stopped": stopped}),
                0,
            ))
        }
        other => Err(Failure::Usage(format!("unknown service verb {other:?}"))),
    }
}
