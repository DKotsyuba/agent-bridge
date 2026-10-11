//! `bridge`: the operator and product CLI.
//!
//! ```text
//! bridge version
//! bridge operator <config> incidents [--all] [--limit N]
//! bridge operator <config> holds [--limit N]
//! bridge operator <config> retry <publisher> <event> --note TEXT --accept-duplicate-risk
//! bridge operator <config> dispose|waive <publisher> <event> --note TEXT
//! bridge operator <config> evidence <publisher> <event> <attempt> <tier> --detail TEXT
//! bridge operator <config> pause <recipient> --reason TEXT
//! bridge operator <config> resume <recipient>
//! bridge operator <config> shutdown
//! bridge notify <config>
//! bridge package --from DIR --out DIR
//! bridge verify <bundle> [--sums-sha256 HEX]   (attested only with the digest)
//! bridge self-install --bundle DIR --home DIR --bin-dir DIR --sums-sha256 HEX
//! bridge rollback --home DIR
//! bridge service start <core|relay> --home DIR --state DIR --config FILE
//! bridge service stop <core|relay> --home DIR --state DIR
//! bridge doctor [--home DIR] [--bin-dir DIR] [--state DIR] [--config FILE] [--daemon-config FILE]
//! ```
//!
//! Results are JSON on stdout. Exit codes: 0 success, 2 the operation or
//! a required check failed (detail on stderr), 3 invalid invocation.
//! Secrets are read only from protected files named by the configuration;
//! none is accepted as an argument or printed.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use bridge_client::{BridgeClient, NativeAddress};
use bridge_interfaces::config::{InterfacesConfig, read_secret};
use bridge_interfaces::operator::{Decision, apply, parse_tier, report};
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
        "version" => Ok((
            json!({"product": install::PRODUCT, "version": env!("CARGO_PKG_VERSION"),
                   "build_label": install::BUILD_LABEL, "target": install::target(),
                   "core_schema": bridge_core::schema::SCHEMA_VERSION}),
            0,
        )),
        "operator" => operator(args).map(|value| (value, 0)),
        "notify" => notify_command(args).map(|value| (value, 0)),
        "package" => {
            let (manifest, sums) = install::package(
                &args
                    .path("--from")
                    .ok_or(Failure::Usage("--from is required".into()))?,
                &args
                    .path("--out")
                    .ok_or(Failure::Usage("--out is required".into()))?,
            )?;
            Ok((json!({"manifest": manifest, "sums_sha256": sums}), 0))
        }
        "verify" => {
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
            let home = args
                .path("--home")
                .ok_or(Failure::Usage("--home is required".into()))?;
            Ok((json!(install::rollback(&home)?), 0))
        }
        "service" => service(args),
        "doctor" => {
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

/// `bridge operator <config> <action> …`.
fn operator(args: &Args) -> Result<Value, Failure> {
    let config = InterfacesConfig::load(&PathBuf::from(
        args.at(1, "configuration").map_err(Failure::Usage)?,
    ))?;
    let operator = config
        .operator
        .as_ref()
        .ok_or_else(|| "the configuration has no [operator] section".to_string())?;
    let token = read_secret(&operator.token_file)?;
    let mut client = BridgeClient::connect(&config.core_socket)
        .map_err(|error| format!("core unreachable: {error}"))?;
    let action = args.at(2, "operator action").map_err(Failure::Usage)?;
    let limit = args
        .optional("--limit")
        .map(|limit| limit.parse::<usize>())
        .transpose()
        .map_err(|_| Failure::Usage("--limit must be a number".into()))?;
    let failed = |error: bridge_client::ProtocolError| Failure::Failed(error.to_string());
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
    let decision = match action.as_str() {
        "incidents" => {
            let incidents = client
                .incidents(&token, args.switch("--all"), limit)
                .map_err(failed)?;
            return Ok(json!({
                "incidents": report(incidents),
                "note": "routine written_no_receipt hand-offs within their deadline are not incidents and are not listed",
            }));
        }
        "holds" => {
            return Ok(json!({"holds": client.holds(&token, limit).map_err(failed)?}));
        }
        "retry" => {
            let (publisher, event_id) = event()?;
            Decision::Retry {
                publisher,
                event_id,
                note: note()?,
                accept_duplicate_risk: args.switch("--accept-duplicate-risk"),
            }
        }
        "dispose" => {
            let (publisher, event_id) = event()?;
            Decision::Dispose {
                publisher,
                event_id,
                note: note()?,
            }
        }
        "waive" => {
            let (publisher, event_id) = event()?;
            Decision::Waive {
                publisher,
                event_id,
                note: note()?,
            }
        }
        "evidence" => {
            let (publisher, event_id) = event()?;
            Decision::Evidence {
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
            }
        }
        "pause" => Decision::Pause {
            recipient: recipient()?,
            reason: args.value("--reason").map_err(Failure::Usage)?,
        },
        "resume" => Decision::Resume {
            recipient: recipient()?,
        },
        "shutdown" => Decision::Shutdown,
        other => return Err(Failure::Usage(format!("unknown operator action {other:?}"))),
    };
    apply(&mut client, &token, &decision).map_err(failed)?;
    Ok(json!({"applied": action, "audited_by": "core operator grant"}))
}

/// `bridge notify <config>`: one owner-notification pass.
fn notify_command(args: &Args) -> Result<Value, Failure> {
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
    let limit = 200;
    let incidents = BridgeClient::connect(&config.core_socket)
        .map_err(|error| format!("core unreachable: {error}"))?
        .incidents(&token, false, Some(limit))
        .map_err(|error| error.to_string())?;
    let complete = incidents.len() < limit;
    let lines = notify::run(
        notify_config,
        &config.core_socket.display().to_string(),
        config.telegram.as_ref(),
        &telegram::CurlTransport::default(),
        &incidents,
        complete,
        bridge_core::service::current_unix_millis(),
    )?;
    Ok(json!({
        "channel": if config.telegram.is_some() { "telegram" } else { "unconfigured" },
        "incidents": lines,
    }))
}

/// `bridge service start|stop <component> …`.
fn service(args: &Args) -> Result<(Value, u8), Failure> {
    let verb = args.at(1, "start or stop").map_err(Failure::Usage)?;
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
