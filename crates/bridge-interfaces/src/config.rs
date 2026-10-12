//! Interfaces configuration and protected secret files.
//!
//! One closed TOML file configures every interface process: the root relay
//! (`[root]`), the operator CLI (`[operator]`), the outbound owner channel
//! (`[telegram]`) and its notification ledger (`[notify]`). Unknown keys
//! are refused at every level. The file holds only paths and allowlists;
//! secret values live in separate protected files ([`read_secret`]). A
//! misplaced secret could still sit in the file, so parse errors report
//! only the line, never parser text that may quote a value.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use bridge_core::{Harness, Kind, MAX_PAYLOAD_BYTES, Mode, NativeAddress};
use serde::Deserialize;

/// Largest accepted secret file, in bytes.
const MAX_SECRET_BYTES: u64 = 4096;

/// Default largest age of the hook record behind a root caller, in ms.
const DEFAULT_MAX_CALLER_AGE_MS: u64 = 10 * 60_000;

/// Default largest root `send` body, in bytes of UTF-8.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024;

/// The only accepted Telegram API origin (exact canonical form: https,
/// no user info, port, path, query or trailing slash).
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// Largest accepted Telegram request deadline, in milliseconds.
pub const MAX_TELEGRAM_TIMEOUT_MS: u64 = 120_000;

/// Largest accepted number of known-unsent attempts per incident.
pub const MAX_NOTIFY_ATTEMPTS: u32 = 10;

/// Default Telegram request deadline, in milliseconds.
const DEFAULT_TELEGRAM_TIMEOUT_MS: u64 = 15_000;

/// Default number of known-unsent owner notification attempts per incident.
const DEFAULT_NOTIFY_ATTEMPTS: u32 = 3;

/// The whole interfaces configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfacesConfig {
    /// Absolute path of the core service socket.
    pub core_socket: PathBuf,
    /// Operator CLI section; absent disables operator commands.
    #[serde(default)]
    pub operator: Option<OperatorConfig>,
    /// Root relay section; absent means the relay refuses to start.
    #[serde(default)]
    pub root: Option<RootConfig>,
    /// Outbound owner channel; absent means "unconfigured", never "notified".
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    /// Owner-notification ledger; required by `bridge notify`.
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
}

/// `[operator]`: the protected operator credential.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    /// Protected file holding the core *operator* grant token
    /// (`admin = true` in the core configuration).
    pub token_file: PathBuf,
}

/// `[root]`: the restricted root relay.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// Relay socket path; its directory must be private (0700, owner).
    pub socket: PathBuf,
    /// Protected file holding the relay's core *publisher* grant token.
    pub token_file: PathBuf,
    /// Adapter channel socket used to redeem sealed caller proofs. Absent:
    /// no attestation provider, so every request refuses
    /// (`caller_unattested`); there is no configured-address fallback.
    #[serde(default)]
    pub channel: Option<PathBuf>,
    /// Largest age of the hook record behind a caller, in milliseconds.
    #[serde(default = "default_caller_age")]
    pub max_caller_age_ms: u64,
    /// Largest root `send` body, in bytes (at most the core payload bound).
    #[serde(default = "default_body_bytes")]
    pub max_body_bytes: usize,
    /// Root callers and what each may send; at least one entry.
    pub callers: Vec<CallerPolicy>,
}

/// One root caller scope and its exact or any-address send policy.
///
/// A caller matches when its attested address has these host, harness and
/// store components and, when `native_session_id` is set, exactly that
/// session. Only attested *root* actors acting as their own address ever
/// match (enforced by the relay, not by this entry).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerPolicy {
    /// `host_id` of the caller address.
    pub host_id: String,
    /// Harness wire name (`codex` or `claude-code`).
    pub harness: String,
    /// Native store namespace of the caller address.
    pub native_store_namespace: String,
    /// Exact caller session; absent matches any root session of the store.
    #[serde(default)]
    pub native_session_id: Option<String>,
    /// Canonical recipient addresses this caller may send to; `"*"` permits
    /// every well-formed address, retaining native dispatch qualification.
    pub recipients: Vec<String>,
    /// Delivery modes this caller may request (`inject`, `message`, `auto`).
    pub modes: Vec<String>,
    /// Event kinds this caller may send.
    pub kinds: Vec<String>,
}

/// `[telegram]`: the fixed owner destination.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    /// Protected file holding the bot token.
    pub token_file: PathBuf,
    /// The one fixed destination chat id; never caller-supplied.
    pub chat_id: String,
    /// API origin; must equal [`TELEGRAM_API`] exactly.
    #[serde(default = "default_api")]
    pub api_base: String,
    /// Whole-request deadline in milliseconds, `1..=MAX_TELEGRAM_TIMEOUT_MS`.
    #[serde(default = "default_telegram_timeout")]
    pub timeout_ms: u64,
}

/// `[notify]`: the owner-notification ledger.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// Ledger file (created 0600; its directory must exist).
    pub ledger: PathBuf,
    /// Known-unsent attempts allowed per incident before giving up,
    /// `1..=MAX_NOTIFY_ATTEMPTS`.
    #[serde(default = "default_notify_attempts")]
    pub max_attempts: u32,
}

/// Serde default for [`RootConfig::max_caller_age_ms`].
fn default_caller_age() -> u64 {
    DEFAULT_MAX_CALLER_AGE_MS
}

/// Serde default for [`RootConfig::max_body_bytes`].
fn default_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

/// Serde default for [`TelegramConfig::api_base`].
fn default_api() -> String {
    TELEGRAM_API.into()
}

/// Serde default for [`TelegramConfig::timeout_ms`].
fn default_telegram_timeout() -> u64 {
    DEFAULT_TELEGRAM_TIMEOUT_MS
}

/// Serde default for [`NotifyConfig::max_attempts`].
fn default_notify_attempts() -> u32 {
    DEFAULT_NOTIFY_ATTEMPTS
}

impl InterfacesConfig {
    /// Reads, parses and validates a configuration file.
    ///
    /// A syntax or schema error reports only its line: parser messages can
    /// quote values, and a misplaced secret must never be echoed. Rule
    /// violations are fixed texts from [`InterfacesConfig::validate`].
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let config: InterfacesConfig = toml::from_str(&text).map_err(|error| {
            let line = error
                .span()
                .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
            match line {
                Some(line) => {
                    format!("invalid configuration at line {line} (parser detail withheld)")
                }
                None => "invalid configuration (parser detail withheld)".to_string(),
            }
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Checks every rule the processes rely on.
    ///
    /// All paths must be absolute; root callers must name a known harness,
    /// valid address components, canonical recipients, known modes and
    /// valid kinds, with no two entries for the same scope; the body bound
    /// must be within `1..=MAX_PAYLOAD_BYTES`; `[telegram]` and `[notify]`
    /// follow [`TelegramConfig::check`] and [`NotifyConfig::check`]. Error
    /// texts are fixed and never quote configured values.
    pub fn validate(&self) -> Result<(), String> {
        absolute("core_socket", &self.core_socket)?;
        if let Some(operator) = &self.operator {
            absolute("operator.token_file", &operator.token_file)?;
        }
        if let Some(root) = &self.root {
            absolute("root.socket", &root.socket)?;
            absolute("root.token_file", &root.token_file)?;
            if let Some(channel) = &root.channel {
                absolute("root.channel", channel)?;
            }
            if root.max_body_bytes == 0 || root.max_body_bytes > MAX_PAYLOAD_BYTES {
                return Err(format!(
                    "root.max_body_bytes must be within 1..={MAX_PAYLOAD_BYTES}"
                ));
            }
            if root.callers.is_empty() {
                return Err("root.callers must name at least one caller scope".into());
            }
            let mut scopes = Vec::new();
            for caller in &root.callers {
                let scope = caller.scope()?;
                if scopes.contains(&scope) {
                    return Err("two root.callers entries share one scope".into());
                }
                scopes.push(scope);
                caller.canonical_recipients()?;
                for mode in &caller.modes {
                    Mode::parse(mode).map_err(|_| "root.callers: invalid mode".to_string())?;
                }
                for kind in &caller.kinds {
                    Kind::new(kind.clone())
                        .map_err(|_| "root.callers: invalid kind".to_string())?;
                }
            }
        }
        if let Some(telegram) = &self.telegram {
            telegram.check()?;
        }
        if let Some(notify) = &self.notify {
            notify.check()?;
        }
        Ok(())
    }
}

impl CallerPolicy {
    /// The validated scope `(host, harness, namespace, session)`.
    ///
    /// Components follow the core address rules (validated by building a
    /// probe address); the harness must be a canonical wire name.
    pub fn scope(&self) -> Result<(String, Harness, String, Option<String>), String> {
        let harness = Harness::parse(&self.harness)
            .map_err(|_| "root.callers: unknown harness".to_string())?;
        NativeAddress::new(
            self.host_id.clone(),
            harness,
            self.native_store_namespace.clone(),
            self.native_session_id
                .clone()
                .unwrap_or_else(|| "probe".into()),
        )
        .map_err(|_| "root.callers: invalid address component".to_string())?;
        Ok((
            self.host_id.clone(),
            harness,
            self.native_store_namespace.clone(),
            self.native_session_id.clone(),
        ))
    }

    /// Whether `address` falls in this scope.
    pub fn matches(&self, address: &NativeAddress) -> bool {
        self.host_id == address.host_id
            && self.harness == address.harness.as_str()
            && self.native_store_namespace == address.native_store_namespace
            && self
                .native_session_id
                .as_ref()
                .is_none_or(|session| *session == address.native_session_id)
    }

    /// The recipient allowlist in canonical form. A literal `"*"` is kept as
    /// the explicit any-address policy; every other entry is parsed and
    /// re-rendered, and malformed addresses or wildcard patterns refuse.
    pub fn canonical_recipients(&self) -> Result<Vec<String>, String> {
        self.recipients
            .iter()
            .map(|recipient| {
                if recipient == "*" {
                    Ok("*".to_string())
                } else {
                    NativeAddress::parse(recipient)
                        .map(|address| address.to_canonical_string())
                        .map_err(|_| "root.callers: invalid recipient address".to_string())
                }
            })
            .collect()
    }
}

impl TelegramConfig {
    /// Checks the fixed-destination contract before any token read or
    /// request: absolute token file, `api_base` exactly [`TELEGRAM_API`]
    /// (no other host, scheme, user info, port, path, query or trailing
    /// slash), a bounded non-zero deadline (`curl --max-time 0` would be
    /// unbounded) and a chat id that is a signed decimal number (at most 20
    /// digits) or a public `@username` (5–32 of `[A-Za-z0-9_]`). Errors are
    /// fixed texts.
    pub fn check(&self) -> Result<(), String> {
        absolute("telegram.token_file", &self.token_file)?;
        if self.api_base != TELEGRAM_API {
            return Err(format!("telegram.api_base must be exactly {TELEGRAM_API}"));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TELEGRAM_TIMEOUT_MS {
            return Err(format!(
                "telegram.timeout_ms must be within 1..={MAX_TELEGRAM_TIMEOUT_MS}"
            ));
        }
        let digits = self.chat_id.strip_prefix('-').unwrap_or(&self.chat_id);
        let numeric =
            (1..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit());
        let username = self.chat_id.strip_prefix('@').is_some_and(|name| {
            (5..=32).contains(&name.len())
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
        if !(numeric || username) {
            return Err("telegram.chat_id must be a numeric chat id or @username".into());
        }
        Ok(())
    }
}

impl NotifyConfig {
    /// Checks an absolute ledger path and `1..=MAX_NOTIFY_ATTEMPTS`
    /// attempts. Errors are fixed texts.
    pub fn check(&self) -> Result<(), String> {
        absolute("notify.ledger", &self.ledger)?;
        if self.max_attempts == 0 || self.max_attempts > MAX_NOTIFY_ATTEMPTS {
            return Err(format!(
                "notify.max_attempts must be within 1..={MAX_NOTIFY_ATTEMPTS}"
            ));
        }
        Ok(())
    }
}

/// Refuses a relative configured path.
fn absolute(field: &str, path: &Path) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!("{field} must be an absolute path"))
    }
}

/// The effective user id of this process, from the kernel's process facts.
pub fn own_uid() -> Result<u32, String> {
    bridge_adapters::os::process_facts(std::process::id())
        .and_then(|facts| facts.uid)
        .ok_or_else(|| "own uid unreadable".to_string())
}

/// Reads one secret from a protected file.
///
/// The file must be a regular file (not a symlink), owned by this user,
/// with no group or other permission bits, non-empty after trimming and at
/// most 4 KiB. The value is returned trimmed and must never be logged,
/// echoed, put in argv or serialized. Errors name the path and the broken
/// rule, never any content.
pub fn read_secret(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("secret {shown}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("secret {shown} is not a regular file"));
    }
    if metadata.uid() != own_uid()? || metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "secret {shown} must be owned by this user with mode 0600"
        ));
    }
    if metadata.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "secret {shown} is larger than {MAX_SECRET_BYTES} bytes"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|error| format!("secret {shown}: {error}"))?;
    let value = text.trim();
    if value.is_empty() {
        return Err(format!("secret {shown} is empty"));
    }
    Ok(value.to_string())
}

/// Whether `path` currently is a Unix socket (without following links).
pub fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

/// Lowercase hex of `bytes` (at most 32) kernel random bytes, for
/// unpredictable temporary names.
pub(crate) fn random_hex(bytes: usize) -> Result<String, String> {
    let random = bridge_adapters::os::random_bytes().map_err(|error| error.to_string())?;
    Ok(random[..bytes.min(random.len())]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Checks an existing path is a private regular file of this user (not a
/// link, no group or other permission bits); `Ok(false)` when absent.
pub(crate) fn private_file(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == own_uid()?
                && metadata.mode() & 0o077 == 0 =>
        {
            Ok(true)
        }
        Ok(_) => Err(format!(
            "{} must be a regular file owned by this user with mode 0600",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Opens a private file for writing without truncating it, creating it
/// exclusively with mode `0600` when absent ([`private_file`] rules for an
/// existing one; the opened handle is re-checked).
pub(crate) fn open_private(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let open = |create: bool| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(create)
            .mode(0o600)
            .open(path)
    };
    let file = match open(!private_file(path)?) {
        // Another process created it between the check and the open:
        // check what is there now and open it without creating.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            private_file(path)?;
            open(false)
        }
        other => other,
    }
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.uid() != own_uid()? || metadata.mode() & 0o077 != 0 {
        return Err(format!("{} is not a private regular file", path.display()));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    //! Configuration and secret-file rules.

    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A minimal valid configuration text with one root caller.
    fn sample(extra: &str) -> String {
        format!(
            r#"core_socket = "/tmp/core.sock"
[root]
socket = "/tmp/r/relay.sock"
token_file = "/tmp/r/token"
[[root.callers]]
host_id = "h"
harness = "claude-code"
native_store_namespace = "ns"
recipients = ["h/codex/ns2/t1"]
modes = ["message"]
kinds = ["root.note"]
{extra}"#
        )
    }

    /// The schema is closed (unknown keys fail), and a plain-http or
    /// relative-path setting fails validation.
    #[test]
    fn closed_schema_and_rules() {
        let config: InterfacesConfig = toml::from_str(&sample("")).unwrap();
        config.validate().unwrap();
        assert!(toml::from_str::<InterfacesConfig>(&sample("surprise = 1")).is_err());
        let bad: InterfacesConfig = toml::from_str(&sample(
            "[telegram]\ntoken_file = \"/t\"\nchat_id = \"1\"\napi_base = \"http://x\"",
        ))
        .unwrap();
        assert!(bad.validate().is_err(), "plain http origin refused");
        let relative = sample("").replace("/tmp/core.sock", "core.sock");
        let relative: InterfacesConfig = toml::from_str(&relative).unwrap();
        assert!(relative.validate().is_err());
    }

    /// A valid fixed-destination Telegram section.
    fn telegram() -> TelegramConfig {
        TelegramConfig {
            token_file: "/t".into(),
            chat_id: "-1001234".into(),
            api_base: TELEGRAM_API.into(),
            timeout_ms: 15_000,
        }
    }

    /// Only the exact official Telegram origin, a bounded timeout, a numeric or
    /// `@name` chat id and bounded notify attempts validate.
    #[test]
    fn only_the_official_origin_and_bounded_deadlines_are_accepted() {
        telegram().check().unwrap();
        for origin in [
            "https://api.telegram.org/",
            "https://api.telegram.org:443",
            "https://user:pw@api.telegram.org",
            "https://api.telegram.org/x",
            "https://api.telegram.org\nurl = \"https://evil\"",
            "https://evil.example",
            "http://api.telegram.org",
            "HTTPS://API.TELEGRAM.ORG",
        ] {
            let config = TelegramConfig {
                api_base: origin.into(),
                ..telegram()
            };
            assert!(config.check().is_err(), "{origin:?} accepted");
        }
        for timeout_ms in [0, MAX_TELEGRAM_TIMEOUT_MS + 1] {
            let config = TelegramConfig {
                timeout_ms,
                ..telegram()
            };
            assert!(config.check().is_err(), "timeout {timeout_ms} accepted");
        }
        for chat_id in ["", "12a", "@abc", "@has space", "1\n2", &"9".repeat(21)] {
            let config = TelegramConfig {
                chat_id: chat_id.into(),
                ..telegram()
            };
            assert!(config.check().is_err(), "chat id {chat_id:?} accepted");
        }
        assert!(
            TelegramConfig {
                chat_id: "@owner_chan".into(),
                ..telegram()
            }
            .check()
            .is_ok()
        );
        for max_attempts in [0, MAX_NOTIFY_ATTEMPTS + 1] {
            let notify = NotifyConfig {
                ledger: "/l".into(),
                max_attempts,
            };
            assert!(notify.check().is_err());
        }
    }

    /// Parse failures name a line but never echo configuration values, so a
    /// misplaced secret is not leaked.
    #[test]
    fn parser_errors_never_quote_values() {
        let scratch = crate::testdir::TestDir::new("cfgerr");
        let path = scratch.path().join("interfaces.toml");
        for extra in [
            "[telegram]\ntoken = \"123456:SECRET-value\"",
            "[telegram]\ntoken_file = \"/t\"\nchat_id = \"1\"\ntimeout_ms = \"123456:SECRET-value\"",
            "core_socket = \"123456:SECRET-value",
        ] {
            std::fs::write(&path, format!("core_socket = \"/c\"\n{extra}\n")).unwrap();
            let error = InterfacesConfig::load(&path).unwrap_err();
            assert!(!error.contains("SECRET"), "parser echoed a value: {error}");
            assert!(error.contains("line"), "{error}");
        }
    }

    /// A caller policy matches only its own host, harness, store namespace and
    /// session.
    #[test]
    fn caller_scope_matches_exactly() {
        let config: InterfacesConfig = toml::from_str(&sample("")).unwrap();
        let policy = &config.root.unwrap().callers[0];
        let inside = NativeAddress::new("h", Harness::ClaudeCode, "ns", "s1").unwrap();
        let other_store = NativeAddress::new("h", Harness::ClaudeCode, "ns2", "s1").unwrap();
        let other_harness = NativeAddress::new("h", Harness::Codex, "ns", "s1").unwrap();
        assert!(policy.matches(&inside));
        assert!(!policy.matches(&other_store));
        assert!(!policy.matches(&other_harness));
    }

    /// A secret file must be a private regular file (no group/other bits, no
    /// symlink), is trimmed, and its content is never echoed in errors.
    #[test]
    fn secrets_must_be_private_regular_files() {
        let scratch = crate::testdir::TestDir::new("secret");
        let dir = scratch.path();
        let file = dir.join("token");
        std::fs::write(&file, "  secret-value\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_secret(&file).unwrap_err();
        assert!(!error.contains("secret-value"), "content never echoed");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret(&file).unwrap(), "secret-value");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_secret(&link).is_err(), "symlink refused");
    }
}
