//! Generic native-owner wake route for already-live, supervisor-owned harnesses.
//!
//! A supervisor that launched a Codex or Claude Code process and keeps its
//! native input open may publish a private Unix socket named by the
//! `BRIDGE_NATIVE_OWNER_SOCKET` variable of that process. When the attested
//! harness environment names one, this route (never a queue helper,
//! application frontend or Claude inbox) hands the frozen manifest of one
//! attempt to that owner, which performs the single native effect (a fresh
//! Codex turn or a replayed Claude user frame) only while the recipient is
//! positively idle. The variable is a locator, never authority: the connected
//! kernel peer must be the exact direct parent of the attested harness
//! incarnation, run as the registry user and run from a trusted executable (a
//! regular file owned by that user or root, not writable by group or other and
//! unchanged since the owner process started). No owner path or digest is
//! configured.
//!
//! Wire format (one request and one receipt per connection): a four-byte
//! little-endian length and a strict JSON object, at most 1 MiB encoded. The
//! request has exactly `thread_id`, `call_id`, `text`, `native_pid`,
//! `native_start_time` and `wake_only: true`; the receipt exactly `call_id`,
//! `state`, `protocol`, `native_id` and `reason`. One absolute 35-second
//! client budget covers connect, peer proof, write and read and is never
//! renewed by partial I/O. Outcomes are conservative: a failure before the
//! request write began is known-unsent; after it, only a well-formed
//! correlated receipt can be anything but an unknown outcome, which is
//! retained and never resent. Native acceptance is not context or processing.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bridge_core::Harness;
use bridge_core::dispatch::Outcome;
use bridge_core::service::current_unix_millis;
use serde::{Deserialize, Deserializer, Serialize};

use crate::desktop::{connect, read_exact, remaining};
use crate::os;
use crate::registry::{Registry, owner_executable_current};
use crate::server::lock_registry;

/// Environment variable of the native process that names its owner socket.
pub const LOCATOR: &str = "BRIDGE_NATIVE_OWNER_SOCKET";

/// Absolute client budget of one delivery exchange, in seconds.
const CLIENT_SECONDS: u64 = 35;

/// Largest encoded frame (request or receipt) in bytes, excluding the length.
const MAX_FRAME_BYTES: usize = 1_048_576;

/// Largest decoded manifest text in bytes (the core framing bound).
const MAX_TEXT_BYTES: usize = 98_304;

/// Largest identifier (session, call or native id) in bytes.
const MAX_ID_BYTES: usize = 256;

/// Bound of the read-only liveness probe made while attesting.
const PROBE_BUDGET: Duration = Duration::from_secs(3);

/// The only known-unsent reasons a receipt may carry.
const KNOWN_UNSENT: [&str; 10] = [
    "actor_mismatch",
    "not_idle",
    "awaiting_input",
    "finished",
    "budget",
    "cancelled",
    "unavailable",
    "invalid_request",
    "capacity",
    "conflict",
];

/// The only unknown reasons a receipt may carry.
const UNKNOWN: [&str; 2] = ["native_uncertain", "channel_failed"];

/// Reads the owner locator of the harness process `pid` from its own OS
/// environment. `Ok(None)` is positive absence (the environment was read and
/// names no owner), so legacy routes apply. A gone process, an environment
/// that cannot be read and a present locator whose value is not valid UTF-8
/// are not absence: each is an error, so a recipient that has or may have an
/// owner is held instead of falling back to a legacy route.
pub(crate) fn locator(pid: u32) -> Result<Option<String>, String> {
    match os::process_env_checked(pid, LOCATOR) {
        Ok(None) => Ok(None),
        Ok(Some(value)) => value
            .into_string()
            .map(Some)
            .map_err(|_| "native owner locator is not valid UTF-8".to_string()),
        Err(_) => Err("native harness environment is unreadable, owner route not excluded".into()),
    }
}

/// Validates a present owner locator for the exact harness incarnation and
/// proves the live owner with a read-only connection that writes nothing.
///
/// Returns `Ok(None)` when the harness environment has no locator (legacy
/// route) and the validated socket path otherwise. Any malformed, unqualified,
/// dead or mismatched owner is an error: a present locator holds and never
/// falls back to another route. Takes the registry lock only briefly for
/// in-memory checks, never across socket I/O.
pub(crate) fn locate(
    registry: &Mutex<Registry>,
    harness: (u32, u64),
) -> Result<Option<PathBuf>, String> {
    let Some(raw) = locator(harness.0)? else {
        return Ok(None);
    };
    let socket = PathBuf::from(raw);
    let uid = lock_registry(registry).owner_uid();
    check_socket(&socket, uid)?;
    let stream = connect(&socket, Instant::now() + PROBE_BUDGET)
        .map_err(|_| "native owner socket is not connectable".to_string())?;
    verify_peer(&stream, harness, uid)?;
    Ok(Some(socket))
}

/// Requires `path` to be a canonical absolute socket, mode 0600 and owned by
/// `uid`, inside a directory that is mode 0700, owned by `uid` and not a
/// symlink. Canonical equality rejects every symlink component.
fn check_socket(path: &Path, uid: u32) -> Result<(), String> {
    let refuse = |what: &str| Err(format!("native owner socket {what}"));
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return refuse("locator is not a canonical absolute path");
    }
    let Some(directory) = path.parent() else {
        return refuse("locator has no directory");
    };
    match std::fs::symlink_metadata(directory) {
        Ok(meta) if meta.is_dir() && meta.uid() == uid && meta.mode() & 0o777 == 0o700 => {}
        _ => return refuse("directory is not private"),
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta)
            if meta.file_type().is_socket()
                && meta.uid() == uid
                && meta.mode() & 0o777 == 0o600 => {}
        _ => return refuse("is not a private socket"),
    }
    Ok(())
}

/// Proves the connected peer is the exact direct parent of the harness
/// incarnation: same registry user, a process born no later than the harness,
/// the harness's recorded parent, and an owner executable that is trusted and
/// unchanged since the owner started ([`owner_executable_current`]). Process
/// facts are re-read here, so a reused or replaced process never inherits an
/// earlier proof.
fn verify_peer(stream: &UnixStream, harness: (u32, u64), uid: u32) -> Result<(), String> {
    let peer = os::peer_identity(stream).map_err(|_| "native owner peer is unidentified")?;
    let owner = os::process_facts(peer.pid).ok_or("native owner process is gone")?;
    let native = os::process_facts(harness.0).ok_or("native harness process is gone")?;
    if peer.uid != uid
        || owner.uid != Some(uid)
        || native.start_time != harness.1
        || native.parent != Some(peer.pid)
        || owner.start_time > harness.1
    {
        return Err("native owner is not the exact direct parent of the attested harness".into());
    }
    owner_executable_current(&owner, uid)
}

/// The closed request frame, exactly the six agreed keys.
#[derive(Serialize)]
struct Request<'a> {
    /// Attested native session identifier; never caller authority.
    thread_id: &'a str,
    /// Stable Bridge attempt correlation, never a fresh retry id.
    call_id: &'a str,
    /// The exact frozen manifest.
    text: &'a str,
    /// Attested harness PID (positive).
    native_pid: u32,
    /// Attested harness start time in Unix seconds.
    native_start_time: u64,
    /// Always `true`: the owner must refuse unless the recipient is idle.
    wake_only: bool,
}

/// The closed receipt frame; any other shape is an unknown outcome.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    /// Must equal the request `call_id`.
    call_id: String,
    /// `accepted`, `known_unsent` or `unknown`.
    state: String,
    /// `codex_turn`, `claude_input` or `opencode_input` when accepted, else null.
    #[serde(deserialize_with = "nullable")]
    protocol: Option<String>,
    /// Fresh native turn id or replayed user id when accepted, else null.
    #[serde(deserialize_with = "nullable")]
    native_id: Option<String>,
    /// Finite refusal or uncertainty code; null when accepted.
    #[serde(deserialize_with = "nullable")]
    reason: Option<String>,
}

/// Deserializes a required key whose value may be null; a missing key is an
/// error because `deserialize_with` disables serde's implicit `None`.
fn nullable<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

/// Whether `value` is a nonempty identifier of at most 256 bytes without
/// control characters.
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_ID_BYTES && !value.chars().any(char::is_control)
}

/// Maps one receipt frame to the attempt outcome for `call_id` and the
/// recipient `harness`. Only a correlated, exactly shaped acceptance carrying
/// the protocol of that harness and a genuine native id is
/// [`Outcome::NativeAccepted`]; a correlated, finitely coded refusal is
/// [`Outcome::KnownUnsent`]; everything else, including bad bytes, extra,
/// missing or duplicate keys, a mismatched call id or an unlisted code, is
/// [`Outcome::OutcomeUnknown`] because the request was already written.
fn classify(frame: &[u8], call_id: &str, harness: Harness) -> Outcome {
    let unknown = |why: &str| Outcome::OutcomeUnknown {
        reason: format!("native owner receipt unusable after the request was written: {why}"),
    };
    let Ok(receipt) = serde_json::from_slice::<Receipt>(frame) else {
        return unknown("malformed or non-closed frame");
    };
    if receipt.call_id != call_id {
        return unknown("call id mismatch");
    }
    let protocol = match harness {
        Harness::Codex => "codex_turn",
        Harness::ClaudeCode => "claude_input",
        Harness::OpenCode => "opencode_input",
    };
    match (
        receipt.state.as_str(),
        receipt.protocol.as_deref(),
        receipt.native_id.as_deref(),
        receipt.reason.as_deref(),
    ) {
        ("accepted", Some(got), Some(id), None) if got == protocol && valid_id(id) => {
            Outcome::NativeAccepted {
                evidence: format!(
                    "native owner {got} accepted {call_id} as native id {id} (native acceptance, not context or processing)"
                ),
            }
        }
        ("known_unsent", None, None, Some(code)) if KNOWN_UNSENT.contains(&code) => {
            Outcome::KnownUnsent {
                evidence: format!("native owner refused before any native effect: {code}"),
            }
        }
        ("unknown", None, None, Some(code)) if UNKNOWN.contains(&code) => Outcome::OutcomeUnknown {
            reason: format!("native owner reported an unknown outcome: {code}"),
        },
        _ => unknown("state, protocol, native id or reason not agreed"),
    }
}

/// Writes all of `bytes` without renewing the absolute `deadline`: the write
/// timeout is re-armed from the remaining budget before every partial write.
fn write_all(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// One frozen manifest of one attempt to hand to a native owner.
pub(crate) struct Handoff<'a> {
    /// Attested native session identifier (nonempty, at most 256 bytes, no
    /// control characters); never caller authority.
    pub thread_id: &'a str,
    /// Stable Bridge attempt correlation (same validity as `thread_id`); a
    /// retry of the attempt reuses it, never a fresh value.
    pub call_id: &'a str,
    /// The exact frozen manifest, at most 98304 bytes.
    pub text: &'a str,
    /// The core attempt's absolute hand-off deadline (Unix milliseconds).
    pub deadline_ms: u64,
}

/// Hands one frozen manifest to the validated native owner and returns the
/// conservative outcome. `socket` was returned by [`locate`] for `harness`;
/// connection and peer proof are repeated here because nothing from attest
/// is trusted at send. `handoff.deadline_ms` is the core attempt's absolute
/// hand-off deadline (Unix milliseconds): with less than the 35-second
/// client budget left, nothing is sent. The budget is proven twice, before
/// connecting and again immediately before the first request byte (connect and
/// peer proof consume time), so the 35-second exchange fits the attempt. After
/// the write a late native effect is still possible whenever the receipt is
/// lost or late; that is always an unknown outcome, retained and never retried.
/// Oversized text is a permanent refusal; every failure before the first
/// request byte is known-unsent; every failure after it is unknown and never
/// retried or replaced by another route.
pub(crate) fn deliver(
    registry: &Mutex<Registry>,
    socket: &Path,
    harness: (u32, u64),
    kind: Harness,
    handoff: &Handoff<'_>,
) -> Outcome {
    let Handoff {
        thread_id,
        call_id,
        text,
        deadline_ms: handoff_deadline_ms,
    } = *handoff;
    let unsent = |why: &str| Outcome::KnownUnsent {
        evidence: format!("native owner route did not send: {why}"),
    };
    if !valid_id(thread_id) || !valid_id(call_id) || harness.0 == 0 {
        return unsent("invalid request identity");
    }
    if text.len() > MAX_TEXT_BYTES {
        return Outcome::PermanentRefusal {
            reason: "manifest exceeds the native owner text bound of 98304 bytes".into(),
        };
    }
    if !budget_holds(handoff_deadline_ms) {
        return unsent("less than 35 seconds of hand-off budget remain");
    }
    let deadline = Instant::now() + Duration::from_secs(CLIENT_SECONDS);
    let uid = lock_registry(registry).owner_uid();
    let mut stream = match connect(socket, deadline) {
        Ok(stream) => stream,
        Err(_) => return unsent("owner socket unavailable"),
    };
    if let Err(why) = check_socket(socket, uid).and_then(|()| verify_peer(&stream, harness, uid)) {
        return unsent(&why);
    }
    let body = match serde_json::to_vec(&Request {
        thread_id,
        call_id,
        text,
        native_pid: harness.0,
        native_start_time: harness.1,
        wake_only: true,
    }) {
        Ok(body) if body.len() <= MAX_FRAME_BYTES => body,
        _ => {
            return Outcome::PermanentRefusal {
                reason: "native owner request exceeds the frame bound".into(),
            };
        }
    };
    exchange(
        &mut stream,
        &body,
        call_id,
        kind,
        deadline,
        handoff_deadline_ms,
    )
}

/// Whether the core attempt, whose absolute hand-off deadline is
/// `handoff_deadline_ms` (Unix milliseconds), still has at least the whole
/// 35-second client budget left right now.
fn budget_holds(handoff_deadline_ms: u64) -> bool {
    handoff_deadline_ms.saturating_sub(current_unix_millis()) >= CLIENT_SECONDS * 1000
}

/// Writes one length-prefixed request `body` and reads one receipt frame, all
/// under the one absolute `deadline`. Immediately before the first byte the
/// attempt's remaining budget is proven again against `handoff_deadline_ms`
/// ([`budget_holds`]); failing it is known-unsent with nothing written. The
/// first request byte makes every later failure (short write, timeout, EOF,
/// oversized or incomplete receipt) an unknown outcome. A complete frame is
/// classified by [`classify`].
fn exchange(
    stream: &mut UnixStream,
    body: &[u8],
    call_id: &str,
    kind: Harness,
    deadline: Instant,
    handoff_deadline_ms: u64,
) -> Outcome {
    let possible = |why: &str| Outcome::OutcomeUnknown {
        reason: format!("native owner request may have been written: {why}; never resent"),
    };
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    if !budget_holds(handoff_deadline_ms) {
        return Outcome::KnownUnsent {
            evidence: "native owner route did not send: less than 35 seconds of hand-off budget remained at the write".into(),
        };
    }
    if write_all(stream, &frame, deadline).is_err() {
        return possible("write did not complete");
    }
    let mut head = [0; 4];
    if read_exact(stream, &mut head, deadline).is_err() {
        return possible("no receipt header");
    }
    let n = u32::from_le_bytes(head) as usize;
    if n == 0 || n > MAX_FRAME_BYTES {
        return possible("receipt frame size refused");
    }
    let mut receipt = vec![0; n];
    if read_exact(stream, &mut receipt, deadline).is_err() {
        return possible("receipt incomplete");
    }
    classify(&receipt, call_id, kind)
}

#[cfg(test)]
mod tests {
    //! Receipt classification and the locator domain, without sockets.

    use super::*;
    use serde_json::json;

    /// Renders a receipt object to frame bytes.
    fn frame(value: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    /// The four agreed receipt shapes map to acceptance, refusal and unknown
    /// exactly, and acceptance needs the harness's own protocol.
    #[test]
    fn agreed_receipts_map_conservatively() {
        let accepted = |protocol: &str| {
            frame(
                json!({"call_id":"c","state":"accepted","protocol":protocol,"native_id":"t-1","reason":null}),
            )
        };
        assert!(matches!(
            classify(&accepted("codex_turn"), "c", Harness::Codex),
            Outcome::NativeAccepted { .. }
        ));
        assert!(matches!(
            classify(&accepted("claude_input"), "c", Harness::ClaudeCode),
            Outcome::NativeAccepted { .. }
        ));
        for (bytes, harness) in [
            (accepted("claude_input"), Harness::Codex),
            (accepted("codex_turn"), Harness::ClaudeCode),
            (accepted("other"), Harness::Codex),
        ] {
            assert!(matches!(
                classify(&bytes, "c", harness),
                Outcome::OutcomeUnknown { .. }
            ));
        }
        for code in KNOWN_UNSENT {
            let bytes = frame(
                json!({"call_id":"c","state":"known_unsent","protocol":null,"native_id":null,"reason":code}),
            );
            assert!(matches!(
                classify(&bytes, "c", Harness::Codex),
                Outcome::KnownUnsent { .. }
            ));
        }
        for code in UNKNOWN {
            let bytes = frame(
                json!({"call_id":"c","state":"unknown","protocol":null,"native_id":null,"reason":code}),
            );
            assert!(matches!(
                classify(&bytes, "c", Harness::Codex),
                Outcome::OutcomeUnknown { .. }
            ));
        }
    }

    /// Every deviation from the closed shape after a write is unknown, never
    /// acceptance and never known-unsent: wrong call id, empty or oversized or
    /// control-bearing native id, a reason on acceptance, an unlisted code,
    /// a known-unsent carrying acceptance fields, missing, extra and duplicate
    /// keys, and bytes that are not strict JSON.
    #[test]
    fn deviations_are_unknown() {
        let long = "x".repeat(257);
        let bad = [
            json!({"call_id":"other","state":"accepted","protocol":"codex_turn","native_id":"t","reason":null}),
            json!({"call_id":"c","state":"accepted","protocol":"codex_turn","native_id":"","reason":null}),
            json!({"call_id":"c","state":"accepted","protocol":"codex_turn","native_id":long,"reason":null}),
            json!({"call_id":"c","state":"accepted","protocol":"codex_turn","native_id":"a\nb","reason":null}),
            json!({"call_id":"c","state":"accepted","protocol":"codex_turn","native_id":"t","reason":"ok"}),
            json!({"call_id":"c","state":"accepted","protocol":null,"native_id":"t","reason":null}),
            json!({"call_id":"c","state":"known_unsent","protocol":null,"native_id":null,"reason":"free text"}),
            json!({"call_id":"c","state":"known_unsent","protocol":null,"native_id":null,"reason":null}),
            json!({"call_id":"c","state":"known_unsent","protocol":"codex_turn","native_id":null,"reason":"not_idle"}),
            json!({"call_id":"c","state":"unknown","protocol":null,"native_id":null,"reason":"not_idle"}),
            json!({"call_id":"c","state":"done","protocol":null,"native_id":null,"reason":null}),
            json!({"call_id":"c","state":"known_unsent","protocol":null,"native_id":null,"reason":"not_idle","extra":1}),
            json!({"call_id":"c","state":"known_unsent","protocol":null,"reason":"not_idle"}),
        ];
        for value in bad {
            assert!(
                matches!(
                    classify(&frame(value.clone()), "c", Harness::Codex),
                    Outcome::OutcomeUnknown { .. }
                ),
                "{value}"
            );
        }
        let duplicate = br#"{"call_id":"c","state":"known_unsent","state":"known_unsent","protocol":null,"native_id":null,"reason":"not_idle"}"#;
        for bytes in [
            &duplicate[..],
            b"",
            b"not json",
            b"{\"call_id\":\"c\"} trailing",
            &[0xff, 0xfe],
        ] {
            assert!(matches!(
                classify(bytes, "c", Harness::Codex),
                Outcome::OutcomeUnknown { .. }
            ));
        }
    }

    /// The exchange is bounded by its absolute deadline and every failure
    /// after the request write is unknown: a silent owner, a closed peer, an
    /// oversized or zero length header, a trickled receipt and a receipt cut
    /// short never become acceptance or known-unsent.
    #[test]
    fn exchange_failures_after_write_are_unknown_and_bounded() {
        let ok = serde_json::to_vec(&json!({"call_id":"c","state":"accepted","protocol":"codex_turn","native_id":"t","reason":null})).unwrap();
        let framed = |bytes: &[u8]| {
            let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
            out.extend_from_slice(bytes);
            out
        };
        // (receipt bytes the peer writes before closing, expected acceptance)
        let cases: Vec<(Vec<u8>, bool)> = vec![
            (framed(&ok), true),
            (Vec::new(), false),
            (0u32.to_le_bytes().to_vec(), false),
            (((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec(), false),
            (framed(&ok)[..framed(&ok).len() - 1].to_vec(), false),
        ];
        for (reply, accepted) in cases {
            let (mut client, mut peer) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let mut head = [0; 4];
                std::io::Read::read_exact(&mut peer, &mut head).unwrap();
                let mut body = vec![0; u32::from_le_bytes(head) as usize];
                std::io::Read::read_exact(&mut peer, &mut body).unwrap();
                peer.write_all(&reply).unwrap();
            });
            let outcome = exchange(
                &mut client,
                b"{}",
                "c",
                Harness::Codex,
                Instant::now() + Duration::from_secs(2),
                u64::MAX,
            );
            server.join().unwrap();
            assert_eq!(
                matches!(outcome, Outcome::NativeAccepted { .. }),
                accepted,
                "{outcome:?}"
            );
            assert!(accepted || matches!(outcome, Outcome::OutcomeUnknown { .. }));
        }
        // A trickling receipt cannot renew the budget.
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut sink = [0; 6];
            let _ = std::io::Read::read_exact(&mut peer, &mut sink);
            for _ in 0..10 {
                if peer.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let started = Instant::now();
        let outcome = exchange(
            &mut client,
            b"{}",
            "c",
            Harness::Codex,
            started + Duration::from_millis(100),
            u64::MAX,
        );
        assert!(matches!(outcome, Outcome::OutcomeUnknown { .. }));
        assert!(started.elapsed() < Duration::from_millis(350));
        drop(client);
        server.join().unwrap();
    }

    /// The 35-second guard is re-proven immediately before the first byte, not
    /// only before connecting: with the connection already open and the peer
    /// proof done, a core attempt that no longer has the whole client budget
    /// writes nothing and is known-unsent, while one that does exchanges.
    #[test]
    fn late_budget_guard_sends_no_byte() {
        let now = current_unix_millis();
        assert!(budget_holds(now + 36_000));
        assert!(!budget_holds(now + 34_000));
        assert!(!budget_holds(0));
        for (handoff, sent) in [(now + 34_000, false), (now + 60_000, true)] {
            let (mut client, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let server = std::thread::spawn(move || {
                let mut seen = Vec::new();
                let _ = std::io::Read::read_to_end(&mut peer, &mut seen);
                seen
            });
            let outcome = exchange(
                &mut client,
                b"{}",
                "c",
                Harness::Codex,
                Instant::now() + Duration::from_millis(300),
                handoff,
            );
            drop(client);
            let seen = server.join().unwrap();
            assert_eq!(!seen.is_empty(), sent, "{outcome:?}");
            assert_eq!(
                matches!(outcome, Outcome::KnownUnsent { .. }),
                !sent,
                "{outcome:?}"
            );
        }
    }

    /// Identifier domain: nonempty, at most 256 bytes, no control characters.
    #[test]
    fn identifier_domain_is_closed() {
        assert!(valid_id("a"));
        assert!(valid_id(&"é".repeat(128)));
        assert!(!valid_id(""));
        assert!(!valid_id(&"é".repeat(129)));
        assert!(!valid_id("a\u{7}b"));
    }
}
