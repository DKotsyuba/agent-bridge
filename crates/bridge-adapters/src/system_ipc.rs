//! Private coordinator/worker protocol over an already connected Unix socket.
//!
//! UID, scope, binding facts and generation are correlation data, not authority.
//! The coordinator must derive authority from its fixed child handle and validate
//! the peer and scope before constructing any verified attestation. A framing or
//! parsing failure requires closing the connection; a partial write is ambiguous.

use std::io::{self, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use bridge_core::dispatch::{AttemptFence, AttemptRecord, Capabilities, Lifecycle, Outcome};
use bridge_core::recovery::EvidenceTier;
use bridge_core::types::NativeAddress;
use serde::{Deserialize, Serialize};

/// Maximum JSON bytes in one frame, excluding its newline.
pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// A request, its response, or an unsolicited worker event, fenced by generation.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Frame {
    /// One request; IDs are unique per connection.
    Request {
        generation: u64,
        request_id: u64,
        request: Request,
    },
    /// One response to the same connection's request ID.
    Response {
        generation: u64,
        request_id: u64,
        response: Response,
    },
    /// An unsolicited observation from this generation.
    Event { generation: u64, event: Event },
}

/// Unverified binding data; it cannot itself grant an attestation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingFacts {
    /// Logical target address.
    pub address: NativeAddress,
    /// Observed acting native identifier.
    pub actor: String,
    /// Observed endpoint fence.
    pub endpoint_epoch: u64,
    /// Observed lifecycle, not an authorization decision.
    pub lifecycle: Lifecycle,
    /// Observed native capabilities.
    pub capabilities: Capabilities,
    /// Reference to the binding record, not proof by itself.
    pub proof_ref: String,
}

/// An explicitly scoped coordinator operation, never an arbitrary command.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    /// Prepare the worker for the supplied epoch.
    Prepare { epoch: u64 },
    /// Fence future endpoint epochs below this floor.
    SetEpochFloor { epoch: u64 },
    /// Activate a prepared worker.
    Activate {},
    /// Stop admitting new work while existing work settles.
    Quiesce {},
    /// Stop this worker.
    Stop {},
    /// Run the worker's predefined maintenance operation.
    Maintenance { now_ms: u64 },
    /// Record a bounded hold when no recipient carrier currently attests.
    RecordHold {
        target: NativeAddress,
        reason: String,
        now_ms: u64,
    },
    /// Freeze dispatch for a target before changing its binding.
    Freeze { target: NativeAddress },
    /// Apply a coordinator-validated binding observation.
    ApplyBinding { binding: BindingFacts, now_ms: u64 },
    /// Resume dispatch for a target after its binding change.
    Unfreeze { target: NativeAddress },
    /// List one bounded, rotating work window.
    ListWork {
        now_ms: u64,
        limit: u32,
        after: Option<NativeAddress>,
    },
    /// Reserve the message path against validated binding facts.
    ReserveMessage {
        binding: BindingFacts,
        now_ms: u64,
        lease_ms: u64,
        handoff_ms: u64,
    },
    /// Commit invocation before a possible native hand-off.
    MarkInvoking {
        fence: AttemptFence,
        binding: BindingFacts,
        now_ms: u64,
    },
    /// Atomically reserve and mark the inject path invoking.
    DrainInject {
        binding: BindingFacts,
        now_ms: u64,
        lease_ms: u64,
        handoff_ms: u64,
    },
    /// Ask the coordinator to select a source for a hook drain.
    HookDrain { binding: BindingFacts },
    /// Read an attempt by its source-store sequence.
    ReadAttempt { attempt_seq: u64 },
    /// Release a reservation that is proven not to have been invoked.
    ReleaseAttempt { fence: AttemptFence },
    /// Record one carrier outcome against its complete fence.
    RecordOutcome {
        fence: AttemptFence,
        outcome: WireOutcome,
        now_ms: u64,
    },
    /// Record late evidence for an identified attempt member.
    RecordEvidence {
        publisher: String,
        event_id: String,
        fence: AttemptFence,
        tier: EvidenceTier,
        detail: String,
        now_ms: u64,
    },
    /// Observe the target for the message path.
    AttestMessage { target: NativeAddress },
    /// Send only the already frozen attempt to its attested target.
    SendMessage {
        source_uid: u32,
        ticket: u64,
        binding: BindingFacts,
        attempt: Box<AttemptRecord>,
    },
}

/// Closed reply forms; callers must match the response to the request.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Response {
    /// The operation completed without a returned value.
    Ok {},
    /// The operation was refused or failed; details remain local.
    Failed {},
    /// Source state and configured scopes, before native ingress is opened.
    Prepared {
        uid: u32,
        max_epoch: u64,
        scopes: Vec<(String, String, String)>,
    },
    /// The native channel and unchanged same-user relay are running.
    Ready { relay_pid: u32 },
    /// Bounded work window.
    Work { recipients: Vec<NativeAddress> },
    /// A binding observation, still requiring coordinator validation.
    Binding { binding: BindingFacts },
    /// A selected or read attempt, absent if no work or no such attempt.
    Attempt { attempt: Option<Box<AttemptRecord>> },
    /// Coordinator-selected source and ticket for a hook attempt.
    HookAttempt {
        source_uid: u32,
        ticket: u64,
        attempt: Option<Box<AttemptRecord>>,
    },
    /// Dispatch was held without a hand-off.
    Held { reason: String },
    /// A reserved attempt was released without hand-off.
    Released { reason: String },
    /// Native carrier's evidence tier.
    Outcome { outcome: WireOutcome },
}

/// Unsolicited observations; source UID is correlation data only.
#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Event {
    /// Worker identifies its protocol generation on connection.
    Hello {},
    /// Worker has completed preparation and can accept requests.
    Ready {},
    /// Worker observed a target binding.
    BindingObserved { binding: BindingFacts },
    /// A source hook is ready to drain for the target.
    HookReady {
        source_uid: u32,
        target: NativeAddress,
    },
    /// A source hook completed a fenced hand-off.
    HookFinished {
        source_uid: u32,
        ticket: u64,
        fence: AttemptFence,
        outcome: WireOutcome,
    },
    /// A delayed carrier outcome for the original fence.
    LateOutcome {
        source_uid: u32,
        ticket: u64,
        fence: AttemptFence,
        outcome: WireOutcome,
    },
    /// Delayed evidence for an original attempt member.
    LateEvidence {
        source_uid: u32,
        ticket: u64,
        publisher: String,
        event_id: String,
        fence: AttemptFence,
        tier: EvidenceTier,
        detail: String,
    },
    /// An expired native callback can no longer produce further evidence.
    CallbackClosed {
        source_uid: u32,
        ticket: u64,
        fence: AttemptFence,
    },
}

/// Serializable counterpart of the closed core outcome taxonomy.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WireOutcome {
    /// Native acceptance evidence.
    NativeAccepted { evidence: String },
    /// A nonterminal hold and its recheck deadline.
    NativeHeld { recheck_ms: u64 },
    /// A completed write without receipt and its deadline.
    WrittenNoReceipt {
        evidence: String,
        receipt_deadline_ms: u64,
    },
    /// A hook payload was fully handed off.
    HookSubmitted { evidence: String },
    /// Positive proof that nothing was sent.
    KnownUnsent { evidence: String },
    /// A temporary refusal with positive proof of no effect.
    DeferredKnownUnsent { evidence: String },
    /// A correlated resume was accepted; no message byte was written.
    ResumeAcceptedNoMessage { evidence: String },
    /// A possible hand-off with unknown effect.
    OutcomeUnknown { reason: String },
    /// Permanent refusal before acceptance.
    PermanentRefusal { reason: String },
}

impl From<Outcome> for WireOutcome {
    /// Preserves the exact evidence tier and its data.
    fn from(value: Outcome) -> Self {
        match value {
            Outcome::NativeAccepted { evidence } => Self::NativeAccepted { evidence },
            Outcome::NativeHeld { recheck_ms } => Self::NativeHeld { recheck_ms },
            Outcome::WrittenNoReceipt {
                evidence,
                receipt_deadline_ms,
            } => Self::WrittenNoReceipt {
                evidence,
                receipt_deadline_ms,
            },
            Outcome::HookSubmitted { evidence } => Self::HookSubmitted { evidence },
            Outcome::KnownUnsent { evidence } => Self::KnownUnsent { evidence },
            Outcome::DeferredKnownUnsent { evidence } => Self::DeferredKnownUnsent { evidence },
            Outcome::ResumeAcceptedNoMessage { evidence } => {
                Self::ResumeAcceptedNoMessage { evidence }
            }
            Outcome::OutcomeUnknown { reason } => Self::OutcomeUnknown { reason },
            Outcome::PermanentRefusal { reason } => Self::PermanentRefusal { reason },
        }
    }
}

impl From<WireOutcome> for Outcome {
    /// Restores the exact evidence tier; core validates its semantics on use.
    fn from(value: WireOutcome) -> Self {
        match value {
            WireOutcome::NativeAccepted { evidence } => Self::NativeAccepted { evidence },
            WireOutcome::NativeHeld { recheck_ms } => Self::NativeHeld { recheck_ms },
            WireOutcome::WrittenNoReceipt {
                evidence,
                receipt_deadline_ms,
            } => Self::WrittenNoReceipt {
                evidence,
                receipt_deadline_ms,
            },
            WireOutcome::HookSubmitted { evidence } => Self::HookSubmitted { evidence },
            WireOutcome::KnownUnsent { evidence } => Self::KnownUnsent { evidence },
            WireOutcome::DeferredKnownUnsent { evidence } => Self::DeferredKnownUnsent { evidence },
            WireOutcome::ResumeAcceptedNoMessage { evidence } => {
                Self::ResumeAcceptedNoMessage { evidence }
            }
            WireOutcome::OutcomeUnknown { reason } => Self::OutcomeUnknown { reason },
            WireOutcome::PermanentRefusal { reason } => Self::PermanentRefusal { reason },
        }
    }
}

/// Reads one bounded complete JSON frame; EOF before a frame returns `None`.
/// Any invalid, oversized, incomplete, or timed-out frame must close the socket.
pub(crate) fn read_frame(
    reader: &mut BufReader<UnixStream>,
    idle: Duration,
    deadline: Duration,
) -> io::Result<Option<Frame>> {
    let Some(line) = bridge_core::wire::read_bounded_line(reader, MAX_FRAME_BYTES, idle, deadline)?
    else {
        return Ok(None);
    };
    serde_json::from_str(&line)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPC frame"))
}

/// Incremental serialization sink that refuses to grow beyond the frame bound.
struct BoundedBuffer(Vec<u8>);

impl Write for BoundedBuffer {
    /// Appends only when the entire chunk fits, before allocating its bytes.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC frame too large",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// No buffered I/O remains to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes under the bound, then writes a frame within one absolute timeout.
/// An error after any bytes were written requires closing the socket.
pub(crate) fn write_frame(
    stream: &mut UnixStream,
    frame: &Frame,
    timeout: Duration,
) -> io::Result<()> {
    let started = Instant::now();
    let mut buffer = BoundedBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "cannot encode IPC frame"))?;
    buffer.0.push(b'\n');
    let mut remaining = buffer.0.as_slice();
    while !remaining.is_empty() {
        let budget = timeout
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "IPC write deadline exceeded")
            })?;
        stream.set_write_timeout(Some(budget))?;
        match stream.write(remaining) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "IPC socket closed",
                ));
            }
            Ok(n) => remaining = &remaining[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "IPC write deadline exceeded",
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Synthetic socketpair framing tests; no native session is contacted.

    /// The private wire preserves correlated resume acceptance as a distinct outcome.
    #[test]
    fn resume_accepted_outcome_round_trips() {
        let original = bridge_core::dispatch::Outcome::ResumeAcceptedNoMessage {
            evidence: "correlated receipt".into(),
        };
        let wire = super::WireOutcome::from(original.clone());
        let value = serde_json::to_value(wire).unwrap();
        assert_eq!(value["kind"], "resume_accepted_no_message");
        let decoded: super::WireOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(bridge_core::dispatch::Outcome::from(decoded), original);
    }

    use super::*;
    use std::net::Shutdown;
    use std::thread;

    /// Complete frames round-trip and unknown or incomplete frames fail closed.
    #[test]
    fn ipc_roundtrip_and_rejections() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let mut reader = BufReader::new(reader);
        let timeout = Duration::from_secs(2);
        write_frame(
            &mut writer,
            &Frame::Request {
                generation: 7,
                request_id: 3,
                request: Request::Activate {},
            },
            timeout,
        )
        .unwrap();
        assert!(matches!(
            read_frame(&mut reader, timeout, timeout).unwrap(),
            Some(Frame::Request {
                generation: 7,
                request_id: 3,
                request: Request::Activate {}
            })
        ));
        writer.write_all(b"{\"kind\":\"event\",\"generation\":7,\"event\":{\"event\":\"hello\",\"extra\":1}}\n").unwrap();
        assert_eq!(
            read_frame(&mut reader, timeout, timeout)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        writer.write_all(b"{\"kind\":\"event\"").unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            read_frame(&mut reader, timeout, timeout)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// An oversized frame is refused and a non-reading peer cannot extend the deadline.
    #[test]
    fn ipc_size_and_write_deadline() {
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let mut reader = BufReader::new(reader);
        let producer = thread::spawn(move || {
            let _ = writer.write_all(&vec![b'x'; MAX_FRAME_BYTES + 1]);
        });
        let timeout = Duration::from_secs(3);
        assert_eq!(
            read_frame(&mut reader, timeout, timeout)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(reader);
        producer.join().unwrap();

        let (mut writer, _reader) = UnixStream::pair().unwrap();
        let frame = Frame::Response {
            generation: 1,
            request_id: 1,
            response: Response::Held {
                reason: "x".repeat(MAX_FRAME_BYTES),
            },
        };
        assert_eq!(
            write_frame(&mut writer, &frame, timeout)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let frame = Frame::Response {
            generation: 1,
            request_id: 1,
            response: Response::Held {
                reason: "x".repeat(MAX_FRAME_BYTES / 2),
            },
        };
        let start = Instant::now();
        assert_eq!(
            write_frame(&mut writer, &frame, Duration::from_millis(100))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(3));
    }
}
