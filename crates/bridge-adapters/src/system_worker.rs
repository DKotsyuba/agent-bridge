//! One account-owned worker with local custody and coordinator-routed delivery.
//!
//! The inherited socket is the only authority for remote binding facts; native
//! caller identity and target attestations still come from the local registry.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use bridge_core::dispatch::{
    AttemptRecord, AttemptState, Attestation, DispatchCarrier, DispatchTiming, EffectiveMode,
    Invoked, Outcome, Selection,
};
use bridge_core::recovery::EvidenceTier;
use bridge_core::service::{self, current_unix_millis};
use bridge_core::{Harness, NativeAddress};
use serde::Deserialize;

use crate::claude::{ClaudeLaterCarrier, ClaudeTiming};
use crate::codex::{CodexQueueCarrier, DEFAULT_HELPER_TIMEOUT};
use crate::native_config::NativeConfig;
use crate::owner_only::OwnerOnlyCarrier;
use crate::registry::{Registry, refresh_executables, stop_executable_refresh};
use crate::server::{
    ChannelServer, Custody, DeliveryRef, DeliverySink, HookSelection, private_directory,
};
use crate::system_ipc::{BindingFacts, Event, Request, Response};
use crate::system_link::{Incoming, Link};

/// Bounded simultaneous incoming operations, including startup and delivery.
const MAX_HANDLERS: usize = 32;
/// Initial state, before the coordinator installs its epoch floor.
const PREPARED: u8 = 0;
/// Starting the native channel and relay.
const STARTING: u8 = 1;
/// Native endpoints started, with custody ingress fenced.
const READY: u8 = 2;
/// Coordinator has admitted new custody ingress.
const ACTIVE: u8 = 3;
/// No further operations may start.
const STOPPING: u8 = 4;

/// Maps only known static attestation failures to safe, coarse diagnostics.
fn attestation_hold_reason(reason: &str) -> &'static str {
    match reason {
        "no message binding" | "no attested binding for this recipient (unknown, not inactive)" => {
            "session not bound"
        }
        "message binding unavailable"
        | "retired Desktop message evidence unavailable"
        | "the recipient session ended (unknown, not inactive)"
        | "a retired recipient cannot use a native owner route" => {
            "session binding unavailable or retired"
        }
        "native thread state unavailable" => "native thread state unavailable",
        "the thread transcript changed since its positive idle (not idle)" => {
            "idle transcript changed"
        }
        "the retained transcript is unreadable or no longer the exact thread" => {
            "idle transcript unavailable"
        }
        "native thread unloaded without an idle-end proof" => "unloaded thread lacks idle proof",
        "retired live-server thread is not unloaded" => "retired thread is still loaded",
        "native control directory unavailable"
        | "native control directory unresolved"
        | "native control directory is not private and owned"
        | "native control directory is not canonical"
        | "native control socket unavailable"
        | "native control socket unresolved"
        | "native control socket has no parent"
        | "native control socket has invalid ownership or type"
        | "native control socket is not owned mode 0600"
        | "native control socket connection failed"
        | "native connect failed" => "native control socket unavailable",
        "native control peer unavailable" | "native control peer incarnation changed" => {
            "native control peer ownership unavailable"
        }
        _ => "target unavailable",
    }
}

/// Accepts only fixed diagnostic categories from an untrusted worker.
pub(crate) fn safe_hold_reason(reason: &str) -> &'static str {
    match reason {
        "session not bound" => "session not bound",
        "session binding unavailable or retired" => "session binding unavailable or retired",
        "native thread state unavailable" => "native thread state unavailable",
        "idle transcript changed" => "idle transcript changed",
        "idle transcript unavailable" => "idle transcript unavailable",
        "unloaded thread lacks idle proof" => "unloaded thread lacks idle proof",
        "retired thread is still loaded" => "retired thread is still loaded",
        "native control socket unavailable" => "native control socket unavailable",
        "native control peer ownership unavailable" => "native control peer ownership unavailable",
        _ => "target unavailable",
    }
}

/// Converts locally verified observations to non-authoritative wire data.
fn facts(attestation: &Attestation) -> BindingFacts {
    BindingFacts {
        address: attestation.address().clone(),
        actor: attestation.actor_id().to_owned(),
        endpoint_epoch: attestation.endpoint_epoch(),
        lifecycle: attestation.lifecycle(),
        capabilities: attestation.capabilities(),
        proof_ref: attestation.proof_ref().to_owned(),
    }
}

/// Restores facts only from the fixed parent socket after coordinator validation.
fn verified(binding: BindingFacts) -> Result<Attestation, &'static str> {
    Attestation::verified(
        binding.address,
        binding.actor,
        binding.endpoint_epoch,
        binding.lifecycle,
        binding.capabilities,
        binding.proof_ref,
    )
    .map_err(|_| "invalid binding")
}

/// Checks that the transmitted manifest is the exact bounded frozen content.
fn valid_manifest(attempt: &AttemptRecord) -> bool {
    !attempt.members.is_empty()
        && attempt.members.len() <= 32
        && attempt.manifest.len() <= bridge_core::framing::MAX_FRAMED_BYTES
        && crate::server::sha256_hex(attempt.manifest.as_bytes()) == attempt.fence.manifest_hash
}

/// Only the relay socket is needed from the account-private interfaces file.
#[derive(Deserialize)]
struct RelaySocketFile {
    /// The relay's configuration section.
    root: RelaySocketPath,
}

/// Minimal relay configuration used to establish readiness.
#[derive(Deserialize)]
struct RelaySocketPath {
    /// The configured Unix listener path.
    socket: PathBuf,
}

/// Waits briefly for the owned relay process to listen with its exact kernel identity.
fn wait_for_relay(
    socket: &Path,
    uid: u32,
    relay: &mut Child,
    link: &Link,
    phase: &AtomicU8,
) -> Result<(), &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "relay probe unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if link.is_closed()
            || phase.load(Ordering::SeqCst) != STARTING
            || !matches!(relay.try_wait(), Ok(None))
        {
            return Err("relay stopped before readiness");
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err("relay readiness timed out");
        };
        let connected = runtime.block_on(async {
            tokio::time::timeout(
                remaining.min(Duration::from_millis(200)),
                tokio::net::UnixStream::connect(socket),
            )
            .await
        });
        if let Ok(Ok(stream)) = connected {
            let stream = stream.into_std().map_err(|_| "relay probe failed")?;
            let peer =
                crate::os::peer_identity(&stream).map_err(|_| "relay identity unavailable")?;
            if peer.uid != uid || peer.pid != relay.id() || !matches!(relay.try_wait(), Ok(None)) {
                return Err("relay identity mismatch");
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20).min(remaining));
    }
}

/// Routes native hooks and Claude callbacks back to their source via the parent.
struct RemoteDelivery {
    /// Fixed parent connection for synchronized delivery.
    link: Link,
}

impl DeliverySink for RemoteDelivery {
    /// Waits until the parent has installed the binding in the source stores.
    fn observe_binding(&self, attestation: &Attestation, now_ms: u64) -> Result<(), String> {
        match self.link.call(
            Request::ApplyBinding {
                binding: facts(attestation),
                now_ms,
            },
            Duration::from_secs(5),
        ) {
            Ok(Response::Ok {}) => Ok(()),
            _ => {
                self.link.close();
                Err("binding synchronization failed".into())
            }
        }
    }

    /// Requests an invoking attempt for this exact verified hook target.
    fn drain_hook(
        &self,
        attestation: &Attestation,
        _now_ms: u64,
        _timing: &DispatchTiming,
    ) -> Result<HookSelection, String> {
        match self.link.call(
            Request::HookDrain {
                binding: facts(attestation),
            },
            Duration::from_secs(3),
        ) {
            Ok(Response::HookAttempt {
                source_uid,
                ticket,
                attempt: Some(record),
            }) if ticket != 0
                && record.state == AttemptState::Invoking
                && record.effective_mode == EffectiveMode::Inject
                && valid_manifest(&record)
                && record.fence.recipient == attestation.address().to_canonical_string()
                && record.fence.endpoint_epoch == attestation.endpoint_epoch()
                && record.actor == attestation.actor_id()
                && record.proof_ref == attestation.proof_ref()
                && record.deadline_ms > current_unix_millis() =>
            {
                Ok(HookSelection::Attempt {
                    delivery: DeliveryRef {
                        source_uid: Some(source_uid),
                        ticket,
                        fence: record.fence.clone(),
                    },
                    record,
                })
            }
            Ok(Response::HookAttempt { attempt: None, .. })
            | Ok(Response::Attempt { attempt: None })
            | Ok(Response::Held { .. }) => Ok(HookSelection::Idle),
            _ => {
                self.link.close();
                Err("hook selection failed".into())
            }
        }
    }

    /// Emits the original source, ticket and complete fence; failure is fatal.
    fn record_outcome(
        &self,
        delivery: &DeliveryRef,
        outcome: Outcome,
        _now_ms: u64,
    ) -> Result<(), String> {
        let Some(source_uid) = delivery.source_uid else {
            self.link.close();
            return Err("missing source".into());
        };
        self.link
            .event(Event::LateOutcome {
                source_uid,
                ticket: delivery.ticket,
                fence: delivery.fence.clone(),
                outcome: outcome.into(),
            })
            .map_err(|_| {
                self.link.close();
                "outcome synchronization failed".into()
            })
    }

    /// Emits evidence with the same original source, ticket and complete fence.
    fn record_evidence(
        &self,
        delivery: &DeliveryRef,
        member: &(String, String),
        tier: EvidenceTier,
        detail: &str,
        _now_ms: u64,
    ) -> Result<(), String> {
        let Some(source_uid) = delivery.source_uid else {
            self.link.close();
            return Err("missing source".into());
        };
        self.link
            .event(Event::LateEvidence {
                source_uid,
                ticket: delivery.ticket,
                publisher: member.0.clone(),
                event_id: member.1.clone(),
                fence: delivery.fence.clone(),
                tier,
                detail: detail.to_owned(),
            })
            .map_err(|_| {
                self.link.close();
                "evidence synchronization failed".into()
            })
    }

    /// Releases only this original callback's coordinator correlation.
    fn callback_closed(&self, delivery: &DeliveryRef) -> Result<(), String> {
        let Some(source_uid) = delivery.source_uid else {
            self.link.close();
            return Err("missing source".into());
        };
        self.link
            .event(Event::CallbackClosed {
                source_uid,
                ticket: delivery.ticket,
                fence: delivery.fence.clone(),
            })
            .map_err(|_| {
                self.link.close();
                "callback synchronization failed".into()
            })
    }
}

/// Native resources whose creation and shutdown must not race each other.
struct Lifecycle {
    /// This process's bound native adapter channel.
    channel: Option<ChannelServer>,
    /// Exact relay child started and reaped by this worker.
    relay: Option<Child>,
}

/// Shared account state, never holding registry or custody locks over IPC.
struct Worker {
    /// Kernel-reported account identity.
    uid: u32,
    /// Coordinator generation for this worker.
    generation: u64,
    /// Validated native namespaces configured for this account.
    scopes: Vec<(String, String, String)>,
    /// Highest epoch read before enabling native ingress.
    max_epoch: u64,
    /// Account-private native process and binding registry.
    registry: Arc<Mutex<Registry>>,
    /// Account-private custody and core socket.
    running: Arc<bridge_core::Running>,
    /// Fixed parent-owned IPC connection.
    link: Link,
    /// Remote hook and callback delivery boundary.
    delivery: Arc<dyn DeliverySink>,
    /// Configured account-private native channel socket.
    channel_path: PathBuf,
    /// Exact canonical, configured relay executable.
    relay_path: PathBuf,
    /// Relay socket to check for readiness and peer identity.
    relay_socket: PathBuf,
    /// Account-private relay configuration file.
    interfaces_path: PathBuf,
    /// Serializes creation and destruction of native endpoints.
    lifecycle: Mutex<Lifecycle>,
    /// Current admission and startup phase.
    phase: AtomicU8,
    /// Whether the parent completed preparation.
    prepared: AtomicBool,
    /// Bounded number of request handlers currently running.
    active_handlers: AtomicUsize,
    /// Serializes native hand-offs across all carriers for this account.
    native_job: Mutex<()>,
    /// Codex carrier and its per-carrier mutable state.
    codex: Mutex<CodexQueueCarrier>,
    /// Claude carrier and its callback owner.
    claude: Mutex<ClaudeLaterCarrier>,
    /// Owner-only carrier for remaining supported harnesses.
    owner: Mutex<OwnerOnlyCarrier>,
}

impl Worker {
    /// Starts this account's existing channel and exact configured relay once.
    fn start_endpoints(&self, epoch: u64) -> Result<u32, &'static str> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| "lifecycle unavailable")?;
        if !self.prepared.load(Ordering::SeqCst)
            || self
                .phase
                .compare_exchange(PREPARED, STARTING, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Err("invalid worker phase");
        }
        self.registry
            .lock()
            .map_err(|_| "registry unavailable")?
            .set_epoch_floor(epoch)
            .map_err(|_| "epoch floor refused")?;
        let channel = ChannelServer::start_with_delivery(
            &self.channel_path,
            Arc::clone(&self.registry),
            Arc::clone(&self.running) as Arc<dyn Custody>,
            DispatchTiming::default(),
            Arc::clone(&self.delivery),
        )
        .map_err(|_| "native channel unavailable")?;
        if self.link.is_closed() || self.phase.load(Ordering::SeqCst) == STOPPING {
            return Err("IPC link closed");
        }
        let relay = Command::new(&self.relay_path)
            .arg(&self.interfaces_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|_| "relay unavailable")?;
        let pid = relay.id();
        lifecycle.channel = Some(channel);
        lifecycle.relay = Some(relay);
        wait_for_relay(
            &self.relay_socket,
            self.uid,
            lifecycle.relay.as_mut().ok_or("relay unavailable")?,
            &self.link,
            &self.phase,
        )?;
        if self
            .phase
            .compare_exchange(STARTING, READY, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("worker stopping");
        }
        Ok(pid)
    }

    /// Uses the applicable local carrier to attest the target's current route.
    fn attest(&self, target: &NativeAddress) -> Result<Attestation, &'static str> {
        if target.harness == Harness::CODEX {
            self.codex
                .lock()
                .map_err(|_| "carrier unavailable")?
                .attest(target)
                .map_err(|reason| attestation_hold_reason(&reason))
        } else if target.harness == Harness::CLAUDE_CODE {
            self.claude
                .lock()
                .map_err(|_| "carrier unavailable")?
                .attest(target)
                .map_err(|reason| attestation_hold_reason(&reason))
        } else {
            self.owner
                .lock()
                .map_err(|_| "carrier unavailable")?
                .attest(target)
                .map_err(|reason| attestation_hold_reason(&reason))
        }
    }

    /// Performs at most one native hand-off after fresh exact target validation.
    fn send(
        &self,
        source_uid: u32,
        ticket: u64,
        binding: BindingFacts,
        attempt: &AttemptRecord,
    ) -> Outcome {
        let unsent = || Outcome::DeferredKnownUnsent {
            evidence: "target or deadline changed before native handoff".into(),
        };
        let Ok(_job) = self.native_job.lock() else {
            return unsent();
        };
        if self.phase.load(Ordering::SeqCst) != ACTIVE
            || self.link.is_closed()
            || attempt.state != AttemptState::Invoking
            || attempt.effective_mode != EffectiveMode::Message
            || !valid_manifest(attempt)
            || ticket == 0
            || attempt.deadline_ms <= current_unix_millis()
            || attempt.fence.recipient != binding.address.to_canonical_string()
            || attempt.fence.endpoint_epoch != binding.endpoint_epoch
        {
            return unsent();
        }
        let Ok(expected) = verified(binding) else {
            return unsent();
        };
        let Ok(fresh) = self.attest(expected.address()) else {
            return unsent();
        };
        if fresh != expected
            || attempt.actor != fresh.actor_id()
            || attempt.proof_ref != fresh.proof_ref()
            || attempt.deadline_ms <= current_unix_millis()
            || self.link.is_closed()
            || self.phase.load(Ordering::SeqCst) != ACTIVE
        {
            return unsent();
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if fresh.address().harness == Harness::CODEX {
                self.codex
                    .lock()
                    .ok()
                    .map(|mut carrier| carrier.send_scoped(source_uid, attempt))
            } else if fresh.address().harness == Harness::CLAUDE_CODE {
                self.claude
                    .lock()
                    .ok()
                    .map(|mut carrier| carrier.send_scoped(source_uid, ticket, attempt))
            } else {
                self.owner
                    .lock()
                    .ok()
                    .map(|mut carrier| carrier.send_scoped(source_uid, attempt))
            }
        }));
        match result {
            Ok(Some(outcome)) => outcome,
            _ => Outcome::OutcomeUnknown {
                reason: "native handoff could not be established".into(),
            },
        }
    }

    /// Applies one parent-owned operation and returns its exact closed reply.
    fn handle(&self, request: Request) -> Response {
        if self.link.is_closed() || self.phase.load(Ordering::SeqCst) == STOPPING {
            return Response::Failed {};
        }
        match request {
            Request::Prepare { epoch }
                if epoch == self.generation && !self.prepared.swap(true, Ordering::SeqCst) =>
            {
                Response::Prepared {
                    uid: self.uid,
                    max_epoch: self.max_epoch,
                    scopes: self.scopes.clone(),
                }
            }
            Request::SetEpochFloor { epoch } => match self.start_endpoints(epoch) {
                Ok(relay_pid) => Response::Ready { relay_pid },
                Err(_) => {
                    self.link.close();
                    Response::Failed {}
                }
            },
            Request::Activate {} => {
                let Ok(_lifecycle) = self.lifecycle.lock() else {
                    return Response::Failed {};
                };
                if self.phase.load(Ordering::SeqCst) == READY
                    && self.running.activate_ingress().is_ok()
                {
                    self.phase.store(ACTIVE, Ordering::SeqCst);
                    Response::Ok {}
                } else {
                    Response::Failed {}
                }
            }
            Request::Quiesce {} => {
                let Ok(_lifecycle) = self.lifecycle.lock() else {
                    return Response::Failed {};
                };
                if matches!(self.phase.load(Ordering::SeqCst), READY | ACTIVE) {
                    self.running.fence_ingress();
                    self.phase.store(READY, Ordering::SeqCst);
                    Response::Ok {}
                } else {
                    Response::Failed {}
                }
            }
            Request::Maintenance { now_ms } => response(self.running.run_maintenance(now_ms)),
            Request::RecordHold {
                target,
                reason,
                now_ms,
            } => response(
                self.running
                    .with_storage(|storage| storage.record_hold(&target, &reason, now_ms)),
            ),
            Request::Freeze { target } => response(
                self.running
                    .with_storage(|storage| storage.freeze_recipient(&target)),
            ),
            Request::Unfreeze { target } => response(
                self.running
                    .with_storage(|storage| storage.unfreeze_recipient(&target)),
            ),
            Request::ApplyBinding { binding, now_ms } => match verified(binding) {
                Ok(attestation) => response(
                    self.running
                        .with_storage(|storage| storage.observe_binding(&attestation, now_ms)),
                ),
                Err(_) => Response::Failed {},
            },
            Request::ListWork {
                now_ms,
                limit,
                after,
            } if (1..=200).contains(&limit) => match self.running.with_storage(|storage| {
                storage.recipients_with_work(now_ms, limit as usize, after.as_ref())
            }) {
                Ok(recipients) => Response::Work { recipients },
                Err(_) => Response::Failed {},
            },
            Request::ReserveMessage {
                binding,
                now_ms,
                lease_ms,
                handoff_ms,
            } => match verified(binding) {
                Ok(attestation) => selection(self.running.with_storage(|storage| {
                    storage.reserve_next(
                        &attestation,
                        EffectiveMode::Message,
                        now_ms,
                        &DispatchTiming {
                            lease_ms,
                            handoff_ms,
                        },
                    )
                })),
                Err(_) => Response::Failed {},
            },
            Request::DrainInject {
                binding,
                now_ms,
                lease_ms,
                handoff_ms,
            } => match verified(binding) {
                Ok(attestation) => selection(self.running.with_storage(|storage| {
                    storage.drain_inject(
                        &attestation,
                        now_ms,
                        &DispatchTiming {
                            lease_ms,
                            handoff_ms,
                        },
                    )
                })),
                Err(_) => Response::Failed {},
            },
            Request::MarkInvoking {
                fence,
                binding,
                now_ms,
            } => match verified(binding) {
                Ok(attestation) => match self
                    .running
                    .with_storage(|storage| storage.mark_invoking(&fence, &attestation, now_ms))
                {
                    Ok(Invoked::Invoking(attempt)) => Response::Attempt {
                        attempt: Some(attempt),
                    },
                    Ok(Invoked::Released(reason)) => Response::Released { reason },
                    Err(_) => Response::Failed {},
                },
                Err(_) => Response::Failed {},
            },
            Request::ReadAttempt { attempt_seq } => match self
                .running
                .with_storage(|storage| storage.attempt(attempt_seq))
            {
                Ok(attempt) => Response::Attempt {
                    attempt: attempt.map(Box::new),
                },
                Err(_) => Response::Failed {},
            },
            Request::ReleaseAttempt { fence } => response(self.running.with_storage(|storage| {
                storage.release_attempt(
                    &fence,
                    "coordinator released before native handoff",
                    current_unix_millis(),
                )
            })),
            Request::RecordOutcome {
                fence,
                outcome,
                now_ms,
            } => response(
                self.running
                    .with_storage(|storage| storage.record_outcome(&fence, outcome.into(), now_ms)),
            ),
            Request::RecordEvidence {
                publisher,
                event_id,
                fence,
                tier,
                detail,
                now_ms,
            } => self.running.with_storage(|storage| {
                let Ok(Some(record)) = storage.attempt(fence.attempt_seq) else {
                    return Response::Failed {};
                };
                if record.fence != fence
                    || !record
                        .members
                        .iter()
                        .any(|member| member.publisher == publisher && member.event_id == event_id)
                {
                    return Response::Failed {};
                }
                response(storage.record_evidence(
                    &publisher,
                    &event_id,
                    fence.attempt_seq,
                    tier,
                    &detail,
                    now_ms,
                ))
            }),
            Request::AttestMessage { target } => match self.attest(&target) {
                Ok(attestation) => Response::Binding {
                    binding: facts(&attestation),
                },
                Err(reason) => Response::Held {
                    reason: safe_hold_reason(reason).into(),
                },
            },
            Request::SendMessage {
                source_uid,
                ticket,
                binding,
                attempt,
            } => Response::Outcome {
                outcome: self.send(source_uid, ticket, binding, &attempt).into(),
            },
            _ => Response::Failed {},
        }
    }

    /// Fences ingress and terminates only the relay this worker started.
    fn stop(&self) {
        self.phase.store(STOPPING, Ordering::SeqCst);
        self.link.close();
        {
            // After shutdown begins, recovering this guard is solely to terminate
            // resources already owned by this worker, never to serve requests.
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.phase.store(STOPPING, Ordering::SeqCst);
            self.running.fence_ingress();
            if let Some(channel) = lifecycle.channel.take() {
                channel.stop();
            }
            if let Some(mut relay) = lifecycle.relay.take() {
                let _ = relay.kill();
                let _ = relay.wait();
            }
        }
        self.running.shutdown();
        stop_executable_refresh(&self.registry);
    }
}

/// Maps any local core result to the corresponding simple reply.
fn response<T, E>(result: Result<T, E>) -> Response {
    if result.is_ok() {
        Response::Ok {}
    } else {
        Response::Failed {}
    }
}

/// Preserves idle, held and frozen attempt states in the wire reply.
fn selection(result: Result<Selection, bridge_core::CoreError>) -> Response {
    match result {
        Ok(Selection::Attempt(attempt)) => Response::Attempt {
            attempt: Some(attempt),
        },
        Ok(Selection::Idle) => Response::Attempt { attempt: None },
        Ok(Selection::Held(reason)) => Response::Held { reason },
        Err(_) => Response::Failed {},
    }
}

/// Releases an admission slot even when a request handler unwinds.
struct HandlerSlot(Arc<Worker>);
impl Drop for HandlerSlot {
    /// Accounts for this completed request.
    fn drop(&mut self) {
        self.0.active_handlers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Refuses a non-regular, foreign or, when required, shared database file.
fn validate_database(metadata: &fs::Metadata, uid: u32, private: bool) -> Result<(), &'static str> {
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || (private && (metadata.mode() & 0o077 != 0 || metadata.nlink() != 1))
    {
        return Err("database ownership or permissions refused");
    }
    Ok(())
}

/// Checks an existing database path without creating it or following a final symlink.
fn validate_existing_database(path: &Path, uid: u32, private: bool) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "existing database required")?;
    validate_database(&metadata, uid, private)
}

/// Requires an existing private, account-owned directory without following a symlink.
fn validate_database_directory(path: &Path, uid: u32) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "database directory unavailable")?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err("database directory refused");
    }
    Ok(())
}

/// Atomically creates only the explicitly approved private database or validates an existing one.
///
/// The target must be below this account's private `.agent-bridge` directory;
/// parent symlinks, traversal, shared files and multiple hard links are refused.
fn prepare_new_database(path: &Path, home: &Path, uid: u32) -> Result<(), &'static str> {
    if !home.is_absolute()
        || !path.is_absolute()
        || home
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("database path refused");
    }
    for ancestor in home.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| "home path unavailable")?;
        if !metadata.file_type().is_dir() {
            return Err("home path refused");
        }
    }
    let home_metadata = fs::symlink_metadata(home).map_err(|_| "home unavailable")?;
    if home_metadata.uid() != uid || home_metadata.mode() & 0o022 != 0 {
        return Err("home ownership or permissions refused");
    }
    let mut directory = home.join(".agent-bridge");
    let relative = path
        .strip_prefix(&directory)
        .map_err(|_| "database path outside home")?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("database path refused");
    }
    validate_database_directory(&directory, uid)?;
    let parent = relative.parent().ok_or("database path refused")?;
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err("database path refused");
        };
        directory.push(name);
        validate_database_directory(&directory, uid)?;
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => {
            validate_database(
                &file
                    .metadata()
                    .map_err(|_| "database metadata unavailable")?,
                uid,
                true,
            )?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| "database permissions unavailable")?;
            validate_database(
                &file
                    .metadata()
                    .map_err(|_| "database metadata unavailable")?,
                uid,
                true,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_existing_database(path, uid, true)
        }
        Err(_) => Err("database creation failed"),
    }
}

/// Runs one UID's service, optionally creating only its explicitly approved new database.
pub(crate) fn run(
    daemon_config: &Path,
    interfaces_config: &Path,
    generation: u64,
    stream: UnixStream,
    new_database: Option<&Path>,
) -> Result<(), String> {
    let uid = crate::os::process_facts(std::process::id())
        .and_then(|facts| facts.uid)
        .ok_or("worker identity unavailable")?;
    if uid == 0 {
        return Err("worker must be unprivileged".into());
    }
    let text = fs::read_to_string(daemon_config).map_err(|_| "configuration unreadable")?;
    let mut config: NativeConfig = toml::from_str(&text).map_err(|_| "configuration invalid")?;
    drop(text);
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("worker home unavailable")?);
    if let Some(path) = new_database {
        prepare_new_database(path, &home, uid)?;
        config.core.database = path.to_path_buf();
    } else {
        validate_existing_database(&config.core.database, uid, false)?;
    }
    let channel_dir = config
        .adapters
        .channel
        .parent()
        .ok_or("channel directory unavailable")?;
    if private_directory(channel_dir).map_err(|_| "channel directory refused")? != uid {
        return Err("channel owner mismatch".into());
    }
    let interfaces_text =
        fs::read_to_string(interfaces_config).map_err(|_| "interfaces configuration unreadable")?;
    let interfaces: RelaySocketFile =
        toml::from_str(&interfaces_text).map_err(|_| "interfaces configuration invalid")?;
    drop(interfaces_text);
    let relay_socket = interfaces.root.socket;
    if !relay_socket.is_absolute() {
        return Err("relay socket must be absolute".into());
    }
    let relay_path = home
        .join(".agent-bridge/current/bin/bridge-root-relay")
        .canonicalize()
        .map_err(|_| "current relay unavailable")?;
    let mut matches = config
        .adapters
        .registry
        .relays
        .iter()
        .filter(|relay| relay.path.canonicalize().ok().as_ref() == Some(&relay_path));
    let relay = matches.next().ok_or("current relay is not configured")?;
    if matches.next().is_some()
        || crate::registry::file_sha256(&relay_path).ok().as_deref() != Some(relay.sha256.as_str())
    {
        return Err("current relay does not match its unique configured build".into());
    }
    let (policies, _) = config
        .adapters
        .registry
        .harness_policies()
        .map_err(|_| "registry configuration invalid")?;
    let scopes = policies
        .into_iter()
        .map(|policy| {
            (
                config.adapters.registry.host_id.clone(),
                policy.harness.as_str().to_owned(),
                policy.namespace,
            )
        })
        .collect();
    let registry = Arc::new(Mutex::new(
        Registry::new(config.adapters.registry, uid).map_err(|_| "registry unavailable")?,
    ));
    let (tx, rx) = mpsc::sync_channel(2 * MAX_HANDLERS);
    let link = Link::new(stream, generation, 0, tx).map_err(str::to_owned)?;
    let delivery: Arc<dyn DeliverySink> = Arc::new(RemoteDelivery { link: link.clone() });
    let claude = ClaudeLaterCarrier::new_with_delivery(
        Arc::clone(&registry),
        Arc::clone(&delivery),
        ClaudeTiming::default(),
    )
    .map_err(|_| "carrier unavailable")?;
    let codex = CodexQueueCarrier::new(
        Arc::clone(&registry),
        config.adapters.sandbox,
        DEFAULT_HELPER_TIMEOUT,
    )
    .with_desktop_directory(channel_dir.to_path_buf());
    let owner = OwnerOnlyCarrier::new(Arc::clone(&registry));
    let running =
        Arc::new(service::start_coordinated(config.core).map_err(|_| "custody unavailable")?);
    let max_epoch = match running.with_storage(|storage| storage.max_endpoint_epoch()) {
        Ok(epoch) => epoch,
        Err(_) => {
            running.shutdown();
            if let Ok(running) = Arc::try_unwrap(running) {
                running.join();
            }
            return Err("custody epoch unavailable".into());
        }
    };
    let worker = Arc::new(Worker {
        uid,
        generation,
        scopes,
        max_epoch,
        registry,
        running,
        link,
        delivery,
        channel_path: config.adapters.channel,
        relay_path,
        relay_socket,
        interfaces_path: interfaces_config.to_path_buf(),
        lifecycle: Mutex::new(Lifecycle {
            channel: None,
            relay: None,
        }),
        phase: AtomicU8::new(PREPARED),
        prepared: AtomicBool::new(false),
        active_handlers: AtomicUsize::new(0),
        native_job: Mutex::new(()),
        codex: Mutex::new(codex),
        claude: Mutex::new(claude),
        owner: Mutex::new(owner),
    });
    let mut graceful = false;
    loop {
        if worker.link.is_closed() {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Incoming::Request {
                request_id,
                request: Request::Stop {},
                ..
            }) => {
                worker.phase.store(STOPPING, Ordering::SeqCst);
                if let Ok(_lifecycle) = worker.lifecycle.lock() {
                    worker.phase.store(STOPPING, Ordering::SeqCst);
                    worker.running.fence_ingress();
                    graceful = worker.link.respond(request_id, Response::Ok {}).is_ok();
                }
                break;
            }
            Ok(Incoming::Request {
                request_id,
                request,
                ..
            }) => {
                if worker
                    .active_handlers
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                        (n < MAX_HANDLERS).then_some(n + 1)
                    })
                    .is_err()
                {
                    worker.link.close();
                    break;
                }
                let state = Arc::clone(&worker);
                if std::thread::Builder::new()
                    .name("bridge-system-work".into())
                    .spawn(move || {
                        let _slot = HandlerSlot(Arc::clone(&state));
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            state.handle(request)
                        })) {
                            Ok(response) => {
                                let _ = state.link.respond(request_id, response);
                            }
                            Err(_) => state.link.close(),
                        }
                    })
                    .is_err()
                {
                    worker.active_handlers.fetch_sub(1, Ordering::SeqCst);
                    worker.link.close();
                    break;
                }
            }
            Ok(Incoming::Closed { peer_uid }) => {
                if peer_uid != 0 {
                    worker.link.close();
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Ok(Incoming::Event { .. }) => {
                worker.link.close();
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if worker.link.is_closed() {
                    break;
                }
                let relay_exited = match worker.lifecycle.try_lock() {
                    Ok(mut lifecycle) => lifecycle
                        .relay
                        .as_mut()
                        .is_some_and(|relay| !matches!(relay.try_wait(), Ok(None))),
                    Err(std::sync::TryLockError::WouldBlock) => false,
                    Err(_) => true,
                };
                if relay_exited {
                    worker.link.close();
                    break;
                }
                refresh_executables(&worker.registry);
            }
        }
    }
    worker.stop();
    if graceful {
        Ok(())
    } else {
        Err("coordinator connection lost".into())
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic attempts never contact a native session.

    use super::*;
    use bridge_core::dispatch::{AttemptFence, MemberRef};

    /// Static categories survive both filters; arbitrary upstream content never does.
    #[test]
    fn attestation_diagnostics_are_closed_and_safe() {
        for (input, expected) in [
            ("no message binding", "session not bound"),
            (
                "message binding unavailable",
                "session binding unavailable or retired",
            ),
            (
                "native thread state unavailable",
                "native thread state unavailable",
            ),
            (
                "the thread transcript changed since its positive idle (not idle)",
                "idle transcript changed",
            ),
            (
                "native thread unloaded without an idle-end proof",
                "unloaded thread lacks idle proof",
            ),
            (
                "native control socket connection failed",
                "native control socket unavailable",
            ),
            (
                "native control peer incarnation changed",
                "native control peer ownership unavailable",
            ),
            ("secret /private/path payload", "target unavailable"),
        ] {
            assert_eq!(attestation_hold_reason(input), expected);
            assert_eq!(safe_hold_reason(attestation_hold_reason(input)), expected);
        }
        assert_eq!(
            safe_hold_reason("native control peer incarnation changed"),
            "target unavailable"
        );
        assert_eq!(
            safe_hold_reason("native thread state unavailable: secret"),
            "target unavailable"
        );
    }

    /// Removes only the unique synthetic tree created by one test.
    struct DatabaseScratch(PathBuf);
    impl Drop for DatabaseScratch {
        /// Removes the test-owned fixture after its files are closed.
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// New databases are atomic, private and never replace existing custody.
    #[test]
    fn explicit_database_is_created_once_and_refuses_unsafe_paths() {
        let task_tmp =
            PathBuf::from(std::env::var_os("TMPDIR").expect("task-owned TMPDIR required"));
        let entropy = crate::os::random_bytes().unwrap();
        let fixture = DatabaseScratch(task_tmp.join(format!(
            "dbtest-{}-{:x}",
            std::process::id(),
            u64::from_le_bytes(entropy[..8].try_into().unwrap())
        )));
        fs::create_dir(&fixture.0).unwrap();
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
        let home = fixture.0.join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let root = home.join(".agent-bridge");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = crate::os::process_facts(std::process::id())
            .unwrap()
            .uid
            .unwrap();
        let old = root.join("old.db");
        fs::write(&old, b"old custody").unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_existing_database(&old, uid, false).is_ok());
        let absent = root.join("absent.db");
        assert!(validate_existing_database(&absent, uid, false).is_err());
        assert!(!absent.exists());
        let database = root.join("new.db");
        let barrier = Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|scope| {
            let calls: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let database = &database;
                    let home = &home;
                    scope.spawn(move || {
                        barrier.wait();
                        prepare_new_database(database, home, uid)
                    })
                })
                .collect();
            for call in calls {
                assert!(call.join().unwrap().is_ok());
            }
        });
        let metadata = fs::symlink_metadata(&database).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        fs::write(&database, b"new custody").unwrap();
        prepare_new_database(&database, &home, uid).unwrap();
        assert_eq!(fs::read(&database).unwrap(), b"new custody");
        assert_eq!(fs::read(&old).unwrap(), b"old custody");
        let schema_database = root.join("schema.db");
        prepare_new_database(&schema_database, &home, uid).unwrap();
        let mut storage =
            bridge_core::Storage::open(&schema_database, bridge_core::storage::Limits::new(100))
                .unwrap();
        storage
            .register_source_tag("synthetic", "synthetic")
            .unwrap();
        drop(storage);
        prepare_new_database(&schema_database, &home, uid).unwrap();
        let reopened =
            bridge_core::Storage::open(&schema_database, bridge_core::storage::Limits::new(100))
                .unwrap();
        assert_eq!(reopened.max_endpoint_epoch().unwrap(), 0);
        drop(reopened);
        assert!(validate_database(&metadata, uid.wrapping_add(1), true).is_err());
        fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(prepare_new_database(&database, &home, uid).is_err());
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = root.join("hardlink.db");
        fs::hard_link(&database, &alias).unwrap();
        assert!(prepare_new_database(&database, &home, uid).is_err());
        fs::remove_file(&alias).unwrap();
        let symlink = root.join("symlink.db");
        std::os::unix::fs::symlink(&old, &symlink).unwrap();
        assert!(prepare_new_database(&symlink, &home, uid).is_err());
        assert!(validate_existing_database(&symlink, uid, false).is_err());
        let outside = home.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link-directory")).unwrap();
        assert!(prepare_new_database(&root.join("link-directory/db"), &home, uid).is_err());
        assert!(prepare_new_database(&root.join("../outside/escape.db"), &home, uid).is_err());
        assert!(prepare_new_database(&outside.join("escape.db"), &home, uid).is_err());
        assert!(!outside.join("escape.db").exists());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_new_database(&root.join("shared.db"), &home, uid).is_err());
        assert!(!root.join("shared.db").exists());
        assert_eq!(fs::read(&old).unwrap(), b"old custody");
    }

    /// Synthetic child process that binds exactly one probe socket when requested.
    #[test]
    fn relay_fixture() {
        use std::io::Read;
        if let Some(path) = std::env::var_os("BRIDGE_SYSTEM_TEST_RELAY_SOCKET") {
            let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.read(&mut [0]);
        }
    }

    /// Readiness accepts the actual child identity and refuses another UID.
    #[test]
    fn relay_readiness_checks_kernel_identity() {
        let uid = crate::os::process_facts(std::process::id())
            .unwrap()
            .uid
            .unwrap();
        for expected_uid in [uid, uid.wrapping_add(1)] {
            let task_tmp =
                PathBuf::from(std::env::var_os("TMPDIR").expect("task-owned TMPDIR required"));
            let socket = task_tmp.join(format!("brr-{}-{expected_uid}.sock", std::process::id()));
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "system_worker::tests::relay_fixture",
                    "--nocapture",
                ])
                .env("BRIDGE_SYSTEM_TEST_RELAY_SOCKET", &socket)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let (local, peer) = UnixStream::pair().unwrap();
            let (tx, _rx) = mpsc::sync_channel(2);
            let link = Link::new(local, 1, 0, tx).unwrap();
            let phase = AtomicU8::new(STARTING);
            let result = wait_for_relay(&socket, expected_uid, &mut child, &link, &phase);
            if result.is_err() {
                let _ = child.kill();
            }
            let _ = child.wait();
            drop(peer);
            let _ = fs::remove_file(&socket);
            assert_eq!(result.is_ok(), expected_uid == uid);
        }
        let task_tmp =
            PathBuf::from(std::env::var_os("TMPDIR").expect("task-owned TMPDIR required"));
        let socket = task_tmp.join(format!("brr-{}-actual.sock", std::process::id()));
        let other_socket = task_tmp.join(format!("brr-{}-other.sock", std::process::id()));
        let spawn_fixture = |path: &Path| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "system_worker::tests::relay_fixture",
                    "--nocapture",
                ])
                .env("BRIDGE_SYSTEM_TEST_RELAY_SOCKET", path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut actual = spawn_fixture(&socket);
        let mut other = spawn_fixture(&other_socket);
        let (local, peer) = UnixStream::pair().unwrap();
        let (tx, _rx) = mpsc::sync_channel(2);
        let link = Link::new(local, 1, 0, tx).unwrap();
        let result = wait_for_relay(&socket, uid, &mut other, &link, &AtomicU8::new(STARTING));
        let _ = actual.kill();
        let _ = other.kill();
        let _ = actual.wait();
        let _ = other.wait();
        drop(peer);
        let _ = fs::remove_file(socket);
        let _ = fs::remove_file(other_socket);
        assert!(matches!(result, Err("relay identity mismatch")));
    }

    /// A corrupted or unbounded manifest cannot reach a hook or message carrier.
    #[test]
    fn manifest_integrity_and_bounds() {
        let manifest = "frozen payload".to_owned();
        let mut record = AttemptRecord {
            fence: AttemptFence {
                attempt_seq: 1,
                recipient: "recipient".into(),
                endpoint_epoch: 1,
                manifest_hash: crate::server::sha256_hex(manifest.as_bytes()),
            },
            state: AttemptState::Invoking,
            requested_mode: bridge_core::Mode::Message,
            effective_mode: EffectiveMode::Message,
            actor: "actor".into(),
            proof_ref: "proof".into(),
            granted: "message".into(),
            members: vec![MemberRef {
                publisher: "publisher".into(),
                event_id: "event".into(),
                envelope_hash: "hash".into(),
            }],
            manifest,
            deadline_ms: 1,
            lease_expires_ms: None,
            recheck_ms: None,
            duplicate_risk: false,
            created_ms: 0,
            updated_ms: 0,
            note: None,
        };
        assert!(valid_manifest(&record));
        record.manifest.push('!');
        assert!(!valid_manifest(&record));
        record.fence.manifest_hash = crate::server::sha256_hex(record.manifest.as_bytes());
        record.members.clear();
        assert!(!valid_manifest(&record));
        record.members.resize(
            33,
            MemberRef {
                publisher: "publisher".into(),
                event_id: "event".into(),
                envelope_hash: "hash".into(),
            },
        );
        assert!(!valid_manifest(&record));
        record.members.truncate(1);
        record.manifest = "x".repeat(bridge_core::framing::MAX_FRAMED_BYTES + 1);
        record.fence.manifest_hash = crate::server::sha256_hex(record.manifest.as_bytes());
        assert!(!valid_manifest(&record));
    }
}
