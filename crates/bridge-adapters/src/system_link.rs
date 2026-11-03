//! Bounded, full-duplex coordinator/worker RPC over one fixed peer connection.
//!
//! One reader owns framing; callers wait for replies without holding a lock.
//! The socket's owner assigns `peer_uid`; a frame cannot change that authority.

use std::collections::HashMap;
use std::io::{self, BufReader};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};
use std::time::{Duration, Instant};

use crate::system_ipc::{Event, Frame, Request, Response, read_frame, write_frame};

/// Maximum simultaneous requests waiting for a reply on this connection.
const MAX_PENDING: usize = 64;
/// Bound for one complete inbound frame and one outbound frame.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle reads periodically check whether the link has been closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);

/// An inbound operation with its socket-assigned peer identity.
pub(crate) enum Incoming {
    /// A peer request requiring exactly one response.
    Request {
        /// Peer identity assigned to this socket.
        peer_uid: u32,
        /// Peer-issued correlation number.
        request_id: u64,
        /// Typed operation from the peer.
        request: Request,
    },
    /// An unsolicited event from the peer.
    Event {
        /// Peer identity assigned to this socket.
        peer_uid: u32,
        /// Typed event from the peer.
        event: Event,
    },
    /// The link failed or its peer closed; in-flight operations are uncertain.
    Closed {
        /// Peer identity assigned to the closed socket.
        peer_uid: u32,
    },
}

/// Correlation state, held only long enough to assign or deliver a reply.
struct Pending {
    /// Next outbound request number, assigned under the writer lock.
    next: u64,
    /// One bounded response channel per in-flight request.
    calls: HashMap<u64, mpsc::SyncSender<Response>>,
}

/// Shared link state; closing the socket wakes the sole reader and callers.
struct State {
    /// Serializes complete outbound frames and request IDs.
    writer: Mutex<UnixStream>,
    /// A separate handle permits shutdown even while the writer is busy.
    shutdown: UnixStream,
    /// Bounded response correlation table.
    pending: Mutex<Pending>,
    /// Bounded delivery queue owned by the connection's caller.
    incoming: mpsc::SyncSender<Incoming>,
    /// Permanent transport-failure flag.
    closed: AtomicBool,
    /// Required generation for every frame on this link.
    generation: u64,
    /// Peer identity fixed by the socket owner.
    peer_uid: u32,
}

impl State {
    /// Closes both directions once and makes all pending requests fail closed.
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.shutdown.shutdown(Shutdown::Both);
            if let Ok(mut pending) = self.pending.lock() {
                pending.calls.clear();
            }
            let _ = self.incoming.try_send(Incoming::Closed {
                peer_uid: self.peer_uid,
            });
        }
    }

    /// Writes under a bounded writer lock; any write failure closes the link.
    fn send(&self, frame: &Frame, budget: Duration) -> Result<(), &'static str> {
        let started = Instant::now();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err("IPC link closed");
            }
            let remaining = budget
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero());
            let Some(remaining) = remaining else {
                self.close();
                return Err("IPC write deadline exceeded");
            };
            match self.writer.try_lock() {
                Ok(mut stream) => {
                    let result = write_frame(&mut stream, frame, remaining);
                    drop(stream);
                    if result.is_err() {
                        self.close();
                        return Err("IPC write failed");
                    }
                    return Ok(());
                }
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining.min(Duration::from_millis(1)))
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.close();
                    return Err("IPC writer unavailable");
                }
            }
        }
    }
}

impl Drop for State {
    /// Closes the socket when its last owner disappears.
    fn drop(&mut self) {
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}

/// Cloneable handle for one generation and one preassigned peer UID.
#[derive(Clone)]
pub(crate) struct Link(Arc<State>);

impl Link {
    /// Starts the single reader and binds all inbound messages to `peer_uid`.
    pub(crate) fn new(
        stream: UnixStream,
        generation: u64,
        peer_uid: u32,
        incoming: mpsc::SyncSender<Incoming>,
    ) -> Result<Self, &'static str> {
        let reader = stream.try_clone().map_err(|_| "IPC socket unavailable")?;
        let shutdown = stream.try_clone().map_err(|_| "IPC socket unavailable")?;
        let state = Arc::new(State {
            writer: Mutex::new(stream),
            shutdown,
            pending: Mutex::new(Pending {
                next: 1,
                calls: HashMap::new(),
            }),
            incoming,
            closed: AtomicBool::new(false),
            generation,
            peer_uid,
        });
        let weak = Arc::downgrade(&state);
        std::thread::Builder::new()
            .name("bridge-system-ipc".into())
            .spawn(move || {
                let mut reader = BufReader::new(reader);
                let mut last_request = 0;
                loop {
                    let frame = match read_frame(&mut reader, IDLE_TIMEOUT, FRAME_TIMEOUT) {
                        Ok(Some(frame)) => frame,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if weak
                                .upgrade()
                                .is_none_or(|state| state.closed.load(Ordering::SeqCst))
                            {
                                break;
                            }
                            continue;
                        }
                        _ => break,
                    };
                    let Some(state) = weak.upgrade() else { break };
                    let valid = match frame {
                        Frame::Response {
                            generation: actual,
                            request_id,
                            response,
                        } if actual == generation => match state.pending.lock() {
                            Ok(mut pending) => pending
                                .calls
                                .remove(&request_id)
                                .is_some_and(|sender| sender.try_send(response).is_ok()),
                            Err(_) => false,
                        },
                        Frame::Request {
                            generation: actual,
                            request_id,
                            request,
                        } if actual == generation && request_id > last_request => {
                            last_request = request_id;
                            state
                                .incoming
                                .try_send(Incoming::Request {
                                    peer_uid,
                                    request_id,
                                    request,
                                })
                                .is_ok()
                        }
                        Frame::Event {
                            generation: actual,
                            event,
                        } if actual == generation => state
                            .incoming
                            .try_send(Incoming::Event { peer_uid, event })
                            .is_ok(),
                        _ => false,
                    };
                    if !valid {
                        state.close();
                        break;
                    }
                }
                if let Some(state) = weak.upgrade() {
                    state.close();
                }
            })
            .map_err(|_| "IPC reader unavailable")?;
        Ok(Self(state))
    }

    /// Sends a request and waits within `timeout`; an uncertain result closes the link.
    pub(crate) fn call(
        &self,
        request: Request,
        timeout: Duration,
    ) -> Result<Response, &'static str> {
        self.call_with_writer_wait(request, timeout, || {})
    }

    /// Calls with a one-shot observation of writer contention for the concurrency test.
    fn call_with_writer_wait(
        &self,
        request: Request,
        timeout: Duration,
        on_writer_wait: impl FnOnce(),
    ) -> Result<Response, &'static str> {
        let started = Instant::now();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut on_writer_wait = Some(on_writer_wait);
        // Assign the ID while holding the writer: the monotonic ID order is
        // therefore identical to wire order even for concurrent callers.
        loop {
            if self.is_closed() {
                return Err("IPC link closed");
            }
            let Some(remaining) = timeout
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
            else {
                self.0.close();
                return Err("IPC request uncertain");
            };
            match self.0.writer.try_lock() {
                Ok(mut stream) => {
                    let request_id = match self.0.pending.lock() {
                        Ok(mut pending) => {
                            if self.is_closed() || pending.calls.len() >= MAX_PENDING {
                                return Err("IPC unavailable");
                            }
                            let id = pending.next;
                            let Some(next) = id.checked_add(1) else {
                                drop(pending);
                                drop(stream);
                                self.0.close();
                                return Err("IPC request IDs exhausted");
                            };
                            pending.next = next;
                            pending.calls.insert(id, sender);
                            id
                        }
                        Err(_) => {
                            drop(stream);
                            self.0.close();
                            return Err("IPC unavailable");
                        }
                    };
                    let frame = Frame::Request {
                        generation: self.0.generation,
                        request_id,
                        request,
                    };
                    let result = write_frame(&mut stream, &frame, remaining);
                    drop(stream);
                    if result.is_err() {
                        self.0.close();
                        return Err("IPC request uncertain");
                    }
                    break;
                }
                Err(TryLockError::WouldBlock) => {
                    if let Some(observe) = on_writer_wait.take() {
                        observe();
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(1)))
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.0.close();
                    return Err("IPC unavailable");
                }
            }
        }
        let remaining = timeout.checked_sub(started.elapsed()).unwrap_or_default();
        match receiver.recv_timeout(remaining) {
            Ok(response) => Ok(response),
            Err(_) => {
                self.0.close();
                Err("IPC request uncertain")
            }
        }
    }

    /// Sends the response to an inbound request or closes on failure.
    pub(crate) fn respond(&self, request_id: u64, response: Response) -> Result<(), &'static str> {
        self.0.send(
            &Frame::Response {
                generation: self.0.generation,
                request_id,
                response,
            },
            FRAME_TIMEOUT,
        )
    }

    /// Sends one unsolicited event or closes on failure.
    pub(crate) fn event(&self, event: Event) -> Result<(), &'static str> {
        self.0.send(
            &Frame::Event {
                generation: self.0.generation,
                event,
            },
            FRAME_TIMEOUT,
        )
    }

    /// Fails the link and wakes the peer and all pending callers.
    pub(crate) fn close(&self) {
        self.0.close();
    }

    /// Reports whether a transport or protocol failure closed this link.
    pub(crate) fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    //! Socketpair tests cover reentrant RPC and fatal timeout handling.
    use super::*;

    /// Concurrent callers allocate IDs only after acquiring the writer, so
    /// every frame arrives in strictly increasing order.
    #[test]
    fn concurrent_calls_preserve_wire_order() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let (tx, _rx) = mpsc::sync_channel(4);
        let link = Link::new(a, 11, 42, tx).unwrap();
        let writer = link.0.writer.lock().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(17));
        let (waiting_tx, waiting_rx) = mpsc::sync_channel(16);
        let callers: Vec<_> = (0..16)
            .map(|_| {
                let link = link.clone();
                let barrier = Arc::clone(&barrier);
                let waiting_tx = waiting_tx.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    link.call_with_writer_wait(Request::Activate {}, Duration::from_secs(5), || {
                        waiting_tx.send(()).unwrap()
                    })
                })
            })
            .collect();
        barrier.wait();
        for _ in 0..16 {
            waiting_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        assert_eq!(link.0.pending.lock().unwrap().next, 1);
        drop(writer);
        let mut reader = BufReader::new(b.try_clone().unwrap());
        for expected in 1..=16 {
            let frame = read_frame(&mut reader, Duration::from_secs(5), Duration::from_secs(5))
                .unwrap()
                .unwrap();
            let Frame::Request { request_id, .. } = frame else {
                panic!("request")
            };
            assert_eq!(request_id, expected);
            write_frame(
                &mut b,
                &Frame::Response {
                    generation: 11,
                    request_id,
                    response: Response::Ok {},
                },
                Duration::from_secs(5),
            )
            .unwrap();
        }
        for caller in callers {
            assert!(matches!(caller.join().unwrap(), Ok(Response::Ok {})));
        }
    }

    /// A full inbound queue fails closed instead of dropping a frame silently.
    #[test]
    fn full_incoming_queue_closes_link() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let link = Link::new(socket, 5, 42, tx).unwrap();
        for _ in 0..2 {
            write_frame(
                &mut peer,
                &Frame::Event {
                    generation: 5,
                    event: Event::Hello {},
                },
                Duration::from_secs(2),
            )
            .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !link.is_closed() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(link.is_closed());
        assert!(matches!(rx.try_recv(), Ok(Incoming::Event { .. })));
    }

    /// A frame from another generation permanently closes the connection.
    #[test]
    fn rejects_other_generation() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::sync_channel(2);
        let link = Link::new(socket, 5, 42, tx).unwrap();
        write_frame(
            &mut peer,
            &Frame::Event {
                generation: 6,
                event: Event::Hello {},
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(2)),
            Ok(Incoming::Closed { peer_uid: 42 })
        ));
        assert!(link.is_closed());
    }

    /// A request may receive and answer a callback before its own reply arrives.
    #[test]
    fn reentrant_calls_and_timeout_close() {
        let (a, b) = UnixStream::pair().unwrap();
        let (a_tx, a_rx) = mpsc::sync_channel(4);
        let (b_tx, b_rx) = mpsc::sync_channel(4);
        let a = Link::new(a, 7, 2, a_tx).unwrap();
        let b = Link::new(b, 7, 1, b_tx).unwrap();
        let worker = std::thread::spawn(move || {
            let Incoming::Request { request_id, .. } = b_rx.recv().unwrap() else {
                panic!("request")
            };
            assert!(matches!(
                b.call(Request::Maintenance { now_ms: 1 }, Duration::from_secs(2)),
                Ok(Response::Ok {})
            ));
            b.respond(request_id, Response::Ok {}).unwrap();
            b
        });
        let caller = a.clone();
        let call =
            std::thread::spawn(move || caller.call(Request::Activate {}, Duration::from_secs(2)));
        let Incoming::Request {
            request_id,
            peer_uid,
            ..
        } = a_rx.recv().unwrap()
        else {
            panic!("callback")
        };
        assert_eq!(peer_uid, 2);
        a.respond(request_id, Response::Ok {}).unwrap();
        assert!(matches!(call.join().unwrap(), Ok(Response::Ok {})));
        let _b = worker.join().unwrap();
        assert!(
            a.call(Request::Activate {}, Duration::from_millis(30))
                .is_err()
        );
        assert!(a.is_closed());
    }
}
