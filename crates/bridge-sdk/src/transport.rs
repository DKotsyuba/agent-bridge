//! One bounded synchronous Unix exchange with kernel peer-user authentication.
//! A private task-free Tokio driver exposes safe peer credentials only.
use crate::{ClientError, TransportOutcome};
use bridge_protocol::{MAX_RESPONSE_BYTES, Request, Response, decode_response, encode_request};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io::{Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};

/// Exchanges an immutable request at most twice within one absolute deadline.
/// The expected effective UID comes from a fresh kernel-owned socket pair; each
/// connected server is checked before any credential/request byte is written.
/// All retried mutations reuse identical bytes and correlation/event IDs. A lost
/// response never grants a direct native fallback or a replacement identity.
pub(crate) fn exchange(
    path: &Path,
    request: &Request,
    timeout: Duration,
    reconnect: bool,
) -> Result<Response, ClientError> {
    let mut bytes = encode_request(request).map_err(ClientError::InvalidRequest)?;
    bytes.push(b'\n');
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ClientError::InvalidConfig("deadline overflow"))?;
    let expected_uid =
        current_uid().map_err(|_| failure(request, false, "current user identity unavailable"))?;
    let mut last = None;
    let mut uncertain = false;
    for _ in 0..if reconnect { 2 } else { 1 } {
        if remaining(deadline).is_err() {
            break;
        }
        match once(path, request, &bytes, deadline, expected_uid) {
            Ok(response) => {
                if uncertain
                    && response.error.as_ref().is_some_and(|e| {
                        !matches!(
                            e.effect,
                            Some(
                                bridge_protocol::MutationEffect::Committed
                                    | bridge_protocol::MutationEffect::CommittedReplay
                            )
                        )
                    })
                {
                    return Err(failure(
                        request,
                        true,
                        "earlier mutation outcome unresolved",
                    ));
                }
                return Ok(response);
            }
            Err(error) => {
                uncertain |= matches!(
                    error,
                    ClientError::Transport {
                        outcome: TransportOutcome::OutcomeUnknown,
                        ..
                    }
                );
                last = Some(error);
            }
        }
    }
    let mut error = last.unwrap_or_else(|| failure(request, false, "deadline exhausted"));
    if uncertain && let ClientError::Transport { outcome, .. } = &mut error {
        *outcome = TransportOutcome::OutcomeUnknown;
    }
    Err(error)
}
/// Returns positive remaining budget; partial traffic never renews it.
fn remaining(deadline: Instant) -> Result<Duration, ()> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(())
}
/// Constructs static safe uncertainty from observed write stage and operation kind.
fn failure(request: &Request, write_attempted: bool, reason: &'static str) -> ClientError {
    let reconciliation = request.reconciliation();
    let outcome = if !write_attempted {
        TransportOutcome::NotSent
    } else if reconciliation.is_some() {
        TransportOutcome::OutcomeUnknown
    } else {
        TransportOutcome::ReadFailed
    };
    ClientError::Transport {
        outcome,
        reconciliation,
        reason,
    }
}
/// Owns one bounded connection and correlated response frame. `expected_uid` is
/// the caller's kernel-observed effective UID; missing/mismatching peer credentials
/// refuse before any write. Credentials and request bytes never enter errors.
fn once(
    path: &Path,
    request: &Request,
    bytes: &[u8],
    deadline: Instant,
    expected_uid: u32,
) -> Result<Response, ClientError> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)
        .map_err(|_| failure(request, false, "socket creation failed"))?;
    let address =
        SockAddr::unix(path).map_err(|_| failure(request, false, "invalid socket address"))?;
    socket
        .connect_timeout(
            &address,
            remaining(deadline).map_err(|_| failure(request, false, "connect deadline"))?,
        )
        .map_err(|_| failure(request, false, "connect failed"))?;
    let owned: OwnedFd = socket.into();
    let mut stream = UnixStream::from(owned);
    if peer_uid(&stream).map_err(|_| failure(request, false, "peer user unavailable"))?
        != expected_uid
    {
        return Err(failure(request, false, "peer user mismatch"));
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let budget =
            remaining(deadline).map_err(|_| failure(request, offset != 0, "write deadline"))?;
        stream
            .set_write_timeout(Some(budget))
            .map_err(|_| failure(request, offset != 0, "write timeout unavailable"))?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(failure(request, true, "write closed")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => return Err(failure(request, true, "write failed")),
        }
    }
    let mut frame = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let budget =
            remaining(deadline).map_err(|_| failure(request, true, "response deadline"))?;
        stream
            .set_read_timeout(Some(budget))
            .map_err(|_| failure(request, true, "read timeout unavailable"))?;
        let n = match stream.read(&mut buffer) {
            Ok(0) => return Err(failure(request, true, "response closed")),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(failure(request, true, "read failed")),
        };
        if let Some(end) = buffer[..n].iter().position(|b| *b == b'\n') {
            if frame.len() + end > MAX_RESPONSE_BYTES || end + 1 != n {
                return Err(failure(request, true, "invalid response framing"));
            }
            frame.extend_from_slice(&buffer[..end]);
            return decode_response(&frame, request)
                .map_err(|_| failure(request, true, "invalid correlated response"));
        }
        if frame.len() + n > MAX_RESPONSE_BYTES {
            return Err(failure(request, true, "response too large"));
        }
        frame.extend_from_slice(&buffer[..n]);
    }
}

/// Reads this process's effective UID from credentials on a fresh private socket
/// pair. Both handles close before return; no environment, path owner or label is
/// identity evidence. Missing kernel credential support fails closed.
fn current_uid() -> std::io::Result<u32> {
    let (local, _other) = UnixStream::pair()?;
    peer_uid(&local)
}

/// Reads connected-peer kernel credentials through Tokio's safe macOS/Linux API.
/// The private current-thread driver runs no tasks and never calls block_on, so
/// synchronous SDK use inside another Tokio runtime cannot trigger nested polling.
/// The borrowed stream must be exclusively used during this call: its clone shares
/// nonblocking flags, restored to blocking on every result. All duplicate handles
/// and the task-free driver are released before return; errors expose no peer data.
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let result = (|| {
        let _entered = runtime.enter();
        let clone = stream.try_clone()?;
        clone.set_nonblocking(true)?;
        let registered = tokio::net::UnixStream::from_std(clone)?;
        let uid = registered.peer_cred().map(|credentials| credentials.uid());
        drop(registered.into_std()?);
        uid
    })();
    // No tasks were spawned. Nonblocking shutdown is valid even when the SDK
    // was called synchronously from a surrounding runtime's worker thread.
    runtime.shutdown_background();
    stream.set_nonblocking(false)?;
    result
}

#[cfg(test)]
mod tests {
    //! Kernel peer controls use real private sockets without changing OS users.
    use super::*;
    use bridge_protocol::{CapabilitiesParams, Operation, Secret};
    use std::os::unix::net::UnixListener;

    /// A wrong expected UID is refused at the production pre-write guard: the
    /// real listener receives EOF and no credential byte. The process's socket-pair
    /// UID is verified first; no privileged cross-user fixture is used.
    #[test]
    fn wrong_peer_uid_sends_no_credential() {
        let base =
            std::path::PathBuf::from(std::env::var_os("TMPDIR").expect("explicit task TMPDIR"));
        assert!(base.is_absolute());
        let path = base.join(format!("sdk-peer-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let uid = current_uid().unwrap();
        let (local, other) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&local).unwrap(), uid);
        assert_eq!(peer_uid(&other).unwrap(), uid);
        let request = Request::new(
            "peer",
            Secret::new("credential-must-not-cross"),
            Operation::Capabilities(CapabilitiesParams {}),
        )
        .unwrap();
        let bytes = encode_request(&request).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut observed = [0_u8; 1];
            assert_eq!(
                stream.read(&mut observed).unwrap(),
                0,
                "credential bytes reached a refused peer"
            );
        });
        let error = once(
            &path,
            &request,
            &bytes,
            Instant::now() + Duration::from_secs(2),
            uid.wrapping_add(1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ClientError::Transport {
                outcome: TransportOutcome::NotSent,
                reconciliation: None,
                reason: "peer user mismatch"
            }
        ));
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
