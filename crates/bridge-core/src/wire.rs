//! Bounded line framing shared by the service and the client.
//!
//! The protocol is one JSON object per line over a Unix stream. Both ends
//! read with a hard byte limit enforced *before* anything is appended to
//! the line buffer, a first-byte idle timeout and a total per-line
//! deadline, so an attacker-controlled or stalled peer can neither grow
//! memory nor pin a thread, and write with a timeout so a peer that never
//! reads cannot hold a writer forever.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Maximum accepted request line length in bytes.
///
/// Requests carry bounded envelopes by contract, so this is a backstop, not
/// a working limit.
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;

/// Maximum accepted response line length in bytes.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Reads one newline-terminated line with a hard incremental byte cap.
///
/// Returns `Ok(None)` at clean EOF before any byte, and one line (without
/// the terminator) once it terminates within `max` bytes. Errors:
/// [`io::ErrorKind::WouldBlock`] when no first byte arrives within
/// `first_byte_timeout` (an idle peer, nothing was started);
/// [`io::ErrorKind::TimedOut`] when a started line is not complete within
/// `line_timeout`; [`io::ErrorKind::InvalidData`] when the line exceeds
/// `max` before terminating or is not valid UTF-8;
/// [`io::ErrorKind::UnexpectedEof`] when the peer closes mid-line. Memory
/// use is bounded by `max` plus one buffer chunk regardless of how much the
/// peer sends, because the limit is checked before every append.
/// Idle and started-line budgets are separate absolute deadlines; interrupted
/// reads never renew either budget. The line budget starts on the first
/// nonempty buffer, including bytes already buffered by an earlier call.
pub fn read_bounded_line(
    reader: &mut BufReader<UnixStream>,
    max: usize,
    first_byte_timeout: Duration,
    line_timeout: Duration,
) -> io::Result<Option<String>> {
    let mut line: Vec<u8> = Vec::with_capacity(256);
    let idle_started = Instant::now();
    let mut started: Option<Instant> = None;
    loop {
        let (budget, elapsed, kind, message) = match started {
            None => (
                first_byte_timeout,
                idle_started.elapsed(),
                io::ErrorKind::WouldBlock,
                "idle: no request started",
            ),
            Some(started) => (
                line_timeout,
                started.elapsed(),
                io::ErrorKind::TimedOut,
                "request line timed out",
            ),
        };
        let timeout = budget
            .checked_sub(elapsed)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(kind, message))?;
        // macOS refuses to set options on a socket its peer already closed
        // (EINVAL); the read below then reports the close promptly, so the
        // refusal is not an error here.
        match reader.get_ref().set_read_timeout(Some(timeout)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(error),
        }
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(if line.is_empty() {
                    io::Error::new(io::ErrorKind::WouldBlock, "idle: no request started")
                } else {
                    io::Error::new(io::ErrorKind::TimedOut, "request line timed out")
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("connection closed mid-line after {} bytes", line.len()),
                ))
            };
        }
        started.get_or_insert_with(Instant::now);
        let terminator = available.iter().position(|&byte| byte == b'\n');
        let take = terminator.unwrap_or(available.len());
        if line.len() + take > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line exceeds {max} bytes before terminating"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        let consumed = take + usize::from(terminator.is_some());
        reader.consume(consumed);
        if terminator.is_some() {
            return String::from_utf8(line).map(Some).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "line is not valid UTF-8")
            });
        }
    }
}

/// Writes one line (the bytes plus a newline) with a write timeout.
///
/// A peer that stops reading makes this fail with
/// [`io::ErrorKind::TimedOut`] or `WouldBlock` instead of blocking the
/// calling thread forever.
pub fn write_line(stream: &mut UnixStream, bytes: &[u8], timeout: Duration) -> io::Result<()> {
    stream.set_write_timeout(Some(timeout))?;
    let mut line = Vec::with_capacity(bytes.len() + 1);
    line.extend_from_slice(bytes);
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    //! Framing checks over real socket pairs.

    use super::*;

    /// A connected pair with a buffered reader on the first end.
    fn pair() -> (BufReader<UnixStream>, UnixStream) {
        let (left, right) = UnixStream::pair().unwrap();
        (BufReader::new(left), right)
    }

    /// A real socket may idle longer than the request budget before a complete
    /// multibuffer line arrives. The observed socket option establishes that
    /// the reader entered its first-byte wait; the delay is intentional idle
    /// input, not a guessed thread-readiness delay.
    #[test]
    fn request_budget_starts_after_idle_on_first_byte() {
        let (mut reader, mut peer) = pair();
        let observer = reader.get_ref().try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let wait = Instant::now();
            while observer.read_timeout().unwrap().is_none() {
                assert!(wait.elapsed() < Duration::from_secs(3));
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(300));
            let mut bytes = vec![b'a'; 16 * 1024];
            bytes.push(b'\n');
            peer.write_all(&bytes).unwrap();
            // Keep the peer open until the reader has consumed every chunk.
            peer
        });
        let result = read_bounded_line(
            &mut reader,
            32 * 1024,
            Duration::from_secs(3),
            Duration::from_millis(100),
        );
        if result.is_err() {
            reader.get_ref().shutdown(std::net::Shutdown::Both).unwrap();
        }
        let writer_result = writer.join();
        assert_eq!(result.unwrap().unwrap(), "a".repeat(16 * 1024));
        let _peer = writer_result.unwrap();
    }

    /// The bounded reader returns complete lines and a clean EOF before any
    /// bytes.
    #[test]
    fn reads_lines_and_clean_eof() {
        let (mut reader, mut peer) = pair();
        peer.write_all(b"one\ntwo\n").unwrap();
        drop(peer);
        let short = Duration::from_secs(2);
        assert_eq!(
            read_bounded_line(&mut reader, 16, short, short)
                .unwrap()
                .as_deref(),
            Some("one")
        );
        assert_eq!(
            read_bounded_line(&mut reader, 16, short, short)
                .unwrap()
                .as_deref(),
            Some("two")
        );
        assert!(
            read_bounded_line(&mut reader, 16, short, short)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    /// An oversized unterminated line is refused without buffering it
    /// whole: memory stays bounded by the cap.
    fn oversize_unterminated_line_is_refused_without_buffering_it() {
        let (mut reader, mut peer) = pair();
        peer.write_all(&[b'a'; 64]).unwrap();
        let error = read_bounded_line(
            &mut reader,
            32,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// Idle and stalled peers hit their read timeout instead of blocking
    /// the connection forever.
    #[test]
    fn idle_and_stalled_peers_time_out() {
        let (mut reader, mut peer) = pair();
        let error = read_bounded_line(
            &mut reader,
            32,
            Duration::from_millis(50),
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::WouldBlock,
            "idle is not a stall"
        );
        peer.write_all(b"partial").unwrap();
        let error = read_bounded_line(
            &mut reader,
            32,
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
