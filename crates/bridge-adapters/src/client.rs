//! Clients of the adapter channel: the hook command and the cross-process
//! root-caller attestor.
//!
//! Both verify the channel before trusting it: the socket's directory must
//! be private to this user and the listening peer must run as this user.
//! The hook side never blocks its harness for long and never fails it:
//! any problem prints nothing and the harness continues; Bridge keeps the
//! event (an unconfirmed reply is a retained unknown outcome, never a
//! re-offer).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_core::Harness;

use crate::os;
use crate::registry::{
    CallerAttestor, CorrelationError, PresentedMeta, SealedProof, VerifiedCaller,
};
use crate::server::{ChannelRequest, ChannelResponse, sha256_hex};

/// Largest hook payload read from the harness, in bytes.
pub const MAX_HOOK_INPUT_BYTES: usize = 64 * 1024;

/// Largest response line accepted from the channel.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// A verified connection target.
#[derive(Debug, Clone)]
pub struct ChannelClient {
    /// The channel socket path.
    socket: PathBuf,
    /// Connect/read/write timeout.
    timeout: Duration,
}

/// What one hook run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookRun {
    /// Admitted; nothing printed.
    Admitted,
    /// A Bridge context reply was printed, flushed and confirmed.
    Injected,
    /// Nothing printed: the channel refused (class, detail).
    Refused(String, String),
    /// Nothing printed or confirmed because of a local failure.
    Failed(String),
}

impl ChannelClient {
    /// A client for `socket` with a per-operation `timeout`.
    pub fn new(socket: impl Into<PathBuf>, timeout: Duration) -> Self {
        ChannelClient {
            socket: socket.into(),
            timeout,
        }
    }

    /// Connects and verifies the channel: private directory owned by this
    /// user, listener running as this user.
    fn connect(&self) -> std::io::Result<UnixStream> {
        let own = os::process_facts(std::process::id())
            .and_then(|facts| facts.uid)
            .ok_or_else(|| std::io::Error::other("own uid unreadable"))?;
        let directory = self
            .socket
            .parent()
            .ok_or_else(|| std::io::Error::other("socket has no directory"))?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != own || metadata.mode() & 0o077 != 0 {
            return Err(std::io::Error::other("channel directory is not private"));
        }
        let stream = UnixStream::connect(&self.socket)?;
        let peer = os::peer_identity(&stream)?;
        if peer.uid != own {
            return Err(std::io::Error::other(
                "channel listener runs as another user",
            ));
        }
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// Sends one request and reads one response.
    fn exchange(
        &self,
        request: &ChannelRequest,
    ) -> std::io::Result<(ChannelResponse, UnixStream, BufReader<UnixStream>)> {
        let mut stream = self.connect()?;
        let mut line = serde_json::to_vec(request).map_err(std::io::Error::other)?;
        line.push(b'\n');
        stream.write_all(&line)?;
        stream.flush()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut text = String::new();
        reader
            .by_ref()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_line(&mut text)?;
        if text.len() > MAX_RESPONSE_BYTES || !text.ends_with('\n') {
            return Err(std::io::Error::other("malformed channel response"));
        }
        let response = serde_json::from_str(&text).map_err(std::io::Error::other)?;
        Ok((response, stream, reader))
    }

    /// Runs one hook event: forwards the native payload, and when the
    /// channel hands a context reply, writes it to `out`, flushes, and only
    /// then confirms with the digest of exactly what was written.
    ///
    /// A write or flush failure is never confirmed (Bridge records an
    /// unknown outcome). The payload must be a JSON object of at most
    /// [`MAX_HOOK_INPUT_BYTES`].
    pub fn run_hook(&self, harness: Harness, input: &[u8], out: &mut dyn Write) -> HookRun {
        if input.len() > MAX_HOOK_INPUT_BYTES {
            return HookRun::Failed("hook payload too large".into());
        }
        let payload: serde_json::Value = match serde_json::from_slice(input) {
            Ok(value @ serde_json::Value::Object(_)) => value,
            _ => return HookRun::Failed("hook payload is not a JSON object".into()),
        };
        let (response, mut stream, _reader) =
            match self.exchange(&ChannelRequest::Hook { harness, payload }) {
                Ok(exchange) => exchange,
                Err(error) => return HookRun::Failed(error.to_string()),
            };
        match response {
            ChannelResponse::Ok => HookRun::Admitted,
            ChannelResponse::Refused { class, detail } => HookRun::Refused(class, detail),
            ChannelResponse::Inject { stdout, digest } => {
                if sha256_hex(stdout.as_bytes()) != digest {
                    return HookRun::Failed("reply digest mismatch; nothing printed".into());
                }
                if out
                    .write_all(stdout.as_bytes())
                    .and_then(|()| out.write_all(b"\n"))
                    .and_then(|()| out.flush())
                    .is_err()
                {
                    return HookRun::Failed("stdout write or flush failed".into());
                }
                let mut line = match serde_json::to_vec(&ChannelRequest::Flushed { digest }) {
                    Ok(line) => line,
                    Err(error) => return HookRun::Failed(error.to_string()),
                };
                line.push(b'\n');
                match stream.write_all(&line).and_then(|()| stream.flush()) {
                    Ok(()) => HookRun::Injected,
                    Err(error) => HookRun::Failed(error.to_string()),
                }
            }
            ChannelResponse::Caller { .. } => HookRun::Failed("unexpected channel response".into()),
        }
    }
}

/// The cross-process [`CallerAttestor`]: asks the Bridge daemon's
/// registry to attest the caller of one MCP request.
///
/// The daemon identifies *this* process by kernel peer credentials; the
/// presented metadata alone attests nothing. Two compositions exist:
///
/// - **Frontend.** A harness-launched MCP server (a marked harness's own
///   descendant) presents native `_meta` with [`CallerAttestor::attest`],
///   or with [`RegistryAttestor::attest_sealed`] to also receive a sealed
///   single-use proof of the result.
/// - **Relay.** A process that is not a harness descendant (the restricted
///   MCP's root daemon) receives that proof from its frontend over its own
///   transport and presents [`PresentedMeta::sealed`]; the registry admits
///   it only from a configured relay build, once, within
///   [`crate::registry::SEALED_PROOF_TTL_MS`], while the binding is
///   unchanged. The relay learns exactly the facts the registry stored —
///   never labels the frontend chose.
#[derive(Debug, Clone)]
pub struct RegistryAttestor {
    /// Channel client.
    client: ChannelClient,
    /// Largest accepted age of the joined record at the consumer's clock.
    max_age_ms: u64,
}

impl RegistryAttestor {
    /// An attestor for the channel at `socket`.
    pub fn new(socket: &Path, timeout: Duration, max_age_ms: u64) -> Self {
        RegistryAttestor {
            client: ChannelClient::new(socket, timeout),
            max_age_ms,
        }
    }

    /// Frontend attestation that also returns a sealed proof to forward to
    /// a relay. Refuses like [`CallerAttestor::attest`]; a sealed `meta`
    /// cannot be resealed.
    pub fn attest_sealed(
        &self,
        meta: &PresentedMeta,
        now_ms: u64,
    ) -> Result<(VerifiedCaller, SealedProof), CorrelationError> {
        let (caller, proof) = self.request(meta, true, now_ms)?;
        let proof =
            proof.ok_or_else(|| CorrelationError::Unavailable("no sealed proof issued".into()))?;
        Ok((caller, proof))
    }

    /// One attestation exchange and its validation.
    fn request(
        &self,
        meta: &PresentedMeta,
        seal: bool,
        now_ms: u64,
    ) -> Result<(VerifiedCaller, Option<SealedProof>), CorrelationError> {
        let (response, _, _) = self
            .client
            .exchange(&ChannelRequest::Attest {
                meta: meta.clone(),
                seal,
            })
            .map_err(|error| CorrelationError::Unavailable(error.to_string()))?;
        match response {
            ChannelResponse::Caller {
                address,
                role,
                native_id,
                epoch,
                observed_at_ms,
                channel,
                relayed,
                proof,
            } => {
                if observed_at_ms > now_ms.saturating_add(60_000)
                    || now_ms.saturating_sub(observed_at_ms) > self.max_age_ms
                {
                    return Err(CorrelationError::Stale("caller record age".into()));
                }
                let caller =
                    VerifiedCaller::new(address, role, native_id, epoch, observed_at_ms, channel);
                Ok((
                    if relayed {
                        caller.into_relayed()
                    } else {
                        caller
                    },
                    proof,
                ))
            }
            ChannelResponse::Refused { class, detail } => {
                Err(CorrelationError::from_wire(&class, detail))
            }
            _ => Err(CorrelationError::Unavailable(
                "unexpected channel response".into(),
            )),
        }
    }
}

impl CallerAttestor for RegistryAttestor {
    /// Asks the registry; refuses on any channel failure, a refusal, or a
    /// record older than `max_age_ms` (or from the future) at `now_ms`.
    fn attest(
        &self,
        meta: &PresentedMeta,
        now_ms: u64,
    ) -> Result<VerifiedCaller, CorrelationError> {
        self.request(meta, false, now_ms).map(|(caller, _)| caller)
    }
}
