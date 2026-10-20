//! Agent Bridge native adapters: protected caller registry, quiet root
//! hooks and Codex/Claude message carriers.
//!
//! This crate owns the `bridge-native-host` and `bridge-root-caller`
//! boundaries. It consumes core's one authoritative custody and attempt
//! state — [`bridge_core::dispatch::DispatchCarrier`], `observe_binding`,
//! `drain_inject` and `record_outcome` — and keeps no second attempt or
//! hook database.
//!
//! Module layout:
//! - [`os`]: kernel-observed peer credentials and process facts.
//! - [`registry`]: harness incarnations, fenced endpoint epochs, owner
//!   lifecycle from the session's own hooks, single-use call records, and
//!   the root-caller ABI ([`registry::CallerAttestor`],
//!   [`registry::PresentedMeta`], [`registry::VerifiedCaller`]).
//! - [`server`]: the daemon-side private channel (hook events, manifest-
//!   first inject drain, caller attestation).
//! - [`client`]: the hook command's client and the cross-process
//!   [`client::RegistryAttestor`].
//! - [`codex`]: source-labelled application delivery or confined CLI queue.
//! - [`desktop`]: bounded native application message-tool framing.
//! - [`claude`]: the Claude `later` message carrier with a callback socket
//!   unique to each attempt.
//! - [`owner`]: the generic native-owner wake route for supervisor-owned live
//!   Codex and Claude Code processes.
//!
//! Binaries: `bridge-hook` (installed as the harness hook command) and
//! `bridge-native-daemon` (core service + carriers + channel).
//!
//! Boundary: capabilities are what the configured harness-level policy supports
//! for a verified harness process, not liveness. Same-user code running inside a harness's own tool
//! sandbox shares its process ancestry and is outside the claimed
//! isolation (see [`registry`]). Library tests use owned fixture processes
//! and do not establish delivery to, or context in, a real model; native
//! qualification is the Root's separate, recorded run of owned frontends and
//! covers only the builds it names.

pub mod claude;
pub mod client;
pub mod codex;
pub mod desktop;
pub mod native_mcp;
pub mod opencode;
pub mod os;
pub mod owner;
pub mod registry;
pub mod server;

pub use client::{ChannelClient, HookRun, RegistryAttestor};
pub use registry::{
    ActorRole, CallerAttestor, CallerChannel, CorrelationError, HarnessPolicy, PresentedMeta,
    Registry, RegistryConfig, Unattested, VendorSignature, VerifiedCaller, refresh_executables,
    stop_executable_refresh,
};
pub use server::{ChannelServer, Custody, LateCustody};
