//! Agent Bridge interfaces crate: the restricted orchestrator surface,
//! operator recovery, outbound owner Telegram and product packaging.
//!
//! This crate owns everything an operator or a root orchestrator touches,
//! layered strictly on top of the durable core (`bridge-core`) through its
//! public client protocol (`bridge-client`):
//!
//! - [`root`]: the closed grant-aware `me`/`send`/`status` ingress for root
//!   orchestrators, on its own Unix socket and, optionally, as a stdio MCP
//!   server. Root credentials are never publisher/admin credentials.
//! - [`operator`]: the retained incident store and protected operator
//!   interfaces, including explicit same-event manual recovery with audited
//!   possible-duplicate risk and no automatic replay anywhere.
//! - [`telegram`]: the outbound-only fixed-destination owner channel with
//!   truthful failure classification; provider acceptance is never reported
//!   as proof of reading, and an unconfigured channel never implies the
//!   owner was notified.
//! - [`install`]: local package/install/rollback/doctor capability for
//!   isolated fixture qualification; release publication is out of scope.
//!
//! Boundary note: durable custody, dispatch and native adapters belong to
//! the core and adapter Modules; this crate never opens the core database
//! directly and never dispatches natively. Its own durable state is the
//! operator incident/audit database.

pub mod install;
pub mod mcp;
pub mod operator;
pub mod root;
pub mod telegram;
