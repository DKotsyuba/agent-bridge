//! Single integration-test binary: each module is a former `tests/*.rs` crate.
//! One binary links dependencies once; nextest still runs every test in its own process.

#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "some helpers serve Linux-only test modules")
)]
#[path = "../common/mod.rs"]
mod common;
#[path = "../corrections.rs"]
mod corrections;
#[path = "../crash_refusal.rs"]
mod crash_refusal;
#[path = "../dispatch.rs"]
mod dispatch;
#[path = "../lifecycle.rs"]
mod lifecycle;
#[path = "../lineage.rs"]
mod lineage;
#[path = "../managed.rs"]
mod managed;
#[path = "../migration.rs"]
mod migration;
#[path = "../owner_v2.rs"]
mod owner_v2;
#[path = "../peer_surface.rs"]
mod peer_surface;
#[path = "../service.rs"]
mod service;
#[path = "../storage.rs"]
mod storage;
#[path = "../universal.rs"]
mod universal;
