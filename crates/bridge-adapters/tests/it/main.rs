//! Single integration-test binary: each module is a former `tests/*.rs` crate.
//! One binary links dependencies once; nextest still runs every test in its own process.

#[path = "../attempt_binding.rs"]
mod attempt_binding;
#[path = "../channel_capacity.rs"]
mod channel_capacity;
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "some helpers serve Linux-only test modules")
)]
#[path = "../common/mod.rs"]
mod common;
#[path = "../hook_load.rs"]
mod hook_load;
#[path = "../hook_token.rs"]
mod hook_token;
#[path = "../native.rs"]
mod native;
#[path = "../native_mcp.rs"]
mod native_mcp;
#[path = "../observations.rs"]
mod observations;
#[path = "../owner.rs"]
mod owner;
#[path = "../producer.rs"]
mod producer;
#[path = "../qualify_codex.rs"]
mod qualify_codex;
#[path = "../system_multi_uid.rs"]
mod system_multi_uid;
