//! Single integration-test binary: each module is a former `tests/*.rs` crate.
//! One binary links dependencies once; nextest still runs every test in its own process.

#[path = "../install_script.rs"]
mod install_script;
#[path = "../lifecycle.rs"]
mod lifecycle;
#[path = "../observe.rs"]
mod observe;
#[path = "../operator_counts.rs"]
mod operator_counts;
#[path = "../root_composition.rs"]
mod root_composition;
