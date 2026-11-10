//! Concurrent first-hook load on the real adapter channel, using only owned
//! fixture harness processes and the product `bridge-hook`.
//!
//! Twenty managed-route harnesses (the shape of twenty Pool members joining at
//! once) each fire five real hooks at the same instant: one hundred
//! simultaneous connections from live peers. Every hook must be answered
//! within the product hook's own client timeout, so none may report a
//! timeout or a refusal, and every session must end up bound. The latency
//! distribution is reported, never asserted as a hard threshold.
#![cfg(target_os = "linux")]
mod common;

use bridge_adapters::registry::{ManagedTools, Registry, RelayExecutable, file_sha256};
use bridge_adapters::server::{ChannelServer, Custody, private_directory};
use bridge_core::Harness;
use bridge_core::dispatch::DispatchTiming;
use common::*;
use serde_json::{Value, json};
use std::sync::{Arc, Barrier, Mutex};

/// Harness processes, one per simulated member.
const MEMBERS: usize = 20;

/// Hooks each member fires at once.
const HOOKS_PER_MEMBER: usize = 5;

/// A lab with a managed tool route, so hooks take the managed ancestry and
/// launch-capture path of a production Pool deployment.
fn managed_lab() -> Lab {
    let mut lab = Lab::new("hl");
    lab.channel.take().unwrap().stop();
    lab.config.managed_tools.push(ManagedTools {
        producer: "pool-fixture".into(),
        server: "pool".into(),
        commands: vec!["join".into()],
        frontend: RelayExecutable {
            path: fixture_exe(),
            sha256: file_sha256(&fixture_exe()).unwrap(),
        },
    });
    let owner = private_directory(lab.socket.parent().unwrap()).unwrap();
    lab.registry = Arc::new(Mutex::new(
        Registry::new(lab.config.clone(), owner).unwrap(),
    ));
    lab.channel = Some(
        ChannelServer::start(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
        )
        .unwrap(),
    );
    lab
}

/// The five hooks of one member's first managed tool call, `round` keeping
/// call ids distinct between bursts.
fn member_payloads(session: &str, round: usize) -> Vec<Value> {
    let mut start = hook("SessionStart", session);
    start["source"] = json!("startup");
    vec![
        start,
        hook("UserPromptSubmit", session),
        tool_hook("PreToolUse", session, &format!("join-{round}"), None),
        {
            let mut managed = tool_hook("PreToolUse", session, &format!("pool-{round}"), None);
            managed["tool_name"] = json!("mcp__pool__join");
            managed
        },
        tool_hook("PostToolUse", session, &format!("join-{round}"), None),
    ]
}

/// Fires one simultaneous burst from every member and returns every hook
/// result tagged with its member index.
fn burst(
    lab: &Lab,
    members: &mut [(Harness, String, Harnessed)],
    round: usize,
) -> Vec<(usize, Value)> {
    let start = Barrier::new(members.len());
    std::thread::scope(|scope| {
        let runs: Vec<_> = members
            .iter_mut()
            .enumerate()
            .map(|(index, (harness, session, member))| {
                let start = &start;
                let request = json!({
                    "cmd": "hook_burst", "bin": hook_exe(), "socket": lab.socket,
                    "harness": harness.as_str(),
                    "payloads": member_payloads(session, round),
                });
                scope.spawn(move || {
                    start.wait();
                    let results = member.cmd(request);
                    results
                        .as_array()
                        .expect("burst results")
                        .iter()
                        .map(|result| (index, result.clone()))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        runs.into_iter()
            .flat_map(|run| run.join().expect("member thread"))
            .collect()
    })
}

/// Nearest-rank percentile of sorted milliseconds.
fn percentile(sorted: &[u64], percent: usize) -> u64 {
    let rank = (sorted.len() * percent).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// One hundred simultaneous hooks from twenty live managed members are all
/// admitted within the client timeout: no timeout, no refusal (in particular
/// no `not_evidence` for a live peer), every session bound. Two bursts: the
/// first sight of every session, then the same members again.
#[test]
fn hundred_concurrent_first_hooks_are_served_within_the_client_timeout() {
    let lab = managed_lab();
    let mut members: Vec<(Harness, String, Harnessed)> = (0..MEMBERS)
        .map(|index| {
            let (harness, store) = if index % 2 == 0 {
                (Harness::CLAUDE_CODE, &lab.claude_store)
            } else {
                (Harness::CODEX, &lab.codex_store)
            };
            let launch = format!("01234567-89ab-4cde-8fab-{index:012x}");
            let session = format!("load-session-{index:02}");
            (
                harness,
                session,
                Harnessed::start_with_launch(harness, store, &launch),
            )
        })
        .collect();
    for round in 0..2 {
        let results = burst(&lab, &mut members, round);
        assert_eq!(results.len(), MEMBERS * HOOKS_PER_MEMBER);
        let mut elapsed: Vec<u64> = results
            .iter()
            .map(|(_, result)| result["elapsed_ms"].as_u64().expect("elapsed"))
            .collect();
        elapsed.sort_unstable();
        let summary = format!(
            "round {round}: {} concurrent hooks, p50 {} ms, p95 {} ms, max {} ms",
            elapsed.len(),
            percentile(&elapsed, 50),
            percentile(&elapsed, 95),
            elapsed[elapsed.len() - 1],
        );
        eprintln!("hook load {summary}");
        let failed: Vec<_> = results
            .iter()
            .filter(|(_, result)| {
                result["status"] != json!(0) || !result["stderr"].as_str().unwrap_or("?").is_empty()
            })
            .collect();
        assert!(
            failed.is_empty(),
            "{summary}; {} hooks failed, first: {:?}",
            failed.len(),
            failed.first()
        );
    }
    let registry = lab.registry.lock().unwrap();
    for (harness, session, _) in &members {
        let address = if *harness == Harness::CLAUDE_CODE {
            lab.claude_address(session)
        } else {
            lab.codex_address(session)
        };
        registry
            .attest_recipient(&address)
            .unwrap_or_else(|error| panic!("{session} is not bound: {error}"));
    }
}
