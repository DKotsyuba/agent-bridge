//! Channel capacity: a burst never silently drops an accepted connection. Every
//! connection is served, or refused with the typed busy reply that tells the
//! client nothing ran; a refused request can be repeated and succeeds. Real
//! sockets, the real registry, and a real `bridge-hook` for the recovery case.
#![cfg(target_os = "linux")]
mod common;

use bridge_adapters::client::{ChannelClient, HookRun};
use bridge_adapters::server::{ChannelServer, Custody};
use bridge_core::Harness;
use bridge_core::dispatch::DispatchTiming;
use common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

/// What one connection came back with.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Reply {
    /// The channel was at capacity and said so before reading anything.
    Busy,
    /// The request was processed (accepted or refused on its merits).
    Served,
}

/// The four request shapes the channel serves, so every protocol's busy reply
/// is checked: a legacy hook, a malformed legacy line, a B1 operation and a
/// producer v1 operation. `n` selects the shape and makes ids unique.
fn request(n: usize) -> (String, Option<String>) {
    match n % 4 {
        0 => (
            json!({"op":"hook","harness":"claude-code","payload":
                {"hook_event_name":"SessionStart","session_id":format!("s{n}")}})
            .to_string(),
            None,
        ),
        1 => ("{\"op\":\"nonsense\"}".into(), None),
        2 => (
            json!({"api_version":1,"request_id":format!("a{n}"),"credential":"synthetic-credential",
                "op":"attempt_binding_capabilities_v1","params":{"version":1}})
            .to_string(),
            Some(format!("a{n}")),
        ),
        _ => (
            json!({"api_version":1,"request_id":format!("p{n}"),"credential":"synthetic-credential",
                "op":"capabilities","params":{}})
            .to_string(),
            Some(format!("p{n}")),
        ),
    }
}

/// Only hook requests, which all wait on the registry lock a test holds.
fn hook_only(n: usize) -> (String, Option<String>) {
    request(n * 4)
}

/// Classifies one response line; panics on anything that is not a well-formed
/// typed answer for the protocol the request used.
fn classify(line: &str, id: Option<&str>) -> Reply {
    let value: Value = serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
    match id {
        None => {
            let kind = value["result"].as_str().unwrap_or_else(|| panic!("{line}"));
            if kind == "refused"
                && value["class"] == "unavailable"
                && value["detail"] == "capacity_exhausted"
            {
                Reply::Busy
            } else {
                Reply::Served
            }
        }
        Some(id) => {
            assert_eq!(value["request_id"], id, "uncorrelated reply: {line}");
            let managed = &value["result"]["value"]["error"];
            if managed["code"] == "capacity_exhausted" {
                assert_eq!(managed["recovery"], "same_key_lookup", "{line}");
                assert_eq!(managed["version"], 1);
                assert_eq!(value["success"], true);
                assert_eq!(value["result"]["op"], "attempt_binding_capabilities_v1");
                return Reply::Busy;
            }
            if value["error"]["reason"] == "capacity_exhausted" {
                assert_eq!(value["success"], false, "{line}");
                assert_eq!(value["error"]["class"], "unavailable");
                assert_eq!(value["error"]["retry_hint"], "same_identity");
                return Reply::Busy;
            }
            Reply::Served
        }
    }
}

/// Connects, writes `line`, and returns the first response line, or the exact
/// transport error (a reset, EOF or timeout is what a silent drop looks like).
fn exchange(socket: &Path, line: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|e| format!("write: {e}"))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("read: {e}"))?;
    if reply.is_empty() {
        return Err("closed without a reply".into());
    }
    Ok(reply)
}

/// Runs `clients` connections of mixed shapes at once through a barrier.
fn burst(socket: &Path, clients: usize) -> Vec<(String, Option<String>, Result<String, String>)> {
    burst_of(socket, clients, request)
}

/// Runs `clients` connections of the shapes chosen by `shape` at once.
fn burst_of(
    socket: &Path,
    clients: usize,
    shape: fn(usize) -> (String, Option<String>),
) -> Vec<(String, Option<String>, Result<String, String>)> {
    let barrier = Arc::new(Barrier::new(clients));
    let handles: Vec<_> = (0..clients)
        .map(|n| {
            let (line, id) = shape(n);
            let (socket, barrier) = (socket.to_path_buf(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                let reply = exchange(&socket, &line);
                (line, id, reply)
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap()).collect()
}

/// Replaces the lab's server with one using explicit limits.
fn with_limits(lab: &mut Lab, max_connections: usize, grace: Duration) {
    lab.channel.take().unwrap().stop();
    lab.channel = Some(
        ChannelServer::start_with_limits(
            &lab.socket,
            Arc::clone(&lab.registry),
            Arc::clone(&lab.storage) as Arc<dyn Custody>,
            DispatchTiming::default(),
            max_connections,
            grace,
        )
        .unwrap(),
    );
}

/// Waits until `check` holds, up to ten seconds.
fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Opens `n` hook connections that stall on the held registry lock and fills
/// every serving slot. Returns the threads, joined by the caller after release.
fn occupy(lab: &Lab, n: usize) -> Vec<std::thread::JoinHandle<Result<String, String>>> {
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let socket = lab.socket.clone();
            let (line, _) = request(i * 4);
            std::thread::spawn(move || exchange(&socket, &line))
        })
        .collect();
    let channel = lab.channel.as_ref().unwrap();
    until("every slot occupied", || channel.load().0 == n);
    handles
}

/// The reproduction of the joint P3-F2 failure with the real default limits: 100
/// simultaneous connections while the registry is busy. The former server
/// accepted 64 and silently closed the other 36 with their request unread
/// (`Connection reset by peer`); now all 100 wait and are all served.
#[test]
fn one_hundred_simultaneous_connections_are_all_served_at_the_default_cap() {
    let lab = Lab::new("cc1");
    let guard = lab.registry.lock().unwrap();
    let socket = lab.socket.clone();
    let clients = std::thread::spawn(move || burst_of(&socket, 100, hook_only));
    let channel = lab.channel.as_ref().unwrap();
    until("all 100 connections held by the server", || {
        let (active, pending) = channel.load();
        active + pending == 100
    });
    drop(guard);
    let results = clients.join().unwrap();
    for (line, id, reply) in &results {
        let reply = reply
            .as_ref()
            .unwrap_or_else(|e| panic!("dropped: {e} for {line}"));
        assert_eq!(classify(reply, id.as_deref()), Reply::Served, "{reply}");
    }
    assert_eq!(
        channel.busy_refusals(),
        0,
        "no refusal was needed below the cap"
    );
}

/// Waiting for a slot is backpressure, not refusal: connections that wait less
/// than the grace period are all served once a slot frees.
#[test]
fn waiting_for_a_slot_within_the_grace_period_is_served() {
    let mut lab = Lab::new("cc2");
    with_limits(&mut lab, 4, Duration::from_secs(5));
    let guard = lab.registry.lock().unwrap();
    let stalled = occupy(&lab, 4);
    let socket = lab.socket.clone();
    let clients = std::thread::spawn(move || burst_of(&socket, 40, hook_only));
    let channel = lab.channel.as_ref().unwrap();
    until("40 connections waiting", || channel.load().1 == 40);
    assert_eq!(channel.busy_refusals(), 0);
    drop(guard);
    for stalled in stalled {
        stalled.join().unwrap().unwrap();
    }
    for (line, id, reply) in clients.join().unwrap() {
        let reply = reply.unwrap_or_else(|e| panic!("dropped: {e} for {line}"));
        assert_eq!(classify(&reply, id.as_deref()), Reply::Served, "{reply}");
    }
    assert_eq!(channel.busy_refusals(), 0);
}

/// Past the grace period a waiting connection gets the typed busy reply of its
/// own protocol, is counted, and its identical request succeeds once the channel
/// recovers. 100 clients of all four shapes, then 400 so the bounded wait queue
/// overflows into the kernel listen queue; none is ever dropped.
#[test]
fn refused_connections_get_a_typed_busy_reply_and_can_retry() {
    for clients in [100, 400] {
        let mut lab = Lab::new("cc3");
        with_limits(&mut lab, 4, Duration::from_millis(300));
        let guard = lab.registry.lock().unwrap();
        let stalled = occupy(&lab, 4);
        let results = burst(&lab.socket, clients);
        let channel = lab.channel.as_ref().unwrap();
        for (line, id, reply) in &results {
            let reply = reply
                .as_ref()
                .unwrap_or_else(|e| panic!("dropped: {e} for {line}"));
            assert_eq!(classify(reply, id.as_deref()), Reply::Busy, "{reply}");
        }
        assert_eq!(
            channel.busy_refusals(),
            clients as u64,
            "every refusal is counted"
        );
        drop(guard);
        for stalled in stalled {
            stalled.join().unwrap().unwrap();
        }
        for (line, id, _) in &results {
            let reply =
                exchange(&lab.socket, line).unwrap_or_else(|e| panic!("retry dropped: {e}"));
            assert_eq!(
                classify(&reply, id.as_deref()),
                Reply::Served,
                "retry: {reply}"
            );
        }
    }
}

/// A refusal at shutdown is typed too: connections still waiting for a slot
/// when the server stops are refused, not closed.
#[test]
fn connections_waiting_at_shutdown_are_refused_not_dropped() {
    let mut lab = Lab::new("cc4");
    with_limits(&mut lab, 2, Duration::from_secs(30));
    let guard = lab.registry.lock().unwrap();
    let stalled = occupy(&lab, 2);
    let (line, id) = request(2);
    let socket = lab.socket.clone();
    let waiter = std::thread::spawn(move || exchange(&socket, &line));
    until("one connection waiting", || {
        lab.channel.as_ref().unwrap().load().1 == 1
    });
    let channel = lab.channel.take().unwrap();
    let stopper = std::thread::spawn(move || channel.stop());
    let reply = waiter
        .join()
        .unwrap()
        .unwrap_or_else(|e| panic!("dropped at stop: {e}"));
    assert_eq!(classify(&reply, id.as_deref()), Reply::Busy);
    drop(guard);
    stopper.join().unwrap();
    for stalled in stalled {
        let _ = stalled.join().unwrap();
    }
}

/// The client retries only the typed busy refusal. A native `PreToolUse` hook
/// runs once per call and fails open, so a drop used to leave that call without
/// its token for good; now the same hook waits out the busy period and the same
/// call receives its token, which attests it once.
#[test]
fn a_pre_tool_use_hook_refused_busy_still_tokens_the_same_call() {
    let mut lab = Lab::new("cc5");
    let mut harness = Harnessed::start(GENERIC, &lab.generic_store);
    let started = harness.hook(&lab.socket, GENERIC, hook("SessionStart", "zs-1"));
    assert_eq!(started["status"], 0, "{started}");
    with_limits(&mut lab, 2, Duration::from_millis(200));
    let guard = lab.registry.lock().unwrap();
    let stalled = occupy(&lab, 2);
    let socket = lab.socket.clone();
    let call = std::thread::spawn(move || {
        let reply = harness.hook(
            &socket,
            GENERIC,
            json!({"hook_event_name":"PreToolUse","session_id":"zs-1","tool_use_id":"call-1",
                "tool_name":"mcp__agent-bridge-root__bridge_me","tool_input":{"address":"x"}}),
        );
        (harness, reply)
    });
    let channel = lab.channel.as_ref().unwrap();
    until("the hook refused busy at least once", || {
        channel.busy_refusals() >= 1
    });
    drop(guard);
    let (mut harness, reply) = call.join().unwrap();
    for stalled in stalled {
        let _ = stalled.join().unwrap();
    }
    let output: Value = serde_json::from_str(reply["stdout"].as_str().unwrap().trim())
        .unwrap_or_else(|_| panic!("the hook printed no token reply: {reply}"));
    let input = &output["hookSpecificOutput"]["updatedInput"];
    assert_eq!(input["address"], "x", "the original input is preserved");
    let token = input["bridge_call_token"].as_str().expect("a token");
    let accepted = harness.mcp(&lab.socket, json!({"bridge_call_token": token}));
    assert_eq!(accepted["ok"]["role"], "root", "{accepted}");
    harness.stop();
}

/// The hook client reports a busy refusal that outlasts its retry budget as the
/// typed refusal it is, never as a transport failure, and never repeats any
/// other failure.
#[test]
fn a_busy_refusal_that_outlasts_the_retry_budget_is_reported_typed() {
    let mut lab = Lab::new("cc6");
    with_limits(&mut lab, 1, Duration::from_millis(100));
    let guard = lab.registry.lock().unwrap();
    let stalled = occupy(&lab, 1);
    let client = ChannelClient::new(&lab.socket, Duration::from_millis(900));
    let mut out = Vec::new();
    let run = client.run_hook(
        Harness::CLAUDE_CODE,
        json!({"hook_event_name":"SessionStart","session_id":"s"})
            .to_string()
            .as_bytes(),
        &mut out,
    );
    assert_eq!(
        run,
        HookRun::Refused("unavailable".into(), "capacity_exhausted".into())
    );
    assert!(out.is_empty(), "a refusal prints nothing");
    assert!(
        lab.channel.as_ref().unwrap().busy_refusals() >= 2,
        "it retried before giving up"
    );
    drop(guard);
    for stalled in stalled {
        let _ = stalled.join().unwrap();
    }
}
