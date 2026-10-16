//! Owned crash-child controls for refused orphan-WAL preservation and native
//! hot rollback to committed content before supported-schema fencing.

/// Shared isolated event and temporary-path fixtures, with no installed state.
mod common;

use bridge_core::{Limits, Storage};
use common::TempDir;
use rusqlite::Connection;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Child-only fixture entrypoint. The parent supplies a fresh isolated path
/// and WAL/hot mode; exit71 deliberately bypasses SQLite/Rust destructors.
/// No native sessions, network or signals are involved.
#[test]
#[ignore = "invoked only by the owned crash-fixture parent"]
fn unsupported_crash_child() {
    let path = std::env::var_os("BRIDGE_CRASH_FIXTURE_PATH").expect("owned fixture path");
    let mode = std::env::var("BRIDGE_CRASH_FIXTURE_MODE").unwrap();
    let foreign = std::env::var("BRIDGE_CRASH_FIXTURE_FOREIGN").unwrap() == "true";
    let path = std::path::PathBuf::from(path);
    let connection = Connection::open(&path).unwrap();
    let supported = mode.starts_with("supported-");
    connection
        .pragma_update(
            None,
            "journal_mode",
            if mode.ends_with("wal") {
                "WAL"
            } else {
                "DELETE"
            },
        )
        .unwrap();
    connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .unwrap();
    connection.execute_batch("CREATE TABLE notes(id INTEGER PRIMARY KEY, body BLOB); INSERT INTO notes VALUES(1,zeroblob(524288));").unwrap();
    if supported {
        connection
            .execute_batch(include_str!("fixtures/schema-v5.sql"))
            .unwrap();
        connection
            .execute("INSERT INTO schema_meta VALUES('schema_version','5')", [])
            .unwrap();
        let envelope = common::keep_all(
            "agent-run",
            "retained",
            &common::codex("crash"),
            bridge_core::Mode::Message,
        );
        connection.execute("INSERT INTO events(publisher_id,event_id,envelope_hash,envelope_json,state,acceptance_seq,accepted_at_ms,recipient,policy_class,mode) VALUES('agent-run','retained',?1,?2,'pending',1,1000,?3,'keep_all','message')", rusqlite::params![envelope.envelope_hash().as_str(), envelope.canonical_bytes(), envelope.recipient.to_canonical_string()]).unwrap();
        connection
            .execute(
                "UPDATE counters SET value=1 WHERE name='acceptance_seq'",
                [],
            )
            .unwrap();
    } else if !foreign {
        connection.execute_batch("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO schema_meta VALUES('schema_version','999');").unwrap();
    }
    if mode.ends_with("hot") {
        std::fs::write(
            path.with_extension("committed"),
            std::fs::read(&path).unwrap(),
        )
        .unwrap();
        connection.pragma_update(None, "cache_size", 4).unwrap();
        connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
        if supported {
            connection.execute("UPDATE events SET envelope_json=zeroblob(length(envelope_json)) WHERE event_id='retained'", []).unwrap();
        }
        // Force cache spill after dirtying custody, using deterministic bytes.
        connection.execute("UPDATE notes SET body=CAST(replace(hex(zeroblob(262144)),'0','x') AS BLOB) WHERE id=1", []).unwrap();
    }
    std::process::exit(71);
}

/// Runs and reaps one owned child within ten seconds. Timeout kills/reaps
/// only that child and fails. Successful fixture termination is exactly71.
/// `path` is a fresh owned file; `mode` is wal/hot or supported-wal/hot;
/// `foreign` omits schema ownership metadata for unsupported fixtures.
fn crash_fixture(path: &Path, mode: &str, foreign: bool) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "unsupported_crash_child",
            "--ignored",
            "--nocapture",
        ])
        .env("BRIDGE_CRASH_FIXTURE_PATH", path)
        .env("BRIDGE_CRASH_FIXTURE_MODE", mode)
        .env("BRIDGE_CRASH_FIXTURE_FOREIGN", foreign.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(71));
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("owned crash fixture exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Captures durable database/WAL/journal bytes and SHM without opening SQLite;
/// only absent files map to None, and other filesystem errors fail the test.
fn files(path: &Path) -> Vec<Option<Vec<u8>>> {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .map(
            |suffix| match std::fs::read(format!("{}{suffix}", path.display())) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("fixture read failed: {error}"),
            },
        )
        .collect()
}

/// Actual Storage::open must refuse unsupported stores without checkpointing
/// orphan WAL. Native hot rollback alone may restore the exact committed DB
/// and remove its journal before schema inspection; it must not enable WAL
/// or migrate the unsupported schema. Reports contain offsets/presence only.
#[test]
fn unsupported_crash_refusal_preserves_wal_or_restores_hot_committed_bytes() {
    let mut violations = Vec::new();
    for mode in ["wal", "hot"] {
        for foreign in [false, true] {
            let dir = TempDir::new("crash-refuse");
            let path = dir.path("state.db");
            crash_fixture(&path, mode, foreign);
            let before = files(&path);
            let committed =
                (mode == "hot").then(|| std::fs::read(path.with_extension("committed")).unwrap());
            if mode == "wal" {
                assert!(before[1].as_ref().is_some_and(|bytes| !bytes.is_empty()));
                assert!(before[2].is_some());
            } else {
                assert!(before[3].as_ref().is_some_and(|bytes| bytes.len() > 512));
                assert!(
                    before[0].as_ref() != committed.as_ref(),
                    "fixture must spill actual uncommitted DB writes"
                );
            }
            let result = Storage::open(&path, Limits::new(10));
            eprintln!(
                "mode={mode} foreign={foreign} result={:?}",
                result.as_ref().err()
            );
            assert!(matches!(&result, Err(bridge_core::CoreError::Integrity(_))));
            drop(result);
            let after = files(&path);
            for (index, suffix) in ["", "-wal", "-shm", "-journal"].into_iter().enumerate() {
                let offsets: Vec<_> = before[index]
                    .iter()
                    .flatten()
                    .zip(after[index].iter().flatten())
                    .enumerate()
                    .filter(|(_, (a, b))| a != b)
                    .map(|(offset, _)| offset)
                    .take(24)
                    .collect();
                eprintln!(
                    "{mode} foreign={foreign} file={suffix:?} before_len={:?} after_len={:?} first_changed_offsets={offsets:?}",
                    before[index].as_ref().map(Vec::len),
                    after[index].as_ref().map(Vec::len)
                );
                let preserved = if mode == "hot" && index == 0 {
                    after[index].as_ref() == committed.as_ref()
                } else if mode == "hot" && index == 3 {
                    after[index].is_none()
                } else if index == 2 {
                    before[index].is_some() == after[index].is_some()
                } else {
                    before[index] == after[index]
                };
                if !preserved {
                    violations.push(format!("{mode} foreign={foreign} file={suffix:?}"));
                }
            }
            {
                let raw =
                    Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                        .unwrap();
                let journal: String = raw
                    .pragma_query_value(None, "journal_mode", |row| row.get(0))
                    .unwrap();
                assert_eq!(journal, if mode == "hot" { "delete" } else { "wal" });
                if !foreign {
                    assert_eq!(
                        raw.query_row(
                            "SELECT value FROM schema_meta WHERE key='schema_version'",
                            [],
                            |row| row.get::<_, String>(0)
                        )
                        .unwrap(),
                        "999"
                    );
                } else {
                    assert_eq!(
                        raw.query_row(
                            "SELECT COUNT(*) FROM sqlite_master WHERE name='schema_meta'",
                            [],
                            |row| row.get::<_, i64>(0)
                        )
                        .unwrap(),
                        0
                    );
                }
                drop(raw);
                let diagnosed = files(&path);
                assert!(
                    [0, 1, 3]
                        .into_iter()
                        .all(|index| diagnosed[index] == after[index])
                );
                assert_eq!(diagnosed[2].is_some(), after[2].is_some());
            }
        }
    }
    assert!(
        violations.is_empty(),
        "durable refusal violations: {violations:?}"
    );
}

/// Supported version-five custody recovers after both orphan-WAL and hot
/// rollback crashes, migrates normally, and retains exact committed envelope
/// bytes/hash. Success restores the usual close-checkpoint policy and permits
/// a fresh publication. Each fixture child is bounded and reaped.
#[test]
fn supported_crash_restart_preserves_custody_and_migrates() {
    for mode in ["supported-wal", "supported-hot"] {
        let dir = TempDir::new("crash-supported");
        let path = dir.path("state.db");
        crash_fixture(&path, mode, false);
        let expected = common::keep_all(
            "agent-run",
            "retained",
            &common::codex("crash"),
            bridge_core::Mode::Message,
        );
        let mut storage = Storage::open(&path, Limits::new(100)).unwrap();
        let receipt = storage
            .lookup(&expected.publisher, &expected.event_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.envelope_hash, expected.envelope_hash());
        assert_eq!(receipt.acceptance_seq, 1);
        {
            let raw = Connection::open(&path).unwrap();
            let bytes: Vec<u8> = raw
                .query_row(
                    "SELECT envelope_json FROM events WHERE event_id='retained'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(bytes, expected.canonical_bytes());
            let version: String = raw
                .query_row(
                    "SELECT value FROM schema_meta WHERE key='schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(version, bridge_core::schema::SCHEMA_VERSION.to_string());
        }
        let next = common::keep_all(
            "agent-run",
            "after",
            &common::codex("crash"),
            bridge_core::Mode::Message,
        );
        assert_eq!(
            storage.publish(&next, 2000).unwrap().receipt.acceptance_seq,
            2
        );
        drop(storage);
        assert!(
            !path.with_extension("db-wal").exists(),
            "normal close checkpoint policy is restored on success"
        );
        assert!(!path.with_extension("db-shm").exists());
    }
}
