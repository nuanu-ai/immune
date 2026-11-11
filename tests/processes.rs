//! Promises of `soc sample` and its rule. Each test feeds the real binary readings made of
//! invented processes, through the same path a reading of the system takes once it is read;
//! the reading of the system itself is tested in `src/processes.rs` on the test process and a
//! child it starts. No test reads the real processes of this Mac.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("soc-proc-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn soc(dir: &Dir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soc"))
        .env("HOME", &dir.0)
        .current_dir(&dir.0)
        .args(args)
        .arg("--store")
        .arg(dir.store())
        .output()
        .unwrap()
}

/// Feeds one reading at time `at` and returns what `soc sample --json` answered.
fn sample(dir: &Dir, at: i64, processes: &[Value]) -> Value {
    let input = dir.0.join(format!("reading-{at}.json"));
    let connection = json!({ "pid": 4242, "start": 7, "transport": "tcp",
                              "address": "::ffff:192.0.2.9", "port": 80 });
    let reading = json!({ "at": at, "processes": processes, "connections": [connection],
                          "other_users": [1, 80, 81, 82, 83, 84, 85], "unreadable": 2, "ended": 3,
                          "sockets_unreadable": 1 });
    std::fs::write(&input, reading.to_string()).unwrap();
    let out = soc(
        dir,
        &[
            "sample",
            "--json",
            "--sample-input",
            input.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["result"].clone()
}

fn findings(dir: &Dir) -> Vec<Value> {
    let out = soc(dir, &["findings", "--all", "--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["result"]["findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// A process as a reading gives it.
fn process(pid: i64, start: i64, parent: i64, exe: &str, args: &[&str], terminal: bool) -> Value {
    json!({ "pid": pid, "start": start, "parent": parent, "executable": exe,
            "name": exe.rsplit('/').next(), "terminal": terminal, "args": args })
}

const T: i64 = 1_800_000_000;
/// Something a command line holds that must never be kept: it stands for code and secrets.
const MARKER: &str = "inline-code-TOKEN-5f1c";

/// The one that must fire, a node given code with its parent gone, and those that must not.
fn table(at: i64) -> Vec<Value> {
    let code = format!("require('net').connect(80, '{MARKER}')");
    vec![
        // The parent of the others, alive.
        process(
            500,
            1,
            1,
            "/Applications/Tool.app/Contents/MacOS/Tool",
            &["Tool"],
            false,
        ),
        // Must fire: detached, code on its command line, no terminal.
        process(
            4242,
            7,
            1,
            "/opt/tools/bin/node",
            &["node", "-e", &code],
            false,
        ),
        // Must not: a terminal was its own when it was first seen.
        process(
            4300,
            7,
            1,
            "/opt/other/bin/node",
            &["node", "-e", &code],
            at == T,
        ),
        // Must not: its parent is alive and is not launchd.
        process(4301, 7, 500, "/bin/sh", &["sh", "-c", &code], false),
        // Must not: it runs a script, and what follows the script is the script's.
        process(
            4302,
            7,
            1,
            "/opt/tools/bin/node",
            &["node", "server.js", "-e", &code],
            false,
        ),
        // Must not: not an interpreter.
        process(4303, 7, 1, "/usr/bin/git", &["git", "-c", &code], false),
        // Must not: the same pid started again is another process, seen once.
        process(4304, at, 1, "/bin/zsh", &["zsh", "-c", &code], false),
    ]
}

#[test]
fn a_detached_interpreter_given_code_is_a_finding_once_two_samples_a_minute_apart_saw_it() {
    let dir = Dir::new("fires");
    // A first sample can fire nothing: it only starts tracking.
    let first = sample(&dir, T, &table(T));
    assert_eq!(first["findings_opened"], 0);
    assert_eq!(first["tracked"]["new"], 3);
    assert_eq!(first["interpreters"]["inline_code"], 4);
    assert_eq!(first["interpreters"]["inline_code_detached"], 3);
    // Two samples, but under a minute apart.
    assert_eq!(sample(&dir, T + 59, &table(T + 59))["findings_opened"], 0);
    assert!(findings(&dir).is_empty());

    let third = sample(&dir, T + 60, &table(T + 60));
    assert_eq!(third["findings_opened"], 1);
    let items = findings(&dir);
    assert_eq!(items.len(), 1, "{items:?}");
    let f = &items[0];
    assert_eq!(f["rule"], "processes.detached-inline-code");
    assert_eq!(f["technique"], "T1059");
    assert_eq!(
        (&f["severity"], &f["confidence"]),
        (&json!("high"), &json!("medium"))
    );
    assert_eq!(f["state"], "open");
    assert_eq!(f["where_text"], "/opt/tools/bin/node");
    assert_eq!(f["value_text"], Value::Null);

    // It stays one finding while the process lives.
    let fourth = sample(&dir, T + 120, &table(T + 120));
    assert_eq!(fourth["findings_opened"], 0);
    assert_eq!(fourth["tracked"]["seen_again"], 2);
    assert_eq!(findings(&dir).len(), 1);

    // Who signed what it tracks is kept beside it.
    let conn = rusqlite::Connection::open(dir.store()).unwrap();
    let signer: String = conn
        .query_row(
            "SELECT code_signature FROM tracked_process WHERE executable = '/bin/zsh' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(signer.starts_with("apple"), "{signer}");
}

#[test]
fn after_the_owner_has_seen_it_the_same_process_raises_nothing_and_another_one_does() {
    let dir = Dir::new("seen");
    let exe = dir.0.join(".local/bin/python3.12");
    let one = |pid| {
        vec![process(
            pid,
            7,
            1,
            exe.to_str().unwrap(),
            &["python3", "-c", "x"],
            false,
        )]
    };
    sample(&dir, T, &one(10));
    sample(&dir, T + 60, &one(10));
    let found = findings(&dir);
    // A program under the home folder is shown as the other readers show it.
    assert_eq!(found[0]["where_text"], "~/.local/bin/python3.12");
    let id = found[0]["id"].as_str().unwrap().to_string();
    assert!(soc(&dir, &["finding", &id, "seen"]).status.success());

    assert_eq!(sample(&dir, T + 120, &one(10))["findings_opened"], 0);
    assert_eq!(sample(&dir, T + 180, &one(11))["findings_opened"], 0);
    assert_eq!(sample(&dir, T + 240, &one(11))["findings_opened"], 1);
    let open: Vec<_> = findings(&dir)
        .into_iter()
        .filter(|f| f["state"] == "open")
        .collect();
    assert_eq!(open.len(), 1);
}

#[test]
fn a_command_line_is_never_kept_in_the_store_nor_printed() {
    let dir = Dir::new("secret");
    sample(&dir, T, &table(T));
    let said = sample(&dir, T + 60, &table(T + 60));
    assert!(!said.to_string().contains(MARKER));
    let input = dir.0.join(format!("reading-{}.json", T + 60));
    let text = soc(&dir, &["sample", "--sample-input", input.to_str().unwrap()]);
    assert!(text.status.success());
    assert!(!String::from_utf8_lossy(&text.stdout).contains(MARKER));
    assert!(!String::from_utf8_lossy(&text.stderr).contains(MARKER));
    for name in ["store.db", "store.db-wal", "store.db-journal"] {
        if let Ok(bytes) = std::fs::read(dir.0.join(name)) {
            let found = bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes());
            assert!(!found, "{name}");
        }
    }
    // What the rule derived is kept instead.
    let views = findings(&dir);
    assert!(!views.iter().any(|f| f.to_string().contains(MARKER)));
}

#[test]
fn every_sample_names_its_level_of_access_and_what_it_cannot_see() {
    let dir = Dir::new("coverage");
    let mut processes = table(T);
    // An interpreter whose arguments could not be read.
    processes.push(json!({ "pid": 9, "start": 1, "parent": 1,
                           "executable": "/opt/tools/bin/node", "name": "node" }));
    let said = sample(&dir, T, &processes);
    assert_eq!(said["level"], "samples without administrator rights");
    assert_eq!(said["processes"]["other_users"], 7);
    assert_eq!(said["processes"]["unreadable"], 2);
    assert_eq!(said["processes"]["ended_while_read"], 3);
    assert_eq!(said["processes"]["read"], 8);
    assert_eq!(said["interpreters"]["seen"], 6);
    assert_eq!(said["interpreters"]["arguments_unreadable"], 1);
    assert_eq!(said["connections"]["read"], 1);
    assert_eq!(said["connections"]["unreadable"], 1);
    let cannot: Vec<&str> = said["cannot_see"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for gap in [
        "the arguments and connections of other users' processes",
        "connections opened and closed between two samples",
        "the names behind addresses: no name resolution is seen",
    ] {
        assert!(cannot.contains(&gap), "{gap}");
    }
    let input = dir.0.join(format!("reading-{T}.json"));
    let text = soc(&dir, &["sample", "--sample-input", input.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("7 of other users not read"), "{text}");
    assert!(
        text.contains("A sample cannot see: the arguments"),
        "{text}"
    );
}

#[test]
fn a_sample_waits_for_a_run_in_progress_and_then_stops_writing_nothing() {
    let dir = Dir::new("locked");
    let held = std::fs::File::open(&dir.0).unwrap();
    held.lock().unwrap();
    let input = dir.0.join("reading.json");
    let reading = json!({ "at": T, "processes": table(T) });
    std::fs::write(&input, reading.to_string()).unwrap();
    let out = soc(
        &dir,
        &[
            "sample",
            "--json",
            "--sample-input",
            input.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "run_in_progress");
    assert!(!dir.store().exists());
}
