//! Promises of the crate `immune-contract` to the response layer, which reads what the core's
//! commands print with that crate and no code of the core. A reader here uses the crate's public
//! API alone, and serde_json as its JSON parser, as the crate leaves the parser to the reader.
//! The real binary runs over an invented home folder, system root and store.

mod common;

use immune_contract::prost::Message;
use immune_contract::v1;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
const T0: &str = "2026-10-04T00:00:02.000002Z";

/// An invented estate: a home folder, a system root and a store beside them.
struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "immune-contract-crate-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        Estate(std::fs::canonicalize(root).unwrap())
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn system(&self) -> PathBuf {
        self.0.join("system")
    }

    fn put(&self, path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// `immune <args> --store <this store>`, as it ran.
    fn immune(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_immune"))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(args)
            .arg("--store")
            .arg(self.0.join("store.db"))
            .output()
            .unwrap()
    }

    /// A full run, with every outside source pointed at nothing.
    fn run(&self) {
        let (empty, none) = (self.0.join("empty"), self.0.join("none"));
        let (system, brew, home) = (self.system(), self.0.join("brew.json"), self.home());
        let mut args = vec!["run", "--machine-name", "mac"];
        for (flag, value) in [
            ("--system-root", &system),
            ("--brew-input", &brew),
            ("--osv-crates-input", &none),
            ("--osv-npm-input", &none),
            ("--tailscale", &none),
            ("--threats-input", &none),
            ("--checkouts-root", &home),
            ("--sessions-root", &empty),
            ("--servers-input", &empty),
        ] {
            args.extend([flag, value.to_str().unwrap()]);
        }
        let out = self.immune(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A command of the contract in one form, which must answer: what it printed on stdout.
    fn answer(&self, args: &[&str], form: &str) -> Vec<u8> {
        let mut args = args.to_vec();
        args.push(form);
        let out = self.immune(&args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// Lays the event level out in the system root as its install does, with a log that holds a
    /// program start a published rule matches and a file event.
    fn event_level(&self) {
        let plist = self.system().join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scripts/event-level/ai.nuanu.immune.eslogger.plist"),
            &plist,
        )
        .unwrap();
        std::fs::create_dir_all(self.system().join(LOG)).unwrap();
        let out = Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments", "json", "-o"])
            .arg(self.system().join(COLLECTS))
            .arg(&plist)
            .output()
            .unwrap();
        assert!(out.status.success());
        let start = format!(
            r#"{{"schema_version":1,"version":10,"seq_num":1,"global_seq_num":1,"time":"{T0}","process":{{"executable":{{"path":"/bin/sh"}}}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example/dev/site"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.example.tool","team_id":null,"is_platform_binary":false}}}}}}}}"#
        );
        let rename = format!(
            r#"{{"schema_version":1,"seq_num":2,"time":"{T0}","process":{{"executable":{{"path":"/usr/local/bin/node"}}}},"event":{{"rename":{{"destination":"/private/tmp/6202033","source":"/Users/example/dev/site/.tmp-1"}}}}}}"#
        );
        self.put(
            &self.system().join(LOG).join("exec-20261004T00.jsonl"),
            &format!("{start}\n{rename}\n"),
        );
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

/// A checkout with an editor task file whose task runs on `run_on`.
fn tasks(e: &Estate, run_on: &str) {
    e.put(
        &e.home().join("dev/shop/.git/HEAD"),
        "ref: refs/heads/main\n",
    );
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        &format!(
            "{{\"version\": \"2.0.0\", \"tasks\": [{{\"label\": \"setup\", \"command\": \"node setup.js\", \"runOptions\": {{\"runOn\": \"{run_on}\"}}}}]}}\n"
        ),
    );
}

/// The major version of the crate, from its manifest.
fn major_version_of_the_crate() -> u32 {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("contract/Cargo.toml"))
            .unwrap();
    let version = manifest
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .expect("the crate's manifest names its version");
    version.split('.').next().unwrap().parse().unwrap()
}

/// Asks a command of the contract in both forms and reads each with the crate: the binary form
/// decodes and the JSON form parses to the same message, and the message written back as JSON
/// by the crate is what the core printed. The two are asked apart, so the second each was
/// answered in is left out.
macro_rules! read_both {
    ($e:expr, $message:ty, $args:expr) => {{
        let args: &[&str] = $args;
        let binary = $e.answer(args, "--proto");
        let json = $e.answer(args, "--json");
        let mut decoded = <$message>::decode(binary.as_slice()).expect("the binary form decodes");
        let mut parsed: $message = serde_json::from_slice(&json).expect("the JSON form reads");
        decoded.answered_at = 0;
        parsed.answered_at = 0;
        assert_eq!(parsed, decoded, "{args:?}");
        let mut printed: Value = serde_json::from_slice(&json).unwrap();
        printed["answered_at"] = Value::from(0);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), printed, "{args:?}");
        decoded
    }};
}

#[test]
fn a_reader_on_the_crate_alone_reads_every_message_the_core_prints_in_both_forms() {
    let e = Estate::new("forms");
    tasks(&e, "default");
    e.run();
    tasks(&e, "folderOpen");
    e.event_level();
    e.run();
    let major = major_version_of_the_crate();

    for args in [
        &["project", "~/dev/shop"][..],
        &["program", "Ledger"],
        &["machine"],
    ] {
        let known = read_both!(e, v1::Known, args);
        assert_eq!(known.format, major, "{args:?}");
    }
    let project = read_both!(e, v1::Known, &["project", "~/dev/shop"]);
    assert!(project.thing.is_some());

    let system = e.system();
    let matches = read_both!(
        e,
        v1::Matches,
        &["matches", "--system-root", system.to_str().unwrap()]
    );
    assert_eq!(matches.format, major);
    assert_eq!(matches.matches.len(), 2, "{matches:?}");
    assert!(matches!(
        matches.matches[0]
            .event
            .as_ref()
            .and_then(|e| e.body.as_ref()),
        Some(v1::event::Body::ProgramStart(_))
    ));
    assert!(matches!(
        matches.matches[1]
            .event
            .as_ref()
            .and_then(|e| e.body.as_ref()),
        Some(v1::event::Body::FileEvent(_))
    ));

    let findings = read_both!(e, v1::Findings, &["findings"]);
    assert_eq!(findings.format, major);
    let ids: Vec<String> = findings
        .findings
        .iter()
        .map(|f| f.finding.as_ref().unwrap().id.clone())
        .collect();
    assert!(!ids.is_empty());
    let mut kinds = Vec::new();
    for id in &ids {
        let finding = read_both!(e, v1::Finding, &["finding", id]);
        assert_eq!(finding.format, major);
        let body = finding.evidence.and_then(|e| e.body);
        kinds.push(std::mem::discriminant(&body.expect("evidence of a kind")));
    }
    // The run raised findings of more than one kind of evidence, each read through its one-of.
    kinds.dedup();
    assert!(kinds.len() >= 2, "{ids:?}");
}

/// An older reader meets a newer core: a word for an enum value the crate does not know reads as
/// the enum's unspecified value, which the schema says to read as the unsafe case, plain or
/// optional, at any depth, and the rest of the message is read.
#[test]
fn an_enum_word_the_crate_does_not_know_reads_as_unspecified_and_the_rest_is_read() {
    let json = r#"{"format": 1, "store_id": "s1",
        "finding": {"id": "f1", "state": "snoozed", "severity": "dire", "confidence": "odd"},
        "answer": {"given": "shrugged", "via": "pigeon"}}"#;
    let f: v1::Finding = serde_json::from_str(json).unwrap();
    assert_eq!((f.format, f.store_id.as_deref()), (1, Some("s1")));
    let r = f.finding.unwrap();
    assert_eq!(
        (r.id.as_str(), r.state, r.severity, r.confidence),
        ("f1", 0, Some(0), Some(0))
    );
    let a = f.answer.unwrap();
    assert_eq!((a.given, a.via), (0, 0));

    let json = r#"{"format": 1, "collector": {"state": "dreaming"},
        "matches": [{"rule": {"name": "r", "level": "apocalyptic"},
            "event": {"file_event": {"action": "teleport", "path_text": "/x"}}}]}"#;
    let m: v1::Matches = serde_json::from_str(json).unwrap();
    assert_eq!(m.collector.unwrap().state, 0);
    let rule = m.matches[0].rule.as_ref().unwrap();
    assert_eq!((rule.name.as_str(), rule.level), ("r", 0));
    match m.matches[0].event.as_ref().and_then(|e| e.body.as_ref()) {
        Some(v1::event::Body::FileEvent(f)) => {
            assert_eq!((f.action, f.path_text.as_str()), (0, "/x"));
        }
        other => panic!("{other:?}"),
    }
}
