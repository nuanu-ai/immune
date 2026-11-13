//! Promises of `immune findings` and `immune finding <id>` as commands of the contract: the
//! core's own findings, whole, as the response layer reads them to give a verdict, and the id of
//! the store every message of the contract carries. Each test runs the real binary over an
//! invented home folder and system root, so nothing of the Mac it runs on is read and the
//! network is never asked.
//!
//! Each kind of evidence is read through the contract where it is raised: a watched place in
//! `tests/promises.rs`, a process and a connection in `tests/processes.rs`, a published rule's
//! program starts and file events in `tests/event_level.rs`, a vulnerable package in
//! `tests/vulnerability_data.rs`; the others are here.

use immune_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// An invented estate: a home folder, a system root and a store beside them.
struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "immune-findings-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        // Made real, as the readers make the home folder real: the temporary folder is a link.
        Estate(std::fs::canonicalize(root).unwrap())
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn system(&self) -> PathBuf {
        self.0.join("system")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
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
            .arg(self.store())
            .output()
            .unwrap()
    }

    /// A full run, with every outside source pointed at nothing.
    fn run(&self) {
        let (empty, none) = (self.0.join("empty"), self.0.join("none"));
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.system())
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .arg("--osv-crates-input")
            .arg(&none)
            .arg("--osv-npm-input")
            .arg(&none)
            .arg("--tailscale")
            .arg(&none)
            .arg("--threats-input")
            .arg(&none)
            .arg("--checkouts-root")
            .arg(self.home())
            .arg("--sessions-root")
            .arg(&empty)
            .arg("--servers-input")
            .arg(&empty)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A command of the contract with `--json`, which must answer: its message.
    fn json(&self, args: &[&str]) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let out = self.immune(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// One finding whole.
    fn finding(&self, id: &str) -> Value {
        self.json(&["finding", id])
    }

    /// The result of `immune status --json`.
    fn status(&self) -> Value {
        let out = self.immune(&["status", "--json"]);
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["result"].clone()
    }

    /// What the status shows of the open finding of this rule.
    fn shown(&self, rule: &str) -> Value {
        self.status()["needs_a_look"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["rule"] == rule)
            .unwrap_or_else(|| panic!("no {rule} in {:#}", self.status()))
            .clone()
    }

    /// The id the store keeps for itself, as SQLite reads it.
    fn kept_id(&self) -> Option<String> {
        rusqlite::Connection::open(self.store())
            .unwrap()
            .query_row("SELECT value FROM meta WHERE key = 'store_id'", [], |r| {
                r.get(0)
            })
            .ok()
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A finding read through the contract says what the status says of it: the core's words, where
/// it is, and its reference.
fn carries_what_the_status_shows(whole: &Value, item: &Value) {
    for part in ["title", "meaning", "advice", "kind", "where_text"] {
        assert_eq!(whole[part], item[part], "{part}");
    }
    for part in ["id", "rule", "state", "severity", "confidence", "urgent"] {
        assert_eq!(whole["finding"][part], item[part], "{part}");
    }
    assert_eq!(whole["technique_text"], item["technique"]);
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
            "{{\n  \"version\": \"2.0.0\",\n  \"tasks\": [{{\"label\": \"setup\", \"command\": \"node setup.js\", \"runOptions\": {{\"runOn\": \"{run_on}\"}}}}]\n}}\n"
        ),
    );
}

/// A task set to run when the folder is opened, in a project the store already held.
fn a_task_run_on_opening(tag: &str) -> Estate {
    let e = Estate::new(tag);
    tasks(&e, "default");
    e.run();
    tasks(&e, "folderOpen");
    e.run();
    e
}

/// The id of the one open finding of this rule.
fn id_of(e: &Estate, rule: &str) -> String {
    e.shown(rule)["id"].as_str().unwrap().to_string()
}

#[test]
fn a_place_where_code_runs_by_itself_is_read_whole_with_what_changed_and_what_it_rests_on() {
    // The response layer judges a finding from what the core kept of it: what changed, and the
    // journal entries it rests on, which hold the digest of the part that counts, never its text.
    let e = a_task_run_on_opening("autorun");
    let id = id_of(&e, "autorun.folder-open");
    let whole = e.finding(&id);
    carries_what_the_status_shows(&whole, &e.shown("autorun.folder-open"));
    assert_eq!(whole["where_text"], "~/dev/shop/.vscode/tasks.json");
    assert_eq!(
        whole["evidence"],
        json!({ "place_changed": { "change": "new", "presence_only": false } })
    );
    let rests = whole["rests_on"].as_array().unwrap();
    assert!(
        rests.iter().any(|r| r["predicate"] == "has_content"
            && r["new_value_text"]
                .as_str()
                .is_some_and(|v| v.starts_with("sha256:"))),
        "{rests:#?}"
    );
    assert!(!whole.to_string().contains("node setup.js"));
    assert_eq!(whole["format"], 1);
    // Each entry is the journal's own, field for field, oldest first.
    let s = |v: &Value| match v {
        Value::Null => "NULL".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let given: Vec<String> = rests
        .iter()
        .map(|r| {
            [
                "seq",
                "recorded_at",
                "run_id",
                "entry",
                "reader",
                "kind",
                "predicate",
                "subject_text",
                "old_value_text",
                "new_value_text",
            ]
            .map(|k| s(&r[k]))
            .join("|")
        })
        .collect();
    let kept: Vec<String> = rusqlite::Connection::open(e.store())
        .unwrap()
        .prepare(
            "SELECT j.seq, j.at, j.run_id, j.entry, IFNULL(j.reader, 'NULL'), IFNULL(j.kind, 'NULL'),
                    IFNULL(j.predicate, 'NULL'), IFNULL(j.subject, 'NULL'),
                    IFNULL(j.old_value, 'NULL'), IFNULL(j.new_value, 'NULL')
             FROM finding_basis b JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 ORDER BY j.seq",
        )
        .unwrap()
        .query_map([&id], |r| {
            Ok((0..10)
                .map(|i| match r.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                    other => other.as_str().unwrap().to_string(),
                })
                .collect::<Vec<_>>()
                .join("|"))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(given, kept);
    assert_eq!(rests.len(), 3);
    assert_eq!(whole["finding"]["about_text"], rests[0]["subject_text"]);

    // Changed again while it is open: the same finding, last seen later, its latest change.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        "{\"version\": \"2.0.0\", \"tasks\": [{\"label\": \"setup\", \"command\": \"make\", \"runOptions\": {\"runOn\": \"folderOpen\"}}]}\n",
    );
    e.run();
    let again = e.finding(&id);
    let rests = again["rests_on"].as_array().unwrap();
    assert_eq!(
        again["evidence"],
        json!({ "place_changed": { "change": "changed", "presence_only": false } })
    );
    assert_eq!(again["first_seen_at"], rests[0]["recorded_at"]);
    assert_eq!(again["last_seen_at"], rests[rests.len() - 1]["recorded_at"]);
    assert!(again["last_seen_at"].as_i64() > again["first_seen_at"].as_i64());
}

/// An application whose executable is a copy of `/usr/bin/true` and whose code is a script in
/// its resources, signed ad hoc as a developer's build would be.
fn application(e: &Estate) -> PathBuf {
    let app = e.system().join("Applications/Ledger.app");
    let contents = app.join("Contents");
    e.put(
        &contents.join("Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key><string>org.example.ledger</string>\n<key>CFBundleExecutable</key><string>Ledger</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleShortVersionString</key><string>5.2</string>\n</dict></plist>\n",
    );
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::copy("/usr/bin/true", contents.join("MacOS/Ledger")).unwrap();
    e.put(&contents.join("Resources/app/main.js"), "start();\n");
    let out = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(&app)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    app
}

#[test]
fn software_changed_in_place_says_what_its_seal_became_and_what_it_was() {
    let e = Estate::new("seal");
    let app = application(&e);
    e.run();
    let main = app.join("Contents/Resources/app/main.js");
    e.put(&main, "start();\nrequire('/tmp/agent.js');\n");
    e.run();
    let item = e.shown("integrity.app-seal");
    let whole = e.finding(item["id"].as_str().unwrap());
    carries_what_the_status_shows(&whole, &item);
    let became = &whole["evidence"]["changed_in_place"]["became_text"];
    assert_eq!(*became, item["value_text"]);
    assert!(
        became.as_str().unwrap().starts_with("does not verify"),
        "{became}"
    );
    let text =
        String::from_utf8(e.immune(&["finding", item["id"].as_str().unwrap()]).stdout).unwrap();
    assert!(text.contains("What it became: \"does not verify"), "{text}");
    // What it was is in the journal entry it rests on.
    let seal = whole["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["predicate"] == "has_seal")
        .unwrap()
        .clone();
    assert_eq!(
        (
            &seal["entry"],
            &seal["old_value_text"],
            &seal["new_value_text"]
        ),
        (&json!("changed"), &json!("verifies"), became)
    );
}

#[test]
fn an_indicator_match_names_the_indicators_it_matched_as_the_list_gives_them() {
    let e = Estate::new("indicator");
    let profile = e.home().join(".zshrc");
    e.put(&profile, "export PATH=/opt/x:$PATH\n");
    let out = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(&profile)
        .output()
        .unwrap();
    let hash = String::from_utf8(out.stdout).unwrap()[..64].to_string();
    e.put(
        &e.store().with_file_name("indicators.json"),
        &format!(
            r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{hash}", "note_text": "invented"}}]"#
        ),
    );
    e.run();
    let item = e.shown("indicator.match");
    let whole = e.finding(item["id"].as_str().unwrap());
    carries_what_the_status_shows(&whole, &item);
    assert_eq!(
        whole["evidence"]["indicator_matched"]["indicators_text"],
        format!("[file:hashes.'SHA-256' = '{hash}']")
    );
    assert_eq!(
        whole["evidence"]["indicator_matched"]["indicators_text"],
        item["value_text"]
    );
    let text =
        String::from_utf8(e.immune(&["finding", item["id"].as_str().unwrap()]).stdout).unwrap();
    assert!(
        text.contains(&format!(
            "Matched indicators: \"[file:hashes.'SHA-256' = '{hash}']\"."
        )),
        "{text}"
    );
}

#[test]
fn a_finding_the_person_answered_says_so_with_who_why_and_until_when_and_reopened_says_none() {
    // A verdict about a finding the person already answered must know it: the answer, who gave
    // it, the reason and how long it holds, in the list and in the finding whole.
    let e = a_task_run_on_opening("answered");
    let id = id_of(&e, "autorun.folder-open");
    let out = e.immune(&[
        "finding",
        &id,
        "expected",
        "--reason",
        "my own build task",
        "--days",
        "7",
        "--via",
        "agent",
    ]);
    assert!(out.status.success());
    let whole = e.finding(&id);
    let answer = &whole["answer"];
    assert_eq!(
        (
            &whole["finding"]["state"],
            &answer["given"],
            &answer["via"],
            &answer["reason_text"],
            &answer["in_force"],
        ),
        (
            &json!("expected"),
            &json!("expected"),
            &json!("agent"),
            &json!("my own build task"),
            &json!(true),
        )
    );
    assert_eq!(
        answer["until_at"].as_i64().unwrap() - answer["given_at"].as_i64().unwrap(),
        7 * 86_400
    );
    // The list carries the same answer, and a finding answered stays in it.
    let listed = e.json(&["findings"]);
    let entry = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(entry["answer"], *answer);
    assert_eq!(entry["finding"], whole["finding"]);
    for part in [
        "first_seen_at",
        "last_seen_at",
        "where_text",
        "title",
        "kind",
    ] {
        assert_eq!(entry[part], whole[part], "{part}");
    }

    // Seen from the command line, with no reason: none is given, and no end.
    assert!(e.immune(&["finding", &id, "reopen"]).status.success());
    let reopened = e.finding(&id);
    assert_eq!(
        (&reopened["finding"]["state"], &reopened["answer"]),
        (&json!("open"), &Value::Null)
    );
    assert!(e.immune(&["finding", &id, "seen"]).status.success());
    let seen = e.finding(&id)["answer"].clone();
    assert_eq!(
        (
            &seen["given"],
            &seen["via"],
            &seen["reason_text"],
            &seen["until_at"]
        ),
        (
            &json!("seen"),
            &json!("command"),
            &Value::Null,
            &Value::Null
        )
    );
    assert_eq!(seen["in_force"], true);

    // Changed again after it was seen: the answer stays, and no longer hides what is new.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    e.put(
        &e.home().join("dev/shop/.vscode/tasks.json"),
        "{\"version\": \"2.0.0\", \"tasks\": [{\"label\": \"setup\", \"command\": \"make\", \"runOptions\": {\"runOn\": \"folderOpen\"}}]}\n",
    );
    e.run();
    let old = e.finding(&id)["answer"].clone();
    assert_eq!(
        (&old["given"], &old["in_force"]),
        (&json!("seen"), &json!(false))
    );
}

#[test]
fn the_list_carries_every_finding_in_every_state_whatever_all_says_and_a_person_sees_the_open_ones()
{
    let e = a_task_run_on_opening("states");
    let id = id_of(&e, "autorun.folder-open");
    assert!(e.immune(&["finding", &id, "seen"]).status.success());
    for args in [&["findings"][..], &["findings", "--all"][..]] {
        let listed = e.json(args);
        let states: Vec<&Value> = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| &f["finding"]["state"])
            .collect();
        assert_eq!(states, [&json!("seen")], "{args:?}");
    }
    let text = String::from_utf8(e.immune(&["findings"]).stdout).unwrap();
    assert!(text.starts_with("0 open findings."), "{text}");
    let text = String::from_utf8(e.immune(&["findings", "--all"]).stdout).unwrap();
    assert!(
        text.starts_with("1 finding.") && text.contains(&id),
        "{text}"
    );
}

#[test]
fn the_binary_and_the_json_forms_are_one_message_for_the_list_and_for_one_finding() {
    let e = a_task_run_on_opening("forms");
    let id = id_of(&e, "autorun.folder-open");
    // The two are asked apart, so the second in which each was answered may differ.
    let mut json = e.json(&["findings"]);
    let binary = e.immune(&["findings", "--proto"]).stdout;
    let mut decoded = v1::Findings::decode(binary.as_slice()).unwrap();
    decoded.answered_at = 0;
    json["answered_at"] = json!(0);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    let parsed: v1::Findings = serde_json::from_value(json).unwrap();
    assert_eq!(parsed, decoded);
    assert_eq!(decoded.findings.len(), 1);
    // The latest run is the one every answer about this store names.
    assert!(decoded.latest_run_at.is_some());
    assert_eq!(
        json!(decoded.latest_run_at),
        e.json(&["machine"])["latest_run_at"]
    );

    let mut json = e.json(&["finding", &id]);
    let binary = e.immune(&["finding", &id, "--proto"]).stdout;
    let mut decoded = v1::Finding::decode(binary.as_slice()).unwrap();
    decoded.answered_at = 0;
    json["answered_at"] = json!(0);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), json);
    let parsed: v1::Finding = serde_json::from_value(json).unwrap();
    assert_eq!(parsed, decoded);
    assert_eq!(decoded.finding.unwrap().id, id);
    // A one-of prints as an object with one key, the case that is set.
    assert!(matches!(
        decoded.evidence.and_then(|e| e.body),
        Some(v1::evidence::Body::PlaceChanged(_))
    ));
}

#[test]
fn a_failure_never_parses_as_an_answer() {
    // A reader checks the exit code first; one that parses all the same reads format 0.
    let e = a_task_run_on_opening("failure");
    let unknown = e.immune(&["finding", "f0000000000", "--json"]);
    assert_eq!(unknown.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "unknown_finding");
    let parsed: v1::Finding = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(parsed.format, 0);
    let text = e.immune(&["finding", "f0000000000"]);
    assert_eq!(text.status.code(), Some(2));
    assert!(text.stdout.is_empty());

    // A misuse of either command, as the contract fails.
    for args in [
        &["findings", "--open", "--json"][..],
        &["finding", "--json"][..],
        &["findings", "--json", "--proto"][..],
    ] {
        let out = e.immune(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("format").is_none(), "{v}");
        assert_eq!(v["errors"][0]["code"], "usage");
        let parsed: v1::Findings = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.format, 0);
    }
    // An answer keeps its own envelope, and has no binary form.
    let out = e.immune(&["finding", "f0000000000", "seen", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (&v["format"], &v["errors"][0]["code"]),
        (&json!(1), &json!("unknown_finding"))
    );
    let id = id_of(&e, "autorun.folder-open");
    let out = e.immune(&["finding", &id, "seen", "--via", "agent", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (&v["format"], &v["errors"][0]["code"]),
        (&json!(1), &json!("usage"))
    );
    // An answer asked in binary is refused, and nothing is answered.
    let out = e.immune(&["finding", &id, "seen", "--proto"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert_eq!(e.finding(&id)["finding"]["state"], "open");

    // No store: a failure with exit code 3, never an empty list.
    let none = Estate::new("no-store");
    for args in [
        &["findings", "--json"][..],
        &["finding", "f0000000000", "--json"][..],
    ] {
        let out = none.immune(args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["errors"][0]["code"], "store_unreadable");
        assert!(v.get("format").is_none(), "{v}");
    }
    assert!(!none.store().exists());
}

#[test]
fn a_store_without_the_table_of_findings_fails_as_older_rather_than_reading_as_none() {
    // False calm: an empty list from a store no run of this build has looked for findings in
    // would read as "nothing found".
    let e = a_task_run_on_opening("older");
    rusqlite::Connection::open(e.store())
        .unwrap()
        .execute_batch("DROP TABLE finding_basis; DROP TABLE rule_line; DROP TABLE rule_finding; DROP TABLE rule_evidence; DROP TABLE rule_file_evidence; DROP TABLE finding;")
        .unwrap();
    let out = e.immune(&["findings", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["errors"][0]["detail_text"]
            .as_str()
            .unwrap()
            .contains("written by an older build of Immune; `immune run` brings it up to date"),
        "{v}"
    );
}

/// The `store_id` of every message of the contract this store answers with.
fn store_ids(e: &Estate) -> Vec<Value> {
    let id = id_of(e, "autorun.folder-open");
    let root = e.system();
    let root = root.to_str().unwrap();
    [
        e.json(&["findings"]),
        e.json(&["finding", &id]),
        e.json(&["machine"]),
        e.json(&["project", "~/dev/shop"]),
        e.json(&["matches", "--system-root", root]),
    ]
    .iter()
    .map(|m| m["store_id"].clone())
    .collect()
}

#[test]
fn every_message_of_one_store_carries_its_id_another_store_has_another_and_a_run_keeps_it() {
    // A finding's id is unique only within one store: a verdict kept by finding id alone would
    // attach to another finding once the store is made again.
    let e = a_task_run_on_opening("store-id");
    let ids = store_ids(&e);
    let first = ids[0].as_str().unwrap().to_string();
    assert!(
        first.len() == 32 && first.bytes().all(|b| b.is_ascii_hexdigit()),
        "{first}"
    );
    assert!(ids.iter().all(|i| *i == ids[0]), "{ids:?}");
    // The binary form carries the same.
    let binary = e.immune(&["findings", "--proto"]).stdout;
    assert_eq!(
        v1::Findings::decode(binary.as_slice()).unwrap().store_id,
        Some(first.clone())
    );
    e.run();
    assert_eq!(store_ids(&e)[0], ids[0]);
    // The same Mac, read the same way, into a store made again: another id.
    let other = a_task_run_on_opening("store-id-other");
    assert_ne!(store_ids(&other)[0], ids[0]);
    // A finding's id, which is not random, can be the same in both.
    assert_eq!(
        id_of(&other, "autorun.folder-open"),
        id_of(&e, "autorun.folder-open")
    );
}

#[test]
fn a_store_an_older_build_made_gets_its_id_at_the_next_run_and_a_command_that_only_reads_makes_none()
 {
    let e = a_task_run_on_opening("store-id-older");
    rusqlite::Connection::open(e.store())
        .unwrap()
        .execute("DELETE FROM meta WHERE key = 'store_id'", [])
        .unwrap();
    assert!(store_ids(&e).iter().all(Value::is_null));
    let out = e.immune(&["status", "--json"]);
    assert!(out.status.success());
    assert_eq!(e.kept_id(), None);
    e.run();
    let made = e.kept_id().unwrap();
    assert!(store_ids(&e).iter().all(|i| *i == json!(made)));
}

#[test]
fn every_command_of_the_contract_answers_in_binary_with_proto_and_refuses_two_forms() {
    let e = a_task_run_on_opening("proto");
    let root = e.system();
    let root = root.to_str().unwrap();
    for args in [
        vec!["project", "~/dev/shop"],
        vec!["program", "Ledger"],
        vec!["machine"],
        vec!["matches", "--system-root", root],
    ] {
        let mut proto = args.clone();
        proto.push("--proto");
        let named = e.immune(&proto);
        assert!(named.status.success(), "{args:?}");
        let mut json = e.json(&args);
        // The time it was answered may differ by a second; the rest is the same message.
        let mut decoded = if args[0] == "matches" {
            serde_json::to_value(v1::Matches::decode(named.stdout.as_slice()).unwrap()).unwrap()
        } else {
            serde_json::to_value(v1::Known::decode(named.stdout.as_slice()).unwrap()).unwrap()
        };
        decoded["answered_at"] = Value::Null;
        json["answered_at"] = Value::Null;
        assert_eq!(decoded, json, "{args:?}");
        let mut both = args.clone();
        both.extend(["--json", "--proto"]);
        let out = e.immune(&both);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("format").is_none(), "{v}");
    }
}
