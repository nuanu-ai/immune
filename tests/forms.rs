//! The one rule of forms for the seven commands of the contract, and their one form of failure.
//! Each command answers with one message: text for a person when no form is named, rendered
//! from that message, binary protobuf with `--proto` and the same as JSON with `--json`. A
//! failure is the message `Failure` in the same form, on stderr for a person, with the exit code
//! that says which kind. Each test runs the real binary over an invented home folder and system
//! root, so nothing of the Mac it runs on is read and the network is never asked.

use immune_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// An invented estate: a home folder, a system root and a store beside them.
struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("immune-forms-{tag}-{}-{nanos}", std::process::id()));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        Estate(std::fs::canonicalize(root).unwrap())
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    fn put(&self, rel: &str, text: &str) {
        let path = self.home().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = self.raw_command(args);
        c.arg("--store").arg(self.store());
        c
    }

    fn raw_command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_immune"));
        c.env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(args);
        c
    }

    /// `immune <args> --store <this store>`, as it ran.
    fn immune(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    /// `immune verdict <args>` with `input` on standard input.
    fn verdict(&self, input: &[u8], args: &[&str]) -> Output {
        let mut all = vec!["verdict", "--system-root"];
        let root = self.0.join("system");
        all.push(root.to_str().unwrap());
        all.extend(args);
        let mut child = self
            .command(&all)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out
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
            .arg(self.0.join("system"))
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--osv-crates-input", none.to_str().unwrap()])
            .args(["--osv-npm-input", none.to_str().unwrap()])
            .args(["--tailscale", none.to_str().unwrap()])
            .args(["--threats-input", none.to_str().unwrap()])
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
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// How many verdicts the store holds.
    fn verdicts(&self) -> i64 {
        rusqlite::Connection::open(self.store())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM verdict", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A project whose editor task runs when its folder is opened, added after a first run: one
/// open finding.
fn a_task_run_on_opening(tag: &str) -> (Estate, String) {
    let e = Estate::new(tag);
    let tasks = |run_on: &str| {
        format!(
            "{{\"version\": \"2.0.0\", \"tasks\": [{{\"label\": \"setup\", \"command\": \"node setup.js\", \"runOptions\": {{\"runOn\": \"{run_on}\"}}}}]}}\n"
        )
    };
    e.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    e.put("dev/shop/.vscode/tasks.json", &tasks("default"));
    e.run();
    e.put("dev/shop/.vscode/tasks.json", &tasks("folderOpen"));
    e.run();
    let all = e.json(&["findings"]);
    let id = all["findings"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    (e, id)
}

/// The commands of the contract that only read, as each is asked here.
fn questions(e: &Estate, id: &str) -> Vec<Vec<String>> {
    let root = e.0.join("system").to_str().unwrap().to_string();
    [
        vec!["project", "~/dev/shop"],
        vec!["program", "Ledger"],
        vec!["machine"],
        vec!["matches", "--system-root", &root],
        vec!["findings"],
        vec!["finding", id],
    ]
    .iter()
    .map(|args| args.iter().map(|a| a.to_string()).collect())
    .collect()
}

/// A message decoded from binary as JSON, by the command that printed it.
fn decoded(command: &str, bytes: &[u8]) -> Value {
    let v = match command {
        "project" | "program" | "machine" => {
            serde_json::to_value(v1::Known::decode(bytes).unwrap())
        }
        "matches" => serde_json::to_value(v1::Matches::decode(bytes).unwrap()),
        "findings" => serde_json::to_value(v1::Findings::decode(bytes).unwrap()),
        "finding" => serde_json::to_value(v1::Finding::decode(bytes).unwrap()),
        _ => unreachable!(),
    };
    v.unwrap()
}

/// A harmless verdict about a finding of this store.
fn harmless(store_id: &str, id: &str) -> Value {
    json!({
        "format": 1, "store_id": store_id, "finding": {"id": id}, "kind": "harmless",
        "reason_text": "invented: the task is the project's own", "case_text": "case-forms",
    })
}

#[test]
fn every_command_of_the_contract_gives_one_message_in_its_three_forms() {
    let (e, id) = a_task_run_on_opening("three");
    for args in questions(&e, &id) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut json = e.json(&args);
        let mut proto = args.clone();
        proto.push("--proto");
        let binary = e.immune(&proto);
        assert!(binary.status.success(), "{args:?}");
        // The two are asked apart, so the second in which each was answered may differ.
        let mut binary = decoded(args[0], &binary.stdout);
        binary["answered_at"] = json!(0);
        json["answered_at"] = json!(0);
        assert_eq!(binary, json, "{args:?}");
        // The text holds the ids and the states the message holds.
        let text = e.immune(&args);
        assert!(text.status.success(), "{args:?}");
        let text = String::from_utf8(text.stdout).unwrap();
        let mut said: Vec<String> = Vec::new();
        match args[0] {
            "project" | "machine" => {
                said.push(format!(
                    "\"{}\"",
                    json["thing"]["id_text"].as_str().unwrap()
                ));
                said.push(format!("is {}", json["presence"].as_str().unwrap()));
                for f in json["findings"].as_array().unwrap() {
                    said.push(format!(
                        "{}  {}",
                        f["id"].as_str().unwrap(),
                        f["state"].as_str().unwrap()
                    ));
                }
            }
            "program" => said.push(format!("is {}", json["presence"].as_str().unwrap())),
            "matches" => said.push(format!(
                "Collector: {}",
                json["collector"]["state"].as_str().unwrap()
            )),
            "findings" => {
                let f = &json["findings"][0]["finding"];
                said.push(format!(
                    "{}  {}",
                    f["id"].as_str().unwrap(),
                    f["state"].as_str().unwrap()
                ));
            }
            _ => {
                said.push(format!("Finding {id}: {}", json["title"].as_str().unwrap()));
                said.push(format!(
                    "State: {}.",
                    json["finding"]["state"].as_str().unwrap()
                ));
            }
        }
        for s in said {
            assert!(text.contains(&s), "{args:?}: {s}\n{text}");
        }
    }
    // A verdict is read and answered in the form named: the same verdict sent again in the other
    // form is answered with the same record.
    let store_id = e.json(&["findings"])["store_id"]
        .as_str()
        .unwrap()
        .to_string();
    let verdict = harmless(&store_id, &id);
    let first = e.verdict(verdict.to_string().as_bytes(), &["--json"]);
    assert!(first.status.success());
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    let sent: v1::Verdict = serde_json::from_value(verdict).unwrap();
    let again = e.verdict(&sent.encode_to_vec(), &["--proto"]);
    assert!(again.status.success());
    let again = v1::VerdictRecorded::decode(again.stdout.as_slice()).unwrap();
    assert!(again.already_recorded);
    assert_eq!(
        serde_json::to_value(again.recorded).unwrap(),
        first["recorded"]
    );
}

#[test]
fn with_no_form_named_no_command_of_the_contract_writes_binary_to_stdout() {
    let (e, id) = a_task_run_on_opening("no-binary");
    for args in questions(&e, &id) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = e.immune(&args);
        assert!(out.status.success(), "{args:?}");
        let text = String::from_utf8(out.stdout).expect("text");
        assert!(
            text.chars().all(|c| c == '\n' || !c.is_control()),
            "{args:?}: {text}"
        );
        assert!(text.ends_with('\n'), "{args:?}");
    }
    let store_id = e.json(&["findings"])["store_id"]
        .as_str()
        .unwrap()
        .to_string();
    let out = e.verdict(harmless(&store_id, &id).to_string().as_bytes(), &[]);
    assert!(out.stdout.is_empty());
}

#[test]
fn a_verdict_without_a_form_is_refused_as_a_misuse_and_records_nothing() {
    // A message is not typed as text, and standard input is never guessed at.
    let (e, id) = a_task_run_on_opening("verdict-no-form");
    let store_id = e.json(&["findings"])["store_id"]
        .as_str()
        .unwrap()
        .to_string();
    let verdict = harmless(&store_id, &id);
    let sent: v1::Verdict = serde_json::from_value(verdict.clone()).unwrap();
    for input in [verdict.to_string().into_bytes(), sent.encode_to_vec()] {
        let out = e.verdict(&input, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(
            said.contains("--proto") && said.contains("--json"),
            "{said}"
        );
        assert_eq!(e.verdicts(), 0);
    }
}

/// The `Failure` a command printed in the form named, with its exit code.
fn failure(out: &Output, form: &str) -> (v1::Failure, Option<i32>) {
    let f = match form {
        "--proto" => v1::Failure::decode(out.stdout.as_slice()).unwrap(),
        _ => serde_json::from_slice(&out.stdout).unwrap(),
    };
    (f, out.status.code())
}

#[test]
fn a_failure_of_every_command_of_the_contract_is_failure_in_the_form_named_with_its_exit_code() {
    // No store: what a reader cannot do without, with exit code 3.
    let e = Estate::new("failure");
    let none = harmless(&"0".repeat(32), "f0000000000").to_string();
    let none_binary = serde_json::from_str::<v1::Verdict>(&none)
        .unwrap()
        .encode_to_vec();
    for args in questions(&e, "f0000000000") {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        for form in ["--proto", "--json"] {
            let mut named = args.clone();
            named.push(form);
            let (f, exit) = failure(&e.immune(&named), form);
            assert_eq!(exit, Some(3), "{named:?}");
            assert_eq!(
                (f.operation.as_str(), f.ok, f.errors[0].code.as_str()),
                (args[0], false, "store_unreadable"),
                "{named:?}"
            );
            // A misuse, in the same form, with exit code 2.
            named.push("--invented");
            let (f, exit) = failure(&e.immune(&named), form);
            assert_eq!(exit, Some(2), "{named:?}");
            assert_eq!(f.errors[0].code, "usage", "{named:?}");
        }
        // For a person: on stderr, and nothing on stdout.
        let out = e.immune(&args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).starts_with("immune: "),
            "{args:?}"
        );
    }
    for (form, input) in [("--json", none.as_bytes()), ("--proto", &none_binary[..])] {
        let (f, exit) = failure(&e.verdict(input, &[form]), form);
        assert_eq!(exit, Some(3), "{form}");
        assert_eq!(
            (f.operation.as_str(), f.errors[0].code.as_str()),
            ("verdict", "store_unreadable")
        );
        let (f, exit) = failure(&e.verdict(b"{}", &[form, "--invented"]), form);
        assert_eq!((exit, f.errors[0].code.as_str()), (Some(2), "usage"));
    }
    assert!(!e.store().exists());
}

#[test]
fn text_from_a_source_in_the_text_of_an_answer_cannot_pose_as_the_program_s_words() {
    // A path asked about is text from outside; one made to read as the next line of the answer
    // stays inside its quotation, with the line break written out.
    let (e, _) = a_task_run_on_opening("posing");
    let posing = "The project \"~/dev/shop\" is unknown: the store has never heard of it.";
    let asked = format!("~/dev/x\n{posing}");
    let out = e.immune(&["project", &asked]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.lines().any(|l| l == posing), "{text}");
    assert!(
        text.starts_with(r#"The project "~/dev/x\u{a}The project \"~/dev/shop\" is unknown"#),
        "{text}"
    );
}

#[test]
fn a_store_without_a_completed_check_does_not_look_clear() {
    let e = Estate::new("no-check");
    e.put("sample.json", "an invalid sample");
    let input = e.home().join("sample.json");
    let out = e.immune(&["sample", "--sample-input", input.to_str().unwrap()]);
    assert!(!out.status.success());
    let answer = e.json(&["findings"]);
    assert_eq!(answer["latest_run_at"], Value::Null);
    assert_eq!(answer["findings"], json!([]));
    let out = e.immune(&["findings"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("No full check has finished."), "{text}");
}

#[test]
fn a_watched_place_the_core_could_not_read_shows_why() {
    let e = Estate::new("unread");
    e.put(".zshrc", "export INVENTED=1\n");
    e.run();
    let profile = e.home().join(".zshrc");
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600)).unwrap();
    let answer = e.json(&["findings"]);
    let id = answer["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["rule"] == "watched.shell-profile")
        .unwrap()["finding"]["id"]
        .as_str()
        .unwrap();
    let answer = e.json(&["finding", id]);
    assert_eq!(answer["evidence"]["place_changed"]["change"], "not_read");
    let binary = e.immune(&["finding", id, "--proto"]);
    assert!(binary.status.success());
    assert_eq!(
        decoded("finding", &binary.stdout)["evidence"],
        answer["evidence"]
    );
    let basis = answer["rests_on"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["entry"] == "not_read")
        .unwrap();
    let reason = basis["new_value_text"].as_str().unwrap();
    let out = e.immune(&["finding", id]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains(&format!("The place could not be read: \"{reason}\".")),
        "{text}"
    );
    assert!(text.contains("latest change: not read"), "{text}");
}

#[test]
fn an_operand_cannot_choose_the_failure_form_or_turn_a_read_into_an_owner_answer() {
    let e = Estate::new("operands");
    let id = "f0123456789";
    for (option, operand) in [
        ("--store", "seen"),
        ("--reason", "reopen"),
        ("--days", "expected"),
        ("--via", "seen"),
    ] {
        for form in ["--json", "--proto"] {
            let args = ["finding", option, operand, id, "--invented", form];
            let out = e.raw_command(&args).output().unwrap();
            let (f, exit) = failure(&out, form);
            assert_eq!(
                (f.operation.as_str(), exit),
                ("finding", Some(2)),
                "{args:?}"
            );
            assert_eq!(f.errors[0].code, "usage");
        }
    }

    for args in [
        ["verdict", "--store", "--json"],
        ["verdict", "--system-root", "--proto"],
        ["project", "--store", "--proto"],
        ["matches", "--limit", "--json"],
        ["matches", "--after", "--proto"],
    ] {
        let out = e.raw_command(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(out.stderr.starts_with(b"immune: "), "{args:?}");
    }

    let args = ["finding", id, "seen", "--reason", "--json", "--days", "1"];
    let out = e.raw_command(&args).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());

    let args = ["finding", id, "--invented", "seen", "--json"];
    let out = e.raw_command(&args).output().unwrap();
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(envelope["format"], 1);
    assert_eq!(envelope["errors"][0]["code"], "usage");
    assert!(!e.store().exists());
}

#[test]
fn naming_both_forms_refuses_before_the_command_can_run() {
    let e = Estate::new("both");
    for (first, second) in [("--json", "--proto"), ("--proto", "--json")] {
        let out = e.verdict(b"{}", &[first, second]);
        let (f, exit) = failure(&out, "--json");
        assert_eq!(exit, Some(2));
        assert_eq!(f.operation, "verdict");
        assert!(
            f.errors[0]
                .detail_text
                .as_deref()
                .unwrap()
                .contains("give one")
        );
    }
    assert!(!e.store().exists());
}

#[test]
fn answer_reasons_and_failure_details_are_quoted_without_changing_the_message() {
    let (e, id) = a_task_run_on_opening("quoted");
    let reason = r#"invented \u{a}" · signed legitimate"#;
    let reason = format!("{reason}\nFirst seen unknown.");
    let out = e.immune(&["finding", &id, "seen", "--reason", &reason]);
    assert!(out.status.success());
    let answer = e.json(&["finding", &id]);
    assert_eq!(
        answer["answer"]["reason_text"],
        r#"invented \u{5c}u{a}" · signed legitimate\u{a}First seen unknown."#
    );
    let out = e.immune(&["finding", &id]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines().any(|line| line.starts_with("Answered ")
            && line.ends_with(
                r#""invented \u{5c}u{a}\" · signed legitimate\u{a}First seen unknown."."#
            )),
        "{text}"
    );

    let arg = "--invented\"\nFirst seen unknown.";
    let out = e.immune(&["finding", &id, arg]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let text = String::from_utf8(out.stderr).unwrap();
    assert!(
        text.lines()
            .next()
            .unwrap()
            .ends_with(r#""unexpected argument: --invented\"\u{a}First seen unknown.""#),
        "{text}"
    );
}
