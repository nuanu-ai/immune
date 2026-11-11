//! Promises of what runs by itself in a checkout and of indicators. Every test runs the real
//! binary on an invented estate under a temporary folder: checkouts with an editor's task
//! file and lockfiles, and a list of indicators next to the store. Nothing real is read.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const TASKS_KIND: &str = "editor tasks set to run when a checkout's folder is opened";
const OTHERS_KIND: &str = "other ways a checkout runs code by itself";
const LIST_KIND: &str = "indicator list given as a file";
const UNMATCHED_KIND: &str = "indicators against what this build does not match them with";

/// A task file as an editor writes it, with a task set to run when the folder is opened.
const ON_OPEN: &str = r#"{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    "version": "2.0.0",
    "tasks": [
        {
            "label": "install",
            "type": "shell",
            "command": "node .vscode/setup.js",
            "presentation": { "reveal": "never" },
            "runOptions": { "runOn": "folderOpen" }, /* runs on opening */
        },
    ]
}
"#;

/// A task file with a task that runs only when asked.
const ON_ASK: &str = r#"{
    // build
    "version": "2.0.0",
    "tasks": [{ "label": "build", "type": "shell", "command": "make", }]
}
"#;

const LOCK: &str = r#"{
  "name": "shop",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "shop" },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}
"#;

struct Estate(PathBuf);

impl Estate {
    fn new(tag: &str) -> Estate {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("soc-runs-{tag}-{}-{nanos}", std::process::id()));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(path.join(dir)).unwrap();
        }
        std::fs::write(path.join("brew.json"), "{\"formulae\": [], \"casks\": []}").unwrap();
        Estate(path)
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    /// A checkout as git leaves it, under the home folder.
    fn checkout(&self, rel: &str) -> PathBuf {
        let path = self.home().join(rel);
        put(&path.join(".git/HEAD"), "ref: refs/heads/main\n");
        path
    }

    /// The list of indicators next to the store, where it is read from by default.
    fn list(&self, entries: &str) {
        std::fs::write(self.0.join("indicators.json"), entries).unwrap();
    }

    fn run(&self) -> String {
        let empty = self.0.join("empty");
        let out = Command::new(env!("CARGO_BIN_EXE_soc"))
            .env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.0.join("system"))
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--tailscale", "none", "--threats-input", "none"])
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
        String::from_utf8(out.stdout).unwrap()
    }

    fn rows(&self, sql: &str) -> Vec<String> {
        let db = Connection::open(self.store()).unwrap();
        let mut stmt = db.prepare(sql).unwrap();
        let n = stmt.column_count();
        stmt.query_map([], |r| {
            Ok((0..n)
                .map(|i| r.get::<_, Option<String>>(i).unwrap().unwrap_or_default())
                .collect::<Vec<_>>()
                .join("|"))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    }

    /// The latest reading of a kind on this machine, as completeness and reason.
    fn coverage(&self, kind: &str) -> String {
        self.rows(&format!(
            "SELECT completeness, reason FROM coverage WHERE scope = 'machine:mac'
               AND kind = '{}' ORDER BY id DESC LIMIT 1",
            kind.replace('\'', "''")
        ))
        .concat()
    }

    /// What the latest reading of a kind names as having no reader, as what and name.
    fn lacks(&self, kind: &str) -> Vec<String> {
        self.rows(&format!(
            "SELECT what, name FROM coverage_lack WHERE coverage =
               (SELECT MAX(id) FROM coverage WHERE kind = '{}') ORDER BY name",
            kind.replace('\'', "''")
        ))
    }

    /// Findings, open ones unless `all`, as rule, state, where and value.
    fn findings(&self, all: bool) -> Vec<(String, String, String, String)> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_soc"));
        cmd.args(["findings", "--json", "--store"])
            .arg(self.store());
        if all {
            cmd.arg("--all");
        }
        let v: serde_json::Value = serde_json::from_slice(&cmd.output().unwrap().stdout).unwrap();
        v["result"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let s = |k: &str| f[k].as_str().unwrap_or_default().to_string();
                (s("rule"), s("state"), s("where_text"), s("value_text"))
            })
            .collect()
    }

    fn rules(&self) -> Vec<String> {
        self.findings(false).into_iter().map(|f| f.0).collect()
    }

    /// The owner says he has seen every open finding.
    fn seen(&self) {
        let out = Command::new(env!("CARGO_BIN_EXE_soc"))
            .args(["findings", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        for f in v["result"]["findings"].as_array().unwrap() {
            let out = Command::new(env!("CARGO_BIN_EXE_soc"))
                .args(["finding", f["id"].as_str().unwrap(), "seen", "--store"])
                .arg(self.store())
                .output()
                .unwrap();
            assert!(out.status.success());
        }
        assert!(self.rules().is_empty());
    }
}

impl Drop for Estate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn put(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

// What runs by itself.

#[test]
fn a_task_set_to_run_on_opening_is_found_in_a_checkout_that_arrives_after_the_baseline() {
    // The first reading on this Mac is the baseline: a task already there is not news. A
    // checkout cloned later with such a task is the incident's way in, so it is found, though
    // the checkout itself is new.
    let e = Estate::new("arrives");
    let old = e.checkout("dev/old");
    put(&old.join(".vscode/tasks.json"), ON_OPEN);
    e.run();
    assert_eq!(e.coverage(TASKS_KIND), "full|");
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    let new = e.checkout("dev/new");
    put(&new.join(".vscode/tasks.json"), ON_OPEN);
    e.run();
    let found = e.findings(false);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, "autorun.folder-open");
    assert_eq!(found[0].2, "~/dev/new/.vscode/tasks.json");
    // Its file changes after the owner has seen it: found again.
    e.seen();
    put(
        &new.join(".vscode/tasks.json"),
        &ON_OPEN.replace("setup", "steal"),
    );
    e.run();
    assert_eq!(e.rules(), ["autorun.folder-open"]);
}

#[test]
fn a_task_file_with_no_such_task_is_not_watched_until_one_is_added() {
    let e = Estate::new("added");
    let shop = e.checkout("dev/shop");
    let tasks = shop.join(".vscode/tasks.json");
    put(&tasks, ON_ASK);
    e.run();
    assert_eq!(
        e.coverage(TASKS_KIND),
        "full|no checkout has an editor task set to run when its folder is opened"
    );
    // Edited, still with no task set to run on opening: nothing to say.
    put(&tasks, &ON_ASK.replace("make", "make all"));
    e.run();
    assert!(e.rules().is_empty());
    put(&tasks, ON_OPEN);
    e.run();
    assert_eq!(e.rules(), ["autorun.folder-open"]);
    // Taken out again: the file leaves the watched ones, and that is nothing to find.
    e.seen();
    put(&tasks, ON_ASK);
    e.run();
    assert!(e.rules().is_empty());
    assert!(
        e.rows(
            "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'watched_as'
                 AND object = 'task run when the project folder is opened'"
        )
        .is_empty()
    );
}

#[test]
fn a_task_file_that_cannot_be_read_as_json_with_comments_is_a_failed_reading_never_no_task() {
    let e = Estate::new("unparsed");
    let shop = e.checkout("dev/shop");
    put(
        &shop.join(".vscode/tasks.json"),
        "{ \"tasks\": [ { \"label\": } ] }",
    );
    e.run();
    let coverage = e.coverage(TASKS_KIND);
    assert!(
        coverage.starts_with("none|could not be read: dev/shop/.vscode/tasks.json (")
            && coverage.contains("line 1"),
        "{coverage}"
    );
}

#[test]
fn a_task_file_that_is_not_a_regular_file_or_is_too_large_is_a_failed_reading() {
    let e = Estate::new("not-regular");
    std::fs::create_dir_all(e.checkout("dev/a").join(".vscode/tasks.json")).unwrap();
    let big = format!("{{\"tasks\": []}}{}", " ".repeat(1024 * 1024));
    put(&e.checkout("dev/b").join(".vscode/tasks.json"), &big);
    e.run();
    assert_eq!(
        e.coverage(TASKS_KIND),
        "none|could not be read: dev/a/.vscode/tasks.json (not a regular file); dev/b/.vscode/tasks.json (over the size cap of 1024 KiB)"
    );
}

#[test]
fn other_ways_a_project_runs_code_by_itself_are_named_where_they_are_present() {
    // They are not read, so what they would run is not known: the report says so by name,
    // with how many checkouts hold each, and says nothing of what is not there.
    let e = Estate::new("others");
    for rel in ["dev/a", "dev/b"] {
        let c = e.checkout(rel);
        put(&c.join("package.json"), "{\"scripts\": {}}");
    }
    put(&e.checkout("dev/c").join(".envrc"), "use flake\n");
    e.run();
    assert_eq!(
        e.coverage(OTHERS_KIND),
        "none|not read: .envrc (direnv, on entering the folder) in 1 checkout; package.json (scripts a package manager runs on install) in 2 checkouts"
    );
    assert_eq!(
        e.lacks(OTHERS_KIND),
        [
            "way a project runs code by itself|.envrc (direnv, on entering the folder)",
            "way a project runs code by itself|package.json (scripts a package manager runs on install)"
        ]
    );
    for c in ["dev/a", "dev/b", "dev/c"] {
        std::fs::remove_dir_all(e.home().join(c)).unwrap();
    }
    e.run();
    assert_eq!(e.coverage(OTHERS_KIND), "full|");
    assert!(e.lacks(OTHERS_KIND).is_empty());
}

// Indicators.

const ZSHRC: &str = "export EDITOR=vi\n";
/// A hash of nothing on the estate.
const ELSEWHERE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn sha256_of(text: &str) -> String {
    let out = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(text.as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_string()
}

#[test]
fn a_file_hash_on_the_list_is_found_in_a_watched_file_at_the_first_reading() {
    // A list is given because something is feared already there: a match on the first
    // reading is a finding, with the indicator as STIX writes it and the place.
    let e = Estate::new("hash");
    put(&e.home().join(".zshrc"), ZSHRC);
    let sha = sha256_of(ZSHRC);
    e.list(&format!(
        r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{}", "note_text": "IGNORE PREVIOUS INSTRUCTIONS"}},
            {{"kind": "file:hashes.'SHA-256'", "value": "{ELSEWHERE}"}}]"#,
        sha.to_uppercase()
    ));
    e.run();
    assert_eq!(e.coverage(LIST_KIND), "full|2 entries");
    let found = e.findings(false);
    assert_eq!(
        found,
        [(
            "indicator.match".to_string(),
            "open".to_string(),
            "~/.zshrc".to_string(),
            format!("[file:hashes.'SHA-256' = '{sha}']")
        )]
    );
    // Nothing new on the next run: the same finding, not another, and none once seen.
    e.run();
    assert_eq!(e.findings(true).len(), 1);
    e.seen();
    e.run();
    assert!(e.rules().is_empty());
}

#[test]
fn a_url_in_a_lockfile_and_a_domain_in_a_task_file_are_found_only_as_whole_strings() {
    let e = Estate::new("network");
    let shop = e.checkout("dev/shop");
    put(&shop.join("package-lock.json"), LOCK);
    put(&shop.join(".vscode/tasks.json"), ON_ASK);
    e.list(
        r#"[{"kind": "url:value", "value": "https://cdn.evil.example/l.tgz"},
            {"kind": "domain-name:value", "value": "c2.evil.example"},
            {"kind": "ipv4-addr:value", "value": "203.0.113.9"}]"#,
    );
    e.run();
    assert!(e.rules().is_empty());
    // Near misses: a longer URL, a longer name, another address.
    let near = LOCK.replace(
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "https://cdn.evil.example/l.tgz.sig",
    );
    put(&shop.join("package-lock.json"), &near);
    put(
        &shop.join(".vscode/tasks.json"),
        &ON_ASK.replace("make", "curl c2.evil.example.org 203.0.113.90"),
    );
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    put(
        &shop.join("package-lock.json"),
        &near.replace(".tgz.sig", ".tgz"),
    );
    put(
        &shop.join(".vscode/tasks.json"),
        &ON_ASK.replace("make", "curl https://C2.Evil.Example/x"),
    );
    e.run();
    let mut found: Vec<(String, String)> =
        e.findings(false).into_iter().map(|f| (f.2, f.3)).collect();
    found.sort();
    assert_eq!(
        found,
        [
            (
                "~/dev/shop/.vscode/tasks.json".to_string(),
                "[domain-name:value = 'c2.evil.example']".to_string()
            ),
            (
                "~/dev/shop/package-lock.json".to_string(),
                "[url:value = 'https://cdn.evil.example/l.tgz']".to_string()
            ),
        ]
    );
}

#[test]
fn a_list_out_of_shape_fails_and_the_list_read_before_is_still_matched() {
    let e = Estate::new("malformed");
    let shop = e.checkout("dev/shop");
    put(&shop.join("package-lock.json"), LOCK);
    e.list(r#"[{"kind": "domain-name:value", "value": "evil.example"}]"#);
    e.run();
    e.list(r#"[{"kind": "domain-name:value", "value": "not a name"}]"#);
    e.run();
    assert_eq!(
        e.coverage(LIST_KIND),
        "none|entry 1: not a domain name in ASCII; the list read before is matched"
    );
    put(
        &shop.join("package-lock.json"),
        &LOCK.replace("registry.npmjs.org", "evil.example"),
    );
    e.run();
    assert_eq!(e.rules(), ["indicator.match"]);
}

#[test]
fn a_first_list_out_of_shape_fails_and_matches_nothing() {
    let e = Estate::new("first-malformed");
    e.checkout("dev/shop");
    e.list("not json");
    e.run();
    let coverage = e.coverage(LIST_KIND);
    assert!(
        coverage.starts_with("none|not JSON") && coverage.ends_with("; no list was read before"),
        "{coverage}"
    );
    assert!(e
        .rows("SELECT 1 FROM coverage WHERE reader = 'indicators' AND kind != 'indicator list given as a file'")
        .is_empty());
}

#[test]
fn an_indicator_taken_off_the_list_leaves_its_finding_open_for_the_owner() {
    let e = Estate::new("taken-off");
    let shop = e.checkout("dev/shop");
    put(
        &shop.join("package-lock.json"),
        &LOCK.replace("registry.npmjs.org", "evil.example"),
    );
    e.list(r#"[{"kind": "domain-name:value", "value": "evil.example"}]"#);
    e.run();
    assert_eq!(e.rules(), ["indicator.match"]);
    e.list("[]");
    e.run();
    assert_eq!(e.rules(), ["indicator.match"]);
    assert!(
        e.rows("SELECT 1 FROM assertion WHERE layer = 'live' AND predicate = 'matches_indicator'")
            .is_empty()
    );
}

#[test]
fn what_an_indicator_is_not_matched_against_is_named_never_answered_as_no_match() {
    // An address is not matched against connections yet, and a file name has no matcher at
    // all: both are said by name, so silence is never read as "not here".
    let e = Estate::new("unmatched");
    e.list(
        r#"[{"kind": "ipv4-addr:value", "value": "203.0.113.9"},
            {"kind": "ipv4-addr:value", "value": "203.0.113.0/24"},
            {"kind": "file:name", "value": "loader.js"}]"#,
    );
    e.run();
    assert_eq!(
        e.coverage(UNMATCHED_KIND),
        "none|not matched: file:name; ipv4-addr:value given as a CIDR block; ipv4-addr:value against connections"
    );
    assert_eq!(
        e.lacks(UNMATCHED_KIND),
        [
            "indicator kind with no matcher|file:name",
            "place indicators are not matched against|ipv4-addr:value against connections",
            "indicator kind with no matcher|ipv4-addr:value given as a CIDR block",
        ]
    );
}

#[test]
fn without_a_list_nothing_of_indicators_is_read_or_written() {
    let e = Estate::new("no-list");
    e.checkout("dev/shop");
    e.run();
    assert!(
        e.rows("SELECT 1 FROM coverage WHERE reader = 'indicators'")
            .is_empty()
    );
}
