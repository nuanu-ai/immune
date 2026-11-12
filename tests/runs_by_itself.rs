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
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immune"));
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

    /// The owner says he has seen every open finding.
    fn seen(&self) {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .args(["findings", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        for f in v["result"]["findings"].as_array().unwrap() {
            let out = Command::new(env!("CARGO_BIN_EXE_immune"))
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
fn a_way_read_for_the_first_time_on_a_store_that_never_read_it_is_its_baseline() {
    // A store of an earlier build held the checkouts and never read their package scripts:
    // the first reading of them is the baseline, not a finding about every project. A script
    // planted after it is found.
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
              OR scope LIKE '%#/%';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
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
fn a_place_in_the_home_folder_read_for_the_first_time_on_an_existing_store_is_its_baseline() {
    // A store of an earlier build never read the home folder's settings: what they hold the
    // first time is the baseline, not a finding about every server and extension.
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
              OR scope LIKE '%#/%' OR scope LIKE '%/.vscode/extensions/%';",
    )
    .unwrap();
    drop(db);
    e.run();
    assert!(e.rules().is_empty(), "{:?}", e.findings(false));
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
