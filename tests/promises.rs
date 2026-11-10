//! Promises of the walking skeleton: store, the readers, the lifecycle, the report and the view.
//! Each test runs the real binary on samples in the formats the sources print: `brew list
//! --versions`, the files the server sweep writes, lockfiles in checkouts, the ssh files and
//! `tailscale status --json`. Every sample is invented, and the home folder is always a
//! temporary one: no test reads the real ssh files or asks the real tailscale.

use rusqlite::Connection;
use rusqlite::types::ValueRef;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SAMPLE: &str = "\
ca-certificates 2024.09.24
git 2.47.0
node 22.9.0 23.1.0
openssl@3 3.4.0
python@3.12 3.12.7_1
firefox 132.0.1
";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("soc-test-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }

    fn input(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs soc with only the brew reader's input and returns the report line.
/// The other readers are pointed at folders that do not exist.
fn soc(store: &Path, input: &Path) -> String {
    let absent = store.parent().unwrap().join("absent");
    soc_all(store, input, &absent, &absent)
}

/// Runs soc with every reader's input and returns the report line.
fn soc_all(store: &Path, brew: &Path, servers: &Path, checkouts: &Path) -> String {
    soc_in(store.parent().unwrap(), store, brew, servers, checkouts)
}

/// The same, from a given folder, which is also the home folder.
fn soc_in(cwd: &Path, store: &Path, brew: &Path, servers: &Path, checkouts: &Path) -> String {
    ok(soc_run(cwd, store)
        .arg("--brew-input")
        .arg(brew)
        .arg("--servers-input")
        .arg(servers)
        .arg("--checkouts-root")
        .arg(checkouts))
}

/// Runs soc with the brew and server inputs; checkouts are found by the walk of the home
/// folder, which is the store's folder.
fn soc_home(store: &Path, brew: &Path, servers: &Path) -> String {
    ok(soc_run(store.parent().unwrap(), store)
        .arg("--brew-input")
        .arg(brew)
        .arg("--servers-input")
        .arg(servers))
}

/// The binary with `home` as both the home folder and the working folder, so that
/// nothing a test runs can reach the real home folder.
fn soc_cmd(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soc"));
    cmd.env("HOME", home).current_dir(home);
    cmd
}

/// `soc run` for the machine `mac`, with no tailscale, so that the real one is never asked.
/// A later `--tailscale` replaces it.
fn soc_run(home: &Path, store: &Path) -> Command {
    let mut cmd = soc_cmd(home);
    cmd.args(["run", "--machine-name", "mac", "--store"])
        .arg(store)
        .arg("--tailscale")
        .arg(home.join("no-tailscale"));
    cmd
}

/// Runs a command that must succeed and returns what it printed.
fn ok(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Runs `soc view` without opening a browser and returns the page it wrote.
fn view(store: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_soc"))
        .args(["view", "--no-open", "--store"])
        .arg(store)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = String::from_utf8(out.stdout).unwrap();
    std::fs::read_to_string(path.trim()).unwrap()
}

/// One section of the page, by its id.
fn section<'a>(page: &'a str, id: &str) -> &'a str {
    let start = page
        .find(&format!("<section id=\"{id}\">"))
        .unwrap_or_else(|| panic!("no section {id}"));
    let end = start + page[start..].find("</section>").unwrap();
    &page[start..end]
}

/// Every row as its columns joined with `|`.
fn rows(store: &Path, sql: &str) -> Vec<String> {
    let conn = Connection::open(store).unwrap();
    let mut stmt = conn.prepare(sql).unwrap();
    let n = stmt.column_count();
    stmt.query_map([], |row| {
        let cols: Vec<String> = (0..n)
            .map(|i| match row.get_ref(i).unwrap() {
                ValueRef::Null => "NULL".to_string(),
                ValueRef::Integer(v) => v.to_string(),
                ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                other => format!("{other:?}"),
            })
            .collect();
        Ok(cols.join("|"))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

const LAST_RUN_EVENTS: &str = "
    SELECT entry, subject, predicate, old_value, new_value FROM journal
    WHERE entry IN ('added', 'changed', 'removed')
      AND run_id = (SELECT run_id FROM journal ORDER BY seq DESC LIMIT 1)
    ORDER BY seq";

const LIVE: &str = "
    SELECT subject, predicate, object FROM assertion WHERE layer = 'live'
    ORDER BY subject, predicate, object";

#[test]
fn second_run_on_unchanged_input_reports_no_changes_and_writes_no_events() {
    let dir = Dir::new("unchanged");
    let input = dir.input("brew.txt", SAMPLE);
    let first = soc(&dir.store(), &input);
    assert!(first.contains("First run."), "{first}");

    let second = soc(&dir.store(), &input);
    assert!(
        second.starts_with(
            "1 reader, 1 machine, 0 checkouts, 6 components. No servers known. \
             Since last run: no changes."
        ),
        "{second}"
    );
    assert!(rows(&dir.store(), LAST_RUN_EVENTS).is_empty());
}

#[test]
fn reader_that_could_not_read_its_scope_retracts_nothing() {
    let dir = Dir::new("unread");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));
    let live_before = rows(&store, LIVE);

    let report = soc(&store, &dir.0.join("missing.txt"));
    assert_eq!(rows(&store, LIVE), live_before);
    assert!(rows(&store, "SELECT 1 FROM assertion WHERE layer = 'retracted'").is_empty());
    assert!(rows(&store, LAST_RUN_EVENTS).is_empty());
    assert!(report.contains("could not be read"), "{report}");
    assert!(!report.contains("no changes"), "{report}");
    assert_eq!(
        rows(
            &store,
            "SELECT completeness FROM coverage WHERE reader = 'brew' ORDER BY id DESC LIMIT 1"
        ),
        ["none"]
    );
}

#[test]
fn package_gone_from_input_moves_to_retracted_and_stays_queryable() {
    let dir = Dir::new("gone");
    let store = dir.store();
    // Seen on two runs, not only the first, before it disappears.
    let before = dir.input("before.txt", SAMPLE);
    soc(&store, &before);
    soc(&store, &before);
    let after = SAMPLE.replace("git 2.47.0\n", "");
    let report = soc(&store, &dir.input("after.txt", &after));

    assert!(
        report.contains("Since last run: +0 added, 0 changed, 1 removed."),
        "{report}"
    );
    let git = "component:machine:mac/brew/git";
    let live = rows(&store, LIVE);
    assert!(!live.iter().any(|r| r.starts_with(git)), "{live:?}");
    let retracted = rows(
        &store,
        "SELECT subject, predicate, object FROM assertion
         WHERE layer = 'retracted' AND retracted_at IS NOT NULL
         ORDER BY predicate",
    );
    assert_eq!(
        retracted,
        [
            format!("{git}|has_version|2.47.0"),
            format!("{git}|part_of|machine:mac"),
        ]
    );
}

#[test]
fn version_change_is_one_changed_event() {
    let dir = Dir::new("version");
    let store = dir.store();
    soc(&store, &dir.input("before.txt", SAMPLE));
    let after = SAMPLE.replace("git 2.47.0", "git 2.47.1");
    let report = soc(&store, &dir.input("after.txt", &after));

    assert!(
        report.contains("Since last run: +0 added, 1 changed, 0 removed."),
        "{report}"
    );
    assert_eq!(
        rows(&store, LAST_RUN_EVENTS),
        ["changed|component:machine:mac/brew/git|has_version|2.47.0|2.47.1"]
    );
}

#[test]
fn entity_ids_are_the_same_across_runs_for_the_same_input() {
    let (a, b) = (Dir::new("ids-a"), Dir::new("ids-b"));
    soc(&a.store(), &a.input("brew.txt", SAMPLE));
    soc(&b.store(), &b.input("brew.txt", SAMPLE));

    let ids = "SELECT id FROM entity ORDER BY id";
    assert_eq!(rows(&a.store(), ids), rows(&b.store(), ids));
}

#[test]
fn raw_input_is_kept_as_read_and_every_assertion_points_at_its_line() {
    // Facts are derived from raw input: the store is rebuilt from it and an assertion shows
    // what it rests on.
    let dir = Dir::new("raw");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));

    let live = rows(
        &store,
        "SELECT subject, predicate, object, source_ref FROM assertion WHERE layer = 'live'",
    );
    assert!(!live.is_empty());
    for row in live {
        let [subject, predicate, object, source_ref] = row.split('|').collect::<Vec<_>>()[..]
        else {
            panic!("{row}")
        };
        let (file, line) = source_ref.rsplit_once(':').unwrap();
        let raw = std::fs::read_to_string(dir.0.join(file)).unwrap();
        assert_eq!(raw, SAMPLE);
        let words: Vec<&str> = raw
            .lines()
            .nth(line.parse::<usize>().unwrap() - 1)
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(subject.rsplit('/').next(), Some(words[0]), "{row}");
        if predicate == "has_version" {
            assert!(words[1..].contains(&object), "{row}");
        }
    }
}

#[test]
fn journal_is_append_only() {
    // The journal is the one part of the store that cannot be rebuilt from raw input.
    let dir = Dir::new("journal");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));
    let before = rows(&store, "SELECT * FROM journal ORDER BY seq");

    let conn = Connection::open(&store).unwrap();
    assert!(conn.execute("UPDATE journal SET text = 'x'", []).is_err());
    assert!(conn.execute("DELETE FROM journal", []).is_err());
    assert_eq!(rows(&store, "SELECT * FROM journal ORDER BY seq"), before);
}

#[test]
fn text_from_the_store_never_becomes_markup() {
    // Package names and versions are partly written by an attacker.
    let dir = Dir::new("escape");
    let store = dir.store();
    let evil = "<script>alert('x')</script>\"onload=\"x 1.0\"><b>bold</b>\n";
    soc(&store, &dir.input("brew.txt", &format!("{SAMPLE}{evil}")));
    let page = view(&store);

    assert!(!page.contains("<script"), "a script tag reached the page");
    assert!(
        !page.contains("<b>"),
        "a tag from a version reached the page"
    );
    assert!(
        !page.contains("\"onload"),
        "a quote from a name reached the page"
    );
    assert!(page.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&quot;onload=&quot;x"));
    assert!(page.contains("1.0&quot;&gt;&lt;b&gt;bold&lt;/b&gt;"));
}

#[test]
fn view_does_not_change_or_create_the_store() {
    let dir = Dir::new("readonly");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));
    let before = std::fs::read(&store).unwrap();
    view(&store);
    assert!(
        std::fs::read(&store).unwrap() == before,
        "the store file changed"
    );

    let missing = dir.0.join("none").join("store.db");
    let out = Command::new(env!("CARGO_BIN_EXE_soc"))
        .args(["view", "--no-open", "--store"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no store"));
    assert!(!missing.exists() && !dir.0.join("none").exists());
}

#[test]
fn reading_that_failed_is_shown_with_its_reason_and_not_as_full() {
    // False calm: the page must not present a scope as read when it was not.
    let dir = Dir::new("failed");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));
    soc(&store, &dir.0.join("missing.txt"));
    let reason = rows(
        &store,
        "SELECT reason FROM coverage WHERE reader = 'brew' ORDER BY id DESC LIMIT 1",
    );
    let page = view(&store);

    let coverage = section(&page, "coverage");
    let row = coverage
        .split("<tr")
        .find(|r| r.contains("machine:mac") && r.contains("brew packages"))
        .expect("no coverage row for the brew reading");
    assert!(row.contains("could not be read"), "{row}");
    assert!(row.contains(reason[0].as_str()), "{row}");
    assert!(!row.contains("full"), "{row}");
    assert!(!coverage.contains("Every reading was full"), "{coverage}");
}

#[test]
fn removed_component_is_under_no_longer_there_and_not_on_the_machine() {
    // The machine shows only what is there now; an old version is gone too.
    let dir = Dir::new("view-gone");
    let store = dir.store();
    soc(&store, &dir.input("before.txt", SAMPLE));
    let after = SAMPLE
        .replace("git 2.47.0\n", "")
        .replace("node 22.9.0 23.1.0", "node 23.1.0");
    soc(&store, &dir.input("after.txt", &after));
    let page = view(&store);

    let git = ">git</td>";
    let machines = section(&page, "machines");
    assert!(machines.contains(">node</td>"), "{machines}");
    assert!(!machines.contains(git), "{machines}");
    assert!(!machines.contains("22.9.0"), "{machines}");
    let gone = section(&page, "gone");
    assert!(gone.contains(git), "{gone}");
    assert!(gone.contains("2.47.0"), "{gone}");
    assert!(gone.contains("22.9.0"), "{gone}");
}

/// A server file as the sweep writes it: a web server with two running containers.
const WEB_1: &str = "\
##os
Ubuntu 24.04.1 LTS
##kernel
6.8.0-45-generic
##reboot_required
no
##pve
##dpkg
bash\t5.2.21-2ubuntu4
openssl\t3.0.13-0ubuntu3.4
##snap
core22\t20240823
##docker_access
docker
##docker_ps
nginx:1.27.1\tshop\tUp 2 days
wordpress:6.6-php8.2-apache\tblog\tUp 3 hours (healthy)
##docker_images
nginx:1.27.1
wordpress:6.6-php8.2-apache
##container_versions
/shop\tNGINX_VERSION=1.27.1
/blog\tPHP_VERSION=8.2.24
##wp
blog\twp_version=6.6.2
##end
";

/// A sweep that stopped before it reached `##end`, in the middle of the package list.
fn cut(file: &str) -> String {
    file[..file.find("openssl").unwrap()].to_string()
}

/// Writes a file under the folder, creating the folders on the way.
fn put(root: &Path, rel: &str, content: &str) -> PathBuf {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path
}

/// A checkout as git leaves it: `.git` with a branch that points at a commit.
fn checkout(root: &Path, rel: &str) -> PathBuf {
    put(root, &format!("{rel}/.git/HEAD"), "ref: refs/heads/main\n");
    put(
        root,
        &format!("{rel}/.git/refs/heads/main"),
        "0123456789abcdef0123456789abcdef01234567\n",
    );
    root.join(rel)
}

const PACKAGE_LOCK: &str = r#"{
  "name": "shop",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "shop", "version": "1.0.0" },
    "node_modules/left-pad": { "version": "1.3.0" },
    "node_modules/@types/node": { "version": "22.7.4" }
  }
}
"#;

const CARGO_LOCK: &str = r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

#[test]
fn under_partial_coverage_new_assertions_become_live_and_nothing_is_retracted() {
    // A checkout with a lockfile the reader cannot read is read partially: a dependency
    // that is no longer seen may still be there, so it must not be reported as gone.
    let dir = Dir::new("partial");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    let root = dir.0.join("dev");
    let shop = checkout(&root, "shop");
    put(&shop, "api/yarn.lock", "# yarn lockfile v1\n");
    put(&shop, "package-lock.json", PACKAGE_LOCK);
    soc_home(&store, &brew, &absent);

    let next = PACKAGE_LOCK
        .replace(
            "left-pad\": { \"version\": \"1.3.0",
            "is-odd\": { \"version\": \"3.0.1",
        )
        .replace("22.7.4", "22.7.5");
    put(&shop, "package-lock.json", &next);
    let report = soc_home(&store, &brew, &absent);

    let npm = "component:checkout:machine:mac/dev/shop/npm";
    let live = rows(&store, LIVE);
    for expected in [
        format!("{npm}/left-pad|has_version|1.3.0"),
        format!("{npm}/is-odd|has_version|3.0.1"),
        format!("{npm}/@types/node|has_version|22.7.4"),
        format!("{npm}/@types/node|has_version|22.7.5"),
    ] {
        assert!(live.contains(&expected), "{expected} is not live");
    }
    assert!(rows(&store, "SELECT 1 FROM assertion WHERE layer = 'retracted'").is_empty());
    assert_eq!(
        rows(&store, LAST_RUN_EVENTS),
        [
            format!("changed|{npm}/@types/node|has_version|22.7.4|22.7.4, 22.7.5"),
            format!("added|{npm}/is-odd|has_version|NULL|3.0.1"),
            format!("added|{npm}/is-odd|part_of|NULL|checkout:machine:mac/dev/shop"),
        ]
    );
    assert!(report.contains("1 reading was partial"), "{report}");
    assert!(report.contains("removals unknown"), "{report}");

    let page = view(&store);
    let coverage = section(&page, "coverage");
    let row = coverage
        .split("<tr")
        .find(|r| r.contains("lockfile dependencies"))
        .expect("no coverage row for the lockfile reading");
    assert!(row.contains("partial, removals unknown"), "{row}");
}

#[test]
fn server_file_without_end_is_a_machine_not_read_and_retracts_nothing() {
    // A sweep that broke off says nothing about what is on the server.
    let dir = Dir::new("cut");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let servers = dir.0.join("servers");
    let absent = dir.0.join("absent");
    put(&servers, "web-1.txt", WEB_1);
    put(&servers, "db-1.txt", &cut(WEB_1));
    soc_all(&store, &brew, &servers, &absent);
    let live_before = rows(&store, LIVE);

    put(&servers, "web-1.txt", &cut(WEB_1));
    let report = soc_all(&store, &brew, &servers, &absent);

    assert_eq!(rows(&store, LIVE), live_before);
    assert!(rows(&store, "SELECT 1 FROM assertion WHERE layer = 'retracted'").is_empty());
    assert!(rows(&store, LAST_RUN_EVENTS).is_empty());
    assert!(report.contains("2 machines could not be read"), "{report}");
    assert!(!report.contains("no changes"), "{report}");
    assert_eq!(
        rows(
            &store,
            "SELECT scope, kind, completeness, reason FROM coverage
             WHERE run_id = (SELECT MAX(run_id) FROM coverage) AND reader = 'servers'
             ORDER BY scope, kind"
        ),
        [
            "machine:db-1|containers|none|the sweep of this server did not complete",
            "machine:db-1|system packages|none|the sweep of this server did not complete",
            "machine:web-1|containers|none|the sweep of this server did not complete",
            "machine:web-1|system packages|none|the sweep of this server did not complete",
        ]
    );

    // The machine that was never read is known, has nothing on it, and says so.
    assert_eq!(
        rows(&store, "SELECT id FROM entity WHERE id = 'machine:db-1'"),
        ["machine:db-1"]
    );
    assert!(!live_before.iter().any(|r| r.contains("machine:db-1")));
    let page = view(&store);
    let machines = section(&page, "machines");
    let db = machines
        .split("<details class=\"machine\">")
        .find(|m| m.contains("<strong>db-1</strong>"))
        .expect("db-1 is not on the page");
    assert!(db.contains("could not be read"), "{db}");
    assert!(db.contains("0 components"), "{db}");
}

/// Sets a file's modification time.
fn touch(file: &Path, secs: u64) {
    std::fs::File::options()
        .write(true)
        .open(file)
        .unwrap()
        .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn time_of_a_server_reading_is_taken_at_from_the_file_not_its_time_on_disk() {
    // Server files can be weeks old, and copying one changes its time on disk; a fresh time
    // on an old reading is false freshness. A file from before `##taken_at` falls back to
    // its time on disk, never to the time of the run.
    let dir = Dir::new("observed");
    let store = dir.store();
    let servers = dir.0.join("servers");
    let taken = 1_767_323_045; // 2026-01-02 03:04:05 UTC
    let web = put(
        &servers,
        "web-1.txt",
        &format!("##taken_at\n{taken}\n{WEB_1}"),
    );
    touch(&web, 1_700_000_000);
    let written = 1_767_000_000;
    touch(&put(&servers, "db-1.txt", WEB_1), written);
    soc_all(
        &store,
        &dir.input("brew.txt", SAMPLE),
        &servers,
        &dir.0.join("absent"),
    );

    let times = |table: &str| {
        rows(
            &store,
            &format!(
                "SELECT DISTINCT substr(scope, 1, instr(scope || '/', '/') - 1), observed_at
                 FROM {table} WHERE reader = 'servers' ORDER BY 1"
            ),
        )
    };
    let expected = [
        format!("container:machine:db-1|{written}"),
        format!("container:machine:web-1|{taken}"),
        format!("machine:db-1|{written}"),
        format!("machine:web-1|{taken}"),
    ];
    assert_eq!(times("coverage"), expected);
    assert_eq!(times("assertion"), expected);
    let page = view(&store);
    let web = section(&page, "machines")
        .split("<details class=\"machine\">")
        .find(|m| m.contains("<strong>web-1</strong>"))
        .unwrap()
        .to_string();
    assert!(web.contains("read 2026-01-02 03:04 UTC"), "{web}");
}

#[test]
fn unsupported_lockfile_gives_partial_coverage_naming_it_and_supported_ones_are_still_read() {
    // A lockfile the reader cannot read hides dependencies; the checkout must not look complete.
    let dir = Dir::new("lockfiles");
    let store = dir.store();
    let root = dir.0.join("dev");
    let shop = checkout(&root, "work/shop");
    // The unsupported one comes first in the order the reader goes through them.
    put(&shop, "api/yarn.lock", "# yarn lockfile v1\n");
    put(&shop, "package-lock.json", PACKAGE_LOCK);
    put(&shop, "web/Cargo.lock", CARGO_LOCK);
    let tools = checkout(&root, "tools");
    put(&tools, "Cargo.lock", CARGO_LOCK);
    soc_all(
        &store,
        &dir.input("brew.txt", SAMPLE),
        &dir.0.join("absent"),
        &root,
    );

    assert_eq!(
        rows(
            &store,
            "SELECT scope, completeness, COALESCE(reason, '') FROM coverage
             WHERE reader = 'lockfiles' ORDER BY scope"
        ),
        [
            "checkout:machine:mac/dev/tools|full|",
            "checkout:machine:mac/dev/work/shop|partial|not supported yet: yarn.lock",
        ]
    );
    let id = "component:checkout:machine:mac/dev/work/shop";
    let live = rows(&store, LIVE);
    for expected in [
        format!("{id}/npm/left-pad|has_version|1.3.0"),
        format!("{id}/npm/@types/node|has_version|22.7.4"),
        format!("{id}/crates.io/serde|has_version|1.0.210"),
    ] {
        assert!(live.contains(&expected), "{expected} is not live");
    }
}

/// Every file under a folder with its size and modification time.
fn snapshot(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            out.push(format!(
                "{}|{}|{:?}",
                entry.path().display(),
                meta.len(),
                meta.modified().unwrap()
            ));
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn readers_write_nothing_outside_the_store_folder() {
    // The readers look at the owner's checkouts and sweep files; they must never change them.
    let dir = Dir::new("outside");
    let inputs = dir.0.join("inputs");
    let brew = put(&inputs, "brew.txt", SAMPLE);
    let servers = inputs.join("servers");
    put(&servers, "web-1.txt", WEB_1);
    put(
        &servers,
        "web-1.err",
        "Warning: Permanently added 'web-1' to the list of known hosts.\n",
    );
    let root = dir.0.join("dev");
    let shop = checkout(&root, "shop");
    put(&shop, "package-lock.json", PACKAGE_LOCK);
    put(&shop, "web/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    let store = dir.0.join("store").join("store.db");
    let (inputs_before, root_before) = (snapshot(&inputs), snapshot(&root));

    // Run from the test folder, so that a write relative to the working folder shows too.
    soc_in(&dir.0, &store, &brew, &servers, &root);
    soc_in(&dir.0, &store, &brew, &servers, &root);
    view(&store);

    assert_eq!(snapshot(&inputs), inputs_before);
    assert_eq!(snapshot(&root), root_before);
    let top: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(top, ["dev", "inputs", "store"]);
}

#[test]
fn unchanged_input_is_not_copied_again_as_raw_input() {
    // Raw input is kept forever, so a copy per run of the same bytes would only grow.
    let dir = Dir::new("copies");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let servers = dir.0.join("servers");
    put(&servers, "web-1.txt", WEB_1);
    let absent = dir.0.join("absent");
    let copies = |name: &str| {
        snapshot(&dir.0.join("raw"))
            .iter()
            .filter(|r| r.contains(&format!("/{name}|")))
            .count()
    };
    soc_all(&store, &brew, &servers, &absent);
    soc_all(&store, &brew, &servers, &absent);
    assert_eq!((copies("brew.txt"), copies("web-1.txt")), (1, 1));

    // Every assertion still points at a saved copy.
    for source in rows(&store, "SELECT DISTINCT source_ref FROM assertion") {
        let file = source.rsplit_once(':').unwrap().0;
        assert!(dir.0.join(file).is_file(), "{source}");
    }

    put(
        &dir.0,
        "brew.txt",
        &SAMPLE.replace("git 2.47.0", "git 2.47.1"),
    );
    soc_all(&store, &brew, &servers, &absent);
    assert_eq!((copies("brew.txt"), copies("web-1.txt")), (2, 1));
}

#[test]
fn without_homebrew_the_brew_reading_has_nothing_to_read_and_earlier_brew_facts_are_retracted() {
    // A colleague's Mac may have no Homebrew. That is not a failure, and what an earlier
    // run read there is no longer there.
    let dir = Dir::new("no-brew");
    let store = dir.store();
    soc(&store, &dir.input("brew.txt", SAMPLE));
    let absent = dir.0.join("absent");
    let report = ok(soc_run(&dir.0, &store)
        .arg("--brew")
        .arg(dir.0.join("nowhere").join("brew"))
        .arg("--servers-input")
        .arg(&absent)
        .arg("--checkouts-root")
        .arg(&absent));

    assert!(
        !rows(&store, LIVE).iter().any(|r| r.contains("/brew/")),
        "brew facts are still live"
    );
    assert_eq!(
        rows(
            &store,
            "SELECT completeness, reason FROM coverage WHERE reader = 'brew' ORDER BY id DESC LIMIT 1"
        ),
        ["full|Homebrew is not installed on this machine"]
    );
    assert!(
        report.contains("Since last run: +0 added, 0 changed, 6 removed."),
        "{report}"
    );
    assert!(report.contains("Homebrew is not installed"), "{report}");
    assert!(!report.contains("could not be read"), "{report}");

    let page = view(&store);
    let row = section(&page, "coverage")
        .split("<tr")
        .find(|r| r.contains("brew packages"))
        .expect("no coverage row for the brew reading")
        .to_string();
    assert!(row.contains("nothing to read"), "{row}");
    assert!(
        row.contains("Homebrew is not installed on this machine"),
        "{row}"
    );
    assert!(!row.contains("could not be read"), "{row}");
}

#[test]
fn deleted_checkout_is_retracted_with_everything_inside_it_as_one_removed_event() {
    // Otherwise a deleted project keeps its dependencies live forever, and with them
    // every vulnerability that matches them.
    let dir = Dir::new("deleted");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    let root = dir.0.join("dev");
    let shop = checkout(&root, "shop");
    put(&shop, "Cargo.lock", CARGO_LOCK);
    // A partial reading inside it is retracted too: the place itself is gone.
    put(&shop, "api/yarn.lock", "# yarn lockfile v1\n");
    checkout(&root, "tools");
    soc_home(&store, &brew, &absent);
    let id = "checkout:machine:mac/dev/shop";
    assert!(rows(&store, LIVE).iter().any(|r| r.contains("/dev/shop/")));

    std::fs::remove_dir_all(&shop).unwrap();
    let report = soc_home(&store, &brew, &absent);

    assert_eq!(
        rows(&store, LAST_RUN_EVENTS),
        [format!("removed|{id}|located_on|machine:mac|NULL")]
    );
    assert!(
        !rows(&store, LIVE).iter().any(|r| r.contains("dev/shop")),
        "something inside the deleted checkout is still live"
    );
    assert_eq!(
        rows(
            &store,
            &format!(
                "SELECT subject, predicate, object FROM assertion
                 WHERE layer = 'retracted' AND scope = '{id}' ORDER BY predicate"
            )
        ),
        [
            format!("component:{id}/crates.io/serde|has_version|1.0.210"),
            format!("component:{id}/crates.io/serde|part_of|{id}"),
        ]
    );
    assert!(
        report.contains("1 checkout,") && report.contains("+0 added, 0 changed, 1 removed."),
        "{report}"
    );

    // Its readings no longer count: nothing is unknown about a place that is gone.
    let next = soc_home(&store, &brew, &absent);
    assert!(next.contains("Since last run: no changes."), "{next}");
    let page = view(&store);
    assert!(!section(&page, "coverage").contains(id));
    assert!(!section(&page, "machines").contains("dev/shop"));
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
fn folder_that_cannot_be_listed_gives_a_partial_checkouts_reading_naming_it_and_retracts_nothing() {
    // macOS may refuse a terminal Desktop or Documents. The checkouts there are unknown,
    // not deleted, and the owner is told which folder was not seen.
    let dir = Dir::new("unlisted");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    let root = dir.0.join("dev");
    let app = checkout(&root, "archive/app");
    put(&app, "Cargo.lock", CARGO_LOCK);
    checkout(&root, "work/site");
    soc_home(&store, &brew, &absent);
    let live_before = rows(&store, LIVE);

    // The walk goes on past the folder it cannot list.
    checkout(&root, "work/new");
    let _locked = Locked::new(root.join("archive"));
    let report = soc_home(&store, &brew, &absent);

    assert_eq!(
        rows(
            &store,
            "SELECT completeness, reason FROM coverage
             WHERE kind = 'checkouts under the home folder' ORDER BY id DESC LIMIT 1"
        ),
        ["partial|could not be listed: dev/archive"]
    );
    assert!(rows(&store, "SELECT 1 FROM assertion WHERE layer = 'retracted'").is_empty());
    let live = rows(&store, LIVE);
    for row in &live_before {
        assert!(live.contains(row), "{row} is no longer live");
    }
    assert!(live.contains(&"checkout:machine:mac/dev/work/new|located_on|machine:mac".to_string()));
    assert!(
        report.contains("Folders that could not be listed: dev/archive."),
        "{report}"
    );
    assert!(!report.contains("no changes"), "{report}");
}

#[test]
fn by_default_nothing_is_written_to_the_working_folder_and_the_store_is_in_the_users_folder() {
    // A colleague runs the binary from wherever the download landed. The store, raw input
    // and the page go to their own folder, and server files are looked for next to them.
    let dir = Dir::new("defaults");
    let (home, cwd) = (dir.0.join("home"), dir.0.join("cwd"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cwd).unwrap();
    let brew = dir.input("brew.txt", SAMPLE);
    let soc = |args: &[&str]| {
        let mut cmd = soc_cmd(&home);
        cmd.current_dir(&cwd).args(args);
        cmd
    };
    let run = || {
        ok(soc(&["run", "--machine-name", "mac", "--brew-input"])
            .arg(&brew)
            .arg("--tailscale")
            .arg(dir.0.join("no-tailscale")))
    };

    let report = run();
    let folder = home.join("Library/Application Support/personal-soc");
    assert!(folder.join("store.db").is_file());
    assert!(folder.join("raw").is_dir());
    assert!(report.contains("No server sweep has been run."), "{report}");

    put(&folder, "sweep/web-1.txt", WEB_1);
    let report = run();
    assert!(report.contains("2 machines"), "{report}");

    let page = ok(&mut soc(&["view", "--no-open"]));
    assert_eq!(PathBuf::from(page), folder.join("view.html"));
    assert!(folder.join("view.html").is_file());

    assert_eq!(std::fs::read_dir(&cwd).unwrap().count(), 0);
    let top: Vec<String> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(top, ["Library"]);
}

#[test]
fn store_from_an_older_format_is_refused_with_a_message_and_left_untouched() {
    // Ids changed between formats; mixing old and new facts would give wrong answers,
    // and the old store is the owner's history.
    let dir = Dir::new("old-format");
    let store = dir.store();
    {
        let conn = Connection::open(&store).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta VALUES ('format_version', '2');
             CREATE TABLE journal (seq INTEGER PRIMARY KEY, entry TEXT);
             INSERT INTO journal (entry) VALUES ('run_finished');",
        )
        .unwrap();
    }
    let before = std::fs::read(&store).unwrap();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");

    let run = soc_run(&dir.0, &store)
        .arg("--brew-input")
        .arg(&brew)
        .arg("--servers-input")
        .arg(&absent)
        .arg("--checkouts-root")
        .arg(&absent)
        .output()
        .unwrap();
    let view = soc_cmd(&dir.0)
        .args(["view", "--no-open", "--store"])
        .arg(&store)
        .output()
        .unwrap();
    for out in [run, view] {
        assert_eq!(out.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("older format"), "{stderr}");
        assert!(stderr.contains("--store"), "{stderr}");
    }
    assert!(
        std::fs::read(&store).unwrap() == before,
        "the old store changed"
    );
    let mut top: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, ["brew.txt", "store.db"]);
}

#[test]
fn after_a_container_version_variable_changes_the_old_version_is_retracted() {
    // Every version variable of every running container is read, so that reading is full
    // and an upgrade leaves no old version behind. What is inside a container as a whole
    // is never read in full and says so.
    let dir = Dir::new("variables");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let servers = dir.0.join("servers");
    let absent = dir.0.join("absent");
    put(&servers, "web-1.txt", WEB_1);
    soc_all(&store, &brew, &servers, &absent);

    let next = WEB_1.replace("NGINX_VERSION=1.27.1", "NGINX_VERSION=1.27.2");
    put(&servers, "web-1.txt", &next);
    soc_all(&store, &brew, &servers, &absent);

    let nginx = "component:container:machine:web-1/shop/container-env/nginx";
    let live = rows(&store, LIVE);
    assert!(live.contains(&format!("{nginx}|has_version|1.27.2")));
    assert!(!live.contains(&format!("{nginx}|has_version|1.27.1")));
    assert_eq!(
        rows(
            &store,
            "SELECT subject, object FROM assertion WHERE layer = 'retracted'"
        ),
        [format!("{nginx}|1.27.1")]
    );
    assert_eq!(
        rows(&store, LAST_RUN_EVENTS),
        [format!("changed|{nginx}|has_version|1.27.1|1.27.2")]
    );
    assert_eq!(
        rows(
            &store,
            "SELECT scope, completeness, reason FROM coverage
             WHERE kind = 'container contents' AND run_id = (SELECT MAX(run_id) FROM coverage)
             ORDER BY scope"
        ),
        [
            "container:machine:web-1/blog|partial|only version variables and the WordPress core version are read",
            "container:machine:web-1/shop|partial|only version variables and the WordPress core version are read",
        ]
    );
    assert!(
        rows(
            &store,
            "SELECT 1 FROM assertion WHERE kind = 'container contents'"
        )
        .is_empty()
    );
}

#[test]
fn checkouts_are_found_anywhere_under_the_home_folder_except_where_none_belong() {
    // Discovery: a colleague keeps projects wherever they like and configures nothing.
    let dir = Dir::new("discovery");
    let home = dir.0.join("home");
    // In the order the store sorts ids.
    let found = ["Code/Music/synth", "Code/a", "x1/x2/x3/x4/deep"];
    for rel in found {
        checkout(&home, rel);
    }
    for rel in [
        "y1/y2/y3/y4/y5/too-deep",
        "Code/a/packages/inner",
        "Code/web/node_modules/pkg",
        "Code/web/vendor/lib",
        "Code/web/target/out",
        "Library/Mobile/repo",
        "Music/song",
        ".config/repo",
    ] {
        checkout(&home, rel);
    }
    // A home folder kept under git holds settings; it does not hide what is inside it.
    put(&home, ".git/HEAD", "ref: refs/heads/main\n");
    std::os::unix::fs::symlink(home.join("Code"), home.join("link")).unwrap();

    ok(soc_run(&home, &dir.store())
        .arg("--brew-input")
        .arg(dir.input("brew.txt", SAMPLE))
        .arg("--servers-input")
        .arg(dir.0.join("absent")));

    let expected: Vec<String> = found
        .iter()
        .map(|rel| format!("checkout:machine:mac/{rel}"))
        .collect();
    assert_eq!(
        rows(
            &dir.store(),
            "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'located_on'
             ORDER BY subject"
        ),
        expected
    );
}

/// An ssh configuration as people write it: a plain alias with its address, a pattern,
/// code hosting under an alias and by `User git`, an alias the owner skips, and an include.
const SSH_CONFIG: &str = "\
# Invented for tests.
Host web-1
    HostName 10.0.0.5
    User deploy
    IdentityFile ~/.ssh/id_invented
Host lab-*
    User admin
Host code-mirror
    HostName github.com
Host forge
    HostName git.example.org
    User git
Host retired-box
    HostName 10.0.0.8
Include config.d/*
";

const SSH_CONFIG_BUILD: &str = "\
Host build
    HostName build-box.example-tail.ts.net
";

/// Invented keys: none of them is a real key.
const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIInventedKeyForTestsOnly";
const SALT: &str = "aW52ZW50ZWRzYWx0";

fn known_hosts_file() -> String {
    format!(
        "\
10.0.0.5 ssh-ed25519 {KEY}Web1
[10.0.0.9]:2222,db-9 ecdsa-sha2-nistp256 {KEY}Db9
|1|{SALT}MQ==|aW52ZW50ZWRoYXNoMQ== ssh-ed25519 {KEY}HashedOne
|1|{SALT}Mg==|aW52ZW50ZWRoYXNoMg== ssh-rsa {KEY}HashedTwo
github.com ssh-ed25519 {KEY}CodeHosting
@cert-authority *.example.org ssh-ed25519 {KEY}Authority
"
    )
}

/// What `tailscale status --json` prints, cut to the fields that matter and a few that
/// must not be kept.
const TAILNET: &str = r#"{
  "Version": "1.76.1",
  "BackendState": "Running",
  "Self": { "HostName": "mac", "DNSName": "mac.example-tail.ts.net.",
            "TailscaleIPs": ["100.64.0.1"], "OS": "macOS" },
  "Peer": {
    "nodekey:invented1": { "PublicKey": "nodekey:invented1", "HostName": "build-box",
      "DNSName": "Build-Box.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.7", "fd7a:115c:a1e0::7"], "OS": "linux" },
    "nodekey:invented2": { "PublicKey": "nodekey:invented2", "HostName": "phone",
      "DNSName": "phone.example-tail.ts.net.", "TailscaleIPs": ["100.64.0.8"], "OS": "iOS" }
  }
}"#;

/// A shell script with this body, made executable.
fn script(path: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_path_buf()
}

/// A command that prints `out` whatever it is asked.
fn fake(path: &Path, out: &str) -> PathBuf {
    script(path, &format!("cat <<'END_OF_FAKE'\n{out}\nEND_OF_FAKE"))
}

/// A home folder with the given ssh files, and a store next to it.
struct Home {
    dir: Dir,
    home: PathBuf,
}

impl Home {
    fn new(tag: &str, config: Option<&str>, known_hosts: Option<&str>) -> Home {
        let dir = Dir::new(tag);
        let home = dir.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        if let Some(config) = config {
            put(&home, ".ssh/config", config);
            put(&home, ".ssh/config.d/build", SSH_CONFIG_BUILD);
        }
        if let Some(known) = known_hosts {
            put(&home, ".ssh/known_hosts", known);
        }
        Home { dir, home }
    }

    fn store(&self) -> PathBuf {
        self.dir.0.join("store").join("store.db")
    }

    /// `soc run` with the given server files and tailscale, and no checkouts.
    fn run(&self, servers: &Path, tailscale: &Path) -> String {
        let brew = put(&self.dir.0, "brew.txt", SAMPLE);
        ok(soc_run(&self.home, &self.store())
            .arg("--brew-input")
            .arg(brew)
            .arg("--servers-input")
            .arg(servers)
            .arg("--checkouts-root")
            .arg(self.dir.0.join("absent"))
            .arg("--tailscale")
            .arg(tailscale))
    }

    fn servers(&self) -> String {
        ok(soc_cmd(&self.home)
            .args(["servers", "--store"])
            .arg(self.store())
            .arg("--tailscale")
            .arg(self.dir.0.join("no-tailscale")))
    }
}

#[test]
fn the_program_never_runs_ssh() {
    // Access to servers is the owner's: the program only reads local files and writes a
    // script the owner runs.
    let h = Home::new("no-ssh", Some(SSH_CONFIG), Some(&known_hosts_file()));
    let marker = h.dir.0.join("ssh-was-called");
    let bin = h.dir.0.join("bin");
    script(&bin.join("ssh"), &format!("touch '{}'", marker.display()));
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let brew = put(&h.dir.0, "brew.txt", SAMPLE);
    ok(soc_run(&h.home, &h.store())
        .env("PATH", &path)
        .arg("--brew-input")
        .arg(brew)
        .arg("--checkouts-root")
        .arg(h.dir.0.join("absent")));
    let printed = ok(soc_cmd(&h.home)
        .env("PATH", &path)
        .args(["servers", "--store"])
        .arg(h.store())
        .arg("--tailscale")
        .arg(h.dir.0.join("no-tailscale")));

    assert!(!marker.exists(), "ssh was called");
    let sweep = h.dir.0.join("store").join("sweep");
    assert!(sweep.join("sweep.sh").is_file());
    assert!(!sweep.join("web-1.txt").exists(), "the sweep was run");
    assert!(printed.contains("Nothing was run."), "{printed}");
}

#[test]
fn hashed_known_hosts_make_the_reading_partial_with_their_count_and_no_key_is_stored() {
    // A hashed entry hides a host we may have; the reading must not look complete. Keys are
    // not ours to copy: neither a key nor its type is kept, in the store or next to it.
    let h = Home::new("hashed", None, Some(&known_hosts_file()));
    h.run(&h.dir.0.join("absent"), &h.dir.0.join("no-tailscale"));

    assert_eq!(
        rows(
            &h.store(),
            "SELECT completeness, reason FROM coverage WHERE kind = 'known hosts'"
        ),
        ["partial|2 hashed entries cannot be read"]
    );
    assert_eq!(
        rows(
            &h.store(),
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND kind = 'known hosts' ORDER BY subject"
        ),
        [
            "machine:10.0.0.5|10.0.0.5",
            "machine:10.0.0.9|10.0.0.9",
            "machine:db-9|db-9"
        ]
    );
    let store_folder = h.dir.0.join("store");
    let mut files = 0;
    let mut stack = vec![store_folder];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            files += 1;
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for secret in [KEY, SALT, "ssh-ed25519", "ecdsa-sha2", "ssh-rsa", "|1|"] {
                assert!(!text.contains(secret), "{secret} is in {}", path.display());
            }
        }
    }
    assert!(files > 1, "nothing was written");
}

#[test]
fn two_traces_that_name_the_same_address_are_one_machine_and_each_reader_keeps_what_it_wrote() {
    // One server under an alias, an address and a tailnet name must not look like three
    // servers, and the resolver must not rewrite what the readers saw.
    let h = Home::new(
        "same",
        Some(SSH_CONFIG),
        Some("10.0.0.5 ssh-ed25519 AAAA\n"),
    );
    let servers = h.dir.0.join("servers");
    put(&servers, "web-1.txt", WEB_1);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET);
    let report = h.run(&servers, &tailscale);

    assert_eq!(
        rows(
            &h.store(),
            "SELECT reader, subject, object FROM assertion
             WHERE layer = 'live' AND predicate = 'known_as' ORDER BY reader, subject, object"
        ),
        [
            "known-hosts|machine:10.0.0.5|10.0.0.5",
            "ssh-config|machine:build|build",
            "ssh-config|machine:build|build-box.example-tail.ts.net",
            "ssh-config|machine:retired-box|10.0.0.8",
            "ssh-config|machine:retired-box|retired-box",
            "ssh-config|machine:web-1|10.0.0.5",
            "ssh-config|machine:web-1|web-1",
            "tailnet|machine:build-box|100.64.0.7",
            "tailnet|machine:build-box|Build-Box.example-tail.ts.net.",
            "tailnet|machine:build-box|build-box",
            "tailnet|machine:build-box|fd7a:115c:a1e0::7",
            "tailnet|machine:phone|100.64.0.8",
            "tailnet|machine:phone|phone",
            "tailnet|machine:phone|phone.example-tail.ts.net.",
        ]
    );
    let links = "SELECT subject, object FROM assertion
                 WHERE layer = 'live' AND predicate = 'same_as' AND reader = 'resolver'
                 ORDER BY subject";
    assert_eq!(
        rows(&h.store(), links),
        [
            "machine:10.0.0.5|machine:web-1",
            "machine:build|machine:build-box"
        ]
    );
    assert!(
        report.contains("5 machines,")
            && report.contains("4 servers known, 3 offered for the sweep, 1 read."),
        "{report}"
    );

    let page = view(&h.store());
    let machines = section(&page, "machines");
    let blocks: Vec<&str> = machines.split("<details class=\"machine\">").collect();
    let web = blocks
        .iter()
        .find(|b| b.contains("<strong>web-1</strong>"))
        .expect("web-1 is not on the page");
    assert!(web.contains("10.0.0.5"), "{web}");
    assert!(
        !machines.contains("<strong>10.0.0.5</strong>"),
        "{machines}"
    );
    let never = blocks
        .iter()
        .find(|b| b.contains("Known and never read"))
        .expect("no list of machines never read");
    let names: Vec<&str> = never
        .split("<tr><td class=\"mono\">")
        .skip(1)
        .map(|r| r.split('<').next().unwrap())
        .collect();
    assert_eq!(names, ["build", "phone", "retired-box"], "{never}");
    let build = never.split("<tr>").find(|r| r.contains(">build<")).unwrap();
    assert!(
        build.contains("build-box") && build.contains("tailnet peers"),
        "{build}"
    );

    // The link goes when its evidence goes.
    std::fs::remove_file(h.home.join(".ssh/known_hosts")).unwrap();
    h.run(&servers, &tailscale);
    assert_eq!(rows(&h.store(), links), ["machine:build|machine:build-box"]);
}

#[test]
fn only_plain_ssh_aliases_are_offered_for_the_sweep() {
    // The sweep is access to servers. It visits only what the owner has an explicit way
    // into: not a host merely seen once, not code hosting, not what the owner skipped.
    let h = Home::new("offered", Some(SSH_CONFIG), Some(&known_hosts_file()));
    put(
        &h.dir.0.join("store").join("sweep"),
        "skip.txt",
        "# not this one\nretired-box\n",
    );
    let printed = h.servers();

    let sweep = h.dir.0.join("store").join("sweep");
    let script = std::fs::read_to_string(sweep.join("sweep.sh")).unwrap();
    let listed: Vec<&str> = script
        .split("servers='\n")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap()
        .lines()
        .collect();
    assert_eq!(listed, ["build", "web-1"]);
    for absent in [
        "lab-",
        "code-mirror",
        "github.com",
        "forge",
        "retired-box",
        "10.0.0.9",
        "db-9",
    ] {
        assert!(!script.contains(absent), "{absent} is in the sweep");
    }
    assert!(
        printed.contains(&format!("sh '{}'", sweep.join("sweep.sh").display())),
        "{printed}"
    );
    assert!(printed.contains("skip.txt"), "{printed}");
}

#[test]
fn an_explicit_checkouts_root_never_retracts_checkouts_found_by_the_home_walk() {
    // A walk of one folder says nothing about the rest of the home folder.
    let dir = Dir::new("given-root");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    checkout(&dir.0, "dev/shop");
    checkout(&dir.0, "other/app");
    soc_home(&store, &brew, &absent);
    let live_before = rows(&store, LIVE);

    let report = soc_all(&store, &brew, &absent, &dir.0.join("dev"));
    assert_eq!(rows(&store, LIVE), live_before);
    assert!(rows(&store, "SELECT 1 FROM assertion WHERE layer = 'retracted'").is_empty());
    assert_eq!(
        rows(
            &store,
            "SELECT completeness, reason FROM coverage
             WHERE reader = 'checkouts' ORDER BY id DESC LIMIT 1"
        ),
        ["partial|only the given folder was walked"]
    );
    assert!(report.contains("0 removed"), "{report}");
}

#[test]
fn a_standing_partial_reading_without_assertions_still_lets_the_report_say_no_changes() {
    // What is inside a container is never read in full and never asserted: nothing there
    // can disappear, so it must not keep the owner from hearing that nothing changed.
    let dir = Dir::new("standing");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let servers = dir.0.join("servers");
    let absent = dir.0.join("absent");
    put(&servers, "web-1.txt", WEB_1);
    soc_all(&store, &brew, &servers, &absent);
    let report = soc_all(&store, &brew, &servers, &absent);

    assert!(report.contains("Since last run: no changes."), "{report}");
    assert!(!report.contains("partial"), "{report}");
    let page = view(&store);
    let latest = section(&page, "changes")
        .split("<details")
        .nth(1)
        .unwrap()
        .split("</summary>")
        .next()
        .unwrap()
        .to_string();
    assert!(latest.ends_with("· no changes"), "{latest}");
    assert_eq!(
        rows(
            &store,
            "SELECT COUNT(*) FROM coverage WHERE kind = 'container contents'
             AND run_id = (SELECT MAX(run_id) FROM coverage)"
        ),
        ["2"]
    );
}

/// A Claude Code session as it lies on disk: one JSON object per line. Lines of a turn carry
/// the working folder in `cwd`; a summary line carries none. Every value is invented.
fn session(sessions: &Path, name: &str, cwds: &[&Path]) -> PathBuf {
    let mut text = String::from(
        "{\"type\":\"summary\",\"summary\":\"Invented summary\",\"leafUuid\":\"00000000-0000-4000-8000-00000000000a\"}\n",
    );
    for (i, cwd) in cwds.iter().enumerate() {
        text.push_str(&format!(
            "{{\"parentUuid\":null,\"isSidechain\":false,\"userType\":\"external\",\"cwd\":{},\
             \"sessionId\":\"00000000-0000-4000-8000-000000000001\",\"version\":\"2.0.0\",\
             \"gitBranch\":\"main\",\"type\":\"user\",\"message\":{{\"role\":\"user\",\
             \"content\":\"invented request {i}\"}},\"uuid\":\"00000000-0000-4000-8000-00000000000{i}\",\
             \"timestamp\":\"2026-11-01T10:00:0{i}.000Z\"}}\n",
            serde_json::Value::from(cwd.to_str().unwrap())
        ));
    }
    put(sessions, &format!("-invented-project/{name}.jsonl"), &text)
}

/// A home folder, a folder outside it and a folder of sessions, all invented.
struct Agents {
    dir: Dir,
    home: PathBuf,
    outside: PathBuf,
    sessions: PathBuf,
}

impl Agents {
    fn new(tag: &str) -> Agents {
        let dir = Dir::new(tag);
        let (home, outside, sessions) = (
            dir.0.join("home"),
            dir.0.join("outside"),
            dir.0.join("sessions"),
        );
        for d in [&home, &outside, &sessions] {
            std::fs::create_dir_all(d).unwrap();
        }
        Agents {
            dir,
            home,
            outside,
            sessions,
        }
    }

    fn store(&self) -> PathBuf {
        self.dir.store()
    }

    /// `soc run` with the home walk of `home` and the given sessions.
    fn run(&self) -> String {
        ok(&mut self.cmd())
    }

    fn cmd(&self) -> Command {
        let mut cmd = soc_run(&self.home, &self.store());
        cmd.arg("--brew-input")
            .arg(self.dir.input("brew.txt", SAMPLE))
            .arg("--servers-input")
            .arg(self.dir.0.join("absent"))
            .arg("--sessions-root")
            .arg(&self.sessions);
        cmd
    }

    /// The id of a checkout outside the home folder: its full path without symbolic links.
    fn outside_id(&self, rel: &str) -> String {
        let real = std::fs::canonicalize(self.outside.join(rel)).unwrap();
        format!("checkout:machine:mac/{}", real.display())
    }

    fn agent_coverage(&self) -> Vec<String> {
        rows(
            &self.store(),
            "SELECT completeness, reason FROM coverage
             WHERE reader = 'agent-folders' ORDER BY id DESC LIMIT 1",
        )
    }
}

#[test]
fn a_checkout_outside_the_home_folder_is_found_through_an_agent_session_and_its_lockfiles_are_read()
{
    // Agents work in temporary folders and worktrees that the home walk never sees.
    let a = Agents::new("agent-outside");
    let app = checkout(&a.outside, "app");
    put(&app, "Cargo.lock", CARGO_LOCK);
    std::fs::create_dir_all(app.join("src/bin")).unwrap();
    // A worktree has a `.git` file, not a folder.
    put(
        &a.outside,
        "tree/.git",
        "gitdir: /invented/repo/.git/worktrees/tree\n",
    );
    std::fs::create_dir_all(a.outside.join("scratch")).unwrap();
    checkout(&a.outside, "relative");
    let file = session(
        &a.sessions,
        "s1",
        &[
            &app.join("src/bin"),
            &a.outside.join("tree"),
            // Not in a checkout, no longer there, or not a full path: none is a checkout.
            &a.outside.join("scratch"),
            &a.outside.join("gone/app"),
            Path::new("../outside/relative"),
        ],
    );
    // Only session files are read.
    put(&a.sessions, "stray.txt", "{\"cwd\":\n");
    put(&a.sessions, "-invented-project/notes.txt", "{\"cwd\":\n");
    // A line cut off mid-text that names no working folder hides nothing.
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str("{\"type\":\"assistant\",\"message\":{\"content\":\"cut off\n");
    std::fs::write(&file, text).unwrap();

    // Found without the home walk, its lockfiles are still read.
    let report = ok(a.cmd().arg("--checkouts-root").arg(a.dir.0.join("absent")));

    let (app_id, tree_id) = (a.outside_id("app"), a.outside_id("tree"));
    assert_eq!(
        rows(
            &a.store(),
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND reader = 'agent-folders' ORDER BY subject"
        ),
        [
            format!("{app_id}|machine:mac"),
            format!("{tree_id}|machine:mac")
        ]
    );
    assert_eq!(
        rows(
            &a.store(),
            &format!(
                "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'part_of'
                 AND object = '{app_id}'"
            )
        ),
        [format!("component:{app_id}/crates.io/serde")]
    );
    assert_eq!(a.agent_coverage(), ["full|NULL"]);
    // The assertion rests on what the reader looked at, not on a session.
    let refs = rows(
        &a.store(),
        "SELECT source_ref FROM assertion WHERE reader = 'agent-folders' ORDER BY subject",
    );
    let (file, line) = refs[0].rsplit_once(':').unwrap();
    let raw = std::fs::read_to_string(a.dir.0.join(file)).unwrap();
    let real = std::fs::canonicalize(&app).unwrap();
    assert_eq!(
        raw.lines().nth(line.parse::<usize>().unwrap() - 1),
        Some(format!("checkout\t{}", real.display()).as_str())
    );
    assert!(report.contains("2 checkouts,"), "{report}");
}

#[test]
fn a_checkout_seen_by_both_readers_is_one_entity() {
    // Two readers that find the same checkout must not make the owner see it twice.
    let a = Agents::new("agent-both");
    let shop = checkout(&a.home, "dev/shop");
    put(&shop, "Cargo.lock", CARGO_LOCK);
    // A home folder kept under git is not a checkout for this reader either.
    put(&a.home, ".git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(a.home.join("notes")).unwrap();
    session(&a.sessions, "s1", &[&shop, &a.home.join("notes")]);

    let report = a.run();

    let id = "checkout:machine:mac/dev/shop";
    assert_eq!(
        rows(
            &a.store(),
            "SELECT DISTINCT subject FROM assertion WHERE layer = 'live' AND predicate = 'located_on'"
        ),
        [id]
    );
    assert_eq!(
        rows(
            &a.store(),
            &format!(
                "SELECT reader FROM assertion WHERE layer = 'live' AND subject = '{id}'
                 ORDER BY reader"
            )
        ),
        ["agent-folders", "checkouts"]
    );
    // Its lockfile is read once.
    assert_eq!(
        rows(
            &a.store(),
            "SELECT COUNT(*) FROM coverage WHERE reader = 'lockfiles'"
        ),
        ["1"]
    );
    assert!(report.contains("1 checkout,"), "{report}");
    let page = view(&a.store());
    assert_eq!(
        section(&page, "machines")
            .matches("<span class=\"mono\">dev/shop</span>")
            .count(),
        1
    );
}

#[test]
fn a_checkout_does_not_vanish_when_its_session_is_deleted() {
    // Sessions age out and the checkout stays. Dropping it would silently drop everything
    // read inside it.
    let a = Agents::new("agent-aged");
    let app = checkout(&a.outside, "app");
    put(&app, "Cargo.lock", CARGO_LOCK);
    let file = session(&a.sessions, "s1", &[&app]);
    a.run();
    let live_before = rows(&a.store(), LIVE);

    std::fs::remove_file(file).unwrap();
    let report = a.run();

    assert_eq!(rows(&a.store(), LIVE), live_before);
    assert!(rows(&a.store(), LAST_RUN_EVENTS).is_empty());
    assert_eq!(a.agent_coverage(), ["full|NULL"]);
    assert!(report.contains("Since last run: no changes."), "{report}");
}

#[test]
fn a_checkout_whose_folder_is_gone_is_removed_once() {
    // A checkout that is really gone must stop being asserted, with what was read inside it,
    // and must not be reported as removed again on later runs.
    let a = Agents::new("agent-gone");
    let app = checkout(&a.outside, "app");
    put(&app, "Cargo.lock", CARGO_LOCK);
    let kept = checkout(&a.outside, "kept");
    // The session still names the folder after it is deleted.
    session(&a.sessions, "s1", &[&app, &kept]);
    a.run();
    let id = a.outside_id("app");

    std::fs::remove_dir_all(&app).unwrap();
    let report = a.run();

    assert_eq!(
        rows(&a.store(), LAST_RUN_EVENTS),
        [format!("removed|{id}|located_on|machine:mac|NULL")]
    );
    assert!(
        !rows(&a.store(), LIVE).iter().any(|r| r.contains(&id)),
        "something inside the deleted checkout is still live"
    );
    assert!(report.contains("1 removed."), "{report}");

    let next = a.run();
    assert!(rows(&a.store(), LAST_RUN_EVENTS).is_empty());
    assert!(next.contains("Since last run: no changes."), "{next}");
}

#[test]
fn a_missing_session_folder_is_not_applicable_not_a_failure() {
    // Without Claude Code there is nothing to read; that must not look like a gap.
    let dir = Dir::new("agent-absent");
    let store = dir.store();
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    // The default place, inside a home folder that has no sessions.
    soc_home(&store, &brew, &absent);
    let report = soc_home(&store, &brew, &absent);

    assert_eq!(
        rows(
            &store,
            "SELECT completeness, reason FROM coverage
             WHERE reader = 'agent-folders' ORDER BY id DESC LIMIT 1"
        ),
        ["full|no Claude Code sessions on this machine"]
    );
    // Brew, the home walk and lockfiles; the absent sessions are not a reader that read.
    assert!(report.starts_with("3 readers,"), "{report}");
    assert!(report.contains("Since last run: no changes."), "{report}");
}

#[test]
fn a_session_that_cannot_be_read_makes_the_reading_partial_with_counts() {
    // A session that could not be read may name a checkout nobody else knows.
    let a = Agents::new("agent-partial");
    let app = checkout(&a.outside, "app");
    session(&a.sessions, "s1", &[&app]);
    let locked = session(&a.sessions, "s2", &[&a.outside]);
    put(
        &a.sessions,
        "-invented-project/s3.jsonl",
        "{\"cwd\":\"/invented\",\"type\":\n",
    );
    session(&a.sessions, "../-locked-project/s4", &[&app]);
    std::fs::create_dir_all(a.outside.join("box/inner")).unwrap();
    session(&a.sessions, "s5", &[&a.outside.join("box/inner")]);
    let _locked = [
        Locked::new(locked),
        Locked::new(a.sessions.join("-locked-project")),
        Locked::new(a.outside.join("box")),
    ];

    a.run();

    assert_eq!(
        a.agent_coverage(),
        ["partial|1 of 4 session files could not be read; \
          1 session folder could not be listed; \
          1 line with a working folder could not be parsed; \
          1 working folder could not be looked at"]
    );
    assert!(
        rows(&a.store(), LIVE)
            .iter()
            .any(|r| r.starts_with(&a.outside_id("app")))
    );
}

#[test]
fn a_checkout_that_cannot_be_looked_at_is_kept() {
    // A disk that is not plugged in is not a deleted checkout: what was read there stays.
    let a = Agents::new("agent-volume");
    // A folder that can no longer be looked into is not a deleted checkout either.
    let app = checkout(&a.outside, "box/app");
    session(&a.sessions, "s1", &[&app]);
    a.run();
    let app_id = a.outside_id("box/app");
    let _locked = Locked::new(a.outside.join("box"));
    let id = "checkout:machine:mac//Volumes/soc-invented-volume-not-mounted/app";
    let conn = Connection::open(a.store()).unwrap();
    conn.execute(
        "INSERT INTO entity (id, type) VALUES (?1, 'checkout')",
        [id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                source_ref, basis, observed_at, run_id)
         VALUES ('live', ?1, 'located_on', 'machine:mac', 'agent-folders', 'machine:mac',
                 'checkouts in agent working folders', 'raw/x:1', 'observed', 0, 'earlier')",
        [id],
    )
    .unwrap();
    drop(conn);

    a.run();

    let live = rows(&a.store(), LIVE);
    assert!(live.iter().any(|r| r.starts_with(id)));
    assert!(live.iter().any(|r| r.starts_with(&app_id)));
    assert_eq!(
        a.agent_coverage(),
        ["partial|1 working folder could not be looked at; \
          2 checkouts could not be checked and are kept"]
    );
}

#[test]
fn a_store_of_the_current_format_learns_a_new_coverage_kind_without_a_rebuild() {
    // The vocabulary is data: a new reader must not cost the owner their store and journal.
    let a = Agents::new("agent-vocabulary");
    a.run();
    let conn = Connection::open(a.store()).unwrap();
    conn.execute_batch(
        "DELETE FROM coverage WHERE kind = 'checkouts in agent working folders';
         DELETE FROM coverage_kind WHERE name = 'checkouts in agent working folders';",
    )
    .unwrap();
    drop(conn);

    a.run();

    assert_eq!(a.agent_coverage(), ["full|NULL"]);
}

#[test]
fn a_session_folder_that_cannot_be_listed_is_a_failed_reading_not_an_empty_one() {
    // A source that is here and unreadable must not look like a source with nothing in it.
    let a = Agents::new("agent-failed");
    let app = checkout(&a.outside, "app");
    session(&a.sessions, "s1", &[&app]);
    a.run();
    let live_before = rows(&a.store(), LIVE);
    let _locked = Locked::new(a.sessions.clone());

    let report = a.run();

    let coverage = a.agent_coverage();
    assert!(
        coverage[0].starts_with("none|") && coverage[0].contains("Permission denied"),
        "{coverage:?}"
    );
    assert_eq!(rows(&a.store(), LIVE), live_before);
    assert!(
        report.contains("Agent sessions could not be read"),
        "{report}"
    );
}
