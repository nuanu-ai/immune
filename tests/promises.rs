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

/// `soc run` for the machine `mac`, with no tailscale, so that the real one is never asked,
/// and a threat catalogue that is not there, so that the network is never asked. A later
/// `--tailscale` or `--threats-input` replaces them.
fn soc_run(home: &Path, store: &Path) -> Command {
    let mut cmd = soc_cmd(home);
    cmd.args(["run", "--machine-name", "mac", "--store"])
        .arg(store)
        .arg("--tailscale")
        .arg(home.join("no-tailscale"))
        .arg("--threats-input")
        .arg(home.join("no-catalogue"));
    cmd
}

/// The same, fetching the threat catalogue with this curl instead.
fn soc_run_curl(home: &Path, store: &Path, curl: &Path) -> Command {
    let mut cmd = soc_cmd(home);
    cmd.args(["run", "--machine-name", "mac", "--store"])
        .arg(store)
        .arg("--tailscale")
        .arg(home.join("no-tailscale"))
        .arg("--curl")
        .arg(curl);
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

/// A server file as the sweep writes it: a web server with two running containers, whose
/// kernel no package owns, as with a kernel the hosting provider boots.
const WEB_1: &str = "\
##os
Ubuntu 24.04.1 LTS
##os_release
ID\tubuntu
VERSION_ID\t24.04
VERSION_CODENAME\tnoble
##kernel
6.8.0-45-generic
##kernel_package
##package_managers
dpkg
##reboot_required
no
##pve
##dpkg_with_source
ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4
ii \topenssl\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4
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
            "machine:db-1|running kernel package|none|the sweep of this server did not complete",
            "machine:db-1|sweep visit|none|the sweep of this server did not complete",
            "machine:db-1|system package sources|none|the sweep of this server did not complete",
            "machine:db-1|system packages|none|the sweep of this server did not complete",
            "machine:db-1|system release|none|the sweep of this server did not complete",
            "machine:web-1|containers|none|the sweep of this server did not complete",
            "machine:web-1|running kernel package|none|the sweep of this server did not complete",
            "machine:web-1|sweep visit|none|the sweep of this server did not complete",
            "machine:web-1|system package sources|none|the sweep of this server did not complete",
            "machine:web-1|system packages|none|the sweep of this server did not complete",
            "machine:web-1|system release|none|the sweep of this server did not complete",
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
            .arg(dir.0.join("no-tailscale"))
            .arg("--threats-input")
            .arg(dir.0.join("no-catalogue")))
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
/// code hosting under an alias and by `User git`, an alias the owner skips, and an include,
/// at the top where ssh reads it for every host.
const SSH_CONFIG: &str = "\
# Invented for tests.
Include config.d/*
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
@revoked * ssh-rsa {KEY}Revoked
*.lab.example.org,!gw.lab.example.org ssh-ed25519 {KEY}Lab
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
        self.servers_with(&self.dir.0.join("no-tailscale"))
    }

    /// `soc servers` with the given tailscale.
    fn servers_with(&self, tailscale: &Path) -> String {
        ok(soc_cmd(&self.home)
            .args(["servers", "--store"])
            .arg(self.store())
            .arg("--tailscale")
            .arg(tailscale))
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
fn known_hosts_that_hide_hosts_make_the_reading_partial_with_their_count_and_no_key_is_stored() {
    // A hashed entry hides a host we may have, a pattern covers hosts it does not name, and
    // ssh writes no key for a host a certificate authority vouches for: the reading must
    // not look complete. A negated pattern and a revoked key name no host. Keys are not
    // ours to copy: neither a key nor its type is kept, in the store or next to it.
    let h = Home::new("hashed", None, Some(&known_hosts_file()));
    h.run(&h.dir.0.join("absent"), &h.dir.0.join("no-tailscale"));

    assert_eq!(
        rows(
            &h.store(),
            "SELECT completeness, reason FROM coverage WHERE kind = 'known hosts'"
        ),
        [
            "partial|2 hashed entries cannot be read; 1 pattern covers hosts it does not name; \
          1 certificate authority vouches for hosts whose keys are not written here"
        ]
    );
    assert_eq!(
        rows(
            &h.store(),
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND kind = 'known hosts' ORDER BY subject"
        ),
        [
            "machine:10.0.0.5|10.0.0.5",
            "machine:[10.0.0.9]:2222|[10.0.0.9]:2222",
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
    assert_eq!(listed(&script), ["build", "web-1"]);
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

/// The machines the sweep script lists, one line each: its aliases, comma separated.
fn listed(script: &str) -> Vec<&str> {
    script
        .split("machines='\n")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap()
        .lines()
        .collect()
}

/// Runs the sweep script as the owner does, with a fake ssh that notes the alias it was
/// asked for and answers like a complete probe. PATH holds only that fake and the tools the
/// script needs, so no real ssh can be reached. Returns the aliases visited, sorted: the
/// sweep visits several at a time.
fn sweep_with_fake_ssh(sweep: &Path, bin: &Path) -> Vec<String> {
    visits(sweep, bin, &[]).0
}

/// The same, with arguments; also returns what the script printed.
fn visits(sweep: &Path, bin: &Path, args: &[&str]) -> (Vec<String>, String) {
    let log = bin.join("visited.log");
    let _ = std::fs::remove_file(&log);
    fake_ssh(
        bin,
        &format!("printf '%s\\n' \"$5\" >> '{}'\necho '##end'", log.display()),
    );
    let printed = run_sweep(sweep, bin, args);
    let mut visited: Vec<String> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    visited.sort();
    (visited, printed)
}

/// Puts an ssh with this body in the folder, next to the tools the sweep script needs.
fn fake_ssh(bin: &Path, body: &str) {
    std::fs::create_dir_all(bin).unwrap();
    for tool in [
        "sed", "grep", "tr", "dirname", "mkdir", "mv", "rm", "date", "cat",
    ] {
        let link = bin.join(tool);
        if !link.exists() {
            let real = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| Path::new(d).join(tool))
                .find(|p| p.exists())
                .unwrap();
            std::os::unix::fs::symlink(real, &link).unwrap();
        }
    }
    script(&bin.join("ssh"), body);
}

/// Runs the sweep script with only the folder on PATH, and returns what it printed.
fn run_sweep(sweep: &Path, bin: &Path, args: &[&str]) -> String {
    let out = Command::new("/bin/sh")
        .arg(sweep.join("sweep.sh"))
        .args(args)
        .env_clear()
        .env("PATH", bin)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

/// One server under two aliases. The alias written first sorts last, so the order of the
/// configuration and the order of names cannot be confused.
const SSH_CONFIG_TWO_ALIASES: &str = "\
Host web-new
    HostName 10.0.0.5
Host web-1
    HostName 10.0.0.5
Host db-1
    HostName 10.0.0.6
";

#[test]
fn a_machine_known_under_two_aliases_is_visited_once_through_its_first_alias() {
    // A machine visited under each of its aliases is read twice and stored twice with all
    // it holds. The sweep goes in once, by the alias written first in the ssh configuration.
    let h = Home::new("once", Some(SSH_CONFIG_TWO_ALIASES), None);
    let printed = h.servers();

    let sweep = h.dir.0.join("store").join("sweep");
    let script = std::fs::read_to_string(sweep.join("sweep.sh")).unwrap();
    assert_eq!(listed(&script), ["db-1", "web-new,web-1"]);
    assert!(
        printed.contains("visits web-new; same machine, not visited: web-1"),
        "{printed}"
    );
    assert!(
        printed.contains("1 alias of the same machine is not visited."),
        "{printed}"
    );
    assert_eq!(
        sweep_with_fake_ssh(&sweep, &h.dir.0.join("bin")),
        ["db-1", "web-new"]
    );
}

#[test]
fn an_alias_in_skip_txt_is_never_visited_even_when_added_after_the_script_was_written() {
    // The owner keeps a server out of the sweep by listing it, and may do so after
    // `soc servers` wrote the script. A listed alias is never visited; its machine is visited
    // through its next alias, or not at all.
    let h = Home::new("skip", Some(SSH_CONFIG_TWO_ALIASES), None);
    let sweep = h.dir.0.join("store").join("sweep");
    let bin = h.dir.0.join("bin");
    put(&sweep, "skip.txt", "db-1\n");
    let printed = h.servers();
    let script = std::fs::read_to_string(sweep.join("sweep.sh")).unwrap();
    assert_eq!(listed(&script), ["web-new,web-1"]);
    assert!(!script.contains("db-1"), "{script}");
    assert!(
        printed.contains("not offered: listed in skip.txt"),
        "{printed}"
    );

    // Added later, with the spaces and line ending an editor may leave around it.
    put(&sweep, "skip.txt", "db-1\n  web-new \r\n");
    assert_eq!(sweep_with_fake_ssh(&sweep, &bin), ["web-1"]);
    put(&sweep, "skip.txt", "db-1\nweb-new\nweb-1\n");
    assert!(sweep_with_fake_ssh(&sweep, &bin).is_empty());
    // A list that cannot be read could name any alias.
    put(&sweep, "skip.txt", "db-1\n");
    let _locked = Locked::new(sweep.join("skip.txt"));
    assert!(sweep_with_fake_ssh(&sweep, &bin).is_empty());
}

/// An ssh configuration with what ssh does not read as aliases: comments, quote marks, the
/// `keyword=value` form, patterns and a negation, an include that matches a dotfile, and a
/// code hosting alias on two lines, counted once.
const SSH_CONFIG_WORDS: &str = "\
# Invented for tests.
Host web # production box
    HostName 192.0.2.10
Host \"db-1\" 'db-2' # replica set
    HostName 192.0.2.11
Host=cache-1
Host gh # mirror
    HostName github.com
Host gh
    User git
Host web-? lab-*
    User admin
Host * !lab-gw
    IdentityFile ~/.ssh/id_invented
Include conf.d/*
Include absent.d/* conf.d/build/*
";

#[test]
fn only_a_literal_alias_of_a_host_line_as_openssh_reads_it_is_ever_visited() {
    // The sweep is access to servers. A word ssh does not read as an alias must never
    // become a server the sweep connects to: ssh would look it up as a host name. Nor may a
    // file ssh does not include, and glob characters in the home folder's name must not
    // change what an Include matches.
    let h = Home::new("words-[a]", Some(SSH_CONFIG_WORDS), None);
    put(
        &h.home,
        ".ssh/conf.d/build",
        "Host build # ci\n    HostName 192.0.2.12\n",
    );
    put(
        &h.home,
        ".ssh/conf.d/.old",
        "Host old-box\n    HostName 192.0.2.13\n",
    );
    // ssh reads a folder as an empty file and skips a file that is not there.
    put(&h.home, ".ssh/conf.d/sub/old", "Host sub-box\n");
    std::os::unix::fs::symlink(h.home.join("gone"), h.home.join(".ssh/conf.d/gone")).unwrap();
    let printed = h.servers();

    let sweep = h.dir.0.join("store").join("sweep");
    let script = std::fs::read_to_string(sweep.join("sweep.sh")).unwrap();
    assert_eq!(listed(&script), ["build", "cache-1", "db-1,db-2", "web"]);
    assert_eq!(
        sweep_with_fake_ssh(&sweep, &h.dir.0.join("bin")),
        ["build", "cache-1", "db-1", "web"]
    );
    assert!(
        printed.contains("Ssh configuration: 5 servers, 1 left out as code hosting.\n"),
        "{printed}"
    );
}

/// What ssh resolves differently from a reader that takes only blocks naming an alias:
/// includes through glob(3) from `~/.ssh`, the home folder and an absolute path, pattern
/// blocks first, a negation, an include inside a block that does not apply, files and a
/// folder that cannot be read, and `Match` blocks that cannot be evaluated without running
/// ssh. `{ABS}` is replaced with an absolute folder.
const SSH_CONFIG_RESOLVED: &str = "\
Include hosts/*/config conf[0-9] ~/.ssh/home.d/* locked.d/* {ABS}/*
Include %d/extra ${EXTRA}/config ~nobody/config
Host pat*
    HostName %h.example.org
Host patterned
    HostName 192.0.2.21
Host db-1 db-* !db-3
    HostName 192.0.2.50
Host db-3
    HostName 192.0.2.51
Host bastion
    Include bastion.d/*
    HostName 192.0.2.70
Host * !late
    IdentityFile ~/.ssh/id_invented
    User deploy
Host never-*
    Include never.d/*
Match exec \"test -e /nonexistent\"
    HostName 192.0.2.60
    User admin
Host late
    HostName 192.0.2.61
Match localuser nobody
    Include match.d/*
";

#[test]
fn an_alias_is_known_by_the_host_name_ssh_would_use_and_what_is_not_resolved_makes_the_reading_partial()
 {
    // A HostName links an alias to the machine other traces know: one ssh would not use
    // joins the wrong machines, and the sweep then visits one of them for both. What the
    // reader cannot resolve without running ssh, it must say, not guess.
    let h = Home::new("resolved", None, None);
    let elsewhere = h.dir.0.join("elsewhere");
    put(
        &h.home,
        ".ssh/config",
        &SSH_CONFIG_RESOLVED.replace("{ABS}", &elsewhere.display().to_string()),
    );
    put(&elsewhere, "abs", "Host abs-box\n    HostName 192.0.2.91\n");
    put(
        &h.home,
        ".ssh/home.d/box",
        "Host home-box\n    HostName 192.0.2.90\n",
    );
    let _file = Locked::new(put(&h.home, ".ssh/conf2", "Host hidden-1\n"));
    put(&h.home, ".ssh/locked.d/box", "Host hidden-2\n");
    let _folder = Locked::new(h.home.join(".ssh/locked.d"));
    put(
        &h.home,
        ".ssh/hosts/a/config",
        "Host web-1\n    HostName 192.0.2.40\n",
    );
    put(&h.home, ".ssh/conf1", "Host db-1\n");
    put(
        &h.home,
        ".ssh/bastion.d/inner",
        "Host inner\n    HostName 192.0.2.71\n",
    );
    put(
        &h.home,
        ".ssh/match.d/box",
        "Host maybe-box\n    HostName 192.0.2.80\nHost maybe-box\n",
    );
    put(
        &h.home,
        ".ssh/never.d/all",
        "Match all\n    HostName 192.0.2.99\n",
    );
    h.run(&h.dir.0.join("absent"), &h.dir.0.join("no-tailscale"));

    assert_eq!(
        rows(
            &h.store(),
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND reader = 'ssh-config' ORDER BY subject, object"
        ),
        [
            "machine:abs-box|192.0.2.91",
            "machine:abs-box|abs-box",
            "machine:bastion|192.0.2.70",
            "machine:bastion|bastion",
            "machine:db-1|192.0.2.50",
            "machine:db-1|db-1",
            "machine:db-3|192.0.2.51",
            "machine:db-3|db-3",
            "machine:home-box|192.0.2.90",
            "machine:home-box|home-box",
            "machine:late|late",
            "machine:patterned|patterned",
            "machine:patterned|patterned.example.org",
            "machine:web-1|192.0.2.40",
            "machine:web-1|web-1",
        ]
    );
    assert_eq!(
        rows(
            &h.store(),
            "SELECT completeness, reason FROM coverage WHERE kind = 'ssh configuration'"
        ),
        [
            "partial|could not read conf2, locked.d; config:2 Include %d/extra was not read: \
             % tokens and ${} variables are not expanded; config:2 Include ${EXTRA}/config was \
             not read: % tokens and ${} variables are not expanded; config:2 Include \
             ~nobody/config was not read: only ~/ is expanded; the Match at config:19 was not \
             applied; it may decide the HostName or User of late; the Match at config:24 was \
             not applied; it may decide the HostName or User of maybe-box"
        ]
    );
    // An alias rests on the first Host line ssh applies for it, here in an included file.
    let source = rows(
        &h.store(),
        "SELECT source_ref FROM assertion WHERE subject = 'machine:db-1' AND object = 'db-1'",
    );
    let (file, line) = source[0].rsplit_once(':').unwrap();
    let extract = std::fs::read_to_string(h.dir.0.join("store").join(file)).unwrap();
    assert_eq!(
        extract.lines().nth(line.parse::<usize>().unwrap() - 1),
        Some("conf1:1\tHost db-1")
    );
}

#[test]
fn a_configuration_ssh_refuses_is_never_read_as_full() {
    // ssh reads includes 16 deep and refuses a configuration that goes deeper, or that has
    // an unclosed quote. A reading that says full there claims ways in that ssh refuses.
    let h = Home::new("refused", Some("Include c1\nHost web\n"), None);
    for n in 1..=16 {
        put(
            &h.home,
            &format!(".ssh/c{n}"),
            &format!("Include c{}\nHost web-{n}\n", n + 1),
        );
    }
    let printed = h.servers();
    assert!(
        printed.contains("Ssh configuration: 17 servers.\n"),
        "{printed}"
    );

    put(&h.home, ".ssh/c17", "Host web-17\n");
    let printed = h.servers();
    assert!(
        printed.contains(
            "Ssh configuration: 17 servers, c16:1 includes c17 too deep, so ssh refuses the \
             configuration.\n"
        ),
        "{printed}"
    );

    std::fs::remove_file(h.home.join(".ssh/c17")).unwrap();
    put(
        &h.home,
        ".ssh/c3",
        "Include c4\nHost \"web-3\nHost web-3b\n",
    );
    let printed = h.servers();
    assert!(
        printed.contains(
            "Ssh configuration: 17 servers, c3:2 has an unclosed quote, so ssh refuses the \
             configuration.\n"
        ),
        "{printed}"
    );
}

#[test]
fn two_ports_on_one_address_are_two_servers_and_neither_is_the_one_on_port_22() {
    // Machines behind one address with forwarded ports are different machines, and ssh
    // keys them by host and port. Folded into one, all but one go unread while the reading
    // looks complete.
    let h = Home::new(
        "ports",
        Some("Host gw\n    HostName nat.example.net\n"),
        Some(&format!(
            "nat.example.net ssh-ed25519 {KEY}Gw\n\
             [nat.example.net]:2201 ssh-ed25519 {KEY}One\n\
             [nat.example.net]:2202 ssh-ed25519 {KEY}Two\n"
        )),
    );
    let report = h.run(&h.dir.0.join("absent"), &h.dir.0.join("no-tailscale"));

    assert_eq!(
        rows(
            &h.store(),
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND predicate = 'same_as' ORDER BY subject"
        ),
        ["machine:gw|machine:nat.example.net"]
    );
    assert!(
        report.contains("3 servers known, 1 offered for the sweep, 0 read."),
        "{report}"
    );
}

/// A server file whose probe also printed the server's own names and addresses, as
/// `ip -o addr show` gives them: loopback, link-local, and a bridge of every kind the
/// reader knows, next to the server's one real address.
fn with_identity(name: &str, address: &str) -> String {
    format!(
        "\
##names
{name}
{name}.example.org
##addresses
lo\t127.0.0.1/8
lo\t::1/128
eth0\t{address}/24
eth0\tfe80::5054:ff:fe12:3456/64
eth1\t169.254.10.20/16
docker0\t172.17.0.1/16
br-0a1b2c3d4e5f\t172.18.0.1/16
virbr0\t192.168.122.1/24
lxcbr0\t10.0.3.1/24
lxdbr0\t10.10.10.1/24
podman0\t10.88.0.1/16
cni0\t10.244.0.1/24
flannel.1\t10.244.0.0/32
cali0a1b2c3d4e5\t10.250.0.1/32
cilium_host\t10.0.0.120/32
kube-ipvs0\t10.96.0.1/32
{WEB_1}"
    )
}

const SAME_AS: &str = "SELECT subject, object FROM assertion
                       WHERE layer = 'live' AND predicate = 'same_as' ORDER BY subject";

#[test]
fn a_sweep_file_under_another_name_is_a_reading_of_the_machine_the_traces_know_by_its_tailnet_address()
 {
    // A file named after an old name of a server must not leave the server "never read"
    // and counted twice. The server says what it is, and the resolver links it. A tailnet
    // address is unique inside the tailnet, so it names the one machine.
    let h = Home::new(
        "identity",
        Some("Host web-1\n    HostName 100.64.0.5\n"),
        None,
    );
    let servers = h.dir.0.join("servers");
    put(
        &servers,
        "old-name.txt",
        &with_identity("web-host", "100.64.0.5"),
    );
    let report = h.run(&servers, &h.dir.0.join("no-tailscale"));

    assert_eq!(
        rows(&h.store(), SAME_AS),
        ["machine:old-name|machine:web-1"]
    );
    assert_eq!(
        rows(
            &h.store(),
            "SELECT object, basis FROM assertion WHERE layer = 'live'
             AND subject = 'machine:old-name' AND kind = 'own names and addresses'
             AND predicate = 'known_as' ORDER BY object"
        ),
        [
            "100.64.0.5|observed",
            "web-host|observed",
            "web-host.example.org|observed"
        ]
    );
    assert!(
        report.contains("1 server known, 1 offered for the sweep, 1 read."),
        "{report}"
    );
    // Tailscale that is not here has nothing to read and is no failure.
    assert_eq!(
        rows(
            &h.store(),
            "SELECT completeness, reason FROM coverage WHERE kind = 'tailnet peers'"
        ),
        ["full|Tailscale is not installed on this machine"]
    );
    assert!(!report.contains("ailscale"), "{report}");
}

#[test]
fn two_servers_that_share_only_loopback_link_local_bridge_addresses_or_a_default_name_stay_two() {
    // Unrelated servers share 127.0.0.1, link-local addresses, the docker bridge and often
    // a default host name. A link through them would silently fold one server into another.
    let dir = Dir::new("not-same");
    let servers = dir.0.join("servers");
    put(&servers, "a.txt", &with_identity("ubuntu", "203.0.113.10"));
    put(&servers, "b.txt", &with_identity("ubuntu", "203.0.113.20"));
    let report = soc_all(
        &dir.store(),
        &dir.input("brew.txt", SAMPLE),
        &servers,
        &dir.0.join("absent"),
    );

    assert!(rows(&dir.store(), SAME_AS).is_empty());
    assert_eq!(
        rows(
            &dir.store(),
            "SELECT object FROM assertion WHERE layer = 'live'
             AND subject = 'machine:a' AND predicate = 'known_as' ORDER BY object"
        ),
        ["203.0.113.10", "ubuntu", "ubuntu.example.org"]
    );
    assert!(report.contains("2 servers known"), "{report}");
}

#[test]
fn one_server_swept_under_two_names_is_one_machine() {
    // Two files that give exactly the same names and addresses are one server read twice.
    let dir = Dir::new("same-server");
    let servers = dir.0.join("servers");
    put(
        &servers,
        "a.txt",
        &with_identity("web-host", "203.0.113.10"),
    );
    put(
        &servers,
        "b.txt",
        &with_identity("web-host", "203.0.113.10"),
    );
    let report = soc_all(
        &dir.store(),
        &dir.input("brew.txt", SAMPLE),
        &servers,
        &dir.0.join("absent"),
    );

    assert_eq!(rows(&dir.store(), SAME_AS), ["machine:a|machine:b"]);
    assert!(report.contains("1 server known"), "{report}");
}

#[test]
fn a_server_whose_addresses_could_not_be_listed_keeps_the_addresses_read_before() {
    // A probe that found no tool to list addresses saw none, which is not a server without
    // addresses: the links they make must not go, and the reading must not look complete.
    let dir = Dir::new("no-addresses");
    let servers = dir.0.join("servers");
    let brew = dir.input("brew.txt", SAMPLE);
    let absent = dir.0.join("absent");
    put(
        &servers,
        "a.txt",
        &with_identity("web-host", "203.0.113.10"),
    );
    soc_all(&dir.store(), &brew, &servers, &absent);
    // No domain: `uname -n` and `hostname -f` print the same name, here with stray blanks.
    put(
        &servers,
        "a.txt",
        &format!("##names\nweb-host\n web-host \n\n##addresses\n{WEB_1}"),
    );
    soc_all(&dir.store(), &brew, &servers, &absent);

    assert_eq!(
        rows(
            &dir.store(),
            "SELECT object FROM assertion WHERE layer = 'live'
             AND subject = 'machine:a' AND predicate = 'known_as' ORDER BY object"
        ),
        ["203.0.113.10", "web-host", "web-host.example.org"]
    );
    assert_eq!(
        rows(
            &dir.store(),
            "SELECT completeness, reason FROM coverage WHERE kind = 'own names and addresses'
             ORDER BY id DESC LIMIT 1"
        ),
        ["partial|the server's addresses could not be listed"]
    );
}

/// A server file from the probe before it read the release, the sources of packages, the
/// package that owns the kernel and the package managers: dpkg's list had names and versions
/// only, removed packages included.
const WEB_1_OLDER_PROBE: &str = "\
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
docker not installed
##end
";

#[test]
fn a_file_from_an_older_probe_is_still_read_links_to_nothing_and_claims_nothing_it_did_not_read() {
    // Files the owner already has were written before the probe said who the server is,
    // what release it runs, what each package was built from and which package owns the
    // kernel. They are read as before; what they do not hold is a reading that read
    // nothing, so a matcher can tell it from a reading that found nothing. The release is
    // never guessed from the pretty name.
    let dir = Dir::new("older-probe");
    let servers = dir.0.join("servers");
    put(&servers, "a.txt", WEB_1_OLDER_PROBE);
    put(&servers, "b.txt", WEB_1_OLDER_PROBE);
    soc_all(
        &dir.store(),
        &dir.input("brew.txt", SAMPLE),
        &servers,
        &dir.0.join("absent"),
    );

    let older = "the file came from an older probe, which did not read this";
    assert_eq!(
        rows(
            &dir.store(),
            "SELECT scope, kind, completeness, COALESCE(reason, '') FROM coverage
             WHERE reader = 'servers' AND scope = 'machine:a' ORDER BY kind"
        ),
        [
            "machine:a|containers|full|".to_string(),
            format!("machine:a|running kernel package|none|{older}"),
            "machine:a|sweep visit|full|".to_string(),
            format!("machine:a|system package sources|none|{older}"),
            "machine:a|system packages|full|".to_string(),
            format!("machine:a|system release|none|{older}"),
        ]
    );
    assert_eq!(
        rows(
            &dir.store(),
            "SELECT subject, predicate, object FROM assertion
             WHERE layer = 'live' AND subject LIKE '%machine:a%' ORDER BY subject, predicate"
        ),
        [
            "component:machine:a/deb/bash|has_version|5.2.21-2ubuntu4",
            "component:machine:a/deb/bash|part_of|machine:a",
            "component:machine:a/deb/openssl|has_version|3.0.13-0ubuntu3.4",
            "component:machine:a/deb/openssl|part_of|machine:a",
            "component:machine:a/snap/core22|has_version|20240823",
            "component:machine:a/snap/core22|part_of|machine:a",
            "machine:a|runs_kernel|6.8.0-45-generic",
            "machine:a|runs_os|Ubuntu 24.04.1 LTS",
        ]
    );
    assert!(rows(&dir.store(), SAME_AS).is_empty());
}

#[test]
fn soc_servers_and_soc_run_count_the_same_servers() {
    // Two commands that disagree on how many servers the owner has leave the owner unable
    // to trust either. A server known only from its sweep file is listed as such.
    let h = Home::new("counts", Some(SSH_CONFIG), Some(&known_hosts_file()));
    let sweep = h.dir.0.join("store").join("sweep");
    put(&sweep, "web-1.txt", &with_identity("web-host", "10.0.0.5"));
    put(
        &sweep,
        "web-old.txt",
        &with_identity("web-host", "10.0.0.5"),
    );
    put(&sweep, "old-db.txt", WEB_1);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET);

    let printed = ok(soc_cmd(&h.home)
        .args(["servers", "--store"])
        .arg(h.store())
        .arg("--tailscale")
        .arg(&tailscale));
    let report = h.run(&sweep, &tailscale);

    assert!(printed.contains("\n7 servers known,"), "{printed}");
    assert!(report.contains(" 7 servers known,"), "{report}");
    let old = printed
        .lines()
        .find(|l| l.starts_with("  old-db "))
        .expect("old-db is not listed");
    assert!(old.contains("sweep file"), "{old}");
    let web = printed
        .lines()
        .find(|l| l.starts_with("  web-1 "))
        .expect("web-1 is not listed");
    assert!(
        web.contains("web-old") && web.contains("read, taken"),
        "{web}"
    );
}

/// `tailscale status --json` of a tailnet shared with other people, cut to the fields that
/// matter. This machine is user 1. Peers: the owner's server; a tagged server another user
/// added; a peer whose user the status does not give; and four devices of another user,
/// of which a test may let the owner know three from other traces.
const TAILNET_SHARED: &str = r#"{
  "BackendState": "Running",
  "Self": { "HostName": "mac", "DNSName": "mac.example-tail.ts.net.",
            "TailscaleIPs": ["100.64.0.1"], "OS": "macOS", "UserID": 1 },
  "Peer": {
    "nodekey:invented1": { "HostName": "build-box", "DNSName": "build-box.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.7"], "OS": "linux", "UserID": 1 },
    "nodekey:invented2": { "HostName": "ci-runner", "DNSName": "ci-runner.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.9"], "OS": "linux", "UserID": 2, "Tags": ["tag:ci"] },
    "nodekey:invented3": { "HostName": "friends-laptop",
      "DNSName": "friends-laptop.example-tail.ts.net.", "TailscaleIPs": ["100.64.0.20"],
      "OS": "macOS", "UserID": 3 },
    "nodekey:invented4": { "HostName": "shared-box", "DNSName": "shared-box.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.21"], "OS": "linux", "UserID": 3 },
    "nodekey:invented5": { "HostName": "no-owner", "DNSName": "no-owner.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.22"], "OS": "linux" },
    "nodekey:invented6": { "HostName": "lab-box", "DNSName": "lab-box.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.23"], "OS": "linux", "UserID": 3 },
    "nodekey:invented7": { "HostName": "old-laptop", "DNSName": "old-laptop.example-tail.ts.net.",
      "TailscaleIPs": ["100.64.0.24"], "OS": "linux", "UserID": 3 }
  }
}"#;

/// The owner reaches the other user's box by ssh, through its tailnet address.
const SSH_CONFIG_SHARED: &str = "\
Host shared
    HostName 100.64.0.21
";

const RELATION: &str = "SELECT subject, object, basis, reader FROM assertion
                        WHERE layer = 'live' AND predicate = 'relation_to_owner'
                        ORDER BY subject";

#[test]
fn another_users_device_known_only_from_the_tailnet_is_not_a_server_and_never_offered() {
    // A tailnet holds other people's laptops and phones. Counted as servers they inflate
    // "servers known" and "never read" with things the owner cannot and must not sweep. They
    // are still shown, with a count, so that nothing disappears silently.
    let h = Home::new("other-user", Some(SSH_CONFIG_SHARED), None);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET_SHARED);
    let printed = h.servers_with(&tailscale);
    let report = h.run(&h.dir.0.join("absent"), &tailscale);

    assert_eq!(
        rows(&h.store(), RELATION),
        [
            "machine:friends-laptop|other user's device|observed|tailnet",
            "machine:lab-box|other user's device|observed|tailnet",
            "machine:old-laptop|other user's device|observed|tailnet",
            "machine:shared-box|other user's device|observed|tailnet",
        ]
    );
    // The raw input says it too, so that the store can be rebuilt from it.
    let source = rows(
        &h.store(),
        "SELECT source_ref FROM assertion WHERE predicate = 'relation_to_owner'
         AND subject = 'machine:friends-laptop'",
    );
    let (file, line) = source[0].rsplit_once(':').unwrap();
    let raw = std::fs::read_to_string(h.dir.0.join("store").join(file)).unwrap();
    let line = raw.lines().nth(line.parse::<usize>().unwrap() - 1).unwrap();
    assert!(
        line.starts_with("friends-laptop\t") && line.ends_with("\tother user's device"),
        "{line}"
    );

    let lines: Vec<&str> = printed.lines().collect();
    let theirs = lines
        .iter()
        .position(|l| {
            *l == "Other users' devices on the tailnet, not counted as servers: 3 devices"
        })
        .unwrap_or_else(|| panic!("no section of other users' devices: {printed}"));
    assert_eq!(
        lines[theirs + 2],
        "  friends-laptop  100.64.0.20, friends-laptop.example-tail.ts.net.",
        "{printed}"
    );
    assert_eq!(
        printed.matches("friends-laptop  ").count(),
        1,
        "listed as a server too: {printed}"
    );
    assert!(
        printed.contains("Tailnet peers: 7 peers, 4 of them other users' devices."),
        "{printed}"
    );
    assert!(
        printed.contains(
            "\n4 servers known, 1 of them under several names, 1 offered for the sweep, \
             0 left out as code hosting, 3 as other users' devices, 4 known and never read."
        ),
        "{printed}"
    );
    let script = std::fs::read_to_string(h.dir.0.join("store/sweep/sweep.sh")).unwrap();
    assert_eq!(listed(&script), ["shared"]);
    assert!(
        report.contains(" 4 servers known, 1 offered for the sweep, 0 read."),
        "{report}"
    );

    let machines = view(&h.store());
    let machines = section(&machines, "machines");
    let blocks: Vec<&str> = machines.split("<details class=\"machine\">").collect();
    let never = blocks
        .iter()
        .find(|b| b.contains("Known and never read"))
        .expect("no list of machines never read");
    assert!(!never.contains("friends-laptop"), "{never}");
    assert!(
        blocks[0].contains("4 known and never read; 3 are other users' devices on the tailnet."),
        "{}",
        blocks[0]
    );
    let devices = blocks
        .iter()
        .find(|b| b.contains("Other users' devices</strong>"))
        .expect("no list of other users' devices");
    assert!(
        devices.contains("3 devices ·") && devices.contains(">friends-laptop<"),
        "{devices}"
    );
}

#[test]
fn another_users_device_also_known_from_the_ssh_configuration_known_hosts_or_a_sweep_file_stays_a_server()
 {
    // The owner keeps a way into it or has swept it: whoever's it is, the owner uses it as a
    // server, and it must stay counted, and offered for the sweep when it has an alias.
    let h = Home::new(
        "other-user-traces",
        Some(SSH_CONFIG_SHARED),
        Some(&format!("lab-box ssh-ed25519 {KEY}\n")),
    );
    let sweep = h.dir.0.join("store").join("sweep");
    put(&sweep, "old-laptop.txt", &cut(WEB_1));
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET_SHARED);
    let printed = h.servers_with(&tailscale);
    let report = h.run(&sweep, &tailscale);

    let shared = printed
        .lines()
        .find(|l| l.starts_with("  shared "))
        .unwrap_or_else(|| panic!("shared is not listed as a server: {printed}"));
    assert!(
        shared.contains("visits shared") && shared.contains("shared-box"),
        "{shared}"
    );
    for server in ["  lab-box ", "  old-laptop "] {
        assert!(
            printed.lines().any(|l| l.starts_with(server)),
            "{server} is not listed as a server: {printed}"
        );
    }
    assert!(
        printed.contains("\n6 servers known,") && printed.contains(" 1 as other users' devices,"),
        "{printed}"
    );
    assert_eq!(
        rows(&h.store(), SAME_AS),
        ["machine:shared|machine:shared-box"]
    );
    assert!(
        report.contains(" 6 servers known, 1 offered for the sweep"),
        "{report}"
    );
    let page = view(&h.store());
    let devices = section(&page, "machines")
        .split("<details class=\"machine\">")
        .find(|b| b.contains("Other users' devices</strong>"))
        .expect("no list of other users' devices");
    assert!(devices.contains("1 device ·"), "{devices}");
}

#[test]
fn a_peer_whose_owner_the_status_does_not_give_is_treated_as_before() {
    // Absence of a user is not evidence that a device is someone else's. Nor is a name
    // that one of the owner's own devices also has.
    let h = Home::new("owner-unknown", None, None);
    let bin = h.dir.0.join("bin");
    let unstated = fake(
        &bin.join("unstated"),
        r#"{ "BackendState": "Running",
             "Self": { "HostName": "mac", "UserID": 1 },
             "Peer": {
               "nodekey:invented1": { "HostName": "no-owner", "TailscaleIPs": ["100.64.0.22"] },
               "nodekey:invented2": { "HostName": "iphone", "TailscaleIPs": ["100.64.0.30"],
                                      "UserID": 1 },
               "nodekey:invented3": { "HostName": "iphone", "TailscaleIPs": ["100.64.0.31"],
                                      "UserID": 3 } } }"#,
    );
    let report = h.run(&h.dir.0.join("absent"), &unstated);
    assert!(rows(&h.store(), RELATION).is_empty());
    assert!(report.contains(" 2 servers known,"), "{report}");

    let no_self = fake(
        &bin.join("no-self"),
        r#"{ "BackendState": "Running", "Self": { "HostName": "mac" },
             "Peer": { "nodekey:invented1": { "HostName": "friends-laptop",
                                              "TailscaleIPs": ["100.64.0.20"], "UserID": 3 } } }"#,
    );
    let report = h.run(&h.dir.0.join("absent"), &no_self);
    assert!(rows(&h.store(), RELATION).is_empty());
    assert!(report.contains(" 1 server known,"), "{report}");
}

#[test]
fn a_store_seeded_before_relation_to_owner_was_used_takes_it_without_a_rebuild() {
    // The vocabulary is data: the owner's store keeps its journal when a reserved word comes
    // into use.
    let h = Home::new("relation-seed", None, None);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET_SHARED);
    h.run(&h.dir.0.join("absent"), &tailscale);
    let conn = Connection::open(h.store()).unwrap();
    conn.execute_batch(
        "DELETE FROM assertion WHERE predicate = 'relation_to_owner';
         UPDATE predicate SET object_kind = NULL, status = 'reserved'
             WHERE name = 'relation_to_owner';",
    )
    .unwrap();
    drop(conn);

    h.run(&h.dir.0.join("absent"), &tailscale);

    assert_eq!(rows(&h.store(), RELATION).len(), 4);
    assert_eq!(
        rows(
            &h.store(),
            "SELECT object_kind, status FROM predicate WHERE name = 'relation_to_owner'"
        ),
        ["literal|used"]
    );
}

/// A sweep file of a server that says only this about itself.
fn with_own(names: &str, addresses: &str) -> String {
    format!("##names\n{names}\n##addresses\n{addresses}\n{WEB_1}")
}

#[test]
fn a_bare_host_name_a_sweep_file_shares_with_an_unrelated_alias_does_not_merge_them() {
    // Servers give themselves short names that the owner's aliases for other servers also
    // use. Merged, the server never read would look read.
    let h = Home::new(
        "bare-name",
        Some("Host web-1\n    HostName 203.0.113.5\n"),
        None,
    );
    let servers = h.dir.0.join("servers");
    put(
        &servers,
        "db-1.txt",
        &with_own("web-1", "eth0\t203.0.113.20/24"),
    );
    let report = h.run(&servers, &h.dir.0.join("no-tailscale"));

    assert!(rows(&h.store(), SAME_AS).is_empty());
    assert_eq!(
        rows(
            &h.store(),
            "SELECT object FROM assertion WHERE layer = 'live'
             AND subject = 'machine:db-1' AND predicate = 'known_as' ORDER BY object"
        ),
        ["203.0.113.20", "web-1"]
    );
    assert!(
        report.contains("2 servers known, 1 offered for the sweep, 1 read."),
        "{report}"
    );
}

#[test]
fn a_private_address_a_sweep_file_shares_with_an_unrelated_known_host_does_not_merge_them() {
    // The same private address is a different machine in every other network.
    let h = Home::new(
        "private-address",
        None,
        Some(&format!("10.0.0.9 ssh-ed25519 {KEY}\n")),
    );
    let servers = h.dir.0.join("servers");
    put(
        &servers,
        "db-1.txt",
        &with_own("db-host", "eth0\t10.0.0.9/24"),
    );
    let report = h.run(&servers, &h.dir.0.join("no-tailscale"));

    assert!(rows(&h.store(), SAME_AS).is_empty());
    assert!(
        report.contains("2 servers known, 0 offered for the sweep, 1 read."),
        "{report}"
    );
}

/// A tailnet peer whose name holds direction controls that would show `soc` reversed.
const TAILNET_HIDDEN: &str = r#"{ "BackendState": "Running",
  "Peer": { "nodekey:invented1": { "HostName": "odd\u202Ecos\u2066x\u2069",
                                   "TailscaleIPs": ["100.64.0.40"] } } }"#;

#[test]
fn a_name_with_direction_controls_is_printed_and_shown_escaped_and_kept_as_read() {
    // Text from a source is partly written by an attacker: printed raw, it can reorder or
    // hide the rest of a terminal line or of the page.
    let h = Home::new("hidden", None, None);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET_HIDDEN);
    let printed = h.servers_with(&tailscale);
    h.run(&h.dir.0.join("absent"), &tailscale);
    let page = view(&h.store());

    let escaped = "odd\\u{202e}cos\\u{2066}x\\u{2069}";
    for (what, text) in [("soc servers", &printed), ("the view", &page)] {
        assert!(text.contains(escaped), "{what}: {text}");
        for c in ['\u{202E}', '\u{2066}', '\u{2069}'] {
            assert!(!text.contains(c), "{what} holds {c:?}");
        }
    }
    assert_eq!(
        rows(
            &h.store(),
            "SELECT DISTINCT subject FROM assertion WHERE reader = 'tailnet'"
        ),
        ["machine:odd\u{202E}cos\u{2066}x\u{2069}"]
    );
}

#[test]
fn a_reason_from_a_source_is_printed_escaped() {
    // A failed reading quotes its source in the one report line.
    let h = Home::new("hidden-reason", None, None);
    let tailscale = fake(
        &h.dir.0.join("bin").join("tailscale"),
        r#"{ "BackendState": "Need\u202ELogin" }"#,
    );
    let printed = h.servers_with(&tailscale);
    let report = h.run(&h.dir.0.join("absent"), &tailscale);

    let escaped = "its state is Need\\u{202e}Login";
    for (what, text) in [("soc servers", &printed), ("soc run", &report)] {
        assert!(
            text.contains(escaped) && !text.contains('\u{202E}'),
            "{what}: {text}"
        );
    }
    assert_eq!(
        rows(
            &h.store(),
            "SELECT reason FROM coverage WHERE kind = 'tailnet peers'"
        ),
        ["tailscale is not running, its state is Need\u{202E}Login"]
    );
}

#[test]
fn an_error_is_printed_escaped() {
    // An argument or a path can hold the same characters as anything read.
    let dir = Dir::new("hidden-error");
    let errors = [
        soc_cmd(&dir.0).args(["view", "--no\u{202E}pen"]).output(),
        soc_cmd(&dir.0)
            .args(["view", "--no-open", "--store"])
            .arg(dir.0.join("a\u{202E}b").join("store.db"))
            .output(),
    ];
    for out in errors {
        let stderr = String::from_utf8(out.unwrap().stderr).unwrap();
        assert!(
            stderr.contains("\\u{202e}") && !stderr.contains('\u{202E}'),
            "{stderr}"
        );
    }
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

impl Home {
    /// `soc owner` with these words, for this store and no tailscale.
    fn owner_out(&self, words: &[&str]) -> std::process::Output {
        soc_cmd(&self.home)
            .arg("owner")
            .args(words)
            .arg("--store")
            .arg(self.store())
            .arg("--tailscale")
            .arg(self.dir.0.join("no-tailscale"))
            .output()
            .unwrap()
    }

    /// `soc owner` that must succeed; what it printed.
    fn owner(&self, words: &[&str]) -> String {
        let out = self.owner_out(words);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn sweep(&self) -> PathBuf {
        self.dir.0.join("store").join("sweep")
    }

    fn none(&self) -> PathBuf {
        self.dir.0.join("no-tailscale")
    }

    fn absent(&self) -> PathBuf {
        self.dir.0.join("absent")
    }
}

/// Moves everything the store has read and been told two hours into the past, as if it had
/// all happened then. The journal is append-only and keeps its times.
fn two_hours_earlier(store: &Path) {
    Connection::open(store)
        .unwrap()
        .execute_batch(
            "UPDATE assertion SET observed_at = observed_at - 7200;
             UPDATE coverage SET observed_at = observed_at - 7200;
             UPDATE owner_statement SET made_at = made_at - 7200;",
        )
        .unwrap();
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The names in the view's table of machines known and never read.
fn never_read(page: &str) -> Vec<String> {
    let machines = section(page, "machines");
    let Some(never) = machines
        .split("<details class=\"machine\">")
        .find(|b| b.contains("Known and never read"))
    else {
        return Vec::new();
    };
    never
        .split("<tr><td class=\"mono\">")
        .skip(1)
        .map(|r| r.split('<').next().unwrap().to_string())
        .collect()
}

/// The view's list of machines the owner set aside.
fn set_aside(page: &str) -> String {
    section(page, "machines")
        .split("<details class=\"machine\">")
        .find(|b| b.contains("Retired or disowned by the owner</strong>"))
        .unwrap_or_default()
        .to_string()
}

const OWNER_WORDS: &str = "SELECT entity, said, reason, withdrawn_at IS NOT NULL
                           FROM owner_statement ORDER BY id";

#[test]
fn a_retired_machine_is_never_visited_by_a_sweep_script_on_disk_even_one_written_before_the_statement()
 {
    // The sweep is access to servers. Once the owner says a machine is retired or not
    // theirs, the script the owner already has must not go in, under any of its aliases.
    let h = Home::new("word-sweep", Some(SSH_CONFIG_TWO_ALIASES), None);
    let bin = h.dir.0.join("bin");
    h.run(&h.absent(), &h.none());
    h.servers();
    assert_eq!(sweep_with_fake_ssh(&h.sweep(), &bin), ["db-1", "web-new"]);

    let said = h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    assert!(
        said.contains("It covers the machine under every name: web-1, web-new.")
            && said.contains("The sweep script was written again: it visits 1 server."),
        "{said}"
    );
    assert_eq!(sweep_with_fake_ssh(&h.sweep(), &bin), ["db-1"]);
    // Nor any script written after it.
    h.servers();
    assert_eq!(sweep_with_fake_ssh(&h.sweep(), &bin), ["db-1"]);
}

#[test]
fn a_statement_under_a_name_a_trace_no_longer_gives_still_keeps_the_machine_out_of_the_sweep() {
    // The owner may name a machine by an address only known hosts gave. When that file goes,
    // the machine is still the one the owner spoke of, under its alias too.
    let h = Home::new(
        "word-forgotten-name",
        Some(SSH_CONFIG_TWO_ALIASES),
        Some(&format!("10.0.0.5 ssh-ed25519 {KEY}\n")),
    );
    h.run(&h.absent(), &h.none());
    let said = h.owner(&["10.0.0.5", "retired", "--reason", "Moved to a new host"]);
    assert!(said.contains("Said: 10.0.0.5 is retired"), "{said}");
    std::fs::remove_file(h.home.join(".ssh/known_hosts")).unwrap();

    h.servers();
    assert_eq!(
        sweep_with_fake_ssh(&h.sweep(), &h.dir.0.join("bin")),
        ["db-1"]
    );
}

#[test]
fn a_sweep_script_that_cannot_be_written_again_after_a_statement_is_removed() {
    // A script left as it was would still visit the machine the owner set aside.
    let h = Home::new("word-stale", Some(SSH_CONFIG_TWO_ALIASES), None);
    h.run(&h.absent(), &h.none());
    h.servers();
    let script = h.sweep().join("sweep.sh");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o444)).unwrap();
    }

    let out = h.owner_out(&["web-1", "retired", "--reason", "Moved to a new host"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("the owner's word was kept") && stderr.contains("no sweep script is left"),
        "{stderr}"
    );
    assert!(!script.exists());
    assert_eq!(
        rows(&h.store(), OWNER_WORDS),
        ["machine:web-1|retired|Moved to a new host|0"]
    );
}

#[test]
fn a_statement_about_one_name_covers_the_machine_under_all_its_names() {
    // The owner names a machine the way they know it, in any case. Left under its other
    // names, it would still be swept and counted.
    let h = Home::new("word-names", Some(SSH_CONFIG), None);
    let tailscale = fake(&h.dir.0.join("bin").join("tailscale"), TAILNET);
    h.run(&h.absent(), &tailscale);
    assert_eq!(
        never_read(&view(&h.store())),
        ["build", "phone", "retired-box", "web-1"]
    );

    let said = h.owner(&[
        "BUILD-BOX.example-tail.ts.net",
        "retired",
        "--reason",
        "Replaced",
    ]);
    assert!(
        said.contains("Said: build is retired,")
            && said.contains("under every name: build, build-box."),
        "{said}"
    );
    let printed = h.servers_with(&tailscale);
    let script = std::fs::read_to_string(h.sweep().join("sweep.sh")).unwrap();
    assert_eq!(listed(&script), ["retired-box", "web-1"]);
    let rows: Vec<&str> = printed
        .lines()
        .filter(|l| l.starts_with("  build"))
        .collect();
    assert_eq!(rows.len(), 1, "{printed}");
    assert!(
        rows[0].starts_with("  build    retired  20")
            && rows[0].ends_with(
                "Replaced  100.64.0.7, Build-Box.example-tail.ts.net., build-box, \
                 build-box.example-tail.ts.net, fd7a:115c:a1e0::7"
            ),
        "{}",
        rows[0]
    );
    h.run(&h.absent(), &tailscale);
    assert_eq!(
        never_read(&view(&h.store())),
        ["phone", "retired-box", "web-1"]
    );
}

const TWO_SERVERS: &str = "\
Host web-1
    HostName 203.0.113.5
Host old-box
    HostName 203.0.113.8
";

#[test]
fn a_retired_machine_is_not_counted_as_known_and_never_read_and_is_listed_with_its_statement() {
    // "Known and never read" is what the owner has left to sweep. A machine the owner
    // retired is not, and it must not disappear either: it is shown with the statement.
    let h = Home::new("word-counts", Some(TWO_SERVERS), None);
    let report = h.run(&h.absent(), &h.none());
    assert!(
        report.contains(" 2 servers known, 2 offered for the sweep, 0 read."),
        "{report}"
    );

    h.owner(&["old-box", "retired", "--reason", "Switched off in October"]);
    let report = h.run(&h.absent(), &h.none());
    let printed = h.servers();
    let page = view(&h.store());

    assert!(
        report.contains(
            " 1 server known, 1 offered for the sweep, 0 read; 1 retired or disowned by the owner."
        ),
        "{report}"
    );
    assert!(
        printed.contains(
            "\n1 server known, 0 of them under several names, 1 offered for the sweep, \
             0 left out as code hosting, 0 as other users' devices, 1 known and never read.\n\
             The owner's word: 1 machine retired or disowned.\n"
        ),
        "{printed}"
    );
    let lines: Vec<&str> = printed.lines().collect();
    let head = lines
        .iter()
        .position(|l| *l == "Retired or disowned by the owner, not counted as servers: 1 machine")
        .unwrap_or_else(|| panic!("no list of retired machines: {printed}"));
    assert!(
        lines[head + 2].starts_with("  old-box  retired  20")
            && lines[head + 2].ends_with("UTC  Switched off in October  203.0.113.8"),
        "{printed}"
    );
    assert_eq!(printed.matches("old-box").count(), 1, "{printed}");

    assert_eq!(never_read(&page), ["web-1"]);
    assert!(
        section(&page, "machines")
            .contains("1 known and never read; 1 retired or disowned by the owner."),
        "{page}"
    );
    let aside = set_aside(&page);
    assert!(
        aside.contains("1 machine ·")
            && aside.contains("<td class=\"mono\">old-box</td><td>retired</td>")
            && aside
                .contains("<td>Switched off in October</td><td class=\"mono\">203.0.113.8</td>"),
        "{aside}"
    );
}

#[test]
fn facts_about_a_retired_machine_are_not_retracted_and_its_readings_go_on() {
    // The owner's word is next to the facts, never an edit of them. What was read on the
    // machine stays, and readers keep reading what is there.
    let h = Home::new(
        "word-facts",
        Some("Host web-1\n    HostName 203.0.113.5\n"),
        None,
    );
    let servers = h.dir.0.join("servers");
    put(&servers, "web-1.txt", WEB_1);
    h.run(&servers, &h.none());
    let live_before = rows(&h.store(), LIVE);

    h.owner(&["web-1", "not-mine", "--reason", "A client's server"]);
    let report = h.run(&servers, &h.none());

    assert_eq!(rows(&h.store(), LIVE), live_before);
    assert!(
        rows(
            &h.store(),
            "SELECT 1 FROM assertion WHERE layer = 'retracted'"
        )
        .is_empty()
    );
    assert!(report.contains("Since last run: no changes."), "{report}");
    assert_eq!(
        rows(
            &h.store(),
            "SELECT kind, completeness FROM coverage WHERE scope = 'machine:web-1'
             AND run_id = (SELECT run_id FROM coverage ORDER BY id DESC LIMIT 1) ORDER BY kind"
        ),
        [
            "containers|full",
            "running kernel package|full",
            "sweep visit|full",
            "system package sources|full",
            "system packages|full",
            "system release|full"
        ]
    );
    // The view still shows what was read on it, with the statement.
    let page = view(&h.store());
    let web = section(&page, "machines")
        .split("<details class=\"machine\">")
        .find(|b| b.contains("<strong>web-1</strong>"))
        .expect("web-1 is not on the page")
        .to_string();
    assert!(
        web.contains("<span class=\"badge good\">not mine by the owner on ")
            && web.contains("A client&#39;s server</span>")
            && web.contains("openssl"),
        "{web}"
    );
}

/// Two servers, the owner's statement that web-1 is retired, and a sweep file of web-1
/// read before it, all two hours ago. Returns the time of the statement.
fn retired_two_hours_ago(h: &Home) -> i64 {
    put(
        &h.sweep(),
        "web-1.txt",
        &format!("##taken_at\n{}\n{WEB_1}", now() - 20_000),
    );
    h.run(&h.sweep(), &h.none());
    h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    two_hours_earlier(&h.store());
    rows(&h.store(), "SELECT made_at FROM owner_statement")[0]
        .parse()
        .unwrap()
}

#[test]
fn a_machine_swept_after_the_statement_is_shown_as_contradicted_counted_again_and_still_not_visited()
 {
    // A statement must never hide a machine that is alive: a server the owner thinks is
    // gone and that answers the sweep is exactly what must be seen. It is still not
    // visited: the owner said it is not theirs to visit.
    let h = Home::new("word-seen", Some(SSH_CONFIG_TWO_ALIASES), None);
    let made = retired_two_hours_ago(&h);
    let contradicted = |h: &Home| {
        h.owner(&[])
            .lines()
            .find(|l| l.starts_with("  web-1 "))
            .unwrap()
            .contains("contradicted")
    };

    // Not seen alive: a reading taken as the statement was made, and a file a failed ssh
    // left empty.
    put(
        &h.sweep(),
        "web-1.txt",
        &format!("##taken_at\n{made}\n{WEB_1}"),
    );
    h.run(&h.sweep(), &h.none());
    assert!(!contradicted(&h));
    put(&h.sweep(), "web-new.txt", "");
    let report = h.run(&h.sweep(), &h.none());
    assert!(!contradicted(&h));
    assert!(
        report.contains(" 1 server known, 1 offered for the sweep, 0 read; 1 retired"),
        "{report}"
    );
    std::fs::remove_file(h.sweep().join("web-new.txt")).unwrap();

    // Swept again after the statement: the same packages, a later reading.
    put(
        &h.sweep(),
        "web-1.txt",
        &format!("##taken_at\n{}\n{WEB_1}", made + 1),
    );
    let report = h.run(&h.sweep(), &h.none());
    assert!(
        report.contains(
            " 2 servers known, 1 offered for the sweep, 1 read; 1 retired or disowned by the owner. \
             Seen alive after the owner's word: web-1."
        ),
        "{report}"
    );
    let listing = h.owner(&[]);
    assert!(
        listing.contains("contradicted: ") && listing.contains("servers read containers on web-1"),
        "{listing}"
    );

    let printed = h.servers();
    let row = printed
        .lines()
        .find(|l| l.starts_with("  web-new "))
        .unwrap_or_else(|| panic!("web-1 is not listed as a server: {printed}"));
    assert!(
        row.contains("not offered: retired by the owner on")
            && row.contains("seen alive after it:"),
        "{row}"
    );
    assert!(
        printed.contains("\n2 servers known,")
            && printed.contains("seen alive after it and counted again: web-1."),
        "{printed}"
    );
    assert!(
        !printed.contains("not counted as servers: 1 machine"),
        "{printed}"
    );
    assert_eq!(
        sweep_with_fake_ssh(&h.sweep(), &h.dir.0.join("bin")),
        ["db-1"]
    );

    let page = view(&h.store());
    assert!(
        section(&page, "machines").contains(
            "<p class=\"alert\">The owner's word is contradicted: <span class=\"mono\">web-1</span>"
        ),
        "{page}"
    );
    assert!(set_aside(&page).is_empty());
    let web = section(&page, "machines")
        .split("<details class=\"machine\">")
        .find(|b| b.contains("<strong>web-1</strong>"))
        .expect("web-1 is not on the page")
        .to_string();
    assert!(
        web.contains("<span class=\"badge bad\">the owner's word is contradicted</span>"),
        "{web}"
    );
}

#[test]
fn a_new_trace_after_the_statement_contradicts_it_and_a_later_statement_clears_it() {
    // A trace that appears later, such as a new known host, is a sign of life too. The
    // owner answers it with a new statement, which is later than what was seen.
    let h = Home::new("word-later", Some(SSH_CONFIG_TWO_ALIASES), None);
    h.run(&h.absent(), &h.none());
    h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    // A statement made in the same second as the reading is not contradicted by it.
    Connection::open(h.store())
        .unwrap()
        .execute_batch(
            "UPDATE owner_statement SET made_at =
                 (SELECT MAX(observed_at) FROM assertion WHERE subject = 'machine:web-1')",
        )
        .unwrap();
    assert!(
        h.owner(&[])
            .contains("Moved to a new host  10.0.0.5, web-new  nothing")
    );
    two_hours_earlier(&h.store());

    put(
        &h.home,
        ".ssh/known_hosts",
        &format!("10.0.0.5 ssh-ed25519 {KEY}\n"),
    );
    let report = h.run(&h.absent(), &h.none());
    assert!(
        report.contains("Seen alive after the owner's word: web-1."),
        "{report}"
    );
    assert!(
        h.owner(&[]).contains("contradicted: ")
            && h.owner(&[])
                .contains("known-hosts saw 10.0.0.5 known_as 10.0.0.5"),
        "{}",
        h.owner(&[])
    );

    let said = h.owner(&["web-1", "not-mine", "--reason", "Handed over to a client"]);
    assert!(said.contains("It replaces the statement"), "{said}");
    let listing = h.owner(&[]);
    assert!(
        listing.contains("The owner's word: 1 statement stands.")
            && listing.contains("not mine")
            && listing.contains("Handed over to a client")
            && !listing.contains("contradicted")
            && listing.contains("1 statement was withdrawn and kept."),
        "{listing}"
    );
    let report = h.run(&h.absent(), &h.none());
    assert!(
        report.contains(" 1 server known, 1 offered for the sweep, 0 read; 1 retired")
            && !report.contains("Seen alive"),
        "{report}"
    );
}

#[test]
fn a_link_the_resolver_makes_after_the_statement_is_not_a_sign_of_life() {
    // Only a reader sees a machine. A link worked out again from what was already known
    // says nothing about whether the machine is alive.
    let h = Home::new(
        "word-link",
        Some("Host web-1\n    HostName 203.0.113.5\n"),
        None,
    );
    let taken = now() - 20_000;
    let file = |names: &str, address: &str| {
        format!(
            "##taken_at\n{taken}\n{}",
            with_own(names, &format!("eth0\t{address}/24"))
        )
    };
    // Two files give the same address with different names: the address links nothing.
    put(
        &h.sweep(),
        "a.txt",
        &file("web-host.example.org", "203.0.113.5"),
    );
    put(
        &h.sweep(),
        "b.txt",
        &file("other.example.org", "203.0.113.5"),
    );
    h.run(&h.sweep(), &h.none());
    assert!(rows(&h.store(), SAME_AS).is_empty());
    h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    two_hours_earlier(&h.store());

    // b turns out to be another server: the address now links a to web-1.
    put(
        &h.sweep(),
        "b.txt",
        &file("other.example.org", "203.0.113.9"),
    );
    h.run(&h.sweep(), &h.none());

    assert_eq!(rows(&h.store(), SAME_AS), ["machine:a|machine:web-1"]);
    let listing = h.owner(&[]);
    assert!(
        listing.contains("a, web-host.example.org") && !listing.contains("contradicted"),
        "{listing}"
    );
}

#[test]
fn a_withdrawn_statement_restores_the_machine_and_stays_in_the_journal() {
    // The owner can be wrong. Withdrawn, the machine is a server again; the statement and
    // its withdrawal stay, because an investigation looks back.
    let h = Home::new("word-withdraw", Some(SSH_CONFIG_TWO_ALIASES), None);
    h.run(&h.absent(), &h.none());
    h.servers();
    h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    assert_eq!(
        sweep_with_fake_ssh(&h.sweep(), &h.dir.0.join("bin")),
        ["db-1"]
    );

    let said = h.owner(&["web-new", "withdraw"]);
    assert!(
        said.contains("Withdrawn: the statement that web-1 is retired no longer stands"),
        "{said}"
    );
    assert_eq!(
        sweep_with_fake_ssh(&h.sweep(), &h.dir.0.join("bin")),
        ["db-1", "web-new"]
    );
    assert_eq!(
        rows(&h.store(), OWNER_WORDS),
        ["machine:web-1|retired|Moved to a new host|1"]
    );
    assert_eq!(
        rows(
            &h.store(),
            "SELECT entry, subject, old_value, new_value, text FROM journal
             WHERE entry LIKE 'owner%' ORDER BY seq"
        ),
        [
            "owner_said|machine:web-1|NULL|retired|Moved to a new host",
            "owner_withdrew|machine:web-1|retired|NULL|withdrawn by the owner"
        ]
    );
    let listing = h.owner(&[]);
    assert!(
        listing.contains("The owner's word: 0 statements stand.")
            && listing.contains("1 statement was withdrawn and kept."),
        "{listing}"
    );
    // The owner's word is not a run, and is not shown as one that did not finish.
    let page = view(&h.store());
    assert!(
        !section(&page, "changes").contains("did not finish"),
        "{page}"
    );

    let report = h.run(&h.absent(), &h.none());
    assert!(
        report.contains(" 2 servers known, 2 offered for the sweep, 0 read.")
            && !report.contains("retired"),
        "{report}"
    );
}

#[test]
fn a_statement_about_a_machine_no_trace_names_any_more_can_still_be_withdrawn() {
    // An alias deleted from the ssh configuration leaves the statement standing; the
    // owner must still be able to take it back.
    let h = Home::new("word-forgotten", Some(TWO_SERVERS), None);
    h.run(&h.absent(), &h.none());
    h.owner(&["old-box", "retired", "--reason", "Switched off in October"]);
    put(
        &h.home,
        ".ssh/config",
        "Host web-1\n    HostName 203.0.113.5\n",
    );
    h.run(&h.absent(), &h.none());
    assert!(h.owner(&[]).contains("  old-box  retired"));

    h.owner(&["old-box", "withdraw"]);
    assert_eq!(
        rows(&h.store(), OWNER_WORDS),
        ["machine:old-box|retired|Switched off in October|1"]
    );
}

#[test]
fn an_unknown_or_ambiguous_name_is_an_error_that_changes_nothing() {
    // Nothing is guessed: a statement about the wrong machine would keep a live server out
    // of the sweep and out of the count.
    let h = Home::new("word-errors", None, None);
    let servers = h.dir.0.join("servers");
    put(&servers, "a.txt", &with_identity("ubuntu", "203.0.113.10"));
    put(&servers, "b.txt", &with_identity("ubuntu", "203.0.113.20"));
    h.run(&servers, &h.none());
    h.servers();
    let state = || {
        (
            rows(&h.store(), "SELECT * FROM journal"),
            rows(&h.store(), "SELECT * FROM owner_statement"),
            std::fs::read(h.sweep().join("sweep.sh")).unwrap(),
        )
    };
    let before = state();

    for (words, says) in [
        (
            &["ubuntu", "retired", "--reason", "Gone"][..],
            "ubuntu fits 2 machines that are not known to be one: a; b.",
        ),
        (
            &["db-9", "retired", "--reason", "Gone"],
            "the store knows no machine as db-9",
        ),
        (&["a", "retired"], "a statement needs a reason"),
        (
            &["a", "retired", "--reason", "  "],
            "a statement needs a reason",
        ),
        (&["a", "withdraw"], "no statement stands about a"),
        (
            &["a", "withdraw", "--reason", "Back"],
            "a withdrawal takes no reason",
        ),
        (&["a", "gone", "--reason", "Gone"], "not gone"),
    ] {
        let out = h.owner_out(words);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{words:?}");
        assert!(stderr.contains(says), "{words:?}: {stderr}");
        assert!(
            state() == before,
            "{words:?} changed the store or the sweep"
        );
    }
    // Named by its id, the machine is one.
    h.owner(&["machine:a", "retired", "--reason", "Gone"]);
    assert_eq!(rows(&h.store(), OWNER_WORDS), ["machine:a|retired|Gone|0"]);
}

#[test]
fn a_store_of_the_current_format_takes_the_first_statement_without_losing_its_journal() {
    // The journal is the one thing raw input cannot rebuild. The owner's store, made before
    // the owner's word, must take it as it is.
    let h = Home::new(
        "word-first",
        Some("Host web-1\n    HostName 203.0.113.5\n"),
        None,
    );
    h.run(&h.absent(), &h.none());
    h.run(&h.absent(), &h.none());
    Connection::open(h.store())
        .unwrap()
        .execute_batch(
            "DROP TABLE owner_statement;
             CREATE TABLE journal_before (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 entry TEXT NOT NULL CHECK (entry IN ('run_started', 'added', 'changed',
                                                      'removed', 'report', 'run_finished')),
                 reader TEXT, scope TEXT, kind TEXT, subject TEXT, predicate TEXT,
                 old_value TEXT, new_value TEXT, text TEXT);
             INSERT INTO journal_before SELECT * FROM journal;
             DROP TABLE journal;
             ALTER TABLE journal_before RENAME TO journal;
             CREATE TRIGGER journal_no_update BEFORE UPDATE ON journal
                 BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
             CREATE TRIGGER journal_no_delete BEFORE DELETE ON journal
                 BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;",
        )
        .unwrap();
    let all = "SELECT * FROM journal ORDER BY seq";
    let before = rows(&h.store(), all);
    // As it is, the store is read by the view and by `soc servers`.
    view(&h.store());
    h.servers();
    assert_eq!(rows(&h.store(), all), before);

    h.owner(&["web-1", "retired", "--reason", "Moved to a new host"]);
    h.run(&h.absent(), &h.none());

    let after = rows(&h.store(), all);
    assert_eq!(after[..before.len()], before[..]);
    assert!(
        after[before.len()].contains("|owner_said|"),
        "{}",
        after[before.len()]
    );
    let seqs: Vec<i64> = rows(&h.store(), "SELECT seq FROM journal ORDER BY seq")
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
    assert_eq!(
        rows(
            &h.store(),
            "SELECT value FROM meta WHERE key = 'format_version'"
        ),
        ["4"]
    );
    let conn = Connection::open(h.store()).unwrap();
    assert!(conn.execute("DELETE FROM journal", []).is_err());
    assert!(conn.execute("UPDATE journal SET text = ''", []).is_err());
}

#[test]
fn the_owners_reason_is_printed_and_shown_escaped_and_kept_as_typed() {
    // The reason is free text, and pasted text can carry direction controls that reorder
    // or hide what is around it.
    let h = Home::new("word-hidden", Some(TWO_SERVERS), None);
    h.run(&h.absent(), &h.none());
    let reason = "gone\u{202E}enog";
    let said = h.owner(&["old-box", "retired", "--reason", reason]);
    let listing = h.owner(&[]);
    let printed = h.servers();
    let page = view(&h.store());

    for (what, text) in [
        ("soc owner", &said),
        ("soc owner list", &listing),
        ("soc servers", &printed),
        ("the view", &page),
    ] {
        assert!(
            text.contains("gone\\u{202e}enog") && !text.contains('\u{202E}'),
            "{what}: {text}"
        );
    }
    assert_eq!(
        rows(&h.store(), "SELECT reason FROM owner_statement"),
        [reason]
    );
}

/// The machine's block in the view's list of machines.
fn machine_block(page: &str, name: &str) -> String {
    section(page, "machines")
        .split("<details class=\"machine\">")
        .find(|b| b.contains(&format!("<strong>{name}</strong>")))
        .unwrap_or_else(|| panic!("{name} is not on the page"))
        .to_string()
}

/// The row `soc servers` prints for a server.
fn server_row(printed: &str, name: &str) -> String {
    printed
        .lines()
        .find(|l| l.starts_with(&format!("  {name} ")))
        .unwrap_or_else(|| panic!("{name} is not listed: {printed}"))
        .to_string()
}

#[test]
fn a_failed_visit_never_replaces_the_reading_an_earlier_one_left_and_a_later_success_clears_it() {
    // A visit that times out must not destroy a complete reading taken earlier. The failure
    // is kept with its time and why, and a visit that succeeds removes it for the machine
    // under every alias.
    let h = Home::new("sweep-failed", Some(SSH_CONFIG_TWO_ALIASES), None);
    h.servers();
    let (sweep, bin) = (h.sweep(), h.dir.0.join("bin"));
    let earlier = format!("##taken_at\n1767323045\n{WEB_1}");
    put(&sweep, "web-new.txt", &earlier);
    fake_ssh(
        &bin,
        "case \"$5\" in
  web-new) echo '##taken_at'; echo 'Warning: invented' >&2
           echo 'ssh: connect to host web-new port 22: Operation timed out' >&2; exit 255;;
  db-1) exit 255;;
esac",
    );
    let before = now();
    let printed = run_sweep(&sweep, &bin, &[]);
    let after = now();

    assert_eq!(
        std::fs::read_to_string(sweep.join("web-new.txt")).unwrap(),
        earlier
    );
    assert!(!sweep.join("db-1.txt").exists());
    let failed = |alias: &str| std::fs::read_to_string(sweep.join(format!("{alias}.failed")));
    let web = failed("web-new").unwrap();
    let at: i64 = web.lines().next().unwrap().parse().unwrap();
    assert!((before..=after).contains(&at), "{web}");
    assert!(
        web.ends_with("\nssh: connect to host web-new port 22: Operation timed out\n"),
        "{web}"
    );
    assert!(
        failed("db-1")
            .unwrap()
            .ends_with("\nssh exited with status 255\n")
    );
    assert!(
        printed.contains("failed  web-new (see web-new.failed)\n")
            && printed.contains("failed  db-1 (see db-1.failed)\n"),
        "{printed}"
    );
    let left: Vec<String> = std::fs::read_dir(&sweep)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".part") || n.starts_with('.'))
        .collect();
    assert!(left.is_empty(), "{left:?}");

    // The probe broke off before its end; the machine succeeds, under its first alias,
    // and a failure left earlier under its other alias goes too.
    put(
        &sweep,
        "web-1.failed",
        "1767323045\nHost key verification failed.\n",
    );
    fake_ssh(
        &bin,
        "case \"$5\" in db-1) echo '##taken_at';; *) echo '##end';; esac",
    );
    run_sweep(&sweep, &bin, &[]);
    assert!(
        failed("db-1")
            .unwrap()
            .ends_with("\nthe probe did not reach its end\n")
    );
    assert_eq!(
        std::fs::read_to_string(sweep.join("web-new.txt")).unwrap(),
        "##end\n"
    );
    assert!(failed("web-new").is_err() && failed("web-1").is_err());
}

#[test]
fn a_failed_visit_is_reported_with_when_and_why_next_to_the_earlier_reading_which_keeps_its_coverage()
 {
    // An earlier full reading is still a full reading taken at that time, and nothing is
    // retracted; the owner is told when it was read and that the latest attempt failed.
    let h = Home::new("visit-failed", Some(SSH_CONFIG_TWO_ALIASES), None);
    let servers = h.sweep();
    let taken = 1_767_323_045; // 2026-01-02 03:04:05 UTC
    put(
        &servers,
        "web-new.txt",
        &format!("##taken_at\n{taken}\n{WEB_1}"),
    );
    h.run(&servers, &h.none());
    let live = rows(&h.store(), LIVE);

    let failed_at = 1_767_412_800; // 2026-01-03 04:00:00 UTC
    put(
        &servers,
        "web-new.failed",
        &format!(
            "{failed_at}\nWarning: invented\nssh: connect to host web-new port 22: Operation timed out\u{202E}\n\n"
        ),
    );
    put(
        &servers,
        "db-1.failed",
        &format!("{failed_at}\nPermission denied (publickey).\n"),
    );
    let report = h.run(&servers, &h.none());

    assert_eq!(rows(&h.store(), LIVE), live);
    assert!(
        rows(
            &h.store(),
            "SELECT 1 FROM assertion WHERE layer = 'retracted'"
        )
        .is_empty()
    );
    let latest = "SELECT scope, kind, completeness, observed_at, COALESCE(reason, '') FROM coverage
                  WHERE scope LIKE 'machine:%' AND reader = 'servers'
                    AND run_id = (SELECT run_id FROM coverage ORDER BY id DESC LIMIT 1)
                  ORDER BY scope, kind";
    assert_eq!(
        rows(&h.store(), latest),
        [
            "containers",
            "running kernel package",
            "sweep visit",
            "system package sources",
            "system packages",
            "system release"
        ]
        .iter()
        .map(|kind| match *kind {
            "sweep visit" => {
                format!("machine:db-1|{kind}|none|{failed_at}|Permission denied (publickey).")
            }
            _ => format!(
                "machine:db-1|{kind}|none|{failed_at}|the latest visit failed: Permission denied (publickey)."
            ),
        })
        .chain(
            [
                "containers",
                "running kernel package",
                "sweep visit",
                "system package sources",
                "system packages",
                "system release"
            ]
            .iter()
            .map(|kind| match *kind {
                "sweep visit" => format!(
                    "machine:web-new|{kind}|none|{failed_at}|ssh: connect to host web-new port 22: Operation timed out\u{202E}"
                ),
                _ => format!("machine:web-new|{kind}|full|{taken}|"),
            })
        )
        .collect::<Vec<_>>()
    );
    let web_said = "web-new was last read 2026-01-02 03:04 UTC; the latest visit failed 2026-01-03 04:00 UTC: ssh: connect to host web-new port 22: Operation timed out\\u{202e}.";
    let db_said = "db-1 was never read; the latest visit failed 2026-01-03 04:00 UTC: Permission denied (publickey).";
    assert!(
        report.contains(web_said) && report.contains(db_said),
        "{report}"
    );
    assert!(
        !report.contains('\u{202E}') && !report.contains("host key"),
        "{report}"
    );

    let printed = h.servers();
    assert!(
        server_row(&printed, "web-new").contains(
            "read, taken 2026-01-02 03:04 UTC; the latest visit failed 2026-01-03 04:00 UTC: ssh: connect to host web-new port 22: Operation timed out\\u{202e}."
        ),
        "{printed}"
    );
    assert!(
        server_row(&printed, "db-1").contains(
            "never read; the latest visit failed 2026-01-03 04:00 UTC: Permission denied (publickey)."
        ),
        "{printed}"
    );

    let page = view(&h.store());
    let web = machine_block(&page, "web-new");
    assert!(
        web.contains("<span class=\"badge bad\">latest visit failed</span>")
            && web.contains("· read 2026-01-02 03:04 UTC")
            && web.contains(
                "<p class=\"alert\">Last read 2026-01-02 03:04 UTC; the latest visit failed 2026-01-03 04:00 UTC: ssh: connect to host web-new port 22: Operation timed out\\u{202e}.</p>"
            )
            && web.contains("openssl"),
        "{web}"
    );
    assert!(
        machine_block(&page, "db-1").contains(
            "<p class=\"alert\">Last read never; the latest visit failed 2026-01-03 04:00 UTC: Permission denied (publickey).</p>"
        ),
        "{page}"
    );

    // A visit that succeeds removes the failure, and nothing is said about it any more.
    std::fs::remove_file(servers.join("web-new.failed")).unwrap();
    let report = h.run(&servers, &h.none());
    assert!(!report.contains("web-new was"), "{report}");
    assert!(
        rows(&h.store(), latest).contains(&format!("machine:web-new|sweep visit|full|{taken}|"))
    );
    assert!(!server_row(&h.servers(), "web-new").contains("failed"));
    assert!(!machine_block(&view(&h.store()), "web-new").contains("failed"));
}

#[test]
fn a_host_key_that_could_not_be_verified_is_left_to_the_owner_to_check_by_hand() {
    // The sweep never accepts a key on the owner's behalf: ssh runs in batch mode, and the
    // owner is told to connect once by hand and check the key, never to turn the check off.
    let h = Home::new("host-key", Some(SSH_CONFIG_TWO_ALIASES), None);
    h.servers();
    let (sweep, bin) = (h.sweep(), h.dir.0.join("bin"));
    let log = bin.join("args.log");
    fake_ssh(
        &bin,
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'
echo 'No ED25519 host key is known for '\"$5\"' and you have requested strict checking.' >&2
echo 'Host key verification failed.' >&2
exit 255",
            log.display()
        ),
    );
    run_sweep(&sweep, &bin, &[]);
    let args = std::fs::read_to_string(&log).unwrap();
    assert_eq!(args.lines().count(), 2, "{args}");
    assert!(
        args.lines()
            .all(|l| l.starts_with("-o BatchMode=yes ") && l.ends_with(" sh -s")),
        "{args}"
    );

    let failed_at = 1_767_412_800; // 2026-01-03 04:00:00 UTC
    let failed = format!(
        "{failed_at}\n{}",
        std::fs::read_to_string(sweep.join("db-1.failed"))
            .unwrap()
            .split_once('\n')
            .unwrap()
            .1
    );
    put(&sweep, "db-1.failed", &failed);
    let said = "the latest visit failed 2026-01-03 04:00 UTC: Host key verification failed. Connect to this server once by hand and check its host key: the sweep never accepts a key for you.";
    let report = h.run(&sweep, &h.none());
    let printed = h.servers();
    let page = view(&h.store());
    assert!(
        report.contains(&format!("db-1 was never read; {said}")),
        "{report}"
    );
    assert!(server_row(&printed, "db-1").contains(said), "{printed}");
    assert!(machine_block(&page, "db-1").contains(said), "{page}");
    let script = std::fs::read_to_string(sweep.join("sweep.sh")).unwrap();
    for text in [&script, &report, &printed, &page] {
        for option in ["StrictHostKeyChecking", "UserKnownHostsFile", "accept-new"] {
            assert!(!text.contains(option), "{option}");
        }
    }
}

/// Seven machines for the sweep, one of them under two aliases. Invented.
const SSH_CONFIG_SEVEN: &str = "\
Host web-new
    HostName 10.0.0.5
Host web-1
    HostName 10.0.0.5
Host db-1
    HostName 10.0.0.6
Host cache-1
    HostName 10.0.0.7
Host mail-1
    HostName 10.0.0.8
Host queue-1
    HostName 10.0.0.9
Host search-1
    HostName 10.0.0.10
Host files-1
    HostName 10.0.0.11
";

#[test]
fn the_sweep_visits_several_machines_at_a_time_never_more_than_its_limit_and_each_gets_one_line() {
    // One slow server must not hold up the rest, and a long list must not open dozens of
    // connections at once. However the visits interleave, each machine is visited once and
    // gets exactly one whole result line, and a failure stops no other visit.
    let h = Home::new("at-once", Some(SSH_CONFIG_SEVEN), None);
    h.servers();
    let (sweep, bin) = (h.sweep(), h.dir.0.join("bin"));
    // The limit the owner can count on: no more connections than this at once.
    let limit = 4;
    let (running, log) = (h.dir.0.join("running"), h.dir.0.join("running.log"));
    std::fs::create_dir_all(&running).unwrap();
    let (running, log) = (running.display(), log.display());
    fake_ssh(
        &bin,
        &format!(
            "alias=$5
: > '{running}/'\"$alias\"
set -- '{running}'/*
echo \"$alias $#\" >> '{log}'
/bin/sleep 1
rm -f '{running}/'\"$alias\"
if [ \"$alias\" = db-1 ]; then echo 'ssh: connect to host db-1 port 22: Connection refused' >&2; exit 255; fi
echo '##end'"
        ),
    );
    let printed = run_sweep(&sweep, &bin, &[]);

    let log = std::fs::read_to_string(log.to_string()).unwrap();
    let mut visited: Vec<&str> = log.lines().map(|l| l.split(' ').next().unwrap()).collect();
    visited.sort();
    let machines = [
        "cache-1", "db-1", "files-1", "mail-1", "queue-1", "search-1", "web-new",
    ];
    assert_eq!(visited, machines, "{log}");
    let most = log
        .lines()
        .map(|l| l.split(' ').nth(1).unwrap().parse::<usize>().unwrap())
        .max()
        .unwrap();
    assert!(
        most > 1 && most <= limit,
        "{most} at once, limit {limit}: {log}"
    );

    let results: Vec<&str> = printed
        .lines()
        .filter(|l| l.starts_with("ok") || l.starts_with("failed"))
        .collect();
    let mut expected: Vec<String> = machines
        .iter()
        .map(|m| match *m {
            "db-1" => "failed  db-1 (see db-1.failed)".to_string(),
            m => format!("ok      {m}"),
        })
        .collect();
    let mut got: Vec<String> = results.iter().map(|l| l.to_string()).collect();
    expected.sort();
    got.sort();
    assert_eq!(got, expected, "{printed}");
}

#[test]
fn named_aliases_restrict_the_sweep_and_a_name_the_script_does_not_list_or_skips_is_never_visited()
{
    // Retrying the servers that failed must not widen the sweep: an argument only chooses
    // among the machines `soc servers` wrote into the script.
    let h = Home::new("sweep-args", Some(SSH_CONFIG_TWO_ALIASES), None);
    let printed = h.servers();
    let (sweep, bin) = (h.sweep(), h.dir.0.join("bin"));
    assert!(
        printed.contains(&format!(
            "name their aliases: sh '{}' <alias>...",
            sweep.join("sweep.sh").display()
        )),
        "{printed}"
    );

    assert_eq!(visits(&sweep, &bin, &["db-1"]).0, ["db-1"]);
    // Named by its other alias, the machine is still visited once, through its first.
    assert_eq!(visits(&sweep, &bin, &["web-1"]).0, ["web-new"]);
    let strangers = [
        "mail-9",
        "10.0.0.5",
        "*",
        "db-1 web-new",
        "-oProxyCommand=x",
    ];
    let (visited, printed) = visits(&sweep, &bin, &strangers);
    assert!(visited.is_empty(), "{visited:?}");
    for name in strangers {
        assert!(
            printed.contains(&format!(
                "Not visited: {name} is not a server this script visits.\n"
            )),
            "{printed}"
        );
    }
    assert!(printed.contains("Servers to visit: none"), "{printed}");

    put(&sweep, "skip.txt", "web-new\n");
    let (visited, printed) = visits(&sweep, &bin, &["web-new"]);
    assert!(visited.is_empty(), "{visited:?}");
    assert!(
        printed.contains("Not visited: web-new is listed in skip.txt.\n"),
        "{printed}"
    );
    assert_eq!(visits(&sweep, &bin, &["web-1"]).0, ["web-1"]);
}

#[test]
fn a_sweep_that_is_stopped_starts_no_further_visit() {
    // Stopping the sweep stops access to servers: the visits under way end on their own,
    // and no machine waiting its turn is visited after the script was told to stop.
    let h = Home::new("sweep-stop", Some(SSH_CONFIG_SEVEN), None);
    h.servers();
    let (sweep, bin) = (h.sweep(), h.dir.0.join("bin"));
    let log = h.dir.0.join("visited.log");
    fake_ssh(
        &bin,
        &format!(
            "echo \"$5\" >> '{}'\n/bin/sleep 1\necho '##end'",
            log.display()
        ),
    );
    let mut child = Command::new("/bin/sh")
        .arg(sweep.join("sweep.sh"))
        .env_clear()
        .env("PATH", &bin)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // Stopped once the first visit is under way.
    for _ in 0..200 {
        if log.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    ok(Command::new("/bin/kill").args(["-TERM", &child.id().to_string()]));
    child.wait().unwrap();
    // Long enough for the machines left to be visited, were anything still taking them.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    let visited = std::fs::read_to_string(&log).unwrap();
    assert!(visited.lines().count() < 7, "{visited}");
    let left: Vec<String> = std::fs::read_dir(&sweep)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// One entry of the threat catalogue in the shape CISA publishes. Ids, vendors and products
/// are invented.
fn kev_entry(id: &str, vendor: &str, product: &str, added: &str) -> serde_json::Value {
    serde_json::json!({
        "cveID": id,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": format!("{vendor} {product} Remote Code Execution Vulnerability"),
        "dateAdded": added,
        "shortDescription": format!("{vendor} {product} contains an invented flaw used only in tests."),
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
        "dueDate": "2099-02-01",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": format!("https://nvd.nist.gov/vuln/detail/{id}"),
        "cwes": ["CWE-94"]
    })
}

/// The whole catalogue with these entries.
fn kev(entries: &[serde_json::Value]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2099.01.10",
        "dateReleased": "2099-01-10T16:00:15.0000Z",
        "count": entries.len(),
        "vulnerabilities": entries
    }))
    .unwrap()
}

/// Three entries, and the same three with a fourth added on a later day.
fn kev_base() -> Vec<serde_json::Value> {
    vec![
        kev_entry(
            "CVE-2099-0002",
            "Invented Corp",
            "Pretend Server",
            "2099-01-05",
        ),
        kev_entry(
            "CVE-2099-0001",
            "Examplesoft",
            "Example Gateway",
            "2099-01-02",
        ),
        kev_entry(
            "CVE-2098-1234",
            "Nowhere Labs",
            "Imaginary VPN",
            "2098-12-30",
        ),
    ]
}

fn kev_plus_one() -> Vec<serde_json::Value> {
    let mut list = vec![kev_entry(
        "CVE-2099-0100",
        "Madeup Systems",
        "Fictional Router",
        "2099-01-09",
    )];
    list.extend(kev_base());
    list
}

const THREAT_EVENTS: &str = "SELECT entry, subject, old_value, new_value FROM journal
                             WHERE entry IN ('threat_added', 'threat_gone', 'threats_first_read')
                             ORDER BY seq";
const THREATS: &str = "SELECT id, gone_at IS NOT NULL FROM threat ORDER BY id";
const LAST_FEED_READING: &str = "SELECT outcome, reason IS NOT NULL, entries FROM feed_reading
                                 ORDER BY id DESC LIMIT 1";

/// A store fed the threat catalogue: from a saved copy, or from a fake curl.
struct Feed {
    dir: Dir,
}

impl Feed {
    fn new(tag: &str) -> Feed {
        Feed { dir: Dir::new(tag) }
    }

    fn store(&self) -> PathBuf {
        self.dir.0.join("store").join("store.db")
    }

    /// `soc run` with the brew sample and nothing else of the estate, and these arguments.
    fn run_with(&self, args: &[&std::ffi::OsStr]) -> String {
        self.run_as(soc_run(&self.dir.0, &self.store()), args)
    }

    fn run_as(&self, mut cmd: Command, args: &[&std::ffi::OsStr]) -> String {
        let brew = put(&self.dir.0, "brew.txt", SAMPLE);
        ok(cmd
            .arg("--brew-input")
            .arg(brew)
            .arg("--servers-input")
            .arg(self.dir.0.join("absent"))
            .arg("--checkouts-root")
            .arg(self.dir.0.join("absent"))
            .args(args))
    }

    /// `soc run` reading this catalogue from a saved copy.
    fn run(&self, catalogue: &str) -> String {
        let file = put(&self.dir.0, "kev.json", catalogue);
        self.run_with(&["--threats-input".as_ref(), file.as_os_str()])
    }

    /// `soc run` fetching the catalogue with this curl.
    fn run_curl(&self, curl: &Path) -> String {
        self.run_as(soc_run_curl(&self.dir.0, &self.store(), curl), &[])
    }
}

/// A curl that notes every argument it is given and answers as the catalogue's server does:
/// with `served.json` and the ETag in `etag`, or with 304 when it is asked with that ETag.
fn fake_curl(dir: &Path) -> PathBuf {
    let d = dir.display();
    script(
        &dir.join("curl"),
        &format!(
            r#"for a in "$@"; do printf '%s\n' "$a"; done >> '{d}/curl.log'
echo '--end--' >> '{d}/curl.log'
etag=$(cat '{d}/etag')
for a in "$@"; do
  if [ "$a" = "If-None-Match: $etag" ]; then printf '\n304 %s\n' "$etag" >&2; exit 0; fi
done
cat '{d}/served.json'
printf '\n200 %s\n' "$etag" >&2"#
        ),
    )
}

/// The argument lists the fake curl was given, one per request.
fn requests(dir: &Path) -> Vec<Vec<String>> {
    std::fs::read_to_string(dir.join("curl.log"))
        .unwrap_or_default()
        .split("--end--\n")
        .filter(|r| !r.is_empty())
        .map(|r| r.lines().map(str::to_string).collect())
        .collect()
}

/// The CVE ids the view marks as new.
fn marked_new(page: &str) -> Vec<String> {
    section(page, "threats")
        .split("<tr class=\"added\"><td class=\"mono\">")
        .skip(1)
        .map(|r| r.split(' ').next().unwrap().to_string())
        .collect()
}

#[test]
fn a_new_catalogue_entry_is_reported_as_new_exactly_once() {
    // A fresh exploited vulnerability is the news the owner reads the line for. Told twice,
    // the line stops meaning anything.
    let f = Feed::new("kev-new");
    f.run(&kev(&kev_base()));

    let second = f.run(&kev(&kev_plus_one()));
    let page = view(&f.store());
    let third = f.run(&kev(&kev_plus_one()));

    assert!(
        second
            .contains("CISA catalogue: 4 exploited vulnerabilities, 1 new since the last reading;"),
        "{second}"
    );
    assert_eq!(marked_new(&page), ["CVE-2099-0100"]);
    assert!(
        third
            .contains("CISA catalogue: 4 exploited vulnerabilities, 0 new since the last reading;"),
        "{third}"
    );
    assert!(marked_new(&view(&f.store())).is_empty());
    let added: Vec<String> = rows(&f.store(), THREAT_EVENTS)
        .into_iter()
        .filter(|r| r.starts_with("threat_added"))
        .collect();
    assert_eq!(
        added,
        [
            "threat_added|CVE-2099-0100|NULL|Madeup Systems Fictional Router Remote Code Execution Vulnerability"
        ]
    );
    // The raw copy is kept, and copied again only when it changed.
    let copies: Vec<_> = std::fs::read_dir(f.dir.0.join("store").join("raw"))
        .unwrap()
        .filter(|run| run.as_ref().unwrap().path().join("cisa-kev.json").exists())
        .collect();
    assert_eq!(copies.len(), 2);
}

#[test]
fn a_second_run_on_an_unchanged_catalogue_reports_nothing_new_and_does_not_download_it_again() {
    // The catalogue is fetched on every run; when it has not changed, the server says so and
    // nothing is downloaded, added or marked gone.
    let f = Feed::new("kev-unchanged");
    let curl = fake_curl(&f.dir.0);
    put(&f.dir.0, "served.json", &kev(&kev_base()));
    put(&f.dir.0, "etag", "\"v1\"");
    f.run_curl(&curl);
    let threats = rows(&f.store(), THREATS);

    let second = f.run_curl(&curl);

    let asked = requests(&f.dir.0);
    assert!(!asked[0].iter().any(|a| a.starts_with("If-None-Match")));
    assert!(
        asked[1].contains(&"If-None-Match: \"v1\"".to_string()),
        "{:?}",
        asked[1]
    );
    assert!(
        second.contains(
            "CISA catalogue: 3 exploited vulnerabilities, unchanged, 0 new since the last reading;"
        ),
        "{second}"
    );
    assert_eq!(rows(&f.store(), LAST_FEED_READING), ["unchanged|0|3"]);
    assert_eq!(rows(&f.store(), THREATS), threats);
    assert_eq!(rows(&f.store(), THREAT_EVENTS).len(), 1);
    // Both readings rest on the one raw copy, and the hash they record is its SHA-256.
    let kept = rows(
        &f.store(),
        "SELECT DISTINCT raw_path, sha256 FROM feed_reading",
    );
    assert_eq!(kept.len(), 1, "{kept:?}");
    let (raw, sha) = kept[0].split_once('|').unwrap();
    let shasum = ok(Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(f.dir.0.join("store").join(raw)));
    assert_eq!(shasum.split(' ').next(), Some(sha));
}

#[test]
fn the_first_reading_of_the_catalogue_is_a_baseline_and_not_a_flood_of_events() {
    // A thousand entries the first time are not a thousand pieces of news. A store that
    // could not read the catalogue before still takes its first reading as the baseline.
    let f = Feed::new("kev-baseline");
    let missing = f.dir.0.join("missing");
    let missing = ["--threats-input".as_ref(), missing.as_os_str()];
    f.run_with(&missing);
    let failed_again = f.run_with(&missing);
    assert!(
        failed_again.contains("the program knows no exploited vulnerability yet"),
        "{failed_again}"
    );

    let report = f.run(&kev(&kev_base()));

    assert!(
        report.contains(
            "CISA catalogue: 3 exploited vulnerabilities, first reading, kept as the baseline;"
        ),
        "{report}"
    );
    assert_eq!(
        rows(&f.store(), THREAT_EVENTS),
        ["threats_first_read|NULL|NULL|3"]
    );
    assert_eq!(rows(&f.store(), THREATS).len(), 3);
    let page = view(&f.store());
    assert!(marked_new(&page).is_empty());
    let threats = section(&page, "threats");
    let order: Vec<usize> = ["CVE-2099-0002", "CVE-2099-0001", "CVE-2098-1234"]
        .iter()
        .map(|id| threats.find(id).unwrap())
        .collect();
    assert!(order.is_sorted(), "newest first: {order:?}");
}

#[test]
fn a_catalogue_that_could_not_be_read_is_reported_as_not_read_and_adds_nothing_and_marks_nothing_gone()
 {
    // A failed download is not an empty catalogue: if it were, every threat would leave it,
    // and the line would say nothing is new when nothing is known.
    let f = Feed::new("kev-failed");
    f.run(&kev(&kev_base()));
    f.run(&kev(&kev_plus_one()));
    let threats = rows(&f.store(), THREATS);
    let curl = script(
        &f.dir.0.join("curl"),
        "echo 'curl: (6) Could not resolve host: www.cisa.gov' >&2\nprintf '\\n000 \\n' >&2\nexit 6",
    );

    let report = f.run_curl(&curl);

    assert!(
        report.contains(
            "CISA catalogue not read: curl failed, exit status: 6: curl: (6) Could not resolve host: www.cisa.gov; \
             what is new is unknown, and the 4 exploited vulnerabilities it held at its last reading"
        ),
        "{report}"
    );
    assert!(
        report.contains("are not matched against this estate yet"),
        "{report}"
    );
    assert_eq!(rows(&f.store(), THREATS), threats);
    assert_eq!(rows(&f.store(), THREAT_EVENTS).len(), 2);
    assert_eq!(rows(&f.store(), LAST_FEED_READING), ["failed|1|NULL"]);
    let page = view(&f.store());
    assert!(
        section(&page, "threats")
            .contains("The latest reading of the catalogue failed: curl failed"),
        "{page}"
    );
    // What was new when it was last read stays marked: nothing newer is known.
    assert_eq!(marked_new(&page), ["CVE-2099-0100"]);

    // A saved copy that is not there is the same.
    let report = f.run_with(&[
        "--threats-input".as_ref(),
        f.dir.0.join("missing").as_os_str(),
    ]);
    assert!(
        report.contains("CISA catalogue not read: cannot read"),
        "{report}"
    );
    assert_eq!(rows(&f.store(), THREATS), threats);
}

#[test]
fn an_answer_other_than_the_catalogue_or_not_modified_when_asked_is_a_failed_reading() {
    // "Not modified" is believed only in answer to the ETag the program sent; a redirect is
    // not followed. Either way nothing is known, and the line must not say otherwise.
    let f = Feed::new("kev-status");
    for (code, report) in [("304", "HTTP 304"), ("301", "HTTP 301")] {
        let curl = script(
            &f.dir.0.join(format!("curl-{code}")),
            &format!("printf '\\n{code} \"v9\"\\n' >&2"),
        );
        let said = f.run_curl(&curl);
        assert!(
            said.contains(&format!(
                "CISA catalogue not read: the server answered {report}; the program knows no exploited vulnerability yet"
            )),
            "{said}"
        );
    }
    assert!(rows(&f.store(), THREATS).is_empty());
}

#[test]
fn an_entry_that_left_the_catalogue_is_recorded_as_gone_and_kept() {
    // CISA withdraws entries now and then. One that left is an event, and is kept: an
    // investigation looks back.
    let f = Feed::new("kev-gone");
    f.run(&kev(&kev_plus_one()));

    let report = f.run(&kev(&kev_base()));

    assert!(
        report.contains(
            "3 exploited vulnerabilities, 0 new since the last reading, 1 left the catalogue;"
        ),
        "{report}"
    );
    assert_eq!(
        rows(&f.store(), THREATS),
        [
            "CVE-2098-1234|0",
            "CVE-2099-0001|0",
            "CVE-2099-0002|0",
            "CVE-2099-0100|1"
        ]
    );
    assert_eq!(
        rows(&f.store(), THREAT_EVENTS)[1],
        "threat_gone|CVE-2099-0100|Madeup Systems Fictional Router Remote Code Execution Vulnerability|NULL"
    );
    let page = view(&f.store());
    let left = section(&page, "threats")
        .split("left the catalogue and is kept")
        .nth(1)
        .unwrap_or_else(|| panic!("{page}"));
    assert!(left.contains("CVE-2099-0100"), "{left}");
    // What the catalogue holds no longer counts it, even when it cannot be read.
    let failed = f.run_with(&[
        "--threats-input".as_ref(),
        f.dir.0.join("missing").as_os_str(),
    ]);
    assert!(
        failed.contains("the 3 exploited vulnerabilities it held at its last reading"),
        "{failed}"
    );

    // One that comes back is in the catalogue again, and that is news.
    let back = f.run(&kev(&kev_plus_one()));
    assert!(back.contains("1 new since the last reading;"), "{back}");
    assert_eq!(rows(&f.store(), THREATS)[3], "CVE-2099-0100|0");
}

#[test]
fn a_catalogue_that_is_malformed_or_over_the_size_cap_is_a_failed_reading() {
    // The catalogue comes from the network and is untrusted. Whatever is not its shape, or
    // is too large to be it, changes nothing.
    let f = Feed::new("kev-malformed");
    f.run(&kev(&kev_base()));
    let threats = rows(&f.store(), THREATS);
    let mut no_id = kev_base();
    no_id[1]["cveID"] = serde_json::json!("CVE-2099-0001/../x");
    let over = format!("{}{}", kev(&kev_base()), " ".repeat(8 * 1024 * 1024));
    let cases = [
        ("<html>Service unavailable</html>", "not JSON"),
        ("{\"vulnerabilities\": {}}", "no list of vulnerabilities"),
        (
            "{\"vulnerabilities\": []}",
            "the list of vulnerabilities is empty",
        ),
        (&kev(&no_id), "entry 2 has no valid CVE id"),
        (&over, "larger than the cap of 8388608 bytes"),
    ];
    for (catalogue, reason) in cases {
        let report = f.run(catalogue);
        assert!(
            report.contains(&format!("CISA catalogue not read: {reason}")),
            "{reason}: {report}"
        );
        assert_eq!(rows(&f.store(), THREATS), threats, "{reason}");
        assert_eq!(rows(&f.store(), LAST_FEED_READING), ["failed|1|NULL"]);
    }
    // At the cap itself, the catalogue is read.
    let at_cap = kev(&kev_base());
    let at_cap = format!("{at_cap}{}", " ".repeat(8 * 1024 * 1024 - at_cap.len()));
    let report = f.run(&at_cap);
    assert!(
        report.contains("3 exploited vulnerabilities, 0 new"),
        "{report}"
    );
}

#[test]
fn what_is_asked_of_the_network_does_not_depend_on_the_estate() {
    // Every user sends the same request, so nothing about what they have leaks to the
    // catalogue's server or to anyone watching the line.
    let (a, b) = (Feed::new("kev-ask-a"), Feed::new("kev-ask-b"));
    for f in [&a, &b] {
        put(&f.dir.0, "served.json", &kev(&kev_base()));
        put(&f.dir.0, "etag", "W/\"5f2c-61a\"");
    }
    let servers = a.dir.0.join("servers");
    put(&servers, "web-1.txt", WEB_1);
    let busy = |f: &Feed| {
        let brew = put(&f.dir.0, "brew.txt", SAMPLE);
        ok(soc_run_curl(&f.dir.0, &f.store(), &fake_curl(&f.dir.0))
            .arg("--brew-input")
            .arg(brew)
            .arg("--servers-input")
            .arg(&servers)
            .arg("--checkouts-root")
            .arg(&f.dir.0))
    };
    let bare = |f: &Feed| {
        ok(soc_run_curl(&f.dir.0, &f.store(), &fake_curl(&f.dir.0))
            .args(["--machine-name", "another-mac", "--brew-input"])
            .arg(f.dir.0.join("absent"))
            .arg("--servers-input")
            .arg(f.dir.0.join("absent"))
            .arg("--checkouts-root")
            .arg(f.dir.0.join("absent")))
    };
    for _ in 0..2 {
        busy(&a);
        bare(&b);
    }

    let (asked_a, asked_b) = (requests(&a.dir.0), requests(&b.dir.0));
    assert_eq!(asked_a.len(), 2);
    assert_eq!(asked_a, asked_b);
    // Exactly this, and the conditional request adds only the ETag the catalogue sent.
    let asked: Vec<&str> = asked_a[0].iter().map(String::as_str).collect();
    assert_eq!(
        asked,
        [
            "--disable", // first, so that ~/.curlrc is never read
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--compressed",
            "--max-filesize",
            "8388608",
            "--connect-timeout",
            "30",
            "--max-time",
            "300",
            "--write-out",
            "%{stderr}\\n%{http_code} %header{etag}\\n",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ]
    );
    let again = &asked_a[1];
    assert_eq!(again.len(), asked.len() + 2);
    assert_eq!(
        again[again.len() - 3..again.len() - 1],
        ["--header", "If-None-Match: W/\"5f2c-61a\""]
    );
}

#[test]
fn text_from_the_catalogue_is_shown_escaped_and_kept_as_read() {
    // Names in the catalogue are text from the network: they must never become markup, and
    // a direction control must never reorder what the owner reads.
    let f = Feed::new("kev-escape");
    f.run(&kev(&kev_base()));
    let mut list = kev_base();
    list.push(kev_entry(
        "CVE-2099-0666",
        "<script>alert('x')</script>",
        "Gate\"way\u{202E}yawetag",
        "2099-01-10",
    ));

    let report = f.run(&kev(&list));
    let page = view(&f.store());

    assert!(
        !report.contains('\u{202E}') && !report.contains("<script"),
        "{report}"
    );
    let threats = section(&page, "threats");
    assert!(!threats.contains("<script") && !threats.contains('\u{202E}'));
    assert!(
        threats.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"),
        "{threats}"
    );
    assert!(
        threats.contains("<td>Gate&quot;way\\u{202e}yawetag</td>"),
        "{threats}"
    );
    assert_eq!(
        rows(
            &f.store(),
            "SELECT product FROM threat WHERE id = 'CVE-2099-0666'"
        ),
        ["Gate\"way\u{202E}yawetag"]
    );
}

#[test]
fn a_store_made_before_the_threat_list_takes_its_tables_and_journal_entries_without_losing_its_journal()
 {
    // The journal is the one thing raw input cannot rebuild. The owner's store, made before
    // the threat list, must take it as it is, in the same format.
    let f = Feed::new("kev-old-store");
    f.run_with(&[]);
    f.run_with(&[]);
    Connection::open(f.store())
        .unwrap()
        .execute_batch(
            "DROP TABLE threat;
             DROP TABLE feed_reading;
             CREATE TABLE journal_before (
                 seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                 run_id TEXT NOT NULL,
                 entry TEXT NOT NULL CHECK (entry IN ('run_started', 'added', 'changed',
                                                      'removed', 'report', 'run_finished',
                                                      'owner_said', 'owner_withdrew')),
                 reader TEXT, scope TEXT, kind TEXT, subject TEXT, predicate TEXT,
                 old_value TEXT, new_value TEXT, text TEXT);
             INSERT INTO journal_before SELECT * FROM journal;
             DROP TABLE journal;
             ALTER TABLE journal_before RENAME TO journal;
             CREATE TRIGGER journal_no_update BEFORE UPDATE ON journal
                 BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
             CREATE TRIGGER journal_no_delete BEFORE DELETE ON journal
                 BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;",
        )
        .unwrap();
    let all = "SELECT * FROM journal ORDER BY seq";
    let before = rows(&f.store(), all);
    // As it is, the store is read by the view.
    assert!(section(&view(&f.store()), "threats").contains("has never been read"));
    assert_eq!(rows(&f.store(), all), before);

    f.run(&kev(&kev_base()));
    f.run(&kev(&kev_plus_one()));

    let after = rows(&f.store(), all);
    assert_eq!(after[..before.len()], before[..]);
    let entries: Vec<&str> = after[before.len()..]
        .iter()
        .map(|r| r.split('|').nth(3).unwrap())
        .filter(|e| e.starts_with("threat"))
        .collect();
    assert_eq!(entries, ["threats_first_read", "threat_added"]);
    let seqs: Vec<i64> = rows(&f.store(), "SELECT seq FROM journal ORDER BY seq")
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
    assert_eq!(
        rows(
            &f.store(),
            "SELECT value FROM meta WHERE key = 'format_version'"
        ),
        ["4"]
    );
    let conn = Connection::open(f.store()).unwrap();
    assert!(conn.execute("DELETE FROM journal", []).is_err());
    assert!(conn.execute("UPDATE journal SET text = ''", []).is_err());
}

/// A server file as the current probe writes it, with the given os-release fields, owners of
/// the running kernel as `dpkg-query -S` prints them, package managers and dpkg rows as
/// `dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n'`
/// prints them. No docker.
fn server(os_release: &str, kernel_package: &str, managers: &str, dpkg: &str) -> String {
    format!(
        "##taken_at\n1767323045\n##os\nInvented Linux\n##os_release\n{os_release}##kernel\n\
         6.8.0-45-generic\n##kernel_package\n{kernel_package}##package_managers\n{managers}\
         ##reboot_required\nno\n##pve\n##dpkg_with_source\n{dpkg}##snap\n\
         ##docker_access\ndocker not installed\n##end\n"
    )
}

const UBUNTU: &str = "ID\tubuntu\nVERSION_ID\t24.04\nVERSION_CODENAME\tnoble\n";

/// Runs soc on these server files and returns the report line.
fn run_servers(dir: &Dir, files: &[(&str, &str)]) -> String {
    let servers = dir.0.join("servers");
    for (name, text) in files {
        put(&servers, &format!("{name}.txt"), text);
    }
    soc_all(
        &dir.store(),
        &dir.input("brew.txt", SAMPLE),
        &servers,
        &dir.0.join("absent"),
    )
}

/// Live assertions about one server and what is on it.
fn live_on(store: &Path, machine: &str) -> Vec<String> {
    rows(
        store,
        &format!(
            "SELECT subject, predicate, object FROM assertion WHERE layer = 'live'
             AND (subject = 'machine:{machine}'
                  OR subject LIKE 'component:machine:{machine}/%')
             AND predicate != 'known_as'
             ORDER BY subject, predicate, object"
        ),
    )
}

/// The latest reading of one kind on one server: completeness and reason.
fn reading_of(store: &Path, machine: &str, kind: &str) -> String {
    rows(
        store,
        &format!(
            "SELECT completeness, COALESCE(reason, '') FROM coverage
             WHERE scope = 'machine:{machine}' AND kind = '{kind}' ORDER BY id DESC LIMIT 1"
        ),
    )
    .join("")
}

#[test]
fn a_package_removed_and_not_purged_is_not_a_component_and_stops_being_one() {
    // dpkg lists a package whose files were removed and whose configuration was kept, and
    // one it knows as not installed. Counting either as present is a false alarm now and,
    // once matching runs, an answer about software that is not there. A package whose files
    // are on disk but not fully configured, or held, is there.
    let dir = Dir::new("removed");
    let store = dir.store();
    let dpkg = "\
ii \tcurl\t8.5.0-2ubuntu10.4\tcurl\t8.5.0-2ubuntu10.4
rc \tapache2\t2.4.58-1ubuntu8.4\tapache2\t2.4.58-1ubuntu8.4
un \tnano\t7.2-2build1\tnano\t7.2-2build1
iU \tvim\t2:9.1.0016-1ubuntu7.3\tvim\t2:9.1.0016-1ubuntu7.3
hi \tzlib1g\t1:1.3.dfsg-3.1ubuntu2.1\tzlib\t1:1.3.dfsg-3.1ubuntu2.1
";
    run_servers(&dir, &[("web", &server(UBUNTU, "", "dpkg\n", dpkg))]);
    let components = "SELECT DISTINCT subject FROM assertion WHERE layer = 'live'
                      AND predicate = 'part_of' AND subject LIKE '%machine:web/%'
                      ORDER BY subject";
    assert_eq!(
        rows(&store, components),
        [
            "component:machine:web/deb/curl",
            "component:machine:web/deb/vim",
            "component:machine:web/deb/zlib1g",
        ]
    );

    let removed = dpkg.replace("ii \tcurl", "rc \tcurl");
    let report = run_servers(&dir, &[("web", &server(UBUNTU, "", "dpkg\n", &removed))]);
    assert_eq!(
        rows(&store, components),
        [
            "component:machine:web/deb/vim",
            "component:machine:web/deb/zlib1g"
        ]
    );
    assert_eq!(
        rows(
            &store,
            "SELECT predicate, object FROM assertion WHERE layer = 'retracted'
             AND subject = 'component:machine:web/deb/curl' ORDER BY predicate"
        ),
        [
            "built_from|curl 8.5.0-2ubuntu10.4",
            "has_version|8.5.0-2ubuntu10.4",
            "part_of|machine:web"
        ]
    );
    assert!(report.contains("1 removed"), "{report}");
}

#[test]
fn a_component_carries_the_source_package_and_version_it_was_built_from() {
    // Distributions publish their security data by source package, and a binary package's
    // name and version can both differ from its source's: a rebuilt binary carries a `+b1`
    // its source does not. A package dpkg gives no source for is said to be unread, so that a
    // matcher never takes a missing source for a package nothing affects.
    let dir = Dir::new("sources");
    let store = dir.store();
    let dpkg = "\
ii \tlibssl3t64\t3.0.13-0ubuntu3.4\topenssl\t3.0.13-0ubuntu3.4
ii \tlibexpat1\t2.5.0-1+b1\texpat\t2.5.0-1
ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4
";
    let without = format!("{dpkg}ii \tmawk\t1.3.4.20240123-1build1\t\t\n");
    run_servers(
        &dir,
        &[
            ("a", &server(UBUNTU, "", "dpkg\n", dpkg)),
            ("b", &server(UBUNTU, "", "dpkg\n", &without)),
        ],
    );

    assert_eq!(
        rows(
            &store,
            "SELECT subject, object, substr(source_ref, instr(source_ref, 'servers/'))
             FROM assertion WHERE layer = 'live' AND predicate = 'built_from'
             AND subject LIKE '%machine:a/%' ORDER BY subject"
        ),
        [
            "component:machine:a/deb/bash|bash 5.2.21-2ubuntu4|servers/a.txt:20",
            "component:machine:a/deb/libexpat1|expat 2.5.0-1|servers/a.txt:19",
            "component:machine:a/deb/libssl3t64|openssl 3.0.13-0ubuntu3.4|servers/a.txt:18",
        ]
    );
    assert_eq!(reading_of(&store, "a", "system package sources"), "full|");
    assert_eq!(
        reading_of(&store, "b", "system package sources"),
        "partial|1 of the packages give no source"
    );
    // The package with no source is still a component.
    assert!(
        live_on(&store, "b").contains(&"component:machine:b/deb/mawk|part_of|machine:b".into())
    );
}

#[test]
fn a_machine_carries_its_exact_release_and_one_the_system_does_not_give_is_not_guessed() {
    // Security data is keyed by release: Ubuntu's by its version, Debian's by its code name.
    // The release is taken as the system gives it, next to the pretty name, which stays as
    // it was. A system that gives no version, as a rolling distribution does, has no release,
    // and that is a reading that read nothing, not a release made up from other fields.
    let dir = Dir::new("release");
    let store = dir.store();
    let dpkg = "ii \tbash\t5.2.15-2+b7\tbash\t5.2.15-2\n";
    run_servers(
        &dir,
        &[
            ("noble", &server(UBUNTU, "", "dpkg\n", dpkg)),
            (
                "bookworm",
                &server("ID\tdebian\nVERSION_ID\t12\n", "", "dpkg\n", dpkg),
            ),
            ("rolling", &server("ID\tarch\n", "", "pacman\n", "")),
        ],
    );

    let release = "SELECT subject, predicate, object FROM assertion WHERE layer = 'live'
                   AND predicate IN ('runs_release', 'release_codename', 'runs_os')
                   ORDER BY subject, predicate";
    assert_eq!(
        rows(&store, release),
        [
            "machine:bookworm|runs_os|Invented Linux",
            "machine:bookworm|runs_release|debian 12",
            "machine:noble|release_codename|noble",
            "machine:noble|runs_os|Invented Linux",
            "machine:noble|runs_release|ubuntu 24.04",
        ]
    );
    assert_eq!(reading_of(&store, "noble", "system release"), "full|");
    assert_eq!(
        reading_of(&store, "rolling", "system release"),
        "none|the system does not give VERSION_ID"
    );
}

#[test]
fn the_package_that_owns_the_running_kernel_is_recorded_and_a_kernel_no_package_owns_records_nothing()
 {
    // Which package the running kernel came from is what its vulnerabilities are matched
    // against; it is asked of dpkg, never built from the kernel's name. A kernel no package
    // owns, such as one the hosting provider boots, has no package, and a diversion line
    // names none.
    let dir = Dir::new("kernel-package");
    let store = dir.store();
    let dpkg = "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n";
    let image = "linux-image-6.8.0-45-generic: /boot/vmlinuz-6.8.0-45-generic\n";
    let modules = "\
diversion by invented-divert from: /lib/modules/6.8.0-45-generic
linux-modules-6.8.0-45-generic, linux-modules-extra-6.8.0-45-generic: /lib/modules/6.8.0-45-generic
";
    run_servers(
        &dir,
        &[
            ("image", &server(UBUNTU, image, "dpkg\n", dpkg)),
            ("modules", &server(UBUNTU, modules, "dpkg\n", dpkg)),
            ("provider", &server(UBUNTU, "", "dpkg\n", dpkg)),
        ],
    );

    assert_eq!(
        rows(
            &store,
            "SELECT subject, object FROM assertion WHERE layer = 'live'
             AND predicate = 'runs_kernel_package' ORDER BY subject, object"
        ),
        [
            "machine:image|linux-image-6.8.0-45-generic",
            "machine:modules|linux-modules-6.8.0-45-generic",
            "machine:modules|linux-modules-extra-6.8.0-45-generic",
        ]
    );
    assert_eq!(
        reading_of(&store, "provider", "running kernel package"),
        "full|"
    );
}

#[test]
fn a_server_whose_package_manager_the_program_cannot_read_is_a_reading_that_read_nothing_naming_it()
{
    // A server without dpkg has an empty dpkg list. Taken as a full reading it would say the
    // server has nothing installed, and every answer about it would be calm. The manager the
    // program has no reader for is named. Next to dpkg, another manager's packages are not
    // read, so what dpkg lists is not all there is.
    let dir = Dir::new("no-reader");
    let store = dir.store();
    let fedora = "ID\tfedora\nVERSION_ID\t40\n";
    let dpkg = "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n";
    run_servers(
        &dir,
        &[
            ("rpm", &server(fedora, "", "rpm\n", "")),
            (
                "unknown",
                &server("ID\tinvented\nVERSION_ID\t1\n", "", "", ""),
            ),
            ("both", &server(UBUNTU, "", "dpkg\nrpm\n", dpkg)),
            (
                "empty",
                &server(UBUNTU, "", "dpkg\n", "rc \tnano\t7.2-2\tnano\t7.2-2\n"),
            ),
            (
                "nolist",
                &server(UBUNTU, "", "dpkg\n", "").replace("##dpkg_with_source\n", ""),
            ),
        ],
    );

    let no_reader = "none|the program has no reader for the package manager this server uses: rpm";
    for kind in [
        "system packages",
        "system package sources",
        "running kernel package",
    ] {
        assert_eq!(reading_of(&store, "rpm", kind), no_reader, "{kind}");
    }
    assert_eq!(
        reading_of(&store, "unknown", "system packages"),
        "none|the server has none of the package managers the probe looks for"
    );
    // What does not depend on the package manager is still read.
    assert_eq!(reading_of(&store, "rpm", "system release"), "full|");
    assert_eq!(
        live_on(&store, "rpm"),
        ["machine:rpm|runs_release|fedora 40"]
    );
    // dpkg that lists nothing installed is a list that failed, not an empty server.
    assert_eq!(
        reading_of(&store, "empty", "system packages"),
        "none|the package list is empty"
    );
    assert_eq!(
        reading_of(&store, "nolist", "system packages"),
        "none|the sweep has no package list"
    );
    let partial = "partial|only dpkg is read; packages of rpm are not";
    assert_eq!(reading_of(&store, "both", "system packages"), partial);
    assert_eq!(
        reading_of(&store, "both", "system package sources"),
        partial
    );
}

/// The lines of the probe from the one that starts with `from` to the one that starts with
/// `to`, both included.
fn probe_part(from: &str, to: &str) -> String {
    let probe =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/probe.sh")).unwrap();
    let lines: Vec<&str> = probe.lines().collect();
    let start = lines.iter().position(|l| l.starts_with(from)).unwrap();
    let end = start
        + lines[start..]
            .iter()
            .position(|l| l.starts_with(to))
            .unwrap();
    lines[start..=end]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect()
}

#[test]
fn os_release_is_read_as_text_and_never_run() {
    // The probe runs on the owner's servers. os-release is written in shell syntax, and a
    // probe that sources it runs whatever the file holds. The part of the probe that reads
    // it is run here against a prepared file; the probe is never run against a server.
    let dir = Dir::new("os-release");
    let marker = dir.0.join("ran");
    let file = put(
        &dir.0,
        "os-release",
        &format!(
            "\
# An invented os-release.
NAME=\"Ubuntu\"
PRETTY_NAME=\"Ubuntu 24.04.1 LTS \\\"x\\\" \\$HOME \\`id\\` a\\\\b\"
VERSION_ID=\"24.04\"
ID=ubuntu
VERSION_CODENAME='noble'
ID_LIKE=debian$(touch '{m}')
HOME_URL=`touch '{m}'`
",
            m = marker.display()
        ),
    );
    // The file would run a command if it were executed.
    ok(Command::new("/bin/sh")
        .arg("-c")
        .arg(". \"$1\"")
        .arg("sh")
        .arg(&file));
    assert!(
        marker.exists(),
        "the prepared file runs nothing when sourced"
    );
    std::fs::remove_file(&marker).unwrap();

    let part = probe_part("F=/etc/os-release", "echo \"##os_release\"");
    let expected = "##os\nUbuntu 24.04.1 LTS \"x\" $HOME `id` a\\b\n##os_release\n\
                    ID\tubuntu\nVERSION_ID\t24.04\nVERSION_CODENAME\tnoble";
    let file = file.display().to_string();
    let printed = ok(Command::new("/bin/sh")
        .arg("-c")
        .arg(part.replace("/etc/os-release", &file)));
    assert!(!marker.exists(), "reading os-release ran a command from it");
    assert_eq!(printed, expected);
    // A system that keeps the file only in /usr/lib, as the format allows, is read the same.
    let missing = dir.0.join("missing").display().to_string();
    let printed = ok(Command::new("/bin/sh").arg("-c").arg(
        part.replace("/etc/os-release", &missing)
            .replace("/usr/lib/os-release", &file),
    ));
    assert_eq!(printed, expected);
}

#[test]
fn the_probe_is_plain_posix_sh() {
    // The probe runs with whatever `sh` a server has, often dash. A syntax error there is a
    // server that is never read.
    let probe = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/probe.sh");
    for sh in ["/bin/sh", "/bin/dash"] {
        if Path::new(sh).exists() {
            ok(Command::new(sh).arg("-n").arg(probe));
        }
    }
}

#[test]
fn the_release_the_source_and_the_kernel_package_are_shown_under_the_machine_escaped() {
    // What a server prints is partly written by whoever controls it.
    let dir = Dir::new("view-new-facts");
    let store = dir.store();
    let dpkg = "ii \tlibexpat1\t2.5.0-1+b1\t<i>expat</i>\t2.5.0-1\n";
    let release = "ID\t<b>x</b>\nVERSION_ID\t1\"2\nVERSION_CODENAME\t<u>c</u>\n";
    let kernel = "<script>k</script>: /boot/vmlinuz-6.8.0-45-generic\n";
    run_servers(&dir, &[("web", &server(release, kernel, "dpkg\n", dpkg))]);
    let page = view(&store);
    let web = machine_block(&page, "web");

    for shown in [
        "&lt;b&gt;x&lt;/b&gt; 1&quot;2",
        "(&lt;u&gt;c&lt;/u&gt;)",
        "&lt;script&gt;k&lt;/script&gt;",
        "&lt;i&gt;expat&lt;/i&gt; 2.5.0-1",
    ] {
        assert!(
            web.contains(shown),
            "{shown} is not under the machine: {web}"
        );
    }
    for raw in ["<b>", "<u>", "<script", "<i>"] {
        assert!(!page.contains(raw), "{raw} reached the page");
    }
}

/// Fake `uname`, `dpkg`, `rpm` and `dpkg-query` for running parts of the probe here.
/// `dpkg-query -S` says `$OWNER` owns `$OWNS` and nothing else; `dpkg-query -W -f=<format>`
/// fills the format as dpkg does for an invented database of three packages, one of them
/// removed and not purged.
fn fake_dpkg(bin: &Path) {
    script(&bin.join("uname"), "echo 6.8.0-45-generic");
    script(&bin.join("dpkg"), "exit 0");
    script(&bin.join("rpm"), "exit 0");
    script(
        &bin.join("dpkg-query"),
        r#"if [ "$1" = -S ]; then
  [ -n "$OWNS" ] && [ "$2" = "$OWNS" ] && { echo "$OWNER: $2"; exit 0; }
  echo "dpkg-query: no path found matching pattern $2" >&2; exit 1
fi
[ "$1" = -W ] || exit 2
fmt=${2#-f=}
printf '%s\n' 'ii |libexpat1|2.5.0-1+b1|expat|2.5.0-1' 'rc |apache2|2.4.58-1|apache2|2.4.58-1' \
  'ii |linux-image-6.8.0-45-generic|6.8.0-45.45|linux-signed|6.8.0-45.45' |
while IFS='|' read -r st p v sp sv; do
  line=$(printf '%s' "$fmt" | sed -e "s/\${db:Status-Abbrev}/$st/g" -e "s/\${Package}/$p/g" \
    -e "s/\${Version}/$v/g" -e "s/\${source:Package}/$sp/g" -e "s/\${source:Version}/$sv/g")
  printf "$line"
done"#,
    );
}

#[test]
fn the_probe_asks_dpkg_which_package_owns_the_running_kernel_and_the_reader_reads_what_it_prints() {
    // The kernel's package is asked of dpkg for the kernel's own image, then its modules
    // folder, wherever the system keeps them; a kernel no package owns prints nothing, not
    // even to stderr. What
    // the probe prints from dpkg is what the reader reads: the parts of the probe run here
    // against fake tools, never against a server, and their output goes through `soc run`.
    let dir = Dir::new("probe-dpkg");
    let bin = dir.0.join("bin");
    fake_dpkg(&bin);
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let run = |part: &str, owns: &str| {
        // A part's last command may fail, as it may in the probe, which goes on. Nothing may
        // reach stderr: the sweep keeps its last line as the reason a failed visit failed.
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("{part}true"))
            .env("PATH", &path)
            .env("OWNS", owns)
            .env("OWNER", "linux-image-6.8.0-45-generic")
            .output()
            .unwrap();
        assert!(out.status.success() && out.stderr.is_empty(), "{out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let kernel = probe_part("echo \"##kernel_package\"", "command -v dpkg-query");
    for owns in [
        "/boot/vmlinuz-6.8.0-45-generic",
        "/lib/modules/6.8.0-45-generic",
        "/usr/lib/modules/6.8.0-45-generic",
    ] {
        assert_eq!(
            run(&kernel, owns),
            format!("##kernel_package\nlinux-image-6.8.0-45-generic: {owns}")
        );
    }
    assert_eq!(run(&kernel, ""), "##kernel_package");

    let managers = probe_part("echo \"##package_managers\"", "echo \"##package_managers\"");
    assert_eq!(run(&managers, ""), "##package_managers\ndpkg\nrpm");

    let dpkg = probe_part("echo \"##dpkg_with_source\"", "echo \"##dpkg_with_source\"");
    let file = format!(
        "{}\n##package_managers\ndpkg\n{}\n##end\n",
        run(&kernel, "/boot/vmlinuz-6.8.0-45-generic"),
        run(&dpkg, "")
    );
    run_servers(&dir, &[("web", &file)]);
    assert_eq!(
        live_on(&dir.store(), "web"),
        [
            "component:machine:web/deb/libexpat1|built_from|expat 2.5.0-1",
            "component:machine:web/deb/libexpat1|has_version|2.5.0-1+b1",
            "component:machine:web/deb/libexpat1|part_of|machine:web",
            "component:machine:web/deb/linux-image-6.8.0-45-generic|built_from|linux-signed 6.8.0-45.45",
            "component:machine:web/deb/linux-image-6.8.0-45-generic|has_version|6.8.0-45.45",
            "component:machine:web/deb/linux-image-6.8.0-45-generic|part_of|machine:web",
            "machine:web|runs_kernel_package|linux-image-6.8.0-45-generic",
        ]
    );
}
