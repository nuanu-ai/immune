//! Promises of the first working whole: store, the brew reader, the lifecycle, the report
//! and the view.
//! Each test runs the real binary on a sample in the format `brew list --versions` prints.

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

/// Runs soc and returns the report line.
fn soc(store: &Path, input: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_soc"))
        .arg("run")
        .arg("--store")
        .arg(store)
        .arg("--brew-input")
        .arg(input)
        .output()
        .unwrap();
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
    assert!(first.ends_with("First run."), "{first}");

    let second = soc(&dir.store(), &input);
    assert_eq!(
        second,
        "mac: 6 components (brew). Since last run: no changes."
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
            "SELECT completeness FROM coverage ORDER BY id DESC LIMIT 1"
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
        report.ends_with("+0 added, 0 changed, 1 removed."),
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
        report.ends_with("+0 added, 1 changed, 0 removed."),
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
        "SELECT reason FROM coverage ORDER BY id DESC LIMIT 1",
    );
    let page = view(&store);

    let coverage = section(&page, "coverage");
    let row = coverage
        .split("<tr")
        .find(|r| r.contains("machine:mac") && r.contains("brew packages"))
        .expect("no coverage row for the brew reading");
    assert!(row.contains("nothing read"), "{row}");
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
