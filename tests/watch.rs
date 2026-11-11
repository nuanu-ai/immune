//! Promises of `soc watch`, the watcher on file-system events. Each test runs the real binary
//! against the real FSEvents on an invented Mac: a temporary home folder and a temporary system
//! root, never the real watched places. Waits are for a line the watcher prints, with a
//! generous timeout. Where a test must show that something did not happen, it makes one more
//! change and waits for that, or, where it cannot, sleeps a fixed time and says why so long.

use rusqlite::Connection;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a test waits for a line it expects.
const WAIT: Duration = Duration::from_secs(30);

/// An invented Mac: a home folder, a system root and a store folder, all temporary.
struct Mac {
    root: PathBuf,
}

impl Mac {
    fn new(tag: &str) -> Mac {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("soc-watch-{tag}-{}-{nanos}", std::process::id()));
        for dir in ["home", "sys/etc", "store"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        Mac { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn sys(&self) -> PathBuf {
        self.root.join("sys")
    }

    fn store(&self) -> PathBuf {
        self.root.join("store/store.db")
    }

    /// Writes a file under the home folder, making the folders on the way.
    fn put(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.home().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    fn soc(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_soc"));
        cmd.env("HOME", self.home()).current_dir(self.home());
        cmd
    }

    /// `soc run` on this Mac for the machine `mac`, asking nothing outside it.
    fn run_cmd(&self) -> Command {
        self.run_cmd_servers(&self.root.join("absent"))
    }

    /// `soc run` as above, reading the servers' files in `servers`.
    fn run_cmd_servers(&self, servers: &std::path::Path) -> Command {
        let absent = self.root.join("absent");
        let mut cmd = self.soc();
        cmd.args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--brew-input")
            .arg(self.root.join("brew.json"))
            .arg("--servers-input")
            .arg(servers)
            .arg("--tailscale")
            .arg(&absent)
            .arg("--threats-input")
            .arg(&absent)
            .arg("--system-root")
            .arg(self.sys());
        cmd
    }

    fn run(&self) {
        let out = self.run_cmd().output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn watch_cmd(&self) -> Command {
        let mut cmd = self.soc();
        cmd.args(["watch", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.sys());
        cmd
    }

    fn watch(&self) -> Watcher {
        Watcher::start(self.watch_cmd())
    }

    fn status(&self) -> Value {
        let out = self
            .soc()
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn rows(&self, sql: &str) -> Vec<String> {
        let conn = Connection::open(self.store()).unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The predicates of the journal's entries of one kind about one watched file, on
    /// whichever machine the store holds.
    fn journaled(&self, rel: &str, entry: &str) -> Vec<String> {
        self.rows(&format!(
            "SELECT predicate FROM journal
             WHERE entry = '{entry}' AND subject LIKE 'file:machine:%'
               AND substr(subject, -length('/{rel}')) = '/{rel}'
             ORDER BY seq"
        ))
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A running `soc watch` and every line it printed so far.
struct Watcher {
    child: Child,
    rx: mpsc::Receiver<Value>,
    seen: Vec<Value>,
}

impl Watcher {
    fn start(mut cmd: Command) -> Watcher {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let line = line.unwrap();
                let v: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|_| panic!("not one JSON object on a line: {line}"));
                if tx.send(v).is_err() {
                    return;
                }
            }
        });
        Watcher {
            child,
            rx,
            seen: Vec::new(),
        }
    }

    /// Waits for the next line of this event that `pick` accepts, keeping every line.
    fn until(&mut self, event: &str, pick: impl Fn(&Value) -> bool) -> Value {
        let end = Instant::now() + WAIT;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            let v = self
                .rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no {event} line in {WAIT:?}; saw {:?}", self.seen));
            self.seen.push(v.clone());
            if v["event"] == event && pick(&v) {
                return v;
            }
        }
    }

    fn next(&mut self, event: &str) -> Value {
        self.until(event, |_| true)
    }

    /// The `read` line after the watcher subscribed, made at its first start.
    fn started(mut self) -> Watcher {
        self.next("watching");
        self.next("read");
        self
    }

    /// Every line of this event printed so far, those not yet waited for included.
    fn lines(&mut self, event: &str) -> Vec<&Value> {
        while let Ok(v) = self.rx.try_recv() {
            self.seen.push(v);
        }
        self.seen.iter().filter(|v| v["event"] == event).collect()
    }

    fn signal(&self, signal: i32) {
        // SAFETY: kill(2) on the watcher's own pid.
        assert_eq!(unsafe { libc::kill(self.child.id() as i32, signal) }, 0);
    }

    /// Waits for the watcher to exit, and returns how.
    fn exit(&mut self) -> ExitStatus {
        let end = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < end, "the watcher did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop(mut self) -> ExitStatus {
        self.signal(libc::SIGTERM);
        self.exit()
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs a command that must end within the wait, and returns what it printed.
fn within(cmd: &mut Command) -> std::process::Output {
    finish(spawn(cmd))
}

fn spawn(cmd: &mut Command) -> Child {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Waits for a command that must end within the wait, and returns what it printed. Its
/// output is small enough for the pipes, so it cannot block on them.
fn finish(mut child: Child) -> std::process::Output {
    let end = Instant::now() + WAIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > end {
            child.kill().unwrap();
            panic!("it did not end");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// Kills a process when dropped, so that a test that fails leaves no watcher behind. Forgotten
/// once the process is known to have ended.
struct Reap(i32);

impl Drop for Reap {
    fn drop(&mut self) {
        // SAFETY: kill(2) on a process this test started.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
    }
}

fn count(v: &Value, change: &str) -> u64 {
    v[change].as_u64().unwrap()
}

#[test]
fn a_file_changed_in_a_watched_place_is_a_changed_event_within_seconds_and_the_read_line_says_so() {
    let mac = Mac::new("changed");
    mac.put(".zshrc", "export A=1\n");
    let mut w = mac.watch().started();
    let written = Instant::now();
    mac.put(".zshrc", "export A=2\n");
    let read = w.until("read", |v| count(v, "changed") == 1);
    assert!(written.elapsed() < Duration::from_secs(10), "read too late");
    assert_eq!((count(&read, "new"), count(&read, "gone")), (0, 0));
    assert_eq!(mac.journaled(".zshrc", "changed"), vec!["has_content"]);
    // The change is the store's: `soc status` lists it after a full run, under the
    // watcher's reading.
    drop(w);
    mac.run();
    let changes = &mac.status()["result"]["watched"]["changes"];
    assert_eq!(changes[0]["path_text"], ".zshrc");
    assert_eq!(changes[0]["change"], "changed");
    assert!(changes[0]["run_id"].as_str().unwrap().starts_with("watch-"));
}

#[test]
fn a_change_the_watcher_sees_is_an_open_finding_at_once_and_its_read_line_counts_as_status_does() {
    // The app learns of a change from the `read` line and then shows `soc status --json`:
    // with no full run in between, the finding is there and both give the same number.
    let mac = Mac::new("finding");
    mac.put(".zshrc", "export A=1\n");
    let mut w = mac.watch().started();
    mac.put(".zshrc", "export A=2\n");
    let read = w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(count(&read, "opened"), 1);
    assert!(
        mac.rows("SELECT run_id FROM journal WHERE entry = 'run_started'")
            .is_empty()
    );
    let result = mac.status()["result"].clone();
    assert_eq!(read["needs_a_look_total"], result["needs_a_look_total"]);
    let items = result["needs_a_look"].as_array().unwrap();
    let found = items
        .iter()
        .find(|i| i["rule"] == "watched.shell-profile")
        .unwrap_or_else(|| panic!("{result}"));
    assert_eq!(
        (found["state"].clone(), found["urgent"].clone()),
        ("open".into(), false.into())
    );
    // A reading that opens nothing says so, and the count does not move.
    mac.put(".zshrc", "export A=2\n# the same finding, still open\n");
    let again = w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(count(&again, "opened"), 0);
    assert_eq!(again["needs_a_look_total"], read["needs_a_look_total"]);
}

#[test]
fn a_watchers_reading_shows_in_the_view_as_what_it_is_and_not_as_a_run_that_did_not_finish() {
    // The owner reads the list of changes: a watcher's reading never writes `run_finished`,
    // and calling it unfinished would say its changes are unknown when they are known. Nor
    // is a server it never reads "not read in this run": it is not a run of every reader.
    let mac = Mac::new("view");
    mac.put(".zshrc", "one\n");
    let servers = mac.root.join("servers");
    std::fs::create_dir_all(&servers).unwrap();
    std::fs::write(servers.join("web-1.txt"), "##end\n").unwrap();
    assert!(
        mac.run_cmd_servers(&servers)
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut w = mac.watch().started();
    mac.put(".zshrc", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    drop(w);
    let out = within(
        mac.soc()
            .args(["view", "--no-open", "--store"])
            .arg(mac.store()),
    );
    assert!(out.status.success());
    let pages: String = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|path| std::fs::read_to_string(path).unwrap())
        .collect();
    assert!(!pages.contains("did not finish"), "{pages}");
    let shown = "watcher&#39;s reading of the watched places: +0 added, 1 changed, 0 removed";
    assert!(pages.contains(shown), "{pages}");
    assert!(!pages.contains("were not read in this run"), "{pages}");
}

#[test]
fn a_first_file_created_in_a_folder_that_did_not_exist_at_start_is_seen() {
    // The first autostart item ever made: neither the folder nor its parent is there.
    let mac = Mac::new("later");
    let mut w = mac.watch().started();
    mac.put("Library/LaunchAgents/com.example.agent.plist", "<plist/>\n");
    let read = w.until("read", |v| count(v, "new") == 1);
    assert_eq!(count(&read, "changed"), 0);
    assert_eq!(
        mac.journaled("Library/LaunchAgents/com.example.agent.plist", "added"),
        vec!["located_on", "watched_as", "has_content"]
    );
    // And when it goes, it is gone.
    std::fs::remove_file(
        mac.home()
            .join("Library/LaunchAgents/com.example.agent.plist"),
    )
    .unwrap();
    let read = w.until("read", |v| count(v, "gone") == 1);
    assert_eq!((count(&read, "new"), count(&read, "changed")), (0, 0));
}

#[test]
fn an_atomic_replace_is_seen() {
    // Editors and installers write a temporary file and rename it over the old one.
    let mac = Mac::new("atomic");
    mac.put(".ssh/config", "Host a\n");
    let mut w = mac.watch().started();
    let tmp = mac.put(".ssh/.config.tmp-123", "Host b\n");
    std::fs::rename(&tmp, mac.home().join(".ssh/config")).unwrap();
    w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(mac.journaled(".ssh/config", "changed"), vec!["has_content"]);
}

#[test]
fn a_thousand_changes_are_one_reading() {
    let mac = Mac::new("burst");
    let mut w = mac.watch().started();
    for i in 0..1000 {
        mac.put(
            &format!("Library/LaunchAgents/item-{i}.plist"),
            "<plist/>\n",
        );
    }
    let burst = w.next("read");
    assert_eq!(count(&burst, "new"), 1000);
    // One more change: had the burst made a second reading, its line would come first.
    mac.put(".zprofile", "a\n");
    let after = w.next("read");
    assert_eq!((count(&after, "new"), count(&after, "changed")), (1, 0));
    assert_eq!(w.lines("read").len(), 3);
}

#[test]
fn a_change_made_while_the_watcher_was_stopped_is_read_when_it_starts_again() {
    let mac = Mac::new("replay");
    mac.put(".zshrc", "one\n");
    let w = mac.watch().started();
    assert!(w.stop().success());
    mac.put(".zshrc", "two\n");
    let mut w = mac.watch();
    w.next("watching");
    w.until("read", |v| count(v, "changed") == 1);
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    assert!(w.stop().success());

    // Nothing changed while it was stopped: the history says so and nothing is read. The
    // first reading after the restart is the one a new change brings.
    let mut w = mac.watch();
    w.next("watching");
    // A reading the replay brought would come before the change. The replay is delivered at
    // once after `watching`, then 0.2 s of event latency and the 1 s quiet period; measured, it
    // reads about 1.1 s after start. Three seconds is that with room for a loaded machine.
    std::thread::sleep(Duration::from_secs(3));
    mac.put(".zshrc", "three\n");
    let first = w.next("read");
    assert_eq!(count(&first, "changed"), 1);
    assert!(w.lines("problem").is_empty());
}

#[test]
fn a_stored_event_id_that_cannot_be_used_is_said_and_everything_is_read_once() {
    let mac = Mac::new("unusable");
    mac.put(".zshrc", "one\n");
    assert!(mac.watch().started().stop().success());
    // An id ahead of this Mac's own, as after the store was moved from another Mac.
    let conn = Connection::open(mac.store()).unwrap();
    conn.execute("UPDATE watcher SET event_id = '18446744073709551614'", [])
        .unwrap();
    drop(conn);
    mac.put(".zshrc", "two\n");
    let mut w = mac.watch();
    w.next("watching");
    let problem = w.next("problem");
    assert_eq!(problem["code"], "history_unusable");
    w.until("read", |v| count(v, "changed") == 1);
    assert!(w.stop().success());

    // A history that is not the one the id belongs to, as after it was purged.
    let conn = Connection::open(mac.store()).unwrap();
    conn.execute("UPDATE watcher SET volumes = '0123456789abcdef'", [])
        .unwrap();
    drop(conn);
    mac.put(".zshrc", "three\n");
    let mut w = mac.watch();
    w.next("watching");
    assert_eq!(w.next("problem")["code"], "history_unusable");
    w.until("read", |v| count(v, "changed") == 1);
}

#[test]
fn a_full_run_holding_the_store_is_waited_for_and_both_finish() {
    let mac = Mac::new("together");
    mac.put(".zshrc", "0\n");
    mac.run();
    let mut w = mac.watch().started();

    // A run in progress holds the run lock; the watcher's reading waits for it.
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    mac.put(".zshrc", "held\n");
    // A watcher that ignored the lock would read 1.2 s after the write (latency and quiet
    // period), at most 5 s with the longest wait for quiet; measured, 1.1 to 1.3 s. Four
    // seconds is three times that, short enough to keep the test quick.
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(w.lines("read").len(), 1, "read while a run held the store");
    let released = Instant::now();
    folder.unlock().unwrap();
    w.until("read", |v| count(v, "changed") == 1);
    assert!(released.elapsed() < Duration::from_secs(10));

    // Real full runs started while the watcher reads: each finishes, and each change is
    // recorded once, by whichever read it first.
    for round in 1..=3 {
        mac.put(".zshrc", &format!("round {round}\n"));
        // Just under the 1.2 s after which the watcher reads, so that the full run starts
        // about when the watcher's reading does and the two meet at the lock.
        std::thread::sleep(Duration::from_millis(900));
        let run = mac.run_cmd().output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        w.next("read");
    }
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    assert_eq!(mac.journaled(".zshrc", "changed").len(), 4);
    assert!(mac.status()["ok"].as_bool().unwrap());
}

#[test]
fn an_hourly_full_run_is_not_lost_to_a_long_reading_of_the_watcher() {
    // The app's timer starts a full run every hour; a watcher's reading of many changed
    // files can hold the run lock longer than the 2 s a run waits for another run. While a
    // watcher runs, a full run waits that out. The test holds the lock as such a reading.
    let mac = Mac::new("long");
    mac.run();
    let mut w = mac.watch().started();
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    let run = spawn(&mut mac.run_cmd());
    // Past the 2 s a full run waits when no watcher runs, with a second to spare.
    std::thread::sleep(Duration::from_secs(3));
    folder.unlock().unwrap();
    assert!(finish(run).status.success());
    // With the watcher gone, the same holding stops a full run with "in progress".
    assert!(w.lines("problem").is_empty());
    drop(w);
    folder.lock().unwrap();
    assert_eq!(within(&mut mac.run_cmd()).status.code(), Some(4));
}

#[test]
fn a_watcher_started_while_a_full_run_holds_the_store_starts_and_reads_once_the_run_ends() {
    // What a full run in progress holds: the run lock and a write transaction. The watcher
    // must neither fail with "database is locked" nor write around them.
    let mac = Mac::new("busy");
    mac.put(".zshrc", "0\n");
    mac.run();
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    let conn = Connection::open(mac.store()).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut w = mac.watch();
    w.next("watching");
    conn.execute_batch("COMMIT").unwrap();
    folder.unlock().unwrap();
    w.next("read");
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
}

#[test]
fn sigterm_and_sigint_stop_it_with_exit_0_and_leave_the_store_consistent() {
    let mac = Mac::new("stop");
    mac.put(".zshrc", "one\n");
    let w = mac.watch().started();
    // Stopped right after a write, before or during the reading it brings.
    mac.put(".zshrc", "two\n");
    let status = w.stop();
    assert_eq!(status.code(), Some(0));
    assert_eq!(mac.rows("PRAGMA integrity_check"), vec!["ok"]);

    let mut w = mac.watch();
    w.next("watching");
    mac.put(".zprofile", "sentinel\n");
    w.until("read", |v| count(v, "new") == 1);
    // The change made before the stop is in the store once, whoever read it.
    assert_eq!(mac.journaled(".zshrc", "changed"), vec!["has_content"]);
    w.signal(libc::SIGINT);
    assert_eq!(w.exit().code(), Some(0));
}

#[test]
fn a_second_watcher_on_one_store_refuses_to_start_and_the_first_keeps_watching() {
    let mac = Mac::new("second");
    let mut first = mac.watch().started();
    let out = within(&mut mac.watch_cmd());
    assert_eq!(out.status.code(), Some(5));
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(answer["ok"], false);
    assert_eq!(answer["operation"], "watch");
    assert_eq!(answer["errors"][0]["code"], "watch_in_progress");
    mac.put(".zshrc", "after\n");
    first.until("read", |v| count(v, "new") == 1);
}

#[test]
fn a_place_that_cannot_be_subscribed_to_is_a_problem_line_and_the_rest_is_still_watched() {
    use std::os::unix::fs::PermissionsExt;
    let mac = Mac::new("closed");
    let etc = mac.sys().join("etc");
    std::fs::create_dir_all(etc.join("ssh")).unwrap();
    std::fs::set_permissions(&etc, std::fs::Permissions::from_mode(0o000)).unwrap();
    struct Open(PathBuf);
    impl Drop for Open {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let _open = Open(etc);

    let mut w = mac.watch();
    let watching = w.next("watching");
    w.next("read");
    let problems: Vec<&Value> = w.lines("problem");
    assert!(!problems.is_empty());
    for p in &problems {
        assert_eq!(p["code"], "place_not_watched");
        assert!(p["detail_text"].as_str().unwrap().contains("etc/ssh"));
    }
    assert_eq!(
        watching["places"].as_u64().unwrap() as usize + problems.len(),
        27
    );
    // An autostart item: its kind of place reads in full here, so it has a baseline.
    mac.put("Library/LaunchAgents/seen.plist", "<plist/>\n");
    w.until("read", |v| count(v, "new") == 1);
}

#[test]
fn no_content_of_a_watched_file_is_in_stdout_or_the_store() {
    const SECRET: &str = "export TOKEN=watcher-must-never-keep-this";
    let mac = Mac::new("content");
    let mut w = mac.watch().started();
    mac.put(".zshrc", SECRET);
    mac.put("Library/LaunchAgents/a.plist", SECRET);
    w.until("read", |v| count(v, "new") == 2);
    assert!(w.seen.iter().all(|v| !v.to_string().contains(SECRET)));
    drop(w);
    let mut files = vec![mac.root.join("store")];
    while let Some(path) = files.pop() {
        if path.is_dir() {
            files.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
        } else {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
                "{}",
                path.display()
            );
        }
    }
}

#[test]
fn a_change_undone_within_the_quiet_period_is_read_as_no_change() {
    // A limit the watcher states: it reads the place after the quiet period, and finds it as
    // it was. The read line says nothing changed, and the store records nothing.
    let mac = Mac::new("undone");
    mac.put(".zshrc", "as it was\n");
    let mut w = mac.watch().started();
    mac.put(".zshrc", "for a moment\n");
    mac.put(".zshrc", "as it was\n");
    let read = w.next("read");
    assert_eq!(
        (
            count(&read, "new"),
            count(&read, "changed"),
            count(&read, "gone")
        ),
        (0, 0, 0)
    );
    assert!(mac.journaled(".zshrc", "changed").is_empty());
}

#[test]
fn status_says_watching_only_while_a_live_watcher_holds_the_store() {
    let mac = Mac::new("status");
    mac.run();
    assert!(mac.status()["result"]["watching"].is_null());
    assert!(mac.watch().started().stop().success());
    // The next watcher starts a second later or more, so its start is after the last
    // reading of the one before; until it reads, it has read nothing. The store keeps whole
    // seconds, so 1.1 s is the least wait that puts the two in different seconds.
    std::thread::sleep(Duration::from_millis(1100));
    let mut w = mac.watch();
    w.next("watching");
    let watching = mac.status()["result"]["watching"].clone();
    assert!(watching["since"].as_str().unwrap().ends_with('Z'));
    assert!(watching["last_read"].is_null(), "{watching}");
    assert_eq!(watching["cannot_see"].as_array().unwrap().len(), 3);
    mac.put(".zshrc", "read\n");
    w.next("read");
    let watching = mac.status()["result"]["watching"].clone();
    assert!(watching["last_read"].as_str().unwrap() >= watching["since"].as_str().unwrap());
    // A watcher killed outright, with no chance to clean up, never shows as watching.
    w.signal(libc::SIGKILL);
    w.exit();
    assert!(mac.status()["result"]["watching"].is_null());
}

#[test]
fn the_hooks_of_the_checkouts_the_store_holds_are_watched() {
    let mac = Mac::new("hooks");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(mac.home().join("dev/shop/.git/hooks")).unwrap();
    mac.run();
    let mut w = mac.watch();
    let watching = w.next("watching");
    assert_eq!(watching["places"], 28);
    w.next("read");
    mac.put("dev/shop/.git/hooks/pre-commit", "#!/bin/sh\n");
    w.until("read", |v| count(v, "new") == 1);
    assert_eq!(
        mac.journaled("dev/shop/.git/hooks/pre-commit", "added"),
        vec!["located_on", "watched_as", "has_content"]
    );
}

#[test]
fn a_link_in_a_watched_place_is_followed_and_a_change_at_its_target_is_seen() {
    // A profile kept in a dotfiles folder and linked into the home folder.
    let mac = Mac::new("link");
    let target = mac.put("dotfiles/zshrc", "one\n");
    std::os::unix::fs::symlink(&target, mac.home().join(".zshrc")).unwrap();
    // A launch agent kept elsewhere and linked into the folder of launch agents.
    let agent = mac.put("tools/agent.plist", "<plist/>\n");
    let agents = mac.home().join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents).unwrap();
    std::os::unix::fs::symlink(&agent, agents.join("tool.plist")).unwrap();
    let mut w = mac.watch().started();
    mac.put("dotfiles/zshrc", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(mac.journaled(".zshrc", "changed"), vec!["has_content"]);
    mac.put("tools/agent.plist", "<plist>changed</plist>\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(
        mac.journaled("Library/LaunchAgents/tool.plist", "changed"),
        vec!["has_content"]
    );
}

#[test]
fn a_reading_that_failed_is_a_problem_line_and_the_watcher_reads_again_later() {
    use std::os::unix::fs::PermissionsExt;
    let mac = Mac::new("failed");
    let mut w = mac.watch().started();
    let mode = |m| std::fs::set_permissions(mac.store(), std::fs::Permissions::from_mode(m));
    mode(0o444).unwrap();
    mac.put(".zshrc", "one\n");
    assert_eq!(w.next("problem")["code"], "read_failed");
    mode(0o644).unwrap();
    mac.put(".zprofile", "two\n");
    w.until("read", |v| count(v, "new") == 2);
}

#[test]
fn sigterm_while_waiting_for_a_full_run_stops_it_at_once() {
    let mac = Mac::new("waiting");
    let mut w = mac.watch().started();
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    mac.put(".zshrc", "one\n");
    // Past the 0.2 s latency and 1 s quiet period with room for a loaded machine: the watcher
    // is now waiting for the run lock, which is the wait this test stops.
    std::thread::sleep(Duration::from_secs(3));
    let asked = Instant::now();
    w.signal(libc::SIGTERM);
    assert_eq!(w.exit().code(), Some(0));
    assert!(asked.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_watcher_whose_reader_is_gone_stops_at_its_next_line() {
    // When the app that started it dies, an orphan must not keep the store's watcher lock.
    let mac = Mac::new("orphan");
    let mut child = mac
        .watch_cmd()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let reap = Reap(child.id() as i32);
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(out).lines();
        for line in lines.by_ref() {
            if line.unwrap().contains("\"event\":\"read\"") {
                break;
            }
        }
        // The reader goes away: the pipe's read end is closed.
        drop(lines);
        let _ = tx.send(());
    });
    rx.recv_timeout(WAIT).expect("the watcher did not start");
    mac.put(".zshrc", "one\n");
    let end = Instant::now() + WAIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < end, "the watcher outlived its reader");
        std::thread::sleep(Duration::from_millis(20));
    };
    // It is gone and its id may be another process's now.
    std::mem::forget(reap);
    assert_eq!(status.code(), Some(0));
}

#[test]
fn when_it_cannot_watch_at_all_it_prints_the_error_envelope_and_exits_non_zero() {
    let mac = Mac::new("cannot");
    let answer = |cmd: &mut Command| {
        let out = cmd.output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            (v["ok"].clone(), v["operation"].clone()),
            (false.into(), "watch".into())
        );
        (out.status.code(), v["errors"][0]["code"].clone())
    };
    assert_eq!(
        answer(mac.watch_cmd().arg("--every")),
        (Some(2), "usage".into())
    );
    std::fs::write(mac.store(), "not a store").unwrap();
    assert_eq!(
        answer(&mut mac.watch_cmd()),
        (Some(3), "store_unreadable".into())
    );
}

#[test]
fn a_watcher_whose_parent_is_gone_stops_and_frees_the_store() {
    // The app died and its child was handed to launchd: the watcher must not keep the
    // store's watcher lock, or the next app's watcher could not start.
    let mac = Mac::new("parent");
    let (out, pid) = (mac.root.join("out.txt"), mac.root.join("pid.txt"));
    let mut parent = Command::new("/bin/sh")
        .env("HOME", mac.home())
        .current_dir(mac.home())
        .arg("-c")
        .arg(r#""$0" watch --store "$1" --system-root "$2" > "$3" & echo $! > "$4"; wait"#)
        .arg(env!("CARGO_BIN_EXE_soc"))
        .arg(mac.store())
        .arg(mac.sys())
        .arg(&out)
        .arg(&pid)
        .spawn()
        .unwrap();
    let end = Instant::now() + WAIT;
    while !std::fs::read_to_string(&out).is_ok_and(|s| s.contains("\"event\":\"read\"")) {
        assert!(Instant::now() < end, "the watcher did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let watcher: i32 = std::fs::read_to_string(&pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let reap = Reap(watcher);
    parent.kill().unwrap();
    parent.wait().unwrap();
    while !mac.status()["result"]["watching"].is_null() {
        assert!(Instant::now() < end, "the orphaned watcher kept the store");
        std::thread::sleep(Duration::from_millis(50));
    }
    // It is gone and its id may be another process's now.
    std::mem::forget(reap);
}
