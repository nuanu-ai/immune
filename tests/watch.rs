//! Promises of `immune watch`, the watcher on file-system events. Each test runs the real binary
//! against the real FSEvents on an invented Mac: a temporary home folder and a temporary system
//! root, never the real watched places. Waits are for a line the watcher prints, with a
//! generous timeout. Where a test must show that something did not happen, it makes one more
//! change and waits for that, or, where it cannot, sleeps a fixed time and says why so long.

use rusqlite::Connection;
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
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
            std::env::temp_dir().join(format!("immune-watch-{tag}-{}-{nanos}", std::process::id()));
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

    fn immune(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_immune"));
        cmd.env("HOME", self.home()).current_dir(self.home());
        cmd
    }

    /// `immune run` on this Mac for the machine `mac`, asking nothing outside it.
    fn run_cmd(&self) -> Command {
        self.run_cmd_servers(&self.root.join("absent"))
    }

    /// `immune run` as above, reading the servers' files in `servers`.
    fn run_cmd_servers(&self, servers: &std::path::Path) -> Command {
        let mut cmd = self.immune();
        cmd.args(["run", "--machine-name", "mac"]);
        self.run_args(cmd, servers)
    }

    /// `immune run` as the app starts it: on this Mac's own name, the one a watcher takes
    /// while the store names no machine. The name is never looked at.
    fn app_run(&self) {
        let out = self.app_run_cmd().output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn app_run_cmd(&self) -> Command {
        let mut cmd = self.immune();
        cmd.arg("run");
        self.run_args(cmd, &self.root.join("absent"))
    }

    fn run_args(&self, mut cmd: Command, servers: &std::path::Path) -> Command {
        let absent = self.root.join("absent");
        cmd.arg("--store")
            .arg(self.store())
            .arg("--brew-input")
            .arg(self.root.join("brew.json"))
            .arg("--servers-input")
            .arg(servers)
            .arg("--tailscale")
            .arg(&absent)
            .arg("--threats-input")
            .arg(&absent)
            .arg("--osv-crates-input")
            .arg(&absent)
            .arg("--osv-npm-input")
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

    /// `immune watch` on this Mac. Its samples are of the reading in `sample.json`, which a test
    /// rewrites; by default no process, so that no test reads the real ones.
    fn watch_cmd(&self) -> Command {
        let reading = self.root.join("sample.json");
        if !reading.exists() {
            self.sample(now(), &[]);
        }
        let mut cmd = self.immune();
        cmd.args(["watch", "--store"])
            .arg(self.store())
            .arg("--system-root")
            .arg(self.sys())
            .arg("--sample-input")
            .arg(reading);
        cmd
    }

    /// Sets what the next sample sees: these processes at `at`.
    fn sample(&self, at: i64, processes: &[Value]) {
        let reading = serde_json::json!({ "at": at, "processes": processes });
        let part = self.root.join("sample.json.part");
        std::fs::write(&part, reading.to_string()).unwrap();
        std::fs::rename(part, self.root.join("sample.json")).unwrap();
    }

    fn watch(&self) -> Watcher {
        Watcher::start(self.watch_cmd())
    }

    fn status(&self) -> Value {
        let out = self
            .immune()
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Every page `immune view` writes, joined.
    fn view(&self) -> String {
        self.view_with(&[])
    }

    /// Every page as `immune view --if-stale` leaves it, joined: written only when not current.
    fn view_if_stale(&self) -> String {
        self.view_with(&["--if-stale"])
    }

    fn view_with(&self, args: &[&str]) -> String {
        let out = within(
            self.immune()
                .args(["view", "--no-open", "--store"])
                .arg(self.store())
                .args(args),
        );
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(|path| std::fs::read_to_string(path).unwrap())
            .collect()
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

/// A running `immune watch` and every line it printed so far.
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
    // The change is the store's: `immune status` lists it after a full run, under the
    // watcher's reading.
    drop(w);
    mac.run();
    let changes = &mac.status()["watched"]["changes"];
    assert_eq!(changes[0]["path_text"], ".zshrc");
    assert_eq!(changes[0]["change"], "changed");
    assert!(changes[0]["run_id"].as_str().unwrap().starts_with("watch-"));
}

#[test]
fn a_change_the_watcher_sees_is_an_open_finding_at_once_and_its_read_line_counts_as_status_does() {
    // The app learns of a change from the `read` line and then shows `immune status --json`:
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
    let result = mac.status().clone();
    assert_eq!(read["needs_a_look_total"], result["needs_a_look"]["total"]);
    // This Mac is watched, live, for what the watcher reads; installed software, which only a
    // full run reads, is not said to be watched with a count of nothing.
    let m = &result["this_mac"];
    assert_eq!((&m["state"], &m["live"]), (&"watched".into(), &true.into()));
    let whats: Vec<&str> = m["watched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["what"].as_str().unwrap())
        .collect();
    assert!(
        whats.contains(&"shell startup files") && !whats.contains(&"applications"),
        "{m}"
    );
    let looked = looks(&result);
    let items = looked.as_array().unwrap();
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
    let pages = mac.view();
    assert!(!pages.contains("did not finish"), "{pages}");
    // Named by what it read, the place the change was in.
    let shown =
        "watcher&#39;s reading of shell profiles of zsh and bash: +0 added, 1 changed, 0 removed";
    assert!(pages.contains(shown), "{pages}");
    assert!(!pages.contains("were not read in this run"), "{pages}");
}

#[test]
fn the_view_says_what_a_watcher_cannot_see_and_whether_one_runs_once_one_has_run() {
    // The owner reading the view must know which changes no watcher would have caught, and
    // whether one watches now; on a store no watcher ever read, neither is said.
    let mac = Mac::new("view-watching");
    mac.run();
    let cannot = "A watcher does not see who made a change";
    assert!(!mac.view().contains(cannot));
    let mut w = mac.watch().started();
    mac.put(".zshrc", "one\n");
    w.until("read", |v| count(v, "new") == 1);
    let now = mac.view_if_stale();
    assert!(now.contains(cannot), "{now}");
    assert!(
        now.contains("watched live: a change in what is watched all the time shows within seconds, last looked 2"),
        "{now}"
    );
    // How many things a running watcher watches leads to where they are listed; once none
    // runs, there is no such number to follow.
    let followed = ", watched all the time\">";
    assert!(
        now.contains("<span class=\"num\"><a href=\"view/this-mac.html\" aria-label=\"What is watched on this Mac: ")
            && now.contains(followed),
        "{now}"
    );
    // A watcher that stopped leaves the journal as it was; the page asked for says so all the
    // same.
    drop(w);
    let after = mac.view_if_stale();
    assert!(!after.contains(followed), "{after}");
    assert!(after.contains(cannot), "{after}");
    assert!(
        after.contains(
            "no watcher is running now, so everything is checked every hour; a watcher last looked 2"
        ),
        "{after}"
    );
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
    // Writing the burst takes about a quarter of a second, well inside the quiet second, but
    // its reading came 7 s after it at background priority, and later still on a loaded
    // machine, past WAIT. Its waits here are longer.
    const LONG: Duration = Duration::from_secs(300);
    let next_read = |w: &mut Watcher| {
        let end = Instant::now() + LONG;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            let v =
                w.rx.recv_timeout(left)
                    .unwrap_or_else(|_| panic!("no read line in {LONG:?}; saw {:?}", w.seen));
            w.seen.push(v.clone());
            if v["event"] == "read" {
                return v;
            }
        }
    };
    let mac = Mac::new("burst");
    let mut w = mac.watch().started();
    for i in 0..1000 {
        mac.put(
            &format!("Library/LaunchAgents/item-{i}.plist"),
            "<plist/>\n",
        );
    }
    let burst = next_read(&mut w);
    assert_eq!(count(&burst, "new"), 1000);
    // One more change: had the burst made a second reading, its line would come first.
    mac.put(".zprofile", "a\n");
    let after = next_read(&mut w);
    assert_eq!((count(&after, "new"), count(&after, "changed")), (1, 0));
    assert_eq!(w.lines("read").len(), 3);
}

#[test]
fn every_start_reads_every_place_a_change_made_while_stopped_is_found_and_none_is_said_when_none_was_made()
 {
    // The first line after `watching` is the start's reading of every place, whatever the
    // store says of earlier watchers: what changed while none ran is in it.
    let mac = Mac::new("restart");
    mac.put(".zshrc", "one\n");
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    let w = mac.watch().started();
    assert!(w.stop().success());
    mac.put(".zshrc", "two\n");
    let mut w = mac.watch();
    w.next("watching");
    let first = w.next("read");
    assert_eq!(count(&first, "changed"), 1, "{:?}", w.seen);
    let needs = count(&first, "needs_a_look_total");
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    assert!(w.stop().success());

    // Nothing changed while it was stopped: the start still reads every place, records no
    // change, opens nothing, and the number that needs a look stays as it was.
    let before = latest_watched(&mac);
    let mut w = mac.watch();
    w.next("watching");
    let first = w.next("read");
    let said: Vec<u64> = ["new", "changed", "gone", "opened"]
        .iter()
        .map(|c| count(&first, c))
        .collect();
    assert_eq!(said, [0, 0, 0, 0], "{first}");
    assert_eq!(count(&first, "needs_a_look_total"), needs);
    let after = latest_watched(&mac);
    assert_eq!(after.len(), before.len());
    for (was, now) in before.iter().zip(&after) {
        assert_ne!(
            was.2, now.2,
            "{} of {} was not read at the start",
            now.1, now.0
        );
    }
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    assert!(w.stop().success());
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
    assert_eq!(mac.status()["format"], 1);
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
        watching["places"].as_u64().unwrap() + problems.len() as u64,
        TABLE_PLACES + HOME_PLACES
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
    assert!(mac.status()["watching"].is_null());
    assert!(mac.watch().started().stop().success());
    // The next watcher starts a second later or more, so its start is after the last
    // reading of the one before; until it reads, it has read nothing. The store keeps whole
    // seconds, so 1.1 s is the least wait that puts the two in different seconds.
    std::thread::sleep(Duration::from_millis(1100));
    // The run lock is held, as by a full run, so the start's reading waits for it.
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    let mut w = mac.watch();
    w.next("watching");
    let watching = mac.status()["watching"].clone();
    assert!(watching["since_at"].as_i64().unwrap() > 0);
    assert!(watching["last_read_at"].is_null(), "{watching}");
    assert_eq!(watching["cannot_see"].as_array().unwrap().len(), 3);
    folder.unlock().unwrap();
    w.next("read");
    let watching = mac.status()["watching"].clone();
    assert!(watching["last_read_at"].as_i64().unwrap() >= watching["since_at"].as_i64().unwrap());
    // A watcher killed outright, with no chance to clean up, never shows as watching.
    w.signal(libc::SIGKILL);
    w.exit();
    assert!(mac.status()["watching"].is_null());
}

#[test]
fn the_hooks_of_the_checkouts_the_store_holds_are_watched() {
    let mac = Mac::new("hooks");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(mac.home().join("dev/shop/.git/hooks")).unwrap();
    mac.run();
    let mut w = mac.watch();
    let watching = w.next("watching");
    // The table's places, and the checkout's hooks and its files that run code by itself.
    assert_eq!(
        watching["places"],
        TABLE_PLACES + HOME_PLACES + CHECKOUT_PLACES
    );
    w.next("read");
    mac.put("dev/shop/.git/hooks/pre-commit", "#!/bin/sh\n");
    w.until("read", |v| count(v, "new") == 1);
    assert_eq!(
        mac.journaled("dev/shop/.git/hooks/pre-commit", "added"),
        vec!["located_on", "watched_as", "has_content"]
    );
}

/// The places of the table of watched places on the machine, every row but a checkout's hooks:
/// launch agents and daemons, the login window's preferences, shell profiles, SSH files, and
/// the policies, modules and plugins of logging in.
const TABLE_PLACES: u64 = 35;

/// The places of the home folder the watcher subscribes to through which a tool's own settings
/// run code by itself: five files of coding agents' settings and VS Code's extensions folder.
/// Claude Code's state file is not one: it is rewritten all the time.
const HOME_PLACES: u64 = 6;

/// The places the watcher subscribes to in each checkout: its hooks folder and the twelve
/// files of the ways a project runs code by itself that are read: the editor's task file and
/// settings, the two places of a dev container's file, `package.json`, and seven files of
/// coding agents' settings. A workspace file has no fixed name and is not subscribed to.
const CHECKOUT_PLACES: u64 = 13;

/// An editor's task file with a task set to run when the folder is opened.
const ON_OPEN: &str = r#"{
    // tasks
    "version": "2.0.0",
    "tasks": [{ "label": "setup", "command": "node setup.js", "runOptions": { "runOn": "folderOpen" } }]
}
"#;

#[test]
fn an_editor_task_planted_while_the_watcher_runs_is_a_finding_within_seconds() {
    // The incident's way in: a task that runs as soon as the folder is opened, planted in a
    // project the store already holds. Waiting for the hourly check would leave an hour in
    // which the owner opens the folder. The folder `.vscode` is not there yet when the
    // watcher starts.
    let mac = Mac::new("tasks");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.run();
    let mut w = mac.watch().started();
    let written = Instant::now();
    mac.put("dev/shop/.vscode/tasks.json", ON_OPEN);
    let read = w.until("read", |v| count(v, "opened") == 1);
    assert!(written.elapsed() < Duration::from_secs(10), "read too late");
    assert_eq!(count(&read, "new"), 1);
    let items = looks(&mac.status()).clone();
    let found = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["rule"] == "autorun.folder-open")
        .unwrap_or_else(|| panic!("{items}"))
        .clone();
    assert_eq!(found["where_text"], "~/dev/shop/.vscode/tasks.json");
}

#[test]
fn a_login_hook_and_a_changed_login_policy_are_findings_within_seconds() {
    // Both run with full control at the next login or password prompt: an hour's wait for
    // the full check is an hour in which the owner logs in. Neither the preferences folder nor
    // the policy folder is there when the watcher starts.
    let mac = Mac::new("login");
    mac.run();
    let mut w = mac.watch().started();
    let written = Instant::now();
    mac.put(
        "Library/Preferences/com.apple.loginwindow.plist",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>LogoutHook</key><string>/Users/Shared/example.sh</string></dict></plist>\n",
    );
    w.until("read", |v| v["needs_a_look_total"] == 1);
    assert!(
        written.elapsed() < Duration::from_secs(10),
        "hook read too late"
    );
    let policy = mac.sys().join("etc/pam.d/sudo");
    let written = Instant::now();
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::write(&policy, "auth       required       pam_deny.so\n").unwrap();
    w.until("read", |v| v["needs_a_look_total"] == 2);
    assert!(
        written.elapsed() < Duration::from_secs(10),
        "policy read too late"
    );
    let r = mac.status().clone();
    let items = &looks(&r);
    let mut found: Vec<(String, String, String, bool)> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let text = |k: &str| i[k].as_str().unwrap_or_default().to_string();
            let (rule, place) = (text("rule"), text("where_text"));
            (rule, place, text("technique_text"), i["urgent"] == true)
        })
        .collect();
    found.sort();
    // A hook is told at once; a changed policy, which an update of macOS also makes, waits
    // for the owner to look. Each names the ATT&CK technique an agent looks it up by.
    assert_eq!(
        found,
        [
            (
                "watched.authentication".into(),
                "/etc/pam.d/sudo".into(),
                "T1556".into(),
                false
            ),
            (
                "watched.login-hook".into(),
                "~/Library/Preferences/com.apple.loginwindow.plist#/LogoutHook".into(),
                "T1037.002".into(),
                true
            ),
        ],
        "{items}"
    );
    // And the status says both kinds are seen within seconds while the watcher runs.
    for what in ["login and logout hooks", "login and password modules"] {
        let watched = r["this_mac"]["watched"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["what"] == what)
            .unwrap_or_else(|| panic!("{what}: {r:#}"))
            .clone();
        assert_eq!(watched["how"], "live", "{watched}");
        assert_eq!(watched["count"], 1, "{watched}");
    }
}

#[test]
fn a_tool_planted_in_an_agents_settings_and_a_new_editor_extension_are_findings_within_seconds() {
    // Malware made agents run its code in every project by adding its own tool to their
    // settings; extensions run as soon as the editor starts. Neither waits for the hourly
    // check. Neither file nor folder is there when the watcher starts.
    let mac = Mac::new("home-autorun");
    mac.run();
    let mut w = mac.watch().started();
    let written = Instant::now();
    mac.put(
        ".cursor/mcp.json",
        "{\n  // added\n  \"mcpServers\": {\"x\": {\"command\": \"node\"},},\n}\n",
    );
    mac.put(
        ".vscode/extensions/invented.tool-1.0.0/package.json",
        "{}\n",
    );
    w.until("read", |v| count(v, "opened") >= 1);
    let mut found = Vec::new();
    while found.len() < 2 {
        assert!(written.elapsed() < Duration::from_secs(10), "read too late");
        found = looks(&mac.status())
            .as_array()
            .unwrap()
            .iter()
            .map(|i| (i["rule"].to_string(), i["where_text"].to_string()))
            .collect();
        found.sort();
        if found.len() < 2 {
            w.next("read");
        }
    }
    assert_eq!(
        found,
        [
            (
                "\"autorun.agent-settings\"".to_string(),
                "\"~/.cursor/mcp.json#/mcpServers/x\"".to_string()
            ),
            (
                "\"autorun.editor-extension\"".to_string(),
                "\"~/.vscode/extensions/invented.tool\"".to_string()
            ),
        ]
    );
}

#[test]
fn a_file_its_tool_rewrites_all_the_time_wakes_no_reading_and_what_is_planted_in_it_is_found_later()
{
    // Claude Code rewrites its state file every few seconds while it works. A reading at each
    // write reads every watched place and grows the store for nothing, so the watcher does not
    // subscribe to it; what is planted in it is found at the next full run.
    let mac = Mac::new("rewritten");
    mac.run();
    let mut w = mac.watch().started();
    // A file that is watched live still is.
    let written = Instant::now();
    mac.put(".cursor/mcp.json", "{\"mcpServers\": {}}");
    w.until("read", |_| true);
    assert!(written.elapsed() < Duration::from_secs(10), "read too late");
    let reads = w.lines("read").len();
    for n in 0..3 {
        mac.put(
            ".claude.json",
            &format!(
                "{{\"numStartups\": {n}, \"mcpServers\": {{\"x\": {{\"command\": \"node\"}}}}}}"
            ),
        );
        std::thread::sleep(Duration::from_millis(1100));
    }
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        w.lines("read").len(),
        reads,
        "a write to the state file woke a reading"
    );
    w.signal(libc::SIGTERM);
    w.exit();
    mac.run();
    let found: Vec<(String, String)> = looks(&mac.status())
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["rule"].to_string(), i["where_text"].to_string()))
        .collect();
    assert_eq!(
        found,
        [(
            "\"autorun.agent-settings\"".to_string(),
            "\"~/.claude.json#/mcpServers/x\"".to_string()
        )]
    );
}

// The first check of a Mac.

/// A project as developers keep them for weeks: settings of Claude Code with a hook it runs
/// when a session starts and commands it runs without asking, and a script the package
/// manager runs at install.
fn project(mac: &Mac, rel: &str) {
    mac.put(&format!("{rel}/.git/HEAD"), "ref: refs/heads/main\n");
    mac.put(
        &format!("{rel}/.claude/settings.json"),
        r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .invented/start.js"}]}]}}"#,
    );
    mac.put(
        &format!("{rel}/.claude/settings.local.json"),
        r#"{"permissions": {"allow": ["Bash(make:*)"]}}"#,
    );
    mac.put(
        &format!("{rel}/package.json"),
        r#"{"name": "x", "scripts": {"postinstall": "node .invented/setup.js"}}"#,
    );
}

/// The open findings, as rule and where, sorted.
fn found(mac: &Mac) -> Vec<(String, String)> {
    let out = mac
        .immune()
        .args(["findings", "--json", "--store"])
        .arg(mac.store())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut found: Vec<(String, String)> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["finding"]["state"] == "open")
        .map(|f| {
            let s = |v: &Value| v.as_str().unwrap_or_default().to_string();
            (s(&f["finding"]["rule"]), s(&f["where_text"]))
        })
        .collect();
    found.sort();
    found
}

/// A Mac with three projects that hold what runs by itself, and an empty store.
fn with_projects(tag: &str) -> Mac {
    let mac = Mac::new(tag);
    for rel in ["dev/api", "dev/shop", "work/site"] {
        project(&mac, rel);
    }
    mac
}

#[test]
fn the_first_check_of_a_mac_finds_nothing_in_what_was_there_whoever_writes_first() {
    // The app starts its watcher next to the first full run, and the run asks for its data
    // before it takes the store, so the watcher's first reading can come first, when the
    // store knows no project. What a Mac held before its first check is its baseline, not
    // one alarm per project: the order in which the two write cannot change that.
    let mac = with_projects("first-watcher");
    let w = mac.watch().started();
    mac.app_run();
    assert!(found(&mac).is_empty(), "{:?}", found(&mac));
    assert!(w.stop().success());

    let mac = with_projects("first-run");
    mac.app_run();
    let w = mac.watch().started();
    assert!(w.stop().success());
    mac.app_run();
    assert!(found(&mac).is_empty(), "{:?}", found(&mac));
}

#[test]
fn after_a_first_check_the_watcher_read_first_what_arrives_later_is_still_found() {
    // The baseline is the Mac at its first check, not "nothing is ever found in a project":
    // a hook planted later in a project the store holds, and a project that arrives later
    // with a script that runs at install, are findings as on any other Mac.
    let mac = with_projects("first-then-later");
    let w = mac.watch().started();
    mac.app_run();
    assert!(w.stop().success());
    assert!(found(&mac).is_empty(), "{:?}", found(&mac));
    // A watcher started now watches the projects the run found.
    let mut w = mac.watch();
    w.next("watching");
    mac.put(
        "dev/api/.claude/settings.local.json",
        r#"{"permissions": {"allow": ["Bash(make:*)"]}, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "sh x"}]}]}}"#,
    );
    w.until("read", |v| count(v, "opened") == 1);
    assert!(w.stop().success());
    mac.put("dev/new/.git/HEAD", "ref: refs/heads/main\n");
    mac.put(
        "dev/new/package.json",
        r#"{"scripts": {"preinstall": "node x.js"}}"#,
    );
    mac.app_run();
    assert_eq!(
        found(&mac),
        [
            (
                "autorun.agent-start".to_string(),
                "~/dev/api/.claude/settings.local.json#/hooks".to_string()
            ),
            (
                "autorun.package-install".to_string(),
                "~/dev/new/package.json#/scripts/preinstall".to_string()
            ),
        ]
    );
}

#[test]
fn a_watcher_that_reads_before_any_project_was_looked_for_claims_no_reading_of_the_projects() {
    // Before the first full check no project is known: a reading over them would look into
    // none and record that it read each one in full.
    let mac = lived_in("before-any-check");
    assert!(mac.watch().started().stop().success());
    let claimed: Vec<String> = Connection::open(mac.store())
        .unwrap()
        .prepare(
            "SELECT kind FROM coverage WHERE reader = 'watched-places'
               AND kind LIKE '% of each checkout, %'",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(claimed.is_empty(), "{claimed:?}");
}

/// A home folder as a developer's is before the program first runs: projects with git hooks,
/// agents' settings, install scripts and an editor task, an autostart item, a shell profile,
/// and agents' own settings in the home folder.
fn lived_in(tag: &str) -> Mac {
    let mac = with_projects(tag);
    for rel in ["dev/api", "dev/shop", "work/site"] {
        mac.put(
            &format!("{rel}/.git/hooks/pre-commit"),
            "#!/bin/sh\nmake lint\n",
        );
    }
    mac.put("dev/shop/.vscode/tasks.json", ON_OPEN);
    mac.put("Library/LaunchAgents/com.invented.sync.plist", "<plist/>\n");
    mac.put(".zshrc", "export PATH=\"$HOME/bin:$PATH\"\n");
    mac.put(
        ".claude/settings.json",
        r#"{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]}}"#,
    );
    mac.put(
        ".claude.json",
        r#"{"mcpServers": {"notes": {"command": "node"}}}"#,
    );
    mac
}

/// A watcher that looks again at what to watch every second, so that it reads the projects
/// a full run found within seconds of it.
fn quick_watch(mac: &Mac) -> Watcher {
    let mut cmd = mac.watch_cmd();
    cmd.args(["--alive-every", "1"]);
    Watcher::start(cmd).started()
}

/// The orders in which the app's watcher and its first full check can write to a store that
/// does not exist yet, each run to the end of the first check; a watcher still running is
/// returned.
fn first_day(mac: &Mac, order: &str) -> Option<Watcher> {
    match order {
        "watcher first" => {
            let mut w = quick_watch(mac);
            mac.app_run();
            // Its reading of the projects the check found.
            w.next("read");
            Some(w)
        }
        "check first" => {
            mac.app_run();
            Some(quick_watch(mac))
        }
        "both at once" => {
            let run = spawn(&mut mac.app_run_cmd());
            let mut w = quick_watch(mac);
            let out = finish(run);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            w.next("read");
            Some(w)
        }
        "watcher stopped and started again" => {
            assert!(quick_watch(mac).stop().success());
            // Started again with nothing changed since, it has nothing to read until the
            // check's projects are watched.
            let mut cmd = mac.watch_cmd();
            cmd.args(["--alive-every", "1"]);
            let mut w = Watcher::start(cmd);
            w.next("watching");
            mac.app_run();
            w.next("read");
            Some(w)
        }
        "watcher stopped before the check" => {
            assert!(quick_watch(mac).stop().success());
            mac.app_run();
            None
        }
        other => panic!("no order {other}"),
    }
}

const FIRST_DAY: [&str; 5] = [
    "watcher first",
    "check first",
    "both at once",
    "watcher stopped and started again",
    "watcher stopped before the check",
];

#[test]
fn the_first_day_on_a_new_mac_finds_nothing_in_what_was_there_in_any_order_of_the_watcher_and_the_first_check()
 {
    // The app starts its watcher and its first full check together, on a store that does not
    // exist yet. What the Mac held before is the baseline, whichever writes first: one
    // finding about each project's settings is what a new user would see at first launch.
    for order in FIRST_DAY {
        let mac = lived_in(&format!("day-one-{}", order.replace(' ', "-")));
        let w = first_day(&mac, order);
        assert!(found(&mac).is_empty(), "{order}: {:?}", found(&mac));
        if let Some(w) = w {
            assert!(w.stop().success());
        }
    }
}

#[test]
fn after_the_first_check_what_appears_in_a_project_or_the_home_folder_is_found_in_every_order() {
    // The first check is a baseline, not a pass for what comes after it.
    for order in FIRST_DAY {
        let mac = lived_in(&format!("day-one-later-{}", order.replace(' ', "-")));
        if let Some(w) = first_day(&mac, order) {
            assert!(w.stop().success());
        }
        mac.put("dev/api/.git/hooks/post-checkout", "#!/bin/sh\nsh .x\n");
        mac.put("dev/api/.vscode/tasks.json", ON_OPEN);
        mac.put(
            "Library/LaunchAgents/com.invented.other.plist",
            "<plist/>\n",
        );
        mac.put("dev/new/.git/HEAD", "ref: refs/heads/main\n");
        mac.put(
            "dev/new/package.json",
            r#"{"scripts": {"preinstall": "node x.js"}}"#,
        );
        mac.app_run();
        let rules: Vec<(String, String)> = found(&mac);
        assert_eq!(
            rules,
            [
                (
                    "autorun.folder-open".to_string(),
                    "~/dev/api/.vscode/tasks.json".to_string()
                ),
                (
                    "autorun.package-install".to_string(),
                    "~/dev/new/package.json#/scripts/preinstall".to_string()
                ),
                (
                    "watched.autostart".to_string(),
                    "~/Library/LaunchAgents/com.invented.other.plist".to_string()
                ),
                (
                    "watched.git-hook".to_string(),
                    "~/dev/api/.git/hooks/post-checkout".to_string()
                ),
            ],
            "{order}"
        );
    }
}

#[test]
fn what_changes_between_the_watchers_first_reading_and_the_first_check_where_the_watcher_read_is_found()
 {
    // The watcher's first reading of the home folder is that folder's baseline, though no
    // full check has run: what is added or changed there before the first check is found by
    // it, and not taken for part of the baseline.
    let mac = lived_in("between");
    assert!(mac.watch().started().stop().success());
    mac.put(
        "Library/LaunchAgents/com.invented.other.plist",
        "<plist/>\n",
    );
    mac.put(".zshrc", "curl -s x | sh\n");
    mac.put(
        ".claude/settings.json",
        r#"{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]}, "env": {"NODE_OPTIONS": "-r x"}}"#,
    );
    mac.app_run();
    assert_eq!(
        found(&mac),
        [
            (
                "autorun.agent-settings".to_string(),
                "~/.claude/settings.json#/env".to_string()
            ),
            (
                "watched.autostart".to_string(),
                "~/Library/LaunchAgents/com.invented.other.plist".to_string()
            ),
            ("watched.shell-profile".to_string(), "~/.zshrc".to_string()),
        ]
    );
}

#[test]
fn a_place_the_watcher_read_first_after_the_first_check_is_told_once_and_what_appears_there_later_is_found()
 {
    // The full check could not list the home folder's autostart items; the watcher's reading
    // could. What the folder held then is its baseline, told once as read for the first time,
    // and an item added after that reading is found by the next check, though no check ever
    // read the folder before.
    let mac = Mac::new("watcher-baseline");
    let agents = mac.home().join("Library/LaunchAgents");
    mac.put("Library/LaunchAgents/com.invented.sync.plist", "<plist/>\n");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = mac.run_cmd().output().unwrap();
        std::fs::set_permissions(&agents, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(out.status.success());
    }
    assert!(mac.watch().started().stop().success());
    mac.put(
        "Library/LaunchAgents/com.invented.other.plist",
        "<plist/>\n",
    );
    mac.run();
    assert_eq!(
        found(&mac),
        [
            (
                "watched.autostart".to_string(),
                "~/Library/LaunchAgents/com.invented.other.plist".to_string()
            ),
            ("watched.first-read".to_string(), "mac".to_string()),
        ]
    );
}

#[test]
fn after_an_upgrade_a_clone_made_before_the_first_full_check_is_found_though_the_watcher_read_first()
 {
    // A store an earlier version made, which recorded no place. The upgraded app's watcher
    // reads first and records its places; the first full check then judges a project cloned
    // since the earlier version's last check by the walks that version made.
    let mac = with_projects("upgraded");
    mac.run();
    Connection::open(mac.store())
        .unwrap()
        .execute_batch("DROP TABLE unit_read; DELETE FROM meta WHERE key = 'units_since';")
        .unwrap();
    assert!(mac.watch().started().stop().success());
    mac.put("dev/new/.git/HEAD", "ref: refs/heads/main\n");
    mac.put(
        "dev/new/package.json",
        r#"{"scripts": {"preinstall": "node x.js"}}"#,
    );
    mac.run();
    assert_eq!(
        found(&mac),
        [(
            "autorun.package-install".to_string(),
            "~/dev/new/package.json#/scripts/preinstall".to_string()
        )]
    );
}

#[test]
fn a_worktree_that_appears_while_the_watcher_runs_raises_nothing_in_the_run_or_the_watcher_and_its_later_change_is_found_live()
 {
    // The full run finds the worktree and the watcher then watches it: both judge it by one
    // code, so neither raises what the other did not. Git writes the pointers relative here,
    // as it does with `worktree.useRelativePaths`.
    let mac = Mac::new("worktree");
    project(&mac, "dev/shop");
    mac.run();
    let mut cmd = mac.watch_cmd();
    cmd.args(["--alive-every", "1"]);
    let mut w = Watcher::start(cmd).started();
    project(&mac, "dev/shop-fix");
    std::fs::remove_dir_all(mac.home().join("dev/shop-fix/.git")).unwrap();
    mac.put(
        "dev/shop-fix/.git",
        "gitdir: ../shop/.git/worktrees/shop-fix\n",
    );
    mac.put(
        "dev/shop/.git/worktrees/shop-fix/gitdir",
        "../../../../shop-fix/.git\n",
    );
    mac.put("dev/shop/.git/worktrees/shop-fix/commondir", "../..\n");
    mac.put(
        "dev/shop/.git/worktrees/shop-fix/HEAD",
        "ref: refs/heads/fix\n",
    );
    mac.run();
    assert!(found(&mac).is_empty(), "{:?}", found(&mac));
    assert_eq!(
        mac.rows(
            "SELECT subject FROM journal WHERE entry = 'same_as_sibling'
               AND subject LIKE '%/dev/shop-fix/%' ORDER BY subject"
        )
        .len(),
        3
    );
    // The watcher now watches the worktree's places and reads them. A change in one that
    // raised nothing is a finding within seconds, and it is the only one: the watcher raises
    // nothing for the places the run judged the same.
    mac.put(
        "dev/shop-fix/.claude/settings.json",
        r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .invented/other.js"}]}]}}"#,
    );
    w.until("read", |v| count(v, "opened") == 1);
    assert_eq!(
        found(&mac),
        [(
            "autorun.agent-start".to_string(),
            "~/dev/shop-fix/.claude/settings.json#/hooks".to_string()
        )]
    );
    assert!(w.stop().success());
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
    let last_read = "SELECT CAST(last_read AS TEXT) FROM watcher";
    let read_every_place = mac.rows(last_read);
    // So that a reading after it cannot have the same time to the second.
    std::thread::sleep(Duration::from_millis(1100));
    let mode = |m| std::fs::set_permissions(mac.store(), std::fs::Permissions::from_mode(m));
    mode(0o444).unwrap();
    mac.put(".zshrc", "one\n");
    // A sample taken meanwhile fails too, with its own line.
    w.until("problem", |v| v["code"] == "read_failed");
    mode(0o644).unwrap();
    mac.put(".zprofile", "two\n");
    w.until("read", |v| count(v, "new") == 2);
    // What a failed reading would have read is not all that may have changed since: it is
    // tried again as a reading of every place.
    assert_ne!(mac.rows(last_read), read_every_place);
}

#[test]
fn a_watcher_waiting_for_a_long_full_run_keeps_saying_it_is_alive_and_reads_once_it_ends() {
    // The app takes a watcher that says nothing for three minutes for dead and kills it; a
    // full run can hold the store for minutes. While it waits for the run lock, the watcher
    // says it is alive at its usual interval, here one second.
    let mac = Mac::new("alive-waiting");
    let mut cmd = mac.watch_cmd();
    cmd.args(["--alive-every", "1"]);
    let mut w = Watcher::start(cmd).started();
    let folder = std::fs::File::open(mac.root.join("store")).unwrap();
    folder.lock().unwrap();
    mac.put(".zshrc", "one\n");
    // Past the 0.2 s latency and 1 s quiet period: the reading now waits for the lock.
    std::thread::sleep(Duration::from_millis(2500));
    let before = w.lines("alive").len();
    // Several alive intervals of waiting, and each lock attempt takes up to 2 s.
    std::thread::sleep(Duration::from_secs(6));
    let during = w.lines("alive").len() - before;
    assert!(
        w.lines("read").len() == 1,
        "read while a run held the store"
    );
    assert!(
        during >= 2,
        "{during} alive lines in 6 s of waiting; saw {:?}",
        w.seen
    );
    folder.unlock().unwrap();
    w.until("read", |v| count(v, "new") == 1);
}

#[test]
fn a_failed_reading_or_sample_is_not_watched_live_with_its_reason_until_the_next_success() {
    // The first invariant: the owner is never told this Mac is watched live while the
    // watcher's latest reading of the watched places, or its latest sample, failed. A store
    // that refuses the reading's rows, and a sample that cannot be read, while the store can
    // still record the failure.
    let mac = Mac::new("failing");
    mac.put(".zshrc", "zero\n");
    mac.run();
    let mut cmd = mac.watch_cmd();
    cmd.args(["--sample-every", "1"]);
    let mut w = Watcher::start(cmd);
    w.next("watching");
    mac.put(".zprofile", "first\n");
    w.until("read", |v| count(v, "new") == 1);
    mac.view_if_stale();
    let live = |mac: &Mac| {
        let r = mac.status().clone();
        (
            r["this_mac"]["live"].clone(),
            r["watching"]["failed"].clone(),
        )
    };
    assert_eq!(live(&mac).0, true);

    let conn = Connection::open(mac.store()).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER refuse BEFORE INSERT ON coverage WHEN NEW.run_id LIKE 'watch-%'
         BEGIN SELECT RAISE(ABORT, 'invented refusal'); END;",
    )
    .unwrap();
    mac.put(".zshrc", "one\n");
    w.until("problem", |v| v["code"] == "read_failed");
    let (is_live, failed) = live(&mac);
    assert_eq!(is_live, false, "{failed}");
    assert_eq!(failed[0]["what"], "read", "{failed}");
    assert!(
        failed[0]["detail_text"]
            .as_str()
            .unwrap()
            .contains("invented refusal"),
        "{failed}"
    );
    // The page and the text say a watcher runs but does not watch live, never that none runs.
    // The failed reading wrote nothing to the journal: the page asked for says it all the same.
    let page = mac.view_if_stale();
    assert!(
        page.contains("a watcher runs, but its latest reading of the watched places failed")
            && page.contains("latest reading of the watched places failed</"),
        "{page}"
    );
    let text = within(mac.immune().args(["status", "--store"]).arg(mac.store()));
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("so it does not watch live"), "{text}");
    conn.execute_batch("DROP TRIGGER refuse").unwrap();
    mac.put(".zshrc", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(live(&mac), (true.into(), serde_json::json!([])));

    std::fs::write(mac.root.join("sample.json"), "not a reading").unwrap();
    w.until("problem", |v| v["code"] == "sample_failed");
    let (is_live, failed) = live(&mac);
    assert_eq!(is_live, false, "{failed}");
    assert_eq!(failed[0]["what"], "sample", "{failed}");
    assert!(!failed[0]["detail_text"].as_str().unwrap().is_empty());
    // The first sample to succeed after it says so, though it opened nothing.
    mac.sample(now(), &[]);
    let said = w.next("sample");
    assert_eq!(said["opened"], 0);
    assert_eq!(live(&mac), (true.into(), serde_json::json!([])));
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
        .arg(env!("CARGO_BIN_EXE_immune"))
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
    while !mac.status()["watching"].is_null() {
        assert!(Instant::now() < end, "the orphaned watcher kept the store");
        std::thread::sleep(Duration::from_millis(50));
    }
    // It is gone and its id may be another process's now.
    std::mem::forget(reap);
}

#[test]
fn a_watcher_whose_parent_is_gone_before_it_starts_stops_at_once() {
    // As the app builder met it: a shell starts the watcher in the background and exits at
    // once, so the watcher may begin life already handed to launchd. It must not take that
    // for its parent and live on holding the store.
    let mac = Mac::new("orphan-at-start");
    let (out, pid) = (mac.root.join("out.txt"), mac.root.join("pid.txt"));
    let status = Command::new("/bin/sh")
        .env("HOME", mac.home())
        .current_dir(mac.home())
        .arg("-c")
        .arg(r#""$0" watch --store "$1" --system-root "$2" > "$3" & echo $! > "$4""#)
        .arg(env!("CARGO_BIN_EXE_immune"))
        .arg(mac.store())
        .arg(mac.sys())
        .arg(&out)
        .arg(&pid)
        .status()
        .unwrap();
    assert!(status.success());
    let watcher: i32 = std::fs::read_to_string(&pid)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let reap = Reap(watcher);
    let end = Instant::now() + WAIT;
    // SAFETY: kill(2) with signal 0 only asks whether the process exists.
    while unsafe { libc::kill(watcher, 0) } == 0 {
        assert!(Instant::now() < end, "the orphaned watcher lives on");
        std::thread::sleep(Duration::from_millis(20));
    }
    // It is gone and its id may be another process's now.
    std::mem::forget(reap);
    assert!(mac.status()["watching"].is_null());
    let said = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(!said.contains("\"problem\""), "{said}");
}

// What the status answers first: whether this Mac is watched and quiet. What is not covered
// is apart, aggregated, and never a thing to look at.

/// The results of `immune status --json` as a person's questions: what needs a look, the state
/// of this Mac, and the ids of what is not covered, what the owner can fix first.
fn answered(r: &Value) -> (u64, String, Vec<String>) {
    let kinds = r["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["id"].as_str().unwrap().to_string())
        .collect();
    (
        r["needs_a_look"]["total"].as_u64().unwrap(),
        r["this_mac"]["state"].as_str().unwrap().to_string(),
        kinds,
    )
}

#[test]
fn a_quiet_mac_needs_no_look_whatever_is_not_covered_and_a_planted_change_does() {
    // The owner saw "6 things need a look" on a Mac where nothing had changed: servers whose
    // sweep did not finish were counted as things to look at. What is not covered is said
    // once per cause, quietly, what he can fix apart from the limits of this version; what
    // needs a look is a change on his Mac.
    let mac = Mac::new("quiet");
    mac.put(".zshrc", "export A=1\n");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.put("dev/shop/yarn.lock", "# yarn lockfile v1\n");
    let servers = mac.root.join("servers");
    std::fs::create_dir_all(&servers).unwrap();
    std::fs::write(servers.join("web-1.txt"), "##end\n").unwrap();
    std::fs::write(servers.join("web-2.txt"), "##packages\n").unwrap();
    // The sweep ran long before the runs that read what it left.
    let swept = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for name in ["web-1.txt", "web-2.txt"] {
        let f = std::fs::File::options()
            .write(true)
            .open(servers.join(name))
            .unwrap();
        f.set_modified(swept).unwrap();
    }
    for _ in 0..2 {
        let out = mac.run_cmd_servers(&servers).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let r = mac.status().clone();
    let (needs, state, kinds) = answered(&r);
    assert_eq!((needs, state.as_str()), (0, "watched"), "{r:#}");
    let who = |id: &str| {
        r["not_covered"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["id"] == id)
            .unwrap_or_else(|| panic!("{id}: {r:#}"))["who"]
            .clone()
    };
    assert_eq!(kinds[0], "servers-not-checked", "{r:#}");
    assert_eq!(who("servers-not-checked"), "you");
    for limit in ["not-understood", "vulnerability-list-not-downloaded"] {
        assert_eq!(who(limit), "nothing");
    }
    // The servers, and turning on the event level, which this Mac does not have.
    assert_eq!(who("program-starts-not-seen"), "you");
    assert_eq!(kinds.iter().filter(|k| who(k) == "you").count(), 2, "{r:#}");
    let servers_item = &r["not_covered"][0];
    assert_eq!(
        (&servers_item["title"], &servers_item["examples_text"]),
        (
            &"1 of your servers was not checked last time.".into(),
            &serde_json::json!(["web-2"])
        )
    );
    // Counted from the sweep itself, not from the run that read its files.
    assert_eq!(servers_item["since_at"], 1_700_000_000);
    assert_eq!(r["this_mac"]["live"], false);
    let watched: Vec<(String, u64, String)> = r["this_mac"]["watched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| {
            (
                w["what"].as_str().unwrap().to_string(),
                w["count"].as_u64().unwrap(),
                w["how"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        watched.contains(&("shell startup files".into(), 1, "hourly".into())),
        "{watched:?}"
    );
    // A kind with nothing to watch on this Mac is left out.
    assert!(watched.iter().all(|w| w.1 > 0), "{watched:?}");
    assert!(
        !watched.iter().any(|w| w.0.starts_with("editor tasks")),
        "{watched:?}"
    );

    // A program set to start by itself, planted: the one thing that needs a look.
    mac.put(
        "Library/LaunchAgents/com.example.planted.plist",
        "<plist/>\n",
    );
    let out = mac.run_cmd_servers(&servers).output().unwrap();
    assert!(out.status.success());
    let line = String::from_utf8_lossy(&out.stdout);
    assert!(
        line.contains(
            " 1 thing needs a look, 1 new in this run. You can fix: servers not checked last time, program starts not seen. Limits of this version: "
        ),
        "{line}"
    );
    assert_eq!(answered(&mac.status()).0, 1);
}

#[test]
fn a_folder_macos_asks_permission_for_is_never_entered_and_what_was_known_there_stays() {
    // A run the app starts must never make macOS ask the owner for his Documents. A project
    // he once pointed the program at there is not gone because the next run did not look.
    let mac = Mac::new("guarded");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.put("Documents/notes/.git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(mac.home().join("Documents/notes/.git/hooks")).unwrap();
    // Pointed there by the owner: read.
    let out = mac
        .run_cmd()
        .arg("--checkouts-root")
        .arg(mac.home().join("Documents"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let known = "SELECT subject FROM assertion WHERE layer = 'live' AND predicate = 'located_on'
                 AND subject LIKE 'checkout:%' ORDER BY subject";
    assert_eq!(mac.rows(known), ["checkout:machine:mac/Documents/notes"]);

    // A project made there later that an agent worked in and nobody pointed at: neither the
    // walk of the home folder nor the agent's session leads into it.
    mac.put("Documents/other/.git/HEAD", "ref: refs/heads/main\n");
    let cwd = mac.home().join("Documents/other");
    mac.put(
        ".claude/projects/-other/s1.jsonl",
        &format!("{}\n", serde_json::json!({ "cwd": cwd })),
    );

    // The run the app starts: Documents is not entered, the project there stays.
    mac.run();
    assert_eq!(
        mac.rows(known),
        [
            "checkout:machine:mac/Documents/notes",
            "checkout:machine:mac/dev/shop"
        ]
    );
    let r = mac.status().clone();
    let item = r["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "protected-folders")
        .unwrap_or_else(|| panic!("{r:#}"))
        .clone();
    assert_eq!(
        (
            &item["who"],
            &item["title"],
            &item["count"],
            &item["examples_text"]
        ),
        (
            &"nothing".into(),
            &"Projects inside a folder macOS protects are not checked.".into(),
            &1.into(),
            &serde_json::json!(["Documents"])
        )
    );
    assert_eq!(r["this_mac"]["state"], "watched", "{r:#}");

    // A watcher started by the app does not look there either: the hooks of the project in
    // Documents are not among its places, those of the other one are.
    let mut w = mac.watch();
    assert_eq!(
        w.next("watching")["places"],
        TABLE_PLACES + HOME_PLACES + CHECKOUT_PLACES
    );
}

#[test]
fn a_watched_place_linked_into_documents_is_neither_entered_nor_subscribed_to_and_is_said() {
    // Dotfiles kept in Documents and linked from the home folder are common, and a project
    // may be moved there and linked back between two full runs. FSEvents resolves a path it
    // is given, so subscribing to such a link would enter Documents too. Documents is shut
    // here first, as macOS keeps it: a watcher that entered it would say a place cannot be
    // watched. Then it is open: what is behind the links is still not subscribed to.
    use std::os::unix::fs::{PermissionsExt, symlink};
    let mac = Mac::new("linked-guarded");
    let docs = mac.home().join("Documents");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    std::fs::create_dir_all(mac.home().join("dev/shop/.git/hooks")).unwrap();
    std::fs::create_dir_all(&docs).unwrap();
    mac.run();
    std::fs::rename(mac.home().join("dev/shop"), docs.join("shop")).unwrap();
    symlink(docs.join("shop"), mac.home().join("dev/shop")).unwrap();
    mac.put("Documents/zshrc", "export A=1\n");
    symlink(docs.join("zshrc"), mac.home().join(".zshrc")).unwrap();
    mac.put("Documents/ssh/config", "Host web\n");
    symlink(docs.join("ssh"), mac.home().join(".ssh")).unwrap();
    mac.put("Documents/claude/settings.json", "{}\n");
    symlink(docs.join("claude"), mac.home().join(".claude")).unwrap();
    struct Open(PathBuf);
    impl Drop for Open {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    // The table's places but the shell file and the three ssh files, the home folder's but
    // the agent's settings, and none of the project's.
    let places = TABLE_PLACES - 4 + HOME_PLACES - 1;
    let open = Open(docs.clone());
    std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut w = mac.watch();
    assert_eq!(w.next("watching")["places"], places);
    // Its first reading, at start, follows the lines of places it cannot watch.
    w.next("read");
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    assert!(w.stop().success());
    drop(open);
    assert_eq!(
        mac.rows(
            "SELECT completeness || '|' || reason FROM coverage
             WHERE reader = 'watched-places' AND kind = 'folders macOS asks permission for'
             ORDER BY id DESC LIMIT 1"
        ),
        ["none|not looked into: ~/Documents"]
    );
    // Open, the targets of the links are not subscribed to either.
    let mut w = mac.watch();
    assert_eq!(w.next("watching")["places"], places);
    assert!(w.stop().success());
}

#[test]
fn a_watched_file_its_permissions_keep_closed_leaves_this_mac_watched_in_part_and_is_the_owners_to_fix()
 {
    // A watched place that is there and cannot be read because of its permissions is the
    // one thing on his own Mac the owner can do something about: the Mac is watched in part,
    // and the item says where and why.
    use std::os::unix::fs::PermissionsExt;
    let mac = Mac::new("in-part");
    let profile = mac.put(".zprofile", "export A=1\n");
    mac.run();
    struct Open(PathBuf);
    impl Drop for Open {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o644));
        }
    }
    let _open = Open(profile.clone());
    std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o000)).unwrap();
    mac.run();
    let r = mac.status().clone();
    assert_eq!(r["this_mac"]["state"], "watched_in_part", "{r:#}");
    let item = r["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "not-permitted")
        .unwrap_or_else(|| panic!("{r:#}"))
        .clone();
    assert_eq!(
        (&item["who"], &item["scope"], &item["title"]),
        (
            &"you".into(),
            &"this_mac".into(),
            &"1 file could not be opened because of its permissions.".into()
        )
    );
    assert_eq!(
        item["examples_text"],
        serde_json::json!(["~/.zprofile: Permission denied (os error 13)"])
    );
    // The page opens on it, not in green, and lists it under what he can fix.
    let page = mac.view();
    let state = &page[page.find("<section id=\"this-mac\">").unwrap()..];
    let state = &state[..state.find("</section>").unwrap()];
    assert!(
        state.contains("<strong>This Mac is watched in part</strong>")
            && !state.contains("--green"),
        "{state}"
    );
    let fix = &page[page.find("<section id=\"you-can-fix\">").unwrap()..];
    let fix = &fix[..fix.find("</section>").unwrap()];
    assert!(
        fix.contains("~/.zprofile: Permission denied (os error 13)"),
        "{fix}"
    );
}

#[test]
fn this_mac_says_live_for_what_a_running_watcher_sees_and_hourly_for_the_rest() {
    let mac = Mac::new("live");
    let keg = mac
        .sys()
        .join("opt/homebrew/Cellar/fmt-tool/1.4/bin/fmt-tool");
    std::fs::create_dir_all(keg.parent().unwrap()).unwrap();
    std::fs::write(keg, "#!/bin/sh\n").unwrap();
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.put("dev/shop/.vscode/tasks.json", ON_OPEN);
    mac.run();
    // Running programs are sampled only while a watcher runs.
    let sampled = "running programs and their connections";
    let tasks = "editor tasks that run when a project is opened";
    let how = |m: &Value, what: &str| {
        m["watched"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["what"] == what)
            .unwrap_or_else(|| panic!("{what}: {m}"))["how"]
            .clone()
    };
    let before = mac.status()["this_mac"].clone();
    assert!(!before["watched"].to_string().contains(sampled), "{before}");
    // Seen within seconds only while a watcher runs.
    assert_eq!(how(&before, tasks), "hourly");
    let mut w = mac.watch().started();
    mac.put(".zshrc", "one\n");
    w.until("read", |v| count(v, "new") == 1);
    let m = mac.status()["this_mac"].clone();
    assert_eq!(m["live"], true);
    assert!(m["live_read_at"].as_i64().unwrap() > 0, "{m}");
    assert_eq!(how(&m, "shell startup files"), "live");
    assert_eq!(how(&m, tasks), "live");
    assert_eq!(how(&m, "Homebrew packages"), "hourly");
    assert_eq!(how(&m, sampled), "sampled");
    // A watcher that stopped samples nothing: the entry goes with it, and nothing is seen
    // within seconds any more.
    assert!(w.stop().success());
    let after = mac.status()["this_mac"].clone();
    assert!(!after["watched"].to_string().contains(sampled), "{after}");
    assert_eq!(how(&after, tasks), "hourly");
    assert_eq!(how(&after, "shell startup files"), "hourly");
}

#[test]
fn the_watcher_writes_no_page_and_the_page_asked_for_after_a_change_shows_it() {
    // A change can come every few seconds and writing the pages costs seconds of processor
    // time, for pages nobody may have open: the watcher writes none. The page the owner asks
    // for must never say "Nothing needs a look" while a change waits, and asking again with
    // nothing new costs no writing.
    let mac = Mac::new("view-fresh");
    mac.put(".zshrc", "one\n");
    mac.put(".zprofile", "one\n");
    mac.run();
    let summary = mac.root.join("store/view.html");
    let mut w = mac.watch().started();
    let page = mac.view_if_stale();
    assert!(page.contains("<h1>Nothing needs a look</h1>"), "{page}");
    std::fs::write(&summary, "as it was").unwrap();
    assert!(mac.view_if_stale().starts_with("as it was"));
    mac.put(".zprofile", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert_eq!(std::fs::read_to_string(&summary).unwrap(), "as it was");
    let page = mac.view_if_stale();
    assert!(page.contains("<h1>1 thing needs a look</h1>"), "{page}");
    // A watched file that can no longer be opened changes no fact, only what the reading
    // covered: the page asked for says the Mac is watched in part.
    use std::os::unix::fs::PermissionsExt;
    let closed = mac.put(".zshrc.new", "two\n");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::rename(&closed, mac.home().join(".zshrc")).unwrap();
    w.until("read", |_| true);
    let page = mac.view_if_stale();
    assert!(page.contains("This Mac is watched in part"), "{page}");
    let _ = std::fs::set_permissions(
        mac.home().join(".zshrc"),
        std::fs::Permissions::from_mode(0o644),
    );
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
}

#[test]
fn pages_asked_for_are_written_again_when_one_is_gone_or_they_are_an_hour_old() {
    // What changes with time alone, such as an answer that expires, is shown at most an hour
    // late; a page removed is never named as there.
    let mac = Mac::new("view-old");
    mac.run();
    let summary = mac.root.join("store/view.html");
    let made = mac.root.join("store/view/made.json");
    mac.view_if_stale();
    std::fs::write(&summary, "as it was").unwrap();
    let mut basis: Value = serde_json::from_str(&std::fs::read_to_string(&made).unwrap()).unwrap();
    let at = basis["made_at"].as_i64().unwrap();
    basis["made_at"] = (at - 3590).into();
    std::fs::write(&made, basis.to_string()).unwrap();
    assert!(mac.view_if_stale().starts_with("as it was"));
    basis["made_at"] = (now() - 3601).into();
    std::fs::write(&made, basis.to_string()).unwrap();
    assert!(mac.view_if_stale().starts_with("<!doctype html>"));
    // Made in the future, by a clock set back since: not current either.
    std::fs::write(&summary, "as it was").unwrap();
    let mut basis: Value = serde_json::from_str(&std::fs::read_to_string(&made).unwrap()).unwrap();
    basis["made_at"] = (now() + 600).into();
    std::fs::write(&made, basis.to_string()).unwrap();
    assert!(mac.view_if_stale().starts_with("<!doctype html>"));
    let changes = mac.root.join("store/view/changes.html");
    std::fs::write(&summary, "as it was").unwrap();
    std::fs::remove_file(&changes).unwrap();
    assert!(mac.view_if_stale().starts_with("<!doctype html>"));
    assert!(changes.is_file());
    // Another program writes its own pages.
    std::fs::write(&summary, "as it was").unwrap();
    let other = mac.root.join("immune-copy");
    std::fs::copy(env!("CARGO_BIN_EXE_immune"), &other).unwrap();
    let out = within(
        Command::new(&other)
            .env("HOME", mac.home())
            .args(["view", "--no-open", "--if-stale", "--store"])
            .arg(mac.store()),
    );
    assert!(out.status.success());
    assert!(
        std::fs::read_to_string(&summary)
            .unwrap()
            .starts_with("<!doctype html>")
    );
}

#[test]
fn after_new_program_starts_a_page_asked_for_writes_again_the_summary_and_the_rules_page_alone() {
    // A click after program starts were read shows them: the pages that count them are
    // written again, once, and the rest, which cost the most, are not.
    let mac = Mac::new("view-events");
    mac.run();
    let page = |name: &str| mac.root.join("store").join(name);
    let made = page("view/made.json");
    mac.view_if_stale();
    assert!(
        std::fs::read_to_string(page("view/happens.js"))
            .unwrap()
            .contains("\"view/live.js?\"")
    );
    let as_made: Value = serde_json::from_str(&std::fs::read_to_string(&made).unwrap()).unwrap();
    for name in ["view.html", "view/rules.html", "view/changes.html"] {
        std::fs::write(page(name), "as it was").unwrap();
    }
    let mut moved = as_made.clone();
    moved["events"] = "a reading before the latest".into();
    std::fs::write(&made, moved.to_string()).unwrap();
    assert!(mac.view_if_stale().starts_with("<!doctype html>"));
    assert!(
        std::fs::read_to_string(page("view/rules.html"))
            .unwrap()
            .starts_with("<!doctype html>")
    );
    assert_eq!(
        std::fs::read_to_string(page("view/changes.html")).unwrap(),
        "as it was"
    );
    let after: Value = serde_json::from_str(&std::fs::read_to_string(&made).unwrap()).unwrap();
    assert_eq!(
        after, as_made,
        "the event basis is kept as now, the rest as made"
    );
    // Current again: nothing is written.
    std::fs::write(page("view.html"), "as it was").unwrap();
    assert!(mac.view_if_stale().starts_with("as it was"));
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A detached interpreter given code on its command line, as a sample reads it.
fn detached_code() -> Value {
    serde_json::json!({ "pid": 4242, "start": 7, "parent": 1,
                        "executable": "/opt/tools/bin/node", "name": "node",
                        "terminal": false, "args": ["node", "-e", "x"] })
}

/// Waits until a query of the store gives a row.
fn until_row(mac: &Mac, sql: &str) -> Vec<String> {
    let end = Instant::now() + WAIT;
    loop {
        if let Ok(conn) = Connection::open(mac.store())
            && let Ok(mut stmt) = conn.prepare(sql)
        {
            let rows: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            if !rows.is_empty() {
                return rows;
            }
        }
        assert!(Instant::now() < end, "no row for {sql}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A watcher on `mac` that takes a sample every second.
fn sampling(mac: &Mac) -> Watcher {
    let mut cmd = mac.watch_cmd();
    cmd.args(["--sample-every", "1"]);
    Watcher::start(cmd).started()
}

#[test]
fn a_sample_that_opens_a_finding_says_so_in_one_line_and_a_quiet_sample_says_nothing() {
    // The app refreshes on a line; a line for every quiet sample would be a line every
    // thirty seconds for nothing.
    let mac = Mac::new("sample");
    // A server read by the run, which a sample never reads.
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
    let t = now();
    mac.sample(t, &[detached_code()]);
    let mut w = sampling(&mac);
    until_row(&mac, "SELECT executable FROM tracked_process");
    mac.view_if_stale();
    // The later sample also sees a shell, so the count the status shows is the latest one.
    let shell = serde_json::json!({ "pid": 4243, "start": 7, "parent": 1,
                                    "executable": "/bin/zsh", "name": "zsh",
                                    "terminal": true, "args": ["zsh"] });
    mac.sample(t + 60, &[detached_code(), shell]);
    let said = w.until("sample", |_| true);
    assert_eq!(
        (count(&said, "opened"), count(&said, "needs_a_look_total")),
        (1, 1)
    );
    // The page asked for after the line shows what the sample opened.
    mac.view_if_stale();
    let summary = std::fs::read_to_string(mac.root.join("store/view.html")).unwrap();
    assert!(
        summary.contains("<h1>1 thing needs a look</h1>"),
        "{summary}"
    );
    // The pages name the sample among the runs. It reads only programs: it is not a run that
    // left out the server the full run read.
    let changes = std::fs::read_to_string(mac.root.join("store/view/changes.html")).unwrap();
    assert!(changes.contains("sample of running programs and their connections"));
    assert!(!changes.contains("were not read in this run"), "{changes}");
    assert!(said["at"].as_str().unwrap().ends_with('Z'), "{said}");
    // Two more samples of the same process are quiet: two seconds at one a second.
    let run = "SELECT last_seen_run FROM tracked_process";
    let before = mac.rows(run);
    std::thread::sleep(Duration::from_millis(2500));
    assert_ne!(
        mac.rows(run),
        before,
        "no sample was taken at the cadence asked for"
    );
    assert_eq!(w.lines("sample").len(), 1, "{:?}", w.seen);
    assert!(w.lines("problem").is_empty(), "{:?}", w.seen);
    // A sample's coverage is one row per kind, replaced at every sample.
    assert_eq!(
        mac.rows("SELECT kind FROM coverage WHERE reader = 'processes' ORDER BY kind"),
        [
            "internet connections of this user's programs, sampled",
            "running programs of this user, sampled"
        ]
    );
    // The finding rests on the journal entry of the sample that raised it.
    assert_eq!(
        mac.rows(
            "SELECT j.entry FROM finding_basis b JOIN journal j ON j.seq = b.journal
             JOIN finding f ON f.id = b.finding WHERE f.rule = 'processes.detached-inline-code'"
        ),
        ["sampled"]
    );
    // The page says what a sample cannot see, apart from what is not covered, and names the
    // sample among the latest runs.
    let page = mac.view();
    assert!(
        page.contains("does not see a program that started and ended between two samples"),
        "{page}"
    );
    assert!(page.contains("sample of running programs and their connections"));
    // A sample reads only programs: it is not a run that left the other readings out.
    assert!(!page.contains("were not read in this run"), "{page}");
    let r = mac.status().clone();
    assert_eq!(r["this_mac"]["state"], "watched", "{r:#}");
    let sampled = r["this_mac"]["watched"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["how"] == "sampled")
        .unwrap_or_else(|| panic!("{r:#}"))
        .clone();
    assert_eq!(
        (&sampled["what"], &sampled["count"]),
        (&"running programs and their connections".into(), &2.into())
    );
    // Running programs are no longer a limit of this version.
    let ids: Vec<&str> = r["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "program-starts-not-seen",
            "project-autorun",
            "home-autorun",
            "vulnerability-list-not-downloaded",
            "vulnerability-data-old",
            "persistence-not-read",
            "vulnerabilities-not-compared",
            "package-managers-elsewhere-not-found"
        ],
        "{r:#}"
    );
    // The summary counts what the latest sample saw, and its section says it in numbers:
    // no list of running programs is kept.
    assert!(
        page.contains(
            "<a href=\"view/this-mac.html#running-programs-and-their-connections\">Running programs and their connections: 2</a>"
        ),
        "{page}"
    );
    let at = page
        .find("<section id=\"running-programs-and-their-connections\">")
        .unwrap();
    let shown = &page[at..at + page[at..].find("</section>").unwrap()];
    assert!(
        shown.contains("saw 2 running programs and ") && shown.contains("no list of them is"),
        "{shown}"
    );
    assert!(w.stop().success());
}

#[test]
fn a_folder_macos_asks_permission_for_does_not_lengthen_the_report_of_a_quiet_mac() {
    // Every Mac with a Documents folder had its report end in "1 reading read nothing ...
    // changes unknown where nothing was read": a folder not looked into is not a reading
    // that read nothing, and it is said under what is not covered.
    let mac = Mac::new("guarded-quiet");
    mac.put("Documents/notes.txt", "x\n");
    mac.run();
    let out = mac.run_cmd().output().unwrap();
    let line = String::from_utf8_lossy(&out.stdout);
    assert!(line.contains("Since last run: no changes."), "{line}");
    assert!(!line.contains("read nothing"), "{line}");
    let r = mac.status().clone();
    assert_eq!(r["last_finished_run"]["readings"]["failed"], 0, "{r:#}");
    assert!(
        r["not_covered"].to_string().contains("protected-folders"),
        "{r:#}"
    );
}

#[test]
fn a_sample_waits_for_a_full_run_and_a_stop_while_it_waits_is_a_clean_one() {
    let mac = Mac::new("sample-lock");
    mac.run();
    let t = now();
    mac.sample(t, &[detached_code()]);
    let mut w = sampling(&mac);
    until_row(&mac, "SELECT executable FROM tracked_process");
    // A full run holds the lock: the sample that would open the finding waits for it.
    let held = std::fs::File::open(mac.root.join("store")).unwrap();
    held.lock().unwrap();
    mac.sample(t + 60, &[detached_code()]);
    // Nothing can say that a sample did not happen; three of its seconds pass.
    std::thread::sleep(Duration::from_secs(3));
    assert!(w.lines("sample").is_empty(), "{:?}", w.seen);
    w.signal(libc::SIGTERM);
    assert!(w.exit().success());
    drop(held);
    assert!(
        mac.rows("SELECT id FROM finding").is_empty(),
        "a stopped watcher raised a finding"
    );
}

#[test]
fn a_sample_that_fails_is_a_problem_line_and_the_watcher_goes_on() {
    let mac = Mac::new("sample-failed");
    mac.put(".zshrc", "one\n");
    mac.run();
    std::fs::write(mac.root.join("sample.json"), "not a reading").unwrap();
    let mut w = sampling(&mac);
    let p = w.until("problem", |v| v["code"] == "sample_failed");
    assert!(p["detail_text"].as_str().is_some(), "{p}");
    mac.put(".zshrc", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert!(w.stop().success());
}

// A store that has watched for months.

/// A Mac with a few projects, after its first full run and its watcher's first reading.
fn watched_for_a_while(tag: &str) -> Mac {
    let mac = Mac::new(tag);
    mac.put(".zshrc", "export EDITOR=vi\n");
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    for c in ["api", "site", "shop"] {
        mac.put(&format!("dev/{c}/.git/HEAD"), "ref: refs/heads/main\n");
        mac.put(&format!("dev/{c}/.git/hooks/pre-commit"), "#!/bin/sh\n");
        mac.put(&format!("dev/{c}/.vscode/tasks.json"), ON_OPEN);
    }
    // What this version does not read, named at every reading: a project's package scripts,
    // and the hooks of a working folder git keeps elsewhere.
    mac.put("dev/shop/package.json", "{\"scripts\": {}}\n");
    mac.put(
        "dev/shop-fix/.git",
        "gitdir: ../shop/.git/worktrees/shop-fix\n",
    );
    // A server the owner's check has read.
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
    let w = mac.watch().started();
    assert!(w.stop().success());
    mac
}

/// The history a watcher leaves after `readings` readings, made in two statements: the rows
/// of its latest reading again, each time under a run id of its own, with what each names as
/// not read.
fn add_watcher_history(mac: &Mac, readings: u32) {
    let conn = Connection::open(mac.store()).unwrap();
    let run: String = conn
        .query_row(
            "SELECT run_id FROM coverage WHERE run_id LIKE 'watch-%' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
         INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness, reason,
                               cause)
         SELECT reader, run_id || '-' || i, observed_at, scope, kind, completeness, reason, cause
         FROM n, coverage WHERE run_id = ?2",
        rusqlite::params![readings, run],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO coverage_lack (coverage, what, name)
         SELECT copy.id, l.what, l.name
         FROM coverage c JOIN coverage_lack l ON l.coverage = c.id
         JOIN coverage copy ON copy.run_id >= ?1 || '-' AND copy.run_id < ?1 || '.'
          AND copy.reader = c.reader AND copy.scope = c.scope AND copy.kind = c.kind
         WHERE c.run_id = ?1",
        [&run],
    )
    .unwrap();
}

/// How long a command takes on a Mac on its first day and on one with ten thousand readings
/// of its watcher behind it: the quickest of seven runs on each, taken in turn, so that the
/// two are measured under the same load and a busy moment of the Mac is not taken for cost.
fn first_day_and_later(tag: &str, args: &[&str]) -> (Duration, Duration) {
    let fresh = watched_for_a_while(&format!("{tag}-first"));
    let later = watched_for_a_while(&format!("{tag}-later"));
    add_watcher_history(&later, 10_000);
    let time = |mac: &Mac| {
        let mut cmd = mac.immune();
        cmd.args(args).arg("--store").arg(mac.store());
        let started = Instant::now();
        let out = within(&mut cmd);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        started.elapsed()
    };
    let (mut a, mut b) = (Duration::MAX, Duration::MAX);
    for _ in 0..7 {
        a = a.min(time(&fresh));
        b = b.min(time(&later));
    }
    (a, b)
}

#[test]
fn the_status_after_ten_thousand_readings_is_as_quick_as_on_the_first_day() {
    // The app asks for the status after every reading of its watcher and every sample. One
    // that grew with what the watcher has read would, after months of an open app, make the
    // panel slow and hold the store while the next reading waits.
    let (first, later) = first_day_and_later("status-flat", &["status", "--json"]);
    assert!(
        later < first * 3 / 2 + Duration::from_millis(5),
        "the status took {first:?} on the first day, {later:?} after ten thousand readings"
    );
}

#[test]
fn the_view_after_ten_thousand_readings_is_made_as_quickly_as_on_the_first_day() {
    // The owner's pages are written when he asks for them after a change; they must not take
    // longer the longer the app has been open.
    let (first, later) = first_day_and_later("view-flat", &["view", "--no-open"]);
    assert!(
        later < first * 3 / 2 + Duration::from_millis(5),
        "the view took {first:?} on the first day, {later:?} after ten thousand readings"
    );
}

/// The latest reading of each scope and kind of the watched places: scope, kind, the run that
/// made it and its completeness.
fn latest_watched(mac: &Mac) -> Vec<(String, String, String, String)> {
    let conn = Connection::open(mac.store()).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT scope, kind, run_id, completeness FROM coverage c
             WHERE reader = 'watched-places'
               AND id = (SELECT MAX(id) FROM coverage l
                         WHERE (l.reader, l.scope, l.kind) = (c.reader, c.scope, c.kind))
             ORDER BY scope, kind",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_change_in_one_watched_place_reads_again_only_its_reading_and_every_other_keeps_its_time() {
    // A reading of one place that wrote coverage for every place would say all of them were
    // read when they were not; one that read them all would read every place at every change.
    // A place that leads into Documents keeps it said that the reader did not look there: only
    // a reading of every place can say what it met.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("touched");
    mac.put(".zshrc", "export A=1\n");
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    mac.put("Documents/ssh/config", "Host web\n");
    symlink(mac.home().join("Documents/ssh"), mac.home().join(".ssh")).unwrap();
    let mut w = mac.watch().started();
    let before = latest_watched(&mac);
    let last_read = "SELECT CAST(last_read AS TEXT) FROM watcher";
    let read_every_place = mac.rows(last_read);
    // So that a reading after it cannot have the same time to the second.
    std::thread::sleep(Duration::from_millis(1100));
    mac.put(".zshrc", "export A=2\n");
    w.until("read", |v| count(v, "changed") == 1);
    let after = latest_watched(&mac);
    assert_eq!(after.len(), before.len());
    let read_again = |scope: &str, kind: &str| {
        (kind == "shell profiles of zsh and bash" && scope.starts_with("machine:"))
            || (kind == "content of a watched file" && scope.ends_with("/.zshrc"))
    };
    for (was, now) in before.iter().zip(&after) {
        assert_eq!((&was.0, &was.1), (&now.0, &now.1));
        if read_again(&now.0, &now.1) {
            assert_ne!(was.2, now.2, "{now:?}");
            assert!(now.2.starts_with("watch-"));
        } else {
            assert_eq!(was, now, "read again though no change was in it");
        }
    }
    assert_eq!(before.iter().filter(|r| read_again(&r.0, &r.1)).count(), 2);
    let guarded = after
        .iter()
        .find(|r| r.1 == "folders macOS asks permission for")
        .unwrap();
    assert_eq!(guarded.3, "none");
    // When every place was last read is not moved by a reading of some.
    assert_eq!(mac.rows(last_read), read_every_place);
}

/// How many readings the store keeps.
fn readings(mac: &Mac) -> i64 {
    mac.rows("SELECT CAST(COUNT(*) AS TEXT) FROM coverage")[0]
        .parse()
        .unwrap()
}

#[test]
fn a_mac_checked_every_hour_keeps_no_more_readings_after_a_month_than_after_a_day() {
    // Every full run reads everything; the readings no page or answer asks for one by one are
    // folded as it ends, so the store stops growing by them. The 20 latest runs are kept whole
    // (`store::RUNS_KEPT`).
    let mac = Mac::new("month");
    mac.put(".zshrc", "export A=1\n");
    mac.put("dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.put("dev/shop/package.json", r#"{"scripts": {"test": "true"}}"#);
    let mut counts = Vec::new();
    for _ in 0..25 {
        mac.run();
        counts.push(readings(&mac));
    }
    // Each run adds its readings until there are 22 runs: the 20 kept whole, and the first and
    // the last of what is older. From then on a run adds as many as it folds.
    assert!(counts[..22].windows(2).all(|w| w[0] < w[1]), "{counts:?}");
    assert!(counts[21..].iter().all(|n| *n == counts[21]), "{counts:?}");
    // The changes page still lists the runs kept whole as having read everything.
    let pages = mac.view();
    assert!(!pages.contains("were not read in this run"), "{pages}");
}

#[test]
fn the_first_check_of_a_store_kept_whole_before_folds_its_readings_and_gives_the_space_back() {
    // A store an earlier build kept every reading of: its first full run folds them, and the
    // file shrinks, so that a year of readings does not stay on the disk as free pages.
    let mac = Mac::new("earlier");
    mac.put(".zshrc", "export A=1\n");
    mac.run();
    {
        // A year of hourly readings before the first, as an earlier build left them: older
        // than every run, so with ids below them.
        let conn = Connection::open(mac.store()).unwrap();
        conn.execute(
            "WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 8760)
             INSERT INTO coverage (id, reader, run_id, observed_at, scope, kind, completeness,
                                   reason, cause)
             SELECT -(i * 10000 + id), reader, 'earlier-' || i, observed_at - i * 3600, scope,
                    kind, completeness, reason, cause
             FROM n, coverage WHERE id > 0",
            [],
        )
        .unwrap();
    }
    let size = || std::fs::metadata(mac.store()).unwrap().len();
    let (rows, before) = (readings(&mac), size());
    mac.run();
    assert!(readings(&mac) * 100 < rows, "{} of {rows}", readings(&mac));
    assert!(size() * 10 < before, "{} bytes of {before}", size());
}

#[test]
fn a_watcher_started_again_reads_every_place_at_its_first_reading_however_small_the_change() {
    // What a watcher reads by the paths of a change is what changed since it read every place;
    // one started again, which goes on from the history FSEvents kept, has not read them yet.
    let mac = Mac::new("again-all");
    mac.put(".zshrc", "one\n");
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    assert!(mac.watch().started().stop().success());
    let before = latest_watched(&mac);
    let last_read = "SELECT CAST(last_read AS TEXT) FROM watcher";
    let read_every_place = mac.rows(last_read);
    // So that a reading after it cannot have the same time to the second.
    std::thread::sleep(Duration::from_millis(1100));
    let mut w = mac.watch();
    w.next("watching");
    // After the history kept while it was stopped, which says nothing changed: as measured in
    // `a_change_made_while_the_watcher_was_stopped_is_read_when_it_starts_again`.
    std::thread::sleep(Duration::from_secs(3));
    mac.put(".zshrc", "two\n");
    w.until("read", |v| count(v, "changed") == 1);
    assert_ne!(mac.rows(last_read), read_every_place);
    let after = latest_watched(&mac);
    assert_eq!(after.len(), before.len());
    assert!(
        before.iter().zip(&after).all(|(was, now)| was.2 != now.2),
        "{after:?}"
    );
    assert!(w.stop().success());
}

#[test]
fn changes_in_two_places_that_come_before_the_reading_is_due_are_both_read() {
    // A reading waits for a quiet second after a change; a second change meanwhile adds its
    // places to those of the first, and never takes their place.
    let mac = Mac::new("two-batches");
    mac.put(".zshrc", "one\n");
    let mut w = mac.watch().started();
    mac.put(".zshrc", "two\n");
    // Long enough for FSEvents to deliver the first change on its own, short of the quiet second.
    std::thread::sleep(Duration::from_millis(500));
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    let seen = std::cell::Cell::new((0, 0));
    w.until("read", |v| {
        let (changed, new) = seen.get();
        seen.set((changed + count(v, "changed"), new + count(v, "new")));
        seen.get() == (1, 1)
    });
}

#[test]
fn a_reading_of_some_places_between_two_of_every_place_saves_no_second_copy_of_an_unchanged_listing()
 {
    // A copy of what was read is saved only when it differs from the last one of its name: a
    // reading of some places is saved under a name of its own, so that the next reading of
    // every place is not saved again only because a shorter listing came between.
    let mac = Mac::new("raw-apart");
    mac.put(".zshrc", "export A=1\n");
    // A place the reading of some places does not list.
    mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
    let copies = |mac: &Mac| {
        std::fs::read_dir(mac.store().with_file_name("raw"))
            .unwrap()
            .filter(|d| {
                d.as_ref()
                    .unwrap()
                    .path()
                    .join("watched-places.txt")
                    .exists()
            })
            .count()
    };
    let mut w = mac.watch().started();
    let first = copies(&mac);
    assert!(first >= 1);
    // Written again as it was: the place is touched, and what is read of it is the same.
    mac.put(".zshrc", "export A=1\n");
    w.next("read");
    assert!(w.stop().success());
    mac.run();
    assert_eq!(copies(&mac), first);
}

const PROFILES: &str = "shell profiles of zsh and bash";
const AGENTS: &str = "launch agents and daemons";

/// A watcher that looks again at what to watch every two seconds, as it does every minute.
fn looking(mac: &Mac) -> Watcher {
    let mut cmd = mac.watch_cmd();
    cmd.args(["--alive-every", "2"]);
    Watcher::start(cmd).started()
}

/// The run that made the latest reading of this kind of watched places on this Mac.
fn read_by(mac: &Mac, kind: &str) -> String {
    latest_watched(mac)
        .into_iter()
        .find(|r| r.0.starts_with("machine:") && r.1 == kind)
        .unwrap_or_else(|| panic!("{kind} was read"))
        .2
}

/// Writes through `path` and asserts that the reading of `kind` is made again by the
/// watcher's next look at what to watch, whatever the path of the change was taken for.
fn read_again_by_the_next_look(mac: &Mac, w: &mut Watcher, kind: &str, path: &Path) {
    let before = read_by(mac, kind);
    std::fs::write(path, "changed\n").unwrap();
    w.next("read");
    if read_by(mac, kind) == before {
        w.next("alive");
        w.next("read");
    }
    assert_ne!(read_by(mac, kind), before, "{kind} was not read again");
}

#[test]
fn a_file_one_reading_reaches_by_a_name_in_another_case_is_read_again_by_the_next_look() {
    // A shell profile that is a link to a launch agent, spelled in another case: FSEvents names
    // the file as it is on the disk, which is in the launch agents' place only.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("other-case");
    let file = mac.put("Library/LaunchAgents/helper.plist", "<plist/>\n");
    let link = mac.home().join("LIBRARY/LaunchAgents/helper.plist");
    symlink(link, mac.home().join(".zshrc")).unwrap();
    let mut w = looking(&mac);
    read_again_by_the_next_look(&mac, &mut w, PROFILES, &file);
    assert!(w.stop().success());
}

#[test]
fn a_file_one_reading_reaches_by_a_name_in_another_unicode_form_is_read_again_by_the_next_look() {
    // The same with a name made on the disk decomposed and named by the link composed, which
    // the file system takes as one name.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("other-form");
    let file = mac.put("Library/LaunchAgents/cafe\u{301}.plist", "<plist/>\n");
    let link = mac.home().join("Library/LaunchAgents/caf\u{e9}.plist");
    symlink(link, mac.home().join(".zshrc")).unwrap();
    let mut w = looking(&mac);
    read_again_by_the_next_look(&mac, &mut w, PROFILES, &file);
    assert!(w.stop().success());
}

#[test]
fn what_a_new_link_to_a_watched_path_leads_to_is_read_again_by_the_next_look() {
    // A launch agent made as a link to a shell profile the watcher subscribes to already: no
    // path is new, but a change there is now one of the launch agents too.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("new-link");
    let profile = mac.put(".zlogin", "echo one\n");
    std::fs::create_dir_all(mac.home().join("Library/LaunchAgents")).unwrap();
    let mut w = looking(&mac);
    let agent = mac
        .home()
        .join("Library/LaunchAgents/org.example.helper.plist");
    symlink(&profile, agent).unwrap();
    w.until("read", |v| count(v, "new") == 1);
    read_again_by_the_next_look(&mac, &mut w, AGENTS, &profile);
    assert!(w.stop().success());
}

#[test]
fn what_a_launch_agent_leads_to_through_a_link_outside_every_watched_place_is_read_again_by_the_next_look()
 {
    // A launch agent that is a link to a link outside every watched place, which leads to one
    // shell profile and is turned to another: both are watched already, so no path changes,
    // and nothing watched is written. What the launch agent leads to has changed.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("hop");
    let bashrc = mac.put(".bashrc", "echo one\n");
    let zprofile = mac.put(".zprofile", "echo two\n");
    let elsewhere = mac.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let hop = elsewhere.join("agent");
    symlink(&bashrc, &hop).unwrap();
    std::fs::create_dir_all(mac.home().join("Library/LaunchAgents")).unwrap();
    let agent = mac
        .home()
        .join("Library/LaunchAgents/org.example.helper.plist");
    symlink(&hop, agent).unwrap();
    let mut w = looking(&mac);
    let agents = read_by(&mac, AGENTS);
    std::fs::remove_file(&hop).unwrap();
    symlink(&zprofile, &hop).unwrap();
    w.next("read");
    assert_ne!(read_by(&mac, AGENTS), agents);
    assert!(w.stop().success());
}

#[test]
fn a_link_outside_every_watched_place_turned_while_the_watcher_was_stopping_is_read_at_its_start() {
    // The launch agent leads through a link outside every watched place, which is turned to
    // another shell profile; the watcher stops before its next look, so no look saw the map
    // change. No full run follows and nothing watched is written: the start alone reads it.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("hop-restart");
    let bashrc = mac.put(".bashrc", "echo one\n");
    let zprofile = mac.put(".zprofile", "echo two\n");
    let elsewhere = mac.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let hop = elsewhere.join("agent");
    symlink(&bashrc, &hop).unwrap();
    std::fs::create_dir_all(mac.home().join("Library/LaunchAgents")).unwrap();
    let agent = mac
        .home()
        .join("Library/LaunchAgents/org.example.helper.plist");
    symlink(&hop, agent).unwrap();
    let w = not_looking(&mac);
    let agents = read_by(&mac, AGENTS);
    std::fs::remove_file(&hop).unwrap();
    symlink(&zprofile, &hop).unwrap();
    assert!(w.stop().success());
    assert_eq!(read_by(&mac, AGENTS), agents, "read before the start");
    let mut w = mac.watch();
    w.next("watching");
    let first = w.next("read");
    assert_ne!(read_by(&mac, AGENTS), agents);
    assert_eq!(count(&first, "changed"), 1, "{first}");
    assert!(w.stop().success());
}

#[test]
fn the_event_id_an_earlier_build_kept_is_emptied_so_that_build_reads_every_place_at_its_start() {
    // An earlier build replays from the id in `watcher.event_id` and reads every place only
    // when there is none. An id left there while this build ran would have it replay from a
    // point whose history it was never shown to cover.
    let mac = Mac::new("event-id");
    mac.put(".zshrc", "one\n");
    assert!(mac.watch().started().stop().success());
    let row = "SELECT event_id || '|' || volumes FROM watcher";
    assert_eq!(mac.rows(row), ["|"]);
    // As an earlier build left the row.
    let conn = Connection::open(mac.store()).unwrap();
    conn.execute(
        "UPDATE watcher SET event_id = '4242', volumes = '0123456789abcdef'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(mac.watch().started().stop().success());
    assert_eq!(mac.rows(row), ["|"]);
}

/// A watcher that does not look at what to watch while a test runs: what it owes is not made.
fn not_looking(mac: &Mac) -> Watcher {
    let mut cmd = mac.watch_cmd();
    cmd.args(["--alive-every", "3600"]);
    Watcher::start(cmd).started()
}

#[test]
fn a_reading_of_every_place_owed_when_the_watcher_stops_is_made_after_it_starts_again() {
    // A shell profile that is a link to a launch agent spelled in another case: a write to the
    // launch agent is read as the launch agents' alone, and every place is owed. The watcher
    // stops before its next look, as when the app quits or the Mac restarts.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("owed-restart");
    let file = mac.put("Library/LaunchAgents/helper.plist", "<plist/>\n");
    let link = mac.home().join("LIBRARY/LaunchAgents/helper.plist");
    symlink(link, mac.home().join(".zshrc")).unwrap();
    let mut w = not_looking(&mac);
    let profiles = read_by(&mac, PROFILES);
    std::fs::write(&file, "changed\n").unwrap();
    w.next("read");
    assert_eq!(
        read_by(&mac, PROFILES),
        profiles,
        "a reading of some places"
    );
    assert!(w.stop().success());
    let mut w = mac.watch();
    w.next("watching");
    w.next("read");
    assert_ne!(read_by(&mac, PROFILES), profiles);
    assert!(w.stop().success());
}

#[test]
fn a_change_only_another_readings_link_reaches_is_found_after_the_watcher_starts_again() {
    // A hook sample of a checkout, which git never runs, that `~/.zshrc` links to by a name in
    // another case: the reading of the hooks finds nothing to record, and only a reading of
    // every place finds the profile changed. The watcher stops before it makes that reading.
    use std::os::unix::fs::symlink;
    let mac = Mac::new("owed-sample");
    mac.put("dev/app/.git/HEAD", "ref: refs/heads/main\n");
    let sample = mac.put(
        "dev/app/.git/hooks/pre-commit.sample",
        "#!/bin/sh\nexit 0\n",
    );
    let link = mac.home().join("dev/app/.git/HOOKS/pre-commit.sample");
    symlink(link, mac.home().join(".zshrc")).unwrap();
    mac.run();
    let mut w = not_looking(&mac);
    let profiles = read_by(&mac, PROFILES);
    std::fs::write(&sample, "#!/bin/sh\necho two\n").unwrap();
    w.next("read");
    assert_eq!(
        read_by(&mac, PROFILES),
        profiles,
        "a reading of some places"
    );
    assert!(w.stop().success());
    let mut w = mac.watch();
    w.next("watching");
    w.next("read");
    assert!(w.stop().success());
    assert!(!mac.journaled(".zshrc", "changed").is_empty());
}

/// What `needs_a_look` lists, each `LookFinding` read as one object: the finding's reference,
/// the finding as listed and its words side by side, so a test names a field once.
fn looks(status: &serde_json::Value) -> serde_json::Value {
    let items = status["needs_a_look"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    items
        .iter()
        .map(|look| {
            let mut flat = serde_json::Map::new();
            for part in [&look["finding"]["finding"], &look["finding"], look] {
                for (k, v) in part.as_object().into_iter().flatten() {
                    if k != "finding" {
                        flat.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            serde_json::Value::Object(flat)
        })
        .collect()
}
