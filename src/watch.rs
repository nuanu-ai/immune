//! `immune watch`: learns within seconds that a watched place changed and records it, so that a
//! change does not wait for the next full run. It runs until it is told to stop, as a child of
//! its caller, or independently with `--standalone`, and installs nothing.
//!
//! The mechanism is FSEvents (`fsevents.rs`). An event is not trusted: it only says that
//! something under the watched paths changed, and where. After a quiet period the watcher runs
//! the watched-places reading of `immune run` and its rules, through the same code
//! (`watch_places`), as a small run of that reader alone, under the same run lock, in one
//! transaction. The lifecycle makes the events and the rules the findings, as in a full run;
//! the reading opens nothing that is not a regular file and keeps no content. A small run
//! writes no `run_started` or `run_finished`: those mark full runs, which `immune status`
//! reports on.
//!
//! What is read again. Each watched place belongs to one reading of `immune run`, a scope and a
//! kind, which writes its own coverage. A reading after events reads again only the readings
//! whose places the events' paths are in (`touched`), each whole, so no row of coverage says
//! a place was read when it was not, and every other reading keeps its own time. Every place
//! is read when that cannot be told: the watcher's first reading, a reading after one that
//! failed, a look at what to watch that found something new, a new way to a place or recovered,
//! events FSEvents says it dropped or coalesced, and a path in no watched place. The paths only
//! decide what is read first: whether a path is in a place is told by its spelling, and a file
//! reached by a link spelled in another case or Unicode form, or by a hard link, is not told by
//! it. So after any reading of some places every place is read at the next look at what to
//! watch, a minute later at most, unless one was read since: the place a change names is read
//! within seconds, every other within about a minute.
//!
//! Every start reads every place at once, whatever the store holds: what changed while no
//! watcher ran, and whatever one that stopped still owed, is read then, and nothing a watcher
//! knew only in memory is lost when it stops. A reading of every place on a Mac where nothing
//! changed records no change and opens nothing. The start closes the gap by its order: the
//! stream is running before that reading begins (`watch`), so a change made meanwhile is
//! either seen by the reading or brings an event and a reading after it. No event id is kept.
//!
//! Threads. The main thread owns the store, the stream and stdout. FSEvents calls back on its
//! own queue and only sends a batch into a channel; a signal handler only writes one byte into
//! a pipe, and a thread waiting on that pipe sends `Stop`. Nothing else is shared.
//!
//! Output: one JSON object per line on stdout, flushed at once, and nothing else there. Every
//! line has `format`, `event` and `at`, and its fields flat beside them:
//! `watching` (`places`, `cannot_see`), `read` (`new`, `changed`, `gone`, `opened`,
//! `needs_a_look_total`, open findings only), `sample` (`opened`, `needs_a_look_total`),
//! `program_starts` (`state`, `starts`, `read_at`, `program_starts_last_day`,
//! `program_starts_by_minute`, `in_words` with `state` and `caveats`: numbers and fixed words
//! only), `alive`, and `problem` (`code`, `detail_text`).
//!
//! Samples. Every `SAMPLE` the watcher takes a sample of this user's running programs and
//! their connections (`processes.rs`), under the run lock like a reading, in one transaction.
//! A `sample` line is printed only when a sample opened a finding, or is the first to succeed
//! after one that failed; another quiet sample prints nothing. A sample that failed is a
//! `problem` line, `sample_failed`, and the next is taken at its time.
//!
//! Program starts. Every `EVENTS_EVERY` (`--events-every`) the watcher reads the event level's
//! log (`events.rs`), under the run lock in its own transaction. A reading that took program
//! starts or changed the level's state prints a `program_starts` line, so that the app shows
//! it without asking for the status; a reading that failed is a `problem` line,
//! `events_failed`; one that took nothing prints nothing. After every reading it writes the
//! numbers of "As it happens" to `view/live.js` for a summary page that is open
//! (`happens::live`).
//!
//! Failures. A reading, a sample or a look at what to watch that failed is a `problem` line,
//! and is recorded in the `watcher_failed` table with what it said, under the run lock, where
//! the store can hold it; the next success of the same kind clears it. A failure the store did
//! not take is said in the watcher's lock file instead, and reads as a failure of the kind
//! `store`. While one stands, `immune status` does not say this Mac is watched live. A look at
//! what to watch that succeeds
//! after one that failed prints `watching` again and reads the watched places at once.
//!
//! While it waits for the run lock, which a full run holds for as long as it runs, it says it
//! is alive at its usual interval, so that a long run does not get it taken for dead.
//! It writes no page of the view, only that small file: a change can come every few seconds and the pages cost
//! seconds of processor time, mostly for pages nobody has open. A page is brought up to date
//! when it is asked for, by `immune view --if-stale`, which writes only when something the pages
//! rest on moved since they were made (`view::basis`). The watcher stops,
//! with exit 0, when stdout is closed or its parent process is gone. `--standalone` keeps it
//! running after its parent exits and permits launchd to supervise it directly.
//!
//! A new core. The watcher the login job runs, `--background`, looks at every turn of
//! `--alive-every` whether the path it was started from still holds the file it started from, by
//! device and inode. When an update put another file there, the watcher leaves by itself
//! with exit 0, between readings and never inside a write transaction: it says why on stderr and
//! in its lock file, and launchd, which keeps the job alive, starts it again from the new file.
//! The status reads that line once the lock is free and says the watcher is restarting on a new
//! core, for `RESTARTING_FOR` at most. A file removed with nothing in its place leaves the
//! watcher running: nothing could start again. A watcher started without `--background` is left
//! running on the file it opened.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::fsevents::{self, Where};
use crate::secrets::Text;
use crate::{autorun, checkouts, status, store, watched};

/// How long the watcher waits after the last event before it reads: a burst of writes, such
/// as an installer's or an editor's safe save, becomes one reading.
pub const QUIET: Duration = Duration::from_secs(1);
/// How long a reading may be put off by events that keep coming.
const MOST_WAIT: Duration = Duration::from_secs(5);
/// How long FSEvents gathers events into one batch, in seconds.
const LATENCY: f64 = 0.2;
/// How often the watcher says it is alive, and looks again at which checkouts the store holds.
const ALIVE: Duration = Duration::from_secs(60);
/// How long a watcher may go without making progress on its loop.
const STALLED: Duration = Duration::from_secs(180);
const HEARTBEAT: &str = "heartbeat";
const READY: &str = "ready";
const UNRECORDED: &str = "unrecorded";
/// The lock file's third line, with the time after it, of a watcher that left because the file it
/// was started from was replaced.
const CORE_REPLACED: &str = "core-replaced";
/// How long after a watcher left for a new core the status says it is restarting, in seconds.
/// launchd starts a job that ran longer than its `ThrottleInterval`, 30 seconds, again at once, and
/// one that ran shorter once the 30 seconds are over; past this, no watcher came back.
const RESTARTING_FOR: i64 = 120;
/// How much of what the store's error said the lock file keeps, in characters.
const UNRECORDED_CAP: usize = 300;
/// How long after a reading that failed it is tried again, unless an event comes first.
const RETRY: Duration = Duration::from_secs(30);
/// How often the watcher looks whether the process that started it is still there.
const PARENT: Duration = Duration::from_secs(1);
/// How often the watcher takes a sample of running programs. The rule over them wants two
/// samples a minute apart, so three samples at this cadence; a sample costs 10 to 20 ms.
pub const SAMPLE: Duration = Duration::from_secs(30);
/// How often the watcher reads the event level's log. A reading that took nothing costs a
/// look at the log's files and one row of `event_count`, see `--events-every`.
pub const EVENTS_EVERY: Duration = Duration::from_secs(10);
/// Another watcher holds the store.
pub const EXIT_WATCHING: u8 = 5;
/// How the run id of a watcher's reading begins; it writes no `run_started` or `run_finished`.
pub const RUN_PREFIX: &str = "watch-";
/// What the watcher cannot see, in its own words; in its first line and in the status.
pub const CANNOT_SEE: [&str; 3] = [
    "who made a change: it sees that a watched place changed, not who changed it",
    "a change undone within the quiet period of one second: the reading after it finds the place as it was and records no change",
    "a symbolic link among the watched places pointed elsewhere, within seconds: FSEvents watches where a link leads, so the new target is seen at the watcher's next look at what to watch, within a minute",
];

/// The watcher's tables, part of the store's schema (`store::schema`).
pub const SCHEMA: &str = "
-- The watcher's state: one row, written by its first reading, in the reading's transaction.
-- When the watcher started is not here but in its lock file, which it writes as it takes the
-- lock, so that nothing is written to the store outside the run lock.
CREATE TABLE watcher (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    last_read INTEGER NOT NULL   -- when a watcher last read every watched place, UTC seconds
);
-- What failed in a watcher and has not succeeded since: one row per kind, written by its first
-- failure, under the run lock, as `watcher` is. A row older than the watcher that holds the
-- lock now is a past watcher's and is not read.
CREATE TABLE watcher_failed (
    what   TEXT PRIMARY KEY,  -- `read`, `sample`, `resubscribe`, `events` or `full_check`
    at     INTEGER NOT NULL,  -- when it failed, UTC seconds
    detail TEXT NOT NULL      -- what the failure said
);
";

/// The kinds of failure kept in `watcher_failed`: a reading of the watched places, a sample of
/// running programs, a look at what to watch, a reading of the event level. A failed reading
/// of the event level stands for that kind alone: program starts are not claimed as seen,
/// and what is watched live otherwise still is.
pub const READ: &str = "read";
pub const SAMPLED: &str = "sample";
pub const RESUBSCRIBE: &str = "resubscribe";
pub const EVENTS: &str = "events";
pub const FULL_CHECK: &str = "full_check";
/// A failure of another kind that the store did not take: it is not in `watcher_failed` but in
/// the watcher's lock file, with what the store's error said.
pub const STORE: &str = "store";

/// A kind of failure in words, for a person.
pub fn failed_words(what: &str) -> &'static str {
    match what {
        READ => "reading of the watched places",
        SAMPLED => "sample of running programs",
        EVENTS => "reading of program starts",
        FULL_CHECK => "full check",
        STORE => "write to the store",
        _ => "look at what to watch",
    }
}

pub struct WatchArgs {
    pub store: PathBuf,
    pub system_root: PathBuf,
    pub home: PathBuf,
    /// A reading made of invented processes, read again at every sample, instead of the
    /// system's: for tests, which set the clock in it.
    pub sample_input: Option<PathBuf>,
    pub sample_every: Duration,
    /// How often it reads the event level's log: `EVENTS_EVERY`.
    pub events_every: Duration,
    /// How often it says it is alive and looks again at what to watch: `ALIVE`, shorter in
    /// tests.
    pub alive_every: Duration,
    /// Run under a supervisor, independently of the process that started it.
    pub standalone: bool,
    /// Own the initial and hourly full checks, independently of any UI.
    pub background: bool,
}

/// Parses what follows `immune watch`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<WatchArgs, String> {
    let (mut store, mut system_root) = (None, None);
    let (mut sample_input, mut sample_every, mut alive_every) = (None, SAMPLE, ALIVE);
    let mut events_every = EVENTS_EVERY;
    let mut standalone = false;
    let mut background = false;
    fn seconds(it: &mut impl Iterator<Item = String>, arg: &str) -> Result<Duration, String> {
        crate::value(it, arg)?
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=3600).contains(s))
            .map(Duration::from_secs)
            .ok_or(format!("{arg} takes a number of seconds from 1 to 3600"))
    }
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            "--system-root" => system_root = Some(crate::value(&mut it, &arg)?.into()),
            "--sample-input" => sample_input = Some(crate::value(&mut it, &arg)?.into()),
            "--sample-every" => sample_every = seconds(&mut it, &arg)?,
            "--events-every" => events_every = seconds(&mut it, &arg)?,
            "--alive-every" => alive_every = seconds(&mut it, &arg)?,
            "--standalone" => standalone = true,
            "--background" => {
                background = true;
                standalone = true;
            }
            _ => return Err(format!("unexpected argument: {arg}")),
        }
    }
    Ok(WatchArgs {
        store: store.map_or_else(crate::default_store, Ok)?,
        system_root: system_root.unwrap_or_else(|| PathBuf::from("/")),
        home: crate::user_home()?,
        sample_input,
        sample_every,
        events_every,
        alive_every,
        standalone,
        background,
    })
}

enum Msg {
    Events(fsevents::Batch),
    Stop,
}

/// Set once SIGTERM or SIGINT arrives; a reading waiting for the run lock gives up on it.
static STOP: AtomicBool = AtomicBool::new(false);
/// The write end of the pipe the signal handler writes to; -1 until it exists.
static SIGNAL_FD: AtomicI32 = AtomicI32::new(-1);

/// Runs the watcher until it is stopped. Exit 0 on SIGTERM or SIGINT; the error envelope of
/// `immune status --json` and a non-zero exit when it cannot watch at all.
pub fn watch(args: &WatchArgs) -> ExitCode {
    // The parent is taken before anything else: taken later, a parent that died meanwhile
    // would leave launchd recorded as the parent, and a parent-bound watcher would never stop.
    // Only an explicitly standalone watcher accepts launchd as its parent.
    // SAFETY: getppid(2) takes nothing and cannot fail.
    let parent = unsafe { libc::getppid() };
    if parent == 1 && !args.standalone {
        return ExitCode::SUCCESS;
    }
    // The file the job's watcher was started from, taken as early as the parent, so that a file
    // replaced after this is seen as replaced.
    let core = args.background.then(Core::started_from).flatten();
    // Next, so that a stop asked for at any moment after this is a clean one.
    let (tx, rx) = mpsc::channel();
    if let Err(e) = on_signals(tx.clone()) {
        return failed(&format!("the signal handlers could not be set: {e}"));
    }
    let folder = crate::home(&args.store);
    let unreadable = |e: &dyn std::fmt::Display| {
        crate::print_json(&status::failure(
            Some("watch"),
            "store_unreadable",
            "the store cannot be read; nothing was changed",
            "immune status --json --store <file>",
            &e.to_string(),
        ));
        ExitCode::from(crate::EXIT_STORE)
    };
    // A store it cannot read is refused before anything is made beside it.
    if let Err(e) = readable(&args.store) {
        return unreadable(&e);
    }
    if let Err(e) = std::fs::create_dir_all(&folder) {
        return unreadable(&e);
    }
    let started = crate::now_secs();
    let watch_lock = match store::lock_watch(&folder) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            crate::print_json(&status::failure(
                Some("watch"),
                "watch_in_progress",
                "another watcher is running on this store; nothing was done",
                "immune status --json",
                "",
            ));
            return ExitCode::from(EXIT_WATCHING);
        }
        Err(e) => return unreadable(&e),
    };
    // Every watcher, however started, says in its lock file since when it holds it and that it
    // is alive, and stops when it stalls; status reads the file.
    let mut heartbeat = match Heartbeat::start(&watch_lock, started, STALLED) {
        Ok(heartbeat) => heartbeat,
        Err(e) => return failed(&format!("the watcher could not be supervised: {e}")),
    };
    if let Err(e) = heartbeat.write() {
        return unreadable(&e);
    }
    // The watcher makes the store where there is none, at its start only: a store that goes or
    // is emptied while it runs is a problem it reports, never one it makes again.
    if let Err(e) = store::make_if_absent(&args.store) {
        return unreadable(&e);
    }
    let checks = if args.background {
        let binary = match std::env::current_exe() {
            Ok(binary) => binary,
            Err(e) => return failed(&format!("the core binary could not be located: {e}")),
        };
        let mut command = crate::background::command(&binary);
        command
            .arg("--store")
            .arg(&args.store)
            .arg("--system-root")
            .arg(&args.system_root);
        Some(crate::background::Checks::new(command))
    } else {
        None
    };
    let mut w = Watcher {
        args,
        folder,
        tx,
        stream: None,
        wanted: Vec::new(),
        targets: Vec::new(),
        read_everything: false,
        owed: false,
        paths: Vec::new(),
        parent,
        signers: crate::processes::Signers::default(),
        standing: BTreeSet::new(),
        checks,
        check_result: None,
        heartbeat,
        core,
        left: false,
    };
    // The stream is started here, and the reading of every place only in `run`, after it: a
    // change made in between is seen by that reading or brings an event.
    let problems = match w.subscribe() {
        Ok(found) => found,
        Err(e) => return failed(&e),
    };
    let watching = json!({
        "format": status::FORMAT,
        "event": "watching",
        "places": w.paths.len(),
        "at": crate::view::iso(started),
        "cannot_see": CANNOT_SEE,
    });
    if !emit(&watching) || problems.iter().any(|p| !emit(p)) {
        return ExitCode::SUCCESS;
    }
    w.run(rx);
    ExitCode::SUCCESS
}

/// The watcher could not watch at all.
fn failed(detail: &str) -> ExitCode {
    crate::print_json(&status::failure(
        Some("watch"),
        "watch_failed",
        "the watcher could not subscribe to file-system events; nothing is watched",
        "immune watch",
        detail,
    ));
    ExitCode::FAILURE
}

/// One line on stdout, flushed. `false` when stdout is gone, which means whoever started the
/// watcher is gone too, and the watcher stops.
fn emit(line: &Value) -> bool {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").and_then(|()| out.flush()).is_ok()
}

fn line(event: &str, mut fields: Value) -> Value {
    fields["format"] = json!(status::FORMAT);
    fields["event"] = json!(event);
    fields["at"] = json!(crate::view::iso(crate::now_secs()));
    fields
}

/// The `program_starts` line's fields: the level's state as a fixed word and in the words a
/// surface shows, the program starts this reading took, those of the last hour by the minute
/// and of the last day, and each caveat in a few words. Numbers and fixed words only: nothing
/// read from an event, and not what the collector said.
fn starts_line(read: &crate::EventsRead) -> Value {
    let Some(l) = &read.level else {
        return json!({ "state": crate::happens::known(None), "starts": read.starts });
    };
    let said = crate::events::words(l);
    let words = crate::events::in_words(&said);
    json!({
        "state": crate::happens::known(Some(l)),
        "starts": read.starts,
        "read_at": crate::view::iso(l.read_at),
        "program_starts_last_day": l.last_day.starts,
        "program_starts_by_minute": crate::events::minutes(&l.starts_by_minute),
        "in_words": { "state": words["state"], "caveats": words["caveats"] },
    })
}

fn problem(code: &str, detail: &str) -> Value {
    problem_of(code, Text::source(detail))
}

/// A problem whose detail is put together from what sources said, each piece cut on its own
/// (`secrets::Text::then`), and at most `TEXT_CAP` characters with no mark broken.
fn problem_of(code: &str, detail: Text) -> Value {
    line(
        "problem",
        json!({
            "code": code,
            "detail_text": detail.said_within(status::TEXT_CAP),
        }),
    )
}

/// Whether the store, where there is one, is one this build can read, read without writing.
/// A store it cannot read stops the watcher here, before it watches anything.
fn readable(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        store::open_read_only(path)?;
    }
    Ok(())
}

struct Watcher<'a> {
    args: &'a WatchArgs,
    folder: PathBuf,
    tx: Sender<Msg>,
    stream: Option<fsevents::Stream>,
    /// The paths asked for, FSEvents refusing some or not.
    wanted: Vec<PathBuf>,
    /// Each path asked for with the reading its place belongs to.
    targets: Vec<(PathBuf, Reading)>,
    /// Whether this watcher has read every watched place: until it has, every reading does.
    read_everything: bool,
    /// Whether a reading of every place is owed: a reading of some places was made since the
    /// last one of every place, or what a change in a watched path reads changed. The next look
    /// at what to watch makes it. Only memory holds it: a watcher started again reads every
    /// place at its start, so what this one owed is read then.
    owed: bool,
    /// The paths the stream watches.
    paths: Vec<PathBuf>,
    /// The process that started the watcher; its exit stops a parent-bound watcher.
    parent: libc::pid_t,
    /// Who signed what the samples track, kept across samples.
    signers: crate::processes::Signers,
    /// The kinds whose latest attempt failed, or whose failure may still stand in the store
    /// because clearing it failed: `READ`, `SAMPLED`, `RESUBSCRIBE`, `EVENTS`.
    standing: BTreeSet<&'static str>,
    checks: Option<crate::background::Checks>,
    /// Applied under the next run lock, so a failed full check is visible in status too.
    check_result: Option<Result<(), String>>,
    heartbeat: Heartbeat<'a>,
    /// The file the job's watcher was started from; `None` for any other watcher, and when it
    /// could not be looked at.
    core: Option<Core>,
    /// Whether the watcher is leaving because that file was replaced.
    left: bool,
}

/// The file a watcher was started from: its path, its device and inode then, and when it is
/// looked at next.
struct Core {
    path: PathBuf,
    identity: (u64, u64),
    next: Instant,
}

impl Core {
    fn started_from() -> Option<Core> {
        let path = std::env::current_exe().ok()?;
        let identity = identity(&std::fs::metadata(&path).ok()?);
        Some(Core {
            path,
            identity,
            next: Instant::now(),
        })
    }
}

fn identity(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}

/// Whether the path a watcher was started from holds another file than the one it started from,
/// given what `stat` says of the path now. Nothing there, or a path that cannot be looked at, is
/// not a new core: launchd would have nothing to start again.
fn replaced(started: (u64, u64), now: std::io::Result<std::fs::Metadata>) -> bool {
    now.is_ok_and(|m| identity(&m) != started)
}

/// What a watcher's lock file says of it: it has not completed its first reading, it has and
/// every failure since is in the store, or a failure is not in the store, with when the store
/// refused it and what the store's error said.
#[derive(Debug, PartialEq)]
enum LockState {
    Starting,
    Ready,
    Unrecorded { at: i64, said: String },
}

/// The lock file's whole content: the start time, `heartbeat`, and the state on a third line,
/// absent while starting, with what the store said on a fourth for `unrecorded`.
fn lock_text(since: i64, state: &LockState) -> String {
    match state {
        LockState::Starting => format!("{since}\n{HEARTBEAT}"),
        LockState::Ready => format!("{since}\n{HEARTBEAT}\n{READY}"),
        LockState::Unrecorded { at, said } => {
            format!("{since}\n{HEARTBEAT}\n{UNRECORDED} {at}\n{said}")
        }
    }
}

/// Reads a lock file's content back. `None` unless it is a heartbeat lock: the start time on
/// the first line and `heartbeat` on the second. A file met while the watcher rewrites it can
/// hold the start of the new content over the rest of the old: only a whole `ready` line with
/// nothing after it is ready, and anything else on the third line is read as starting.
fn read_lock(text: &str) -> Option<(i64, LockState)> {
    let lines: Vec<&str> = text.lines().collect();
    let since = lines.first()?.parse().ok()?;
    if lines.get(1) != Some(&HEARTBEAT) {
        return None;
    }
    let unrecorded = |line: &str| -> Option<i64> {
        line.strip_prefix(UNRECORDED)?
            .strip_prefix(' ')?
            .parse()
            .ok()
    };
    let state = match lines[2..] {
        [READY] => LockState::Ready,
        // An error that said nothing leaves no fourth line.
        [third, ref said @ ..] if said.len() <= 1 => match unrecorded(third) {
            Some(at) => LockState::Unrecorded {
                at,
                said: said.first().copied().unwrap_or_default().to_string(),
            },
            None => LockState::Starting,
        },
        _ => LockState::Starting,
    };
    Some((since, state))
}

/// The watcher's lock file and the thread that stops a watcher that stalls. It owns the file's
/// whole content and rewrites it as one piece.
struct Heartbeat<'a> {
    lock: &'a std::fs::File,
    since: i64,
    tx: Sender<()>,
    next: Instant,
    /// Whether a first reading has completed.
    read: bool,
    /// The kinds whose latest failure the store did not take, each with when and what the
    /// store's error said.
    unrecorded: BTreeMap<&'static str, (i64, String)>,
    /// Why a rewrite failed; the watcher stops at its next turn.
    broken: Option<String>,
}

impl<'a> Heartbeat<'a> {
    fn start(lock: &'a std::fs::File, since: i64, timeout: Duration) -> std::io::Result<Self> {
        // What the watcher before this one left is not this one's word: its `ready` under a
        // new start time would read as this watcher's. An empty file is no watcher.
        lock.set_len(0)?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new().spawn(move || {
            if stalled(rx, timeout) {
                // A stall can hold the run lock. Exiting releases it, and a supervisor starts
                // the watcher again.
                // SAFETY: _exit does not wait for user-space locks held by a stalled thread.
                unsafe { libc::_exit(1) };
            }
        })?;
        Ok(Self {
            lock,
            since,
            tx,
            next: Instant::now(),
            read: false,
            unrecorded: BTreeMap::new(),
            broken: None,
        })
    }

    /// What the file should say now: a failure the store did not take withdraws `ready`.
    fn state(&self) -> LockState {
        match self.unrecorded.values().max_by_key(|(at, _)| *at) {
            Some((at, said)) => LockState::Unrecorded {
                at: *at,
                said: said.clone(),
            },
            None if self.read => LockState::Ready,
            None => LockState::Starting,
        }
    }

    /// Rewrites the file: one write at its start, then its length. A reader meeting it between
    /// the two sees the new start over the old rest, which `read_lock` never reads as ready.
    fn write(&mut self) -> std::io::Result<()> {
        let text = lock_text(self.since, &self.state());
        let wrote = self
            .lock
            .write_all_at(text.as_bytes(), 0)
            .and_then(|()| self.lock.set_len(text.len() as u64));
        if let Err(e) = &wrote {
            self.broken = Some(e.to_string());
        }
        wrote
    }

    fn progress(&mut self) -> std::io::Result<()> {
        // It stays broken: a turn that takes this as a stop asked for must meet it again.
        if let Some(why) = &self.broken {
            return Err(std::io::Error::other(why.clone()));
        }
        if Instant::now() >= self.next {
            self.lock.set_modified(SystemTime::now())?;
            self.tx.send(()).map_err(std::io::Error::other)?;
            self.next = Instant::now() + ALIVE;
        }
        Ok(())
    }

    /// The watcher leaves at `at` because the file it was started from was replaced: the last
    /// thing written to the file, which the status reads once the lock is free.
    fn left_for_new_core(&mut self, at: i64) -> std::io::Result<()> {
        let text = format!("{}\n{HEARTBEAT}\n{CORE_REPLACED} {at}", self.since);
        self.lock
            .write_all_at(text.as_bytes(), 0)
            .and_then(|()| self.lock.set_len(text.len() as u64))
    }

    /// A first reading has completed.
    fn read(&mut self) -> std::io::Result<()> {
        self.read = true;
        self.write()
    }

    /// The store did not take a failure of `what`; `why` is what its error said.
    fn unrecorded(&mut self, what: &'static str, why: &str) {
        let said: String = why
            .chars()
            .map(|c| if matches!(c, '\n' | '\r') { ' ' } else { c })
            .take(UNRECORDED_CAP)
            .collect();
        self.unrecorded.insert(what, (crate::now_secs(), said));
        let _ = self.write();
    }

    /// A failure of `what` is in the store, or `what` succeeded.
    fn recorded(&mut self, what: &'static str) {
        if self.unrecorded.remove(what).is_some() {
            let _ = self.write();
        }
    }
}

fn stalled(rx: mpsc::Receiver<()>, timeout: Duration) -> bool {
    loop {
        if let Err(stopped) = rx.recv_timeout(timeout) {
            return stopped == RecvTimeoutError::Timeout;
        }
    }
}

/// A reading that is due: when, since which event it was first due, and where the changes it
/// reads are.
struct Due {
    first: Instant,
    at: Instant,
    changed: Where,
}

impl Watcher<'_> {
    /// Subscribes to the watched places: the stream is running when it returns. Returns the
    /// problem lines.
    fn subscribe(&mut self) -> Result<Vec<Value>, String> {
        let (wanted, targets, mut problems) = self.derive().map_err(|e| e.to_string())?;
        self.targets = targets;
        problems.extend(self.start(wanted)?);
        Ok(problems)
    }

    /// Starts a stream on `wanted` in place of the one running, if any. Returns the problem
    /// lines of the paths FSEvents refused.
    fn start(&mut self, wanted: Vec<PathBuf>) -> Result<Vec<Value>, String> {
        let tx = self.tx.clone();
        let deliver = Box::new(move |b: fsevents::Batch| {
            let _ = tx.send(Msg::Events(b));
        });
        let refs: Vec<&Path> = wanted.iter().map(PathBuf::as_path).collect();
        let (stream, refused) = fsevents::Stream::start(&refs, LATENCY, deliver)?;
        let problems = refused
            .iter()
            .map(|(i, why)| place_problem(&wanted[*i], why))
            .collect();
        let refused: BTreeSet<usize> = refused.into_iter().map(|(i, _)| i).collect();
        // The new stream runs before the old one stops, so no change falls between them.
        self.stream = Some(stream);
        self.wanted = wanted.clone();
        self.paths = wanted
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !refused.contains(i))
            .map(|(_, p)| p)
            .collect();
        Ok(problems)
    }

    /// The paths to watch now, from the table of places and the checkouts the store holds,
    /// each path with the reading its place belongs to, and a problem line for each place that
    /// cannot be watched.
    fn derive(&self) -> Result<Derived, Box<dyn Error>> {
        let (machine, found) = holds(self.args)?;
        let homes = watched::homes(&self.args.home);
        let homes = [homes[0].as_path(), homes[1].as_path()];
        let mut wanted = BTreeSet::new();
        let mut targets = Vec::new();
        let mut problems = Vec::new();
        for p in places(&self.args.home, &self.args.system_root, &machine, &found) {
            match subscribed(&p.path, p.folder, &homes) {
                Ok(paths) => {
                    targets.extend(paths.iter().map(|path| (path.clone(), p.reading.clone())));
                    wanted.extend(paths);
                }
                Err(why) => problems.push(place_problem(&p.path, &why)),
            }
        }
        Ok((wanted.into_iter().collect(), targets, problems))
    }

    /// Runs until stopped, starting with a reading of every place, due at once. The stream is
    /// running already (`subscribe`).
    fn run(&mut self, rx: mpsc::Receiver<Msg>) {
        let mut due = Some(every_place(Instant::now()));
        let mut alive = Instant::now() + self.args.alive_every;
        // The first sample is taken at start, after the reading due then, and the first
        // reading of program starts after it.
        let mut sample = Instant::now();
        let mut starts = Instant::now();
        loop {
            if !self.progress() {
                return;
            }
            let next = due.as_ref().map_or(alive, |d| d.at.min(alive)).min(sample);
            let next = next.min(starts);
            let next = next.min(Instant::now() + PARENT);
            match rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
                Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(Msg::Events(b)) if b.events > 0 => {
                    let now = Instant::now();
                    due = Some(match due {
                        None => Due {
                            first: now,
                            at: now + QUIET,
                            changed: b.at,
                        },
                        Some(d) => Due {
                            at: (now + QUIET).min(d.first + MOST_WAIT),
                            first: d.first,
                            changed: d.changed.and(b.at),
                        },
                    });
                }
                Ok(Msg::Events(_)) | Err(RecvTimeoutError::Timeout) => {}
            }
            if self.orphaned() {
                return;
            }
            let now = Instant::now();
            if let Some(d) = due.take_if(|d| d.at <= now) {
                match self.read(&d.changed) {
                    Ok(Some(counts)) => {
                        if let Err(why) = self.heartbeat.read() {
                            emit(&problem("heartbeat_failed", &why.to_string()));
                            return;
                        }
                        if !emit(&line("read", counts)) {
                            return;
                        }
                    }
                    // Stopped while it waited for a full run to finish.
                    Ok(None) => return,
                    // Tried again with every place: what the failed reading would have read is
                    // not all that may have changed since.
                    Err(e) => {
                        if !emit(&problem("read_failed", &e.to_string())) {
                            return;
                        }
                        due = Some(Due {
                            first: now,
                            at: now + RETRY,
                            changed: Where::Anywhere,
                        });
                    }
                }
            }
            if sample <= Instant::now() {
                sample = Instant::now() + self.args.sample_every;
                let recovered = self.standing.contains(SAMPLED);
                match self.sample() {
                    // A sample that opened a finding, or the first to succeed after one that
                    // failed, which the app takes as the end of that failure.
                    Ok(Some((opened, needs))) if opened > 0 || recovered => {
                        let said = json!({ "opened": opened, "needs_a_look_total": needs });
                        if !emit(&line("sample", said)) {
                            return;
                        }
                    }
                    // Quiet, or stopped while it waited: the loop ends at its next turn.
                    Ok(_) => {}
                    Err(e) => {
                        if !emit(&problem("sample_failed", &e.to_string())) {
                            return;
                        }
                    }
                }
            }
            if starts <= Instant::now() {
                starts = Instant::now() + self.args.events_every;
                match self.events() {
                    // A reading that took program starts or changed the level's state is said,
                    // so that the app shows it without asking for the status.
                    Ok(Some(read)) => {
                        if (read.starts > 0 || read.changed)
                            && !emit(&line("program_starts", starts_line(&read)))
                        {
                            return;
                        }
                        if let Some(why) = read.failed
                            && !emit(&problem("events_failed", &why))
                        {
                            return;
                        }
                    }
                    // Stopped while it waited: the loop ends at its next turn.
                    Ok(None) => {}
                    Err(e) => {
                        if !emit(&problem("events_failed", &e.to_string())) {
                            return;
                        }
                    }
                }
            }
            if alive <= now {
                alive = now + self.args.alive_every;
                if !emit(&line("alive", json!({}))) {
                    return;
                }
                let again = self.again();
                // A look that failed counts as not watching what it would have watched: it is
                // recorded until a look succeeds.
                let recovered = self.standing.contains(RESUBSCRIBE);
                if again.is_err() || recovered {
                    match self.lock() {
                        Ok(Some(_lock)) => {
                            self.mark_held(RESUBSCRIBE, again.as_ref().err().cloned());
                        }
                        Ok(None) => {}
                        // A failed look that cannot be recorded; a look that succeeded has
                        // nothing left unrecorded, whatever the store still holds.
                        Err(e) if again.is_err() => self.unrecorded(RESUBSCRIBE, &e),
                        Err(_) => self.heartbeat.recorded(RESUBSCRIBE),
                    }
                }
                match again {
                    Ok(found) => {
                        if let Some(problems) = &found
                            && problems.iter().any(|p| !emit(p))
                        {
                            return;
                        }
                        // After a look that failed, the watcher says it watches again.
                        if recovered && !emit(&self.watching_line()) {
                            return;
                        }
                        // What changed in a place newly watched, or in one not watched while
                        // looks failed, is read now.
                        if found.is_some() || recovered {
                            due = Some(every_place(now));
                        }
                    }
                    Err(e) => {
                        self.standing.insert(RESUBSCRIBE);
                        if !emit(&problem("resubscribe_failed", &e)) {
                            return;
                        }
                    }
                }
                // What a change names decides only what is read first: after a reading of
                // some places, every place is read at this look, so that a place the change
                // was not mapped to is read within a minute, and a burst of changes costs one
                // reading of every place a minute.
                if self.owed {
                    due = Some(every_place(now));
                }
            }
        }
    }

    fn orphaned(&self) -> bool {
        // SAFETY: getppid(2) takes nothing and cannot fail.
        !self.args.standalone && unsafe { libc::getppid() != self.parent }
    }

    /// Looks again at what should be watched, after a full run may have changed the
    /// checkouts. Returns `None` when the paths did not change, else the new problem lines. What
    /// a change in each path reads is taken anew every time, and when that changed, a reading of
    /// every place is owed (`owed`).
    fn again(&mut self) -> Result<Option<Vec<Value>>, String> {
        let (wanted, targets, mut problems) = self.derive().map_err(|e| e.to_string())?;
        // Where a watched path now leads to the place of another reading, as when a link on
        // the way to it, outside every watched place, was turned, nothing watched need have
        // been written: every place is owed, and read at this look.
        self.owed |= targets != self.targets;
        self.targets = targets;
        if wanted == self.wanted {
            return Ok(None);
        }
        problems.extend(self.start(wanted)?);
        Ok(Some(problems))
    }

    /// One reading of the watched places, as a small run of that reader alone: of the readings
    /// the changes are in, or of every place where that cannot be told. `None` when the watcher
    /// was stopped, or orphaned, while it waited for the run lock. The counts are of this
    /// reading, the baseline counting as nothing new.
    fn read(&mut self, changed: &Where) -> Result<Option<Value>, Box<dyn Error>> {
        let only = to_read(&self.targets, changed, self.read_everything);
        let Some(_lock) = self.lock_for(READ)? else {
            return Ok(None);
        };
        let read = read_held(self.args, &self.folder, only.as_ref());
        self.mark_held(READ, read.as_ref().err().map(|e| e.to_string()));
        // The first reading is of every place (`to_read`), and one that failed is tried again as
        // one of every place (`run`): after any reading, every place was read or is read next,
        // and after one of some places, every place is owed.
        self.read_everything = true;
        self.owed = only.is_some();
        read.map(Some)
    }

    /// The run lock, waited for; `None` when the watcher was stopped, or orphaned, meanwhile,
    /// or stdout is gone. A full run holds the lock for as long as it runs, minutes at times:
    /// meanwhile the watcher refreshes its heartbeat and says it is alive at its usual interval.
    fn lock(&mut self) -> std::io::Result<Option<std::fs::File>> {
        let mut alive = Instant::now() + self.args.alive_every;
        loop {
            if STOP.load(Ordering::SeqCst) || self.orphaned() {
                return Ok(None);
            }
            // The full check may hold this lock: its timeout must still be enforced here.
            if !self.progress() {
                return Ok(None);
            }
            // Waits a little each time.
            if let Some(lock) = store::lock_run(&self.folder)? {
                if let Some(result) = self.check_result.take() {
                    self.mark_held(FULL_CHECK, result.err());
                }
                return Ok(Some(lock));
            }
            if alive <= Instant::now() {
                alive = Instant::now() + self.args.alive_every;
                if !emit(&line("alive", json!({}))) {
                    return Ok(None);
                }
            }
        }
    }

    /// The run lock for a reading of the kind `what`. When it cannot be taken, the failure
    /// cannot be recorded either, and the lock file says so.
    fn lock_for(&mut self, what: &'static str) -> std::io::Result<Option<std::fs::File>> {
        let lock = self.lock();
        if let Err(e) = &lock {
            self.unrecorded(what, e);
        }
        lock
    }

    fn progress(&mut self) -> bool {
        if self.core_replaced() {
            return false;
        }
        if let Err(why) = self.heartbeat.progress() {
            emit(&problem("heartbeat_failed", &why.to_string()));
            return false;
        }
        if let Some(checks) = &mut self.checks
            && let Some(result) = checks.tick(crate::now_secs())
        {
            if let Err(why) = &result
                && !emit(&problem("full_check_failed", why))
            {
                return false;
            }
            self.check_result = Some(result);
        }
        true
    }

    /// Whether the file the job's watcher was started from was replaced, looked at every
    /// `--alive-every`. Once it was, the watcher says so on stderr and in its lock file, and every
    /// later turn and every wait for the run lock ends, so the watcher leaves between readings.
    fn core_replaced(&mut self) -> bool {
        if self.left {
            return true;
        }
        let Some(core) = &mut self.core else {
            return false;
        };
        if Instant::now() < core.next {
            return false;
        }
        core.next = Instant::now() + self.args.alive_every;
        if !replaced(core.identity, std::fs::metadata(&core.path)) {
            return false;
        }
        self.left = true;
        eprintln!(
            "immune watch: the core this watcher was started from was replaced: {}; it leaves, and launchd starts it again from the new file",
            core.path.display()
        );
        if let Err(e) = self.heartbeat.left_for_new_core(crate::now_secs()) {
            eprintln!("immune watch: its lock file could not say so: {e}");
        }
        true
    }

    /// One sample under the run lock: how many findings it opened and how many things need a
    /// look after it. `None` when the watcher was stopped while it waited for the lock.
    fn sample(&mut self) -> Result<Option<(usize, usize)>, Box<dyn Error>> {
        let Some(_lock) = self.lock_for(SAMPLED)? else {
            return Ok(None);
        };
        let sampled = crate::sample_held(
            &self.args.store,
            self.args.sample_input.as_deref(),
            &mut self.signers,
        );
        self.mark_held(SAMPLED, sampled.as_ref().err().map(|e| e.to_string()));
        let (report, needs) = sampled?;
        Ok(Some((report.findings_opened, needs)))
    }

    /// One reading of the event level under the run lock, and then the numbers of
    /// "As it happens" written beside the pages for a page that is open (`happens::live`).
    /// `None` when the watcher was stopped while it waited for the lock.
    fn events(&mut self) -> Result<Option<crate::EventsRead>, Box<dyn Error>> {
        let Some(_lock) = self.lock_for(EVENTS)? else {
            return Ok(None);
        };
        let read = crate::read_events_held(&self.args.store, &self.args.system_root);
        let failed = match &read {
            Ok(r) => r.failed.clone(),
            Err(e) => Some(e.to_string()),
        };
        self.mark_held(EVENTS, failed);
        let read = read?;
        // A page that is open shows these numbers; one that could not be written is a page
        // that says it is not updating, not a failed reading.
        let _ = crate::happens::write_live(&self.folder, read.level.as_ref(), read.at);
        Ok(Some(read))
    }

    /// Under the run lock the caller holds: records that `what` failed, with what the failure
    /// said, or that it succeeded, which clears a failure recorded before. A failure the store
    /// does not take is said in the lock file until the kind succeeds or its failure is
    /// recorded.
    fn mark_held(&mut self, what: &'static str, failed: Option<String>) {
        match failed {
            Some(detail) => {
                self.standing.insert(what);
                match mark(&self.args.store, what, Some(&detail)) {
                    Ok(()) => self.heartbeat.recorded(what),
                    Err(e) => self.heartbeat.unrecorded(what, &e.to_string()),
                }
            }
            None => {
                self.heartbeat.recorded(what);
                if self.standing.contains(what) && mark(&self.args.store, what, None).is_ok() {
                    self.standing.remove(what);
                }
            }
        }
    }

    /// A failure of `what` that cannot be recorded: the run lock could not be taken.
    fn unrecorded(&mut self, what: &'static str, why: &std::io::Error) {
        self.standing.insert(what);
        self.heartbeat.unrecorded(what, &why.to_string());
    }

    /// The `watching` line: how many places are watched, and what the watcher cannot see.
    fn watching_line(&self) -> Value {
        line(
            "watching",
            json!({ "places": self.paths.len(), "cannot_see": CANNOT_SEE }),
        )
    }
}

/// Records a failure of `what` with what it said, or with `None` clears it. The caller holds
/// the run lock.
fn mark(store: &Path, what: &str, failed: Option<&str>) -> Result<(), Box<dyn Error>> {
    let conn = store::open(store)?;
    match failed {
        Some(detail) => conn.execute(
            "INSERT INTO watcher_failed (what, at, detail) VALUES (?1, ?2, ?3)
             ON CONFLICT (what) DO UPDATE SET at = excluded.at, detail = excluded.detail",
            params![what, crate::now_secs(), detail],
        )?,
        None => conn.execute("DELETE FROM watcher_failed WHERE what = ?1", [what])?,
    };
    Ok(())
}

/// One reading of the watched places under the run lock the caller holds, as a small run of
/// that reader alone: of `only` these readings, or of every place, which records when every
/// place was last read. The counts are of this reading, the baseline counting as nothing new.
fn read_held(
    args: &WatchArgs,
    folder: &Path,
    only: Option<&BTreeSet<Reading>>,
) -> Result<Value, Box<dyn Error>> {
    let (machine, found) = holds(args)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let at = now.as_secs() as i64;
    let run_id = format!("{RUN_PREFIX}{}-{:09}", now.as_secs(), now.subsec_nanos());
    let mut conn = store::open(&args.store)?;
    let tx = conn.transaction()?;
    store::put_entity(&tx, &machine)?;
    let mut run = crate::Run {
        tx: &tx,
        home: folder,
        run_id: &run_id,
        at,
        machine: &machine,
        notes: Vec::new(),
        readers: 0,
    };
    // The reading and the rules of `immune run`: a change seen here is a finding at once.
    let (rows, opened) = crate::watch_places(&mut run, &reader_args(args), &found, only)?;
    // What needs a look after it, counted by the code `immune status --json` counts it with.
    let needs = status::needs(&tx, at)?.items.len();
    // The row says when every place was last read: only a reading of every place moves it.
    if only.is_none() {
        tx.execute(
            "INSERT INTO watcher (id, last_read) VALUES (1, ?1)
             ON CONFLICT (id) DO UPDATE SET last_read = excluded.last_read",
            [at],
        )?;
    }
    // The job's watcher is what knows Immune is on: its reading says so in the journal, once for
    // each turning on (`service::note_on`). Not being able to say it fails nothing.
    if args.background {
        let _ = crate::service::note_on(&tx, at);
    }
    tx.commit()?;
    let count = |change: &str| rows.iter().filter(|r| r[0] == change).count();
    Ok(json!({
        "needs_a_look_total": needs,
        "opened": opened,
        "new": count("new"),
        "changed": count("changed"),
        "gone": count("gone"),
    }))
}

/// This machine's id and the checkouts the store holds on it.
fn holds(args: &WatchArgs) -> Result<(String, Vec<checkouts::Checkout>), Box<dyn Error>> {
    if !args.store.exists() {
        return Ok((this_machine(None)?, Vec::new()));
    }
    let conn = store::open_read_only(&args.store)?;
    let machine = this_machine(Some(&conn))?;
    let found = held_checkouts(&conn, &machine, &args.home)?;
    Ok((machine, found))
}

/// What `watch_places` takes from the run's arguments: the home folder and the system root.
fn reader_args(args: &WatchArgs) -> crate::Args {
    crate::Args {
        store: args.store.clone(),
        machine: String::new(),
        brew: None,
        brew_input: None,
        servers_input: None,
        home: args.home.clone(),
        checkouts_root: None,
        sessions_root: None,
        tailscale: None,
        threats_input: None,
        osv_crates_input: None,
        osv_npm_input: None,
        curl: None,
        system_root: args.system_root.clone(),
        indicators: None,
        form: crate::answer::Form::Text,
    }
}

/// The machine whose watched places were read last, so the watcher reads the same one as
/// the full runs; this Mac's own name when they never were.
fn this_machine(conn: Option<&Connection>) -> rusqlite::Result<String> {
    let last: Option<String> = match conn {
        Some(conn) => conn
            .query_row(
                "SELECT scope FROM coverage WHERE reader = ?1 AND kind = ?2
                 ORDER BY id DESC LIMIT 1",
                params![watched::READER, watched::AUTOSTART_KIND],
                |r| r.get(0),
            )
            .optional()?,
        None => None,
    };
    Ok(last.unwrap_or_else(|| format!("machine:{}", crate::machine_name())))
}

/// The checkouts the store holds live on this machine, with their paths: relative to the home
/// folder unless the id gives a full path.
fn held_checkouts(
    conn: &Connection,
    machine: &str,
    home: &Path,
) -> rusqlite::Result<Vec<checkouts::Checkout>> {
    let prefix = format!("checkout:{machine}/");
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer = 'live' AND predicate = 'located_on'
           AND substr(subject, 1, length(?1)) = ?1
         ORDER BY subject",
    )?;
    let ids: Vec<String> = stmt
        .query_map([&prefix], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let homes = watched::homes(home);
    let homes = [homes[0].as_path(), homes[1].as_path()];
    Ok(ids
        .into_iter()
        .map(|id| {
            let rel = id[prefix.len()..].to_string();
            let path = if rel.starts_with('/') {
                PathBuf::from(&rel)
            } else {
                home.join(&rel)
            };
            checkouts::Checkout { rel, path }
        })
        // A watcher started by the app never looks into a folder macOS asks permission for,
        // whatever name leads there: a checkout may have been moved there and linked back
        // since the run that found it. What is held about it is kept as it was.
        .filter(|c| {
            !matches!(
                crate::guarded::real(&c.path, &homes),
                crate::guarded::Real::Guarded(_)
            )
        })
        .collect())
}

/// A reading of the watched places as `immune run` writes its coverage: its scope and kind.
pub type Reading = (String, String);

/// The paths to watch, each path with the reading its place belongs to, and the problem lines.
type Derived = (Vec<PathBuf>, Vec<(PathBuf, Reading)>, Vec<Value>);

/// One watched place: its path, whether it is a folder whose entries are watched, and the
/// reading it belongs to.
struct Place {
    path: PathBuf,
    folder: bool,
    reading: Reading,
}

/// Every watched place on this machine: the table of places, the hooks folder of each
/// checkout, and the files of each checkout through which something runs by itself
/// (`autorun::files`), and the places of the home folder through which a tool's own settings
/// do (`autorun::home_places`).
fn places(home: &Path, system: &Path, machine: &str, found: &[checkouts::Checkout]) -> Vec<Place> {
    let mut out = Vec::new();
    let mut add = |path: PathBuf, folder: bool, scope: &str, kind: &str| {
        out.push(Place {
            path,
            folder,
            reading: (scope.to_string(), kind.to_string()),
        })
    };
    for (p, (_, kind)) in autorun::places() {
        let folder = p.part == autorun::Part::Entries;
        for path in p.paths {
            match p.scope {
                autorun::Scope::Home => add(home.join(path), folder, machine, kind),
                autorun::Scope::System => add(system.join(path), folder, machine, kind),
                _ => {
                    for c in found {
                        let scope = format!("checkout:{machine}/{}", c.rel);
                        add(c.path.join(path), folder, &scope, kind);
                    }
                }
            }
        }
    }
    for c in found {
        for (file, kind) in autorun::files() {
            add(c.path.join(file), false, machine, &kind);
        }
    }
    for (place, folder, kind) in autorun::home_places() {
        add(home.join(place), folder, machine, &kind);
    }
    out
}

/// What a reading of changes `changed` reads: the readings they are in, or every place
/// (`None`) until this watcher has read every place once, when FSEvents cannot say where they
/// are, and when one of their paths is in no reading's place.
fn to_read(
    targets: &[(PathBuf, Reading)],
    changed: &Where,
    read_everything: bool,
) -> Option<BTreeSet<Reading>> {
    match changed {
        // No path is no place named: every place is read, never none.
        Where::Paths(paths) if read_everything && !paths.is_empty() => touched(targets, paths),
        _ => None,
    }
}

/// A reading of every place, due now.
fn every_place(now: Instant) -> Due {
    Due {
        first: now,
        at: now,
        changed: Where::Anywhere,
    }
}

/// The readings the changes at `paths` are in: each reading one of whose watched paths is the
/// path, holds it, or lies under it, as a folder made or moved on the way to a place.
/// `None` when a path is in no reading's place: what changed cannot be told, and every place
/// is read.
fn touched(targets: &[(PathBuf, Reading)], paths: &BTreeSet<PathBuf>) -> Option<BTreeSet<Reading>> {
    let mut out = BTreeSet::new();
    for path in paths {
        let mut placed = false;
        for (watched, reading) in targets {
            if path.starts_with(watched) || watched.starts_with(path) {
                out.insert(reading.clone());
                placed = true;
            }
        }
        if !placed {
            return None;
        }
    }
    Some(out)
}

/// The paths FSEvents is given for one place: the place by the real path of its folder, and
/// where symbolic links among it lead, the place itself when it is a link and each link in a
/// watched folder; a change at a target is reported under the target. Nothing that leads
/// into a folder macOS asks permission for: FSEvents resolves the paths it is given, and the
/// reading of the place says it was not looked into. Made real without entering one.
fn subscribed(place: &Path, folder: bool, homes: &[&Path]) -> Result<Vec<PathBuf>, String> {
    let Some(at) = real(place, homes)? else {
        return Ok(Vec::new());
    };
    let target = |link: &Path| -> Result<Option<PathBuf>, ()> {
        if !std::fs::symlink_metadata(link).is_ok_and(|m| m.file_type().is_symlink()) {
            return Ok(None);
        }
        match crate::guarded::real(link, homes) {
            crate::guarded::Real::At(t) => Ok(Some(t)),
            crate::guarded::Real::Guarded(_) => Err(()),
            crate::guarded::Real::Failed(_) => Ok(None),
        }
    };
    let Ok(own) = target(&at) else {
        return Ok(Vec::new());
    };
    let mut out = vec![at.clone()];
    if folder && let Ok(entries) = std::fs::read_dir(own.as_ref().unwrap_or(&at)) {
        for entry in entries.flatten() {
            out.extend(target(&at.join(entry.file_name())).ok().flatten());
        }
    }
    out.extend(own);
    Ok(out)
}

/// The path as FSEvents names it: the real path of its folder, which need not exist yet, and
/// its own name. FSEvents reports real paths, and `/etc` is a link to `/private/etc`. `None`
/// when its folder leads into a folder macOS asks permission for, which is not entered.
fn real(path: &Path, homes: &[&Path]) -> Result<Option<PathBuf>, String> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(Some(path.to_path_buf()));
    };
    let mut missing = Vec::new();
    let mut existing = parent.to_path_buf();
    let mut out = loop {
        match crate::guarded::real(&existing, homes) {
            crate::guarded::Real::At(real) => break real,
            crate::guarded::Real::Guarded(_) => return Ok(None),
            // A folder that is not there yet: its own folder is watched. Looking at it
            // without following it fails only where making it real failed.
            crate::guarded::Real::Failed(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && matches!(std::fs::symlink_metadata(&existing),
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound) =>
            {
                let Some(last) = existing.file_name() else {
                    return Err(e.to_string());
                };
                missing.push(last.to_os_string());
                existing.pop();
            }
            // Any other error, such as a folder that cannot be searched.
            crate::guarded::Real::Failed(e) => return Err(e.to_string()),
        }
    };
    out.extend(missing.iter().rev());
    out.push(name);
    Ok(Some(out))
}

fn place_problem(place: &Path, why: &str) -> Value {
    // The place is a name, never cut, and why is cut on its own: it never takes the name with
    // it. Both are written with a source's backslash as `\u{5c}`.
    problem_of(
        "place_not_watched",
        Text::ours(&place.display().to_string())
            .then(Text::ours(": "))
            .then(Text::source(why)),
    )
}

/// SIGTERM and SIGINT stop the watcher: the handler writes one byte to a pipe, which is all it
/// may safely do, and a thread waiting on the pipe sets `STOP` and tells the main loop.
fn on_signals(tx: Sender<Msg>) -> std::io::Result<()> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe(2) writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: `fd` is open; neither end is inherited by a program the reading starts.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: the write end never blocks the handler.
    unsafe { libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) };
    SIGNAL_FD.store(fds[1], Ordering::SeqCst);
    // SAFETY: the read end is open and owned by this file alone from here on.
    let mut read_end = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = read_end.read(&mut byte);
        STOP.store(true, Ordering::SeqCst);
        let _ = tx.send(Msg::Stop);
    });
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a zeroed sigaction is a valid empty one; the handler is async-signal-safe.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action` is valid for the call; the old action is not asked for.
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The signal handler: only write(2), which is async-signal-safe, and errno kept as it was.
extern "C" fn on_signal(_: libc::c_int) {
    // SAFETY: `__error` returns this thread's errno; write(2) on a descriptor that is open
    // for as long as the process runs, from a valid one-byte buffer.
    unsafe {
        let saved = *libc::__error();
        let fd = SIGNAL_FD.load(Ordering::SeqCst);
        if fd >= 0 {
            libc::write(fd, [1u8].as_ptr().cast(), 1);
        }
        *libc::__error() = saved;
    }
}

/// `watching` of the contract's `Status`: absent unless a watcher holds its lock on this store
/// now, so a watcher that died never shows as watching. What a failure said is whole.
pub fn watcher(store: &Path) -> Option<crate::contract::v1::Watcher> {
    use crate::contract::v1;
    let folder = crate::home(store);
    let since = Some(responsive(&folder)?.0);
    let conn = store::open_read_only(store).ok();
    let last = conn
        .as_ref()
        .and_then(|conn| last_read(conn).ok().flatten())
        .filter(|last| since.is_some_and(|since| *last >= since));
    let failed = conn
        .as_ref()
        .and_then(|conn| failures(conn, &folder).ok())
        .unwrap_or_default();
    Some(v1::Watcher {
        since_at: since,
        last_read_at: last,
        failed: failed
            .iter()
            .map(|f| v1::WatcherFailure {
                what: f.what.clone(),
                at: f.at,
                // What the failure said, which can repeat what the system or a tool said.
                detail_text: crate::secrets::said(&f.detail),
            })
            .collect(),
        cannot_see: CANNOT_SEE.iter().map(|s| s.to_string()).collect(),
    })
}

/// What the pages of the view rest on about the watcher: when the one that holds the store
/// started, and what has failed in it and not succeeded since; `none` while none holds it.
pub fn basis(conn: &Connection, folder: &Path) -> rusqlite::Result<String> {
    let Some((since, state)) = responsive(folder) else {
        return Ok("none".into());
    };
    let state = match state {
        LockState::Starting => "starting",
        LockState::Ready => "ready",
        LockState::Unrecorded { .. } => "unrecorded",
    };
    let failed: Vec<String> = failures(conn, folder)?
        .into_iter()
        .map(|f| f.what)
        .collect();
    Ok(format!("{since} {state} {}", failed.join(",")))
}

/// When the watcher that holds the lock took it, and what its lock file says of it. `None`
/// while no watcher holds the lock, when the file is not a heartbeat lock (`read_lock`), and
/// when the watcher has not touched it within `STALLED`.
fn responsive(folder: &Path) -> Option<(i64, LockState)> {
    if !store::watch_in_progress(folder).unwrap_or(false) {
        return None;
    }
    let path = folder.join(store::WATCH_LOCK);
    let text = std::fs::read(&path).ok()?;
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    if modified.elapsed().ok()? >= STALLED {
        return None;
    }
    read_lock(&String::from_utf8_lossy(&text))
}

pub fn watching_live(folder: &Path) -> bool {
    responsive(folder).is_some_and(|(_, state)| state == LockState::Ready)
}

/// Whether a watcher that is ready watches live with these failures standing: a failed reading
/// of program starts or full check does not stop it, any other failure does.
pub fn live_with(failed: &[Failure]) -> bool {
    failed
        .iter()
        .all(|f| matches!(f.what.as_str(), EVENTS | FULL_CHECK))
}

/// What the status says of the watcher on a store, as `seen` tells it.
#[derive(Clone, Debug, PartialEq)]
pub enum Seen {
    /// A watcher watches the store live.
    Live,
    /// A watcher holds the store and has not completed its first reading.
    Starting,
    /// A watcher holds the store and these kinds of what it does failed.
    Failing(Vec<String>),
    /// The latest watcher left for a new core, within `RESTARTING_FOR`, and none holds the store.
    Restarting,
    /// No watcher holds the store.
    Absent,
}

/// A watcher that has not completed its first reading, in the status's words.
pub const STARTING_WORDS: &str = "a watcher runs and has not completed its first reading";
/// A watcher that left for a new core, in the status's words.
pub const RESTARTING_WORDS: &str = "the watcher is restarting on a new core";

/// A watcher whose latest attempts of these kinds failed, in the status's words.
pub fn failing_words(failed: &[&str]) -> String {
    format!(
        "a watcher runs, but its latest {} failed, so it does not watch live",
        failed.join(" and ")
    )
}

impl Seen {
    /// Whether a watcher is there and working: it holds the store and its heartbeat is fresh
    /// (`responsive`), whether or not its first check is done or something failed since.
    pub fn started(&self) -> bool {
        matches!(self, Seen::Live | Seen::Starting | Seen::Failing(_))
    }

    /// What the status says of it, in the core's words.
    pub fn words(&self) -> String {
        match self {
            Seen::Live => "live".to_string(),
            Seen::Starting => STARTING_WORDS.to_string(),
            Seen::Failing(failed) => {
                let words: Vec<&str> = failed.iter().map(|f| failed_words(f)).collect();
                failing_words(&words)
            }
            Seen::Restarting => RESTARTING_WORDS.to_string(),
            Seen::Absent => "no watcher runs on the store now".to_string(),
        }
    }
}

/// What the status would say now of the watcher on `store`, by the liveness it uses
/// (`ThisMac.live`). `None` when that cannot be told: the store's folder or, for a watcher that is
/// ready, the store cannot be read.
pub fn seen(store: &Path) -> Option<Seen> {
    let folder = crate::home(store);
    if !store::watch_in_progress(&folder).ok()? {
        return Some(match restarting_since(&folder, crate::now_secs()) {
            Some(_) => Seen::Restarting,
            None => Seen::Absent,
        });
    }
    // A watcher that stalled, or whose lock file is not a heartbeat lock, is no watcher.
    let Some((_, state)) = responsive(&folder) else {
        return Some(Seen::Absent);
    };
    if state == LockState::Starting {
        return Some(Seen::Starting);
    }
    // Ready, or a failure the store did not take, which `failures` gives as one of `STORE`.
    let conn = store::open_read_only(store).ok()?;
    let failed = failures(&conn, &folder).ok()?;
    Some(if live_with(&failed) {
        Seen::Live
    } else {
        Seen::Failing(failed.into_iter().map(|f| f.what).collect())
    })
}

/// When the latest watcher of the store in `folder` left because the file it was started from
/// was replaced, while no watcher holds the store and for `RESTARTING_FOR` after it left, at
/// `now`.
pub fn restarting_since(folder: &Path, now: i64) -> Option<i64> {
    if store::watch_in_progress(folder).ok()? {
        return None;
    }
    let text = std::fs::read(folder.join(store::WATCH_LOCK)).ok()?;
    let at = left_at(&String::from_utf8_lossy(&text))?;
    ((now - at).abs() <= RESTARTING_FOR).then_some(at)
}

/// When a lock file says its watcher left for a new core: the start time, `heartbeat`, and the
/// line `core-replaced <at>`, with nothing after it.
fn left_at(text: &str) -> Option<i64> {
    let lines: Vec<&str> = text.lines().collect();
    let [since, HEARTBEAT, left] = lines[..] else {
        return None;
    };
    since.parse::<i64>().ok()?;
    left.strip_prefix(CORE_REPLACED)?
        .strip_prefix(' ')?
        .parse()
        .ok()
}

/// A failure of the watcher that stands: what failed (`READ`, `SAMPLED`, `RESUBSCRIBE`,
/// `EVENTS`, `FULL_CHECK`, or `STORE` for one the store did not take), when, and what the
/// failure said.
pub struct Failure {
    pub what: String,
    pub at: i64,
    pub detail: String,
}

/// What has failed in the watcher that holds its lock on this store now and not succeeded
/// since. Empty while no watcher runs; a failure recorded before this one started is a past
/// watcher's and is left out. A failure the store did not take, which the lock file says, is
/// one of the kind `STORE`.
pub fn failures(conn: &Connection, folder: &Path) -> rusqlite::Result<Vec<Failure>> {
    let Some((since, state)) = responsive(folder) else {
        return Ok(Vec::new());
    };
    let mut failed = conn
        .prepare("SELECT what, at, detail FROM watcher_failed WHERE at >= ?1 ORDER BY what")?
        .query_map([since], |r| {
            Ok(Failure {
                what: r.get(0)?,
                at: r.get(1)?,
                detail: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if let LockState::Unrecorded { at, said } = state {
        failed.push(Failure {
            what: STORE.into(),
            at,
            detail: said,
        });
        failed.sort_by(|a, b| a.what.cmp(&b.what));
    }
    Ok(failed)
}

/// When a watcher last read every watched place of this store, whichever watcher it was;
/// `None` when none ever did.
pub fn last_read(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT last_read FROM watcher WHERE id = 1", [], |r| {
        r.get(0)
    })
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder whose watcher's lock is held by the returned handle, as a watcher holds it.
    fn held(tag: &str) -> (crate::common::Scratch, std::fs::File) {
        let dir = crate::common::Scratch::new(tag);
        let lock = store::lock_watch(&dir).unwrap().unwrap();
        (dir, lock)
    }

    fn put_lock(lock: &std::fs::File, text: &str) {
        lock.write_all_at(text.as_bytes(), 0).unwrap();
        lock.set_len(text.len() as u64).unwrap();
    }

    /// The job's watcher leaves when the path it was started from holds another file, as after
    /// an update that renamed a new core into place; nothing there, or a path it cannot look
    /// at, does not make it leave.
    #[test]
    fn a_watcher_s_file_is_replaced_only_when_its_path_holds_another_file() {
        let dir = crate::common::Scratch::new("watch-core-replaced");
        let core = dir.join("immune");
        std::fs::write(&core, "invented core").unwrap();
        let started = identity(&std::fs::metadata(&core).unwrap());
        assert!(!replaced(started, std::fs::metadata(&core)));
        let new = dir.join("immune.new");
        std::fs::write(&new, "invented new core").unwrap();
        std::fs::rename(&new, &core).unwrap();
        assert!(replaced(started, std::fs::metadata(&core)));
        std::fs::remove_file(&core).unwrap();
        assert!(!replaced(started, std::fs::metadata(&core)));
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(!replaced(started, Err(denied)));
    }

    /// The status says a watcher is restarting on a new core only from the line a watcher that
    /// left for one wrote, while no watcher holds the store, and not for long.
    #[test]
    fn a_watcher_that_left_for_a_new_core_is_restarting_only_while_none_holds_the_store() {
        let dir = crate::common::Scratch::new("watch-restarting");
        let path = dir.join(store::WATCH_LOCK);
        let left = 1_800_000_100;
        std::fs::write(
            &path,
            format!("1800000000\nheartbeat\ncore-replaced {left}"),
        )
        .unwrap();
        assert_eq!(restarting_since(&dir, left + 5), Some(left));
        assert_eq!(restarting_since(&dir, left + RESTARTING_FOR), Some(left));
        assert_eq!(restarting_since(&dir, left + RESTARTING_FOR + 1), None);
        // A time far ahead of the clock is not a watcher that left a moment ago.
        assert_eq!(restarting_since(&dir, left - RESTARTING_FOR - 1), None);
        let held = store::lock_watch(&dir).unwrap().unwrap();
        assert_eq!(restarting_since(&dir, left + 5), None);
        drop(held);
        for text in [
            "1800000000\nheartbeat\nready",
            "1800000000\nheartbeat\ncore-replaced 1800000100\nmore",
            "1800000000\nheartbeat\ncore-replaced",
            "1800000000\nheartbeat\ncore-replaced1800000100",
            "18OO000000\nheartbeat\ncore-replaced 1800000100",
            "1800000000\nheartbeet\ncore-replaced 1800000100",
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(restarting_since(&dir, left + 5), None, "{text:?}");
        }
    }

    /// Install takes what `seen` says for whether Immune is watching: live only for a watcher
    /// that is ready on a store with nothing failed but program starts or a full check, and
    /// unknown, never no, when the store cannot be read.
    #[test]
    fn a_watcher_is_seen_live_only_when_ready_with_nothing_failed_and_unknown_is_none() {
        let (dir, lock) = held("watch-seen");
        let store_path = dir.join("store.db");
        let since = crate::now_secs() - 10;
        put_lock(&lock, &format!("{since}\nheartbeat"));
        assert_eq!(seen(&store_path), Some(Seen::Starting));
        put_lock(&lock, &format!("{since}\nheartbeat\nready"));
        assert_eq!(seen(&store_path), None);
        store::open_or_make(&store_path).unwrap();
        assert_eq!(seen(&store_path), Some(Seen::Live));
        mark(&store_path, EVENTS, Some("invented")).unwrap();
        assert_eq!(seen(&store_path), Some(Seen::Live));
        mark(&store_path, READ, Some("invented")).unwrap();
        assert_eq!(
            seen(&store_path),
            Some(Seen::Failing(vec![EVENTS.into(), READ.into()]))
        );
        mark(&store_path, READ, None).unwrap();
        put_lock(
            &lock,
            &format!("{since}\nheartbeat\nunrecorded {since}\ninvented"),
        );
        assert_eq!(
            seen(&store_path),
            Some(Seen::Failing(vec![EVENTS.into(), STORE.into()]))
        );
        // A lock held with no heartbeat in it is no watcher.
        put_lock(&lock, "damaged");
        assert_eq!(seen(&store_path), Some(Seen::Absent));
        // One that left for a new core a moment ago is restarting, until the time is over.
        let left = format!("{since}\nheartbeat\ncore-replaced {}", crate::now_secs());
        put_lock(&lock, &left);
        drop(lock);
        assert_eq!(seen(&store_path), Some(Seen::Restarting));
        let path = dir.join(store::WATCH_LOCK);
        std::fs::write(&path, format!("{since}\nheartbeat\nready")).unwrap();
        assert_eq!(seen(&store_path), Some(Seen::Absent));
    }

    #[test]
    fn a_held_lock_without_a_heartbeat_line_or_with_a_damaged_one_is_not_a_watcher() {
        let (dir, lock) = held("watch-lock-damaged");
        for text in [
            "1800000000",
            "1800000000\n",
            "1800000000\nheartbeet\nready",
            "18OO000000\nheartbeat\nready",
            "",
        ] {
            put_lock(&lock, text);
            assert!(responsive(&dir).is_none(), "{text:?}");
            assert!(!watching_live(&dir), "{text:?}");
        }
        put_lock(&lock, "1800000000\nheartbeat\nready");
        assert!(watching_live(&dir));
    }

    #[test]
    fn a_new_watcher_is_not_ready_on_the_word_of_the_one_before_it() {
        // The watcher before it left `ready` in the file; start times are of one length, so a
        // new one written over the first two lines would keep that third line.
        let (dir, lock) = held("watch-lock-inherited");
        put_lock(&lock, "1800000000\nheartbeat\nready");
        assert!(watching_live(&dir));
        let mut heartbeat =
            Heartbeat::start(&lock, 1_800_000_001, Duration::from_secs(3600)).unwrap();
        assert!(responsive(&dir).is_none());
        heartbeat.write().unwrap();
        assert_eq!(responsive(&dir), Some((1_800_000_001, LockState::Starting)));
        drop(heartbeat);
    }

    #[test]
    fn a_lock_read_mid_rewrite_is_never_ready() {
        // The start of the new content over the rest of the old, or a part of the new.
        for text in [
            "17\nheartbeat\nreadycorded 18\nthe disk is full",
            "17\nheartbeat\nready\nthe disk is full",
            "17\nheartbeat\nrea",
            "17\nheartbeat\nunrec",
        ] {
            let (_, state) = read_lock(text).unwrap();
            assert_ne!(state, LockState::Ready, "{text:?}");
        }
        for state in [
            LockState::Starting,
            LockState::Ready,
            LockState::Unrecorded {
                at: 18,
                said: "the disk is full".into(),
            },
            LockState::Unrecorded {
                at: 18,
                said: String::new(),
            },
        ] {
            assert_eq!(read_lock(&lock_text(17, &state)), Some((17, state)));
        }
    }

    #[test]
    fn a_failure_the_store_did_not_take_withdraws_ready_until_the_kind_succeeds_or_is_recorded() {
        let (dir, lock) = held("watch-lock-unrecorded");
        let mut heartbeat = Heartbeat::start(&lock, 17, Duration::from_secs(3600)).unwrap();
        let said = || read_lock(&std::fs::read_to_string(dir.join(store::WATCH_LOCK)).unwrap());
        heartbeat.write().unwrap();
        assert_eq!(said(), Some((17, LockState::Starting)));
        heartbeat.read().unwrap();
        assert_eq!(said(), Some((17, LockState::Ready)));
        // What the store said is one line, and at most `UNRECORDED_CAP` characters.
        let long = format!("disk\nfull\r{}", "é".repeat(400));
        heartbeat.unrecorded(READ, &long);
        heartbeat.unrecorded(SAMPLED, "read-only");
        let Some((17, LockState::Unrecorded { said: first, .. })) = said() else {
            panic!("{:?}", said());
        };
        assert!(
            first == "read-only" || first.starts_with("disk full é"),
            "{first}"
        );
        heartbeat.recorded(SAMPLED);
        let Some((17, LockState::Unrecorded { said: left, .. })) = said() else {
            panic!("{:?}", said());
        };
        assert!(left.starts_with("disk full é"), "{left}");
        assert_eq!(left.chars().count(), UNRECORDED_CAP);
        // Ready comes back only when every kind left, and the old, longer content is gone.
        heartbeat.recorded(READ);
        assert_eq!(said(), Some((17, LockState::Ready)));
        assert_eq!(
            std::fs::read_to_string(dir.join(store::WATCH_LOCK)).unwrap(),
            "17\nheartbeat\nready"
        );
        drop(heartbeat);
    }

    #[test]
    fn a_watcher_whose_lock_file_cannot_say_an_unrecorded_failure_stops() {
        // A file it cannot rewrite would go on saying `ready`: the watcher stops instead, and
        // its lock goes with it.
        let (dir, lock) = held("watch-lock-unwritable");
        let read_only = std::fs::File::open(dir.join(store::WATCH_LOCK)).unwrap();
        let mut heartbeat = Heartbeat::start(&lock, 17, Duration::from_secs(3600)).unwrap();
        heartbeat.read().unwrap();
        assert!(watching_live(&dir));
        heartbeat.lock = &read_only;
        heartbeat.progress().unwrap();
        heartbeat.unrecorded(READ, "attempt to write a readonly database");
        // At every turn after it, not at the next one alone.
        assert!(heartbeat.progress().is_err());
        assert!(heartbeat.progress().is_err());
        drop(heartbeat);
    }

    #[test]
    fn a_failure_the_lock_file_says_is_a_store_failure_of_the_watcher_and_not_live() {
        let (dir, lock) = held("watch-lock-store-failure");
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO watcher_failed (what, at, detail) VALUES ('events', 18, 'refused')",
            [],
        )
        .unwrap();
        put_lock(
            &lock,
            "17\nheartbeat\nunrecorded 19\nattempt to write a readonly database",
        );
        assert!(!watching_live(&dir));
        let failed = failures(&conn, &dir).unwrap();
        let failed: Vec<_> = failed
            .iter()
            .map(|f| (f.what.as_str(), f.at, f.detail.as_str()))
            .collect();
        assert_eq!(
            failed,
            [
                (EVENTS, 18, "refused"),
                (STORE, 19, "attempt to write a readonly database")
            ]
        );
        put_lock(&lock, "17\nheartbeat\nready");
        assert!(watching_live(&dir));
        assert_eq!(failures(&conn, &dir).unwrap().len(), 1);
    }

    #[test]
    fn a_background_stall_is_distinct_from_a_regular_shutdown_even_after_progress() {
        let (tx, rx) = mpsc::channel();
        tx.send(()).unwrap();
        assert!(stalled(rx, Duration::ZERO));
        let (tx, rx) = mpsc::channel();
        tx.send(()).unwrap();
        drop(tx);
        assert!(!stalled(rx, Duration::ZERO));
    }

    // A store that has watched for months. The watcher reads at every change for as long as
    // the Mac runs, every reading adds to the history of what was looked through, and the app
    // asks for the status after each. What reads the store must not do more work as that history
    // grows. The work is counted in SQLite's steps (`store::steps`), not timed: a time on a
    // loaded machine grows for nothing, while a statement that looks through the history takes
    // a step for each of its rows, and the history added here is a reading's rows ten thousand
    // times over. Less than one more step for each reading added says that nothing looked
    // through them.

    /// The readings of the watcher added for a Mac open for months.
    const READINGS: u64 = 10_000;

    /// A Mac with a few projects, after its first full run and its watcher's first reading,
    /// with what a reading takes: the watcher's arguments and the store's folder.
    fn watched_for_a_while(dir: &Path) -> (WatchArgs, PathBuf) {
        let (home, sys) = (dir.join("home"), dir.join("sys"));
        let put = |p: PathBuf, s: &str| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        put(home.join(".zshrc"), "export EDITOR=vi\n");
        put(
            home.join("Library/LaunchAgents/org.example.sync.plist"),
            "<plist/>\n",
        );
        put(sys.join("etc/zshrc"), "setopt nobeep\n");
        for c in ["api", "site", "shop"] {
            put(
                home.join(format!("dev/{c}/.git/HEAD")),
                "ref: refs/heads/main\n",
            );
            put(
                home.join(format!("dev/{c}/.git/hooks/pre-commit")),
                "#!/bin/sh\n",
            );
            put(
                home.join(format!("dev/{c}/.vscode/tasks.json")),
                r#"{"tasks": [{"label": "dev", "runOptions": {"runOn": "folderOpen"}}]}"#,
            );
        }
        // A working folder whose hooks git keeps elsewhere, which a reading names as not read.
        put(
            home.join("dev/shop-fix/.git"),
            "gitdir: ../shop/.git/worktrees/shop-fix\n",
        );
        // A server the owner's check has read.
        put(
            dir.join("servers/web-1.txt"),
            "##os_release\n##kernel_package\n##package_managers\ndpkg\n##dpkg_with_source\n##docker_access\n##end\n",
        );
        put(dir.join("brew.json"), r#"{"formulae": [], "casks": []}"#);
        let (store, absent) = (dir.join("store/store.db"), dir.join("absent"));
        crate::run(&crate::Args {
            store: store.clone(),
            machine: "mac".into(),
            brew: None,
            brew_input: Some(dir.join("brew.json")),
            servers_input: Some(dir.join("servers")),
            home: home.clone(),
            checkouts_root: Some(home.clone()),
            sessions_root: Some(absent.clone()),
            tailscale: Some(absent.clone()),
            threats_input: Some(absent.clone()),
            osv_crates_input: Some(absent.clone()),
            osv_npm_input: Some(absent),
            curl: None,
            system_root: sys.clone(),
            indicators: None,
            form: crate::answer::Form::Text,
        })
        .unwrap();
        let w = WatchArgs {
            store: store.clone(),
            system_root: sys,
            home,
            sample_input: None,
            sample_every: SAMPLE,
            events_every: EVENTS_EVERY,
            alive_every: ALIVE,
            standalone: false,
            background: false,
        };
        let folder = crate::home(&store);
        read_held(&w, &folder, None).unwrap();
        (w, folder)
    }

    /// The history `READINGS` readings of the watcher leave, made in two statements: the rows
    /// of its latest reading again, each time under a run id of its own, with what each names
    /// as not read.
    fn add_watcher_history(store: &Path) {
        let conn = Connection::open(store).unwrap();
        let run: String = conn
            .query_row(
                "SELECT run_id FROM coverage WHERE run_id LIKE 'watch-%' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let rows = conn
            .execute(
                "WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1)
                 INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness,
                                       reason, cause)
                 SELECT reader, run_id || '-' || i, observed_at, scope, kind, completeness,
                        reason, cause
                 FROM n, coverage WHERE run_id = ?2",
                params![READINGS as i64, run],
            )
            .unwrap();
        assert!(rows as u64 >= READINGS, "{rows}");
        let lacks = conn
            .execute(
                "INSERT INTO coverage_lack (coverage, what, name)
                 SELECT copy.id, l.what, l.name
                 FROM coverage c JOIN coverage_lack l ON l.coverage = c.id
                 JOIN coverage copy ON copy.run_id >= ?1 || '-' AND copy.run_id < ?1 || '.'
                  AND copy.reader = c.reader AND copy.scope = c.scope AND copy.kind = c.kind
                 WHERE c.run_id = ?1",
                [&run],
            )
            .unwrap();
        assert!(lacks as u64 >= READINGS, "{lacks}");
    }

    /// The steps SQLite takes for `work` on a Mac watched for a while, on its first day and
    /// after `READINGS` readings of its watcher.
    fn first_day_and_later<T>(tag: &str, work: impl Fn(&WatchArgs, &Path) -> T) -> (u64, u64) {
        let dir = crate::common::Scratch::new(tag);
        let (w, folder) = watched_for_a_while(&dir);
        let (_, first) = store::steps::counted(|| work(&w, &folder));
        add_watcher_history(&w.store);
        let (_, later) = store::steps::counted(|| work(&w, &folder));
        assert!(first > 0, "nothing was counted");
        (first, later)
    }

    #[test]
    fn a_watchers_reading_after_ten_thousand_readings_does_no_more_work_than_the_first() {
        // A reading that grew with the history would after months take longer than the quiet
        // second it waits, and hold the store from a full run and from the status as long.
        let (first, later) = first_day_and_later("watch-flat", |w, folder| {
            read_held(w, folder, None).unwrap()
        });
        assert!(
            later < first + READINGS,
            "a reading took {first} steps, one after {READINGS} readings {later}"
        );
    }

    #[test]
    fn the_status_after_ten_thousand_readings_does_no_more_work_than_on_the_first_day() {
        // The app asks for the status after every reading of its watcher and every sample. One
        // that grew with what the watcher has read would, after months of an open app, make the
        // panel slow and hold the store while the next reading waits.
        let (first, later) = first_day_and_later("status-flat", |w, _| {
            crate::status_answer(&w.store, 1_800_000_000).unwrap()
        });
        assert!(
            later < first + READINGS,
            "the status took {first} steps on the first day, {later} after {READINGS} readings"
        );
    }

    #[test]
    fn the_view_after_ten_thousand_readings_is_made_with_no_more_work_than_on_the_first_day() {
        // The owner's pages are written when asked for after a change; they must not take
        // longer the longer the app has been open.
        let (first, later) =
            first_day_and_later("view-flat", |w, _| crate::write_view(&w.store).unwrap());
        assert!(
            later < first + READINGS,
            "the view took {first} steps on the first day, {later} after {READINGS} readings"
        );
    }

    fn reading(scope: &str, kind: &str) -> Reading {
        (scope.to_string(), kind.to_string())
    }

    /// Places of three readings: a watched folder, a profile with a link elsewhere, and a
    /// checkout's hooks.
    fn targets() -> Vec<(PathBuf, Reading)> {
        let (mac, hooks) = ("machine:mac", "checkout:machine:mac/dev/app");
        vec![
            (
                "/h/Library/LaunchAgents".into(),
                reading(mac, watched::AUTOSTART_KIND),
            ),
            ("/h/.zshrc".into(), reading(mac, watched::PROFILE_KIND)),
            ("/h/.zprofile".into(), reading(mac, watched::PROFILE_KIND)),
            (
                "/dotfiles/zprofile".into(),
                reading(mac, watched::PROFILE_KIND),
            ),
            (
                "/h/dev/app/.git/hooks".into(),
                reading(hooks, watched::HOOK_KIND),
            ),
        ]
    }

    fn at(paths: &[&str]) -> Where {
        Where::Paths(paths.iter().map(PathBuf::from).collect())
    }

    #[test]
    fn a_change_reads_again_only_the_readings_its_path_is_in() {
        let t = targets();
        let read = |paths: &[&str]| to_read(&t, &at(paths), true);
        let autostart = reading("machine:mac", watched::AUTOSTART_KIND);
        let profiles = reading("machine:mac", watched::PROFILE_KIND);
        let hooks = reading("checkout:machine:mac/dev/app", watched::HOOK_KIND);
        // An entry of a watched folder, a watched file, a link's target, a hook.
        assert_eq!(
            read(&["/h/Library/LaunchAgents/org.example.plist"]),
            Some([autostart.clone()].into())
        );
        assert_eq!(read(&["/h/.zshrc"]), Some([profiles.clone()].into()));
        assert_eq!(
            read(&["/dotfiles/zprofile"]),
            Some([profiles.clone()].into())
        );
        assert_eq!(
            read(&["/h/dev/app/.git/hooks/pre-commit", "/h/.zshrc"]),
            Some([profiles.clone(), hooks.clone()].into())
        );
        // A folder made or moved on the way to places is every reading under it.
        assert_eq!(read(&["/h/Library"]), Some([autostart.clone()].into()));
        assert_eq!(read(&["/h/dev"]), Some([hooks].into()));
    }

    #[test]
    fn every_place_is_read_where_the_change_cannot_be_placed_and_until_every_place_was_read_once() {
        let t = targets();
        // A path in no reading's place, alone or among others: a name only like one, as an
        // editor's swap file, is not the place.
        for paths in [
            &["/elsewhere/file"][..],
            &["/h/.zshrc.swp"],
            &["/h/.zshrc", "/h/Documents/x"],
        ] {
            assert_eq!(to_read(&t, &at(paths), true), None, "{paths:?}");
        }
        // Events FSEvents dropped or coalesced.
        assert_eq!(to_read(&t, &Where::Anywhere, true), None);
        // No path at all: never a reading of nothing.
        assert_eq!(to_read(&t, &Where::default(), true), None);
        // The watcher's first reading, and every one until a reading of every place succeeds.
        assert_eq!(to_read(&t, &at(&["/h/.zshrc"]), false), None);
    }

    #[test]
    fn a_place_is_named_by_the_real_path_of_its_folder_even_before_it_exists() {
        let dir = std::env::temp_dir().join(format!("immune-watch-real-{}", std::process::id()));
        let _removed = crate::common::Scratch::at(dir.clone());
        std::fs::create_dir_all(dir.join("real")).unwrap();
        let _ = std::fs::remove_file(dir.join("link"));
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let base = std::fs::canonicalize(&dir).unwrap();
        let homes = [base.as_path()];
        assert_eq!(
            real(&dir.join("link/not/yet/there"), &homes).unwrap(),
            Some(base.join("real/not/yet/there"))
        );
        // The place itself is not resolved: a link there is watched as a link.
        assert_eq!(
            real(&dir.join("link"), &homes).unwrap(),
            Some(base.join("link"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_problem_the_watcher_prints_holds_no_secret_what_failed_said_and_marks_the_cut() {
        // What failed can repeat what the system or a tool said: a token in it is cut, marked as
        // in a failure's detail.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let line = problem(
            "events_failed",
            &format!("the log said ?t={token} and stopped"),
        );
        let detail = line["detail_text"].as_str().unwrap();
        assert!(
            !detail.contains(&token)
                && detail.contains(&crate::secrets::mark("gitleaks:github-pat", 40)),
            "{detail}"
        );
    }

    #[test]
    fn a_problem_s_detail_keeps_the_place_s_name_breaks_no_mark_and_holds_none_a_source_wrote() {
        // The place and why are cut each on its own, so why, however long, never takes the name
        // with it; the cap never breaks a mark; and a mark a source wrote is its text.
        let place = Path::new("/Users/example/Library/LaunchAgents");
        let long = "x".repeat(crate::secrets::LINE_CAP + 1);
        let detail = |v: Value| v["detail_text"].as_str().unwrap().to_string();
        assert_eq!(
            detail(place_problem(place, &long)),
            format!(
                "{}: {}",
                place.display(),
                crate::secrets::mark(crate::secrets::TOO_LONG, long.len())
            )
        );
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        assert_eq!(
            detail(problem(
                "read_failed",
                &format!("{} ?t={token}", "y".repeat(240))
            )),
            format!("{} ?t=…", "y".repeat(240))
        );
        assert_eq!(
            detail(problem("read_failed", "x \\cut{gitleaks:github-pat 40}")),
            "x \\u{5c}cut{gitleaks:github-pat 40}"
        );
        // The name stays when nothing can be cut, and a failure's detail has the same cap.
        assert_eq!(
            crate::secrets::without_patterns(|| detail(place_problem(place, "denied"))),
            format!(
                "{}: {}",
                place.display(),
                crate::secrets::mark(crate::secrets::NO_PATTERNS, 6)
            )
        );
        let failure = status::failure(Some("watch"), "usage", "m", "e", &long);
        assert_eq!(
            failure["errors"][0]["detail_text"],
            crate::secrets::mark(crate::secrets::TOO_LONG, long.len())
        );
        let near = format!("{} ?t={token}", "y".repeat(240));
        let failure = status::failure(Some("watch"), "usage", "m", "e", &near);
        assert_eq!(
            failure["errors"][0]["detail_text"],
            format!("{} ?t=…", "y".repeat(240))
        );
    }
}
