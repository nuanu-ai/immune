//! `immune watch`: learns within seconds that a watched place changed and records it, so that a
//! change does not wait for the next full run. It runs until it is told to stop, as a child of
//! the menu-bar app, and installs nothing.
//!
//! The mechanism is FSEvents (`fsevents.rs`). An event is not trusted: it only says that
//! something under the watched paths changed. After a quiet period the watcher runs the
//! watched-places reading of `immune run` and its rules, through the same code (`watch_places`),
//! as a small run of that reader alone, under the same run lock, in one transaction. The
//! lifecycle makes the events and the rules the findings, as in a full run; the reading opens
//! nothing that is not a regular file and keeps no content. A small run writes no
//! `run_started` or `run_finished`: those mark full runs, which `immune status` reports on.
//!
//! The last event id handled is kept with the identity of the FSEvents history of each volume
//! watched, in the `watcher` table, and written in the transaction of the reading that handled
//! it: an id is kept only once what it stands for is in the store. Every change with an id at
//! or before it happened before that reading began. At start FSEvents replays what happened
//! since; when the id cannot be used, the watcher says why and reads at once.
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
//! the store can hold it; the next success of the same kind clears it. While one stands,
//! `immune status` does not say this Mac is watched live. A look at what to watch that succeeds
//! after one that failed prints `watching` again and reads the watched places at once.
//!
//! While it waits for the run lock, which a full run holds for as long as it runs, it says it
//! is alive at its usual interval, so that a long run does not get it taken for dead.
//! It writes no page of the view, only that small file: a change can come every few seconds and the pages cost
//! seconds of processor time, mostly for pages nobody has open. A page is brought up to date
//! when it is asked for, by `immune view --if-stale`, which writes only when something the pages
//! rest on moved since they were made (`view::basis`). The watcher stops,
//! with exit 0, when stdout is closed or its parent process is gone, so that an app that died
//! leaves no watcher holding the store.

use std::collections::BTreeSet;
use std::error::Error;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::fsevents::{self, EventId};
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

/// The watcher's state in the store: one row, made by its first reading, in the reading's
/// transaction. The store's format does not change for it. When the watcher started is not
/// here but in its lock file, which it writes as it takes the lock, so that nothing is
/// written to the store outside the run lock.
const TABLE: &str = "
CREATE TABLE IF NOT EXISTS watcher (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    last_read INTEGER NOT NULL,  -- when a watcher last read the watched places, UTC seconds
    event_id  TEXT NOT NULL,     -- the last FSEvents event id handled, in decimal
    volumes   TEXT NOT NULL      -- the FSEvents history identity of each volume watched
);
";

/// What failed in a watcher and has not succeeded since: one row per kind, made by its first
/// failure, under the run lock, as `watcher` is. A row older than the watcher that holds the
/// lock now is a past watcher's and is not read.
const FAILED_TABLE: &str = "
CREATE TABLE IF NOT EXISTS watcher_failed (
    what   TEXT PRIMARY KEY,  -- `read`, `sample`, `resubscribe` or `events`
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

/// A kind of failure in words, for a person.
pub fn failed_words(what: &str) -> &'static str {
    match what {
        READ => "reading of the watched places",
        SAMPLED => "sample of running programs",
        EVENTS => "reading of program starts",
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
}

/// Parses what follows `immune watch`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<WatchArgs, String> {
    let (mut store, mut system_root) = (None, None);
    let (mut sample_input, mut sample_every, mut alive_every) = (None, SAMPLE, ALIVE);
    let mut events_every = EVENTS_EVERY;
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
    // would leave launchd recorded as the parent, and the watcher would never stop. A parent
    // that is launchd already is one that is gone, since nothing starts a watcher from launchd
    // in this build; it stops at once with exit 0 and prints nothing.
    // SAFETY: getppid(2) takes nothing and cannot fail.
    let parent = unsafe { libc::getppid() };
    if parent == 1 {
        return ExitCode::SUCCESS;
    }
    // Next, so that a stop asked for at any moment after this is a clean one.
    let (tx, rx) = mpsc::channel();
    if let Err(e) = on_signals(tx.clone()) {
        return failed(&format!("the signal handlers could not be set: {e}"));
    }
    let folder = crate::home(&args.store);
    let unreadable =
        |e: &dyn std::fmt::Display| crate::fail_json("watch", &crate::Stop::Store(e.to_string()));
    if let Err(e) = std::fs::create_dir_all(&folder) {
        return unreadable(&e);
    }
    let started = crate::now_secs();
    let _lock = match store::lock_watch(&folder) {
        Ok(Some(mut lock)) => {
            // The lock file says since when this watcher holds it; status reads it there.
            let marked = lock
                .set_len(0)
                .and_then(|()| lock.write_all(started.to_string().as_bytes()));
            if let Err(e) = marked {
                return unreadable(&e);
            }
            lock
        }
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
    let stored = match stored(&args.store) {
        Ok(stored) => stored,
        Err(e) => return unreadable(&e),
    };
    let mut w = Watcher {
        args,
        folder,
        tx,
        stream: None,
        wanted: Vec::new(),
        paths: Vec::new(),
        volumes: String::new(),
        handled: None,
        parent,
        signers: crate::processes::Signers::default(),
        standing: BTreeSet::new(),
    };
    let (problems, since) = match w.subscribe(stored) {
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
    w.run(rx, since);
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
    line(
        "problem",
        json!({ "code": code, "detail_text": status::text(detail) }),
    )
}

/// What the store kept of the watcher that ran before: the last id it handled and the
/// identities of the volumes that id belongs to.
#[derive(Debug, PartialEq)]
struct Stored {
    event_id: EventId,
    volumes: String,
}

/// What the last watcher kept, read without writing: nothing while there is no store or no
/// watcher has read yet. A store this build cannot read stops the watcher here.
fn stored(path: &Path) -> Result<Option<Stored>, Box<dyn Error>> {
    if !path.exists() {
        return Ok(None);
    }
    let conn = store::open_read_only(path)?;
    if !has_table(&conn, "watcher")? {
        return Ok(None);
    }
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT event_id, volumes FROM watcher WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(id, volumes)| id.parse().ok().map(|event_id| Stored { event_id, volumes })))
}

fn has_table(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |r| r.get(0),
    )
}

/// Why a stored id cannot be used, or `None` when FSEvents can replay from it.
fn unusable(stored: &Stored, volumes: &str, current: EventId) -> Option<&'static str> {
    if volumes.is_empty() || volumes.split(' ').any(|v| v == NO_HISTORY) {
        Some("a watched volume keeps no FSEvents history")
    } else if stored.volumes != volumes {
        Some(
            "the FSEvents history of the watched volumes is not the one the stored id belongs to: it was discarded or purged, or the volumes watched changed",
        )
    } else if stored.event_id > current {
        Some("the stored event id is ahead of this Mac's")
    } else {
        None
    }
}

/// How a volume without FSEvents history is named among the identities.
const NO_HISTORY: &str = "none";

struct Watcher<'a> {
    args: &'a WatchArgs,
    folder: PathBuf,
    tx: Sender<Msg>,
    stream: Option<fsevents::Stream>,
    /// The paths asked for, FSEvents refusing some or not.
    wanted: Vec<PathBuf>,
    /// The paths the stream watches.
    paths: Vec<PathBuf>,
    /// The identities of the FSEvents histories of the volumes the paths are on.
    volumes: String,
    /// The last event id handled, as the store keeps it.
    handled: Option<EventId>,
    /// The process that started the watcher. When it is gone the watcher is an orphan, its
    /// parent now another process, and it stops: a new app must be able to start its own.
    parent: libc::pid_t,
    /// Who signed what the samples track, kept across samples.
    signers: crate::processes::Signers,
    /// The kinds whose latest attempt failed, or whose failure may still stand in the store
    /// because clearing it failed: `READ`, `SAMPLED`, `RESUBSCRIBE`, `EVENTS`.
    standing: BTreeSet<&'static str>,
}

/// A reading that is due: when, since which event it was first due, and the latest id it
/// will have handled.
struct Due {
    first: Instant,
    at: Instant,
    latest: EventId,
}

impl Watcher<'_> {
    /// Subscribes to the watched places. Returns the problem lines, and the id a reading at
    /// start must record, or `None` when FSEvents replays from the stored id instead.
    fn subscribe(
        &mut self,
        stored: Option<Stored>,
    ) -> Result<(Vec<Value>, Option<EventId>), String> {
        let (wanted, mut problems) = self.derive().map_err(|e| e.to_string())?;
        let volumes = identities(&wanted);
        let current = fsevents::current_event_id();
        let since = match &stored {
            Some(s) => match unusable(s, &volumes, current) {
                Some(why) => {
                    problems.push(problem("history_unusable", why));
                    None
                }
                None => Some(s.event_id),
            },
            None => None,
        };
        problems.extend(self.start(wanted, volumes, since)?);
        self.handled = since;
        // Without a usable id, what changed while no watcher ran is read now; `current` was
        // taken before the stream started, so nothing after it is missed.
        Ok((problems, since.is_none().then_some(current)))
    }

    /// Starts a stream on `wanted` in place of the one running, if any. Returns the problem
    /// lines of the paths FSEvents refused.
    fn start(
        &mut self,
        wanted: Vec<PathBuf>,
        volumes: String,
        since: Option<EventId>,
    ) -> Result<Vec<Value>, String> {
        let tx = self.tx.clone();
        let deliver = Box::new(move |b: fsevents::Batch| {
            let _ = tx.send(Msg::Events(b));
        });
        let refs: Vec<&Path> = wanted.iter().map(PathBuf::as_path).collect();
        let (stream, refused) = fsevents::Stream::start(&refs, since, LATENCY, deliver)?;
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
        self.volumes = volumes;
        Ok(problems)
    }

    /// The paths to watch now, from the table of places and the checkouts the store holds,
    /// and a problem line for each place that cannot be watched.
    fn derive(&self) -> Result<(Vec<PathBuf>, Vec<Value>), Box<dyn Error>> {
        let (_, found) = holds(self.args)?;
        let mut wanted = BTreeSet::new();
        let mut problems = Vec::new();
        for (place, folder) in places(&self.args.home, &self.args.system_root, &found) {
            match real(&place) {
                Ok(path) => {
                    wanted.insert(path);
                    wanted.extend(link_targets(&place, folder));
                }
                Err(why) => problems.push(place_problem(&place, &why)),
            }
        }
        Ok((wanted.into_iter().collect(), problems))
    }

    fn run(&mut self, rx: mpsc::Receiver<Msg>, at_start: Option<EventId>) {
        let mut due = at_start.map(|latest| Due {
            first: Instant::now(),
            at: Instant::now(),
            latest,
        });
        let mut alive = Instant::now() + self.args.alive_every;
        // The first sample is taken at start, after the reading due then, and the first
        // reading of program starts after it.
        let mut sample = Instant::now();
        let mut starts = Instant::now();
        loop {
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
                            latest: b.latest,
                        },
                        Some(d) => Due {
                            at: (now + QUIET).min(d.first + MOST_WAIT),
                            latest: d.latest.max(b.latest),
                            first: d.first,
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
                match self.read(d.latest) {
                    Ok(Some(counts)) => {
                        self.handled = Some(d.latest);
                        if !emit(&line("read", counts)) {
                            return;
                        }
                    }
                    // Stopped while it waited for a full run to finish.
                    Ok(None) => return,
                    Err(e) => {
                        if !emit(&problem("read_failed", &e.to_string())) {
                            return;
                        }
                        due = Some(Due {
                            first: now,
                            at: now + RETRY,
                            latest: d.latest,
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
                if (again.is_err() || recovered)
                    && let Ok(Some(_lock)) = self.lock()
                {
                    self.mark_held(RESUBSCRIBE, again.as_ref().err().cloned());
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
                            let latest = due.as_ref().map_or(0, |d| d.latest);
                            let latest = latest.max(self.handled.unwrap_or(0));
                            due = Some(Due {
                                first: now,
                                at: now,
                                latest,
                            });
                        }
                    }
                    Err(e) => {
                        self.standing.insert(RESUBSCRIBE);
                        if !emit(&problem("resubscribe_failed", &e)) {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn orphaned(&self) -> bool {
        // SAFETY: getppid(2) takes nothing and cannot fail.
        unsafe { libc::getppid() != self.parent }
    }

    /// Looks again at what should be watched, after a full run may have changed the
    /// checkouts. Returns `None` when nothing changed, else the new problem lines.
    fn again(&mut self) -> Result<Option<Vec<Value>>, String> {
        let (wanted, mut problems) = self.derive().map_err(|e| e.to_string())?;
        if wanted == self.wanted {
            return Ok(None);
        }
        let volumes = identities(&wanted);
        problems.extend(self.start(wanted, volumes, None)?);
        Ok(Some(problems))
    }

    /// One reading of the watched places, as a small run of that reader alone, recording
    /// `latest` as handled. `None` when the watcher was stopped, or orphaned, while it waited for the run
    /// lock. The counts are of this reading, the baseline counting as nothing new.
    fn read(&mut self, latest: EventId) -> Result<Option<Value>, Box<dyn Error>> {
        let Some(_lock) = self.lock()? else {
            return Ok(None);
        };
        let read = read_held(self.args, &self.folder, &self.volumes, latest);
        self.mark_held(READ, read.as_ref().err().map(|e| e.to_string()));
        read.map(Some)
    }

    /// The run lock, waited for; `None` when the watcher was stopped, or orphaned, meanwhile,
    /// or stdout is gone. A full run holds the lock for as long as it runs, minutes at times:
    /// meanwhile the watcher says it is alive at its usual interval, since the app takes a
    /// watcher that says nothing for three minutes for dead.
    fn lock(&self) -> std::io::Result<Option<std::fs::File>> {
        let mut alive = Instant::now() + self.args.alive_every;
        loop {
            if STOP.load(Ordering::SeqCst) || self.orphaned() {
                return Ok(None);
            }
            // Waits a little each time.
            if let Some(lock) = store::lock_run(&self.folder)? {
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

    /// One sample under the run lock: how many findings it opened and how many things need a
    /// look after it. `None` when the watcher was stopped while it waited for the lock.
    fn sample(&mut self) -> Result<Option<(usize, usize)>, Box<dyn Error>> {
        let Some(_lock) = self.lock()? else {
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
        let Some(_lock) = self.lock()? else {
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
    /// said, or that it succeeded, which clears a failure recorded before. Where the store
    /// cannot hold it, the `problem` line alone says it.
    fn mark_held(&mut self, what: &'static str, failed: Option<String>) {
        match failed {
            Some(detail) => {
                self.standing.insert(what);
                let _ = mark(&self.args.store, what, Some(&detail));
            }
            None if self.standing.contains(what) && mark(&self.args.store, what, None).is_ok() => {
                self.standing.remove(what);
            }
            None => {}
        }
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
    conn.execute_batch(FAILED_TABLE)?;
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
/// that reader alone, recording `latest` as handled with the identities of `volumes`. The
/// counts are of this reading, the baseline counting as nothing new.
fn read_held(
    args: &WatchArgs,
    folder: &Path,
    volumes: &str,
    latest: EventId,
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
        events: Vec::new(),
        notes: Vec::new(),
        readers: 0,
    };
    // The reading and the rules of `immune run`: a change seen here is a finding at once.
    let (rows, opened) = crate::watch_places(&mut run, &reader_args(args), &found)?;
    // What needs a look after it, counted by the code `immune status --json` counts it with.
    let needs = status::needs(&tx, at)?.items.len();
    tx.execute_batch(TABLE)?;
    tx.execute(
        "INSERT INTO watcher (id, last_read, event_id, volumes) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT (id) DO UPDATE SET last_read = excluded.last_read,
             event_id = excluded.event_id, volumes = excluded.volumes",
        params![at, latest.to_string(), volumes],
    )?;
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
        json: false,
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
        // A watcher started by the app never looks into a folder macOS asks permission for.
        .filter(|c| crate::guarded::folder_of(&c.path, home).is_none())
        .collect())
}

/// Every watched place on this machine as a path, and whether it is a folder whose entries
/// are watched: the table of places, the hooks folder of each checkout, and the files of
/// each checkout through which something runs by itself (`autorun::files`), and the places of
/// the home folder through which a tool's own settings do (`autorun::home_places`).
fn places(home: &Path, system: &Path, found: &[checkouts::Checkout]) -> Vec<(PathBuf, bool)> {
    let mut out = Vec::new();
    for p in &watched::PLACES {
        match p.base {
            watched::Base::Home => out.push((home.join(p.path), p.folder)),
            watched::Base::System => out.push((system.join(p.path), p.folder)),
            watched::Base::Checkout => {
                for c in found {
                    out.push((c.path.join(p.path), p.folder));
                }
            }
        }
    }
    for c in found {
        for file in autorun::files() {
            out.push((c.path.join(file), false));
        }
    }
    for (place, folder) in autorun::home_places() {
        out.push((home.join(place), folder));
    }
    out
}

/// The path as FSEvents names it: the real path of its folder, which need not exist yet, and
/// its own name. FSEvents reports real paths, and `/etc` is a link to `/private/etc`.
fn real(path: &Path) -> Result<PathBuf, String> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Ok(path.to_path_buf());
    };
    let mut missing = Vec::new();
    let mut existing = parent.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(last) = existing.file_name() else {
                    return Err(e.to_string());
                };
                missing.push(last.to_os_string());
                existing.pop();
            }
            // Any other error, such as a folder that cannot be searched, comes back from
            // resolving the path below.
            Err(_) => break,
        }
    }
    let mut out = std::fs::canonicalize(&existing).map_err(|e| e.to_string())?;
    out.extend(missing.iter().rev());
    out.push(name);
    Ok(out)
}

/// Where symbolic links among the watched places lead: the place itself when it is a link,
/// and each link in a watched folder. A change at the target is reported under the target.
fn link_targets(place: &Path, folder: bool) -> Vec<PathBuf> {
    let mut links = vec![place.to_path_buf()];
    if folder && let Ok(entries) = std::fs::read_dir(place) {
        links.extend(entries.flatten().map(|e| e.path()));
    }
    links
        .into_iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()))
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

fn place_problem(place: &Path, why: &str) -> Value {
    problem("place_not_watched", &format!("{}: {why}", place.display()))
}

/// The identities of the FSEvents histories of the volumes the paths are on, sorted, with
/// `none` for a volume that keeps no history.
fn identities(paths: &[PathBuf]) -> String {
    use std::os::unix::fs::MetadataExt;
    let mut devices = BTreeSet::new();
    for path in paths {
        // The nearest folder that exists is on the volume the path will be on.
        if let Some(m) = path.ancestors().find_map(|p| std::fs::metadata(p).ok()) {
            devices.insert(m.dev() as fsevents::Dev);
        }
    }
    let ids: BTreeSet<String> = devices
        .into_iter()
        .map(|d| fsevents::volume_identity(d).unwrap_or_else(|| NO_HISTORY.to_string()))
        .collect();
    ids.into_iter().collect::<Vec<_>>().join(" ")
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

/// What `immune status --json` says about the watcher: `null` unless one holds its lock on this
/// store now, so a watcher that died never shows as watching. `since` is from the lock file;
/// `last_read` is the latest reading of a watcher, if this one made it; `failed` is what has
/// failed in this one and not succeeded since, with what the failure said.
pub fn status(store: &Path) -> Value {
    let folder = crate::home(store);
    if !store::watch_in_progress(&folder).unwrap_or(false) {
        return Value::Null;
    }
    let since = started(&folder);
    let conn = store::open_read_only(store).ok();
    let last = conn
        .as_ref()
        .and_then(|conn| last_read(conn).ok().flatten());
    let last = last.filter(|last| since.is_some_and(|since| *last >= since));
    let failed = conn
        .as_ref()
        .and_then(|conn| failures(conn, &folder).ok())
        .unwrap_or_default();
    let iso = |secs: i64| json!(crate::view::iso(secs));
    let failed: Vec<Value> = failed
        .iter()
        .map(|f| json!({ "what": f.what, "at": iso(f.at), "detail_text": status::text(&f.detail) }))
        .collect();
    json!({
        "since": since.map_or(Value::Null, iso),
        "last_read": last.map_or(Value::Null, iso),
        "failed": failed,
        "cannot_see": CANNOT_SEE,
    })
}

/// What the pages of the view rest on about the watcher: when the one that holds the store
/// started, and what has failed in it and not succeeded since; `none` while none holds it.
pub fn basis(conn: &Connection, folder: &Path) -> rusqlite::Result<String> {
    if !store::watch_in_progress(folder).unwrap_or(false) {
        return Ok("none".into());
    }
    let failed: Vec<String> = failures(conn, folder)?
        .into_iter()
        .map(|f| f.what)
        .collect();
    Ok(format!("{:?} {}", started(folder), failed.join(",")))
}

/// When the watcher that holds the lock now started, from its lock file. A watcher that has
/// just taken its lock may not have written its start yet.
fn started(folder: &Path) -> Option<i64> {
    std::fs::read_to_string(folder.join(store::WATCH_LOCK))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// A failure of the watcher that stands: what failed (`READ`, `SAMPLED`, `RESUBSCRIBE`,
/// `EVENTS`), when, and what the failure said.
pub struct Failure {
    pub what: String,
    pub at: i64,
    pub detail: String,
}

/// What has failed in the watcher that holds its lock on this store now and not succeeded
/// since. Empty while no watcher runs; a failure recorded before this one started is a past
/// watcher's and is left out.
pub fn failures(conn: &Connection, folder: &Path) -> rusqlite::Result<Vec<Failure>> {
    if !store::watch_in_progress(folder).unwrap_or(false) {
        return Ok(Vec::new());
    }
    let Some(since) = started(folder) else {
        return Ok(Vec::new());
    };
    if !has_table(conn, "watcher_failed")? {
        return Ok(Vec::new());
    }
    conn.prepare("SELECT what, at, detail FROM watcher_failed WHERE at >= ?1 ORDER BY what")?
        .query_map([since], |r| {
            Ok(Failure {
                what: r.get(0)?,
                at: r.get(1)?,
                detail: r.get(2)?,
            })
        })?
        .collect()
}

/// When a watcher last read the watched places of this store, whichever watcher it was;
/// `None` when none ever did.
pub fn last_read(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    if !has_table(conn, "watcher")? {
        return Ok(None);
    }
    conn.query_row("SELECT last_read FROM watcher WHERE id = 1", [], |r| {
        r.get(0)
    })
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(event_id: EventId, volumes: &str) -> Stored {
        Stored {
            event_id,
            volumes: volumes.to_string(),
        }
    }

    #[test]
    fn a_watchers_reading_after_ten_thousand_readings_is_as_quick_as_the_first() {
        // The watcher reads at every change for as long as the Mac runs, and every reading
        // adds to the history of what was looked through. A reading that grew with that
        // history would after months take longer than the quiet second it waits, and hold
        // the store from a full run and from the owner's status for as long.
        let dir = std::env::temp_dir().join(format!("immune-watch-flat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
        put(dir.join("brew.json"), r#"{"formulae": [], "casks": []}"#);
        let (store, absent) = (dir.join("store/store.db"), dir.join("absent"));
        crate::run(&crate::Args {
            store: store.clone(),
            machine: "mac".into(),
            brew: None,
            brew_input: Some(dir.join("brew.json")),
            servers_input: Some(absent.clone()),
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
            json: false,
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
        };
        let folder = crate::home(&store);
        // The quickest of a few, so that a busy moment of the Mac is not taken for the cost.
        let quickest = || {
            (0..5)
                .map(|_| {
                    let t = Instant::now();
                    read_held(&w, &folder, "", 1).unwrap();
                    t.elapsed()
                })
                .min()
                .unwrap()
        };
        let first = quickest();
        // The history ten thousand readings of the watcher leave, made in one statement: the
        // latest reading's rows again, each time under a run id of its own.
        let conn = Connection::open(&store).unwrap();
        let run: String = conn
            .query_row(
                "SELECT run_id FROM coverage WHERE run_id LIKE 'watch-%' ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
             INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness,
                                   reason, cause)
             SELECT reader, run_id || '-' || i, observed_at, scope, kind, completeness, reason,
                    cause
             FROM n, coverage WHERE run_id = ?1",
            [&run],
        )
        .unwrap();
        drop(conn);
        let later = quickest();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            later < first * 3 + Duration::from_millis(5),
            "the first reading took {first:?}, one after ten thousand {later:?}"
        );
    }

    #[test]
    fn a_stored_id_is_used_only_on_the_same_histories_and_never_ahead_of_this_mac() {
        // A replay from an id that belongs to another history would silently miss changes.
        assert_eq!(unusable(&stored(10, "a b"), "a b", 10), None);
        assert!(unusable(&stored(10, "a b"), "a c", 20).is_some());
        assert!(unusable(&stored(10, "a"), "a b", 20).is_some());
        assert!(unusable(&stored(11, "a"), "a", 10).is_some());
        assert!(unusable(&stored(10, "a none"), "a none", 20).is_some());
        assert!(unusable(&stored(10, ""), "", 20).is_some());
    }

    #[test]
    fn a_place_is_named_by_the_real_path_of_its_folder_even_before_it_exists() {
        let dir = std::env::temp_dir().join(format!("immune-watch-real-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("real")).unwrap();
        let _ = std::fs::remove_file(dir.join("link"));
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let base = std::fs::canonicalize(&dir).unwrap();
        assert_eq!(
            real(&dir.join("link/not/yet/there")).unwrap(),
            base.join("real/not/yet/there")
        );
        // The place itself is not resolved: a link there is watched as a link.
        assert_eq!(real(&dir.join("link")).unwrap(), base.join("link"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
