//! `soc watch`: learns within seconds that a watched place changed and records it, so that a
//! change does not wait for the next full run. It runs until it is told to stop, as a child of
//! the menu-bar app, and installs nothing.
//!
//! The mechanism is FSEvents (`fsevents.rs`). An event is not trusted: it only says that
//! something under the watched paths changed. After a quiet period the watcher runs the
//! watched-places reading of `soc run` and its rules, through the same code (`watch_places`),
//! as a small run of that reader alone, under the same run lock, in one transaction. The
//! lifecycle makes the events and the rules the findings, as in a full run; the reading opens
//! nothing that is not a regular file and keeps no content. A small run writes no
//! `run_started` or `run_finished`: those mark full runs, which `soc status` reports on.
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
//! `alive`, and `problem` (`code`, `detail_text`).
//!
//! Samples. Every `SAMPLE` the watcher takes a sample of this user's running programs and
//! their connections (`processes.rs`), under the run lock like a reading, in one transaction.
//! A `sample` line is printed only when a sample opened a finding; a quiet sample prints
//! nothing. A sample that failed is a `problem` line, `sample_failed`, and the next is taken
//! at its time.
//! After a reading that changed something it brings the view up to date, when the owner has
//! made it once; `view_failed` says when it could not. The watcher stops,
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
use crate::{checkouts, status, store, watched};

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

pub struct WatchArgs {
    pub store: PathBuf,
    pub system_root: PathBuf,
    pub home: PathBuf,
    /// A reading made of invented processes, read again at every sample, instead of the
    /// system's: for tests, which set the clock in it.
    pub sample_input: Option<PathBuf>,
    pub sample_every: Duration,
}

/// Parses what follows `soc watch`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<WatchArgs, String> {
    let (mut store, mut system_root) = (None, None);
    let (mut sample_input, mut sample_every) = (None, SAMPLE);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            "--system-root" => system_root = Some(crate::value(&mut it, &arg)?.into()),
            "--sample-input" => sample_input = Some(crate::value(&mut it, &arg)?.into()),
            "--sample-every" => {
                let seconds = crate::value(&mut it, &arg)?
                    .parse::<u64>()
                    .ok()
                    .filter(|s| (1..=3600).contains(s))
                    .ok_or("--sample-every takes a number of seconds from 1 to 3600")?;
                sample_every = Duration::from_secs(seconds);
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
/// `soc status --json` and a non-zero exit when it cannot watch at all.
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
                "soc status --json",
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
        "soc watch",
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
    if !has_table(&conn)? {
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

fn has_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'watcher')",
        [],
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
        let (_, found) = self.holds()?;
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

    /// This machine's id and the checkouts the store holds on it.
    fn holds(&self) -> Result<(String, Vec<checkouts::Checkout>), Box<dyn Error>> {
        if !self.args.store.exists() {
            return Ok((this_machine(None)?, Vec::new()));
        }
        let conn = store::open_read_only(&self.args.store)?;
        let machine = this_machine(Some(&conn))?;
        let found = held_checkouts(&conn, &machine, &self.args.home)?;
        Ok((machine, found))
    }

    fn run(&mut self, rx: mpsc::Receiver<Msg>, at_start: Option<EventId>) {
        let mut due = at_start.map(|latest| Due {
            first: Instant::now(),
            at: Instant::now(),
            latest,
        });
        let mut alive = Instant::now() + ALIVE;
        // The first sample is taken at start, after the reading due then.
        let mut sample = Instant::now();
        loop {
            let next = due.as_ref().map_or(alive, |d| d.at.min(alive)).min(sample);
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
                        let changed = ["new", "changed", "gone"]
                            .iter()
                            .any(|c| counts[*c].as_u64().unwrap_or_default() > 0);
                        // A view the owner has open shows the change too, by the time the
                        // line says it.
                        let view = if changed {
                            crate::refresh_view(&self.args.store).err()
                        } else {
                            None
                        };
                        if !emit(&line("read", counts)) {
                            return;
                        }
                        if let Some(e) = view
                            && !emit(&problem("view_failed", &e.to_string()))
                        {
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
                match self.sample() {
                    Ok(Some((opened, needs))) if opened > 0 => {
                        let view = crate::refresh_view(&self.args.store).err();
                        let said = json!({ "opened": opened, "needs_a_look_total": needs });
                        if !emit(&line("sample", said)) {
                            return;
                        }
                        if let Some(e) = view
                            && !emit(&problem("view_failed", &e.to_string()))
                        {
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
            if alive <= now {
                alive = now + ALIVE;
                if !emit(&line("alive", json!({}))) {
                    return;
                }
                match self.again() {
                    Ok(Some(problems)) => {
                        if problems.iter().any(|p| !emit(p)) {
                            return;
                        }
                        // What changed in a place newly watched is read now.
                        let latest = due.as_ref().map_or(0, |d| d.latest);
                        let latest = latest.max(self.handled.unwrap_or(0));
                        due = Some(Due {
                            first: now,
                            at: now,
                            latest,
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
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
    fn read(&self, latest: EventId) -> Result<Option<Value>, Box<dyn Error>> {
        let Some(_lock) = self.lock()? else {
            return Ok(None);
        };
        let (machine, found) = self.holds()?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let at = now.as_secs() as i64;
        let run_id = format!("{RUN_PREFIX}{}-{:09}", now.as_secs(), now.subsec_nanos());
        let mut conn = store::open(&self.args.store)?;
        let tx = conn.transaction()?;
        store::put_entity(&tx, &machine)?;
        let mut run = crate::Run {
            tx: &tx,
            home: &self.folder,
            run_id: &run_id,
            at,
            machine: &machine,
            events: Vec::new(),
            notes: Vec::new(),
            readers: 0,
        };
        // The reading and the rules of `soc run`: a change seen here is a finding at once.
        let (rows, opened) = crate::watch_places(&mut run, &self.reader_args(), &found)?;
        // What needs a look after it, counted by the code `soc status --json` counts it with.
        let needs = status::needs(&tx, at)?.items.len();
        tx.execute_batch(TABLE)?;
        tx.execute(
            "INSERT INTO watcher (id, last_read, event_id, volumes) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET last_read = excluded.last_read,
                 event_id = excluded.event_id, volumes = excluded.volumes",
            params![at, latest.to_string(), self.volumes],
        )?;
        tx.commit()?;
        let count = |change: &str| rows.iter().filter(|r| r[0] == change).count();
        Ok(Some(json!({
            "needs_a_look_total": needs,
            "opened": opened,
            "new": count("new"),
            "changed": count("changed"),
            "gone": count("gone"),
        })))
    }

    /// The run lock, waited for; `None` when the watcher was stopped, or orphaned, meanwhile.
    fn lock(&self) -> std::io::Result<Option<std::fs::File>> {
        loop {
            if STOP.load(Ordering::SeqCst) || self.orphaned() {
                return Ok(None);
            }
            // Waits a little each time; a full run holds the lock for as long as it runs.
            if let Some(lock) = store::lock_run(&self.folder)? {
                return Ok(Some(lock));
            }
        }
    }

    /// One sample under the run lock: how many findings it opened and how many things need a
    /// look after it. `None` when the watcher was stopped while it waited for the lock.
    fn sample(&mut self) -> Result<Option<(usize, usize)>, Box<dyn Error>> {
        let Some(_lock) = self.lock()? else {
            return Ok(None);
        };
        let (report, needs) = crate::sample_held(
            &self.args.store,
            self.args.sample_input.as_deref(),
            &mut self.signers,
        )?;
        Ok(Some((report.findings_opened, needs)))
    }

    /// What `watch_places` takes from the run's arguments: the home folder and the system root.
    fn reader_args(&self) -> crate::Args {
        crate::Args {
            store: self.args.store.clone(),
            machine: String::new(),
            brew: None,
            brew_input: None,
            servers_input: None,
            home: self.args.home.clone(),
            checkouts_root: None,
            sessions_root: None,
            tailscale: None,
            threats_input: None,
            curl: None,
            system_root: self.args.system_root.clone(),
            indicators: None,
            json: false,
        }
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
/// are watched: the table of places, and the hooks folder of each checkout.
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

/// What `soc status --json` says about the watcher: `null` unless one holds its lock on this
/// store now, so a watcher that died never shows as watching. `since` is from the lock file;
/// `last_read` is the latest reading of a watcher, if this one made it.
pub fn status(store: &Path) -> Value {
    let folder = crate::home(store);
    if !store::watch_in_progress(&folder).unwrap_or(false) {
        return Value::Null;
    }
    // A watcher that has just taken its lock may not have written its start yet.
    let since: Option<i64> = std::fs::read_to_string(folder.join(store::WATCH_LOCK))
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let last = store::open_read_only(store)
        .ok()
        .and_then(|conn| last_read(&conn).ok().flatten());
    let last = last.filter(|last| since.is_some_and(|since| *last >= since));
    let iso = |secs: i64| json!(crate::view::iso(secs));
    json!({
        "since": since.map_or(Value::Null, iso),
        "last_read": last.map_or(Value::Null, iso),
        "cannot_see": CANNOT_SEE,
    })
}

/// When a watcher last read the watched places of this store, whichever watcher it was;
/// `None` when none ever did.
pub fn last_read(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    if !has_table(conn)? {
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
        let dir = std::env::temp_dir().join(format!("soc-watch-real-{}", std::process::id()));
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
