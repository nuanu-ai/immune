//! The event level: every program start on this Mac, as Apple's `eslogger` records it. This is
//! level of access (b) in `docs/scheme.md`. The collecting side runs as root and is data in
//! `scripts/event-level/`: launchd runs `/usr/bin/eslogger exec` into a FIFO, Apple's `jq`
//! keeps of each message only what this reader uses, under `eslogger`'s own names, and Apple's
//! `rotatelogs` appends that to one file per hour in a folder only root and the installing
//! account can read; the root side deletes files older than a day, and the oldest while the
//! log is over its size cap, and notes each deletion in `removed`. This reader runs as the
//! owner, without rights, on the collection path: no model and no network. It is stage 1: it reads the log honestly and counts. No rule runs
//! over the events yet, and the store keeps none of them: only where each log file was read
//! up to, the last sequence number, counts per reading, the state, and coverage.
//!
//! A reader first finds out whether its source exists. The level is installed when its launch
//! daemon's property list is in `/Library/LaunchDaemons`; when it is not, that is "not
//! applicable", a limit the owner can lift, and not a failure. A log folder that is there and
//! cannot be read is a failed reading with its reason.
//!
//! Lines are read whole, from where the last reading stopped in each file, by the file's name
//! and inode; a line still being written is left for the next reading. A file that is gone is
//! forgotten, so a deleted file is never read again and one with the same name and another
//! inode is read from its start. A line that is not a JSON object, such as the two halves of
//! a line `rotatelogs` split between two files, is counted and skipped. A message of another
//! kind than `exec` is counted and ignored. A message without a field this reader needs, or
//! with an unknown `schema_version`, means the format changed: the reading fails with the
//! reason, never with a default, and nothing is taken as read, so a build that knows the new
//! format reads the same lines. The message `version` alone fails nothing: Apple raises it
//! with macOS releases as it adds fields (6 in 2023, 10 on macOS 26, 11 in the macOS 27
//! beta), and failing on it would turn the level off at every update until the program
//! follows; what the reader uses is checked field by field instead, and the latest version
//! read is served.
//!
//! Files the root side deleted are told from its notes: a file deleted to stay under the size
//! cap held lines younger than a day, and a file deleted before this reader read it to its end
//! held lines it never read. Both make the reading partial with their counts.
//!
//! Losses are counted from `seq_num`, not `global_seq_num`. `ESMessage.h` defines `seq_num` as
//! per client and per event type, incrementing by one for each message of that type, with the
//! number dropped equal to the difference from the last seen plus one; it exists from message
//! version 2, `global_seq_num` from 4. With `exec` alone the two move together; `seq_num` stays
//! a count of lost program starts if another event type is subscribed later. The numbers belong
//! to one run of `eslogger`: a number at or below the last one means it started again, and
//! what was lost across that is a gap of unknown size, counted as such and never as zero.
//! A gap also takes in starts that were deleted before any reading saw them, which the notes
//! of deletions count apart.
//!
//! The typed event names its fields after the Elastic Common Schema where it has one, as the
//! samples do. Stage 2, rules over these events, consumes it.

use crate::store::{Cause, Gap, Reading};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The reader's name in coverage.
pub const READER: &str = "events";
/// The coverage kind of a reading.
pub const KIND: &str = "program starts on this Mac, from Apple's eslogger";
/// The level of access the events come from.
pub const LEVEL: &str = "Apple's eslogger as administrator";
/// How the run id of a watcher's reading begins.
pub const RUN_PREFIX: &str = "events-";
/// The launch daemon's property list, under the system root: there when the level is installed.
pub const PLIST: &str = "Library/LaunchDaemons/local.personal-soc.eslogger.plist";
/// The log folder, under the system root.
pub const LOG: &str = "Library/Application Support/personal-soc/event-level/log";
/// What `eslogger` prints, and what the root side's own scripts print, in the log folder.
pub const ESLOGGER_SAID: &str = "eslogger.err";
pub const SCRIPTS_SAID: &str = "scripts.err";
/// The root side's notes of what it deleted: `<when> <file> <bytes> age|cap`, one a line.
pub const REMOVED: &str = "removed";
/// The log files: `exec-YYYYMMDDTHH.jsonl`, one per hour, so their names sort in time.
const PREFIX: &str = "exec-";
const SUFFIX: &str = ".jsonl";
/// No line written for this long means the level does not record. The root side's tidy job
/// runs every ten minutes, and the programs it starts are themselves program starts
/// `eslogger` records, so a level that runs on a Mac that is awake writes at least that
/// often. Right after a wake from sleep a reading may say silent before the first start is
/// written; the next one says otherwise.
pub const SILENT_AFTER: i64 = 15 * 60;
/// The span the log keeps, and the span over which counts are served and coverage is judged:
/// a loss in it is a gap in what the log holds.
const DAY: i64 = 24 * 60 * 60;
/// How long counts per reading are kept: a day is served, and the reading since the last
/// full check.
const KEEP: i64 = 2 * DAY;
/// The `schema_version`s this reader knows.
pub const SCHEMA_VERSIONS: [u64; 1] = [1];
/// What `eslogger` prints when macOS refuses it Full Disk Access: the result code of
/// `es_new_client`, as Mullvad's parser matches it.
const NOT_PERMITTED: &str = "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED";
/// The most bytes read from the end of what `eslogger` or the scripts printed.
const SAID_TAIL: u64 = 4096;

/// The states of the level, as `event_level.state` serves them.
pub const NOT_INSTALLED: &str = "not_installed";
pub const RUNNING: &str = "running";
pub const REFUSED: &str = "refused";
pub const FAILING: &str = "failing";
pub const SILENT: &str = "silent";
pub const FAILED: &str = "failed";

/// What this level cannot see, in its own words.
pub const CANNOT_SEE: [&str; 6] = [
    "connections: eslogger gives no network event",
    "file writes: only program starts are collected",
    "program starts while the level is not running",
    "program starts the kernel dropped: counted, not seen",
    "program starts deleted to keep the log under its size cap before they were read: counted, not seen",
    "a program's environment: it is never written",
];

/// Created at the first reading, in its transaction.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS event_level (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    read_at   INTEGER NOT NULL,  -- the latest reading, UTC seconds
    state     TEXT NOT NULL,     -- not_installed, running, refused, failing, silent, failed
    written   INTEGER,           -- when the log was last written to, UTC seconds
    said_by   TEXT,              -- eslogger or scripts, when refused or failing
    said      TEXT,              -- the last line it printed, text from a source
    reason    TEXT,              -- why the reading failed
    last_seq  INTEGER,           -- seq_num of the latest exec read, NULL before any
    version   INTEGER,           -- the message version of the latest exec read
    counted   INTEGER            -- notes of deletions up to this time are counted
);
-- Where each log file was read up to: every byte before `offset` is whole lines already read.
CREATE TABLE IF NOT EXISTS event_file (
    name   TEXT PRIMARY KEY,
    inode  INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
-- What one reading of a log read, kept for two days.
CREATE TABLE IF NOT EXISTS event_count (
    at           INTEGER NOT NULL,
    starts       INTEGER NOT NULL,  -- program starts read
    lost         INTEGER NOT NULL,  -- program starts missing from the numbering
    unknown_gaps INTEGER NOT NULL,  -- times the numbering started again: losses of unknown size
    unreadable   INTEGER NOT NULL,  -- lines that could not be read
    other        INTEGER NOT NULL,  -- messages of another kind than exec
    removed_cap  INTEGER NOT NULL,  -- log files deleted to stay under the size cap
    removed_unread INTEGER NOT NULL -- log files deleted before they were read to their end
);
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('program starts on this Mac, from Apple''s eslogger');
";

/// One program start, as rules over events will read it. Built from an `exec` message: the
/// new image is `event.exec.target`, and `process` is the image before the exec, which is the
/// parent program as coreSigma and pySigma's macOS pipeline take it.
#[derive(Debug, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))] // Rules over events read every field in stage 2.
pub struct ProcessStart {
    /// `@timestamp`: the message's `time`, as `eslogger` writes it, in UTC.
    pub timestamp: String,
    /// `process.executable`: `event.exec.target.executable.path`.
    pub executable: String,
    /// `process.args`: `event.exec.args`.
    pub args: Vec<String>,
    /// `process.parent.executable`: `process.executable.path`.
    pub parent_executable: Option<String>,
    /// `process.working_directory`: `event.exec.cwd.path`.
    pub working_directory: Option<String>,
    /// `process.pid`: the pid of `event.exec.target.audit_token`.
    pub pid: i64,
    /// `process.parent.pid`: `event.exec.target.ppid`.
    pub parent_pid: Option<i64>,
    /// `process.user.id`: the effective user id of the target's audit token.
    pub user_id: Option<i64>,
    /// `process.code_signature.signing_id`.
    pub signing_id: Option<String>,
    /// `process.code_signature.team_id`.
    pub team_id: Option<String>,
    /// Whether the program is part of macOS: `is_platform_binary`. ECS has no field for it.
    pub platform_binary: Option<bool>,
}

/// One line of the log, as read.
#[derive(Debug, PartialEq)]
pub enum Line {
    /// An `exec` message: its sequence number, its message version, and the start.
    Exec {
        seq: u64,
        version: Option<u64>,
        start: Box<ProcessStart>,
    },
    /// A message of another kind.
    Other,
    /// Not a JSON object.
    Unreadable,
}

/// Reads one line. `Err` says the format changed: a message without a field this reader
/// needs, or with a `schema_version` it does not know. That fails the reading.
pub fn line(bytes: &[u8]) -> Result<Line, String> {
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(Line::Unreadable);
    };
    let changed = |what: &str| {
        format!("a message without {what}: the format of eslogger or of its filter has changed")
    };
    let schema = m
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| changed("schema_version"))?;
    if !SCHEMA_VERSIONS.contains(&schema) {
        return Err(format!(
            "eslogger writes schema_version {schema}, which this version does not read"
        ));
    }
    let event = m
        .get("event")
        .and_then(Value::as_object)
        .ok_or_else(|| changed("an event"))?;
    if !event.contains_key("exec") {
        return Ok(Line::Other);
    }
    let seq = m
        .get("seq_num")
        .and_then(Value::as_u64)
        .ok_or_else(|| changed("seq_num"))?;
    let v = Value::Object(m);
    let start = start(&v).map_err(changed)?;
    Ok(Line::Exec {
        seq,
        version: v.get("version").and_then(Value::as_u64),
        start: Box::new(start),
    })
}

/// The program start an `exec` message describes, or the name of a field it needs and lacks.
fn start(v: &Value) -> Result<ProcessStart, &'static str> {
    const ARGS: &str = "event.exec.args";
    const TOKEN: &str = "event.exec.target.audit_token";
    let exec = v.pointer("/event/exec").ok_or("event.exec")?;
    let target = exec.get("target").ok_or("event.exec.target")?;
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    let token = token(target.get("audit_token").ok_or(TOKEN)?).ok_or(TOKEN)?;
    Ok(ProcessStart {
        timestamp: text(v.get("time")).ok_or("time")?,
        executable: text(target.pointer("/executable/path"))
            .ok_or("event.exec.target.executable.path")?,
        args: exec
            .get("args")
            .and_then(Value::as_array)
            .ok_or(ARGS)?
            .iter()
            .map(|a| a.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or(ARGS)?,
        parent_executable: text(v.pointer("/process/executable/path")),
        working_directory: text(exec.pointer("/cwd/path")),
        pid: token.0,
        parent_pid: target.get("ppid").and_then(Value::as_i64),
        user_id: token.1,
        signing_id: text(target.get("signing_id")),
        team_id: text(target.get("team_id")),
        platform_binary: target.get("is_platform_binary").and_then(Value::as_bool),
    })
}

/// The pid and effective user id of an audit token. `eslogger` writes it as an object with
/// named fields, and in some builds as the eight words of `audit_token_t`, in the order
/// OpenBSM's `audit_token_to_*` read them: auid, euid, egid, ruid, rgid, pid, asid,
/// pidversion. Mullvad's parser accepts both the same way.
fn token(v: &Value) -> Option<(i64, Option<i64>)> {
    match v {
        Value::Object(m) => Some((
            m.get("pid")?.as_i64()?,
            m.get("euid").and_then(Value::as_i64),
        )),
        Value::Array(words) if words.len() == 8 => Some((words[5].as_i64()?, words[1].as_i64())),
        _ => None,
    }
}

/// What a reading read.
#[derive(Debug, Default, PartialEq)]
pub struct Tally {
    pub starts: i64,
    pub lost: i64,
    pub unknown_gaps: i64,
    pub unreadable: i64,
    pub other: i64,
    pub removed_cap: i64,
    pub removed_unread: i64,
}

/// What a look at the source found.
#[derive(Debug)]
enum Found {
    NotInstalled,
    /// The source is there and could not be read; nothing is taken as read.
    Failed(String),
    Read(Log),
}

/// A log that was read: what it held, where each file was read up to, the last sequence
/// number, when it was last written, and the state the evidence gives.
#[derive(Debug)]
struct Log {
    tally: Tally,
    files: Vec<(String, u64, u64)>,
    last_seq: Option<u64>,
    version: Option<u64>,
    written: Option<i64>,
    state: &'static str,
    said: Option<(&'static str, String)>,
}

/// Where the last reading left off: each file's inode and offset, the last sequence number,
/// and up to when the root side's notes of deletions were counted.
#[derive(Default)]
struct Left {
    files: BTreeMap<String, (u64, u64)>,
    last_seq: Option<u64>,
    counted: Option<i64>,
}

/// Reads the log under `root` from where `left` says, at `now`.
fn look(root: &Path, left: &Left, now: i64) -> Found {
    let plist = root.join(PLIST);
    let installed_at = match std::fs::metadata(&plist) {
        Ok(m) => m.mtime(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Found::NotInstalled,
        Err(e) => return Found::Failed(format!("the event level's launch daemon: {e}")),
    };
    let dir = root.join(LOG);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => return Found::Failed(format!("the event level's log: {e}")),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        match entry {
            Ok(e) => {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with(PREFIX) && name.ends_with(SUFFIX) {
                    names.push(name);
                }
            }
            Err(e) => return Found::Failed(format!("the event level's log: {e}")),
        }
    }
    names.sort();
    let mut tally = Tally::default();
    if let Err(e) = removed(&dir, left, &mut tally) {
        return Found::Failed(format!("{REMOVED} in the event level's log: {e}"));
    }
    let mut last_seq = left.last_seq;
    let mut version = None;
    let mut files = Vec::new();
    let mut written: Option<i64> = None;
    let newest = names.last().cloned();
    for name in names {
        let path = dir.join(&name);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            // Deleted by the root side between the listing and now.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Found::Failed(format!("{name} in the event level's log: {e}")),
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => return Found::Failed(format!("{name} in the event level's log: {e}")),
        };
        written = written.max(Some(meta.mtime()));
        // The same file is read on from where it was left; another file of that name, or one
        // shorter than what was read, from its start.
        let from = match left.files.get(&name) {
            Some((inode, offset)) if *inode == meta.ino() && *offset <= meta.len() => *offset,
            _ => 0,
        };
        match read_from(file, from, &mut tally, &mut last_seq, &mut version) {
            // A file of an hour that is over is not written to again. rotatelogs moves to the
            // next hour's file at whatever it read from the pipe, so a line can end in the old
            // file without its newline and go on at the start of the new one: the end left
            // here is counted as a line that could not be read, once.
            Ok(to) if to < meta.len() && newest.as_ref() != Some(&name) => {
                tally.unreadable += 1;
                files.push((name, meta.ino(), meta.len()));
            }
            Ok(to) => files.push((name, meta.ino(), to)),
            Err(Stop::Io(e)) => {
                return Found::Failed(format!("{name} in the event level's log: {e}"));
            }
            Err(Stop::Schema(why)) => return Found::Failed(why),
        }
    }
    let (state, said) = judge(&dir, written.unwrap_or(installed_at), written, now);
    Found::Read(Log {
        tally,
        files,
        last_seq,
        version,
        written,
        state,
        said,
    })
}

/// Counts what the root side's notes say it deleted since the last reading: files deleted to
/// stay under the size cap, and files deleted before this reader read them to their end.
fn removed(dir: &Path, left: &Left, tally: &mut Tally) -> std::io::Result<()> {
    let text = match std::fs::read_to_string(dir.join(REMOVED)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for note in text.lines() {
        let words: Vec<&str> = note.split(' ').collect();
        let [when, name, bytes, why] = words[..] else {
            continue;
        };
        let (Ok(when), Ok(bytes)) = (when.parse::<i64>(), bytes.parse::<u64>()) else {
            continue;
        };
        if left.counted.is_some_and(|at| when <= at) {
            continue;
        }
        if why == "cap" {
            tally.removed_cap += 1;
        }
        if left
            .files
            .get(name)
            .is_none_or(|(_, offset)| *offset < bytes)
        {
            tally.removed_unread += 1;
        }
    }
    Ok(())
}

enum Stop {
    Io(std::io::Error),
    Schema(String),
}

/// Reads the whole lines of `file` from `from` on into the tally and returns the offset after
/// the last whole line.
fn read_from(
    mut file: std::fs::File,
    from: u64,
    tally: &mut Tally,
    last_seq: &mut Option<u64>,
    version: &mut Option<u64>,
) -> Result<u64, Stop> {
    file.seek(SeekFrom::Start(from)).map_err(Stop::Io)?;
    let mut lines = BufReader::new(file);
    let mut at = from;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = lines.read_until(b'\n', &mut buf).map_err(Stop::Io)?;
        // The end, or a line still being written: left for the next reading.
        if n == 0 || buf.last() != Some(&b'\n') {
            return Ok(at);
        }
        at += n as u64;
        match line(&buf[..n - 1]).map_err(Stop::Schema)? {
            Line::Exec {
                seq, version: v, ..
            } => {
                count_seq(seq, last_seq, tally);
                tally.starts += 1;
                *version = v.or(*version);
            }
            Line::Other => tally.other += 1,
            Line::Unreadable => tally.unreadable += 1,
        }
    }
}

/// Counts what the sequence number says was lost since the last one.
fn count_seq(seq: u64, last: &mut Option<u64>, tally: &mut Tally) {
    if let Some(l) = *last {
        if seq > l + 1 {
            tally.lost += (seq - l - 1) as i64;
        } else if seq <= l {
            tally.unknown_gaps += 1;
        }
    }
    *last = Some(seq);
}

/// The state the root side's own evidence gives: refused or failing when `eslogger` or the
/// scripts printed something after the log was last written to, silent when nothing has been
/// written for `SILENT_AFTER` since `quiet_since` (the last write, or the install), else
/// running.
fn judge(
    dir: &Path,
    quiet_since: i64,
    written: Option<i64>,
    now: i64,
) -> (&'static str, Option<(&'static str, String)>) {
    for (by, name) in [("eslogger", ESLOGGER_SAID), ("scripts", SCRIPTS_SAID)] {
        let path = dir.join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() == 0 || written.is_some_and(|w| meta.mtime() <= w) {
            continue;
        }
        let tail = tail(&path).unwrap_or_default();
        let last = tail
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_default()
            .trim()
            .to_string();
        let state = if by == "eslogger" && tail.contains(NOT_PERMITTED) {
            REFUSED
        } else {
            FAILING
        };
        return (state, Some((by, last)));
    }
    if now - quiet_since > SILENT_AFTER {
        (SILENT, None)
    } else {
        (RUNNING, None)
    }
}

/// The last `SAID_TAIL` bytes of a file, as text.
fn tail(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(SAID_TAIL)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// What a reading came to, for the caller: the state, and the reason when it failed.
pub struct Outcome {
    pub state: &'static str,
    pub failed: Option<String>,
}

/// One reading of the event level under `root`, at `now`, recorded in `tx`: the state, the
/// counts, where each file was read up to, and coverage of this machine, one row in place of
/// the one before, as samples keep theirs.
pub fn read(
    tx: &Transaction,
    run_id: &str,
    machine: &str,
    root: &Path,
    now: i64,
) -> rusqlite::Result<Outcome> {
    tx.execute_batch(SCHEMA)?;
    let left = left(tx)?;
    let found = look(root, &left, now);
    let state = match &found {
        Found::NotInstalled => NOT_INSTALLED,
        Found::Failed(_) => FAILED,
        Found::Read(log) => log.state,
    };
    match &found {
        // Nothing to continue: an install after this starts its numbering anew.
        Found::NotInstalled => {
            put_level(tx, now, state, None, (None, None), (None, None, None))?;
        }
        // Nothing is taken as read.
        Found::Failed(why) => {
            tx.execute(
                "INSERT INTO event_level (id, read_at, state, reason) VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT (id) DO UPDATE SET read_at = excluded.read_at,
                     state = excluded.state, said_by = NULL, said = NULL,
                     reason = excluded.reason",
                params![now, state, why],
            )?;
        }
        Found::Read(log) => {
            tx.execute("DELETE FROM event_file", [])?;
            for (name, inode, offset) in &log.files {
                tx.execute(
                    "INSERT INTO event_file (name, inode, offset) VALUES (?1, ?2, ?3)",
                    params![name, *inode as i64, *offset as i64],
                )?;
            }
            let t = &log.tally;
            tx.execute(
                "INSERT INTO event_count (at, starts, lost, unknown_gaps, unreadable, other,
                                          removed_cap, removed_unread)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    now,
                    t.starts,
                    t.lost,
                    t.unknown_gaps,
                    t.unreadable,
                    t.other,
                    t.removed_cap,
                    t.removed_unread
                ],
            )?;
            let (by, said) = match &log.said {
                Some((by, said)) => (Some(*by), Some(said.as_str())),
                None => (None, None),
            };
            put_level(
                tx,
                now,
                state,
                log.written,
                (by, said),
                (
                    log.last_seq.map(|s| s as i64),
                    log.version.map(|v| v as i64),
                    Some(now),
                ),
            )?;
        }
    }
    tx.execute("DELETE FROM event_count WHERE at < ?1", [now - KEEP])?;
    let (completeness, reason, cause): (&str, Option<String>, Option<Cause>) = match &found {
        Found::NotInstalled => (
            "none",
            Some("the event level is not installed".to_string()),
            Some(Cause::NotGiven),
        ),
        Found::Failed(why) => ("none", Some(why.clone()), Some(Cause::Failed)),
        Found::Read(log) => covered(log.state, &tally_since(tx, now - DAY)?),
    };
    tx.execute(
        "DELETE FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
        params![READER, machine, KIND],
    )?;
    let reading = Reading {
        reader: READER,
        scope: machine,
        kind: KIND,
        run_id,
        at: now,
        observed_at: now,
    };
    crate::store::put_coverage(
        tx,
        &reading,
        completeness,
        reason.as_deref(),
        &Gap::when(cause),
    )?;
    Ok(Outcome {
        state,
        failed: match found {
            Found::Failed(why) => Some(why),
            _ => None,
        },
    })
}

/// The coverage of a log that was read. Running, it is full unless something was lost,
/// could not be read or was deleted early over the last day `t`, the span the log keeps,
/// which makes it partial with the counts; refused, failing or silent, no program start is
/// being recorded, and the state says why.
fn covered(state: &str, t: &Tally) -> (&'static str, Option<String>, Option<Cause>) {
    match state {
        RUNNING => {
            let mut said = Vec::new();
            if t.lost > 0 {
                said.push(format!("program starts missing from the numbering: {}", t.lost));
            }
            if t.unknown_gaps > 0 {
                said.push(format!(
                    "times eslogger started again, each a loss of unknown size: {}",
                    t.unknown_gaps
                ));
            }
            if t.unreadable > 0 {
                said.push(format!("lines that could not be read: {}", t.unreadable));
            }
            if t.removed_cap > 0 {
                said.push(format!(
                    "log files deleted to stay under the size cap before their day was over: {}",
                    t.removed_cap
                ));
            }
            if t.removed_unread > 0 {
                said.push(format!(
                    "log files deleted before this reader read them to their end: {}",
                    t.removed_unread
                ));
            }
            if said.is_empty() {
                ("full", None, None)
            } else {
                // Lines this reader could not read are its failure; what never reached the
                // log is not in the source.
                let cause = if t.unreadable > 0 {
                    Cause::Failed
                } else {
                    Cause::NotGiven
                };
                (
                    "partial",
                    Some(format!("over the last day, {}", said.join("; "))),
                    Some(cause),
                )
            }
        }
        REFUSED => (
            "none",
            Some("macOS refuses eslogger Full Disk Access, so no program start is recorded".into()),
            Some(Cause::NotGiven),
        ),
        FAILING => (
            "none",
            Some("the event level printed an error after its last line, so no program start is recorded".into()),
            Some(Cause::NotGiven),
        ),
        _ => (
            "none",
            Some(format!(
                "nothing has been written to the event level's log for more than {} minutes",
                SILENT_AFTER / 60
            )),
            Some(Cause::NotGiven),
        ),
    }
}

/// The level's row: the state, when the log was last written to, who said what, the last
/// sequence number and message version read, and up to when notes of deletions are counted.
fn put_level(
    tx: &Transaction,
    now: i64,
    state: &str,
    written: Option<i64>,
    (said_by, said): (Option<&str>, Option<&str>),
    (last_seq, version, counted): (Option<i64>, Option<i64>, Option<i64>),
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO event_level (id, read_at, state, written, said_by, said, reason, last_seq,
                                  version, counted)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)
         ON CONFLICT (id) DO UPDATE SET read_at = excluded.read_at, state = excluded.state,
             written = excluded.written, said_by = excluded.said_by, said = excluded.said,
             reason = NULL, last_seq = excluded.last_seq,
             version = COALESCE(excluded.version, version), counted = excluded.counted",
        params![
            now, state, written, said_by, said, last_seq, version, counted
        ],
    )?;
    Ok(())
}

/// Where the last reading left off.
fn left(tx: &Transaction) -> rusqlite::Result<Left> {
    let files = tx
        .prepare("SELECT name, inode, offset FROM event_file")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let row: Option<(Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT last_seq, counted FROM event_level WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(Left {
        files,
        last_seq: row.and_then(|r| r.0).map(|s| s as u64),
        counted: row.and_then(|r| r.1),
    })
}

/// The level as the latest reading left it, with its counts since the latest full check
/// and over the last day.
pub struct Level {
    pub state: String,
    pub read_at: i64,
    pub written: Option<i64>,
    pub said_by: Option<String>,
    pub said: Option<String>,
    pub reason: Option<String>,
    /// The message version of the latest program start read.
    pub version: Option<i64>,
    pub since_check: Tally,
    pub last_day: Tally,
}

/// The level, or `None` before any reading of it.
pub fn level(conn: &Connection, now: i64) -> rusqlite::Result<Option<Level>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'event_level')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let row = conn
        .query_row(
            "SELECT state, read_at, written, said_by, said, reason, version
             FROM event_level WHERE id = 1",
            [],
            |r| {
                Ok((
                    (r.get::<_, String>(0)?, r.get::<_, i64>(1)?),
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(((state, read_at), written, said_by, said, reason, version)) = row else {
        return Ok(None);
    };
    // The latest full check's own reading counts as since it.
    let check = crate::status::latest_finished(conn)?.map_or(0, |r| r.started_at);
    Ok(Some(Level {
        state,
        read_at,
        written,
        said_by,
        said,
        reason,
        version,
        since_check: tally_since(conn, check)?,
        last_day: tally_since(conn, now - DAY)?,
    }))
}

/// The counts of every reading at or after `from`.
fn tally_since(conn: &Connection, from: i64) -> rusqlite::Result<Tally> {
    conn.query_row(
        "SELECT COALESCE(SUM(starts), 0), COALESCE(SUM(lost), 0),
                COALESCE(SUM(unknown_gaps), 0), COALESCE(SUM(unreadable), 0),
                COALESCE(SUM(other), 0), COALESCE(SUM(removed_cap), 0),
                COALESCE(SUM(removed_unread), 0)
         FROM event_count WHERE at >= ?1",
        [from],
        |r| {
            Ok(Tally {
                starts: r.get(0)?,
                lost: r.get(1)?,
                unknown_gaps: r.get(2)?,
                unreadable: r.get(3)?,
                other: r.get(4)?,
                removed_cap: r.get(5)?,
                removed_unread: r.get(6)?,
            })
        },
    )
}

/// `event_level` in `soc status --json`. What `eslogger` or the scripts printed, and why a
/// reading failed, are text from a source, each in its own field.
pub fn json(l: &Level) -> Value {
    let iso = |t: Option<i64>| t.map(crate::view::iso);
    let pair = |f: fn(&Tally) -> i64| json!({ "since_check": f(&l.since_check), "last_day": f(&l.last_day) });
    json!({
        "state": l.state,
        "level": LEVEL,
        "read_at": crate::view::iso(l.read_at),
        "written_at": iso(l.written),
        "program_starts": pair(|t| t.starts),
        "lost": pair(|t| t.lost),
        "unknown_losses": pair(|t| t.unknown_gaps),
        "unreadable_lines": pair(|t| t.unreadable),
        "other_messages": pair(|t| t.other),
        "files_removed_by_cap": pair(|t| t.removed_cap),
        "files_removed_unread": pair(|t| t.removed_unread),
        "message_version": l.version,
        "said_by": l.said_by,
        "said_text": l.said.as_deref().map(crate::status::text),
        "reason_text": l.reason.as_deref().map(crate::status::text),
        "silent_after_seconds": SILENT_AFTER,
        "cannot_see": CANNOT_SEE,
    })
}

/// The level in words, for a person: the line `soc status` prints and the page's row.
pub fn words(l: &Level) -> String {
    let counted = crate::view::counted;
    match l.state.as_str() {
        RUNNING => {
            let d = &l.last_day;
            let mut said = format!(
                "on: {} read in the last day",
                counted(d.starts, "program start", "program starts")
            );
            if d.lost > 0 {
                said.push_str(&format!(", {} lost", counted(d.lost, "", "").trim_end()));
            }
            if d.unknown_gaps > 0 {
                said.push_str(&format!(
                    ", and an unknown number lost when eslogger started again {}",
                    counted(d.unknown_gaps, "time", "times")
                ));
            }
            if d.unreadable > 0 {
                said.push_str(&format!(
                    ", {} could not be read",
                    counted(d.unreadable, "line", "lines")
                ));
            }
            if d.removed_cap > 0 {
                said.push_str(&format!(
                    "; the size cap deleted {} before its day was over",
                    counted(d.removed_cap, "hour of the log", "hours of the log")
                ));
            }
            if d.removed_unread > 0 {
                said.push_str(&format!(
                    "; {} deleted before they were read, to keep the log small",
                    counted(
                        d.removed_unread,
                        "hour of the log was",
                        "hours of the log were"
                    )
                ));
            }
            said
        }
        NOT_INSTALLED => "not installed, so program starts are not seen".to_string(),
        REFUSED => {
            "installed, but macOS refuses eslogger Full Disk Access, so program starts are not seen"
                .to_string()
        }
        FAILING => "installed, but it printed an error, so program starts are not seen".to_string(),
        SILENT => format!(
            "installed, but nothing has been written {}, so program starts are not seen",
            l.written
                .map_or("since it was installed".to_string(), |t| format!(
                    "since {}",
                    crate::view::utc(t)
                ))
        ),
        _ => "its log could not be read, so program starts are not seen".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `exec` message as the filter writes it from eslogger's message version 10, with
    /// invented content.
    fn exec(seq: u64, token: &str) -> String {
        format!(
            r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/zsh"}}}},"event":{{"exec":{{"args":["git","status","--short"],"cwd":{{"path":"/Users/example/dev/site"}},"target":{{"executable":{{"path":"/usr/bin/git"}},"audit_token":{token},"ppid":401,"signing_id":"com.apple.git","team_id":null,"is_platform_binary":true}}}}}}}}"#
        )
    }

    const OBJECT: &str = r#"{"pid":402,"euid":501}"#;
    const LIST: &str = "[501,501,20,501,20,402,100001,9002]";

    #[test]
    fn an_audit_token_is_read_as_an_object_and_as_the_eight_words_of_audit_token_t() {
        // Between builds eslogger has written the same field in both forms; reading one alone
        // would fail every reading on a Mac that writes the other.
        for token in [OBJECT, LIST] {
            let Ok(Line::Exec {
                seq: 7,
                version: Some(10),
                start: s,
            }) = line(exec(7, token).as_bytes())
            else {
                panic!("{token}");
            };
            assert_eq!(s.pid, 402);
            assert_eq!(s.user_id, Some(501));
            assert_eq!(s.parent_pid, Some(401));
            assert_eq!(s.executable, "/usr/bin/git");
            assert_eq!(s.args, ["git", "status", "--short"]);
            assert_eq!(s.parent_executable.as_deref(), Some("/bin/zsh"));
            assert_eq!(
                s.working_directory.as_deref(),
                Some("/Users/example/dev/site")
            );
            assert_eq!(s.signing_id.as_deref(), Some("com.apple.git"));
            assert_eq!(s.team_id, None);
            assert_eq!(s.platform_binary, Some(true));
            assert_eq!(s.timestamp, "2026-10-04T00:00:02.000002Z");
        }
        // A list of another length is not a token: the format changed.
        let short = exec(7, "[501,501,20,501,20,402,100001]");
        let said = line(short.as_bytes()).unwrap_err();
        assert!(said.contains("event.exec.target.audit_token"), "{said}");
    }

    #[test]
    fn an_unknown_schema_version_fails_the_reading_with_its_reason() {
        // Apple says new events may come without a new schema_version; a new one means the
        // format changed in a way this reader cannot vouch for.
        let two = exec(1, OBJECT).replace(r#""schema_version":1"#, r#""schema_version":2"#);
        let said = line(two.as_bytes()).unwrap_err();
        assert!(said.contains("schema_version 2"), "{said}");
    }

    #[test]
    fn a_missing_field_is_a_change_of_format_never_a_default_and_a_new_version_alone_is_not() {
        // A field read as missing would count starts with nothing in them as seen.
        for (field, without) in [
            ("seq_num", exec(1, OBJECT).replace(r#""seq_num":1,"#, "")),
            (
                "event.exec.args",
                exec(1, OBJECT).replace(r#"["git","status","--short"]"#, "null"),
            ),
            (
                "time",
                exec(1, OBJECT).replace(r#""time":"2026-10-04T00:00:02.000002Z","#, ""),
            ),
            (
                "event.exec.target.executable.path",
                exec(1, OBJECT).replace(r#"{"path":"/usr/bin/git"}"#, r#"{"path":null}"#),
            ),
            (
                "schema_version",
                exec(1, OBJECT).replace(r#""schema_version":1,"#, ""),
            ),
            (
                "an event",
                r#"{"schema_version":1,"seq_num":3}"#.to_string(),
            ),
        ] {
            let said = line(without.as_bytes()).unwrap_err();
            assert!(said.contains(field), "{field}: {said}");
        }
        // macOS raises the message version as it adds fields; what is read is still there.
        let eleven = exec(1, OBJECT).replace(r#""version":10"#, r#""version":11"#);
        assert!(matches!(
            line(eleven.as_bytes()),
            Ok(Line::Exec {
                version: Some(11),
                ..
            })
        ));
        // Half a line, split between two files, is counted and skipped; so is any JSON that is
        // not a message. A message of another kind is ignored.
        assert_eq!(line(b"{\"schema_version\":1,"), Ok(Line::Unreadable));
        assert_eq!(line(b"[1,2]"), Ok(Line::Unreadable));
        let fork = r#"{"schema_version":1,"version":10,"seq_num":1,"event":{"fork":{}}}"#;
        assert_eq!(line(fork.as_bytes()), Ok(Line::Other));
    }

    #[test]
    fn counts_older_than_two_days_are_deleted_so_the_store_does_not_grow_with_the_readings() {
        // The watcher reads at every sample for as long as the Mac runs.
        let dir = std::env::temp_dir().join(format!("soc-events-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root").join(LOG)).unwrap();
        let plist = dir.join("root").join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        let now = 1_791_000_000;
        let read = |conn: &mut rusqlite::Connection, at: i64| {
            let tx = conn.transaction().unwrap();
            crate::store::put_entity(&tx, "machine:mac").unwrap();
            read(&tx, "events-1", "machine:mac", &dir.join("root"), at).unwrap();
            tx.commit().unwrap();
        };
        read(&mut conn, now - KEEP - 1);
        read(&mut conn, now - KEEP + 1);
        read(&mut conn, now);
        let kept: Vec<i64> = conn
            .prepare("SELECT at FROM event_count ORDER BY at")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(kept, [now - KEEP + 1, now]);
    }

    #[test]
    fn a_busy_mac_is_read_many_times_faster_than_it_starts_programs() {
        // The watcher reads at every sample, every thirty seconds, and a full run reads what
        // accumulated since the last one, under the lock. 100,000 projected lines are about 17
        // minutes at 100 starts a second; at the bound, 5,000 lines a second, the thirty
        // seconds a sample adds at that pace are read in under a second. Measured, and printed with `--nocapture`; the bound is loose, so
        // that a Mac busy with other builds does not fail it, and catches a reader that
        // became quadratic or reads a line twice.
        let dir = std::env::temp_dir().join(format!("soc-events-speed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(LOG)).unwrap();
        let plist = dir.join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let n: u64 = 100_000;
        let mut text = String::new();
        for seq in 1..=n {
            text.push_str(&exec(seq, OBJECT));
            text.push('\n');
        }
        std::fs::write(dir.join(LOG).join("exec-20261004T00.jsonl"), &text).unwrap();
        let t = std::time::Instant::now();
        let found = look(&dir, &Left::default(), 1_791_000_000);
        let took = t.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        let Found::Read(log) = found else {
            panic!("{found:?}");
        };
        assert_eq!((log.tally.starts, log.tally.lost), (n as i64, 0));
        let rate = n as f64 / took.as_secs_f64();
        println!(
            "read {n} lines of {} bytes each in {took:?}: {rate:.0} lines a second",
            text.len() as u64 / n
        );
        assert!(rate > 5_000.0, "{rate:.0} lines a second");
    }

    #[test]
    fn a_gap_in_the_numbering_is_counted_and_a_restart_is_a_loss_of_unknown_size() {
        let mut t = Tally::default();
        let mut last = None;
        for seq in [1, 2, 5, 6, 1, 2] {
            count_seq(seq, &mut last, &mut t);
        }
        assert_eq!((t.lost, t.unknown_gaps), (2, 1));
        // The first number ever read says nothing about what came before.
        let (mut t, mut last) = (Tally::default(), None);
        count_seq(40, &mut last, &mut t);
        assert_eq!((t.lost, t.unknown_gaps, last), (0, 0, Some(40)));
    }
}
