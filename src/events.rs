//! The event level: every program start, and every file created or renamed, on this Mac, as
//! Apple's `eslogger` records them. This is the level of access "Apple's `eslogger` as
//! administrator" in `docs/how-it-works.md`. The collecting side runs as root and is data in
//! `scripts/event-level/`: launchd runs `/usr/bin/eslogger exec create rename` into a FIFO,
//! Apple's `jq` keeps of each message only what this reader uses, under `eslogger`'s own
//! names, and Apple's `rotatelogs` appends that to one file per hour in a folder only root and
//! the installing account can read; the root side deletes files older than a day, and the
//! oldest while the log is over its size cap, and notes each deletion in `removed`. This
//! reader runs as the owner, without rights, on the collection path: no model and no network.
//! It reads the log honestly and counts, and evaluates every program start and file event it
//! reads against SigmaHQ's published rules for macOS (`src/sigma.rs`), loaded once per
//! process. The store keeps no event: only where each log file was read up to, the last
//! sequence numbers, counts per reading, the state, coverage, how many starts or file events
//! matched each rule, and for a rule that raises a finding the latest few it matched, as the
//! finding's evidence.
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
//! a line `rotatelogs` split between two files, is counted and skipped. A message of a kind
//! other than `exec`, `create` and `rename` is counted and ignored. A message without a field this reader needs, or
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
//! version 2, `global_seq_num` from 4. `global_seq_num` runs across every subscribed type, so
//! only `seq_num` counts lost program starts apart from lost file events. The numbers belong
//! to one run of `eslogger`: a number at or below the last one means it started again, and
//! what was lost across that is a gap of unknown size, counted as such and never as zero.
//! A gap also takes in starts that were deleted before any reading saw them, which the notes
//! of deletions count apart.
//!
//! The typed event names its fields after the Elastic Common Schema where it has one, as the
//! samples do.
//!
//! Every match of every rule evaluated is counted per rule, by the hour of the reading, for a
//! week. A match of a rule marked high or critical is also a finding: one per rule on this Mac, not one per
//! start, as SIEMs group alerts by rule. A start is matched where it is read, inside the
//! reading's transaction, so a reading that fails or is rolled back has matched nothing and a
//! start read again after it is matched once.
//!
//! File events. The same collector subscribes to `create` and `rename` as well, and its filter
//! writes each as one line in the same hourly files, `exec-…` though they hold more than
//! `exec` now: the name stays, so the files an older collector wrote are read and deleted as
//! before and nothing else changes. A file event is the file's path, a rename's source too,
//! and the program that did it; it is asked only of the rules for file events, a program start
//! only of the rules for program starts. A file event the filter could not make out is a line
//! of its kind with nothing in it, and a file event this reader cannot make out is the same:
//! counted as an unreadable file event, never a failed reading, since the reading goes on
//! serving program starts. Its losses are counted from `seq_num` per event type, as for
//! program starts.
//!
//! No false calm about files. A collector installed before this version records program
//! starts only, and its log never holds a file event, which reads the same as a Mac where no
//! file was created. So file events count as collected only when the installer's record of
//! what the collector records, `collects`, is there, names `create` and `rename`, and is not
//! older than the collector's launch daemon: an install that replaces the daemon without
//! writing it again leaves a record that says nothing. Until then the rules for file events
//! are said by name not to watch, with why, and coverage of file events is none.

use crate::sigma::{Meta, Rules, Subject};
use crate::store::{Cause, Gap, Reading};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The reader's name in coverage.
pub const READER: &str = "events";
/// The coverage kind of a reading.
pub const KIND: &str = "program starts on this Mac, from Apple's eslogger";
/// The coverage kind of a reading's file events, written while the level runs.
pub const KIND_FILES: &str = "file events on this Mac, from Apple's eslogger";
/// The installer's record of what the collector records: the eslogger arguments of the
/// installed launch daemon, as Apple's `plutil` extracts them, a JSON array of strings.
pub const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
/// The file events collected, as `eslogger` names them.
pub const FILE_KINDS: [&str; 2] = ["create", "rename"];
/// Why file events are not counted as collected, in the program's words.
pub const STARTS_ONLY: &str = "the collector installed here records program starts only; installing the event level again adds files created and renamed";
pub const REPLACED: &str = "the collector's launch daemon was replaced after the record of what it collects was written, so file events are not counted as collected; installing the event level again settles it";
/// The level of access the events come from.
pub const LEVEL: &str = "Apple's eslogger as administrator";
/// How the run id of a watcher's reading begins.
pub const RUN_PREFIX: &str = "events-";
/// The launch daemon's property list, under the system root: there when the level is installed.
pub const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
/// The log folder, under the system root.
pub const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
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
/// How long counts of matches per rule are kept: a week of every match, enough to see which
/// rules match routine work before they are promoted or tuned. A row is a rule's id, an hour and a
/// number, so a week is at most 168 rows per rule.
const KEEP_MATCHES: i64 = 7 * DAY;
/// Counts of matches are kept by the hour of the reading, so the last day is served by the
/// hour: the hour that holds its start is counted whole.
const HOUR: i64 = 60 * 60;
/// The most program starts a finding from a published rule keeps as its evidence, the latest.
pub const EVIDENCE: usize = 5;
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

/// What this level cannot see, in its own words; `cannot_see` adds what this Mac's collector
/// does not record.
pub const CANNOT_SEE: [&str; 6] = [
    "connections: eslogger gives no network event",
    "changes to files that already exist, and files removed: only files created and renamed are collected",
    "program starts and file events while the level is not running",
    "program starts and file events the kernel dropped: counted, not seen",
    "program starts and file events deleted to keep the log under its size cap before they were read: counted, not seen",
    "a program's environment: it is never written",
];
/// What it cannot see while the collector installed here does not record file events.
pub const FILES_NOT_SEEN: &str =
    "files created and renamed: the collector installed here does not record them";

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
    other        INTEGER NOT NULL,  -- messages of a kind this reader does not read
    removed_cap  INTEGER NOT NULL,  -- log files deleted to stay under the size cap
    removed_unread INTEGER NOT NULL -- log files deleted before they were read to their end
);
-- How many program starts matched each published rule, by the hour of the reading that read
-- them, kept a week. A rule's id and a number: nothing of the start.
CREATE TABLE IF NOT EXISTS rule_match (
    hour    INTEGER NOT NULL,  -- the reading's time, UTC seconds divided by 3600
    rule    TEXT NOT NULL,     -- the rule's id
    matches INTEGER NOT NULL,
    PRIMARY KEY (hour, rule)
);
-- How many program starts a finding from a published rule counts since it was raised.
CREATE TABLE IF NOT EXISTS rule_finding (
    finding TEXT PRIMARY KEY REFERENCES finding (id),
    matches INTEGER NOT NULL
);
-- The latest program starts a finding from a published rule rests on, at most five per
-- finding. The one place arguments enter the store; the environment never does. Field
-- names are the Elastic Common Schema's.
CREATE TABLE IF NOT EXISTS rule_evidence (
    finding           TEXT NOT NULL REFERENCES finding (id),
    read_at           INTEGER NOT NULL,
    timestamp         TEXT NOT NULL,
    executable        TEXT NOT NULL,
    args              TEXT NOT NULL,  -- a JSON array of strings
    parent_executable TEXT,
    working_directory TEXT,
    pid               INTEGER NOT NULL,
    parent_pid        INTEGER,
    user_id           INTEGER,
    signing_id        TEXT,
    team_id           TEXT,
    platform_binary   INTEGER
);
-- File events: whether the collector installed here is established to record them, why not,
-- and the latest sequence number of each kind read, NULL before any.
CREATE TABLE IF NOT EXISTS event_files (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    collected   INTEGER NOT NULL,
    why         TEXT,              -- why they are not counted as collected, the program's words
    last_create INTEGER,
    last_rename INTEGER
);
-- What one reading read of file events, kept for two days beside event_count.
CREATE TABLE IF NOT EXISTS event_file_count (
    at           INTEGER NOT NULL,
    files        INTEGER NOT NULL,  -- file events read
    lost         INTEGER NOT NULL,  -- file events missing from the numbering
    unknown_gaps INTEGER NOT NULL,  -- times their numbering started again
    unreadable   INTEGER NOT NULL   -- file events that could not be made out
);
-- The latest file events a finding from a published rule rests on, at most five per finding:
-- the file and the program, nothing more.
CREATE TABLE IF NOT EXISTS rule_file_evidence (
    finding    TEXT NOT NULL REFERENCES finding (id),
    read_at    INTEGER NOT NULL,
    timestamp  TEXT NOT NULL,
    action     TEXT NOT NULL,  -- create or rename
    path       TEXT NOT NULL,  -- the file created, or a rename's destination
    source     TEXT,           -- a rename's source
    executable TEXT NOT NULL   -- the program that did it
);
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('program starts on this Mac, from Apple''s eslogger'),
    ('file events on this Mac, from Apple''s eslogger');
";

/// One program start, as the published rules (`src/sigma.rs`) read it and as a finding's
/// evidence keeps it. Built from an `exec` message, whose `event.exec.target` is the program
/// started. Each field is named after the Elastic Common Schema; the rules read three of them
/// under Sigma's names, and `SIGMA_FIELDS` below is the one place that says which.
///
/// | eslogger, as the filter projects it | here | ECS | Sigma |
/// |---|---|---|---|
/// | `time` | `timestamp` | `@timestamp` | |
/// | `event.exec.target.executable.path` | `executable` | `process.executable` | `Image` |
/// | `event.exec.args` | `args` | `process.args` | `CommandLine`, joined by spaces |
/// | `process.executable.path` | `parent_executable` | `process.parent.executable` | `ParentImage` |
/// | `event.exec.cwd.path` | `working_directory` | `process.working_directory` | |
/// | the pid of `event.exec.target.audit_token` | `pid` | `process.pid` | |
/// | `event.exec.target.ppid` | `parent_pid` | `process.parent.pid` | |
/// | the euid of `event.exec.target.audit_token` | `user_id` | `process.user.id` | |
/// | `event.exec.target.signing_id`, `.team_id` | `signing_id`, `team_id` | `process.code_signature.*` | |
/// | `event.exec.target.is_platform_binary` | `platform_binary` | none | |
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessStart {
    pub timestamp: String,
    pub executable: String,
    pub args: Vec<String>,
    /// The program the process ran before this `exec`, not always its parent: see
    /// `SIGMA_FIELDS`.
    pub parent_executable: Option<String>,
    pub working_directory: Option<String>,
    pub pid: i64,
    pub parent_pid: Option<i64>,
    pub user_id: Option<i64>,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub platform_binary: Option<bool>,
}

/// How a Sigma field's value is taken from a program start; `None` leaves the field absent,
/// and an absent field matches nothing.
pub type Take = fn(&ProcessStart) -> Option<String>;

/// The Sigma fields a program start gives the published rules, and how each is taken. Sigma's
/// taxonomy names no macOS fields; these are the three of Windows' `process_creation` that
/// `eslogger` can fill, as `docs/event-level.md` maps them. A field a rule names that
/// is not here is one this level does not have, and `src/sigma.rs` names such rules.
pub const SIGMA_FIELDS: [(&str, Take); 3] = [
    ("Image", |s| Some(s.executable.clone())),
    // The arguments joined by single spaces, the first included: Sigma's command lines on
    // other systems hold the program too. An argument holding a space is not quoted, as
    // `eslogger` gives the arguments apart and no shell's quoting is the right one.
    ("CommandLine", |s| Some(s.args.join(" "))),
    // `process` in an `exec` message is the process that called `exec`, described as it was
    // before the call: the same pid as the program started, with its old image. After a fork
    // or `posix_spawn`, which is how a shell, a build tool or an agent starts a program, that
    // old image is a copy of the parent, so this is the parent's program. After an `exec`
    // without a fork it is not: a wrapper that replaces itself with the program (`nohup`,
    // `env`, `exec` in a shell script, `xcrun`) is named here, and whatever started the
    // wrapper is not, though `ppid` is its pid. coreSigma's collector takes the parent the same
    // way. So a rule on `ParentImage` can miss a start one wrapper away from the parent it
    // names, and never sees a parent this field does not name.
    ("ParentImage", |s| s.parent_executable.clone()),
];

/// One file created or renamed, as the published rules for file events read it and as a
/// finding's evidence keeps it: the file, and the program that did it.
///
/// | eslogger | the filter writes | here | ECS | Sigma |
/// |---|---|---|---|---|
/// | `time` | `time` | `timestamp` | `@timestamp` | |
/// | the event's name | `create` or `rename` | `action` | `event.action` | |
/// | `create.destination`: `existing_file.path`, or `new_path.dir.path` and `.filename` | `create.destination`, one path | `path` | `file.path` | `TargetFilename` |
/// | `rename.destination`, either form | `rename.destination` | `path` | `file.path` | `TargetFilename` |
/// | `rename.source.path` | `rename.source` | `source` | `file.Ext.original.path` | |
/// | `process.executable.path` | the same | `executable` | `process.executable` | `Image` |
///
/// For a rename, `TargetFilename` is where the file went: Sigma's own `file_rename` category
/// on Windows names the destination so and the source `SourceFilename`; ECS's `file.path` is
/// the destination in Elastic's rename events; pySigma's macOS pipeline for `eslogger` data
/// maps `file_event` to every file event, `TargetFilename` to `file.path`. Every shipped file
/// rule asks where a file appeared, which a rename into place is as much as a create.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileEvent {
    pub timestamp: String,
    /// `create` or `rename`, one of `FILE_KINDS`.
    pub action: &'static str,
    pub path: String,
    pub source: Option<String>,
    pub executable: String,
}

/// The folders at the top of every Mac that are links into `/private`. Endpoint Security
/// gives the path it resolved, `/private/tmp/x`, while a rule's author writes `/tmp/x`, as a
/// person and a shell do.
const LINKED: [&str; 3] = ["/private/etc/", "/private/tmp/", "/private/var/"];

impl FileEvent {
    /// The names a rule may know the file by: its path as Endpoint Security gives it, and,
    /// under one of macOS's links into `/private`, the same path through the link. A rule
    /// matches the event when it matches either: "Axios NPM Compromise File Creation
    /// Indicators" asks for `/tmp/6202033`, which Endpoint Security reports as
    /// `/private/tmp/6202033`, and "MacOS Emond Launch Daemon" asks for `/private/var/db/…`.
    pub fn names(&self) -> Vec<&str> {
        let mut names = vec![self.path.as_str()];
        if LINKED.iter().any(|l| self.path.starts_with(l)) {
            names.push(&self.path["/private".len()..]);
        }
        names
    }
}

/// How a Sigma field's value is taken from a file event under one of its names.
pub type FileTake = fn(&FileEvent, &str) -> Option<String>;

/// The Sigma fields a file event gives the rules for file events, and how each is taken; the
/// table above `FileEvent` says why.
pub const FILE_SIGMA_FIELDS: [(&str, FileTake); 2] = [
    ("TargetFilename", |_, name| Some(name.to_string())),
    ("Image", |f, _| Some(f.executable.clone())),
];

/// One line of the log, as read.
#[derive(Debug, PartialEq)]
pub enum Line {
    /// An `exec` message: its sequence number, its message version, and the start.
    Exec {
        seq: u64,
        version: Option<u64>,
        start: Box<ProcessStart>,
    },
    /// A file event: its kind by its place in `FILE_KINDS`, its sequence number when the line
    /// has one, and the event, or `None` when the filter or this reader could not make it out.
    File {
        kind: usize,
        seq: Option<u64>,
        event: Option<Box<FileEvent>>,
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
    // A file event without its number is not made out: what was lost around it could not be
    // counted.
    if let Some(kind) = FILE_KINDS.iter().position(|k| event.contains_key(*k)) {
        let seq = m.get("seq_num").and_then(Value::as_u64);
        return Ok(Line::File {
            kind,
            seq,
            event: seq
                .and_then(|_| file(&m, event, FILE_KINDS[kind]))
                .map(Box::new),
        });
    }
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

/// The file event a `create` or `rename` line describes, as the filter writes it, or `None`
/// when a part it needs is missing or is not an absolute path: the filter writes such a line
/// for an event whose shape it did not know.
fn file(
    m: &serde_json::Map<String, Value>,
    event: &serde_json::Map<String, Value>,
    action: &'static str,
) -> Option<FileEvent> {
    let e = event.get(action)?;
    let path = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .filter(|p| p.starts_with('/'))
            .map(str::to_string)
    };
    Some(FileEvent {
        timestamp: m.get("time")?.as_str()?.to_string(),
        action,
        path: path(e.get("destination"))?,
        source: match action {
            "rename" => Some(path(e.get("source"))?),
            _ => None,
        },
        executable: path(m.get("process").and_then(|p| p.pointer("/executable/path")))?,
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

impl Tally {
    /// Nothing the log held was lost, unreadable or deleted before it was read: every start
    /// it held was read, and so judged by the rules. The same test as full coverage.
    pub fn whole(&self) -> bool {
        self.gaps().is_empty()
    }

    /// What was lost, unreadable or deleted early, each with its count, in coverage's words.
    fn gaps(&self) -> Vec<String> {
        let mut said = Vec::new();
        if self.lost > 0 {
            said.push(format!(
                "program starts missing from the numbering: {}",
                self.lost
            ));
        }
        if self.unknown_gaps > 0 {
            said.push(format!(
                "times eslogger started again, each a loss of unknown size: {}",
                self.unknown_gaps
            ));
        }
        if self.unreadable > 0 {
            said.push(format!("lines that could not be read: {}", self.unreadable));
        }
        if self.removed_cap > 0 {
            said.push(format!(
                "log files deleted to stay under the size cap before their day was over: {}",
                self.removed_cap
            ));
        }
        if self.removed_unread > 0 {
            said.push(format!(
                "log files deleted before this reader read them to their end: {}",
                self.removed_unread
            ));
        }
        said
    }

    /// Nothing the log held was unreadable or deleted early, whatever its kind: what file
    /// events share with program starts.
    fn shared_whole(&self) -> bool {
        self.unreadable + self.removed_cap + self.removed_unread == 0
    }
}

/// What a reading read of file events. Lines that could not be read at all, and hours deleted,
/// are counted once in `Tally` and judge both kinds.
#[derive(Debug, Default, PartialEq)]
pub struct FileTally {
    pub files: i64,
    pub lost: i64,
    pub unknown_gaps: i64,
    pub unreadable: i64,
}

impl FileTally {
    /// What was lost or could not be made out of file events, each with its count, in
    /// coverage's words.
    fn gaps(&self) -> Vec<String> {
        let mut said = Vec::new();
        if self.lost > 0 {
            said.push(format!(
                "file events missing from the numbering: {}",
                self.lost
            ));
        }
        if self.unknown_gaps > 0 {
            said.push(format!(
                "times the numbering of file events started again, each a loss of unknown size: {}",
                self.unknown_gaps
            ));
        }
        if self.unreadable > 0 {
            said.push(format!(
                "file events that could not be made out: {}",
                self.unreadable
            ));
        }
        said
    }
}

/// What the published rules matched in a reading: per rule, how many events, and for a rule
/// that raises a finding the latest `EVIDENCE` of them. Nothing else of an event is kept, so a
/// lower rule's match leaves only its count.
#[derive(Debug, Default)]
pub struct Matched {
    pub rules: BTreeMap<&'static str, Hits>,
}

/// One rule's matches in a reading.
#[derive(Debug)]
pub struct Hits {
    pub meta: &'static Meta,
    pub count: i64,
    pub latest: VecDeque<Evidence>,
}

/// An event a finding rests on: a rule is about one kind, so its finding keeps one kind.
#[derive(Clone, Debug, PartialEq)]
pub enum Evidence {
    Start(ProcessStart),
    File(FileEvent),
}

impl Matched {
    /// Evaluates one event against the rules of its kind and counts what it matched.
    fn add(&mut self, rules: &'static Rules, subject: Subject) {
        for m in rules.evaluate(subject) {
            let hits = self.rules.entry(m.meta.id.as_str()).or_insert(Hits {
                meta: m.meta,
                count: 0,
                latest: VecDeque::new(),
            });
            hits.count += 1;
            if m.meta.level.raises() {
                if hits.latest.len() == EVIDENCE {
                    hits.latest.pop_front();
                }
                hits.latest.push_back(match subject {
                    Subject::Start(s) => Evidence::Start(s.clone()),
                    Subject::File(f) => Evidence::File(f.clone()),
                });
            }
        }
    }
}

/// What a look at the source found.
#[derive(Debug)]
enum Found {
    NotInstalled,
    /// The source is there and could not be read; nothing is taken as read.
    Failed(String),
    Read(Box<Log>),
}

/// A log that was read: what it held, where each file was read up to, the last sequence
/// number, when it was last written, and the state the evidence gives.
#[derive(Debug)]
struct Log {
    tally: Tally,
    file_tally: FileTally,
    matched: Matched,
    files: Vec<(String, u64, u64)>,
    last_seq: Option<u64>,
    file_seq: [Option<u64>; 2],
    version: Option<u64>,
    written: Option<i64>,
    state: &'static str,
    said: Option<(&'static str, String)>,
    /// Whether the collector installed here is established to record file events, or why not:
    /// not given, or a record that is there and could not be read.
    collects: Result<(), (Cause, String)>,
}

/// Where the last reading left off: each file's inode and offset, the last sequence number of
/// program starts and of each kind of file event, and up to when the root side's notes of
/// deletions were counted.
#[derive(Default)]
struct Left {
    files: BTreeMap<String, (u64, u64)>,
    last_seq: Option<u64>,
    file_seq: [Option<u64>; 2],
    counted: Option<i64>,
}

/// Reads the log under `root` from where `left` says, at `now`, and evaluates every program
/// start read against `rules`.
fn look(root: &Path, left: &Left, now: i64, rules: &'static Rules) -> Found {
    let plist = root.join(PLIST);
    let daemon = match std::fs::metadata(&plist) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Found::NotInstalled,
        Err(e) => return Found::Failed(format!("the event level's launch daemon: {e}")),
    };
    let installed_at = daemon.mtime();
    let collects = collects(root, &daemon);
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
    let mut file_tally = FileTally::default();
    let mut matched = Matched::default();
    if let Err(e) = removed(&dir, left, &mut tally) {
        return Found::Failed(format!("{REMOVED} in the event level's log: {e}"));
    }
    let mut last_seq = left.last_seq;
    let mut file_seq = left.file_seq;
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
        let mut into = Into {
            tally: &mut tally,
            file_tally: &mut file_tally,
            last_seq: &mut last_seq,
            file_seq: &mut file_seq,
            version: &mut version,
            rules,
            matched: &mut matched,
        };
        match read_from(file, from, &mut into) {
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
    Found::Read(Box::new(Log {
        tally,
        file_tally,
        matched,
        files,
        last_seq,
        file_seq,
        version,
        written,
        state,
        said,
        collects,
    }))
}

/// Whether the collector installed here is established to record file events: the installer's
/// record of what it collects names every kind in `FILE_KINDS` and was written no earlier than
/// the launch daemon now installed. Otherwise why not, in the program's words: not given, or a
/// record that is there and cannot be read, a failed reading with what failed.
fn collects(root: &Path, daemon: &std::fs::Metadata) -> Result<(), (Cause, String)> {
    let path = root.join(COLLECTS);
    let unread = |e: String| {
        (
            Cause::Failed,
            format!("what the collector records could not be read: {e}"),
        )
    };
    let not_given = |why: &str| (Cause::NotGiven, why.to_string());
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_given(STARTS_ONLY)),
        Err(e) => return Err(unread(e.to_string())),
    };
    if (meta.mtime(), meta.mtime_nsec()) < (daemon.mtime(), daemon.mtime_nsec()) {
        return Err(not_given(REPLACED));
    }
    let bytes = std::fs::read(&path).map_err(|e| unread(e.to_string()))?;
    let Ok(Value::Array(names)) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(unread("it is not a JSON list".into()));
    };
    if FILE_KINDS
        .iter()
        .all(|k| names.iter().any(|n| n.as_str() == Some(k)))
    {
        Ok(())
    } else {
        Err(not_given(STARTS_ONLY))
    }
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

/// Where a reading puts what it reads.
struct Into<'a> {
    tally: &'a mut Tally,
    file_tally: &'a mut FileTally,
    last_seq: &'a mut Option<u64>,
    file_seq: &'a mut [Option<u64>; 2],
    version: &'a mut Option<u64>,
    rules: &'static Rules,
    matched: &'a mut Matched,
}

/// Reads the whole lines of `file` from `from` on, counts them, evaluates each program start
/// against the rules, and returns the offset after the last whole line.
fn read_from(mut file: std::fs::File, from: u64, into: &mut Into) -> Result<u64, Stop> {
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
                seq,
                version: v,
                start,
            } => {
                let t = &mut *into.tally;
                count_seq(seq, into.last_seq, (&mut t.lost, &mut t.unknown_gaps));
                t.starts += 1;
                *into.version = v.or(*into.version);
                into.matched.add(into.rules, Subject::Start(&start));
            }
            Line::File { kind, seq, event } => {
                let t = &mut *into.file_tally;
                if let Some(seq) = seq {
                    let last = &mut into.file_seq[kind];
                    count_seq(seq, last, (&mut t.lost, &mut t.unknown_gaps));
                }
                match event {
                    Some(e) => {
                        t.files += 1;
                        into.matched.add(into.rules, Subject::File(&e));
                    }
                    None => t.unreadable += 1,
                }
            }
            Line::Other => into.tally.other += 1,
            Line::Unreadable => into.tally.unreadable += 1,
        }
    }
}

/// Counts what the sequence number says was lost since the last one of its kind: into `lost`
/// a gap, into `unknown` a number that fell back.
fn count_seq(seq: u64, last: &mut Option<u64>, (lost, unknown): (&mut i64, &mut i64)) {
    if let Some(l) = *last {
        if seq > l + 1 {
            *lost += (seq - l - 1) as i64;
        } else if seq <= l {
            *unknown += 1;
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

/// What a reading came to, for the caller: the state, the reason when it failed, how many
/// program starts it took, and how many findings the rules opened.
pub struct Outcome {
    pub state: &'static str,
    pub failed: Option<String>,
    pub starts: i64,
    pub opened: usize,
}

/// The level's state as the latest reading left it, without reading anything else; `None`
/// before any reading.
pub fn state(conn: &Connection) -> rusqlite::Result<Option<String>> {
    if !has(conn, "event_level")? {
        return Ok(None);
    }
    conn.query_row("SELECT state FROM event_level WHERE id = 1", [], |r| {
        r.get(0)
    })
    .optional()
}

/// What the pages show of the level that moves with every program start read, and nothing
/// that moves with the clock alone: the state, the latest start read, what the collector said,
/// why a reading failed, and whether file events are collected. File events alone, many a
/// second, do not move it: the pages say their count as made, and the live file says it now.
/// Readings that took nothing leave it as it was.
pub fn basis(conn: &Connection) -> rusqlite::Result<String> {
    if !has(conn, "event_level")? {
        return Ok(String::new());
    }
    let level = conn
        .query_row(
            "SELECT state, last_seq, said_by, said, reason FROM event_level WHERE id = 1",
            [],
            |r| {
                Ok(format!(
                    "{:?}",
                    (
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    )
                ))
            },
        )
        .optional()?
        .unwrap_or_default();
    Ok(match collected(conn)?.0 {
        true => format!("{level} files"),
        false => level,
    })
}

/// Whether file events are counted as collected, and why not, as the latest reading left it;
/// not collected before any reading of this version.
fn collected(conn: &Connection) -> rusqlite::Result<(bool, Option<String>)> {
    if !has(conn, "event_files")? {
        return Ok((false, None));
    }
    Ok(conn
        .query_row(
            "SELECT collected, why FROM event_files WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((false, None)))
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
    let found = look(root, &left, now, Rules::shipped());
    let mut opened = 0;
    let state = match &found {
        Found::NotInstalled => NOT_INSTALLED,
        Found::Failed(_) => FAILED,
        Found::Read(log) => log.state,
    };
    match &found {
        // Nothing to continue: an install after this starts its numbering anew.
        Found::NotInstalled => {
            put_level(tx, now, state, None, (None, None), (None, None, None))?;
            tx.execute("DELETE FROM event_files", [])?;
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
            let f = &log.file_tally;
            tx.execute(
                "INSERT INTO event_file_count (at, files, lost, unknown_gaps, unreadable)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now, f.files, f.lost, f.unknown_gaps, f.unreadable],
            )?;
            let seq = |k: usize| log.file_seq[k].map(|s| s as i64);
            tx.execute(
                "INSERT INTO event_files (id, collected, why, last_create, last_rename)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT (id) DO UPDATE SET collected = excluded.collected,
                     why = excluded.why, last_create = excluded.last_create,
                     last_rename = excluded.last_rename",
                params![
                    log.collects.is_ok(),
                    log.collects.as_ref().err().map(|e| &e.1),
                    seq(0),
                    seq(1)
                ],
            )?;
            opened = record(tx, run_id, machine, now, &log.matched)?;
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
    tx.execute("DELETE FROM event_file_count WHERE at < ?1", [now - KEEP])?;
    tx.execute(
        "DELETE FROM rule_match WHERE hour < ?1",
        [(now - KEEP_MATCHES) / HOUR],
    )?;
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
    // File events have coverage of their own while the level runs; otherwise the level's
    // state, above, says why nothing is recorded, once.
    tx.execute(
        "DELETE FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
        params![READER, machine, KIND_FILES],
    )?;
    if let Found::Read(log) = &found
        && log.state == RUNNING
    {
        let (completeness, reason, cause) = files_covered(
            &log.collects,
            &tally_since(tx, now - DAY)?,
            &file_tally_since(tx, now - DAY)?,
        );
        crate::store::put_coverage(
            tx,
            &Reading {
                kind: KIND_FILES,
                ..reading
            },
            completeness,
            reason.as_deref(),
            &Gap::when(cause),
        )?;
    }
    Ok(Outcome {
        state,
        starts: match &found {
            Found::Read(log) => log.tally.starts,
            _ => 0,
        },
        failed: match found {
            Found::Failed(why) => Some(why),
            _ => None,
        },
        opened,
    })
}

/// Records what the rules matched in a reading: every rule's count by the hour, and for a rule
/// that raises a finding, the finding, its count and its latest starts. Returns how many
/// findings were opened.
fn record(
    tx: &Transaction,
    run_id: &str,
    machine: &str,
    now: i64,
    matched: &Matched,
) -> rusqlite::Result<usize> {
    let mut opened = 0;
    for (id, hits) in &matched.rules {
        tx.execute(
            "INSERT INTO rule_match (hour, rule, matches) VALUES (?1, ?2, ?3)
             ON CONFLICT (hour, rule) DO UPDATE SET matches = matches + excluded.matches",
            params![now / HOUR, id, hits.count],
        )?;
        if !hits.meta.level.raises() {
            continue;
        }
        // One finding per rule on this Mac: a repeated match of a rule whose finding stands
        // adds to its count and its examples and raises nothing new.
        let rule = hits.meta.finding_rule.as_str();
        let (finding, raised) = crate::findings::occur(tx, rule, machine, "new", run_id, now)?;
        if raised {
            // What the finding rests on: a journal entry naming the rule and how many starts
            // matched it, never what they were.
            tx.execute(
                "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, text)
                 VALUES (?1, ?2, 'matched', ?3, ?4, ?5, ?4, ?6)",
                params![
                    now,
                    run_id,
                    READER,
                    machine,
                    rule,
                    json!({ "rule_id": id, "matches": hits.count }).to_string()
                ],
            )?;
            tx.execute(
                "INSERT INTO finding_basis (finding, journal) VALUES (?1, ?2)",
                params![finding, tx.last_insert_rowid()],
            )?;
            opened += 1;
        }
        tx.execute(
            "INSERT INTO rule_finding (finding, matches) VALUES (?1, ?2)
             ON CONFLICT (finding) DO UPDATE SET matches = matches + excluded.matches",
            params![finding, hits.count],
        )?;
        for e in &hits.latest {
            match e {
                Evidence::Start(s) => tx.execute(
                    "INSERT INTO rule_evidence (finding, read_at, timestamp, executable, args,
                         parent_executable, working_directory, pid, parent_pid, user_id,
                         signing_id, team_id, platform_binary)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        finding,
                        now,
                        s.timestamp,
                        s.executable,
                        json!(s.args).to_string(),
                        s.parent_executable,
                        s.working_directory,
                        s.pid,
                        s.parent_pid,
                        s.user_id,
                        s.signing_id,
                        s.team_id,
                        s.platform_binary
                    ],
                )?,
                Evidence::File(f) => tx.execute(
                    "INSERT INTO rule_file_evidence (finding, read_at, timestamp, action, path,
                         source, executable)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        finding,
                        now,
                        f.timestamp,
                        f.action,
                        f.path,
                        f.source,
                        f.executable
                    ],
                )?,
            };
        }
        for table in ["rule_evidence", "rule_file_evidence"] {
            tx.execute(
                &format!(
                    "DELETE FROM {table} WHERE finding = ?1 AND rowid NOT IN
                         (SELECT rowid FROM {table} WHERE finding = ?1
                          ORDER BY rowid DESC LIMIT ?2)"
                ),
                params![finding, EVIDENCE as i64],
            )?;
        }
    }
    Ok(opened)
}

/// Whether the store has a table: one this build creates at the first reading may be missing
/// from a store read before it.
fn has(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )
}

/// What a finding from a published rule carries beside its words, each in its own field: the
/// rule as it describes itself, its authors among them, as the Detection Rule License asks of
/// a message made from a match; the kind of event it is about, `events`; how many events it
/// counts since it was raised; and the latest of them, newest first. Text from the rule or
/// from an event is only in `_text` fields.
pub fn finding_detail(
    conn: &Connection,
    finding: &str,
    file: &'static str,
    meta: &Meta,
    kind: crate::sigma::Kind,
) -> rusqlite::Result<Value> {
    let mut v = crate::sigma::Match { file, meta, kind }.json();
    v["licence"] = json!(crate::sigma::LICENCE);
    v["source"] = json!(crate::sigma::SOURCE);
    let table = match kind {
        crate::sigma::Kind::Process => "rule_evidence",
        crate::sigma::Kind::File => "rule_file_evidence",
    };
    let (matches, evidence) = if has(conn, table)? {
        let evidence = match kind {
            crate::sigma::Kind::Process => evidence(conn, finding)?,
            crate::sigma::Kind::File => file_evidence(conn, finding)?,
        };
        (counted(conn, finding)?, evidence)
    } else {
        (0, Vec::new())
    };
    v["matches"] = json!(matches);
    v["evidence"] = json!(evidence);
    Ok(v)
}

/// The file events a finding from a published rule keeps, newest first: the file, a rename's
/// source, and the program, under ECS's names, with `action` the event's own fixed name.
fn file_evidence(conn: &Connection, finding: &str) -> rusqlite::Result<Vec<Value>> {
    let text = |s: Option<String>| s.as_deref().map(crate::status::text);
    conn.prepare(
        "SELECT timestamp, action, path, source, executable
         FROM rule_file_evidence WHERE finding = ?1 ORDER BY rowid DESC",
    )?
    .query_map([finding], |r| {
        let action: String = r.get(1)?;
        Ok(json!({
            "timestamp_text": crate::status::text(&r.get::<_, String>(0)?),
            "action": FILE_KINDS.iter().find(|k| **k == action),
            "file_text": crate::status::text(&r.get::<_, String>(2)?),
            "source_text": text(r.get(3)?),
            "executable_text": crate::status::text(&r.get::<_, String>(4)?),
        }))
    })?
    .collect()
}

/// How many events a finding from a published rule counts.
fn counted(conn: &Connection, finding: &str) -> rusqlite::Result<i64> {
    Ok(conn
        .query_row(
            "SELECT matches FROM rule_finding WHERE finding = ?1",
            [finding],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// The starts a finding from a published rule keeps, newest first, under ECS's names.
fn evidence(conn: &Connection, finding: &str) -> rusqlite::Result<Vec<Value>> {
    let text = |s: Option<String>| s.as_deref().map(crate::status::text);
    conn.prepare(
        "SELECT timestamp, executable, args, parent_executable, working_directory, pid,
                parent_pid, user_id, signing_id, team_id, platform_binary
         FROM rule_evidence WHERE finding = ?1 ORDER BY rowid DESC",
    )?
    .query_map([finding], |r| {
        let args: Vec<String> = serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default();
        Ok(json!({
            "timestamp_text": crate::status::text(&r.get::<_, String>(0)?),
            "executable_text": crate::status::text(&r.get::<_, String>(1)?),
            "args_text": args.iter().map(|a| crate::status::text(a)).collect::<Vec<_>>(),
            "parent_executable_text": text(r.get(3)?),
            "working_directory_text": text(r.get(4)?),
            "pid": r.get::<_, i64>(5)?,
            "parent_pid": r.get::<_, Option<i64>>(6)?,
            "user_id": r.get::<_, Option<i64>>(7)?,
            "signing_id_text": text(r.get(8)?),
            "team_id_text": text(r.get(9)?),
            "platform_binary": r.get::<_, Option<bool>>(10)?,
        }))
    })?
    .collect()
}

/// What a replay of the log on disk found. Nothing is read from the store or written to it.
pub enum Replay {
    NotInstalled,
    Failed(String),
    Read {
        tally: Tally,
        file_tally: FileTally,
        matched: Matched,
    },
}

/// Evaluates the rules over every line of the event log under `root` as it is now, from the
/// start of each file: what would have matched, for tuning before the findings are trusted.
pub fn replay(root: &Path, now: i64) -> Replay {
    match look(root, &Left::default(), now, Rules::shipped()) {
        Found::NotInstalled => Replay::NotInstalled,
        Found::Failed(why) => Replay::Failed(why),
        Found::Read(log) => Replay::Read {
            tally: log.tally,
            file_tally: log.file_tally,
            matched: log.matched,
        },
    }
}

/// The coverage of file events while the level runs: none while the collector installed here
/// is not established to record them, with why; else full unless a file event was lost or
/// could not be made out, or a line could not be read or an hour was deleted early, over the
/// last day.
fn files_covered(
    collects: &Result<(), (Cause, String)>,
    t: &Tally,
    f: &FileTally,
) -> (&'static str, Option<String>, Option<Cause>) {
    if let Err((cause, why)) = collects {
        return ("none", Some(why.clone()), Some(*cause));
    }
    let mut said = f.gaps();
    if !t.shared_whole() {
        said.extend(
            Tally {
                unreadable: t.unreadable,
                removed_cap: t.removed_cap,
                removed_unread: t.removed_unread,
                ..Tally::default()
            }
            .gaps(),
        );
    }
    if said.is_empty() {
        return ("full", None, None);
    }
    let cause = if f.unreadable + t.unreadable > 0 {
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

/// The coverage of a log that was read. Running, it is full unless something was lost,
/// could not be read or was deleted early over the last day `t`, the span the log keeps,
/// which makes it partial with the counts; refused, failing or silent, no program start is
/// being recorded, and the state says why.
fn covered(state: &str, t: &Tally) -> (&'static str, Option<String>, Option<Cause>) {
    match state {
        RUNNING => {
            let said = t.gaps();
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
    let file_seq: Option<(Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT last_create, last_rename FROM event_files WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let seq = |s: Option<i64>| s.map(|s| s as u64);
    Ok(Left {
        files,
        last_seq: row.and_then(|r| r.0).map(|s| s as u64),
        file_seq: file_seq.map_or([None, None], |(c, r)| [seq(c), seq(r)]),
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
    /// How many program starts matched each rule, by its id, over the last day and the last
    /// week, by the hour of the reading.
    pub matches_last_day: BTreeMap<String, i64>,
    pub matches_last_week: BTreeMap<String, i64>,
    /// Program starts read over the last day, hour by hour.
    pub starts_by_hour: Series,
    /// Program starts read over the last hour, minute by minute.
    pub starts_by_minute: Series,
    pub files: Files,
}

/// File events, as the latest reading left them.
#[derive(Debug, Default)]
pub struct Files {
    /// The collector installed here is established to record them.
    pub collected: bool,
    /// Why not, in the program's words; `None` when collected or before any reading of them.
    pub why: Option<String>,
    pub since_check: FileTally,
    pub last_day: FileTally,
}

impl Level {
    /// The rules for file events watch: the level runs and its collector records file events.
    pub fn files_watched(&self) -> bool {
        self.state == RUNNING && self.files.collected
    }

    /// Every file event the log held over the last day was read: none lost, none that could
    /// not be made out, no line unreadable and no hour deleted early.
    pub fn files_whole(&self) -> bool {
        self.files.last_day.gaps().is_empty() && self.last_day.shared_whole()
    }
}

/// How many hours the series by hour counts: the last day.
pub const HOURS: usize = 24;
/// How many minutes the series by minute counts: the last hour.
pub const MINUTES: usize = 60;
const MINUTE: i64 = 60;

/// Program starts read over a span, step by step, for a drawing: counts oldest first, each
/// `step` seconds, the last ending at `ends_at`, the time it was asked at. A reading is
/// counted in the step it was made in; one stamped later than `ends_at`, by a clock set back,
/// is in the last step.
///
/// By the hour (`starts_by_hour`), the counts add up to `last_day.starts`: the first hour also
/// holds the readings at the very start of the day. By the minute (`starts_by_minute`), they
/// hold exactly the readings of the last hour by the hour, so the two series never disagree:
/// the minutes add up to the last hour.
#[derive(Debug, Default, PartialEq)]
pub struct Series {
    pub ends_at: i64,
    pub step: i64,
    pub counts: Vec<i64>,
}

/// Program starts read hour by hour over the day before `now`, see `Series`.
pub fn starts_by_hour(conn: &Connection, now: i64) -> rusqlite::Result<Series> {
    series(conn, now, HOUR, HOURS, now - DAY)
}

/// Program starts read minute by minute over the hour before `now`, see `Series`: the readings
/// less than an hour old, which are the last hour's by the hour.
pub fn starts_by_minute(conn: &Connection, now: i64) -> rusqlite::Result<Series> {
    series(conn, now, MINUTE, MINUTES, now - HOUR + 1)
}

/// Program starts read since `from`, in `n` steps of `step` seconds ending at `now`.
fn series(conn: &Connection, now: i64, step: i64, n: usize, from: i64) -> rusqlite::Result<Series> {
    let mut counts = vec![0; n];
    let last = n as i64 - 1;
    let mut stmt = conn.prepare(
        "SELECT MIN(MAX((?1 - at) / ?2, 0), ?3), SUM(starts) FROM event_count
         WHERE at >= ?4 GROUP BY 1",
    )?;
    for row in stmt.query_map(params![now, step, last, from], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (ago, n) = row?;
        counts[(last - ago) as usize] += n;
    }
    Ok(Series {
        ends_at: now,
        step,
        counts,
    })
}

/// The level, or `None` before any reading of it.
pub fn level(conn: &Connection, now: i64) -> rusqlite::Result<Option<Level>> {
    if !has(conn, "event_level")? {
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
    let (collected, why) = collected(conn)?;
    let files = Files {
        collected,
        why,
        since_check: file_tally_since(conn, check)?,
        last_day: file_tally_since(conn, now - DAY)?,
    };
    Ok(Some(Level {
        files,
        state,
        read_at,
        written,
        said_by,
        said,
        reason,
        version,
        since_check: tally_since(conn, check)?,
        last_day: tally_since(conn, now - DAY)?,
        matches_last_day: matches_since(conn, now - DAY)?,
        matches_last_week: matches_since(conn, now - KEEP_MATCHES)?,
        starts_by_hour: starts_by_hour(conn, now)?,
        starts_by_minute: starts_by_minute(conn, now)?,
    }))
}

/// How many program starts matched each rule in readings from the hour that holds `from` on.
fn matches_since(conn: &Connection, from: i64) -> rusqlite::Result<BTreeMap<String, i64>> {
    if !has(conn, "rule_match")? {
        return Ok(BTreeMap::new());
    }
    conn.prepare("SELECT rule, SUM(matches) FROM rule_match WHERE hour >= ?1 GROUP BY rule")?
        .query_map([from / HOUR], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect()
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

/// The counts of file events of every reading at or after `from`; none in a store read before
/// this version.
fn file_tally_since(conn: &Connection, from: i64) -> rusqlite::Result<FileTally> {
    if !has(conn, "event_file_count")? {
        return Ok(FileTally::default());
    }
    conn.query_row(
        "SELECT COALESCE(SUM(files), 0), COALESCE(SUM(lost), 0),
                COALESCE(SUM(unknown_gaps), 0), COALESCE(SUM(unreadable), 0)
         FROM event_file_count WHERE at >= ?1",
        [from],
        |r| {
            Ok(FileTally {
                files: r.get(0)?,
                lost: r.get(1)?,
                unknown_gaps: r.get(2)?,
                unreadable: r.get(3)?,
            })
        },
    )
}

/// What this level cannot see on this Mac: `CANNOT_SEE`, and file events while the collector
/// installed here does not record them.
pub fn cannot_see(l: &Level) -> Vec<&'static str> {
    let mut said = CANNOT_SEE.to_vec();
    if !l.files.collected {
        said.push(FILES_NOT_SEEN);
    }
    said
}

/// `event_level` in `immune status --json`. What `eslogger` or the scripts printed, and why a
/// reading failed, are text from a source, each in its own field.
pub fn json(l: &Level) -> Value {
    let iso = |t: Option<i64>| t.map(crate::view::iso);
    let pair = |f: fn(&Tally) -> i64| json!({ "since_check": f(&l.since_check), "last_day": f(&l.last_day) });
    let files = |f: fn(&FileTally) -> i64| json!({ "since_check": f(&l.files.since_check), "last_day": f(&l.files.last_day) });
    let said = words(l);
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
        "cannot_see": cannot_see(l),
        // Files created and renamed. `collected` is true only when the collector installed
        // here is established to record them; else `not_collected_reason` says why, in the
        // program's words, and the rules for file events do not watch. Lines that could not be
        // read and hours deleted are in the counts above and judge file events too.
        "file_events": {
            "collected": l.files.collected,
            "not_collected_reason": l.files.why.as_deref().filter(|_| !l.files.collected),
            "kinds": FILE_KINDS,
            "events": files(|f| f.files),
            "lost": files(|f| f.lost),
            "unknown_losses": files(|f| f.unknown_gaps),
            "unreadable_events": files(|f| f.unreadable),
        },
        // For a drawing: program starts read in each hour of the last day, oldest first, the
        // last hour ending at `ends_at`; they add up to `program_starts.last_day`.
        "program_starts_by_hour": {
            "ends_at": crate::view::iso(l.starts_by_hour.ends_at),
            "hour_seconds": HOUR,
            "counts": l.starts_by_hour.counts,
        },
        // The same minute by minute over the last hour, oldest first; they add up to the last
        // of the hours above.
        "program_starts_by_minute": minutes(&l.starts_by_minute),
        // The level for a person, the words every surface takes: a short state, and each
        // caveat a sentence of its own, none when nothing was lost; `caveats` holds the same
        // caveats in a few words each, under stable names. The program's own words.
        "in_words": in_words(&said),
    })
}

/// `program_starts_by_minute`, in the status and in what a watcher says after a reading.
pub fn minutes(s: &Series) -> Value {
    json!({
        "ends_at": crate::view::iso(s.ends_at),
        "minute_seconds": MINUTE,
        "counts": s.counts,
        "last_hour": s.counts.iter().sum::<i64>(),
    })
}

/// `in_words`, see `Said`.
pub fn in_words(said: &Said) -> Value {
    json!({
        "state": said.state,
        "notes": said.notes,
        "caveats": said.caveats.iter().map(|c| json!({ "kind": c.kind, "short": c.short })).collect::<Vec<_>>(),
    })
}

/// The level for a person: a short state, the count of program starts while it records them,
/// and each caveat as a short sentence of its own, so that a surface shows the state at a
/// glance and the caveats under it, quieter, or folded. The page's row, `immune status` and
/// anything else that tells the level take these words. None names `eslogger`: a person reads
/// "the collector".
pub struct Said {
    pub state: &'static str,
    /// Program starts read in the last day, while the level records them.
    pub last_day: Option<i64>,
    pub notes: Vec<String>,
    /// The same caveats, one for each note while the level records program starts, each with
    /// a stable name and a few words: for a row that has room for a mark and not a sentence.
    pub caveats: Vec<Caveat>,
}

/// A caveat in a few words, "2 restarts", "12 lost"; `kind` is a stable name.
#[derive(Debug, PartialEq)]
pub struct Caveat {
    pub kind: &'static str,
    pub short: String,
}

impl Said {
    /// The state with its count, for a row whose label already says what is counted:
    /// "on, 49,842 in the last day".
    pub fn short(&self) -> String {
        match self.last_day {
            Some(n) => format!(
                "{}, {} in the last day",
                self.state,
                crate::view::counted(n, "", "").trim_end()
            ),
            None => self.state.to_string(),
        }
    }

    /// One line, with what is counted named, then the caveats: what `immune status` prints.
    pub fn line(&self) -> String {
        let head = match self.last_day {
            Some(n) => format!(
                "{}, {} in the last day.",
                self.state,
                crate::view::counted(n, "program start", "program starts")
            ),
            None => format!("{}.", self.state),
        };
        std::iter::once(head)
            .chain(self.notes.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// How many times, as a person says it: once, twice, then a number.
fn how_often(n: i64) -> String {
    match n {
        1 => "once".to_string(),
        2 => "twice".to_string(),
        n => crate::view::counted(n, "time", "times"),
    }
}

/// The level in words, see `Said`. A restart of the collector is counted only after a start
/// it continued from (`count_seq`), so installing the level is never one; each restart after
/// that is a short moment in which program starts were not seen, and is said so, neither
/// hidden nor made more of.
pub fn words(l: &Level) -> Said {
    let counted = crate::view::counted;
    let not_seen = |state: &'static str, why: String| Said {
        state,
        last_day: None,
        notes: vec![why],
        caveats: Vec::new(),
    };
    match l.state.as_str() {
        RUNNING => {
            let d = &l.last_day;
            let mut notes = Vec::new();
            let mut caveats = Vec::new();
            let mut short = |kind, n, one, many| {
                caveats.push(Caveat {
                    kind,
                    short: counted(n, one, many),
                })
            };
            if d.unknown_gaps > 0 {
                short("restarts", d.unknown_gaps, "restart", "restarts");
                notes.push(format!(
                    "The collector restarted {}; program starts in {} were not seen.",
                    how_often(d.unknown_gaps),
                    if d.unknown_gaps == 1 {
                        "that moment"
                    } else {
                        "those moments"
                    }
                ));
            }
            if d.lost > 0 {
                short("lost", d.lost, "lost", "lost");
                notes.push(format!(
                    "{} missed because the collector fell behind.",
                    counted(d.lost, "program start was", "program starts were")
                ));
            }
            if d.unreadable > 0 {
                short(
                    "unreadable",
                    d.unreadable,
                    "unreadable line",
                    "unreadable lines",
                );
                notes.push(format!(
                    "{} of the log could not be read.",
                    counted(d.unreadable, "line", "lines")
                ));
            }
            if d.removed_cap > 0 {
                short(
                    "deleted_early",
                    d.removed_cap,
                    "hour deleted early",
                    "hours deleted early",
                );
                notes.push(format!(
                    "{} deleted early to keep the log under its size limit.",
                    counted(
                        d.removed_cap,
                        "hour of the log was",
                        "hours of the log were"
                    )
                ));
            }
            if d.removed_unread > 0 {
                short(
                    "deleted_unread",
                    d.removed_unread,
                    "hour deleted unread",
                    "hours deleted unread",
                );
                notes.push(format!(
                    "{} deleted before they were read.",
                    counted(
                        d.removed_unread,
                        "hour of the log was",
                        "hours of the log were"
                    )
                ));
            }
            Said {
                state: "on",
                last_day: Some(d.starts),
                notes,
                caveats,
            }
        }
        NOT_INSTALLED => not_seen(
            "not installed",
            "Program starts are not seen until it is installed.".to_string(),
        ),
        REFUSED => not_seen(
            "refused by macOS",
            "macOS does not give the collector Full Disk Access, so program starts are not seen."
                .to_string(),
        ),
        FAILING => not_seen(
            "stopped by an error",
            "The collector reported an error, so program starts are not seen.".to_string(),
        ),
        SILENT => not_seen(
            "silent",
            format!(
                "Nothing has been recorded {}, so program starts are not seen.",
                l.written
                    .map_or("since it was installed".to_string(), |t| format!(
                        "since {}",
                        crate::view::utc(t)
                    ))
            ),
        ),
        _ => not_seen(
            "cannot be read",
            "Its log could not be read, so program starts are not seen.".to_string(),
        ),
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

    /// A file event as the filter writes it, with invented content.
    fn created(seq: u64, path: &str) -> String {
        format!(
            r#"{{"schema_version":1,"seq_num":{seq},"time":"2026-10-04T00:00:03.000003Z","process":{{"executable":{{"path":"/usr/bin/curl"}}}},"event":{{"create":{{"destination":"{path}"}}}}}}"#
        )
    }

    #[test]
    fn a_file_event_is_read_and_one_it_cannot_make_out_is_counted_never_a_failed_reading() {
        // The reading goes on serving program starts whatever shape a file event comes in: a
        // file event this reader cannot make out is counted as such, its number still counted
        // for losses, and never fails the reading or passes as nothing. A file created is
        // never told as renamed, whatever else its line holds.
        let stray = created(7, "/private/tmp/6202033").replace(
            r#""destination":"#,
            r#""source":"/private/tmp/y","destination":"#,
        );
        let Ok(Line::File {
            kind: 0,
            seq: Some(7),
            event: Some(f),
        }) = line(stray.as_bytes())
        else {
            panic!("a create");
        };
        assert_eq!(
            *f,
            FileEvent {
                timestamp: "2026-10-04T00:00:03.000003Z".into(),
                action: "create",
                path: "/private/tmp/6202033".into(),
                source: None,
                executable: "/usr/bin/curl".into(),
            }
        );
        let renamed = r#"{"schema_version":1,"seq_num":2,"time":"t","process":{"executable":{"path":"/bin/mv"}},"event":{"rename":{"destination":"/Library/LaunchDaemons/b.plist","source":"/private/tmp/a.plist"}}}"#;
        let Ok(Line::File {
            kind: 1,
            event: Some(f),
            ..
        }) = line(renamed.as_bytes())
        else {
            panic!("a rename");
        };
        assert_eq!(
            (f.action, f.path.as_str(), f.source.as_deref()),
            (
                "rename",
                "/Library/LaunchDaemons/b.plist",
                Some("/private/tmp/a.plist")
            )
        );
        for (why, text) in [
            (
                "the filter's line for a shape it did not know",
                r#"{"schema_version":1,"seq_num":9,"time":"t","event":{"create":{}}}"#.to_string(),
            ),
            ("a path that is not absolute", created(9, "tmp/x")),
            (
                "no program",
                created(9, "/x")
                    .replace(r#""process":{"executable":{"path":"/usr/bin/curl"}},"#, ""),
            ),
            (
                "no time",
                created(9, "/x").replace(r#""time":"2026-10-04T00:00:03.000003Z","#, ""),
            ),
            (
                "a rename without its source",
                renamed
                    .replace(r#","source":"/private/tmp/a.plist""#, "")
                    .replace("2,", "9,"),
            ),
        ] {
            assert_eq!(
                line(text.as_bytes()),
                Ok(Line::File {
                    kind: FILE_KINDS
                        .iter()
                        .position(|k| text.contains(&format!("\"{k}\"")))
                        .unwrap(),
                    seq: Some(9),
                    event: None
                }),
                "{why}"
            );
        }
        // Without its number its losses cannot be counted: it is not made out either.
        let bare = created(1, "/x").replace(r#""seq_num":1,"#, "");
        assert_eq!(
            line(bare.as_bytes()),
            Ok(Line::File {
                kind: 0,
                seq: None,
                event: None
            })
        );
        // An unknown schema_version fails the reading whatever the event.
        let two = created(1, "/x").replace(r#""schema_version":1"#, r#""schema_version":2"#);
        assert!(line(two.as_bytes()).is_err());
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
        let dir = std::env::temp_dir().join(format!("immune-events-keep-{}", std::process::id()));
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
    fn the_pages_basis_moves_with_a_start_read_or_a_new_state_and_not_with_a_reading_alone() {
        // A click after new program starts writes the pages that count them again; a reading
        // every ten seconds that took nothing writes nothing, or every click would.
        let dir = std::env::temp_dir().join(format!("immune-events-basis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = dir.join("root").join(LOG);
        std::fs::create_dir_all(&log).unwrap();
        let plist = dir.join("root").join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        let read = |conn: &mut rusqlite::Connection, at: i64| {
            let tx = conn.transaction().unwrap();
            crate::store::put_entity(&tx, "machine:mac").unwrap();
            read(&tx, "events-1", "machine:mac", &dir.join("root"), at).unwrap();
            tx.commit().unwrap();
            basis(conn).unwrap()
        };
        let now = crate::now_secs();
        let first = read(&mut conn, now);
        std::fs::write(log.join("exec-20261004T00.jsonl"), exec(1, OBJECT) + "\n").unwrap();
        let started = read(&mut conn, now + 10);
        assert_ne!(started, first);
        assert_eq!(read(&mut conn, now + 20), started);
        // The collector is established to record file events: the pages that said the rules
        // for files do not watch are written again.
        std::fs::write(
            dir.join("root").join(COLLECTS),
            r#"["/usr/bin/eslogger","exec","create","rename"]"#,
        )
        .unwrap();
        let collecting = read(&mut conn, now + 25);
        assert_ne!(collecting, started);
        std::fs::remove_file(&plist).unwrap();
        let removed = read(&mut conn, now + 30);
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(removed, collecting);
    }

    #[test]
    fn matches_are_served_by_the_hour_for_the_last_day_and_the_week_and_deleted_after_a_week() {
        // The owner tunes the rules on a week of counts; the status serves the last day. Both
        // are kept by the hour of the reading, so the hour that holds the start of the span
        // counts whole, and an hour older than the week is deleted.
        let dir = std::env::temp_dir().join(format!("immune-events-hours-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root").join(LOG)).unwrap();
        let plist = dir.join("root").join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        // On the hour, so that each reading below is in an hour of its own.
        let now = 1_791_000_000;
        assert_eq!(now % HOUR, 0);
        let log = dir.join("root").join(LOG).join("exec-20261004T00.jsonl");
        let mut text = String::new();
        for (seq, at) in [
            (1, now - KEEP_MATCHES - HOUR),
            (2, now - KEEP_MATCHES),
            (3, now - DAY - HOUR),
            (4, now - DAY),
            (5, now),
        ] {
            text.push_str(
                &exec(seq, OBJECT)
                    .replace(
                        r#"["git","status","--short"]"#,
                        r#"["sw_vers","-productVersion"]"#,
                    )
                    .replace("/usr/bin/git", "/usr/bin/sw_vers"),
            );
            text.push('\n');
            std::fs::write(&log, &text).unwrap();
            let tx = conn.transaction().unwrap();
            crate::store::put_entity(&tx, "machine:mac").unwrap();
            read(&tx, "events-1", "machine:mac", &dir.join("root"), at).unwrap();
            tx.commit().unwrap();
        }
        let l = level(&conn, now).unwrap().unwrap();
        let hours: i64 = conn
            .query_row("SELECT COUNT(*) FROM rule_match", [], |r| r.get(0))
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let sw_vers = "5de06a6f-673a-4fc0-8d48-bcfe3837b033";
        assert_eq!(l.matches_last_day[sw_vers], 2);
        assert_eq!(l.matches_last_week[sw_vers], 4);
        assert_eq!(hours, 4);
    }

    #[test]
    fn a_busy_mac_is_read_many_times_faster_than_it_starts_programs() {
        // The watcher reads at every sample, every thirty seconds, and a full run reads what
        // accumulated since the last one, under the lock, each start evaluated against every
        // published rule. A busy Mac starts about 100 programs a second, so a sample adds
        // about 3,000 lines. The bound is ten times that pace in a debug build and fifty times
        // in a release one: loose, so that a Mac busy with other builds does not fail it, and
        // it catches a reader that became quadratic or reads a line twice. One start in ten
        // matches a high rule, so a finding's evidence is taken too, and one in ten a medium
        // rule. Measured and printed with `--nocapture`, with the share of the time the rules
        // take, measured over the same starts apart from the reading.
        let dir = std::env::temp_dir().join(format!("immune-events-speed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(LOG)).unwrap();
        let plist = dir.join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let git = r#"["git","status","--short"]"#;
        let n: u64 = 5_000;
        let mut text = String::new();
        for seq in 1..=n {
            let line = exec(seq, OBJECT);
            text.push_str(&match seq % 10 {
                0 => line
                    .replace(git, r#"["grep","-r","password","."]"#)
                    .replace("/usr/bin/git", "/usr/bin/grep"),
                5 => line
                    .replace(git, r#"["sw_vers","-productVersion"]"#)
                    .replace("/usr/bin/git", "/usr/bin/sw_vers"),
                _ => line,
            });
            text.push('\n');
        }
        std::fs::write(dir.join(LOG).join("exec-20261004T00.jsonl"), &text).unwrap();
        let rules = Rules::shipped();
        let t = std::time::Instant::now();
        let found = look(&dir, &Left::default(), 1_791_000_000, rules);
        let took = t.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        let Found::Read(log) = found else {
            panic!("{found:?}");
        };
        assert_eq!((log.tally.starts, log.tally.lost), (n as i64, 0));
        let counts: Vec<(&str, i64)> = log
            .matched
            .rules
            .iter()
            .map(|(id, h)| (*id, h.count))
            .collect();
        assert_eq!(
            counts,
            [
                ("53b1b378-9b06-4992-b972-dde6e423d2b4", n as i64 / 10),
                ("5de06a6f-673a-4fc0-8d48-bcfe3837b033", n as i64 / 10),
            ]
        );
        // However many starts a high rule matched, a reading holds only the latest few.
        let credentials = &log.matched.rules["53b1b378-9b06-4992-b972-dde6e423d2b4"];
        assert_eq!(credentials.latest.len(), EVIDENCE);
        assert_eq!(
            log.matched.rules["5de06a6f-673a-4fc0-8d48-bcfe3837b033"]
                .latest
                .len(),
            0
        );
        let starts: Vec<ProcessStart> = text
            .lines()
            .map(|l| match line(l.as_bytes()) {
                Ok(Line::Exec { start, .. }) => *start,
                other => panic!("{other:?}"),
            })
            .collect();
        let t = std::time::Instant::now();
        let matched: usize = starts.iter().map(|s| rules.evaluate(s).len()).sum();
        let evaluating = t.elapsed();
        assert_eq!(matched as u64, n / 5);
        let rate = n as f64 / took.as_secs_f64();
        println!(
            "read {n} lines of {} bytes each in {took:?}: {rate:.0} lines a second; evaluating {} rules over them alone took {evaluating:?}",
            text.len() as u64 / n,
            rules.groups().0.len() + rules.groups().1.len()
        );
        let bound = if cfg!(debug_assertions) {
            1_000.0
        } else {
            5_000.0
        };
        assert!(rate > bound, "{rate:.0} lines a second");
    }

    #[test]
    fn a_busy_mac_s_file_events_are_read_many_times_faster_than_they_happen() {
        // A Mac under agents' builds creates and renames about 200 files a second, measured on
        // a developer's Mac, so the watcher's reading every ten seconds takes about 2,000.
        // The bound is ten times that pace in a debug build and fifty in a release one, as for
        // program starts. One file event in ten matches a high rule for file events, so its
        // finding's evidence is taken, and only the latest few are kept. Each file event is
        // asked only of the rules for file events.
        let dir = std::env::temp_dir().join(format!("immune-events-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(LOG)).unwrap();
        let plist = dir.join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let n: u64 = 20_000;
        let mut text = String::new();
        for seq in 1..=n {
            let path = match seq % 10 {
                3 => "/Users/example/.helper".to_string(),
                _ => format!("/Users/example/dev/site/target/debug/build/obj-{seq}.o"),
            };
            text.push_str(&created(seq, &path));
            text.push('\n');
        }
        std::fs::write(dir.join(LOG).join("exec-20261004T00.jsonl"), &text).unwrap();
        let t = std::time::Instant::now();
        let found = look(&dir, &Left::default(), 1_791_000_000, Rules::shipped());
        let took = t.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        let Found::Read(log) = found else {
            panic!("{found:?}");
        };
        assert_eq!(
            log.file_tally,
            FileTally {
                files: n as i64,
                ..FileTally::default()
            }
        );
        assert_eq!(log.tally.starts, 0);
        let amos = "e710a880-1f18-4417-b6a0-b5afdf7e3023";
        let counts: Vec<(&str, i64)> = log
            .matched
            .rules
            .iter()
            .map(|(id, h)| (*id, h.count))
            .collect();
        assert_eq!(counts, [(amos, n as i64 / 10)]);
        let latest = &log.matched.rules[amos].latest;
        assert_eq!(latest.len(), EVIDENCE);
        assert!(
            latest
                .iter()
                .all(|e| matches!(e, Evidence::File(f) if f.path == "/Users/example/.helper"))
        );
        let rate = n as f64 / took.as_secs_f64();
        println!(
            "read {n} file events of {} bytes each in {took:?}: {rate:.0} a second",
            text.len() as u64 / n
        );
        let bound = if cfg!(debug_assertions) {
            2_000.0
        } else {
            10_000.0
        };
        assert!(rate > bound, "{rate:.0} file events a second");
    }

    #[test]
    fn the_level_is_told_as_a_short_state_then_each_caveat_on_its_own() {
        // Form before text: a surface shows the state and the count at a glance and folds the
        // caveats under it. Counts read as a person says them, thousands separated.
        let mut l = Level {
            state: RUNNING.to_string(),
            read_at: 0,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally {
                starts: 49_842,
                unknown_gaps: 2,
                ..Tally::default()
            },
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: Files::default(),
        };
        let said = words(&l);
        assert_eq!(said.short(), "on, 49,842 in the last day");
        assert_eq!(
            said.notes,
            ["The collector restarted twice; program starts in those moments were not seen."]
        );
        assert_eq!(
            said.caveats,
            [Caveat {
                kind: "restarts",
                short: "2 restarts".to_string()
            }]
        );
        assert_eq!(
            said.line(),
            "on, 49,842 program starts in the last day. The collector restarted twice; program starts in those moments were not seen."
        );
        l.last_day.unknown_gaps = 1_200;
        assert!(words(&l).notes[0].starts_with("The collector restarted 1,200 times;"));
        l.last_day = Tally::default();
        assert!(words(&l).notes.is_empty());
        l.state = NOT_INSTALLED.to_string();
        assert_eq!(words(&l).short(), "not installed");
    }

    #[test]
    fn the_status_serves_the_series_ending_when_asked_and_the_words_a_surface_shows() {
        // The app holds no logic: it draws the series Immune gives, says where the day ends as
        // Immune says, and takes "none lost" only from an empty list of caveats.
        let l = Level {
            state: RUNNING.to_string(),
            read_at: 1_000,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally {
                starts: 7,
                unknown_gaps: 1,
                ..Tally::default()
            },
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series {
                ends_at: 1_791_000_000,
                step: HOUR,
                counts: vec![7],
            },
            starts_by_minute: Series {
                ends_at: 1_791_000_000,
                step: MINUTE,
                counts: vec![2, 0, 3],
            },
            files: Files::default(),
        };
        let v = json(&l);
        assert_eq!(
            v["program_starts_by_hour"],
            json!({ "ends_at": crate::view::iso(1_791_000_000), "hour_seconds": 3600, "counts": [7] })
        );
        assert_eq!(
            v["program_starts_by_minute"],
            json!({ "ends_at": crate::view::iso(1_791_000_000), "minute_seconds": 60, "counts": [2, 0, 3], "last_hour": 5 })
        );
        assert_eq!(
            v["in_words"],
            json!({
                "state": "on",
                "notes": ["The collector restarted once; program starts in that moment were not seen."],
                "caveats": [{ "kind": "restarts", "short": "1 restart" }],
            })
        );
    }

    #[test]
    fn every_caveat_has_a_few_words_under_a_stable_name_beside_its_sentence() {
        // A row has room for a mark, not a sentence: it shows the few words and leads to the
        // sentence. A caveat with a sentence and no mark would let the row read as calm.
        let l = Level {
            state: RUNNING.to_string(),
            read_at: 0,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally {
                starts: 10,
                lost: 12,
                unknown_gaps: 1,
                unreadable: 3,
                removed_cap: 2,
                removed_unread: 1,
                ..Tally::default()
            },
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: Files::default(),
        };
        let said = words(&l);
        let shorts: Vec<_> = said
            .caveats
            .iter()
            .map(|c| (c.kind, c.short.as_str()))
            .collect();
        assert_eq!(
            shorts,
            [
                ("restarts", "1 restart"),
                ("lost", "12 lost"),
                ("unreadable", "3 unreadable lines"),
                ("deleted_early", "2 hours deleted early"),
                ("deleted_unread", "1 hour deleted unread"),
            ]
        );
        assert_eq!(said.caveats.len(), said.notes.len());
    }

    #[test]
    fn the_series_by_hour_adds_up_to_the_count_of_the_day_and_puts_each_reading_in_its_hour() {
        // The panel and the page draw the day as 24 bars beside its count. A bar that loses a
        // reading at the edge of the day, or counts one twice, makes the drawing disagree
        // with the number next to it.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE event_count (at INTEGER NOT NULL, starts INTEGER NOT NULL,
                 lost INTEGER NOT NULL, unknown_gaps INTEGER NOT NULL,
                 unreadable INTEGER NOT NULL, other INTEGER NOT NULL,
                 removed_cap INTEGER NOT NULL, removed_unread INTEGER NOT NULL);",
        )
        .unwrap();
        let now = 1_791_000_000;
        for (at, starts) in [
            (now - DAY - 1, 1_000),    // older than the day: in neither
            (now - DAY, 7),            // the very start of the day: the first hour
            (now - DAY + HOUR, 1),     // the end of the first hour: still the first
            (now - DAY + HOUR + 1, 3), // just after: the second
            (now - 2 * HOUR, 11),      // the end of the hour that ends two hours ago
            (now - HOUR + 1, 5),       // within the last hour
            (now, 2),                  // this reading: the last hour
            (now + 90, 4),             // a clock set back: the last hour, as the day counts it
        ] {
            conn.execute(
                "INSERT INTO event_count VALUES (?1, ?2, 0, 0, 0, 0, 0, 0)",
                params![at, starts],
            )
            .unwrap();
        }
        let h = starts_by_hour(&conn, now).unwrap();
        assert_eq!(h.ends_at, now);
        assert_eq!(h.counts.len(), HOURS);
        assert_eq!(
            h.counts.iter().sum::<i64>(),
            tally_since(&conn, now - DAY).unwrap().starts
        );
        assert_eq!((h.counts[0], h.counts[1]), (8, 3));
        assert_eq!((h.counts[21], h.counts[22], h.counts[23]), (11, 0, 11));
    }

    #[test]
    fn the_minutes_of_the_last_hour_add_up_to_the_last_hour_of_the_day() {
        // The panel draws the last hour by the minute and the page the day by the hour: the
        // two drawings must not disagree about the same hour.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE event_count (at INTEGER NOT NULL, starts INTEGER NOT NULL,
                 lost INTEGER NOT NULL, unknown_gaps INTEGER NOT NULL,
                 unreadable INTEGER NOT NULL, other INTEGER NOT NULL,
                 removed_cap INTEGER NOT NULL, removed_unread INTEGER NOT NULL);",
        )
        .unwrap();
        let now = 1_791_000_000;
        for (at, starts) in [
            (now - HOUR, 1_000),  // an hour old: the hour before, in neither
            (now - HOUR + 1, 5),  // the first minute
            (now - HOUR + 61, 3), // the second
            (now - 61, 2),        // the minute before the last
            (now - 59, 7),        // the last minute
            (now + 90, 4),        // a clock set back: the last minute
        ] {
            conn.execute(
                "INSERT INTO event_count VALUES (?1, ?2, 0, 0, 0, 0, 0, 0)",
                params![at, starts],
            )
            .unwrap();
        }
        let m = starts_by_minute(&conn, now).unwrap();
        let h = starts_by_hour(&conn, now).unwrap();
        assert_eq!((m.ends_at, m.step, m.counts.len()), (now, MINUTE, MINUTES));
        assert_eq!(m.counts.iter().sum::<i64>(), h.counts[HOURS - 1]);
        assert_eq!((m.counts[0], m.counts[1]), (5, 3));
        assert_eq!((m.counts[58], m.counts[59]), (2, 11));
    }

    #[test]
    fn a_gap_in_the_numbering_is_counted_and_a_restart_is_a_loss_of_unknown_size() {
        let mut t = Tally::default();
        let mut last = None;
        for seq in [1, 2, 5, 6, 1, 2] {
            count_seq(seq, &mut last, (&mut t.lost, &mut t.unknown_gaps));
        }
        assert_eq!((t.lost, t.unknown_gaps), (2, 1));
        // The first number ever read says nothing about what came before.
        let (mut t, mut last) = (Tally::default(), None);
        count_seq(40, &mut last, (&mut t.lost, &mut t.unknown_gaps));
        assert_eq!((t.lost, t.unknown_gaps, last), (0, 0, Some(40)));
    }
}
