//! The event level: every program start, and every file created or renamed, on this Mac, as
//! Apple's `eslogger` records them. This is the level of access "Apple's `eslogger` as
//! administrator" in `docs/how-it-works.md`. The collecting side runs as root and is data in
//! `scripts/event-level/`: launchd runs `/usr/bin/eslogger exec create rename` into a FIFO,
//! Apple's `jq` keeps of each message only what this reader uses, under `eslogger`'s own
//! names, and Apple's `rotatelogs` writes that into a new file at each hour and at 128 MiB, in a
//! folder only root and the installing account can read; the root side deletes files older
//! than a day, and the oldest while the log is over its size cap, each time a file is started
//! and every ten minutes, and notes each deletion in `removed`. This
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
//! a line `rotatelogs` split between two files, is counted and skipped, and so is the marker
//! the filter writes for a message `jq` could not read, which is counted as such and not as a
//! loss. A message of a kind
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
//! writes each as one line in the same files, `exec-…` though they hold more than
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
//!
//! Who a process is. The collector keeps, beside a pid, the pid's version from the audit token
//! and the process's start time, for the program started, the process that acted and, as pid
//! and pid version, the parent; and the script a start names and some code-signing details
//! (`KEEPS`). A collector installed before it did keeps none of them, and its lines are read as
//! before: what a line lacks is absent. Each line says by its own keys which of `KEEPS` its
//! collector kept, and a rule that reads a field one of them fills is not asked about a line
//! that lacks it. What arrives says the same of the Mac (`Arrival`): each of `KEEPS` is not
//! kept while the latest line of a kind that marks it lacks its key, kept and never filled
//! while lines carry the key and none a value, arriving from the first line that gave one, and
//! no longer arriving once as many lines in a row as its mark allows gave none (`MARKS`);
//! before any line, not yet known. Only the lines of the file the collector is writing now
//! speak of it (`writing`), so lines an earlier or later collector left in other files, read in
//! whatever order, never do. Only the core's reading tells it, since only it reads every file to
//! its end; `immune matches` gives what the latest one stored. A rule that reads one watches
//! only while it arrives, and is otherwise named as not watching, with which.

use crate::sigma::{Match, Meta, Rules, Subject};
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
/// The tidy job's launch daemon. Its fourth argument is the cap of the log in bytes, which only
/// the installer writes there.
pub const TIDY_PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.event-tidy.plist";
/// Why the cap of the log is not known while the collector is installed and its tidy job is not.
pub const NO_TIDY: &str = "the tidy job's launch daemon is not installed, so nothing keeps the log under a cap; installing the event level again puts it back";
/// The file events collected, as `eslogger` names them.
pub const FILE_KINDS: [&str; 2] = ["create", "rename"];
/// Why file events are not counted as collected, in the program's words.
pub const STARTS_ONLY: &str = "the collector installed here records program starts only; installing the event level again adds files created and renamed";
pub const REPLACED: &str = "the collector's launch daemon was replaced after the record of what it collects was written, so file events are not counted as collected; installing the event level again settles it";
/// What a collector may keep beyond what the first one kept, by the names the status and the
/// contract give them, each with what it is in a person's words:
/// - `identity`: the pid version and start time of a program started and of the process that
///   acted, in a program start and in a file event, and the pid and pid version of the parent;
/// - `script`: the script a program start names;
/// - `signature`: the code-signing flags of a program started and of the program before it,
///   and the signing id of a program that created or renamed a file.
pub const KEEPS: [(&str, &str); 3] = [
    ("identity", "who each process is"),
    ("script", "the script a program start runs"),
    ("signature", "code-signing details"),
];
/// A set of `KEEPS`, one bit for each in their order.
pub type Keeps = u8;
pub const IDENTITY: Keeps = 1;
pub const SCRIPT: Keeps = 2;
pub const SIGNATURE: Keeps = 4;
#[cfg(test)]
pub const ALL_KEPT: Keeps = IDENTITY | SCRIPT | SIGNATURE;
/// Where a line marks each of `KEEPS`, by the kind of event it is about: a program start carries
/// all three, a file event who the process that acted is and its signer. Each is marked by one
/// key, which the filter that keeps it writes on every line of the kind, null when eslogger gave
/// nothing: `event.exec.target.start_time`, `event.exec.script` and
/// `event.exec.target.codesigning_flags` in a program start; `process.start_time` and
/// `process.signing_id` in a file event. That last one is the field a rule reads
/// (`ECS_KEPT`), so whether it arrives is decided by the field itself.
///
/// Each mark also says how many lines of its kind in a row that carry the key and no value tell
/// that the collector no longer fills it (`Arrival::NoLonger`). The rule is how often eslogger
/// fills the field by nature. A start time, an audit token and code-signing flags belong to
/// every process, and a signing id to all code that runs natively on Apple silicon, which is
/// signed at least ad hoc: on the first install on a Mac each was filled on all 1,060 program
/// starts and 483 file events, so one line without a value is the collector not filling it. An
/// unsigned Intel program run by Rosetta has no signing id, and a file it creates makes the
/// signer of file events not arrive until the next file event that gives one. A script
/// belongs only to an interpreter started on a script file: 33 of those 1,060 starts, about one
/// in 32, gave one. A thousand starts in a row without one, about thirty times that gap, tell
/// that it stopped. A Mac that runs no script for longer is told the same: not watching, which
/// is never calm, until the next script arrives. The lines counted are those of the file the
/// collector is writing, as the core reads it (`writing`): a reading that finds new lines in two
/// files, across a new file, counts only the newer one's, so a run that crosses the turn of a
/// file is told up to that file's starts later.
pub const MARKS: [(crate::sigma::Kind, Keeps, u64); 5] = [
    (crate::sigma::Kind::Process, IDENTITY, 1),
    (crate::sigma::Kind::Process, SCRIPT, 1000),
    (crate::sigma::Kind::Process, SIGNATURE, 1),
    (crate::sigma::Kind::File, IDENTITY, 1),
    (crate::sigma::Kind::File, SIGNATURE, 1),
];
/// Why a rule that reads one of `KEEPS` does not watch, by what the lines say of it
/// (`Arrival`), in the program's words.
pub const NOT_KEPT: &str = "the lines the collector installed here writes do not carry it: it is an earlier collector, and installing the event level again adds it";
pub const NEVER_FILLED: &str =
    "the collector installed here keeps it, and no line read has carried a value for it yet";
pub const NO_LONGER: &str = "the collector installed here keeps it, and lines gave values for it and then stopped: the latest ones read carry none, as when a macOS update changed the field, or a Mac runs nothing that has it";
pub const NOT_YET_KNOWN: &str = "no line that would carry it has been read yet, so whether the collector installed here keeps it is not yet known";
/// Why a rule that reads one of `KEEPS` judged only some of the lines an answer of `immune
/// matches` read, whatever the core's latest reading says arrives (`Lacked`).
pub const NOT_IN_LINES: &str = "some lines this answer read do not give it: they lack it, as an earlier collector writes them, or carry it with no value; the rule judged none of them by it";
/// The fields rules are given that only a collector that keeps one of `KEEPS` fills, by the
/// kind of event, the field's name under the Elastic Common Schema, and what fills it. A rule
/// that reads one is not asked about a line whose collector did not keep it, and watches only
/// while values of it arrive (`Arrival`); otherwise it is named as not watching, with which.
pub const ECS_KEPT: [(crate::sigma::Kind, &str, Keeps); 1] = [(
    crate::sigma::Kind::File,
    "process.code_signature.signing_id",
    SIGNATURE,
)];
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
/// The log files: `exec-<run>-<start>.jsonl`, or an earlier collector's `exec-YYYYMMDDTHH.jsonl`
/// (`Key`).
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
-- Which finding each match of a rule that raises one went to, so `immune matches` says it
-- exactly: the line, by its log file's name and inode and the offset where it begins; the rule
-- by its name, its set and its id; and the finding. Only rules marked high or critical raise
-- one. A row of a log file the reading no longer finds is removed, so a row lives as long as its
-- line.
CREATE TABLE IF NOT EXISTS rule_line (
    file    TEXT NOT NULL,
    inode   INTEGER NOT NULL,
    offset  INTEGER NOT NULL,
    rule    TEXT NOT NULL,
    finding TEXT NOT NULL REFERENCES finding (id),
    PRIMARY KEY (file, inode, offset, rule)
) WITHOUT ROWID;
-- Where each log file had been read up to when this store began keeping rule_line: a match on
-- a line before that went to a finding the store cannot name. Removed with its file.
CREATE TABLE IF NOT EXISTS rule_line_from (
    file   TEXT NOT NULL,
    inode  INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    PRIMARY KEY (file, inode)
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
-- An earlier build kept what the installer's record said the collector keeps; lines say it now.
DROP TABLE IF EXISTS event_kept;
-- What the lines read say of each of `KEEPS`, by kind of event (`MARKS`): a row once a line of
-- the kind was read, none before.
CREATE TABLE IF NOT EXISTS event_arrival (
    kind   TEXT NOT NULL,     -- program_start or file_event
    keep   TEXT NOT NULL,     -- identity, script or signature
    kept   INTEGER NOT NULL,  -- whether the latest line of the kind holds its key
    filled INTEGER,           -- while it arrives, the time of the first line that gave it a value
    stopped INTEGER,          -- when it no longer arrives, since when
    quiet  INTEGER NOT NULL DEFAULT 0,  -- while it arrives, lines in a row since without a value
    quiet_from INTEGER,       -- and the time of the first of them
    PRIMARY KEY (kind, keep)
);
-- The filter's markers read whose number in eslogger's numbering no gap has taken in yet.
CREATE TABLE IF NOT EXISTS event_marks (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    pending INTEGER NOT NULL
);
-- The cap of the log, as the latest reading of an installed collector found it in the tidy
-- job's launch daemon: its bytes, or why it could not be read.
CREATE TABLE IF NOT EXISTS event_cap (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    bytes INTEGER,  -- NULL when it could not be read
    why   TEXT      -- the program's words, NULL when it was read
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
///
/// What a collector that keeps `KEEPS` adds is in `who`, and no rule is given it.
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
    pub who: Box<Who>,
    /// Which of `KEEPS` the collector that wrote the line kept.
    pub kept: Keeps,
}

/// Who the processes of a program start are, the script and the code-signing flags: what a
/// collector that keeps `KEEPS` adds to a start, each absent where the line does not give it.
///
/// | eslogger | here |
/// |---|---|
/// | the pidversion of `event.exec.target.audit_token`, `.start_time` | `pid_version`, `started` |
/// | `event.exec.target.parent_audit_token` | `parent` |
/// | `process.audit_token`, `process.start_time` | `instigator` |
/// | `event.exec.script.path` | `script` |
/// | `event.exec.target.codesigning_flags`, `process.codesigning_flags` | `codesigning_flags`, `instigator_codesigning_flags` |
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Who {
    pub pid_version: Option<i64>,
    /// When the process started, as eslogger writes it.
    pub started: Option<String>,
    pub parent: Identity,
    /// The same process before this `exec`.
    pub instigator: Identity,
    pub script: Option<String>,
    pub codesigning_flags: Option<i64>,
    pub instigator_codesigning_flags: Option<i64>,
}

/// Who a process is, as far as a line of the log says: its pid and the pid's version, from an
/// audit token, and when it started. Each is absent where the line does not give it, or gives
/// it in a shape this reader does not know.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Identity {
    pub pid: Option<i64>,
    pub pid_version: Option<i64>,
    pub started: Option<String>,
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

/// The last component of a path, as Elastic's `process.name` and `file.name` give it.
fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// What follows the last dot of a file's name, as Elastic's `file.extension` gives it: none
/// when the name has no dot, begins with its only one, or ends with one.
fn extension(name: &str) -> Option<&str> {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => Some(&name[i + 1..]),
        _ => None,
    }
}

/// The fields a program start gives the rules translated from Elastic's, under the Elastic
/// Common Schema's names, and how each is taken. The translation into Sigma was checked on
/// events built exactly this way (`rules/elastic/NOTICE`), so this is the mapping it rests on.
/// Each is filled from what the event level records, as far as Elastic's own rules for macOS
/// show how Elastic Defend fills it; how Elastic fills `process.name` and `process.command_line`
/// on macOS is not documented, and these are assumptions, said in `docs/event-level.md`. Every
/// text is also given folded (`crate::sigma::ECS`). `process.args_count` is a number.
pub const ECS_FIELDS: [(&str, Take); 11] = [
    // What Elastic Defend writes for every program start on macOS, as Elastic's rules ask for
    // it: `event.type == "start" and event.action == "exec"`.
    ("event.type", |_| Some("start".into())),
    ("event.action", |_| Some("exec".into())),
    ("process.executable", |s| Some(s.executable.clone())),
    ("process.name", |s| {
        Some(basename(&s.executable).to_string())
    }),
    // Elastic's `process.args` is an array, and a Sigma field holds one value. The arguments
    // are one text here, each preceded by NUL and the last followed by one, so that a
    // translated rule finds one argument whole between two NULs, or its start after one. Absent
    // when there are none, as Elasticsearch treats an empty array.
    ("process.args", |s| {
        (!s.args.is_empty()).then(|| {
            let mut text = String::from("\0");
            for a in &s.args {
                text.push_str(a);
                text.push('\0');
            }
            text
        })
    }),
    ("process.args_count", |s| Some(s.args.len().to_string())),
    // The arguments joined by single spaces, as `CommandLine` is.
    ("process.command_line", |s| Some(s.args.join(" "))),
    // The image before the `exec`, as `ParentImage` is: the parent's program after a fork or
    // `posix_spawn`, the wrapper after an `exec` without a fork.
    ("process.parent.executable", |s| s.parent_executable.clone()),
    ("process.parent.name", |s| {
        s.parent_executable
            .as_deref()
            .map(|p| basename(p).to_string())
    }),
    ("process.working_directory", |s| s.working_directory.clone()),
    // The effective user id, as text, as Elastic gives it.
    ("user.id", |s| s.user_id.map(|u| u.to_string())),
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
///
/// A collector that keeps `KEEPS` also gives who the program that did it is, from
/// `process.audit_token` and `process.start_time` (`instigator`), and its signing id,
/// `process.signing_id` (`signing_id`), which Elastic's rules read as
/// `process.code_signature.signing_id`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileEvent {
    pub timestamp: String,
    /// `create` or `rename`, one of `FILE_KINDS`.
    pub action: &'static str,
    pub path: String,
    pub source: Option<String>,
    pub executable: String,
    pub instigator: Identity,
    pub signing_id: Option<String>,
    /// Which of `KEEPS` the collector that wrote the line kept.
    pub kept: Keeps,
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

/// The fields a file event gives the rules translated from Elastic's, as `ECS_FIELDS` does for
/// a program start. The path is given as Endpoint Security gives it, and only so: the translation
/// was checked without a second name through macOS's links into `/private`, and Elastic's rules
/// write `/private/...` where they mean it.
pub const FILE_ECS_FIELDS: [(&str, FileTake); 8] = [
    // What Elastic Defend writes for a file created, and for one renamed.
    ("event.type", |f, _| {
        Some(
            if f.action == "rename" {
                "change"
            } else {
                "creation"
            }
            .into(),
        )
    }),
    ("event.action", |f, _| {
        Some(
            if f.action == "rename" {
                "rename"
            } else {
                "creation"
            }
            .into(),
        )
    }),
    ("file.path", |_, name| Some(name.to_string())),
    ("file.name", |_, name| Some(basename(name).to_string())),
    ("file.extension", |_, name| {
        extension(basename(name)).map(str::to_string)
    }),
    ("process.executable", |f, _| Some(f.executable.clone())),
    ("process.name", |f, _| {
        Some(basename(&f.executable).to_string())
    }),
    // The signing id of the program that did it, as Endpoint Security gives it: Elastic's
    // `process.code_signature.signing_id`, "the identifier used to sign the process", on a
    // file event. Only a collector that keeps `SIGNATURE` writes it (`ECS_KEPT`).
    ("process.code_signature.signing_id", |f, _| {
        f.signing_id.clone()
    }),
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
    /// The filter's marker, `{"unreadable":true}`: a message of eslogger it could not read or
    /// shape (`scripts/event-level/filter.jq`). Counted as a line that could not be read, and
    /// the number it took in eslogger's numbering is not counted as lost by the kernel.
    Marker,
}

/// Reads one line. `Err` says the format changed: a message without a field this reader
/// needs, or with a `schema_version` it does not know. That fails the reading.
pub fn line(bytes: &[u8]) -> Result<Line, String> {
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(Line::Unreadable);
    };
    if m.get("unreadable") == Some(&Value::Bool(true)) && !m.contains_key("event") {
        return Ok(Line::Marker);
    }
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
    let process = m.get("process");
    let has = |key: &str| process.and_then(|p| p.get(key)).is_some();
    Some(FileEvent {
        timestamp: m.get("time")?.as_str()?.to_string(),
        action,
        path: path(e.get("destination"))?,
        source: match action {
            "rename" => Some(path(e.get("source"))?),
            _ => None,
        },
        executable: path(process.and_then(|p| p.pointer("/executable/path")))?,
        instigator: process.map(identity).unwrap_or_default(),
        signing_id: text(process.and_then(|p| p.get("signing_id"))),
        kept: kept(&[
            (has("start_time"), IDENTITY),
            (has("signing_id"), SIGNATURE),
        ]),
    })
}

/// A text, or absent for anything else.
fn text(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

/// Which of `KEEPS` a line's collector kept, from the keys the line holds: the filter that keeps
/// one writes its key on every line, null when eslogger gave nothing, and an earlier filter
/// never writes it.
fn kept(marks: &[(bool, Keeps)]) -> Keeps {
    marks
        .iter()
        .filter(|(has, _)| *has)
        .fold(0, |kept, (_, k)| kept | k)
}

/// Which of `KEEPS` a program start gives a value for, by the keys that mark them (`MARKS`).
fn filled_start(s: &ProcessStart) -> Keeps {
    kept(&[
        (s.who.started.is_some(), IDENTITY),
        (s.who.script.is_some(), SCRIPT),
        (s.who.codesigning_flags.is_some(), SIGNATURE),
    ])
}

/// Which of `KEEPS` a file event gives a value for, by the keys that mark them (`MARKS`).
fn filled_file(f: &FileEvent) -> Keeps {
    kept(&[
        (f.instigator.started.is_some(), IDENTITY),
        (f.signing_id.is_some(), SIGNATURE),
    ])
}

/// When a line happened, in seconds, as its time gives it, or else `now`.
fn second_of(timestamp: &str, now: i64) -> i64 {
    instant(timestamp).map_or(now, |(secs, _)| secs)
}

/// Who a process eslogger describes is: the pid and pid version of its `audit_token` and its
/// `start_time`, each absent when the line does not give it as eslogger writes it.
fn identity(process: &Value) -> Identity {
    let (pid, pid_version) = other_token(process.get("audit_token"));
    Identity {
        pid,
        pid_version,
        started: text(process.get("start_time")),
    }
}

/// The pid and pid version of an audit token that is not the one a program start needs: as an
/// object, or as the eight words of `audit_token_t` (`token`); any other shape gives neither,
/// and fails nothing.
fn other_token(v: Option<&Value>) -> (Option<i64>, Option<i64>) {
    match v {
        Some(Value::Object(m)) => (
            m.get("pid").and_then(Value::as_i64),
            m.get("pidversion").and_then(Value::as_i64),
        ),
        Some(Value::Array(words)) if words.len() == 8 => (words[5].as_i64(), words[7].as_i64()),
        _ => (None, None),
    }
}

/// The program start an `exec` message describes, or the name of a field it needs and lacks.
fn start(v: &Value) -> Result<ProcessStart, &'static str> {
    const ARGS: &str = "event.exec.args";
    const TOKEN: &str = "event.exec.target.audit_token";
    let exec = v.pointer("/event/exec").ok_or("event.exec")?;
    let target = exec.get("target").ok_or("event.exec.target")?;
    let token = token(target.get("audit_token").ok_or(TOKEN)?).ok_or(TOKEN)?;
    let instigator = v.get("process");
    let has = |v: &Value, key: &str| v.get(key).is_some();
    let (parent_pid, parent_version) = other_token(target.get("parent_audit_token"));
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
        who: Box::new(Who {
            pid_version: token.2,
            started: text(target.get("start_time")),
            parent: Identity {
                pid: parent_pid,
                pid_version: parent_version,
                started: None,
            },
            instigator: instigator.map(identity).unwrap_or_default(),
            script: text(exec.pointer("/script/path")),
            codesigning_flags: target.get("codesigning_flags").and_then(Value::as_i64),
            instigator_codesigning_flags: instigator
                .and_then(|p| p.get("codesigning_flags"))
                .and_then(Value::as_i64),
        }),
        kept: kept(&[
            (has(target, "start_time"), IDENTITY),
            (has(exec, "script"), SCRIPT),
            (has(target, "codesigning_flags"), SIGNATURE),
        ]),
    })
}

/// The pid, effective user id and pid version of an audit token. `eslogger` writes it as an
/// object with named fields, and in some builds as the eight words of `audit_token_t`, in the
/// order OpenBSM's `audit_token_to_*` read them: auid, euid, egid, ruid, rgid, pid, asid,
/// pidversion. Mullvad's parser accepts both the same way.
fn token(v: &Value) -> Option<(i64, Option<i64>, Option<i64>)> {
    match v {
        Value::Object(m) => Some((
            m.get("pid")?.as_i64()?,
            m.get("euid").and_then(Value::as_i64),
            m.get("pidversion").and_then(Value::as_i64),
        )),
        Value::Array(words) if words.len() == 8 => {
            Some((words[5].as_i64()?, words[1].as_i64(), words[7].as_i64()))
        }
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
    /// For a rule that raises a finding, where every line it matched is, so that the store keeps
    /// which finding each went to (`rule_line`).
    pub lines: Vec<LineAt>,
}

/// An event a finding rests on: a rule is about one kind, so its finding keeps one kind.
#[derive(Clone, Debug, PartialEq)]
pub enum Evidence {
    Start(ProcessStart),
    File(FileEvent),
}

impl Matched {
    /// Counts what one event, the line at `at`, matched, as `Into::judge` evaluated it.
    fn add(&mut self, matches: &[Match<'static>], subject: Subject, at: &LineAt) {
        for m in matches {
            let hits = self.rules.entry(m.meta.id.as_str()).or_insert(Hits {
                meta: m.meta,
                count: 0,
                latest: VecDeque::new(),
                lines: Vec::new(),
            });
            hits.count += 1;
            if m.meta.raises() {
                hits.lines.push(at.clone());
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
    /// What the lines say of each of `KEEPS`, after the last line read.
    arrivals: Arrivals,
    /// The filter's markers no gap has taken in yet.
    pending: u64,
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
    arrivals: Arrivals,
    pending: u64,
}

/// Reads the log under `root` from where `left` says, at `now`, and evaluates every program
/// start read against `rules`.
fn look(root: &Path, left: &Left, now: i64, rules: &'static Rules) -> Found {
    let opened = match open(root) {
        Ok(opened) => opened,
        Err(None) => return Found::NotInstalled,
        Err(Some(why)) => return Found::Failed(why),
    };
    let Opened {
        installed_at,
        collects,
        dir,
        files: listed,
        ..
    } = opened;
    let mut tally = Tally::default();
    let mut file_tally = FileTally::default();
    let mut matched = Matched::default();
    if let Err(e) = removed(&dir, left, &mut tally) {
        return Found::Failed(format!("{REMOVED} in the event level's log: {e}"));
    }
    let mut last_seq = left.last_seq;
    let mut file_seq = left.file_seq;
    let mut arrivals = left.arrivals;
    let mut pending = left.pending;
    let mut version = None;
    let mut files = Vec::new();
    let mut times = Vec::new();
    let now_written = writing(&listed, |f| left.files.get(&f.name).copied());
    for (i, f) in listed.iter().enumerate() {
        let name = &f.name;
        let mut into = Into {
            tally: &mut tally,
            file_tally: &mut file_tally,
            last_seq: &mut last_seq,
            file_seq: &mut file_seq,
            version: &mut version,
            arrivals: (now_written == Some(i)).then_some(&mut arrivals),
            lacked: None,
            pending: &mut pending,
            now,
            rules,
            matched: &mut matched,
            file: String::new(),
            inode: 0,
            queue: None,
        };
        // The same file is read on from where it was left; another file of that name, or one
        // shorter than what was read, from its start.
        let from = |meta: &std::fs::Metadata| match left.files.get(name) {
            Some((inode, offset)) if *inode == meta.ino() && *offset <= meta.len() => *offset,
            _ => 0,
        };
        match read_file(&dir, name, from, f.over, &mut into) {
            Ok(Some(f)) => {
                times.push(f.mtime);
                files.push((name.clone(), f.inode, f.to));
            }
            // Deleted by the root side between the listing and now.
            Ok(None) => {}
            Err(why) => return Found::Failed(why),
        }
    }
    let written = times.iter().copied().max();
    let (state, said) = judge(&dir, installed_at, times, now);
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
        arrivals,
        pending,
    }))
}

/// The cap of the log under `root`, in bytes, as the installed tidy job is given it: the fourth
/// argument of its launch daemon, read by Apple's `plutil`. A launch daemon that is there and
/// cannot be read, or whose argument is not a whole number of bytes, is a failed reading with
/// its reason, never a guess.
///
/// The cap is read only from that launch daemon, which belongs to root and which only the
/// installer writes. No file or setting a program running as the user can change sets it: a
/// cap such a program could shrink would let it empty the log, and that is quieting.
fn log_cap(root: &Path) -> Result<u64, String> {
    use std::sync::Mutex;
    let path = root.join(TIDY_PLIST);
    let failed = |e: &dyn std::fmt::Display| {
        format!("the cap of the event level's log could not be read: {e}")
    };
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_TIDY.to_string()),
        Err(e) => return Err(failed(&e)),
    };
    // `immune watch` reads the log every few seconds, and `plutil` started each time would be a
    // program start the collector records: the answer is kept while the file is the same.
    type Seen = Option<(
        (std::path::PathBuf, u64, i64, i64, u64),
        Result<u64, String>,
    )>;
    static SEEN: Mutex<Seen> = Mutex::new(None);
    let key = (
        path.clone(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.len(),
    );
    if let Ok(seen) = SEEN.lock()
        && let Some((k, cap)) = seen.as_ref()
        && *k == key
    {
        return cap.clone();
    }
    let out = std::process::Command::new(crate::integrity::PLUTIL)
        .args(["-extract", "ProgramArguments", "json", "-o", "-"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .output();
    let cap = match out {
        Err(e) => Err(failed(&e)),
        Ok(out) if !out.status.success() => Err(failed(&format!(
            "plutil: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
        Ok(out) => serde_json::from_slice::<Value>(&out.stdout)
            .ok()
            .and_then(|v| v.get(3).and_then(Value::as_str).and_then(bytes_of))
            .ok_or_else(|| {
                failed(&"its fourth argument is not a cap tidy.sh takes, a whole number of bytes of at least 1 GiB")
            }),
    };
    // A failure is not kept: the next reading runs plutil again.
    if let Ok(mut seen) = SEEN.lock() {
        *seen = cap.as_ref().ok().map(|bytes| (key, Ok(*bytes)));
    }
    cap
}

/// A cap as tidy.sh takes one: digits only, so no sign, without a leading zero, at most 16 of
/// them, and at least 1 GiB, the smallest the installer writes. tidy.sh refuses anything else
/// and deletes nothing to keep the log under it.
fn bytes_of(text: &str) -> Option<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let form = digits && text.len() <= 16 && !text.starts_with('0');
    form.then(|| text.parse().ok())
        .flatten()
        .filter(|n| *n >= 1 << 30)
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

/// What the lines read so far say of one of `KEEPS` in one kind of event (`MARKS`). Kept is
/// decided by what arrives, never by a record: a field counts only once a line carried a value
/// for it, and goes on counting only while lines go on giving values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Arrival {
    /// No line of the kind has been read.
    #[default]
    Unknown,
    /// The latest line of the kind lacks its key: the collector that wrote it does not keep it.
    NotKept,
    /// Lines carry its key; with the time of the first line that gave it a value since it last
    /// did not arrive, while it arrives. Without one, the collector keeps it and eslogger has
    /// filled it in no line since the key appeared.
    Kept(Option<i64>),
    /// Lines carry its key and gave it values, and then as many lines in a row as its mark
    /// allows (`MARKS`) gave none: it no longer arrives, since the time of the first of them.
    /// As when a macOS update renames the field or changes its shape, which the filter then
    /// writes as null.
    NoLonger(i64),
}

/// The lines of a kind read in a row that carry a key and no value under it, since the last
/// that gave one, and the time of the first of them: how far an arriving field is from being
/// told as no longer arriving.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Quiet {
    lines: u64,
    from: i64,
}

impl Arrival {
    /// What a line of the kind, at `t`, says after what was said before: whether it holds the
    /// key, and whether a value under it. A line without the key starts it again. `quiet` is
    /// the run of lines without a value so far, and `most` how long a run tells it stopped.
    fn after(self, quiet: &mut Quiet, most: u64, has: bool, filled: bool, t: i64) -> Arrival {
        let state = match (has, filled, self) {
            (false, _, _) => Arrival::NotKept,
            (true, true, Arrival::Kept(Some(since))) => Arrival::Kept(Some(since)),
            (true, true, _) => Arrival::Kept(Some(t)),
            (true, false, Arrival::Kept(Some(since))) => {
                if quiet.lines == 0 {
                    quiet.from = t;
                }
                quiet.lines = quiet.lines.saturating_add(1);
                if quiet.lines < most {
                    return Arrival::Kept(Some(since));
                }
                Arrival::NoLonger(quiet.from)
            }
            (true, false, Arrival::NoLonger(from)) => Arrival::NoLonger(from),
            (true, false, _) => Arrival::Kept(None),
        };
        *quiet = Quiet::default();
        state
    }

    /// How far it is from arriving: what a rule that reads it is named with when they differ.
    fn distance(self) -> u8 {
        match self {
            Arrival::NotKept => 4,
            Arrival::Unknown => 3,
            Arrival::Kept(None) => 2,
            Arrival::NoLonger(_) => 1,
            Arrival::Kept(Some(_)) => 0,
        }
    }

    /// Why a rule that reads it does not watch, in the program's words; `None` while it arrives.
    pub fn why(self) -> Option<&'static str> {
        match self {
            Arrival::NotKept => Some(NOT_KEPT),
            Arrival::Unknown => Some(NOT_YET_KNOWN),
            Arrival::Kept(None) => Some(NEVER_FILLED),
            Arrival::NoLonger(_) => Some(NO_LONGER),
            Arrival::Kept(Some(_)) => None,
        }
    }

    /// Its stable name in the status, beside a rule that does not watch.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Arrival::NotKept => Some("collector_does_not_keep"),
            Arrival::Unknown => Some("not_yet_known"),
            Arrival::Kept(None) => Some("kept_never_filled"),
            Arrival::NoLonger(_) => Some("no_longer_arriving"),
            Arrival::Kept(Some(_)) => None,
        }
    }
}

/// What the lines read so far say of each of `KEEPS` in each kind of event, in the order of
/// `MARKS`, and for each the run of lines without a value since the last that gave one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arrivals(pub [Arrival; 5], [Quiet; 5]);

impl From<[Arrival; 5]> for Arrivals {
    fn from(states: [Arrival; 5]) -> Arrivals {
        Arrivals(states, Default::default())
    }
}

impl Arrivals {
    /// Takes in one line of `kind` at `t`: which of `KEEPS` it holds the key of, and which a
    /// value under.
    fn line(&mut self, kind: crate::sigma::Kind, kept: Keeps, filled: Keeps, t: i64) {
        for ((a, quiet), (k, keep, most)) in self.0.iter_mut().zip(&mut self.1).zip(MARKS) {
            if k == kind {
                *a = a.after(quiet, most, kept & keep != 0, filled & keep != 0, t);
            }
        }
    }

    /// What the lines say of one of `KEEPS`: of the kinds that mark it, the one furthest from
    /// arriving; arriving only when it arrives in each, since the latest of them began to; no
    /// longer arriving since the first of them stopped.
    pub fn of(&self, keep: Keeps) -> Arrival {
        self.0
            .iter()
            .zip(MARKS)
            .filter(|(_, (_, k, _))| *k == keep)
            .map(|(a, _)| *a)
            .reduce(|a, b| match (a, b) {
                (Arrival::Kept(Some(x)), Arrival::Kept(Some(y))) => Arrival::Kept(Some(x.max(y))),
                (Arrival::NoLonger(x), Arrival::NoLonger(y)) => Arrival::NoLonger(x.min(y)),
                _ if b.distance() > a.distance() => b,
                _ => a,
            })
            .unwrap_or_default()
    }

    /// Of a set of `KEEPS`, the one furthest from arriving, as a rule that reads them all is
    /// named with.
    pub fn worst(&self, keeps: Keeps) -> Arrival {
        of(keeps)
            .map(|(name, _)| self.of(keeps_named(&[name])))
            .max_by_key(|a| a.distance())
            .unwrap_or(Arrival::Kept(Some(0)))
    }

    /// What of `KEEPS` does not arrive: a rule that reads it does not watch.
    pub fn not_arriving(&self) -> Keeps {
        (0..KEEPS.len())
            .map(|i| 1 << i)
            .filter(|keep| !matches!(self.of(*keep), Arrival::Kept(Some(_))))
            .fold(0, |set, keep| set | keep)
    }

    /// The names of `KEEPS` the lines say this of, in their order.
    pub fn named(&self, state: impl Fn(Arrival) -> bool) -> Vec<&'static str> {
        KEEPS
            .iter()
            .enumerate()
            .filter(|(i, _)| state(self.of(1 << i)))
            .map(|(_, (name, _))| *name)
            .collect()
    }

    /// The names of `KEEPS` that arrive, each with the time since when.
    pub fn arriving(&self) -> Vec<(&'static str, i64)> {
        self.timed(|a| match a {
            Arrival::Kept(Some(since)) => Some(since),
            _ => None,
        })
    }

    /// The names of `KEEPS` that no longer arrive, each with the time since when.
    pub fn no_longer(&self) -> Vec<(&'static str, i64)> {
        self.timed(|a| match a {
            Arrival::NoLonger(since) => Some(since),
            _ => None,
        })
    }

    /// The names of `KEEPS` whose state gives a time, with it.
    fn timed(&self, time: impl Fn(Arrival) -> Option<i64>) -> Vec<(&'static str, i64)> {
        KEEPS
            .iter()
            .enumerate()
            .filter_map(|(i, (name, _))| Some((*name, time(self.of(1 << i))?)))
            .collect()
    }
}

/// Of each of `MARKS`, whether some line of its kind that a stretch judged did not give it: a
/// line without its key, whose collector did not keep it, so a rule that reads it was not asked
/// about the line; and for a mark whose bound is one line, a field every process has, a line
/// with the key and no value, which the rule was asked about without it. A script is given by a
/// few starts by nature, so a start without one counts only when it lacks the key. What a rule
/// judged is a fact of the lines read, whatever the store says arrives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lacked([bool; 5]);

impl Lacked {
    /// Takes in one judged line of `kind`: which of `KEEPS` it holds the key of, and which a
    /// value under.
    fn line(&mut self, kind: crate::sigma::Kind, kept: Keeps, filled: Keeps) {
        for (lacked, (k, keep, most)) in self.0.iter_mut().zip(MARKS) {
            if k == kind && (kept & keep == 0 || (most == 1 && filled & keep == 0)) {
                *lacked = true;
            }
        }
    }

    /// What of `KEEPS` some judged line of `kind` did not give.
    pub fn of(&self, kind: crate::sigma::Kind) -> Keeps {
        self.0
            .iter()
            .zip(MARKS)
            .filter(|(lacked, (k, _, _))| **lacked && *k == kind)
            .fold(0, |set, (_, (_, keep, _))| set | keep)
    }
}

/// The set of `KEEPS` these names name; a name it does not know names nothing.
fn keeps_named(names: &[impl AsRef<str>]) -> Keeps {
    KEEPS
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| names.iter().any(|n| n.as_ref() == *name))
        .fold(0, |keeps, (i, _)| keeps | 1 << i)
}

/// The names of a set of `KEEPS`, in their order.
pub fn names(keeps: Keeps) -> Vec<&'static str> {
    of(keeps).map(|(name, _)| *name).collect()
}

/// The `KEEPS` in a set, in their order.
fn of(keeps: Keeps) -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    KEEPS
        .iter()
        .enumerate()
        .filter(move |(i, _)| keeps & (1 << i) != 0)
        .map(|(_, k)| k)
}

/// The root side's notes of what it deleted, `<when> <file> <bytes> age|cap` a line; a note
/// not in that form is skipped. Empty when it has deleted nothing.
fn notes(dir: &Path) -> std::io::Result<Vec<(i64, String, u64, String)>> {
    let text = match std::fs::read_to_string(dir.join(REMOVED)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .filter_map(|note| {
            let words: Vec<&str> = note.split(' ').collect();
            let [when, name, bytes, why] = words[..] else {
                return None;
            };
            Some((
                when.parse().ok()?,
                name.to_string(),
                bytes.parse().ok()?,
                why.to_string(),
            ))
        })
        .collect())
}

/// Counts what the root side's notes say it deleted since the last reading: files deleted to
/// stay under the size cap, and files deleted before this reader read them to their end.
fn removed(dir: &Path, left: &Left, tally: &mut Tally) -> std::io::Result<()> {
    for (when, name, bytes, why) in notes(dir)? {
        if left.counted.is_some_and(|at| when <= at) {
            continue;
        }
        if why == "cap" {
            tally.removed_cap += 1;
        }
        if left
            .files
            .get(&name)
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
    /// What the lines say of each of `KEEPS`, taken on line by line, while the core's reading
    /// reads the file the collector is writing now (`writing`); `None` for any other file, and
    /// always for `immune matches`, which tells what the core's latest reading stored.
    arrivals: Option<&'a mut Arrivals>,
    /// For `immune matches`: what of `KEEPS` the lines it judged did not give.
    lacked: Option<&'a mut Lacked>,
    /// Markers read whose number in eslogger's numbering no gap has taken in yet.
    pending: &'a mut u64,
    /// The time of the reading: a line whose time cannot be read is taken to be of it.
    now: i64,
    rules: &'static Rules,
    matched: &'a mut Matched,
    /// The log file being read, by its name and inode: where each line evaluated is.
    file: String,
    inode: u64,
    /// For `immune matches`: every event that matched, with where its line is, and when to
    /// stop. The core's own reading keeps none.
    queue: Option<&'a mut Sink>,
}

impl Into<'_> {
    /// Evaluates one event against the rules of its kind. This is the one place an event is
    /// evaluated: what the core's reading counts and raises, and what `immune matches` gives,
    /// both come from this call, so the two cannot disagree on what matched. `line` is where
    /// the event's line begins and `len` its length. Returns whether the queue is full.
    fn judge(&mut self, subject: Subject, line: u64, len: usize) -> bool {
        let matches = self.rules.evaluate(subject);
        if matches.is_empty() {
            return false;
        }
        let at = LineAt {
            file: self.file.clone(),
            inode: self.inode,
            offset: line,
        };
        self.matched.add(&matches, subject, &at);
        let Some(q) = self.queue.as_deref_mut() else {
            return false;
        };
        q.matches += matches.len();
        q.bytes += len * matches.len();
        q.hits.push(Hit {
            at,
            event: match subject {
                Subject::Start(s) => Evidence::Start(s.clone()),
                Subject::File(f) => Evidence::File(f.clone()),
            },
            matched: matches.iter().map(|m| (m.file, m.meta)).collect(),
        });
        q.matches >= q.limit || q.bytes >= BYTES
    }
}

/// What a reading of one file from an offset came to.
struct Upto {
    /// The offset after the last whole line read.
    to: u64,
    /// Where the last whole line read begins, when one was read.
    last: Option<u64>,
    /// It stopped because the queue was full, before the end of what the file holds.
    full: bool,
}

/// Reads the whole lines of `file` from `from` on, counts them, evaluates each program start
/// and file event against the rules, and says where it stopped: at the end, at a line still
/// being written, or when the queue is full.
fn read_from(mut file: std::fs::File, from: u64, into: &mut Into) -> Result<Upto, Stop> {
    file.seek(SeekFrom::Start(from)).map_err(Stop::Io)?;
    let mut lines = BufReader::new(file);
    let mut at = from;
    let mut last = None;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = lines.read_until(b'\n', &mut buf).map_err(Stop::Io)?;
        // The end, or a line still being written: left for the next reading.
        if n == 0 || buf.last() != Some(&b'\n') {
            return Ok(Upto {
                to: at,
                last,
                full: false,
            });
        }
        let begins = at;
        at += n as u64;
        last = Some(begins);
        let full = match line(&buf[..n - 1]).map_err(Stop::Schema)? {
            Line::Exec {
                seq,
                version: v,
                start,
            } => {
                let t = &mut *into.tally;
                let counts = (&mut t.lost, &mut t.unknown_gaps);
                count_seq(seq, into.last_seq, counts, into.pending);
                t.starts += 1;
                *into.version = v.or(*into.version);
                if let Some(arrivals) = into.arrivals.as_deref_mut() {
                    arrivals.line(
                        crate::sigma::Kind::Process,
                        start.kept,
                        filled_start(&start),
                        second_of(&start.timestamp, into.now),
                    );
                }
                if let Some(lacked) = into.lacked.as_deref_mut() {
                    let kind = crate::sigma::Kind::Process;
                    lacked.line(kind, start.kept, filled_start(&start));
                }
                into.judge(Subject::Start(&start), begins, n)
            }
            Line::File { kind, seq, event } => {
                let t = &mut *into.file_tally;
                if let Some(seq) = seq {
                    let last = &mut into.file_seq[kind];
                    count_seq(seq, last, (&mut t.lost, &mut t.unknown_gaps), into.pending);
                }
                match event {
                    Some(e) => {
                        t.files += 1;
                        if let Some(arrivals) = into.arrivals.as_deref_mut() {
                            arrivals.line(
                                crate::sigma::Kind::File,
                                e.kept,
                                filled_file(&e),
                                second_of(&e.timestamp, into.now),
                            );
                        }
                        if let Some(lacked) = into.lacked.as_deref_mut() {
                            lacked.line(crate::sigma::Kind::File, e.kept, filled_file(&e));
                        }
                        into.judge(Subject::File(&e), begins, n)
                    }
                    None => {
                        t.unreadable += 1;
                        false
                    }
                }
            }
            Line::Other => {
                into.tally.other += 1;
                false
            }
            Line::Unreadable => {
                into.tally.unreadable += 1;
                false
            }
            Line::Marker => {
                into.tally.unreadable += 1;
                *into.pending += 1;
                false
            }
        };
        if full {
            return Ok(Upto {
                to: at,
                last,
                full: true,
            });
        }
    }
}

/// What a reading of one log file came to.
struct FileRead {
    inode: u64,
    mtime: i64,
    /// Its length when it was read.
    len: u64,
    /// Every byte before this was read.
    to: u64,
    /// Where the last line read begins, a line that could not be read included.
    last: Option<u64>,
    /// It stopped because the queue was full.
    full: bool,
}

/// Reads one log file of `dir` from the offset `from` gives for it, as the core's reading and
/// `immune matches` both do. `over` says that its hour is over (`LogFile::over`). `None` when
/// the root side deleted it between the listing and now. A failure is the reason, in the
/// program's words.
fn read_file(
    dir: &Path,
    name: &str,
    from: impl FnOnce(&std::fs::Metadata) -> u64,
    over: bool,
    into: &mut Into,
) -> Result<Option<FileRead>, String> {
    let failed = |e: &dyn std::fmt::Display| format!("{name} in the event level's log: {e}");
    let file = match std::fs::File::open(dir.join(name)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(failed(&e)),
    };
    let meta = file.metadata().map_err(|e| failed(&e))?;
    let from = from(&meta);
    into.file = name.to_string();
    into.inode = meta.ino();
    let upto = match read_from(file, from, into) {
        Ok(upto) => upto,
        Err(Stop::Io(e)) => return Err(failed(&e)),
        Err(Stop::Schema(why)) => return Err(why),
    };
    let mut read = FileRead {
        inode: meta.ino(),
        mtime: meta.mtime(),
        len: meta.len(),
        to: upto.to,
        last: upto.last,
        full: upto.full,
    };
    // A file of an hour that is over is not written to again. rotatelogs moves to the next
    // hour's file at whatever it read from the pipe, so a line can end in the old file without
    // its newline and go on at the start of the new one: the end left here is counted as a
    // line that could not be read, once.
    if !upto.full && upto.to < meta.len() && over {
        into.tally.unreadable += 1;
        read.last = Some(upto.to);
        read.to = meta.len();
    }
    Ok(Some(read))
}

/// The log as a look at the source finds it: when the collector was installed, whether it is
/// established to record file events, the log folder and its files in the order of their
/// hours, and how many other files the folder holds.
struct Opened {
    installed_at: i64,
    collects: Result<(), (Cause, String)>,
    dir: std::path::PathBuf,
    files: Vec<LogFile>,
    /// Files in the log folder that are not the collector's own, by their names: not read.
    foreign: u64,
}

/// One of the collector's log files, as listed.
struct LogFile {
    name: String,
    /// Where its name puts it in the order files are written (`Key`).
    key: Key,
    /// When it was last written to: seconds, and nanoseconds within the second.
    mtime: (i64, i64),
    /// Its inode and length when it was listed.
    inode: u64,
    len: u64,
    /// It is over: a file later in the order was written to at or after this one was last.
    /// rotatelogs moves to the next file and does not come back, so a line left without its
    /// newline at the end of this one is never finished. The last file is never over, nor one
    /// written after it, as when the clock was set back.
    over: bool,
}

/// Where a log file's name puts it in the order files are written. The collector names a file
/// `exec-<run>-<start>.jsonl`, when its run of the filter began and when the file was started,
/// each `YYYYMMDDTHHMMSS` in UTC (`scripts/event-level/collect.sh`); `run` and `at` are those as
/// numbers, `YYYYMMDDHHMMSS`. An earlier collector named a file by its hour alone,
/// `exec-YYYYMMDDTHH.jsonl`: `run` is 0 and `at` the hour, `YYYYMMDDHH`, so its files come
/// before any of a later collector's, as they were written before it was installed. Ordered by
/// run, then by start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    run: u64,
    at: u64,
}

impl Key {
    /// A key some log file's name can give: an hour of a date for an earlier collector's, a
    /// second of a date for both of a later one's numbers.
    fn real(&self) -> bool {
        match self.run {
            0 => real_hour(self.at),
            run => real_second(run) && real_second(self.at),
        }
    }
}

/// The files the root side writes in the log folder beside the log: what eslogger and the
/// scripts print, and the notes of deletions. tidy.sh shortens each through a copy named with
/// `.new` added.
const SIDE_FILES: [&str; 4] = [ESLOGGER_SAID, SCRIPTS_SAID, REMOVED, "tidy.lock"];

/// The number the digits of `b` write, for bytes that are digits but for a `T` at `t`; `None`
/// for any others.
fn stamp(b: &[u8], t: usize) -> Option<u64> {
    let form = b.iter().enumerate().all(|(i, c)| match i {
        _ if i == t => *c == b'T',
        _ => c.is_ascii_digit(),
    });
    form.then(|| {
        b.iter()
            .filter(|c| c.is_ascii_digit())
            .fold(0, |n, c| n * 10 + u64::from(c - b'0'))
    })
}

/// Where a log file's name puts it (`Key`), for a name in exactly a form a collector writes,
/// of a real date and time; `None` for any other name: such a file is not the collector's and
/// is never read.
fn key_of(name: &str) -> Option<Key> {
    let b = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?.as_bytes();
    let key = match b.len() {
        11 => Key {
            run: 0,
            at: stamp(b, 8)?,
        },
        31 if b[15] == b'-' => Key {
            run: stamp(&b[..15], 8)?,
            at: stamp(&b[16..], 8)?,
        },
        _ => return None,
    };
    key.real().then_some(key)
}

/// Whether `YYYYMMDDHH` is an hour of a date: a month from 1 to 12, a day from 1 to 31, an hour
/// from 0 to 23.
fn real_hour(hour: u64) -> bool {
    let (month, day, h) = (hour / 10_000 % 100, hour / 100 % 100, hour % 100);
    hour < 10_000_000_000 && (1..=12).contains(&month) && (1..=31).contains(&day) && h < 24
}

/// Whether `YYYYMMDDHHMMSS` is a second of a date: an hour of a date, a minute from 0 to 59 and
/// a second from 0 to 60, as `strftime(3)` writes a leap second.
fn real_second(second: u64) -> bool {
    real_hour(second / 10_000) && second / 100 % 100 < 60 && second % 100 <= 60
}

/// The name of the log file a key is of.
fn name_of(key: Key) -> String {
    let stamp = |n: u64| format!("{:08}T{:06}", n / 1_000_000, n % 1_000_000);
    match key.run {
        0 => format!("{PREFIX}{:08}T{:02}{SUFFIX}", key.at / 100, key.at % 100),
        run => format!("{PREFIX}{}-{}{SUFFIX}", stamp(run), stamp(key.at)),
    }
}

/// Which of `files` the collector is writing now, as far as a look can tell: of those holding
/// bytes past where a reading left them (`read`, by inode and offset; a file of another inode is
/// read from its start), the one written last, and of two written at once the later in the
/// order of names. Only its lines say what arrives (`Arrival`). After a downgrade the earlier
/// collector writes files whose names sort first, and the later collector's files, written
/// before, sort after them; names also sort out of the order of writing after a clock was set
/// back. A file nobody writes any more holds nothing new, so from the second reading on only the
/// file being written is a candidate, whatever its name and whatever the clock said. When a
/// reading finds several, at the first reading or across a new file, the time each was last
/// written decides, as `tidy.sh` keeps the one written last.
fn writing(files: &[LogFile], read: impl Fn(&LogFile) -> Option<(u64, u64)>) -> Option<usize> {
    files
        .iter()
        .enumerate()
        .filter(|(_, f)| match read(f) {
            Some((inode, offset)) if inode == f.inode && offset <= f.len => f.len > offset,
            _ => f.len > 0,
        })
        .max_by_key(|(i, f)| (f.mtime, *i))
        .map(|(i, _)| i)
}

/// Looks at the source without reading a line. `Err(None)` is a level not installed, `Err` with
/// a reason one that is there and cannot be read.
fn open(root: &Path) -> Result<Opened, Option<String>> {
    let plist = root.join(PLIST);
    let daemon = match std::fs::metadata(&plist) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(None),
        Err(e) => return Err(Some(format!("the event level's launch daemon: {e}"))),
    };
    let collects = collects(root, &daemon);
    let dir = root.join(LOG);
    let failed = |e: std::io::Error| Some(format!("the event level's log: {e}"));
    let mut files: Vec<LogFile> = Vec::new();
    let mut foreign = 0;
    for entry in std::fs::read_dir(&dir).map_err(failed)? {
        let name = entry.map_err(failed)?.file_name();
        // A log file's name is ASCII, so a name that is not text is another file.
        let name = name.to_string_lossy();
        let Some(key) = key_of(&name) else {
            let side = |s: &&str| name == *s || name.strip_suffix(".new") == Some(*s);
            if !SIDE_FILES.iter().any(side) {
                foreign += 1;
            }
            continue;
        };
        let meta = match std::fs::metadata(dir.join(&*name)) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(failed(e)),
        };
        files.push(LogFile {
            name: name.to_string(),
            key,
            mtime: (meta.mtime(), meta.mtime_nsec()),
            inode: meta.ino(),
            len: meta.len(),
            over: false,
        });
    }
    files.sort_by_key(|f| f.key);
    for i in 0..files.len() {
        files[i].over = files[i + 1..].iter().any(|g| g.mtime >= files[i].mtime);
    }
    Ok(Opened {
        installed_at: daemon.mtime(),
        collects,
        dir,
        files,
        foreign,
    })
}

/// Counts what the sequence number says was lost since the last one of its kind: into `lost`
/// a gap, into `unknown` a number that fell back. A gap first takes in the numbers of the
/// filter's markers read before it (`pending`), which are counted as lines that could not be
/// read and not again as lost. A marker does not say which kind its message was, so the gap
/// it is taken from may be another kind's: the two kinds' losses may then trade one, and the
/// sum is right. A number that fell back is a restart, a loss of unknown size, and takes in
/// every marker before it.
fn count_seq(
    seq: u64,
    last: &mut Option<u64>,
    (lost, unknown): (&mut i64, &mut i64),
    pending: &mut u64,
) {
    if let Some(l) = *last {
        if seq > l + 1 {
            let gap = seq - l - 1;
            let markers = gap.min(*pending);
            *pending -= markers;
            *lost += (gap - markers) as i64;
        } else if seq <= l {
            *unknown += 1;
            *pending = 0;
        }
    }
    *last = Some(seq);
}

/// The state the root side's own evidence gives: refused or failing when `eslogger` or the
/// scripts printed something after the log was last written to, silent when nothing has been
/// written for `SILENT_AFTER` since the last write or, before any, the install, else running.
/// `written` is when each log file was last written to. A time ahead of `now` by more than
/// the clock's allowance (`store::age`) is no sign of life: a file's time can be set ahead, and
/// a clock set back leaves the times written before ahead of it. A time ahead by less is the
/// collector writing while this reading went on, since `now` is when the reading began.
fn judge(
    dir: &Path,
    installed_at: i64,
    written: impl IntoIterator<Item = i64>,
    now: i64,
) -> (&'static str, Option<(&'static str, String)>) {
    let written = written
        .into_iter()
        .filter(|w| crate::store::age(*w, now).is_some())
        .max();
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
    let quiet_since = written.unwrap_or(installed_at);
    if crate::store::age(quiet_since, now).is_none_or(|age| age > SILENT_AFTER) {
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
    // What the collector said, read cut as every reader reads it: this goes into a page's file.
    let form = crate::secrets::form(conn)?;
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
                        r.get::<_, Option<String>>(3)?
                            .map(|s| crate::secrets::Kept::Said.read(form, &s).store()),
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

/// Makes the level's tables in `tx` where they are missing: at every reading, and before a
/// verdict keeps the event it is about (`verdict.rs`).
pub fn schema(tx: &Transaction) -> rusqlite::Result<()> {
    let recorded = has(tx, "rule_line")?;
    tx.execute_batch(SCHEMA)?;
    // A store an earlier build made keeps no run of lines without a value.
    if !has_run(tx)? {
        tx.execute_batch(
            "ALTER TABLE event_arrival ADD COLUMN stopped INTEGER;
             ALTER TABLE event_arrival ADD COLUMN quiet INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE event_arrival ADD COLUMN quiet_from INTEGER;",
        )?;
    }
    if !recorded {
        // The store begins to keep which finding each match went to. What was read before is
        // not in it, and is told apart from a line no finding holds.
        tx.execute(
            "INSERT INTO rule_line_from (file, inode, offset)
             SELECT name, inode, offset FROM event_file",
            [],
        )?;
    }
    Ok(())
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
    schema(tx)?;
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
            tx.execute("DELETE FROM event_arrival", [])?;
            tx.execute("DELETE FROM event_marks", [])?;
            tx.execute("DELETE FROM event_cap", [])?;
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
            put_cap(tx, &log_cap(root))?;
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
            put_arrivals(tx, &log.arrivals)?;
            tx.execute(
                "INSERT INTO event_marks (id, pending) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET pending = excluded.pending",
                [log.pending as i64],
            )?;
            put_cap(tx, &log_cap(root))?;
            opened = record(tx, run_id, machine, now, &log.matched)?;
            // A line of a file the reading no longer finds cannot be asked about again.
            for table in ["rule_line", "rule_line_from"] {
                tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE NOT EXISTS (SELECT 1 FROM event_file e
                             WHERE e.name = {table}.file AND e.inode = {table}.inode)"
                    ),
                    [],
                )?;
            }
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
        if !hits.meta.raises() {
            continue;
        }
        // One finding per rule on this Mac: a repeated match of a rule whose finding stands
        // adds to its count and its examples and raises nothing new.
        let rule = hits.meta.name.as_str();
        let (finding, raised) = crate::findings::occur(tx, rule, machine, "new", run_id, now)?;
        // A journal entry naming the rule and how many starts matched it, never what they were,
        // for every reading that matched it: an answer read before a match joined the finding is
        // refused by it (`findings::unchanged`). The finding rests on the one that raised it.
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
        if raised {
            tx.execute(
                "INSERT INTO finding_basis (finding, journal) VALUES (?1, ?2)",
                params![finding, tx.last_insert_rowid()],
            )?;
            opened += 1;
        }
        let mut line = tx.prepare(
            "INSERT OR REPLACE INTO rule_line (file, inode, offset, rule, finding)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for l in &hits.lines {
            line.execute(params![
                l.file,
                l.inode as i64,
                l.offset as i64,
                rule,
                finding
            ])?;
        }
        keep(tx, &finding, now, hits.count, &hits.latest)?;
    }
    Ok(opened)
}

/// Keeps what one occurrence of a rule found with its finding: how many events, and the latest
/// of them, at most `EVIDENCE`. The core's reading keeps a published rule's here, and a verdict
/// keeps the event it is about (`verdict.rs`).
pub fn keep(
    tx: &Transaction,
    finding: &str,
    now: i64,
    count: i64,
    latest: &VecDeque<Evidence>,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO rule_finding (finding, matches) VALUES (?1, ?2)
         ON CONFLICT (finding) DO UPDATE SET matches = matches + excluded.matches",
        params![finding, count],
    )?;
    for e in latest {
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
                    // Kept cut: a secret on the command line never enters the store.
                    json!(crate::secrets::Args::raw(&s.args).store()).to_string(),
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
    Ok(())
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
/// counts since it was raised; and the latest of them, newest first; and where the rule's set
/// comes from, with its licence, each by its address or identifier and by its name in words.
/// Text from the rule or from an event is only in `_text` fields.
pub fn finding_detail(
    conn: &Connection,
    finding: &str,
    file: &'static str,
    meta: &Meta,
    kind: crate::sigma::Kind,
) -> rusqlite::Result<Value> {
    let mut v = crate::sigma::Match { file, meta, kind }.json();
    v["licence"] = json!(meta.source.licence);
    v["licence_name"] = json!(meta.source.licence_name);
    // Here `source` is where the set comes from, its repository, as the contract's
    // `PublishedRuleMatched.source` has it since version 1.0.0; the set's machine name is the
    // prefix of `name`, and `set` and `source_name` give it in words.
    v["source"] = json!(meta.source.url);
    v["source_name"] = json!(meta.source.set);
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

/// The starts a finding from a published rule keeps, newest first, under ECS's names. The
/// arguments are cut again, so a set newer than the one that kept them applies, before they
/// are escaped and capped; `cuts` lists what was cut, since a mark in this JSON's text can be
/// forged.
fn evidence(conn: &Connection, finding: &str) -> rusqlite::Result<Vec<Value>> {
    let text = |s: Option<String>| s.as_deref().map(crate::status::text);
    let form = crate::secrets::form(conn)?;
    conn.prepare(
        "SELECT timestamp, executable, args, parent_executable, working_directory, pid,
                parent_pid, user_id, signing_id, team_id, platform_binary
         FROM rule_evidence WHERE finding = ?1 ORDER BY rowid DESC",
    )?
    .query_map([finding], |r| {
        let args: Vec<String> = serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default();
        let args = crate::secrets::Args::stored(&args, form);
        Ok(json!({
            "timestamp_text": crate::status::text(&r.get::<_, String>(0)?),
            "executable_text": crate::status::text(&r.get::<_, String>(1)?),
            "args_text": args
                .shown(crate::view::shown)
                .into_iter()
                .map(crate::status::capped)
                .collect::<Vec<_>>(),
            "cuts": args.cuts().iter().map(|c| json!({
                "argument": c.argument, "kind": c.kind, "length": c.length,
            })).collect::<Vec<_>>(),
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

// ---- The queue of matches: `immune matches` reads the log again from a caller's place. ----
//
// The store keeps no event. The queue is the day's log read again, evaluated by the same
// `Into::judge` as the core's own reading, from a place the caller keeps. The place holds what
// the core's own reading keeps for itself in `event_file`: per log file, its identity and how far
// it was read. One point in an ordering of the files by name would not do: a clock set ahead
// leaves a file of a later hour while lines go on into an earlier one, a reinstall within an
// hour starts a file of the same name again, and a file can be deleted before it was read.

/// The most bytes of matched lines one answer of `immune matches` holds, each line counted once
/// for every rule it matched. An argument list is never cut and can be a megabyte, so the
/// count of matches alone does not keep an answer small.
pub const BYTES: usize = 4 << 20;
/// The most log files a place holds. The root side deletes a file not written to for a day, and
/// a file holds at most an hour or 128 MiB, so a day's log is about 25 files, one more for each
/// 128 MiB written and one more each time the filter started again: a day of a building Mac at
/// the rates the installer states is about 170. A log of more cannot be read on from a place,
/// and an answer fails rather than leave files out of it.
const MAX_FILES: usize = 4096;
/// The version of a place's encoding this build writes, its first number. It reads versions 1
/// and 2 too, which earlier builds wrote: version 1 while every log file was named by its hour,
/// version 2 while a place carried what the lines said arrives.
const PLACE_VERSION: u64 = 3;

/// Where a line of the log is: its file's name and inode, and the byte offset where the line
/// begins. A log file is only appended to, so a line keeps its place until its file is deleted,
/// and the inode tells the file from another of the same name made after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineAt {
    pub file: String,
    pub inode: u64,
    pub offset: u64,
}

/// A line's place as `immune matches` gives it in `position`: its file's name without `exec-`
/// and `.jsonl`, the file's inode and the offset, such as
/// `20261004T000013-20261004T000000-48151623-4096`, or `20261004T00-48151623-4096` in a file an
/// earlier collector named by its hour. The core's own words, for a reader to keep and compare
/// whole; nothing reads it back.
impl std::fmt::Display for LineAt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hour = self
            .file
            .strip_prefix(PREFIX)
            .and_then(|n| n.strip_suffix(SUFFIX))
            .unwrap_or(&self.file);
        write!(f, "{hour}-{}-{}", self.inode, self.offset)
    }
}

impl LineAt {
    /// A position exactly as `immune matches` printed it; `None` for any other text. The name
    /// must be one a collector gives a log file, and the text must be what this build prints for the
    /// place it reads, so a sign, a leading zero or anything left over is refused. A position
    /// names no path: the file is the log file of that hour, looked up in the log folder.
    pub fn parse(text: &str) -> Option<LineAt> {
        // The inode and the offset are the last two parts: a file's name may hold a dash.
        let (rest, offset) = text.rsplit_once('-')?;
        let (name, inode) = rest.rsplit_once('-')?;
        let file = format!("{PREFIX}{name}{SUFFIX}");
        key_of(&file)?;
        let at = LineAt {
            file,
            inode: inode.parse().ok()?,
            offset: offset.parse().ok()?,
        };
        (at.to_string() == text).then_some(at)
    }
}

/// What the log holds at a position, for a verdict about a match.
pub enum AtLine {
    /// The log no longer holds it: its file is gone, or a file of that hour now is another one.
    Gone,
    /// Its file is there and no whole line of an event begins at it.
    NoLine,
    /// The event whose line begins at it, with the rules it matched, in the order they are
    /// shipped; none when it matched none.
    Event(Box<Hit>),
}

/// Reads the one line at `at` in the log under `root` and evaluates its event at the one place
/// an event is evaluated (`Into::judge`), as the core's own reading and `immune matches` do, so a
/// verdict about a match is about what they matched. Nothing is read from the store or written
/// to it. A failure is the reason, in the program's words.
pub fn at_line(root: &Path, at: &LineAt, now: i64) -> Result<AtLine, String> {
    let failed = |e: &dyn std::fmt::Display| format!("{} in the event level's log: {e}", at.file);
    let file = match std::fs::File::open(root.join(LOG).join(&at.file)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AtLine::Gone),
        Err(e) => return Err(failed(&e)),
    };
    let meta = file.metadata().map_err(|e| failed(&e))?;
    if meta.ino() != at.inode {
        return Ok(AtLine::Gone);
    }
    // A log file is only appended to: a position past its end was never a line in it.
    if at.offset >= meta.len() {
        return Ok(AtLine::NoLine);
    }
    let mut lines = BufReader::new(file);
    // A line begins at the start of the file or right after a newline.
    let from = at.offset.saturating_sub(1);
    lines.seek(SeekFrom::Start(from)).map_err(|e| failed(&e))?;
    if at.offset > 0 {
        let mut before = [0u8; 1];
        lines.read_exact(&mut before).map_err(|e| failed(&e))?;
        if before[0] != b'\n' {
            return Ok(AtLine::NoLine);
        }
    }
    let mut buf = Vec::new();
    let n = lines.read_until(b'\n', &mut buf).map_err(|e| failed(&e))?;
    if buf.last() != Some(&b'\n') {
        return Ok(AtLine::NoLine);
    }
    let parsed = line(&buf[..n - 1])?;
    let (mut tally, mut file_tally) = (Tally::default(), FileTally::default());
    let (mut last_seq, mut file_seq, mut version) = (None, [None; 2], None);
    let mut matched = Matched::default();
    let mut pending = 0;
    let mut sink = Sink {
        hits: Vec::new(),
        matches: 0,
        bytes: 0,
        limit: usize::MAX,
    };
    let mut into = Into {
        tally: &mut tally,
        file_tally: &mut file_tally,
        last_seq: &mut last_seq,
        file_seq: &mut file_seq,
        version: &mut version,
        arrivals: None,
        lacked: None,
        pending: &mut pending,
        now,
        rules: Rules::shipped(),
        matched: &mut matched,
        file: at.file.clone(),
        inode: at.inode,
        queue: Some(&mut sink),
    };
    let event = match parsed {
        Line::Exec { start, .. } => {
            into.judge(Subject::Start(&start), at.offset, n);
            Evidence::Start(*start)
        }
        Line::File {
            event: Some(event), ..
        } => {
            into.judge(Subject::File(&event), at.offset, n);
            Evidence::File(*event)
        }
        _ => return Ok(AtLine::NoLine),
    };
    Ok(AtLine::Event(Box::new(sink.hits.pop().unwrap_or(Hit {
        at: at.clone(),
        event,
        matched: Vec::new(),
    }))))
}

/// A caller's place in the log, as `immune matches` prints it in `continue_after` and takes it
/// in `--after`: for each log file, where its name puts it (`Key`), its inode, how far it was
/// read, and whether it was over (`LogFile::over`) when it was read to its end; the last number
/// eslogger gave each kind of event read, and the filter's markers no gap has taken in yet, so
/// that a gap at the seam between two answers is counted once. What arrives is not in it:
/// `immune matches` tells what the core's latest reading stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Place {
    /// The last `seq_num` of a program start, a file created and a file renamed.
    seq: [Option<u64>; 3],
    pending: u64,
    /// What a place of version 2 said of each of `MARKS`, its numbers as read: kept only so
    /// that its text is held to one form, and otherwise ignored.
    said: Vec<u64>,
    /// In the order of their keys, each key once.
    files: Vec<Kept>,
}

/// One log file in a place.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Kept {
    key: Key,
    inode: u64,
    /// Every byte before it was read.
    offset: u64,
    /// Read to its end, and over: no line is left in it unread.
    finished: bool,
}

/// A place is printed as lower-case hexadecimal of a run of numbers, each an unsigned varint in
/// protobuf's encoding, written and read by prost. Version 3: the encoding's version, 3; each
/// of the three last numbers plus one, 0 for none; the markers pending; how many files; then
/// for each file the difference of its run from the file's before (from 0 for the first); when
/// the run is the same, the difference of its start from the file's before (from 0 for the
/// first), else its start, doubled, plus one when it is finished; its inode; and its offset.
/// Version 2, which an earlier build wrote, has after the markers one number for each of
/// `MARKS`, what its lines said arrives: 0, 1, 2, or 3 plus a second; they are read and
/// ignored. Version 1 has no markers, and gives each file's hour as the difference from the one
/// before, doubled, plus one when finished. Hexadecimal, because sixteen characters pass through a shell and an
/// argument parser untouched and are checked one by one, and it needs no encoder of someone
/// else's format but the varint, which is prost's. A day of 25 files is about 360 bytes, so
/// about 730 characters.
impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bytes = self.encode(PLACE_VERSION);
        bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Place {
    /// The place's numbers in the encoding of `version`, 1, 2 or 3, as varints.
    fn encode(&self, version: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut put = |n: u64| prost::encoding::encode_varint(n, &mut bytes);
        put(version);
        for s in self.seq {
            put(s.map_or(0, |s| s + 1));
        }
        if version >= 2 {
            put(self.pending);
        }
        if version == 2 {
            self.said.iter().for_each(|n| put(*n));
        }
        put(self.files.len() as u64);
        let mut before = Key { run: 0, at: 0 };
        for k in &self.files {
            let finished = u64::from(k.finished);
            if version >= 2 {
                put(k.key.run - before.run);
                let at = if k.key.run == before.run {
                    k.key.at - before.at
                } else {
                    k.key.at
                };
                put((at << 1) | finished);
            } else {
                put(((k.key.at - before.at) << 1) | finished);
            }
            put(k.inode);
            put(k.offset);
            before = k.key;
        }
        bytes
    }

    /// A place as `immune matches` prints it, or as an earlier build printed it; `None` for any
    /// other text. Read strictly: version 1, 2 or 3, at most `MAX_FILES` files, each of a key some
    /// log file's name can give and later than the one before, and the text exactly as this
    /// build prints the place it reads in that version. That last check also holds the text to
    /// lower-case hexadecimal, to its length, and to nothing left over, and no two texts are one
    /// place. A place never names a path: a file is only looked up among those the log folder
    /// lists.
    pub fn parse(text: &str) -> Option<Place> {
        let bytes: Vec<u8> = text
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<_>>()?;
        let mut buf = bytes.as_slice();
        let mut next = || prost::encoding::decode_varint(&mut buf).ok();
        let version = next()?;
        if !(1..=PLACE_VERSION).contains(&version) {
            return None;
        }
        let mut place = Place::default();
        for s in &mut place.seq {
            *s = next()?.checked_sub(1);
        }
        if version >= 2 {
            place.pending = next()?;
        }
        if version == 2 {
            for _ in MARKS {
                // A second its build could write: 3 plus at most the largest one.
                let n = next()?;
                i64::try_from(n.saturating_sub(3)).ok()?;
                place.said.push(n);
            }
        }
        let n = next()?;
        if n > MAX_FILES as u64 {
            return None;
        }
        let mut before = Key { run: 0, at: 0 };
        for _ in 0..n {
            let key = if version >= 2 {
                let run = before.run.checked_add(next()?)?;
                let step = next()?;
                let at = if run == before.run {
                    if step >> 1 == 0 {
                        return None;
                    }
                    before.at.checked_add(step >> 1)?
                } else {
                    step >> 1
                };
                (Key { run, at }, step & 1 == 1)
            } else {
                let step = next()?;
                if step >> 1 == 0 {
                    return None;
                }
                let at = before.at.checked_add(step >> 1)?;
                (Key { run: 0, at }, step & 1 == 1)
            };
            if !key.0.real() {
                return None;
            }
            place.files.push(Kept {
                key: key.0,
                finished: key.1,
                inode: next()?,
                offset: next()?,
            });
            before = key.0;
        }
        let printed: String = place
            .encode(version)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (printed == text).then_some(place)
    }
}

/// One event that matched, with the rules it matched.
#[derive(Debug)]
pub struct Hit {
    pub at: LineAt,
    pub event: Evidence,
    /// The rules it matched, each by its file and what it says of itself, in the order they
    /// are shipped.
    pub matched: Vec<(&'static str, &'static Meta)>,
}

/// What `immune matches` collects while it reads, and when it stops.
struct Sink {
    hits: Vec<Hit>,
    matches: usize,
    bytes: usize,
    limit: usize,
}

/// What `immune matches` read of the log after a place.
#[derive(Debug)]
pub struct Stretch {
    pub hits: Vec<Hit>,
    pub tally: Tally,
    pub file_tally: FileTally,
    /// The place to read on from.
    pub place: Place,
    /// It stopped at its limit with whole lines left to read.
    pub more: bool,
    /// Lines the place asked after had not read are gone: deleted, or their file replaced, and
    /// never evaluated here.
    pub gone: bool,
    /// When they are gone, where the log kept goes on: the first line of the first file kept at
    /// or after the hour of the lines that are gone.
    pub kept_from: Option<LineAt>,
    pub state: &'static str,
    pub said: Option<(&'static str, String)>,
    pub written: Option<i64>,
    pub collects: Result<(), (Cause, String)>,
    /// Files in the log folder that are not the collector's own: not read.
    pub foreign: u64,
    /// What of `KEEPS` the lines it judged did not give, by kind.
    pub lacked: Lacked,
}

/// What `immune matches` found.
#[derive(Debug)]
pub enum Queue {
    /// The collector is not installed. Uninstalling deletes the log, so lines a place had not
    /// read are `gone`.
    NotInstalled {
        gone: bool,
    },
    Failed(String),
    Read(Box<Stretch>),
}

/// Reads the log under `root` on from `after`, or from the oldest line kept, until it ends or
/// `limit` matches are taken, evaluating every program start and file event as the core's own
/// reading does. Nothing is read from the store or written to it.
///
/// A file the place holds with the same inode is read on from its offset. A file it does not
/// hold is read from its start, whatever its name; so is one of a held name with another inode,
/// or shorter than the offset, which is another file. A held file that is gone, or replaced,
/// had lines the place had not read when the root side's note of its deletion says it held
/// more than the offset, or, with no note, when it was not finished: then the answer says the
/// lines are `gone`.
pub fn queue(root: &Path, after: Option<&Place>, limit: usize, now: i64) -> Queue {
    let Opened {
        installed_at,
        collects,
        dir,
        files,
        foreign,
    } = match open(root) {
        Ok(opened) => opened,
        Err(None) => {
            return Queue::NotInstalled {
                gone: after.is_some_and(|p| p.files.iter().any(|k| !k.finished)),
            };
        }
        Err(Some(why)) => return Queue::Failed(why),
    };
    if files.len() > MAX_FILES {
        return Queue::Failed(format!(
            "the event level's log holds {} files, more than the {MAX_FILES} a place in it holds",
            files.len()
        ));
    }
    let failed = |name: &str, e: std::io::Error| format!("{name} in the event level's log: {e}");
    let held = after.cloned().unwrap_or_default();
    // The most each deleted file held, as the root side noted it.
    let mut deleted: BTreeMap<String, u64> = BTreeMap::new();
    match notes(&dir) {
        Ok(notes) => {
            for (_, name, bytes, _) in notes {
                let most = deleted.entry(name).or_default();
                *most = (*most).max(bytes);
            }
        }
        Err(e) => return Queue::Failed(failed(REMOVED, e)),
    }
    // Whether a file the place held, now gone or replaced, had lines the place did not read. The
    // root side's note says how much it held when it was deleted; without one, as after an
    // uninstall, only a file read to its end with its hour over held no more.
    let unread = |k: &Kept| match deleted.get(&name_of(k.key)) {
        Some(bytes) => *bytes > k.offset,
        None => !k.finished,
    };
    let held_of: BTreeMap<Key, &Kept> = held.files.iter().map(|k| (k.key, k)).collect();
    // The keys of files the place held whose unread lines are gone.
    let mut gone: Vec<Key> = held
        .files
        .iter()
        .filter(|k| files.binary_search_by_key(&k.key, |f| f.key).is_err() && unread(k))
        .map(|k| k.key)
        .collect();
    let mut tally = Tally::default();
    let mut file_tally = FileTally::default();
    let mut matched = Matched::default();
    let mut last_seq = held.seq[0];
    let mut file_seq = [held.seq[1], held.seq[2]];
    let mut pending = held.pending;
    let mut version = None;
    let mut lacked = Lacked::default();
    let mut sink = Sink {
        hits: Vec::new(),
        matches: 0,
        bytes: 0,
        limit,
    };
    let mut place = Place::default();
    let mut more = false;
    let mut stopped = files.len();
    for (k, f) in files.iter().enumerate() {
        let mut into = Into {
            tally: &mut tally,
            file_tally: &mut file_tally,
            last_seq: &mut last_seq,
            file_seq: &mut file_seq,
            version: &mut version,
            arrivals: None,
            lacked: Some(&mut lacked),
            pending: &mut pending,
            now,
            rules: Rules::shipped(),
            matched: &mut matched,
            file: String::new(),
            inode: 0,
            queue: Some(&mut sink),
        };
        // The same file is read on from where the place left it. Another of its name, or one
        // shorter than the place read, is another file, read from its start, and the one the
        // place held is replaced.
        let was = held_of.get(&f.key).copied();
        let mut replaced = false;
        let from = |m: &std::fs::Metadata| match was {
            Some(k) if k.inode == m.ino() && k.offset <= m.len() => k.offset,
            other => {
                replaced = other.is_some();
                0
            }
        };
        let read = match read_file(&dir, &f.name, from, f.over, &mut into) {
            Ok(Some(read)) => read,
            // Deleted between the listing and now.
            Ok(None) => {
                gone.extend(was.filter(|k| unread(k)).map(|k| k.key));
                continue;
            }
            Err(why) => return Queue::Failed(why),
        };
        if replaced {
            gone.extend(was.filter(|k| unread(k)).map(|k| k.key));
        }
        place.files.push(Kept {
            key: f.key,
            inode: read.inode,
            offset: read.to,
            finished: f.over && read.to == read.len,
        });
        if read.full {
            more = match more_after(&dir, &files, k, read.to) {
                Ok(more) => more,
                Err(e) => return Queue::Failed(failed(&f.name, e)),
            };
            stopped = k + 1;
            break;
        }
    }
    // The files after where it stopped keep what the place held of them; the next answer tells
    // whether they are still the same files.
    place.files.extend(
        files[stopped..]
            .iter()
            .filter_map(|f| held_of.get(&f.key).map(|k| (*k).clone())),
    );
    place.seq = [last_seq, file_seq[0], file_seq[1]];
    place.pending = pending;
    let gone_at = gone.into_iter().min();
    let kept_from = gone_at.and_then(|g| {
        let f = files.iter().find(|f| f.key >= g)?;
        let inode = std::fs::metadata(dir.join(&f.name)).ok()?.ino();
        Some(LineAt {
            file: f.name.clone(),
            inode,
            offset: 0,
        })
    });
    let times: Vec<i64> = files.iter().map(|f| f.mtime.0).collect();
    let written = times.iter().copied().max();
    let (state, said) = judge(&dir, installed_at, times, now);
    Queue::Read(Box::new(Stretch {
        hits: sink.hits,
        tally,
        file_tally,
        place,
        more,
        gone: gone_at.is_some(),
        kept_from,
        state,
        said,
        written,
        collects,
        foreign,
        lacked,
    }))
}

/// Whether a whole line is left after `to` in `files[k]`, or anything in a file after it. A
/// line still being written at the end of the file is not.
fn more_after(dir: &Path, files: &[LogFile], k: usize, to: u64) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(dir.join(&files[k].name))?;
    if to < file.metadata()?.len() {
        file.seek(SeekFrom::Start(to))?;
        let mut buf = Vec::new();
        BufReader::new(file).read_until(b'\n', &mut buf)?;
        if buf.last() == Some(&b'\n') {
            return Ok(true);
        }
    }
    Ok(files[k + 1..]
        .iter()
        .any(|f| std::fs::metadata(dir.join(&f.name)).is_ok_and(|m| m.len() > 0)))
}

/// Which finding the core's own reading recorded a match as going to.
pub enum WentTo {
    Finding(String),
    /// Read with the record kept, and no finding holds it.
    None,
    /// Read before the store kept the record.
    Unrecorded,
}

/// Which finding the core's own reading recorded the match of `rule` (by its name) on
/// the line at `at` as going to, for a line it has read.
pub fn went_to(conn: &Connection, at: &LineAt, rule: &str) -> rusqlite::Result<WentTo> {
    if !has(conn, "rule_line")? {
        return Ok(WentTo::Unrecorded);
    }
    let (inode, offset) = (at.inode as i64, at.offset as i64);
    let finding: Option<String> = conn
        .query_row(
            "SELECT finding FROM rule_line
             WHERE file = ?1 AND inode = ?2 AND offset = ?3 AND rule = ?4",
            params![at.file, inode, offset, rule],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(f) = finding {
        return Ok(WentTo::Finding(f));
    }
    let from: Option<i64> = conn
        .query_row(
            "SELECT offset FROM rule_line_from WHERE file = ?1 AND inode = ?2",
            params![at.file, inode],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match from {
        Some(from) if offset < from => WentTo::Unrecorded,
        _ => WentTo::None,
    })
}

/// Where the core's own reading has read each log file up to, by name: the file's inode and the
/// offset before which every byte is read. Empty before any reading.
pub fn read_up_to(conn: &Connection) -> rusqlite::Result<BTreeMap<String, (u64, u64)>> {
    if !has(conn, "event_file")? {
        return Ok(BTreeMap::new());
    }
    conn.prepare("SELECT name, inode, offset FROM event_file")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (r.get::<_, i64>(1)? as u64, r.get::<_, i64>(2)? as u64),
            ))
        })?
        .collect()
}

/// The level's state as the latest reading left it, with when that reading was made: what
/// `immune status` serves. `None` before any reading.
pub fn state_read(conn: &Connection) -> rusqlite::Result<Option<(String, i64)>> {
    if !has(conn, "event_level")? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT state, read_at FROM event_level WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// The time eslogger gives an event, RFC 3339 in UTC as it writes it
/// (`2026-10-04T00:00:02.000002Z`), as seconds since the epoch and the nanoseconds within the
/// second; `None` for any other form. The date and time are read by the C library's
/// `strptime(3)` and `timegm(3)`, which macOS ships; the fraction, up to nine digits, is ours.
pub fn instant(text: &str) -> Option<(i64, u32)> {
    let (whole, rest) = text.split_at_checked(19)?;
    let nanos = match rest.strip_suffix('Z')? {
        "" => 0,
        fraction => {
            let digits = fraction.strip_prefix('.')?;
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|c| c.is_ascii_digit())
            {
                return None;
            }
            digits.parse::<u32>().ok()? * 10u32.pow(9 - digits.len() as u32)
        }
    };
    let c = std::ffi::CString::new(whole).ok()?;
    // SAFETY: `tm` is a plain C structure that strptime fills; both strings end in NUL and
    // outlive the calls; strptime returns NULL or a pointer into `c`.
    let secs = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let end = libc::strptime(c.as_ptr(), c"%Y-%m-%dT%H:%M:%S".as_ptr(), &mut tm);
        if end.is_null() || *end != 0 {
            return None;
        }
        libc::timegm(&mut tm)
    };
    Some((secs, nanos))
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
    // What the collector printed is text from a source, which can quote a command line: kept cut.
    let said = said.map(|s| crate::secrets::Text::source(s).store());
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

/// The cap of the log as this reading found it in the tidy job's launch daemon, whatever else the
/// reading came to.
fn put_cap(tx: &Transaction, cap: &Result<u64, String>) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO event_cap (id, bytes, why) VALUES (1, ?1, ?2)
         ON CONFLICT (id) DO UPDATE SET bytes = excluded.bytes, why = excluded.why",
        params![cap.as_ref().ok().map(|b| *b as i64), cap.as_ref().err()],
    )?;
    Ok(())
}

/// The names `event_arrival` gives a kind of event.
fn kind_name(kind: crate::sigma::Kind) -> &'static str {
    match kind {
        crate::sigma::Kind::Process => "program_start",
        crate::sigma::Kind::File => "file_event",
    }
}

/// What the lines read say of each of `KEEPS`, one row for each of `MARKS` that a line spoke of.
fn put_arrivals(tx: &Transaction, arrivals: &Arrivals) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM event_arrival", [])?;
    for ((a, quiet), (kind, keep, _)) in arrivals.0.iter().zip(&arrivals.1).zip(MARKS) {
        let (kept, filled, stopped) = match a {
            Arrival::Unknown => continue,
            Arrival::NotKept => (false, None, None),
            Arrival::Kept(filled) => (true, *filled, None),
            Arrival::NoLonger(since) => (true, None, Some(*since)),
        };
        tx.execute(
            "INSERT INTO event_arrival (kind, keep, kept, filled, stopped, quiet, quiet_from)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                kind_name(kind),
                names(keep)[0],
                kept,
                filled,
                stopped,
                quiet.lines as i64,
                quiet.from
            ],
        )?;
    }
    Ok(())
}

/// What the lines read say of each of `KEEPS`, as the latest reading left it; nothing is known
/// before any reading. Read-only commands call it on a store an earlier build left, before any
/// reading of this build has added the run's columns. A row of that build's shape, a kept field
/// with a value and no run, is not yet known: that build told a field arriving for ever after
/// one value. Such a row has no `quiet_from`, before the columns are added and after, while this
/// build writes one on every row. A run no build stores, as long as the bound of its mark or
/// longer, is told as no longer arriving, since its first line: a store is a file a program
/// running as the user can rewrite, and what it says never makes calm.
pub fn arrivals(conn: &Connection) -> rusqlite::Result<Arrivals> {
    let mut arrivals = Arrivals::default();
    if !has(conn, "event_arrival")? {
        return Ok(arrivals);
    }
    let sql = if has_run(conn)? {
        "SELECT kind, keep, kept, filled, stopped, quiet, quiet_from FROM event_arrival"
    } else {
        "SELECT kind, keep, kept, filled, NULL, 0, NULL FROM event_arrival"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |r| {
        Ok((
            (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
            r.get::<_, bool>(2)?,
            (r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?),
            r.get::<_, i64>(5)?.max(0) as u64,
            r.get::<_, Option<i64>>(6)?,
        ))
    })?;
    for row in rows {
        let ((kind, keep), kept, (filled, stopped), lines, from) = row?;
        let at = MARKS
            .iter()
            .position(|(k, m, _)| kind_name(*k) == kind && names(*m) == [keep.as_str()]);
        if let Some(i) = at {
            let quiet = Quiet {
                lines,
                from: from.unwrap_or_default(),
            };
            arrivals.0[i] = match (kept, stopped, filled) {
                (false, _, _) => Arrival::NotKept,
                (true, Some(since), _) => Arrival::NoLonger(since),
                (true, None, Some(_)) if from.is_none() => Arrival::Unknown,
                (true, None, Some(_)) if lines >= MARKS[i].2 => Arrival::NoLonger(quiet.from),
                (true, None, Some(since)) => {
                    arrivals.1[i] = quiet;
                    Arrival::Kept(Some(since))
                }
                (true, None, None) => Arrival::Kept(None),
            };
        }
    }
    Ok(arrivals)
}

/// Whether `event_arrival` has the columns of the run, which this build adds at its first
/// reading.
fn has_run(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('event_arrival') WHERE name = 'stopped')",
        [],
        |r| r.get(0),
    )
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
    let pending: Option<i64> = tx
        .query_row("SELECT pending FROM event_marks WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(Left {
        files,
        last_seq: row.and_then(|r| r.0).map(|s| s as u64),
        file_seq: file_seq.map_or([None, None], |(c, r)| [seq(c), seq(r)]),
        counted: row.and_then(|r| r.1),
        arrivals: arrivals(tx)?,
        pending: pending.map_or(0, |p| p as u64),
    })
}

/// The level as the latest reading left it, with its counts since the latest full check
/// and over the last day.
pub struct Level {
    pub state: String,
    pub read_at: i64,
    pub written: Option<i64>,
    pub said_by: Option<String>,
    pub said: Option<crate::secrets::Text>,
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
    /// What the lines read say of each of `KEEPS`, as the latest reading left it: nothing is
    /// known before any reading of a collector's lines, or while none is installed.
    pub arrivals: Arrivals,
    /// The cap of the log in bytes, or why it could not be read, as the latest reading of an
    /// installed collector found it; `None` before any such reading, or while none is installed.
    pub cap: Option<Result<u64, String>>,
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

    /// What of `KEEPS` does not arrive: a rule that reads it does not watch.
    pub fn not_arriving(&self) -> Keeps {
        self.arrivals.not_arriving()
    }

    /// Every file event the log held over the last day was read: none lost, none that could
    /// not be made out, no line unreadable and no file deleted early.
    pub fn files_whole(&self) -> bool {
        self.files.last_day.gaps().is_empty() && self.last_day.shared_whole()
    }

    /// The rules judged all the log held over the last day: the level runs, and no program
    /// start, nor a file event where they are collected, was lost, could not be read or was
    /// deleted before it was read. `rules.judged` is `all` exactly when this holds.
    pub fn judged_whole(&self) -> bool {
        self.state == RUNNING
            && self.last_day.whole()
            && (!self.files_watched() || self.files_whole())
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
        arrivals: arrivals(conn)?,
        cap: cap(conn)?,
        state,
        read_at,
        written,
        said_by,
        said: match said {
            Some(s) => Some(crate::secrets::Kept::Said.read(crate::secrets::form(conn)?, &s)),
            None => None,
        },
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

/// The cap of the log, as the latest reading left it.
fn cap(conn: &Connection) -> rusqlite::Result<Option<Result<u64, String>>> {
    if !has(conn, "event_cap")? {
        return Ok(None);
    }
    let row: Option<(Option<i64>, Option<String>)> = conn
        .query_row("SELECT bytes, why FROM event_cap WHERE id = 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(row.map(|(bytes, why)| match bytes {
        Some(b) => Ok(b as u64),
        None => Err(why.unwrap_or_default()),
    }))
}

/// A cap in a person's words: whole GiB when it is, else bytes.
pub fn cap_words(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    if bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else {
        format!("{bytes} bytes")
    }
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

/// `event_level` of the contract's `Status`. What `eslogger` or the scripts printed, and why a
/// reading failed, are text from a source, each in its own field, whole.
pub fn message(l: &Level) -> crate::contract::v1::EventLevel {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    let n = |x: i64| u64::try_from(x).unwrap_or(0);
    let span = |f: fn(&Tally) -> i64| v1::Span {
        since_check: n(f(&l.since_check)),
        last_day: n(f(&l.last_day)),
    };
    let files = |f: fn(&FileTally) -> i64| v1::Span {
        since_check: n(f(&l.files.since_check)),
        last_day: n(f(&l.files.last_day)),
    };
    let series = |s: &Series| v1::Series {
        ends_at: s.ends_at,
        step_seconds: n(s.step),
        counts: s.counts.iter().map(|c| n(*c)).collect(),
    };
    let said = words(l);
    let names = |state: Arrival| -> Vec<String> {
        l.arrivals
            .named(|a| a == state)
            .into_iter()
            .map(str::to_string)
            .collect()
    };
    v1::EventLevel {
        state: value_of::<v1::CollectorState>(&l.state),
        level: LEVEL.to_string(),
        read_at: l.read_at,
        written_at: l.written,
        program_starts: Some(span(|t| t.starts)),
        lost: Some(span(|t| t.lost)),
        unknown_losses: Some(span(|t| t.unknown_gaps)),
        unreadable_lines: Some(span(|t| t.unreadable)),
        other_messages: Some(span(|t| t.other)),
        files_removed_by_cap: Some(span(|t| t.removed_cap)),
        files_removed_unread: Some(span(|t| t.removed_unread)),
        message_version: l.version,
        said_by: l.said_by.clone(),
        // Read cut (`level`), as every reader of it reads it.
        said_text: l.said.as_ref().map(|s| s.shown(whole)),
        reason_text: l.reason.as_deref().map(whole),
        silent_after_seconds: n(SILENT_AFTER),
        cannot_see: cannot_see(l).into_iter().map(str::to_string).collect(),
        not_kept: names(Arrival::NotKept),
        kept_never_filled: names(Arrival::Kept(None)),
        not_yet_known: names(Arrival::Unknown),
        arriving: l
            .arrivals
            .arriving()
            .into_iter()
            .map(|(name, since)| v1::Arriving {
                name: name.to_string(),
                since,
            })
            .collect(),
        file_events: Some(v1::FileEvents {
            collected: l.files.collected,
            not_collected_reason: l.files.why.clone().filter(|_| !l.files.collected),
            kinds: FILE_KINDS.iter().map(|k| k.to_string()).collect(),
            events: Some(files(|f| f.files)),
            lost: Some(files(|f| f.lost)),
            unknown_losses: Some(files(|f| f.unknown_gaps)),
            unreadable_events: Some(files(|f| f.unreadable)),
        }),
        program_starts_by_hour: Some(series(&l.starts_by_hour)),
        program_starts_by_minute: Some(series(&l.starts_by_minute)),
        in_words: Some(v1::EventLevelWords {
            state: said.state.to_string(),
            notes: said.notes.clone(),
            caveats: said
                .caveats
                .iter()
                .map(|c| v1::Caveat {
                    kind: c.kind.to_string(),
                    short: c.short.clone(),
                })
                .collect(),
        }),
        log_cap_bytes: l.cap.as_ref().and_then(|c| c.as_ref().ok().copied()),
        log_cap_reason_text: l
            .cap
            .as_ref()
            .and_then(|c| c.as_ref().err().map(|why| whole(why))),
        no_longer_arriving: l
            .arrivals
            .no_longer()
            .into_iter()
            .map(|(name, since)| v1::NoLongerArriving {
                name: name.to_string(),
                since,
            })
            .collect(),
    }
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
    let mut said = state_words(l);
    // An earlier collector keeps less than this version reads, as its latest lines show: said
    // in every state it is installed in, and as a caveat while it records.
    let missing = keeps_named(&l.arrivals.named(|a| a == Arrival::NotKept));
    if missing != 0 {
        let what: Vec<&str> = of(missing).map(|(_, words)| *words).collect();
        let list = match what.split_last() {
            Some((last, [])) => last.to_string(),
            Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
            None => String::new(),
        };
        said.notes.push(format!(
            "The collector installed here is an earlier one and does not keep {list}; installing the event level again adds {}.",
            if what.len() == 1 { "it" } else { "them" }
        ));
        if l.state == RUNNING {
            said.caveats.push(Caveat {
                kind: "earlier_collector",
                short: "reinstall needed".to_string(),
            });
        }
    }
    said
}

/// The level's state in words, before what its collector does not keep.
fn state_words(l: &Level) -> Said {
    let counted = crate::view::counted;
    let not_seen = |state: &'static str, why: String| Said {
        state,
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
                    "file deleted early",
                    "files deleted early",
                );
                notes.push(format!(
                    "{} deleted early to keep the log under its size limit{}.",
                    counted(
                        d.removed_cap,
                        "file of the log was",
                        "files of the log were"
                    ),
                    match &l.cap {
                        Some(Ok(bytes)) => format!(" of {}", cap_words(*bytes)),
                        _ => String::new(),
                    }
                ));
            }
            if d.removed_unread > 0 {
                short(
                    "deleted_unread",
                    d.removed_unread,
                    "file deleted unread",
                    "files deleted unread",
                );
                notes.push(format!(
                    "{} deleted before they were read.",
                    counted(
                        d.removed_unread,
                        "file of the log was",
                        "files of the log were"
                    )
                ));
            }
            Said {
                state: "on",
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

    #[test]
    fn the_cap_reported_is_the_one_tidy_sh_takes_and_is_said_in_gib_or_in_bytes_never_rounded() {
        // tidy.sh takes its cap as at most 16 digits without a leading zero, of at least 1 GiB,
        // and refuses anything else, so the status reports a cap only where tidy.sh has one: no
        // zero, no sign, no leading zero, nothing its arithmetic would wrap.
        for (text, read) in [
            ("2147483648", Some(2147483648)),
            ("1073741824", Some(1073741824)),
            ("1073741823", None),
            ("01073741824", None),
            ("0", None),
            ("00", None),
            ("9999999999999999", Some(9999999999999999)),
            ("10000000000000000", None),
            ("+2147483648", None),
            ("-1", None),
            ("2G", None),
            ("", None),
            ("99999999999999999999", None),
        ] {
            assert_eq!(bytes_of(text), read, "{text}");
        }
        assert_eq!(cap_words(2147483648), "2 GiB");
        assert_eq!(cap_words(1073741825), "1073741825 bytes");
    }

    #[test]
    fn the_cap_is_read_again_only_when_the_tidy_job_s_launch_daemon_changed_and_a_failure_is_never_kept()
     {
        // `immune watch` reads the log every few seconds, and each `plutil` it started would be
        // a program start in the log: the same file, by inode, size and time, is not read again.
        // A reading that failed is not kept: the next one runs plutil again, even on a file
        // that looks the same.
        use std::io::Write;
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-cap-{}", std::process::id())),
        );
        let plist = dir.join(TIDY_PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        let shipped = include_str!("../scripts/event-level/ai.nuanu.immune.event-tidy.plist");
        // Writes `text` over the file in place, then gives it back the times it had before, so
        // it keeps its inode, its size when `text` is as long, and its time.
        let rewrite = |text: &str| {
            let meta = std::fs::metadata(&plist).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&plist)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            let times = [
                libc::timespec {
                    tv_sec: meta.atime(),
                    tv_nsec: meta.atime_nsec(),
                },
                libc::timespec {
                    tv_sec: meta.mtime(),
                    tv_nsec: meta.mtime_nsec(),
                },
            ];
            let path = std::ffi::CString::new(plist.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: a valid C path and two timespecs, as utimensat(2) takes them.
            let set = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) };
            assert_eq!(set, 0);
        };
        std::fs::write(&plist, shipped).unwrap();
        assert_eq!(log_cap(&dir), Ok(2147483648));
        // The same size, inode and time, other bytes: taken as the same file.
        rewrite(&shipped.replace("2147483648", "3221225472"));
        assert_eq!(log_cap(&dir), Ok(2147483648));
        // Another file: read again.
        std::fs::remove_file(&plist).unwrap();
        std::fs::write(&plist, shipped.replace("2147483648", "5368709120")).unwrap();
        assert_eq!(log_cap(&dir), Ok(5368709120));
        // A file that cannot be read, then the same file by inode, size and time that can.
        std::fs::remove_file(&plist).unwrap();
        std::fs::write(&plist, shipped.replace("2147483648", "53687091x0")).unwrap();
        assert!(log_cap(&dir).is_err());
        assert!(log_cap(&dir).is_err());
        rewrite(&shipped.replace("2147483648", "6442450944"));
        assert_eq!(log_cap(&dir), Ok(6442450944));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bytes as lower-case hexadecimal, as a place is printed.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Numbers as varints, as a place encodes them.
    fn varints(numbers: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        for n in numbers {
            prost::encoding::encode_varint(*n, &mut out);
        }
        out
    }

    /// A file of a later collector's, of run `run` started at `at`, both `YYYYMMDDHHMMSS`.
    fn kept_at(run: u64, at: u64, i: u64, finished: bool) -> Kept {
        Kept {
            key: Key { run, at },
            inode: 150_000_000 + i * 40_000,
            offset: 300_000_000 + i,
            finished,
        }
    }

    #[test]
    fn a_place_is_taken_back_only_as_the_core_printed_it_and_a_day_of_it_is_short() {
        // `--after` comes from a caller. Only the text the core printed is taken: anything
        // else is refused as a misuse, and nothing in a place names a path. A day of 25 files
        // fits a command line.
        let day = Place {
            seq: [Some(4_000_000), None, Some(0)],
            pending: 1,
            said: Vec::new(),
            files: (0..25u64)
                .map(|i| {
                    let run = 20261003000013 + if i < 24 { 0 } else { 1_000_000 };
                    let at = if i < 24 {
                        20261003000000 + i * 10_000
                    } else {
                        20261004000000
                    };
                    kept_at(run, at, i, i < 24)
                })
                .collect(),
        };
        let text = day.to_string();
        assert_eq!(Place::parse(&text), Some(day.clone()));
        assert!(text.len() < 800, "{} characters", text.len());
        println!("a place of a day of 25 files: {} characters", text.len());
        let empty = Place::default().to_string();
        assert_eq!(empty, "030000000000");
        assert_eq!(Place::parse(&empty), Some(Place::default()));
        let head = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let one = |run: u64, step: u64| hex(&varints(&[&head[..], &[1, run, step, 7, 9]].concat()));
        assert!(Place::parse(&one(20261004000013, 20261004000000 << 1)).is_some());
        let two = |run: u64, step: u64| {
            hex(&varints(
                &[
                    &head[..],
                    &[
                        2,
                        20261004000013,
                        20261004000000 << 1,
                        7,
                        9,
                        run,
                        step,
                        8,
                        9,
                    ],
                ]
                .concat(),
            ))
        };
        // The same run, a later start; a later run, any start.
        assert!(Place::parse(&two(0, 2)).is_some());
        assert!(Place::parse(&two(1, 20261003000000 << 1)).is_some());
        let most = |n: u64| Place {
            files: (0..n)
                .map(|i| {
                    let second = i / 3600 * 10_000 + i / 60 % 60 * 100 + i % 60;
                    kept_at(20261001000000, 20261001000000 + second, i, false)
                })
                .collect(),
            ..Place::default()
        };
        let full = most(MAX_FILES as u64);
        assert_eq!(Place::parse(&full.to_string()), Some(full));
        let too_many = most(MAX_FILES as u64 + 1).to_string();
        for bad in [
            String::new(),
            "../../../etc/x".to_string(),
            text.to_uppercase(),
            format!("{text}00"),
            text[..text.len() - 1].to_string(),
            format!(" {text}"),
            hex(&varints(&[3, 0, 0, 0, 0])),
            hex(&varints(&[0, 0, 0, 0, 0])),
            // The same numbers in a longer varint: one place, one text.
            "820000000000000000000000".to_string(),
            // Seconds that are not seconds, and a file that does not follow the one before.
            one(20261004000013, 20261304000000 << 1),
            one(20261004000013, 20261004240000 << 1),
            one(20261004000013, 20261004006000 << 1),
            one(20261004000013, 20261004000061 << 1),
            one(20261304000013, 20261004000000 << 1),
            one(120261004000013, 20261004000000 << 1),
            one(20261004000013, 0),
            one(0, 20261004000000 << 1),
            two(0, 0),
            two(0, 1),
            // A version 2 arrival's time beyond what a second holds.
            hex(&varints(&[2, 0, 0, 0, 0, u64::MAX, 0, 0, 0, 0, 0])),
            hex(&varints(&[2, 0, 0, 0, 0, 3 + (1 << 63), 0, 0, 0, 0, 0])),
            // Version 3 holds nothing of what arrives.
            hex(&varints(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
            hex(&varints(&[3, 0, 0, 0, 0, 3, 7, 0, 0, 0, 0, 0, 0])),
            too_many,
            "0".repeat(20_000),
        ] {
            assert_eq!(Place::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn a_place_an_earlier_build_printed_is_read_on_from_where_it_was() {
        // A response layer holds a place across an upgrade: one printed when every file was
        // named by its hour reads on, and is refused only as any other text would be.
        let v1 = |numbers: &[u64]| hex(&varints(numbers));
        let held = v1(&[1, 5, 0, 0, 2, 2026100400 << 1 | 1, 7, 90, 2 << 1, 8, 30]);
        let place = Place::parse(&held).expect("a version-1 place is read");
        assert_eq!(place.seq, [Some(4), None, None]);
        assert_eq!(
            place.files,
            [
                Kept {
                    key: Key {
                        run: 0,
                        at: 2026100400
                    },
                    inode: 7,
                    offset: 90,
                    finished: true,
                },
                Kept {
                    key: Key {
                        run: 0,
                        at: 2026100402
                    },
                    inode: 8,
                    offset: 30,
                    finished: false,
                },
            ]
        );
        assert_eq!((place.pending, place.said.len()), (0, 0));
        // One version 2 printed carries what its lines said arrives: read and ignored, so its
        // text is still held to one form, and the place it prints next carries none of it.
        let held2 = v1(&[
            2,
            5,
            0,
            0,
            1,
            3 + 7,
            0,
            1,
            2,
            0,
            1,
            0,
            2026100400 << 1,
            7,
            90,
        ]);
        let v2 = Place::parse(&held2).expect("a version-2 place is read");
        assert_eq!(
            (v2.seq, v2.pending, v2.files.len()),
            ([Some(4), None, None], 1, 1)
        );
        assert_eq!(hex(&v2.encode(2)), held2);
        let next = Place::parse(&v2.to_string()).expect("its next place is read back");
        assert_eq!(
            (next.seq, next.pending, &next.files),
            (v2.seq, 1, &v2.files)
        );
        assert!(next.said.is_empty() && next.to_string().len() < held2.len());
        // What it prints next is this build's version, and it reads that back.
        assert!(place.to_string().starts_with("03"));
        assert_eq!(Place::parse(&place.to_string()), Some(place));
        for bad in [
            v1(&[1, 0, 0, 0, 1, 2026130400 << 1, 7, 9]),
            v1(&[1, 0, 0, 0, 2, 2026100400 << 1, 7, 9, 0, 8, 9]),
            format!("{held}00"),
            format!("{held2}00"),
            v1(&[2, 5, 0, 0, 1, 3 + 7, 0, 1, 2, 0]),
        ] {
            assert_eq!(Place::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn only_a_file_named_as_a_collector_names_one_is_a_log_file_and_names_sort_as_written() {
        // A file in the log folder is the collector's only in an exact form a collector writes,
        // of a real date and time; any other is never read, and a place can name no other. An
        // earlier collector's files, named by the hour, come before a later one's, and a later
        // one's go by run, then by start.
        let old = key_of("exec-20261004T00.jsonl").unwrap();
        assert_eq!(
            old,
            Key {
                run: 0,
                at: 2026100400
            }
        );
        assert_eq!(
            key_of("exec-20261231T23.jsonl"),
            Some(Key {
                run: 0,
                at: 2026123123
            })
        );
        assert_eq!(
            name_of(Key {
                run: 0,
                at: 2026100409
            }),
            "exec-20261004T09.jsonl"
        );
        let new = "exec-20261004T093012-20261004T090000.jsonl";
        let k = key_of(new).unwrap();
        assert_eq!(
            k,
            Key {
                run: 20261004093012,
                at: 20261004090000
            }
        );
        assert_eq!(name_of(k), new);
        let later_in_run = key_of("exec-20261004T093012-20261004T094511.jsonl").unwrap();
        let next_run = key_of("exec-20261004T100002-20261004T100000.jsonl").unwrap();
        let leap = key_of("exec-20261231T235960-20261231T235960.jsonl").unwrap();
        assert!(old < k && k < later_in_run && later_in_run < next_run && next_run < leap);
        for bad in [
            "exec-20261004T24.jsonl",
            "exec-20261304T00.jsonl",
            "exec-20260004T00.jsonl",
            "exec-20261000T00.jsonl",
            "exec-20261032T00.jsonl",
            "exec-2026100T00.jsonl",
            "exec-202610040T00.jsonl",
            "exec-20261004X00.jsonl",
            "exec-20261004T00.jsonl.bak",
            "exec-20261004T00.json",
            "Exec-20261004T00.jsonl",
            "exec-zz.jsonl",
            "exec-2026100\u{0663}T00.jsonl",
            "exec-../../x.jsonl",
            "exec-20261004T093012-20261004T096000.jsonl",
            "exec-20261004T093012-20261004T090061.jsonl",
            "exec-20261004T243012-20261004T090000.jsonl",
            "exec-20261004T093012_20261004T090000.jsonl",
            "exec-20261004T093012-20261004T09000.jsonl",
            "exec-20261004T093012-20261004X090000.jsonl",
            "exec-20261004T093012-20261004T090000-.jsonl",
            "exec-20261004T09301-220261004T090000.jsonl",
        ] {
            assert_eq!(key_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_event_s_time_is_read_to_the_nanosecond_as_eslogger_writes_it_and_no_other_form_is_guessed()
     {
        // The log gives RFC 3339 in UTC with a fraction of a second; a form it does not write
        // is left absent rather than read as some other time.
        assert_eq!(
            instant("2026-10-04T00:00:02.000002Z"),
            Some((1_791_072_002, 2_000))
        );
        assert_eq!(instant("2026-10-04T00:00:02Z"), Some((1_791_072_002, 0)));
        assert_eq!(
            instant("1970-01-01T00:00:00.123456789Z"),
            Some((0, 123_456_789))
        );
        assert_eq!(
            instant("2026-10-04T00:00:02.5Z"),
            Some((1_791_072_002, 500_000_000))
        );
        for bad in [
            "2026-10-04T00:00:02.0000000001Z",
            "2026-10-04T00:00:02.Z",
            "2026-10-04T00:00:02.00a002Z",
            "2026-10-04T00:00:02+03:00",
            "2026-10-04T00:00:02",
            "2026-10-04 00:00:02Z",
            "2026-10-04T00:00:2xZ",
            "2026-13-04T00:00:02Z",
            "",
        ] {
            assert_eq!(instant(bad), None, "{bad}");
        }
    }

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

    /// An `exec` line as the filter writes it now, which keeps who each process is: `before` is
    /// the process before the `exec`, `parent` the parent's audit token, `script` the script.
    fn kept_exec(before: &str, target: &str, parent: &str, script: &str) -> String {
        format!(
            r#"{{"schema_version":1,"version":10,"seq_num":7,"global_seq_num":7,"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/zsh"}},{before},"codesigning_flags":570522385}},"event":{{"exec":{{"args":["sh","run.sh"],"cwd":{{"path":"/Users/example"}},"script":{script},"target":{{"executable":{{"path":"/bin/sh"}},"audit_token":{target},"start_time":"2026-10-04T00:00:01.900000Z","parent_audit_token":{parent},"ppid":401,"signing_id":"com.apple.sh","team_id":null,"is_platform_binary":true,"codesigning_flags":570522304}}}}}}}}"#
        )
    }

    fn start_of(text: &str) -> ProcessStart {
        match line(text.as_bytes()) {
            Ok(Line::Exec { start, .. }) => *start,
            other => panic!("{other:?}: {text}"),
        }
    }

    #[test]
    fn who_each_process_of_a_start_is_read_from_either_shape_and_a_shape_nobody_expects_is_absent()
    {
        // A pid is reused; with its version and start time it names one process. The reader
        // takes the audit token of the process before the `exec`, of the program started and of
        // the parent in both shapes eslogger has written, and the script. A shape it does not
        // know leaves that part absent and the start read: only the started program's pid is
        // needed, and it is the one part whose absence fails a reading.
        let before = r#""audit_token":{"pid":402,"pidversion":9401},"start_time":"2026-10-04T00:00:01.900000Z""#;
        let s = start_of(&kept_exec(
            before,
            r#"{"pid":402,"euid":501,"pidversion":9402}"#,
            r#"{"pid":401,"pidversion":9300}"#,
            r#"{"path":"/Users/example/run.sh"}"#,
        ));
        let at = Some("2026-10-04T00:00:01.900000Z".to_string());
        assert_eq!(
            (s.pid, s.who.pid_version, s.who.started.clone(), s.user_id),
            (402, Some(9402), at.clone(), Some(501))
        );
        assert_eq!(
            s.who.instigator,
            Identity {
                pid: Some(402),
                pid_version: Some(9401),
                started: at.clone()
            }
        );
        assert_eq!(
            s.who.parent,
            Identity {
                pid: Some(401),
                pid_version: Some(9300),
                started: None
            }
        );
        assert_eq!(s.who.script.as_deref(), Some("/Users/example/run.sh"));
        assert_eq!(
            (s.who.codesigning_flags, s.who.instigator_codesigning_flags),
            (Some(570522304), Some(570522385))
        );
        assert_eq!(s.kept, ALL_KEPT);
        // The eight words of audit_token_t, for each of the three.
        let s = start_of(&kept_exec(
            r#""audit_token":[501,501,20,501,20,402,100001,9401],"start_time":null"#,
            "[501,501,20,501,20,402,100001,9402]",
            "[501,501,20,501,20,401,100001,9300]",
            "null",
        ));
        assert_eq!(
            (s.pid, s.who.pid_version, s.user_id),
            (402, Some(9402), Some(501))
        );
        assert_eq!(
            (
                s.who.instigator.pid,
                s.who.instigator.pid_version,
                s.who.instigator.started
            ),
            (Some(402), Some(9401), None)
        );
        assert_eq!(
            (s.who.parent.pid, s.who.parent.pid_version),
            (Some(401), Some(9300))
        );
        assert_eq!(s.who.script, None);
        assert_eq!(s.kept, ALL_KEPT);
        // Shapes nobody expects: absent, and the start read whole.
        let s = start_of(&kept_exec(
            r#""audit_token":"402","start_time":{"tv_sec":1}"#,
            r#"{"pid":402,"euid":501,"pidversion":"9402"}"#,
            "[401,9300]",
            r#"{"path":["/Users/example/run.sh"]}"#,
        ));
        assert_eq!((s.pid, s.who.pid_version), (402, None));
        assert_eq!(s.who.instigator, Identity::default());
        assert_eq!(s.who.parent, Identity::default());
        assert_eq!(s.who.script, None);
        assert_eq!(s.args, ["sh", "run.sh"]);
        // A line of the collector before it kept them: as it was always read, keeping none.
        let s = start_of(&exec(7, OBJECT));
        assert_eq!(
            (
                s.who.pid_version,
                s.who.started.clone(),
                s.who.script.clone(),
                s.kept
            ),
            (None, None, None, 0)
        );
        assert_eq!(
            (s.who.instigator, s.who.parent, s.who.codesigning_flags),
            (Identity::default(), Identity::default(), None)
        );
        // What each mark stands for: a line that kept only some says so.
        let no_script = kept_exec(before, OBJECT, "null", "null").replace(r#""script":null,"#, "");
        assert_eq!(start_of(&no_script).kept, IDENTITY | SIGNATURE);
        let no_flags = kept_exec(before, OBJECT, "null", "null")
            .replace(r#","codesigning_flags":570522304"#, "");
        assert_eq!(start_of(&no_flags).kept, IDENTITY | SCRIPT);
        let no_start = kept_exec(before, OBJECT, "null", "null").replace(
            r#""start_time":"2026-10-04T00:00:01.900000Z","parent"#,
            r#""parent"#,
        );
        assert_eq!(start_of(&no_start).kept, SCRIPT | SIGNATURE);
    }

    #[test]
    fn who_did_a_file_event_is_read_where_its_line_gives_it_and_an_older_line_keeps_none() {
        // As for a start: the program that created or renamed a file, by its audit token in
        // either shape and its start time, and its signing id, which a rule of Elastic's reads.
        let kept = |token: &str, started: &str, signing: &str| {
            created(3, "/Users/example/a").replace(
                r#"{"executable":{"path":"/usr/bin/curl"}}"#,
                &format!(
                    r#"{{"executable":{{"path":"/usr/bin/curl"}},"audit_token":{token},"start_time":{started},"signing_id":{signing}}}"#
                ),
            )
        };
        let file_of = |text: &str| match line(text.as_bytes()) {
            Ok(Line::File { event: Some(f), .. }) => *f,
            other => panic!("{other:?}: {text}"),
        };
        let f = file_of(&kept(
            r#"{"pid":500,"pidversion":9500}"#,
            r#""2026-10-04T00:00:02.5Z""#,
            r#""com.apple.curl""#,
        ));
        assert_eq!(
            f.instigator,
            Identity {
                pid: Some(500),
                pid_version: Some(9500),
                started: Some("2026-10-04T00:00:02.5Z".into())
            }
        );
        assert_eq!(
            (f.signing_id.as_deref(), f.kept),
            (Some("com.apple.curl"), IDENTITY | SIGNATURE)
        );
        let f = file_of(&kept("[501,501,20,501,20,500,100001,9500]", "null", "null"));
        assert_eq!(
            (
                f.instigator.pid,
                f.instigator.pid_version,
                f.signing_id,
                f.kept
            ),
            (Some(500), Some(9500), None, IDENTITY | SIGNATURE)
        );
        let f = file_of(&kept(
            r#""500""#,
            r#"{"tv_sec":1}"#,
            r#"["com.apple.curl"]"#,
        ));
        assert_eq!((f.instigator, f.signing_id), (Identity::default(), None));
        assert_eq!(f.path, "/Users/example/a");
        let f = file_of(&created(3, "/Users/example/a"));
        assert_eq!(
            (f.instigator, f.signing_id, f.kept),
            (Identity::default(), None, 0)
        );
        // What each mark stands for: a line that kept only one says so.
        let only_who = kept("null", "null", "null").replace(r#","signing_id":null"#, "");
        assert_eq!(file_of(&only_who).kept, IDENTITY);
        let only_signer = kept("null", "null", "null").replace(r#","start_time":null"#, "");
        assert_eq!(file_of(&only_signer).kept, SIGNATURE);
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
                ..FileEvent::default()
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
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-keep-{}", std::process::id())),
        );
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
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-basis-{}", std::process::id())),
        );
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
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-hours-{}", std::process::id())),
        );
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
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-speed-{}", std::process::id())),
        );
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
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-files-{}", std::process::id())),
        );
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
            arrivals: Default::default(),
            cap: None,
        };
        let said = words(&l);
        assert_eq!(said.state, "on");
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
        l.last_day.unknown_gaps = 1_200;
        assert!(words(&l).notes[0].starts_with("The collector restarted 1,200 times;"));
        l.last_day = Tally::default();
        assert!(words(&l).notes.is_empty());
        l.state = NOT_INSTALLED.to_string();
        let off = words(&l);
        assert_eq!(off.state, "not installed");
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
            arrivals: Default::default(),
            cap: None,
        };
        let v = serde_json::to_value(message(&l)).unwrap();
        assert_eq!(
            v["program_starts_by_hour"],
            json!({ "ends_at": 1_791_000_000, "step_seconds": 3600, "counts": [7] })
        );
        assert_eq!(
            v["program_starts_by_minute"],
            json!({ "ends_at": 1_791_000_000, "step_seconds": 60, "counts": [2, 0, 3] })
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
            arrivals: Default::default(),
            cap: None,
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
                ("deleted_early", "2 files deleted early"),
                ("deleted_unread", "1 file deleted unread"),
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
        let mut pending = 0;
        for seq in [1, 2, 5, 6, 1, 2] {
            count_seq(
                seq,
                &mut last,
                (&mut t.lost, &mut t.unknown_gaps),
                &mut pending,
            );
        }
        assert_eq!((t.lost, t.unknown_gaps), (2, 1));
        // The first number ever read says nothing about what came before.
        let (mut t, mut last) = (Tally::default(), None);
        count_seq(
            40,
            &mut last,
            (&mut t.lost, &mut t.unknown_gaps),
            &mut pending,
        );
        assert_eq!((t.lost, t.unknown_gaps, last), (0, 0, Some(40)));
    }

    #[test]
    fn a_message_the_filter_marked_unreadable_is_counted_once_and_never_again_as_lost() {
        // Two markers, then a gap of three: two of the numbers are the markers' messages, one
        // the kernel dropped. A marker no gap took in is still pending, and a restart takes in
        // every marker before it, since what was lost across it is of unknown size.
        let (mut t, mut last, mut pending) = (Tally::default(), Some(10), 2);
        count_seq(
            14,
            &mut last,
            (&mut t.lost, &mut t.unknown_gaps),
            &mut pending,
        );
        assert_eq!((t.lost, pending), (1, 0));
        let mut pending = 3;
        count_seq(
            16,
            &mut last,
            (&mut t.lost, &mut t.unknown_gaps),
            &mut pending,
        );
        assert_eq!((t.lost, pending), (1, 2));
        count_seq(
            17,
            &mut last,
            (&mut t.lost, &mut t.unknown_gaps),
            &mut pending,
        );
        assert_eq!((t.lost, pending), (1, 2));
        count_seq(
            3,
            &mut last,
            (&mut t.lost, &mut t.unknown_gaps),
            &mut pending,
        );
        assert_eq!((t.lost, t.unknown_gaps, pending), (1, 1, 0));
        // The filter's marker is told from a line that is not an object and from a message.
        assert_eq!(line(br#"{"unreadable":true}"#), Ok(Line::Marker));
        assert_eq!(line(br#""unreadable""#), Ok(Line::Unreadable));
        assert!(line(br#"{"unreadable":true,"event":{"exec":{}}}"#).is_err());
        assert!(line(br#"{"unreadable":false}"#).is_err());
    }

    /// What the lines say of each of `KEEPS`, by name: `-` not yet known, `x` not kept, `0`
    /// kept and never filled, `+<since>` arriving, `!<since>` no longer arriving.
    fn told(a: &Arrivals) -> Vec<String> {
        (0..KEEPS.len())
            .map(|i| match a.of(1 << i) {
                Arrival::Unknown => "-".to_string(),
                Arrival::NotKept => "x".to_string(),
                Arrival::Kept(None) => "0".to_string(),
                Arrival::Kept(Some(t)) => format!("+{t}"),
                Arrival::NoLonger(t) => format!("!{t}"),
            })
            .collect()
    }

    /// How many lines of its kind in a row without a value tell that `keep` stopped.
    fn most(keep: Keeps) -> u64 {
        MARKS.iter().find(|(_, k, _)| *k == keep).unwrap().2
    }

    #[test]
    fn a_field_the_collector_stops_filling_is_told_as_no_longer_arriving_and_since_when() {
        // No false calm after a macOS update renames a field or changes its shape, or after an
        // older filter is put back: the filter then writes the key with null, and the state
        // follows the lines read now. A field every process has (who it is, its code-signing
        // flags, its signer on a file event) no longer arrives from the first line without it;
        // the script, which few starts have, after `most(SCRIPT)` starts in a row without one.
        // Each says since the first line without a value, and arrives again from the next value.
        use crate::sigma::Kind::{File, Process};
        let mut a = Arrivals::default();
        a.line(Process, ALL_KEPT, ALL_KEPT, 10);
        a.line(File, IDENTITY | SIGNATURE, IDENTITY | SIGNATURE, 11);
        assert_eq!(told(&a), ["+11", "+10", "+11"]);
        // A start that gives no start time: who each process is no longer arrives.
        a.line(Process, ALL_KEPT, SIGNATURE, 20);
        assert_eq!(told(&a), ["!20", "+10", "+11"]);
        assert_eq!(a.not_arriving(), IDENTITY);
        assert_eq!(a.no_longer(), [("identity", 20)]);
        a.line(Process, ALL_KEPT, SIGNATURE, 21);
        assert_eq!(told(&a), ["!20", "+10", "+11"]);
        // It arrives again from the next start that gives it.
        a.line(Process, ALL_KEPT, IDENTITY | SIGNATURE, 30);
        assert_eq!(told(&a), ["+30", "+10", "+11"]);
        // A file event whose program's signer is null: the signer no longer arrives.
        a.line(File, IDENTITY | SIGNATURE, IDENTITY, 31);
        assert_eq!(told(&a), ["+30", "+10", "!31"]);
        // Starts 20, 21 and 30 gave no script. The rest of a run of `most(SCRIPT)` keeps it
        // arriving until its last line, and then it no longer arrives, since the first of them.
        let run = most(SCRIPT);
        assert!(run > 4);
        for t in 0..run - 4 {
            a.line(Process, ALL_KEPT, IDENTITY | SIGNATURE, 100 + t as i64);
        }
        assert_eq!(told(&a)[1], "+10");
        a.line(Process, ALL_KEPT, IDENTITY | SIGNATURE, 5000);
        assert_eq!(told(&a)[1], "!20");
        a.line(Process, ALL_KEPT, IDENTITY | SIGNATURE, 5001);
        assert_eq!(told(&a)[1], "!20");
        // A line that lacks a key is an earlier collector's, whatever came before.
        a.line(Process, 0, 0, 5002);
        assert_eq!(told(&a), ["x", "x", "x"]);
        // And a key that is there with no value after it, kept and never filled.
        a.line(Process, ALL_KEPT, 0, 5003);
        assert_eq!(told(&a), ["0", "0", "0"]);
        assert_eq!(a.0[4], Arrival::NoLonger(31));
        // Both kinds that mark a group stopped: it stopped when the first of them did.
        let mut b = Arrivals::default();
        b.line(Process, ALL_KEPT, ALL_KEPT, 1);
        b.line(File, IDENTITY | SIGNATURE, IDENTITY | SIGNATURE, 2);
        b.line(File, IDENTITY | SIGNATURE, 0, 7);
        b.line(Process, ALL_KEPT, SCRIPT, 9);
        assert_eq!(told(&b), ["!7", "+1", "!7"]);
        // Each mark of a field every process has: one line of its kind without a value.
        for (kind, keep) in [
            (Process, IDENTITY),
            (Process, SIGNATURE),
            (File, IDENTITY),
            (File, SIGNATURE),
        ] {
            let mut c = Arrivals::default();
            c.line(Process, ALL_KEPT, ALL_KEPT, 1);
            c.line(File, IDENTITY | SIGNATURE, IDENTITY | SIGNATURE, 1);
            let kept = if kind == Process {
                ALL_KEPT
            } else {
                IDENTITY | SIGNATURE
            };
            c.line(kind, kept, kept & !keep, 5);
            assert_eq!(c.of(keep), Arrival::NoLonger(5), "{kind:?} {keep}");
        }
    }

    #[test]
    fn a_rarely_filled_field_is_not_told_as_stopped_by_starts_that_never_carry_it_by_nature() {
        // On the first install on a Mac one start in 32 named a script. Starts that are no
        // interpreter run on a script file carry its key with null, in runs as long as the work
        // of the moment makes them: up to one short of `most(SCRIPT)`, the script goes on
        // arriving since the first start that gave one, and who each process is and its
        // signer, which every start gives, go on arriving too.
        use crate::sigma::Kind::{File, Process};
        let mut a = Arrivals::default();
        a.line(File, IDENTITY | SIGNATURE, IDENTITY | SIGNATURE, 1_000);
        let mut t = 1_000;
        for run in [31, 0, 5, most(SCRIPT) - 1, 400, most(SCRIPT) - 1] {
            a.line(Process, ALL_KEPT, ALL_KEPT, t);
            for _ in 0..run {
                t += 1;
                a.line(Process, ALL_KEPT, IDENTITY | SIGNATURE, t);
            }
            assert_eq!(told(&a), ["+1000", "+1000", "+1000"], "a run of {run}");
            t += 1;
        }
        // A start without a value under a field every process has is no such run.
        a.line(Process, ALL_KEPT, SCRIPT | SIGNATURE, t);
        assert_eq!(told(&a), [format!("!{t}"), "+1000".into(), "+1000".into()]);
        // The run is the one the document states.
        assert_eq!(most(SCRIPT), 1000);
        assert!(
            include_str!("../docs/event-level.md")
                .contains("It no longer arrives after 1,000 program starts in a row without one")
        );
    }

    /// A program start as the filter that keeps who each process is writes it, at `second`:
    /// the program's start time given or null, a script named or null.
    fn kept_start(seq: u64, second: i64, identity: bool, script: bool) -> String {
        let script = if script {
            r#"{"path":"/Users/example/run.sh"}"#
        } else {
            "null"
        };
        let line = kept_exec(
            r#""audit_token":{"pid":401,"pidversion":9401}"#,
            r#"{"pid":402,"euid":501,"pidversion":9402}"#,
            r#"{"pid":401,"pidversion":9300}"#,
            script,
        )
        .replace(
            r#""seq_num":7,"global_seq_num":7"#,
            &format!(r#""seq_num":{seq},"global_seq_num":{seq}"#),
        )
        .replace("2026-10-04T00:00:02.000002Z", &crate::view::iso(second));
        if identity {
            line + "\n"
        } else {
            line.replace(
                r#""start_time":"2026-10-04T00:00:01.900000Z""#,
                r#""start_time":null"#,
            ) + "\n"
        }
    }

    /// A system root of its own for a test, with the collector installed and its log empty.
    fn installed(tag: &str) -> crate::common::Scratch {
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-{tag}-{}", std::process::id())),
        );
        std::fs::create_dir_all(dir.join(LOG)).unwrap();
        let plist = dir.join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        dir
    }

    /// Appends `text` to the log file `name` under `root`, then gives it `at` as the time it was
    /// last written.
    fn write_at(root: &Path, name: &str, text: &str, at: i64) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join(LOG).join(name))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at as u64))
            .unwrap();
    }

    /// A reading of the log under `root` on from `left`: what it says arrives, and where it left
    /// off, for the next.
    fn looked(root: &Path, left: &Left, now: i64) -> Left {
        let Found::Read(log) = look(root, left, now, Rules::shipped()) else {
            panic!("the log is read");
        };
        Left {
            files: log
                .files
                .iter()
                .map(|(name, inode, to)| (name.clone(), (*inode, *to)))
                .collect(),
            arrivals: log.arrivals,
            ..Left::default()
        }
    }

    #[test]
    fn lines_of_an_earlier_collector_read_before_or_after_the_current_one_s_do_not_change_what_is_told()
     {
        // No false calm after a downgrade. An earlier collector names its files by the hour, and
        // they sort before a later collector's, so after a downgrade the files the later one
        // wrote before are read after what the earlier one writes now. What the core's reading
        // tells comes from the file being written now, however the names sort.
        let now = 1_791_090_000;
        let earlier = "exec-20261004T00.jsonl";
        let later = "exec-20261004T000013-20261004T000000.jsonl";
        let kept = kept_start(1, now - 100, true, false);
        let old = exec(2, OBJECT) + "\n";
        // A file event as each collector writes it: the later one keeps who acted and its
        // signer.
        let old_file = created(1, "/Users/example/a") + "\n";
        let kept_file = old_file.replace(
            r#"{"executable":{"path":"/usr/bin/curl"}}"#,
            r#"{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":402,"pidversion":9402},"start_time":"2026-10-04T00:00:01.900000Z","signing_id":"com.example.tool","codesigning_flags":570522385}"#,
        );
        assert_ne!(kept_file, old_file);
        // An upgrade: the earlier collector's file written first, the later one's after. No
        // file event was read, so who acts on files is not yet known.
        let up = installed("arrival-upgrade");
        write_at(&up, earlier, &old, now - 200);
        write_at(&up, later, &kept, now - 100);
        assert_eq!(
            told(&looked(&up, &Left::default(), now).arrivals),
            ["-", "0", "-"]
        );
        // The earlier collector put back: its lines, written now, say what is kept, though its
        // file is read first and the later collector's after it. It has written a file event
        // and no program start yet, so what program starts carry is not yet known. A file the
        // later collector left empty, written last, holds nothing to tell.
        let down = installed("arrival-downgrade");
        write_at(&down, later, &(kept.clone() + &kept_file), now - 200);
        write_at(&down, earlier, &old_file, now - 100);
        write_at(&down, "exec-20261004T000013-20261004T060000.jsonl", "", now);
        let read = looked(&down, &Left::default(), now);
        assert_eq!(told(&read.arrivals), ["x", "-", "x"]);
        // Read on: the earlier collector goes on writing, and the later one's file holds
        // nothing new.
        write_at(&down, earlier, &(exec(3, OBJECT) + "\n"), now - 50);
        let read = looked(&down, &read, now);
        assert_eq!(told(&read.arrivals), ["x", "x", "x"]);
        // The later collector installed again: told from its first line.
        write_at(&down, later, &kept_start(4, now - 10, true, true), now - 10);
        assert_eq!(
            told(&looked(&down, &read, now).arrivals),
            ["x", "+1791089990", "x"]
        );
        // A clock set back: the file being written has the earlier name and the earlier time of
        // the two, and the other, written before with the clock ahead, held values its
        // collector no longer gives. Only the file that grows speaks.
        let back = installed("arrival-clock");
        let ahead_name = "exec-20261004T000013-20261004T050000.jsonl";
        let back_name = "exec-20261004T000013-20261004T010000.jsonl";
        write_at(&back, ahead_name, &kept, now);
        write_at(&back, back_name, &kept, now - 3600);
        let read = looked(&back, &Left::default(), now);
        write_at(
            &back,
            back_name,
            &kept_start(5, now - 3500, false, false),
            now - 3500,
        );
        // Who the program started is, in a program start: no file event was read.
        let stopped = Arrival::NoLonger(now - 3500);
        assert_eq!(looked(&back, &read, now).arrivals.0[0], stopped);
        for root in [up, down, back] {
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn a_run_of_lines_without_a_value_is_counted_across_readings() {
        // The core reads every ten seconds, so the run of starts without a script goes on from
        // where the last reading left it, in the store. An earlier build's store has no such
        // run and is given one.
        let now = 1_791_090_000;
        let root = installed("arrival-run");
        let name = "exec-20261004T000013-20261004T000000.jsonl";
        let starts = |from: u64, n: u64| -> String {
            (from..from + n)
                .map(|seq| kept_start(seq, now - 5000 + seq as i64, true, seq == 1))
                .collect()
        };
        let run = most(SCRIPT);
        write_at(&root, name, &starts(1, run / 2), now - 2);
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-run-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE event_arrival (kind TEXT NOT NULL, keep TEXT NOT NULL,
                 kept INTEGER NOT NULL, filled INTEGER, PRIMARY KEY (kind, keep));",
        )
        .unwrap();
        let read = |conn: &mut rusqlite::Connection| {
            let tx = conn.transaction().unwrap();
            crate::store::put_entity(&tx, "machine:mac").unwrap();
            read(&tx, "events-1", "machine:mac", &root, now).unwrap();
            tx.commit().unwrap();
            told(&arrivals(conn).unwrap())
        };
        assert_eq!(read(&mut conn)[1], format!("+{}", now - 4999));
        write_at(
            &root,
            name,
            &starts(run / 2 + 1, run - run / 2 + 1),
            now - 1,
        );
        assert_eq!(read(&mut conn)[1], format!("!{}", now - 4998));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_bound_counts_the_starts_of_the_file_being_written_as_the_core_reads_them() {
        // The bound of a script's run is 1,000 starts of the file the collector is writing,
        // read by the core. A reading that finds new lines in two files, across a new file,
        // counts only the newer one's: 1,200 starts without a script over two files leave the
        // script arriving, and it no longer arrives once the newer file alone holds 1,000.
        let now = 1_791_090_000;
        let root = installed("arrival-bound");
        let older = "exec-20261004T000013-20261004T000000.jsonl";
        let newer = "exec-20261004T000013-20261004T010000.jsonl";
        let starts = |from: u64, to: u64| -> String {
            (from..to)
                .map(|seq| kept_start(seq, now - 5000 + seq as i64, true, seq == 1))
                .collect()
        };
        let first = kept_start(1, now - 4999, true, true);
        write_at(&root, older, &first, now - 3000);
        let read = looked(&root, &Left::default(), now);
        assert_eq!(told(&read.arrivals)[1], format!("+{}", now - 4999));
        write_at(&root, older, &starts(2, 602), now - 2000);
        write_at(&root, newer, &starts(602, 1202), now - 1000);
        let read = looked(&root, &read, now);
        assert_eq!(told(&read.arrivals)[1], format!("+{}", now - 4999));
        write_at(&root, newer, &starts(1202, 1602), now - 500);
        let read = looked(&root, &read, now);
        assert_eq!(told(&read.arrivals)[1], format!("!{}", now - 5000 + 602));
        let _ = std::fs::remove_dir_all(&root);
        assert!(include_str!("../docs/event-level.md").contains(
            "1,000 program starts in a row without one, counted in the file the collector is writing as the core reads it"
        ));
    }

    #[test]
    fn a_store_an_earlier_build_left_is_answered_from_before_its_first_reading_by_this_one() {
        // `immune status`, `rules` and `matches` read the store without a reading of their own,
        // and the store an earlier build left has no columns for the run yet. They answer. A
        // field kept and never filled is so, and one not kept is not kept; a field that build
        // told arriving is not yet known, since it told one arriving for ever after one value,
        // and stays so once this build's first reading has added the columns.
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-old-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.db");
        let mut conn = crate::store::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        schema(&tx).unwrap();
        tx.commit().unwrap();
        conn.execute_batch(
            "ALTER TABLE event_arrival DROP COLUMN stopped;
             ALTER TABLE event_arrival DROP COLUMN quiet;
             ALTER TABLE event_arrival DROP COLUMN quiet_from;
             INSERT INTO event_level (id, read_at, state) VALUES (1, 1, 'running');
             INSERT INTO event_arrival VALUES ('program_start', 'script', 1, 5);
             INSERT INTO event_arrival VALUES ('program_start', 'identity', 1, NULL);
             INSERT INTO event_arrival VALUES ('program_start', 'signature', 0, NULL);",
        )
        .unwrap();
        drop(conn);
        let conn = crate::store::open_read_only(&path).unwrap();
        let level = level(&conn, 10).unwrap().expect("the level is read");
        assert_eq!(
            level.arrivals,
            Arrivals::from([
                Arrival::Kept(None),
                Arrival::Unknown,
                Arrival::NotKept,
                Arrival::Unknown,
                Arrival::Unknown,
            ])
        );
        drop(conn);
        let mut conn = crate::store::open(&path).unwrap();
        let tx = conn.transaction().unwrap();
        schema(&tx).unwrap();
        assert!(has_run(&tx).unwrap());
        assert_eq!(arrivals(&tx).unwrap().0[1], Arrival::Unknown);
        drop(tx);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stretch_names_what_its_lines_did_not_give_a_missing_key_or_an_empty_field_every_process_has()
     {
        // What `immune matches` names beside the store's reading. A line of a kind without a
        // mark's key was not judged by a rule that reads it; a line with the key and no value
        // was judged without it when every process has the field. Most starts run no script,
        // so a start with the script's key and no value is not named. Each kind stands for its
        // own rules, and one line that did not give a field names it for the whole stretch.
        use crate::sigma::Kind::{File, Process};
        let after = |lines: &[(crate::sigma::Kind, Keeps, Keeps)]| {
            let mut lacked = Lacked::default();
            for (kind, kept, filled) in lines {
                lacked.line(*kind, *kept, *filled);
            }
            (lacked.of(Process), lacked.of(File))
        };
        let file = IDENTITY | SIGNATURE;
        assert_eq!(after(&[]), (0, 0));
        assert_eq!(
            after(&[(Process, ALL_KEPT, ALL_KEPT), (File, file, file)]),
            (0, 0)
        );
        assert_eq!(after(&[(Process, ALL_KEPT, IDENTITY | SIGNATURE)]), (0, 0));
        assert_eq!(
            after(&[(Process, IDENTITY | SIGNATURE, IDENTITY | SIGNATURE)]),
            (SCRIPT, 0)
        );
        assert_eq!(
            after(&[
                (Process, ALL_KEPT, SCRIPT | SIGNATURE),
                (Process, ALL_KEPT, ALL_KEPT)
            ]),
            (IDENTITY, 0)
        );
        assert_eq!(
            after(&[(Process, ALL_KEPT, IDENTITY | SCRIPT)]),
            (SIGNATURE, 0)
        );
        assert_eq!(after(&[(File, file, IDENTITY)]), (0, SIGNATURE));
        assert_eq!(after(&[(File, SIGNATURE, SIGNATURE)]), (0, IDENTITY));
        assert_eq!(after(&[(Process, 0, 0)]), (ALL_KEPT, 0));
    }

    #[test]
    fn every_kept_field_a_shipped_rule_reads_is_its_group_s_mark_and_filled_on_every_line() {
        // `immune matches` names a rule whose group some line it read did not give (`Lacked`),
        // and that is whole only for a field that is its group's mark and that every line of
        // its kind fills: one line without it is then the collector not filling it. A group
        // filled only on some lines by nature, as the script is, is judged by the core's latest
        // reading alone, and an answer over starts that reading has not read stays quiet after
        // the collector stops filling it, until the reading has counted the bound, or for as
        // long as the core does not read. So no shipped rule may read one. Before one does, the
        // answer must say how many of the lines it judged the core's latest reading has not
        // read, and count that in what makes an answer quiet. A field that is not its group's
        // mark needs the same: what the mark says would not be what the rule reads.
        //
        // The kept fields known to be their group's mark, by kind, name and group. A field is
        // added here only when the key `MARKS` describes for it is the one its value comes from.
        let marked_by_itself = [(
            crate::sigma::Kind::File,
            "process.code_signature.signing_id",
            SIGNATURE,
        )];
        let filled_on_every_line = |kind, keep| {
            MARKS
                .iter()
                .any(|(k, m, most)| *k == kind && *m == keep && *most == 1)
        };
        for source in crate::sigma::SOURCES {
            for &(kind, field, keep) in source.schema.kept {
                assert!(
                    marked_by_itself.contains(&(kind, field, keep)),
                    "{field} of {} is not its group's mark",
                    source.name
                );
                assert!(filled_on_every_line(kind, keep), "{field}");
            }
        }
        for rule in &Rules::shipped().rules {
            for keep in (0..KEEPS.len())
                .map(|i| 1 << i)
                .filter(|k| rule.needs & k != 0)
            {
                let kind = rule
                    .kind
                    .expect("a rule that needs a kept field has a kind");
                assert!(filled_on_every_line(kind, keep), "{}", rule.file);
            }
        }
    }

    #[test]
    fn a_run_no_build_stores_never_makes_calm_and_a_long_one_does_not_overflow() {
        // The store is a file a program running as the user can rewrite. A run of lines
        // without a value as long as its mark's bound, or longer, is told as no longer
        // arriving, since its first line; one shorter goes on. A run at the largest count
        // stays there instead of wrapping to none, in a debug build and a release one.
        let mut quiet = Quiet {
            lines: u64::MAX,
            from: 7,
        };
        let a = Arrival::Kept(Some(1)).after(&mut quiet, u64::MAX, true, false, 9);
        assert_eq!(a, Arrival::NoLonger(7));
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-events-forged-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        schema(&tx).unwrap();
        tx.commit().unwrap();
        conn.execute_batch(
            "INSERT INTO event_arrival VALUES ('program_start', 'script', 1, 5, NULL, 1000, 6);
             INSERT INTO event_arrival VALUES ('program_start', 'identity', 1, 5, NULL, 9, 6);
             INSERT INTO event_arrival VALUES ('file_event', 'identity', 1, 5, NULL, 1, 8);",
        )
        .unwrap();
        let a = arrivals(&conn).unwrap();
        assert_eq!(
            a.0,
            [
                Arrival::NoLonger(6),
                Arrival::NoLonger(6),
                Arrival::Unknown,
                Arrival::NoLonger(8),
                Arrival::Unknown,
            ]
        );
        conn.execute_batch("UPDATE event_arrival SET quiet = 999 WHERE keep = 'script';")
            .unwrap();
        let mut a = arrivals(&conn).unwrap();
        assert_eq!(a.0[1], Arrival::Kept(Some(5)));
        a.line(
            crate::sigma::Kind::Process,
            ALL_KEPT,
            IDENTITY | SIGNATURE,
            20,
        );
        assert_eq!(a.0[1], Arrival::NoLonger(6));
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
