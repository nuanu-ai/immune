//! Samples of this user's processes and their internet connections, and the one rule over
//! them. This is level of access (a) in `docs/scheme.md`: no administrator rights and nothing
//! that asks for a permission. A sample says what is running at one moment. It is not an
//! event: Apple's Endpoint Security names the start of a program `exec`, and a sample never
//! sees that moment, so nothing here carries an Endpoint Security event name. The fields are
//! named after the Elastic Common Schema: `process.pid`, `process.start`,
//! `process.parent.pid`, `process.executable`, `process.interactive`,
//! `process.code_signature`, `destination.ip`, `destination.port`, `network.transport`.
//!
//! The calls are the system's own: libproc (`libproc.h`, `sys/proc_info.h`) and sysctl
//! (`sys/sysctl.h`), through `libc` where it declares them. Where it does not, the declaration
//! is below, copied from `sys/proc_info.h` of the macOS SDK with its line, and its size is
//! checked at build time against the SDK's `sizeof` and at each call against what the kernel
//! says it wrote. No tool is run.
//!
//! A command line is read into memory only for a program the interpreter table names, only to
//! decide one literal, and is dropped there. It is never stored, printed or returned.
//!
//! What is kept: a small table of the processes the rule is tracking and one of connections
//! that matched an indicator, see `SCHEMA`, both trimmed of what has been gone for `KEEP`.
//! A process is not an entity with a lifecycle: it lives for minutes or days, and the facts
//! and their lifecycle are for what the owner has. The scheme's Event table is where a process
//! with a stable identity belongs; these tables are its first rough form, for two rules.
//! A finding a sample raises rests on a journal entry `sampled`, one per raise, naming the
//! program, the process's identity and what was derived; never its command line.
//! Each sample's coverage is one row per kind, replaced at every sample: a sample every
//! thirty seconds would otherwise outgrow every other reading's history.

use crate::codesign;
use crate::findings::Observed;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, c_void};
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

/// Created when a sample is first recorded. One row per process the rule is tracking: an
/// interpreter given code on its command line whose parent was gone or was launchd when a
/// sample saw it.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS tracked_process (
    pid            INTEGER NOT NULL,  -- process.pid
    start          INTEGER NOT NULL,  -- process.start, microseconds since the epoch
    executable     TEXT NOT NULL,     -- process.executable
    interpreter    TEXT NOT NULL,     -- the kind in the interpreter table
    shape          TEXT NOT NULL,     -- what the rule derived from the command line
    -- process.interactive: some sample saw it with a controlling terminal.
    interactive    INTEGER NOT NULL,
    code_signature TEXT,              -- who signed the executable, as `signed_by` says it
    first_seen_at  INTEGER NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    last_seen_run  TEXT NOT NULL,
    PRIMARY KEY (pid, start)
);
-- A connection of a process to an address on the indicator list, once per process and
-- indicator, so that a connection that stays raises its finding once.
CREATE TABLE IF NOT EXISTS matched_connection (
    pid           INTEGER NOT NULL,
    start         INTEGER NOT NULL,
    indicator     TEXT NOT NULL,     -- the STIX comparison it matched
    executable    TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (pid, start, indicator)
);
-- The latest sample, for the status: when, and how many processes and connections it read.
CREATE TABLE IF NOT EXISTS last_sample (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    at          INTEGER NOT NULL,
    processes   INTEGER NOT NULL,
    connections INTEGER NOT NULL
);
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('running programs of this user, sampled'),
    ('internet connections of this user''s programs, sampled');
";

/// The reader's name in coverage and the journal.
pub const READER: &str = "processes";
/// The coverage kinds of a sample.
pub const PROGRAMS_KIND: &str = "running programs of this user, sampled";
pub const CONNECTIONS_KIND: &str = "internet connections of this user's programs, sampled";
/// How the run id of a sample begins.
pub const RUN_PREFIX: &str = "sample-";
/// How long a process, or its matched connection, is kept after the last sample that saw it.
pub const KEEP: i64 = 24 * 60 * 60;
/// What a sample cannot see, for a person, as the view says it under what a watcher cannot see.
pub const PERSON_CANNOT_SEE: [&str; 3] = [
    "a program that started and ended between two samples",
    "other users' programs",
    "who a connection's address belongs to: it has an address, not a name",
];

/// The one literal derived from a command line.
pub const INLINE_CODE: &str = "interpreter given code on its command line";

/// What the rule is told, and the kind of its findings.
pub const DETACHED_INLINE: &str = "interpreter running code from its command line, detached";

/// Two samples must see a process at least this far apart before the rule fires. It is the
/// resync interval the research proposes for a watcher.
pub const MIN_APART: i64 = 60;

/// What every sample says it cannot see.
pub const CANNOT_SEE: [&str; 8] = [
    "the arguments and connections of other users' processes",
    "processes that started and ended between two samples",
    "connections opened and closed between two samples",
    "UDP sockets without a connected peer",
    "the names behind addresses: no name resolution is seen",
    "who started a process",
    "an interpreter running under another program's name, such as an application run as node",
    "an agent session outside a terminal: its detached children are not told apart from others",
];

/// The level of access a sample is taken at.
pub const LEVEL: &str = "samples without administrator rights";

/// A kind of interpreter and how it is given code on its command line. This is data: a new
/// interpreter is one more row, and nothing here is a rule about one product.
pub struct Interpreter {
    pub kind: &'static str,
    /// The executable's file name, lower case, with a version at its end taken off:
    /// `python3.12` and `Python` are `python`.
    pub names: &'static [&'static str],
    /// Options that take code: a short one also inside a cluster, as in `-lc`; a long one
    /// also as `--eval=…`.
    pub inline: &'static [&'static str],
    /// Options that take a value, so that the value is not taken for a script.
    pub with_value: &'static [&'static str],
    /// A word that, as the first argument that is not an option, means code follows.
    pub subcommand: Option<&'static str>,
}

/// The interpreters the research saw run on a Mac, and nothing else. Their ATT&CK
/// sub-techniques of Command and Scripting Interpreter (T1059): JavaScript (.007) for node,
/// bun and deno, Python (.006), Unix Shell (.004), AppleScript (.002); Ruby and Perl have
/// none of their own.
pub const INTERPRETERS: [Interpreter; 7] = [
    Interpreter {
        kind: "node",
        names: &["node", "bun"],
        inline: &["-e", "--eval", "-p", "--print"],
        with_value: &[
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "-C",
            "--conditions",
            "--input-type",
            "--preload",
        ],
        subcommand: None,
    },
    Interpreter {
        kind: "deno",
        names: &["deno"],
        inline: &[],
        with_value: &[],
        subcommand: Some("eval"),
    },
    Interpreter {
        kind: "python",
        names: &["python"],
        inline: &["-c"],
        with_value: &["-W", "-X"],
        subcommand: None,
    },
    Interpreter {
        kind: "ruby",
        names: &["ruby"],
        inline: &["-e"],
        with_value: &["-r", "-I", "-C", "-E"],
        subcommand: None,
    },
    Interpreter {
        kind: "perl",
        names: &["perl"],
        inline: &["-e", "-E"],
        with_value: &["-I", "-M", "-m"],
        subcommand: None,
    },
    Interpreter {
        kind: "shell",
        names: &["sh", "bash", "zsh", "dash", "ksh"],
        inline: &["-c"],
        with_value: &["-o"],
        subcommand: None,
    },
    Interpreter {
        kind: "osascript",
        names: &["osascript"],
        inline: &["-e"],
        with_value: &["-l", "-s"],
        subcommand: None,
    },
];

/// The interpreter a file name names, if any.
pub fn interpreter(file_name: &str) -> Option<&'static Interpreter> {
    let lower = file_name.to_ascii_lowercase();
    let name = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().find(|i| i.names.contains(&name))
}

/// Whether these arguments, the first one being the program's own name, give the interpreter
/// code. Options are read as getopt reads them, up to the first argument that is not an
/// option: what follows a script's path belongs to the script. An option with a value that
/// the table does not list ends the reading early, so code after it is not seen.
pub fn inline_code(i: &Interpreter, args: &[String]) -> bool {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--" || a == "-" || !a.starts_with('-') {
            return i.subcommand == Some(a.as_str());
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = format!("--{}", long.split('=').next().unwrap_or_default());
            if i.inline.contains(&name.as_str()) {
                return true;
            }
            if i.with_value.contains(&name.as_str()) && !long.contains('=') {
                it.next();
            }
            continue;
        }
        // A cluster of short options: each letter is one, until one that takes a value,
        // which takes the rest of the cluster or else the next argument.
        let letters: Vec<char> = a.chars().skip(1).collect();
        for (n, c) in letters.iter().enumerate() {
            let flag = format!("-{c}");
            if i.inline.contains(&flag.as_str()) {
                return true;
            }
            if i.with_value.contains(&flag.as_str()) {
                if n + 1 == letters.len() {
                    it.next();
                }
                break;
            }
        }
    }
    false
}

/// One process as the reading of the system gives it, before anything is derived.
pub struct Seen {
    pub pid: i32,
    /// Microseconds since the epoch. With the pid it is the identity: a pid reused after a
    /// process ends is another process.
    pub start: i64,
    pub parent: i32,
    /// `None` when the file is gone and nothing else said where it was.
    pub executable: Option<String>,
    /// The kernel's short name, to recognise an interpreter whose file is gone.
    pub name: String,
    /// It has a controlling terminal.
    pub terminal: bool,
    /// Its arguments, read only for an interpreter, and dropped once the shape is derived.
    /// `None` for an interpreter whose arguments could not be read.
    pub args: Option<Vec<String>>,
}

/// One internet socket of a process, with a remote end.
#[derive(Clone, Debug, PartialEq)]
pub struct Connection {
    pub pid: i32,
    pub start: i64,
    /// `tcp` or `udp`.
    pub transport: &'static str,
    /// The TCP state in the header's words, `connected` for UDP.
    pub state: &'static str,
    /// Canonical: an IPv4 address mapped into IPv6 is that IPv4 address.
    pub address: IpAddr,
    pub port: u16,
}

/// What one reading of the system gave.
pub struct Reading {
    pub at: i64,
    pub processes: Vec<Seen>,
    pub connections: Vec<Connection>,
    /// The pids of other users' processes, launchd among them: listed, not read.
    pub other_users: Vec<i32>,
    /// Processes of this user that could not be read.
    pub unreadable: usize,
    /// Processes that ended between the list and their reading.
    pub ended: usize,
    pub sockets_unreadable: usize,
}

/// A process as the rule reads it: nothing from its command line but the derived literal.
pub struct Process {
    pub pid: i32,
    pub start: i64,
    pub executable: Option<String>,
    pub terminal: bool,
    /// Its parent was launchd or was gone.
    pub detached: bool,
    pub interpreter: Option<&'static Interpreter>,
    /// `Some(INLINE_CODE)` when its arguments gave it code, `None` when they did not;
    /// for an interpreter whose arguments could not be read, see `args_unreadable`.
    pub shape: Option<&'static str>,
}

pub struct Sample {
    pub at: i64,
    pub processes: Vec<Process>,
    pub connections: Vec<Connection>,
    pub other_users: usize,
    pub unreadable: usize,
    pub ended: usize,
    pub sockets_unreadable: usize,
    pub args_unreadable: usize,
}

/// Derives what the rule reads from a reading, and drops every command line in it.
pub fn derive(r: Reading) -> Sample {
    let alive: HashSet<i32> = r
        .processes
        .iter()
        .map(|p| p.pid)
        .chain(r.other_users.iter().copied())
        .collect();
    let mut args_unreadable = 0;
    let processes = r
        .processes
        .into_iter()
        .map(|p| {
            let file_name = p
                .executable
                .as_deref()
                .and_then(|e| e.rsplit('/').next())
                .unwrap_or(&p.name);
            let kind = interpreter(file_name);
            let shape = match (kind, p.args) {
                (Some(i), Some(args)) => inline_code(i, &args).then_some(INLINE_CODE),
                (Some(_), None) => {
                    args_unreadable += 1;
                    None
                }
                _ => None,
            };
            Process {
                pid: p.pid,
                start: p.start,
                executable: p.executable,
                terminal: p.terminal,
                detached: p.parent == 1 || !alive.contains(&p.parent),
                interpreter: kind,
                shape,
            }
        })
        .collect();
    Sample {
        at: r.at,
        processes,
        connections: r.connections,
        other_users: r.other_users.len(),
        unreadable: r.unreadable,
        ended: r.ended,
        sockets_unreadable: r.sockets_unreadable,
        args_unreadable,
    }
}

/// The connections to any of these addresses, compared in canonical form. The port is not
/// compared: an indicator names an address.
pub fn connections_to<'a>(all: &'a [Connection], addresses: &[IpAddr]) -> Vec<&'a Connection> {
    let wanted: HashSet<IpAddr> = addresses.iter().map(IpAddr::to_canonical).collect();
    all.iter().filter(|c| wanted.contains(&c.address)).collect()
}

/// A file by its path, device, inode, size, and modification and change times.
type FileKey = (String, u64, u64, u64, i64, i64, i64, i64);

/// Who signed an executable, looked up once per file: the key is the path with the file's
/// device, inode, size and times, so a file replaced in place is looked up again. A lookup
/// costs about one to two milliseconds; only tracked processes are looked up.
#[derive(Default)]
pub struct Signers {
    known: HashMap<FileKey, Option<String>>,
    pub looked_up: usize,
}

impl Signers {
    pub fn of(&mut self, path: &str) -> Option<String> {
        let m = std::fs::metadata(path).ok()?;
        let key = (
            path.to_string(),
            m.dev(),
            m.ino(),
            m.size(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        );
        self.known
            .entry(key)
            .or_insert_with(|| {
                self.looked_up += 1;
                codesign::Code::at(Path::new(path))
                    .ok()
                    .and_then(|c| c.signer())
            })
            .clone()
    }
}

/// A tracked process as the rule reads it.
struct Tracked {
    interactive: bool,
    first: i64,
    last: i64,
}

/// The rule: seen in two samples at least `MIN_APART` apart, and never with a terminal.
fn fires(t: &Tracked) -> bool {
    !t.interactive && t.last - t.first >= MIN_APART
}

/// What one sample did, in counts.
pub struct Report {
    pub sample: Sample,
    pub took_ms: u128,
    pub tracked_new: usize,
    pub tracked_again: usize,
    /// Connections to an address on the indicator list.
    pub matched: usize,
    pub findings_opened: usize,
}

/// Where a sample is recorded: its run id, this machine, the home folder, and the store's
/// folder, where the indicator list the last run read is kept.
pub struct At<'a> {
    pub run_id: &'a str,
    pub machine: &'a str,
    pub home: &'a Path,
    pub folder: &'a Path,
}

/// Records a sample: the processes the rule tracks, the connections that match the indicator
/// list, the sample's coverage, and the findings. The watcher calls this on a timer; `soc
/// sample` calls it once.
pub fn take(
    tx: &Transaction,
    w: &At,
    reading: Reading,
    took: Instant,
    signers: &mut Signers,
) -> Result<Report, Box<dyn std::error::Error>> {
    let sample = derive(reading);
    let took_ms = took.elapsed().as_millis();
    tx.execute_batch(SCHEMA)?;
    let at = sample.at;
    let (mut tracked_new, mut tracked_again, mut seen) = (0, 0, Vec::new());
    for p in &sample.processes {
        let (Some(i), Some(shape), Some(path), true) =
            (p.interpreter, p.shape, &p.executable, p.detached)
        else {
            continue;
        };
        let before: Option<Tracked> = tx
            .query_row(
                "SELECT interactive, first_seen_at, last_seen_at FROM tracked_process
                 WHERE pid = ?1 AND start = ?2",
                params![p.pid, p.start],
                |r| {
                    Ok(Tracked {
                        interactive: r.get(0)?,
                        first: r.get(1)?,
                        last: r.get(2)?,
                    })
                },
            )
            .optional()?;
        let after = match &before {
            Some(t) => {
                tracked_again += 1;
                tx.execute(
                    "UPDATE tracked_process SET last_seen_at = ?3, last_seen_run = ?4,
                            interactive = interactive OR ?5
                     WHERE pid = ?1 AND start = ?2",
                    params![p.pid, p.start, at, w.run_id, p.terminal],
                )?;
                Tracked {
                    interactive: t.interactive || p.terminal,
                    first: t.first,
                    last: at,
                }
            }
            None => {
                tracked_new += 1;
                tx.execute(
                    "INSERT INTO tracked_process (pid, start, executable, interpreter, shape,
                         interactive, code_signature, first_seen_at, first_seen_run,
                         last_seen_at, last_seen_run)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?8, ?9)",
                    params![
                        p.pid,
                        p.start,
                        path,
                        i.kind,
                        shape,
                        p.terminal,
                        signers.of(path),
                        at,
                        w.run_id
                    ],
                )?;
                Tracked {
                    interactive: p.terminal,
                    first: at,
                    last: at,
                }
            }
        };
        // Raised once per process: when it first meets the rule.
        if fires(&after) && !before.as_ref().is_some_and(fires) {
            let file = program(w, path);
            basis(tx, w, at, DETACHED_INLINE, &file, None, shape, p)?;
            seen.push(observed(DETACHED_INLINE, file));
        }
    }
    let matched = match_connections(tx, w, &sample, &mut seen)?;
    // What has been gone for a day is no longer kept.
    tx.execute(
        "DELETE FROM tracked_process WHERE last_seen_at < ?1",
        [at - KEEP],
    )?;
    tx.execute(
        "DELETE FROM matched_connection WHERE last_seen_at < ?1",
        [at - KEEP],
    )?;
    cover(tx, w, &sample)?;
    let findings_opened = crate::findings::detect(tx, w.run_id, at, &seen)?;
    Ok(Report {
        sample,
        took_ms,
        tracked_new,
        tracked_again,
        matched,
        findings_opened,
    })
}

/// The program's file as the store names it: under the home folder relative to it.
fn program(w: &At, path: &str) -> String {
    let shown = path
        .strip_prefix(&format!("{}/", w.home.display()))
        .unwrap_or(path);
    format!("file:{}/{shown}", w.machine)
}

fn observed(kind: &str, file: String) -> Observed {
    Observed {
        change: "new",
        place: kind.to_string(),
        file,
    }
}

/// The journal entry a raise rests on: the program, the process's identity and what was
/// derived or matched.
#[allow(clippy::too_many_arguments)]
fn basis(
    tx: &Transaction,
    w: &At,
    at: i64,
    kind: &str,
    file: &str,
    predicate: Option<&str>,
    value: &str,
    p: &Process,
) -> rusqlite::Result<()> {
    crate::store::put_entity(tx, file)?;
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              new_value, text)
         VALUES (?1, ?2, 'sampled', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            at,
            w.run_id,
            READER,
            w.machine,
            kind,
            file,
            predicate,
            value,
            json!({ "pid": p.pid, "start": p.start }).to_string()
        ],
    )?;
    Ok(())
}

/// The indicator list the last run read, from its saved copy; `None` when there is none or it
/// cannot be read now.
fn indicator_list(
    tx: &Transaction,
    folder: &Path,
) -> rusqlite::Result<Option<crate::indicators::List>> {
    use crate::indicators;
    let raw = crate::store::last_raw(tx, indicators::READER, indicators::LIST)?;
    Ok(raw
        .and_then(|raw| std::fs::read(folder.join(raw)).ok())
        .and_then(|bytes| indicators::parse(&bytes).ok()))
}

/// Connections to an address of an `ipv4-addr:value` indicator, each raised once per process
/// and indicator. A `domain-name:value` indicator is not matched: a sample has addresses, not
/// names, and names are not resolved. Returns how many connections matched.
fn match_connections(
    tx: &Transaction,
    w: &At,
    sample: &Sample,
    seen: &mut Vec<Observed>,
) -> rusqlite::Result<usize> {
    use crate::indicators::{self, IPV4, Indicator};
    let Some(list) = indicator_list(tx, w.folder)? else {
        return Ok(0);
    };
    let addresses: Vec<IpAddr> = list
        .matched
        .iter()
        .filter(|i| i.kind == IPV4)
        .filter_map(|i| i.value.parse().ok())
        .collect();
    // Indicators: the list's addresses are matched against the sample's connections here.
    let found = connections_to(&sample.connections, &addresses);
    for c in &found {
        let Some(p) = sample
            .processes
            .iter()
            .find(|p| p.pid == c.pid && p.start == c.start)
        else {
            continue;
        };
        let Some(path) = &p.executable else {
            continue;
        };
        let literal = Indicator {
            kind: IPV4,
            value: c.address.to_string(),
        }
        .literal();
        let new = tx.execute(
            "INSERT INTO matched_connection (pid, start, indicator, executable, first_seen_at,
                                            last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT (pid, start, indicator) DO NOTHING",
            params![c.pid, c.start, literal, path, sample.at],
        )? == 1;
        if new {
            let file = program(w, path);
            basis(
                tx,
                w,
                sample.at,
                indicators::MATCHED,
                &file,
                Some("matches_indicator"),
                &literal,
                p,
            )?;
            seen.push(observed(indicators::MATCHED, file));
        } else {
            tx.execute(
                "UPDATE matched_connection SET last_seen_at = ?4
                 WHERE pid = ?1 AND start = ?2 AND indicator = ?3",
                params![c.pid, c.start, literal, sample.at],
            )?;
        }
    }
    Ok(found.len())
}

/// The sample's coverage, one row per kind, in place of the one before, and the counts the
/// status shows. A program or a socket that could not be read makes its kind partial.
fn cover(tx: &Transaction, w: &At, s: &Sample) -> rusqlite::Result<()> {
    use crate::store::{Cause, Gap, Reading as Covered};
    let kinds = [
        (PROGRAMS_KIND, s.unreadable, "programs"),
        (CONNECTIONS_KIND, s.sockets_unreadable, "sockets"),
    ];
    for (kind, failed, why) in kinds {
        tx.execute(
            "DELETE FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
            params![READER, w.machine, kind],
        )?;
        let reading = Covered {
            reader: READER,
            scope: w.machine,
            kind,
            run_id: w.run_id,
            at: s.at,
            observed_at: s.at,
        };
        if failed == 0 {
            crate::store::put_coverage(tx, &reading, "full", None, &Gap::default())?;
        } else {
            let reason = format!("{why} that could not be read: {failed}");
            crate::store::put_coverage(
                tx,
                &reading,
                "partial",
                Some(&reason),
                &Gap::of(Cause::Failed),
            )?;
        }
    }
    tx.execute(
        "INSERT INTO last_sample (id, at, processes, connections) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT (id) DO UPDATE SET at = excluded.at, processes = excluded.processes,
             connections = excluded.connections",
        params![s.at, s.processes.len() as i64, s.connections.len() as i64],
    )?;
    Ok(())
}

/// How many programs the latest sample read, or `None` when no sample was taken here.
pub fn last_sampled(conn: &rusqlite::Connection) -> rusqlite::Result<Option<i64>> {
    Ok(last_sample(conn)?.map(|(_, programs, _)| programs))
}

/// When the latest sample was taken, and how many programs and connections it read.
pub fn last_sample(conn: &rusqlite::Connection) -> rusqlite::Result<Option<(i64, i64, i64)>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'last_sample')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    conn.query_row(
        "SELECT at, processes, connections FROM last_sample WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
}

impl Report {
    pub fn json(&self) -> Value {
        let s = &self.sample;
        let interpreters = s.processes.iter().filter(|p| p.interpreter.is_some());
        let inline: Vec<&Process> = s.processes.iter().filter(|p| p.shape.is_some()).collect();
        json!({
            "level": LEVEL,
            "at": crate::view::iso(s.at),
            "took_ms": self.took_ms as u64,
            "processes": {
                "read": s.processes.len(),
                "unreadable": s.unreadable,
                "ended_while_read": s.ended,
                "other_users": s.other_users,
            },
            "interpreters": {
                "seen": interpreters.count(),
                "arguments_unreadable": s.args_unreadable,
                "inline_code": inline.len(),
                "inline_code_detached": inline.iter().filter(|p| p.detached).count(),
            },
            "connections": {
                "read": s.connections.len(),
                "matched_indicators": self.matched,
                "unreadable": s.sockets_unreadable,
            },
            "tracked": { "new": self.tracked_new, "seen_again": self.tracked_again },
            "findings_opened": self.findings_opened,
            "rule": { "kind": DETACHED_INLINE, "min_apart_seconds": MIN_APART },
            "cannot_see": CANNOT_SEE,
        })
    }

    /// The report for a person: counts only.
    pub fn line(&self) -> String {
        let v = self.json();
        let n = |a: &str, b: &str| v[a][b].as_u64().unwrap_or_default();
        format!(
            "Sample: {} processes read, {} unreadable, {} of other users not read; {} interpreters, \
             {} given code on the command line, {} of them detached; {} connections. \
             Tracking {} new, {} again; {} findings opened. Took {} ms.",
            n("processes", "read"),
            n("processes", "unreadable"),
            n("processes", "other_users"),
            n("interpreters", "seen"),
            n("interpreters", "inline_code"),
            n("interpreters", "inline_code_detached"),
            n("connections", "read"),
            self.tracked_new,
            self.tracked_again,
            self.findings_opened,
            self.took_ms,
        )
    }
}

// ---- A reading made of invented processes, for the promise tests: the same path as a reading
// of the system from `derive` on. ----

impl Reading {
    /// A reading from JSON in the shape of `Reading`.
    pub fn from_json(text: &str) -> Result<Reading, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let int = |v: &Value, k: &str| v[k].as_i64().ok_or(format!("{k} is not a number"));
        let count = |k: &str| v[k].as_u64().unwrap_or_default() as usize;
        let mut processes = Vec::new();
        for p in v["processes"].as_array().ok_or("no processes")? {
            processes.push(Seen {
                pid: int(p, "pid")? as i32,
                start: int(p, "start")?,
                parent: int(p, "parent")? as i32,
                executable: p["executable"].as_str().map(str::to_string),
                name: p["name"].as_str().unwrap_or_default().to_string(),
                terminal: p["terminal"].as_bool().unwrap_or_default(),
                args: p["args"].as_array().map(|a| {
                    a.iter()
                        .map(|s| s.as_str().unwrap_or_default().to_string())
                        .collect()
                }),
            });
        }
        let mut connections = Vec::new();
        for c in v["connections"].as_array().into_iter().flatten() {
            let address: IpAddr = c["address"]
                .as_str()
                .and_then(|a| a.parse().ok())
                .ok_or("an address is not one")?;
            connections.push(Connection {
                pid: int(c, "pid")? as i32,
                start: int(c, "start")?,
                transport: if c["transport"] == "udp" {
                    "udp"
                } else {
                    "tcp"
                },
                state: "established",
                address: address.to_canonical(),
                port: int(c, "port")? as u16,
            });
        }
        Ok(Reading {
            at: int(&v, "at")?,
            processes,
            connections,
            other_users: v["other_users"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_i64().map(|p| p as i32))
                .collect(),
            unreadable: count("unreadable"),
            ended: count("ended"),
            sockets_unreadable: count("sockets_unreadable"),
        })
    }
}

// ---- The reading of the system. ----

/// `PROC_ALL_PIDS` and `PROC_UID_ONLY`, `sys/proc_info.h` lines 51 and 54: every pid, and
/// the pids of one effective user.
const PROC_ALL_PIDS: u32 = 1;
const PROC_UID_ONLY: u32 = 4;
/// `PROC_FLAG_CONTROLT`, line 110: "Has a controlling terminal".
const PROC_FLAG_CONTROLT: u32 = 0x80;
/// `PROC_PIDFDSOCKETINFO`, line 777.
const PROC_PIDFDSOCKETINFO: c_int = 3;
/// `SOCKINFO_IN` and `SOCKINFO_TCP`, lines 529 and 530.
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
/// `INI_IPV4` and `INI_IPV6`, lines 366 and 367.
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
/// `TSI_S_CLOSED` to `TSI_S_TIME_WAIT`, lines 414 to 424, in order.
const TCP_STATES: [&str; 11] = [
    "closed",
    "listen",
    "syn sent",
    "syn received",
    "established",
    "close wait",
    "fin wait 1",
    "closing",
    "last ack",
    "fin wait 2",
    "time wait",
];

/// `struct proc_fileinfo`, line 248.
#[repr(C)]
struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct sockbuf_info`, line 517.
#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// `struct in_sockinfo`, line 374. The two address unions are 16 bytes: `in4in6_addr` keeps
/// an IPv4 address in its last four, `in6_addr` is the whole.
#[repr(C)]
struct InSockinfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: [u8; 16],
    insi_laddr: [u8; 16],
    insi_v4: u8,
    insi_v6: [u32; 3],
}

/// `struct tcp_sockinfo`, line 427.
#[repr(C)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// The union `soi_proto`: only the two members read here are named; its size is that of the
/// largest member, 528 bytes in the SDK.
#[repr(C)]
union SoiProto {
    pri_in: std::mem::ManuallyDrop<InSockinfo>,
    pri_tcp: std::mem::ManuallyDrop<TcpSockinfo>,
    size: [u64; 66],
}

/// `struct socket_info`, line 538.
#[repr(C)]
struct SocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: SoiProto,
}

/// `struct socket_fdinfo`, line 569.
#[repr(C)]
struct SocketFdinfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

// The SDK's own sizes and offsets, as clang gives them for these headers: a declaration that
// does not match does not build.
const _: () = {
    assert!(size_of::<SocketFdinfo>() == 792);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(size_of::<InSockinfo>() == 80);
    assert!(size_of::<TcpSockinfo>() == 120);
    assert!(offset_of!(SocketFdinfo, psi) == 24);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);
    assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The pids `proc_listpids` gives for a kind of list; it returns bytes.
fn pids(kind: u32, arg: u32) -> Vec<i32> {
    // SAFETY: with no buffer the call returns the size it needs.
    let need = unsafe { libc::proc_listpids(kind, arg, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Vec::new();
    }
    // Room for processes started since the size was given.
    let mut buf = vec![0i32; need as usize / 4 + 256];
    let size = (buf.len() * 4) as c_int;
    // SAFETY: the buffer is valid for `size` bytes.
    let got = unsafe { libc::proc_listpids(kind, arg, buf.as_mut_ptr().cast(), size) };
    buf.truncate(got.max(0) as usize / 4);
    buf.retain(|&p| p > 0);
    buf
}

/// The executable's path, as the kernel gives it.
fn path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is valid for its length.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// `kern.argmax`: the largest argument area, the buffer `KERN_PROCARGS2` needs.
fn argmax() -> usize {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut value: c_int = 0;
    let mut size = size_of::<c_int>();
    // SAFETY: `value` is valid for `size` bytes.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut value as *mut c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if r == 0 && value > 0 {
        value as usize
    } else {
        1 << 20
    }
}

/// The area `KERN_PROCARGS2` gives: the argument count as an `int`, the path the program was
/// started by, padding, then the arguments, then the environment, each ending in a zero byte.
/// No system function parses it; this is the layout Apple's `ps` reads. Only the path and the
/// arguments are taken; the environment is never read.
fn parse_procargs(b: &[u8]) -> Option<(String, Vec<String>)> {
    let argc = i32::from_ne_bytes(b.get(..4)?.try_into().ok()?);
    let rest = &b[4..];
    let end = rest.iter().position(|&c| c == 0)?;
    let exec = String::from_utf8_lossy(&rest[..end]).into_owned();
    let mut rest = &rest[end..];
    let mut args = Vec::new();
    for _ in 0..argc.max(0) {
        let from = rest.iter().position(|&c| c != 0)?;
        rest = &rest[from..];
        let end = rest.iter().position(|&c| c == 0)?;
        args.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = &rest[end..];
    }
    Some((exec, args))
}

/// Where a process's executable is: where the kernel says, or else, when its file is gone, the
/// absolute path it was started by.
fn where_from(kernel: Option<String>, started_by: String) -> Option<String> {
    kernel.or(Some(started_by).filter(|p| p.starts_with('/')))
}

/// A process's start path and arguments. The bytes read are zeroed before the buffer is used
/// again or dropped.
fn arguments(pid: i32, buf: &mut [u8]) -> Option<(String, Vec<String>)> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size = buf.len();
    // SAFETY: the buffer is valid for `size` bytes; the call writes at most that and says how
    // much it wrote.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    let read = buf.get_mut(..size.min(buf.len()))?;
    let out = if r == 0 { parse_procargs(read) } else { None };
    read.fill(0);
    out
}

fn c_name(raw: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The internet sockets of a process that have a remote end. Returns them and how many sockets
/// could not be read.
fn sockets(pid: i32, start: i64) -> (Vec<Connection>, usize) {
    let fd_size = size_of::<libc::proc_fdinfo>();
    // SAFETY: with no buffer the call returns the size it needs.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return (Vec::new(), 0);
    }
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(need as usize / fd_size + 32);
    let size = (fds.capacity() * fd_size) as c_int;
    // SAFETY: the buffer is valid for `size` bytes, and the call says how many it wrote.
    let got =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), size) };
    // SAFETY: the kernel wrote `got` bytes of whole entries.
    unsafe { fds.set_len(got.max(0) as usize / fd_size) };
    let (mut out, mut failed) = (Vec::new(), 0);
    for fd in fds
        .iter()
        .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
    {
        // SAFETY: all-zero is a valid value of these plain C structures.
        let mut info: SocketFdinfo = unsafe { std::mem::zeroed() };
        let want = size_of::<SocketFdinfo>() as c_int;
        // SAFETY: `info` is valid for `want` bytes.
        let n = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                (&mut info as *mut SocketFdinfo).cast::<c_void>(),
                want,
            )
        };
        if n != want {
            // A socket closed since the list is not a failure.
            failed += usize::from(errno() != libc::EBADF);
            continue;
        }
        if let Some(c) = connection(&info.psi, pid, start) {
            out.push(c);
        }
    }
    (out, failed)
}

/// The remote end of an internet socket, if it has one.
fn connection(s: &SocketInfo, pid: i32, start: i64) -> Option<Connection> {
    if ![libc::AF_INET, libc::AF_INET6].contains(&s.soi_family) {
        return None;
    }
    // SAFETY: both kinds begin with an `in_sockinfo`, which the kernel filled for them.
    let (ini, state) = match s.soi_kind {
        SOCKINFO_TCP => {
            let tcp = unsafe { &s.soi_proto.pri_tcp };
            let state = usize::try_from(tcp.tcpsi_state).ok();
            (
                &tcp.tcpsi_ini,
                state.and_then(|s| TCP_STATES.get(s)).copied()?,
            )
        }
        SOCKINFO_IN if s.soi_protocol == libc::IPPROTO_UDP => {
            (unsafe { &*s.soi_proto.pri_in }, "connected")
        }
        _ => return None,
    };
    // The port is kept in network order in the low 16 bits.
    let port = u16::from_be(ini.insi_fport as u16);
    let address = if ini.insi_vflag & INI_IPV4 != 0 {
        let a: [u8; 4] = ini.insi_faddr[12..].try_into().ok()?;
        IpAddr::V4(Ipv4Addr::from(a))
    } else if ini.insi_vflag & INI_IPV6 != 0 {
        IpAddr::V6(Ipv6Addr::from(ini.insi_faddr)).to_canonical()
    } else {
        return None;
    };
    (port != 0 && !address.is_unspecified()).then_some(Connection {
        pid,
        start,
        transport: if s.soi_kind == SOCKINFO_TCP {
            "tcp"
        } else {
            "udp"
        },
        state,
        address,
        port,
    })
}

/// Reads this user's processes and their internet sockets now.
pub fn read_system(at: i64) -> Reading {
    // SAFETY: plain calls without arguments.
    let uid = unsafe { libc::geteuid() };
    let mine: HashSet<i32> = pids(PROC_UID_ONLY, uid).into_iter().collect();
    let all = pids(PROC_ALL_PIDS, 0);
    let mut r = Reading {
        at,
        processes: Vec::new(),
        connections: Vec::new(),
        other_users: all.iter().filter(|p| !mine.contains(p)).copied().collect(),
        unreadable: 0,
        ended: 0,
        sockets_unreadable: 0,
    };
    let mut buf = vec![0u8; argmax()];
    for pid in mine {
        // SAFETY: all-zero is a valid `proc_bsdinfo`.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let want = size_of::<libc::proc_bsdinfo>() as c_int;
        // SAFETY: `info` is valid for `want` bytes.
        let n = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                want,
            )
        };
        if n != want {
            if errno() == libc::ESRCH {
                r.ended += 1;
            } else {
                r.unreadable += 1;
            }
            continue;
        }
        let start = info.pbi_start_tvsec as i64 * 1_000_000 + info.pbi_start_tvusec as i64;
        let name = c_name(&info.pbi_comm);
        let mut executable = path(pid);
        let file_name = executable
            .as_deref()
            .and_then(|e| e.rsplit('/').next())
            .unwrap_or(&name);
        let args = if interpreter(file_name).is_some() {
            arguments(pid, &mut buf).map(|(exec, args)| {
                executable = where_from(executable.take(), exec);
                args
            })
        } else {
            None
        };
        let (connections, failed) = sockets(pid, start);
        r.connections.extend(connections);
        r.sockets_unreadable += failed;
        r.processes.push(Seen {
            pid,
            start,
            parent: info.pbi_ppid as i32,
            executable,
            name,
            terminal: info.pbi_flags & PROC_FLAG_CONTROLT != 0,
            args,
        });
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn kind(k: &str) -> &'static Interpreter {
        INTERPRETERS.iter().find(|i| i.kind == k).unwrap()
    }

    #[test]
    fn an_interpreter_is_known_by_its_file_name_whatever_its_version() {
        for (name, k) in [
            ("node", "node"),
            ("bun", "node"),
            ("python3.12", "python"),
            ("Python", "python"),
            ("perl5.34", "perl"),
            ("zsh", "shell"),
            ("osascript", "osascript"),
        ] {
            assert_eq!(interpreter(name).map(|i| i.kind), Some(k), "{name}");
        }
        for name in ["nodemon", "git", "pythonw-helper", ""] {
            assert!(interpreter(name).is_none(), "{name}");
        }
    }

    #[test]
    fn code_on_the_command_line_is_judged_by_the_interpreters_own_options() {
        let given = [
            ("node", &["node", "-e", "x"][..]),
            ("node", &["node", "--eval=x"]),
            ("node", &["node", "--inspect", "-p", "x"]),
            ("node", &["node", "-r", "mod", "-e", "x"]),
            ("node", &["node", "--require", "mod", "--eval", "x"]),
            ("shell", &["bash", "-lc", "x"]),
            ("shell", &["sh", "-o", "pipefail", "-c", "x"]),
            ("python", &["python3", "-W", "ignore", "-c", "x"]),
            ("python", &["python3", "-Ic", "x"]),
            ("deno", &["deno", "eval", "x"]),
            ("osascript", &["osascript", "-l", "JavaScript", "-e", "x"]),
            ("perl", &["perl", "-le", "x"]),
            ("perl", &["perl", "-Mstrict", "-e", "x"]),
        ];
        for (k, args) in given {
            assert!(inline_code(kind(k), &strings(args)), "{args:?}");
        }
        let not_given = [
            ("node", &["node", "server.js", "-e"][..]),
            ("node", &["node", "--require=mod", "server.js", "-e", "x"]),
            ("node", &["node", "-r", "-e"]),
            ("shell", &["bash", "script.sh", "-c", "x"]),
            ("shell", &["sh", "-o", "c", "x"]),
            ("shell", &["sh", "--", "-c"]),
            ("shell", &["sh", "-"]),
            ("python", &["python3", "-X", "c", "x.py"]),
            ("python", &["python3", "-m", "http.server", "-c"]),
            ("deno", &["deno", "run", "eval"]),
            ("perl", &["perl", "-Mfeature", "x.pl"]),
            ("node", &["node"]),
        ];
        for (k, args) in not_given {
            assert!(!inline_code(kind(k), &strings(args)), "{args:?}");
        }
    }

    #[test]
    fn a_detached_process_is_one_whose_parent_is_launchd_or_gone_and_its_command_line_is_dropped() {
        let seen = |pid, parent, args: &[&str]| Seen {
            pid,
            start: 1,
            parent,
            executable: Some(format!("/x/{}", args[0])),
            name: String::new(),
            terminal: false,
            args: Some(strings(args)),
        };
        let mut gone_file = seen(13, 1, &["node", "-e", "x"]);
        gone_file.executable = None;
        gone_file.name = "node".into();
        let mut unreadable = seen(14, 10, &["node"]);
        unreadable.args = None;
        let s = derive(Reading {
            at: 0,
            processes: vec![
                seen(10, 1, &["node", "-e", "x"]),
                seen(11, 10, &["sh", "-c", "x"]),
                seen(12, 99, &["sh", "-c", "x"]),
                gone_file,
                unreadable,
                seen(15, 10, &["git", "-c", "x"]),
            ],
            connections: Vec::new(),
            other_users: vec![1],
            unreadable: 0,
            ended: 0,
            sockets_unreadable: 0,
        });
        let got: Vec<_> = s
            .processes
            .iter()
            .map(|p| (p.pid, p.detached, p.interpreter.map(|i| i.kind), p.shape))
            .collect();
        assert_eq!(
            got,
            [
                (10, true, Some("node"), Some(INLINE_CODE)),
                (11, false, Some("shell"), Some(INLINE_CODE)),
                (12, true, Some("shell"), Some(INLINE_CODE)),
                (13, true, Some("node"), Some(INLINE_CODE)),
                (14, false, Some("node"), None),
                (15, false, None, None),
            ]
        );
        assert_eq!(s.args_unreadable, 1);
    }

    #[test]
    fn connections_to_a_listed_address_are_found_in_either_form_and_others_are_not() {
        let c = |a: &str, port| Connection {
            pid: 1,
            start: 1,
            transport: "tcp",
            state: "established",
            address: a.parse::<IpAddr>().unwrap().to_canonical(),
            port,
        };
        let all = [
            c("192.0.2.7", 80),
            c("::ffff:192.0.2.8", 443),
            c("2001:db8::1", 443),
            c("198.51.100.1", 80),
        ];
        let list: Vec<IpAddr> = ["::ffff:192.0.2.7", "192.0.2.8", "2001:db8::1"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let found: Vec<_> = connections_to(&all, &list);
        assert_eq!(found, vec![&all[0], &all[1], &all[2]]);
        assert!(connections_to(&all, &[]).is_empty());
    }

    #[test]
    fn a_signer_is_looked_up_once_per_file_and_again_when_the_file_is_replaced() {
        let dir = std::env::temp_dir().join(format!("soc-signers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("tool");
        std::fs::write(&file, "one").unwrap();
        let path = file.to_str().unwrap();
        let mut s = Signers::default();
        s.of(path);
        s.of(path);
        assert_eq!(s.looked_up, 1);
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, "two!").unwrap();
        s.of(path);
        assert_eq!(s.looked_up, 2);
        assert_eq!(
            s.of("/bin/sh").as_deref().map(|v| v.starts_with("apple")),
            Some(true)
        );
        assert_eq!(s.of(dir.join("absent").to_str().unwrap()), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The real reading, on this test process and a child it starts in a session of its own.
    #[test]
    fn the_reading_of_the_system_sees_this_process_its_child_with_code_and_its_connection() {
        use std::os::unix::process::CommandExt;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.connect(("127.0.0.1", port)).unwrap();
        let six = std::net::TcpListener::bind("[::1]:0").unwrap();
        let six_port = six.local_addr().unwrap().port();
        let six_stream = std::net::TcpStream::connect(("::1", six_port)).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30; :"]).stdin(Stdio::null());
        // SAFETY: setsid is safe to call in the child before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        // `/bin/sh` is a stub that starts the shell it is set to be: while it does, its
        // arguments cannot be read.
        let given = strings(&["/bin/sh", "-c", "sleep 30; :"]);
        let mut r = read_system(1);
        for _ in 0..100 {
            let kid = r.processes.iter().find(|p| p.pid == child.id() as i32);
            if kid.and_then(|k| k.args.as_ref()) == Some(&given) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            r = read_system(1);
        }
        // What the argument area held is zeroed once it is read.
        let mut area = vec![0u8; argmax()];
        assert_eq!(
            arguments(child.id() as i32, &mut area).map(|a| a.1),
            Some(given)
        );
        assert!(area.iter().all(|&b| b == 0));
        let me = std::process::id() as i32;
        let this = r.processes.iter().find(|p| p.pid == me).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(this.executable.as_deref(), exe.to_str());
        let started = this.start / 1_000_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(started <= now && now - started < 3600, "{started}");
        let kid = r
            .processes
            .iter()
            .find(|p| p.pid == child.id() as i32)
            .unwrap();
        assert_eq!(kid.parent, me);
        assert!(!kid.terminal);
        assert_eq!(
            kid.args.as_deref(),
            Some(&strings(&["/bin/sh", "-c", "sleep 30; :"])[..])
        );
        let to_listener = r
            .connections
            .iter()
            .find(|c| c.pid == me && c.port == port && c.transport == "tcp")
            .unwrap();
        assert_eq!(to_listener.start, this.start);
        assert_eq!(to_listener.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            (to_listener.transport, to_listener.state),
            ("tcp", "established")
        );
        let mine = |port| r.connections.iter().find(|c| c.pid == me && c.port == port);
        let datagram = r
            .connections
            .iter()
            .find(|c| c.pid == me && c.transport == "udp" && c.port == port)
            .unwrap();
        assert_eq!(datagram.state, "connected");
        assert_eq!(
            mine(six_port).map(|c| c.address),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(r.other_users.contains(&1));
        let s = derive(r);
        let kid = s
            .processes
            .iter()
            .find(|p| p.pid == child.id() as i32)
            .unwrap();
        assert_eq!(kid.shape, Some(INLINE_CODE));
        assert!(!kid.detached);
        child.kill().unwrap();
        child.wait().unwrap();
        drop((stream, udp, six_stream));
    }

    /// An interpreter whose file was deleted while it runs is still known, by the absolute path
    /// it was started by. A copy of a system shell cannot stand in for one on a real system:
    /// macOS stops a copied platform binary before it runs.
    #[test]
    fn an_interpreter_whose_file_is_gone_is_known_by_the_path_it_was_started_by() {
        let s = |p: &str| p.to_string();
        assert_eq!(
            where_from(Some(s("/opt/a/node")), s("/opt/b/node")),
            Some(s("/opt/a/node"))
        );
        assert_eq!(where_from(None, s("/opt/b/node")), Some(s("/opt/b/node")));
        assert_eq!(where_from(None, s("node")), None);
    }

    /// A shell that its parent left behind is detached: its parent is launchd now.
    #[test]
    fn the_reading_of_the_system_sees_a_process_its_parent_left_as_detached() {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "/bin/sh -c 'sleep 30; :' </dev/null >/dev/null 2>&1 & echo $!",
        ]);
        // SAFETY: setsid is safe to call in the child before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        let pid: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        // The shell left behind may not have started its own program yet.
        let started = strings(&["/bin/sh", "-c", "sleep 30; :"]);
        let mut reading = read_system(1);
        for _ in 0..100 {
            let p = reading.processes.iter().find(|p| p.pid == pid).unwrap();
            if p.args.as_ref() == Some(&started) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            reading = read_system(1);
        }
        let s = derive(reading);
        // SAFETY: a plain signal to the shell this test started.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let left = s.processes.iter().find(|p| p.pid == pid).unwrap();
        assert!(left.detached);
        assert_eq!(left.shape, Some(INLINE_CODE));
        // `/bin/sh` is a stub that starts the shell it is set to be.
        assert_eq!(left.interpreter.map(|i| i.kind), Some("shell"));
    }

    #[test]
    fn the_argument_area_is_read_to_its_count_and_the_environment_is_not() {
        let mut area = 2i32.to_ne_bytes().to_vec();
        area.extend_from_slice(b"/bin/sh\0\0\0\0sh\0-c\0SECRET=1\0");
        assert_eq!(
            parse_procargs(&area),
            Some(("/bin/sh".to_string(), strings(&["sh", "-c"])))
        );
        area[0] = 4;
        assert_eq!(parse_procargs(&area), None);
        assert_eq!(parse_procargs(&area[..2]), None);
    }
}
