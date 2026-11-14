//! The state the store holds after the last finished run, read back from the store alone.
//!
//! The run's report line, `immune status` and the machine-readable form of both are built from
//! one `Summary`, so they cannot count differently. What a run learns while it runs is read
//! back from what it wrote: its events from the journal, its readings from coverage, the
//! catalogue from its reading. The one number of the report line the store does not hold is
//! how many readers had input to read, and the line's closing notes; neither is in the
//! machine-readable form.
//!
//! Text taken from a source on the machine or from a feed goes only into fields whose name
//! ends in `_text`, shown as the terminal shows it and cut to `TEXT_CAP` characters. Every
//! other string is a closed literal of the store or a sentence of the program's own.

use crate::store::{self, Totals};
use crate::view::{self, Latest};
use crate::{ServerCounts, findings, resolver, servers, threats, watched};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// The version of the machine-readable form. A field may be added without changing it; one
/// renamed, removed or changed in meaning changes it.
pub const FORMAT: i64 = 1;
/// The most characters of text from a source in one field. A longer text ends in `…`.
pub const TEXT_CAP: usize = 256;
/// The most changes of watched places given, newest first; `changes_total` counts them all.
pub const CHANGES_SHOWN: usize = 50;
/// The most groups of readings that were not plainly full given; `problems_total` counts
/// them all.
pub const PROBLEMS_SHOWN: usize = 100;
/// The most scopes given as examples of one group of readings.
pub const EXAMPLES: usize = 3;
/// The most machines that could not be reached given; `unreached_total` counts them all.
pub const UNREACHED_SHOWN: usize = 100;
/// The most things without a reader given, most places first.
pub const NO_READER_SHOWN: usize = 100;
/// At most this many things that need a look are listed; the total is always given.
pub const NEEDS_SHOWN: usize = 50;
/// What this build cannot answer at all, in its own words. One sentence a line: the builder
/// who closes a gap deletes its line, and nothing else changes.
pub const CANNOT_JUDGE: &[&str] = &[
    // Places of persistence left out of the watched places (`watched.rs`): readable by root
    // only or without a permission dialog, rewritten at every logout, or not a file.
    PERSISTENCE_UNREAD,
    // Lockfiles of npm and crates.io are matched (`vulnerabilities`); the rest is planned in
    // docs/threats.md.
    "no vulnerability is matched against installed software, servers' packages or ecosystems other than npm and crates.io yet",
    // Homebrew and npm are read; other package managers are named only when looked for, and
    // every tool is looked for at its installers' default places only (`managers`, `tools`).
    OTHER_MANAGERS,
];
/// What this version cannot judge of software installed on this Mac, whatever the table of
/// package managers holds.
pub const OTHER_MANAGERS: &str = "software installed by a package manager other than Homebrew and npm is not checked, and Homebrew or Tailscale installed outside the places their installers use by default is not found";
/// The places of persistence this version does not read, by name.
pub const PERSISTENCE_UNREAD: &str = "these places of persistence are not read: login and logout hooks in root's preferences, in ByHost preferences and in Managed Preferences, a PAM policy a device management profile installs, the authorization database, the sudoers file and its folder, login items and background items, crontabs, launchd jobs with no file on disk, and the applications reopened at login";
/// The sections of a result that hold numbers, in the order of the result.
const SECTIONS: [&str; 15] = [
    "needs_a_look",
    "vulnerabilities",
    "answered_outside_app",
    "statements_outside_app",
    "not_covered",
    "last_run",
    "last_finished_run",
    "estate",
    "watched",
    "event_level",
    "integrity",
    "threats",
    "vulnerability_data",
    "coverage",
    "no_reader_for",
];

/// A run as the journal records it.
pub struct RunMark {
    pub id: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

/// The latest run that started, by the order of the journal, finished or not.
pub fn latest_run(conn: &Connection) -> rusqlite::Result<Option<RunMark>> {
    let started: Option<(String, i64)> = conn
        .query_row(
            "SELECT run_id, at FROM journal WHERE entry = 'run_started' ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, started_at)) = started else {
        return Ok(None);
    };
    let finished_at = conn.query_row(
        "SELECT MAX(at) FROM journal WHERE entry = 'run_finished' AND run_id = ?1",
        [&id],
        |r| r.get(0),
    )?;
    Ok(Some(RunMark {
        id,
        started_at,
        finished_at,
    }))
}

/// The latest run that finished. A run writes in one transaction, so what the store holds is
/// what this run left, with the owner's word since.
pub fn latest_finished(conn: &Connection) -> rusqlite::Result<Option<RunMark>> {
    let finished: Option<(String, i64)> = conn
        .query_row(
            "SELECT run_id, at FROM journal WHERE entry = 'run_finished' ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((id, at)) = finished else {
        return Ok(None);
    };
    let started: Option<i64> = conn.query_row(
        "SELECT MIN(at) FROM journal WHERE entry = 'run_started' AND run_id = ?1",
        [&id],
        |r| r.get(0),
    )?;
    Ok(Some(RunMark {
        id,
        started_at: started.unwrap_or(at),
        finished_at: Some(at),
    }))
}

/// Things added, changed and removed by a run, each counted once however many assertions.
pub struct Since {
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
}

/// One change of a watched place, as the run that found it counts it.
pub struct FileChange {
    pub run_id: String,
    pub at: i64,
    /// `new`, `changed` or `gone`.
    pub change: &'static str,
    /// The kind of place, the literal of `watched_as`.
    pub kind: String,
    /// The path as ids name it: text from the machine.
    pub path: String,
}

/// What a run learned of the watched places.
pub struct Watched {
    /// No reading of watched places was made before this run: this one is the baseline.
    pub first: bool,
    /// Files watched now.
    pub files: i64,
    pub new: usize,
    pub changed: usize,
    pub gone: usize,
    /// Kinds of place on the machine whose reading in this run was not full, as their
    /// coverage kind and completeness, in the order of the table of places.
    pub kinds_not_full: Vec<(&'static str, String)>,
    /// Readings of checkouts' hooks in this run that were not full, by completeness.
    pub hooks_not_full: BTreeMap<String, usize>,
    /// Files whose content could not be read in this run.
    pub unread: usize,
    /// Entries watched now only for whether they are there (`watched::PRESENCE_ONLY`).
    pub presence_only: i64,
}

/// What the latest reading of the threat catalogue found.
pub enum Catalogue {
    /// Read whole: how many entries it holds, how many are new and how many left it.
    Read {
        total: usize,
        new: usize,
        gone: usize,
        first: bool,
        at: i64,
    },
    /// Not changed since the last reading.
    Unchanged { total: usize, at: i64 },
    /// Not read, and when it was last read, with how many entries it held then.
    Failed {
        reason: String,
        last: Option<(i64, usize)>,
        at: i64,
    },
}

/// Everything the report line counts, for one finished run, from the store.
pub struct Summary {
    pub run: RunMark,
    /// No run finished before this one.
    pub first_run: bool,
    pub totals: Totals,
    pub servers: ServerCounts,
    pub since: Since,
    /// Facts set aside as no longer read since the run before, by this run or by a watcher in
    /// between (`lifecycle::set_aside`): never counted in `since`.
    pub set_aside: u64,
    /// `None`: watched places were never read.
    pub watched: Option<Watched>,
    /// `None`: the catalogue was never read.
    pub catalogue: Option<Catalogue>,
    /// Every change of a watched place the journal holds, oldest first.
    pub changes: Vec<FileChange>,
    /// What this build has no reader for on this estate; `None` on a store made before it
    /// was recorded.
    pub no_reader_for: Option<Vec<NoReader>>,
    /// What is installed and whether it changed in place; `None`: never read.
    pub integrity: Option<crate::integrity::Summary>,
    /// Each feed of vulnerability data: what it holds and how its latest reading went.
    pub feeds: Vec<crate::osv::State>,
    /// What matching the lockfiles against that data answered.
    pub vulnerabilities: crate::vulnerabilities::Totals,
}

/// One kind of thing this build has no reader for, and in how many places it was found.
pub struct NoReader {
    /// What it is, in the program's words.
    pub what: String,
    /// Its name as the source gives it, where there is one, such as a lockfile's.
    pub name: Option<String>,
    /// How many scopes read last hold it.
    pub places: i64,
}

/// What the latest readings found this build has no reader for, most places first.
fn no_reader_for(conn: &Connection) -> rusqlite::Result<Option<Vec<NoReader>>> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'coverage_lack')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(None);
    }
    conn.prepare(&format!(
        "{}
         SELECT l.what, l.name, COUNT(DISTINCT c.scope) AS places
         FROM latest c CROSS JOIN coverage_lack l ON l.coverage = c.id
         WHERE c.scope NOT IN (SELECT id FROM gone_entity)
         GROUP BY l.what, l.name
         ORDER BY places DESC, l.what, l.name",
        store::LATEST
    ))?
    .query_map([], |r| {
        Ok(NoReader {
            what: r.get(0)?,
            name: r.get(1)?,
            places: r.get(2)?,
        })
    })?
    .collect::<rusqlite::Result<_>>()
    .map(Some)
}

/// Reads what `run` left. `home` is the store's folder, where the sweep's skip list is.
/// The run calls this inside its transaction before it finishes; `immune status` calls it on
/// the latest finished run.
pub fn summary(conn: &Connection, run: RunMark, home: &Path) -> Res<Summary> {
    let base = baselines(conn)?;
    let changes = file_changes(conn, &base)?;
    let machine = this_machine(conn, &run.id)?;
    let skip = crate::sweep::skip_list(&home.join("sweep"));
    Ok(Summary {
        first_run: !conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM journal WHERE entry = 'run_finished' AND run_id != ?1)",
            [&run.id],
            |r| r.get(0),
        )?,
        totals: store::totals(conn, &run.id)?,
        servers: crate::server_counts(conn, &machine, &skip)?,
        since: since(conn, &run.id, &base)?,
        set_aside: crate::lifecycle::set_aside(conn, &run.id, None)?,
        watched: watched_summary(conn, &run.id, &changes)?,
        catalogue: catalogue(conn)?,
        no_reader_for: no_reader_for(conn)?,
        integrity: crate::integrity::summary(conn, &run.id)?,
        feeds: crate::osv::states(conn)?,
        vulnerabilities: crate::vulnerabilities::totals(conn, crate::now_secs())?,
        changes,
        run,
    })
}

/// The machine a run ran on: the scope of its resolver reading, which every run makes.
fn this_machine(conn: &Connection, run_id: &str) -> rusqlite::Result<String> {
    let scope: Option<String> = conn
        .query_row(
            "SELECT scope FROM coverage WHERE run_id = ?1 AND reader = ?2 LIMIT 1",
            params![run_id, resolver::READER],
            |r| r.get(0),
        )
        .optional()?;
    Ok(scope.unwrap_or_default())
}

/// Readers whose first reading of a scope and kind is a baseline.
const BASELINED: [&str; 2] = [watched::READER, crate::integrity::READER];

/// Which differences the journal holds are a baseline, journaled and counted as nothing new.
struct Baselines {
    /// For each reading of a reader in `BASELINED`, the run whose reading of it first read
    /// something. The two readers' kinds differ, so scope and kind name one reading.
    first: HashMap<(String, String), String>,
    /// The last journal entry written before units were recorded (`baseline.rs`). After it a
    /// reading of the watched places says in each entry whether it was a first reading, and
    /// `first` no longer speaks for it.
    units_since: Option<i64>,
}

/// The baselines of the journal: before units were recorded, a reading's events are the
/// baseline when it was the first of its scope and kind to read something.
fn baselines(conn: &Connection) -> rusqlite::Result<Baselines> {
    let units_since = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
            [crate::baseline::UNITS_SINCE],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Baselines {
        first: first_readings(conn)?,
        units_since,
    })
}

/// For each reading of a reader in `BASELINED`, the run whose reading of it first read
/// something.
fn first_readings(conn: &Connection) -> rusqlite::Result<HashMap<(String, String), String>> {
    // The first reading of each that read something, looked up from where its readings
    // begin, not found by going through every reading.
    let mut stmt = conn.prepare(&format!(
        "{}
         SELECT r.scope, r.kind,
                (SELECT c.run_id FROM coverage c
                 WHERE c.reader = r.reader AND c.scope = r.scope AND c.kind = r.kind
                   AND c.completeness != 'none'
                 ORDER BY c.id LIMIT 1)
         FROM reading r WHERE r.reader IN (?1, ?2)",
        store::LATEST
    ))?;
    let rows = stmt.query_map(BASELINED, |r| {
        Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        if let (scope, kind, Some(run)) = row? {
            out.insert((scope, kind), run);
        }
    }
    Ok(out)
}

/// One difference the journal holds.
struct Journaled {
    at: i64,
    run_id: String,
    entry: String,
    scope: String,
    subject: String,
    predicate: String,
    old: Option<String>,
    new: Option<String>,
    /// A first reading: recorded and counted as nothing new.
    first: bool,
}

/// The differences of one run, or of every run, oldest first, from one reader or all, each
/// with whether it is a first reading.
fn journaled(
    conn: &Connection,
    run_id: Option<&str>,
    reader: Option<&str>,
    base: &Baselines,
) -> rusqlite::Result<Vec<Journaled>> {
    // One run is asked for by a plain comparison, so that its differences are found through
    // `journal_run` and not by going through the whole journal, which `?1 IS NULL OR` would.
    let run = if run_id.is_some() {
        "run_id = ?1"
    } else {
        "?1 IS NULL"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT at, run_id, entry, reader, scope, kind, subject, predicate, old_value, new_value,
                seq, text IN (?3, ?4)
         FROM journal
         WHERE {run} AND entry IN ('added', 'changed', 'removed') AND (?2 IS NULL OR reader = ?2)
         ORDER BY seq"
    ))?;
    let rows = stmt.query_map(
        params![run_id, reader, store::FIRST_READING, store::READ_FIRST],
        |r| {
            let reader: Option<String> = r.get(3)?;
            let kind: Option<String> = r.get(5)?;
            let seq: i64 = r.get(10)?;
            // A difference a reading journaled as a first reading is not a change; before
            // readings said so, the first reading of each scope and kind was the baseline.
            let marked = r.get::<_, Option<bool>>(11)?.unwrap_or(false);
            let judged = reader.as_deref() == Some(watched::READER)
                && base.units_since.is_some_and(|since| seq > since);
            let mut e = Journaled {
                at: r.get(0)?,
                run_id: r.get(1)?,
                entry: r.get(2)?,
                scope: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                subject: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                predicate: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                old: r.get(8)?,
                new: r.get(9)?,
                first: marked,
            };
            e.first |= reader.as_deref().is_some_and(|r| BASELINED.contains(&r))
                && !judged
                && base.first.get(&(e.scope.clone(), kind.unwrap_or_default())) == Some(&e.run_id);
            Ok(e)
        },
    )?;
    rows.collect()
}

/// Counts things, not assertions: a new component is one addition however many assertions
/// it brings. A first reading counts as nothing new.
fn since(conn: &Connection, run_id: &str, base: &Baselines) -> rusqlite::Result<Since> {
    let events = journaled(conn, Some(run_id), None, base)?;
    Ok(count_since(&events))
}

fn count_since(events: &[Journaled]) -> Since {
    let count = |entry: &str| {
        events
            .iter()
            .filter(|e| e.entry == entry && !e.first)
            .map(|e| e.subject.as_str())
            .collect::<HashSet<_>>()
            .len()
    };
    Since {
        added: count("added"),
        changed: count("changed"),
        removed: count("removed"),
    }
}

/// One difference a run journaled, as the page of changes shows it.
pub struct RunEvent {
    pub entry: String,
    pub subject: String,
    pub predicate: String,
    pub old: Option<String>,
    pub new: Option<String>,
    /// A first reading: what was there, taken as the baseline.
    pub first: bool,
}

/// What one run journaled, counted as the report and `immune status` count it, and how many
/// things it read for the first time and took as their baseline.
pub fn run_changes(
    conn: &Connection,
    run_id: &str,
) -> rusqlite::Result<(Since, usize, Vec<RunEvent>)> {
    let mut events = journaled(conn, Some(run_id), None, &baselines(conn)?)?;
    // The store's first run, as the report calls it: everything it found is the baseline.
    let first_run: bool = conn.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM journal WHERE entry = 'run_finished' AND run_id != ?1
                              AND seq < (SELECT MIN(seq) FROM journal WHERE run_id = ?1))",
        [run_id],
        |r| r.get(0),
    )?;
    if first_run {
        events.iter_mut().for_each(|e| e.first = true);
    }
    let first = events
        .iter()
        .filter(|e| e.first)
        .map(|e| e.subject.as_str())
        .collect::<HashSet<_>>()
        .len();
    let since = count_since(&events);
    let events = events
        .into_iter()
        .map(|e| RunEvent {
            entry: e.entry,
            subject: e.subject,
            predicate: e.predicate,
            old: e.old,
            new: e.new,
            first: e.first,
        })
        .collect();
    Ok((since, first, events))
}

/// A file's path from its id, `file:<machine>/<path>`.
fn path_of(id: &str) -> &str {
    id.strip_prefix("file:")
        .and_then(|rest| rest.split_once('/'))
        .map_or(id, |(_, path)| path)
}

/// Every change of a watched place, oldest first. A file that appears is new, one that
/// disappears is gone, and one whose content or link target was replaced is changed unless
/// it is new in the same run.
fn file_changes(conn: &Connection, base: &Baselines) -> rusqlite::Result<Vec<FileChange>> {
    let mut events = journaled(conn, None, Some(watched::READER), base)?;
    events.retain(|e| !e.first);
    let new: HashSet<(&str, &str)> = events
        .iter()
        .filter(|e| e.entry == "added" && e.predicate == "watched_as")
        .map(|e| (e.run_id.as_str(), e.subject.as_str()))
        .collect();
    // The kind of each file, from its latest `watched_as`, live or retracted.
    let mut kind_of: HashMap<String, String> = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT subject, object FROM assertion
         WHERE layer IN ('live', 'retracted') AND reader = ?1 AND predicate = 'watched_as'
         ORDER BY id",
    )?;
    for row in stmt.query_map([watched::READER], |r| Ok((r.get(0)?, r.get(1)?)))? {
        let (subject, object) = row?;
        kind_of.insert(subject, object);
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for e in &events {
        let (change, id, kind) = match (e.entry.as_str(), e.predicate.as_str()) {
            ("added", "watched_as") => ("new", &e.subject, e.new.clone()),
            ("removed", "watched_as") => ("gone", &e.subject, e.old.clone()),
            ("added" | "changed" | "removed", "has_content" | "links_to")
                if !new.contains(&(e.run_id.as_str(), e.scope.as_str())) =>
            {
                ("changed", &e.scope, kind_of.get(&e.scope).cloned())
            }
            _ => continue,
        };
        if seen.insert((e.run_id.as_str(), change, id.as_str())) {
            out.push(FileChange {
                run_id: e.run_id.clone(),
                at: e.at,
                change,
                kind: kind.unwrap_or_default(),
                path: path_of(id).to_string(),
            });
        }
    }
    Ok(out)
}

fn watched_summary(
    conn: &Connection,
    run_id: &str,
    changes: &[FileChange],
) -> rusqlite::Result<Option<Watched>> {
    if !store::read_any(conn, watched::READER)? {
        return Ok(None);
    }
    let first = !conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND run_id != ?2)",
        params![watched::READER, run_id],
        |r| r.get::<_, bool>(0),
    )?;
    let files = conn.query_row(
        "SELECT COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'",
        [watched::READER],
        |r| r.get(0),
    )?;
    let count = |change: &str| {
        changes
            .iter()
            .filter(|c| c.run_id == run_id && c.change == change)
            .count()
    };
    let mut w = Watched {
        first,
        files,
        new: count("new"),
        changed: count("changed"),
        gone: count("gone"),
        kinds_not_full: Vec::new(),
        hooks_not_full: BTreeMap::new(),
        unread: 0,
        presence_only: watched::presence_only_by_kind(conn)?.values().sum(),
    };
    let mut stmt = conn.prepare(
        "SELECT kind, completeness FROM coverage
         WHERE reader = ?1 AND run_id = ?2 AND completeness != 'full'",
    )?;
    let mut places: HashMap<String, String> = HashMap::new();
    for row in stmt.query_map(params![watched::READER, run_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (kind, completeness) = row?;
        if kind == watched::HOOK_KIND {
            *w.hooks_not_full.entry(completeness).or_default() += 1;
        } else if kind == watched::CONTENT {
            w.unread += 1;
        } else {
            places.insert(kind, completeness);
        }
    }
    for (_, kind) in watched::kinds() {
        if let Some(completeness) = places.remove(kind) {
            w.kinds_not_full.push((kind, completeness));
        }
    }
    Ok(Some(w))
}

/// The latest reading of the threat catalogue, with what it changed in the threat list.
pub fn catalogue(conn: &Connection) -> rusqlite::Result<Option<Catalogue>> {
    // A store made before the threat list has no tables for it until a run opens it.
    let has_tables: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'feed_reading')",
        [],
        |r| r.get(0),
    )?;
    if !has_tables {
        return Ok(None);
    }
    type Row = (i64, String, i64, String, Option<String>, Option<i64>);
    let latest: Option<Row> = conn
        .query_row(
            "SELECT id, run_id, at, outcome, reason, entries FROM feed_reading
             WHERE source = ?1 ORDER BY id DESC LIMIT 1",
            [threats::SOURCE],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((id, run_id, at, outcome, reason, entries)) = latest else {
        return Ok(None);
    };
    let total = entries.unwrap_or_default() as usize;
    let journaled = |entry: &str| -> rusqlite::Result<usize> {
        conn.query_row(
            "SELECT COUNT(*) FROM journal WHERE run_id = ?1 AND reader = ?2 AND entry = ?3",
            params![run_id, threats::SOURCE, entry],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n as usize)
    };
    Ok(Some(match outcome.as_str() {
        "read" => Catalogue::Read {
            total,
            new: journaled("threat_added")?,
            gone: journaled("threat_gone")?,
            first: journaled("threats_first_read")? > 0,
            at,
        },
        "unchanged" => Catalogue::Unchanged { total, at },
        _ => {
            let last: Option<i64> = conn
                .query_row(
                    "SELECT at FROM feed_reading
                     WHERE source = ?1 AND outcome != 'failed' AND id < ?2
                     ORDER BY id DESC LIMIT 1",
                    params![threats::SOURCE, id],
                    |r| r.get(0),
                )
                .optional()?;
            let held = threats::held(conn)?;
            Catalogue::Failed {
                reason: reason.unwrap_or_default(),
                last: last.map(|at| (at, held)),
                at,
            }
        }
    }))
}

/// What the report line says cannot be known about the run's changes, in its words.
pub fn unknown(t: &Totals) -> Vec<&'static str> {
    let mut out = Vec::new();
    if t.partial > 0 {
        out.push("removals unknown where a reading was partial");
    }
    if t.none > 0 || t.not_repeated > 0 {
        out.push("changes unknown where nothing was read");
    }
    out
}

/// Everything `immune status` shows, read in one transaction.
pub struct State {
    /// The latest run that started.
    pub last: Option<RunMark>,
    /// What the latest finished run left; `None` when no run finished.
    pub summary: Option<Summary>,
    /// The latest reading of each reader, scope and kind, not full first.
    pub coverage: Vec<Latest>,
    /// The incomplete readings grouped, and the machines that could not be reached.
    pub problems: Problems,
    /// Live files per kind of watched place.
    pub files: BTreeMap<String, i64>,
    /// Of them, those watched only for presence, per kind.
    pub presence_only: BTreeMap<String, i64>,
    /// What needs a look now: findings only.
    pub needs: findings::Needs,
    /// The findings whose answer is in force now, the latest answer first; `None` before
    /// any run of this build looked for findings.
    pub answered: Option<Vec<findings::Item>>,
    /// The owner's statements that stand: machines set aside as retired or not theirs.
    pub standing: Vec<crate::owner::Standing>,
    /// Is this Mac watched, and how.
    pub this_mac: crate::covered::ThisMac,
    /// What the program does not cover, aggregated for a person.
    pub not_covered: Vec<crate::covered::Uncovered>,
    /// The event level as its latest reading left it; `None` before any reading of it.
    pub event_level: Option<crate::events::Level>,
}

pub fn state(conn: &Connection, home: &Path, now: i64) -> Res<State> {
    let summary = match latest_finished(conn)? {
        Some(run) => Some(summary(conn, run, home)?),
        None => None,
    };
    let mut files = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT object, COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as' GROUP BY object",
    )?;
    for row in stmt.query_map([watched::READER], |r| Ok((r.get(0)?, r.get(1)?)))? {
        let (kind, n): (String, i64) = row?;
        files.insert(kind, n);
    }
    let (coverage, problems, needs) = looked(conn, now)?;
    // Watched live while a watcher runs and its latest reading, sample and look at what to
    // watch did not fail. A failed reading of the event level stands for program starts
    // alone, which are then not claimed as seen.
    let failed = crate::watch::failures(conn, home)?;
    let live = store::watch_in_progress(home).unwrap_or(false)
        && failed.iter().all(|f| f.what == crate::watch::EVENTS);
    let mut this_mac = crate::covered::this_mac(conn, &coverage, live)?;
    this_mac.failed = failed;
    let event_level = crate::events::level(conn, now)?;
    // A collector that is installed and records nothing (refused, failing or silent), or that
    // runs and lost part of what it was to record over the last day (a gap in its numbering, a
    // restart it cannot account for, lines it could not read, log files the cap or the tidy job
    // deleted before they were read), leaves a place of this Mac read in part, as a reading that
    // failed does: never the calm of a Mac watched whole. It holds as long as `rules.judged`
    // says `part`. Its reading's coverage names the cause `not_given`, which the test of a
    // failed reading does not count, so it is said here. Not installed is a limit the person can
    // lift, and `not_covered` says it.
    if this_mac.state == "watched"
        && event_level.as_ref().is_some_and(|l| {
            [
                crate::events::REFUSED,
                crate::events::FAILING,
                crate::events::SILENT,
            ]
            .contains(&l.state.as_str())
                || (l.state == crate::events::RUNNING && !l.judged_whole())
        })
    {
        this_mac.state = "watched_in_part";
    }
    // Program starts are watched only while the level records them.
    if let Some(l) = event_level
        .as_ref()
        .filter(|l| l.state == crate::events::RUNNING)
    {
        this_mac
            .watched
            .push((crate::covered::EVENTS, l.last_day.starts, "events"));
    }
    let not_covered =
        crate::covered::not_covered(conn, &coverage, &problems, catalogue(conn)?.as_ref())?;
    Ok(State {
        last: latest_run(conn)?,
        summary,
        problems,
        coverage,
        files,
        presence_only: watched::presence_only_by_kind(conn)?,
        needs,
        answered: findings::answered(conn, now)?,
        standing: crate::owner::standing(conn)?,
        this_mac,
        not_covered,
        event_level,
    })
}

/// The latest readings, their problems and what needs a look at `now`: what `needs_a_look`
/// serves.
fn looked(conn: &Connection, now: i64) -> Res<(Vec<Latest>, Problems, findings::Needs)> {
    let coverage = view::latest_coverage(conn)?;
    let problems = problems(conn, &coverage)?;
    let needs = findings::needs(conn, now)?;
    Ok((coverage, problems, needs))
}

/// What needs a look at `now`, as `immune status --json` counts it; `immune watch` gives its total
/// after each reading.
pub fn needs(conn: &Connection, now: i64) -> Res<findings::Needs> {
    Ok(findings::needs(conn, now)?)
}

/// Text from a source as a field's value: hidden characters as the terminal shows them,
/// and at most `TEXT_CAP` characters.
pub fn text(s: &str) -> Value {
    Value::String(text_string(s))
}

/// The same as a string, for the contract's `_text` fields.
pub fn text_string(s: &str) -> String {
    capped(view::shown(s))
}

/// A text the core cut, as `text` gives one, each mark as it is.
pub fn cut_text(t: &crate::secrets::Text) -> Value {
    Value::String(capped(t.shown(view::shown)))
}

/// Text already shown, cut to `TEXT_CAP` characters.
pub fn capped(shown: String) -> String {
    if shown.chars().count() <= TEXT_CAP {
        return shown;
    }
    let mut cut: String = shown.chars().take(TEXT_CAP - 1).collect();
    cut.push('…');
    cut
}

/// The envelope of a failure. `message` and `example` are the program's own words; what the
/// failure said, which may hold a path or a name from the machine or what a caller gave, is
/// `detail_text`, cut as every text from a source is.
pub fn failure(
    operation: Option<&str>,
    code: &str,
    message: &str,
    example: &str,
    detail: &str,
) -> Value {
    json!({
        "format": FORMAT,
        "operation": operation,
        "ok": false,
        "errors": [{
            "code": code,
            "message": message,
            "example": example,
            "detail_text": cut_text(&crate::secrets::Text::source(detail)),
        }],
    })
}

/// How long a status stays fresh after the latest full check finished: the app starts one every
/// hour with a limit of 30 minutes, so an older check is one that should have been followed by
/// another and was not.
pub const FRESH_FOR: i64 = 2 * 60 * 60;

/// The version of the contract this build prints.
const CONTRACT_FORMAT: u32 = 1;

/// A count as the contract gives it: never below zero.
fn n<T: TryInto<u64>>(x: T) -> u64 {
    x.try_into().unwrap_or(0)
}

/// The contract's `Status`: what `immune status` answers, and `immune run` once its check
/// finished. `found` is every finding at `now`, read in the same transaction as `state`; `conn`
/// is that transaction. Without a store, `conn` and `state` are `None`. A section that cannot be
/// computed is absent and named in `not_computed` with the reason; nothing unknown is given as
/// zero.
pub fn message(
    conn: Option<&Connection>,
    state: Option<&State>,
    running: bool,
    path: &Path,
    now: i64,
) -> Res<crate::contract::v1::Status> {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    let mut out = v1::Status {
        format: CONTRACT_FORMAT,
        answered_at: now,
        running,
        cannot_judge: CANNOT_JUDGE.iter().map(|s| s.to_string()).collect(),
        rules: Some(rules_now(state.and_then(|s| s.event_level.as_ref()))),
        watching: crate::watch::watcher(path),
        answers_note: findings::ANSWERS_NOTE.to_string(),
        ..Default::default()
    };
    out.store = Some(v1::StoreFile {
        path_text: whole(&path.display().to_string()),
        exists: state.is_some(),
        view_sections: match state {
            Some(_) => view::section_files(path)
                .into_iter()
                .map(|(anchor, file)| v1::ViewSection {
                    section: anchor.to_string(),
                    path_text: whole(&file.display().to_string()),
                })
                .collect(),
            None => Vec::new(),
        },
    });
    let mut absent = |section: &str, reason: &str| {
        out.not_computed.push(v1::NotComputed {
            section: section.to_string(),
            reason: reason.to_string(),
        });
    };
    let (Some(conn), Some(st)) = (conn, state) else {
        for section in SECTIONS {
            absent(section, "there is no store yet; `immune run` makes it");
        }
        out.this_mac = Some(this_mac_message(
            &crate::covered::ThisMac::unchecked(false),
            now,
        ));
        return Ok(out);
    };
    let mut not_computed = Vec::new();
    let mut absent = |section: &str, reason: &str| {
        not_computed.push(v1::NotComputed {
            section: section.to_string(),
            reason: reason.to_string(),
        });
    };
    out.store_id = crate::store::id(conn)?;
    // Of the same state of the store as what needs a look: the caller reads `state` and this in
    // one transaction.
    out.journal_seq = Some(findings::journal_seq(conn)?);
    out.this_mac = Some(this_mac_message(&st.this_mac, now));
    match &st.event_level {
        Some(l) => out.event_level = Some(crate::events::message(l)),
        None => absent(
            "event_level",
            "program starts have not been looked for yet; the next check does",
        ),
    }
    out.not_covered = st.not_covered.iter().map(uncovered_message).collect();
    match &st.last {
        Some(l) => out.last_run = Some(mark(l)),
        None => absent("last_run", "no run has started"),
    }
    match &st.summary {
        Some(s) => {
            let t = &s.totals;
            out.last_finished_run = Some(v1::FinishedCheck {
                check: Some(mark(&s.run)),
                first_run: s.first_run,
                readings: Some(v1::CheckReadings {
                    partial: n(t.partial),
                    failed: n(t.none),
                    not_repeated: n(t.not_repeated),
                    machines_unread: n(t.machines_unread),
                }),
                since_previous_run: (!s.first_run).then(|| v1::SinceCheck {
                    added: n(s.since.added),
                    changed: n(s.since.changed),
                    removed: n(s.since.removed),
                }),
                unknown: if s.first_run {
                    Vec::new()
                } else {
                    unknown(t).into_iter().map(str::to_string).collect()
                },
                set_aside: s.set_aside,
            });
            let sv = &s.servers;
            out.estate = Some(v1::Estate {
                machines: n(t.machines),
                servers: n(sv.known),
                servers_offered: n(sv.offered),
                servers_read: n(sv.read),
                servers_in_last_check: n(sv.in_last_check),
                servers_checked_in_last_check: n(sv.checked_in_last_check),
                servers_system_not_given: n(sv.system_not_given),
                own_devices: n(sv.own_devices),
                other_devices: n(sv.other_devices),
                machines_set_aside: n(sv.set_aside),
                machines_seen_after_owner_word_text: sv.seen.iter().map(|m| whole(m)).collect(),
                checkouts: n(t.checkouts),
                components: n(t.components),
            });
            match &s.watched {
                Some(w) => out.watched = Some(watched_message(st, s, w)),
                None => absent("watched", "watched places have never been read"),
            }
            out.threats = Some(threats_message(s.catalogue.as_ref()));
            out.vulnerability_data = Some(v1::VulnerabilityData {
                matched: true,
                feeds: s.feeds.iter().map(|f| feed_message(f, &s.run.id)).collect(),
            });
            out.vulnerabilities = crate::vulnerabilities::totals_message(conn, now)?;
            if out.vulnerabilities.is_none() {
                absent("vulnerabilities", crate::vulnerabilities::NEVER_MATCHED);
            }
            match &s.integrity {
                Some(i) => out.integrity = Some(crate::integrity::message(i)),
                None => absent("integrity", "installed software has never been read"),
            }
            match &s.no_reader_for {
                Some(list) => {
                    out.no_reader_for = Some(v1::NoReaderFor {
                        items: list
                            .iter()
                            .take(NO_READER_SHOWN)
                            .map(|r| v1::NoReader {
                                what: r.what.clone(),
                                what_text: r.name.as_deref().map(whole),
                                where_count: n(r.places),
                            })
                            .collect(),
                    })
                }
                None => absent(
                    "no_reader_for",
                    "the store was made before this was recorded; the next run records it",
                ),
            }
        }
        None => {
            for section in [
                "last_finished_run",
                "estate",
                "watched",
                "integrity",
                "threats",
                "vulnerability_data",
                "vulnerabilities",
                "no_reader_for",
            ] {
                absent(section, "no run has finished yet");
            }
        }
    }
    if st.coverage.is_empty() {
        absent("coverage", "nothing has been read yet");
    } else {
        out.coverage = Some(coverage_message(&st.problems));
    }
    // Every finding, so that a finding named from another (a verdict's) is given by reference.
    let found = findings::all(conn, now)?.unwrap_or_default();
    let items: Vec<findings::Item> = found.iter().filter_map(findings::item).collect();
    let refs = crate::finding_answer::refs(&items);
    let store_id = out.store_id.clone();
    if st.needs.findings_unknown {
        absent(
            "needs_a_look",
            "no run of this build has looked for findings yet; the next run does",
        );
    } else {
        let all = &st.needs.items;
        let is_urgent = |i: &findings::Item| findings::urgent(i.severity, i.confidence);
        // The cut is taken per source, in the one order, urgent first: up to `NEEDS_SHOWN` of
        // the core's findings and up to as many of the response layer's, so that neither source
        // can push the other's findings out of the list. Within a source the order puts urgent
        // findings first, so its cut never drops an urgent finding while it keeps one that is
        // not; `urgent_total` says how many urgent ones there are over both.
        let mut taken = [0; 2];
        let mut kept: Vec<&findings::Item> = Vec::new();
        for i in all {
            let source = usize::from(i.rule == Some(crate::verdict::RULE));
            taken[source] += 1;
            if taken[source] <= NEEDS_SHOWN {
                kept.push(i);
            }
        }
        let mut shown = Vec::new();
        for i in kept {
            let f = found.iter().find(|f| f.id == i.id);
            shown.push(v1::LookFinding {
                finding: Some(crate::finding_answer::listed(i, store_id.as_deref(), &refs)),
                meaning: i.words.meaning.to_string(),
                advice: i.words.advice.to_string(),
                value_text: i.value.as_deref().map(whole),
                technique_text: i.technique.map(whole),
                change: i
                    .change
                    .as_deref()
                    .filter(|_| i.rule.is_some())
                    .map(crate::finding_answer::change_of),
                evidence: match f {
                    Some(f) => crate::finding_answer::evidence(conn, f)?
                        .map(|body| v1::Evidence { body: Some(body) }),
                    None => None,
                },
            });
        }
        out.needs_a_look = Some(v1::NeedsALook {
            items: shown,
            total: n(all.len()),
            urgent_total: n(all.iter().filter(|i| is_urgent(i)).count()),
        });
    }
    match &st.answered {
        Some(answered) => {
            let outside: Vec<&findings::Item> = answered
                .iter()
                .filter(|i| i.answer.as_ref().is_some_and(|a| a.via.outside_app()))
                .collect();
            out.answered_outside_app = Some(v1::AnsweredOutsideApp {
                total: n(outside.len()),
                items: outside
                    .iter()
                    .take(NEEDS_SHOWN)
                    .map(|i| crate::finding_answer::listed(i, store_id.as_deref(), &refs))
                    .collect(),
            });
        }
        None => absent(
            "answered_outside_app",
            "no run of this build has looked for findings yet; the next run does",
        ),
    }
    out.statements_outside_app = Some(crate::owner::outside_app(&st.standing, NEEDS_SHOWN));
    out.not_computed = not_computed;
    let _ = value_of::<v1::Level>;
    Ok(out)
}

/// A run as the contract gives it.
fn mark(r: &RunMark) -> crate::contract::v1::CheckMark {
    crate::contract::v1::CheckMark {
        id: r.id.clone(),
        started_at: r.started_at,
        finished_at: r.finished_at,
    }
}

/// `this_mac`, with whether what the status says is fresh: the latest full check finished
/// within `FRESH_FOR` of `now`.
fn this_mac_message(m: &crate::covered::ThisMac, now: i64) -> crate::contract::v1::ThisMac {
    use crate::contract::{v1, value_of};
    // Through `store::age`, as every judgment of freshness: a time ahead of the clock has no
    // age and is never fresh.
    let stale_reason = match m.checked_at.map(|at| (at, crate::store::age(at, now))) {
        None => Some("no full check has finished on this store".to_string()),
        Some((at, None)) => Some(format!(
            "the latest full check is dated {}: {}",
            view::utc(at),
            crate::store::AHEAD
        )),
        Some((at, Some(age))) if age > FRESH_FOR => Some(format!(
            "the latest full check finished at {}, more than {} hours before this answer, and none has finished since",
            view::utc(at),
            FRESH_FOR / 3600
        )),
        Some(_) => None,
    };
    v1::ThisMac {
        state: value_of::<v1::ThisMacState>(m.state),
        live: m.live,
        checked_at: m.checked_at,
        live_read_at: m.live_read_at,
        watched: m
            .watched
            .iter()
            .map(|(what, count, how)| v1::WatchedThing {
                what: what.to_string(),
                count: n(*count),
                how: how.to_string(),
            })
            .collect(),
        fresh: stale_reason.is_none(),
        stale_reason,
        fresh_for_seconds: n(FRESH_FOR),
    }
}

fn uncovered_message(u: &crate::covered::Uncovered) -> crate::contract::v1::Uncovered {
    use crate::known::whole;
    crate::contract::v1::Uncovered {
        id: u.cause.id.to_string(),
        who: u.cause.who.to_string(),
        scope: u.scope.to_string(),
        kind: u.cause.kind.to_string(),
        title: u.title(),
        meaning: u.meaning(),
        advice: u.cause.advice.to_string(),
        count: n(u.count),
        since_at: u.since,
        value_text: u.value.as_deref().map(whole),
        examples_text: u.examples().iter().map(|e| whole(&e.name)).collect(),
        holds_on: if u.every_mac {
            crate::contract::v1::HoldsOn::EveryMac
        } else {
            crate::contract::v1::HoldsOn::ThisMac
        } as i32,
        // What a source said is prose from it: cut where it is printed, as every such text.
        examples: u
            .examples()
            .iter()
            .map(|e| crate::contract::v1::UncoveredExample {
                name_text: whole(&e.name),
                reason_text: e.reason.as_deref().map(|r| crate::secrets::text(r, whole)),
            })
            .collect(),
    }
}

fn watched_message(st: &State, s: &Summary, w: &Watched) -> crate::contract::v1::WatchedPlaces {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    let mine: Vec<&Latest> = st
        .coverage
        .iter()
        .filter(|r| r.reader == watched::READER)
        .collect();
    let kinds = watched::kinds()
        .into_iter()
        .map(|(watched_as, kind)| {
            let rows: Vec<&&Latest> = mine.iter().filter(|r| r.kind == kind).collect();
            let presence = st
                .presence_only
                .get(watched_as)
                .copied()
                .unwrap_or_default();
            let count = |c: &str| rows.iter().filter(|r| r.completeness == c).count();
            let (full, partial, none) = (count("full"), count("partial"), count("none"));
            let coverage = match (full, partial, none) {
                (0, 0, 0) => None,
                (_, 0, 0) => Some("full"),
                (0, 0, _) => Some("none"),
                _ => Some("partial"),
            };
            let mut reasons: Vec<&str> = Vec::new();
            for r in rows.iter().filter(|r| r.completeness != "full") {
                if let Some(reason) = r.reason.as_deref().filter(|x| !reasons.contains(x)) {
                    reasons.push(reason);
                }
            }
            let reason = match (reasons.is_empty(), rows.as_slice()) {
                (false, _) => Some(reasons.join("; ")),
                (true, [only]) => only.reason.clone(),
                _ => None,
            };
            v1::WatchedKind {
                kind: watched_as.to_string(),
                files: n(st.files.get(watched_as).copied().unwrap_or_default()),
                presence_only: n(presence),
                presence_only_note: (presence > 0).then(|| watched::PRESENCE_ONLY.to_string()),
                coverage: coverage.map(value_of::<v1::Completeness>),
                readings: Some(v1::CompletenessCounts {
                    full: n(full),
                    partial: n(partial),
                    none: n(none),
                }),
                reason_text: reason.as_deref().map(whole),
            }
        })
        .collect();
    v1::WatchedPlaces {
        files: n(w.files),
        first_reading: w.first,
        since_last_reading: (!w.first).then(|| v1::PlaceCounts {
            new: n(w.new),
            changed: n(w.changed),
            gone: n(w.gone),
        }),
        kinds,
        content_not_read: n(mine
            .iter()
            .filter(|r| r.kind == watched::CONTENT && r.completeness != "full")
            .count()),
        changes: s
            .changes
            .iter()
            .rev()
            .take(CHANGES_SHOWN)
            .map(|c| v1::PlaceChange {
                at: c.at,
                run_id: c.run_id.clone(),
                change: crate::finding_answer::change_of(c.change),
                kind: c.kind.clone(),
                path_text: whole(&c.path),
            })
            .collect(),
        changes_total: n(s.changes.len()),
    }
}

/// The latest reading of the catalogue, as `threats_section` says it.
fn threats_message(c: Option<&Catalogue>) -> crate::contract::v1::Threats {
    use crate::contract::v1::{FeedOutcome, Threats};
    let mut t = Threats {
        source: threats::SOURCE.to_string(),
        matched: false,
        ..Default::default()
    };
    match c {
        Some(Catalogue::Read {
            total,
            new,
            gone,
            first,
            at,
        }) => {
            t.outcome = FeedOutcome::Read as i32;
            t.entries = Some(n(*total));
            t.first_reading = Some(*first);
            t.new = Some(n(*new));
            t.gone = Some(n(*gone));
            t.read_at = Some(*at);
            t.checked_at = Some(*at);
        }
        Some(Catalogue::Unchanged { total, at }) => {
            t.outcome = FeedOutcome::Unchanged as i32;
            t.entries = Some(n(*total));
            t.first_reading = Some(false);
            t.new = Some(0);
            t.gone = Some(0);
            t.read_at = Some(*at);
            t.checked_at = Some(*at);
        }
        Some(Catalogue::Failed { reason, last, at }) => {
            t.outcome = FeedOutcome::Failed as i32;
            t.reason_text = Some(crate::known::whole(reason));
            t.entries = last.map(|(_, held)| n(held));
            t.read_at = last.map(|(at, _)| at);
            t.checked_at = Some(*at);
        }
        None => t.outcome = FeedOutcome::NeverRead as i32,
    }
    t
}

/// One feed of vulnerability data, as `feeds_section` says it.
fn feed_message(s: &crate::osv::State, run_id: &str) -> crate::contract::v1::FeedState {
    use crate::contract::v1::{FeedChanges, FeedOutcome, FeedState};
    let mut f = FeedState {
        source: s.feed.source.to_string(),
        ecosystem: s.feed.ecosystem.to_string(),
        asked_this_run: s.asked_in(run_id),
        read_at: s.good_at,
        changed_at: s.changed_at,
        checked_at: s.latest.as_ref().map(|(_, at, ..)| *at),
        // Nothing is counted of a feed never read whole.
        records: s.good_at.map(|_| n(s.records)),
        malicious_records: s.good_at.map(|_| n(s.malicious)),
        withdrawn_records: s.good_at.map(|_| n(s.withdrawn)),
        matched: true,
        ..Default::default()
    };
    match &s.latest {
        None => f.outcome = FeedOutcome::NeverRead as i32,
        Some((_, _, outcome, reason)) if outcome == "failed" => {
            f.outcome = FeedOutcome::Failed as i32;
            f.reason_text = Some(crate::known::whole(reason.as_deref().unwrap_or_default()));
        }
        Some((_, _, outcome, _)) if outcome == "read" && s.asked_in(run_id) => {
            f.outcome = FeedOutcome::Read as i32;
            if let Some(c) = &s.counts {
                f.first_reading = Some(c.first);
                f.since_last_reading = Some(FeedChanges {
                    new: n(c.new),
                    changed: n(c.changed),
                    withdrawn: n(c.withdrawn),
                    gone: n(c.gone),
                });
            }
        }
        Some(_) => f.outcome = FeedOutcome::Unchanged as i32,
    }
    f
}

fn coverage_message(p: &Problems) -> crate::contract::v1::CoverageSummary {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    let class = |c: &str| n(p.classes.get(c).copied().unwrap_or_default());
    v1::CoverageSummary {
        readings: n(p.readings),
        full: n(p.full),
        partial: n(p.partial),
        none: n(p.none),
        implied_by_unreached: n(p.implied),
        failed: class("failed"),
        no_reader: class("no_reader"),
        not_given: class("not_given"),
        read_nothing: class("read_nothing"),
        problems: p
            .groups
            .iter()
            .take(PROBLEMS_SHOWN)
            .map(|g| v1::ReadingGroup {
                class: value_of::<v1::ReadingClass>(g.class),
                reader: g.reader.clone(),
                kind: g.kind.clone(),
                // A reason is prose from a source: cut where it is printed, as every such text.
                reason_text: g.reason.as_deref().map(|r| crate::secrets::text(r, whole)),
                count: n(g.scopes.len()),
                examples_text: g.scopes.iter().take(EXAMPLES).map(|s| whole(s)).collect(),
            })
            .collect(),
        problems_total: n(p.groups.len()),
        unreached: p
            .unreached
            .iter()
            .take(UNREACHED_SHOWN)
            .map(|u| v1::Unreached {
                scope_text: whole(&u.scope),
                since_at: u.since,
                reason_text: u.reason.as_deref().map(|r| crate::secrets::text(r, whole)),
            })
            .collect(),
        unreached_total: n(p.unreached.len()),
    }
}

/// The published rules this build ships and what they do now, as the contract gives them.
pub fn rules_now(level: Option<&crate::events::Level>) -> crate::contract::v1::RulesNow {
    rules_now_of(crate::sigma::Rules::shipped(), level)
}

/// `rules_now` for these rules: see `rules_section`.
pub(crate) fn rules_now_of(
    rules: &crate::sigma::Rules,
    level: Option<&crate::events::Level>,
) -> crate::contract::v1::RulesNow {
    use crate::contract::{v1, value_of};
    use crate::known::whole;
    use crate::sigma::Kind;
    let (evaluated, in_part, not_evaluated) = rules.groups();
    let watching = level.filter(|l| l.state == crate::events::RUNNING);
    let files = watching.is_some_and(|l| l.files_watched());
    let starts_whole = watching.is_none_or(|l| l.last_day.whole());
    let files_whole = !files || watching.is_none_or(|l| l.files_whole());
    let (judged, note) = match watching {
        None => (
            v1::Judged::None,
            Some("The event level is not running, so no program start is judged now."),
        ),
        Some(_) => match (starts_whole, files_whole) {
            (true, true) => (v1::Judged::All, None),
            (false, true) => (
                v1::Judged::Part,
                Some(
                    "Over the last day some program starts were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
            (true, false) => (
                v1::Judged::Part,
                Some(
                    "Over the last day some file events were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
            (false, false) => (
                v1::Judged::Part,
                Some(
                    "Over the last day some program starts and file events were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
        },
    };
    // Whether a rule watches now is one predicate, the page's too (`happens::Watching`).
    let now = crate::happens::Watching::of(level);
    // While the level runs, a rule evaluated in full that does not watch is named, with why:
    // its events are not collected, or what it reads does not arrive because the collector
    // does not keep it, keeps it and never filled it, or no line that would carry it was read.
    let unwatched = |l: &crate::sigma::Loaded| -> Option<(&'static str, Vec<&'static str>)> {
        let level = watching?;
        if now.watches(l) {
            None
        } else if l.kind == Some(Kind::File) && !files {
            Some(("file_events_not_collected", Vec::new()))
        } else {
            let missing = l.needs & now.missing;
            Some((
                level.arrivals.worst(missing).reason()?,
                crate::events::names(missing),
            ))
        }
    };
    let watching_of = |kind: Kind| {
        evaluated
            .iter()
            .filter(|l| l.kind == Some(kind) && now.watches(l))
            .count()
    };
    let watching_file_rules = watching_of(Kind::File);
    let watching_rules = watching_of(Kind::Process) + watching_file_rules;
    let not_watching = evaluated
        .iter()
        .filter_map(|l| Some((l, l.meta.as_ref()?, unwatched(l)?)))
        .map(|(l, m, (reason, not_arriving))| v1::NotWatching {
            rule: Some(crate::matches::rule(l.file, m)),
            reason: value_of::<v1::NotWatchingReason>(reason),
            not_arriving: not_arriving.into_iter().map(str::to_string).collect(),
        })
        .collect();
    let empty = BTreeMap::new();
    let day = level.map_or(&empty, |l| &l.matches_last_day);
    let mut matched: Vec<(&String, &i64)> = day.iter().collect();
    matched.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    v1::RulesNow {
        shipped: n(rules.rules.iter().filter(|l| !l.not_taken()).count()),
        not_taken: n(rules.rules.iter().filter(|l| l.not_taken()).count()),
        evaluated: n(evaluated.len()),
        in_part: n(in_part.len()),
        not_evaluated: n(not_evaluated.len()),
        // Before any reading of the event level, what the rules do now is not known.
        watching: level.map(|_| watching.is_some()),
        watching_rules: level.map(|_| n(watching_rules)),
        file_rules: n(rules.evaluated(Kind::File)),
        watching_file_rules: level.map(|_| n(watching_file_rules)),
        file_events_collected: watching.map(|_| files),
        not_watching,
        judged: judged as i32,
        judged_note: note.map(str::to_string),
        // Absent before any reading of the event level: nothing was counted.
        matches_last_day: level.map(|_| n(day.values().sum::<i64>())),
        matched_last_day: matched
            .iter()
            .take(MATCHED_SHOWN)
            .map(|(id, count)| v1::RuleMatches {
                id_text: whole(id),
                rule: rules
                    .by_id(id)
                    .and_then(|l| l.meta.as_ref().map(|m| crate::matches::rule(l.file, m))),
                matches: n(**count),
            })
            .collect(),
        matched_last_day_total: level.map(|_| n(matched.len())),
    }
}

/// How many rules that matched in the last day the status lists; the rest are counted.
const MATCHED_SHOWN: usize = 10;

/// The class of a reading, from the store's own data: an incomplete reading is classed by its
/// cause, and one written without a cause, before causes were kept, is `failed`; a full
/// reading with a note had nothing to read. A full reading without a note is no problem.
pub fn class(
    completeness: &str,
    reason: Option<&str>,
    cause: Option<&str>,
) -> Option<&'static str> {
    match (completeness, reason, cause) {
        ("full", Some(_), _) => Some("read_nothing"),
        ("full", None, _) => None,
        (_, _, Some("no_reader")) => Some("no_reader"),
        (_, _, Some("not_given")) => Some("not_given"),
        _ => Some("failed"),
    }
}

/// The classes in the order the problems are listed: worst first.
pub const CLASSES: [&str; 4] = ["failed", "no_reader", "not_given", "read_nothing"];

/// Readings of one class, reader, kind and reason.
pub struct Group {
    pub class: &'static str,
    pub reader: String,
    pub kind: String,
    pub reason: Option<String>,
    pub scopes: Vec<String>,
    /// When the latest of its readings was taken.
    pub latest: i64,
}

/// A machine whose latest sweep visit failed or did not complete.
pub struct Unreached {
    pub scope: String,
    /// When its visits began to fail: the first of the failed ones since the last that
    /// completed.
    pub since: i64,
    pub reason: Option<String>,
}

/// The incomplete readings of the latest readings, grouped, and the machines that could not
/// be reached. What failed on a machine that could not be reached is implied by it and left
/// out of the groups.
pub struct Problems {
    pub groups: Vec<Group>,
    pub unreached: Vec<Unreached>,
    /// Readings by class, over the readings in the groups.
    pub classes: BTreeMap<&'static str, usize>,
    /// Readings full without a note.
    pub full: usize,
    /// Readings that failed on a machine that could not be reached.
    pub implied: usize,
    /// Readings by completeness, all of them.
    pub partial: usize,
    pub none: usize,
    pub readings: usize,
}

pub fn problems(conn: &Connection, latest: &[Latest]) -> rusqlite::Result<Problems> {
    let mut unreached = Vec::new();
    for r in latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .filter(|r| r.completeness != "full")
    {
        let since: i64 = conn.query_row(
            "SELECT MIN(observed_at) FROM coverage
             WHERE reader = ?1 AND kind = ?2 AND scope = ?3 AND completeness != 'full'
               AND id > COALESCE((SELECT MAX(id) FROM coverage
                                  WHERE reader = ?1 AND kind = ?2 AND scope = ?3
                                    AND completeness = 'full'), 0)",
            params![servers::READER, servers::VISIT, r.scope],
            |row| row.get(0),
        )?;
        unreached.push(Unreached {
            scope: r.scope.clone(),
            since,
            reason: r.reason.clone(),
        });
    }
    unreached.sort_by(|a, b| (a.since, &a.scope).cmp(&(b.since, &b.scope)));
    let away: HashSet<&str> = unreached.iter().map(|u| u.scope.as_str()).collect();
    let mut p = Problems {
        groups: Vec::new(),
        classes: CLASSES.iter().map(|c| (*c, 0)).collect(),
        full: 0,
        implied: 0,
        partial: latest
            .iter()
            .filter(|r| r.completeness == "partial")
            .count(),
        none: latest.iter().filter(|r| r.completeness == "none").count(),
        readings: latest.len(),
        unreached: Vec::new(),
    };
    let mut index: HashMap<(&str, &str, &str, Option<&str>), usize> = HashMap::new();
    for r in latest {
        let Some(class) = class(&r.completeness, r.reason.as_deref(), r.cause.as_deref()) else {
            p.full += 1;
            continue;
        };
        if class == "failed" && r.reader == servers::READER && away.contains(r.scope.as_str()) {
            p.implied += 1;
            continue;
        }
        *p.classes.entry(class).or_default() += 1;
        let key = (
            class,
            r.reader.as_str(),
            r.kind.as_str(),
            r.reason.as_deref(),
        );
        let i = *index.entry(key).or_insert_with(|| {
            p.groups.push(Group {
                class,
                reader: r.reader.clone(),
                kind: r.kind.clone(),
                reason: r.reason.clone(),
                scopes: Vec::new(),
                latest: r.at,
            });
            p.groups.len() - 1
        });
        p.groups[i].scopes.push(r.scope.clone());
        p.groups[i].latest = p.groups[i].latest.max(r.at);
    }
    let rank = |c: &str| CLASSES.iter().position(|x| *x == c);
    p.groups.sort_by(|a, b| {
        (rank(a.class), b.scopes.len(), &a.reader, &a.kind, &a.reason).cmp(&(
            rank(b.class),
            a.scopes.len(),
            &b.reader,
            &b.kind,
            &b.reason,
        ))
    });
    p.unreached = unreached;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Arrival, Arrivals, Files, Level, RUNNING, Series, Tally};
    use crate::sigma::{ELASTIC, Rules};

    /// A rule of Elastic's set as the translation writes one, about `category`.
    fn rule(id: &str, category: &str, detection: &str) -> &'static str {
        let text = format!(
            "title: Invented {id}\nid: {id}\nstatus: test\nlevel: high\n\
             logsource: {{\"product\": \"macos\", \"category\": \"{category}\"}}\n\
             detection:\n{detection}{}",
            crate::sigma::testing::record_of(&ELASTIC, "\"high\"", "")
        );
        Box::leak(text.into_boxed_str())
    }

    /// What the lines say: everything arrives but the signer, which is as `signature` says, in
    /// a program start and in a file event alike.
    fn signature(signature: Arrival) -> Arrivals {
        let on = Arrival::Kept(Some(1_791_072_002));
        Arrivals::from([on, on, signature, on, signature])
    }

    fn running(arrivals: Arrivals) -> Level {
        Level {
            state: RUNNING.to_string(),
            read_at: 0,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally::default(),
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: Files {
                collected: true,
                ..Files::default()
            },
            arrivals,
            cap: None,
        }
    }

    #[test]
    fn a_rule_that_reads_what_does_not_arrive_is_named_with_which_and_never_counted_as_watching() {
        // No false calm: a rule watches only while lines give values for what it reads. While
        // the latest lines lack it, carry it empty, or no line was read, the rule is not among
        // those watching and is named with which of the three and what does not arrive.
        let rules = Rules::load_as(
            &ELASTIC,
            &[
                (
                    "signer.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000001",
                        "file_event",
                        "  s1: {\"process.code_signature.signing_id|cased\": [\"com.example\"]}\n  condition: s1\n",
                    ),
                ),
                (
                    "start.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000002",
                        "process_creation",
                        "  s1: {\"process.name|cased\": [\"curl\"]}\n  condition: s1\n",
                    ),
                ),
            ],
        );
        for (arrivals, reason) in [
            (signature(Arrival::NotKept), "collector_does_not_keep"),
            (signature(Arrival::Kept(None)), "kept_never_filled"),
            (signature(Arrival::NoLonger(1)), "no_longer_arriving"),
            (signature(Arrival::Unknown), "not_yet_known"),
            (Arrivals::default(), "not_yet_known"),
        ] {
            let r = serde_json::to_value(rules_now_of(&rules, Some(&running(arrivals)))).unwrap();
            assert_eq!(
                (&r["watching_rules"], &r["watching_file_rules"]),
                (&json!(1), &json!(0)),
                "{r}"
            );
            let named = &r["not_watching"][0];
            assert_eq!(
                (
                    &named["rule"]["id_text"],
                    &named["rule"]["level"],
                    &named["rule"]["source"],
                    &named["reason"],
                    &named["not_arriving"]
                ),
                (
                    &json!("00000000-0000-4000-8000-000000000001"),
                    &json!("high"),
                    &json!("elastic"),
                    &json!(reason),
                    &json!(["signature"])
                ),
                "{r}"
            );
            assert_eq!(r["not_watching"].as_array().map(Vec::len), Some(1));
        }
        // Lines that lack it say most: an earlier collector, whatever the other kind says.
        let mixed = Arrivals::from([
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::NotKept,
        ]);
        let r = serde_json::to_value(rules_now_of(&rules, Some(&running(mixed)))).unwrap();
        assert_eq!(r["not_watching"][0]["reason"], "collector_does_not_keep");
        let now = running(signature(Arrival::Kept(Some(1_791_072_003))));
        let r = serde_json::to_value(rules_now_of(&rules, Some(&now))).unwrap();
        assert_eq!(
            (
                &r["watching_rules"],
                &r["watching_file_rules"],
                &r["not_watching"]
            ),
            (&json!(2), &json!(1), &json!([])),
            "{r}"
        );
        // Not running: nothing watches and nothing is named for what the collector keeps.
        let silent = Level {
            state: crate::events::SILENT.to_string(),
            ..running(Arrivals::default())
        };
        let r = serde_json::to_value(rules_now_of(&rules, Some(&silent))).unwrap();
        assert_eq!(
            (&r["watching_rules"], &r["not_watching"]),
            (&json!(0), &json!([]))
        );
    }
}
