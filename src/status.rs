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
use serde_json::{Map, Value, json};
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
    /// Known vulnerabilities in packages the projects use, beside what needs a look and never
    /// counted in it: `vulnerabilities::status_json`.
    pub vulnerabilities: Value,
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
        vulnerabilities: crate::vulnerabilities::status_json(conn, now)?,
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
    let shown = view::shown(s);
    if shown.chars().count() <= TEXT_CAP {
        return shown;
    }
    let mut cut: String = shown.chars().take(TEXT_CAP - 1).collect();
    cut.push('…');
    cut
}

fn iso(secs: i64) -> Value {
    Value::String(view::iso(secs))
}

/// The envelope of an answer.
pub fn envelope(operation: &str, result: Value) -> Value {
    json!({
        "format": FORMAT,
        "operation": operation,
        "ok": true,
        "errors": [],
        "result": result,
    })
}

/// The envelope of a failure. `message` and `example` are the program's own words; what the
/// failure said, which may hold a path or a name from the machine, is `detail_text`.
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
            "detail_text": text(detail),
        }],
    })
}

/// The result of `immune status`, and of `immune run` once it finished. `state` is `None` when
/// there is no store. A section that cannot be computed is left out and named in
/// `not_computed` with the reason; nothing unknown is given as zero.
pub fn result(state: Option<&State>, running: bool, path: &Path, now: i64) -> Value {
    let mut out = Map::new();
    out.insert("generated_at".into(), iso(now));
    out.insert("running".into(), json!(running));
    let mut store =
        json!({ "path_text": text(&path.display().to_string()), "exists": state.is_some() });
    if state.is_some() {
        // The pages `immune view` writes for its sections, so the app opens a file and never
        // builds a path or depends on a `#section` surviving the hand-over to a browser.
        store["view_sections"] = view::section_files(path)
            .into_iter()
            .map(|(anchor, file)| {
                json!({ "section": anchor, "path_text": text(&file.display().to_string()) })
            })
            .collect();
    }
    out.insert("store".into(), store);
    out.insert("cannot_judge".into(), json!(CANNOT_JUDGE));
    // The published rules this build ships, `src/sigma.rs`, and what they did over the program
    // starts the event level read.
    out.insert(
        "rules".into(),
        rules_section(state.and_then(|s| s.event_level.as_ref())),
    );
    // Whether a watcher runs on this store now: `immune watch`, src/watch.rs.
    out.insert("watching".into(), crate::watch::status(path));
    let mut not_computed: Vec<Value> = Vec::new();
    let mut absent = |section: &str, reason: &str| {
        not_computed.push(json!({ "section": section, "reason": reason }));
    };
    let Some(st) = state else {
        out.insert(
            "this_mac".into(),
            crate::covered::this_mac_json(&crate::covered::ThisMac::unchecked(false)),
        );
        for section in SECTIONS {
            absent(section, "there is no store yet; `immune run` makes it");
        }
        out.insert("not_computed".into(), Value::Array(not_computed));
        return Value::Object(out);
    };
    out.insert(
        "this_mac".into(),
        crate::covered::this_mac_json(&st.this_mac),
    );
    // The event level, `src/events.rs`: every program start, when it is installed.
    match &st.event_level {
        Some(l) => {
            out.insert("event_level".into(), crate::events::json(l));
        }
        None => absent(
            "event_level",
            "program starts have not been looked for yet; the next check does",
        ),
    }
    let not_covered: Vec<Value> = st
        .not_covered
        .iter()
        .map(crate::covered::uncovered_json)
        .collect();
    out.insert("not_covered_total".into(), json!(not_covered.len()));
    out.insert("not_covered".into(), Value::Array(not_covered));
    match &st.last {
        Some(l) => {
            out.insert(
                "last_run".into(),
                json!({
                    "id": l.id,
                    "started_at": iso(l.started_at),
                    "finished_at": l.finished_at.map(iso),
                    "finished": l.finished_at.is_some(),
                }),
            );
        }
        None => absent("last_run", "no run has started"),
    }
    match &st.summary {
        Some(s) => {
            out.insert("last_finished_run".into(), finished_run(s));
            out.insert("estate".into(), estate(s));
            match &s.watched {
                Some(w) => {
                    out.insert("watched".into(), watched_section(st, s, w));
                }
                None => absent("watched", "watched places have never been read"),
            }
            out.insert("threats".into(), threats_section(s.catalogue.as_ref()));
            out.insert(
                "vulnerability_data".into(),
                feeds_section(&s.feeds, &s.run.id),
            );
            out.insert("vulnerabilities".into(), st.vulnerabilities.clone());
            match &s.integrity {
                Some(i) => {
                    out.insert("integrity".into(), crate::integrity::section(i));
                }
                None => absent("integrity", "installed software has never been read"),
            }
            match &s.no_reader_for {
                Some(list) => {
                    out.insert("no_reader_for".into(), no_reader_section(list));
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
        out.insert("coverage".into(), coverage_section(&st.problems));
    }
    if st.needs.findings_unknown {
        absent(
            "needs_a_look",
            "no run of this build has looked for findings yet; the next run does",
        );
    } else {
        let items = &st.needs.items;
        // The cut is taken per source, in the one order: up to `NEEDS_SHOWN` of the core's
        // findings and up to as many of the response layer's, so that verdicts cannot push the
        // core's findings out of the list.
        let mut taken = [0; 2];
        let shown: Vec<Value> = items
            .iter()
            .filter(|i| {
                let source = usize::from(i.rule == Some(crate::verdict::RULE));
                taken[source] += 1;
                taken[source] <= NEEDS_SHOWN
            })
            .map(findings::item_json)
            .collect();
        out.insert("needs_a_look".into(), Value::Array(shown));
        out.insert("needs_a_look_total".into(), json!(items.len()));
        out.insert("answers_note".into(), json!(findings::ANSWERS_NOTE));
    }
    match &st.answered {
        Some(answered) => {
            out.insert(
                "answered_outside_app".into(),
                findings::outside_app_json(answered, NEEDS_SHOWN),
            );
        }
        None => absent(
            "answered_outside_app",
            "no run of this build has looked for findings yet; the next run does",
        ),
    }
    out.insert(
        "statements_outside_app".into(),
        crate::owner::outside_app_json(&st.standing, NEEDS_SHOWN),
    );
    out.insert("not_computed".into(), Value::Array(not_computed));
    Value::Object(out)
}

fn finished_run(s: &Summary) -> Value {
    let t = &s.totals;
    let (since, unknown) = if s.first_run {
        (Value::Null, Vec::new())
    } else {
        (
            json!({ "added": s.since.added, "changed": s.since.changed, "removed": s.since.removed }),
            unknown(t),
        )
    };
    json!({
        "id": s.run.id,
        "started_at": iso(s.run.started_at),
        "finished_at": s.run.finished_at.map(iso),
        "first_run": s.first_run,
        "readings": {
            "partial": t.partial,
            "failed": t.none,
            "not_repeated": t.not_repeated,
            "machines_unread": t.machines_unread,
        },
        "since_previous_run": since,
        "unknown": unknown,
    })
}

fn estate(s: &Summary) -> Value {
    json!({
        "machines": s.totals.machines,
        "servers": s.servers.known,
        "servers_offered": s.servers.offered,
        "servers_read": s.servers.read,
        "servers_in_last_check": s.servers.in_last_check,
        "servers_checked_in_last_check": s.servers.checked_in_last_check,
        "servers_system_not_given": s.servers.system_not_given,
        "own_devices": s.servers.own_devices,
        "other_devices": s.servers.other_devices,
        "machines_set_aside": s.servers.set_aside,
        "machines_seen_after_owner_word": s.servers.seen.len(),
        "checkouts": s.totals.checkouts,
        "components": s.totals.components,
    })
}

fn watched_section(st: &State, s: &Summary, w: &Watched) -> Value {
    // On the first reading these are zeros: everything found is the baseline.
    let since = json!({ "new": w.new, "changed": w.changed, "gone": w.gone });
    let mine: Vec<&Latest> = st
        .coverage
        .iter()
        .filter(|r| r.reader == watched::READER)
        .collect();
    let kinds: Vec<Value> = watched::kinds()
        .into_iter()
        .map(|(watched_as, kind)| {
            let rows: Vec<&&Latest> = mine.iter().filter(|r| r.kind == kind).collect();
            let presence = st
                .presence_only
                .get(watched_as)
                .copied()
                .unwrap_or_default();
            let n = |c: &str| rows.iter().filter(|r| r.completeness == c).count();
            let (full, partial, none) = (n("full"), n("partial"), n("none"));
            let coverage = match (full, partial, none) {
                (0, 0, 0) => Value::Null,
                (_, 0, 0) => json!("full"),
                (0, 0, _) => json!("none"),
                _ => json!("partial"),
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
            json!({
                "kind": watched_as,
                "files": st.files.get(watched_as).copied().unwrap_or_default(),
                "presence_only": presence,
                "presence_only_note": (presence > 0).then_some(watched::PRESENCE_ONLY),
                "coverage": coverage,
                "readings": { "full": full, "partial": partial, "none": none },
                "reason_text": reason.as_deref().map(text),
            })
        })
        .collect();
    let content_not_read = mine
        .iter()
        .filter(|r| r.kind == watched::CONTENT && r.completeness != "full")
        .count();
    let changes: Vec<Value> = s
        .changes
        .iter()
        .rev()
        .take(CHANGES_SHOWN)
        .map(|c| {
            json!({
                "at": iso(c.at),
                "run_id": c.run_id,
                "change": c.change,
                "kind": c.kind,
                "path_text": text(&c.path),
            })
        })
        .collect();
    json!({
        "files": w.files,
        "first_reading": w.first,
        "since_last_reading": since,
        "kinds": kinds,
        "content_not_read": content_not_read,
        "changes": changes,
        "changes_total": s.changes.len(),
    })
}

/// How many rules that matched in the last day the status lists; the rest are counted.
const MATCHED_SHOWN: usize = 10;

/// The published rules this build ships, counted by what the event level lets them do, and
/// what they did. `watching` is true only while the event level's latest state is `running`:
/// then every program start read is judged by the rules for program starts evaluated in full,
/// and every file created or renamed by the rules for file events evaluated in full, but only
/// while `file_events_collected`, the collector installed here being established to record
/// them. `watching_rules` counts the rules that watch now; one evaluated in part or not at all
/// is never among them, and a rule for file events whose events are not collected is named in
/// `not_watching` with its reason, as is a rule that reads what the collector installed here
/// does not keep (`crate::events::KEEPS`), with what it does not keep. `judged` says how much
/// of the last day the watching rules judged: `all`, `part` when the log lost events they
/// read, could not read lines or deleted hours before they were read, or `none` while the
/// level does not run, each but `all` with its fixed words in `judged_note`. Matches in the
/// last day are served whether or not the level runs now: they happened.
pub fn rules_section(level: Option<&crate::events::Level>) -> Value {
    rules_section_of(crate::sigma::Rules::shipped(), level)
}

/// `rules_section` for these rules.
pub(crate) fn rules_section_of(
    rules: &crate::sigma::Rules,
    level: Option<&crate::events::Level>,
) -> Value {
    use crate::sigma::Kind;
    let (evaluated, in_part, not_evaluated) = rules.groups();
    let watching = level.filter(|l| l.state == crate::events::RUNNING);
    let files = watching.is_some_and(|l| l.files_watched());
    let starts_whole = watching.is_none_or(|l| l.last_day.whole());
    let files_whole = !files || watching.is_none_or(|l| l.files_whole());
    let (judged, note) = match watching {
        None => (
            "none",
            Some("The event level is not running, so no program start is judged now."),
        ),
        Some(_) => match (starts_whole, files_whole) {
            (true, true) => ("all", None),
            (false, true) => (
                "part",
                Some(
                    "Over the last day some program starts were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
            (true, false) => (
                "part",
                Some(
                    "Over the last day some file events were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
            (false, false) => (
                "part",
                Some(
                    "Over the last day some program starts and file events were lost, could not be read or were deleted before they were read, so the rules judged only those that were read.",
                ),
            ),
        },
    };
    let file_rules = rules.evaluated(Kind::File);
    let not_arriving = watching.map_or(0, |l| l.not_arriving());
    // While the level runs, a rule evaluated in full watches unless its events are not
    // collected or it reads what does not arrive; then it is named, with why: the collector
    // does not keep it, keeps it and never filled it, or no line that would carry it was read.
    let unwatched = |l: &crate::sigma::Loaded| -> Option<(&'static str, Vec<&'static str>)> {
        let level = watching?;
        if l.kind == Some(Kind::File) && !files {
            Some(("file_events_not_collected", Vec::new()))
        } else if l.silenced_by(not_arriving) {
            let missing = l.needs & not_arriving;
            Some((
                level.arrivals.worst(missing).reason()?,
                crate::events::names(missing),
            ))
        } else {
            None
        }
    };
    let watching_of = |kind: Kind| {
        evaluated
            .iter()
            .filter(|l| l.kind == Some(kind) && watching.is_some() && unwatched(l).is_none())
            .count()
    };
    let watching_file_rules = watching_of(Kind::File);
    let watching_rules = watching_of(Kind::Process) + watching_file_rules;
    let not_watching: Vec<Value> = evaluated
        .iter()
        .filter_map(|l| Some((l.meta.as_ref()?, unwatched(l)?)))
        .map(|(m, (reason, not_arriving))| {
            let mut v = json!({
                "id_text": text(&m.id),
                "title_text": text(&m.title),
                "level": m.level_name(),
                "source": m.source.name,
                "set": m.source.set,
                "reason": reason,
            });
            if !not_arriving.is_empty() {
                v["not_arriving"] = json!(not_arriving);
            }
            v
        })
        .collect();
    let empty = BTreeMap::new();
    let day = level.map_or(&empty, |l| &l.matches_last_day);
    let mut matched: Vec<(&String, &i64)> = day.iter().collect();
    matched.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let shown: Vec<Value> = matched
        .iter()
        .take(MATCHED_SHOWN)
        .map(|(id, n)| {
            let meta = rules.by_id(id).and_then(|l| l.meta.as_ref());
            json!({
                "id_text": text(id),
                "title_text": meta.map(|m| text(&m.title)),
                "level": meta.and_then(crate::sigma::Meta::level_name),
                // Its set, by name and in words: two sets can have rules of the same title.
                "source": meta.map(|m| m.source.name),
                "set": meta.map(|m| m.source.set),
                "matches": n,
            })
        })
        .collect();
    json!({
        // Shipped as files; an upstream rule a translated set did not take is counted apart,
        // and as not evaluated.
        "shipped": rules.rules.iter().filter(|l| !l.not_taken()).count(),
        "not_taken": rules.rules.iter().filter(|l| l.not_taken()).count(),
        "evaluated": evaluated.len(),
        "in_part": in_part.len(),
        "not_evaluated": not_evaluated.len(),
        "watching": watching.is_some(),
        "watching_rules": watching_rules,
        "file_rules": file_rules,
        "watching_file_rules": watching_file_rules,
        "file_events_collected": files,
        "not_watching": not_watching,
        "judged": judged,
        "judged_note": note,
        "matches_last_day": day.values().sum::<i64>(),
        "matched_last_day": shown,
        "matched_last_day_total": matched.len(),
    })
}

/// The latest reading of the catalogue. `outcome` is one of `read`, `unchanged`, `failed`
/// and `never_read`. A first reading is the baseline: nothing in it counts as new or gone.
/// After a failed reading what is new is unknown, so there is no count of new or gone.
fn threats_section(c: Option<&Catalogue>) -> Value {
    let mut v = match c {
        Some(Catalogue::Read {
            total,
            new,
            gone,
            first,
            at,
        }) => json!({
            "outcome": "read",
            "entries": total,
            "first_reading": first,
            "new": new,
            "gone": gone,
            "read_at": iso(*at),
            "checked_at": iso(*at),
        }),
        Some(Catalogue::Unchanged { total, at }) => json!({
            "outcome": "unchanged",
            "entries": total,
            "first_reading": false,
            "new": 0,
            "gone": 0,
            "read_at": iso(*at),
            "checked_at": iso(*at),
        }),
        Some(Catalogue::Failed { reason, last, at }) => json!({
            "outcome": "failed",
            "reason_text": text(reason),
            "entries": last.map(|(_, n)| n),
            "read_at": last.map(|(at, _)| iso(at)),
            "checked_at": iso(*at),
        }),
        None => json!({ "outcome": "never_read" }),
    };
    v["source"] = json!(threats::SOURCE);
    v["matched"] = json!(false);
    v
}

/// The feeds of vulnerability data, one entry each. `outcome` is the latest reading's: `read`,
/// `unchanged`, `failed` or `never_read`; a run that did not ask for a feed, because its last
/// good reading is recent, leaves it `unchanged` with `asked_this_run` false. `read_at` is when
/// it was last read successfully, `changed_at` when what it holds last changed. `matched` says
/// that its ecosystem is matched against the projects' lockfiles; the answers are in the part
/// `vulnerabilities`.
fn feeds_section(feeds: &[crate::osv::State], run_id: &str) -> Value {
    let list: Vec<Value> = feeds
        .iter()
        .map(|s| {
            let mut v = json!({
                "source": s.feed.source,
                "ecosystem": s.feed.ecosystem,
                "asked_this_run": s.asked_in(run_id),
                "read_at": s.good_at.map(iso),
                "changed_at": s.changed_at.map(iso),
                "checked_at": s.latest.as_ref().map(|(_, at, ..)| iso(*at)),
                "records": s.records,
                "malicious_records": s.malicious,
                "withdrawn_records": s.withdrawn,
                "matched": true,
            });
            match &s.latest {
                None => v["outcome"] = json!("never_read"),
                Some((_, _, outcome, reason)) if outcome == "failed" => {
                    v["outcome"] = json!("failed");
                    v["reason_text"] = text(reason.as_deref().unwrap_or_default());
                }
                Some((_, _, outcome, _)) if outcome == "read" && s.asked_in(run_id) => {
                    v["outcome"] = json!("read");
                    if let Some(c) = &s.counts {
                        v["first_reading"] = json!(c.first);
                        v["since_last_reading"] = json!({
                            "new": c.new,
                            "changed": c.changed,
                            "withdrawn": c.withdrawn,
                            "gone": c.gone,
                        });
                    }
                }
                Some(_) => v["outcome"] = json!("unchanged"),
            }
            v
        })
        .collect();
    json!({ "matched": true, "feeds": list })
}

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

/// Counts of the latest readings by class and by completeness, the problems grouped so that
/// many readings with one reason are one entry with up to three of their scopes, and the
/// machines that could not be reached.
fn coverage_section(p: &Problems) -> Value {
    let problems: Vec<Value> = p
        .groups
        .iter()
        .take(PROBLEMS_SHOWN)
        .map(|g| {
            let examples: Vec<Value> = g.scopes.iter().take(EXAMPLES).map(|s| text(s)).collect();
            json!({
                "class": g.class,
                "reader": g.reader,
                "kind": g.kind,
                "reason_text": g.reason.as_deref().map(text),
                "count": g.scopes.len(),
                "examples_text": examples,
            })
        })
        .collect();
    let unreached: Vec<Value> = p
        .unreached
        .iter()
        .take(UNREACHED_SHOWN)
        .map(|u| {
            json!({
                "scope_text": text(&u.scope),
                "since": iso(u.since),
                "reason_text": u.reason.as_deref().map(text),
            })
        })
        .collect();
    let mut v = json!({
        "readings": p.readings,
        "full": p.full,
        "partial": p.partial,
        "none": p.none,
        "implied_by_unreached": p.implied,
        "problems": problems,
        "problems_total": p.groups.len(),
        "unreached": unreached,
        "unreached_total": p.unreached.len(),
    });
    for (class, n) in &p.classes {
        v[*class] = json!(n);
    }
    v
}

fn no_reader_section(list: &[NoReader]) -> Value {
    Value::Array(
        list.iter()
            .take(NO_READER_SHOWN)
            .map(|n| {
                json!({
                    "what": n.what,
                    "what_text": n.name.as_deref().map(text),
                    "where_count": n.places,
                })
            })
            .collect(),
    )
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
            let r = rules_section_of(&rules, Some(&running(arrivals)));
            assert_eq!(
                (&r["watching_rules"], &r["watching_file_rules"]),
                (&json!(1), &json!(0)),
                "{r}"
            );
            assert_eq!(
                r["not_watching"],
                json!([{
                    "id_text": "00000000-0000-4000-8000-000000000001",
                    "title_text": "Invented 00000000-0000-4000-8000-000000000001",
                    "level": "high",
                    "source": "elastic",
                    "set": "Elastic's detection rules",
                    "reason": reason,
                    "not_arriving": ["signature"],
                }])
            );
        }
        // Lines that lack it say most: an earlier collector, whatever the other kind says.
        let mixed = Arrivals::from([
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::Kept(Some(1)),
            Arrival::NotKept,
        ]);
        let r = rules_section_of(&rules, Some(&running(mixed)));
        assert_eq!(r["not_watching"][0]["reason"], "collector_does_not_keep");
        let now = running(signature(Arrival::Kept(Some(1_791_072_003))));
        let r = rules_section_of(&rules, Some(&now));
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
        let r = rules_section_of(&rules, Some(&silent));
        assert_eq!(
            (&r["watching_rules"], &r["not_watching"]),
            (&json!(0), &json!([]))
        );
    }
}
