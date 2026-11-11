//! The state the store holds after the last finished run, read back from the store alone.
//!
//! The run's report line, `soc status` and the machine-readable form of both are built from
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
use crate::{ServerCounts, resolver, threats, watched};
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
/// What this build cannot answer at all, in its own words.
pub const CANNOT_JUDGE: [&str; 1] = ["no threat is matched against the estate yet"];
/// The sections of a result that hold numbers, in the order of the result.
const SECTIONS: [&str; 6] = [
    "last_run",
    "last_finished_run",
    "estate",
    "watched",
    "threats",
    "coverage",
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
}

/// Reads what `run` left. `home` is the store's folder, where the sweep's skip list is.
/// The run calls this inside its transaction before it finishes; `soc status` calls it on
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

/// For each reading of the watched places reader, the run whose reading of it first read
/// something. That run's events of the reading are the baseline: journaled, and counted as
/// nothing new.
fn baselines(conn: &Connection) -> rusqlite::Result<HashMap<(String, String), String>> {
    let mut stmt = conn.prepare(
        "SELECT scope, kind, run_id FROM coverage
         WHERE reader = ?1 AND completeness != 'none' ORDER BY id",
    )?;
    let rows = stmt.query_map([watched::READER], |r| {
        Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (scope, kind, run) = row?;
        out.entry((scope, kind)).or_insert(run);
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
}

/// The differences of one run, or of every run, oldest first, from one reader or all,
/// without the baseline of the watched places.
fn journaled(
    conn: &Connection,
    run_id: Option<&str>,
    reader: Option<&str>,
    base: &HashMap<(String, String), String>,
) -> rusqlite::Result<Vec<Journaled>> {
    let mut stmt = conn.prepare(
        "SELECT at, run_id, entry, reader, scope, kind, subject, predicate, old_value, new_value
         FROM journal
         WHERE entry IN ('added', 'changed', 'removed')
           AND (?1 IS NULL OR run_id = ?1) AND (?2 IS NULL OR reader = ?2)
         ORDER BY seq",
    )?;
    let rows = stmt.query_map(params![run_id, reader], |r| {
        let reader: Option<String> = r.get(3)?;
        let kind: Option<String> = r.get(5)?;
        let e = Journaled {
            at: r.get(0)?,
            run_id: r.get(1)?,
            entry: r.get(2)?,
            scope: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
            subject: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
            predicate: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
            old: r.get(8)?,
            new: r.get(9)?,
        };
        let baseline = reader.as_deref() == Some(watched::READER)
            && base.get(&(e.scope.clone(), kind.unwrap_or_default())) == Some(&e.run_id);
        Ok((!baseline).then_some(e))
    })?;
    rows.filter_map(Result::transpose).collect()
}

/// Counts things, not assertions: a new component is one addition however many assertions
/// it brings.
fn since(
    conn: &Connection,
    run_id: &str,
    base: &HashMap<(String, String), String>,
) -> rusqlite::Result<Since> {
    let events = journaled(conn, Some(run_id), None, base)?;
    let count = |entry: &str| {
        events
            .iter()
            .filter(|e| e.entry == entry)
            .map(|e| e.subject.as_str())
            .collect::<HashSet<_>>()
            .len()
    };
    Ok(Since {
        added: count("added"),
        changed: count("changed"),
        removed: count("removed"),
    })
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
fn file_changes(
    conn: &Connection,
    base: &HashMap<(String, String), String>,
) -> rusqlite::Result<Vec<FileChange>> {
    let events = journaled(conn, None, Some(watched::READER), base)?;
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

/// Everything `soc status` shows, read in one transaction.
pub struct State {
    /// The latest run that started.
    pub last: Option<RunMark>,
    /// What the latest finished run left; `None` when no run finished.
    pub summary: Option<Summary>,
    /// The latest reading of each reader, scope and kind, not full first.
    pub coverage: Vec<Latest>,
    /// Live files per kind of watched place.
    pub files: BTreeMap<String, i64>,
}

pub fn state(conn: &Connection, home: &Path) -> Res<State> {
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
    Ok(State {
        last: latest_run(conn)?,
        summary,
        coverage: view::latest_coverage(conn)?,
        files,
    })
}

/// Text from a source as a field's value: hidden characters as the terminal shows them,
/// and at most `TEXT_CAP` characters.
pub fn text(s: &str) -> Value {
    let shown = view::shown(s);
    if shown.chars().count() <= TEXT_CAP {
        return Value::String(shown);
    }
    let mut cut: String = shown.chars().take(TEXT_CAP - 1).collect();
    cut.push('…');
    Value::String(cut)
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

/// The result of `soc status`, and of `soc run` once it finished. `state` is `None` when
/// there is no store. A section that cannot be computed is left out and named in
/// `not_computed` with the reason; nothing unknown is given as zero.
pub fn result(state: Option<&State>, running: bool, path: &Path, now: i64) -> Value {
    let mut out = Map::new();
    out.insert("generated_at".into(), iso(now));
    out.insert("running".into(), json!(running));
    let path = text(&path.display().to_string());
    out.insert(
        "store".into(),
        json!({ "path_text": path, "exists": state.is_some() }),
    );
    out.insert("cannot_judge".into(), json!(CANNOT_JUDGE));
    let mut not_computed: Vec<Value> = Vec::new();
    let mut absent = |section: &str, reason: &str| {
        not_computed.push(json!({ "section": section, "reason": reason }));
    };
    let Some(st) = state else {
        for section in SECTIONS {
            absent(section, "there is no store yet; `soc run` makes it");
        }
        out.insert("not_computed".into(), Value::Array(not_computed));
        return Value::Object(out);
    };
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
        }
        None => {
            for section in ["last_finished_run", "estate", "watched", "threats"] {
                absent(section, "no run has finished yet");
            }
        }
    }
    if st.coverage.is_empty() {
        absent("coverage", "nothing has been read yet");
    } else {
        out.insert("coverage".into(), coverage_section(&st.coverage));
    }
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

/// The class of a reading: `failed` read nothing, `partial` read some and cannot tell what
/// disappeared, `read_nothing` was full with a note that there was nothing to read, as the
/// view's "nothing to read". A full reading without a note is no problem. The report line's
/// "readings read nothing" are the `failed` ones.
pub fn class(completeness: &str, reason: Option<&str>) -> Option<&'static str> {
    match (completeness, reason) {
        ("none", _) => Some("failed"),
        ("partial", _) => Some("partial"),
        ("full", Some(_)) => Some("read_nothing"),
        _ => None,
    }
}

/// The order of classes in the list of problems.
const CLASSES: [&str; 3] = ["failed", "partial", "read_nothing"];

/// Readings of one class, reader, kind and reason.
struct Group<'a> {
    class: &'static str,
    reader: &'a str,
    kind: &'a str,
    reason: Option<&'a str>,
    scopes: Vec<&'a str>,
}

/// Counts of the latest readings by class, and the problems grouped so that many readings
/// with one reason are one entry, with up to three of their scopes as examples.
fn coverage_section(latest: &[Latest]) -> Value {
    let mut full = 0;
    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<(&str, &str, &str, Option<&str>), usize> = HashMap::new();
    for r in latest {
        let Some(class) = class(&r.completeness, r.reason.as_deref()) else {
            full += 1;
            continue;
        };
        let key = (
            class,
            r.reader.as_str(),
            r.kind.as_str(),
            r.reason.as_deref(),
        );
        let i = *index.entry(key).or_insert_with(|| {
            groups.push(Group {
                class,
                reader: &r.reader,
                kind: &r.kind,
                reason: r.reason.as_deref(),
                scopes: Vec::new(),
            });
            groups.len() - 1
        });
        groups[i].scopes.push(&r.scope);
    }
    let rank = |c: &str| CLASSES.iter().position(|x| *x == c);
    groups.sort_by(|a, b| {
        (rank(a.class), b.scopes.len(), a.reader, a.kind, a.reason).cmp(&(
            rank(b.class),
            a.scopes.len(),
            b.reader,
            b.kind,
            b.reason,
        ))
    });
    let count = |c: &str| {
        groups
            .iter()
            .filter(|g| g.class == c)
            .map(|g| g.scopes.len())
            .sum::<usize>()
    };
    let problems: Vec<Value> = groups
        .iter()
        .take(PROBLEMS_SHOWN)
        .map(|g| {
            let examples: Vec<Value> = g.scopes.iter().take(EXAMPLES).map(|s| text(s)).collect();
            json!({
                "class": g.class,
                "reader": g.reader,
                "kind": g.kind,
                "reason_text": g.reason.map(text),
                "count": g.scopes.len(),
                "examples_text": examples,
            })
        })
        .collect();
    json!({
        "readings": latest.len(),
        "full": full,
        "read_nothing": count("read_nothing"),
        "partial": count("partial"),
        "failed": count("failed"),
        "problems": problems,
        "problems_total": groups.len(),
    })
}
