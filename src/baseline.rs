//! Whether something a reading of the watched places found is a change, the baseline, or read
//! for the first time. A thing found has three possible judgements, because the store either
//! can show that it was not there before, or can show that nobody could have known, or can show
//! neither:
//!
//! - a change, raised by its rule, when the store can show it was not there: the unit that
//!   holds it was read in full by an earlier run; or the unit is new to a listing an earlier
//!   run made in full; or it is in a checkout new to a listing an earlier walk made in full,
//!   and was in reach since that checkout was first seen;
//! - the baseline, recorded and silent, during the store's first check, for a unit nothing met
//!   before: nobody could have known what was there;
//! - read for the first time, recorded and told once, in every other case: a project reached
//!   later by a run pointed at its folder, a folder that could not be read before, a unit an
//!   older store recorded nothing about.
//!
//! A unit is the smallest thing one failure can hit: one file, read or found absent, or one
//! folder's listing. A listing that worked and could not follow one entry is still a listing:
//! that entry is its own unit, and its neighbours are judged as they are. Each unit is recorded
//! once per reader and kind, by the first run that read it in full (`read`) and the first that
//! met it present (`seen`). The record keeps the order in which units were first met, so that
//! a listing made in one run and an entry first seen in a later one tell that the entry is new.
//!
//! File integrity monitors build their baseline from their first scan of the paths given to
//! them. Immune's readings cover different places at different times, the watcher's and a full
//! check's, so its baseline is kept per unit.

use crate::{agent_folders, autorun, checkouts, store, watched};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::{BTreeSet, HashMap};

/// Every unit a reader met, by the first run that read it in full and the first that saw it
/// present. Rows are only added; their order is the order units were first met.
const SCHEMA: &str = "
CREATE TABLE unit_read (
    reader TEXT NOT NULL,
    kind   TEXT NOT NULL,
    unit   TEXT NOT NULL,     -- a path as ids name it: a file, or a folder that was listed
    how    TEXT NOT NULL CHECK (how IN ('read', 'seen')),
    run_id TEXT NOT NULL,     -- the first run that did
    at     INTEGER NOT NULL,  -- UTC seconds
    PRIMARY KEY (reader, kind, unit, how)
);
";

/// Every unit that was there and could not be read when a reading judged it. It is judged once
/// while it stays so; the row goes when the unit is read again.
const UNREAD: &str = "
CREATE TABLE IF NOT EXISTS unit_unread (
    reader TEXT NOT NULL,
    kind   TEXT NOT NULL,
    unit   TEXT NOT NULL,
    run_id TEXT NOT NULL,     -- the run that judged it
    PRIMARY KEY (reader, kind, unit)
);
";

// Whole-path tables keep their layout. A build that does not know parts will never see a
// part read as a whole file read.
const PARTS: &str = "
CREATE TABLE IF NOT EXISTS part_read (
    reader TEXT NOT NULL,
    kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    part TEXT NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, kind, unit, part)
);
CREATE TABLE IF NOT EXISTS part_unread (
    reader TEXT NOT NULL,
    kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    part TEXT NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, kind, unit, part)
);
";
const TYPED_UNITS: &str = "typed_units";

/// The physical unit of a watched assertion, scoped to the reading that made it.
const WATCHED_UNITS: &str = "
CREATE TABLE IF NOT EXISTS watched_unit (
    kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    path TEXT NOT NULL,
    part TEXT NOT NULL,
    PRIMARY KEY (kind, scope, subject)
);
";

pub fn remember_units(
    tx: &Transaction,
    r: &store::Reading,
    units: &HashMap<String, &Unit>,
) -> rusqlite::Result<()> {
    if units.is_empty() {
        return Ok(());
    }
    let mut stmt = tx.prepare(
        "INSERT INTO watched_unit (kind, scope, subject, path, part) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (kind, scope, subject) DO UPDATE SET path = excluded.path, part = excluded.part
         WHERE (path, part) != (excluded.path, excluded.part)",
    )?;
    for (subject, unit) in units {
        stmt.execute(params![r.kind, r.scope, subject, unit.path, unit.part])?;
    }
    Ok(())
}

/// The key in `meta` of the last journal entry written before units were recorded. Entries up
/// to it were judged by the rule of their time, which `status.rs` applies to them.
pub const UNITS_SINCE: &str = "units_since";

/// Makes the table on the first open by a build that has it, and fills it from what the store
/// already holds, each unit as of the run that first read it: every file an earlier reading
/// recorded, with its folder where the kind lists folders; every place of a kind a reading read
/// in full, which its coverage says; every checkout a walk found, and the folders above it,
/// listed by a walk of the home folder that read in full. From then on one rule judges every
/// reading, whatever run of this build comes first.
pub fn open(conn: &mut Connection) -> Result<(), Box<dyn std::error::Error>> {
    if made(conn)? && typed(conn)? {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !typed(&tx)? || !made(&tx)? {
        tx.execute_batch(UNREAD)?;
        tx.execute_batch(PARTS)?;
        tx.execute_batch(WATCHED_UNITS)?;
        if made(&tx)? {
            invalidate_split_units(&tx)?;
        } else {
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT OR REPLACE INTO meta (key, value)
                 VALUES (?1, (SELECT COALESCE(MAX(seq), 0) FROM journal))",
                [UNITS_SINCE],
            )?;
            fill(&tx)?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, '1')",
            [TYPED_UNITS],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn typed(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM meta WHERE key = ?1)",
        [TYPED_UNITS],
        |r| r.get(0),
    )
}

fn made(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'unit_read')",
        [],
        |r| r.get(0),
    )
}

/// Old backfills and unread judgements could use the prefix before a literal hash as a path.
/// Discard that evidence if it might have come from a different physical unit. Preserve the
/// chronology of all other rows; the next successful reading establishes the discarded ones.
fn invalidate_split_units(tx: &Transaction) -> rusqlite::Result<()> {
    let mut stmt = tx.prepare(
        "SELECT DISTINCT kind, subject FROM assertion
         WHERE reader = ?1 AND predicate = 'watched_as' AND instr(subject, '#') > 0",
    )?;
    let checkouts = past_checkouts(tx)?;
    let mut suspect = BTreeSet::new();
    for row in stmt.query_map([watched::READER], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (kind, subject) = row?;
        let Some((machine, path)) = subject
            .strip_prefix("file:")
            .and_then(|s| s.split_once('/'))
        else {
            continue;
        };
        let Some((prefix, _)) = path.split_once('#') else {
            continue;
        };
        if legacy_unit(&kind, path, |rel| {
            checkouts.contains(&format!("{machine}/{rel}"))
        })
        .is_none_or(|unit| unit.path != prefix)
        {
            suspect.insert((kind, prefix.to_string()));
        }
    }
    for (kind, path) in suspect {
        tx.execute(
            "DELETE FROM unit_read WHERE reader = ?1 AND kind = ?2 AND unit = ?3",
            params![watched::READER, kind, path],
        )?;
    }
    // A legacy unread mark is a suppression, not proof of coverage. If it was created
    // without an assertion (the path was never readable), it has no source to disambiguate it.
    tx.execute(
        "DELETE FROM unit_unread WHERE reader = ?1 AND kind != ?2",
        params![watched::READER, watched::CONTENT],
    )?;
    Ok(())
}

fn past_checkouts(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT substr(subject, 10) FROM assertion
         WHERE predicate = 'located_on' AND layer != 'draft'
           AND reader IN (?1, ?2) AND subject LIKE 'checkout:%'",
    )?
    .query_map([checkouts::READER, agent_folders::READER], |r| r.get(0))?
    .collect()
}

/// One unit to record when the table is filled.
struct Filled {
    reader: &'static str,
    kind: String,
    unit: String,
    how: &'static str,
    run_id: String,
    at: i64,
}

fn fill(tx: &Transaction) -> rusqlite::Result<()> {
    let mut out: Vec<Filled> = Vec::new();
    let mut add = |reader, kind: &str, unit: &str, how, run_id: &str, at| {
        out.push(Filled {
            reader,
            kind: kind.to_string(),
            unit: unit.to_string(),
            how,
            run_id: run_id.to_string(),
            at,
        })
    };
    type Row = (String, String, String, i64);
    let checkouts = past_checkouts(tx)?;
    let rows: Vec<Row> = tx
        .prepare(
            "SELECT subject, kind, run_id, observed_at FROM assertion
             WHERE reader = ?1 AND predicate = 'watched_as' AND layer != 'draft' ORDER BY id",
        )?
        .query_map([watched::READER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut parts = tx.prepare(
        "INSERT OR IGNORE INTO part_read (reader, kind, unit, part, run_id)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (subject, kind, run_id, at) in rows {
        let Some((machine, path)) = subject
            .strip_prefix("file:")
            .and_then(|s| s.split_once('/'))
        else {
            continue;
        };
        let Some(unit) = legacy_unit(&kind, path, |rel| {
            checkouts.contains(&format!("{machine}/{rel}"))
        }) else {
            continue;
        };
        let u = &unit.path;
        add(watched::READER, &kind, u, "seen", &run_id, at);
        // Before this build, a selected autorun entry came only from a whole-file read.
        // A plist can yield one key while leaving another unread.
        if unit.part.is_empty() || kind != watched::LOGIN_HOOK_KIND {
            add(watched::READER, &kind, u, "read", &run_id, at);
        } else {
            parts.execute(params![watched::READER, kind, unit.path, unit.part, run_id])?;
        }
        if lists_parent(&kind, u) {
            add(watched::READER, &kind, parent(u), "read", &run_id, at);
        }
    }
    let rows: Vec<Row> = tx
        .prepare(
            "SELECT scope, kind, run_id, observed_at FROM coverage
             WHERE reader = ?1 AND completeness = 'full' ORDER BY id",
        )?
        .query_map([watched::READER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (scope, kind, run_id, at) in rows {
        for unit in read_whole(&scope, &kind) {
            add(watched::READER, &kind, &unit, "read", &run_id, at);
        }
    }
    let rows: Vec<(String, String, i64, bool)> = tx
        .prepare(
            "SELECT a.subject, a.run_id, a.observed_at,
                    EXISTS (SELECT 1 FROM coverage c WHERE c.reader = a.reader
                              AND c.run_id = a.run_id AND c.completeness = 'full')
             FROM assertion a
             WHERE a.reader = ?1 AND a.predicate = 'located_on' AND a.layer != 'draft'
             ORDER BY a.id",
        )?
        .query_map([checkouts::READER], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let (r, k) = (checkouts::READER, checkouts::KIND);
    for (subject, run_id, at, whole) in rows {
        let Some(rel) = path_of(&subject, "checkout:") else {
            continue;
        };
        add(r, k, rel, "seen", &run_id, at);
        // A walk of the home folder that read in full listed every folder on the way to each
        // checkout it found.
        if whole && !rel.starts_with('/') {
            let mut here = rel;
            loop {
                let up = parent(here);
                add(r, k, up, "read", &run_id, at);
                if up == here || up == "." {
                    break;
                }
                add(r, k, up, "seen", &run_id, at);
                here = up;
            }
        }
    }
    for f in out {
        let unit = [Unit::whole(f.unit)];
        let (read, seen): (&[Unit], &[Unit]) = if f.how == "read" {
            (&unit, &[])
        } else {
            (&[], &unit)
        };
        record(tx, f.reader, &f.kind, &f.run_id, f.at, read, seen)?;
    }
    Ok(())
}

/// The units a full reading of `kind` in `scope` read, by the places of the kind: every place
/// of a kind of this machine, the hooks of a checkout, the files of a row of the home folder.
/// A row over every checkout does not say which checkouts it read, and gives none.
fn read_whole(scope: &str, kind: &str) -> Vec<String> {
    if kind == watched::HOOK_KIND {
        return path_of(scope, "checkout:")
            .map(|rel| vec![format!("{rel}/.git/hooks")])
            .unwrap_or_default();
    }
    let places: Vec<String> = watched::PLACES
        .iter()
        .filter(|p| p.kind == kind)
        .filter_map(|p| match p.base {
            watched::Base::Home => Some(p.path.to_string()),
            watched::Base::System => Some(format!("/{}", p.path)),
            watched::Base::Checkout => None,
        })
        .collect();
    if !places.is_empty() {
        return places;
    }
    autorun::POINTS
        .iter()
        .filter(|p| p.read_here() && p.scope == autorun::Scope::Home && p.kind() == kind)
        .flat_map(|p| p.paths.iter())
        .map(|path| match path.rsplit_once('/') {
            Some((folder, name)) if name.contains('*') => folder.to_string(),
            None if path.contains('*') => ".".to_string(),
            _ => path.to_string(),
        })
        .collect()
}

/// The path in an id, `<prefix><machine>/<path>`.
fn path_of<'a>(id: &'a str, prefix: &str) -> Option<&'a str> {
    id.strip_prefix(prefix)
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, path)| path)
}

/// A physical path, or one selected part of it. Only the public name combines the two.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unit {
    pub path: String,
    pub part: String,
}

impl Unit {
    pub fn whole(path: impl Into<String>) -> Self {
        let path = path.into();
        let path = if path == "/" {
            "/"
        } else {
            path.trim_end_matches('/')
        };
        Self {
            path: if path.is_empty() {
                ".".to_string()
            } else {
                path.to_string()
            },
            part: String::new(),
        }
    }

    pub fn part(path: impl Into<String>, pointer: impl Into<String>) -> Self {
        Self {
            part: pointer.into(),
            ..Self::whole(path)
        }
    }

    /// Whether a failure of this unit leaves the observed unit unknown.
    pub fn hides(&self, observed: &Self) -> bool {
        if self.part.is_empty() {
            under(&observed.path, &self.path)
        } else {
            self == observed
        }
    }
}

impl std::fmt::Display for Unit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)?;
        if !self.part.is_empty() {
            write!(f, "#{}", self.part)?;
        }
        Ok(())
    }
}

/// Recover a legacy assertion's physical source only where the owning reader could have
/// produced it. A literal path and a selected pointer can contain the same characters.
pub fn legacy_unit(kind: &str, name: &str, checkout: impl Fn(&str) -> bool) -> Option<Unit> {
    let mut candidates = BTreeSet::new();
    for p in watched::PLACES.iter().filter(|p| p.kind == kind) {
        let file = match p.base {
            watched::Base::Home => p.path.to_string(),
            watched::Base::System => format!("/{}", p.path),
            watched::Base::Checkout => {
                if parent(name)
                    .strip_suffix(&format!("/{}", p.path))
                    .is_some_and(&checkout)
                {
                    candidates.insert(Unit::whole(name));
                }
                continue;
            }
        };
        match p.counts {
            watched::Counts::Keys(keys) => {
                for key in keys {
                    let unit = Unit::part(&file, format!("/{key}"));
                    if name == unit.to_string() {
                        candidates.insert(unit);
                    }
                }
            }
            watched::Counts::Whole
                if (p.folder && parent(name) == file) || (!p.folder && name == file) =>
            {
                candidates.insert(Unit::whole(name));
            }
            _ => {}
        }
    }
    autorun::legacy_units(kind, name, &checkout, &mut candidates);
    (candidates.len() == 1)
        .then(|| candidates.pop_first())
        .flatten()
}

/// The folder that holds a unit: `.` for one directly in the home folder, `/` for one directly
/// at the root.
pub fn parent(unit: &str) -> &str {
    match unit.rsplit_once('/') {
        Some(("", _)) => "/",
        Some((folder, _)) => folder,
        None => ".",
    }
}

/// Whether `path` is the unit `unit` or inside it.
pub fn under(path: &str, unit: &str) -> bool {
    if unit == "." {
        return !path.starts_with('/');
    }
    path == unit
        || path
            .strip_prefix(unit)
            .is_some_and(|rest| rest.starts_with('/'))
        || (unit == "/" && path.starts_with('/'))
}

/// Whether a reading of `kind` lists the folder that holds `unit`: a watched folder, a
/// checkout's hooks, the folders of an editor's extensions, the files a name with `*` matches.
pub fn lists_parent(kind: &str, unit: &str) -> bool {
    if kind == watched::HOOK_KIND {
        return true;
    }
    let folder = parent(unit);
    let watched_folder = watched::PLACES.iter().any(|p| {
        p.kind == kind
            && p.folder
            && match p.base {
                watched::Base::Home => p.path == folder,
                watched::Base::System => folder.strip_prefix('/') == Some(p.path),
                watched::Base::Checkout => false,
            }
    });
    watched_folder
        || autorun::POINTS.iter().any(|p| {
            p.read_here()
                && p.kind() == kind
                && (matches!(p.part, autorun::Part::Folders(_))
                    || p.paths.iter().any(|path| path.contains('*')))
        })
}

/// Records the units a reading read in full and those it saw present; a unit recorded before
/// keeps its first run.
pub fn record(
    tx: &Transaction,
    reader: &str,
    kind: &str,
    run_id: &str,
    at: i64,
    read: &[Unit],
    seen: &[Unit],
) -> rusqlite::Result<()> {
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO unit_read (reader, kind, unit, how, run_id, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (how, units) in [("read", read), ("seen", seen)] {
        for unit in units.iter().filter(|u| u.part.is_empty()) {
            stmt.execute(params![reader, kind, unit.path, how, run_id, at])?;
        }
    }
    let mut again =
        tx.prepare("DELETE FROM unit_unread WHERE reader = ?1 AND kind = ?2 AND unit = ?3")?;
    let mut part_again = tx.prepare(
        "DELETE FROM part_unread WHERE reader = ?1 AND kind = ?2 AND unit = ?3
           AND (?4 = '' OR part = ?4)",
    )?;
    for unit in read {
        // A readable part ends the whole-file failure without establishing full coverage.
        again.execute(params![reader, kind, unit.path])?;
        if !unit.part.is_empty() {
            tx.execute(
                "INSERT OR IGNORE INTO part_read (reader, kind, unit, part, run_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![reader, kind, unit.path, unit.part, run_id],
            )?;
        }
        part_again.execute(params![reader, kind, unit.path, unit.part])?;
    }
    Ok(())
}

/// Records an unread unit once while it stays unread.
pub fn judged_unread(
    tx: &Transaction,
    reader: &str,
    kind: &str,
    unit: &Unit,
    run_id: &str,
) -> rusqlite::Result<bool> {
    if unit.part.is_empty() {
        let added = tx.execute(
            "INSERT OR IGNORE INTO unit_unread (reader, kind, unit, run_id) VALUES (?1, ?2, ?3, ?4)",
            params![reader, kind, unit.path, run_id],
        )?;
        if added == 1 {
            return Ok(false);
        }
        tx.query_row(
            "SELECT run_id != ?4 FROM unit_unread WHERE reader = ?1 AND kind = ?2 AND unit = ?3",
            params![reader, kind, unit.path, run_id],
            |r| r.get(0),
        )
    } else {
        let added = tx.execute(
            "INSERT OR IGNORE INTO part_unread (reader, kind, unit, part, run_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![reader, kind, unit.path, unit.part, run_id],
        )?;
        if added == 1 {
            return Ok(false);
        }
        tx.query_row(
            "SELECT run_id != ?5 FROM part_unread
             WHERE reader = ?1 AND kind = ?2 AND unit = ?3 AND part = ?4",
            params![reader, kind, unit.path, unit.part, run_id],
            |r| r.get(0),
        )
    }
}

/// Forgets a whole content reading's unread mark.
pub fn read_again(tx: &Transaction, reader: &str, kind: &str, id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM unit_unread WHERE reader = ?1 AND kind = ?2 AND unit = ?3",
        params![reader, kind, id],
    )?;
    Ok(())
}

/// Whether the store has had a full check before `run_id`: a walk for checkouts, or a reading
/// of agents' sessions, which only a full check makes.
pub fn checked_before(tx: &Transaction, run_id: &str) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader IN (?1, ?2) AND run_id != ?3)",
        params![checkouts::READER, agent_folders::READER, run_id],
        |r| r.get(0),
    )
}

/// How something found is judged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Verdict {
    /// The store can show it was not there: a change, raised by its rule.
    Change,
    /// Nobody could have known what was there: the baseline, recorded and silent.
    Baseline,
    /// Neither: the baseline, recorded and told once.
    FirstRead,
}

impl Verdict {
    /// What the journal says of a difference judged so: nothing for a change.
    pub fn text(self) -> Option<&'static str> {
        match self {
            Verdict::Change => None,
            Verdict::Baseline => Some(store::FIRST_READING),
            Verdict::FirstRead => Some(store::READ_FIRST),
        }
    }
}

/// What the store can show about the unit that holds something found.
#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    /// An earlier run read the unit in full.
    pub read_before: bool,
    /// The unit is new to a listing an earlier run made in full.
    pub new_to_listing: bool,
    /// The unit is in a checkout new to a listing an earlier walk made in full, and was in
    /// reach since the checkout was first seen.
    pub in_new_checkout: bool,
    /// An earlier run read the unit or saw it present.
    pub met_before: bool,
    /// The store has had no full check before this run.
    pub first_check: bool,
}

/// The rule. A unit present and not shown to be new is never silent after the first check.
pub fn verdict(f: Facts) -> Verdict {
    if f.read_before || f.new_to_listing || f.in_new_checkout {
        Verdict::Change
    } else if f.first_check && !f.met_before {
        Verdict::Baseline
    } else {
        Verdict::FirstRead
    }
}

/// When a unit was first met.
struct Met {
    run: String,
    order: i64,
}

/// Whether something first met at `seen`, `None` when it is met for the first time in this
/// run, is new to a listing first made at `listing`: the listing was made by an earlier run,
/// and the thing was first met by this run or by a run later than the listing's.
fn newer(listing: Option<&Met>, seen: Option<&Met>, run_id: &str) -> bool {
    let Some(listing) = listing.filter(|l| l.run != run_id) else {
        return false;
    };
    match seen {
        None => true,
        Some(s) => s.run != listing.run && s.order > listing.order,
    }
}

/// How a checkout the store did not hold is journaled when a walk or an agent's sessions find
/// it: a change when it is new to a folder an earlier walk listed in full, the baseline in the
/// first check, and read for the first time otherwise. Finding a checkout raises nothing by
/// itself; what it holds is judged by `Judge`.
pub fn found_checkout(tx: &Transaction, run_id: &str, rel: &str) -> rusqlite::Result<Verdict> {
    let judge = Judge {
        tx,
        reader: checkouts::READER,
        kind: checkouts::KIND,
        run_id,
        first_check: false,
        checkouts: &[],
    };
    Ok(verdict(Facts {
        in_new_checkout: judge.arrived(rel)?,
        first_check: !checked_before(tx, run_id)?,
        ..Facts::default()
    }))
}

/// The verdict finding a checkout, `subject` as ids name it, was journaled with in this run,
/// if this run found it.
pub fn found_as(
    tx: &Transaction,
    run_id: &str,
    subject: &str,
) -> rusqlite::Result<Option<Verdict>> {
    let text: Option<Option<String>> = tx
        .query_row(
            "SELECT text FROM journal WHERE run_id = ?1 AND subject = ?2 AND entry = 'added'
               AND predicate = 'located_on' AND reader IN (?3, ?4)
             ORDER BY seq LIMIT 1",
            params![run_id, subject, checkouts::READER, agent_folders::READER],
            |r| r.get(0),
        )
        .optional()?;
    Ok(text.map(|t| match t.as_deref() {
        Some(store::FIRST_READING) => Verdict::Baseline,
        Some(store::READ_FIRST) => Verdict::FirstRead,
        _ => Verdict::Change,
    }))
}

/// Judges what one reading found.
pub struct Judge<'a> {
    pub tx: &'a Transaction<'a>,
    pub reader: &'a str,
    pub kind: &'a str,
    pub run_id: &'a str,
    pub first_check: bool,
    /// The checkouts the reading looked into, by their paths as ids name them.
    pub checkouts: &'a [String],
}

impl Judge<'_> {
    fn met(
        &self,
        reader: &str,
        kind: &str,
        unit: &str,
        how: &str,
    ) -> rusqlite::Result<Option<Met>> {
        self.tx
            .prepare(
                "SELECT run_id, rowid FROM unit_read
                 WHERE reader = ?1 AND kind = ?2 AND unit = ?3 AND how = ?4",
            )?
            .query_row(params![reader, kind, unit, how], |r| {
                Ok(Met {
                    run: r.get(0)?,
                    order: r.get(1)?,
                })
            })
            .optional()
    }

    fn part_read_before(&self, unit: &Unit) -> rusqlite::Result<bool> {
        self.tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM part_read
             WHERE reader = ?1 AND kind = ?2 AND unit = ?3 AND part = ?4 AND run_id != ?5)",
            params![self.reader, self.kind, unit.path, unit.part, self.run_id],
            |r| r.get(0),
        )
    }

    /// Met by a run before this one.
    fn before(&self, met: Option<Met>) -> Option<Met> {
        met.filter(|m| m.run != self.run_id)
    }

    /// Whether an earlier run read the unit in full.
    pub fn read_before(&self, unit: &str) -> rusqlite::Result<bool> {
        Ok(self
            .before(self.met(self.reader, self.kind, unit, "read")?)
            .is_some())
    }

    /// The deepest checkout the reading looked into that holds `unit`.
    pub fn checkout_of(&self, unit: &str) -> Option<&str> {
        self.checkouts
            .iter()
            .filter(|c| {
                unit.strip_prefix(c.as_str())
                    .is_some_and(|r| r.starts_with('/'))
            })
            .max_by_key(|c| c.len())
            .map(String::as_str)
    }

    /// Whether a checkout, `c` as ids name it, is new: the nearest folder above it that an
    /// earlier walk listed in full did not hold the folder on the way to it then. A clone made
    /// in a folder that is itself new is new; one in a folder no walk listed before, such as
    /// one a run is pointed at for the first time, is not shown to be.
    fn arrived(&self, c: &str) -> rusqlite::Result<bool> {
        let (r, k) = (checkouts::READER, checkouts::KIND);
        let mut here = c;
        loop {
            let up = parent(here);
            if up == here {
                return Ok(false);
            }
            if let Some(listed) = self.before(self.met(r, k, up, "read")?) {
                let found = self.met(r, k, here, "seen")?;
                return Ok(newer(Some(&listed), found.as_ref(), self.run_id));
            }
            here = up;
        }
    }

    /// What the store can show about the unit that holds what is at `path`.
    pub fn facts(&self, observed: &Unit) -> rusqlite::Result<Facts> {
        let unit = &observed.path;
        let read = self.before(self.met(self.reader, self.kind, unit, "read")?);
        let part_read =
            read.is_none() && !observed.part.is_empty() && self.part_read_before(observed)?;
        let seen = self.met(self.reader, self.kind, unit, "seen")?;
        let listing = self.before(self.met(self.reader, self.kind, parent(unit), "read")?);
        let seen_before = seen.as_ref().filter(|s| s.run != self.run_id);
        let first = [read.as_ref(), seen_before]
            .into_iter()
            .flatten()
            .min_by_key(|m| m.order);
        let in_new_checkout = match self.checkout_of(unit) {
            None => false,
            Some(c) => {
                let found = self.met(checkouts::READER, checkouts::KIND, c, "seen")?;
                self.arrived(c)?
                    && match (first, &found) {
                        // Met for the first time now, in a checkout first found now.
                        (None, found) => found.as_ref().is_none_or(|f| f.run == self.run_id),
                        // Met since the run that first found its checkout.
                        (Some(first), Some(found)) => first.run == found.run,
                        (Some(_), None) => false,
                    }
            }
        };
        Ok(Facts {
            read_before: read.is_some() || part_read,
            new_to_listing: newer(listing.as_ref(), seen.as_ref(), self.run_id),
            in_new_checkout,
            met_before: first.is_some(),
            first_check: self.first_check,
        })
    }

    pub fn verdict(&self, unit: &Unit) -> rusqlite::Result<Verdict> {
        Ok(verdict(self.facts(unit)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_the_first_check_a_unit_not_shown_to_be_new_is_read_for_the_first_time_and_never_silent()
     {
        // Every combination of what the store can show: the silent baseline only during the
        // first check and only for a unit nothing met before; a change whenever the store
        // shows the unit was not there.
        for bits in 0..32u8 {
            let f = Facts {
                read_before: bits & 1 != 0,
                new_to_listing: bits & 2 != 0,
                in_new_checkout: bits & 4 != 0,
                met_before: bits & 8 != 0,
                first_check: bits & 16 != 0,
            };
            let shown_new = f.read_before || f.new_to_listing || f.in_new_checkout;
            let expected = if shown_new {
                Verdict::Change
            } else if f.first_check && !f.met_before {
                Verdict::Baseline
            } else {
                Verdict::FirstRead
            };
            assert_eq!(verdict(f), expected, "{f:?}");
        }
    }

    #[test]
    fn something_is_new_to_a_listing_only_when_an_earlier_run_made_the_listing_before_it_was_met() {
        let met = |run: &str, order| Met {
            run: run.to_string(),
            order,
        };
        let listing = met("run-1", 10);
        // Never met, or met first now: new.
        assert!(newer(Some(&listing), None, "run-3"));
        assert!(newer(Some(&listing), Some(&met("run-3", 30)), "run-3"));
        // Met first by a later run than the listing's: new, whatever run judges it.
        assert!(newer(Some(&listing), Some(&met("run-2", 20)), "run-3"));
        // Met by the run that made the listing, or before it: not new.
        assert!(!newer(Some(&listing), Some(&met("run-1", 11)), "run-3"));
        assert!(!newer(Some(&listing), Some(&met("run-0", 5)), "run-3"));
        // A listing made now, or never, proves nothing.
        assert!(!newer(Some(&met("run-3", 31)), None, "run-3"));
        assert!(!newer(None, None, "run-3"));
    }

    #[test]
    fn a_part_hides_only_itself_while_a_file_failure_hides_every_part() {
        let file = Unit::whole("dev/demo#/package.json");
        let part = Unit::part(&file.path, "/scripts/install");
        let same_name = Unit::whole(part.to_string());
        let neighbor = Unit::part(&file.path, "/scripts/prepare");
        assert!(file.hides(&part));
        assert!(part.hides(&part));
        assert!(!part.hides(&same_name));
        assert!(!part.hides(&neighbor));
        assert!(!file.hides(&same_name));
        assert!(Unit::whole("dev/demo#").hides(&part));
        assert!(Unit::whole("/").hides(&Unit::whole("/etc/pam.d/login#2")));
    }

    #[test]
    fn a_legacy_part_is_resolved_by_its_source_and_selector_even_when_both_have_hashes() {
        let kind = autorun::POINTS
            .iter()
            .find(|p| p.paths == [".mcp.json"] && p.scope == autorun::Scope::Checkout)
            .unwrap()
            .kind();
        let checkout = "dev/demo#/child";
        let part = Unit::part(format!("{checkout}/.mcp.json"), "/mcpServers/a#/x");
        assert!(legacy_unit(&kind, &part.to_string(), |p| p == checkout).is_none());
        let part = Unit::part(format!("{checkout}/.mcp.json"), "/mcpServers/a#~1x");
        assert_eq!(
            legacy_unit(&kind, &part.to_string(), |p| p == checkout),
            Some(part)
        );
    }
}
