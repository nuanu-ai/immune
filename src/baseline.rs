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
//!   later by a run pointed at its folder, a folder that could not be read before, or a place
//!   a later version reads that an earlier one did not.
//!
//! A unit is the smallest thing one failure can hit: one file, read or found absent, or one
//! folder's listing. A listing that worked and could not follow one entry is still a listing:
//! that entry is its own unit, and its neighbours are judged as they are. Each unit is recorded
//! once per reader and kind, by the first run that read it in full (`read`) and the first that
//! met it present (`seen`). The record keeps the order in which units were first met, so that
//! a listing made in one run and an entry first seen in a later one tell that the entry is new.
//!
//! File integrity monitors build their baseline from their first scan of the paths given to
//! them. Immunity Core's readings cover different places at different times, the watcher's and a full
//! check's, so its baseline is kept per unit.

use crate::{agent_folders, autorun, checkouts, store};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::{BTreeSet, HashMap};

/// The baseline's tables, part of the store's schema (`store::schema`).
pub const SCHEMA: &str = "
-- Every unit a reader met, by the first run that read it in full and the first that saw it
-- present. Rows are only added; their order is the order units were first met.
CREATE TABLE unit_read (
    reader TEXT NOT NULL,
    kind   TEXT NOT NULL,
    unit   TEXT NOT NULL,     -- a path as ids name it: a file, or a folder that was listed
    how    TEXT NOT NULL CHECK (how IN ('read', 'seen')),
    run_id TEXT NOT NULL,     -- the first run that did
    at     INTEGER NOT NULL,  -- UTC seconds
    PRIMARY KEY (reader, kind, unit, how)
);
-- Every unit that was there and could not be read when a reading judged it. It is judged once
-- while it stays so; the row goes when the unit is read again.
CREATE TABLE unit_unread (
    reader TEXT NOT NULL,
    kind   TEXT NOT NULL,
    unit   TEXT NOT NULL,
    run_id TEXT NOT NULL,     -- the run that judged it
    PRIMARY KEY (reader, kind, unit)
);
-- A selected part of a file read, or that could not be read, apart from whole units.
CREATE TABLE part_read (
    reader TEXT NOT NULL,
    kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    part TEXT NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, kind, unit, part)
);
CREATE TABLE part_unread (
    reader TEXT NOT NULL,
    kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    part TEXT NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, kind, unit, part)
);
-- The physical unit of a watched assertion, scoped to the reading that made it.
CREATE TABLE watched_unit (
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

/// Every checkout a walk or an agent's sessions ever found, as `<machine>/<path>`.
pub fn past_checkouts(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT substr(subject, 10) FROM assertion
         WHERE predicate = 'located_on' AND layer != 'draft'
           AND reader IN (?1, ?2) AND subject LIKE 'checkout:%'",
    )?
    .query_map([checkouts::READER, agent_folders::READER], |r| r.get(0))?
    .collect()
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

/// Every unit a row of this build of `kind` could name `name`, its public name: none when no
/// row reads such a thing any more.
pub fn candidates(kind: &str, name: &str, checkout: impl Fn(&str) -> bool) -> BTreeSet<Unit> {
    let mut candidates = BTreeSet::new();
    for (p, path) in autorun::places()
        .filter(|(_, k)| k.1 == kind)
        .flat_map(|(p, _)| p.paths.iter().map(move |path| (p, *path)))
    {
        let file = match p.scope {
            autorun::Scope::Home => path.to_string(),
            autorun::Scope::System => format!("/{path}"),
            _ => {
                if parent(name)
                    .strip_suffix(&format!("/{path}"))
                    .is_some_and(&checkout)
                {
                    candidates.insert(Unit::whole(name));
                }
                continue;
            }
        };
        match p.part {
            autorun::Part::Keys(keys) => {
                for key in keys {
                    let unit = Unit::part(&file, format!("/{key}"));
                    if name == unit.to_string() {
                        candidates.insert(unit);
                    }
                }
            }
            autorun::Part::Entries if parent(name) == file => {
                candidates.insert(Unit::whole(name));
            }
            autorun::Part::File if name == file => {
                candidates.insert(Unit::whole(name));
            }
            _ => {}
        }
    }
    autorun::pattern_units(kind, name, &checkout, &mut candidates);
    candidates
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

    pub fn part_read_before(&self, unit: &Unit) -> rusqlite::Result<bool> {
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
    fn a_part_whose_checkout_and_selector_both_hold_a_hash_is_claimed_only_by_the_row_that_reads_it()
     {
        let kind = autorun::POINTS
            .iter()
            .find(|p| p.paths == [".mcp.json"] && p.scope == autorun::Scope::Checkout)
            .unwrap()
            .kind();
        let checkout = "dev/demo#/child";
        let part = Unit::part(format!("{checkout}/.mcp.json"), "/mcpServers/a#/x");
        assert!(candidates(&kind, &part.to_string(), |p| p == checkout).is_empty());
        let part = Unit::part(format!("{checkout}/.mcp.json"), "/mcpServers/a#~1x");
        assert_eq!(
            candidates(&kind, &part.to_string(), |p| p == checkout),
            BTreeSet::from([part])
        );
    }
}
