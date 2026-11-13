//! Draft becomes live at the end of a run, for one reading, by its coverage.
//! Full: new assertions become live and those no longer made are retracted.
//! Partial: new assertions become live and nothing is retracted.
//! None: nothing changes. A missing reading is not evidence of absence.
//!
//! A container or checkout that is no longer anywhere takes what was read inside it along:
//! when its last `located_on` is retracted, every live assertion of a reading scoped to it
//! is retracted in the same run, whatever that reading's completeness was, and with it what
//! was read inside anything located there. The entity's removal is the one event; what was
//! inside it adds none.
//!
//! A kind an earlier version read and this one does not is retired, which is neither a full
//! reading nor a removal: nothing was looked at, so nothing is known to be gone. Its facts are
//! closed with a journal entry of their own, `retired`, that says why, and its reading becomes
//! `none` with no reader. It is done once per scope.

use crate::store::{Cause, Event, Gap, Reading};
use rusqlite::{Transaction, params};
use std::collections::{BTreeMap, BTreeSet};

/// Objects per (subject, predicate), each with the id of one row that holds it.
type Layer = BTreeMap<(String, String), BTreeMap<String, i64>>;

fn load(tx: &Transaction, r: &Reading, layer: &str) -> rusqlite::Result<Layer> {
    // Draft holds only this run: promote empties it for the reading.
    let mut stmt = tx.prepare(
        "SELECT id, subject, predicate, object FROM assertion
         WHERE layer = ?1 AND reader = ?2 AND scope = ?3 AND kind = ?4",
    )?;
    let mut out = Layer::new();
    let rows = stmt.query_map(params![layer, r.reader, r.scope, r.kind], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    for row in rows {
        let (id, subject, predicate, object): (i64, String, String, String) = row?;
        out.entry((subject, predicate))
            .or_default()
            .entry(object)
            .or_insert(id);
    }
    Ok(out)
}

fn joined(objects: &BTreeMap<String, i64>) -> Option<String> {
    if objects.is_empty() {
        return None;
    }
    Some(objects.keys().cloned().collect::<Vec<_>>().join(", "))
}

/// Compares this run's draft with live and returns the differences as events.
/// A different set of objects for the same subject and predicate is one
/// `changed` event, so a new version of a component is not a remove plus an add.
/// Under partial coverage only growth is seen: `added` and `changed`, never `removed`.
pub fn promote(tx: &Transaction, r: &Reading, completeness: &str) -> rusqlite::Result<Vec<Event>> {
    let mut events = Vec::new();
    if completeness != "none" {
        events = compare(tx, r, completeness == "full")?;
    }
    // What is still draft was already live, repeated within the run, or not read.
    tx.execute(
        "DELETE FROM assertion
         WHERE layer = 'draft' AND reader = ?1 AND scope = ?2 AND kind = ?3",
        params![r.reader, r.scope, r.kind],
    )?;
    Ok(events)
}

fn compare(tx: &Transaction, r: &Reading, full: bool) -> rusqlite::Result<Vec<Event>> {
    let draft = load(tx, r, "draft")?;
    let live = load(tx, r, "live")?;
    let empty = BTreeMap::new();
    let keys: BTreeSet<_> = draft.keys().chain(live.keys()).cloned().collect();
    let mut events = Vec::new();

    for key in keys {
        let old = live.get(&key).unwrap_or(&empty);
        let mut new = draft.get(&key).unwrap_or(&empty).clone();
        if !full {
            // What partial reading did not see stays as it was.
            for (object, id) in old {
                new.entry(object.clone()).or_insert(*id);
            }
        }
        let new = &new;
        if new.keys().eq(old.keys()) {
            continue;
        }
        for (object, id) in new {
            if !old.contains_key(object) {
                tx.execute("UPDATE assertion SET layer = 'live' WHERE id = ?1", [id])?;
            }
        }
        for (object, id) in old {
            if !new.contains_key(object) {
                tx.execute(
                    "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
                     WHERE id = ?3",
                    params![r.at, r.run_id, id],
                )?;
            }
        }
        let kind = match (old.is_empty(), new.is_empty()) {
            (true, _) => "added",
            (_, true) => "removed",
            _ => "changed",
        };
        if kind == "removed" && key.1 == "located_on" {
            retract_inside(tx, r, &key.0)?;
        }
        events.push(Event {
            kind,
            subject: key.0,
            predicate: key.1,
            old: joined(old),
            new: joined(new),
        });
    }
    Ok(events)
}

/// How the reason of the reading of a retired kind begins; why follows.
pub const NO_LONGER_READ: &str = "no longer read by this version: ";

/// Retires one kind of one reader (see the top of this file) in every scope that holds live
/// facts of it, or whose latest reading of it does not say it is retired yet. `r` gives the
/// reader, the kind, the run and its time; its scope is ignored. Returns the facts closed and
/// the scopes retired, both 0 once it was done.
pub fn retire(tx: &Transaction, r: &Reading, why: &str) -> rusqlite::Result<(usize, usize)> {
    let reason = format!("{NO_LONGER_READ}{why}");
    let scopes: Vec<String> = tx
        .prepare(
            "SELECT scope FROM assertion WHERE layer = 'live' AND reader = ?1 AND kind = ?2
             UNION
             SELECT c.scope FROM coverage c
             WHERE c.reader = ?1 AND c.kind = ?2
               AND c.id = (SELECT MAX(id) FROM coverage
                           WHERE reader = c.reader AND scope = c.scope AND kind = c.kind)
               AND NOT (c.completeness = 'none' AND c.reason IS ?3)
             ORDER BY 1",
        )?
        .query_map(params![r.reader, r.kind, reason], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut closed = 0;
    for scope in &scopes {
        let here = Reading { scope, ..*r };
        for ((subject, predicate), objects) in load(tx, &here, "live")? {
            for id in objects.values() {
                tx.execute(
                    "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
                     WHERE id = ?3",
                    params![r.at, r.run_id, id],
                )?;
            }
            closed += objects.len();
            tx.execute(
                "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                                      old_value, text)
                 VALUES (?1, ?2, 'retired', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    r.at,
                    r.run_id,
                    r.reader,
                    scope,
                    r.kind,
                    subject,
                    predicate,
                    joined(&objects),
                    reason
                ],
            )?;
        }
        crate::store::put_coverage(tx, &here, "none", Some(&reason), &Gap::of(Cause::NoReader))?;
    }
    Ok((closed, scopes.len()))
}

/// Retracts everything read inside an entity once nothing says where it is any more, and
/// so on down: a file located in a checkout that is gone takes its own readings along.
fn retract_inside(tx: &Transaction, r: &Reading, entity: &str) -> rusqlite::Result<()> {
    let still_somewhere: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM assertion
                        WHERE layer = 'live' AND predicate = 'located_on' AND subject = ?1)",
        [entity],
        |row| row.get(0),
    )?;
    if still_somewhere {
        return Ok(());
    }
    let inside: Vec<String> = tx
        .prepare(
            "SELECT DISTINCT subject FROM assertion
             WHERE layer = 'live' AND scope = ?1 AND predicate = 'located_on'",
        )?
        .query_map([entity], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    tx.execute(
        "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
         WHERE layer = 'live' AND scope = ?3",
        params![r.at, r.run_id, entity],
    )?;
    for thing in inside {
        retract_inside(tx, r, &thing)?;
    }
    Ok(())
}
