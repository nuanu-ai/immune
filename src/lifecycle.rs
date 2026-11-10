//! Draft becomes live at the end of a run, for one reading that was read in full.
//! Callers must not call this for partial or missing coverage: a missing reading
//! is not evidence of absence, so nothing may be retracted on it.

use crate::store::{Event, Reading};
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
pub fn promote(tx: &Transaction, r: &Reading) -> rusqlite::Result<Vec<Event>> {
    let draft = load(tx, r, "draft")?;
    let live = load(tx, r, "live")?;
    let empty = BTreeMap::new();
    let keys: BTreeSet<_> = draft.keys().chain(live.keys()).cloned().collect();
    let mut events = Vec::new();

    for key in keys {
        let new = draft.get(&key).unwrap_or(&empty);
        let old = live.get(&key).unwrap_or(&empty);
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
        events.push(Event {
            kind,
            subject: key.0,
            predicate: key.1,
            old: joined(old),
            new: joined(new),
        });
    }

    // What is still draft was already live, or repeated within the run.
    tx.execute(
        "DELETE FROM assertion
         WHERE layer = 'draft' AND reader = ?1 AND scope = ?2 AND kind = ?3",
        params![r.reader, r.scope, r.kind],
    )?;
    Ok(events)
}
