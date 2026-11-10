//! The store: vocabulary, entities, the three assertion layers, coverage and the journal.
//! The shape follows docs/facts.md.

use rusqlite::{Connection, Transaction, params};
use std::path::Path;

pub const FORMAT_VERSION: &str = "1";

const SCHEMA: &str = "
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Vocabulary is data: a new type or predicate is a new row, not a new table.
CREATE TABLE entity_type (
    name   TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('used', 'reserved'))
);
CREATE TABLE predicate (
    name        TEXT PRIMARY KEY,
    object_kind TEXT CHECK (object_kind IN ('entity', 'literal')),
    status      TEXT NOT NULL CHECK (status IN ('used', 'reserved'))
);
CREATE TABLE basis_kind (
    name     TEXT PRIMARY KEY,
    strength INTEGER NOT NULL UNIQUE  -- 1 is strongest
);

CREATE TABLE entity (
    id   TEXT PRIMARY KEY,
    type TEXT NOT NULL REFERENCES entity_type (name)
);

-- One row is one assertion in one layer. scope and kind tie it to the coverage
-- record of the reading that made it; the lifecycle compares within them.
CREATE TABLE assertion (
    id           INTEGER PRIMARY KEY,
    layer        TEXT NOT NULL CHECK (layer IN ('draft', 'live', 'retracted')),
    subject      TEXT NOT NULL REFERENCES entity (id),
    predicate    TEXT NOT NULL REFERENCES predicate (name),
    object       TEXT NOT NULL,
    reader       TEXT NOT NULL,
    scope        TEXT NOT NULL REFERENCES entity (id),
    kind         TEXT NOT NULL,
    source_ref   TEXT NOT NULL,
    basis        TEXT NOT NULL REFERENCES basis_kind (name),
    observed_at  INTEGER NOT NULL,  -- UTC seconds
    run_id       TEXT NOT NULL,
    retracted_at INTEGER,           -- UTC seconds
    retracted_by TEXT,              -- run id
    CHECK ((layer = 'retracted') = (retracted_at IS NOT NULL))
);
CREATE INDEX assertion_reading ON assertion (layer, reader, scope, kind);

CREATE TABLE coverage (
    id           INTEGER PRIMARY KEY,
    reader       TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    observed_at  INTEGER NOT NULL,
    scope        TEXT NOT NULL REFERENCES entity (id),
    kind         TEXT NOT NULL,
    completeness TEXT NOT NULL CHECK (completeness IN ('full', 'partial', 'none')),
    reason       TEXT,
    CHECK (completeness = 'full' OR reason IS NOT NULL)
);

-- The journal cannot be rebuilt from raw input, so it only grows.
CREATE TABLE journal (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    run_id    TEXT NOT NULL,
    entry     TEXT NOT NULL
              CHECK (entry IN ('run_started', 'added', 'changed', 'removed', 'report', 'run_finished')),
    reader    TEXT,
    scope     TEXT,
    kind      TEXT,
    subject   TEXT,
    predicate TEXT,
    old_value TEXT,
    new_value TEXT,
    text      TEXT
);
CREATE TRIGGER journal_no_update BEFORE UPDATE ON journal
    BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER journal_no_delete BEFORE DELETE ON journal
    BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;

INSERT INTO entity_type (name, status) VALUES
    ('machine', 'used'), ('container', 'used'), ('checkout', 'used'), ('component', 'used'),
    ('repository', 'reserved'), ('service', 'reserved'), ('account', 'reserved'),
    ('domain', 'reserved'), ('key', 'reserved'), ('party', 'reserved');
INSERT INTO predicate (name, object_kind, status) VALUES
    ('located_on', 'entity', 'used'), ('part_of', 'entity', 'used'),
    ('has_version', 'literal', 'used'), ('runs_os', 'literal', 'used'),
    ('copy_of', NULL, 'reserved'), ('reachable_from', NULL, 'reserved'),
    ('relation_to_owner', NULL, 'reserved'), ('same_as', NULL, 'reserved');
INSERT INTO basis_kind (name, strength) VALUES
    ('observed', 1), ('declared', 2), ('mentioned', 3);
";

/// One reading: which reader looked for which kind of thing in which scope.
pub struct Reading<'a> {
    pub reader: &'a str,
    pub scope: &'a str,
    pub kind: &'a str,
    pub run_id: &'a str,
    pub at: i64,
}

/// A statement as a reader makes it, before it becomes a draft assertion.
pub struct Statement {
    pub subject: String,
    pub predicate: &'static str,
    pub object: String,
    pub source_ref: String,
}

/// A difference between draft and live for one subject and predicate.
pub struct Event {
    pub kind: &'static str,
    pub subject: String,
    pub predicate: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    let created: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')",
        [],
        |r| r.get(0),
    )?;
    if !created {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('format_version', ?1)",
            [FORMAT_VERSION],
        )?;
        tx.commit()?;
    }
    Ok(conn)
}

/// The entity type is the part of the id before the first colon.
pub fn put_entity(tx: &Transaction, id: &str) -> rusqlite::Result<()> {
    let entity_type = id.split(':').next().unwrap_or(id);
    tx.execute(
        "INSERT OR IGNORE INTO entity (id, type) VALUES (?1, ?2)",
        params![id, entity_type],
    )?;
    Ok(())
}

pub fn put_draft(
    tx: &Transaction,
    r: &Reading,
    basis: &str,
    s: &Statement,
) -> rusqlite::Result<()> {
    put_entity(tx, &s.subject)?;
    tx.execute(
        "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                source_ref, basis, observed_at, run_id)
         VALUES ('draft', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            s.subject,
            s.predicate,
            s.object,
            r.reader,
            r.scope,
            r.kind,
            s.source_ref,
            basis,
            r.at,
            r.run_id
        ],
    )?;
    Ok(())
}

pub fn put_coverage(
    tx: &Transaction,
    r: &Reading,
    completeness: &str,
    reason: Option<&str>,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness, reason)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            r.reader,
            r.run_id,
            r.at,
            r.scope,
            r.kind,
            completeness,
            reason
        ],
    )?;
    Ok(())
}

/// Whether this scope and kind were read before. Call before writing this run's coverage.
pub fn read_before(tx: &Transaction, r: &Reading) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3)",
        params![r.reader, r.scope, r.kind],
        |row| row.get(0),
    )
}

pub fn live_components(tx: &Transaction, r: &Reading) -> rusqlite::Result<i64> {
    tx.query_row(
        "SELECT COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3
           AND predicate = 'part_of'",
        params![r.reader, r.scope, r.kind],
        |row| row.get(0),
    )
}

pub fn journal_note(
    conn: &Connection,
    at: i64,
    run_id: &str,
    entry: &str,
    text: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO journal (at, run_id, entry, text) VALUES (?1, ?2, ?3, ?4)",
        params![at, run_id, entry, text],
    )?;
    Ok(())
}

pub fn journal_event(tx: &Transaction, r: &Reading, e: &Event) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              old_value, new_value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            r.at,
            r.run_id,
            e.kind,
            r.reader,
            r.scope,
            r.kind,
            e.subject,
            e.predicate,
            e.old,
            e.new
        ],
    )?;
    Ok(())
}
