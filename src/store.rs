//! The store: vocabulary, entities, the three assertion layers, coverage and the journal.
//! The shape follows docs/facts.md.

use crate::resolver;
use rusqlite::{Connection, OpenFlags, Transaction, params};
use std::collections::BTreeSet;
use std::path::Path;

pub const FORMAT_VERSION: &str = "4";

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
-- What a reading looks for in its scope. A reading of an unknown kind cannot be written.
CREATE TABLE coverage_kind (
    name TEXT PRIMARY KEY
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
    kind         TEXT NOT NULL REFERENCES coverage_kind (name),
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
    kind         TEXT NOT NULL REFERENCES coverage_kind (name),
    completeness TEXT NOT NULL CHECK (completeness IN ('full', 'partial', 'none')),
    -- Why the reading was not full. On a full reading it is a note: why there was
    -- nothing to read, such as a tool that is not installed.
    reason       TEXT,
    CHECK (completeness = 'full' OR reason IS NOT NULL)
);

-- Containers and checkouts that were somewhere and are no longer anywhere. What was read
-- inside them was retracted with them, and their readings no longer count.
CREATE VIEW gone_entity AS
    SELECT DISTINCT r.subject AS id FROM assertion r
    WHERE r.layer = 'retracted' AND r.predicate = 'located_on'
      AND NOT EXISTS (SELECT 1 FROM assertion l
                      WHERE l.layer = 'live' AND l.predicate = 'located_on'
                        AND l.subject = r.subject);

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
-- The last saved copy of each raw input, so that unchanged input is not copied again.
CREATE TABLE raw_input (
    reader TEXT NOT NULL,
    input  TEXT NOT NULL,
    path   TEXT NOT NULL,  -- relative to the store's folder
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, input)
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
    ('runs_kernel', 'literal', 'used'), ('runs_image', 'literal', 'used'),
    ('known_as', 'literal', 'used'), ('same_as', 'entity', 'used'),
    ('copy_of', NULL, 'reserved'), ('reachable_from', NULL, 'reserved'),
    ('relation_to_owner', NULL, 'reserved');
INSERT INTO basis_kind (name, strength) VALUES
    ('observed', 1), ('declared', 2), ('mentioned', 3);
INSERT INTO coverage_kind (name) VALUES
    ('brew packages'), ('checkouts under the home folder'), ('lockfile dependencies'),
    ('system packages'), ('containers'), ('container version variables'),
    ('wordpress core version'), ('container contents'),
    ('ssh configuration'), ('known hosts'), ('tailnet peers'),
    ('machines under several names');
";

/// One reading: which reader looked for which kind of thing in which scope.
/// `at` is the time of the run; `observed_at` is when the source itself was read,
/// which for a server file is when the sweep wrote it.
pub struct Reading<'a> {
    pub reader: &'a str,
    pub scope: &'a str,
    pub kind: &'a str,
    pub run_id: &'a str,
    pub at: i64,
    pub observed_at: i64,
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

type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Opens the store, creating it in an empty file. A store of another format is refused
/// and left as it is: old stores are not converted.
pub fn open(path: &Path) -> Res<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
    if tables == 0 {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('format_version', ?1)",
            [FORMAT_VERSION],
        )?;
        tx.commit()?;
    }
    check_format(&conn, path)?;
    Ok(conn)
}

/// Opens an existing store so that nothing can be written to it. Creates nothing.
pub fn open_read_only(path: &Path) -> Res<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    check_format(&conn, path)?;
    Ok(conn)
}

fn check_format(conn: &Connection, path: &Path) -> Res<()> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')",
        [],
        |r| r.get(0),
    )?;
    let version: Option<String> = if has_meta {
        conn.query_row(
            "SELECT MAX(value) FROM meta WHERE key = 'format_version'",
            [],
            |r| r.get(0),
        )?
    } else {
        None
    };
    let Some(version) = version else {
        return Err(format!("{} is not a store of this tool", path.display()).into());
    };
    let (Ok(found), Ok(ours)) = (version.parse::<u32>(), FORMAT_VERSION.parse::<u32>()) else {
        return Err(format!("store format {version} is not supported").into());
    };
    if found < ours {
        return Err(format!(
            "the store at {} is from an older format ({found}); this version uses format {ours} \
             and does not convert old stores. Nothing was changed. Move the old store aside \
             or pass another --store.",
            path.display()
        )
        .into());
    }
    if found > ours {
        return Err(format!(
            "the store at {} is from a newer format ({found}) than this version knows ({ours})",
            path.display()
        )
        .into());
    }
    Ok(())
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

/// Writes one draft assertion, and the entities it names: the subject, and the object
/// when the vocabulary says the predicate points at an entity.
pub fn put_draft(
    tx: &Transaction,
    r: &Reading,
    basis: &str,
    s: &Statement,
) -> rusqlite::Result<()> {
    put_entity(tx, &s.subject)?;
    let points_at_entity: bool = tx.query_row(
        "SELECT object_kind = 'entity' FROM predicate WHERE name = ?1",
        [s.predicate],
        |row| row.get(0),
    )?;
    if points_at_entity {
        put_entity(tx, &s.object)?;
    }
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
            r.observed_at,
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
            r.observed_at,
            r.scope,
            r.kind,
            completeness,
            reason
        ],
    )?;
    Ok(())
}

/// Whether any run finished before this one.
pub fn any_run_finished(tx: &Transaction) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM journal WHERE entry = 'run_finished')",
        [],
        |row| row.get(0),
    )
}

/// What the report line says about the store after a run.
pub struct Totals {
    /// Machines, each counted once however many names it has.
    pub machines: i64,
    pub checkouts: i64,
    pub components: i64,
    pub partial: i64,
    pub none: i64,
    /// Machines this run tried to read and could read nothing on.
    pub machines_unread: i64,
    /// Readings made by earlier runs whose scope this run did not read at all:
    /// nothing is known about what changed in them. A scope that is gone is not counted.
    pub not_repeated: i64,
}

pub fn totals(tx: &Transaction, run_id: &str) -> rusqlite::Result<Totals> {
    let all = |sql: &str| tx.query_row(sql, [], |row| row.get::<_, i64>(0));
    let one = |sql: &str| tx.query_row(sql, [run_id], |row| row.get::<_, i64>(0));
    Ok(Totals {
        machines: machine_groups(tx)?.len() as i64,
        checkouts: all("SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND predicate = 'located_on' AND subject LIKE 'checkout:%'")?,
        components: all("SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND predicate = 'part_of'")?,
        // A partial reading that never made an assertion has nothing that could be removed.
        partial: one("SELECT COUNT(*) FROM coverage c
             WHERE run_id = ?1 AND completeness = 'partial'
               AND EXISTS (SELECT 1 FROM assertion a WHERE a.layer IN ('live', 'retracted')
                             AND a.reader = c.reader
                             AND a.scope = c.scope AND a.kind = c.kind)")?,
        none: one("SELECT COUNT(*) FROM coverage WHERE run_id = ?1 AND completeness = 'none'")?,
        machines_unread: one("SELECT COUNT(*) FROM (SELECT scope FROM coverage
             WHERE run_id = ?1 AND scope IN (SELECT id FROM entity WHERE type = 'machine')
             GROUP BY scope HAVING MAX(completeness != 'none') = 0)")?,
        not_repeated: one(
            "SELECT COUNT(*) FROM (SELECT DISTINCT reader, scope, kind FROM coverage
             WHERE scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
               AND scope NOT IN (SELECT id FROM gone_entity))",
        )?,
    })
}

/// The ids of machines the store knows now: something live names them, or a reading
/// covered them. An entity whose every trace was retracted is no longer known.
fn machines_known(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let column = |sql: &str| -> rusqlite::Result<BTreeSet<String>> {
        conn.prepare(sql)?.query_map([], |r| r.get(0))?.collect()
    };
    let entities = column("SELECT id FROM entity WHERE type = 'machine'")?;
    let mut named = column("SELECT DISTINCT scope FROM coverage")?;
    named.extend(column(
        "SELECT DISTINCT subject FROM assertion WHERE layer = 'live' AND subject LIKE 'machine:%'",
    )?);
    named.extend(column(
        "SELECT DISTINCT object FROM assertion WHERE layer = 'live' AND object LIKE 'machine:%'",
    )?);
    Ok(entities.intersection(&named).cloned().collect())
}

/// The machines the store knows, as groups of entities the resolver found to be one
/// machine. Each group and the list are sorted.
pub fn machine_groups(conn: &Connection) -> rusqlite::Result<Vec<Vec<String>>> {
    let links: Vec<(String, String)> = conn
        .prepare(
            "SELECT subject, object FROM assertion WHERE layer = 'live' AND predicate = 'same_as'",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(resolver::groups(machines_known(conn)?, &links))
}

/// Live `known_as` assertions, which the resolver works from.
pub fn live_known_as(conn: &Connection) -> rusqlite::Result<Vec<resolver::Known>> {
    conn.prepare(
        "SELECT subject, object, basis FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as' ORDER BY subject, object",
    )?
    .query_map([], |r| {
        Ok(resolver::Known {
            entity: r.get(0)?,
            value: r.get(1)?,
            basis: r.get(2)?,
        })
    })?
    .collect()
}

/// The subjects one reader makes live assertions about.
pub fn live_subjects(conn: &Connection, reader: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare("SELECT DISTINCT subject FROM assertion WHERE layer = 'live' AND reader = ?1")?
        .query_map([reader], |r| r.get(0))?
        .collect()
}

/// Scopes where the latest reading of some kind by this reader read something.
pub fn scopes_read(conn: &Connection, reader: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT scope FROM coverage
         WHERE reader = ?1 AND completeness != 'none'
           AND id IN (SELECT MAX(id) FROM coverage GROUP BY reader, scope, kind)",
    )?
    .query_map([reader], |r| r.get(0))?
    .collect()
}

/// The last saved raw copy of this input, relative to the store's folder.
pub fn last_raw(tx: &Transaction, reader: &str, input: &str) -> rusqlite::Result<Option<String>> {
    tx.query_row(
        "SELECT path FROM raw_input WHERE reader = ?1 AND input = ?2",
        params![reader, input],
        |row| row.get(0),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e),
    })
}

pub fn set_raw(
    tx: &Transaction,
    reader: &str,
    input: &str,
    path: &str,
    run_id: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO raw_input (reader, input, path, run_id) VALUES (?1, ?2, ?3, ?4)",
        params![reader, input, path, run_id],
    )?;
    Ok(())
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
