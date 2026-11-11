//! The store: vocabulary, entities, the three assertion layers, coverage and the journal.
//! The shape follows docs/facts.md.

use crate::resolver;
use rusqlite::{Connection, OpenFlags, Transaction, params};
use std::collections::BTreeSet;
use std::fs::{File, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

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

-- The last saved copy of each raw input, so that unchanged input is not copied again.
CREATE TABLE raw_input (
    reader TEXT NOT NULL,
    input  TEXT NOT NULL,
    path   TEXT NOT NULL,  -- relative to the store's folder
    run_id TEXT NOT NULL,
    PRIMARY KEY (reader, input)
);
";

/// What the journal records. The list only grows: a store whose journal was made with a
/// shorter list is made again with this one when it is opened, so a new kind of entry is a
/// new word here and nothing else.
const JOURNAL_ENTRIES: [&str; 11] = [
    "run_started",
    "added",
    "changed",
    "removed",
    "report",
    "run_finished",
    "owner_said",
    "owner_withdrew",
    "threat_added",
    "threat_gone",
    "threats_first_read",
];

/// The journal. It cannot be rebuilt from raw input, so it only grows. Its entries are the
/// differences a run finds, the run's own notes, the owner's word and the threat list's
/// changes.
fn journal_sql() -> String {
    let entries: Vec<String> = JOURNAL_ENTRIES.iter().map(|e| format!("'{e}'")).collect();
    format!(
        "
CREATE TABLE journal (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    run_id    TEXT NOT NULL,
    entry     TEXT NOT NULL CHECK (entry IN ({})),
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
",
        entries.join(", ")
    )
}

/// The owner's word: what the owner said about an entity, next to the facts and never an
/// edit of them. A withdrawn statement is kept with the time it was withdrawn. Created on
/// every open, so a store of the current format takes it without a rebuild.
const OWNER: &str = "
CREATE TABLE IF NOT EXISTS owner_statement (
    id           INTEGER PRIMARY KEY,
    entity       TEXT NOT NULL REFERENCES entity (id),
    said         TEXT NOT NULL CHECK (said IN ('retired', 'not mine')),
    reason       TEXT NOT NULL,
    made_at      INTEGER NOT NULL,  -- UTC seconds
    withdrawn_at INTEGER            -- UTC seconds
);
";

/// The threat list and its readings, see docs/threats.md. Threats are not facts: they live
/// in their own tables and never touch assertions. Created on every open, like the owner's
/// word. Text in `threat` is the catalogue's own and is partly written by an attacker.
const THREATS: &str = "
CREATE TABLE IF NOT EXISTS threat (
    source        TEXT NOT NULL,     -- which list, such as 'cisa-kev'
    id            TEXT NOT NULL,     -- the CVE id
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    name          TEXT NOT NULL,
    date_added    TEXT NOT NULL,     -- as the list gives it
    first_run     TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,  -- UTC seconds
    gone_at       INTEGER,           -- when it left the list, UTC seconds
    gone_run      TEXT,
    PRIMARY KEY (source, id),
    CHECK ((gone_at IS NULL) = (gone_run IS NULL))
);
CREATE TABLE IF NOT EXISTS feed_reading (
    id       INTEGER PRIMARY KEY,
    source   TEXT NOT NULL,
    run_id   TEXT NOT NULL,
    at       INTEGER NOT NULL,       -- UTC seconds
    outcome  TEXT NOT NULL CHECK (outcome IN ('read', 'unchanged', 'failed')),
    reason   TEXT,
    etag     TEXT,                   -- what the source sent, for the next conditional request
    sha256   TEXT,                   -- of the raw copy
    raw_path TEXT,                   -- relative to the store's folder
    entries  INTEGER,                -- how many entries the list held
    CHECK ((outcome = 'failed') = (reason IS NOT NULL))
);
";

/// The vocabulary seed. It is data, not format: it is applied on every open, so a store of
/// the current format learns a new row without being rebuilt, and a row is never removed.
const VOCABULARY: &str = "
INSERT OR IGNORE INTO entity_type (name, status) VALUES
    ('machine', 'used'), ('container', 'used'), ('checkout', 'used'), ('component', 'used'),
    ('repository', 'reserved'), ('service', 'reserved'), ('account', 'reserved'),
    ('domain', 'reserved'), ('key', 'reserved'), ('party', 'reserved'), ('file', 'used');
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('located_on', 'entity', 'used'), ('part_of', 'entity', 'used'),
    ('has_version', 'literal', 'used'), ('runs_os', 'literal', 'used'),
    ('runs_kernel', 'literal', 'used'), ('runs_image', 'literal', 'used'),
    ('known_as', 'literal', 'used'), ('same_as', 'entity', 'used'),
    ('relation_to_owner', 'literal', 'used'), ('built_from', 'literal', 'used'),
    ('runs_release', 'literal', 'used'), ('release_codename', 'literal', 'used'),
    ('runs_kernel_package', 'literal', 'used'), ('watched_as', 'literal', 'used'),
    ('has_content', 'literal', 'used'), ('links_to', 'literal', 'used'),
    ('copy_of', NULL, 'reserved'), ('reachable_from', NULL, 'reserved');
-- A reserved row comes into use: a store seeded before keeps the row and learns its use.
UPDATE predicate SET object_kind = 'literal', status = 'used'
    WHERE name = 'relation_to_owner' AND status = 'reserved';
INSERT OR IGNORE INTO basis_kind (name, strength) VALUES
    ('observed', 1), ('declared', 2), ('mentioned', 3);
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('brew packages'), ('checkouts under the home folder'), ('lockfile dependencies'),
    ('system packages'), ('containers'), ('container version variables'),
    ('wordpress core version'), ('container contents'),
    ('ssh configuration'), ('known hosts'), ('tailnet peers'),
    ('machines under several names'), ('checkouts in agent working folders'),
    ('own names and addresses'), ('sweep visit'), ('system package sources'),
    ('system release'), ('running kernel package'), ('launch agents and daemons'),
    ('shell profiles of zsh and bash'), ('ssh access files'),
    ('hooks in the checkout''s .git folder'), ('content of a watched file');
";

/// Why a reading is incomplete. The order is from worst: a reading incomplete for several
/// reasons takes the worst of them, so that it never looks better than it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cause {
    /// The reader tried and could not: no access, an error, a visit that failed or did not
    /// complete, a file that could not be opened.
    Failed,
    /// The thing is there and this build has no reader for it.
    NoReader,
    /// The source was read and does not hold this.
    NotGiven,
}

impl Cause {
    /// The literal kept in `coverage.cause`.
    pub fn literal(self) -> &'static str {
        match self {
            Cause::Failed => "failed",
            Cause::NoReader => "no_reader",
            Cause::NotGiven => "not_given",
        }
    }

    /// The worst of several causes, or `None` when there is none.
    pub fn worst(causes: impl IntoIterator<Item = Cause>) -> Option<Cause> {
        causes.into_iter().min()
    }
}

/// Something this build has no reader for, found in a reading: what it is in the program's
/// words, and its name where the source gives one, such as a lockfile's or a package
/// manager's. It is recorded whatever the reading's worst cause is.
#[derive(Clone, Debug, PartialEq)]
pub struct Lack {
    pub what: &'static str,
    pub name: Option<String>,
}

impl Lack {
    pub fn new(what: &'static str, name: Option<&str>) -> Lack {
        Lack {
            what,
            name: name.map(str::to_string),
        }
    }
}

/// Why a reading is incomplete, and what this build has no reader for in it. Empty on a
/// full reading.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Gap {
    pub cause: Option<Cause>,
    pub lacks: Vec<Lack>,
}

impl Gap {
    pub fn of(cause: Cause) -> Gap {
        Gap {
            cause: Some(cause),
            lacks: Vec::new(),
        }
    }

    /// The gap of a reading with this cause, if it is incomplete at all.
    pub fn when(cause: Option<Cause>) -> Gap {
        Gap {
            cause,
            lacks: Vec::new(),
        }
    }
}

/// Why a reading is incomplete, as data: a cause from a closed set, and what this build has
/// no reader for. Added on open, so a store of the current format takes it without a rebuild;
/// readings written before have no cause, which is read as `failed`.
fn add_causes(conn: &Connection) -> Res<()> {
    let has_cause: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('coverage') WHERE name = 'cause')",
        [],
        |r| r.get(0),
    )?;
    if !has_cause {
        conn.execute_batch(
            "ALTER TABLE coverage ADD COLUMN cause TEXT
                 CHECK (cause IN ('failed', 'no_reader', 'not_given'));",
        )?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS coverage_lack (
             coverage INTEGER NOT NULL REFERENCES coverage (id),
             what     TEXT NOT NULL,
             name     TEXT  -- as the source gives it, where it names one
         );",
    )?;
    Ok(())
}

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
///
/// A run writes in one transaction that lasts the whole run. Readers such as `soc status`
/// must be able to read the last committed state all that time, so the run never takes the
/// exclusive lock before it commits: a cache that grew past its size would otherwise be
/// spilled to the file, which takes the exclusive lock in the middle of the transaction and
/// shuts every reader out until the commit. The rollback journal is kept, rather than
/// write-ahead logging, because a reader in a folder it cannot write must open the store
/// without creating files next to it. Waiting on a lock is rusqlite's busy timeout of five
/// seconds on every connection: a reader waits out the commit, and the commit waits out a
/// reader.
pub fn open(path: &Path) -> Res<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "cache_spill", false)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
    if tables == 0 {
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(&journal_sql())?;
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('format_version', ?1)",
            [FORMAT_VERSION],
        )?;
        tx.commit()?;
    }
    check_format(&conn, path)?;
    conn.execute_batch(VOCABULARY)?;
    conn.execute_batch(OWNER)?;
    conn.execute_batch(THREATS)?;
    add_causes(&conn)?;
    widen_journal(&mut conn)?;
    Ok(conn)
}

/// A journal made with a shorter list of entries refuses the new ones. It is made again with
/// the whole list, row for row and with the same sequence, in one transaction: the store
/// keeps its history and its format.
fn widen_journal(conn: &mut Connection) -> Res<()> {
    let sql: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'journal'",
        [],
        |r| r.get(0),
    )?;
    if JOURNAL_ENTRIES
        .iter()
        .all(|e| sql.contains(&format!("'{e}'")))
    {
        return Ok(());
    }
    let tx = conn.transaction()?;
    tx.execute_batch(
        "ALTER TABLE journal RENAME TO journal_before_widening;
         DROP TRIGGER journal_no_update;
         DROP TRIGGER journal_no_delete;",
    )?;
    tx.execute_batch(&journal_sql())?;
    tx.execute_batch(
        "INSERT INTO journal SELECT * FROM journal_before_widening;
         DROP TABLE journal_before_widening;",
    )?;
    tx.commit()?;
    Ok(())
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

/// How long a run waits for the run lock before it says another run is in progress. A
/// `soc status` holds the lock shared for a moment only; another run holds it for minutes.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// Takes the run lock on the store's folder, for as long as the handle returned stays open,
/// or `None` when another run holds it. The lock is flock(2) on the folder: on macOS flock
/// and the record locks SQLite takes on the database file are one mechanism, so the file
/// itself cannot carry it, and a folder needs no file of its own. It is the kernel's lock:
/// it goes when the process ends, however it ends, so a run that died never looks like one
/// in progress. Two stores in one folder share it.
pub fn lock_run(folder: &Path) -> std::io::Result<Option<File>> {
    let handle = File::open(folder)?;
    let start = Instant::now();
    loop {
        match handle.try_lock() {
            Ok(()) => return Ok(Some(handle)),
            Err(TryLockError::WouldBlock) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// Whether a run holds the run lock on the store's folder now. It opens the folder only to
/// read and holds the lock shared for a moment, which a run starting meanwhile waits out.
pub fn run_in_progress(folder: &Path) -> std::io::Result<bool> {
    let handle = match File::open(folder) {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match handle.try_lock_shared() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(e)) => Err(e),
    }
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

/// Writes one reading's coverage, with why it is incomplete and what this build has no
/// reader for in it. A full reading has no cause. An incomplete one without a cause is a
/// mistake in a reader: it is written as `failed`, because unknown is never calm.
pub fn put_coverage(
    tx: &Transaction,
    r: &Reading,
    completeness: &str,
    reason: Option<&str>,
    gap: &Gap,
) -> rusqlite::Result<()> {
    debug_assert_eq!(
        completeness == "full",
        gap.cause.is_none(),
        "{} {} {completeness}",
        r.reader,
        r.kind
    );
    // An incomplete reading without a cause is read back as failed, like one written
    // before causes were kept.
    let cause = gap.cause.map(Cause::literal);
    tx.execute(
        "INSERT INTO coverage (reader, run_id, observed_at, scope, kind, completeness, reason,
                               cause)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            r.reader,
            r.run_id,
            r.observed_at,
            r.scope,
            r.kind,
            completeness,
            reason,
            cause
        ],
    )?;
    let id = tx.last_insert_rowid();
    for lack in &gap.lacks {
        tx.execute(
            "INSERT INTO coverage_lack (coverage, what, name) VALUES (?1, ?2, ?3)",
            params![id, lack.what, lack.name],
        )?;
    }
    Ok(())
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

pub fn totals(tx: &Connection, run_id: &str) -> rusqlite::Result<Totals> {
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

/// Machine entities known only as another user's device: the reader that says so is the
/// only one that names them, besides the resolver, and nothing was ever read on them.
pub fn other_users_devices(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT a.subject FROM assertion a
         WHERE a.layer = 'live' AND a.predicate = 'relation_to_owner' AND a.object = ?1
           AND NOT EXISTS (SELECT 1 FROM assertion o
                           WHERE o.layer = 'live' AND o.subject = a.subject
                             AND o.reader NOT IN (a.reader, ?2))
           AND NOT EXISTS (SELECT 1 FROM coverage c WHERE c.scope = a.subject)",
    )?
    .query_map(params![crate::tailnet::OTHER_USER, resolver::READER], |r| {
        r.get(0)
    })?
    .collect()
}

/// Whether a machine, as a group of entities, is another user's device and nothing more.
pub fn only_someone_elses(group: &[String], devices: &BTreeSet<String>) -> bool {
    group.iter().all(|m| devices.contains(m))
}

/// Live `known_as` assertions, which the resolver works from.
pub fn live_known_as(conn: &Connection) -> rusqlite::Result<Vec<resolver::Known>> {
    conn.prepare(
        "SELECT subject, object, basis, reader FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as' ORDER BY subject, object",
    )?
    .query_map([], |r| {
        Ok(resolver::Known {
            entity: r.get(0)?,
            value: r.get(1)?,
            basis: r.get(2)?,
            reader: r.get(3)?,
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

/// Whether an earlier reading of this kind by this reader read something in this scope.
/// A reading that is not preceded by one is the baseline: what it finds is not new.
pub fn read_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
                          AND completeness != 'none')",
        params![reader, scope, kind],
        |r| r.get(0),
    )
}

/// Whether every earlier reading of this kind by this reader in this scope read nothing,
/// and there was at least one.
pub fn only_failed_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 AND MAX(completeness != 'none') = 0 FROM coverage
         WHERE reader = ?1 AND scope = ?2 AND kind = ?3",
        params![reader, scope, kind],
        |r| r.get(0),
    )
}

/// Whether this reader ever made a reading.
pub fn read_any(conn: &Connection, reader: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1)",
        [reader],
        |r| r.get(0),
    )
}

/// When one reader last read a scope in full.
pub fn last_read(conn: &Connection, reader: &str, scope: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(observed_at) FROM coverage
         WHERE reader = ?1 AND scope = ?2 AND completeness = 'full'",
        params![reader, scope],
        |r| r.get(0),
    )
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

/// One entry of the owner's word: `owner_said` with what was said and the reason, or
/// `owner_withdrew` with what had been said and how it was withdrawn.
pub fn journal_owner(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    entity: &str,
    said: &str,
    text: &str,
) -> rusqlite::Result<()> {
    let (old, new) = if entry == "owner_said" {
        (None, Some(said))
    } else {
        (Some(said), None)
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, subject, old_value, new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![at, run_id, entry, entity, old, new, text],
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

/// One entry about the threat list: `threat_added` with the threat's name, `threat_gone`
/// with the name it had, or `threats_first_read` with how many entries the list held.
pub fn journal_threat(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    source: &str,
    subject: Option<&str>,
    value: &str,
) -> rusqlite::Result<()> {
    let (old, new) = if entry == "threat_gone" {
        (Some(value), None)
    } else {
        (None, Some(value))
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, subject, old_value, new_value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![at, run_id, entry, source, subject, old, new],
    )?;
    Ok(())
}
