//! The store: vocabulary, entities, the three assertion layers, coverage and the journal.
//! The shape is described in docs/how-it-works.md.

use crate::resolver;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use std::collections::BTreeSet;
use std::fs::{File, TryLockError};
use std::path::Path;
use std::time::{Duration, Instant};

/// Format 5 keeps text from a source with its secrets cut and in the store's form (see
/// `secrets::Form`). A store of format 4 is accepted only to be cleaned: this build reads it
/// cut on the fly, and the first open for writing cleans it and raises it to 5
/// (`secrets::clean`). A build of format 4 refuses a store of 5 as newer, so it never writes
/// raw text into a cleaned store.
pub const FORMAT_VERSION: &str = "5";
/// The format a store had before secrets were cut, taken only to be cleaned.
pub const UNCLEANED_FORMAT: &str = "4";

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
const JOURNAL_ENTRIES: [&str; 24] = [
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
    "finding_raised",
    "finding_reopened",
    "finding_cleared",
    "finding_expected",
    "finding_seen",
    // What a sample saw that a finding rests on, see `processes.rs`.
    "sampled",
    // One reading of a vulnerability data feed with its counts, see `osv.rs`.
    "advisories_read",
    // A published rule's match that a finding rests on: the rule and a count, see `events.rs`.
    "matched",
    // A place new in a worktree that is the same as in another checkout of its repository,
    // and so raised no finding, see `worktrees.rs`.
    "same_as_sibling",
    // A place read for the first time, with how many things it held that were taken as its
    // baseline, see `baseline.rs`.
    "place_first_read",
    // Something an earlier reading read in full that is there and could not be read, with why,
    // see `baseline.rs`.
    "not_read",
    // A fact of a kind this version no longer reads, closed with why: not a removal, see
    // `lifecycle::retire`.
    "retired",
    // A verdict of the response layer about a match or a finding, see `verdict.rs`.
    "verdict",
];

/// The journal. It cannot be rebuilt from raw input, so it only grows. Its entries are the
/// differences a run finds, the run's own notes, the owner's word, the threat list's
/// changes, and findings raised and answered.
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
    ('domain', 'reserved'), ('key', 'reserved'), ('party', 'reserved'), ('file', 'used'),
    ('check', 'used');
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
-- Integrity of what is installed, see src/integrity.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('installed_at', 'literal', 'used'), ('signed_by', 'literal', 'used'),
    ('has_seal', 'literal', 'used'), ('has_digest', 'literal', 'used');
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('application bundles in /Applications and ~/Applications'), ('Homebrew kegs'),
    ('global npm packages'),
    ('code kept by applications not signed by Apple under ~/Library/Application Support'),
    ('software of package managers this version does not read');
-- What runs by itself, see src/autorun.rs, and indicators, see src/indicators.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('matches_indicator', 'literal', 'used');
-- A peer's system as the private network names it, see src/tailnet.rs.
INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES
    ('runs_platform', 'literal', 'used');
INSERT OR IGNORE INTO coverage_kind (name) VALUES
    ('editor tasks set to run when a checkout''s folder is opened'),
    ('other ways a checkout runs code by itself'),
    ('indicator list given as a file'),
    ('indicators matched against watched files and texts read in checkouts'),
    ('indicators against what this build does not match them with');
-- Folders macOS asks the owner's permission for, see src/guarded.rs.
INSERT OR IGNORE INTO coverage_kind (name) VALUES ('folders macOS asks permission for');
";

/// Indexes what `immune status` and the view read by, made on every open so that a store of the
/// current format takes them. Without them the status of a store of tens of thousands of
/// things took seconds: each finding looked up its subject and its basis by a full scan, and
/// each latest reading looked for its last full one the same way.
///
/// Every reading adds coverage rows, a watcher's too; only those older than the runs kept whole
/// are folded (`fold`), so the runs kept whole and what came after them can be many. The latest
/// reading of a kind, which a watcher asks for at every reading to know which machine it
/// reads, is found through `coverage_latest_of_kind`. Without it a watcher's reading looked
/// through every reading before it: 3 ms after ten readings, 124 ms after ten thousand,
/// measured when it also counted every earlier failed reading, which it no longer does.
///
/// The status and the view ask for the latest reading of each reader, scope and kind, when
/// each was last read in full, and what one run read. `LATEST` finds the first through
/// `coverage_reading`, `coverage_full` answers the second in one look-up and `coverage_run`
/// the third; `coverage_lack_of` finds what a latest reading names as not read. Without them `immune status` took 8 ms after ten watcher readings and 325 ms after
/// ten thousand, and `immune view` 9 ms and 589 ms.
const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS coverage_reading ON coverage (reader, scope, kind);
CREATE INDEX IF NOT EXISTS coverage_latest_of_kind ON coverage (reader, kind);
CREATE INDEX IF NOT EXISTS coverage_full ON coverage (reader, scope, kind, completeness, observed_at);
CREATE INDEX IF NOT EXISTS coverage_run ON coverage (run_id);
CREATE INDEX IF NOT EXISTS coverage_lack_of ON coverage_lack (coverage);
CREATE INDEX IF NOT EXISTS assertion_subject ON assertion (subject, predicate);
CREATE INDEX IF NOT EXISTS finding_basis_finding ON finding_basis (finding);
";

/// The journal by run: what one run found, how it started and ended, what a reading of a feed
/// or the catalogue changed. Every run, watcher reading and sample adds to the journal and
/// nothing is ever removed from it, so without this each of those questions went through
/// the whole journal: the page of threats asked it once for each of the catalogue's 1,450
/// entries, 2.5 s of a full `immune view` on a journal of 40,000 entries. Made after the journal
/// is widened, which makes the table again.
const JOURNAL_INDEXES: &str = "
CREATE INDEX IF NOT EXISTS journal_run ON journal (run_id, entry);
";

/// The start of a query that names two tables: `reading (reader, scope, kind)`, one row for
/// each reader, scope and kind ever read, and `latest`, the coverage row of the latest
/// reading of each, with every column of `coverage`. It is what `coverage WHERE id IN (SELECT
/// MAX(id) FROM coverage GROUP BY reader, scope, kind)` says, asked so that its cost follows
/// the number of things read and not the number of readings: `reading` steps through
/// `coverage_reading` from one reader, scope and kind to the next (a loose index scan), and
/// `latest` takes the last row of each from the same index. A query starts from `latest`, not
/// from `coverage`, so that SQLite never goes through every reading to match it.
pub const LATEST: &str = "
WITH RECURSIVE reading (reader, scope, kind) AS (
    SELECT * FROM (SELECT reader, scope, kind FROM coverage ORDER BY reader, scope, kind LIMIT 1)
    UNION ALL
    SELECT n.reader, n.scope, n.kind FROM reading r JOIN coverage n ON n.id = COALESCE(
        (SELECT id FROM coverage WHERE reader = r.reader AND scope = r.scope AND kind > r.kind
         ORDER BY reader, scope, kind LIMIT 1),
        (SELECT id FROM coverage WHERE reader = r.reader AND scope > r.scope
         ORDER BY reader, scope, kind LIMIT 1),
        (SELECT id FROM coverage WHERE reader > r.reader ORDER BY reader, scope, kind LIMIT 1))
),
latest AS (
    SELECT c.* FROM reading r CROSS JOIN coverage c
    ON c.id = (SELECT l.id FROM coverage l
               WHERE l.reader = r.reader AND l.scope = r.scope AND l.kind = r.kind
               ORDER BY l.id DESC LIMIT 1)
)
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
/// A run writes in one transaction that lasts the whole run. Readers such as `immune status`
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
    give_id(&conn)?;
    conn.execute_batch(VOCABULARY)?;
    crate::autorun::add_kinds(&conn)?;
    crate::watched::add_kinds(&conn)?;
    conn.execute_batch(OWNER)?;
    crate::owner::add_via(&conn)?;
    conn.execute_batch(THREATS)?;
    conn.execute_batch(crate::osv::SCHEMA)?;
    conn.execute_batch(crate::vulnerabilities::SCHEMA)?;
    conn.execute_batch(crate::findings::SCHEMA)?;
    crate::findings::add_via(&conn)?;
    conn.execute_batch(crate::agent_folders::SCHEMA)?;
    conn.execute_batch(crate::verdict::SCHEMA)?;
    add_causes(&conn)?;
    conn.execute_batch(INDEXES)?;
    widen_journal(&mut conn)?;
    conn.execute_batch(JOURNAL_INDEXES)?;
    crate::baseline::open(&mut conn)?;
    // What a build before this one kept uncut is cut once, before anything is read or written.
    let folder = path.parent().filter(|p| !p.as_os_str().is_empty());
    crate::secrets::clean(&mut conn, folder.unwrap_or(Path::new(".")))?;
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

/// The store's own id, as every message of the contract carries it (`store_id`): a finding's id
/// is unique only within one store, and a store deleted and made again can give it to another
/// finding. `None` for a store an older build made that nothing has opened for writing since.
pub fn id(conn: &Connection) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = 'store_id'", [], |r| {
        r.get(0)
    })
    .optional()
}

/// Gives the store its id once: when it is made, or the first time this build opens an older
/// store for writing. 16 random bytes from `getentropy`, which macOS ships, as hexadecimal. It is
/// never derived from anything on the Mac, so it says nothing about it. An id already kept is
/// never replaced, so two processes that open a store without one at once keep the first.
fn give_id(conn: &Connection) -> Res<()> {
    let mut bytes = [0u8; 16];
    // SAFETY: the pointer and the length are those of `bytes`, which outlives the call;
    // getentropy fills at most 256 bytes and writes nothing else.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(format!(
            "no random bytes for the store's id: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    conn.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES ('store_id', ?1)",
        [hex],
    )?;
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
    if version == UNCLEANED_FORMAT {
        return Ok(());
    }
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
/// `immune status` holds the lock shared for a moment only; another run holds it for minutes.
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

// --- The watcher's lock, for `immune watch` (src/watch.rs). ---

/// The file in the store's folder that the watcher holds locked while it runs. The run lock is
/// on the folder itself, so the watcher's needs a file of its own.
pub const WATCH_LOCK: &str = "watch.lock";

/// Takes the watcher's lock on the store's folder for as long as the handle returned stays
/// open, or `None` when another watcher holds it. The same kernel lock as the run lock: it
/// goes when the process ends, however it ends, so a watcher that died never looks alive.
pub fn lock_watch(folder: &Path) -> std::io::Result<Option<File>> {
    let handle = File::options()
        .create(true)
        .append(true)
        .open(folder.join(WATCH_LOCK))?;
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

/// Whether a watcher holds its lock on the store's folder now. Opens the lock file only to
/// read, creates nothing, and holds the lock shared for a moment, which a watcher starting
/// meanwhile waits out.
pub fn watch_in_progress(folder: &Path) -> std::io::Result<bool> {
    let handle = match File::open(folder.join(WATCH_LOCK)) {
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

/// How long a full run goes on waiting for the run lock while a watcher runs on the store.
/// Measured on a store of 30,000 things: a watcher's reading holds the lock 0.03 s when one of
/// 40 watched files changed, 0.3 s when all 40 did, and about 1 s and 8 s with 1,000 watched
/// files. It leaves at least a second between readings, so a run waiting gets the lock.
pub const WATCHER_WAIT: Duration = Duration::from_secs(60);

/// The run lock for a full run: as `lock_run`, and while a watcher runs on the store, which
/// may be the one reading, up to `WATCHER_WAIT` more rather than give up.
pub fn lock_run_past_watcher(folder: &Path) -> std::io::Result<Option<File>> {
    let start = Instant::now();
    loop {
        if let Some(lock) = lock_run(folder)? {
            return Ok(Some(lock));
        }
        if !watch_in_progress(folder)? || start.elapsed() >= WATCHER_WAIT {
            return Ok(None);
        }
    }
}

// --- End of the watcher's lock. ---

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

// --- Folding the history of readings. ---

/// How many runs the changes page lists, each with every reading it made.
pub const RUNS_KEPT: i64 = 20;

/// One run the changes page lists.
pub struct Listed {
    pub run_id: String,
    /// When it began: its earliest journal entry.
    pub at: i64,
    pub finished: bool,
    /// The report line of a full run that finished.
    pub report: Option<String>,
}

/// The runs a page or an answer asks about by their id, newest first: the last `RUNS_KEPT`
/// the journal holds, which the changes page lists. A run is what the journal says started as
/// one, a watcher's reading or a sample; an answer, a statement or a verdict is not a run,
/// whatever its id. The fold keeps every reading of each of them (`kept_from`).
pub fn listed_runs(conn: &Connection) -> rusqlite::Result<Vec<Listed>> {
    conn.prepare(
        "SELECT run_id, MIN(at),
                MAX(entry = 'run_finished'),
                MAX(CASE WHEN entry = 'report' THEN text END)
         FROM journal WHERE entry NOT IN ('owner_said', 'owner_withdrew')
         GROUP BY run_id
         HAVING MAX(entry = 'run_started') OR run_id LIKE ?2 OR run_id LIKE ?3
         ORDER BY MAX(seq) DESC LIMIT ?1",
    )?
    .query_map(
        params![
            RUNS_KEPT,
            format!("{}%", crate::watch::RUN_PREFIX),
            format!("{}%", crate::processes::RUN_PREFIX)
        ],
        |r| {
            Ok(Listed {
                run_id: r.get(0)?,
                at: r.get(1)?,
                finished: r.get(2)?,
                report: r.get(3)?,
            })
        },
    )?
    .collect()
}

/// Where the history of readings the fold thins ends: the first row of the runs any page or
/// answer asks about by their id, the listed runs (`listed_runs`) and the latest finished run,
/// which `immune status` reports on. Every row from there on is kept. Rows are written with ids
/// that grow, and runs never overlap, so a row with a smaller id was written before every one
/// of those runs. A reader that keeps one row per reading, the event level and the samples,
/// takes its row out and writes it again: a reading of one row, which no fold touches. `None`
/// while no such run wrote a reading.
fn kept_from(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let finished: Option<String> = conn
        .query_row(
            "SELECT run_id FROM journal WHERE entry = 'run_finished' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let mut first = conn.prepare("SELECT MIN(id) FROM coverage WHERE run_id = ?1")?;
    let mut from = None;
    for run in listed_runs(conn)?
        .into_iter()
        .map(|l| l.run_id)
        .chain(finished)
    {
        let id: Option<i64> = first.query_row([run], |r| r.get(0))?;
        from = from.into_iter().chain(id).min();
    }
    Ok(from)
}

/// The readings older than `kept_from` that lie between the first and the last of a run of
/// unchanged readings of one reader, scope and kind: the same completeness, reason and cause,
/// one after another, with times that do not go back. A reading that differs in any of them,
/// a failure or a loss of sight among them, ends the run, and so does one dated before the
/// reading before it, as a server's reading dated by its sweep or one made after the clock
/// went back: the next starts a run of its own. What is left of a run is its first reading,
/// which says since when, and its last, which says until when, and so every earliest and
/// latest time of a reading is kept. What a reading names as having no reader is not part of
/// what it said here: only the latest reading's is ever asked for.
const FOLDED: &str = "
INSERT INTO temp.folded (id)
SELECT id FROM (
    SELECT id, completeness, reason, cause, observed_at AS t,
           LAG(completeness) OVER w AS c0, LAG(reason) OVER w AS r0, LAG(cause) OVER w AS k0,
           LAG(observed_at) OVER w AS t0,
           LEAD(completeness) OVER w AS c1, LEAD(reason) OVER w AS r1, LEAD(cause) OVER w AS k1,
           LEAD(observed_at) OVER w AS t1
    FROM coverage WHERE id < ?1
    WINDOW w AS (PARTITION BY reader, scope, kind ORDER BY id)
)
WHERE c0 IS completeness AND r0 IS reason AND k0 IS cause AND t0 <= t
  AND c1 IS completeness AND r1 IS reason AND k1 IS cause AND t <= t1
";

/// How many readings `fold` took out, of how many there were.
#[derive(Debug, Default, PartialEq)]
pub struct Folded {
    pub removed: usize,
    pub rows: i64,
}

/// Whether `free` pages of the file's `pages` are a quarter of it or more: then the space goes
/// back to the file, whichever run freed it. Fewer free pages are left for the rows written
/// next, as SQLite keeps them.
fn worth_giving_back(free: i64, pages: i64) -> bool {
    free > 0 && free * 4 >= pages
}

/// The free pages of the store's file and all its pages, as SQLite counts them.
fn free_pages(conn: &Connection) -> rusqlite::Result<(i64, i64)> {
    let free = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let pages = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    Ok((free, pages))
}

/// How many readings one transaction of `fold` takes out. A store is opened so that a writer
/// never shuts readers out before it commits, which keeps what it changes in memory. On a
/// store of 543,182 readings, a year of them: taken out in one transaction, the run that did
/// it held 235 MB at most; in transactions of this many, 92 MB, and it took 6 s.
const FOLD_AT_ONCE: i64 = 10_000;

/// Folds the history of readings older than the runs kept whole (`FOLDED`), outside any
/// transaction of the caller's, in transactions of `FOLD_AT_ONCE` readings, so that a reading
/// unchanged for a year is two rows and not one per run; on a store kept by an earlier build,
/// the first full run folds the whole history that way. A fold cut short leaves only readings
/// that lay between two of the same kept, and the next one goes on. Nothing a finding or an
/// answer rests on is a coverage row, and the latest reading of each reader, scope and kind is
/// never taken out.
pub fn fold(conn: &Connection) -> rusqlite::Result<Folded> {
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM coverage", [], |r| r.get(0))?;
    let Some(kept_from) = kept_from(conn)? else {
        return Ok(Folded { removed: 0, rows });
    };
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.folded;
         CREATE TEMP TABLE folded (id INTEGER PRIMARY KEY);",
    )?;
    conn.execute(FOLDED, [kept_from])?;
    let mut removed = 0;
    loop {
        let tx = conn.unchecked_transaction()?;
        let next = "SELECT id FROM temp.folded ORDER BY id LIMIT ?1";
        tx.execute(
            &format!("DELETE FROM coverage_lack WHERE coverage IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        removed += tx.execute(
            &format!("DELETE FROM coverage WHERE id IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        let done = tx.execute(
            &format!("DELETE FROM temp.folded WHERE id IN ({next})"),
            [FOLD_AT_ONCE],
        )?;
        tx.commit()?;
        if done == 0 {
            break;
        }
    }
    conn.execute_batch("DROP TABLE temp.folded")?;
    Ok(Folded { removed, rows })
}

/// Gives the file back the space of what was taken out of it, outside any transaction. SQLite
/// keeps freed pages for the rows written next, so the file does not grow again by them; this
/// is for when much was freed (`worth_giving_back`).
pub fn give_back(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("VACUUM")
}

/// What follows a full run's commit, still under the run lock: the fold, and where a quarter of
/// the file or more is free pages, the space given back. It is housekeeping and never changes
/// what the run did, so it returns nothing: a fold or a vacuum that fails, as when a reader
/// holds the store, is left as it is. The next run folds what is left, and gives back the space
/// still free, whichever run freed it.
pub fn tidy(conn: &Connection) {
    let _ = fold(conn);
    if free_pages(conn).is_ok_and(|(free, pages)| worth_giving_back(free, pages)) {
        let _ = give_back(conn);
    }
}

// --- End of folding. ---

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
        // Folders macOS asks permission for were not looked into, which is not a reading
        // that read nothing: they are told apart, under what is not covered. The event level
        // keeps no facts, so a reading of it that read nothing hides no change of one.
        none: tx.query_row(
            "SELECT COUNT(*) FROM coverage WHERE run_id = ?1 AND completeness = 'none'
               AND kind NOT IN (?2, ?3, ?4)",
            params![
                run_id,
                crate::guarded::KIND,
                crate::events::KIND,
                crate::events::KIND_FILES
            ],
            |row| row.get::<_, i64>(0),
        )?,
        machines_unread: one("SELECT COUNT(*) FROM (SELECT scope FROM coverage
             WHERE run_id = ?1 AND scope IN (SELECT id FROM entity WHERE type = 'machine')
             GROUP BY scope HAVING MAX(completeness != 'none') = 0)")?,
        not_repeated: one(&format!(
            "{LATEST}
             SELECT COUNT(*) FROM reading
             WHERE scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
               AND scope NOT IN (SELECT id FROM gone_entity)"
        ))?,
    })
}

/// The ids of machines the store knows now: something live names them, or a reading
/// covered them. An entity whose every trace was retracted is no longer known.
fn machines_known(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let column = |sql: &str| -> rusqlite::Result<BTreeSet<String>> {
        conn.prepare(sql)?.query_map([], |r| r.get(0))?.collect()
    };
    let entities = column("SELECT id FROM entity WHERE type = 'machine'")?;
    let mut named = column(&format!("{LATEST} SELECT DISTINCT scope FROM reading"))?;
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
    conn.prepare(&format!(
        "{LATEST}
         SELECT DISTINCT scope FROM latest WHERE reader = ?1 AND completeness != 'none'"
    ))?
    .query_map([reader], |r| r.get(0))?
    .collect()
}

/// Whether a reading of this kind by this reader in an earlier run than `run_id` read
/// something in this scope.
pub fn read_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
    run_id: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
                          AND completeness != 'none' AND run_id != ?4)",
        params![reader, scope, kind, run_id],
        |r| r.get(0),
    )
}

/// What the journal says of a difference found where nobody could have known what was there
/// before: during the store's first check. It is recorded, and it is not a change.
pub const FIRST_READING: &str = "first reading of its place";
/// What the journal says of a difference found in a place read for the first time after the
/// store's first check: it is recorded, it is not a change, and it is told once.
pub const READ_FIRST: &str = "read for the first time";

/// Whether a reading of this kind by this reader in an earlier run than `run_id` read this
/// scope in full.
pub fn read_full_before(
    conn: &Connection,
    reader: &str,
    scope: &str,
    kind: &str,
    run_id: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
                          AND completeness = 'full' AND run_id != ?4)",
        params![reader, scope, kind, run_id],
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

/// How far ahead of this Mac's clock a time may be and still be taken as now: clocks of two
/// sources differ by seconds, not by minutes.
pub const AHEAD_ALLOWED: i64 = 5 * 60;
/// Why a reading whose time is ahead of the clock has no age.
pub const AHEAD: &str = "its time is ahead of this Mac's clock, so how old it is is not known";

/// The age at `now` of what was read at `at`, both UTC seconds. A time ahead of the clock by
/// more than `AHEAD_ALLOWED` gives none: the clock was set back, or the time is wrong, and
/// what has no age is never taken as fresh. Every judgment of freshness goes through this.
pub fn age(at: i64, now: i64) -> Option<i64> {
    (at <= now + AHEAD_ALLOWED).then(|| (now - at).max(0))
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

/// This Mac's id in the store, kept in `meta` from the store's first run, so that a new
/// name of the Mac does not make it another machine. macOS changes its local host name by
/// itself when another device on the network has it, and the owner can rename the Mac. A
/// store made before the id was kept takes the machine its latest readings are of. `name`
/// is the Mac's name now: it is kept beside the id, and it is what is shown.
pub fn this_mac(tx: &Connection, name: &str) -> rusqlite::Result<String> {
    let id = match held_mac(tx)? {
        Some((id, _)) => id,
        None => crate::covered::this_machine(tx)?.unwrap_or_else(|| format!("machine:{name}")),
    };
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('machine', ?1), ('machine_name', ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![id, name],
    )?;
    Ok(id)
}

/// This Mac's id and its name at the latest run, as `this_mac` kept them.
pub fn held_mac(conn: &Connection) -> rusqlite::Result<Option<(String, String)>> {
    let get = |key: &str| {
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .optional()
    };
    Ok(match (get("machine")?, get("machine_name")?) {
        (Some(id), Some(name)) => Some((id, name)),
        _ => None,
    })
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
/// `owner_withdrew` with what had been said and how it was withdrawn; `kind` is how it was
/// given: app, agent or command.
#[allow(clippy::too_many_arguments)]
pub fn journal_owner(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    entity: &str,
    said: &str,
    text: &str,
    via: &str,
) -> rusqlite::Result<()> {
    let (old, new) = if entry == "owner_said" {
        (None, Some(said))
    } else {
        (Some(said), None)
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, kind, subject, old_value, new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![at, run_id, entry, via, entity, old, new, text],
    )?;
    Ok(())
}

/// One difference a reading found, with `text` when it is not a change: `FIRST_READING` or
/// `READ_FIRST`.
pub fn journal_event(
    tx: &Transaction,
    r: &Reading,
    e: &Event,
    text: Option<&str>,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              old_value, new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
            e.new,
            text
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_more_than_a_few_minutes_ahead_of_the_clock_has_no_age_and_a_little_ahead_is_now() {
        // Two clocks differ by seconds; a reading dated later than that is not fresh forever.
        let now = 2_000_000_000;
        assert_eq!(age(now - 90, now), Some(90));
        assert_eq!(age(now + 60, now), Some(0));
        assert_eq!(age(now + AHEAD_ALLOWED, now), Some(0));
        assert_eq!(age(now + AHEAD_ALLOWED + 1, now), None);
    }

    // --- Folding the history of readings, on invented stores. ---

    const MAC: &str = "machine:mac";
    const PROFILES: &str = "shell profiles of zsh and bash";
    const BREW: &str = "brew packages";

    /// What a reading said: its completeness, and its reason and cause when not full.
    #[derive(Clone, Copy)]
    struct Said {
        completeness: &'static str,
        reason: Option<&'static str>,
        cause: Option<Cause>,
        lack: Option<&'static str>,
    }

    const FULL: Said = Said {
        completeness: "full",
        reason: None,
        cause: None,
        lack: None,
    };

    fn failed(reason: &'static str) -> Said {
        Said {
            completeness: "none",
            reason: Some(reason),
            cause: Some(Cause::Failed),
            lack: None,
        }
    }

    fn partial(reason: &'static str) -> Said {
        Said {
            completeness: "partial",
            reason: Some(reason),
            cause: Some(Cause::NotGiven),
            lack: None,
        }
    }

    /// An invented store and the runs made on it, one a minute.
    struct Kept {
        dir: std::path::PathBuf,
        conn: Connection,
        runs: i64,
        /// Seconds the clock is off by for the next run's readings, as a clock set back is.
        skew: i64,
    }

    impl Kept {
        fn new(tag: &str) -> Kept {
            let dir = std::env::temp_dir().join(format!(
                "immune-fold-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let conn = open(&dir.join("store.db")).unwrap();
            Kept {
                dir,
                conn,
                runs: 0,
                skew: 0,
            }
        }

        /// One run that writes these readings, `(reader, scope, kind, said)`: a full run with
        /// its start and end in the journal, or a watcher's reading with neither.
        fn run(&mut self, full: bool, readings: &[(&str, &str, &str, Said)]) -> String {
            self.runs += 1;
            let at = 1_900_000_000 + self.runs * 60;
            let run_id = if full {
                format!("{at}-000000000")
            } else {
                format!("watch-{at}-000000000")
            };
            if full {
                journal_note(&self.conn, at, &run_id, "run_started", "").unwrap();
            }
            let tx = self.conn.transaction().unwrap();
            for (reader, scope, kind, said) in readings {
                put_entity(&tx, scope).unwrap();
                let r = Reading {
                    reader,
                    scope,
                    kind,
                    run_id: &run_id,
                    at: at + self.skew,
                    observed_at: at + self.skew,
                };
                let gap = Gap {
                    cause: said.cause,
                    lacks: said
                        .lack
                        .map(|l| vec![Lack::new(l, None)])
                        .unwrap_or_default(),
                };
                put_coverage(&tx, &r, said.completeness, said.reason, &gap).unwrap();
            }
            tx.commit().unwrap();
            if full {
                journal_note(&self.conn, at, &run_id, "run_finished", "").unwrap();
            }
            run_id
        }

        fn fold(&self) -> Folded {
            fold(&self.conn).unwrap()
        }

        fn rows(&self) -> i64 {
            self.conn
                .query_row("SELECT COUNT(*) FROM coverage", [], |r| r.get(0))
                .unwrap()
        }

        /// The readings of one reader, scope and kind, oldest first: completeness, reason, run
        /// and time.
        fn history(&self, scope: &str, kind: &str) -> Vec<(String, Option<String>, String, i64)> {
            self.conn
                .prepare(
                    "SELECT completeness, reason, run_id, observed_at FROM coverage
                     WHERE scope = ?1 AND kind = ?2 ORDER BY id",
                )
                .unwrap()
                .query_map(params![scope, kind], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect()
        }
    }

    impl Drop for Kept {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A deterministic sequence of readings for a history, so that a failing case can be read
    /// again: each step a number below `n`.
    fn steps(seed: u64, count: usize, n: u64) -> Vec<u64> {
        let mut x = seed;
        (0..count)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) % n
            })
            .collect()
    }

    #[test]
    fn unchanged_readings_beyond_the_runs_kept_whole_add_no_rows() {
        // The bound itself: a Mac read every hour for a year holds no more readings than one
        // read for a day, once nothing changes.
        let mut k = Kept::new("bound");
        let readings = [
            ("brew", MAC, BREW, FULL),
            ("watched-places", MAC, PROFILES, FULL),
            ("tailnet", MAC, "tailnet peers", failed("switched off")),
        ];
        let mut after = Vec::new();
        for i in 0..(RUNS_KEPT + 40) {
            k.run(true, &readings);
            // Watchers' readings between the runs, of the watched places alone.
            if i % 3 == 0 {
                k.run(false, &readings[1..2]);
            }
            k.fold();
            after.push(k.rows());
        }
        // The runs kept whole hold a watcher's reading every third run, so the count repeats
        // every three runs and never grows.
        let late = &after[after.len() - 30..];
        assert!(late.windows(4).all(|w| w[0] == w[3]), "{after:?}");
        // Each reading of the runs kept whole, and the first and the last of what is older.
        let most = *late.iter().max().unwrap();
        assert!(most <= 3 * (RUNS_KEPT + 2) + (RUNS_KEPT / 3 + 3), "{most}");
    }

    #[test]
    fn a_failure_ends_a_run_of_unchanged_readings_and_a_reading_after_it_starts_a_new_one() {
        let mut k = Kept::new("failure");
        let mut said = Vec::new();
        said.extend([FULL; 5]);
        said.extend([failed("permission denied"); 4]);
        said.push(failed("no such file"));
        said.extend([FULL; 5]);
        for s in &said {
            k.run(true, &[("watched-places", MAC, PROFILES, *s)]);
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        assert!(k.fold().removed > 0);
        let kept: Vec<(String, Option<String>)> = k
            .history(MAC, PROFILES)
            .into_iter()
            .map(|(c, r, _, _)| (c, r))
            .collect();
        let full = ("full".to_string(), None);
        let denied = ("none".to_string(), Some("permission denied".to_string()));
        let missing = ("none".to_string(), Some("no such file".to_string()));
        assert_eq!(
            kept,
            vec![
                full.clone(),
                full.clone(),
                denied.clone(),
                denied,
                missing,
                full.clone(),
                full
            ]
        );
    }

    #[test]
    fn a_change_of_completeness_reason_or_cause_ends_a_run_of_unchanged_readings() {
        let mut k = Kept::new("reason");
        let lacking = Said {
            lack: Some("software of a package manager this version does not read"),
            ..partial("one")
        };
        // Each run differs from the one before it in one of these alone.
        let none = Said {
            completeness: "none",
            ..partial("one")
        };
        for s in [partial("one"); 3]
            .into_iter()
            .chain([none; 3])
            .chain([failed("one"); 3])
            .chain([failed("two"); 3])
            .chain([lacking; 3])
        {
            k.run(true, &[("brew", MAC, BREW, s)]);
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(k.fold().removed, 5);
        let left: Vec<_> = k.history(MAC, BREW).into_iter().map(|h| h.3).collect();
        let at = |run: i64| 1_900_000_000 + run * 60;
        assert_eq!(
            left,
            [1, 3, 4, 6, 7, 9, 10, 12, 13, 15].map(at),
            "the first and the last of each run"
        );
        // What has no reader goes with the readings taken out, and stays with those kept, the
        // latest among them.
        let lacks: i64 = k
            .conn
            .query_row(
                "SELECT COUNT(*) FROM coverage_lack l JOIN coverage c ON c.id = l.coverage
                 WHERE c.kind = ?1",
                [BREW],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lacks, 2);
    }

    #[test]
    fn folding_never_turns_a_failed_or_partial_reading_into_a_full_one_nor_moves_a_time() {
        // Over invented histories: what each reading said, in order and with consecutive
        // repeats taken as one, is the same before and after; so are the first and the last
        // time of each repeat.
        let said = [FULL, failed("a"), failed("b"), partial("c")];
        for seed in 1..40 {
            let mut k = Kept::new("histories");
            // Long runs of one outcome, as on a real Mac, and now and then a clock set back
            // by up to three runs.
            for step in steps(seed, 60, 12) {
                let s = said[(step / 3).min(3) as usize];
                k.skew = if step % 4 == 0 {
                    -(step as i64 * 15)
                } else {
                    0
                };
                k.run(true, &[("watched-places", MAC, PROFILES, s)]);
            }
            k.skew = 0;
            for _ in 0..RUNS_KEPT {
                k.run(true, &[("brew", MAC, BREW, FULL)]);
            }
            // A run of repeats ends where what was said changes, or where the time goes back.
            let runs = |h: Vec<(String, Option<String>, String, i64)>| {
                let mut out: Vec<(String, Option<String>, i64, i64)> = Vec::new();
                for (c, r, _, at) in h {
                    match out.last_mut() {
                        Some(last) if last.0 == c && last.1 == r && at >= last.3 => last.3 = at,
                        _ => out.push((c, r, at, at)),
                    }
                }
                out
            };
            let before = runs(k.history(MAC, PROFILES));
            k.fold();
            let after = k.history(MAC, PROFILES);
            assert!(after.len() <= 2 * before.len(), "seed {seed}");
            assert_eq!(runs(after), before, "seed {seed}");
        }
    }

    #[test]
    fn every_answer_the_store_gives_about_coverage_is_the_same_after_folding() {
        // The latest reading of each reader, scope and kind is the freshness every answer
        // uses: when it was taken, when it was last full, since when it fails, whether a
        // place was read before. A stale or uncovered answer stays so, a fresh one stays fresh.
        let mut k = Kept::new("answers");
        let server = "machine:web-1";
        let visit = crate::servers::VISIT;
        let mut first = None;
        for i in 0..(RUNS_KEPT + 30) {
            let visited = match i {
                0..10 => FULL,
                10..14 => failed("timed out"),
                14..16 => failed("refused"),
                _ => failed("timed out"),
            };
            let shell = if i < 12 { FULL } else { partial("one file") };
            let run = k.run(
                true,
                &[
                    (crate::servers::READER, server, visit, visited),
                    ("watched-places", MAC, PROFILES, shell),
                    ("resolver", MAC, "machines under several names", FULL),
                ],
            );
            first.get_or_insert(run);
        }
        let answers = |k: &Kept| {
            let c = &k.conn;
            let latest: Vec<_> = crate::view::latest_coverage(c)
                .unwrap()
                .into_iter()
                .map(|l| {
                    (
                        l.reader,
                        l.scope,
                        l.kind,
                        l.completeness,
                        l.reason,
                        l.at,
                        l.last_full,
                        l.cause,
                    )
                })
                .collect();
            let problems =
                crate::status::problems(c, &crate::view::latest_coverage(c).unwrap()).unwrap();
            let unreached: Vec<_> = problems
                .unreached
                .iter()
                .map(|u| (u.scope.clone(), u.since, u.reason.clone()))
                .collect();
            let run = "the next run";
            (
                latest,
                unreached,
                last_read(c, crate::servers::READER, server).unwrap(),
                read_before(c, "watched-places", MAC, PROFILES, run).unwrap(),
                read_full_before(c, "watched-places", MAC, PROFILES, run).unwrap(),
                read_full_before(c, crate::servers::READER, server, visit, run).unwrap(),
                scopes_read(c, crate::servers::READER).unwrap(),
                c.query_row(&format!("{LATEST} SELECT COUNT(*) FROM latest"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                // The run that first read each place, which the journal's baselines go by.
                c.query_row(
                    "SELECT run_id FROM coverage WHERE reader = 'watched-places'
                       AND completeness != 'none' ORDER BY id LIMIT 1",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
            )
        };
        let before = answers(&k);
        assert!(k.fold().removed > 0);
        assert_eq!(answers(&k), before);
        // Since when the server fails is the first failure after the last full visit.
        assert_eq!(before.1[0].1, 1_900_000_000 + 11 * 60);
        assert_eq!(before.8, first.unwrap());
    }

    #[test]
    fn readings_of_two_readers_of_one_place_are_folded_each_in_its_own_history() {
        // Freshness is told per reader, scope and kind: one reader's readings never end a run
        // of another's, nor stand for its first or its latest.
        let mut k = Kept::new("readers");
        for _ in 0..6 {
            k.run(
                true,
                &[("brew", MAC, BREW, FULL), ("another", MAC, BREW, FULL)],
            );
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(k.fold().removed, 8);
        let each: Vec<(String, i64, i64)> = k
            .conn
            .prepare(
                "SELECT reader, MIN(observed_at), MAX(observed_at) FROM coverage
                 WHERE kind = ?1 GROUP BY reader ORDER BY reader",
            )
            .unwrap()
            .query_map([BREW], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let at = |run: i64| 1_900_000_000 + run * 60;
        assert_eq!(
            each,
            [
                ("another".to_string(), at(1), at(6)),
                ("brew".to_string(), at(1), at(6))
            ]
        );
    }

    #[test]
    fn folding_never_lowers_a_time_an_answer_reads_when_times_go_back() {
        // A server's reading is dated by its sweep, and any reading by a clock that can go
        // back: times need not grow with the row id. A reading dated before the one before it
        // starts a run of its own, so the latest and the earliest time of each are kept.
        let mut k = Kept::new("time");
        let server = "machine:web-1";
        for t in [100, 300, 200, 210, 220] {
            k.runs += 1;
            let run_id = format!("{}-000000000", 1_900_000_000 + k.runs * 60);
            journal_note(&k.conn, t, &run_id, "run_started", "").unwrap();
            let tx = k.conn.transaction().unwrap();
            put_entity(&tx, server).unwrap();
            let r = Reading {
                reader: crate::servers::READER,
                scope: server,
                kind: "system packages",
                run_id: &run_id,
                at: t,
                observed_at: t,
            };
            put_coverage(&tx, &r, "full", None, &Gap::default()).unwrap();
            tx.commit().unwrap();
            journal_note(&k.conn, t, &run_id, "run_finished", "").unwrap();
        }
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        // The owner said the server was retired at 150: the reading at 300 contradicts it.
        crate::owner::say(
            &mut k.conn,
            server,
            &[server.to_string()],
            "retired",
            "moved",
            crate::findings::Via::Command,
            150,
            "owner-1",
        )
        .unwrap();
        let answers = |k: &Kept| {
            let last_full = crate::view::latest_coverage(&k.conn)
                .unwrap()
                .into_iter()
                .find(|l| l.scope == server)
                .unwrap()
                .last_full;
            let seen = crate::owner::standing(&k.conn).unwrap()[0].contradiction();
            (
                last_read(&k.conn, crate::servers::READER, server).unwrap(),
                last_full,
                seen,
            )
        };
        let before = answers(&k);
        assert_eq!((before.0, before.1), (Some(300), Some(300)));
        assert_eq!(k.fold().removed, 1);
        assert_eq!(answers(&k), before);
        let left: Vec<i64> = k
            .history(server, "system packages")
            .into_iter()
            .map(|h| h.3)
            .collect();
        assert_eq!(left, [100, 300, 200, 220]);
    }

    #[test]
    fn a_fold_beside_a_reader_that_holds_the_store_does_not_fail_the_run_and_the_next_run_folds() {
        // What follows a full run's commit is housekeeping, and returns nothing: a fold that
        // cannot commit while a reader holds the store, here for the five seconds a writer
        // waits, leaves the readings as they were, and the next run folds them.
        let mut k = Kept::new("busy");
        for _ in 0..(RUNS_KEPT + 5) {
            k.run(true, &[("brew", MAC, BREW, FULL)]);
        }
        let rows = k.rows();
        let reader = Connection::open(k.dir.join("store.db")).unwrap();
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM coverage;")
            .unwrap();
        tidy(&k.conn);
        assert_eq!(k.rows(), rows);
        reader.execute_batch("COMMIT").unwrap();
        tidy(&k.conn);
        assert_eq!(k.rows(), rows - 3);
    }

    #[test]
    fn only_a_file_a_quarter_or_more_free_is_rewritten() {
        // Rewriting the file takes as long as the store is large and shuts readers out
        // meanwhile: the few pages a run frees in the ordinary way stay free for the next run.
        assert!(!worth_giving_back(0, 0));
        assert!(!worth_giving_back(0, 100));
        assert!(!worth_giving_back(24, 100));
        assert!(worth_giving_back(25, 100));
        assert!(worth_giving_back(57_000, 57_861));
    }

    #[test]
    fn a_run_that_leaves_little_free_keeps_its_free_pages_for_the_rows_written_next() {
        let mut k = Kept::new("free-little");
        let scopes: Vec<String> = (0..40).map(|i| format!("machine:m{i}")).collect();
        let readings: Vec<(&str, &str, &str, Said)> = scopes
            .iter()
            .map(|s| ("brew", s.as_str(), BREW, FULL))
            .collect();
        for _ in 0..RUNS_KEPT {
            k.run(true, &readings);
        }
        // A few pages freed, as by the readings an ordinary run folds.
        k.conn
            .execute_batch(
                "CREATE TABLE spare (v TEXT);
                 WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100)
                 INSERT INTO spare SELECT hex(randomblob(100)) FROM n;
                 DROP TABLE spare;",
            )
            .unwrap();
        let (free, pages) = free_pages(&k.conn).unwrap();
        assert!(
            free > 0 && !worth_giving_back(free, pages),
            "{free} of {pages}"
        );
        tidy(&k.conn);
        assert_eq!(free_pages(&k.conn).unwrap(), (free, pages));
    }

    #[test]
    fn space_a_fold_freed_and_could_not_give_back_is_given_back_by_a_later_run() {
        // The vacuum after a fold met a reader and failed; the next run folds almost nothing,
        // and still gives back the space the file holds free.
        let mut k = Kept::new("free-later");
        let scopes: Vec<String> = (0..40).map(|i| format!("machine:m{i}")).collect();
        let readings: Vec<(&str, &str, &str, Said)> = scopes
            .iter()
            .map(|s| ("brew", s.as_str(), BREW, FULL))
            .collect();
        for _ in 0..(RUNS_KEPT + 200) {
            k.run(true, &readings);
        }
        let path = k.dir.join("store.db");
        let size = || std::fs::metadata(&path).unwrap().len();
        let before = size();
        k.fold();
        let reader = Connection::open(&path).unwrap();
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM coverage;")
            .unwrap();
        assert!(give_back(&k.conn).is_err(), "the vacuum met the reader");
        reader.execute_batch("COMMIT").unwrap();
        drop(reader);
        assert_eq!(size(), before);
        k.run(true, &readings);
        tidy(&k.conn);
        assert!(size() * 3 < before, "{} bytes of {before}", size());
    }

    #[test]
    fn the_runs_kept_whole_and_the_latest_finished_keep_every_reading_they_made() {
        // The changes page and `immune status` ask what each of these runs read: a run in the
        // middle of unchanged readings still read them, and is never shown as having read
        // nothing or everything.
        let mut k = Kept::new("window");
        let readings = [
            ("brew", MAC, BREW, failed("no output")),
            ("watched-places", MAC, PROFILES, FULL),
        ];
        let mut runs = Vec::new();
        for _ in 0..(RUNS_KEPT + 10) {
            runs.push(k.run(true, &readings));
        }
        // Runs that died before they finished, after the latest one that finished.
        let finished = runs.last().unwrap().clone();
        for _ in 0..(RUNS_KEPT + 5) {
            k.runs += 1;
            let at = 1_900_000_000 + k.runs * 60;
            let run_id = format!("{at}-000000000");
            journal_note(&k.conn, at, &run_id, "run_started", "").unwrap();
            let tx = k.conn.transaction().unwrap();
            for (reader, scope, kind, said) in &readings {
                let r = Reading {
                    reader,
                    scope,
                    kind,
                    run_id: &run_id,
                    at,
                    observed_at: at,
                };
                put_coverage(
                    &tx,
                    &r,
                    said.completeness,
                    said.reason,
                    &Gap::when(said.cause),
                )
                .unwrap();
            }
            tx.commit().unwrap();
            runs.push(run_id);
        }
        let per_run = |k: &Kept, run: &str| {
            let t = totals(&k.conn, run).unwrap();
            (t.partial, t.none, t.machines_unread, t.not_repeated)
        };
        let kept: Vec<&String> = runs[runs.len() - RUNS_KEPT as usize..]
            .iter()
            .chain([&finished])
            .collect();
        let before: Vec<_> = kept.iter().map(|r| per_run(&k, r)).collect();
        assert!(k.fold().removed > 0);
        let after: Vec<_> = kept.iter().map(|r| per_run(&k, r)).collect();
        assert_eq!(after, before);
        assert!(before.iter().all(|t| t.1 == 1), "{before:?}");
    }

    #[test]
    fn nothing_is_folded_before_any_run_journaled_nor_from_the_runs_kept_whole() {
        let mut k = Kept::new("young");
        for _ in 0..5 {
            k.run(false, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        assert_eq!(
            k.fold(),
            Folded {
                removed: 0,
                rows: 5
            }
        );
        for _ in 0..RUNS_KEPT {
            k.run(true, &[("watched-places", MAC, PROFILES, FULL)]);
        }
        // The watcher's readings before the first run are older than every run kept whole.
        assert_eq!(k.fold().removed, 3);
        assert_eq!(k.fold().removed, 0);
    }

    #[test]
    fn a_store_kept_whole_by_an_earlier_build_is_folded_and_its_file_gives_the_space_back() {
        let mut k = Kept::new("earlier");
        let readings: Vec<(&str, String, &str, Said)> = (0..40)
            .map(|i| {
                (
                    "watched-places",
                    format!("file:mac/f{i}"),
                    crate::watched::CONTENT,
                    FULL,
                )
            })
            .collect();
        let readings: Vec<(&str, &str, &str, Said)> = readings
            .iter()
            .map(|(r, s, kind, said)| (*r, s.as_str(), *kind, *said))
            .collect();
        for _ in 0..(RUNS_KEPT + 200) {
            k.run(true, &readings);
        }
        let path = k.dir.join("store.db");
        let size = || std::fs::metadata(&path).unwrap().len();
        let before = size();
        tidy(&k.conn);
        assert!(size() * 3 < before, "{} then {before}", size());
        assert_eq!(k.rows(), 40 * (RUNS_KEPT + 2));
    }
}
