//! Open vulnerability data of the ecosystems whose lockfiles are read: OSV.dev's export of
//! each, `crates.io/all.zip` and `npm/all.zip`, fetched whole. The contract is in
//! docs/threats.md.
//!
//! What is asked of the network never depends on the estate: each request is built from the
//! feed's address and from the feed's own readings (the ETag it sent, when it was last read),
//! never from facts. Nothing here reads a fact.
//!
//! The archive is untrusted. It is unpacked by `/usr/bin/bsdtar`, which macOS ships, to
//! stdout only, so nothing in it ever becomes a path or a command; its entries are checked
//! against its own listing, and every record against a fixed shape. A reading that fails in
//! any way changes nothing: the data read before stays in force, with its age, and the reason
//! is named. Text from a record is kept as the record gives it and escaped wherever shown.
//!
//! Nothing is matched here: the projects' lockfiles are matched against this data in
//! `vulnerabilities.rs`.

use crate::sha256;
use crate::threats::{self, Answer};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The tables of the vulnerability data. Advisories are not facts: like threats they live in
/// their own tables and never touch assertions. Created on every open. Text in them is the
/// feed's own and is partly written by an attacker.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS advisory (
    source        TEXT NOT NULL,     -- the feed, such as 'osv-npm'
    id            TEXT NOT NULL,
    modified      TEXT NOT NULL,     -- as the record gives it
    withdrawn     TEXT,              -- as the record gives it, when it is withdrawn
    kind          TEXT NOT NULL CHECK (kind IN ('malicious', 'informational', 'vulnerability')),
    summary       TEXT,
    severity      TEXT,              -- GitHub's label, database_specific.severity
    cvss          TEXT NOT NULL,     -- severity[] as a JSON array of {type, score}
    aliases       TEXT NOT NULL,     -- JSON array
    cwe_ids       TEXT NOT NULL,     -- JSON array, database_specific.cwe_ids
    first_run     TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,  -- UTC seconds
    written_run   TEXT NOT NULL,     -- the reading that wrote this version of it
    written_at    INTEGER NOT NULL,
    gone_at       INTEGER,           -- when it left the feed, UTC seconds
    gone_run      TEXT,
    PRIMARY KEY (source, id),
    CHECK ((gone_at IS NULL) = (gone_run IS NULL))
);
-- What an advisory affects, one row per affected package of the feed's own ecosystem.
CREATE TABLE IF NOT EXISTS advisory_affects (
    source        TEXT NOT NULL,
    advisory      TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,     -- as the record gives it
    name          TEXT NOT NULL,     -- as the record gives it
    normalized    TEXT NOT NULL,     -- what a lockfile's name is compared with
    ranges        TEXT NOT NULL,     -- JSON array of {type, events, repo}, events as given
    versions      TEXT NOT NULL,     -- JSON array, as given
    informational TEXT,              -- RustSec's kind of informational advisory
    FOREIGN KEY (source, advisory) REFERENCES advisory (source, id)
);
CREATE INDEX IF NOT EXISTS advisory_affects_name ON advisory_affects (ecosystem, normalized);
CREATE INDEX IF NOT EXISTS advisory_affects_advisory ON advisory_affects (source, advisory);
-- What the status, the view and every run ask of the records held now: how many there are of
-- each kind (`held`), the newest change (`freshness`) and how many are informational. Each was
-- a read of the whole table, about 235,000 rows and 40 MB for npm, several times per
-- `immune status`. Each index holds what its question reads, so it is answered from the index
-- alone: `advisory_held` by a pass over its entries for one feed, the other two by a look-up.
CREATE INDEX IF NOT EXISTS advisory_held ON advisory (source, gone_at, kind, withdrawn);
CREATE INDEX IF NOT EXISTS advisory_newest ON advisory (source, gone_at, modified);
CREATE INDEX IF NOT EXISTS advisory_informational ON advisory (kind, withdrawn, gone_at);
";

/// One feed of vulnerability data.
pub struct Feed {
    /// Its name in `feed_reading` and the journal.
    pub source: &'static str,
    /// The ecosystem as OSV and the lockfiles reader name it.
    pub ecosystem: &'static str,
    pub url: &'static str,
    /// The archive is not read above this many bytes, however it arrives.
    pub cap: u64,
    /// Seconds curl may take.
    pub max_time: u32,
    /// How long its last good reading stands before it is asked for again, in seconds; 0:
    /// every run.
    pub every: i64,
    /// How often it is asked for, in words.
    pub asked: &'static str,
    /// How long its last good reading counts as current for "does not affect me, known for
    /// certain", in seconds: two hours where it is asked for on every run, a day and two hours
    /// where once a day.
    pub current_for: i64,
}

pub const FEEDS: [Feed; 2] = [
    Feed {
        source: "osv-crates.io",
        ecosystem: "crates.io",
        url: "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
        cap: 64 * 1024 * 1024,
        max_time: 300,
        every: 0,
        asked: "on every run",
        current_for: 2 * 3600,
    },
    // About 220 MB in 2026, 93% of it malicious-package reports: asked for once a day. Its
    // time, with crates.io's and the catalogue's 300 s each and a watcher's reading waited out
    // for up to 60 s, keeps a run inside the app's 30 minutes (1,800 s): 1,560 s at most.
    Feed {
        source: "osv-npm",
        ecosystem: "npm",
        url: "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        cap: 512 * 1024 * 1024,
        max_time: 900,
        every: 24 * 3600,
        asked: "once a day",
        current_for: 26 * 3600,
    },
];

/// The folder next to the store where each feed's archive is kept.
pub const FOLDER: &str = "feeds";
/// The most bytes the unpacked records of one archive may take: 391 MB for npm in 2026.
pub const STREAM_CAP: u64 = 1024 * 1024 * 1024;
/// The most bytes one record may take: the largest was 1.15 MB in 2026.
pub const RECORD_CAP: usize = 4 * 1024 * 1024;
/// The unpacker macOS ships. No other is looked for.
const BSDTAR: &str = "/usr/bin/bsdtar";
/// The most bytes of the archive's listing read: 6 MB for npm in 2026.
const LISTING_CAP: u64 = 64 * 1024 * 1024;
/// What curl or bsdtar may say on stderr before it is cut.
const SAID_CAP: u64 = 64 * 1024;

/// The archive of a feed's latest reading that read it, relative to the store's folder. Only
/// the latest is kept: an exception to keeping every changed copy of raw input, since npm's
/// would be about 80 GB a year. Beside it, what that reading read, one line per record with
/// `id`, `modified` and the SHA-256 of its text (`kept_lines`), also the latest only, since
/// npm's is 23 MB: both are overwritten by the next reading that changes them, so nothing
/// grows by the day. History is in the public sources behind OSV, which keep theirs.
pub fn kept(feed: &Feed) -> String {
    format!("{FOLDER}/{}.zip", feed.source)
}

/// The lines of what the latest reading of a feed read, relative to the store's folder.
pub fn kept_lines(feed: &Feed) -> String {
    format!("{FOLDER}/{}.records.txt", feed.source)
}

/// The archive of a reading that failed, kept until a reading succeeds, so that the reason can
/// be looked into and a server that says it has not changed since is not asked again.
fn kept_failed(feed: &Feed) -> String {
    format!("{FOLDER}/{}.failed.zip", feed.source)
}

/// What asking for a feed brought.
pub enum Got {
    /// An archive to read: a file given, or what curl downloaded, with the ETag it came with.
    Archive {
        path: PathBuf,
        etag: Option<String>,
        downloaded: bool,
    },
    /// The server said the archive has not changed since the ETag it was asked with.
    Unchanged,
    /// Not asked: its last good reading is recent enough.
    NotDue,
    Failed(String),
}

/// The ETag to ask with and whether the reading that brought it failed.
fn last_etag(conn: &Connection, source: &str) -> rusqlite::Result<Option<(String, bool)>> {
    conn.query_row(
        "SELECT etag, outcome = 'failed' FROM feed_reading
         WHERE source = ?1 AND etag IS NOT NULL ORDER BY id DESC LIMIT 1",
        [source],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// When the feed was last read successfully: read whole, or found unchanged.
pub fn last_good_at(conn: &Connection, source: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(at) FROM feed_reading WHERE source = ?1 AND outcome != 'failed'",
        [source],
        |r| r.get(0),
    )
}

/// Why the feed's latest reading failed, when it did. `None` in a store made before the
/// feeds' tables.
pub fn last_failure(conn: &Connection, source: &str) -> rusqlite::Result<Option<String>> {
    if !has_tables(conn)? {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT reason FROM feed_reading WHERE source = ?1 AND outcome = 'failed'
               AND id = (SELECT MAX(id) FROM feed_reading WHERE source = ?1)",
            [source],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

/// The arguments curl is run with for a feed: the catalogue's invocation with the feed's cap
/// and time, the body to `output`, and the feed's own last ETag. Nothing else goes in.
pub fn request(feed: &Feed, output: &Path, etag: Option<&str>) -> Vec<String> {
    threats::curl_args(feed.url, feed.cap, feed.max_time, Some(output), etag)
}

/// The lock a run holds on the feeds' folder from before its downloads until it ends, so that
/// two runs never write the same partial download. It is not the run lock: a download, which
/// can take minutes, holds up no watcher's reading and no `immune status`. `None` when another
/// run holds it.
pub fn lock_fetch(home: &Path) -> std::io::Result<Option<std::fs::File>> {
    let dir = home.join(FOLDER);
    std::fs::create_dir_all(&dir)?;
    let handle = std::fs::File::options()
        .create(true)
        .append(true)
        .open(dir.join("fetch.lock"))?;
    match handle.try_lock() {
        Ok(()) => Ok(Some(handle)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

/// Whether the store has the feeds' tables: one made before them has none until a run
/// opens it.
fn has_tables(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) = 2 FROM sqlite_master
         WHERE type = 'table' AND name IN ('advisory', 'feed_reading')",
        [],
        |r| r.get(0),
    )
}

/// Asks for a feed, or takes the archive given instead. Run before the run lock is taken, with
/// the store open only to read, or with no store yet: what it needs of the store, the ETag
/// and when the feed was last read, is read first, and the download touches nothing in it.
pub fn get(
    conn: Option<&Connection>,
    feed: &Feed,
    input: Option<&Path>,
    curl: &Path,
    home: &Path,
    now: i64,
) -> rusqlite::Result<Got> {
    if let Some(path) = input {
        return Ok(Got::Archive {
            path: path.to_path_buf(),
            etag: None,
            downloaded: false,
        });
    }
    let conn = match conn {
        Some(conn) if has_tables(conn)? => Some(conn),
        _ => None,
    };
    if feed.every > 0
        && let Some(conn) = conn
        && let Some(at) = last_good_at(conn, feed.source)?
        && crate::store::age(at, now).is_some_and(|age| age <= feed.every)
    {
        return Ok(Got::NotDue);
    }
    // The ETag of the archive held: the one last read, or the one that failed, while it is
    // still there to be read again.
    let etag = match conn {
        Some(conn) => last_etag(conn, feed.source)?,
        None => None,
    }
    .filter(|(_, failed)| !failed || home.join(kept_failed(feed)).is_file())
    .map(|(etag, _)| etag);
    let dir = home.join(FOLDER);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Ok(Got::Failed(format!("cannot make {}: {e}", dir.display())));
    }
    let part = dir.join(format!("{}.zip.part", feed.source));
    let _ = std::fs::remove_file(&part);
    let child = Command::new(curl)
        .args(request(feed, &part, etag.as_deref()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(e) => return Ok(Got::Failed(format!("cannot run {}: {e}", curl.display()))),
    };
    let said = said(&mut child);
    let got = match child.wait() {
        Err(e) => Got::Failed(format!("curl did not finish: {e}")),
        Ok(status) => match threats::answer(status, &said, etag.is_some()) {
            Answer::Body(etag) => Got::Archive {
                path: part.clone(),
                etag,
                downloaded: true,
            },
            Answer::NotModified => Got::Unchanged,
            Answer::Failed(reason) => Got::Failed(reason),
        },
    };
    if !matches!(got, Got::Archive { .. }) {
        let _ = std::fs::remove_file(&part);
    }
    Ok(got)
}

/// What a process wrote to stderr, up to `SAID_CAP` bytes.
fn said(child: &mut Child) -> Vec<u8> {
    drain(child.stderr.take())
}

fn drain(stderr: Option<std::process::ChildStderr>) -> Vec<u8> {
    let mut said = Vec::new();
    if let Some(mut stderr) = stderr {
        let _ = (&mut stderr).take(SAID_CAP).read_to_end(&mut said);
        // Whatever is past the cap is drained, so the child can finish.
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    }
    said
}

/// What reading a feed changed in the advisories it holds. The first reading is a baseline.
#[derive(Default, Debug, PartialEq)]
pub struct Counts {
    pub first: bool,
    pub records: usize,
    /// Not held before, or held as gone.
    pub new: usize,
    /// Held, and its `modified` is not what it was.
    pub changed: usize,
    /// Of those changed, the ones withdrawn in this reading.
    pub withdrawn: usize,
    /// Held, and not in the archive any more.
    pub gone: usize,
}

/// One reading as `feed_reading` keeps it.
#[derive(Default)]
pub struct Reading {
    pub outcome: &'static str,
    pub reason: Option<String>,
    pub etag: Option<String>,
    pub sha256: Option<String>,
    pub raw_path: Option<String>,
    pub entries: Option<usize>,
}

fn put_reading(
    tx: &Transaction,
    source: &str,
    run_id: &str,
    at: i64,
    r: &Reading,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO feed_reading (source, run_id, at, outcome, reason, etag, sha256,
                                   raw_path, entries)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            source,
            run_id,
            at,
            r.outcome,
            r.reason,
            r.etag,
            r.sha256,
            r.raw_path,
            r.entries.map(|n| n as i64)
        ],
    )?;
    Ok(())
}

/// The latest reading of a feed that read it or found it unchanged.
fn last_good(tx: &Transaction, source: &str) -> rusqlite::Result<Option<Reading>> {
    tx.query_row(
        "SELECT sha256, raw_path, entries FROM feed_reading
         WHERE source = ?1 AND outcome != 'failed' ORDER BY id DESC LIMIT 1",
        [source],
        |r| {
            Ok(Reading {
                sha256: r.get(0)?,
                raw_path: r.get(1)?,
                entries: r.get::<_, Option<i64>>(2)?.map(|n| n as usize),
                ..Reading::default()
            })
        },
    )
    .optional()
}

/// The latest reading that brought an archive with an ETag, its outcome and its reason.
fn last_with_etag(tx: &Transaction, source: &str) -> rusqlite::Result<Option<(String, String)>> {
    tx.query_row(
        "SELECT outcome, COALESCE(reason, '') FROM feed_reading
         WHERE source = ?1 AND etag IS NOT NULL ORDER BY id DESC LIMIT 1",
        [source],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

/// What the store holds of a feed now: records present, and of them malicious and withdrawn.
pub fn held(conn: &Connection, source: &str) -> rusqlite::Result<(usize, usize, usize)> {
    conn.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(kind = 'malicious' AND withdrawn IS NULL), 0),
                COALESCE(SUM(withdrawn IS NOT NULL), 0)
         FROM advisory WHERE source = ?1 AND gone_at IS NULL",
        [source],
        |r| {
            Ok((
                r.get::<_, i64>(0)? as usize,
                r.get::<_, i64>(1)? as usize,
                r.get::<_, i64>(2)? as usize,
            ))
        },
    )
}

/// Records what was got for a feed, in the run's transaction. A reading that failed changes
/// no advisory. An archive read whole is kept, with its lines (see `kept`).
pub fn record(
    tx: &Transaction,
    run_id: &str,
    at: i64,
    home: &Path,
    feed: &Feed,
    got: Got,
) -> Result<(), Box<dyn std::error::Error>> {
    let put = |r: Reading| put_reading(tx, feed.source, run_id, at, &r);
    let failed = |reason: String| Reading {
        outcome: "failed",
        reason: Some(reason),
        ..Reading::default()
    };
    let (path, etag, downloaded) = match got {
        Got::NotDue => return Ok(()),
        Got::Failed(reason) => {
            put(failed(reason))?;
            return Ok(());
        }
        Got::Unchanged => match last_with_etag(tx, feed.source)? {
            // The archive that failed has not changed: it is read again, never taken as good.
            Some((outcome, _)) if outcome == "failed" => (
                home.join(kept_failed(feed)),
                last_etag(tx, feed.source)?.map(|(e, _)| e),
                false,
            ),
            _ => {
                let before = last_good(tx, feed.source)?.unwrap_or_default();
                put(Reading {
                    outcome: "unchanged",
                    etag: last_etag(tx, feed.source)?.map(|(e, _)| e),
                    entries: Some(held(tx, feed.source)?.0),
                    ..before
                })?;
                return Ok(());
            }
        },
        Got::Archive {
            path,
            etag,
            downloaded,
        } => (path, etag, downloaded),
    };
    let failed_path = home.join(kept_failed(feed));
    let reread = path == failed_path;
    let sha = match archive_sha(&path, feed.cap) {
        Ok(sha) => sha,
        Err(reason) => {
            if downloaded {
                let _ = std::fs::remove_file(&path);
            }
            put(Reading {
                etag: None,
                ..failed(reason)
            })?;
            return Ok(());
        }
    };
    // The same bytes as the archive last read: nothing to read again.
    if let Some(before) = last_good(tx, feed.source)?
        && before.sha256.as_deref() == Some(sha.as_str())
    {
        if downloaded {
            let _ = std::fs::remove_file(&path);
        }
        put(Reading {
            outcome: "unchanged",
            etag,
            entries: Some(held(tx, feed.source)?.0),
            ..before
        })?;
        return Ok(());
    }
    match ingest(tx, run_id, at, feed, &path, STREAM_CAP, RECORD_CAP)? {
        Err(reason) => {
            // Kept for a look, and for the next conditional request.
            let raw_path = if downloaded || reread {
                if !reread {
                    std::fs::rename(&path, &failed_path)?;
                }
                Some(kept_failed(feed))
            } else {
                None
            };
            put(Reading {
                outcome: "failed",
                reason: Some(reason),
                etag: etag.filter(|_| raw_path.is_some()),
                sha256: Some(sha),
                raw_path,
                entries: None,
            })?;
            Ok(())
        }
        Ok((counts, lines)) => {
            let keep = home.join(kept(feed));
            if downloaded || reread {
                std::fs::rename(&path, &keep)?;
            } else {
                std::fs::create_dir_all(home.join(FOLDER))?;
                std::fs::copy(&path, &keep)?;
            }
            let _ = std::fs::remove_file(&failed_path);
            // What was read, one line per record, in place of the one before.
            let lines_at = home.join(kept_lines(feed));
            let part = lines_at.with_extension("txt.part");
            std::fs::write(&part, &lines)?;
            std::fs::rename(&part, &lines_at)?;
            let text = json!({
                "first": counts.first,
                "records": counts.records,
                "new": counts.new,
                "changed": counts.changed,
                "withdrawn": counts.withdrawn,
                "gone": counts.gone,
            });
            tx.execute(
                "INSERT INTO journal (at, run_id, entry, reader, text)
                 VALUES (?1, ?2, 'advisories_read', ?3, ?4)",
                params![at, run_id, feed.source, text.to_string()],
            )?;
            put(Reading {
                outcome: "read",
                reason: None,
                etag,
                sha256: Some(sha),
                raw_path: Some(kept(feed)),
                entries: Some(counts.records),
            })?;
            Ok(())
        }
    }
}

/// The SHA-256 of the archive, if it is a zip archive under the cap. Read in pieces, so that
/// the archive is never held in memory.
fn archive_sha(path: &Path, cap: u64) -> Result<String, String> {
    let cannot = |e: std::io::Error| format!("cannot read {}: {e}", path.display());
    let mut file = std::fs::File::open(path).map_err(cannot)?.take(cap + 1);
    let mut hasher = sha256::Hasher::new();
    let mut piece = vec![0u8; 1024 * 1024];
    let (mut total, mut head) = (0u64, Vec::<u8>::with_capacity(4));
    loop {
        let n = match file.read(&mut piece) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(cannot(e)),
        };
        let want = 4 - head.len();
        head.extend(piece[..n].iter().take(want));
        hasher.update(&piece[..n]);
        total += n as u64;
    }
    if total > cap {
        return Err(format!("the archive is larger than the cap of {cap} bytes"));
    }
    if head != b"PK\x03\x04" {
        return Err("not a zip archive".to_string());
    }
    Ok(hasher.hex())
}

/// Why a reading stopped: the feed, named for a person, or the store.
pub enum Stop {
    Feed(String),
    Store(rusqlite::Error),
}

impl From<rusqlite::Error> for Stop {
    fn from(e: rusqlite::Error) -> Stop {
        Stop::Store(e)
    }
}

impl From<String> for Stop {
    fn from(reason: String) -> Stop {
        Stop::Feed(reason)
    }
}

/// Reads every record of an archive into the advisories, inside a savepoint of the run's
/// transaction, so that a reading that fails halfway writes nothing. Returns what it changed
/// and the lines of what it read; a reason when the feed failed.
type Ingested = (Counts, Vec<u8>);

fn ingest(
    tx: &Transaction,
    run_id: &str,
    at: i64,
    feed: &Feed,
    archive: &Path,
    stream_cap: u64,
    record_cap: usize,
) -> rusqlite::Result<Result<Ingested, String>> {
    tx.execute_batch("SAVEPOINT advisories")?;
    let done = write_all(tx, run_id, at, feed, archive, stream_cap, record_cap);
    match done {
        Ok(ok) => {
            tx.execute_batch("RELEASE advisories")?;
            Ok(Ok(ok))
        }
        Err(stop) => {
            tx.execute_batch("ROLLBACK TO advisories; RELEASE advisories")?;
            match stop {
                Stop::Feed(reason) => Ok(Err(reason)),
                Stop::Store(e) => Err(e),
            }
        }
    }
}

/// What the store held of one advisory before this reading.
struct Held {
    modified: String,
    withdrawn: bool,
    gone: bool,
}

fn write_all(
    tx: &Transaction,
    run_id: &str,
    at: i64,
    feed: &Feed,
    archive: &Path,
    stream_cap: u64,
    record_cap: usize,
) -> Result<Ingested, Stop> {
    let held: HashMap<String, Held> = tx
        .prepare(
            "SELECT id, modified, withdrawn IS NOT NULL, gone_at IS NOT NULL FROM advisory
             WHERE source = ?1",
        )?
        .query_map([feed.source], |r| {
            Ok((
                r.get(0)?,
                Held {
                    modified: r.get(1)?,
                    withdrawn: r.get(2)?,
                    gone: r.get(3)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut counts = Counts {
        first: held.is_empty(),
        ..Counts::default()
    };
    let mut lines: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut writer = Writer::new(tx)?;
    let records = each_record(archive, stream_cap, record_cap, |text, record| {
        let sha = sha256::hex(text);
        lines.push(format!("{}\t{}\t{sha}\n", record.id, record.modified));
        let before = held.get(&record.id);
        let write = match before {
            None => {
                counts.new += 1;
                true
            }
            Some(h) if h.gone => {
                counts.new += 1;
                true
            }
            Some(h) if h.modified != record.modified => {
                if !h.withdrawn && record.withdrawn.is_some() {
                    counts.withdrawn += 1;
                }
                counts.changed += 1;
                true
            }
            Some(_) => false,
        };
        if write {
            put_advisory(&mut writer, run_id, at, feed, &record, before.is_some())?;
        }
        seen.insert(record.id);
        Ok(())
    })?;
    let mut gone = tx
        .prepare("UPDATE advisory SET gone_at = ?1, gone_run = ?2 WHERE source = ?3 AND id = ?4")?;
    for (id, _) in held.iter().filter(|(id, h)| !h.gone && !seen.contains(*id)) {
        gone.execute(params![at, run_id, feed.source, id])?;
        counts.gone += 1;
    }
    counts.records = records;
    if counts.first {
        // The first reading is the baseline: nothing in it is news.
        counts.new = 0;
    }
    lines.sort();
    Ok((counts, lines.concat().into_bytes()))
}

/// The statements that write advisories, prepared once for a reading.
struct Writer<'a> {
    upsert: rusqlite::Statement<'a>,
    delete: rusqlite::Statement<'a>,
    insert: rusqlite::Statement<'a>,
}

impl<'a> Writer<'a> {
    fn new(tx: &'a Transaction) -> rusqlite::Result<Writer<'a>> {
        Ok(Writer {
            upsert: tx.prepare(UPSERT)?,
            delete: tx
                .prepare("DELETE FROM advisory_affects WHERE source = ?1 AND advisory = ?2")?,
            insert: tx.prepare(
                "INSERT INTO advisory_affects (source, advisory, ecosystem, name, normalized,
                                               ranges, versions, informational)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?,
        })
    }
}

const UPSERT: &str =
    "INSERT INTO advisory (source, id, modified, withdrawn, kind, summary, severity, cvss,
                               aliases, cwe_ids, first_run, first_seen_at, written_run,
                               written_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?11, ?12)
         ON CONFLICT (source, id) DO UPDATE SET
             modified = excluded.modified, withdrawn = excluded.withdrawn,
             kind = excluded.kind, summary = excluded.summary, severity = excluded.severity,
             cvss = excluded.cvss, aliases = excluded.aliases, cwe_ids = excluded.cwe_ids,
             written_run = excluded.written_run,
             written_at = excluded.written_at, gone_at = NULL, gone_run = NULL";

/// Writes one advisory as the record gives it now, and replaces what it affects.
fn put_advisory(
    w: &mut Writer,
    run_id: &str,
    at: i64,
    feed: &Feed,
    r: &Record,
    held: bool,
) -> rusqlite::Result<()> {
    let cvss: Vec<Value> = r
        .severity
        .iter()
        .map(|(kind, score)| json!({ "type": kind, "score": score }))
        .collect();
    w.upsert.execute(params![
        feed.source,
        r.id,
        r.modified,
        r.withdrawn,
        r.kind(),
        r.summary,
        r.label,
        Value::from(cvss).to_string(),
        json!(r.aliases).to_string(),
        json!(r.cwe_ids).to_string(),
        run_id,
        at
    ])?;
    if held {
        w.delete.execute(params![feed.source, r.id])?;
    }
    // Only the feed's own ecosystem: a record that also affects another is in that
    // ecosystem's feed too, and is answered from there.
    for a in r.affected.iter().filter(|a| a.ecosystem == feed.ecosystem) {
        let ranges: Vec<Value> = a
            .ranges
            .iter()
            .map(|range| {
                let events: Vec<Value> = range
                    .events
                    .iter()
                    .map(|(event, version)| json!({ *event: version }))
                    .collect();
                let mut v = json!({ "type": range.kind, "events": events });
                if let Some(repo) = &range.repo {
                    v["repo"] = json!(repo);
                }
                v
            })
            .collect();
        w.insert.execute(params![
            feed.source,
            r.id,
            a.ecosystem,
            a.name,
            normalized(feed.ecosystem, &a.name),
            Value::from(ranges).to_string(),
            json!(a.versions).to_string(),
            a.informational
        ])?;
    }
    Ok(())
}

/// The name a lockfile's name is compared with: crates.io compares names without case and
/// with `_` as `-`, as Cargo does; npm compares them exactly.
pub fn normalized(ecosystem: &str, name: &str) -> String {
    if ecosystem == "crates.io" {
        name.to_ascii_lowercase().replace('_', "-")
    } else {
        name.to_string()
    }
}

// ---- Unpacking and checking an archive. ----

/// bsdtar with an empty environment, so that nothing such as `TAR_READER_OPTIONS` changes how
/// it reads, and nothing to read on stdin.
fn bsdtar(args: &[&str], archive: &Path) -> Command {
    let mut cmd = Command::new(BSDTAR);
    cmd.env_clear()
        .args(args)
        .arg("-f")
        .arg(archive)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Reads stderr of a child on a thread, so that a child that says much is never stuck.
fn stderr_of(child: &mut Child) -> std::thread::JoinHandle<Vec<u8>> {
    let stderr = child.stderr.take();
    std::thread::spawn(move || drain(stderr))
}

/// That bsdtar finished cleanly: exit 0 and nothing said. A warning is a failure too.
fn finished(child: &mut Child, said: std::thread::JoinHandle<Vec<u8>>) -> Result<(), String> {
    let status = child
        .wait()
        .map_err(|e| format!("bsdtar did not finish: {e}"))?;
    let said = said.join().unwrap_or_default();
    let first = String::from_utf8_lossy(&said);
    let first = first.lines().map(str::trim).find(|l| !l.is_empty());
    match (status.success(), first) {
        (true, None) => Ok(()),
        (_, Some(line)) => Err(format!("bsdtar said: {}", cut(line))),
        (false, None) => Err(format!("bsdtar failed, {status}")),
    }
}

/// Text from the feed or a tool, cut to a length that fits a reason.
fn cut(text: &str) -> String {
    const MOST: usize = 120;
    if text.chars().count() <= MOST {
        return text.to_string();
    }
    let mut s: String = text.chars().take(MOST - 1).collect();
    s.push('…');
    s
}

/// An id as the OSV schema allows it: `^[a-zA-Z0-9:_.-]+$`.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
}

/// The ids the archive's own listing names: every entry must be `<id>.json` at the top
/// level, once.
fn listed_ids(archive: &Path) -> Result<HashSet<String>, String> {
    let mut child = bsdtar(&["-t"], archive)
        .spawn()
        .map_err(|e| format!("cannot run {BSDTAR}: {e}"))?;
    let said = stderr_of(&mut child);
    let mut listing = Vec::new();
    let read = child
        .stdout
        .take()
        .expect("stdout is piped")
        .take(LISTING_CAP + 1)
        .read_to_end(&mut listing);
    if read.is_err() || listing.len() as u64 > LISTING_CAP {
        let _ = child.kill();
        let _ = finished(&mut child, said);
        return Err(format!(
            "the archive's listing is larger than the cap of {LISTING_CAP} bytes"
        ));
    }
    finished(&mut child, said)?;
    let listing = String::from_utf8_lossy(&listing);
    let mut ids = HashSet::new();
    for name in listing.split_terminator('\n') {
        let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) else {
            return Err(format!(
                "an entry of the archive is not a record: {}",
                cut(name)
            ));
        };
        if !ids.insert(id.to_string()) {
            return Err(format!("the archive holds {id}.json more than once"));
        }
    }
    if ids.is_empty() {
        return Err("the archive holds no records".to_string());
    }
    Ok(ids)
}

/// Calls `each` with every record of the archive, its text and its parsed form, one record in
/// memory at a time, and returns how many there were. The archive's own listing must name
/// exactly the records it holds, one entry each: no record is added, lost, doubled or merged
/// unnoticed. Unpacked to stdout only, under `stream_cap` bytes in all and `record_cap` each.
pub fn each_record(
    archive: &Path,
    stream_cap: u64,
    record_cap: usize,
    mut each: impl FnMut(&[u8], Record) -> Result<(), Stop>,
) -> Result<usize, Stop> {
    let ids = listed_ids(archive)?;
    let mut child = bsdtar(&["-x", "-O"], archive)
        .spawn()
        .map_err(|e| format!("cannot run {BSDTAR}: {e}"))?;
    let said = stderr_of(&mut child);
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut seen = HashSet::new();
    let streamed = stream(stdout, stream_cap, record_cap, |text, value| {
        let record = parse(&value).map_err(Stop::Feed)?;
        if !ids.contains(&record.id) {
            return Err(Stop::Feed(format!(
                "record {} is not the record its entry names",
                record.id
            )));
        }
        if !seen.insert(record.id.clone()) {
            return Err(Stop::Feed(format!(
                "record {} is in the archive more than once",
                record.id
            )));
        }
        each(text, record)
    });
    if streamed.is_err() {
        let _ = child.kill();
    }
    let ended = finished(&mut child, said);
    streamed?;
    ended?;
    let missing = ids.len() - seen.len();
    if missing > 0 {
        return Err(Stop::Feed(format!(
            "{missing} of the archive's {} entries hold no record",
            ids.len()
        )));
    }
    Ok(seen.len())
}

/// Splits a stream of JSON values written one after another into values, one at a time, each
/// with its own text. Records are self-delimiting objects, so no separator is needed between
/// them. What is buffered never holds more than one record and one chunk.
fn stream(
    mut from: impl Read,
    stream_cap: u64,
    record_cap: usize,
    mut each: impl FnMut(&[u8], Value) -> Result<(), Stop>,
) -> Result<(), Stop> {
    const CHUNK: usize = 256 * 1024;
    let too_large = || format!("a record is larger than the cap of {record_cap} bytes");
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK * 2);
    let (mut start, mut total, mut eof) = (0usize, 0u64, false);
    loop {
        let rest = &buf[start..];
        let blank = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if blank < rest.len() {
            let text = &rest[blank..];
            let mut values = serde_json::Deserializer::from_slice(text).into_iter::<Value>();
            match values.next() {
                Some(Ok(value)) => {
                    let len = values.byte_offset();
                    if len > record_cap {
                        return Err(Stop::Feed(too_large()));
                    }
                    each(&text[..len], value)?;
                    start += blank + len;
                    continue;
                }
                Some(Err(e)) if !(e.is_eof() && !eof) => {
                    return Err(Stop::Feed(format!("a record is not JSON: {e}")));
                }
                _ => {}
            }
        } else if eof {
            return Ok(());
        }
        // More is needed: the rest is blank or a record not yet whole.
        if buf.len() - start > record_cap {
            return Err(Stop::Feed(too_large()));
        }
        buf.drain(..start);
        start = 0;
        let filled = buf.len();
        buf.resize(filled + CHUNK, 0);
        let n = loop {
            match from.read(&mut buf[filled..]) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Stop::Feed(format!("the archive could not be read: {e}"))),
            }
        };
        buf.truncate(filled + n);
        total += n as u64;
        if total > stream_cap {
            return Err(Stop::Feed(format!(
                "the unpacked records are larger than the cap of {stream_cap} bytes"
            )));
        }
        eof = n == 0;
    }
}

// ---- The shape of a record. ----

/// The fields of an OSV record that are kept, in a fixed shape. Unknown fields are ignored.
pub struct Record {
    pub id: String,
    pub modified: String,
    pub withdrawn: Option<String>,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// `severity[]`: the kind of score and the vector.
    pub severity: Vec<(String, String)>,
    /// GitHub's label, `database_specific.severity`.
    pub label: Option<String>,
    pub cwe_ids: Vec<String>,
    pub affected: Vec<Affected>,
}

pub struct Affected {
    pub ecosystem: String,
    pub name: String,
    pub ranges: Vec<Range>,
    pub versions: Vec<String>,
    /// RustSec's `affected[].database_specific.informational`, such as `unmaintained`.
    pub informational: Option<String>,
}

pub struct Range {
    pub kind: String,
    pub repo: Option<String>,
    /// Each event's one key, `introduced`, `fixed`, `last_affected` or `limit`, and its
    /// value, in the record's order.
    pub events: Vec<(&'static str, String)>,
}

const EVENTS: [&str; 4] = ["introduced", "fixed", "last_affected", "limit"];

impl Record {
    /// Malicious for a `MAL-` id or CWE-506, "embedded malicious code"; informational where
    /// RustSec says so; otherwise a vulnerability.
    pub fn kind(&self) -> &'static str {
        if self.id.starts_with("MAL-") || self.cwe_ids.iter().any(|c| c == "CWE-506") {
            "malicious"
        } else if self.affected.iter().any(|a| a.informational.is_some()) {
            "informational"
        } else {
            "vulnerability"
        }
    }
}

/// A field, or `None` when it is absent or null.
fn field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key).filter(|f| !f.is_null())
}

fn text(v: &Value, key: &str, id: &str) -> Result<Option<String>, String> {
    match field(v, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(out_of_shape(id, key)),
    }
}

fn texts(v: &Value, key: &str, id: &str) -> Result<Vec<String>, String> {
    let Some(list) = field(v, key) else {
        return Ok(Vec::new());
    };
    list.as_array()
        .ok_or_else(|| out_of_shape(id, key))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_string)
                .ok_or_else(|| out_of_shape(id, key))
        })
        .collect()
}

fn list<'a>(v: &'a Value, key: &str, id: &str) -> Result<&'a [Value], String> {
    match field(v, key) {
        None => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(out_of_shape(id, key)),
    }
}

fn object<'a>(v: &'a Value, key: &str, id: &str) -> Result<Option<&'a Value>, String> {
    match field(v, key) {
        None => Ok(None),
        Some(o) if o.is_object() => Ok(Some(o)),
        Some(_) => Err(out_of_shape(id, key)),
    }
}

fn out_of_shape(id: &str, key: &str) -> String {
    format!("record {id} is out of shape: {key}")
}

/// A time as OSV writes it: RFC 3339 in UTC, `2026-11-11T15:50:00Z`, with or without a
/// fraction of a second.
fn utc_time(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    let shape = digits(0..4)
        && at(4, b'-')
        && digits(5..7)
        && at(7, b'-')
        && digits(8..10)
        && at(10, b'T')
        && digits(11..13)
        && at(13, b':')
        && digits(14..16)
        && at(16, b':')
        && digits(17..19);
    let rest = s.get(19..).unwrap_or_default();
    let fraction = match rest.strip_prefix('.') {
        Some(f) => f
            .strip_suffix('Z')
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())),
        None => rest == "Z",
    };
    shape && fraction
}

/// A record in the fixed shape, or why it is not. Anything out of shape fails the whole
/// reading: a reading that dropped a record would mark it gone.
pub fn parse(v: &Value) -> Result<Record, String> {
    if !v.is_object() {
        return Err("a record is not a JSON object".to_string());
    }
    let id = match field(v, "id") {
        Some(Value::String(id)) if valid_id(id) => id.clone(),
        _ => return Err("a record has no valid id".to_string()),
    };
    let id = id.as_str();
    let time = |key: &str| -> Result<Option<String>, String> {
        let t = text(v, key, id)?;
        match t {
            Some(t) if !utc_time(&t) => Err(out_of_shape(id, key)),
            t => Ok(t),
        }
    };
    let modified = time("modified")?.ok_or_else(|| out_of_shape(id, "modified"))?;
    let withdrawn = time("withdrawn")?;
    let mut severity = Vec::new();
    for s in list(v, "severity", id)? {
        let kind = text(s, "type", id)?.ok_or_else(|| out_of_shape(id, "severity"))?;
        let score = text(s, "score", id)?.ok_or_else(|| out_of_shape(id, "severity"))?;
        severity.push((kind, score));
    }
    let specific = object(v, "database_specific", id)?;
    let (label, cwe_ids) = match specific {
        Some(d) => (text(d, "severity", id)?, texts(d, "cwe_ids", id)?),
        None => (None, Vec::new()),
    };
    let mut affected = Vec::new();
    for a in list(v, "affected", id)? {
        if !a.is_object() {
            return Err(out_of_shape(id, "affected"));
        }
        // The schema lets an affected entry name no package, as for a range of commits alone.
        // It names nothing a lockfile holds, so there is nothing of it to keep.
        let Some(package) = object(a, "package", id)? else {
            continue;
        };
        let ecosystem =
            text(package, "ecosystem", id)?.ok_or_else(|| out_of_shape(id, "package"))?;
        let name = text(package, "name", id)?
            .filter(|n| !n.is_empty())
            .ok_or_else(|| out_of_shape(id, "package"))?;
        let mut ranges = Vec::new();
        for r in list(a, "ranges", id)? {
            let kind = text(r, "type", id)?.ok_or_else(|| out_of_shape(id, "ranges"))?;
            let repo = text(r, "repo", id)?;
            let mut events = Vec::new();
            for e in list(r, "events", id)? {
                let mut one = EVENTS
                    .iter()
                    .filter_map(|key| e.get(*key).map(|value| (*key, value)));
                let (Some((key, Value::String(value))), None) = (one.next(), one.next()) else {
                    return Err(out_of_shape(id, "events"));
                };
                events.push((key, value.clone()));
            }
            ranges.push(Range { kind, repo, events });
        }
        let informational = match object(a, "database_specific", id)? {
            Some(d) => text(d, "informational", id)?,
            None => None,
        };
        affected.push(Affected {
            ecosystem,
            name,
            ranges,
            versions: texts(a, "versions", id)?,
            informational,
        });
    }
    Ok(Record {
        id: id.to_string(),
        modified,
        withdrawn,
        aliases: texts(v, "aliases", id)?,
        summary: text(v, "summary", id)?,
        severity,
        label,
        cwe_ids,
        affected,
    })
}

// ---- What a person and an agent are told. ----

/// The state of one feed after a run, from the store alone.
pub struct State {
    pub feed: &'static Feed,
    /// The latest reading: its run, when, its outcome and reason. `None`: never asked.
    pub latest: Option<(String, i64, String, Option<String>)>,
    /// When it was last read successfully, and when its content last changed.
    pub good_at: Option<i64>,
    pub changed_at: Option<i64>,
    pub records: usize,
    pub malicious: usize,
    pub withdrawn: usize,
    /// What the latest reading that read an archive changed, from its journal entry.
    pub counts: Option<Counts>,
}

impl State {
    /// Whether the run asked for this feed: a run that did not had its last good reading
    /// recent enough.
    pub fn asked_in(&self, run_id: &str) -> bool {
        self.latest.as_ref().is_some_and(|(run, ..)| run == run_id)
    }
}

/// The state of every feed.
pub fn states(conn: &Connection) -> rusqlite::Result<Vec<State>> {
    let has_tables = has_tables(conn)?;
    let mut out = Vec::new();
    for feed in &FEEDS {
        if !has_tables {
            out.push(State {
                feed,
                latest: None,
                good_at: None,
                changed_at: None,
                records: 0,
                malicious: 0,
                withdrawn: 0,
                counts: None,
            });
            continue;
        }
        let latest = conn
            .query_row(
                "SELECT run_id, at, outcome, reason FROM feed_reading
                 WHERE source = ?1 ORDER BY id DESC LIMIT 1",
                [feed.source],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let changed: Option<(i64, String)> = conn
            .query_row(
                "SELECT at, run_id FROM feed_reading
                 WHERE source = ?1 AND outcome = 'read' ORDER BY id DESC LIMIT 1",
                [feed.source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let counts = match &changed {
            None => None,
            Some((_, run)) => conn
                .query_row(
                    "SELECT text FROM journal
                     WHERE entry = 'advisories_read' AND reader = ?1 AND run_id = ?2
                     ORDER BY seq DESC LIMIT 1",
                    params![feed.source, run],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .map(|v| {
                    let n = |k: &str| v[k].as_u64().unwrap_or_default() as usize;
                    Counts {
                        first: v["first"].as_bool().unwrap_or_default(),
                        records: n("records"),
                        new: n("new"),
                        changed: n("changed"),
                        withdrawn: n("withdrawn"),
                        gone: n("gone"),
                    }
                }),
        };
        let (records, malicious, withdrawn) = held(conn, feed.source)?;
        out.push(State {
            feed,
            latest,
            good_at: last_good_at(conn, feed.source)?,
            changed_at: changed.map(|(at, _)| at),
            records,
            malicious,
            withdrawn,
            counts,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Record, STREAM_CAP, Stop, archive_sha, each_record, normalized, parse, stream};
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// A folder of its own for one test, removed after it.
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Dir {
            let dir = std::env::temp_dir().join(format!("immune-osv-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A public record from the test fixtures, as OSV serves it.
    fn record(ecosystem: &str, id: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/osv")
            .join(ecosystem)
            .join(format!("{id}.json"));
        std::fs::read(path).unwrap()
    }

    const NPM: [&str; 4] = [
        "GHSA-2275-rpf5-xv8h",
        "GHSA-f29h-pxvx-f335",
        "MAL-2021-1",
        "MAL-2025-47141",
    ];

    /// What an entry of a test archive is.
    enum Entry {
        Text(Vec<u8>),
        Link(&'static str),
    }

    /// A zip archive made by bsdtar, with these entries in this order, names as given.
    fn zip(dir: &Path, name: &str, entries: Vec<(&str, Entry)>) -> PathBuf {
        let mut cmd = Command::new("/usr/bin/bsdtar");
        cmd.args(["-c", "--format", "zip"]);
        let mut files = Vec::new();
        for (i, (entry_name, entry)) in entries.into_iter().enumerate() {
            let folder = dir.join(format!("{name}-src/{i}"));
            std::fs::create_dir_all(&folder).unwrap();
            let file = format!("e{i}");
            match entry {
                Entry::Text(bytes) => std::fs::write(folder.join(&file), bytes).unwrap(),
                Entry::Link(target) => {
                    std::os::unix::fs::symlink(target, folder.join(&file)).unwrap()
                }
            }
            cmd.arg("-s").arg(format!("|^{file}$|{entry_name}|"));
            files.push((folder, file));
        }
        let out = dir.join(name);
        cmd.arg("-f").arg(&out);
        for (folder, file) in files {
            cmd.arg("-C").arg(folder).arg(file);
        }
        assert!(cmd.status().unwrap().success());
        out
    }

    /// A hostile archive: what it is, the entries added to good ones, and the reason it fails.
    type Case<'a> = (&'a str, Vec<(&'a str, Entry)>, &'a str);

    /// The four npm records, each under its own name, and these entries after them.
    fn npm_zip(dir: &Path, name: &str, more: Vec<(&str, Entry)>) -> PathBuf {
        let names: Vec<String> = NPM.iter().map(|id| format!("{id}.json")).collect();
        let mut entries: Vec<(&str, Entry)> = names
            .iter()
            .zip(NPM)
            .map(|(n, id)| (n.as_str(), Entry::Text(record("npm", id))))
            .collect();
        entries.extend(more);
        zip(dir, name, entries)
    }

    /// The ids read, in order, or why the reading failed.
    fn read(archive: &Path, stream_cap: u64, record_cap: usize) -> Result<Vec<String>, String> {
        let mut ids = Vec::new();
        let n = each_record(archive, stream_cap, record_cap, |_, r| {
            ids.push(r.id);
            Ok(())
        })
        .map_err(|stop| match stop {
            Stop::Feed(reason) => reason,
            Stop::Store(e) => panic!("{e}"),
        })?;
        assert_eq!(n, ids.len());
        Ok(ids)
    }

    #[test]
    fn an_archive_whose_entries_are_not_its_records_one_for_one_fails_the_whole_reading() {
        // A reading that took a record twice, lost one or took one under another's name
        // would mark records gone or keep a false one; any of these fails the reading, and
        // the data read before stays in force.
        let dir = Dir::new("entries");
        let good = npm_zip(&dir.0, "good.zip", vec![]);
        assert_eq!(read(&good, STREAM_CAP, super::RECORD_CAP).unwrap(), NPM);
        let mal = || Entry::Text(record("npm", "MAL-2021-1"));
        let cases: Vec<Case> = vec![
            (
                "added",
                vec![(
                    "GHSA-0000-0000-0000.json",
                    Entry::Text(record("npm", "GHSA-2299-ghjr-6vjp")),
                )],
                "record GHSA-2299-ghjr-6vjp is not the record its entry names",
            ),
            (
                "copied under another name",
                vec![("GHSA-0000-0000-0000.json", mal())],
                "record MAL-2021-1 is in the archive more than once",
            ),
            (
                "missing",
                vec![("GHSA-0000-0000-0000.json", Entry::Text(Vec::new()))],
                "1 of the archive's 5 entries hold no record",
            ),
            (
                "doubled",
                vec![("MAL-2021-1.json", mal())],
                "the archive holds MAL-2021-1.json more than once",
            ),
            (
                "not a record",
                vec![("README.txt", Entry::Text(b"hello".to_vec()))],
                "an entry of the archive is not a record: README.txt",
            ),
            (
                "up a folder",
                vec![("../GHSA-0000-0000-0000.json", mal())],
                "an entry of the archive is not a record: ../GHSA-0000-0000-0000.json",
            ),
            (
                "in a folder",
                vec![("x/GHSA-0000-0000-0000.json", mal())],
                "an entry of the archive is not a record: x/GHSA-0000-0000-0000.json",
            ),
            (
                "a link",
                vec![("GHSA-0000-0000-0000.json", Entry::Link("/etc/hosts"))],
                "1 of the archive's 5 entries hold no record",
            ),
        ];
        for (case, more, reason) in cases {
            let archive = npm_zip(&dir.0, &format!("{case}.zip"), more);
            assert_eq!(
                read(&archive, STREAM_CAP, super::RECORD_CAP),
                Err(reason.to_string()),
                "{case}"
            );
        }
        // One entry that holds two records, the second under no name of its own.
        let mut merged = record("npm", "MAL-2021-1");
        merged.extend(record("npm", "GHSA-2275-rpf5-xv8h"));
        let archive = zip(
            &dir.0,
            "merged.zip",
            vec![("MAL-2021-1.json", Entry::Text(merged))],
        );
        assert_eq!(
            read(&archive, STREAM_CAP, super::RECORD_CAP),
            Err("record GHSA-2275-rpf5-xv8h is not the record its entry names".to_string())
        );
        // A truncated archive, and a file that is not one.
        let bytes = std::fs::read(&good).unwrap();
        let cut = dir.0.join("cut.zip");
        std::fs::write(&cut, &bytes[..bytes.len() / 2]).unwrap();
        let said = read(&cut, STREAM_CAP, super::RECORD_CAP).unwrap_err();
        assert!(said.starts_with("bsdtar"), "{said}");
        let html = dir.0.join("page.zip");
        std::fs::write(&html, "<html>Service unavailable</html>").unwrap();
        assert_eq!(
            archive_sha(&html, 1024).err().as_deref(),
            Some("not a zip archive")
        );
    }

    #[test]
    fn an_archive_or_its_records_over_their_caps_are_not_read() {
        // The archive comes from the network: however it arrives, it is not read past what
        // the real one could be, and no record is held in memory past its cap.
        let dir = Dir::new("caps");
        let good = npm_zip(&dir.0, "good.zip", vec![]);
        let size = std::fs::metadata(&good).unwrap().len();
        // Hashed in pieces, the archive's hash is the hash of its whole bytes.
        let whole = crate::sha256::hex(&std::fs::read(&good).unwrap());
        assert_eq!(archive_sha(&good, size), Ok(whole));
        // So is the hash of one larger than a piece, as npm's is.
        let mut bytes = b"PK\x03\x04".to_vec();
        bytes.extend((0..3 * 1024 * 1024 + 7).map(|i: u32| (i % 251) as u8));
        let large = dir.0.join("large.zip");
        std::fs::write(&large, &bytes).unwrap();
        assert_eq!(
            archive_sha(&large, bytes.len() as u64),
            Ok(crate::sha256::hex(&bytes))
        );
        assert_eq!(
            archive_sha(&good, size - 1).err(),
            Some(format!(
                "the archive is larger than the cap of {} bytes",
                size - 1
            ))
        );
        let total: usize = NPM.iter().map(|id| record("npm", id).len()).sum();
        let largest = NPM.iter().map(|id| record("npm", id).len()).max().unwrap();
        assert_eq!(read(&good, total as u64, largest).unwrap().len(), 4);
        assert_eq!(
            read(&good, total as u64 - 1, largest),
            Err(format!(
                "the unpacked records are larger than the cap of {} bytes",
                total - 1
            ))
        );
        assert_eq!(
            read(&good, total as u64, largest - 1),
            Err(format!(
                "a record is larger than the cap of {} bytes",
                largest - 1
            ))
        );
    }

    /// A reader that gives at most a few bytes at a time, as a pipe may.
    struct Trickle<'a>(&'a [u8]);

    impl std::io::Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(7).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn records_written_one_after_another_are_read_one_each_with_their_own_text() {
        // The SHA-256 kept for each record is of exactly its text, wherever the pipe cut it,
        // and whitespace between records belongs to none of them.
        let records: Vec<Vec<u8>> = NPM.iter().map(|id| record("npm", id)).collect();
        let mut text = records.concat();
        text.extend(b"\n ");
        let mut seen = Vec::new();
        stream(
            Trickle(&text),
            STREAM_CAP,
            super::RECORD_CAP,
            |bytes, value| {
                seen.push((bytes.to_vec(), value["id"].as_str().unwrap().to_string()));
                Ok(())
            },
        )
        .map_err(|_| "failed")
        .unwrap();
        assert_eq!(
            seen.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            NPM
        );
        assert_eq!(
            seen.into_iter().map(|(b, _)| b).collect::<Vec<_>>(),
            records
        );
        // A stream that ends inside a record is not a record fewer.
        let cut = &text[..text.len() - 40];
        let stopped = stream(Trickle(cut), STREAM_CAP, super::RECORD_CAP, |_, _| Ok(()));
        assert!(matches!(stopped, Err(Stop::Feed(r)) if r.starts_with("a record is not JSON")));
    }

    fn with(mut v: Value, path: &[&str], value: Value) -> Value {
        let (last, head) = path.split_last().unwrap();
        let mut at = &mut v;
        for key in head {
            at = match key.parse::<usize>() {
                Ok(i) => &mut at[i],
                Err(_) => &mut at[*key],
            };
        }
        match last.parse::<usize>() {
            Ok(i) => at[i] = value,
            Err(_) => at[*last] = value,
        }
        v
    }

    fn reason(v: &Value) -> String {
        parse(v).err().unwrap_or_else(|| "parsed".to_string())
    }

    #[test]
    fn a_record_out_of_shape_is_refused_by_name_and_unknown_fields_are_ignored() {
        // A field the program keeps that is not in its shape fails the whole reading, so no
        // record is half read; a field it does not keep is never a reason to fail.
        let v: Value = serde_json::from_slice(&record("npm", "GHSA-2275-rpf5-xv8h")).unwrap();
        let r = parse(&with(v.clone(), &["anything_new"], json!({"x": [1]}))).unwrap();
        assert_eq!(r.id, "GHSA-2275-rpf5-xv8h");
        assert_eq!(r.modified, "2023-11-08T04:08:51.701195Z");
        assert_eq!(r.aliases, ["CVE-2022-25906"]);
        assert_eq!(r.label.as_deref(), Some("HIGH"));
        assert_eq!(r.cwe_ids, ["CWE-20", "CWE-78"]);
        assert_eq!(
            r.severity,
            [(
                "CVSS_V3".to_string(),
                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string()
            )]
        );
        let a = &r.affected[0];
        assert_eq!((a.ecosystem.as_str(), a.name.as_str()), ("npm", "is-http2"));
        assert_eq!(
            a.ranges[0].events,
            [
                ("introduced", "0".to_string()),
                ("last_affected", "1.2.0".to_string())
            ]
        );
        let out = |key: &str| format!("record GHSA-2275-rpf5-xv8h is out of shape: {key}");
        let cases = [
            (
                with(v.clone(), &["modified"], json!(20231108)),
                out("modified"),
            ),
            (with(v.clone(), &["modified"], Value::Null), out("modified")),
            (
                with(v.clone(), &["modified"], json!("2023-11-08 04:08:51")),
                out("modified"),
            ),
            (
                with(v.clone(), &["modified"], json!("2023-11-08T04:08:51+00:00")),
                out("modified"),
            ),
            (
                with(v.clone(), &["modified"], json!("2023-11-08T04:08:51.Z")),
                out("modified"),
            ),
            (
                with(v.clone(), &["withdrawn"], json!("yesterday")),
                out("withdrawn"),
            ),
            (with(v.clone(), &["summary"], json!(["a"])), out("summary")),
            (
                with(v.clone(), &["aliases"], json!("CVE-2022-25906")),
                out("aliases"),
            ),
            (with(v.clone(), &["aliases", "0"], json!(1)), out("aliases")),
            (
                with(v.clone(), &["severity", "0", "score"], json!(7.8)),
                out("score"),
            ),
            (
                with(v.clone(), &["database_specific"], json!("HIGH")),
                out("database_specific"),
            ),
            (
                with(
                    v.clone(),
                    &["database_specific", "cwe_ids"],
                    json!("CWE-20"),
                ),
                out("cwe_ids"),
            ),
            (
                with(v.clone(), &["affected", "0"], json!("is-http2")),
                out("affected"),
            ),
            (
                with(v.clone(), &["affected", "0", "package", "name"], json!("")),
                out("package"),
            ),
            (
                with(
                    v.clone(),
                    &["affected", "0", "package", "ecosystem"],
                    json!(1),
                ),
                out("ecosystem"),
            ),
            (
                with(
                    v.clone(),
                    &["affected", "0", "ranges", "0", "type"],
                    Value::Null,
                ),
                out("ranges"),
            ),
            (
                with(
                    v.clone(),
                    &["affected", "0", "ranges", "0", "events", "1"],
                    json!({"fixed": "1", "last_affected": "1"}),
                ),
                out("events"),
            ),
            (
                with(
                    v.clone(),
                    &["affected", "0", "ranges", "0", "events", "1"],
                    json!({"until": "1"}),
                ),
                out("events"),
            ),
            (
                with(
                    v.clone(),
                    &["affected", "0", "ranges", "0", "events", "1"],
                    json!({"fixed": 1}),
                ),
                out("events"),
            ),
            (
                with(v.clone(), &["affected", "0", "versions"], json!(["1.0", 2])),
                out("versions"),
            ),
            (
                with(v.clone(), &["id"], json!("GHSA/../x")),
                "a record has no valid id".to_string(),
            ),
            (
                with(v.clone(), &["id"], json!("")),
                "a record has no valid id".to_string(),
            ),
            (
                json!(["GHSA-2275-rpf5-xv8h"]),
                "a record is not a JSON object".to_string(),
            ),
        ];
        for (value, said) in cases {
            assert_eq!(reason(&value), said);
        }
        // Null is absent, and a record may name no package in an affected entry.
        let r = parse(&with(v.clone(), &["summary"], Value::Null)).unwrap();
        assert_eq!(r.summary, None);
        let r = parse(&with(v, &["affected", "0", "package"], Value::Null)).unwrap();
        assert!(r.affected.is_empty());
    }

    fn kind(ecosystem: &str, id: &str) -> &'static str {
        let v: Value = serde_json::from_slice(&record(ecosystem, id)).unwrap();
        let r: Record = parse(&v).unwrap();
        r.kind()
    }

    #[test]
    fn malicious_means_a_mal_id_or_cwe_506_and_rustsec_informational_is_told_apart() {
        // A malicious-package record is what makes a match urgent; GitHub reports malware
        // under its own ids with CWE-506, as for eslint-config-prettier.
        assert_eq!(kind("npm", "MAL-2021-1"), "malicious");
        assert_eq!(kind("npm", "GHSA-f29h-pxvx-f335"), "malicious");
        assert_eq!(kind("crates.io", "RUSTSEC-2016-0004"), "informational");
        assert_eq!(kind("npm", "GHSA-2275-rpf5-xv8h"), "vulnerability");
        assert_eq!(kind("npm", "GHSA-257q-pv89-v3xv"), "vulnerability");
    }

    #[test]
    fn a_crates_io_name_is_compared_as_cargo_compares_it_and_an_npm_name_exactly() {
        // Cargo takes `Foo_Bar` and `foo-bar` for one crate; npm's names are exact.
        assert_eq!(normalized("crates.io", "Foo_Bar"), "foo-bar");
        assert_eq!(normalized("npm", "Foo_Bar"), "Foo_Bar");
    }
}
