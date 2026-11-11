//! Matching: what the projects' lockfiles declare against the open vulnerability data of their
//! ecosystem (`osv.rs`), with the four answers of docs/threats.md. The research behind it is
//! docs/research/vulnerability-matching.md, sections 3 to 7.
//!
//! A match is the OSV schema's own `IsVulnerable`, on SemVer precedence, on an entry from the
//! ecosystem's public registry only. Versions are parsed strictly and never coerced. Whatever
//! cannot be compared is "don't know" with its reason from a closed list, never "not affected":
//! an entry not from the registry, a version or a range that is not strict SemVer, a release
//! above a record's `last_affected` with no fix, a lockfile reading that is partial or old, a
//! feed that is not current. "Affects me" wins over every reason.
//!
//! The answers are computed by every run and kept, each with what it rests on: the lockfile
//! and line, the record with its `modified`, the feed reading and its time. An answer that
//! changes between runs keeps the one before in `vulnerability_answer_past`, so the change can
//! be seen later; no event is made of it in this version.
//!
//! Text from a record is the feed's, partly written by anyone: it is returned only in `_text`
//! fields and escaped wherever it is shown, always with the record's id and its source.

use crate::osv::{FEEDS, Feed};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use semver::Version;
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The tables of the answers. Created on every open.
pub const SCHEMA: &str = "
-- One answer per advisory, checkout and package the checkout's lockfiles hold, as the latest
-- run gave it.
CREATE TABLE IF NOT EXISTS vulnerability_answer (
    checkout   TEXT NOT NULL,      -- the checkout's entity id
    ecosystem  TEXT NOT NULL,
    package    TEXT NOT NULL,      -- the package's name in the registry
    source     TEXT NOT NULL,      -- the feed, such as 'osv-npm'
    advisory   TEXT NOT NULL,
    modified   TEXT NOT NULL,      -- the record's `modified` the answer rests on
    answer     TEXT NOT NULL CHECK (answer IN ('affected', 'unknown', 'not_affected')),
    -- unknown: one of the closed list of reasons; not_affected: 'fixed' or 'not_in_range'
    reason     TEXT NOT NULL,
    detail     TEXT NOT NULL,      -- in the program's words
    entries    TEXT NOT NULL,      -- JSON: [{version, at, from, affected}], at as the lockfile's line
    fixed      TEXT NOT NULL,      -- JSON: the releases the record names as fixing it here
    reading    INTEGER,            -- the feed_reading the data rests on
    read_at    INTEGER,            -- when that reading was made, UTC seconds
    since_run  TEXT NOT NULL,      -- when this answer began
    since_at   INTEGER NOT NULL,
    run_id     TEXT NOT NULL,      -- the run that last gave it
    at         INTEGER NOT NULL,
    PRIMARY KEY (checkout, ecosystem, package, source, advisory)
);
-- An answer that changed or went, with when it stopped holding.
CREATE TABLE IF NOT EXISTS vulnerability_answer_past (
    checkout   TEXT NOT NULL,
    ecosystem  TEXT NOT NULL,
    package    TEXT NOT NULL,
    source     TEXT NOT NULL,
    advisory   TEXT NOT NULL,
    modified   TEXT NOT NULL,
    answer     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    entries    TEXT NOT NULL,
    fixed      TEXT NOT NULL,
    reading    INTEGER,
    read_at    INTEGER,
    since_run  TEXT NOT NULL,
    since_at   INTEGER NOT NULL,
    run_id     TEXT NOT NULL,
    at         INTEGER NOT NULL,
    until_run  TEXT NOT NULL,
    until_at   INTEGER NOT NULL
);
-- One row per checkout and matched ecosystem: whether the conditions for 'does not affect me,
-- known for certain' hold there, so the answer for any advisory is derived on demand.
CREATE TABLE IF NOT EXISTS vulnerability_place (
    checkout        TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    lockfiles       TEXT NOT NULL CHECK (lockfiles IN ('full', 'partial', 'not_read')),
    lockfiles_why   TEXT,
    feed            TEXT NOT NULL CHECK (feed IN ('current', 'not_current')),
    feed_why        TEXT,
    reading         INTEGER,
    read_at         INTEGER,
    run_id          TEXT NOT NULL,
    at              INTEGER NOT NULL,
    PRIMARY KEY (checkout, ecosystem)
);
-- The catalogue's exploited CVEs that records of the data are linked to through aliases.
CREATE TABLE IF NOT EXISTS vulnerability_linked (
    cve       TEXT NOT NULL,
    source    TEXT NOT NULL,
    advisory  TEXT NOT NULL,
    PRIMARY KEY (cve, source, advisory)
);
";

// ---- Why an answer is "don't know": a closed list. ----

/// The lockfile reading is missing, not from the latest check, or partial for this ecosystem.
pub const PLACE_NOT_READ: &str = "place_not_read";
/// The data set was not read whole within its limit, or its newest change is old.
pub const FEED_NOT_READ: &str = "feed_not_read";
/// An entry's version, or the record's range or versions, is not strict SemVer.
pub const NOT_COMPARABLE: &str = "version_cannot_be_compared";
/// Git, a path or a file, a link, or another registry.
pub const NOT_FROM_REGISTRY: &str = "not_from_registry";
/// The release is above the record's `last_affected`, and no fix is named.
pub const NOT_COVERED: &str = "data_does_not_cover_this_version";
/// An ecosystem for which no data set is fetched.
pub const NO_MATCHER: &str = "no_matcher";

/// Every reason, in the order one answer takes the first that applies: what is wrong with the
/// entry before what is wrong with the place, and the feed last.
pub const REASONS: [&str; 6] = [
    NOT_FROM_REGISTRY,
    NOT_COMPARABLE,
    NOT_COVERED,
    PLACE_NOT_READ,
    FEED_NOT_READ,
    NO_MATCHER,
];

/// How old the newest change of a data set may be for it to count as current.
const NEWEST_CHANGE: i64 = 7 * 86_400;

/// What "known for certain" speaks for, in its words.
pub const DECLARED: &str = "This speaks for what the project's lockfiles declare. What is installed in its node_modules, or what was built and deployed from it, can differ.";

// ---- Ordering versions. ----

/// A version as SemVer 2.0 writes it, strictly: three numbers, no leading `v`, no `=`, no
/// spaces. Anything else is `None` and is never coerced. The parser is the `semver` crate's.
pub fn version(s: &str) -> Option<Version> {
    Version::parse(s).ok()
}

/// SemVer precedence, build metadata disregarded (semver.org, item 11).
pub fn compare(a: &Version, b: &Version) -> Ordering {
    a.cmp_precedence(b)
}

/// An event's value: `"0"` for `introduced` is before every version.
#[derive(Clone)]
enum Bound {
    Zero,
    At(Version),
}

impl Bound {
    fn cmp_to(&self, v: &Version) -> Ordering {
        match self {
            Bound::Zero => Ordering::Less,
            Bound::At(b) => compare(b, v),
        }
    }

    fn order(a: &Bound, b: &Bound) -> Ordering {
        match (a, b) {
            (Bound::Zero, Bound::Zero) => Ordering::Equal,
            (Bound::Zero, _) => Ordering::Less,
            (_, Bound::Zero) => Ordering::Greater,
            (Bound::At(x), Bound::At(y)) => compare(x, y),
        }
    }
}

/// What one record says of one release.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Affected,
    /// Not affected; `fixed` when the release is at or above a fix.
    NotAffected {
        fixed: bool,
    },
    /// The reason, from the closed list, and the detail in the program's words.
    Unknown(&'static str, String),
}

/// The OSV schema's `IsVulnerable` for one release and one affected entry of a record:
/// `ranges` and `versions` as `advisory_affects` keeps them. A range of SemVer or of the
/// ecosystem's own versions (npm's and crates.io's are SemVer) is walked over its sorted events;
/// a range of commits, or of a kind not known, cannot be compared here.
pub fn judge(v: &Version, ranges: &Value, versions: &Value) -> Verdict {
    let mut uncomparable: Option<String> = None;
    let mut uncovered: Option<String> = None;
    let mut fixed = false;
    let listed: Vec<&str> = versions
        .as_array()
        .map(|l| l.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for s in &listed {
        match version(s) {
            Some(x) if compare(&x, v) == Ordering::Equal => return Verdict::Affected,
            Some(_) => {}
            None => {
                uncomparable.get_or_insert(format!("the record lists the release {s}"));
            }
        }
    }
    let ranges = ranges.as_array().cloned().unwrap_or_default();
    if ranges.is_empty() && listed.is_empty() {
        return Verdict::Unknown(
            NOT_COMPARABLE,
            "the record names no range and no release".to_string(),
        );
    }
    for range in &ranges {
        let kind = range["type"].as_str().unwrap_or_default();
        if kind != "SEMVER" && kind != "ECOSYSTEM" {
            // A range of commits says nothing about a release unless releases are listed.
            if listed.is_empty() {
                uncomparable.get_or_insert(format!("the record gives a range of kind {kind}"));
            }
            continue;
        }
        let mut events: Vec<(&str, Bound)> = Vec::new();
        let mut limits: Vec<Option<Version>> = Vec::new();
        let mut bad = None;
        for e in range["events"].as_array().into_iter().flatten() {
            let Some((key, value)) = e
                .as_object()
                .and_then(|o| o.iter().next())
                .and_then(|(k, v)| v.as_str().map(|v| (k.as_str(), v)))
            else {
                bad = Some("an event out of shape".to_string());
                continue;
            };
            match (key, value) {
                ("introduced", "0") => events.push(("introduced", Bound::Zero)),
                ("limit", "*") => limits.push(None),
                (key, value) => match version(value) {
                    Some(x) if key == "limit" => limits.push(Some(x)),
                    Some(x) => events.push((
                        match key {
                            "introduced" => "introduced",
                            "fixed" => "fixed",
                            _ => "last_affected",
                        },
                        Bound::At(x),
                    )),
                    None => bad = Some(format!("the record's range has {key} {value}")),
                },
            }
        }
        if let Some(why) = bad {
            uncomparable.get_or_insert(why);
            continue;
        }
        events.sort_by(|a, b| Bound::order(&a.1, &b.1));
        let mut vulnerable = false;
        let mut off_by_fix = false;
        for (key, bound) in &events {
            let c = bound.cmp_to(v);
            match *key {
                "introduced" if c != Ordering::Greater => vulnerable = true,
                "fixed" if c != Ordering::Greater => {
                    vulnerable = false;
                    off_by_fix = true;
                }
                "last_affected" if c == Ordering::Less => {
                    vulnerable = false;
                    off_by_fix = false;
                }
                _ => {}
            }
        }
        let before_limits = limits.is_empty()
            || limits
                .iter()
                .any(|l| l.as_ref().is_none_or(|l| compare(v, l) == Ordering::Less));
        if vulnerable && before_limits {
            return Verdict::Affected;
        }
        fixed |= off_by_fix;
        // Past the last release named as affected, with no fix anywhere in the range: the
        // record does not say whether this release is affected.
        let has_fix = events.iter().any(|(k, _)| *k == "fixed");
        let above_last = events
            .iter()
            .any(|(k, b)| *k == "last_affected" && b.cmp_to(v) == Ordering::Less);
        let after_start = events
            .iter()
            .any(|(k, b)| *k == "introduced" && b.cmp_to(v) != Ordering::Greater);
        if !has_fix && above_last && after_start {
            uncovered.get_or_insert(
                "the release is above the last one the record names as affected, and no fix is named"
                    .to_string(),
            );
        }
    }
    if let Some(why) = uncomparable {
        return Verdict::Unknown(NOT_COMPARABLE, why);
    }
    if let Some(why) = uncovered {
        return Verdict::Unknown(NOT_COVERED, why);
    }
    Verdict::NotAffected { fixed }
}

/// The releases a record names as fixing it, for one affected entry.
fn fixes(ranges: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for range in ranges.as_array().into_iter().flatten() {
        for e in range["events"].as_array().into_iter().flatten() {
            if let Some(f) = e["fixed"].as_str() {
                out.push(f.to_string());
            }
        }
    }
    out
}

/// The source of a record by its id, named as docs/threats.md names it wherever a record's
/// text is shown.
pub fn source_name(id: &str) -> &'static str {
    if id.starts_with("GHSA-") {
        "GitHub Advisory Database"
    } else if id.starts_with("RUSTSEC-") {
        "RustSec"
    } else if id.starts_with("MAL-") {
        "OpenSSF malicious packages"
    } else {
        "OSV.dev"
    }
}

// ---- The conditions of a place. ----

/// Whether a feed's data counts as current at `now`, and the reading it rests on.
pub struct Fresh {
    pub feed: &'static Feed,
    /// The latest reading that read the feed or found it unchanged: its id and time.
    pub reading: Option<(i64, i64)>,
    /// `None` when current; else why not, in the program's words.
    pub not_current: Option<String>,
}

fn has_feed_tables(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) = 2 FROM sqlite_master
         WHERE type = 'table' AND name IN ('advisory', 'feed_reading')",
        [],
        |r| r.get(0),
    )
}

/// Each feed: whether it was read whole within its limit and its newest change is recent.
pub fn freshness(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Fresh>> {
    let tables = has_feed_tables(conn)?;
    let mut out = Vec::new();
    for feed in &FEEDS {
        if !tables {
            out.push(Fresh {
                feed,
                reading: None,
                not_current: Some("it has never been read".to_string()),
            });
            continue;
        }
        let reading: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, at FROM feed_reading WHERE source = ?1 AND outcome != 'failed'
                 ORDER BY id DESC LIMIT 1",
                [feed.source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let newest: Option<String> = conn.query_row(
            "SELECT MAX(modified) FROM advisory WHERE source = ?1 AND gone_at IS NULL",
            [feed.source],
            |r| r.get(0),
        )?;
        let not_current = match reading {
            None => Some("it has never been read".to_string()),
            Some((_, at)) if now - at > feed.current_for => Some(format!(
                "it was last read {}, more than {} hours before this check",
                crate::view::utc(at),
                feed.current_for / 3600
            )),
            _ => match newest {
                Some(t) if t.as_str() >= crate::view::iso(now - NEWEST_CHANGE).as_str() => None,
                Some(t) => Some(format!(
                    "its newest record changed {t}, more than 7 days before this check"
                )),
                None => Some("it holds no record".to_string()),
            },
        };
        out.push(Fresh {
            feed,
            reading,
            not_current,
        });
    }
    Ok(out)
}

/// A checkout's lockfiles reading: its scope, completeness, reason and run.
type LockfileReading = (String, String, Option<String>, String);

/// The lockfiles reader's latest reading of each checkout that is still there.
fn lockfile_readings(conn: &Connection) -> rusqlite::Result<Vec<LockfileReading>> {
    conn.prepare(
        "SELECT c.scope, c.completeness, c.reason, c.run_id FROM coverage c
         WHERE c.reader = ?1
           AND c.id = (SELECT MAX(l.id) FROM coverage l WHERE l.reader = c.reader AND l.scope = c.scope)
           AND c.scope NOT IN (SELECT id FROM gone_entity)
         ORDER BY c.scope",
    )?
    .query_map([crate::lockfiles::READER], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })?
    .collect()
}

/// How the lockfiles of a checkout were read for one ecosystem: `full`, `partial` or
/// `not_read`, and why.
fn lockfiles_for(
    completeness: &str,
    reason: Option<&str>,
    reading_run: &str,
    run_id: &str,
    ecosystem: &str,
) -> (&'static str, Option<String>) {
    if reading_run != run_id {
        return (
            "not_read",
            Some("its lockfiles were not read in the latest check".to_string()),
        );
    }
    match completeness {
        "full" => ("full", None),
        "partial" if !crate::lockfiles::partial_for(reason.unwrap_or_default(), ecosystem) => {
            ("full", None)
        }
        "partial" => ("partial", reason.map(str::to_string)),
        _ => ("not_read", reason.map(str::to_string)),
    }
}

// ---- Matching, in the run. ----

/// One entry of a package in a checkout: its component, where it comes from (`None`: the
/// registry), its version and where in the lockfile it is.
struct Entry {
    from: Option<&'static str>,
    version: Option<String>,
    at: String,
}

/// One answer as computed.
struct Computed {
    checkout: String,
    ecosystem: &'static str,
    package: String,
    source: &'static str,
    advisory: String,
    modified: String,
    kind: String,
    answer: &'static str,
    reason: &'static str,
    detail: String,
    entries: Value,
    fixed: Value,
    reading: Option<(i64, i64)>,
}

/// One advisory's rows for a package.
struct Named {
    source: &'static str,
    advisory: String,
    modified: String,
    kind: String,
    affects: Vec<(Value, Value)>,
}

/// What a run's matching found, for the findings.
pub struct Matched {
    /// Per component of the registry: its affecting records of each kind, with the versions
    /// they affect.
    pub affected: BTreeMap<String, Vec<(String, String, Vec<String>)>>,
}

/// Matches every package the checkouts' lockfiles hold against the data, writes the answers
/// and the conditions of each place, and links records to the catalogue. Run in the run's
/// transaction after the feeds are read.
pub fn match_all(tx: &Transaction, run_id: &str, at: i64) -> rusqlite::Result<Matched> {
    let fresh = freshness(tx, at)?;
    let fresh_of = |eco: &str| fresh.iter().find(|f| f.feed.ecosystem == eco);
    // The conditions of each place.
    let readings = lockfile_readings(tx)?;
    tx.execute("DELETE FROM vulnerability_place", [])?;
    let mut places: HashMap<(String, &'static str), (&'static str, Option<String>)> =
        HashMap::new();
    for (scope, completeness, reason, reading_run) in &readings {
        for f in &fresh {
            let eco = f.feed.ecosystem;
            let (lockfiles, why) =
                lockfiles_for(completeness, reason.as_deref(), reading_run, run_id, eco);
            tx.execute(
                "INSERT INTO vulnerability_place (checkout, ecosystem, lockfiles, lockfiles_why,
                     feed, feed_why, reading, read_at, run_id, at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    scope,
                    eco,
                    lockfiles,
                    why,
                    if f.not_current.is_none() {
                        "current"
                    } else {
                        "not_current"
                    },
                    f.not_current,
                    f.reading.map(|r| r.0),
                    f.reading.map(|r| r.1),
                    run_id,
                    at
                ],
            )?;
            places.insert((scope.clone(), eco), (lockfiles, why));
        }
    }

    // Every package the lockfiles hold now, grouped by checkout, ecosystem and name.
    let mut packages: BTreeMap<(String, &'static str, String), Vec<Entry>> = BTreeMap::new();
    {
        let mut stmt = tx.prepare(
            "SELECT subject, predicate, object, source_ref, scope FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate IN ('has_version', 'part_of')
             ORDER BY subject, predicate",
        )?;
        let rows = stmt.query_map([crate::lockfiles::READER], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut versioned: HashSet<String> = HashSet::new();
        for row in rows {
            let (subject, predicate, object, at, scope) = row?;
            let Some(rest) = subject.strip_prefix(&format!("component:{scope}/")) else {
                continue;
            };
            let Some((eco, name)) = rest.split_once('/') else {
                continue;
            };
            let Some(eco) = FEEDS.iter().map(|f| f.ecosystem).find(|e| *e == eco) else {
                continue;
            };
            let (package, from) = crate::lockfiles::split_name(name);
            let version = if predicate == "has_version" {
                versioned.insert(subject.clone());
                Some(object)
            } else if versioned.contains(&subject) {
                // Its versions were taken; `part_of` alone says nothing more.
                continue;
            } else {
                None
            };
            packages
                .entry((scope.clone(), eco, package.to_string()))
                .or_default()
                .push(Entry { from, version, at });
        }
    }

    // What the data says of each package, once per ecosystem and name.
    let mut computed: Vec<Computed> = Vec::new();
    {
        let mut lookup = tx.prepare(
            "SELECT f.source, f.advisory, f.ranges, f.versions, a.kind, a.modified
             FROM advisory_affects f JOIN advisory a ON a.source = f.source AND a.id = f.advisory
             WHERE f.ecosystem = ?1 AND f.normalized = ?2
               AND a.withdrawn IS NULL AND a.gone_at IS NULL AND a.kind != 'informational'
             ORDER BY f.source, f.advisory",
        )?;
        let mut cache: HashMap<(&'static str, String), Vec<Named>> = HashMap::new();
        for ((checkout, eco, package), entries) in &packages {
            let key = (*eco, crate::osv::normalized(eco, package));
            if !cache.contains_key(&key) {
                let mut named: Vec<Named> = Vec::new();
                let rows = lookup.query_map(params![key.0, key.1], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                    ))
                })?;
                for row in rows {
                    let (source, advisory, ranges, versions, kind, modified) = row?;
                    let Some(source) = FEEDS.iter().map(|f| f.source).find(|s| *s == source) else {
                        continue;
                    };
                    let ranges = serde_json::from_str(&ranges).unwrap_or(Value::Null);
                    let versions = serde_json::from_str(&versions).unwrap_or(Value::Null);
                    match named.last_mut() {
                        Some(n) if n.source == source && n.advisory == advisory => {
                            n.affects.push((ranges, versions));
                        }
                        _ => named.push(Named {
                            source,
                            advisory,
                            modified,
                            kind,
                            affects: vec![(ranges, versions)],
                        }),
                    }
                }
                cache.insert(key.clone(), named);
            }
            let place = places.get(&(checkout.clone(), *eco));
            let feed = fresh_of(eco);
            for n in &cache[&key] {
                computed.push(answer_one(checkout, eco, package, entries, n, place, feed));
            }
        }
    }

    write_answers(tx, &computed, run_id, at)?;
    link_catalogue(tx)?;

    // What the findings rest on: affected registry components, by record kind.
    let mut affected: BTreeMap<String, Vec<(String, String, Vec<String>)>> = BTreeMap::new();
    for c in computed.iter().filter(|c| c.answer == "affected") {
        let component = format!("component:{}/{}/{}", c.checkout, c.ecosystem, c.package);
        let kind = c.kind.clone();
        let versions: Vec<String> = c
            .entries
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["affected"] == true)
            .filter_map(|e| e["version"].as_str().map(str::to_string))
            .collect();
        affected
            .entry(component)
            .or_default()
            .push((c.advisory.clone(), kind, versions));
    }
    Ok(Matched { affected })
}

/// The answer for one advisory and one package in one checkout.
fn answer_one(
    checkout: &str,
    eco: &'static str,
    package: &str,
    entries: &[Entry],
    n: &Named,
    place: Option<&(&'static str, Option<String>)>,
    feed: Option<&Fresh>,
) -> Computed {
    let mut reasons: Vec<(&'static str, String)> = Vec::new();
    let mut shown: Vec<Value> = Vec::new();
    let mut any_affected = false;
    let mut all_fixed = true;
    for e in entries {
        let verdict = match (e.from, e.version.as_deref()) {
            (Some(from), _) => Verdict::Unknown(
                NOT_FROM_REGISTRY,
                format!("{package} comes from {from} at {}", e.at),
            ),
            (None, None) => Verdict::Unknown(
                NOT_COMPARABLE,
                format!("the lockfile gives no version at {}", e.at),
            ),
            (None, Some(v)) => match version(v) {
                None => Verdict::Unknown(
                    NOT_COMPARABLE,
                    format!("the release {v} at {} is not a SemVer version", e.at),
                ),
                Some(parsed) => {
                    let verdicts: Vec<Verdict> = n
                        .affects
                        .iter()
                        .map(|(ranges, versions)| judge(&parsed, ranges, versions))
                        .collect();
                    if verdicts.contains(&Verdict::Affected) {
                        Verdict::Affected
                    } else if let Some(Verdict::Unknown(r, d)) =
                        verdicts.iter().find(|v| matches!(v, Verdict::Unknown(..)))
                    {
                        Verdict::Unknown(r, format!("{d}, for {v} at {}", e.at))
                    } else {
                        Verdict::NotAffected {
                            fixed: verdicts
                                .iter()
                                .all(|v| matches!(v, Verdict::NotAffected { fixed: true })),
                        }
                    }
                }
            },
        };
        let affected = verdict == Verdict::Affected;
        any_affected |= affected;
        match verdict {
            Verdict::Unknown(r, d) => reasons.push((r, d)),
            Verdict::NotAffected { fixed } => all_fixed &= fixed,
            Verdict::Affected => {}
        }
        shown.push(json!({
            "version": e.version,
            "at": e.at,
            "from": e.from.unwrap_or("registry"),
            "affected": affected,
        }));
    }
    match place {
        Some(("full", _)) => {}
        Some((_, why)) => reasons.push((
            PLACE_NOT_READ,
            why.clone()
                .unwrap_or_else(|| "its lockfiles were not read".to_string()),
        )),
        None => reasons.push((PLACE_NOT_READ, "its lockfiles have no reading".to_string())),
    }
    if let Some(why) = feed.and_then(|f| f.not_current.as_ref()) {
        reasons.push((
            FEED_NOT_READ,
            format!("the {eco} data is not current: {why}"),
        ));
    }
    let fixed: Vec<String> = n.affects.iter().flat_map(|(r, _)| fixes(r)).collect();
    let (answer, reason, detail) = if any_affected {
        (
            "affected",
            "affected",
            format!("{} affects {package} here", n.advisory),
        )
    } else if let Some((r, d)) = REASONS
        .iter()
        .find_map(|code| reasons.iter().find(|(r, _)| r == code))
    {
        ("unknown", *r, d.clone())
    } else if all_fixed {
        (
            "not_affected",
            "fixed",
            "every release here is at or above a fix".to_string(),
        )
    } else {
        (
            "not_affected",
            "not_in_range",
            "no release here is in the record's ranges or list".to_string(),
        )
    };
    Computed {
        checkout: checkout.to_string(),
        ecosystem: eco,
        package: package.to_string(),
        source: n.source,
        advisory: n.advisory.clone(),
        modified: n.modified.clone(),
        kind: n.kind.clone(),
        answer,
        reason,
        detail,
        entries: Value::Array(shown),
        fixed: json!(fixed),
        reading: feed.and_then(|f| f.reading),
    }
}

/// Writes the answers: an answer that stays keeps when it began; one that changed or went is
/// kept in the past table with when it stopped.
fn write_answers(
    tx: &Transaction,
    computed: &[Computed],
    run_id: &str,
    at: i64,
) -> rusqlite::Result<()> {
    type Key = (String, String, String, String, String);
    let held: HashMap<Key, (String, String)> = tx
        .prepare(
            "SELECT checkout, ecosystem, package, source, advisory, answer, reason
             FROM vulnerability_answer",
        )?
        .query_map([], |r| {
            Ok((
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?),
                (r.get(5)?, r.get(6)?),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut keep_past = tx.prepare(
        "INSERT INTO vulnerability_answer_past
         SELECT checkout, ecosystem, package, source, advisory, modified, answer, reason, detail,
                entries, fixed, reading, read_at, since_run, since_at, run_id, at, ?6, ?7
         FROM vulnerability_answer
         WHERE checkout = ?1 AND ecosystem = ?2 AND package = ?3 AND source = ?4 AND advisory = ?5",
    )?;
    let mut put = tx.prepare(
        "INSERT INTO vulnerability_answer (checkout, ecosystem, package, source, advisory,
             modified, answer, reason, detail, entries, fixed, reading, read_at, since_run,
             since_at, run_id, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?14, ?15)
         ON CONFLICT (checkout, ecosystem, package, source, advisory) DO UPDATE SET
             modified = excluded.modified, answer = excluded.answer, reason = excluded.reason,
             detail = excluded.detail, entries = excluded.entries, fixed = excluded.fixed,
             reading = excluded.reading, read_at = excluded.read_at,
             since_run = CASE WHEN ?16 THEN excluded.since_run ELSE since_run END,
             since_at = CASE WHEN ?16 THEN excluded.since_at ELSE since_at END,
             run_id = excluded.run_id, at = excluded.at",
    )?;
    let mut seen: HashSet<Key> = HashSet::new();
    for c in computed {
        let key: Key = (
            c.checkout.clone(),
            c.ecosystem.to_string(),
            c.package.clone(),
            c.source.to_string(),
            c.advisory.clone(),
        );
        let changed = match held.get(&key) {
            Some((answer, reason)) if answer == c.answer && reason == c.reason => false,
            Some(_) => {
                keep_past.execute(params![key.0, key.1, key.2, key.3, key.4, run_id, at])?;
                true
            }
            None => true,
        };
        put.execute(params![
            c.checkout,
            c.ecosystem,
            c.package,
            c.source,
            c.advisory,
            c.modified,
            c.answer,
            c.reason,
            c.detail,
            c.entries.to_string(),
            c.fixed.to_string(),
            c.reading.map(|r| r.0),
            c.reading.map(|r| r.1),
            run_id,
            at,
            changed
        ])?;
        seen.insert(key);
    }
    let mut gone = tx.prepare(
        "DELETE FROM vulnerability_answer
         WHERE checkout = ?1 AND ecosystem = ?2 AND package = ?3 AND source = ?4 AND advisory = ?5",
    )?;
    for key in held.keys().filter(|k| !seen.contains(*k)) {
        keep_past.execute(params![key.0, key.1, key.2, key.3, key.4, run_id, at])?;
        gone.execute(params![key.0, key.1, key.2, key.3, key.4])?;
    }
    Ok(())
}

/// Links records to the catalogue's exploited CVEs through their aliases, and through the
/// aliases of a record they name, as a RustSec record names a GitHub one.
fn link_catalogue(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM vulnerability_linked", [])?;
    let catalogue: HashSet<String> = tx
        .prepare("SELECT id FROM threat WHERE gone_at IS NULL")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if catalogue.is_empty() {
        return Ok(());
    }
    let records: Vec<(String, String, Vec<String>)> = tx
        .prepare(
            "SELECT source, id, aliases FROM advisory
             WHERE gone_at IS NULL AND withdrawn IS NULL AND aliases != '[]'",
        )?
        .query_map([], |r| {
            let aliases: String = r.get(2)?;
            Ok((
                r.get(0)?,
                r.get(1)?,
                serde_json::from_str(&aliases).unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let by_id: HashMap<&str, &Vec<String>> =
        records.iter().map(|(_, id, a)| (id.as_str(), a)).collect();
    let mut put = tx.prepare(
        "INSERT OR IGNORE INTO vulnerability_linked (cve, source, advisory) VALUES (?1, ?2, ?3)",
    )?;
    for (source, id, aliases) in &records {
        let mut names: BTreeSet<&str> = aliases.iter().map(String::as_str).collect();
        for a in aliases {
            if let Some(more) = by_id.get(a.as_str()) {
                names.extend(more.iter().map(String::as_str));
            }
        }
        names.insert(id);
        for cve in names.into_iter().filter(|n| catalogue.contains(*n)) {
            put.execute(params![cve, source, id])?;
        }
    }
    Ok(())
}

// ---- What is told. ----

/// The order of labels, most severe first; a malicious package before every label.
const LABELS: [&str; 6] = ["malicious", "critical", "high", "moderate", "low", "none"];

/// The label an affecting record is listed under: malicious, or the source's own label.
fn label_of(kind: &str, severity: Option<&str>) -> &'static str {
    if kind == "malicious" {
        return "malicious";
    }
    match severity.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => "critical",
        Some("high") => "high",
        Some("moderate" | "medium") => "moderate",
        Some("low") => "low",
        _ => "none",
    }
}

/// One "affects me" answer, as it is listed.
pub struct Affecting {
    pub checkout: String,
    pub ecosystem: String,
    pub package: String,
    pub source: String,
    pub advisory: String,
    pub modified: String,
    pub kind: String,
    pub label: &'static str,
    pub summary: Option<String>,
    pub aliases: Vec<String>,
    pub exploited: bool,
    pub entries: Value,
    pub fixed: Vec<String>,
    pub read_at: Option<i64>,
    pub since_at: i64,
}

impl Affecting {
    /// The releases here the record affects, with where each is.
    pub fn affected(&self) -> Vec<(String, String)> {
        self.entries
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["affected"] == true)
            .map(|e| {
                (
                    e["version"].as_str().unwrap_or_default().to_string(),
                    e["at"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }
}

fn has_tables(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) = 3 FROM sqlite_master WHERE type = 'table'
         AND name IN ('vulnerability_answer', 'vulnerability_place', 'vulnerability_linked')",
        [],
        |r| r.get(0),
    )
}

/// Every "affects me" answer, most severe first by the source's label, then by project.
pub fn affecting(conn: &Connection) -> rusqlite::Result<Vec<Affecting>> {
    if !has_tables(conn)? {
        return Ok(Vec::new());
    }
    let mut list: Vec<Affecting> = conn
        .prepare(
            "SELECT v.checkout, v.ecosystem, v.package, v.source, v.advisory, v.modified,
                    a.kind, a.severity, a.summary, a.aliases, v.entries, v.fixed, v.read_at,
                    v.since_at,
                    EXISTS (SELECT 1 FROM vulnerability_linked l
                            WHERE l.source = v.source AND l.advisory = v.advisory)
             FROM vulnerability_answer v
             JOIN advisory a ON a.source = v.source AND a.id = v.advisory
             WHERE v.answer = 'affected'",
        )?
        .query_map([], |r| {
            let kind: String = r.get(6)?;
            let severity: Option<String> = r.get(7)?;
            let aliases: String = r.get(9)?;
            let entries: String = r.get(10)?;
            let fixed: String = r.get(11)?;
            Ok(Affecting {
                checkout: r.get(0)?,
                ecosystem: r.get(1)?,
                package: r.get(2)?,
                source: r.get(3)?,
                advisory: r.get(4)?,
                modified: r.get(5)?,
                label: label_of(&kind, severity.as_deref()),
                kind,
                summary: r.get(8)?,
                aliases: serde_json::from_str(&aliases).unwrap_or_default(),
                entries: serde_json::from_str(&entries).unwrap_or(Value::Null),
                fixed: serde_json::from_str(&fixed).unwrap_or_default(),
                read_at: r.get(12)?,
                since_at: r.get(13)?,
                exploited: r.get(14)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let rank = |a: &Affecting| {
        (
            a.kind != "malicious" && !a.exploited,
            LABELS.iter().position(|l| *l == a.label),
        )
    };
    list.sort_by(|a, b| {
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.checkout.cmp(&b.checkout))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.advisory.cmp(&b.advisory))
    });
    Ok(list)
}

/// The totals of the answers the store holds. A record that affects several projects is one
/// answer in each, so every number a person reads counts records, not answers.
#[derive(Default)]
pub struct Totals {
    pub affected: usize,
    pub unknown: usize,
    pub not_affected: usize,
    /// Catalogue CVEs no record of the data names: "does not affect me, no signs" for
    /// every lockfile. `None` when the catalogue was never read.
    pub no_signs: Option<usize>,
    /// Affecting answers by label, in the order of `LABELS`.
    pub by_label: Vec<(&'static str, usize)>,
    /// What a person calls a known vulnerability: a record that affects something, counted
    /// once however many projects it affects; with the packages and projects it is in.
    pub records: usize,
    pub packages: usize,
    pub projects: usize,
    /// Affecting records by label, each counted once, in the order of `LABELS`.
    pub records_by_label: Vec<(&'static str, usize)>,
    /// "Don't know" answers by reason, in the order of `REASONS`.
    pub by_reason: Vec<(&'static str, usize)>,
    /// Packages with a "don't know" answer, each counted once, by reason; the feed's reason
    /// apart, since it is told as its own item.
    pub packages_unknown: usize,
    pub packages_by_reason: Vec<(&'static str, usize)>,
    /// Informational advisories held, which this version does not answer.
    pub informational: usize,
    /// Whether matching ever ran on this store.
    pub matched: bool,
}

pub fn totals(conn: &Connection) -> rusqlite::Result<Totals> {
    if !has_tables(conn)? {
        return Ok(Totals::default());
    }
    let mut t = Totals {
        matched: conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM vulnerability_place)",
            [],
            |r| r.get(0),
        )?,
        ..Totals::default()
    };
    let counts: Vec<(String, String, i64)> = conn
        .prepare(
            "SELECT answer, reason, COUNT(*) FROM vulnerability_answer GROUP BY answer, reason",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (answer, reason, n) in &counts {
        let n = *n as usize;
        match answer.as_str() {
            "affected" => t.affected += n,
            "unknown" => t.unknown += n,
            _ => t.not_affected += n,
        }
        let _ = reason;
    }
    t.by_reason = REASONS
        .iter()
        .map(|code| {
            let n = counts
                .iter()
                .filter(|(a, r, _)| a == "unknown" && r == code)
                .map(|(_, _, n)| *n as usize)
                .sum();
            (*code, n)
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    let mut labels: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut records: BTreeMap<(String, String), &'static str> = BTreeMap::new();
    let mut packages: BTreeSet<(String, String)> = BTreeSet::new();
    let mut projects: BTreeSet<String> = BTreeSet::new();
    for a in affecting(conn)? {
        *labels.entry(a.label).or_default() += 1;
        records.insert((a.source, a.advisory), a.label);
        packages.insert((a.ecosystem, a.package));
        projects.insert(a.checkout);
    }
    let in_order = |of: &BTreeMap<&'static str, usize>| -> Vec<(&'static str, usize)> {
        LABELS
            .iter()
            .filter_map(|l| of.get(l).map(|n| (*l, *n)))
            .collect()
    };
    t.by_label = in_order(&labels);
    let mut record_labels: BTreeMap<&'static str, usize> = BTreeMap::new();
    for label in records.values() {
        *record_labels.entry(label).or_default() += 1;
    }
    t.records_by_label = in_order(&record_labels);
    (t.records, t.packages, t.projects) = (records.len(), packages.len(), projects.len());
    // A package counts once, under the first reason of its "don't know" answers.
    let unknown: Vec<(String, String, String, String)> = conn
        .prepare(
            "SELECT checkout, ecosystem, package, reason FROM vulnerability_answer
             WHERE answer = 'unknown' AND reason != ?1",
        )?
        .query_map([FEED_NOT_READ], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut first: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (c, e, p, reason) in unknown {
        let rank = REASONS
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(REASONS.len());
        let slot = first.entry((c, e, p)).or_insert(rank);
        *slot = (*slot).min(rank);
    }
    t.packages_unknown = first.len();
    t.packages_by_reason = REASONS
        .iter()
        .enumerate()
        .map(|(i, code)| (*code, first.values().filter(|r| **r == i).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    t.informational = if has_feed_tables(conn)? {
        conn.query_row(
            "SELECT COUNT(*) FROM advisory
             WHERE kind = 'informational' AND withdrawn IS NULL AND gone_at IS NULL",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize
    } else {
        0
    };
    // A store made before the catalogue was kept has no table of it until a run opens it.
    let has_threats: bool = conn.query_row(
        "SELECT COUNT(*) = 2 FROM sqlite_master
         WHERE type = 'table' AND name IN ('threat', 'feed_reading')",
        [],
        |r| r.get(0),
    )?;
    if has_threats {
        let read: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM feed_reading WHERE source = ?1 AND outcome != 'failed')",
            [crate::threats::SOURCE],
            |r| r.get(0),
        )?;
        let catalogue: i64 = conn.query_row(
            "SELECT COUNT(*) FROM threat t WHERE t.gone_at IS NULL
               AND NOT EXISTS (SELECT 1 FROM vulnerability_linked l WHERE l.cve = t.id)",
            [],
            |r| r.get(0),
        )?;
        t.no_signs = read.then_some(catalogue as usize);
    }
    Ok(t)
}

/// "473 known vulnerabilities in 116 packages, across 9 projects.": what a person calls them.
pub fn records_said(t: &Totals) -> String {
    let n = |n: usize, one: &str, many: &str| crate::view::counted(n as i64, one, many);
    format!(
        "{} in {}, across {}.",
        n(t.records, "known vulnerability", "known vulnerabilities"),
        n(t.packages, "package", "packages"),
        n(t.projects, "project", "projects"),
    )
}

/// What one reason of "don't know" says of packages, for one and for many.
pub fn reason_words(code: &str) -> (&'static str, &'static str) {
    match code {
        NOT_FROM_REGISTRY => (
            "1 does not come from the public registry",
            "{n} do not come from the public registry",
        ),
        NOT_COMPARABLE => (
            "1 has a version that cannot be compared with a record's",
            "{n} have a version that cannot be compared with a record's",
        ),
        NOT_COVERED => (
            "1 is newer than the last release a record names as affected, and no fix is named",
            "{n} are newer than the last release a record names as affected, and no fix is named",
        ),
        PLACE_NOT_READ => (
            "1 is in a project whose lockfiles were not all read, such as a pnpm, yarn or bun lockfile",
            "{n} are in a project whose lockfiles were not all read, such as a pnpm, yarn or bun lockfile",
        ),
        FEED_NOT_READ => (
            "1 is judged by a list of vulnerabilities that is not current",
            "{n} are judged by a list of vulnerabilities that is not current",
        ),
        _ => (
            "1 is in an ecosystem this version has no data for",
            "{n} are in an ecosystem this version has no data for",
        ),
    }
}

/// `{n}` packages for one reason, in words.
pub fn reason_said(code: &str, n: usize) -> String {
    let (one, many) = reason_words(code);
    if n == 1 {
        one.to_string()
    } else {
        many.replace("{n}", &n.to_string())
    }
}

/// The oldest time a feed that is not current was last read, and whether any is not current.
pub fn stale(conn: &Connection, now: i64) -> rusqlite::Result<Option<Option<i64>>> {
    let fresh = freshness(conn, now)?;
    let old: Vec<&Fresh> = fresh.iter().filter(|f| f.not_current.is_some()).collect();
    if old.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        old.iter().filter_map(|f| f.reading.map(|r| r.1)).min(),
    ))
}

// ---- The machine-readable forms. ----

fn iso(t: Option<i64>) -> Value {
    t.map_or(Value::Null, |t| json!(crate::view::iso(t)))
}

/// Where a lockfile line is, as a person finds it: under the home folder unless it starts at
/// the root.
pub fn at_shown(at: &str) -> String {
    if at.starts_with('/') {
        at.to_string()
    } else {
        format!("~/{at}")
    }
}

fn affecting_json(a: &Affecting, this: Option<&str>) -> Value {
    let releases: Vec<Value> = a
        .affected()
        .iter()
        .map(|(v, at)| json!({ "version_text": crate::status::text(v), "at_text": crate::status::text(&at_shown(at)) }))
        .collect();
    json!({
        "record": a.advisory,
        "record_source": source_name(&a.advisory),
        "feed": a.source,
        "modified": a.modified,
        "kind": a.kind,
        "label": a.label,
        "exploited": a.exploited,
        "project_text": crate::status::text(&crate::findings::place(&a.checkout, this)),
        "ecosystem": a.ecosystem,
        "package_text": crate::status::text(&a.package),
        "releases": releases,
        "fixed_text": a.fixed.iter().map(|f| crate::status::text(f)).collect::<Vec<_>>(),
        "aliases_text": a.aliases.iter().map(|f| crate::status::text(f)).collect::<Vec<_>>(),
        "summary_text": a.summary.as_deref().map(crate::status::text),
        "data_read_at": iso(a.read_at),
        "since": crate::view::iso(a.since_at),
    })
}

fn totals_json(t: &Totals) -> Value {
    let by = |list: &[(&'static str, usize)]| -> Value {
        Value::Object(
            list.iter()
                .map(|(k, n)| (k.to_string(), json!(n)))
                .collect(),
        )
    };
    json!({
        "affected": t.affected,
        "unknown": t.unknown,
        "not_affected_known": t.not_affected,
        "not_affected_no_signs": t.no_signs,
        "affected_by_label": by(&t.by_label),
        "affected_records": t.records,
        "affected_packages": t.packages,
        "affected_projects": t.projects,
        "affected_records_by_label": by(&t.records_by_label),
        "unknown_by_reason": by(&t.by_reason),
    })
}

fn feeds_json(conn: &Connection, now: i64) -> rusqlite::Result<Value> {
    Ok(Value::Array(
        freshness(conn, now)?
            .iter()
            .map(|f| {
                json!({
                    "source": f.feed.source,
                    "ecosystem": f.feed.ecosystem,
                    "matched": true,
                    "read_at": iso(f.reading.map(|r| r.1)),
                    "current": f.not_current.is_none(),
                    "not_current_why": f.not_current,
                })
            })
            .collect(),
    ))
}

/// The status's part about known vulnerabilities, beside what needs a look and never counted
/// in it.
pub fn status_json(conn: &Connection, now: i64) -> rusqlite::Result<Value> {
    let t = totals(conn)?;
    let mut v = totals_json(&t);
    v["matched_this_store"] = json!(t.matched);
    v["feeds"] = feeds_json(conn, now)?;
    v["not_answered"] = json!({ "informational_records": t.informational });
    Ok(v)
}

/// The most "affects me" answers `soc vulnerabilities` lists; the total is always given.
pub const SHOWN: usize = 200;

/// `soc vulnerabilities --json`: the "affects me" answers, most severe first.
pub fn list_json(conn: &Connection, now: i64) -> rusqlite::Result<Value> {
    let this = crate::covered::this_machine(conn)?;
    let list = affecting(conn)?;
    let t = totals(conn)?;
    Ok(json!({
        "generated_at": crate::view::iso(now),
        "totals": totals_json(&t),
        "feeds": feeds_json(conn, now)?,
        "affected": list.iter().take(SHOWN).map(|a| affecting_json(a, this.as_deref())).collect::<Vec<_>>(),
        "affected_total": list.len(),
        "not_answered": { "informational_records": t.informational },
        "declared_note": DECLARED,
    }))
}

/// A record the data holds, as `soc vulnerability` reads it.
struct Held {
    source: String,
    id: String,
    modified: String,
    kind: String,
    withdrawn: Option<String>,
    gone: bool,
    summary: Option<String>,
    aliases: Vec<String>,
}

fn held_records(conn: &Connection, id: &str) -> rusqlite::Result<Vec<Held>> {
    if !has_feed_tables(conn)? {
        return Ok(Vec::new());
    }
    // A record by its own id, or by an alias such as a CVE id. The alias is matched as the
    // whole quoted string inside the JSON array, never as a part of one.
    let quoted = serde_json::to_string(id).unwrap_or_default();
    let found: Vec<Held> = conn
        .prepare(
            "SELECT source, id, modified, kind, withdrawn, gone_at IS NOT NULL, summary, aliases
             FROM advisory WHERE id = ?1 OR instr(aliases, ?2) > 0 ORDER BY source, id",
        )?
        .query_map(params![id, quoted], |r| {
            let aliases: String = r.get(7)?;
            Ok(Held {
                source: r.get(0)?,
                id: r.get(1)?,
                modified: r.get(2)?,
                kind: r.get(3)?,
                withdrawn: r.get(4)?,
                gone: r.get(5)?,
                summary: r.get(6)?,
                aliases: serde_json::from_str(&aliases).unwrap_or_default(),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(found
        .into_iter()
        .filter(|h| h.id == id || h.aliases.iter().any(|a| a == id))
        .collect())
}

/// A place's row: checkout, ecosystem, lockfiles, why, feed, why, when the data was read.
type Place = (
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<i64>,
);

/// `soc vulnerability <id> --json`: the answer for one record id or CVE id in every checkout
/// whose lockfiles were read, with what it rests on. An id the data does not hold is said as
/// such, never as "not affected".
pub fn one_json(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<Value> {
    let this = crate::covered::this_machine(conn)?;
    let place_of = |c: &str| crate::status::text(&crate::findings::place(c, this.as_deref()));
    let records = held_records(conn, id)?;
    let in_catalogue: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM threat WHERE id = ?1 AND gone_at IS NULL)",
            [id],
            |r| r.get(0),
        )
        .unwrap_or(false);
    let places: Vec<Place> = if has_tables(conn)? {
        conn.prepare(
            "SELECT checkout, ecosystem, lockfiles, lockfiles_why, feed, feed_why, read_at
                 FROM vulnerability_place ORDER BY checkout, ecosystem",
        )?
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?
    } else {
        Vec::new()
    };
    // A place's answer for a record that names none of its packages, from the conditions of
    // the place: "not affected" only when its lockfiles were all read and the data is
    // current, with this certainty.
    let derived = |p: &Place, certainty: &str| {
        let mut a = json!({ "project_text": place_of(&p.0), "ecosystem": p.1 });
        match (p.2.as_str(), p.4.as_str()) {
            ("full", "current") => {
                a["answer"] = json!("not_affected");
                a["certainty"] = json!(certainty);
            }
            ("full", _) => {
                a["answer"] = json!("unknown");
                a["reason"] = json!(FEED_NOT_READ);
                a["detail_text"] = json!(p.5.as_deref().map(crate::status::text));
            }
            _ => {
                a["answer"] = json!("unknown");
                a["reason"] = json!(PLACE_NOT_READ);
                a["detail_text"] = json!(p.3.as_deref().map(crate::status::text));
            }
        }
        a["data_read_at"] = iso(p.6);
        a
    };
    let mut out = json!({
        "generated_at": crate::view::iso(now),
        "id_text": crate::status::text(id),
        "in_catalogue": in_catalogue,
        "declared_note": DECLARED,
    });
    if records.is_empty() {
        let (known, said) = if in_catalogue {
            (
                "no_record",
                "The catalogue of exploited vulnerabilities holds this id, and no record of the npm or crates.io data names it: it does not affect any project's lockfiles, with no signs. The data does not claim to name every vulnerability a package may hold.",
            )
        } else {
            (
                "unknown_id",
                "The data held here has no record with this id or alias, so nothing can be said about it; this is not an answer that it does not affect you.",
            )
        };
        out["data"] = json!(known);
        out["said"] = json!(said);
        let answers: Vec<Value> = if in_catalogue {
            places.iter().map(|p| derived(p, "no_signs")).collect()
        } else {
            Vec::new()
        };
        out["answers"] = Value::Array(answers);
        return Ok(out);
    }
    out["data"] = json!("held");
    let mut list: Vec<Value> = Vec::new();
    for r in &records {
        let feed = FEEDS.iter().find(|f| f.source == r.source);
        let eco = feed.map_or("", |f| f.ecosystem);
        let mut v = json!({
            "record": r.id,
            "record_source": source_name(&r.id),
            "feed": r.source,
            "ecosystem": eco,
            "modified": r.modified,
            "kind": r.kind,
            "summary_text": r.summary.as_deref().map(crate::status::text),
        });
        if r.withdrawn.is_some() || r.gone {
            v["answered"] = json!(false);
            v["said"] = json!(if r.gone {
                "The record has left the data, so it matches nothing."
            } else {
                "The record is withdrawn, so it matches nothing."
            });
            list.push(v);
            continue;
        }
        if r.kind == "informational" {
            v["answered"] = json!(false);
            v["said"] = json!(
                "An informational advisory, such as an unmaintained crate: this version does not answer these."
            );
            list.push(v);
            continue;
        }
        v["answered"] = json!(true);
        let stored: HashMap<String, Vec<Value>> = {
            let mut m: HashMap<String, Vec<Value>> = HashMap::new();
            let mut stmt = conn.prepare(
                "SELECT checkout, package, answer, reason, detail, entries, fixed, read_at, since_at,
                        modified
                 FROM vulnerability_answer WHERE source = ?1 AND advisory = ?2
                 ORDER BY checkout, package",
            )?;
            let rows = stmt.query_map(params![r.source, r.id], |q| {
                let entries: String = q.get(5)?;
                let fixed: String = q.get(6)?;
                let answer: String = q.get(2)?;
                let reason: String = q.get(3)?;
                let entries: Value = serde_json::from_str(&entries).unwrap_or(Value::Null);
                let at: Vec<Value> = entries
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|e| {
                        json!({
                            "version_text": e["version"].as_str().map(crate::status::text),
                            "at_text": e["at"].as_str().map(|a| crate::status::text(&at_shown(a))),
                            "from": e["from"],
                            "affected": e["affected"],
                        })
                    })
                    .collect();
                let mut v = json!({
                    "package_text": crate::status::text(&q.get::<_, String>(1)?),
                    "answer": answer,
                    "detail_text": crate::status::text(&q.get::<_, String>(4)?),
                    "entries": at,
                    "fixed_text": serde_json::from_str::<Vec<String>>(&fixed).unwrap_or_default().iter().map(|f| crate::status::text(f)).collect::<Vec<_>>(),
                    "data_read_at": iso(q.get(7)?),
                    "since": crate::view::iso(q.get(8)?),
                    "record_modified": q.get::<_, String>(9)?,
                });
                match answer.as_str() {
                    "unknown" => v["reason"] = json!(reason),
                    "not_affected" => {
                        v["certainty"] = json!("known");
                        v["openvex"] = json!(if reason == "fixed" { "fixed" } else { "vulnerable_code_not_present" });
                    }
                    _ => {}
                }
                Ok((q.get::<_, String>(0)?, v))
            })?;
            for row in rows {
                let (checkout, v) = row?;
                m.entry(checkout).or_default().push(v);
            }
            m
        };
        let mut answers: Vec<Value> = Vec::new();
        for p in places.iter().filter(|p| p.1 == eco) {
            let a = match stored.get(&p.0) {
                Some(found) => json!({
                    "project_text": place_of(&p.0),
                    "ecosystem": p.1,
                    "packages": found,
                }),
                // The project holds no package the record names.
                None => {
                    let mut a = derived(p, "known");
                    if a["answer"] == "not_affected" {
                        a["openvex"] = json!("component_not_present");
                    }
                    a
                }
            };
            answers.push(a);
        }
        v["answers"] = Value::Array(answers);
        list.push(v);
    }
    out["records"] = Value::Array(list);
    Ok(out)
}

// ---- Findings: what they say of the thing they are about. ----

/// Where a finding about a component is and what it rests on, as a person reads them: the
/// lockfile lines of the releases, and the package, its releases and the records with their
/// sources and summaries. `None` when no answer affects it now.
pub fn finding_detail(conn: &Connection, about: &str) -> Option<(String, String)> {
    let list = affecting(conn).ok()?;
    let mine: Vec<&Affecting> = list
        .iter()
        .filter(|a| format!("component:{}/{}/{}", a.checkout, a.ecosystem, a.package) == about)
        .collect();
    let first = mine.first()?;
    let mut at: Vec<String> = Vec::new();
    let mut releases: BTreeSet<String> = BTreeSet::new();
    for a in &mine {
        for (v, line) in a.affected() {
            releases.insert(v);
            let shown = at_shown(&line);
            if !at.contains(&shown) {
                at.push(shown);
            }
        }
    }
    let records: Vec<String> = mine
        .iter()
        .map(|a| {
            let mut s = format!("{} from {}", a.advisory, source_name(&a.advisory));
            if let Some(summary) = &a.summary {
                s.push_str(&format!(": {summary}"));
            }
            if !a.fixed.is_empty() {
                s.push_str(&format!(" (fixed in {})", a.fixed.join(", ")));
            }
            s
        })
        .collect();
    let value = format!(
        "{} {}; {}",
        first.package,
        releases.into_iter().collect::<Vec<_>>().join(", "),
        records.join("; ")
    );
    Some((at.join(", "), value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        version(s).unwrap_or_else(|| panic!("{s}"))
    }

    #[test]
    fn the_line_a_person_reads_says_one_as_one() {
        let t = |records, packages, projects| Totals {
            records,
            packages,
            projects,
            ..Totals::default()
        };
        assert_eq!(
            records_said(&t(1, 1, 1)),
            "1 known vulnerability in 1 package, across 1 project."
        );
        assert_eq!(
            records_said(&t(1473, 116, 9)),
            "1,473 known vulnerabilities in 116 packages, across 9 projects."
        );
    }

    /// node-semver's fixture rows, `[a, b, opt]`, as data. `opt` is loose when it is `true`
    /// or `{ loose: true }`.
    fn rows(file: &str) -> Vec<(String, String, bool)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/semver")
            .join(file);
        let text = std::fs::read_to_string(path).unwrap();
        text.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("['") || l.starts_with("[\""))
            .map(|l| {
                let quoted: Vec<&str> = l.split('\'').collect();
                let rest = quoted.get(4).copied().unwrap_or_default();
                let loose = rest.contains("true") && !rest.contains("loose: false");
                (quoted[1].to_string(), quoted[3].to_string(), loose)
            })
            .collect()
    }

    #[test]
    fn versions_are_ordered_as_node_semver_orders_strict_ones_and_a_loose_one_is_never_read() {
        // npm's reference is node-semver; its own fixtures are the samples. A strict row must
        // compare as node-semver does. A row node-semver reads only loosely must not parse:
        // coercing it would give an answer the data does not support.
        let comparisons = rows("comparisons.js");
        assert_eq!(comparisons.len(), 31);
        let mut strict = 0;
        for (a, b, loose) in &comparisons {
            if *loose {
                assert!(version(a).is_none() || version(b).is_none(), "{a} {b}");
                continue;
            }
            strict += 1;
            assert_eq!(compare(&v(a), &v(b)), Ordering::Greater, "{a} > {b}");
            assert_eq!(compare(&v(b), &v(a)), Ordering::Less, "{b} < {a}");
        }
        assert_eq!(strict, 19);
        let equality = rows("equality.js");
        assert_eq!(equality.len(), 37);
        for (a, b, loose) in &equality {
            // node-semver trims and takes a leading `v` even when strict; this program does
            // neither, which is the safe side: such a version is "don't know".
            if *loose || a.trim() != a || a.starts_with('v') {
                assert!(version(a).is_none() || version(b).is_none(), "{a} {b}");
                continue;
            }
            assert_eq!(compare(&v(a), &v(b)), Ordering::Equal, "{a} = {b}");
        }
        // invalid-versions.js: none is a version. Its numbers too big for JavaScript fit in
        // 64 bits here and are ordered as numbers; a registry never serves them.
        let max_length = 256;
        let too_long = format!("{}.0.0", "1".repeat(max_length - 1));
        for s in [too_long.as_str(), "hello, world", "xyz"] {
            assert!(version(s).is_none(), "{s}");
        }
        assert_eq!(
            compare(&v("90071992547409910.0.0"), &v("9007199254740991.0.0")),
            Ordering::Greater
        );
    }

    #[test]
    fn a_pre_release_sits_where_semver_puts_it() {
        // semver.org, item 11: the chain, and build metadata ignored. RustSec writes
        // `0.0.0-0` and `x.y.z-0` so that every pre-release falls in a range.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.0",
            "2.1.0",
            "2.1.1",
        ];
        for w in chain.windows(2) {
            assert_eq!(
                compare(&v(w[0]), &v(w[1])),
                Ordering::Less,
                "{} < {}",
                w[0],
                w[1]
            );
        }
        assert_eq!(compare(&v("1.0.0+a"), &v("1.0.0+b")), Ordering::Equal);
        let ranges = json!([{ "type": "SEMVER", "events": [{"introduced": "0.0.0-0"}, {"fixed": "1.2.0-0"}] }]);
        assert_eq!(
            judge(&v("1.2.0-beta.1"), &ranges, &json!([])),
            Verdict::NotAffected { fixed: true }
        );
        assert_eq!(judge(&v("1.1.9"), &ranges, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("0.1.0-alpha"), &ranges, &json!([])),
            Verdict::Affected
        );
        let plain =
            json!([{ "type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}] }]);
        assert_eq!(
            judge(&v("2.0.0-rc.1"), &plain, &json!([])),
            Verdict::Affected
        );
    }

    #[test]
    fn a_range_is_walked_as_the_osv_schema_says_and_what_it_cannot_say_is_never_not_affected() {
        // IsVulnerable: events sorted, introduced on, fixed or past last_affected off, below a
        // limit. Unsorted events, as the schema allows, give the same answer.
        let r = |events: Value| json!([{ "type": "SEMVER", "events": events }]);
        let two = r(
            json!([{"fixed": "1.2.5"}, {"introduced": "1.2.0"}, {"introduced": "0"}, {"fixed": "1.0.0"}]),
        );
        for (release, verdict) in [
            ("0.9.0", Verdict::Affected),
            ("1.0.0", Verdict::NotAffected { fixed: true }),
            ("1.1.0", Verdict::NotAffected { fixed: true }),
            ("1.2.0", Verdict::Affected),
            ("1.2.5", Verdict::NotAffected { fixed: true }),
        ] {
            assert_eq!(judge(&v(release), &two, &json!([])), verdict, "{release}");
        }
        let last = r(json!([{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]));
        assert_eq!(judge(&v("1.4.0"), &last, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("0.9.0"), &last, &json!([])),
            Verdict::NotAffected { fixed: false }
        );
        assert!(matches!(
            judge(&v("1.5.0"), &last, &json!([])),
            Verdict::Unknown(NOT_COVERED, _)
        ));
        let limited = r(json!([{"introduced": "0"}, {"limit": "2.0.0"}]));
        assert_eq!(judge(&v("1.9.9"), &limited, &json!([])), Verdict::Affected);
        assert_eq!(
            judge(&v("2.0.0"), &limited, &json!([])),
            Verdict::NotAffected { fixed: false }
        );
        // A listed release is affected by equality; a value that is not SemVer is never
        // taken for "not affected".
        assert_eq!(
            judge(&v("3.1.4"), &json!([]), &json!(["3.1.4"])),
            Verdict::Affected
        );
        let loose = r(json!([{"introduced": "13.0"}, {"fixed": "14.2.10"}]));
        assert!(matches!(
            judge(&v("15.0.0"), &loose, &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        let commits = json!([{ "type": "GIT", "repo": "https://example.org/x", "events": [{"introduced": "0"}] }]);
        assert!(matches!(
            judge(&v("1.0.0"), &commits, &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        assert!(matches!(
            judge(&v("1.0.0"), &json!([]), &json!([])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
        assert!(matches!(
            judge(&v("1.0.0"), &json!([]), &json!(["v1.0.0"])),
            Verdict::Unknown(NOT_COMPARABLE, _)
        ));
    }
}
