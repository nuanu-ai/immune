//! `immune project <what>`: what the store knows of one project, a checkout, printed as the
//! contract's `Known` message (`contract/immune/v1/known.proto`).
//!
//! It reads the store and nothing else. No reader runs and the project's folder is never looked
//! at: a project may be in a folder macOS asks permission for, and looking would raise the
//! dialog. A path is turned into the checkout's id by the rule the readers name checkouts by.
//!
//! The answer is built by `known_of`, which takes any entity: the same message will answer for a
//! program and a machine. What is particular to a project is only how the question names it and
//! which readings find projects (`FOUND_BY`).
//!
//! False calm is what this guards against. "The store has never heard of it" (`unknown`), "known,
//! and every reading of it full" and "known, but a part of it was not read" are told apart: the
//! first by `presence`, the other two by the coverage that comes with every answer. A project in
//! a folder macOS asks permission for carries the reading that says the folder was not looked
//! into, whatever was read in it before.

use crate::contract::{v1, value_of};
use crate::{Stop, checkouts, findings, guarded, status, store};
use prost::Message;
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

/// The version of the contract this build prints.
const FORMAT: u32 = 1;

/// The readings that find projects on a Mac, as reader and kind. Their latest reading of this
/// Mac speaks for every project, known or not: a project the walk did not reach is unknown for
/// that reason.
const FOUND_BY: [(&str, &str); 2] = [
    (checkouts::READER, checkouts::KIND),
    (crate::agent_folders::READER, crate::agent_folders::KIND),
];

/// What `immune project` takes as a project.
const WHAT: &str = "immune project takes a path on this Mac, absolute or beginning with ~/, or a project's id as the store names it, beginning with checkout:";

/// `immune project <what>`.
pub struct ProjectArgs {
    pub store: PathBuf,
    pub json: bool,
    /// What was asked for, as given.
    pub asked: String,
    pub what: What,
    /// The home folder: checkout ids name a path inside it relative to it.
    pub home: PathBuf,
}

/// The project asked for.
pub enum What {
    /// A folder, as checkout ids name it: relative to the home folder when it is inside it,
    /// the full path otherwise.
    Path(String),
    /// A checkout's id.
    Id(String),
}

/// Reads the arguments after `project`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<ProjectArgs, String> {
    let (mut store, mut json, mut words) = (None, false, Vec::new());
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            "--json" => json = true,
            _ if arg.starts_with("--") => return Err(format!("unexpected argument: {arg}")),
            _ => words.push(arg),
        }
    }
    let [asked] = <[String; 1]>::try_from(words).map_err(|_| WHAT.to_string())?;
    let home = crate::user_home()?;
    let what = what_of(&asked, &home)?;
    Ok(ProjectArgs {
        store: store.map_or_else(crate::default_store, Ok)?,
        json,
        asked,
        what,
        home,
    })
}

/// The project a word names. A path is made plain by its words alone: `..` is resolved without
/// looking at the disk, and no link is followed.
fn what_of(asked: &str, home: &Path) -> Result<What, String> {
    if asked.starts_with("checkout:") {
        return Ok(What::Id(asked.to_string()));
    }
    let path = match asked.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if asked.starts_with('/') => PathBuf::from(asked),
        None => return Err(WHAT.to_string()),
    };
    let mut plain = PathBuf::new();
    for part in path.components() {
        if part == Component::ParentDir {
            plain.pop();
        } else {
            plain.push(part);
        }
    }
    Ok(What::Path(checkouts::rel(home, &plain)))
}

/// Answers `immune project`: the message on stdout, binary or JSON, or a failure the way the
/// report commands give one.
pub fn project_cmd(args: &ProjectArgs) -> ExitCode {
    let known = match read(args, crate::now_secs()) {
        Ok(known) => known,
        Err(e) => return crate::store_failed(args.json, "project", &e),
    };
    if args.json {
        match serde_json::to_string(&known) {
            Ok(line) => println!("{line}"),
            Err(e) => return crate::store_failed(true, "project", &Stop::Store(e.to_string())),
        }
    } else if std::io::stdout().write_all(&known.encode_to_vec()).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// The answer from the store, in one read transaction so that it is of one state of it.
fn read(args: &ProjectArgs, now: i64) -> Result<v1::Known, Stop> {
    if !args.store.is_file() {
        return Err(Stop::Store(format!(
            "there is no store at {}; `immune run` makes it",
            args.store.display()
        )));
    }
    let unreadable = |e: Box<dyn std::error::Error>| Stop::Store(e.to_string());
    let conn = store::open_read_only(&args.store).map_err(unreadable)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Stop::Store(e.to_string()))?;
    let this = crate::covered::this_machine(&tx).map_err(|e| Stop::Store(e.to_string()))?;
    let id = match &args.what {
        What::Id(id) => Some(id.clone()),
        // A store no run has written names no Mac, and so no project on it.
        What::Path(rel) => this.as_ref().map(|m| format!("checkout:{m}/{rel}")),
    };
    known_of(
        &tx,
        id.as_deref(),
        this.as_deref(),
        &FOUND_BY,
        &args.home,
        &args.asked,
        now,
    )
    .map_err(|e| Stop::Store(older(e.to_string())))
}

/// What a failure to read the store says. A store of this format written by an older build lacks
/// a column or a table that a run of this build adds when it opens the store: SQLite says
/// so in these words, and the owner is told what it is and what to do.
fn older(e: String) -> String {
    if e.starts_with("no such column") || e.starts_with("no such table") {
        format!(
            "the store was written by an older build of Immune; `immune run` brings it up to date ({e})"
        )
    } else {
        e
    }
}

/// What the store knows of the entity `id`, its parts, the readings that speak for it and the
/// findings about it. `None` is a thing the store cannot name. `found_by` are the readings, as
/// reader and kind, that find things of its kind on `machine`. `home` is the home folder ids
/// name paths in.
pub fn known_of(
    conn: &Connection,
    id: Option<&str>,
    machine: Option<&str>,
    found_by: &[(&str, &str)],
    home: &Path,
    asked: &str,
    now: i64,
) -> rusqlite::Result<v1::Known> {
    let mut known = v1::Known {
        format: FORMAT,
        asked_text: status::text_string(asked),
        answered_at: now,
        presence: v1::Presence::Unknown as i32,
        ..Default::default()
    };
    let thing = match id {
        Some(id) => conn
            .query_row("SELECT type FROM entity WHERE id = ?1", [id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|ty| (id, ty)),
        None => None,
    };
    // The thing and its parts, by id: whose facts are given and whose readings speak.
    let mut subjects: BTreeMap<String, String> = BTreeMap::new();
    if let Some((id, ty)) = &thing {
        let held: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM assertion WHERE layer = 'live' AND subject = ?1)",
            [id],
            |r| r.get(0),
        )?;
        known.presence = if held {
            v1::Presence::Held
        } else {
            v1::Presence::Gone
        } as i32;
        known.thing = Some(entity(id, ty));
        let parts = parts(conn, id)?;
        known.parts = parts.iter().map(|(id, ty)| entity(id, ty)).collect();
        subjects.insert(id.to_string(), ty.clone());
        subjects.extend(parts);
    }
    known.facts = facts(conn, subjects.keys())?;
    let read_by = reading_keys(conn, subjects.keys())?;
    let folder = id.and_then(|id| guarded_folder(id, home));
    known.coverage = latest(conn)?
        .into_iter()
        .filter(|r| {
            subjects.contains_key(&r.scope)
                || read_by.contains(&(r.reader.clone(), r.scope.clone(), r.kind.clone()))
                || (Some(r.scope.as_str()) == machine
                    && (found_by.contains(&(r.reader.as_str(), r.kind.as_str()))
                        || folder.as_deref().is_some_and(|f| not_looked_into(r, f))))
        })
        .map(|r| coverage(conn, r))
        .collect::<rusqlite::Result<_>>()?;
    known.findings = finding_refs(conn, &subjects, now)?;
    Ok(known)
}

/// A reference, an entity id or the place a fact was read, given whole so that it can be matched
/// and asked about again. Hidden characters are escaped, as in all text from a source.
fn whole(s: &str) -> String {
    crate::view::shown(s)
}

fn entity(id: &str, ty: &str) -> v1::Entity {
    v1::Entity {
        id_text: whole(id),
        r#type: ty.to_string(),
    }
}

/// The things inside `id` with facts in force: what is `part_of` or `located_on` it, and files
/// whose path is in its folder, by id with their types. In a project that is every depth there
/// is: nothing is `part_of` a component or `located_on` a file.
fn parts(conn: &Connection, id: &str) -> rusqlite::Result<BTreeMap<String, String>> {
    // One pass over the assertions: the store has no index by object. A machine, whose parts
    // have parts of their own, will need more than one level.
    let mut out: BTreeMap<String, String> = conn
        .prepare(
            "SELECT DISTINCT a.subject, e.type FROM assertion a JOIN entity e ON e.id = a.subject
             WHERE a.layer = 'live' AND a.predicate IN ('part_of', 'located_on')
               AND a.object = ?1",
        )?
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if let Some((machine, rel)) = place_of(id) {
        // Every file id that begins with the folder's: from `file:<machine>/<path>/` up to,
        // not including, the same with `0`, the character after `/`.
        let from = format!("file:{machine}/{rel}/");
        let to = format!("file:{machine}/{rel}0");
        let mut q = conn.prepare(
            "SELECT DISTINCT a.subject, e.type FROM assertion a JOIN entity e ON e.id = a.subject
             WHERE a.layer = 'live' AND a.subject > ?1 AND a.subject < ?2",
        )?;
        for row in q.query_map([&from, &to], |r| Ok((r.get(0)?, r.get(1)?)))? {
            let (id, ty): (String, String) = row?;
            out.insert(id, ty);
        }
    }
    Ok(out)
}

/// The machine and the path an id of a checkout or a file names.
fn place_of(id: &str) -> Option<(&str, &str)> {
    ["checkout:", "file:"]
        .iter()
        .find_map(|p| id.strip_prefix(p))
        .and_then(|rest| rest.split_once('/'))
}

/// The folder macOS asks permission for that holds the thing, as the readers name it in their
/// reasons, such as `~/Documents`.
fn guarded_folder(id: &str, home: &Path) -> Option<String> {
    // A full path, outside the home folder, replaces it in the join.
    let (_, rel) = place_of(id)?;
    guarded::folder_of(&home.join(rel), home).map(|g| guarded::shown(&g, home))
}

/// Whether a reading says that it did not look into `folder`, as the reading of folders macOS asks
/// permission for words it.
fn not_looked_into(r: &Reading, folder: &str) -> bool {
    r.reason
        .as_deref()
        .and_then(|s| s.strip_prefix(guarded::NOT_LOOKED_INTO))
        .is_some_and(|named| named.split(", ").any(|f| f == folder))
}

/// The facts in force about these subjects, each with the assertions it rests on.
fn facts<'a>(
    conn: &Connection,
    subjects: impl Iterator<Item = &'a String>,
) -> rusqlite::Result<Vec<v1::Fact>> {
    let mut q = conn.prepare(
        "SELECT predicate, object, reader, basis, source_ref, observed_at, scope, kind
         FROM assertion WHERE layer = 'live' AND subject = ?1
         ORDER BY predicate, object, reader, id",
    )?;
    let mut out: Vec<v1::Fact> = Vec::new();
    for subject in subjects {
        let mut last: Option<(String, String)> = None;
        let mut rows = q.query([subject])?;
        while let Some(r) = rows.next()? {
            let (predicate, object): (String, String) = (r.get(0)?, r.get(1)?);
            let basis: String = r.get(3)?;
            let assertion = v1::Assertion {
                reader: r.get(2)?,
                basis: value_of::<v1::Basis>(&basis),
                source_ref_text: whole(&r.get::<_, String>(4)?),
                observed_at: r.get(5)?,
                scope_text: whole(&r.get::<_, String>(6)?),
                kind: r.get(7)?,
            };
            let key = Some((predicate.clone(), object.clone()));
            match out.last_mut() {
                Some(fact) if last == key => fact.assertions.push(assertion),
                _ => {
                    out.push(v1::Fact {
                        subject_text: whole(subject),
                        predicate,
                        object_text: whole(&object),
                        assertions: vec![assertion],
                    });
                    last = key;
                }
            }
        }
    }
    Ok(out)
}

/// The readings, as reader, scope and kind, that wrote the facts in force about these subjects.
fn reading_keys<'a>(
    conn: &Connection,
    subjects: impl Iterator<Item = &'a String>,
) -> rusqlite::Result<BTreeSet<(String, String, String)>> {
    let mut q = conn.prepare(
        "SELECT DISTINCT reader, scope, kind FROM assertion WHERE layer = 'live' AND subject = ?1",
    )?;
    let mut out = BTreeSet::new();
    for subject in subjects {
        for row in q.query_map([subject], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))? {
            out.insert(row?);
        }
    }
    Ok(out)
}

/// The latest reading of a reader, scope and kind, as the store keeps it.
struct Reading {
    id: i64,
    reader: String,
    scope: String,
    kind: String,
    completeness: String,
    reason: Option<String>,
    cause: Option<String>,
    at: i64,
}

/// The latest reading of every reader, scope and kind.
fn latest(conn: &Connection) -> rusqlite::Result<Vec<Reading>> {
    conn.prepare(&format!(
        "{latest}
         SELECT id, reader, scope, kind, completeness, reason, cause, observed_at FROM latest
         ORDER BY scope, reader, kind",
        latest = store::LATEST
    ))?
    .query_map([], |r| {
        Ok(Reading {
            id: r.get(0)?,
            reader: r.get(1)?,
            scope: r.get(2)?,
            kind: r.get(3)?,
            completeness: r.get(4)?,
            reason: r.get(5)?,
            cause: r.get(6)?,
            at: r.get(7)?,
        })
    })?
    .collect()
}

/// A reading as the contract gives it, with what it names as having no reader. A reading that
/// is not full and was written before causes were kept failed, as the status reads it.
fn coverage(conn: &Connection, r: Reading) -> rusqlite::Result<v1::Coverage> {
    let cause = match (r.completeness.as_str(), r.cause.as_deref()) {
        ("full", c) => c,
        (_, c) => Some(c.unwrap_or(store::Cause::Failed.literal())),
    };
    let lacks = conn
        .prepare("SELECT what, name FROM coverage_lack WHERE coverage = ?1 ORDER BY what, name")?
        .query_map([r.id], |row| {
            let (what, name): (String, Option<String>) = (row.get(0)?, row.get(1)?);
            Ok(v1::Lack {
                what,
                name_text: name.as_deref().map(status::text_string),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(v1::Coverage {
        completeness: value_of::<v1::Completeness>(&r.completeness),
        reason_text: r.reason.as_deref().map(status::text_string),
        cause: cause.map(value_of::<v1::Cause>),
        observed_at: r.at,
        scope_text: whole(&r.scope),
        reader: r.reader,
        kind: r.kind,
        lacks,
    })
}

/// The findings about these subjects, in every state, the most severe first.
fn finding_refs(
    conn: &Connection,
    subjects: &BTreeMap<String, String>,
    now: i64,
) -> rusqlite::Result<Vec<v1::FindingRef>> {
    let Some(found) = findings::all(conn, now)? else {
        return Ok(Vec::new());
    };
    let mut items: Vec<findings::Item> = found
        .iter()
        .filter(|f| subjects.contains_key(&f.about))
        .filter_map(findings::item)
        .collect();
    findings::order(&mut items);
    Ok(items
        .iter()
        .map(|i| v1::FindingRef {
            id: i.id.clone(),
            rule: i.rule.unwrap_or_default().to_string(),
            about_text: whole(&i.about),
            state: value_of::<v1::FindingState>(&i.state),
            severity: value_of::<v1::Level>(i.severity),
            confidence: value_of::<v1::Level>(i.confidence.unwrap_or_default()),
            urgent: findings::urgent(i.severity, i.confidence),
        })
        .collect())
}
