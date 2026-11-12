//! What the store knows of one thing, as the contract's `Known` message
//! (`contract/immune/v1/known.proto`): the answer that `immune project`, `immune program` and
//! `immune machine` share.
//!
//! It reads the store and nothing else. No reader runs and no path is looked at: a thing may be
//! in a folder macOS asks permission for, and looking would raise the dialog.
//!
//! A command of the contract only turns what was asked into a `Question`: the entity it names,
//! the folder it lies in where it has one, and the readings that find things of its kind. The
//! rest is here, the same for each.
//!
//! False calm is what this guards against. "The store has never heard of it" (`unknown`), "known,
//! and every reading of it full" and "known, but a part of it was not read" are told apart: the
//! first by `presence`, the other two by the coverage that comes with every answer. An unknown
//! thing carries the readings that could have found it, so "unknown because nothing looked" is
//! visible. A thing in a folder macOS asks permission for carries the reading that says the folder
//! was not looked into, whatever was read in it before. A path that none of those readings looks
//! at, answered `unknown`, carries a reading made by rule that says so, since "every reading
//! full" would otherwise read as "looked, and not there".

use crate::contract::{self, v1, value_of};
use crate::{Stop, checkouts, findings, guarded, status, store};
use prost::Message;
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

/// The version of the contract this build prints.
const FORMAT: u32 = 1;

/// One question, as the store can answer it.
pub struct Question<'a> {
    /// Which question it is.
    pub question: v1::Question,
    /// What was asked for, as given.
    pub asked: &'a str,
    /// The entity asked for; `None` when the store cannot name it.
    pub id: Option<&'a str>,
    /// The ids the store knows the same thing by, such as a machine's under names the resolver
    /// found to be one (`same_as`). What the store knows under each is the thing's own.
    pub also: &'a [String],
    /// The machine and the path of the folder it lies in, as ids name paths, where it has one:
    /// files whose path is in it are its parts, findings about anything in it are its findings,
    /// and a folder macOS asks permission for that holds it speaks for it.
    pub folder: Option<(&'a str, &'a str)>,
    /// The path asked about, as ids name paths, when the question was a path on this Mac: a
    /// folder macOS asks permission for that holds it speaks for the answer.
    pub place: Option<&'a str>,
    /// When the question was a path that no reading in `found_by` looks at: why, in the core's
    /// words. The answer carries a reading made by rule with it. Such a path names nothing the
    /// store knows, since what the store knows was found by those readings.
    pub unread: Option<&'static str>,
    /// This Mac: its latest readings in `found_by` speak for the thing, known or not.
    pub machine: Option<&'a str>,
    /// The readings, as reader and kind, that find things of its kind on this Mac.
    pub found_by: &'a [(&'a str, &'a str)],
    /// The readings of this Mac, as reader and kind, that read inside every thing of its kind:
    /// they speak for every one the store knows, whatever was found in it.
    pub inside: &'a [(&'a str, String)],
}

/// The reader of the reading made by rule for a path no reading looks at: the core itself.
pub const RULE_READER: &str = "immune";

/// A question the store cannot answer with one thing of the kind asked for: a misuse, told with
/// the ids of what it found, so that the caller can ask again for one.
pub struct Refused {
    pub code: &'static str,
    /// The core's own words.
    pub message: &'static str,
    pub example: &'static str,
    /// The entities the question fits, whole.
    pub ids: Vec<String>,
}

/// A path that names nothing the store knows as written, and something it knows when the two are
/// compared without regard to case. On a volume that ignores case, as a Mac's do by default, it
/// may be the same place; answering `unknown` would say that nothing is known of it.
pub fn spelled_otherwise(ids: Vec<String>, example: &'static str) -> Refused {
    Refused {
        code: "spelled_otherwise",
        message: "the path names nothing the store knows as written, and these when case is ignored; nothing was answered",
        example,
        ids,
    }
}

/// The form a command of the contract prints its message in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// Binary protobuf, `--proto`: what a command of the contract prints when no form is named.
    Proto,
    /// The same message as one line of JSON, `--json`.
    Json,
}

/// Takes `--json` or `--proto` into `form`, so that a program can always name the form it
/// wants; false for any other argument. Naming both is a misuse.
pub fn take_form(arg: &str, form: &mut Option<Form>) -> Result<bool, String> {
    let named = match arg {
        "--json" => Form::Json,
        "--proto" => Form::Proto,
        _ => return Ok(false),
    };
    if form.is_some_and(|f| f != named) {
        return Err("--json and --proto each name the form of the answer; give one".to_string());
    }
    *form = Some(named);
    Ok(true)
}

/// The words after the command: `--store`, the form, and the rest in order.
pub struct Words {
    pub store: PathBuf,
    pub json: bool,
    pub words: Vec<String>,
}

/// Reads the arguments after a command of the contract.
pub fn words(mut it: impl Iterator<Item = String>) -> Result<Words, String> {
    let (mut store, mut form, mut words) = (None, None, Vec::new());
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            _ if take_form(&arg, &mut form)? => {}
            _ if arg.starts_with("--") => return Err(format!("unexpected argument: {arg}")),
            _ => words.push(arg),
        }
    }
    Ok(Words {
        store: store.map_or_else(crate::default_store, Ok)?,
        json: form == Some(Form::Json),
        words,
    })
}

/// A path as ids name it on this Mac: relative to the home folder when it is inside it, the full
/// path otherwise. `None` when `asked` is neither absolute nor begins with `~/`. A path is made
/// plain by its words alone: `..` is resolved without looking at the disk, and no link is
/// followed.
pub fn path_of(asked: &str, home: &Path) -> Option<String> {
    let path = match asked.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if asked.starts_with('/') => PathBuf::from(asked),
        None => return None,
    };
    let mut plain = PathBuf::new();
    for part in path.components() {
        if part == Component::ParentDir {
            plain.pop();
        } else {
            plain.push(part);
        }
    }
    Some(checkouts::rel(home, &plain))
}

/// Answers a command of the contract: the message on stdout, binary or JSON; a refusal as a
/// misuse; a store that cannot be read the way the report commands say it. `ask` turns the
/// question into the answer, in one read transaction so that it is of one state of the store.
pub fn command<M: Message + serde::Serialize>(
    op: &str,
    store: &Path,
    json: bool,
    ask: impl FnOnce(&Connection, i64) -> rusqlite::Result<Result<M, Refused>>,
) -> ExitCode {
    let answer = match read(store, |conn| ask(conn, crate::now_secs())) {
        Ok(Ok(answer)) => answer,
        Ok(Err(refused)) => return refuse(op, json, &refused),
        Err(e) => return failed(op, json, &e),
    };
    if json {
        match serde_json::to_string(&answer) {
            Ok(line) => println!("{line}"),
            Err(e) => return failed(op, true, &Stop::Store(e.to_string())),
        }
    } else if std::io::stdout()
        .write_all(&answer.encode_to_vec())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// A store that cannot be read, said as the report commands say it, in the envelope of the
/// contract with `--json`.
fn failed(op: &str, json: bool, e: &Stop) -> ExitCode {
    if !json {
        return crate::store_failed(false, op, e);
    }
    let (v, exit) = crate::failure_of(op, e);
    println!("{}", envelope(v));
    ExitCode::from(exit)
}

fn read<T>(store: &Path, ask: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T, Stop> {
    if !store.is_file() {
        return Err(Stop::Store(format!(
            "there is no store at {}; `immune run` makes it",
            store.display()
        )));
    }
    let unreadable = |e: Box<dyn std::error::Error>| Stop::Store(e.to_string());
    let conn = store::open_read_only(store).map_err(unreadable)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Stop::Store(e.to_string()))?;
    ask(&tx).map_err(|e| Stop::Store(older(e.to_string())))
}

/// The failure envelope of a command of the contract: the report commands' envelope without
/// `format`. Parsed with the contract's types all the same, it reads as format 0, which no
/// reader takes for an answer.
pub fn envelope(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(fields) = v.as_object_mut() {
        fields.remove("format");
    }
    v
}

/// A refusal as a misuse: nothing on stdout in binary, the failure envelope with `--json`, whose
/// error lists the ids it fits in `ids_text`, whole.
fn refuse(op: &str, json: bool, r: &Refused) -> ExitCode {
    let ids: Vec<String> = r.ids.iter().map(|id| whole(id)).collect();
    if json {
        let mut v = status::failure(Some(op), r.code, r.message, r.example, &ids.join(", "));
        v["errors"][0]["ids_text"] = serde_json::json!(ids);
        println!("{}", envelope(v));
    } else {
        eprintln!("immune: {}. {}", r.message, r.example);
        for id in &ids {
            eprintln!("  {id}");
        }
    }
    ExitCode::from(crate::EXIT_USAGE)
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

/// Whether the store has an entity with this id, of any type.
pub fn exists(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM entity WHERE id = ?1)",
        [id],
        |r| r.get(0),
    )
}

/// The readings among `found_by` that speak for the thing `id`. For a thing the store never
/// heard of, every one: each could have found it, and the answer says that none did. For a
/// thing the store holds or held, those that wrote about it, whether what they wrote is in
/// force or retracted: a reading that finds another kind of thing says nothing of this one.
pub fn found_by<'a>(
    conn: &Connection,
    id: Option<&str>,
    found_by: &[(&'a str, &'a str)],
) -> rusqlite::Result<Vec<(&'a str, &'a str)>> {
    let id = match id {
        Some(id) if exists(conn, id)? => id,
        _ => return Ok(found_by.to_vec()),
    };
    let mut q = conn.prepare(
        "SELECT EXISTS (SELECT 1 FROM assertion WHERE subject = ?1 AND reader = ?2 AND kind = ?3
                          AND layer IN ('live', 'retracted'))",
    )?;
    let mut out = Vec::new();
    for &(reader, kind) in found_by {
        if q.query_row([id, reader, kind], |r| r.get(0))? {
            out.push((reader, kind));
        }
    }
    Ok(out)
}

/// What the store knows of the thing asked for, its parts, the readings that speak for it and the
/// findings about it. `home` is the home folder ids name paths in.
pub fn known_of(
    conn: &Connection,
    q: &Question,
    home: &Path,
    now: i64,
) -> rusqlite::Result<v1::Known> {
    let mut known = v1::Known {
        format: FORMAT,
        question: q.question as i32,
        asked_text: whole(q.asked),
        answered_at: now,
        presence: v1::Presence::Unknown as i32,
        latest_run_at: status::latest_finished(conn)?.and_then(|r| r.finished_at),
        store_id: store::id(conn)?,
        ..Default::default()
    };
    let thing = match q.id {
        Some(id) => type_of(conn, id)?.map(|ty| (id, ty)),
        None => None,
    };
    // The thing under each of its ids, and its parts, by id: whose facts are given and whose
    // readings speak. Findings are those about these, and about what was ever inside the thing.
    let mut subjects: BTreeMap<String, String> = BTreeMap::new();
    let mut ever: BTreeSet<String> = BTreeSet::new();
    if let Some((id, ty)) = &thing {
        let mut own: Parts = Parts::new();
        own.insert(id.to_string(), ty.clone());
        for other in q.also {
            own.extend(type_of(conn, other)?.map(|ty| (other.clone(), ty)));
        }
        let mut all = Parts::new();
        let mut held = false;
        for own_id in own.keys() {
            let (inside, in_folder) = parts(conn, own_id, q.folder)?;
            // Held while something read of it is in force: a fact about it, or a part `part_of`
            // or `located_on` it. A machine may have no fact of its own and still hold everything
            // on it.
            held = held
                || !inside.is_empty()
                || conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM assertion WHERE layer = 'live' AND subject = ?1)",
                    [own_id],
                    |r| r.get(0),
                )?;
            all.extend(inside);
            all.extend(in_folder);
            ever.extend(ever_inside(conn, own_id)?);
        }
        known.presence = if held {
            v1::Presence::Held
        } else {
            v1::Presence::Gone
        } as i32;
        known.thing = Some(entity(id, ty));
        known.same_as = own
            .iter()
            .filter(|(other, _)| other.as_str() != *id)
            .map(|(other, ty)| entity(other, ty))
            .collect();
        known.parts = all.iter().map(|(id, ty)| entity(id, ty)).collect();
        subjects.extend(own);
        subjects.extend(all);
    }
    known.facts = facts(conn, subjects.keys())?;
    let read_by = reading_keys(conn, subjects.keys())?;
    let guarded = q
        .folder
        .map(|(_, rel)| rel)
        .or(q.place)
        .and_then(|rel| guarded_folder(rel, home));
    known.coverage = latest(conn)?
        .into_iter()
        .filter(|r| {
            let this = Some(r.scope.as_str()) == q.machine;
            let key = (r.reader.as_str(), r.kind.as_str());
            subjects.contains_key(&r.scope)
                || read_by.contains(&(r.reader.clone(), r.scope.clone(), r.kind.clone()))
                || (this
                    && (q.found_by.contains(&key)
                        || (thing.is_some()
                            && q.inside
                                .iter()
                                .any(|(reader, kind)| (*reader, kind.as_str()) == key))
                        || guarded.as_deref().is_some_and(|f| not_looked_into(r, f))))
        })
        .map(|r| coverage(conn, r))
        .collect::<rusqlite::Result<_>>()?;
    if let (Some(reason), Some(machine)) = (q.unread, q.machine) {
        by_rule(
            &mut known,
            RULE_READER,
            unread_kind(q.question),
            machine,
            reason,
        );
    }
    known.findings = finding_refs(conn, now, |about| {
        subjects.contains_key(about)
            || ever.contains(about)
            || q.folder.is_some_and(|(machine, rel)| {
                place_of(about).is_some_and(|(m, at)| m == machine && within(at, rel))
            })
    })?;
    Ok(known)
}

/// The kind of the reading made by rule for a path no reading that finds things of the kind
/// looks at.
fn unread_kind(question: v1::Question) -> &'static str {
    match question {
        v1::Question::Program => "places the readings that find programs look in",
        _ => "places the readings that find projects look in",
    }
}

/// Adds to the answer a reading made by rule rather than read from the store: not made, with
/// the core's own words for why, in its place in the order of scope, reader and kind.
pub fn by_rule(known: &mut v1::Known, reader: &str, kind: &str, scope: &str, reason: &str) {
    let reading = v1::Coverage {
        reader: reader.to_string(),
        kind: kind.to_string(),
        scope_text: whole(scope),
        completeness: v1::Completeness::None as i32,
        reason_text: Some(reason.to_string()),
        cause: Some(v1::Cause::NotGiven as i32),
        observed_at: None,
        lacks: Vec::new(),
    };
    let key = |c: &v1::Coverage| (c.scope_text.clone(), c.reader.clone(), c.kind.clone());
    let at = known.coverage.partition_point(|c| key(c) < key(&reading));
    known.coverage.insert(at, reading);
}

/// The type of the entity with this id, if the store has one.
pub fn type_of(conn: &Connection, id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT type FROM entity WHERE id = ?1", [id], |r| r.get(0))
        .optional()
}

/// Whether the path `rel` is the folder `folder` or lies in it, as ids name paths.
pub fn within(rel: &str, folder: &str) -> bool {
    rel.strip_prefix(folder)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Text from the Mac as the contract gives it: hidden characters and the backslash escaped, so
/// that the shown form is unique and asks back the same thing (`contract::unescape`).
pub fn whole(s: &str) -> String {
    contract::escape(s, crate::icu::hidden)
}

fn entity(id: &str, ty: &str) -> v1::Entity {
    v1::Entity {
        id_text: whole(id),
        r#type: ty.to_string(),
    }
}

/// Things by id, with their types.
type Parts = BTreeMap<String, String>;

/// The things inside `id` with facts in force: what is `part_of` or `located_on` it, one level,
/// and apart, files whose path is in its folder. Nothing deeper is followed: in a project there
/// is nothing deeper, since nothing is `part_of` a component or `located_on` a file, and a
/// machine's checkouts and containers are asked about with their own question.
fn parts(
    conn: &Connection,
    id: &str,
    folder: Option<(&str, &str)>,
) -> rusqlite::Result<(Parts, Parts)> {
    // One pass over the assertions: the store has no index by object.
    let inside: Parts = conn
        .prepare(
            "SELECT DISTINCT a.subject, e.type FROM assertion a JOIN entity e ON e.id = a.subject
             WHERE a.layer = 'live' AND a.predicate IN ('part_of', 'located_on')
               AND a.object = ?1",
        )?
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let in_folder: Parts = match folder {
        // Every file id that begins with the folder's: from `file:<machine>/<path>/` up to,
        // not including, the same with `0`, the character after `/`.
        Some((machine, rel)) => conn
            .prepare(
                "SELECT DISTINCT a.subject, e.type FROM assertion a JOIN entity e ON e.id = a.subject
                 WHERE a.layer = 'live' AND a.subject > ?1 AND a.subject < ?2",
            )?
            .query_map(
                [format!("file:{machine}/{rel}/"), format!("file:{machine}/{rel}0")],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
            .collect::<rusqlite::Result<_>>()?,
        None => Parts::new(),
    };
    Ok((inside, in_folder))
}

/// What was ever `part_of` or `located_on` `id`, whether that is in force or retracted: a finding
/// about a part stays the thing's after the part is gone, as it stays open until it is answered.
fn ever_inside(conn: &Connection, id: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer IN ('live', 'retracted') AND predicate IN ('part_of', 'located_on')
           AND object = ?1",
    )?
    .query_map([id], |r| r.get(0))?
    .collect()
}

/// The machine and the path an id of a checkout or a file names.
pub fn place_of(id: &str) -> Option<(&str, &str)> {
    ["checkout:", "file:"]
        .iter()
        .find_map(|p| id.strip_prefix(p))
        .and_then(|rest| rest.split_once('/'))
}

/// The folder macOS asks permission for that holds a path as ids name it, as the readers name
/// it in their reasons, such as `~/Documents`.
fn guarded_folder(rel: &str, home: &Path) -> Option<String> {
    // A full path, outside the home folder, replaces it in the join.
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
/// Looked up by subject: left to itself, SQLite takes the index by layer and goes through every
/// live assertion once per subject, 2.7 s for a Mac of 3,600 packages instead of 0.1 s.
fn reading_keys<'a>(
    conn: &Connection,
    subjects: impl Iterator<Item = &'a String>,
) -> rusqlite::Result<BTreeSet<(String, String, String)>> {
    let mut q = conn.prepare(
        "SELECT DISTINCT reader, scope, kind FROM assertion WHERE +layer = 'live' AND subject = ?1",
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
/// is not full and was written before causes were kept failed, as the status reads it. Its
/// reason is given whole: what was cut off could be what the reading did not cover.
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
                name_text: name.as_deref().map(whole),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(v1::Coverage {
        completeness: value_of::<v1::Completeness>(&r.completeness),
        reason_text: r.reason.as_deref().map(whole),
        cause: cause.map(value_of::<v1::Cause>),
        observed_at: Some(r.at),
        scope_text: whole(&r.scope),
        reader: r.reader,
        kind: r.kind,
        lacks,
    })
}

/// The findings about what `about` takes, in every state, the most severe first.
fn finding_refs(
    conn: &Connection,
    now: i64,
    about: impl Fn(&str) -> bool,
) -> rusqlite::Result<Vec<v1::FindingRef>> {
    let Some(found) = findings::all(conn, now)? else {
        return Ok(Vec::new());
    };
    let mut items: Vec<findings::Item> = found
        .iter()
        .filter(|f| about(&f.about))
        .filter_map(findings::item)
        .collect();
    findings::order(&mut items);
    Ok(items.iter().map(finding_ref).collect())
}

/// A finding by reference, as every message of the contract names one.
pub fn finding_ref(i: &findings::Item) -> v1::FindingRef {
    v1::FindingRef {
        id: i.id.clone(),
        rule: i.rule.map(str::to_string),
        about_text: whole(&i.about),
        state: value_of::<v1::FindingState>(&i.state),
        severity: value_of::<v1::Level>(i.severity),
        confidence: i.confidence.map(value_of::<v1::Level>),
        urgent: findings::urgent(i.severity, i.confidence),
    }
}
