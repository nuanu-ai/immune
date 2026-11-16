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
//!
//! A thing answered with fewer findings than the store holds about it reads as safer than it is.
//! So its findings are those about it under every id it is known by and about anything inside it
//! at any depth, whatever was asked: a machine's include the packages of its projects, which its
//! parts, one level, do not list. Inside is the union of two ways, each of which only adds: what a
//! reading ever tied to it by `part_of` or `located_on`, in force or retracted, followed link by
//! link; and what its id names as inside it, which covers what no reading tied, such as a place
//! on a machine that could not be read.

use crate::answer::{self, Form};
use crate::contract::{self, v1, value_of};
use crate::{Stop, checkouts, findings, guarded, status, store};
use prost::Message;
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
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
    /// The folders of the thing's units, those it has and those it had, as ids name paths on
    /// `machine`: a finding about anything in one is the thing's, whatever form it was asked in.
    pub places: &'a [String],
    /// When the question was a path that is not judged on its own, such as one inside a thing or
    /// one under no thing the store holds: why, in the core's words. The answer carries a reading
    /// made by rule with it, of completeness `none`.
    pub unread: Option<&'a str>,
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

/// Why a path that names a thing the store holds only when case and Unicode form are ignored is
/// answered for that thing: on a volume that ignores both, as a Mac's do by default, it is the
/// same place, and answering `unknown` would leave out what is known of it.
const SPELLED: &str = "the path is spelled otherwise than the store holds it, in case or Unicode form: on a volume that ignores both, as a Mac's do by default, it is the same place, and the answer is about what the store holds there; on one that does not, it may be another place";

/// Why a name or an id is answered for a thing the store holds under another spelling of it.
pub const NAME_SPELLED: &str = "what was asked is spelled otherwise than the store holds it, in case or Unicode form: the answer is about what the store holds by that spelling";

/// Why a path asked about is not judged on its own, if it is not: found only when spelled
/// otherwise (`same_place`), and `inside`, the words for a path strictly inside a thing.
pub fn not_judged(spelled: bool, inside: Option<&str>) -> Option<String> {
    match (spelled, inside) {
        (true, Some(inside)) => Some(format!("{SPELLED}; {inside}")),
        (true, None) => Some(SPELLED.to_string()),
        (false, inside) => inside.map(str::to_string),
    }
}

impl Refused {
    /// The refusal as the contract's error, with the ids it fits whole.
    pub fn error(&self) -> v1::Error {
        v1::Error {
            ids_text: self.ids.iter().map(|id| whole(id)).collect(),
            ..answer::error(self.code, self.message, self.example, "")
        }
    }
}

/// Reads the positionals after a command of the contract that takes only the common options.
pub fn words(
    it: impl Iterator<Item = String>,
    options: &mut answer::Options,
) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    options.read(it, |arg, _| {
        if arg.starts_with("--") {
            return Err(format!("unexpected argument: {arg}"));
        }
        words.push(arg);
        Ok(())
    })?;
    Ok(words)
}

/// A path as ids name it on this Mac: relative to the home folder when it is inside it, the full
/// path otherwise. `None` when `asked` is neither absolute nor begins with `~/`. See `place_asked`.
pub fn path_of(asked: &str, home: &Path) -> Option<String> {
    place_asked(asked, None, home)
}

/// What a caller gives as a place on this Mac, `this`, in the one form ids name paths in: a path,
/// absolute or beginning with `~/`, or the id of a file of this Mac, which names its path after
/// the machine (`immune project` gives a checkout's id as a file's). `..`, `.`, doubled and
/// trailing slashes are resolved by the words alone, in an id as in a path: nothing on the disk
/// is looked at and no link is followed. Every command that takes a path or such an id puts it
/// through here, so two spellings of one place are one question. Case and Unicode form are kept:
/// they are compared only by `same_place`. `None` for anything else.
pub fn place_asked(asked: &str, this: Option<&str>, home: &Path) -> Option<String> {
    place_spelled(asked, this, home).map(|(rel, _)| rel)
}

/// The same, with whether the machine an id names is this Mac only when the two are compared by
/// the key (`spelling::key`): a match by the key alone is said, as for a path.
pub fn place_spelled(asked: &str, this: Option<&str>, home: &Path) -> Option<(String, bool)> {
    let mut spelled = false;
    let in_id = this.and_then(|machine| {
        let (named, rest) = asked.strip_prefix("file:")?.split_once('/')?;
        if named != machine {
            (crate::spelling::key(named) == crate::spelling::key(machine)).then_some(())?;
            spelled = true;
        }
        Some(rest)
    });
    let path = match (asked.strip_prefix("~/"), in_id) {
        // Only what follows the home folder: a slash after `~/` never leaves it.
        (Some(rest), _) => home.join(rest.trim_start_matches('/')),
        (None, _) if asked.starts_with('/') => PathBuf::from(asked),
        // An id names a path inside the home folder relative to it.
        (None, Some(rest)) if rest.starts_with('/') => PathBuf::from(rest),
        (None, Some(rest)) => home.join(rest),
        (None, None) => return None,
    };
    let mut plain = PathBuf::new();
    for part in path.components() {
        if part == Component::ParentDir {
            plain.pop();
        } else {
            plain.push(part);
        }
    }
    Some((checkouts::rel(home, &plain), spelled))
}

/// Answers a command of the contract in the form asked (`answer::print`), with `text` the text
/// for a person of the message; a refusal as a misuse, and a store that cannot be read, as every
/// failure of the contract is told (`answer::fail`). `ask` turns the question into the answer, in
/// one read transaction so that it is of one state of the store.
pub fn command<M: Message + serde::Serialize>(
    op: &str,
    store: &Path,
    form: Form,
    ask: impl FnOnce(&Connection, i64) -> rusqlite::Result<Result<M, Refused>>,
    text: impl FnOnce(&M) -> String,
) -> ExitCode {
    command_told(op, store, form, ask, text, |f| {
        crate::text::failure(f, &crate::screen::Screen::of_stderr())
    })
}

/// The same, with `refused` the text for a person of a refusal: for a command whose refusal
/// gives the command to run next made from what was typed (`text::refusal`).
pub fn command_told<M: Message + serde::Serialize>(
    op: &str,
    store: &Path,
    form: Form,
    ask: impl FnOnce(&Connection, i64) -> rusqlite::Result<Result<M, Refused>>,
    text: impl FnOnce(&M) -> String,
    refused: impl FnOnce(&v1::Failure) -> String,
) -> ExitCode {
    match read(store, |conn| ask(conn, crate::now_secs())) {
        Ok(Ok(m)) => answer::print(op, form, &m, text),
        Ok(Err(r)) => answer::fail_as(op, form, r.error(), crate::EXIT_USAGE, refused),
        Err(e) => {
            let (error, exit) = answer::stopped(&e, "immune status --json --store <file>");
            answer::fail(op, form, error, exit)
        }
    }
}

fn read<T>(store: &Path, ask: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T, Stop> {
    if !store.is_file() {
        return Err(Stop::Store(store::absent(store)));
    }
    let unreadable = |e: Box<dyn std::error::Error>| Stop::Store(e.to_string());
    let conn = store::open_read_only(store).map_err(unreadable)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Stop::Store(e.to_string()))?;
    ask(&tx).map_err(|e| Stop::Store(e.to_string()))
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
        asked_text: crate::secrets::said(q.asked),
        answered_at: now,
        presence: v1::Presence::Unknown as i32,
        latest_run_at: status::latest_finished(conn)?.and_then(|r| r.finished_at),
        store_id: Some(store::id(conn)?),
        ..Default::default()
    };
    let thing = match q.id {
        Some(id) => type_of(conn, id)?.map(|ty| (id, ty)),
        None => None,
    };
    // The thing under each of its ids, and its parts, by id: whose facts are given and whose
    // readings speak. Findings are those about these, and about anything ever inside the thing.
    let mut subjects: BTreeMap<String, String> = BTreeMap::new();
    let mut own_ids: BTreeSet<String> = BTreeSet::new();
    let mut owners: BTreeSet<ReadingKey> = BTreeSet::new();
    if let Some((id, ty)) = &thing {
        let mut own: Parts = Parts::new();
        own.insert(id.to_string(), ty.clone());
        for other in q.also {
            own.extend(type_of(conn, other)?.map(|ty| (other.clone(), ty)));
        }
        let mut all = Parts::new();
        let mut with_parts = false;
        for own_id in own.keys() {
            let (inside, in_folder) = parts(conn, own_id, q.folder)?;
            with_parts = with_parts || !inside.is_empty();
            all.extend(inside);
            all.extend(in_folder);
        }
        own_ids.extend(own.keys().cloned());
        let (presence, readings) = presence(conn, own.keys(), with_parts)?;
        known.presence = presence as i32;
        owners = readings;
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
            let key = (r.reader.clone(), r.scope.clone(), r.kind.clone());
            subjects.contains_key(&r.scope)
                || read_by.contains(&key)
                || owners.contains(&key)
                || (this
                    && (q.found_by.contains(&(r.reader.as_str(), r.kind.as_str()))
                        || (thing.is_some()
                            && q.inside
                                .iter()
                                .any(|(reader, kind)| *reader == r.reader && *kind == r.kind))
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
    // A finding is the thing's when what it is about, or anything a reading ever tied it to, at
    // any depth, is the thing under one of its ids or a part of it, lies in its folder or at or
    // inside the place asked, or is named by its id as inside it. Places are compared by the key
    // a Mac's volumes compare names by, so no spelling of a place leaves out a finding about it.
    // Each way can only add: the store's links are its own word, and the names add what no
    // reading tied. A finding about a part that is gone stays the thing's, as it stays open until
    // it is answered.
    let links = links(conn)?;
    let at_place = |at: &str, machine: &str, rel: &str| {
        place_of(at).is_some_and(|(m, path)| m == machine && same_place(path, rel))
    };
    let theirs = |at: &str| {
        subjects.contains_key(at)
            || own_ids.iter().any(|own| named_in(at, own))
            || q.folder
                .is_some_and(|(machine, rel)| at_place(at, machine, rel))
            || q.place
                .zip(q.machine)
                .is_some_and(|(rel, machine)| at_place(at, machine, rel))
            || q.machine
                .is_some_and(|machine| q.places.iter().any(|rel| at_place(at, machine, rel)))
    };
    known.findings = finding_refs(conn, now, |about| held_by(about, &links, &theirs))?;
    Ok(known)
}

/// A reading, as reader, scope and kind.
type ReadingKey = (String, String, String);

/// Whether the thing whose units are `units` is held, gone or unknown, and the readings that own
/// those units. Presence is told here alone, for every question.
///
/// A thing is the sum of its units: it is held while any unit is held, by a fact in force about
/// it or, when `with_parts`, by a part in force. A reading that wrote about a unit, in force or
/// retracted, owns it, and its latest reading speaks for it. `gone` needs every such latest
/// reading full: after a partial reading, what it did not read again is kept as it was, so a
/// unit no longer held may only not have been read. Then the thing is `unknown`. A held thing
/// whose owning reading was partial is held, and that reading comes with the answer, so it reads
/// as not read now. A thing the store has no entity of is `unknown`.
fn presence<'a>(
    conn: &Connection,
    units: impl Iterator<Item = &'a String>,
    with_parts: bool,
) -> rusqlite::Result<(v1::Presence, BTreeSet<ReadingKey>)> {
    let mut held = with_parts;
    let mut owners: BTreeSet<ReadingKey> = BTreeSet::new();
    let mut live = conn
        .prepare("SELECT EXISTS (SELECT 1 FROM assertion WHERE layer = 'live' AND subject = ?1)")?;
    let mut owning = conn.prepare(
        "SELECT DISTINCT reader, scope, kind FROM assertion
         WHERE subject = ?1 AND layer IN ('live', 'retracted')",
    )?;
    for unit in units {
        held = held || live.query_row([unit], |r| r.get::<_, bool>(0))?;
        for row in owning.query_map([unit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))? {
            owners.insert(row?);
        }
    }
    if held {
        return Ok((v1::Presence::Held, owners));
    }
    let mut latest = conn.prepare(
        "SELECT completeness FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
         ORDER BY id DESC LIMIT 1",
    )?;
    let mut all_full = !owners.is_empty();
    for (reader, scope, kind) in &owners {
        let completeness: Option<String> = latest
            .query_row([reader, scope, kind], |r| r.get(0))
            .optional()?;
        all_full = all_full && completeness.as_deref() == Some("full");
    }
    let presence = if all_full {
        v1::Presence::Gone
    } else {
        v1::Presence::Unknown
    };
    Ok((presence, owners))
}

/// What each entity was ever `part_of` or `located_on`, in force or retracted, by its id.
type Links = BTreeMap<String, Vec<String>>;

/// Every link of a part to what holds it that the store ever held: one pass over the assertions,
/// since the store has no index by object.
fn links(conn: &Connection) -> rusqlite::Result<Links> {
    let mut out = Links::new();
    let mut q = conn.prepare(
        "SELECT DISTINCT subject, object FROM assertion
         WHERE layer IN ('live', 'retracted') AND predicate IN ('part_of', 'located_on')",
    )?;
    for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?)))? {
        let (subject, object) = row?;
        out.entry(subject).or_default().push(object);
    }
    Ok(out)
}

/// Whether `about`, or anything it is tied to through `links` at any depth, is one `theirs`
/// takes. Each id is looked at once, so links that run in a circle end.
fn held_by(about: &str, links: &Links, theirs: &impl Fn(&str) -> bool) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut next = vec![about];
    while let Some(at) = next.pop() {
        if !seen.insert(at) {
            continue;
        }
        if theirs(at) {
            return true;
        }
        next.extend(links.get(at).into_iter().flatten().map(String::as_str));
    }
    false
}

/// Whether the id `at` names a thing inside the thing whose id is `own`, by how ids are made: a
/// type, then the natural key, which for a thing in another begins with the other's id. So after
/// one or two types it begins with `own` and a `/`: `file:<machine>/<path>`, `check:<machine>/…`
/// and `checkout:<machine>/<path>` for a machine, `component:checkout:<machine>/<path>/…` for a
/// machine and for that project. It sits beside the store's links (`held_by`) and adds what no
/// reading tied to the thing, such as a program that ran on a machine or a place on it that
/// could not be read; a part a reading tied is the thing's by the link, however its id is made.
fn named_in(at: &str, own: &str) -> bool {
    let mut rest = at;
    for _ in 0..2 {
        let Some((_, key)) = rest.split_once(':') else {
            return false;
        };
        if key.strip_prefix(own).is_some_and(|r| r.starts_with('/')) {
            return true;
        }
        rest = key;
    }
    false
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
    by_rule_for(known, reader, kind, scope, reason, v1::Cause::NotGiven);
}

/// The same, for a reason of its own: a limit of this version is `NoReader`.
pub fn by_rule_for(
    known: &mut v1::Known,
    reader: &str,
    kind: &str,
    scope: &str,
    reason: &str,
    cause: v1::Cause,
) {
    let reading = v1::Coverage {
        reader: reader.to_string(),
        kind: kind.to_string(),
        scope_text: whole(scope),
        completeness: v1::Completeness::None as i32,
        reason_text: Some(reason.to_string()),
        cause: Some(cause as i32),
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

/// Whether the path `rel` is the folder `folder` or lies in it, as ids name paths. The root, `/`,
/// holds every path, the home folder's among them; the home folder, `.`, holds every path ids
/// name relative to it.
pub fn within(rel: &str, folder: &str) -> bool {
    match folder {
        "/" => true,
        "." => !rel.starts_with('/'),
        _ => rel
            .strip_prefix(folder)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/')),
    }
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

/// Whether the path `rel` is the folder `folder` or inside it when both are compared by the key a
/// Mac's volumes compare names by (`spelling::key`): to find what a caller meant, and to tell
/// that it is spelled otherwise.
pub fn same_place(rel: &str, folder: &str) -> bool {
    within(&crate::spelling::key(rel), &crate::spelling::key(folder))
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
    let found = findings::all(conn, now)?;
    let mut items: Vec<findings::Item> = found
        .iter()
        .filter(|f| about(&f.about))
        .map(findings::item)
        .collect();
    findings::order(&mut items);
    Ok(items.iter().map(finding_ref).collect())
}

/// A finding by reference, as every message of the contract names one.
pub fn finding_ref(i: &findings::Item) -> v1::FindingRef {
    v1::FindingRef {
        id: i.id.clone(),
        rule: Some(i.rule.clone()),
        about_text: whole(&i.about),
        state: value_of::<v1::FindingState>(&i.state),
        severity: i.severity.map(value_of::<v1::Level>),
        confidence: i.confidence.map(value_of::<v1::Level>),
        urgent: i.urgent(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_thing_is_inside_another_only_when_its_id_names_that_whole_id_as_where_it_is() {
        // What lies on a machine, or in a project, at any depth, is its; what lies on another
        // machine or in another project whose name begins the same is not.
        let mac = "machine:mac";
        let shop = "checkout:machine:mac/dev/shop";
        for at in [
            "file:machine:mac//Library/Security/SecurityAgentPlugins",
            "checkout:machine:mac/dev/shop",
            "component:checkout:machine:mac/dev/shop/npm/left-pad",
        ] {
            assert!(super::named_in(at, mac), "{at}");
        }
        assert!(super::named_in(
            "component:checkout:machine:mac/dev/shop/npm/left-pad",
            shop
        ));
        for (at, own) in [
            ("file:machine:mac-2/.zshrc", mac),
            (
                "component:checkout:machine:mac/dev/shop-old/npm/left-pad",
                shop,
            ),
            ("machine:mac", mac),
        ] {
            assert!(!super::named_in(at, own), "{at} in {own}");
        }
    }
}
