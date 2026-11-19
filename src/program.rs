//! `immunity program <what>`: what the store knows of one program installed on this Mac, printed
//! as the contract's `Known` message. The answer is built by `known::known_of`; what is
//! particular to a program is how the question names it and which readings find programs.
//!
//! A program is a thing a reading of installed programs wrote about (`FOUND_BY`): an application
//! bundle, a Homebrew formula or cask, a Homebrew keg, a global npm package. Which entities are
//! programs is taken from those readings' assertions, so no product is named here. The folder of
//! code an application keeps in `~/Library/Application Support` is not a program: it is a part of
//! its application.
//!
//! What was asked becomes the program's entity from the store alone, and no path is looked at.
//! An answer is about a unit the store holds, never about a path inside one:
//! - A path, absolute or beginning with `~/`, or a `file:` id, is first put into one form
//!   (`known::place_asked`). It leads to the program whose unit holds it: a program's folder is
//!   where the store says it is installed (`installed_at`), or the path of a program the store
//!   names by its path, as it names a keg (a `file`), and a folder of code an application keeps
//!   in `~/Library/Application Support` leads to that application. Where no program is now, a
//!   program that was installed there and moved, or one copy of it that went, is the program.
//! - A path strictly inside a unit answers for the unit, with a reading made by rule that says a
//!   single path inside is not judged on its own: the readings compare a unit as a whole and do
//!   not keep which paths inside it they compared.
//! - A path under no unit is `unknown` with a reading made by rule that no reading opened it. A
//!   folder that holds units without being one, such as a Cellar, is `unknown` too, and says how
//!   many units lie inside.
//! - A path that fits a unit only when case and Unicode form are ignored (`known::same_place`)
//!   answers for that unit, with a reading made by rule that says so.
//! - A program's id is that program. A `file:` id of this Mac that is not a program is the path
//!   it names; any other id the store holds is not a program, and is refused.
//! - Anything else is a name, matched against the last part of a program's id,
//!   `component:<machine>/<ecosystem>/<name>`: a bundle identifier (or a bundle's folder name
//!   where it has none), a formula's or cask's name as Homebrew gives it, a package's name.
//!
//!   A keg is also found by its formula's name, which Homebrew may not have given.
//!
//! One program can be known under several ids that no fact links: a Homebrew formula and its
//! kegs, an application and the folder of code it keeps outside its bundle. Asked by any of them,
//! the answer is about all of them (`kin`), so a finding about a keg is in the answer about its
//! formula, however the program was named. The tie runs between a program and its own parts and
//! never on from them: two applications that match one folder are not one program, nor are two
//! formulas of one short name.
//!
//! A question that fits more than one program is refused, with their ids: the message holds one
//! thing, and choosing one would hide the others.

use crate::contract::{self, v1};
use crate::known::{self, Question, Refused};
use crate::{brew, covered, integrity, spelling};
use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The readings that find programs on a Mac, as reader and kind. Their latest reading of this
/// Mac speaks for every program the store never heard of. The last finds none: it says which
/// package managers no reader reads, so a program one of them installed is never answered as
/// absent on the others alone.
const FOUND_BY: [(&str, &str); 5] = [
    (integrity::READER, integrity::BUNDLES),
    (integrity::READER, integrity::KEGS),
    (integrity::READER, integrity::NPM),
    (brew::READER, brew::KIND),
    (integrity::READER, crate::managers::KIND),
];

/// What `immunity program` takes as a program.
const WHAT: &str = "immunity program takes a path on this Mac, absolute or beginning with ~/, the name the store gives a program (a bundle identifier, a Homebrew formula's or cask's name, a global npm package's name), or its id, beginning with component: or file:";

/// `immunity program <what>`.
pub struct ProgramArgs {
    pub store: PathBuf,
    pub form: crate::answer::Form,
    /// What was asked for, as given.
    pub asked: String,
    /// The home folder: ids name a path inside it relative to it.
    pub home: PathBuf,
}

/// Reads the arguments after `program`.
pub fn parse(
    it: impl Iterator<Item = String>,
    options: &mut crate::answer::Options,
) -> Result<ProgramArgs, String> {
    let words = known::words(it, options)?;
    let [asked] = <[String; 1]>::try_from(words).map_err(|_| WHAT.to_string())?;
    Ok(ProgramArgs {
        store: options.store()?,
        form: options.form(),
        asked,
        home: crate::user_home()?,
    })
}

/// Why a path under no program the store holds is not "looked, and not there".
const NOT_OPENED: &str = "no reading opened this place for this answer: no program the store knows is installed at it or holds it";

/// Why a path strictly inside a program is answered for the program.
const INSIDE: &str = "a single path inside a program is not judged on its own: the answer is about the program that holds it, which the readings compare as a whole without keeping which paths inside they compared";

/// Answers `immunity program`.
pub fn program_cmd(args: &ProgramArgs) -> ExitCode {
    known::command(
        "program",
        &args.store,
        args.form,
        |conn, now| {
            let this = covered::this_machine(conn)?;
            // A store no run has written names no Mac, and so no program on it.
            let asked = contract::unescape(&args.asked);
            let found = match &this {
                Some(this) => find(conn, this, &asked, &args.home)?,
                None => Ok(Found::default()),
            };
            let found = match found {
                Ok(found) => found,
                Err(not) => return Ok(Err(not)),
            };
            // The program asked for, and every id the store knows it by: whichever of them was
            // asked, the answer is about all of them, so no way of naming it hides a finding.
            let (id, also) = match (found.ids.first(), &this) {
                (Some(first), Some(this)) => {
                    let one = kin(conn, this, first)?;
                    if found.ids.iter().any(|i| !one.contains(i)) {
                        // One id for each program the question fits.
                        let (mut ids, mut named) = (Vec::new(), BTreeSet::new());
                        for i in &found.ids {
                            if !named.contains(i) {
                                named.extend(kin(conn, this, i)?);
                                ids.push(i.clone());
                            }
                        }
                        return Ok(Err(several(ids)));
                    }
                    let also: Vec<String> = one.into_iter().filter(|i| i != first).collect();
                    (Some(first.clone()), also)
                }
                _ => (None, Vec::new()),
            };
            let found_by = known::found_by(conn, id.as_deref(), &FOUND_BY)?;
            let place = found.place.as_deref();
            // The folders of every unit of the program, now and before: asked by its name, its
            // id or a path, the answer holds the findings about anything in them.
            let places: Vec<String> = match (&id, &this) {
                (Some(first), Some(this)) => {
                    let ids: BTreeSet<&String> = std::iter::once(first).chain(&also).collect();
                    let programs = programs(conn, this)?;
                    ids.iter()
                        .flat_map(|i| {
                            let p = programs.get(*i);
                            p.into_iter()
                                .flat_map(|p| p.at.iter().chain(&p.was_at).cloned())
                                .chain(known::place_of(i).map(|(_, rel)| rel.to_string()))
                        })
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                }
                _ => Vec::new(),
            };
            let q = Question {
                places: &places,
                question: v1::Question::Program,
                asked: &args.asked,
                id: id.as_deref(),
                also: &also,
                folder: None,
                place,
                unread: found.unread.as_deref(),
                machine: this.as_deref(),
                found_by: &found_by,
                inside: &[],
            };
            let mut known = known::known_of(conn, &q, &args.home, now)?;
            // A program the store never heard of may be one a package manager this version does
            // not read installed: the answer says so, whatever the table of managers found.
            if let (true, Some(machine)) = (
                known.presence == v1::Presence::Unknown as i32,
                this.as_deref(),
            ) {
                known::by_rule_for(
                    &mut known,
                    known::RULE_READER,
                    OTHER_MANAGERS_KIND,
                    machine,
                    OTHER_MANAGERS_LIMIT,
                    v1::Cause::NoReader,
                );
            }
            Ok(Ok(known))
        },
        |k| crate::answers_text::known(k, &crate::screen::Screen::of_stdout()),
    )
}

/// The kind of the reading made by rule for what no reader of this version finds programs in.
const OTHER_MANAGERS_KIND: &str = "software of package managers this version does not look for";
/// Its reason: the standing limit, in the words of what this version cannot judge.
const OTHER_MANAGERS_LIMIT: &str = crate::status::OTHER_MANAGERS;

/// The programs a question names, the path it asked about, as ids name paths, when it was one,
/// and why that path is not judged on its own, when it is not.
#[derive(Default)]
struct Found {
    ids: Vec<String>,
    place: Option<String>,
    unread: Option<String>,
}

/// The programs `asked` names on this Mac, `this`, or the refusal of an id that is not one or
/// of a path the store knows only under another case.
fn find(
    conn: &Connection,
    this: &str,
    asked: &str,
    home: &Path,
) -> rusqlite::Result<Result<Found, Refused>> {
    let programs = programs(conn, this)?;
    if programs.contains_key(asked) {
        return Ok(Ok(Found {
            ids: vec![asked.to_string()],
            ..Found::default()
        }));
    }
    if let Some((rel, spelled)) = known::place_spelled(asked, Some(this), home) {
        return at_place(conn, this, &programs, rel, spelled);
    }
    // An id of a program spelled otherwise is that program, and says so.
    let key = spelling::key(asked);
    let ids: Vec<String> = programs
        .keys()
        .filter(|id| spelling::key(id) == key)
        .cloned()
        .collect();
    if !ids.is_empty() {
        return Ok(Ok(Found {
            ids,
            unread: Some(known::NAME_SPELLED.to_string()),
            ..Found::default()
        }));
    }
    if known::exists(conn, asked)? {
        return Ok(Err(not_a_program(asked)));
    }
    let prefix = format!("component:{this}/");
    let files = format!("file:{this}/");
    // The name a program is known by: the last part of its id, or for a keg its formula's name,
    // which Homebrew may not have named.
    let name = |id: &str| -> Option<String> {
        id.strip_prefix(&prefix)
            .and_then(|rest| rest.split_once('/'))
            .map(|(_, name)| name.to_string())
            .or_else(|| {
                id.strip_prefix(&files)
                    .and_then(integrity::keg_formula)
                    .map(str::to_string)
            })
    };
    // As written first; only then by the key, which is said.
    let named = |fits: &dyn Fn(&str) -> bool| -> Vec<String> {
        programs
            .keys()
            .filter(|id| name(id).is_some_and(|n| fits(&n)))
            .cloned()
            .collect()
    };
    let exact = named(&|n| n == asked);
    if !exact.is_empty() {
        return Ok(Ok(Found {
            ids: exact,
            ..Found::default()
        }));
    }
    let ids = named(&|n| spelling::key(n) == key);
    let unread = (!ids.is_empty()).then(|| known::NAME_SPELLED.to_string());
    Ok(Ok(Found {
        ids,
        unread,
        ..Found::default()
    }))
}

/// The ids the store knows one program by, `id` among them. Two readings find one program under
/// two ids, and nothing in the store links them: the reading of Homebrew names a formula, the
/// reading of kegs names each keg by its path, and the reading of applications' code names the
/// folder an application keeps outside its bundle by its path. A program is tied to its own
/// parts and the tie goes no further: an application to the folders of code that match it
/// (`belongs`), a formula to its own kegs and a keg to its formulas (`own_keg`). So two
/// applications that match one folder, or two formulas of one short name, stay two programs. A
/// folder is never asked for itself: `find` takes it to its application.
fn kin(conn: &Connection, this: &str, id: &str) -> rusqlite::Result<BTreeSet<String>> {
    let programs = programs(conn, this)?;
    let folders = code_folders(conn, this)?;
    let mut one: BTreeSet<String> = BTreeSet::from([id.to_string()]);
    one.extend(
        folders
            .into_iter()
            .filter(|f| belongs(&programs, this, id, f)),
    );
    one.extend(
        programs
            .keys()
            .filter(|other| {
                own_keg(&programs, this, id, other) || own_keg(&programs, this, other, id)
            })
            .cloned(),
    );
    Ok(one)
}

/// Whether the folder of code `folder` is the application `app`'s: its name is the application's
/// identifier or its folder's name, as the reading of applications' code matches them
/// (`integrity::app_names`), wherever the application is or was installed.
fn belongs(programs: &BTreeMap<String, Program>, this: &str, app: &str, folder: &str) -> bool {
    let Some(p) = programs.get(app) else {
        return false;
    };
    if !app.starts_with(&format!("component:{this}/macos-app/")) {
        return false;
    }
    let Some(name) = folder
        .strip_prefix(&format!("file:{this}/"))
        .and_then(integrity::app_support_name)
    else {
        return false;
    };
    p.at.iter()
        .chain(&p.was_at)
        .any(|at| integrity::app_names(app, at).contains(&name))
}

/// Whether `keg` is a keg of the formula `formula`. Homebrew names a keg's folder by the last
/// part of the formula's full name, and gives each formula's installed versions: a keg is the
/// formula's when the names match and its version is one Homebrew gave for that formula. A keg
/// whose version Homebrew gave for no formula of that name is tied to each of them, so that no
/// finding about it is left out of an answer.
fn own_keg(programs: &BTreeMap<String, Program>, this: &str, formula: &str, keg: &str) -> bool {
    let brew = format!("component:{this}/brew/");
    let short = |id: &str| {
        id.strip_prefix(&brew)
            .map(|full| full.rsplit('/').next().unwrap_or(full).to_string())
    };
    let Some((name, version)) = keg
        .strip_prefix(&format!("file:{this}/"))
        .and_then(integrity::keg_of)
    else {
        return false;
    };
    if short(formula).as_deref() != Some(name) {
        return false;
    }
    let gave = |f: &str| {
        programs
            .get(f)
            .is_some_and(|p| p.versions.iter().any(|v| v == version))
    };
    gave(formula)
        || !programs
            .keys()
            .any(|f| short(f).as_deref() == Some(name) && gave(f))
}

/// The units of programs on this Mac, each a folder as ids name paths with the programs it
/// answers for: a program where it is installed or where its id names it, and a folder of code
/// for the applications it belongs to. `now` takes programs where they are now; otherwise where
/// they were installed and are no longer. A folder of code is in both.
fn units(
    conn: &Connection,
    this: &str,
    programs: &BTreeMap<String, Program>,
    now: bool,
) -> rusqlite::Result<Vec<(String, Vec<String>)>> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for (id, p) in programs {
        let folders: Vec<&str> = if now {
            p.folders(id)
        } else {
            p.was_at.iter().map(String::as_str).collect()
        };
        out.extend(
            folders
                .into_iter()
                .map(|f| (f.to_string(), vec![id.clone()])),
        );
    }
    // A folder of code is a unit whether its reading holds it or no longer does: the reading opens
    // every folder the store holds or held whenever it is there, so one it no longer holds was
    // looked for and was not there, and its application's presence says so. No folder of code
    // lies in another unit or holds one, so it is the same unit now and before.
    for folder in code_folders(conn, this)? {
        let Some((_, path)) = known::place_of(&folder) else {
            continue;
        };
        let mut apps: Vec<String> = programs
            .keys()
            .filter(|a| belongs(programs, this, a, &folder))
            .cloned()
            .collect();
        if apps.is_empty() {
            apps.push(folder.clone());
        }
        out.push((path.to_string(), apps));
    }
    Ok(out)
}

/// The answer to a place `rel` on this Mac, in the form ids name paths in: the programs whose
/// unit is the place or holds it, where one is now, else where one was. A place strictly inside
/// a unit is not judged on its own; a place that fits units only when case and Unicode form are
/// ignored is refused; a folder holding units says how many; any other place was not opened.
fn at_place(
    conn: &Connection,
    this: &str,
    programs: &BTreeMap<String, Program>,
    rel: String,
    machine_spelled: bool,
) -> rusqlite::Result<Result<Found, Refused>> {
    let now = units(conn, this, programs, true)?;
    let was = units(conn, this, programs, false)?;
    let holding = |fits: &dyn Fn(&str) -> bool| -> Vec<&(String, Vec<String>)> {
        let here: Vec<_> = now.iter().filter(|(f, _)| fits(f)).collect();
        if here.is_empty() {
            was.iter().filter(|(f, _)| fits(f)).collect()
        } else {
            here
        }
    };
    // As written first; only then as a Mac's volumes compare names, which is said.
    let mut spelled = machine_spelled;
    let mut held = holding(&|f| known::within(&rel, f));
    if held.is_empty() {
        held = holding(&|f| known::same_place(&rel, f));
        spelled = spelled || !held.is_empty();
    }
    if !held.is_empty() {
        let mut ids: Vec<String> = held.iter().flat_map(|(_, ids)| ids.clone()).collect();
        ids.sort();
        ids.dedup();
        let inside = held.iter().any(|(f, _)| *f != rel);
        return Ok(Ok(Found {
            ids,
            unread: known::not_judged(spelled, inside.then_some(INSIDE)),
            place: Some(rel),
        }));
    }
    let inside = now
        .iter()
        .chain(&was)
        .filter(|(f, _)| f != &rel && known::within(f, &rel))
        .map(|(f, _)| f)
        .collect::<BTreeSet<_>>()
        .len();
    let unread = if inside > 0 {
        format!(
            "this folder is not a program the store knows, and it holds {}: ask about one of them by its id or its path",
            crate::things(inside as i64, "program", "programs")
        )
    } else {
        NOT_OPENED.to_string()
    };
    Ok(Ok(Found {
        ids: Vec::new(),
        place: Some(rel),
        unread: Some(unread),
    }))
}

/// The folders of code applications keep in `~/Library/Application Support` that the reading of
/// them ever wrote about on this Mac, by id, whether that reading holds them now or not.
fn code_folders(conn: &Connection, this: &str) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer IN ('live', 'retracted') AND reader = ?1 AND scope = ?2 AND kind = ?3",
    )?
    .query_map([integrity::READER, this, integrity::APP_SUPPORT], |r| {
        r.get(0)
    })?
    .collect()
}

/// A program as the readings that find programs left it.
#[derive(Default)]
struct Program {
    /// Where it is installed now, from `installed_at` in force.
    at: Vec<String>,
    /// Where it was installed, from retracted `installed_at`.
    was_at: Vec<String>,
    /// The versions it was given, in force or retracted (`has_version`).
    versions: Vec<String>,
}

impl Program {
    /// Its folders now, as ids name paths: where it is installed, and the path its id names when
    /// it is a `file`. Every program is on this Mac: the readings that find programs read this
    /// Mac alone.
    fn folders<'a>(&'a self, id: &'a str) -> Vec<&'a str> {
        let mut out: Vec<&str> = self.at.iter().map(String::as_str).collect();
        out.extend(known::place_of(id).map(|(_, rel)| rel));
        out
    }
}

/// Every program the readings that find programs ever wrote about on this Mac, whether what
/// they wrote is in force or retracted, by id.
fn programs(conn: &Connection, this: &str) -> rusqlite::Result<BTreeMap<String, Program>> {
    let mut q = conn.prepare(
        "SELECT DISTINCT subject, layer = 'live',
                CASE WHEN predicate = 'installed_at' THEN object END,
                CASE WHEN predicate = 'has_version' THEN object END
         FROM assertion
         WHERE layer IN ('live', 'retracted') AND reader = ?1 AND scope = ?2 AND kind = ?3",
    )?;
    let mut out: BTreeMap<String, Program> = BTreeMap::new();
    for (reader, kind) in FOUND_BY {
        let rows = q.query_map([reader, this, kind], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (id, live, at, version) = row?;
            let p = out.entry(id).or_default();
            match (at, live) {
                (Some(at), true) => p.at.push(at),
                (Some(at), false) => p.was_at.push(at),
                (None, _) => {}
            }
            p.versions.extend(version);
        }
    }
    Ok(out)
}

fn several(ids: Vec<String>) -> Refused {
    Refused {
        code: "several_programs",
        message: "the question fits more than one program the store knows; nothing was answered",
        example: "ask for one of them by its id, as in: immunity program <id> --json",
        ids,
    }
}

fn not_a_program(id: &str) -> Refused {
    Refused {
        code: "not_a_program",
        message: "the store holds this id, and no reading of the programs installed on this Mac wrote about it",
        example: "immunity project asks about a project, immunity machine about a machine",
        ids: vec![id.to_string()],
    }
}
