//! `immune program <what>`: what the store knows of one program installed on this Mac, printed
//! as the contract's `Known` message. The answer is built by `known::known_of`; what is
//! particular to a program is how the question names it and which readings find programs.
//!
//! A program is a thing a reading of installed programs wrote about (`FOUND_BY`): an application
//! bundle, a Homebrew formula or cask, a Homebrew keg, a global npm package. Which entities are
//! programs is taken from those readings' assertions, so no product is named here. The folder of
//! code an application keeps in `~/Library/Application Support` is not a program: it is a part of
//! its application.
//!
//! What was asked becomes the program's entity from the store alone, and no path is looked at:
//! - A path, absolute or beginning with `~/`, leads to the program whose folder holds it. A
//!   program's folder is where the store says it is installed (`installed_at`), or the path of a
//!   program the store names by its path, as it names a keg (a `file`). So a bundle, a keg and a
//!   file inside either lead to their program. Where no program is now, a program that was
//!   installed there and moved, or one copy of it that went, is the program.
//! - A path at or inside a folder of code the store holds in force, or that folder's id, leads to
//!   the application it belongs to. Any other path in `~/Library/Application Support` is a place
//!   no reading opened: the reading of applications' code opens there only the folders named
//!   after an installed application that Apple did not sign. It is answered `unknown` with a
//!   reading made by rule that says so, never as looked at. So is a place inside a folder of code
//!   that its reading passes over, such as a cache, though it leads to the application.
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
//! thing, and choosing one would hide the others. So is a path that fits programs only when case
//! is ignored. A path that no reading of programs looks at, answered `unknown`, carries a reading
//! made by rule that says so (`integrity::reads`).

use crate::contract::{self, v1};
use crate::known::{self, Question, Refused};
use crate::{brew, covered, integrity};
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

/// What `immune program` takes as a program.
const WHAT: &str = "immune program takes a path on this Mac, absolute or beginning with ~/, the name the store gives a program (a bundle identifier, a Homebrew formula's or cask's name, a global npm package's name), or its id, beginning with component: or file:";

/// `immune program <what>`.
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

/// Why an answer about a path that no reading in `FOUND_BY` looks at is not "looked, and not
/// there": the readings of installed programs read their own places, and the reading of
/// Homebrew asks Homebrew by name.
const UNREAD: &str = "no reading that finds programs looks at this place: they read the applications folders, Homebrew's kegs and the global npm packages, and ask Homebrew by name";

/// Why a path in `~/Library/Application Support` outside every folder of code read now is not
/// "looked, and not there".
const NOT_OPENED: &str = "Immune opens in ~/Library/Application Support only the folders named after an installed application that Apple did not sign, so it has not looked into this one";

/// Why a place inside a folder of code that its reading passes over is not read.
const NOT_WALKED: &str = "Immune does not compare caches, web storage, crash reports and logs inside an application's folder of code, so this place in it was not looked at";

/// Answers `immune program`.
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
            let q = Question {
                question: v1::Question::Program,
                asked: &args.asked,
                id: id.as_deref(),
                also: &also,
                folder: None,
                place,
                unread: found.unread,
                machine: this.as_deref(),
                found_by: &found_by,
                inside: &[],
            };
            let mut known = known::known_of(conn, &q, &args.home, now)?;
            // A program is held while a reading of programs holds it: a folder of code it shares
            // with another application still installed holds that one, not this.
            if known.presence == v1::Presence::Held as i32 {
                let mut held = false;
                for one in id.iter().chain(&also) {
                    held = held || held_as_program(conn, one)?;
                }
                if !held {
                    known.presence = v1::Presence::Gone as i32;
                }
            }
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
        crate::text::known,
    )
}

/// The kind of the reading made by rule for what no reader of this version finds programs in.
const OTHER_MANAGERS_KIND: &str = "software of package managers this version does not look for";
/// Its reason: the standing limit, in the words of what this version cannot judge.
const OTHER_MANAGERS_LIMIT: &str = crate::status::OTHER_MANAGERS;

/// The programs a question names, the path it asked about, as ids name paths, when it was one,
/// and why no reading looked at that path, when none did.
#[derive(Default)]
struct Found {
    ids: Vec<String>,
    place: Option<String>,
    unread: Option<&'static str>,
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
    let file = asked
        .strip_prefix("file:")
        .and_then(|rest| rest.strip_prefix(this))
        .and_then(|rest| rest.strip_prefix('/'));
    if let Some(rel) = file
        .map(str::to_string)
        .or_else(|| known::path_of(asked, home))
    {
        // A folder of code read now, and a place in it, are its application's; a place in it
        // the reading passes over is not read.
        let folders = code_folders(conn, this)?;
        let live = folders
            .iter()
            .filter(|(_, live)| **live)
            .find_map(|(id, _)| {
                known::place_of(id)
                    .filter(|(_, f)| known::within(&rel, f))
                    .map(|(_, f)| (id, f))
            });
        if let Some((folder, path)) = live {
            let ids: Vec<String> = programs
                .keys()
                .filter(|a| belongs(&programs, this, a, folder))
                .cloned()
                .collect();
            if !ids.is_empty() {
                let rest = rel[path.len()..].trim_start_matches('/');
                return Ok(Ok(Found {
                    ids,
                    unread: integrity::not_walked(rest).then_some(NOT_WALKED),
                    place: Some(rel),
                }));
            }
        }
        if integrity::in_app_support(&rel) {
            return Ok(Ok(Found {
                ids: Vec::new(),
                place: Some(rel),
                unread: Some(NOT_OPENED),
            }));
        }
        let ids = at(&programs, |f| known::within(&rel, f));
        if ids.is_empty() {
            let wanted = rel.to_lowercase();
            let spelled = at(&programs, |f| known::within(&wanted, &f.to_lowercase()));
            if !spelled.is_empty() {
                return Ok(Err(known::spelled_otherwise(
                    spelled,
                    "ask for one of them by its id, as in: immune program <id> --json",
                )));
            }
        }
        return Ok(Ok(Found {
            ids,
            unread: (!integrity::reads(&rel)).then_some(UNREAD),
            place: Some(rel),
        }));
    }
    if known::exists(conn, asked)? {
        return Ok(Err(not_a_program(asked)));
    }
    let prefix = format!("component:{this}/");
    let files = format!("file:{this}/");
    Ok(Ok(Found {
        ids: programs
            .keys()
            .filter(|id| {
                id.strip_prefix(&prefix)
                    .and_then(|rest| rest.split_once('/'))
                    .is_some_and(|(_, name)| name == asked)
                    // A keg by its formula's name, which Homebrew may not have named.
                    || id.strip_prefix(&files).and_then(integrity::keg_formula) == Some(asked)
            })
            .cloned()
            .collect(),
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
            .keys()
            .filter(|f| belongs(&programs, this, id, f))
            .cloned(),
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

/// Whether a reading that finds programs holds `id` now: an assertion in force about it by one
/// of `FOUND_BY`.
fn held_as_program(conn: &Connection, id: &str) -> rusqlite::Result<bool> {
    let mut q = conn.prepare(
        "SELECT EXISTS (SELECT 1 FROM assertion
                        WHERE layer = 'live' AND subject = ?1 AND reader = ?2 AND kind = ?3)",
    )?;
    for (reader, kind) in FOUND_BY {
        if q.query_row([id, reader, kind], |r| r.get::<_, bool>(0))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The folders of code applications keep in `~/Library/Application Support` that the reading of
/// them ever wrote about on this Mac, by id, each with whether that reading holds it now.
fn code_folders(conn: &Connection, this: &str) -> rusqlite::Result<BTreeMap<String, bool>> {
    conn.prepare(
        "SELECT subject, MAX(layer = 'live') FROM assertion
         WHERE layer IN ('live', 'retracted') AND reader = ?1 AND scope = ?2 AND kind = ?3
         GROUP BY subject",
    )?
    .query_map([integrity::READER, this, integrity::APP_SUPPORT], |r| {
        Ok((r.get(0)?, r.get(1)?))
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

/// The programs whose folder `holds` the path asked about: where one is now, else where one was.
/// A program that moved, or one of two copies of it that went, is still the program at the
/// folder it left, unless another program is there now.
fn at(programs: &BTreeMap<String, Program>, holds: impl Fn(&str) -> bool) -> Vec<String> {
    let now: Vec<String> = programs
        .iter()
        .filter(|(id, p)| p.folders(id).into_iter().any(&holds))
        .map(|(id, _)| id.clone())
        .collect();
    if !now.is_empty() {
        return now;
    }
    programs
        .iter()
        .filter(|(_, p)| p.was_at.iter().any(|f| holds(f)))
        .map(|(id, _)| id.clone())
        .collect()
}

fn several(ids: Vec<String>) -> Refused {
    Refused {
        code: "several_programs",
        message: "the question fits more than one program the store knows; nothing was answered",
        example: "ask for one of them by its id, as in: immune program <id> --json",
        ids,
    }
}

fn not_a_program(id: &str) -> Refused {
    Refused {
        code: "not_a_program",
        message: "the store holds this id, and no reading of the programs installed on this Mac wrote about it",
        example: "immune project asks about a project, immune machine about a machine",
        ids: vec![id.to_string()],
    }
}
