//! `immune program <what>`: what the store knows of one program installed on this Mac, printed
//! as the contract's `Known` message. The answer is built by `known::known_of`; what is
//! particular to a program is how the question names it and which readings find programs.
//!
//! A program is a thing a reading of installed programs wrote about (`FOUND_BY`): an application
//! bundle, a Homebrew formula or cask, a Homebrew keg, a global npm package. Which entities are
//! programs is taken from those readings' assertions, so no product is named here.
//!
//! What was asked becomes the program's entity from the store alone, and no path is looked at:
//! - A path, absolute or beginning with `~/`, leads to the program whose folder holds it. A
//!   program's folder is where the store says it is installed (`installed_at`), or the path of a
//!   program the store names by its path, as it names a keg (a `file`). So a bundle, a file
//!   inside it, a keg and a file inside it each lead to their program.
//! - A program's id is that program. A `file:` id of this Mac that is not a program is the path
//!   it names; any other id the store holds is not a program, and is refused.
//! - Anything else is a name, matched against the last part of a program's id,
//!   `component:<machine>/<ecosystem>/<name>`: a bundle identifier (or a bundle's folder name
//!   where it has none), a formula's or cask's name as Homebrew gives it, a package's name.
//!
//! A question that fits more than one program is refused, with their ids: the message holds one
//! thing, and choosing one would hide the others.

use crate::known::{self, Question, Refused};
use crate::{brew, covered, integrity};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The readings that find programs on a Mac, as reader and kind. Their latest reading of this
/// Mac speaks for every program the store never heard of.
const FOUND_BY: [(&str, &str); 4] = [
    (integrity::READER, integrity::BUNDLES),
    (integrity::READER, integrity::KEGS),
    (integrity::READER, integrity::NPM),
    (brew::READER, brew::KIND),
];

/// What `immune program` takes as a program.
const WHAT: &str = "immune program takes a path on this Mac, absolute or beginning with ~/, the name the store gives a program (a bundle identifier, a Homebrew formula's or cask's name, a global npm package's name), or its id, beginning with component: or file:";

/// `immune program <what>`.
pub struct ProgramArgs {
    pub store: PathBuf,
    pub json: bool,
    /// What was asked for, as given.
    pub asked: String,
    /// The home folder: ids name a path inside it relative to it.
    pub home: PathBuf,
}

/// Reads the arguments after `program`.
pub fn parse(it: impl Iterator<Item = String>) -> Result<ProgramArgs, String> {
    let w = known::words(it)?;
    let [asked] = <[String; 1]>::try_from(w.words).map_err(|_| WHAT.to_string())?;
    Ok(ProgramArgs {
        store: w.store,
        json: w.json,
        asked,
        home: crate::user_home()?,
    })
}

/// Answers `immune program`.
pub fn program_cmd(args: &ProgramArgs) -> ExitCode {
    known::command("program", &args.store, args.json, |conn, now| {
        let this = covered::this_machine(conn)?;
        // A store no run has written names no Mac, and so no program on it.
        let found = match &this {
            Some(this) => find(conn, this, &args.asked, &args.home)?,
            None => Ok(Vec::new()),
        };
        let id = match found.map(<[String; 1]>::try_from) {
            Ok(Ok([id])) => Some(id),
            Ok(Err(ids)) if ids.is_empty() => None,
            Ok(Err(ids)) => return Ok(Err(several(ids))),
            Err(not) => return Ok(Err(not)),
        };
        let found_by = known::found_by(conn, id.as_deref(), &FOUND_BY)?;
        let q = Question {
            asked: &args.asked,
            id: id.as_deref(),
            also: &[],
            folder: None,
            machine: this.as_deref(),
            found_by: &found_by,
        };
        known::known_of(conn, &q, &args.home, now).map(Ok)
    })
}

/// The programs `asked` names on this Mac, `this`, or the refusal of an id that is not one.
fn find(
    conn: &Connection,
    this: &str,
    asked: &str,
    home: &Path,
) -> rusqlite::Result<Result<Vec<String>, Refused>> {
    let programs = programs(conn, this)?;
    if programs.contains_key(asked) {
        return Ok(Ok(vec![asked.to_string()]));
    }
    let file = asked
        .strip_prefix("file:")
        .and_then(|rest| rest.strip_prefix(this))
        .and_then(|rest| rest.strip_prefix('/'));
    if let Some(rel) = file
        .map(str::to_string)
        .or_else(|| known::path_of(asked, home))
    {
        return Ok(Ok(at(&programs, &rel)));
    }
    if known::exists(conn, asked)? {
        return Ok(Err(not_a_program(asked)));
    }
    let prefix = format!("component:{this}/");
    Ok(Ok(programs
        .keys()
        .filter(|id| {
            id.strip_prefix(&prefix)
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(_, name)| name == asked)
        })
        .cloned()
        .collect()))
}

/// A program as the readings that find programs left it.
#[derive(Default)]
struct Program {
    /// Where it is installed now, from `installed_at` in force.
    at: Vec<String>,
    /// Where it was installed, from retracted `installed_at`.
    was_at: Vec<String>,
}

impl Program {
    /// Its folders, as ids name paths: where it is installed now, else where it was, and the
    /// path its id names when it is a `file`. Every program is on this Mac: the readings that
    /// find programs read this Mac alone.
    fn folders(&self, id: &str) -> Vec<String> {
        let mut out = if self.at.is_empty() {
            self.was_at.clone()
        } else {
            self.at.clone()
        };
        if let Some((_, rel)) = known::place_of(id) {
            out.push(rel.to_string());
        }
        out
    }
}

/// Every program the readings that find programs ever wrote about on this Mac, whether what
/// they wrote is in force or retracted, by id.
fn programs(conn: &Connection, this: &str) -> rusqlite::Result<BTreeMap<String, Program>> {
    let mut q = conn.prepare(
        "SELECT DISTINCT subject, layer = 'live',
                CASE WHEN predicate = 'installed_at' THEN object END
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
            ))
        })?;
        for row in rows {
            let (id, live, at) = row?;
            let p = out.entry(id).or_default();
            match (at, live) {
                (Some(at), true) => p.at.push(at),
                (Some(at), false) => p.was_at.push(at),
                (None, _) => {}
            }
        }
    }
    Ok(out)
}

/// The programs whose folder holds the path `rel`, or is it.
fn at(programs: &BTreeMap<String, Program>, rel: &str) -> Vec<String> {
    programs
        .iter()
        .filter(|(id, p)| {
            p.folders(id).iter().any(|f| {
                rel.strip_prefix(f.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            })
        })
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
