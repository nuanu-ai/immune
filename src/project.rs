//! `immune project <what>`: what the store knows of one project, a checkout, printed as the
//! contract's `Known` message. The answer is built by `known::known_of`; what is particular to a
//! project is only how the question names it and which readings find projects (`FOUND_BY`).
//!
//! A path is turned into the checkout's id by the rule the readers name checkouts by. A path
//! inside a project the store knows, such as the working folder of a program that ran there,
//! answers for that project, the nearest one that holds it. A path that names no project as
//! written may lead to one through a symbolic link: it is followed with `guarded::real`, which
//! never looks inside a folder macOS asks permission for. The project's folder is never looked
//! into. A path the store knows only under another case is refused with the ids it knows, since
//! the Mac's volumes usually ignore case and the answer could be about the same folder.
//!
//! A project in a folder macOS asks permission for carries the reading that says the folder was
//! not looked into, whatever was read in it before.

use crate::contract::{self, v1};
use crate::known::{self, Question, Refused};
use crate::{autorun, checkouts, covered, guarded, watched};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The readings that find projects on a Mac, as reader and kind. Their latest reading of this
/// Mac speaks for every project, known or not: a project the walk did not reach is unknown for
/// that reason.
const FOUND_BY: [(&str, &str); 2] = [
    (checkouts::READER, checkouts::KIND),
    (crate::agent_folders::READER, crate::agent_folders::KIND),
];

/// Why an answer about a path that no reading in `FOUND_BY` looks at is not "looked, and not
/// there": the walk keeps to the home folder, and the reading of agent working folders finds a
/// project only where an agent worked.
const UNREAD: &str = "no reading that finds projects looks at this place: the walk of the home folder does not reach it, and agent working folders name only where an agent worked";

/// What `immune project` takes as a project.
const WHAT: &str = "immune project takes a path on this Mac, absolute or beginning with ~/, or an id as the store names it: a project's, beginning with checkout:, or a file's, beginning with file:";

/// `immune project <what>`.
pub struct ProjectArgs {
    pub store: PathBuf,
    pub form: crate::answer::Form,
    /// What was asked for, as given.
    pub asked: String,
    pub what: What,
    /// The home folder: checkout ids name a path inside it relative to it.
    pub home: PathBuf,
}

/// The project asked for.
pub enum What {
    /// A folder or a file, as checkout ids name it: relative to the home folder when it is inside
    /// it, the full path otherwise.
    Path(String),
    /// An id as the store names it.
    Id(String),
}

/// Reads the arguments after `project`. An id or a path given as the core shows it, with its
/// escapes, is the one the core showed.
pub fn parse(
    it: impl Iterator<Item = String>,
    options: &mut crate::answer::Options,
) -> Result<ProjectArgs, String> {
    let words = known::words(it, options)?;
    let [asked] = <[String; 1]>::try_from(words).map_err(|_| WHAT.to_string())?;
    let home = crate::user_home()?;
    let word = contract::unescape(&asked);
    let what = match known::path_of(&word, &home) {
        Some(rel) => What::Path(rel),
        None if word.contains(':') => What::Id(word),
        None => return Err(WHAT.to_string()),
    };
    Ok(ProjectArgs {
        store: options.store()?,
        form: options.form(),
        asked,
        what,
        home,
    })
}

/// Answers `immune project`.
pub fn project_cmd(args: &ProjectArgs) -> ExitCode {
    known::command(
        "project",
        &args.store,
        args.form,
        |conn, now| {
            let this = covered::this_machine(conn)?;
            // A store no run has written names no Mac, and so no project on it.
            let Some(this) = this else {
                let q = question(&args.asked, None, None, None, None, &[]);
                return known::known_of(conn, &q, &args.home, now).map(Ok);
            };
            // A path of this Mac, as an id of a checkout or a file names one.
            let path = |id: &str| {
                known::place_of(id)
                    .filter(|(machine, _)| *machine == this)
                    .map(|(_, rel)| rel.to_string())
            };
            let what = match &args.what {
                What::Path(rel) => What::Path(rel.clone()),
                What::Id(id) => match (known::type_of(conn, id)?.as_deref(), path(id)) {
                    // A project the store knows is answered for as it is named.
                    (Some(checkouts::TYPE), _) => What::Id(id.clone()),
                    (Some("file") | None, Some(rel)) => What::Path(rel),
                    // A project of another machine, which the store never heard of.
                    (None, None) if id.starts_with("checkout:") => What::Id(id.clone()),
                    (Some(_), _) => return Ok(Err(not_a_project(id))),
                    (None, None) => return Ok(Err(not_an_id(id))),
                },
            };
            // The project's id, the place asked about, and why no reading looks there.
            let (id, place, unread) = match &what {
                What::Id(id) => (Some(id.clone()), None, None),
                What::Path(rel) => match holding(conn, &this, rel)? {
                    Some(id) => (Some(id), None, None),
                    None => match through_link(conn, &this, rel, &args.home)? {
                        Some(Found::At(id)) => (Some(id), None, None),
                        Some(Found::Guarded(folder)) => (None, Some(folder), Some(UNREAD)),
                        None => {
                            let spelled = otherwise(conn, &this, rel)?;
                            if !spelled.is_empty() {
                                return Ok(Err(known::spelled_otherwise(
                                    spelled,
                                    "ask for one of them by its id, as in: immune project <id> --json",
                                )));
                            }
                            let unread = (!checkouts::reaches(rel)).then_some(UNREAD);
                            (
                                Some(format!("checkout:{this}/{rel}")),
                                Some(rel.clone()),
                                unread,
                            )
                        }
                    },
                },
            };
            let inside = inside_projects();
            let q = question(
                &args.asked,
                id.as_deref(),
                Some(&this),
                place.as_deref(),
                unread,
                &inside,
            );
            known::known_of(conn, &q, &args.home, now).map(Ok)
        },
        crate::text::known,
    )
}

/// The question of a project, by its id where the store can name one.
fn question<'a>(
    asked: &'a str,
    id: Option<&'a str>,
    machine: Option<&'a str>,
    place: Option<&'a str>,
    unread: Option<&'static str>,
    inside: &'a [(&'a str, String)],
) -> Question<'a> {
    Question {
        question: v1::Question::Project,
        asked,
        id,
        also: &[],
        folder: id.and_then(known::place_of),
        place,
        unread,
        machine,
        found_by: &FOUND_BY,
        inside,
    }
}

/// The readings of this Mac that read inside every project: they speak for each one.
fn inside_projects() -> Vec<(&'static str, String)> {
    autorun::checkout_kinds()
        .into_iter()
        .map(|kind| (watched::READER, kind))
        .collect()
}

/// What a path leads to.
enum Found {
    /// The project that holds it, by id.
    At(String),
    /// A folder macOS asks permission for, which it leads into through a link, as ids name it.
    Guarded(String),
}

/// The folder that holds `rel`, a path as ids name it; none above the first name.
fn up(rel: &str) -> Option<&str> {
    rel.rsplit_once('/')
        .map(|(up, _)| up)
        .filter(|up| !up.is_empty())
}

/// The nearest project the store knows, held or gone, whose folder is the path `rel` or holds it.
fn holding(conn: &Connection, this: &str, rel: &str) -> rusqlite::Result<Option<String>> {
    let mut at = Some(rel);
    while let Some(folder) = at {
        let id = format!("checkout:{this}/{folder}");
        if known::type_of(conn, &id)?.as_deref() == Some(checkouts::TYPE) {
            return Ok(Some(id));
        }
        at = up(folder);
    }
    Ok(None)
}

/// The project the path `rel` leads to through a symbolic link, made real one part at a time by
/// `guarded::real`, which never looks inside a folder macOS asks permission for; or that folder,
/// when the link leads into one. A path that does not exist to its end is made real as far as it
/// does, such as a folder a program worked in that is gone. Nothing when the path leads where it
/// is written, or cannot be followed.
fn through_link(
    conn: &Connection,
    this: &str,
    rel: &str,
    home: &Path,
) -> rusqlite::Result<Option<Found>> {
    // A real path is under the real home folder; a guarded folder is named under the home
    // folder as given, the first of the two.
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut at = Some(rel);
    while let Some(part) = at {
        match guarded::real(&home.join(part), &[home, &real_home]) {
            guarded::Real::At(p) => {
                let led = format!("{}{}", checkouts::rel(&real_home, &p), &rel[part.len()..]);
                return Ok(holding(conn, this, &led)?.map(Found::At));
            }
            guarded::Real::Guarded(g) => {
                return Ok(Some(Found::Guarded(checkouts::rel(home, &g))));
            }
            guarded::Real::Failed(_) => at = up(part),
        }
    }
    Ok(None)
}

/// The projects the store knows whose folder is the path `rel`, or holds it, when the two are
/// compared without regard to case. The disk is not asked whether they are the same folder.
fn otherwise(conn: &Connection, this: &str, rel: &str) -> rusqlite::Result<Vec<String>> {
    let prefix = format!("checkout:{this}/");
    let wanted = rel.to_lowercase();
    let mut ids: Vec<String> = conn
        .prepare("SELECT id FROM entity WHERE type = ?1")?
        .query_map([checkouts::TYPE], |r| r.get::<_, String>(0))?
        .filter_map(|id| match id {
            Ok(id) => id
                .strip_prefix(&prefix)
                .is_some_and(|folder| known::within(&wanted, &folder.to_lowercase()))
                .then_some(Ok(id)),
            Err(e) => Some(Err(e)),
        })
        .collect::<rusqlite::Result<_>>()?;
    ids.sort();
    Ok(ids)
}

fn not_a_project(id: &str) -> Refused {
    Refused {
        code: "not_a_project",
        message: "the store holds this id, and it is not a project or a file of this Mac",
        example: "immune program asks about a program, immune machine about a machine",
        ids: vec![id.to_string()],
    }
}

fn not_an_id(id: &str) -> Refused {
    Refused {
        code: "usage",
        message: WHAT,
        example: "immune project ~/<folder> --json",
        ids: vec![id.to_string()],
    }
}
