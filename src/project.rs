//! `immune project <what>`: what the store knows of one project, a checkout, printed as the
//! contract's `Known` message. The answer is built by `known::known_of`; what is particular to a
//! project is only how the question names it and which readings find projects (`FOUND_BY`).
//!
//! An answer is about a project the store holds, never about a path inside one. A path, or the
//! id of a file or a checkout of this Mac, is first put into one form (`known::place_asked`) and
//! turned into the checkout's id by the rule the readers name checkouts by. A path inside a
//! project the store knows, such as the working folder of a program that ran there, answers for
//! that project, the nearest one that holds it, with a reading made by rule that a single path
//! inside is not judged on its own. A path that names no project as written may lead to one
//! through a symbolic link: it is followed with `guarded::real`, which never looks inside a
//! folder macOS asks permission for. The project's folder is never looked into. A path the store
//! knows only under another case or Unicode form answers for the project it knows, with a reading
//! made by rule that says so, since the Mac's volumes usually ignore both. A path under
//! no project is `unknown` with a reading made by rule that no reading opened it; a folder that
//! holds projects says how many.
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

/// Why an answer about a path under no project the store holds is not "looked, and not there".
const NOT_OPENED: &str =
    "no reading opened this place for this answer: no project the store knows is at it or holds it";

/// Why a path strictly inside a project is answered for the project.
const INSIDE: &str = "a single path inside a project is not judged on its own: the answer is about the project that holds it";

/// Why a folder macOS asks permission for, reached through a link, is not looked into.
const GUARDED: &str = "the path leads through a link into a folder macOS asks permission for, which is not looked into";

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
            // A path of this Mac, as an id of a checkout or a file names one, in one form.
            let path = |id: &str| {
                let file = id
                    .strip_prefix("checkout:")
                    .map(|rest| format!("file:{rest}"));
                known::place_spelled(file.as_deref().unwrap_or(id), Some(&this), &args.home)
            };
            // Whether the id named this Mac only when compared by the key: said in the answer.
            let mut id_spelled = false;
            let what = match &args.what {
                What::Path(rel) => What::Path(rel.clone()),
                What::Id(id) => match (known::type_of(conn, id)?.as_deref(), path(id)) {
                    // A project the store knows is answered for as it is named.
                    (Some(checkouts::TYPE), _) => What::Id(id.clone()),
                    (Some("file") | None, Some((rel, spelled))) => {
                        id_spelled = spelled;
                        What::Path(rel)
                    }
                    // A project of another machine, which the store never heard of.
                    (None, None) if id.starts_with("checkout:") => What::Id(id.clone()),
                    (Some(_), _) => return Ok(Err(not_a_project(id))),
                    (None, None) => return Ok(Err(not_an_id(id))),
                },
            };
            // The project's id, the place asked about, and why that place is not judged on its
            // own, when it is not.
            let (id, place, unread) = match &what {
                What::Id(id) => (Some(id.clone()), None, None),
                What::Path(rel) => match holding(conn, &this, rel)? {
                    Some(id) => {
                        let inside = known::place_of(&id).is_some_and(|(_, f)| f != rel);
                        (
                            Some(id),
                            Some(rel.clone()),
                            known::not_judged(id_spelled, inside.then_some(INSIDE)),
                        )
                    }
                    None => match through_link(conn, &this, rel, &args.home)? {
                        Some(Found::At(id)) => (
                            Some(id),
                            Some(rel.clone()),
                            known::not_judged(id_spelled, Some(INSIDE)),
                        ),
                        Some(Found::Guarded(folder)) => {
                            (None, Some(folder), Some(GUARDED.to_string()))
                        }
                        None => match otherwise(conn, &this, rel)? {
                            Some((id, folder)) => {
                                let inside = !known::same_place(&folder, rel);
                                (
                                    Some(id),
                                    Some(rel.clone()),
                                    known::not_judged(true, inside.then_some(INSIDE)),
                                )
                            }
                            None => {
                                let inside = inside(conn, &this, rel)?;
                                let unread = if inside > 0 {
                                    format!(
                                        "this folder is not a project the store knows, and it holds {}: ask about one of them by its id or its path",
                                        crate::things(inside as i64, "project", "projects")
                                    )
                                } else {
                                    NOT_OPENED.to_string()
                                };
                                (None, Some(rel.clone()), Some(unread))
                            }
                        },
                    },
                },
            };
            let inside = inside_projects();
            let q = question(
                &args.asked,
                id.as_deref(),
                Some(&this),
                place.as_deref(),
                unread.as_deref(),
                &inside,
            );
            known::known_of(conn, &q, &args.home, now).map(Ok)
        },
        |k| crate::answers_text::known(k, &crate::screen::Screen::of_stdout()),
    )
}

/// The question of a project, by its id where the store can name one.
fn question<'a>(
    asked: &'a str,
    id: Option<&'a str>,
    machine: Option<&'a str>,
    place: Option<&'a str>,
    unread: Option<&'a str>,
    inside: &'a [(&'a str, String)],
) -> Question<'a> {
    Question {
        places: &[],
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

/// The folders of the projects the store knows on this Mac, held or gone, by id.
fn projects(conn: &Connection, this: &str) -> rusqlite::Result<Vec<(String, String)>> {
    let prefix = format!("checkout:{this}/");
    let ids: Vec<String> = conn
        .prepare("SELECT id FROM entity WHERE type = ?1 ORDER BY id")?
        .query_map([checkouts::TYPE], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ids
        .into_iter()
        .filter_map(|id| {
            let folder = id.strip_prefix(&prefix)?.to_string();
            Some((id, folder))
        })
        .collect())
}

/// The nearest project the store knows whose folder is the path `rel`, or holds it, when the two
/// are compared by the key a Mac's volumes compare names by (`known::same_place`), with its
/// folder. The disk is not asked whether they are the same folder.
fn otherwise(
    conn: &Connection,
    this: &str,
    rel: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    Ok(projects(conn, this)?
        .into_iter()
        .filter(|(_, folder)| known::same_place(rel, folder))
        .max_by_key(|(_, folder)| folder.len()))
}

/// How many projects the store knows lie strictly inside the folder `rel`.
fn inside(conn: &Connection, this: &str, rel: &str) -> rusqlite::Result<usize> {
    Ok(projects(conn, this)?
        .iter()
        .filter(|(_, folder)| folder != rel && known::within(folder, rel))
        .count())
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
