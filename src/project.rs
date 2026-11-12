//! `immune project <what>`: what the store knows of one project, a checkout, printed as the
//! contract's `Known` message. The answer is built by `known::known_of`; what is particular to a
//! project is only how the question names it and which readings find projects (`FOUND_BY`).
//!
//! A path is turned into the checkout's id by the rule the readers name checkouts by, and the
//! project's folder is never looked at. A project in a folder macOS asks permission for carries
//! the reading that says the folder was not looked into, whatever was read in it before.

use crate::known::{self, Question};
use crate::{checkouts, covered};
use std::path::PathBuf;
use std::process::ExitCode;

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
pub fn parse(it: impl Iterator<Item = String>) -> Result<ProjectArgs, String> {
    let w = known::words(it)?;
    let [asked] = <[String; 1]>::try_from(w.words).map_err(|_| WHAT.to_string())?;
    let home = crate::user_home()?;
    let what = if asked.starts_with("checkout:") {
        What::Id(asked.clone())
    } else {
        What::Path(known::path_of(&asked, &home).ok_or_else(|| WHAT.to_string())?)
    };
    Ok(ProjectArgs {
        store: w.store,
        json: w.json,
        asked,
        what,
        home,
    })
}

/// Answers `immune project`.
pub fn project_cmd(args: &ProjectArgs) -> ExitCode {
    known::command("project", &args.store, args.json, |conn, now| {
        let this = covered::this_machine(conn)?;
        let id = match &args.what {
            What::Id(id) => Some(id.clone()),
            // A store no run has written names no Mac, and so no project on it.
            What::Path(rel) => this.as_ref().map(|m| format!("checkout:{m}/{rel}")),
        };
        let q = Question {
            asked: &args.asked,
            id: id.as_deref(),
            also: &[],
            folder: id.as_deref().and_then(known::place_of),
            machine: this.as_deref(),
            found_by: &FOUND_BY,
        };
        known::known_of(conn, &q, &args.home, now).map(Ok)
    })
}
