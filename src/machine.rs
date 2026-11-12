//! `immune machine [<what>]`: what the store knows of one machine, this Mac or another the store
//! knows (a server, a tailnet peer), printed as the contract's `Known` message. The answer is
//! built by `known::known_of`; what is particular to a machine is how the question names it and
//! which readings find machines.
//!
//! Without `<what>` it is this Mac. Otherwise `<what>` is a machine's name as the store shows it,
//! a name or address the store knows it by, or its id: found the way `immune owner` finds one,
//! so the two commands name machines alike. A name that fits several machines not known to be
//! one is refused with their ids.
//!
//! A machine other than this Mac that the server check never visited, under any of its ids,
//! carries a reading of that visit made here by rule, `none` with `observed_at` 0: otherwise a
//! server known only by its name would be answered with every reading full and nothing on it
//! read.
//!
//! A machine the resolver found under several ids (`same_as`) is one machine: asked by any of
//! its names, the answer holds what was read under every one of them, and names the id asked.
//!
//! Its parts are one level: what is `part_of` or `located_on` the machine, such as its
//! containers, packages, checkouts and watched files. Their own parts are not given; a project
//! is asked about with `immune project`.

use crate::contract::v1;
use crate::known::{self, Question, Refused};
use crate::{covered, known_hosts, owner, servers, ssh_config, tailnet};
use rusqlite::Connection;
use std::path::PathBuf;
use std::process::ExitCode;

/// The readings that find machines, as reader and kind. Their latest reading of this Mac speaks
/// for every machine, known or not.
const FOUND_BY: [(&str, &str); 3] = [
    (ssh_config::READER, ssh_config::KIND),
    (known_hosts::READER, known_hosts::KIND),
    (tailnet::READER, tailnet::KIND),
];

/// What `immune machine` takes as a machine.
const WHAT: &str = "immune machine takes nothing for this Mac, or one machine: its name as the store shows it, a name or address it is known by, or its id, beginning with machine:";

/// `immune machine [<what>]`.
pub struct MachineArgs {
    pub store: PathBuf,
    pub json: bool,
    /// What was asked for, as given; `None` for this Mac.
    pub asked: Option<String>,
    /// The home folder: ids name a path inside it relative to it.
    pub home: PathBuf,
}

/// Reads the arguments after `machine`.
pub fn parse(it: impl Iterator<Item = String>) -> Result<MachineArgs, String> {
    let w = known::words(it)?;
    let asked = match <[String; 1]>::try_from(w.words) {
        Ok([asked]) => Some(asked),
        Err(words) if words.is_empty() => None,
        Err(_) => return Err(WHAT.to_string()),
    };
    Ok(MachineArgs {
        store: w.store,
        json: w.json,
        asked,
        home: crate::user_home()?,
    })
}

/// Answers `immune machine`.
pub fn machine_cmd(args: &MachineArgs) -> ExitCode {
    known::command("machine", &args.store, args.json, |conn, now| {
        let this = covered::this_machine(conn)?;
        // The machine asked for, and every id the resolver found to be the same machine.
        let (id, group) = match &args.asked {
            None => (this.clone(), this.iter().cloned().collect()),
            Some(asked) => match owner::find(conn, asked)? {
                owner::Found::One(id, group) => (Some(id), group),
                owner::Found::Several(groups) => {
                    return Ok(Err(Refused {
                        code: "several_machines",
                        message: "the name fits several machines the store does not know to be one; nothing was answered",
                        example: "ask for one of them by its id, as in: immune machine <id> --json",
                        ids: groups.into_iter().flatten().collect(),
                    }));
                }
                // A machine whose every trace was retracted is not among those the store knows
                // now, and its id still names it: it is gone, not unknown. The server check never
                // visited it, since a machine a reading was ever scoped to stays known.
                owner::Found::Unknown => {
                    let id = if asked.starts_with("machine:") {
                        asked.clone()
                    } else {
                        format!("machine:{asked}")
                    };
                    (known::exists(conn, &id)?.then_some(id), Vec::new())
                }
            },
        };
        let found_by = known::found_by(conn, id.as_deref(), &FOUND_BY)?;
        let q = Question {
            asked: args.asked.as_deref().unwrap_or_default(),
            id: id.as_deref(),
            // The machine under its other ids is the same machine.
            also: &group,
            folder: None,
            machine: this.as_deref(),
            found_by: &found_by,
        };
        let mut known = known::known_of(conn, &q, &args.home, now)?;
        if let Some(id) = &id
            && !group.iter().any(|m| Some(m) == this.as_ref())
            && !visited(conn, &group)?
        {
            never_visited(&mut known, id);
        }
        Ok(Ok(known))
    })
}

/// Why a machine the server check never visited carries a reading of its visit: the core's own
/// words, since the reading is made by rule and not read from the store.
const NEVER_VISITED: &str =
    "the server check has never visited this machine, so nothing on it was read";

/// Whether the server check ever visited the machine under any of its ids.
fn visited(conn: &Connection, group: &[String]) -> rusqlite::Result<bool> {
    let mut q = conn.prepare(
        "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND kind = ?2 AND scope = ?3)",
    )?;
    for m in group {
        if q.query_row([servers::READER, servers::VISIT, m], |r| r.get(0))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Adds to the answer the reading of a visit that was never made, in its place in the order of
/// scope, reader and kind. Without it a server known only by its name would be answered with
/// every reading full, and nothing on it read: false calm.
fn never_visited(known: &mut v1::Known, id: &str) {
    let reading = v1::Coverage {
        reader: servers::READER.to_string(),
        kind: servers::VISIT.to_string(),
        scope_text: known::whole(id),
        completeness: v1::Completeness::None as i32,
        reason_text: Some(NEVER_VISITED.to_string()),
        cause: Some(v1::Cause::NotGiven as i32),
        observed_at: 0,
        lacks: Vec::new(),
    };
    let key = |c: &v1::Coverage| (c.scope_text.clone(), c.reader.clone(), c.kind.clone());
    let at = known.coverage.partition_point(|c| key(c) < key(&reading));
    known.coverage.insert(at, reading);
}
