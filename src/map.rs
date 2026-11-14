//! What the program has collected beyond this Mac's own watched places, grouped as a person
//! knows them (projects on this Mac, servers, and devices on the private network), each thing
//! with its state: what the summary's table of what is watched counts for projects and servers.
//!
//! No false calm, the project's first invariant: a thing is never counted as judged beyond what
//! the program knows. A project is calm only where its dependencies were compared with known
//! vulnerabilities and none affects it; a server only where it was read in full at the last
//! server check; everything else is open.

use crate::covered;
use crate::view::Latest;
use crate::{beyond, servers};
use rusqlite::Connection;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;

/// The state of one thing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum State {
    /// An open finding rests on it.
    Look,
    /// A project with at least one "affects" answer.
    Vulnerable,
    /// Judged, and nothing to look at: only where the program really judged it.
    Calm,
    /// Not judged or not checked.
    Open,
    /// Someone else's device: not the owner's to check.
    Theirs,
}

/// One thing: its name as a person recognises it, and its state.
pub struct Mark {
    pub name: String,
    pub state: State,
}

#[derive(Default)]
pub struct Map {
    pub projects: Vec<Mark>,
    pub servers: Vec<Mark>,
    pub own: Vec<Mark>,
    pub others: Vec<Mark>,
    /// Open findings resting on a server.
    pub on_servers: usize,
    /// Servers whose latest visit read them in full, whatever findings rest on them: a server
    /// marked `Look` may not have been checked at all.
    pub servers_checked: usize,
}

impl Map {
    /// Projects whose dependencies were not all compared.
    pub fn projects_open(&self) -> usize {
        self.projects
            .iter()
            .filter(|m| m.state == State::Open)
            .count()
    }
}

/// Where an open finding rests, by the entity it is about.
enum Area {
    Mac,
    Project(usize),
    Server(usize),
}

/// The project a thing is in: a file or a component whose id continues a checkout's, the
/// longest such checkout. A file's id is `file:<machine>/<path>`, a checkout's
/// `checkout:<machine>/<path>`, a lockfile entry's `component:<checkout id>/…`.
fn project_of(about: &str, checkouts: &[String]) -> Option<usize> {
    checkouts
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            let inside = |rest: &str, prefix: &str| {
                rest == prefix
                    || rest
                        .strip_prefix(prefix)
                        .is_some_and(|tail| tail.starts_with('/'))
            };
            let bare = c.strip_prefix("checkout:").unwrap_or(c);
            about
                .strip_prefix("file:")
                .is_some_and(|rest| inside(rest, bare))
                || about
                    .strip_prefix("component:")
                    .is_some_and(|rest| inside(rest, c))
                || about == c.as_str()
        })
        .max_by_key(|(_, c)| c.len())
        .map(|(i, _)| i)
}

fn area(about: &str, checkouts: &[String], servers: &[Vec<String>]) -> Area {
    if let Some(i) = project_of(about, checkouts) {
        return Area::Project(i);
    }
    let machine = about
        .strip_prefix("container:")
        .and_then(|rest| rest.rsplit_once('/').map(|(m, _)| m))
        .unwrap_or(about);
    match servers.iter().position(|g| g.iter().any(|m| m == machine)) {
        Some(i) => Area::Server(i),
        None => Area::Mac,
    }
}

/// How many packages each project's lockfiles declare, and whether its dependencies were
/// judged: the only case in which its mark may be calm. All of these must hold, read from the
/// tables the answers come from:
/// - its latest lockfile reading is full, so no lockfile of a kind this version does not read,
///   no unreadable one and no entry that could not be told is left out;
/// - it declares at least one package, and for every ecosystem among its packages the latest
///   matching found its lockfiles read in full and that ecosystem's data current
///   (`vulnerability_place`): an ecosystem with no data has no place and is never judged;
/// - no answer for it is "don't know" (`vulnerability_answer`).
///
/// Whether the data has aged since that check is said where the limits of this version are:
/// the mark speaks for the latest check, as the answers do.
pub fn judged(
    conn: &Connection,
    latest: &[Latest],
    checkouts: &[String],
) -> rusqlite::Result<HashMap<String, (usize, bool)>> {
    let mut ecosystems: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut packages: HashMap<String, usize> = HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject, scope FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'part_of'",
    )?;
    for row in stmt.query_map([crate::lockfiles::READER], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (subject, scope) = row?;
        let Some(rest) = subject.strip_prefix(&format!("component:{scope}/")) else {
            continue;
        };
        let eco = rest.split_once('/').map_or(rest, |(e, _)| e);
        ecosystems
            .entry(scope.clone())
            .or_default()
            .insert(eco.to_string());
        *packages.entry(scope).or_default() += 1;
    }
    // A store an older build left, opened only for reading, may not hold the answers yet:
    // then nothing was compared, and no project is calm.
    let tables = crate::vulnerabilities::has_tables(conn)?;
    let mut places: HashSet<(String, String)> = HashSet::new();
    let mut unknown: HashSet<String> = HashSet::new();
    if tables {
        let mut stmt = conn.prepare(
            "SELECT checkout, ecosystem FROM vulnerability_place
             WHERE lockfiles = 'full' AND feed = 'current'",
        )?;
        for row in stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))? {
            places.insert(row?);
        }
        let mut stmt = conn.prepare(
            "SELECT DISTINCT checkout FROM vulnerability_answer WHERE answer = 'unknown'",
        )?;
        for row in stmt.query_map([], |r| r.get(0))? {
            unknown.insert(row?);
        }
    }
    let mut out = HashMap::new();
    for c in checkouts {
        let read_full = latest
            .iter()
            .filter(|r| r.reader == crate::lockfiles::READER && r.scope == *c)
            .all(|r| r.completeness == "full");
        // No package means no ecosystem, and nothing compared.
        let compared = ecosystems.get(c).is_some_and(|e| {
            e.iter()
                .all(|eco| places.contains(&(c.clone(), eco.clone())))
        });
        out.insert(
            c.clone(),
            (
                packages.get(c).copied().unwrap_or_default(),
                read_full && compared && !unknown.contains(c),
            ),
        );
    }
    Ok(out)
}

/// The checkouts on this Mac, by id, in the order of their ids.
pub fn checkouts(conn: &Connection, this: &str) -> rusqlite::Result<Vec<String>> {
    conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer = 'live' AND predicate = 'located_on' AND object = ?1
           AND subject LIKE 'checkout:%' ORDER BY subject",
    )?
    .query_map([this], |r| r.get(0))?
    .collect()
}

/// Projects, servers and devices, from the store and the open findings of the status.
pub fn read(
    conn: &Connection,
    st: &crate::status::State,
    latest: &[Latest],
) -> Result<Map, Box<dyn Error>> {
    let Some(this) = covered::this_machine(conn)? else {
        return Ok(Map::default());
    };
    let mac = crate::findings::This::of(conn, Some(this.clone()))?;
    let mut map = Map::default();
    let checkouts = checkouts(conn, &this)?;
    let split = beyond::split(conn, &this)?;

    // Where each open finding rests.
    let mut look_projects: HashSet<usize> = HashSet::new();
    let mut look_servers: HashSet<usize> = HashSet::new();
    for i in &st.needs.items {
        match area(&i.about, &checkouts, &split.servers) {
            Area::Project(p) => {
                look_projects.insert(p);
            }
            Area::Server(s) => {
                look_servers.insert(s);
                map.on_servers += 1;
            }
            Area::Mac => {}
        }
    }

    // Projects: calm only where `judged` says so.
    let judged = judged(conn, latest, &checkouts)?;
    let affected: HashSet<String> = crate::vulnerabilities::affecting(conn)?
        .into_iter()
        .map(|a| a.checkout)
        .collect();
    for (i, c) in checkouts.iter().enumerate() {
        let (_, calm) = judged.get(c).copied().unwrap_or_default();
        let state = if look_projects.contains(&i) {
            State::Look
        } else if affected.contains(c) {
            State::Vulnerable
        } else if calm {
            State::Calm
        } else {
            State::Open
        };
        map.projects.push(Mark {
            name: crate::findings::place(c, mac.as_ref()),
            state,
        });
    }
    order(&mut map.projects);

    // Servers: calm only where read in full at the last server check.
    let visits: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .collect();
    let bare = |m: &str| m.strip_prefix("machine:").unwrap_or(m).to_string();
    let label = |group: &[String]| -> String {
        group
            .iter()
            .find(|m| visits.iter().any(|v| &v.scope == *m))
            .or(group.first())
            .map(|m| bare(m))
            .unwrap_or_default()
    };
    for (i, group) in split.servers.iter().enumerate() {
        let last = visits
            .iter()
            .filter(|v| group.contains(&v.scope))
            .max_by_key(|v| v.at);
        let full = last.is_some_and(|v| v.completeness == "full");
        map.servers_checked += usize::from(full);
        let state = match last {
            _ if look_servers.contains(&i) => State::Look,
            _ if full => State::Calm,
            _ => State::Open,
        };
        map.servers.push(Mark {
            name: label(group),
            state,
        });
    }
    order(&mut map.servers);
    for group in &split.own_devices {
        map.own.push(Mark {
            name: label(group),
            state: State::Open,
        });
    }
    for group in &split.other_devices {
        map.others.push(Mark {
            name: label(group),
            state: State::Theirs,
        });
    }
    Ok(map)
}

/// What needs a look first, then the rest by name.
fn order(marks: &mut [Mark]) {
    marks.sort_by(|a, b| a.state.cmp(&b.state).then_with(|| a.name.cmp(&b.name)));
}
