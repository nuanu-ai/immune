//! The map on the summary: one mark per thing the program has collected, grouped as a person
//! knows them (projects on this Mac, what is watched on this Mac, servers, and devices on the
//! private network), each a link to where that thing is described. No script: a mark's name
//! and state are in its `title`, which is also its accessible name.
//!
//! No false calm, the project's first invariant: a mark never says more than the program
//! knows. The calm mark is drawn only where the program judged the thing, from the same data
//! its answers come from; everything else is drawn hollow. What calm claims differs by group
//! and the legend says so: for a project, its dependencies were compared with known
//! vulnerabilities and none affects it; for something on this Mac, it is watched for change
//! and no finding rests on it; for a server, it was read in full at the last server check.

use crate::covered::{self, Count};
use crate::pages::{self, BEYOND, THIS_MAC, VULNERABILITIES};
use crate::view::{DETAILS, Latest, Out, esc};
use crate::{autorun, beyond, integrity, servers, watched};
use rusqlite::{Connection, params};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt::Write;

/// The state of one mark.
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

impl State {
    pub fn class(self) -> &'static str {
        match self {
            State::Look => "look",
            State::Vulnerable => "vuln",
            State::Calm => "calm",
            State::Open => "open",
            State::Theirs => "theirs",
        }
    }
}

/// One thing on the map: its name as a person recognises it, its state in words, and the
/// section it leads to with that section's heading, which begins its title.
pub struct Mark {
    pub name: String,
    pub state: State,
    pub said: &'static str,
    href: String,
    heading: String,
}

impl Mark {
    fn title(&self) -> String {
        format!("{}: {} · {}", self.heading, self.name, self.said)
    }
}

/// The things of one kind watched on this Mac.
pub struct Kind {
    pub what: &'static str,
    pub marks: Vec<Mark>,
}

#[derive(Default)]
pub struct Map {
    /// Projects were looked for on this Mac.
    pub projects_looked: bool,
    /// A full check of this Mac has finished.
    pub checked: bool,
    pub projects: Vec<Mark>,
    pub mac: Vec<Kind>,
    pub servers: Vec<Mark>,
    pub own: Vec<Mark>,
    pub others: Vec<Mark>,
    /// Machines the owner set aside while nothing contradicts it.
    pub set_aside: i64,
    /// Open findings by where they rest.
    pub on_mac: usize,
    pub on_projects: usize,
    pub on_servers: usize,
}

impl Map {
    /// Projects whose mark is hollow: their dependencies were not all compared.
    pub fn projects_open(&self) -> usize {
        self.projects
            .iter()
            .filter(|m| m.state == State::Open)
            .count()
    }
}

/// What a project's mark says when it is calm, and when it is hollow.
const PROJECT_CALM: &str = "dependencies compared with known vulnerabilities, none affects it";
const PROJECT_NO_PACKAGES: &str = "no dependencies this version can compare";
const PROJECT_NOT_ALL: &str = "not all of its dependencies could be compared";
const LOOK: &str = "needs a look";

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

/// Everything on the map, from the store and the open findings of the status.
pub fn read(
    conn: &Connection,
    st: &crate::status::State,
    latest: &[Latest],
) -> Result<Map, Box<dyn Error>> {
    let checked = st.this_mac.checked_at.is_some();
    let Some(this) = covered::this_machine(conn)? else {
        return Ok(Map {
            checked,
            ..Map::default()
        });
    };
    let mut map = Map {
        checked,
        projects_looked: latest
            .iter()
            .any(|r| r.reader == crate::checkouts::READER && r.scope == this),
        ..Map::default()
    };
    let checkouts = checkouts(conn, &this)?;
    let split = beyond::split(conn, &this)?;

    // Where each open finding rests.
    let mut look_projects: HashSet<usize> = HashSet::new();
    let mut look_servers: HashSet<usize> = HashSet::new();
    let mut look_mac: HashSet<&str> = HashSet::new();
    for i in &st.needs.items {
        match area(&i.about, &checkouts, &split.servers) {
            Area::Project(p) => {
                look_projects.insert(p);
                map.on_projects += 1;
            }
            Area::Server(s) => {
                look_servers.insert(s);
                map.on_servers += 1;
            }
            Area::Mac => {
                look_mac.insert(&i.about);
                map.on_mac += 1;
            }
        }
    }

    // Projects.
    let judged = judged(conn, latest, &checkouts)?;
    let affected: HashSet<String> = crate::vulnerabilities::affecting(conn)?
        .into_iter()
        .map(|a| a.checkout)
        .collect();
    let projects_page = format!("{DETAILS}/{THIS_MAC}.html#projects");
    for (i, c) in checkouts.iter().enumerate() {
        let (n, calm) = judged.get(c).copied().unwrap_or_default();
        let name = crate::findings::place(c, Some(&this));
        let mark = if look_projects.contains(&i) {
            looked(name)
        } else if affected.contains(c) {
            Mark {
                name,
                state: State::Vulnerable,
                said: "known vulnerabilities in its dependencies",
                href: format!("{DETAILS}/{VULNERABILITIES}.html#by-project"),
                heading: "Known vulnerabilities by project".to_string(),
            }
        } else {
            let (state, said) = match (calm, n) {
                (true, _) => (State::Calm, PROJECT_CALM),
                (false, 0) => (State::Open, PROJECT_NO_PACKAGES),
                (false, _) => (State::Open, PROJECT_NOT_ALL),
            };
            Mark {
                name,
                state,
                said,
                href: projects_page.clone(),
                heading: "Projects".to_string(),
            }
        };
        map.projects.push(mark);
    }
    order(&mut map.projects);

    // What is watched on this Mac, kind by kind, except what is inside a project.
    for (count, what, _) in covered::watched() {
        let href = format!("{DETAILS}/{THIS_MAC}.html#{}", pages::anchor(what));
        let heading = pages::capital(what);
        let mut marks = Vec::new();
        match count {
            Count::Files(as_) => {
                let mut kinds = autorun::kinds_of(as_);
                kinds.extend(
                    watched::kinds()
                        .into_iter()
                        .filter(|(w, _)| *w == as_)
                        .map(|(_, kind)| kind.to_string()),
                );
                let kind_failed = latest.iter().any(|r| {
                    r.reader == watched::READER
                        && r.scope == this
                        && kinds.contains(&r.kind)
                        && r.completeness != "full"
                });
                let files: Vec<String> = conn
                    .prepare(
                        "SELECT DISTINCT subject FROM assertion
                         WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'
                           AND object = ?2 ORDER BY subject",
                    )?
                    .query_map(params![watched::READER, as_], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                for f in files {
                    if project_of(&f, &checkouts).is_some() {
                        continue;
                    }
                    let failed = kind_failed
                        || latest
                            .iter()
                            .any(|r| r.scope == f && r.completeness != "full");
                    marks.push(on_mac(
                        crate::findings::place(&f, Some(&this)),
                        look_mac.contains(f.as_str()),
                        failed,
                        &href,
                        &heading,
                    ));
                }
            }
            Count::Installed(kind) => {
                let failed = latest.iter().any(|r| {
                    r.reader == integrity::READER
                        && r.scope == this
                        && r.kind == kind
                        && r.completeness != "full"
                });
                for (subject, name) in pages::installed_names(conn, kind, Some(&this))? {
                    marks.push(on_mac(
                        name,
                        look_mac.contains(subject.as_str()),
                        failed,
                        &href,
                        &heading,
                    ));
                }
            }
            Count::Dependencies => continue,
        }
        if !marks.is_empty() {
            order(&mut marks);
            map.mac.push(Kind { what, marks });
        }
    }

    // Servers, the owner's other devices and other people's devices.
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
        let name = label(group);
        if look_servers.contains(&i) {
            map.servers.push(looked(name));
            continue;
        }
        let last = visits
            .iter()
            .filter(|v| group.contains(&v.scope))
            .max_by_key(|v| v.at);
        let (state, said) = match last {
            Some(v) if v.completeness == "full" => {
                (State::Calm, "read in full at the last server check")
            }
            Some(v) if v.reason.as_deref() == Some(servers::NOT_COMPLETE) => {
                (State::Open, "did not finish at the last server check")
            }
            Some(_) => (State::Open, "could not be opened at the last server check"),
            None => (State::Open, "not part of the last server check"),
        };
        map.servers.push(Mark {
            name,
            state,
            said,
            href: format!("{DETAILS}/{BEYOND}.html#servers"),
            heading: "Servers".to_string(),
        });
    }
    order(&mut map.servers);
    for group in &split.own_devices {
        map.own.push(Mark {
            name: label(group),
            state: State::Open,
            said: "not checked: this version looks at this Mac and at servers",
            href: format!("{DETAILS}/{BEYOND}.html#your-devices"),
            heading: "Your other devices".to_string(),
        });
    }
    for group in &split.other_devices {
        map.others.push(Mark {
            name: label(group),
            state: State::Theirs,
            said: "not yours to check",
            href: format!("{DETAILS}/{BEYOND}.html#other-devices"),
            heading: "Other devices".to_string(),
        });
    }
    for list in [&mut map.own, &mut map.others] {
        list.sort_by(|a, b| a.name.cmp(&b.name));
    }
    map.set_aside = crate::owner::standing(conn)?
        .iter()
        .filter(|s| s.seen.is_none())
        .count() as i64;
    Ok(map)
}

/// A thing an open finding rests on: it leads to what needs a look.
fn looked(name: String) -> Mark {
    Mark {
        name,
        state: State::Look,
        said: LOOK,
        href: format!("{}#needs", crate::view::SUMMARY),
        heading: "Needs a look".to_string(),
    }
}

/// A thing watched on this Mac: calm only while its reading is full.
fn on_mac(name: String, look: bool, failed: bool, href: &str, heading: &str) -> Mark {
    if look {
        return looked(name);
    }
    let (state, said) = if failed {
        (State::Open, "not fully read at the last check")
    } else {
        (State::Calm, "watched for change, no finding rests on it")
    };
    Mark {
        name,
        state,
        said,
        href: href.to_string(),
        heading: heading.to_string(),
    }
}

/// What needs a look first, then the rest by name.
fn order(marks: &mut [Mark]) {
    marks.sort_by(|a, b| a.state.cmp(&b.state).then_with(|| a.name.cmp(&b.name)));
}

/// A legend mark and its words.
const LEGEND: [(&str, &str); 5] = [
    ("look", "Needs a look"),
    ("vuln", "Known vulnerabilities"),
    ("calm", "Nothing to look at"),
    ("open", "Not checked or not compared"),
    ("theirs", "Not yours to check"),
];

/// What the calm mark claims, group by group.
const CALM_MEANS: &str = "Nothing to look at says only what was checked: for a project, that its dependencies were compared with known vulnerabilities and none affects it; for something on this Mac, that it is watched for change and no finding rests on it; for a server, that it was read in full at the last server check. Each mark is one thing; point at it to see its name, and follow it to where it is described.";

/// How large marks are drawn: large while a group fits about four rows of its width, then
/// smaller, then smallest. Marks wrap; none is left out.
#[derive(Clone, Copy)]
enum Size {
    /// Projects take the whole width of the card: about forty large marks a row.
    Wide,
    /// Servers and devices take a column: about nineteen a row.
    Column,
    /// What is watched on this Mac: small from the start.
    Small,
}

/// Marks drawn as links.
fn marks(out: &mut String, list: &[Mark], round: bool, size: Size) -> Out {
    let n = list.len();
    let class = match size {
        Size::Wide if n <= 160 => "",
        Size::Column if n <= 76 => "",
        _ if n <= 300 => " small",
        _ => " tiny",
    };
    writeln!(
        out,
        "<div class=\"marks{class}{}\">",
        if round { " round" } else { "" }
    )?;
    for m in list {
        writeln!(
            out,
            "<a class=\"m {}\" href=\"{}\" title=\"{}\"></a>",
            m.state.class(),
            esc(&m.href),
            esc(&m.title())
        )?;
    }
    out.push_str("</div>\n");
    Ok(())
}

impl Map {
    /// Whether anything beyond this Mac is known: a server, or a device of either kind.
    pub fn beyond(&self) -> bool {
        !(self.servers.is_empty() && self.own.is_empty() && self.others.is_empty())
    }
}

/// The map, as a card of its own: the legend, then each group with its count and its marks;
/// what the marks and the groups mean is closed at the bottom. A Mac with nothing known beyond
/// it has no group for servers.
pub fn draw(out: &mut String, map: &Map, own_devices_said: &str) -> Out {
    out.push_str("<section id=\"map\">\n<div class=\"head\"><h2>What you have</h2></div>\n<ul class=\"legend\">\n");
    for (class, words) in LEGEND {
        writeln!(
            out,
            "<li><span class=\"m {class}\" aria-hidden=\"true\"></span>{words}</li>"
        )?;
    }
    out.push_str("</ul>\n<div class=\"groups\">\n");

    // Projects, the main thing, across the whole width.
    writeln!(
        out,
        "<div class=\"group wide\">\n<h3>Projects <span>{}</span></h3>",
        map.projects.len()
    )?;
    if map.projects.is_empty() {
        let said = if map.projects_looked {
            "None found on this Mac."
        } else {
            "Not looked for yet: this Mac has not been checked."
        };
        writeln!(out, "<p class=\"note\">{said}</p>")?;
    } else {
        marks(out, &map.projects, false, Size::Wide)?;
    }
    out.push_str("</div>\n");

    // This Mac.
    let total: usize = map.mac.iter().map(|k| k.marks.len()).sum();
    writeln!(
        out,
        "<div class=\"group\">\n<h3>This Mac <span>{total}</span></h3>"
    )?;
    if map.mac.is_empty() {
        out.push_str(if map.checked {
            "<p class=\"note\">Nothing to watch was found on this Mac at the last check.</p>\n"
        } else {
            "<p class=\"note\">Nothing has been read on this Mac yet.</p>\n"
        });
    }
    for k in &map.mac {
        writeln!(
            out,
            "<h4>{} <span>{}</span></h4>",
            esc(&pages::capital(k.what)),
            k.marks.len()
        )?;
        marks(out, &k.marks, false, Size::Small)?;
    }
    out.push_str("</div>\n");

    // Servers and devices, only where any is known.
    if map.beyond() {
        writeln!(
            out,
            "<div class=\"group\">\n<h3>Servers <span>{}</span></h3>",
            map.servers.len()
        )?;
        if map.servers.is_empty() {
            out.push_str("<p class=\"note\">None known.</p>\n");
        } else {
            marks(out, &map.servers, true, Size::Column)?;
        }
        if !map.own.is_empty() {
            writeln!(
                out,
                "<h4>Your other devices <span>{}</span></h4>",
                map.own.len()
            )?;
            marks(out, &map.own, false, Size::Column)?;
        }
        if !map.others.is_empty() {
            writeln!(
                out,
                "<h4>Other people's devices <span>{}</span></h4>",
                map.others.len()
            )?;
            marks(out, &map.others, false, Size::Column)?;
        }
        out.push_str("</div>\n");
    }
    if map.set_aside > 0 {
        writeln!(
            out,
            "<p class=\"note\"><a href=\"{DETAILS}/{BEYOND}.html#retired\">Retired or not yours: {}</a></p>",
            map.set_aside
        )?;
    }
    out.push_str("</div>\n");

    // What the marks and the groups mean, closed.
    writeln!(
        out,
        "<details class=\"means\">\n<summary>What the marks mean</summary>\n<p>{}</p>\n<p><strong>Projects</strong>: folders of code kept with git. Their git hooks are watched, and the files that say what they depend on are read at every check.</p>",
        esc(CALM_MEANS)
    )?;
    if map.beyond() {
        out.push_str("<p><strong>Servers</strong>: machines you log in to over SSH, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself.</p>\n");
    }
    if !map.own.is_empty() {
        writeln!(
            out,
            "<p><strong>Your other devices</strong>: {}</p>",
            esc(own_devices_said)
        )?;
    }
    if !map.others.is_empty() {
        out.push_str("<p><strong>Other people's devices</strong>: computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them.</p>\n");
    }
    if map.set_aside > 0 {
        out.push_str("<p><strong>Retired or not yours</strong>: machines you said are retired or not yours; they are not checked.</p>\n");
    }
    out.push_str("</details>\n</section>\n");
    Ok(())
}
