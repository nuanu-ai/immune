//! The pages a person lands on: the summary, which answers what the app answers; what is
//! watched on this Mac, kind by kind; and what is beyond it. Every sentence is in plain
//! words: what something means for the owner, and whether he can do something about it.
//! What holds on every Mac, the limits of this version, is not on the pages: the documents
//! and the commands' machine form say it. The other pages are reached from the links at the
//! bottom of the summary.
//!
//! Every link on the summary leads to a section that lists exactly what its label says,
//! under a heading that says it, first thing on arrival.
//!
//! Text from the store goes through `esc`, as on every page of the view.

use crate::contract::v1;
use crate::covered::{self, Count, Uncovered, YOU};
use crate::view::{self, DETAILS, FOOT, Latest, Out, counted, esc, utc, utc_or};
use crate::{beyond, findings, integrity, servers, watched};
use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

/// The person's pages of details, by file name in the folder of details.
pub const THIS_MAC: &str = "this-mac";
/// The heading of that page, which a link to it is named by.
pub const THIS_MAC_TITLE: &str = "What is watched on this Mac";
pub const BEYOND: &str = "beyond";
/// Every source of threat data, with the list of vulnerabilities used in attacks.
pub const THREAT_DATA: &str = "threats";
/// Every published rule this build ships.
pub const RULES: &str = "rules";
/// The heading of that page and of the summary's section about it.
const RULES_TITLE: &str = "Published rules";
/// The heading of that page, which the tile leading to it is named by.
const THREAT_DATA_TITLE: &str = "Threat data";
pub const TECHNICAL: &str = "technical";
pub const VULNERABILITIES: &str = "vulnerabilities";

/// At most this many things that need a look are shown in full, so the summary stays small.
const ITEMS_SHOWN: usize = 100;
/// At most this many examples are listed under a thing not covered.
const EXAMPLES_SHOWN: usize = 20;

/// The link back to the summary, on every page of details.
const BACK: &str = "<nav class=\"meta\"><a href=\"../view.html\">← What needs a look</a></nav>\n";

/// The anchor of a kind of watched thing: its words in lower case, joined by dashes.
pub fn anchor(what: &str) -> String {
    what.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

/// Words as they begin a line: `Startup items`. A name written in lower case stays so.
pub fn capital(s: &str) -> String {
    if s.starts_with("npm ") {
        return s.to_string();
    }
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// `1,234`.
fn grouped(n: i64) -> String {
    counted(n, "", "").trim_end().to_string()
}

/// What each kind of watched thing is, in a line.
fn about(what: &str) -> &'static str {
    match what {
        "startup items" => {
            "Programs macOS starts by itself when you log in or the Mac starts: the usual way for something unwanted to stay on a Mac."
        }
        covered::LOGIN_HOOKS => {
            "Scripts the login window runs with full control at every login and logout, a way Apple replaced years ago."
        }
        "shell startup files" => "Files your terminal runs every time it opens a shell.",
        "SSH files" => "Your SSH settings, and the keys allowed to log in to this Mac.",
        covered::LOGIN_MODULES => {
            "The rules and plugins that decide how you log in, unlock and approve an administrator action, and how your password is checked."
        }
        "git hooks in projects" => {
            "Scripts git runs by itself in your projects, for example before a commit."
        }
        "applications" => "Applications in the Applications folders, with who signed each.",
        "Homebrew packages" => "What Homebrew installed in /opt/homebrew or /usr/local.",
        "npm packages" => {
            "Packages npm installed for every project at once in /opt/homebrew/lib/node_modules or /usr/local/lib/node_modules. Those installed under nvm or another Node version manager are not read."
        }
        "app code kept outside the app" => {
            "Code that applications not made by Apple keep in your Library folder, outside the application itself."
        }
        covered::DEPENDENCIES => {
            "Packages your projects list in package-lock.json, pnpm-lock.yaml and Cargo.lock, compared at every check with the known vulnerabilities and malicious packages of npm and crates.io."
        }
        _ => crate::autorun::about(what),
    }
}

/// The summary page, a report read from the top: the state in the panel's words, with one line
/// on what it rests on; the findings as a table, open, answered and all, each row opening in
/// place to its evidence as `immune finding` gives it; what is watched, area by area, with its
/// state and when it was last read; "As it happens", every program start checked against
/// published rules (`happens.rs`); what the person can fix, and what on this Mac was not judged;
/// and a line of links to the other pages. Built from the state and the result
/// `immune status --json` gives, so the two agree.
pub fn summary(
    conn: &Connection,
    st: &crate::status::State,
    r: &v1::Status,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = view::head("What needs a look").replacen("<body>", "<body class=\"summary\">", 1);
    let latest = view::latest_coverage(conn)?;
    let map = crate::map::read(conn, st, &latest)?;
    let mac = findings::This::of(conn, covered::this_machine(conn)?)?;
    let fixable: Vec<&Uncovered> = st
        .not_covered
        .iter()
        .filter(|u| u.cause.who == YOU)
        .collect();
    // The scope of the answer, said once as a link to where each thing is named.
    let unjudged = unjudged(st).len();
    state(conn, &mut out, st, r, now)?;
    findings_table(conn, &mut out, st, mac.as_ref(), now)?;
    watched_table(conn, &mut out, st, &map, &latest, &fixable, unjudged, now)?;
    crate::happens::draw(&mut out, st, &r.rules.clone().unwrap_or_default(), now)?;
    you_can_fix(&mut out, &fixable)?;
    let name = crate::store::held_mac(conn)?.map(|(_, name)| name);
    links(&mut out, name.as_deref(), now)?;
    out.push_str(FOOT);
    Ok(out)
}

/// What on this Mac was not judged and nothing the person does changes, as the panel counts it.
/// What holds on every Mac, a limit of this version, is not on the pages; the documents and the
/// commands' machine form say it.
fn unjudged(st: &crate::status::State) -> Vec<&Uncovered> {
    st.not_covered
        .iter()
        .filter(|u| u.cause.who != YOU && !u.every_mac)
        .collect()
}

/// The state's glyph, one shape for each state, as the panel draws it, so colour is never the
/// only sign: a disc with an exclamation mark in `--now` when something needs the person now; a
/// disc with an eye in `--quiet` when there are things to look at and none is urgent; a disc with
/// a tick in `--calm` for nothing to look at on a Mac watched in full; a ring with a tick for one
/// watched in part; a ring with a clock for an answer that is old; a dashed ring with a question
/// mark when it is not known. The three colours are the stylesheet's, defined once.
const GLYPH_NOW: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--now)\"/><path d=\"M20 10.5v11\" style=\"stroke:var(--on);stroke-width:3.2;stroke-linecap:round\"/><circle cx=\"20\" cy=\"28.5\" r=\"2\" style=\"fill:var(--on)\"/></svg>";
const GLYPH_LOOK: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--quiet)\"/><path d=\"M9.5 20c2.8-4.6 6.3-6.9 10.5-6.9s7.7 2.3 10.5 6.9c-2.8 4.6-6.3 6.9-10.5 6.9S12.3 24.6 9.5 20z\" style=\"fill:none;stroke:var(--on);stroke-width:2.4;stroke-linejoin:round\"/><circle cx=\"20\" cy=\"20\" r=\"3.2\" style=\"fill:var(--on)\"/></svg>";
const GLYPH_CALM: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--calm)\"/><path d=\"M12.5 20.5l5 5 10-11\" style=\"fill:none;stroke:var(--on);stroke-width:3.2;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_PART: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--quiet);stroke-width:1.5\"/><path d=\"M12.5 20.5l5 5 10-11\" style=\"fill:none;stroke:var(--quiet);stroke-width:3;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_STALE: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--quiet);stroke-width:1.5\"/><circle cx=\"20\" cy=\"20\" r=\"10\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.4\"/><path d=\"M20 14v6.5l4 2.5\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_UNKNOWN: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--quiet);stroke-width:1.5;stroke-dasharray:4 3\"/><path d=\"M15.8 16a4.3 4.3 0 1 1 6.1 3.9c-1.3.6-1.9 1.5-1.9 2.9v.7\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.6;stroke-linecap:round\"/><circle cx=\"20\" cy=\"28.2\" r=\"1.7\" style=\"fill:var(--quiet)\"/></svg>";

/// "1 needs you now · 2 to look at": the findings Immune marked urgent, and the rest of its
/// total, in the panel's words (`Panel.headline`).
fn needs_you(urgent: u64, total: u64) -> String {
    let rest = total.saturating_sub(urgent);
    let mut parts = Vec::new();
    if urgent > 0 {
        parts.push(if urgent == 1 {
            "1 needs you now".to_string()
        } else {
            format!("{} need you now", grouped(urgent as i64))
        });
    }
    if rest > 0 {
        parts.push(format!("{} to look at", grouped(rest as i64)));
    }
    parts.join(" · ")
}

/// The state band: the glyph and the headline in the panel's words, then one short line: this
/// Mac's name as data, why the headline cannot say more when it cannot, how it is watched, the
/// last full check and when the page was made. A state the page cannot work out is said as not
/// known, never as calm.
fn state(
    conn: &Connection,
    out: &mut String,
    st: &crate::status::State,
    r: &v1::Status,
    now: i64,
) -> Out {
    let m = &st.this_mac;
    let not_computed: Vec<&v1::NotComputed> = r
        .not_computed
        .iter()
        .filter(|n| n.section == "needs_a_look")
        .collect();
    let needs = r.needs_a_look.as_ref().filter(|_| not_computed.is_empty());
    // Things as the rows show them, a pair one thing: the band says what the table draws.
    let shown = shown(&rows_of(st));
    let total = needs.map(|_| (shown.now + shown.look) as u64);
    let urgent = shown.now as u64;
    let fresh = r.this_mac.as_ref().is_some_and(|t| t.fresh);
    // Why the headline cannot say more, in the program's own words, set beside the name.
    let mut why: Vec<String> = not_computed.iter().map(|n| esc(&n.reason)).collect();
    let (glyph, headline) = match total {
        // Colour marks only what needs the person now: the glyph is red only for urgent ones.
        Some(n) if n > 0 && urgent > 0 => (GLYPH_NOW, esc(&needs_you(urgent, n))),
        Some(n) if n > 0 => (GLYPH_LOOK, esc(&needs_you(urgent, n))),
        _ if m.state == "not_checked" && m.checked_at.is_none() => {
            (GLYPH_UNKNOWN, "Nothing has been checked yet.".to_string())
        }
        None => {
            if why.is_empty() {
                why.push("what needs a look is not known yet".to_string());
            }
            (GLYPH_UNKNOWN, "I can't tell".to_string())
        }
        Some(_) if !fresh => {
            if let Some(reason) = r.this_mac.as_ref().and_then(|t| t.stale_reason.as_deref()) {
                why.push(esc(reason));
            }
            (
                GLYPH_STALE,
                match m.checked_at {
                    Some(t) => format!("Not checked since {}", view::when(t, now)),
                    None => "No full check has finished".to_string(),
                },
            )
        }
        Some(_) => match m.state {
            "watched" => (GLYPH_CALM, "Nothing needs you".to_string()),
            "watched_in_part" => (GLYPH_PART, "Nothing needs you".to_string()),
            _ => {
                why.push("whether this Mac is watched is not known".to_string());
                (GLYPH_UNKNOWN, "I can't tell".to_string())
            }
        },
    };
    let mut parts: Vec<String> = Vec::new();
    // Its name now, which can differ from the one in its id.
    if let Some((_, name)) = crate::store::held_mac(conn)? {
        parts.push(format!("<span class=\"name\">{}</span>", esc(&name)));
    } else if let Some(id) = covered::this_machine(conn)? {
        parts.push(format!(
            "<span class=\"name\">{}</span>",
            esc(id.strip_prefix("machine:").unwrap_or(&id))
        ));
    }
    parts.extend(why);
    let how = match (m.state, m.live) {
        ("not_checked", _) => None,
        (_, false) if !m.failed.is_empty() => Some(format!(
            "hourly only: the watcher's latest {} failed",
            covered::watcher_failed(m)
        )),
        ("watched_in_part", true) => Some("watched in part · live".to_string()),
        ("watched_in_part", false) => Some("watched in part · hourly only".to_string()),
        (_, true) => Some("watched live".to_string()),
        (_, false) => Some("hourly only".to_string()),
    };
    parts.extend(how);
    parts.push(match m.checked_at {
        Some(t) => format!("last check {}", view::when(t, now)),
        None => "no full check yet".to_string(),
    });
    parts.push(format!("page made {}", view::when(now, now)));
    if r.running {
        parts.push("a check was running".to_string());
    }
    writeln!(
        out,
        "<section id=\"this-mac\">\n{glyph}\n<div>\n<h1>{headline}</h1>\n<p class=\"sub\">{}</p>\n</div>\n</section>",
        parts.join(" · ")
    )?;
    Ok(())
}

/// One row of the table of findings: one thing. Its finding, whether that is open, and the
/// response layer's own finding about the same thing with whether that is open: the two are one
/// row, and the opened row shows both, each with its own answer.
struct FindingRow<'a> {
    item: &'a findings::Item,
    open: bool,
    under: Vec<(&'a findings::Item, bool)>,
}

impl FindingRow<'_> {
    /// The row is in Open while any finding in it is open, and in Answered while any is
    /// answered: a verdict never takes a finding out of Open.
    fn open(&self) -> bool {
        self.open || self.under.iter().any(|(_, open)| *open)
    }

    fn answered(&self) -> bool {
        !self.open || self.under.iter().any(|(_, open)| !*open)
    }

    /// It needs the person now: an open finding in it, the core's or the response layer's,
    /// is one Immune marks urgent.
    fn urgent(&self) -> bool {
        (self.open && findings::urgent(self.item.severity, self.item.confidence))
            || self
                .under
                .iter()
                .any(|(c, open)| *open && findings::urgent(c.severity, c.confidence))
    }
}

/// The rows, open first in the order of `findings::order`, then the answered, the latest answer
/// first. A finding of `verdict.suspicious` about a rule and a thing is shown in the row of that
/// rule's finding about that thing, once, and is not a row of its own; every finding is in
/// exactly one row.
fn finding_rows<'a>(
    open: &'a [findings::Item],
    answered: &'a [findings::Item],
) -> Vec<FindingRow<'a>> {
    let all: Vec<(&findings::Item, bool)> = open
        .iter()
        .map(|i| (i, true))
        .chain(answered.iter().map(|i| (i, false)))
        .collect();
    // Each finding of the response layer goes into the row of the first finding of the core it
    // is one thing with (`findings::one_thing`: the rule its verdicts were about, and the same
    // thing). One with no such partner is a row of its own. A row takes every partner, so no
    // finding is ever left out of the rows.
    let mut nested: BTreeSet<usize> = BTreeSet::new();
    let mut under: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (k, (own, _)) in all.iter().enumerate() {
        if let Some(n) = (0..all.len()).find(|n| findings::one_thing(all[*n].0, own)) {
            nested.insert(k);
            under.entry(n).or_default().push(k);
        }
    }
    all.iter()
        .enumerate()
        .filter(|(n, _)| !nested.contains(n))
        .map(|(n, (i, open))| FindingRow {
            item: i,
            open: *open,
            under: under
                .get(&n)
                .into_iter()
                .flatten()
                .map(|k| all[*k])
                .collect(),
        })
        .collect()
}

/// Every row of the table, from the state's open and answered findings.
fn rows_of(st: &crate::status::State) -> Vec<FindingRow<'_>> {
    finding_rows(&st.needs.items, st.answered.as_deref().unwrap_or_default())
}

/// What the band and the tabs count: things, as the rows show them. A finding and the response
/// layer's own finding about the same thing are one row, so one thing to the person; the store's
/// totals count them as two. `now` and `look` are the open rows in the two groups; `open`,
/// `answered` and `all` are the rows under each tab, a row with one finding open and one
/// answered under both.
#[derive(Debug, PartialEq)]
struct Shown {
    now: usize,
    look: usize,
    open: usize,
    answered: usize,
    all: usize,
}

/// The one count of what the page shows, which the band and the tabs both say.
fn shown(rows: &[FindingRow]) -> Shown {
    let now = rows.iter().filter(|r| r.urgent()).count();
    let open = rows.iter().filter(|r| r.open()).count();
    Shown {
        now,
        look: open - now,
        open,
        answered: rows.iter().filter(|r| r.answered()).count(),
        all: rows.len(),
    }
}

/// The findings as a table with three tabs, Open, Answered and All, each with its count of
/// things as the rows show them, the same count as the band's (`shown`). The tabs are links within
/// the page, and the stylesheet shows the rows of the one in the address (`:target`), Open when
/// none is; a browser that cannot select by what an element holds shows every row, so nothing
/// is hidden by a browser's age. The open rows are in two groups, as the panel has them: what
/// needs the person now, then what is to look at; then the answered. Each row opens in place to
/// its facts and who said what.
fn findings_table(
    conn: &Connection,
    out: &mut String,
    st: &crate::status::State,
    mac: Option<&findings::This>,
    now: i64,
) -> Out {
    let rows = rows_of(st);
    let counts = shown(&rows);
    let found = findings::all(conn, now)?.unwrap_or_default();
    writeln!(
        out,
        "<section id=\"findings\" class=\"findings\">\n<div class=\"wsh\"><h2>Findings</h2><nav class=\"tabs\" aria-label=\"Findings\"><a id=\"open\" href=\"#open\">Open <span class=\"tn\">{}</span></a><a id=\"answered\" href=\"#answered\">Answered <span class=\"tn\">{}</span></a><a id=\"all\" href=\"#all\">All <span class=\"tn\">{}</span></a></nav></div>",
        grouped(counts.open as i64),
        grouped(counts.answered as i64),
        grouped(counts.all as i64)
    )?;
    if counts.open == 0 {
        out.push_str("<p class=\"empty open\">Nothing is open. A change in what is watched shows here when it is found.</p>\n");
    }
    if counts.answered == 0 {
        out.push_str("<p class=\"empty answered\">Nothing is marked seen or expected now.</p>\n");
    }
    let (now_rows, rest): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rows.iter().partition(|r| r.urgent());
    let (look, done): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rest.into_iter().partition(|r| r.open());
    // The open rows drawn, the urgent first, and the answered, each cut at `ITEMS_SHOWN`.
    let open_cut = now_rows.len().min(ITEMS_SHOWN);
    let look_cut = look.len().min(ITEMS_SHOWN - open_cut);
    if !rows.is_empty() {
        out.push_str("<div class=\"fh open answered\" aria-hidden=\"true\"><span>Thing</span><span>What happened</span><span>Response layer</span><span class=\"fs\">Seen</span><span></span></div>\n");
        for (group, class, rows) in [
            // The one place on the page in the colour of what needs the person now.
            ("Needs you now", "open now", &now_rows[..open_cut]),
            ("To look at", "open", &look[..look_cut]),
            ("Answered", "answered", &done[..done.len().min(ITEMS_SHOWN)]),
        ] {
            if rows.is_empty() {
                continue;
            }
            writeln!(out, "<p class=\"fg {class}\">{group}</p>")?;
            for row in rows {
                finding_row(conn, out, &found, row, mac, now)?;
            }
        }
    }
    if counts.open > ITEMS_SHOWN {
        // Urgent ones come first, so the rest are the mildest unless urgent ones overflow.
        let urgent = now_rows.len() - open_cut;
        let which = match urgent {
            0 => "the mildest".to_string(),
            u => format!("{} of them urgent", grouped(u as i64)),
        };
        writeln!(
            out,
            "<p class=\"meta more open\">{} more, {which}; <span class=\"mono\">immune findings</span> lists them.</p>",
            grouped((counts.open - ITEMS_SHOWN) as i64)
        )?;
    }
    if done.len() > ITEMS_SHOWN {
        writeln!(
            out,
            "<p class=\"meta more answered\">{} more answered; <span class=\"mono\">immune findings --all</span> lists them.</p>",
            grouped((done.len() - ITEMS_SHOWN) as i64)
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The response layer's verdict as one word: suspicious when any of its verdicts is, harmless
/// when every one is harmless; `None` with no verdict.
fn verdict_word(i: &findings::Item) -> Option<&'static str> {
    let v = i.verdicts.as_ref()?;
    if i.rule == Some(crate::verdict::RULE) || v.suspicious > 0 {
        Some("Suspicious")
    } else if v.total > 0 {
        Some("Harmless")
    } else {
        None
    }
}

/// Where a finding's thing is, in a few words: the project for a package of one, this Mac for
/// what is on it, and another machine by its name.
fn where_of(i: &findings::Item, mac: Option<&findings::This>) -> String {
    let checkout = view::component_place(&i.about);
    if !checkout.is_empty() {
        return findings::place(checkout, mac);
    }
    let rest = ["file:", "checkout:", "container:"]
        .iter()
        .find_map(|p| i.about.strip_prefix(p))
        .unwrap_or(&i.about);
    let machine = rest.split('/').next().unwrap_or(rest);
    if !machine.starts_with("machine:") || mac.is_some_and(|m| m.id == machine) {
        "this Mac".to_string()
    } else {
        findings::place(machine, mac)
    }
}

/// The thing a finding is about, as data: the package and its releases, the program or file a
/// rule matched, else where it is. A finding whose thing no name from the Mac says, the item of
/// places read for the first time, is about what it names in the program's words.
fn thing_of(i: &findings::Item, f: Option<&v1::Finding>) -> String {
    if let Some(thing) = &i.thing {
        return thing.clone();
    }
    use v1::evidence::Body;
    let events: &[v1::Event] = match f.and_then(|f| f.evidence.as_ref()?.body.as_ref()) {
        Some(Body::VulnerablePackage(p)) => {
            if let Some(name) = &p.package_text {
                let releases: Vec<&str> =
                    p.releases.iter().map(|r| r.version_text.as_str()).collect();
                return format!("{name} {}", releases.join(", "))
                    .trim_end()
                    .to_string();
            }
            &[]
        }
        Some(Body::PublishedRuleMatched(p)) => &p.events,
        Some(Body::VerdictGiven(v)) => &v.events,
        _ => &[],
    };
    use v1::event::Body as E;
    match events.first().and_then(|e| e.body.as_ref()) {
        Some(E::ProgramStart(s)) => {
            if let Some(p) = &s.process {
                return p.executable_text.clone();
            }
        }
        Some(E::FileEvent(e)) => return e.path_text.clone(),
        None => {}
    }
    i.place.clone().unwrap_or_else(|| i.about.clone())
}

/// One row, one thing: the thing as data, its kind and what happened, the response layer's word
/// as plain text, and when it was last seen. It opens to the facts and voices of each finding in
/// it, each with the command that answers it.
fn finding_row(
    conn: &Connection,
    out: &mut String,
    found: &[findings::Found],
    row: &FindingRow,
    mac: Option<&findings::This>,
    now: i64,
) -> Out {
    let i = row.item;
    let whole = match i.rule {
        Some(_) => crate::finding_answer::of(conn, found, &i.id, now)?,
        None => None,
    };
    let id = if row.open {
        esc(&i.id)
    } else {
        format!("answered-{}", esc(&i.id))
    };
    // The kind in the words a person reads, the same as the app's (`findings::kind_title`).
    let mut kind = findings::kind_title(i.kind).to_string();
    if let Some(change) = &i.change {
        kind.push_str(" · ");
        kind.push_str(change);
    }
    let answer = i.answer.as_ref().filter(|_| !row.open).map(|a| {
        let said = match a.until {
            Some(u) => format!("expected until {}", view::when(u, now)),
            None => "seen".to_string(),
        };
        format!(
            "<span class=\"ans\">Answered: {said} {}</span>",
            esc(view::given_by(a.via))
        )
    });
    writeln!(
        out,
        "<details class=\"fr{}{}{}\" id=\"{id}\">\n<summary><span class=\"fw\">{}</span><span class=\"fk\">{}{}</span><span class=\"fv\">{}</span><span class=\"fs\">{}</span><span class=\"fch\" aria-hidden=\"true\"></span></summary>\n<div class=\"fx\">",
        if row.open() { " open" } else { "" },
        if row.answered() { " answered" } else { "" },
        if row.urgent() { " urgent" } else { "" },
        esc(&thing_of(i, whole.as_ref())),
        esc(&kind),
        answer.unwrap_or_default(),
        verdict_word(i).map_or("<span class=\"none\">—</span>".to_string(), |w| format!(
            "<span class=\"src\">Response layer: </span>{w}"
        )),
        i.last_seen.map_or(String::new(), |t| view::when(t, now)),
    )?;
    finding_body(out, i, whole.as_ref(), &where_of(i, mac), now)?;
    for (c, open) in &row.under {
        let id = if *open {
            esc(&c.id)
        } else {
            format!("answered-{}", esc(&c.id))
        };
        writeln!(
            out,
            "<div class=\"also\" id=\"{id}\">\n<p class=\"wsh2\">The response layer's own finding about it</p>"
        )?;
        let whole = crate::finding_answer::of(conn, found, &c.id, now)?;
        finding_body(out, c, whole.as_ref(), &where_of(c, mac), now)?;
        out.push_str("</div>\n");
    }
    out.push_str("</div>\n</details>\n");
    Ok(())
}

/// What one finding says in an opened row: on the left its facts, where first, then the evidence
/// as `immune finding <id>` gives it; on the right who said what, each voice named: the rule's
/// authors, the response layer, the person's answer, Immune's own words, and what to do. Under
/// them, when it was seen and the command an agent reads it with.
fn finding_body(
    out: &mut String,
    i: &findings::Item,
    whole: Option<&v1::Finding>,
    place: &str,
    now: i64,
) -> Out {
    let mut facts: Vec<(&str, String)> = vec![("Where", data(place))];
    // What the source said, as data beside the sentences.
    if let Some(value) = &i.value {
        facts.push((
            "Source said",
            format!("<span class=\"said\">{}</span>", esc(value)),
        ));
    }
    let mut voices: Vec<Voice> = Vec::new();
    if let Some(f) = whole {
        evidence(f, &mut facts, &mut voices, now);
    }
    if let Some(t) = i.technique {
        facts.push(("ATT&amp;CK", data(t)));
    }
    out.push_str("<div>");
    dl(out, &facts);
    out.push_str("</div>\n<div><p class=\"wsh2\">Who said what</p><div class=\"voices\">");
    voices.push(Voice {
        name: "Immune".to_string(),
        said: esc(i.words.title),
        detail: esc(i.words.meaning),
        quote: None,
    });
    voices.push(Voice {
        name: "What to do".to_string(),
        said: format!("<span class=\"advice\">{}</span>", esc(i.words.advice)),
        detail: String::new(),
        quote: None,
    });
    for v in &voices {
        write!(
            out,
            "<div class=\"voice\"><div class=\"vn\">{}</div><div class=\"vs\">{}</div>",
            v.name, v.said
        )?;
        if !v.detail.is_empty() {
            write!(out, "<div class=\"vd\">{}</div>", v.detail)?;
        }
        if let Some(q) = &v.quote {
            write!(
                out,
                "\n<blockquote class=\"quote\">{}</blockquote>\n",
                esc(q)
            )?;
        }
        out.push_str("</div>");
    }
    out.push_str("</div></div>\n");
    let seen = match (i.first_seen, i.last_seen) {
        (Some(f), Some(l)) if f != l => format!(
            "First seen {} · last seen {}",
            view::when(f, now),
            view::when(l, now)
        ),
        (_, Some(l)) => format!("Seen {}", view::when(l, now)),
        _ => String::new(),
    };
    let command = match i.rule {
        None => "immune status --json".to_string(),
        Some(_) => format!("immune finding {} --json", i.id),
    };
    writeln!(
        out,
        "<div class=\"fxb\"><span>{seen}</span><span>For your agent<span class=\"mono\">{}</span></span></div>",
        esc(&command)
    )?;
    Ok(())
}

/// One voice of "Who said what": who, what they said and a quieter line, all safe HTML, and a
/// quote of their own words, escaped when it is written.
struct Voice {
    name: String,
    said: String,
    detail: String,
    quote: Option<String>,
}

/// Text from the Mac as data, in an element of its own.
fn data(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", esc(s))
}

/// One event a rule matched: for a program start its program, each argument apart, its folder
/// and the program that started it; for a file event the file, what was done, from where and by
/// which program. Arguments come cut, as `immune finding` prints them (`matches::event_cut`).
fn event_facts(e: &v1::Event, now: i64) -> Vec<(&'static str, String)> {
    use v1::event::Body;
    let mut facts = Vec::new();
    match e.body.as_ref() {
        Some(Body::ProgramStart(s)) => {
            if let Some(at) = s.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            if let Some(p) = &s.process {
                facts.push(("Program", data(&p.executable_text)));
            }
            if !s.args_text.is_empty() {
                let args: Vec<String> = s
                    .args_text
                    .iter()
                    .map(|a| format!("<span class=\"arg\">{}</span>", esc(a)))
                    .collect();
                facts.push((
                    "Arguments",
                    format!("<span class=\"mono\">{}</span>", args.join(" ")),
                ));
            }
            if let Some(wd) = &s.working_directory_text {
                facts.push(("Folder", data(wd)));
            }
            if let Some(p) = &s.instigator {
                facts.push(("Started by", data(&p.executable_text)));
            }
        }
        Some(Body::FileEvent(f)) => {
            if let Some(at) = f.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            facts.push(("File", data(&f.path_text)));
            let action = match v1::FileAction::try_from(f.action) {
                Ok(v1::FileAction::Create) => "created",
                Ok(v1::FileAction::Rename) => "renamed",
                _ => "not known",
            };
            facts.push(("Done", action.to_string()));
            if let Some(from) = &f.source_text {
                facts.push(("From", data(from)));
            }
            if let Some(p) = &f.instigator {
                facts.push(("By", data(&p.executable_text)));
            }
        }
        None => {}
    }
    facts
}

/// Facts as a list of terms and values; each value is already safe.
fn dl(out: &mut String, facts: &[(&str, String)]) {
    if facts.is_empty() {
        return;
    }
    out.push_str("<dl class=\"facts\">");
    for (k, v) in facts {
        let _ = write!(out, "<dt>{k}</dt><dd>{v}</dd>");
    }
    out.push_str("</dl>\n");
}

/// A finding's evidence as `immune finding <id>` gives it, from the same message: what it rests
/// on by its kind as facts, and as voices the rule's authors, the response layer's verdicts with
/// their reasons quoted, and the person's answer with who gave it and why. Every value from the
/// Mac is escaped and set apart.
fn evidence(f: &v1::Finding, facts: &mut Vec<(&str, String)>, voices: &mut Vec<Voice>, now: i64) {
    use v1::evidence::Body;
    let word = |s: &str| format!("<span class=\"w\">{}</span>", esc(s));
    match f.evidence.as_ref().and_then(|e| e.body.as_ref()) {
        Some(Body::PlaceChanged(p)) => {
            let change = match v1::Change::try_from(p.change) {
                Ok(v1::Change::New) => "appeared",
                Ok(v1::Change::Gone) => "went",
                Ok(v1::Change::FirstRead) => "read for the first time",
                Ok(v1::Change::NotRead) => "could not be read",
                _ => "changed",
            };
            facts.push(("What happened", word(change)));
            if p.presence_only == Some(true) {
                facts.push((
                    "Watched",
                    word(&format!(
                        "only for presence: {}",
                        crate::watched::PRESENCE_ONLY
                    )),
                ));
            }
            if p.change == v1::Change::NotRead as i32 {
                let latest = f.rests_on.last().map(|b| b.run_id.as_str());
                let why = f
                    .rests_on
                    .iter()
                    .rev()
                    .take_while(|b| Some(b.run_id.as_str()) == latest)
                    .find(|b| b.entry == "not_read")
                    .and_then(|b| b.new_value_text.as_deref());
                facts.push(("Why", why.map_or(word("the store gives no reason"), data)));
            }
            for b in f.rests_on.iter().filter(|b| b.entry == "place_first_read") {
                if let Some(place) = &b.subject_text {
                    facts.push(("First read", data(place)));
                }
            }
        }
        Some(Body::ChangedInPlace(p)) => {
            match &p.became_text {
                Some(value) => facts.push(("It became", data(value))),
                None => {
                    if let Some(b) = f.rests_on.iter().rev().find(|b| {
                        b.entry == "changed" && b.predicate.as_deref() == Some("has_digest")
                    }) {
                        facts.push((
                            "Digest before",
                            data(b.old_value_text.as_deref().unwrap_or("not known")),
                        ));
                        facts.push((
                            "Digest after",
                            data(b.new_value_text.as_deref().unwrap_or("not known")),
                        ));
                    }
                }
            }
        }
        Some(Body::IndicatorMatched(p)) => {
            if let Some(value) = &p.indicators_text {
                facts.push(("Matched", data(value)));
            }
        }
        Some(Body::DetachedProcess(p)) => {
            if let Some(pid) = p.pid {
                facts.push(("Process id", data(&pid.to_string())));
            }
            if let Some(start) = p.start_micros {
                facts.push(("Started", view::when(start.div_euclid(1_000_000), now)));
            }
        }
        Some(Body::VulnerablePackage(p)) => {
            if let Some(name) = &p.package_text {
                facts.push(("Package", data(name)));
            }
            for r in &p.releases {
                facts.push(("Version", data(&r.version_text)));
                facts.push(("Declared at", data(&r.at_text)));
            }
            for r in &p.records {
                facts.push(("Record", data(&r.id_text)));
                if !r.fixed_text.is_empty() {
                    facts.push(("Fixed in", data(&r.fixed_text.join(", "))));
                }
                voices.push(Voice {
                    name: esc(&r.source),
                    said: r.summary_text.as_deref().map_or(String::new(), data),
                    detail: String::new(),
                    quote: None,
                });
            }
        }
        Some(Body::PublishedRuleMatched(p)) => {
            let rule = p.rule.clone().unwrap_or_default();
            if let Some(n) = p.matches {
                facts.push(("Matched", word(&counted(n as i64, "time", "times"))));
            }
            for e in &p.events {
                facts.extend(event_facts(e, now));
            }
            voices.push(Voice {
                name: format!("Published rule · {}", esc(&rule.set)),
                said: format!("<span class=\"src\">{}</span>", esc(&rule.title_text)),
                detail: if rule.level == v1::Level::NotStated as i32 {
                    String::new()
                } else {
                    format!(
                        "its authors rate it {}",
                        esc(&crate::text::word::<v1::Level>(rule.level))
                    )
                },
                quote: None,
            });
        }
        Some(Body::VerdictGiven(v)) => {
            facts.push(("About the rule", data(&v.rule)));
            for e in &v.events {
                facts.extend(event_facts(e, now));
            }
        }
        None => {}
    }
    if let Some(v) = &f.verdicts {
        for listed in &v.listed {
            let verdict = listed.verdict.clone().unwrap_or_default();
            let mut said = capital(&crate::text::word::<v1::VerdictKind>(verdict.kind));
            if let Some(c) = verdict.confidence {
                let _ = write!(said, ", how sure: {}", crate::text::word::<v1::Level>(c));
            }
            voices.push(Voice {
                name: "Response layer".to_string(),
                said: esc(&said),
                detail: view::when(listed.recorded_at, now),
                quote: Some(verdict.reason_text.clone()),
            });
        }
    }
    if let Some(a) = &f.answer {
        let said = match a.until_at {
            Some(u) => format!("Expected until {}", view::when(u, now)),
            None => "Seen".to_string(),
        };
        let via = match v1::Via::try_from(a.via) {
            Ok(v1::Via::App) => findings::Via::App,
            Ok(v1::Via::Agent) => findings::Via::Agent,
            Ok(v1::Via::Command) => findings::Via::Command,
            _ => findings::Via::Unknown,
        };
        voices.push(Voice {
            name: match via {
                findings::Via::Agent => "Your agent".to_string(),
                _ => "Your answer".to_string(),
            },
            said,
            detail: format!(
                "answered {} {}",
                view::when(a.given_at, now),
                esc(view::given_by(via))
            ),
            quote: a.reason_text.clone(),
        });
    }
}

/// How a row of what is watched stands: whether it was read, as a filled or a hollow dot of
/// `--quiet`, and its words, which are safe HTML. Only coverage: findings are not repeated here.
struct Standing {
    read: bool,
    said: String,
}

impl Standing {
    fn read(said: &str) -> Standing {
        Standing {
            read: true,
            said: esc(said),
        }
    }

    fn not(said: String) -> Standing {
        Standing { read: false, said }
    }
}

/// One row of what is watched: the kind of place, how often it is looked at, how many things,
/// its state and when it was last read. The count leads, where `href` is given, to the things.
fn watched_row(
    out: &mut String,
    id: Option<&str>,
    (kind, how): (&str, &str),
    (things, href): (&str, Option<&str>),
    states: &[Standing],
    last: Option<i64>,
    now: i64,
) -> Out {
    let id = id.map_or(String::new(), |id| format!(" id=\"{id}\""));
    let said: Vec<String> = states
        .iter()
        .map(|s| {
            format!(
                "<span class=\"dot{}\"></span>{}",
                if s.read { "" } else { " off" },
                s.said
            )
        })
        .collect();
    writeln!(
        out,
        "<div class=\"wr\"{id}><span>{}</span><span class=\"wh2 t2\">{}</span><span class=\"wn\">{}</span><span class=\"wc\">{}</span><span class=\"wl\">{}</span></div>",
        esc(kind),
        esc(how),
        match href {
            Some(href) => format!(
                "<a href=\"{href}\" aria-label=\"{}: {}\">{}</a>",
                esc(kind),
                esc(things),
                esc(things)
            ),
            None => esc(things),
        },
        said.join(" · "),
        last.map_or("<span class=\"none\">—</span>".to_string(), |t| {
            view::when(t, now)
        })
    )?;
    Ok(())
}

/// Whether any record that affects a project is one attackers are using, counted from the same
/// tables the findings are raised from.
fn any_used(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(crate::vulnerabilities::affecting(conn)?
        .iter()
        .any(|a| a.exploited))
}

/// The latest reading time among some readings.
fn last_read(readings: &[&Latest]) -> Option<i64> {
    readings.iter().map(|r| r.at).max()
}

/// What is watched, as a table by kind of place, grouped as on this Mac, in your projects and
/// beyond this Mac: how often each is looked at, how many things, whether it was read and when,
/// from the latest readings in the store, as the page of coverage shows them. "None here" and
/// "read in full" are said only where every reading that fills the row is full and fresh. Then
/// one line: how many things on this Mac were not judged, as a link to the page that names each.
#[allow(clippy::too_many_arguments)]
fn watched_table(
    conn: &Connection,
    out: &mut String,
    st: &crate::status::State,
    map: &crate::map::Map,
    latest: &[Latest],
    fixable: &[&Uncovered],
    unjudged: usize,
    now: i64,
) -> Out {
    let m = &st.this_mac;
    let this = covered::this_machine(conn)?;
    let mac = findings::This::of(conn, this.clone())?;
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let fix_link = "<a href=\"#you-can-fix\">you can fix</a>";
    // An example is the place's name alone (`covered::Example`), so it is matched whole.
    let can_fix = |place: &str| {
        fixable
            .iter()
            .any(|u| u.examples.iter().any(|e| e.name == place))
    };
    writeln!(
        out,
        "<section id=\"watched-here\">\n<div class=\"wsh\"><h2>What is watched</h2><span class=\"n\">on this Mac, in your projects and beyond</span></div>\n<div class=\"wt\">\n<div class=\"wr wh\" aria-hidden=\"true\"><span>Kind of place</span><span>How often</span><span class=\"wn\">Things</span><span>State</span><span class=\"wl\">Last read</span></div>"
    )?;
    let mut on_mac = String::new();
    let mut in_projects = String::new();
    for (count, what, fast) in covered::watched() {
        let how = if m.live && fast {
            "within seconds"
        } else {
            "every hour"
        };
        let readings = readings_of(count, latest);
        let n = m.watched.iter().find(|w| w.0 == what).map(|w| w.1);
        let mut walk = walk_gap(count, latest, this.as_deref());
        if let Count::Dependencies = count {
            // Known vulnerabilities rest on the data too: a feed not current leaves the
            // answer short, as on the page of known vulnerabilities (`vulnerability_gap`).
            walk.extend(old_feeds(conn, now)?);
        }
        let gap = unread(&readings, latest_run, now, &walk);
        let mut states: Vec<Standing> = Vec::new();
        if let Count::Files(as_) = count {
            let failed: Vec<String> = conn
                .prepare(
                    "SELECT DISTINCT subject FROM assertion
                     WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'
                       AND object = ?2 ORDER BY subject",
                )?
                .query_map(params![watched::READER, as_], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?
                .into_iter()
                .filter(|f| {
                    latest
                        .iter()
                        .any(|r| r.scope == *f && r.completeness != "full")
                })
                .map(|f| findings::place(&f, mac.as_ref()))
                .collect();
            if !failed.is_empty() {
                let mut said = format!("{} can't be read", grouped(failed.len() as i64));
                if failed.iter().any(|f| can_fix(f)) {
                    let _ = write!(said, " · {fix_link}");
                }
                states.push(Standing::not(said));
            }
        }
        let mut things = n.map_or("—".to_string(), grouped);
        if let Count::Dependencies = count {
            if let Some(n) = n {
                things = grouped(n);
            }
            let t = crate::vulnerabilities::totals(conn, now)?;
            let open = map.projects_open();
            if !t.matched {
                states.push(Standing::not("not compared yet".to_string()));
            } else if open > 0 {
                states.push(Standing::not(esc(&format!(
                    "{} not compared",
                    counted(open as i64, "project", "projects")
                ))));
            } else if gap.is_none() {
                states.push(Standing::read("compared at every check"));
            }
            if t.matched {
                let known: usize = t
                    .records_by_label
                    .iter()
                    .filter(|(label, _)| *label != "malicious")
                    .map(|(_, n)| n)
                    .sum();
                if known > 0 {
                    states.push(Standing {
                        read: true,
                        said: format!(
                            "<a href=\"{DETAILS}/{VULNERABILITIES}.html\">{}</a>",
                            esc(&counted(
                                known as i64,
                                "known vulnerability",
                                "known vulnerabilities"
                            ))
                        ),
                    });
                    // "None used in attacks" rests on the list of them having been read; one
                    // that is used is a finding, in the table of findings.
                    if !any_used(conn)? {
                        states.push(match exploited_gap(conn, now)? {
                            Some(gap) => Standing::not(format!(
                                "<span title=\"{}\">whether any is used in attacks is not known</span>",
                                esc(&gap)
                            )),
                            None => Standing::read("none is known to be used in attacks"),
                        });
                    }
                }
            }
        }
        if let Some(gap) = &gap {
            if readings.is_empty() && walk.is_empty() && n.is_none() && states.is_empty() {
                states.push(Standing::not("not checked yet".to_string()));
            } else {
                states.push(Standing::not(format!(
                    "<span title=\"{}\">not read in full</span>",
                    esc(gap)
                )));
            }
        }
        if states.is_empty() {
            states.push(Standing::read(if n.unwrap_or(0) == 0 {
                "none here"
            } else {
                "read in full"
            }));
        }
        let id = matches!(count, Count::Dependencies).then_some("vulnerabilities");
        let href = format!("{DETAILS}/{THIS_MAC}.html#{}", anchor(what));
        let group = if covered::in_projects(count) || matches!(count, Count::Dependencies) {
            &mut in_projects
        } else {
            &mut on_mac
        };
        watched_row(
            group,
            id,
            (&capital(what), how),
            (&things, n.is_some().then_some(href.as_str())),
            &states,
            last_read(&readings),
            now,
        )?;
    }
    for (group, rows) in [("On this Mac", &on_mac), ("In your projects", &in_projects)] {
        if !rows.is_empty() {
            writeln!(out, "<p class=\"wg\">{group}</p>\n{rows}")?;
        }
    }
    // Servers, checked only when the person runs the server check. A person with no servers is
    // not told about servers at all. "Checked" rests on every server's latest visit having read
    // it in full, whatever findings rest on it; a server not read in full is one that could not
    // be opened or one the check did not finish on (`servers-not-checked`), counted apart.
    let not_checked = map.servers.len() - map.servers_checked;
    let unopened: usize = fixable
        .iter()
        .filter(|u| u.cause.id == covered::SERVERS_NOT_OPENED.id)
        .map(|u| u.count)
        .sum();
    if !map.servers.is_empty() || map.on_servers > 0 {
        let mut states = Vec::new();
        if unopened > 0 {
            states.push(Standing::not(format!(
                "{} could not be opened · {fix_link}",
                grouped(unopened as i64)
            )));
        }
        if not_checked > unopened {
            states.push(Standing::not(esc(&format!(
                "{} not checked",
                grouped((not_checked - unopened) as i64)
            ))));
        }
        if states.is_empty() {
            states.push(Standing::read("checked at the last server check"));
        }
        let visits: Vec<&Latest> = latest
            .iter()
            .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
            .collect();
        out.push_str("<p class=\"wg\">Beyond this Mac</p>\n");
        let listed = format!("{DETAILS}/{BEYOND}.html#servers");
        watched_row(
            out,
            None,
            (
                "Servers you log in to over SSH",
                "when you run the server check",
            ),
            (&grouped(map.servers.len() as i64), Some(listed.as_str())),
            &states,
            last_read(&visits),
            now,
        )?;
    }
    out.push_str("</div>\n");
    if unjudged > 0 {
        let said = if unjudged == 1 {
            "1 thing on this Mac was not judged".to_string()
        } else {
            format!(
                "{} things on this Mac were not judged",
                grouped(unjudged as i64)
            )
        };
        writeln!(
            out,
            "<p class=\"nj\" id=\"limits\"><a href=\"{DETAILS}/{THIS_MAC}.html#{NOT_JUDGED}\">{said}</a></p>"
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The anchor of what was not judged on this Mac, on the page of what is watched.
pub const NOT_JUDGED: &str = "not-judged";

/// What the person can fix, one cause beside another: what it is, every example as data, and
/// Immune's advice.
fn you_can_fix(out: &mut String, fixable: &[&Uncovered]) -> Out {
    writeln!(
        out,
        "<section id=\"you-can-fix\">\n<div class=\"wsh\"><h2>You can fix</h2><span class=\"n\">{}</span></div>",
        esc(&counted(fixable.len() as i64, "thing", "things"))
    )?;
    if fixable.is_empty() {
        out.push_str("<p class=\"empty\">Nothing for you to fix.</p>\n");
    } else {
        out.push_str("<div class=\"fixg\">\n");
        for u in fixable {
            writeln!(
                out,
                "<article class=\"fixc\" id=\"{}\">\n<p class=\"fct\">{}</p>",
                esc(u.cause.id),
                esc(&u.title())
            )?;
            let apart = u.apart();
            if !apart.is_empty() {
                out.push_str("<ul>\n");
                for (name, reason) in &apart {
                    writeln!(out, "<li>{}</li>", example(name, *reason))?;
                }
                out.push_str("</ul>\n");
            }
            writeln!(
                out,
                "<p class=\"fad\">{}</p>\n<p class=\"fad\">{}</p>\n</article>",
                esc(&u.meaning()),
                esc(u.cause.advice)
            )?;
        }
        out.push_str("</div>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The links to the other pages, and when the page was made and on which Mac.
fn links(out: &mut String, name: Option<&str>, now: i64) -> Out {
    writeln!(
        out,
        "<footer class=\"links\">\n<a href=\"{DETAILS}/{RULES}.html\">{RULES_TITLE}</a>\n<a href=\"{DETAILS}/{TECHNICAL}.html\">Technical details</a>\n</footer>\n<p class=\"wfoot\">Page made at {} by immune view{}</p>",
        view::when(now, now),
        name.map_or(String::new(), |n| format!(
            " on <span class=\"mono\">{}</span>",
            esc(n)
        ))
    )?;
    Ok(())
}

/// A kind of thing that is listed as watched and that no rule speaks about.
const KEPT_AS_LIST: &str = "Kept as a list. Nothing tells you about a change here in this version.";
/// The mark of a rule whose findings notify at once.
const NOTIFIES: &str = "Sends a notification";
/// The rule about a match of a list of indicators, which is about no one kind.
const INDICATOR_RULE: &str = "indicator.match";
/// The rule about places read for the first time, which is about every watched kind.
const FIRST_READ_RULE: &str = "watched.first-read";

/// What the owner is told about: each rule's title and what it means, marked where its
/// findings notify at once; for no rule, that the thing is only kept as a list. The page of
/// what is watched says it under each kind.
fn told(out: &mut String, rules: &[findings::Rule]) -> Out {
    if rules.is_empty() {
        writeln!(out, "<p class=\"muted\">{}</p>", esc(KEPT_AS_LIST))?;
        return Ok(());
    }
    out.push_str("<ul class=\"rules\">\n");
    for r in rules {
        let mark = if findings::urgent(r.severity, Some(r.confidence)) {
            format!(" <span class=\"badge notify\">{NOTIFIES}</span>")
        } else {
            String::new()
        };
        writeln!(
            out,
            "<li>{}{mark}<br><span class=\"muted\">{}</span></li>",
            esc(r.words.title),
            esc(r.words.meaning)
        )?;
    }
    out.push_str("</ul>\n");
    Ok(())
}

/// The rules with one id, as `told` takes them.
fn rule_with(id: &str) -> Vec<findings::Rule> {
    findings::rules()
        .into_iter()
        .filter(|r| r.id == id)
        .collect()
}

/// Whether a list of indicators was read at the last full check: `Some(true)` read in full,
/// `Some(false)` given and not read, `None` not given.
fn indicator_list(conn: &Connection) -> rusqlite::Result<Option<bool>> {
    let Some(run) = crate::status::latest_finished(conn)? else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT MAX(completeness = 'full') FROM coverage
         WHERE run_id = ?1 AND reader = ?2 AND kind = ?3",
        params![
            run.id,
            crate::indicators::READER,
            crate::indicators::LIST_KIND
        ],
        |r| r.get::<_, Option<bool>>(0),
    )
}

/// On the page of what is watched, after the kinds: the rules about no one kind, so that every
/// rule the owner can be told by is named on that page.
fn also(conn: &Connection, out: &mut String) -> Result<(), Box<dyn Error>> {
    out.push_str("<section id=\"also\">\n<h2>Also told</h2>\n<h3>A list of signs of a known attack, when you give one</h3>\n");
    told(out, &rule_with(INDICATOR_RULE))?;
    let said = match indicator_list(conn)? {
        Some(true) => "A list was read at the last check.",
        Some(false) => "A list was given but could not be read at the last check.",
        None => "No list has been given, so nothing is compared.",
    };
    writeln!(
        out,
        "<p class=\"muted\">{said}</p>\n<h3>Every watched place</h3>"
    )?;
    told(out, &rule_with(FIRST_READ_RULE))?;
    out.push_str("</section>\n");
    Ok(())
}

/// What the summary says first of known vulnerabilities.
const VULNERABILITIES_SAY: &str = "These are published weaknesses in packages your projects depend on. They are listed, not alarmed: most matter only under particular conditions. A package known to be malicious, or a vulnerability attackers are using, is shown at the top as something that needs a look.";
/// A label as a person reads it.
fn label_words(label: &str) -> &'static str {
    match label {
        "malicious" => "Malicious package",
        "critical" => "Critical",
        "high" => "High",
        "moderate" => "Moderate",
        "low" => "Low",
        _ => "No label",
    }
}

/// One known vulnerability as a row: package and release, project, label, fixed release,
/// record with its source. Text from the record is escaped by `td`.
fn vulnerability_row(
    out: &mut String,
    a: &crate::vulnerabilities::Affecting,
    project: bool,
    this: Option<&findings::This>,
) -> Out {
    let releases: Vec<String> = a.affected().into_iter().map(|(v, _)| v).collect();
    out.push_str("<tr>");
    view::td(
        out,
        "mono",
        &format!("{} {}", a.package, releases.join(", ")),
    )?;
    if project {
        view::td(out, "mono", &findings::place(&a.checkout, this))?;
    }
    view::td(out, "", label_words(a.label))?;
    view::td(out, "mono", &a.fixed.join(", "))?;
    view::td(
        out,
        "mono",
        &format!(
            "{} ({})",
            a.advisory,
            crate::vulnerabilities::source_name(&a.advisory)
        ),
    )?;
    out.push_str("</tr>\n");
    Ok(())
}

/// Every known vulnerability in packages the projects use, grouped by project.
pub fn vulnerabilities(conn: &Connection, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = top(
        "Known vulnerabilities in packages your projects use",
        &format!("This page made {}", utc(now)),
    );
    writeln!(
        out,
        "<section id=\"by-project\">\n<h2>Known vulnerabilities by project</h2>\n<p class=\"muted\">{}</p>\n<p class=\"muted\">{}</p>",
        esc(VULNERABILITIES_SAY),
        esc(crate::vulnerabilities::DECLARED)
    )?;
    let this = findings::This::of(conn, covered::this_machine(conn)?)?;
    let list = crate::vulnerabilities::affecting(conn)?;
    let gap = vulnerability_gap(conn, now)?;
    coverage_of_list(&mut out, gap.as_deref(), list.is_empty(), "None is known.");
    let mut projects: BTreeMap<&str, Vec<&crate::vulnerabilities::Affecting>> = BTreeMap::new();
    for a in &list {
        projects.entry(a.checkout.as_str()).or_default().push(a);
    }
    for (checkout, of) in projects {
        writeln!(
            out,
            "<h3 class=\"mono\">{}</h3>\n<div class=\"scroll\"><table class=\"dense\">",
            esc(&findings::place(checkout, this.as_ref()))
        )?;
        view::thead(&mut out, &["Package", "Label", "Fixed in", "Record"]);
        for a in of {
            vulnerability_row(&mut out, a, false, this.as_ref())?;
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
}

/// One example of a thing not covered, as safe HTML: its name, and beside it what its source said
/// of it. What a source said is prose from it: cut, as every such text is where it is printed,
/// and escaped apart from the name.
fn example(name: &str, reason: Option<&str>) -> String {
    match reason {
        Some(r) => format!(
            "{}: {}",
            esc(name),
            esc(&crate::secrets::text(r, view::shown))
        ),
        None => esc(name),
    }
}

/// One thing not covered, in full: its title, where, what it means and what to do.
fn uncovered(out: &mut String, u: &Uncovered) -> Out {
    writeln!(
        out,
        "<article class=\"item\" id=\"{}\">\n<h3>{}</h3>",
        esc(u.cause.id),
        esc(&u.title())
    )?;
    let apart = u.apart();
    if !apart.is_empty() {
        out.push_str("<ul class=\"readings mono\">\n");
        for (name, reason) in apart.iter().take(EXAMPLES_SHOWN) {
            writeln!(out, "<li>{}</li>", example(name, *reason))?;
        }
        if apart.len() > EXAMPLES_SHOWN {
            writeln!(
                out,
                "<li class=\"muted\">and {} more</li>",
                apart.len() - EXAMPLES_SHOWN
            )?;
        }
        out.push_str("</ul>\n");
    }
    writeln!(
        out,
        "<p>{}</p>\n<p class=\"advice\">{}</p>\n</article>",
        esc(&u.meaning()),
        esc(u.cause.advice)
    )?;
    Ok(())
}

/// The projects on this Mac, as they are shown, with how many dependencies are known of each.
fn projects(conn: &Connection, this: Option<&str>) -> rusqlite::Result<Vec<(String, i64)>> {
    let Some(this) = this else {
        return Ok(Vec::new());
    };
    let mac = findings::This::of(conn, Some(this.to_string()))?;
    // The dependencies are counted in one pass over them, not once per project: no index
    // leads from a project to what is part of it.
    let list: Vec<(String, i64)> = conn
        .prepare(
            "SELECT a.subject, COALESCE(p.n, 0)
             FROM assertion a
             LEFT JOIN (SELECT object, COUNT(DISTINCT subject) AS n FROM assertion
                        WHERE layer = 'live' AND predicate = 'part_of' GROUP BY object) p
               ON p.object = a.subject
             WHERE a.layer = 'live' AND a.predicate = 'located_on' AND a.object = ?1
               AND a.subject LIKE 'checkout:%'
             GROUP BY a.subject ORDER BY a.subject",
        )?
        .query_map([this], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(list
        .into_iter()
        .map(|(id, n)| (findings::place(&id, mac.as_ref()), n))
        .collect())
}

/// Every source of threat data the summary's tile counts, from the same result the tile is
/// built from: first the scale, the short list of vulnerabilities used in attacks beside every
/// record of known vulnerabilities held; then the list, then each set of records, one section
/// each, saying what it is, how much it holds, when it was read and whether that is current,
/// and what it is compared with here. A source never read or not current says so, and nothing
/// says it was compared.
pub fn threat_data(conn: &Connection, r: &v1::Status, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = top(THREAT_DATA_TITLE, &format!("This page made {}", utc(now)));
    let fresh = r
        .vulnerabilities
        .as_ref()
        .map(|v| v.feeds.clone())
        .unwrap_or_default();
    let held = |source: &str| -> v1::FeedState {
        r.vulnerability_data
            .as_ref()
            .and_then(|d| d.feeds.iter().find(|f| f.source == source).cloned())
            .unwrap_or_default()
    };
    let entries = r.threats.as_ref().and_then(|t| t.entries);
    // The scale: only counts the program has, and none where a source was never read.
    let read: Vec<(&str, i64)> = fresh
        .iter()
        .filter(|f| f.read_at.is_some())
        .map(|f| {
            let records = held(&f.source).records.unwrap_or_default();
            (f.ecosystem.as_str(), records as i64)
        })
        .collect();
    // A count, big, and what it counts beside it.
    let figure = |n: i64, one: &str, many: &str| {
        format!(
            "<p><span class=\"num\">{}</span> <span>{}</span></p>\n",
            grouped(n),
            esc(if n == 1 { one } else { many })
        )
    };
    out.push_str("<div class=\"scale\">\n");
    match entries {
        Some(n) => out.push_str(&figure(
            n as i64,
            "vulnerability known to be used in real attacks",
            "vulnerabilities known to be used in real attacks",
        )),
        None => out.push_str("<p class=\"quiet\">The list of vulnerabilities used in real attacks has not been read.</p>\n"),
    }
    if read.is_empty() {
        out.push_str("<p class=\"quiet\">No record of known vulnerabilities has been read.</p>\n");
    } else {
        let names: Vec<&str> = read.iter().map(|(e, _)| *e).collect();
        let of = format!(
            "of known vulnerabilities and malicious packages, for {} packages",
            covered::listed(&names)
        );
        out.push_str(&figure(
            read.iter().map(|(_, n)| n).sum(),
            &format!("record {of}"),
            &format!("records {of}"),
        ));
    }
    out.push_str("</div>\n");
    // The two side by side are explained only where both are counts.
    if entries.is_some() && !read.is_empty() {
        out.push_str("<p class=\"muted\">The first is the short list of what attackers are known to use. The second is every record the program holds from OSV, the open database of published vulnerabilities, for the packages named; most of them are never used in an attack.</p>\n");
    }

    crate::view::catalogue(conn, &mut out, now)?;

    let compared = crate::vulnerabilities::catalogue_compared(conn)?;
    for f in &fresh {
        let source = f.source.as_str();
        let eco = f.ecosystem.as_str();
        let h = held(source);
        let asked = crate::osv::FEEDS
            .iter()
            .find(|feed| feed.source == source)
            .map_or("", |feed| feed.asked);
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>Known vulnerabilities in {} packages</h2>\n<p>Records from OSV, the open database of published vulnerabilities, for {} packages, including packages known to be malicious. It is read {}.</p>",
            anchor(source),
            esc(eco),
            esc(eco),
            esc(asked)
        )?;
        let at = f.read_at;
        // Counts exist only for a feed read whole.
        if let (Some(at), Some(records)) = (at, h.records) {
            writeln!(
                out,
                "<p class=\"facts\"><strong>{}</strong> {}, {} among them · last read {}{}</p>",
                grouped(records as i64),
                if records == 1 { "record" } else { "records" },
                counted(
                    h.malicious_records.unwrap_or_default() as i64,
                    "malicious package",
                    "malicious packages"
                ),
                esc(&utc(at)),
                if f.current { " · current" } else { "" }
            )?;
        }
        let said = match (at, f.current) {
            (None, _) => format!(
                "<p class=\"quiet\">Never read, so none of your {} packages is compared with it.</p>",
                esc(eco)
            ),
            (Some(_), false) => format!(
                "<p class=\"quiet\">Not current: {}. Until it is read again, a {} package it says nothing about is not known to be clear.</p>",
                esc(f.not_current_why.as_deref().unwrap_or("no reason given")),
                esc(eco)
            ),
            (Some(_), true) if compared.contains(&eco) => format!(
                "<p>Compared at the last check with the {} packages in your projects' lockfiles.</p>",
                esc(eco)
            ),
            (Some(_), true) => format!(
                "<p class=\"quiet\">No {} packages from your projects' lockfiles were compared with it at the last check.</p>",
                esc(eco)
            ),
        };
        writeln!(out, "{said}\n</section>")?;
    }
    out.push_str(FOOT);
    Ok(out)
}

/// The three places of a rule, as the rules page names them: its anchor there, its heading,
/// and what being there means.
const PLACED: [(&str, &str, &str); 3] = [
    (
        "evaluated",
        "Can be checked in full",
        "Everything these rules look for is in what the event level gives: for a program start, the program, its command line and the program that started it; for a file created or renamed, its path and the program that did it.",
    ),
    (
        "in-part",
        "Can be checked in part",
        "Some alternatives in these rules need something an event does not give. Those never match here; the rest of each rule can.",
    ),
    (
        "not-evaluated",
        "Cannot be checked in this version",
        "These need events or details this version does not collect. They are listed so that none is counted without being checked.",
    ),
];

/// Every published rule this build ships, for a person: by place, then by level, the most
/// severe first. Each with its title, its level, what it looks for in its author's words, its
/// ATT&CK techniques and its authors, and, where it is not checked in full, what is missing.
/// Everything from a rule file is the rule's own text, each in an element of its own. The
/// counts at the top are the status's; how many times each rule matched in the last day is
/// the event level's, `events`.
pub fn rules(r: &v1::RulesNow, events: Option<&crate::events::Level>, now: i64) -> String {
    rules_page(crate::sigma::Rules::shipped(), r, events, now)
}

/// The rules page for these rules.
fn rules_page(
    shipped: &crate::sigma::Rules,
    r: &v1::RulesNow,
    events: Option<&crate::events::Level>,
    now: i64,
) -> String {
    use crate::sigma::{self, Placement, Reason};
    let from: Vec<String> = shipped
        .sources()
        .iter()
        .map(|s| match s.commit_date {
            Some(date) => format!("{}, as published on {date}", s.set),
            None => format!("{}, at commit {}", s.set, &s.commit[..12]),
        })
        .collect();
    let mut out = top(
        RULES_TITLE,
        &format!("From {} · this page made {}", from.join("; "), utc(now)),
    );
    let mut w = |s: String| out.push_str(&s);
    w(format!(
        "<p>{}</p>\n<div class=\"scale\">\n",
        esc(&crate::text::rules_said(&shipped.sources_said(), r))
    ));
    for ((anchor, title, _), n) in PLACED.iter().zip([r.evaluated, r.in_part, r.not_evaluated]) {
        w(format!(
            "<p><span class=\"num\">{n}</span> <a href=\"#{anchor}\">{}</a></p>\n",
            esc(title)
        ));
    }
    w("</div>\n".to_string());
    let (evaluated, in_part, not_evaluated) = shipped.groups();
    let source = |s: &str| format!("<span class=\"src\">{}</span>", esc(s));
    let mono = |list: &[String]| {
        list.iter()
            .map(|s| format!("<span class=\"mono\">{}</span>", esc(s)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for ((anchor, title, means), group) in PLACED.iter().zip([evaluated, in_part, not_evaluated]) {
        w(format!(
            "<section id=\"{anchor}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>\n",
            esc(title),
            esc(means)
        ));
        if group.is_empty() {
            w("<p class=\"muted\">None.</p>\n".to_string());
        }
        let mut level: Option<&str> = None;
        for l in group {
            let (this, said) = match &l.meta {
                None => ("unknown", "unknown"),
                Some(m) => (m.level_name().unwrap_or("none"), sigma::level_said(m.level)),
            };
            // A heading for each level, from the most severe down; the rules of a set that states
            // no level come last under their own, as a group and not as a level.
            if level != Some(this) {
                let heading = if l.states_no_level() {
                    sigma::NO_LEVEL_GROUP
                } else {
                    said
                };
                w(format!("<h3>{}</h3>\n", esc(&capital(heading))));
                level = Some(this);
            }
            let label = l
                .meta
                .as_ref()
                .map_or_else(|| sigma::label(l.file, l.source), sigma::Meta::label);
            w(format!(
                "<article class=\"rule\">\n<h4>{} <span class=\"chip lvl-{this}\">{said}</span></h4>\n",
                source(&label)
            ));
            // How many times it matched in the last day: any count there is, and while the
            // rules watch, that a rule they evaluate did not match.
            let matched = l
                .meta
                .as_ref()
                .and_then(|m| events?.matches_last_day.get(&m.id))
                .copied()
                .unwrap_or(0);
            // A rule for file events watches only while they are collected here, and a rule
            // that reads what a collector may keep only while values of it arrive; while the
            // level runs and they do not, the rule says so by name, with which.
            let file_rule = l.kind == Some(sigma::Kind::File);
            let on = r.watching == Some(true);
            let files_unwatched = file_rule && r.file_events_collected != Some(true);
            let not_arriving = events
                .filter(|e| on && !files_unwatched && l.silenced_by(e.not_arriving()))
                .map(|e| e.arrivals.worst(l.needs & e.not_arriving()));
            let unwatched = files_unwatched || not_arriving.is_some();
            if matched > 0 {
                w(format!(
                    "<p class=\"meta\">Matched {} in the last day.</p>\n",
                    sigma::times(matched)
                ));
            } else if on && !unwatched && !matches!(l.placement, Placement::NotEvaluated(_)) {
                w("<p class=\"meta\">No match in the last day.</p>\n".to_string());
            }
            if files_unwatched && on && l.placement == Placement::Evaluated {
                w("<p class=\"missing\">Not watching on this Mac: the collector installed here records program starts only. Installing the event level again adds files created and renamed.</p>\n".to_string());
            }
            match not_arriving {
                Some(crate::events::Arrival::NotKept) => w("<p class=\"missing\">Not watching on this Mac: it reads what the collector installed here does not keep. Installing the event level again adds it.</p>\n".to_string()),
                Some(crate::events::Arrival::Kept(None)) => w("<p class=\"missing\">Not watching on this Mac: it reads what the collector keeps and no line has given a value for yet.</p>\n".to_string()),
                Some(crate::events::Arrival::NoLonger(_)) => w("<p class=\"missing\">Not watching on this Mac: it reads what the collector keeps, and the latest lines give no value for it.</p>\n".to_string()),
                Some(_) => w("<p class=\"missing\">Not watching on this Mac: it reads what no line read so far would carry, so whether the collector keeps it is not yet known.</p>\n".to_string()),
                None => {}
            }
            match &l.placement {
                Placement::Evaluated => {}
                Placement::InPart(branches) => {
                    for b in branches {
                        w(match (&b.selection, &b.said) {
                            (Some(selection), _) => format!(
                                "<p class=\"missing\">Never matches here: the alternative {} needs {}, which {} does not give.</p>\n",
                                mono(std::slice::from_ref(selection)),
                                mono(&b.fields),
                                sigma::given_by(l.kind)
                            ),
                            (None, _) if !b.fields.is_empty() => format!(
                                "<p class=\"missing\">Never matches here: an alternative of the upstream rule needs {}, which {} does not give.</p>\n",
                                mono(&b.fields),
                                sigma::given_by(l.kind)
                            ),
                            (None, said) => format!(
                                "<p class=\"missing\">Never matches here: an alternative of the upstream rule was left out in translation, {}.</p>\n",
                                source(said.as_deref().unwrap_or(""))
                            ),
                        });
                    }
                }
                Placement::NotEvaluated(reason) => w(format!(
                    "<p class=\"missing\">{}</p>\n",
                    match reason {
                        Reason::NeedsEvents(c) => format!(
                            "Needs {} events, which this version does not collect.",
                            mono(std::slice::from_ref(c))
                        ),
                        Reason::NeedsFields(f) => format!(
                            "Needs {}, which {} does not give.",
                            mono(f),
                            sigma::given_by(l.kind)
                        ),
                        Reason::KeywordSearch => {
                            "Searches whole messages for words; this version has the parts of an event, not messages.".to_string()
                        }
                        Reason::NotParsed(said) => format!("Could not be read: {}", source(said)),
                        Reason::Sequence => "Correlates a sequence of events, which is not translated into Sigma.".to_string(),
                        Reason::NotEql => "Not written in EQL, the only language translated into Sigma.".to_string(),
                        Reason::BackslashInWildcard => "Has a backslash in a wildcard pattern, whose meaning in Elasticsearch is not documented, so it is not translated.".to_string(),
                        Reason::SpansKinds => "Is about program starts and file events at once, which one Sigma rule cannot be.".to_string(),
                        Reason::NeverTrue | Reason::Regex | Reason::Unsupported | Reason::Function => {
                            format!("{}.", capital(&reason.said()))
                        }
                    } + &l.detail.map_or(String::new(), |d| format!(" {}", source(d)))
                )),
            }
            let Some(m) = &l.meta else {
                w("</article>\n".to_string());
                continue;
            };
            w(format!(
                "<details>\n<summary>{}</summary>\n<ul class=\"about\">\n",
                m.description
                    .as_deref()
                    .map_or("Details".to_string(), |d| format!(
                        "<span class=\"src desc\">{}</span>",
                        esc(&d.split_whitespace().collect::<Vec<_>>().join(" "))
                    ))
            ));
            if !m.techniques.is_empty() {
                w(format!("<li>ATT&amp;CK: {}</li>\n", mono(&m.techniques)));
            }
            if let Some(a) = &m.author {
                w(format!("<li>Author: {}</li>\n", source(a)));
            }
            if l.detail.is_some() {
                w(format!(
                    "<li>Not taken from {}, upstream in <span class=\"mono\">{}</span></li>\n</ul>\n</details>\n</article>\n",
                    esc(l.source.set),
                    esc(l.file)
                ));
            } else {
                w(format!(
                    "<li>Published as {}, in <span class=\"mono\">{}</span></li>\n</ul>\n</details>\n</article>\n",
                    source(m.status.as_str()),
                    esc(l.file)
                ));
            }
        }
        w("</section>\n".to_string());
    }
    // The licences' addresses, as the sets' NOTICEs give them. Addresses are named, not linked:
    // no page of the view carries a web address to follow.
    let named = |notice: &'static str, marker: &str| {
        notice
            .split_whitespace()
            .find(|word| word.contains(marker))
            .map_or("", |word| word.trim_end_matches([',', '.']))
    };
    let licence = named(
        include_str!("../rules/sigma/NOTICE"),
        "Detection-Rule-License",
    );
    let elastic_licence = named(
        include_str!("../rules/elastic/NOTICE"),
        "licensing/elastic-license",
    );
    let behaviour_licence = named(
        include_str!("../rules/elastic-behaviour/NOTICE"),
        "licensing/elastic-license",
    );
    let bare = |url: &'static str| url.strip_prefix("https://").unwrap_or(url);
    w(format!(
        "<footer class=\"licence\">\n<p class=\"meta\">SigmaHQ's rules are copied unchanged from its rule set, <span class=\"mono\">{}</span>, at commit <span class=\"mono\">{}</span> of {}. They are licensed under the Detection Rule License 1.1, <span class=\"mono\">{}</span>, and each keeps its authors, shown with it.</p>\n<p class=\"meta\">Elastic's rules are translated mechanically into Sigma from its detection rules, <span class=\"mono\">{}</span>, at commit <span class=\"mono\">{}</span>; none is edited by hand. They carry Elastic License 2.0, <span class=\"mono\">{}</span>, and each keeps its authors, shown with it.</p>\n<p class=\"meta\">Elastic's behaviour rules are translated the same way from <span class=\"mono\">{}</span> at commit <span class=\"mono\">{}</span>, under Elastic License 2.0, <span class=\"mono\">{}</span>. They state no level and name no authors.</p>\n</footer>\n",
        esc(bare(sigma::SOURCE)),
        sigma::COMMIT,
        sigma::COMMIT_DATE,
        esc(bare(licence)),
        esc(bare(sigma::ELASTIC.url)),
        sigma::ELASTIC.commit,
        esc(bare(elastic_licence)),
        esc(bare(sigma::ELASTIC_BEHAVIOUR.url)),
        sigma::ELASTIC_BEHAVIOUR.commit,
        esc(bare(behaviour_licence)),
    ));
    out.push_str(FOOT);
    out
}

/// At most this many readings are named under a list that is not whole.
const GAPS_SHOWN: usize = 3;
/// What an empty list says when everything that fills it was read in full and fresh.
const NONE_FOUND: &str = "None found here.";
/// The same for the list of servers.
const NONE_KNOWN: &str = "None known.";
/// The same for lists of devices seen in the private network.
const NONE_SEEN: &str = "None seen.";

/// What a list cannot claim, from the latest readings that fill it: `None` when there is at
/// least one and every one is full and fresh, that is taken by the latest check and dated no
/// later than now (`store::age`); else a sentence naming each one that is not, with why and
/// when it was last read in full, and `extra`, what else the list rests on that is not current.
/// A list states that nothing is there only when this is `None` (`absent`).
fn unread(
    readings: &[&Latest],
    latest_run: Option<i64>,
    now: i64,
    extra: &[String],
) -> Option<String> {
    let fresh = |r: &Latest| crate::look::fresh(r.at, latest_run, now);
    let mut seen = BTreeSet::new();
    let mut said: Vec<String> = readings
        .iter()
        .filter(|r| r.completeness != "full" || !fresh(r))
        .map(|r| {
            let why = match (r.completeness.as_str(), r.reason.as_deref()) {
                ("full", _) => "not read at the latest check".to_string(),
                (_, Some(reason)) => reason.to_string(),
                (_, None) => "not read in full".to_string(),
            };
            let last = r.last_full.map_or("never read in full".to_string(), |at| {
                format!("last read in full {}", utc(at))
            });
            format!("{} ({why}; {last})", r.kind)
        })
        .filter(|s| seen.insert(s.clone()))
        .collect();
    if said.len() > GAPS_SHOWN {
        let more = said.len() - GAPS_SHOWN;
        said.truncate(GAPS_SHOWN);
        said.push(format!("and {more} more"));
    }
    said.extend(extra.iter().cloned());
    if readings.is_empty() && extra.is_empty() {
        return Some("Not read yet, so what is here is not known.".to_string());
    }
    (!said.is_empty()).then(|| {
        format!(
            "Not read in full, so this list may not be whole: {}.",
            said.join("; ")
        )
    })
}

/// What a list of a kind of watched thing rests on beside its own readings: for a kind kept in
/// projects, the walk that finds them (`covered::projects_gap`), so that no "none" is said of
/// projects the walk did not find.
fn walk_gap(count: Count, latest: &[Latest], this: Option<&str>) -> Vec<String> {
    covered::in_projects(count)
        .then(|| covered::projects_gap(latest, this))
        .flatten()
        .map(str::to_string)
        .into_iter()
        .collect()
}

/// The readings that fill the list of a kind of watched thing on this Mac: of files, every
/// kind of place watched as it; of installed things, that kind; of the packages projects
/// depend on, finding the projects and reading their lockfiles.
fn readings_of(count: Count, coverage: &[Latest]) -> Vec<&Latest> {
    let kinds: Vec<String> = match count {
        Count::Files(as_) => {
            let mut kinds = crate::autorun::kinds_of(as_);
            kinds.extend(
                crate::autorun::places()
                    .filter(|(_, k)| k.0 == as_)
                    .map(|(_, k)| k.1.to_string()),
            );
            kinds
        }
        Count::Installed(kind) => vec![kind.to_string()],
        Count::Dependencies => vec![
            crate::checkouts::KIND.to_string(),
            crate::agent_folders::KIND.to_string(),
        ],
    };
    coverage
        .iter()
        .filter(|r| {
            kinds.contains(&r.kind)
                || (matches!(count, Count::Dependencies) && r.reader == crate::lockfiles::READER)
        })
        .collect()
}

/// What a list of known vulnerabilities rests on and did not have at `now`: the projects'
/// lockfiles read, and the vulnerability data current.
fn vulnerability_gap(conn: &Connection, now: i64) -> rusqlite::Result<Option<String>> {
    let latest = view::latest_coverage(conn)?;
    let lockfiles: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == crate::lockfiles::READER)
        .collect();
    let old = old_feeds(conn, now)?;
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    Ok(unread(&lockfiles, latest_run, now, &old))
}

/// Each feed of vulnerability data that is not current, with why, as `unread` names a gap.
fn old_feeds(conn: &Connection, now: i64) -> rusqlite::Result<Vec<String>> {
    Ok(crate::vulnerabilities::freshness(conn, now)?
        .into_iter()
        .filter_map(|f| {
            f.not_current
                .map(|why| format!("the {} vulnerability data ({why})", f.feed.ecosystem))
        })
        .collect())
}

/// What "none used in attacks" lacks while the list of them was never downloaded; `None` once
/// it was read.
fn exploited_gap(conn: &Connection, now: i64) -> rusqlite::Result<Option<String>> {
    // A store made before the list was kept has no table of its readings: never read.
    if crate::threats::last_good(conn).unwrap_or(None).is_some() {
        return Ok(None);
    }
    let never = ["the list of vulnerabilities used in attacks (never downloaded)".to_string()];
    Ok(unread(&[], Some(now), now, &never))
}

/// Writes what a list rests on when it is not whole, and, for an empty list, that nothing is
/// there only when it is (`unread`).
fn coverage_of_list(out: &mut String, unread: Option<&str>, empty: bool, absent: &str) {
    match unread {
        Some(said) => {
            out.push_str("<p class=\"muted\">");
            out.push_str(&esc(said));
            out.push_str("</p>\n");
        }
        None if empty => {
            out.push_str("<p class=\"muted\">");
            out.push_str(&esc(absent));
            out.push_str("</p>\n");
        }
        None => {}
    }
}

/// The top of a page of details for a person.
fn top(title: &str, meta: &str) -> String {
    let mut out = view::head(title);
    out.push_str(BACK);
    out.push_str(&format!(
        "<header>\n<h1>{}</h1>\n<p class=\"meta\">{}</p>\n</header>\n",
        esc(title),
        esc(meta)
    ));
    out
}

/// What is watched on this Mac, one section per kind with the things of that kind, and the
/// projects.
pub fn this_mac(
    conn: &Connection,
    st: &crate::status::State,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = top(
        THIS_MAC_TITLE,
        &format!(
            "Last full check {} · this page made {}",
            utc_or(st.this_mac.checked_at, "never"),
            utc(now)
        ),
    );
    let this = covered::this_machine(conn)?;
    let this = this.as_deref();
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let of_kinds = |kinds: &[&str]| -> Vec<&Latest> {
        st.coverage
            .iter()
            .filter(|r| kinds.contains(&r.kind.as_str()))
            .collect()
    };
    for (count, what, _) in covered::watched() {
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            anchor(what),
            esc(&capital(what)),
            esc(about(what))
        )?;
        told(&mut out, &covered::rules_about(what))?;
        match count {
            Count::Files(as_) => {
                let walk = walk_gap(count, &st.coverage, this);
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &walk);
                files(conn, &mut out, as_, this, gap.as_deref())?
            }
            Count::Installed(kind) => {
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &[]);
                installed(conn, &mut out, kind, this, gap.as_deref())?
            }
            Count::Dependencies => {
                let n: i64 = conn.query_row(
                    "SELECT COUNT(DISTINCT subject) FROM assertion
                     WHERE layer = 'live' AND reader = ?1 AND predicate = 'part_of'
                       AND scope LIKE ?2",
                    params![
                        crate::lockfiles::READER,
                        format!("checkout:{}/%", this.unwrap_or_default())
                    ],
                    |r| r.get(0),
                )?;
                writeln!(
                    out,
                    "<p>Your projects on this Mac depend on {} packages, each counted once per project; each project and its count are under Projects below. <a href=\"{VULNERABILITIES}.html\">Known vulnerabilities in them</a> are listed by project.</p>",
                    grouped(n)
                )?;
                // The count is of the projects found: what the walk left out is said under it.
                let walk = walk_gap(count, &st.coverage, this);
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &walk);
                coverage_of_list(&mut out, gap.as_deref(), false, "");
            }
        }
        out.push_str("</section>\n");
    }
    // Running programs: what the latest sample saw, in numbers. No list is kept.
    writeln!(
        out,
        "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">While a watcher runs, it looks at the programs running under your user and where they connect, every {} seconds. Only a program or connection that needs a look is kept; no list of them is.</p>",
        anchor(covered::SAMPLED),
        esc(&capital(covered::SAMPLED)),
        crate::watch::SAMPLE.as_secs()
    )?;
    told(&mut out, &covered::rules_about(covered::SAMPLED))?;
    match crate::processes::last_sample(conn)? {
        Some((at, programs, connections)) => writeln!(
            out,
            "<p>The latest sample, taken {}, saw {} and {}.</p>",
            utc(at),
            counted(programs, "running program", "running programs"),
            counted(connections, "connection", "connections")
        )?,
        None => out.push_str("<p class=\"muted\">No sample has been taken yet.</p>\n"),
    }
    out.push_str("</section>\n");
    also(conn, &mut out)?;

    ways(conn, &mut out, this)?;

    out.push_str("<section id=\"projects\">\n<h2>Projects</h2>\n<p class=\"muted\">Folders of code kept with git on this Mac, with how many of their dependencies are known from the files that list them.</p>\n");
    // Folders the walk did not enter: the list is not every project on this Mac.
    let unseen = covered::projects_not_looked_into(&st.coverage);
    if !unseen.is_empty() {
        let unseen: Vec<&str> = unseen.iter().map(String::as_str).collect();
        writeln!(
            out,
            "<p>Not looked into: {}. macOS asks your permission before a program looks inside these folders, and this version does not ask, so a new project kept there is not found. One found there before is listed as it was, and nothing inside it is read.</p>",
            esc(&covered::listed(&unseen))
        )?;
    }
    // What the walk does not look in by design, said once, quietly.
    writeln!(
        out,
        "<p class=\"muted\">{}</p>",
        esc(&crate::checkouts::not_walked())
    )?;
    let list = projects(conn, this)?;
    let gap = unread(
        &of_kinds(&[crate::checkouts::KIND, crate::agent_folders::KIND]),
        latest_run,
        now,
        &[],
    );
    coverage_of_list(
        &mut out,
        gap.as_deref(),
        list.is_empty(),
        "None found in the folders looked into.",
    );
    if !list.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Project", "Dependencies known"]);
        for (shown, n) in list {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &shown)?;
            view::td(&mut out, "", &grouped(n))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    // What on this Mac was not judged, each thing in full, where the summary's line leads.
    let unjudged = unjudged(st);
    writeln!(
        out,
        "<section id=\"{NOT_JUDGED}\">\n<h2>Not judged on this Mac</h2>\n<p class=\"muted\">{}</p>",
        esc(&if unjudged.is_empty() {
            "Nothing beyond what you can fix, which the summary lists.".to_string()
        } else {
            format!(
                "{} on this Mac this version could not judge here, and nothing you do changes.",
                counted(unjudged.len() as i64, "thing", "things")
            )
        })
    )?;
    for u in unjudged {
        uncovered(&mut out, u)?;
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
}

/// What the section of every known way a project runs code by itself says first.
const WAYS: &str = "Files in a project that make a tool run code by itself during routine work, such as opening the folder or installing its packages. This version reads some of them and watches what they say; the others are only named here, so a change in them goes unseen. Every way known to this version is listed, whether it is in your projects or not.";

/// What the section of every known place in the home folder says first.
const HOME_WAYS: &str = "Files and folders in your home folder where a developer tool keeps its own settings for what it runs by itself, such as the programs a coding agent starts or an editor's extensions. This version reads some of them and watches what they say; the others are only named here, so a change in them goes unseen. Every place known to this version is listed, whether it is on this Mac or not.";

/// Every known way a project runs code by itself, from the table in `autorun`: the file, what
/// runs it, whether the tool asks first, whether it is read, and in how many projects here it
/// is; then, in a section of their own, the places of the home folder, and whether this Mac
/// holds each. None is left out, present or not.
fn ways(conn: &Connection, out: &mut String, this: Option<&str>) -> Out {
    use crate::autorun::{self, Part, Scope};
    // Which subjects hold a way: checkouts of this Mac by the start of their id, or this Mac
    // itself for the home folder.
    let holding = |name: &str, home: bool| -> rusqlite::Result<i64> {
        let this = this.unwrap_or_default();
        conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = ?2 AND object = ?3
               AND CASE WHEN ?5 THEN subject = ?4
                        ELSE substr(subject, 1, length(?4)) = ?4 END",
            params![
                watched::READER,
                autorun::HOLDS,
                name,
                if home {
                    this.to_string()
                } else {
                    format!("checkout:{this}/")
                },
                home
            ],
            |r| r.get(0),
        )
    };
    for home in [false, true] {
        let (read, known) = autorun::counts(home);
        let (id, heading, intro, unit, column) = if home {
            (
                "home-code-runs",
                "Places where a developer tool's own settings can make code run by itself",
                HOME_WAYS,
                "places",
                "On this Mac",
            )
        } else {
            (
                "ways-code-runs",
                "Ways a project can make code run by itself",
                WAYS,
                "ways",
                "Projects here",
            )
        };
        writeln!(
            out,
            "<section id=\"{id}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>\n<p>{}</p>",
            esc(heading),
            esc(intro),
            esc(&format!(
                "This version reads {read} of the {known} known {unit}."
            ))
        )?;
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(out, &["File", "What runs it", "Asks first", "Read", column]);
        for (p, way) in autorun::ways().filter(|(p, _)| (p.scope == Scope::Home) == home) {
            let words = if home {
                way.trigger.words_home()
            } else {
                way.trigger.words()
            };
            let runs = format!("{} ({})", capital(words), way.tool);
            let read = match p.part {
                Part::Present => "Not read",
                Part::Entries => "Read: every entry",
                _ if p.hourly().is_some() => "Read at each hourly check",
                Part::Folders(_) => "Read: every folder, by name",
                _ => "Read",
            };
            let here = match p.scope {
                Scope::NamedBy(_) => "Not looked for".to_string(),
                Scope::Checkout | Scope::System => grouped(holding(&p.name(), false)?),
                Scope::Home if holding(&p.name(), true)? > 0 => "Yes".to_string(),
                Scope::Home => "No".to_string(),
            };
            out.push_str("<tr>");
            view::td(out, "mono", &p.name())?;
            view::td(out, "", &runs)?;
            view::td(out, "", way.asks.words())?;
            view::td(out, "", read)?;
            view::td(out, "", &here)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</section>\n");
    }
    Ok(())
}

/// The watched files of one kind: where each is, when it was first seen and when it last
/// changed. Only checksums are kept, never content. `gap` is what the list cannot claim
/// (`unread`). An entry watched only for presence says so instead of when it changed.
fn files(
    conn: &Connection,
    out: &mut String,
    as_: &str,
    this: Option<&str>,
    gap: Option<&str>,
) -> Out {
    let mac = findings::This::of(conn, this.map(str::to_string))?;
    let first: Vec<(String, i64)> = conn
        .prepare(
            "SELECT subject, MIN(observed_at) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as' AND object = ?2
             GROUP BY subject ORDER BY subject",
        )?
        .query_map(params![watched::READER, as_], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    coverage_of_list(out, gap, first.is_empty(), NONE_FOUND);
    if first.is_empty() {
        return Ok(());
    }
    let presence = watched::presence_only(conn)?;
    let now = watched::content_now(conn)?;
    let has_content: BTreeSet<String> = conn
        .prepare(
            "SELECT DISTINCT subject FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'has_content'",
        )?
        .query_map([watched::READER], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    // A file whose content or link target was replaced, and when the current one was seen.
    let changed: BTreeMap<String, i64> = conn
        .prepare(
            "SELECT l.subject, MAX(l.observed_at) FROM assertion l
             WHERE l.layer = 'live' AND l.reader = ?1 AND l.predicate IN ('has_content', 'links_to')
               AND EXISTS (SELECT 1 FROM assertion o
                           WHERE o.layer = 'retracted' AND o.reader = ?1 AND o.subject = l.subject
                             AND o.predicate IN ('has_content', 'links_to'))
             GROUP BY l.subject",
        )?
        .query_map([watched::READER], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    view::thead(out, &["File", "First seen", "Last changed"]);
    for (id, at) in first {
        out.push_str("<tr>");
        view::td(out, "mono", &findings::place(&id, mac.as_ref()))?;
        view::td(out, "nowrap", &utc(at))?;
        // Never "unchanged" of what the latest check did not read in full.
        let (class, last) = if let Some(n) = now.get(&id).filter(|n| !n.read()) {
            ("", n.not_read())
        } else if presence.contains(&id) {
            ("", watched::PRESENCE_ONLY.to_string())
        } else if let Some(t) = changed.get(&id) {
            ("nowrap", utc(*t))
        } else if !has_content.contains(&id) {
            ("", watched::NEVER_READ.to_string())
        } else {
            ("nowrap", "not since first seen".to_string())
        };
        view::td(out, class, &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// One installed thing as a person reads it.
#[derive(Default)]
struct Installed {
    name: String,
    signed_by: BTreeSet<String>,
    version: BTreeSet<String>,
    at: String,
}

/// The installed things of one kind, each with its subject, named as a person reads it and in
/// the order of their names.
fn installed_list(
    conn: &Connection,
    kind: &str,
    this: Option<&str>,
) -> rusqlite::Result<Vec<(String, Installed)>> {
    let mac = findings::This::of(conn, this.map(str::to_string))?;
    let mut things: BTreeMap<String, Installed> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND kind = ?2",
    )?;
    let rows = stmt.query_map(params![integrity::READER, kind], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (subject, predicate, object) = row?;
        let t = things.entry(subject).or_default();
        match predicate.as_str() {
            "signed_by" => {
                t.signed_by.insert(object);
            }
            "has_version" => {
                t.version.insert(object);
            }
            "installed_at" => t.at = object,
            _ => {}
        }
    }
    let mut list: Vec<(String, Installed)> = things
        .into_iter()
        .map(|(subject, mut t)| {
            if t.at.is_empty() {
                t.at = findings::place(&subject, mac.as_ref());
            }
            let path = t.at.trim_end_matches('/');
            let last = path.rsplit('/').next().unwrap_or(path);
            t.name = if let Some(app) = last.strip_suffix(".app") {
                app.to_string()
            } else if subject.starts_with("component:") {
                view::component_name(&subject).1.to_string()
            } else if let Some((_, keg)) = path.split_once("/Cellar/") {
                // A Homebrew keg, `<name>/<version>`.
                let (name, version) = keg.split_once('/').unwrap_or((keg, ""));
                if t.version.is_empty() && !version.is_empty() {
                    t.version.insert(version.to_string());
                }
                name.to_string()
            } else {
                last.to_string()
            };
            (subject, t)
        })
        .collect();
    list.sort_by_key(|(_, t)| t.name.to_lowercase());
    Ok(list)
}

/// The installed things of one kind: name first, who signed it where that is known, version
/// and where it is. `gap` is what the list cannot claim (`unread`).
fn installed(
    conn: &Connection,
    out: &mut String,
    kind: &str,
    this: Option<&str>,
    gap: Option<&str>,
) -> Out {
    let list: Vec<Installed> = installed_list(conn, kind, this)?
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    coverage_of_list(out, gap, list.is_empty(), NONE_FOUND);
    if list.is_empty() {
        return Ok(());
    }
    let signed = list.iter().any(|t| !t.signed_by.is_empty());
    let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    if signed {
        view::thead(out, &["Name", "Signed by", "Version", "Where"]);
    } else {
        view::thead(out, &["Name", "Version", "Where"]);
    }
    for t in &list {
        out.push_str("<tr>");
        view::td(out, "", &t.name)?;
        if signed {
            view::td(out, "", &join(&t.signed_by))?;
        }
        view::td(out, "mono", &join(&t.version))?;
        view::td(out, "mono", &t.at)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// What the owner's other devices are, on the summary and on the page beyond this Mac.
const YOUR_DEVICES: &str = "Phones, tablets and computers on your private network that you do not log in to over SSH. They are not checked: this version looks at this Mac and at servers.";

/// Servers, the owner's other devices, other people's devices and machines the owner set
/// aside, each in a section of its own.
pub fn beyond(conn: &Connection, latest: &[Latest], now: i64) -> Result<String, Box<dyn Error>> {
    // When its "none" was established: the last full check, as on the page of this Mac.
    let checked_at = crate::status::latest_finished(conn)?.and_then(|r| r.finished_at);
    let mut out = top(
        "Beyond this Mac",
        &format!(
            "Last full check {} · this page made {}",
            utc_or(checked_at, "never"),
            utc(now)
        ),
    );
    let this = covered::this_machine(conn)?.unwrap_or_default();
    let split = beyond::split(conn, &this)?;
    // Every name and address each machine entity is known by.
    let mut names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject, object FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as' AND subject LIKE 'machine:%'",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (subject, name) = row?;
        names.entry(subject).or_default().insert(name);
    }
    let visits: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .collect();
    let bare = |m: &str| m.strip_prefix("machine:").unwrap_or(m).to_string();
    // The name a machine is shown by, the one it was checked under if any, and the others.
    let named = |group: &[String]| -> (String, String) {
        let label = group
            .iter()
            .find(|m| visits.iter().any(|v| &v.scope == *m))
            .or(group.first())
            .map(|m| bare(m))
            .unwrap_or_default();
        let mut others: BTreeSet<String> = group.iter().map(|m| bare(m)).collect();
        for m in group {
            others.extend(names.get(m).into_iter().flatten().cloned());
        }
        others.remove(&label);
        (label, others.into_iter().collect::<Vec<_>>().join(", "))
    };

    // What each list rests on: the readings of this Mac that name machines.
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let of_readers = |readers: &[&str]| -> Vec<&Latest> {
        latest
            .iter()
            .filter(|r| r.scope == this && readers.contains(&r.reader.as_str()))
            .collect()
    };
    let tailnet = unread(&of_readers(&[crate::tailnet::READER]), latest_run, now, &[]);

    out.push_str("<section id=\"servers\">\n<h2>Servers</h2>\n<p class=\"muted\">Machines you log in to over SSH, as your SSH settings, the list of machines SSH has connected to and the server check name them, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself.</p>\n");
    let gap = unread(
        &of_readers(&[
            crate::ssh_config::READER,
            crate::known_hosts::READER,
            crate::tailnet::READER,
        ]),
        latest_run,
        now,
        &[],
    );
    coverage_of_list(
        &mut out,
        gap.as_deref(),
        split.servers.is_empty(),
        NONE_KNOWN,
    );
    if !split.servers.is_empty() {
        let mut rows: Vec<[String; 4]> = Vec::new();
        for group in &split.servers {
            let (label, others) = named(group);
            let mine: Vec<&&Latest> = visits.iter().filter(|v| group.contains(&v.scope)).collect();
            let state = match mine.iter().max_by_key(|v| v.at) {
                None => "not part of it".to_string(),
                Some(v) if v.completeness == "full" => "checked".to_string(),
                Some(v) if v.reason.as_deref() == Some(servers::NOT_COMPLETE) => {
                    "did not finish".to_string()
                }
                Some(v) => format!(
                    "could not be opened: {}",
                    v.reason.as_deref().unwrap_or_default()
                ),
            };
            let last = mine.iter().filter_map(|v| v.last_full).max();
            rows.push([label, state, utc_or(last, "never"), others]);
        }
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(
            &mut out,
            &[
                "Server",
                "At the last server check",
                "Last checked",
                "Also known as",
            ],
        );
        for [label, state, last, others] in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td(&mut out, "", &state)?;
            view::td(&mut out, "nowrap", &last)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    // Never guessed: a server the private network alone knows, without a system, says so.
    match split.system_not_given {
        0 => {}
        1 => out.push_str("<p class=\"muted\">1 of them is known only from your private network, which does not say what system it runs, so it is counted as a server.</p>\n"),
        n => writeln!(
            out,
            "<p class=\"muted\">{n} of them are known only from your private network, which does not say what system they run, so they are counted as servers.</p>"
        )?,
    }
    out.push_str("</section>\n");

    writeln!(
        out,
        "<section id=\"your-devices\">\n<h2>Your other devices</h2>\n<p class=\"muted\">{YOUR_DEVICES}</p>"
    )?;
    coverage_of_list(
        &mut out,
        tailnet.as_deref(),
        split.own_devices.is_empty(),
        NONE_SEEN,
    );
    if !split.own_devices.is_empty() {
        let mut rows: Vec<(String, String, String)> = split
            .own_devices
            .iter()
            .map(|g| {
                let (label, others) = named(g);
                let system = g
                    .iter()
                    .find_map(|m| split.platform.get(m))
                    .cloned()
                    .unwrap_or_default();
                (label, system, others)
            })
            .collect();
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Device", "System", "Also known as"]);
        for (label, system, others) in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td(&mut out, "", &system)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");

    out.push_str("<section id=\"other-devices\">\n<h2>Other devices</h2>\n<p class=\"muted\">Other people's computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them. Only a Tailscale network is looked at; devices in a network of another kind are not known here.</p>\n");
    coverage_of_list(
        &mut out,
        tailnet.as_deref(),
        split.other_devices.is_empty(),
        NONE_SEEN,
    );
    if !split.other_devices.is_empty() {
        let mut rows: Vec<(String, String)> =
            split.other_devices.iter().map(|g| named(g)).collect();
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Device", "Also known as"]);
        for (label, others) in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");

    out.push_str("<section id=\"retired\">\n<h2>Retired or not yours</h2>\n<p class=\"muted\">Machines you said are retired or not yours. They are not checked, and what was read on them before is kept.</p>\n");
    let standing: Vec<crate::owner::Standing> = crate::owner::standing(conn)?
        .into_iter()
        .filter(|s| s.seen.is_none())
        .collect();
    if standing.is_empty() {
        out.push_str("<p class=\"muted\">None.</p>\n");
    } else {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(
            &mut out,
            &["Machine", "You said", "Since", "Why", "How it was given"],
        );
        for s in &standing {
            out.push_str("<tr>");
            view::td(&mut out, "mono", s.name())?;
            view::td(&mut out, "", &s.word.said)?;
            view::td(&mut out, "nowrap", &utc(s.word.made_at))?;
            view::td(&mut out, "", &s.word.reason.shown(view::shown))?;
            view::td(&mut out, "", view::given_by(s.word.via))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
}

/// The technical pages, each in a line: everything the program keeps, as it keeps it.
pub fn technical() -> String {
    let mut out = top(
        "Technical details",
        "Everything the program keeps, as it keeps it: for your agent, or for a closer look.",
    );
    out.push_str("<section id=\"technical\">\n<ul class=\"counts\">\n");
    out.push_str(&format!(
        "<li><a href=\"{THIS_MAC}.html\">{THIS_MAC_TITLE}: every kind of place, its things and its rules</a></li>\n<li><a href=\"{VULNERABILITIES}.html\">Known vulnerabilities in the packages your projects use</a></li>\n"
    ));
    out.push_str(&format!(
        "<li><a href=\"{BEYOND}.html\">Beyond this Mac: servers, your other devices, other people's devices, and machines you set aside</a></li>\n"
    ));
    out.push_str(&format!(
        "<li><a href=\"{THREAT_DATA}.html\">{THREAT_DATA_TITLE}: every source of known vulnerabilities, and the list of those used in attacks</a></li>\n"
    ));
    for (name, title) in view::DETAIL_PAGES {
        out.push_str(&format!(
            "<li><a href=\"{name}.html\">{}</a></li>\n",
            esc(title)
        ));
    }
    out.push_str("</ul>\n</section>\n");
    out.push_str(FOOT);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_of_watched_places_or_of_ways_read_at_a_time_ahead_of_the_clock_never_says_none_found()
    {
        // A time from the future proves nothing, whichever kind of autorun point the list is
        // of: a kind of watched place, or a way a project runs code.
        let (run, now) = (1_000_000, 1_000_100);
        let mcp = crate::autorun::POINTS
            .iter()
            .find(|p| p.paths == [".mcp.json"])
            .unwrap();
        for (count, kind) in [
            (
                Count::Files(watched::PROFILE),
                watched::PROFILE_KIND.to_string(),
            ),
            (Count::Files(crate::autorun::AGENT_START.0), mcp.kind()),
        ] {
            let at = |at| Latest {
                reader: watched::READER.to_string(),
                scope: "machine:mac".to_string(),
                kind: kind.clone(),
                completeness: "full".to_string(),
                reason: None,
                cause: None,
                at,
                last_full: Some(at),
            };
            let ahead = [at(now + crate::store::AHEAD_ALLOWED + 1)];
            let said = unread(&readings_of(count, &ahead), Some(run), now, &[]);
            assert!(said.is_some_and(|s| s.contains(&kind)), "{kind}");
            let on_time = [at(run)];
            assert_eq!(
                unread(&readings_of(count, &on_time), Some(run), now, &[]),
                None
            );
        }
    }

    #[test]
    fn a_list_says_nothing_is_there_only_when_every_reading_that_fills_it_is_full_and_fresh() {
        // "None found" on a list whose reading failed, was partial, was taken by an earlier
        // check, is dated ahead of the clock, or never ran, is false calm.
        let (run, now) = (1_000_000, 1_000_100);
        let reading = |completeness: &str, at: i64| Latest {
            reader: "invented".to_string(),
            scope: "machine:mac".to_string(),
            kind: "invented things".to_string(),
            completeness: completeness.to_string(),
            reason: (completeness != "full").then(|| "an invented reason".to_string()),
            cause: None,
            at,
            last_full: Some(run - 86_400),
        };
        let said = |readings: &[&Latest], extra: &[String]| {
            let mut out = String::new();
            coverage_of_list(
                &mut out,
                unread(readings, Some(run), now, extra).as_deref(),
                true,
                NONE_FOUND,
            );
            out
        };
        let full = reading("full", run);
        assert!(said(&[&full], &[]).contains(NONE_FOUND));
        for not in [
            reading("partial", run),
            reading("none", run),
            reading("full", run - 1),
            reading("full", now + crate::store::AHEAD_ALLOWED + 1),
        ] {
            let out = said(&[&full, &not], &[]);
            assert!(
                !out.contains(NONE_FOUND)
                    && out.contains("invented things")
                    && out.contains("last read in full"),
                "{out}"
            );
        }
        assert!(!said(&[], &[]).contains(NONE_FOUND));
        // Many gaps are told briefly: the first few and how many more, each kind once.
        let many: Vec<Latest> = (0..5)
            .map(|i| Latest {
                kind: format!("invented kind {i}"),
                ..reading("none", run)
            })
            .collect();
        let mut refs: Vec<&Latest> = many.iter().collect();
        refs.push(&many[0]);
        let out = said(&refs, &[]);
        assert!(
            out.contains("invented kind 2 (")
                && out.contains("; and 2 more.")
                && !out.contains("invented kind 3")
                && out.matches("invented kind 0").count() == 1,
            "{out}"
        );
        let old = ["the invented data (it is old)".to_string()];
        let out = said(&[&full], &old);
        assert!(!out.contains(NONE_FOUND) && out.contains(&old[0]), "{out}");
        // Without any finished check, nothing is fresh.
        let mut out = String::new();
        coverage_of_list(
            &mut out,
            unread(&[&full], None, now, &[]).as_deref(),
            true,
            NONE_FOUND,
        );
        assert!(!out.contains(NONE_FOUND), "{out}");
        // A list that is not empty is not told as empty either way.
        let mut out = String::new();
        coverage_of_list(&mut out, None, false, NONE_FOUND);
        assert!(out.is_empty());
    }

    #[test]
    fn the_rules_page_never_says_no_match_of_a_rule_that_reads_what_does_not_arrive() {
        // "No match in the last day" is calm. A rule, in full or in part, that reads what no
        // line has given a value for has judged nothing, and says so instead, with which: the
        // collector does not keep it, keeps it and never filled it, or no line was read yet.
        use crate::events::{Arrival, Arrivals, Files, Level, RUNNING, Series, Tally};
        use crate::sigma::{ELASTIC, Rules};
        let rule = |id: &str, title: &str, detection: &str, left_out: &str| -> &'static str {
            Box::leak(
                format!(
                    "title: {title}\nid: {id}\nstatus: test\nlevel: high\n\
                     logsource: {{\"product\": \"macos\", \"category\": \"file_event\"}}\n\
                     detection:\n{detection}{}",
                    crate::sigma::testing::record_of(&ELASTIC, "\"high\"", left_out)
                )
                .into_boxed_str(),
            )
        };
        let signer = "  s1: {\"process.code_signature.signing_id|cased\": [\"com.example\"]}\n  condition: s1\n";
        let rules = Rules::load_as(
            &ELASTIC,
            &[
                (
                    "full.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000001",
                        "Invented in full",
                        signer,
                        "",
                    ),
                ),
                (
                    "part.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000002",
                        "Invented in part",
                        signer,
                        "\"needs_fields process.code_signature.trusted\"",
                    ),
                ),
            ],
        );
        let on = Arrival::Kept(Some(1));
        let sig = |a| Arrivals::from([on, on, a, on, a]);
        let script = |a| Arrivals::from([on, a, on, on, on]);
        let level_as = |state: &str, collected: bool, arrivals| Level {
            state: state.to_string(),
            read_at: 0,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally::default(),
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: Files {
                collected,
                ..Files::default()
            },
            arrivals,
            cap: None,
        };
        let level = |arrivals| level_as(RUNNING, true, arrivals);
        let page = |l: &Level| {
            let r = crate::status::rules_now_of(&rules, Some(l));
            rules_page(&rules, &r, Some(l), 0)
        };
        let said = "Not watching on this Mac: it reads what the collector installed here does not keep. Installing the event level again adds it.";
        let earlier = page(&level(sig(Arrival::NotKept)));
        assert_eq!(earlier.matches(said).count(), 2, "{earlier}");
        assert!(!earlier.contains("No match in the last day"), "{earlier}");
        let empty = page(&level(sig(Arrival::Kept(None))));
        assert_eq!(
            empty
                .matches("Not watching on this Mac: it reads what the collector keeps and no line has given a value for yet.")
                .count(),
            2,
            "{empty}"
        );
        assert!(!empty.contains("No match in the last day"), "{empty}");
        let stopped = page(&level(sig(Arrival::NoLonger(1))));
        assert_eq!(
            stopped
                .matches("Not watching on this Mac: it reads what the collector keeps, and the latest lines give no value for it.")
                .count(),
            2,
            "{stopped}"
        );
        assert!(!stopped.contains("No match in the last day"), "{stopped}");
        let unknown = page(&level(sig(Arrival::Unknown)));
        assert_eq!(
            unknown
                .matches("so whether the collector keeps it is not yet known")
                .count(),
            2,
            "{unknown}"
        );
        assert!(!unknown.contains("No match in the last day"), "{unknown}");
        // The count at the top counts neither among the rules watching file events.
        let r = crate::status::rules_now_of(&rules, Some(&level(sig(Arrival::NotKept))));
        let said_now = crate::text::rules_said("", &r);
        assert!(
            said_now.contains("0 every program start and 0 every file created or renamed"),
            "{said_now}"
        );
        let now = page(&level(sig(on)));
        assert!(!now.contains(said), "{now}");
        assert_eq!(now.matches("No match in the last day.").count(), 2, "{now}");
        // One reason at a time: while file events are not collected, that is the one said.
        let no_files = page(&level_as(RUNNING, false, sig(Arrival::NotKept)));
        assert!(!no_files.contains(said), "{no_files}");
        assert!(
            no_files.contains("records program starts only"),
            "{no_files}"
        );
        // With no collector running there is no earlier collector to name, though nothing
        // is known to arrive.
        let off = page(&level_as("not_installed", false, Arrivals::default()));
        assert!(!off.contains("Not watching on this Mac: it reads"), "{off}");
        // The same for a rule about program starts, which no change of file events covers.
        let starts = crate::sigma::testing::process_kept();
        let page = |l: &Level| {
            let r = crate::status::rules_now_of(&starts, Some(l));
            rules_page(&starts, &r, Some(l), 0)
        };
        let earlier = page(&level(script(Arrival::NotKept)));
        assert_eq!(earlier.matches(said).count(), 1, "{earlier}");
        let off = page(&level_as("not_installed", false, Arrivals::default()));
        assert!(!off.contains(said), "{off}");
    }

    #[test]
    fn a_way_read_is_in_every_place_derived_from_the_table_so_adding_a_row_changes_no_code() {
        // Adding a product is adding a row. Every place that tells or acts on what runs by
        // itself takes it from the table: a row read here that one of them missed would be
        // read and never told, or told and never watched live.
        use crate::autorun;
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-ways-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let conn = crate::store::open(&dir.join("store.db")).unwrap();
        let mut page = String::new();
        ways(&conn, &mut page, None).unwrap();
        let registered: Vec<String> = conn
            .prepare("SELECT name FROM coverage_kind")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
        for (p, way) in autorun::ways() {
            let cell = format!("<td class=\"mono\">{}</td>", esc(&p.name()));
            assert!(page.contains(&cell));
            // A row read only at the hourly check says so where it says it is read.
            let rest = &page[page.find(&cell).unwrap()..];
            let line = &rest[..rest.find("</tr>").unwrap()];
            assert_eq!(
                line.contains(">Read at each hourly check<"),
                p.hourly().is_some(),
                "{line}"
            );
            if !p.read_here() {
                continue;
            }
            let as_ = p.watched_as().unwrap_or_default();
            let (_, what, line) = p.watched().unwrap_or_default();
            assert!(!as_.is_empty() && !line.is_empty(), "{}", p.name());
            // A row not watched live says why; a path with a `*` cannot be watched live.
            for path in p.paths {
                let live = match p.scope {
                    autorun::Scope::Home => {
                        autorun::home_places().iter().any(|(h, _, _)| h == path)
                    }
                    _ => autorun::files().iter().any(|(f, _)| f == path),
                };
                assert_eq!(live, p.hourly().is_none(), "{path}");
                assert!(!live || !path.contains('*'), "{path}");
            }
            assert!(registered.contains(&p.kind()), "{}", p.kind());
            assert!(autorun::kinds_of(as_).contains(&p.kind()));
            assert!(
                covered::watched()
                    .iter()
                    .any(|w| matches!(w.0, Count::Files(a) if a == as_) && w.1 == what)
            );
            assert_eq!(about(what), line);
            let rules = covered::rules_about(what);
            assert_eq!(rules.len(), 1, "{}", p.name());
            assert_eq!(
                (rules[0].technique, rules[0].severity, rules[0].confidence),
                (way.technique, way.severity, way.confidence),
                "{}",
                p.name()
            );
        }
    }

    #[test]
    fn every_kind_of_watched_place_says_on_the_page_what_it_is_and_which_rule_tells_of_it() {
        // A kind listed with no line leaves the owner a name without a meaning, and one no
        // rule speaks about is watched without anyone being told of a change.
        for (_, (watched_as, _)) in crate::autorun::places() {
            let (_, what, _) = covered::watched()
                .into_iter()
                .find(|w| matches!(w.0, Count::Files(a) if a == watched_as))
                .unwrap_or_else(|| panic!("{}", watched_as));
            assert!(about(what).ends_with('.'), "{what}");
            assert_eq!(covered::rules_about(what).len(), 1, "{what}");
        }
    }

    /// The page of what is watched for a store nothing was read into, with a home that does
    /// not exist; the folder it made goes, also when the test fails.
    fn this_mac_page() -> String {
        let dir = crate::common::Scratch::new("told");
        let conn = crate::store::open(&dir.0.join("store.db")).unwrap();
        let st = crate::status::state(&conn, &dir.0.join("no-home"), 1_791_000_000).unwrap();
        this_mac(&conn, &st, 1_791_000_000).unwrap()
    }

    /// Each section of a kind of watched thing on the page, by its anchor, up to its end.
    fn kinds(page: &str) -> Vec<&str> {
        covered::watched()
            .into_iter()
            .map(|(_, what, _)| what)
            .chain([covered::SAMPLED])
            .map(|what| {
                let at = page
                    .find(&format!("<section id=\"{}\">", anchor(what)))
                    .unwrap_or_else(|| panic!("{what}"));
                &page[at..at + page[at..].find("</section>").unwrap()]
            })
            .collect()
    }

    /// Each line of what is told, as the text of its `<li>`.
    fn rule_lines(html: &str) -> Vec<&str> {
        html.split("<ul class=\"rules\">")
            .skip(1)
            .flat_map(|list| list[..list.find("</ul>").unwrap()].split("<li>").skip(1))
            .collect()
    }

    #[test]
    fn every_rule_is_on_the_page_of_what_is_watched() {
        // The owner reads on the page what he is told about. A rule added later and not
        // placed under a kind or under "Also told" would tell him something the page never
        // says it does.
        let page = this_mac_page();
        for r in findings::rules() {
            assert!(page.contains(&esc(r.words.title)), "{}: {page}", r.id);
            assert!(page.contains(&esc(r.words.meaning)), "{}: {page}", r.id);
        }
    }

    #[test]
    fn the_page_never_calls_a_thing_watched_without_saying_what_is_told_about_it() {
        // False calm: a kind listed as watched that no rule can fire about must say so in
        // words, or "watched" promises a warning that never comes.
        let page = this_mac_page();
        for kind in kinds(&page) {
            let said = kind.contains("<ul class=\"rules\">\n<li>") || kind.contains(KEPT_AS_LIST);
            assert!(said, "{kind}");
        }
        let mut lone = String::new();
        told(&mut lone, &[]).unwrap();
        assert!(lone.contains(KEPT_AS_LIST), "{lone}");
    }

    #[test]
    fn a_rule_marked_as_sending_a_notification_is_exactly_an_urgent_one() {
        // The page tells the owner which changes notify at once; the app notifies for what
        // is urgent. The two must not disagree.
        let page = this_mac_page();
        let lines = rule_lines(&page);
        for r in findings::rules() {
            let line = lines
                .iter()
                .find(|l| l.starts_with(&esc(r.words.title)))
                .unwrap_or_else(|| panic!("{} is not on the page", r.id));
            assert_eq!(
                line.contains(NOTIFIES),
                findings::urgent(r.severity, Some(r.confidence)),
                "{}: {line}",
                r.id
            );
        }
    }
}
