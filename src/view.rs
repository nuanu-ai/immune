//! The view: one self-contained HTML page that shows what is in the store.
//! It only reads. No scripts, no outside files: plain HTML, `<details>` and inline CSS.
//!
//! Invariant: every piece of text that comes from the store goes through `esc`
//! before it enters the page. Names, versions, reasons and source references are
//! partly written by an attacker and must never become markup.

use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

use crate::servers::VISIT;

const RUNS_SHOWN: i64 = 20;
/// The latest run is shown open only when its changes fit on a screen or a few.
const EVENTS_SHOWN_OPEN: usize = 500;

type Out = Result<(), Box<dyn Error>>;

pub fn page(conn: &Connection, store: &str, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = String::new();
    out.push_str(HEAD);
    header(conn, &mut out, store, now)?;
    let latest = latest_coverage(conn)?;
    coverage(conn, &mut out, &latest, now)?;
    machines(conn, &mut out, &latest, now)?;
    threats(conn, &mut out, now)?;
    changes(conn, &mut out)?;
    retracted(conn, &mut out)?;
    vocabulary(conn, &mut out)?;
    out.push_str("</main>\n</body>\n</html>\n");
    Ok(out)
}

/// Makes text safe to put anywhere in the page, inside elements and inside quoted attributes.
/// Characters that could reorder or hide text are shown escaped, as `shown` shows them.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if hidden(c) => out.extend(c.escape_unicode()),
            _ => out.push(c),
        }
    }
    out
}

/// Text as the terminal may show it: every character that is hidden is written as
/// `\u{…}`. The store keeps the text as it was read; only what is shown is escaped.
pub fn shown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if hidden(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Unicode's format characters: invisible, and some of them reorder the text around them,
/// such as the bidirectional controls. With the line and paragraph separators.
const FORMAT: [(char, char); 21] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{2028}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// Whether a character, printed as it is, could rearrange or hide what is shown: a control
/// character or an invisible format character.
fn hidden(c: char) -> bool {
    c.is_control() || FORMAT.iter().any(|(from, to)| (*from..=*to).contains(&c))
}

/// UTC seconds as `YYYY-MM-DD HH:MM UTC`, from the civil-from-days algorithm.
pub fn utc(secs: i64) -> String {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn utc_or(secs: Option<i64>, missing: &str) -> String {
    secs.map(utc).unwrap_or_else(|| missing.to_string())
}

/// Place, ecosystem and name from `component:<place>/<ecosystem>/<name>`. The place is
/// an entity id and may hold slashes; a scoped npm name (`@scope/name`) holds one too.
fn split_component(id: &str) -> Option<(&str, &str, &str)> {
    let rest = id.strip_prefix("component:")?;
    let (head, name) = rest.rsplit_once('/')?;
    let (place, ecosystem) = head.rsplit_once('/')?;
    if ecosystem.starts_with('@') {
        let (place, ecosystem) = place.rsplit_once('/')?;
        let name = &rest[place.len() + ecosystem.len() + 2..];
        return Some((place, ecosystem, name));
    }
    Some((place, ecosystem, name))
}

/// Ecosystem and name of a component, or no ecosystem and the whole id for anything else.
fn component_name(id: &str) -> (&str, &str) {
    split_component(id).map_or(("", id), |(_, ecosystem, name)| (ecosystem, name))
}

/// Where a component is, or nothing for anything else.
fn component_place(id: &str) -> &str {
    split_component(id).map_or("", |(place, _, _)| place)
}

/// The time and how many whole days ago it was.
fn utc_age(secs: i64, now: i64) -> String {
    let days = (now - secs).max(0) / 86_400;
    format!(
        "{} · {days} {} ago",
        utc(secs),
        if days == 1 { "day" } else { "days" }
    )
}

/// The predicate in plain words where there is one.
fn what(predicate: &str) -> &str {
    match predicate {
        "part_of" => "present on",
        "has_version" => "version",
        "located_on" => "located on",
        "runs_os" => "operating system",
        "runs_kernel" => "kernel",
        "runs_image" => "image",
        "known_as" => "known as",
        "same_as" => "same machine as",
        other => other,
    }
}

/// A table cell with escaped text and an optional class.
fn td(out: &mut String, class: &str, text: &str) -> Out {
    if class.is_empty() {
        write!(out, "<td>{}</td>", esc(text))?;
    } else {
        write!(out, "<td class=\"{class}\">{}</td>", esc(text))?;
    }
    Ok(())
}

/// A cell that shows a component's name and keeps its full id as a tooltip.
fn td_component(out: &mut String, id: &str) -> Out {
    write!(
        out,
        "<td title=\"{}\">{}</td>",
        esc(id),
        esc(component_name(id).1)
    )?;
    Ok(())
}

fn thead(out: &mut String, columns: &[&str]) {
    out.push_str("<thead><tr>");
    for c in columns {
        out.push_str("<th>");
        out.push_str(c);
        out.push_str("</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");
}

fn header(conn: &Connection, out: &mut String, store: &str, now: i64) -> Out {
    let version: String = conn.query_row(
        "SELECT value FROM meta WHERE key = 'format_version'",
        [],
        |r| r.get(0),
    )?;
    let finished: Option<i64> = conn.query_row(
        "SELECT MAX(at) FROM journal WHERE entry = 'run_finished'",
        [],
        |r| r.get(0),
    )?;
    write!(
        out,
        "<header>\n<h1>What the store holds</h1>\n<p class=\"meta\">Generated {} · store <span class=\"mono\">{}</span> · format version {} · last run finished {}</p>\n</header>\n",
        utc(now),
        esc(store),
        esc(&version),
        utc_or(finished, "never")
    )?;
    Ok(())
}

/// The latest run, by the order of the journal, if it never wrote `run_finished`.
fn unfinished_latest_run(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let latest: Option<(i64, bool)> = conn
        .query_row(
            "SELECT at, EXISTS (SELECT 1 FROM journal f
                                WHERE f.run_id = j.run_id AND f.entry = 'run_finished')
             FROM journal j WHERE entry = 'run_started' ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(latest.and_then(|(at, finished)| (!finished).then_some(at)))
}

/// The latest coverage record of one reader, scope and kind.
struct Latest {
    reader: String,
    scope: String,
    kind: String,
    completeness: String,
    reason: Option<String>,
    at: i64,
    last_full: Option<i64>,
}

/// The latest record for each reader, scope and kind, and its latest full one.
/// Readings that are not full come first. Readings inside a container or checkout that
/// is gone no longer count and are left out.
fn latest_coverage(conn: &Connection) -> rusqlite::Result<Vec<Latest>> {
    conn.prepare(
        "SELECT c.reader, c.scope, c.kind, c.completeness, c.reason, c.observed_at,
                (SELECT MAX(f.observed_at) FROM coverage f
                 WHERE f.reader = c.reader AND f.scope = c.scope AND f.kind = c.kind
                   AND f.completeness = 'full')
         FROM coverage c
         WHERE c.id IN (SELECT MAX(id) FROM coverage GROUP BY reader, scope, kind)
           AND c.scope NOT IN (SELECT id FROM gone_entity)
         ORDER BY c.completeness = 'full', c.completeness, c.reader, c.scope, c.kind",
    )?
    .query_map([], |r| {
        Ok(Latest {
            reader: r.get(0)?,
            scope: r.get(1)?,
            kind: r.get(2)?,
            completeness: r.get(3)?,
            reason: r.get(4)?,
            at: r.get(5)?,
            last_full: r.get(6)?,
        })
    })?
    .collect()
}

/// A completeness as the owner reads it: what is known and what is not. A full reading
/// with a note had nothing to read, which is not the same as having read something.
fn completeness_label<'a>(completeness: &'a str, note: Option<&str>) -> &'a str {
    match (completeness, note) {
        ("full", Some(_)) => "nothing to read",
        ("none", _) => "could not be read",
        ("partial", _) => "partial, removals unknown",
        (other, _) => other,
    }
}

fn badge(out: &mut String, completeness: &str, note: Option<&str>) -> Out {
    write!(
        out,
        "<span class=\"badge {}\">{}</span>",
        if completeness == "full" {
            "good"
        } else {
            "bad"
        },
        esc(completeness_label(completeness, note))
    )?;
    Ok(())
}

fn coverage(conn: &Connection, out: &mut String, rows: &[Latest], now: i64) -> Out {
    out.push_str("<section id=\"coverage\">\n<h2>What was read and how completely</h2>\n");
    out.push_str("<p class=\"muted\">Everything below is only as good as this.</p>\n");
    if let Some(at) = unfinished_latest_run(conn)? {
        writeln!(
            out,
            "<p class=\"alert\">The latest run started at {} and never finished. Nothing it read is in the store.</p>",
            utc(at)
        )?;
    }
    if rows.is_empty() {
        out.push_str("<p class=\"alert\">Nothing has been read yet.</p>\n</section>\n");
        return Ok(());
    }
    let not_full = rows.iter().filter(|r| r.completeness != "full").count();
    let partial = rows.iter().filter(|r| r.completeness == "partial").count();
    if not_full == 0 {
        out.push_str("<p class=\"ok\">Every reading was full at its latest run.</p>\n");
    } else {
        writeln!(
            out,
            "<p class=\"alert\">{not_full} of {} readings were not full at their latest run. \
             What they cover below may be out of date or missing.</p>",
            rows.len()
        )?;
    }
    if partial > 0 {
        writeln!(
            out,
            "<p class=\"alert\">{partial} of them were partial: what they saw was added, \
             but what disappeared there cannot be seen. Removals there are unknown.</p>"
        )?;
    }

    out.push_str("<div class=\"scroll\"><table>\n");
    thead(
        out,
        &[
            "Reader",
            "Where",
            "What",
            "Completeness",
            "Why, or what was there",
            "Last read",
            "Last full read",
        ],
    );
    for r in rows {
        let full = r.completeness == "full";
        out.push_str(if full { "<tr>" } else { "<tr class=\"bad\">" });
        td(out, "", &r.reader)?;
        td(out, "mono", &r.scope)?;
        td(out, "", &r.kind)?;
        out.push_str("<td>");
        badge(out, &r.completeness, r.reason.as_deref())?;
        out.push_str("</td>");
        td(
            out,
            "",
            r.reason
                .as_deref()
                .unwrap_or(if full { "" } else { "no reason given" }),
        )?;
        td(out, "nowrap", &utc_age(r.at, now))?;
        let last = if full {
            "this one".to_string()
        } else {
            utc_or(r.last_full, "never")
        };
        td(out, "nowrap", &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</section>\n");
    Ok(())
}

#[derive(Default)]
struct Component {
    versions: BTreeSet<String>,
    bases: BTreeSet<String>,
    sources: BTreeSet<String>,
    first_seen: Option<i64>,
}

/// What is live in the store, arranged by where things are.
#[derive(Default)]
struct Estate {
    components: BTreeMap<String, Component>,
    /// Machine, container or checkout -> the components in it.
    inside: BTreeMap<String, Vec<String>>,
    /// Machine -> the containers on it.
    containers: BTreeMap<String, Vec<String>>,
    /// Machine -> the checkouts on it.
    checkouts: BTreeMap<String, Vec<String>>,
    /// Subject -> predicate -> objects, for literal attributes such as the OS.
    attrs: BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
}

impl Estate {
    fn load(conn: &Connection) -> rusqlite::Result<Estate> {
        // Only live rows: a component whose assertions were all retracted is not there.
        let mut stmt = conn.prepare(
            "SELECT subject, predicate, object, basis, observed_at, source_ref
             FROM assertion WHERE layer = 'live'",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut e = Estate::default();
        for row in rows {
            let (subject, predicate, object, basis, at, source) = row?;
            if !subject.starts_with("component:") {
                if predicate == "located_on" && subject.starts_with("container:") {
                    e.containers.entry(object).or_default().push(subject);
                } else if predicate == "located_on" && subject.starts_with("checkout:") {
                    e.checkouts.entry(object).or_default().push(subject);
                } else {
                    e.attrs
                        .entry(subject)
                        .or_default()
                        .entry(predicate)
                        .or_default()
                        .insert(object);
                }
                continue;
            }
            let c = e.components.entry(subject.clone()).or_default();
            match predicate.as_str() {
                "has_version" => {
                    c.versions.insert(object);
                }
                "part_of" => e.inside.entry(object).or_default().push(subject),
                _ => {}
            }
            c.bases.insert(basis);
            c.sources.insert(source);
            c.first_seen = Some(c.first_seen.map_or(at, |t| t.min(at)));
        }
        // Two readers that found one checkout make two assertions about one entity.
        for list in e.checkouts.values_mut() {
            list.sort();
            list.dedup();
        }
        for list in e.inside.values_mut().chain(e.containers.values_mut()) {
            list.sort_by_key(|id| {
                let (ecosystem, name) = component_name(id);
                (name.to_lowercase(), ecosystem.to_string())
            });
        }
        Ok(e)
    }

    fn attr(&self, subject: &str, predicate: &str) -> String {
        self.attrs
            .get(subject)
            .and_then(|p| p.get(predicate))
            .map(|set| set.iter().cloned().collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    }

    fn inside(&self, id: &str) -> &[String] {
        self.inside.get(id).map(Vec::as_slice).unwrap_or_default()
    }
}

/// The table of components inside one place.
fn components_table(out: &mut String, estate: &Estate, ids: &[String]) -> Out {
    if ids.is_empty() {
        out.push_str("<p class=\"muted\">No components known.</p>\n");
        return Ok(());
    }
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    thead(
        out,
        &[
            "Name",
            "Ecosystem",
            "Version",
            "Basis",
            "First seen",
            "Source",
        ],
    );
    let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    for id in ids {
        let Some(c) = estate.components.get(id) else {
            continue;
        };
        out.push_str("<tr>");
        td_component(out, id)?;
        td(out, "nowrap", component_name(id).0)?;
        td(out, "mono", &join(&c.versions))?;
        td(out, "", &join(&c.bases))?;
        td(out, "nowrap", &utc_or(c.first_seen, ""))?;
        td(out, "mono", &join(&c.sources))?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Which traces name each machine entity: the kinds of its live `known_as` assertions.
fn traces(conn: &Connection) -> rusqlite::Result<BTreeMap<String, BTreeSet<String>>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject, kind FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as'",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    for row in rows {
        let (subject, kind) = row?;
        out.entry(subject).or_default().insert(kind);
    }
    Ok(out)
}

/// One machine: the entities the resolver found to be it, and how the owner reads it.
struct Machine<'a> {
    members: &'a [String],
    label: String,
    /// Every other name and address it is known by.
    others: Vec<String>,
    traces: Vec<String>,
}

impl<'a> Machine<'a> {
    fn new(
        members: &'a [String],
        estate: &Estate,
        traces_of: &BTreeMap<String, BTreeSet<String>>,
        read: impl Fn(&str) -> bool,
    ) -> Machine<'a> {
        let bare = |m: &'a String| m.strip_prefix("machine:").unwrap_or(m);
        // The name it was read under, else the first.
        let label = members
            .iter()
            .find(|m| read(m))
            .or(members.first())
            .map(bare)
            .unwrap_or_default()
            .to_string();
        let mut others: BTreeSet<String> = members.iter().map(|m| bare(m).to_string()).collect();
        let mut traces = BTreeSet::new();
        for m in members {
            if let Some(names) = estate.attrs.get(m).and_then(|p| p.get("known_as")) {
                others.extend(names.iter().cloned());
            }
            traces.extend(traces_of.get(m).into_iter().flatten().cloned());
        }
        others.remove(&label);
        Machine {
            members,
            label,
            others: others.into_iter().collect(),
            traces: traces.into_iter().collect(),
        }
    }
}

fn machines(conn: &Connection, out: &mut String, latest: &[Latest], now: i64) -> Out {
    out.push_str("<section id=\"machines\">\n<h2>Machines</h2>\n");
    let groups = crate::store::machine_groups(conn)?;
    if groups.is_empty() {
        out.push_str("<p>No machines known.</p>\n</section>\n");
        return Ok(());
    }
    let estate = Estate::load(conn)?;
    let traces_of = traces(conn)?;
    let coverage_of =
        |scope: &str| -> Vec<&Latest> { latest.iter().filter(|r| r.scope == scope).collect() };
    let read = |m: &str| !coverage_of(m).is_empty();
    let all: Vec<Machine> = groups
        .iter()
        .map(|g| Machine::new(g, &estate, &traces_of, read))
        .collect();
    // The owner's word covers a machine under every name. A statement nothing contradicts
    // sets the machine aside; a contradicted one leaves it where it was, with an alert.
    let standing = crate::owner::standing(conn)?;
    let word_of = |m: &Machine| {
        standing
            .iter()
            .find(|s| m.members.iter().any(|id| s.covers(id)))
    };
    let set_aside: Vec<&crate::owner::Standing> =
        standing.iter().filter(|s| s.seen.is_none()).collect();
    let (seen, never): (Vec<&Machine>, Vec<&Machine>) = all
        .iter()
        .partition(|m| m.members.iter().any(|id| read(id)));
    let never: Vec<&Machine> = never
        .into_iter()
        .filter(|m| word_of(m).is_none_or(|w| w.seen.is_some()))
        .collect();
    // Another user's device known only from the tailnet is not a server never read.
    let devices = crate::store::other_users_devices(conn)?;
    let (theirs, never): (Vec<&Machine>, Vec<&Machine>) = never
        .into_iter()
        .partition(|m| crate::store::only_someone_elses(m.members, &devices));
    // A machine is unread when every latest reading of it read nothing.
    let unread = |m: &Machine| {
        m.members
            .iter()
            .flat_map(|id| coverage_of(id))
            .all(|r| r.completeness == "none")
    };
    let unread_count = seen.iter().filter(|m| unread(m)).count();
    write!(
        out,
        "<p class=\"muted\">{}",
        plural(all.len(), "machine", "machines")
    )?;
    if unread_count > 0 {
        write!(
            out,
            "; {unread_count} could not be read at their latest reading"
        )?;
    }
    if !never.is_empty() {
        write!(out, "; {} known and never read", never.len())?;
    }
    if !set_aside.is_empty() {
        write!(
            out,
            "; {} retired or disowned by the owner",
            set_aside.len()
        )?;
    }
    if !theirs.is_empty() {
        write!(
            out,
            "; {} on the tailnet",
            plural(
                theirs.len(),
                "is another user's device",
                "are other users' devices"
            )
        )?;
    }
    out.push_str(". Open one to see what is on it.</p>\n");
    for s in standing.iter().filter(|s| s.seen.is_some()) {
        writeln!(
            out,
            "<p class=\"alert\">The owner's word is contradicted: <span class=\"mono\">{}</span>, {}, was seen alive after it: {}. It is counted again and still not offered for the sweep.</p>",
            esc(s.name()),
            esc(&s.summary()),
            esc(&s.contradiction().unwrap_or_default())
        )?;
    }

    let mut seen = seen;
    seen.sort_by(|a, b| a.label.cmp(&b.label));
    for machine in seen {
        let word = word_of(machine);
        machine_block(
            out,
            machine,
            &estate,
            &coverage_of,
            unread(machine),
            word,
            now,
        )?;
    }

    if !never.is_empty() {
        let mut never = never;
        never.sort_by(|a, b| a.label.cmp(&b.label));
        write!(
            out,
            "<details class=\"machine\">\n<summary><strong>Known and never read</strong> <span class=\"muted\">· {} · traces on this machine name them, and nothing was ever read on them</span></summary>\n<div class=\"inner\">\n",
            plural(never.len(), "machine", "machines")
        )?;
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(out, &["Name", "Also known as", "Known from"]);
        for m in never {
            out.push_str("<tr>");
            td(out, "mono", &m.label)?;
            td(out, "mono", &m.others.join(", "))?;
            td(out, "", &m.traces.join(", "))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</div>\n</details>\n");
    }

    if !set_aside.is_empty() {
        write!(
            out,
            "<details class=\"machine\">\n<summary><strong>Retired or disowned by the owner</strong> <span class=\"muted\">· {} · the owner's word, and nothing seen alive since; not counted as servers, never offered for the sweep, and what was read on them is kept</span></summary>\n<div class=\"inner\">\n",
            plural(set_aside.len(), "machine", "machines")
        )?;
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(out, &["Name", "Said", "Since", "Reason", "Also known as"]);
        for s in set_aside {
            out.push_str("<tr>");
            td(out, "mono", s.name())?;
            td(out, "", &s.word.said)?;
            td(out, "nowrap", &utc(s.word.made_at))?;
            td(out, "", &s.word.reason)?;
            td(out, "mono", &s.names[1..].join(", "))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</div>\n</details>\n");
    }

    if !theirs.is_empty() {
        write!(
            out,
            "<details class=\"machine\">\n<summary><strong>Other users' devices</strong> <span class=\"muted\">· {} · the tailnet says they belong to another user, and no other trace names them; not counted as servers</span></summary>\n<div class=\"inner\">\n",
            plural(theirs.len(), "device", "devices")
        )?;
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(out, &["Name", "Also known as"]);
        for m in theirs {
            out.push_str("<tr>");
            td(out, "mono", &m.label)?;
            td(out, "mono", &m.others.join(", "))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</div>\n</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

/// One machine that something was read on, with every entity it is known as.
fn machine_block<'a>(
    out: &mut String,
    machine: &Machine,
    estate: &Estate,
    coverage_of: &dyn Fn(&str) -> Vec<&'a Latest>,
    not_read: bool,
    word: Option<&crate::owner::Standing>,
    now: i64,
) -> Out {
    let members = machine.members;
    let count = |f: &dyn Fn(&String) -> usize| members.iter().map(f).sum::<usize>();
    let own = count(&|m| estate.inside(m).len());
    let containers = count(&|m| estate.containers.get(m).map_or(0, Vec::len));
    let checkouts = count(&|m| estate.checkouts.get(m).map_or(0, Vec::len));
    // A failed visit read nothing: the machine was read when its readings say.
    let read_at = members
        .iter()
        .flat_map(|m| coverage_of(m))
        .filter(|r| r.kind != VISIT)
        .map(|r| r.at)
        .max();

    out.push_str("<details class=\"machine\">\n<summary>");
    write!(out, "<strong>{}</strong>", esc(&machine.label))?;
    if not_read {
        out.push_str(" <span class=\"badge bad\">could not be read</span>");
    }
    if members
        .iter()
        .flat_map(|m| coverage_of(m))
        .any(|r| r.kind == VISIT && r.completeness == "none")
    {
        out.push_str(" <span class=\"badge bad\">latest visit failed</span>");
    }
    match word {
        Some(w) if w.seen.is_some() => {
            out.push_str(" <span class=\"badge bad\">the owner's word is contradicted</span>");
        }
        Some(w) => write!(
            out,
            " <span class=\"badge good\">{}</span>",
            esc(&w.summary())
        )?,
        None => {}
    }
    let os: BTreeSet<String> = members
        .iter()
        .map(|m| estate.attr(m, "runs_os"))
        .filter(|os| !os.is_empty())
        .collect();
    if !os.is_empty() {
        write!(
            out,
            " · {}",
            esc(&os.into_iter().collect::<Vec<_>>().join(", "))
        )?;
    }
    write!(
        out,
        " <span class=\"muted\">· {}",
        plural(own, "component", "components")
    )?;
    if containers > 0 {
        write!(out, " · {}", plural(containers, "container", "containers"))?;
    }
    if checkouts > 0 {
        write!(out, " · {}", plural(checkouts, "checkout", "checkouts"))?;
    }
    if let Some(at) = read_at {
        write!(out, " · read {}", utc_age(at, now))?;
    }
    out.push_str("</span></summary>\n<div class=\"inner\">\n");
    if !machine.others.is_empty() || !machine.traces.is_empty() {
        out.push_str("<p class=\"muted\">");
        if !machine.others.is_empty() {
            write!(
                out,
                "Also known as <span class=\"mono\">{}</span>. ",
                esc(&machine.others.join(", "))
            )?;
        }
        if !machine.traces.is_empty() {
            write!(out, "Known from {}.", esc(&machine.traces.join(", ")))?;
        }
        out.push_str("</p>\n");
    }
    for member in members {
        let empty = coverage_of(member).is_empty()
            && estate.inside(member).is_empty()
            && !estate.containers.contains_key(member)
            && !estate.checkouts.contains_key(member);
        if !empty {
            machine_body(out, member, estate, coverage_of, now)?;
        }
    }
    out.push_str("</div>\n</details>\n");
    Ok(())
}

/// What was read on one machine entity and what is on it.
fn machine_body<'a>(
    out: &mut String,
    machine: &str,
    estate: &Estate,
    coverage_of: &dyn Fn(&str) -> Vec<&'a Latest>,
    now: i64,
) -> Out {
    let own = estate.inside(machine);
    let containers = estate
        .containers
        .get(machine)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let prefix = format!("checkout:{machine}/");
    let mine: Vec<&String> = estate
        .checkouts
        .get(machine)
        .map(|list| list.iter().collect())
        .unwrap_or_default();

    let kernel = estate.attr(machine, "runs_kernel");
    write!(
        out,
        "<p class=\"muted\"><span class=\"mono\">{}</span>",
        esc(machine)
    )?;
    if !kernel.is_empty() {
        write!(
            out,
            " · kernel <span class=\"mono\">{}</span>",
            esc(&kernel)
        )?;
    }
    out.push_str("</p>\n");

    // What was read here and how completely, so the lists below are read for what they are.
    let all = coverage_of(machine);
    let last = all.iter().filter_map(|r| r.last_full).max();
    let (visits, readings): (Vec<&Latest>, Vec<&Latest>) =
        all.into_iter().partition(|r| r.kind == VISIT);
    // A failed visit is told next to the reading it left as it was.
    if let Some(v) = visits.iter().find(|v| v.completeness == "none") {
        writeln!(
            out,
            "<p class=\"alert\">Last read {}; {}</p>",
            utc_or(last, "never"),
            esc(&crate::sweep::failed_visit(
                v.at,
                v.reason.as_deref().unwrap_or_default()
            ))
        )?;
    }
    if readings.is_empty() {
        out.push_str("<p class=\"alert\">Nothing was ever read on this machine itself.</p>\n");
    } else {
        out.push_str("<ul class=\"readings\">\n");
        for r in readings {
            write!(out, "<li>{} ", esc(&r.kind))?;
            badge(out, &r.completeness, r.reason.as_deref())?;
            if let Some(reason) = &r.reason {
                write!(out, " {}", esc(reason))?;
            }
            writeln!(
                out,
                " <span class=\"muted nowrap\">{}</span></li>",
                utc_age(r.at, now)
            )?;
        }
        out.push_str("</ul>\n");
    }

    components_table(out, estate, own)?;

    if !containers.is_empty() {
        out.push_str("<h3>Containers</h3>\n");
    }
    for container in containers {
        let name = container.rsplit('/').next().unwrap_or(container);
        let inside = estate.inside(container);
        write!(
            out,
            "<details class=\"sub\">\n<summary>{} <span class=\"muted\">· <span class=\"mono\">{}</span> · {}</span></summary>\n",
            esc(name),
            esc(&estate.attr(container, "runs_image")),
            plural(inside.len(), "component", "components")
        )?;
        components_table(out, estate, inside)?;
        out.push_str("</details>\n");
    }

    let (with, without): (Vec<&String>, Vec<&String>) =
        mine.iter().partition(|c| !coverage_of(c).is_empty());
    if !mine.is_empty() {
        out.push_str("<h3>Checkouts</h3>\n");
    }
    for checkout in with {
        let rel = &checkout[prefix.len()..];
        let inside = estate.inside(checkout);
        write!(
            out,
            "<details class=\"sub\">\n<summary><span class=\"mono\">{}</span> <span class=\"muted\">· {}</span>",
            esc(rel),
            plural(inside.len(), "component", "components")
        )?;
        for r in coverage_of(checkout) {
            out.push(' ');
            badge(out, &r.completeness, r.reason.as_deref())?;
        }
        out.push_str("</summary>\n");
        for r in coverage_of(checkout) {
            if let Some(reason) = &r.reason {
                writeln!(
                    out,
                    "<p class=\"alert\">{}: {}</p>",
                    esc(&r.kind),
                    esc(reason)
                )?;
            }
        }
        components_table(out, estate, inside)?;
        out.push_str("</details>\n");
    }
    if !without.is_empty() {
        let names: Vec<String> = without.iter().map(|c| esc(&c[prefix.len()..])).collect();
        writeln!(
            out,
            "<p class=\"muted\">No lockfile found in {}: <span class=\"mono\">{}</span></p>",
            plural(without.len(), "checkout", "checkouts"),
            names.join(", ")
        )?;
    }
    Ok(())
}

/// The threat list: the catalogue's latest reading, its threats newest first with those new
/// in that reading marked, and those that left it. No threat is judged against the estate.
fn threats(conn: &Connection, out: &mut String, now: i64) -> Out {
    out.push_str("<section id=\"threats\">\n<h2>Exploited vulnerabilities</h2>\n");
    // A store made before the threat list has no tables for it until a run opens it.
    let has_tables: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'feed_reading')",
        [],
        |r| r.get(0),
    )?;
    // The latest reading, and the latest one that read the catalogue.
    type Reading = (
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let reading = |outcomes: &str| -> rusqlite::Result<Option<Reading>> {
        if !has_tables {
            return Ok(None);
        }
        conn.query_row(
            &format!(
                "SELECT run_id, outcome, at, reason, raw_path, sha256 FROM feed_reading
                 WHERE source = ?1 AND outcome IN ({outcomes}) ORDER BY id DESC LIMIT 1"
            ),
            [crate::threats::SOURCE],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
    };
    let (latest, good) = (
        reading("'read', 'unchanged', 'failed'")?,
        reading("'read', 'unchanged'")?,
    );
    let Some((_, outcome, at, reason, _, _)) = latest else {
        out.push_str("<p class=\"alert\">The catalogue of exploited vulnerabilities has never been read. Nothing is known about threats.</p>\n</section>\n");
        return Ok(());
    };
    writeln!(
        out,
        "<p class=\"muted\">The CISA catalogue of known exploited vulnerabilities, read whole on every run. Latest reading {}: {}.</p>",
        utc_age(at, now),
        esc(&outcome)
    )?;
    if outcome == "failed" {
        writeln!(
            out,
            "<p class=\"alert\">The latest reading of the catalogue failed: {}. What is new since {} is unknown.</p>",
            esc(reason.as_deref().unwrap_or("no reason given")),
            good.as_ref().map_or("then".to_string(), |g| utc(g.2))
        )?;
    }
    // Threats new in the latest reading that read the catalogue are marked.
    let mut new_in = String::new();
    if let Some((run_id, _, at, _, raw_path, sha256)) = &good {
        new_in = run_id.clone();
        write!(out, "<p class=\"muted\">Last read {}", utc_age(*at, now))?;
        if let Some(path) = raw_path {
            write!(out, ", raw copy <span class=\"mono\">{}</span>", esc(path))?;
        }
        if let Some(hash) = sha256 {
            write!(out, ", SHA-256 <span class=\"mono\">{}</span>", esc(hash))?;
        }
        out.push_str(".</p>\n");
    }
    out.push_str("<p class=\"alert\">None of these is matched against this estate yet: whether any of them affects it is unknown.</p>\n");

    type Threat = (
        String,
        String,
        String,
        String,
        String,
        i64,
        Option<i64>,
        bool,
    );
    let list: Vec<Threat> = conn
        .prepare(
            "SELECT t.id, t.vendor, t.product, t.name, t.date_added, t.first_seen_at, t.gone_at,
                    EXISTS (SELECT 1 FROM journal j WHERE j.entry = 'threat_added'
                              AND j.run_id = ?2 AND j.reader = t.source AND j.subject = t.id)
             FROM threat t WHERE t.source = ?1
             ORDER BY t.date_added DESC, t.id DESC",
        )?
        .query_map(params![crate::threats::SOURCE, new_in], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let (gone, present): (Vec<&Threat>, Vec<&Threat>) = list.iter().partition(|t| t.6.is_some());
    let new = present.iter().filter(|t| t.7).count();
    let table = |out: &mut String, rows: &[&Threat], last: &str| -> Out {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(
            out,
            &[
                "CVE",
                "Vendor",
                "Product",
                "Name",
                "Added to the catalogue",
                last,
            ],
        );
        for (id, vendor, product, name, added, seen, left, is_new) in rows.iter().copied() {
            out.push_str(if *is_new {
                "<tr class=\"added\">"
            } else {
                "<tr>"
            });
            write!(out, "<td class=\"mono\">{}", esc(id))?;
            if *is_new {
                out.push_str(" <span class=\"badge bad\">new</span>");
            }
            out.push_str("</td>");
            td(out, "", vendor)?;
            td(out, "", product)?;
            td(out, "", name)?;
            td(out, "nowrap", added)?;
            td(out, "nowrap", &utc(left.unwrap_or(*seen)))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
        Ok(())
    };
    write!(
        out,
        "<details{}>\n<summary>{} in the catalogue, newest first; {} new when it was last read</summary>\n",
        if new > 0 { " open" } else { "" },
        plural(
            present.len(),
            "exploited vulnerability",
            "exploited vulnerabilities"
        ),
        new
    )?;
    table(out, &present, "First seen here")?;
    out.push_str("</details>\n");
    if !gone.is_empty() {
        write!(
            out,
            "<details>\n<summary>{} left the catalogue and {} kept</summary>\n",
            plural(gone.len(), "threat", "threats"),
            if gone.len() == 1 { "is" } else { "are" }
        )?;
        table(out, &gone, "Left the catalogue")?;
        out.push_str("</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

fn changes(conn: &Connection, out: &mut String) -> Out {
    write!(
        out,
        "<section id=\"changes\">\n<h2>Changes</h2>\n<p class=\"muted\">The last {RUNS_SHOWN} runs, newest first.</p>\n"
    )?;
    let mut runs_stmt = conn.prepare(
        "SELECT run_id, MIN(at),
                MAX(entry = 'run_finished'),
                MAX(CASE WHEN entry = 'report' THEN text END)
         FROM journal WHERE entry NOT IN ('owner_said', 'owner_withdrew')
         GROUP BY run_id ORDER BY MAX(seq) DESC LIMIT ?1",
    )?;
    let runs: Vec<(String, i64, bool, Option<String>)> = runs_stmt
        .query_map([RUNS_SHOWN], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if runs.is_empty() {
        out.push_str("<p>No runs yet.</p>\n");
    }

    let mut events_stmt = conn.prepare(
        "SELECT entry, subject, predicate, old_value, new_value FROM journal
         WHERE run_id = ?1 AND entry IN ('added', 'changed', 'removed') ORDER BY seq",
    )?;
    // Whether a partial reading ever made an assertion: one that never did has nothing
    // that could be removed, so removals there are not unknown.
    let mut not_full_stmt = conn.prepare(
        "SELECT scope, kind, completeness, reason,
                EXISTS (SELECT 1 FROM assertion a WHERE a.layer IN ('live', 'retracted')
                          AND a.reader = c.reader AND a.scope = c.scope AND a.kind = c.kind)
         FROM coverage c
         WHERE run_id = ?1 AND completeness != 'full'
         ORDER BY completeness, scope, kind",
    )?;
    // Scopes read before this run and not read by it: nothing is known about them.
    let mut not_repeated_stmt = conn.prepare(
        "SELECT COUNT(*) FROM (SELECT DISTINCT reader, scope, kind FROM coverage
         WHERE id < (SELECT MIN(id) FROM coverage WHERE run_id = ?1)
           AND scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
           AND scope NOT IN (SELECT id FROM gone_entity))",
    )?;
    for (i, (run_id, at, finished, report)) in runs.iter().enumerate() {
        type Event = (String, String, String, Option<String>, Option<String>);
        let events: Vec<Event> = events_stmt
            .query_map([run_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let not_full: Vec<(String, String, String, Option<String>, bool)> = not_full_stmt
            .query_map([run_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let not_repeated: i64 = not_repeated_stmt.query_row([run_id], |r| r.get(0))?;
        let partial = not_full.iter().any(|r| r.2 == "partial" && r.4);
        let nothing = not_repeated > 0 || not_full.iter().any(|r| r.2 == "none");

        // Counts things, not assertions, as the report does.
        let count = |kind: &str| {
            events
                .iter()
                .filter(|e| e.0 == kind)
                .map(|e| e.1.as_str())
                .collect::<BTreeSet<_>>()
                .len()
        };
        // No events is "no changes" only when the run finished, read everything in full
        // and read again every scope read before.
        let counts = format!(
            "+{} added, {} changed, {} removed",
            count("added"),
            count("changed"),
            count("removed")
        );
        let mut unknown = Vec::new();
        if partial {
            unknown.push("removals unknown where a reading was partial");
        }
        if nothing {
            unknown.push("changes unknown where nothing was read");
        }
        let summary = if !finished {
            "did not finish, changes unknown".to_string()
        } else if !unknown.is_empty() {
            format!("{counts}; {}", unknown.join(", "))
        } else if !events.is_empty() {
            counts
        } else {
            "no changes".to_string()
        };

        write!(
            out,
            "<details{}>\n<summary><span class=\"nowrap\">{}</span> · {}</summary>\n",
            if i == 0 && events.len() <= EVENTS_SHOWN_OPEN {
                " open"
            } else {
                ""
            },
            utc(*at),
            esc(&summary)
        )?;
        if let Some(report) = report {
            writeln!(out, "<p class=\"muted mono\">{}</p>", esc(report))?;
        }
        if not_repeated > 0 {
            writeln!(
                out,
                "<p class=\"alert\">{} read before were not read in this run.</p>",
                plural(not_repeated as usize, "reading", "readings")
            )?;
        }
        if !not_full.is_empty() {
            out.push_str("<ul class=\"readings\">\n");
            for (scope, kind, completeness, reason, _) in &not_full {
                write!(
                    out,
                    "<li><span class=\"mono\">{}</span> · {} ",
                    esc(scope),
                    esc(kind)
                )?;
                badge(out, completeness, reason.as_deref())?;
                writeln!(
                    out,
                    " {}</li>",
                    esc(reason.as_deref().unwrap_or("no reason given"))
                )?;
            }
            out.push_str("</ul>\n");
        }
        if !events.is_empty() {
            out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
            thead(out, &["Change", "Component", "Where", "What", "Value"]);
            for (entry, subject, predicate, old, new) in &events {
                write!(out, "<tr class=\"{}\">", esc(entry))?;
                td(out, "", entry)?;
                td_component(out, subject)?;
                td(out, "mono", component_place(subject))?;
                td(out, "", what(predicate))?;
                let value = match (old, new) {
                    (Some(o), Some(n)) => format!("{o} → {n}"),
                    (Some(v), None) | (None, Some(v)) => v.clone(),
                    (None, None) => String::new(),
                };
                td(out, "mono", &value)?;
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table></div>\n");
        }
        out.push_str("</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

fn retracted(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"gone\">\n<h2>No longer there</h2>\n");
    type Row = (String, String, String, String, i64, Option<i64>, String);
    let rows: Vec<Row> = conn
        .prepare(
            "SELECT subject, predicate, object, reader, observed_at, retracted_at, source_ref
             FROM assertion WHERE layer = 'retracted'
             ORDER BY retracted_at DESC, subject, predicate, object",
        )?
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        out.push_str("<p>Nothing has disappeared yet.</p>\n</section>\n");
        return Ok(());
    }
    write!(
        out,
        "<details>\n<summary>{} statements no longer made, newest first</summary>\n",
        rows.len()
    )?;
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    thead(
        out,
        &[
            "Component",
            "Where",
            "What",
            "Value",
            "Reader",
            "First seen",
            "Gone since",
            "Source",
        ],
    );
    for (subject, predicate, object, reader, seen, gone, source) in &rows {
        out.push_str("<tr>");
        td_component(out, subject)?;
        td(out, "mono", component_place(subject))?;
        td(out, "", what(predicate))?;
        td(out, "mono", object)?;
        td(out, "", reader)?;
        td(out, "nowrap", &utc(*seen))?;
        td(out, "nowrap", &utc_or(*gone, ""))?;
        td(out, "mono", source)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</details>\n</section>\n");
    Ok(())
}

fn vocabulary(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"vocabulary\">\n<h2>Vocabulary</h2>\n<details>\n");
    out.push_str("<summary>The words the store uses: kinds of things, links between them, what readings look for and how a source knows</summary>\n");
    let tables: [(&str, &[&str], &str); 4] = [
        (
            "Kinds of things",
            &["Name", "Status"],
            "SELECT name, status FROM entity_type ORDER BY status = 'reserved', name",
        ),
        (
            "Links",
            &["Name", "Points to", "Status"],
            "SELECT name, COALESCE(object_kind, ''), status FROM predicate
             ORDER BY status = 'reserved', name",
        ),
        (
            "What readings look for",
            &["Name"],
            "SELECT name FROM coverage_kind ORDER BY name",
        ),
        (
            "Basis, strongest first",
            &["Name", "Strength"],
            "SELECT name, CAST(strength AS TEXT) FROM basis_kind ORDER BY strength",
        ),
    ];
    for (title, columns, sql) in tables {
        write!(
            out,
            "<h3>{title}</h3>\n<div class=\"scroll\"><table class=\"dense\">\n"
        )?;
        thead(out, columns);
        let mut stmt = conn.prepare(sql)?;
        let n = stmt.column_count();
        let rows = stmt.query_map([], |r| {
            (0..n)
                .map(|i| r.get::<_, String>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for row in rows {
            out.push_str("<tr>");
            for cell in row? {
                td(out, "", &cell)?;
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</details>\n</section>\n");
    Ok(())
}

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>What the store holds</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --fg: #1d1d1f; --muted: #5c5f66; --line: #e2e2df; --head: #f2f2ef;
  --bad-bg: #fdeceb; --bad-fg: #a3120a; --ok-bg: #e7f3ea; --ok-fg: #1b6331;
  --added: #1b6331; --removed: #a3120a; --changed: #8a4b00;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #151517; --fg: #e9e9e7; --muted: #a2a3a8; --line: #2f2f34; --head: #1f1f23;
    --bad-bg: #3b1714; --bad-fg: #ffb3a8; --ok-bg: #15301d; --ok-fg: #94d6a5;
    --added: #94d6a5; --removed: #ffb3a8; --changed: #f2c27b;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 76rem; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 1.4rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 40px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: .95rem; margin: 16px 0 6px; }
p { margin: 8px 0; }
.meta { color: var(--muted); font-size: .875rem; margin: 0; overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; margin: 6px 0; }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--head); font-weight: 600; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
table.dense th, table.dense td { padding: 3px 10px; }
td.mono { overflow-wrap: normal; white-space: nowrap; }
tr.bad td { background: var(--bad-bg); }
tr.added td:first-child { color: var(--added); }
tr.removed td:first-child { color: var(--removed); }
tr.changed td:first-child { color: var(--changed); }
.badge { display: inline-block; padding: 0 8px; border-radius: 999px; font-weight: 600; font-size: .8rem; white-space: nowrap; }
.badge.good { background: var(--ok-bg); color: var(--ok-fg); }
.badge.bad { background: var(--bad-fg); color: var(--bg); }
.alert { background: var(--bad-bg); color: var(--bad-fg); border-left: 4px solid var(--bad-fg);
  padding: 8px 12px; border-radius: 4px; font-weight: 600; overflow-wrap: anywhere; }
.ok { background: var(--ok-bg); color: var(--ok-fg); border-left: 4px solid var(--ok-fg);
  padding: 8px 12px; border-radius: 4px; }
details { margin: 8px 0; }
summary { cursor: pointer; padding: 4px 0; overflow-wrap: anywhere; }
details.machine { border-top: 1px solid var(--line); margin: 0; padding: 4px 0; }
details.machine > .inner { padding: 0 0 8px 12px; }
details.sub { margin: 4px 0; }
details.sub > :not(summary) { margin-left: 0; }
ul.readings { margin: 6px 0; padding-left: 18px; font-size: .875rem; }
ul.readings li { margin: 2px 0; overflow-wrap: anywhere; }
</style>
</head>
<body>
<main>
"#;

#[cfg(test)]
mod tests {
    use super::{esc, shown, utc};

    #[test]
    fn every_character_that_could_reorder_or_hide_text_is_shown_escaped() {
        // A name from a source is partly written by an attacker. Printed raw, a direction
        // control reorders the rest of the line and an invisible character hides text.
        let hidden = [
            '\u{0}',
            '\u{9}',
            '\u{A}',
            '\u{1B}',
            '\u{7F}',
            '\u{85}',
            '\u{9F}',
            '\u{AD}',
            '\u{600}',
            '\u{605}',
            '\u{61C}',
            '\u{6DD}',
            '\u{70F}',
            '\u{890}',
            '\u{891}',
            '\u{8E2}',
            '\u{180E}',
            '\u{200B}',
            '\u{200F}',
            '\u{2028}',
            '\u{202E}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{206F}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1BCA0}',
            '\u{1BCA3}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
        ];
        for c in hidden {
            let escaped: String = c.escape_unicode().collect();
            let text = format!("a{c}b");
            assert_eq!(shown(&text), format!("a{escaped}b"), "{escaped}");
            assert_eq!(esc(&text), format!("a{escaped}b"), "{escaped}");
        }
        // Everything else is shown as it is, names in any script included.
        let plain = "web-1 сервер 東京 café ✓ \u{2027}\u{2030}\u{FFFC}";
        assert_eq!(shown(plain), plain);
        assert_eq!(esc(plain), plain);
    }

    #[test]
    fn times_are_shown_as_utc_calendar_dates() {
        // The owner reads every time on the page; a wrong date misleads silently.
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc(1_731_196_800), "2024-11-10 00:00 UTC");
        assert_eq!(utc(4_107_542_340), "2100-02-28 23:59 UTC");
    }
}
