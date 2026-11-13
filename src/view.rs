//! The view: a small summary page that answers what the app answers, and pages of details
//! next to it with the big tables. It only reads. Nothing from the network: plain HTML,
//! `<details>` and inline CSS. One script, fixed in the program and named by one fixed tag,
//! keeps the numbers of "As it happens" fresh while the summary is open (`happens.rs`); no
//! other page has one, and nothing from the store ever becomes script.
//!
//! Invariant: every piece of text that comes from the store goes through `esc`
//! before it enters the page. Names, versions, reasons and source references are
//! partly written by an attacker and must never become markup.

use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

use crate::servers::VISIT;

/// The runs the changes page lists (`store::listed_runs`).
const RUNS_SHOWN: i64 = crate::store::RUNS_KEPT;
/// The most kinds of watched places a watcher's reading is named by on the changes page.
const KINDS_NAMED: usize = 3;
/// The latest run is shown open only when its changes fit on a screen or a few.
const EVENTS_SHOWN_OPEN: usize = 500;

pub type Out = Result<(), Box<dyn Error>>;

/// The summary page, in the store's folder.
pub const SUMMARY: &str = "view.html";

/// The folder next to the summary page that holds the pages of details.
pub const DETAILS: &str = "view";

/// What the pages were made from and when, written after them, relative to the store's folder.
pub const MADE: &str = "view/made.json";

/// How long pages stand as current while nothing in their basis moved, in seconds. What
/// changes with time alone, such as an answer that expires or how old the last check is, is
/// shown at most this late; every page says when it was made.
pub const CURRENT_FOR: i64 = 3600;

/// What the pages rest on that changes without the clock: the journal's latest entry (every
/// change, finding raised or answered, owner's word, run and reading of threat data), what
/// each latest reading covered, the watcher that holds the store and what failed in it, and
/// the program that writes the pages. Equal bases make the same pages, but for the time
/// they were made, the latest sample's counts, and what the event level records, which pages
/// show with their time. What the event level records has a basis of its own,
/// `events::basis`, kept beside this one in `MADE`: when only it moved, the pages that show it
/// are written again (`event_pages`). Cheap: a lookup by key, the latest readings and a lock.
pub fn basis(conn: &Connection, folder: &std::path::Path) -> Result<String, Box<dyn Error>> {
    use std::hash::{Hash, Hasher};
    let journal: i64 = conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM journal", [], |r| {
        r.get(0)
    })?;
    // A reading's time and id are new at every reading; what it covered is not.
    let mut covered = std::collections::hash_map::DefaultHasher::new();
    for l in latest_coverage(conn)? {
        (l.reader, l.scope, l.kind, l.completeness, l.reason, l.cause).hash(&mut covered);
    }
    let watcher = crate::watch::basis(conn, folder)?;
    let program = std::env::current_exe()?;
    let meta = std::fs::metadata(&program)?;
    Ok(format!(
        "journal {journal}; covered {:016x}; watcher {watcher}; program {} {} {:?}",
        covered.finish(),
        program.display(),
        meta.len(),
        meta.modified()?
    ))
}

/// Every page the view writes, as its path relative to the store's folder and its HTML: the
/// summary first, then the pages its links lead a person to (`pages.rs`), then one technical
/// page for each of the big tables. The summary is built from the state and the
/// machine-readable result `immune status --json` gives, so the two say the same; the technical
/// pages are what the store holds, reached from one line at the bottom of the summary.
pub fn pages(
    conn: &Connection,
    st: &crate::status::State,
    result: &serde_json::Value,
    store: &str,
    now: i64,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let latest = latest_coverage(conn)?;
    let mut pages = vec![
        (
            SUMMARY.to_string(),
            crate::pages::summary(conn, st, result, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::THIS_MAC),
            crate::pages::this_mac(conn, st, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::BEYOND),
            crate::pages::beyond(conn, &latest, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::TECHNICAL),
            crate::pages::technical(),
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::VULNERABILITIES),
            crate::pages::vulnerabilities(conn, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::THREAT_DATA),
            crate::pages::threat_data(conn, result, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::RULES),
            crate::pages::rules(result, st.event_level.as_ref(), now),
        ),
    ];
    for (name, title) in DETAIL_PAGES {
        let mut body = String::new();
        match name {
            "coverage" => coverage(conn, &mut body, &latest, now)?,
            "machines" => machines(conn, &mut body, &latest, now)?,
            "watched" => watched(conn, &mut body, &latest, now)?,
            "changes" => changes(conn, &mut body)?,
            "gone" => retracted(conn, &mut body)?,
            _ => vocabulary(conn, &mut body)?,
        }
        let mut out = head(title);
        out.push_str(
            "<nav class=\"meta\"><a href=\"../view.html\">← What needs a look</a></nav>\n",
        );
        header(conn, &mut out, store, now)?;
        out.push_str(&body);
        out.push_str(FOOT);
        pages.push((format!("{DETAILS}/{name}.html"), out));
    }
    for (anchor, title) in SECTIONS {
        pages.push((section_file(anchor), section_page(anchor, title)));
    }
    Ok(pages)
}

/// The pages that show what the event level counts, as `pages` makes them: the summary and the
/// page of rules. When only `events::basis` moved since the pages were made, these alone are
/// written again.
pub fn event_pages(
    conn: &Connection,
    st: &crate::status::State,
    result: &serde_json::Value,
    now: i64,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    Ok(vec![
        (
            SUMMARY.to_string(),
            crate::pages::summary(conn, st, result, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::RULES),
            crate::pages::rules(result, st.event_level.as_ref(), now),
        ),
    ])
}

/// The sections of the summary something outside the page may ask for, by anchor and
/// title. Each has a page of its own that only sends the browser on to it, because macOS
/// can lose the `#section` of a file URL when it hands one to the browser.
pub const SECTIONS: [(&str, &str); 6] = [
    (
        "watched-here",
        "What is watched, and what you are told about",
    ),
    (
        "vulnerabilities",
        "Known vulnerabilities in packages your projects use",
    ),
    ("you-can-fix", "You can fix"),
    ("limits", "Limits of this version"),
    ("answered", "Answered"),
    ("as-it-happens", "As it happens"),
];

/// Where a section's own page is, relative to the store's folder.
pub fn section_file(anchor: &str) -> String {
    format!("{DETAILS}/section-{anchor}.html")
}

/// The files of the sections for a store, as anchor and absolute path: what
/// `immune status --json` names so that nothing outside builds these paths.
pub fn section_files(store: &std::path::Path) -> Vec<(&'static str, std::path::PathBuf)> {
    let folder = store.parent().unwrap_or(std::path::Path::new("."));
    SECTIONS
        .iter()
        .map(|(anchor, _)| (*anchor, folder.join(section_file(anchor))))
        .collect()
}

/// A page that only sends the browser on to the summary at one section, with a plain link
/// for a browser that does not follow the refresh. No script.
fn section_page(anchor: &str, title: &str) -> String {
    let target = format!("../{SUMMARY}#{}", esc(anchor));
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"refresh\" content=\"0; url={target}\">\n<title>{title}</title>\n\
         </head>\n<body>\n<p><a href=\"{target}\">{title}</a></p>\n</body>\n</html>\n",
        title = esc(title)
    )
}

/// The pages of details, by file name and title.
pub const DETAIL_PAGES: [(&str, &str); 6] = [
    ("coverage", "What was read and how completely"),
    ("machines", "Machines"),
    ("watched", "Watched places"),
    ("changes", "Changes"),
    ("gone", "No longer there"),
    ("vocabulary", "Vocabulary"),
];

pub const FOOT: &str = "</main>\n</body>\n</html>\n";

pub fn head(title: &str) -> String {
    HEAD.replace(
        "<title>What the store holds</title>",
        &format!("<title>{}</title>", esc(title)),
    )
}

/// `15,617 components`.
pub fn counted(n: i64, one: &str, many: &str) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("{out} {}", if n == 1 { one } else { many })
}

/// One thing that needs a look, as a card: urgent or not, where, its title and what it means
/// first; then, behind Details, what the source says, what to do, when, how bad and how sure,
/// and the command that reads it.
pub fn item(out: &mut String, i: &crate::findings::Item) -> Out {
    let urgent = crate::findings::urgent(i.severity, i.confidence);
    writeln!(
        out,
        "<article class=\"item card {}{}\" id=\"{}\">",
        esc(i.severity),
        if urgent { " urgent" } else { "" },
        esc(&i.id)
    )?;
    out.push_str("<p class=\"top\">");
    if urgent {
        out.push_str("<span class=\"pill\">Urgent</span> ");
    }
    if let Some(place) = &i.place {
        write!(out, "<span class=\"where mono\">{}</span>", esc(place))?;
    }
    writeln!(
        out,
        "</p>\n<h3>{}</h3>\n<p>{}</p>",
        esc(i.words.title),
        esc(i.words.meaning)
    )?;
    // What the response layer said: the core's words, then for its own finding the reason that
    // raised it, whole, in an element of its own, which nothing in the text can close.
    if let Some(s) = &i.verdicts {
        writeln!(
            out,
            "<p class=\"verdict\">{}</p>",
            esc(&crate::verdict::said(s))
        )?;
        if let Some(o) = &s.opening {
            writeln!(
                out,
                "<blockquote class=\"sent\">{}</blockquote>",
                esc(&shown(&o.reason))
            )?;
        }
    }
    out.push_str("<details>\n<summary>Details</summary>\n");
    if let Some(value) = &i.value {
        writeln!(out, "<p class=\"said\">{}</p>", esc(value))?;
    }
    writeln!(out, "<p class=\"advice\">{}</p>", esc(i.words.advice))?;
    let mut facts = Vec::new();
    match (i.first_seen, i.last_seen) {
        (Some(f), Some(l)) if f != l => {
            facts.push(format!("first seen {}, last seen {}", utc(f), utc(l)));
        }
        (_, Some(l)) => facts.push(format!("seen {}", utc(l))),
        _ => {}
    }
    if let Some(change) = &i.change {
        facts.push(format!("latest change: {change}"));
    }
    if let Some(a) = &i.answer {
        let mut said = match a.until {
            Some(u) => format!("expected until {}", utc(u)),
            None => format!("seen {}", utc(a.at)),
        };
        said.push_str(&format!(" {}", given_by(a.via)));
        if let Some(reason) = &a.reason {
            said.push_str(&format!(": {reason}"));
        }
        facts.push(said);
    }
    facts.push(format!(
        "how bad: {}{}",
        i.severity,
        i.confidence
            .map(|c| format!(", how sure: {c}"))
            .unwrap_or_default()
    ));
    if let Some(t) = i.technique {
        facts.push(format!("ATT&CK {t}"));
    }
    let command = if i.rule.is_some() {
        format!("immune finding {}", i.id)
    } else {
        "immune status".to_string()
    };
    writeln!(
        out,
        "<p class=\"meta\">{} · <span class=\"mono\">{}</span></p>\n</details>\n</article>",
        esc(&facts.join(" · ")),
        esc(&command)
    )?;
    Ok(())
}

/// Who gave an answer, as the owner reads it after the answer.
pub fn given_by(via: crate::findings::Via) -> &'static str {
    match via {
        crate::findings::Via::App => "in the app",
        crate::findings::Via::Agent => "through your agent",
        crate::findings::Via::Command => "from the command line",
        crate::findings::Via::Unknown => "given before this version recorded who",
    }
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
            c if crate::icu::hidden(c) => out.extend(c.escape_unicode()),
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
        if crate::icu::hidden(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// UTC seconds as `YYYY-MM-DD HH:MM UTC`.
pub fn utc(secs: i64) -> String {
    let (date, rest) = civil(secs);
    format!("{date} {:02}:{:02} UTC", rest / 3600, rest % 3600 / 60)
}

/// UTC seconds as ISO 8601 in UTC, `YYYY-MM-DDTHH:MM:SSZ`, for the machine-readable form.
pub fn iso(secs: i64) -> String {
    let (date, rest) = civil(secs);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The date `YYYY-MM-DD` and the seconds into that day, from the civil-from-days algorithm.
fn civil(secs: i64) -> (String, i64) {
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
    (format!("{year:04}-{month:02}-{day:02}"), rest)
}

pub fn utc_or(secs: Option<i64>, missing: &str) -> String {
    secs.map(utc).unwrap_or_else(|| missing.to_string())
}

/// Place, ecosystem and name from `component:<place>/<ecosystem>/<name>`. The place is
/// an entity id and may hold slashes; a scoped npm name (`@scope/name`) holds one too, and
/// a Homebrew name from a tap other than core, `<user>/<tap>/<name>`, holds two.
fn split_component(id: &str) -> Option<(&str, &str, &str)> {
    let rest = id.strip_prefix("component:")?;
    let (head, name) = rest.rsplit_once('/')?;
    let (place, ecosystem) = head.rsplit_once('/')?;
    let whole = |place: &'_ str, ecosystem: &'_ str| &rest[place.len() + ecosystem.len() + 2..];
    if ecosystem.starts_with('@') {
        let (place, ecosystem) = place.rsplit_once('/')?;
        return Some((place, ecosystem, whole(place, ecosystem)));
    }
    if let Some((tapped, _user)) = place.rsplit_once('/')
        && let Some((place, ecosystem)) = tapped.rsplit_once('/')
        && matches!(ecosystem, "brew" | "brew-cask")
    {
        return Some((place, ecosystem, whole(place, ecosystem)));
    }
    Some((place, ecosystem, name))
}

/// Ecosystem and name of a component, or no ecosystem and the whole id for anything else.
pub fn component_name(id: &str) -> (&str, &str) {
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
        "runs_platform" => "system, as the private network names it",
        "runs_kernel" => "kernel",
        "runs_image" => "image",
        "known_as" => "known as",
        "same_as" => "same machine as",
        other => other,
    }
}

/// A table cell with escaped text and an optional class.
pub fn td(out: &mut String, class: &str, text: &str) -> Out {
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

pub fn thead(out: &mut String, columns: &[&str]) {
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
pub struct Latest {
    pub reader: String,
    pub scope: String,
    pub kind: String,
    pub completeness: String,
    pub reason: Option<String>,
    /// Why it is incomplete, as `coverage.cause` holds it; `None` on a full reading and on
    /// a reading written before causes were kept.
    pub cause: Option<String>,
    pub at: i64,
    pub last_full: Option<i64>,
}

/// The latest record for each reader, scope and kind, and its latest full one.
/// Readings that are not full come first. Readings inside a container or checkout that
/// is gone no longer count and are left out. `immune status` counts coverage from this too.
pub fn latest_coverage(conn: &Connection) -> rusqlite::Result<Vec<Latest>> {
    // A store opened read-only may predate the column: its readings have no cause.
    let has_cause: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('coverage') WHERE name = 'cause')",
        [],
        |r| r.get(0),
    )?;
    let cause = if has_cause { "c.cause" } else { "NULL" };
    conn.prepare(&format!(
        "{latest}
         SELECT c.reader, c.scope, c.kind, c.completeness, c.reason, c.observed_at,
                (SELECT MAX(f.observed_at) FROM coverage f
                 WHERE f.reader = c.reader AND f.scope = c.scope AND f.kind = c.kind
                   AND f.completeness = 'full'),
                {cause}
         FROM latest c
         WHERE c.scope NOT IN (SELECT id FROM gone_entity)
         ORDER BY c.completeness = 'full', c.completeness, c.reader, c.scope, c.kind",
        latest = crate::store::LATEST
    ))?
    .query_map([], |r| {
        Ok(Latest {
            reader: r.get(0)?,
            scope: r.get(1)?,
            kind: r.get(2)?,
            completeness: r.get(3)?,
            reason: r.get(4)?,
            at: r.get(5)?,
            last_full: r.get(6)?,
            cause: r.get(7)?,
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
    // The content of each watched file and the hooks of each checkout are readings of their
    // own; those read in full are shown under watched places, not here.
    let per_thing = [crate::watched::CONTENT, crate::watched::HOOK_KIND];
    let rows: Vec<&Latest> = rows
        .iter()
        .filter(|r| !per_thing.contains(&r.kind.as_str()) || r.completeness != "full")
        .collect();
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
    /// The source package and version it was built from, where the reader knows them.
    built_from: BTreeSet<String>,
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
                "built_from" => {
                    c.built_from.insert(object);
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
            "Built from",
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
        td(out, "mono", &join(&c.built_from))?;
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
        .map(|m| match estate.attr(m, "runs_os") {
            os if os.is_empty() => estate.attr(m, "runs_platform"),
            os => os,
        })
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
    let release = estate.attr(machine, "runs_release");
    if !release.is_empty() {
        write!(
            out,
            " · release <span class=\"mono\">{}</span>",
            esc(&release)
        )?;
        let codename = estate.attr(machine, "release_codename");
        if !codename.is_empty() {
            write!(out, " ({})", esc(&codename))?;
        }
    }
    if !kernel.is_empty() {
        write!(
            out,
            " · kernel <span class=\"mono\">{}</span>",
            esc(&kernel)
        )?;
    }
    let package = estate.attr(machine, "runs_kernel_package");
    if !package.is_empty() {
        write!(
            out,
            " from package <span class=\"mono\">{}</span>",
            esc(&package)
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

    // The hooks of a checkout are shown under watched places.
    let (with, without): (Vec<&String>, Vec<&String>) = mine.iter().partition(|c| {
        coverage_of(c)
            .iter()
            .any(|r| r.reader != crate::watched::READER)
    });
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

/// One watched file as the view shows it.
#[derive(Default)]
struct WatchedFile {
    first_seen: i64,
    content: String,
    link: String,
    /// When the current content or link target was first seen.
    content_since: i64,
}

/// Watched files whose content or link target was ever replaced.
fn watched_changed(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer = 'retracted' AND reader = ?1 AND predicate IN ('has_content', 'links_to')",
    )?
    .query_map([crate::watched::READER], |r| r.get(0))?
    .collect()
}

/// Watched places: per kind, each file with when it was first seen and when its content last
/// changed, and the coverage of each reading. Only checksums are in the store, never content.
fn watched(conn: &Connection, out: &mut String, latest: &[Latest], now: i64) -> Out {
    use crate::watched::READER;
    out.push_str("<section id=\"watched\">\n<h2>Watched places</h2>\n");
    out.push_str("<p class=\"muted\">Places where persistence lives. Each file is kept as a checksum of its content, never the content.</p>\n");
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object, observed_at FROM assertion
         WHERE layer = 'live' AND reader = ?1 ORDER BY subject, observed_at",
    )?;
    let rows = stmt.query_map([READER], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
        ))
    })?;
    // Kind -> file id -> what is known of it.
    let mut files: BTreeMap<String, BTreeMap<String, WatchedFile>> = BTreeMap::new();
    let mut kind_of: BTreeMap<String, String> = BTreeMap::new();
    let mut facts = Vec::new();
    for row in rows {
        let (subject, predicate, object, at) = row?;
        if predicate == "watched_as" {
            kind_of.insert(subject.clone(), object.clone());
            files
                .entry(object)
                .or_default()
                .entry(subject)
                .or_default()
                .first_seen = at;
        } else {
            facts.push((subject, predicate, object, at));
        }
    }
    for (subject, predicate, object, at) in facts {
        let Some(f) = kind_of
            .get(&subject)
            .and_then(|k| files.get_mut(k))
            .and_then(|m| m.get_mut(&subject))
        else {
            continue;
        };
        match predicate.as_str() {
            "has_content" => f.content = object,
            "links_to" => f.link = object,
            _ => continue,
        }
        // Rows come oldest first: the last is when the current content was first seen.
        f.content_since = at;
    }
    let changed = watched_changed(conn)?;
    let now_known = crate::watched::content_now(conn)?;
    let read_by_us: Vec<&Latest> = latest.iter().filter(|r| r.reader == READER).collect();
    for (watched_as, kind) in crate::watched::kinds() {
        let readings: Vec<&&Latest> = read_by_us.iter().filter(|r| r.kind == kind).collect();
        let of_kind = files.remove(watched_as).unwrap_or_default();
        writeln!(
            out,
            "<h3>{} <span class=\"muted\">· {}</span></h3>",
            esc(kind),
            plural(of_kind.len(), "file", "files")
        )?;
        out.push_str("<ul class=\"readings\">\n");
        // One reading per checkout: those read in full are counted, the rest are listed.
        let (listed, full): (Vec<&&Latest>, Vec<&&Latest>) = readings
            .iter()
            .partition(|r| kind != crate::watched::HOOK_KIND || r.completeness != "full");
        if !full.is_empty() {
            writeln!(
                out,
                "<li>{} read in full</li>",
                plural(full.len(), "checkout", "checkouts")
            )?;
        }
        for r in listed {
            write!(out, "<li><span class=\"mono\">{}</span> ", esc(&r.scope))?;
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
        if of_kind.is_empty() {
            continue;
        }
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(
            out,
            &[
                "Path",
                "Content",
                "Link to",
                "First seen",
                "Content last changed",
                "Latest reading of its content",
            ],
        );
        for (id, f) in &of_kind {
            let path = id
                .strip_prefix("file:")
                .and_then(|rest| rest.split_once('/'))
                .map_or(id.as_str(), |(_, path)| path);
            write!(
                out,
                "<tr><td class=\"mono\" title=\"{}\">{}</td>",
                esc(id),
                esc(path)
            )?;
            td(out, "mono", &f.content)?;
            td(out, "mono", &f.link)?;
            td(out, "nowrap", &utc(f.first_seen))?;
            // Never "unchanged" where the content is not compared: what the latest check did
            // not read in full, a folder watched only for whether it is there, and content no
            // reading read.
            let now = now_known.get(id).filter(|n| !n.read());
            let (class, last) = if let Some(n) = now {
                ("", n.not_read())
            } else if f.content.starts_with(crate::watched::NOT_A_FILE) {
                ("", crate::watched::PRESENCE_ONLY.to_string())
            } else if changed.contains(id) {
                ("nowrap", utc(f.content_since))
            } else if f.content.is_empty() && f.link.is_empty() {
                ("", crate::watched::NEVER_READ.to_string())
            } else {
                ("nowrap", "not since first seen".to_string())
            };
            td(out, class, &last)?;
            // The latest reading that speaks of it, never an earlier one.
            out.push_str("<td>");
            if let Some(n) = now_known.get(id) {
                badge(out, &n.completeness, None)?;
                if let Some(reason) = &n.reason {
                    write!(out, " {}", esc(reason))?;
                }
            }
            out.push_str("</td></tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

/// What the list of vulnerabilities used in attacks is, why it is short, and what the program
/// does with it, in words a person without security training follows.
pub const CATALOGUE_IS: &str = "A list kept by CISA, a US government agency, of vulnerabilities that attackers are known to have used in real attacks. It is short because most published vulnerabilities are never seen used in one. When a package your projects use has one of them, the program shows it as something that needs a look.";

/// The list of vulnerabilities used in real attacks, as one source of threat data: what it is,
/// how many it holds, when it was read and whether it is current, what it is compared with, and,
/// closed, the list itself newest first with those new in the latest reading marked, and those
/// that left it. No threat is judged against the estate.
pub fn catalogue(conn: &Connection, out: &mut String, now: i64) -> Out {
    writeln!(
        out,
        "<section id=\"threats\">\n<h2>Vulnerabilities used in real attacks</h2>\n<p>{}</p>",
        esc(CATALOGUE_IS)
    )?;
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
    let Some((_, outcome, _, reason, _, _)) = latest else {
        out.push_str("<p class=\"quiet\">This list has never been read, so which vulnerabilities attackers use is not known here, and nothing is compared with it.</p>\n</section>\n");
        return Ok(());
    };
    // Threats new in the latest reading that read the catalogue are marked.
    let new_in = good.as_ref().map(|g| g.0.clone()).unwrap_or_default();
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
    // How many it holds, when it was read, and whether that is current.
    match &good {
        Some((_, _, at, ..)) => writeln!(
            out,
            "<p class=\"facts\"><strong>{}</strong> on the list · last read {}{}</p>",
            counted(present.len() as i64, "", "").trim_end(),
            utc_age(*at, now),
            if outcome == "failed" {
                ""
            } else {
                " · current"
            }
        )?,
        None => out.push_str("<p class=\"quiet\">Never read in full, so which vulnerabilities attackers use is not known here.</p>\n"),
    }
    if outcome == "failed" {
        writeln!(
            out,
            "<p class=\"quiet\">Not current. The latest reading of the catalogue failed: {}. What is new since {} is unknown.</p>",
            esc(reason.as_deref().unwrap_or("no reason given")),
            good.as_ref().map_or("then".to_string(), |g| utc(g.2))
        )?;
    }
    writeln!(
        out,
        "<p>These are {}.</p>",
        esc(&crate::vulnerabilities::catalogue_said(
            &crate::vulnerabilities::catalogue_compared(conn)?
        ))
    )?;
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
    if good.is_some() {
        write!(
            out,
            "<details>\n<summary>The list: {}, newest first; {} new when it was last read</summary>\n",
            plural(
                present.len(),
                "vulnerability used in attacks",
                "vulnerabilities used in attacks"
            ),
            new
        )?;
        table(out, &present, "First seen here")?;
        out.push_str("</details>\n");
    }
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
    // The copy that was read, for a closer look.
    if let Some((_, _, _, _, raw_path, sha256)) = &good {
        let mut kept = Vec::new();
        if let Some(path) = raw_path {
            kept.push(format!(
                "copy kept at <span class=\"mono\">{}</span>",
                esc(path)
            ));
        }
        if let Some(hash) = sha256 {
            kept.push(format!("SHA-256 <span class=\"mono\">{}</span>", esc(hash)));
        }
        if !kept.is_empty() {
            writeln!(
                out,
                "<p class=\"meta\">The reading: {}.</p>",
                kept.join(", ")
            )?;
        }
    }
    out.push_str("</section>\n");
    Ok(())
}

fn changes(conn: &Connection, out: &mut String) -> Out {
    write!(
        out,
        "<section id=\"changes\">\n<h2>Changes</h2>\n<p class=\"muted\">The last {RUNS_SHOWN} runs, newest first.</p>\n"
    )?;
    // The runs whose every reading the store keeps (`store::listed_runs`), so that what the page
    // says of each does not change when older readings are folded.
    let runs = crate::store::listed_runs(conn)?;
    if runs.is_empty() {
        out.push_str("<p>No runs yet.</p>\n");
    }

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
    let mut not_repeated_stmt = conn.prepare(&format!(
        "{}
         SELECT COUNT(*) FROM reading r
         WHERE (SELECT c.id FROM coverage c
                WHERE c.reader = r.reader AND c.scope = r.scope AND c.kind = r.kind
                ORDER BY c.id LIMIT 1) < (SELECT MIN(id) FROM coverage WHERE run_id = ?1)
           AND r.scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
           AND r.scope NOT IN (SELECT id FROM gone_entity)",
        crate::store::LATEST
    ))?;
    // What a watcher's reading read: the kinds its readings are of, a file's content aside.
    let mut kinds_stmt = conn.prepare(
        "SELECT DISTINCT kind FROM coverage WHERE run_id = ?1 AND kind != ?2 ORDER BY kind",
    )?;
    for (i, run) in runs.iter().enumerate() {
        let (run_id, at, finished, report) = (&run.run_id, &run.at, &run.finished, &run.report);
        // Counted as the report and `immune status` count them: what was read for the first
        // time is the baseline, shown as such and never as added.
        let (since, first, events) = crate::status::run_changes(conn, run_id)?;
        let not_full: Vec<(String, String, String, Option<String>, bool)> = not_full_stmt
            .query_map([run_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        // A watcher's reading, `immune watch`, reads only the watched places and never finishes
        // a run: it is shown as a watcher's reading, not as a run that did not finish.
        let sampled = run_id.starts_with(crate::processes::RUN_PREFIX);
        let watcher = run_id.starts_with(crate::watch::RUN_PREFIX) || sampled;
        let not_repeated: i64 = if watcher {
            0
        } else {
            not_repeated_stmt.query_row([run_id], |r| r.get(0))?
        };
        let partial = not_full.iter().any(|r| r.2 == "partial" && r.4);
        // The event level keeps no facts: a reading of it that read nothing hides no change.
        let nothing = not_repeated > 0
            || not_full.iter().any(|r| {
                r.2 == "none" && r.1 != crate::events::KIND && r.1 != crate::events::KIND_FILES
            });

        // No events is "no changes" only when the run finished, read everything in full
        // and read again every scope read before.
        let mut counts = format!(
            "+{} added, {} changed, {} removed",
            since.added, since.changed, since.removed
        );
        if first > 0 {
            counts.push_str(&format!(
                ", {} read for the first time and kept as the baseline",
                plural(first, "thing", "things")
            ));
        }
        let mut unknown = Vec::new();
        if partial {
            unknown.push("removals unknown where a reading was partial");
        }
        if nothing {
            unknown.push("changes unknown where nothing was read");
        }
        let summary = if !finished && !watcher {
            "did not finish, changes unknown".to_string()
        } else if !unknown.is_empty() {
            format!("{counts}; {}", unknown.join(", "))
        } else if !events.is_empty() {
            counts
        } else {
            "no changes".to_string()
        };
        let summary = if sampled {
            "sample of running programs and their connections".to_string()
        } else if watcher {
            // A reading of some places names them; one of every place, too many to name, says
            // how many kinds it read.
            let kinds: Vec<String> = kinds_stmt
                .query_map(params![run_id, crate::watched::CONTENT], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let read = if kinds.len() <= KINDS_NAMED {
                kinds.join(", ")
            } else {
                format!("{} kinds of watched places", kinds.len())
            };
            format!("watcher's reading of {read}: {summary}")
        } else {
            summary
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
            for e in &events {
                let entry = if e.first { "first reading" } else { &e.entry };
                write!(out, "<tr class=\"{}\">", esc(&e.entry))?;
                td(out, "", entry)?;
                td_component(out, &e.subject)?;
                td(out, "mono", component_place(&e.subject))?;
                td(out, "", what(&e.predicate))?;
                let value = match (&e.old, &e.new) {
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
            // A fact of a kind no longer read was set aside, not found gone
            // (`lifecycle::retire`).
            "SELECT subject, predicate, object, reader, observed_at, retracted_at, source_ref
             FROM assertion a WHERE layer = 'retracted'
               AND NOT EXISTS (SELECT 1 FROM journal j
                               WHERE j.entry = 'retired' AND j.run_id = a.retracted_by
                                 AND j.reader = a.reader AND j.scope = a.scope
                                 AND j.kind = a.kind AND j.subject = a.subject
                                 AND j.predicate = a.predicate)
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
a { color: inherit; text-decoration-color: var(--muted); }
nav { margin-bottom: 12px; }
article.item { border: 1px solid var(--line); border-left: 4px solid var(--muted); border-radius: 8px;
  padding: 10px 14px; margin: 12px 0; background: var(--head); }
article.item.high, article.item.critical { border-left-color: var(--bad-fg); }
article.item.medium { border-left-color: var(--changed); }
article.item h2, article.item h3 { font-size: 1rem; margin: 0 0 4px; padding: 0; border: 0; }
article.item .where { margin: 0 0 6px; }
article.item .said { color: var(--muted); overflow-wrap: anywhere; }
article.item blockquote.sent { margin: 4px 0 8px; padding: 2px 10px; border-left: 3px solid var(--line);
  color: var(--muted); overflow-wrap: anywhere; white-space: pre-wrap; }
article.item .advice { font-weight: 600; }
ul.counts { list-style: none; padding: 0; }
ul.counts li { margin: 4px 0; }
ul.rules { margin: 2px 0 12px; padding-left: 18px; font-size: .875rem; }
ul.rules li { margin: 4px 0; }
.badge.notify { border: 1px solid var(--line); font-weight: 500; }
.quiet { color: var(--muted); }
.facts { font-size: .95rem; }
.scale { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr)); gap: 12px; margin: 20px 0 8px; }
.scale p { margin: 0; padding: 12px 14px; border: 1px solid var(--line); border-radius: 8px; background: var(--head);
  display: flex; flex-direction: column; gap: 2px; }
.scale .num { font-size: 1.8rem; font-weight: 700; line-height: 1.15; }
article.rule { border-top: 1px solid var(--line); padding: 10px 0; }
article.rule h4 { font-size: .95rem; margin: 0 0 4px; display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; }
.chip { display: inline-block; padding: 0 7px; border-radius: 4px; font-size: .75rem; font-weight: 600;
  border: 1px solid var(--line); color: var(--muted); text-transform: uppercase; letter-spacing: .03em; }
.chip.lvl-critical, .chip.lvl-high { color: var(--bad-fg); border-color: var(--bad-fg); }
.chip.lvl-medium { color: var(--changed); border-color: var(--changed); }
article.rule .missing { margin: 2px 0 4px; font-size: .875rem; }
article.rule details { margin: 0; }
article.rule summary { color: var(--muted); font-size: .875rem; list-style: none; display: flex; gap: 6px; }
article.rule summary::-webkit-details-marker { display: none; }
article.rule summary::before { content: "\25B8"; flex: none; }
article.rule details[open] summary::before { content: "\25BE"; }
article.rule summary .desc { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
article.rule details[open] summary .desc { display: block; }
article.rule ul.about { margin: 4px 0 0; padding-left: 18px; font-size: .875rem; }
article.rule ul.about li { margin: 2px 0; overflow-wrap: anywhere; }
footer.licence { margin-top: 32px; }

/* The summary: a dashboard. Red is for findings only; what is not covered stays quiet. */
:root {
  --ink: #1d1d1f; --sec: #55555a; --ln: #e5e5ea; --grp: #f5f5f7; --card: #ffffff;
  --blue: #0064e0; --green: #2e9e5b; --orange: #c25e00; --red: #d92d20; --red-ink: #b42318;
  --red-line: #f3c6c1; --calm: #b9e3c8; --calm-edge: #2e9e5b; --vuln: #e8a33d; --vuln-light: #f7dfb6;
  --hollow: #8e8e93; --faint: #c7c7cc;
  --sev-malicious: #3d1f0a; --sev-critical: #8a3a00; --sev-high: #c25e00;
  --sev-moderate: #e3b25a; --sev-low: #c7c7cc; --sev-none: #e5e5ea;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ink: #f2f2f5; --sec: #a8a8b0; --ln: #3a3a3f; --grp: #131315; --card: #1e1e21;
    --blue: #5ea2ff; --green: #4cc27a; --orange: #ff9f43; --red: #ff5a4f; --red-ink: #ff7a70;
    --red-line: #6b2a25; --calm: #24553a; --calm-edge: #4cc27a; --vuln: #e0a043; --vuln-light: #5a4321;
    --hollow: #9a9aa2; --faint: #55555c;
    --sev-malicious: #f0c8a0; --sev-critical: #c9682c; --sev-high: #f0913a;
    --sev-moderate: #d9b25e; --sev-low: #77777f; --sev-none: #48484e;
  }
}
body.summary { background: var(--grp); color: var(--ink);
  font: 15px/1.45 -apple-system, BlinkMacSystemFont, system-ui, "Segoe UI", sans-serif; }
.summary main { max-width: 1120px; padding: 32px 20px 56px; display: flex; flex-direction: column; gap: 28px; }
.summary a { color: var(--blue); text-decoration: none; }
.summary a:hover { text-decoration: underline; }
.summary a:focus-visible, .summary summary:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; border-radius: 4px; }
.summary h2 { font-size: 20px; line-height: 26px; margin: 0; padding: 0; border: 0; }
.summary h3 { font-size: 15px; margin: 0; }
.summary p { margin: 0; }
.summary .meta, .summary .muted, .summary .sub { color: var(--sec); }
.summary .meta, .summary .sub { font-size: 13px; }
.summary section, .summary .card { min-width: 0; }
.summary .card, .summary #you-can-fix, .summary #vulnerabilities, .summary #map, .summary #watched-here, .summary #rules { background: var(--card); border: 1px solid var(--ln); border-radius: 14px; padding: 20px; }
.summary .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; margin-bottom: 12px; }
.summary .head h2 { flex: 1 1 auto; }
.summary .head .n, .summary .head a { font-size: 14px; color: var(--sec); }
.summary .head a { color: var(--blue); }

/* The state, first. */
.summary #this-mac { display: flex; align-items: center; gap: 20px; }
.summary .glyph { width: 64px; height: 64px; flex: none; }
.summary #this-mac > div { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.summary #this-mac h1 { font-size: 30px; line-height: 36px; margin: 0; }
.summary #this-mac .sub { font-size: 15px; overflow-wrap: anywhere; }
.summary #this-mac .sub strong { color: var(--ink); font-weight: 600; }

/* Four tiles. */
.summary .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
.summary .tile { display: flex; flex-direction: column; gap: 2px; min-height: 124px; padding: 16px;
  background: var(--card); border: 1px solid var(--ln); border-radius: 14px; color: var(--ink); }
.summary .tile:hover { text-decoration: none; border-color: var(--hollow); }
.summary .tile.look { border-color: var(--red-line); }
.summary .tile .th { display: flex; align-items: center; gap: 8px; margin-bottom: auto; padding-bottom: 10px; }
.summary .tile svg { width: 22px; height: 22px; flex: none; stroke: var(--sec); fill: none; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }
.summary .tile .tn { font-size: 14px; font-weight: 600; flex: 1 1 auto; }
.summary .tile .tv { font-size: 30px; font-weight: 700; line-height: 34px; }
.summary .tile .tl { font-size: 13px; color: var(--sec); min-height: 36px; }
.summary .pill { display: inline-block; padding: 1px 8px; border-radius: 11px; background: var(--red-ink); color: #fff;
  font-size: 12px; font-weight: 700; white-space: nowrap; }
.summary .quiet { font-size: 12px; color: var(--sec); white-space: nowrap; }

/* What needs a look. */
.summary .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(400px, 100%), 1fr)); gap: 16px; }
.summary article.card { display: flex; flex-direction: column; gap: 8px; margin: 0; border-left-color: var(--ln); }
.summary article.card.urgent { border-color: var(--red-line); }
.summary article.card h3 { font-size: 18px; line-height: 24px; font-weight: 600; }
.summary article.card > p:not(.top) { color: var(--sec); font-size: 14px; }
.summary article.card .top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; min-width: 0; }
.summary article.card .pill { border-radius: 4px; text-transform: uppercase; letter-spacing: .04em; font-size: 12px; }
.summary .where { color: var(--sec); overflow-wrap: anywhere; }
.summary details > summary { cursor: pointer; color: var(--blue); font-size: 14px; padding: 2px 0; }
.summary details[open] > summary { margin-bottom: 8px; }
.summary details > :not(summary) + :not(summary) { margin-top: 8px; }
.summary .said { color: var(--sec); overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.summary .advice { font-weight: 600; }
.summary .more { font-size: 13px; color: var(--sec); }

/* Two cards side by side. */
.summary .pair { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(400px, 100%), 1fr)); gap: 16px; align-items: start; }
.summary .rows > details, .summary .rows > p { border-top: 1px solid var(--ln); }
.summary .rows > details > summary { list-style: none; display: flex; align-items: center; gap: 12px; min-height: 52px;
  color: var(--ink); font-size: 15px; padding: 0; }
.summary .rows > details > summary::-webkit-details-marker { display: none; }
.summary summary .t { flex: 1 1 auto; }
.summary summary .n { font-weight: 600; }
.summary summary .chev { width: 14px; height: 14px; flex: none; stroke: var(--hollow); fill: none; stroke-width: 2; transition: transform .15s; }
.summary details[open] > summary .chev { transform: rotate(90deg); }
.summary .rows > p { padding: 14px 0 4px; }
.summary .rows article.item { margin: 0 0 14px; background: var(--grp); border: 0; border-radius: 10px; padding: 12px 14px; }
.summary .rows article.item h3 { font-size: 15px; }
.summary .big { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 10px; color: var(--sec); font-size: 14px; }
.summary .big .num { font-size: 38px; line-height: 42px; font-weight: 700; color: var(--ink); }
.summary .bar { display: flex; gap: 2px; height: 12px; border-radius: 6px; overflow: hidden; background: var(--ln); margin: 14px 0 10px; }
.summary .bar span { display: block; min-width: 3px; }
.summary .keys { display: flex; flex-wrap: wrap; gap: 6px 18px; list-style: none; padding: 0; margin: 0 0 12px; font-size: 13px; }
.summary .keys li { display: flex; align-items: center; gap: 6px; }
.summary .keys i { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.summary .s-malicious { background: var(--sev-malicious); } .summary .s-critical { background: var(--sev-critical); }
.summary .s-high { background: var(--sev-high); } .summary .s-moderate { background: var(--sev-moderate); }
.summary .s-low { background: var(--sev-low); } .summary .s-none { background: var(--sev-none); }
.summary #vulnerabilities > p + p { margin-top: 10px; }
.summary #vulnerabilities > .sub { margin: -8px 0 14px; }
.summary #rules .cover { margin: 12px 0 8px; }
.summary #vulnerabilities > p.used { margin-top: 4px; font-size: 15px; }
.summary .used strong { font-weight: 600; }

/* The map of what the program has collected. */
.summary .legend { display: flex; flex-wrap: wrap; gap: 8px 18px; list-style: none; padding: 0; margin: 0; font-size: 13px; color: var(--sec); }
.summary .legend li { display: flex; align-items: center; gap: 6px; }
.summary .groups { display: flex; flex-wrap: wrap; gap: 24px 32px; margin-top: 20px; }
.summary .group { display: flex; flex-direction: column; gap: 8px; min-width: 0; flex: 1 1 300px; }
.summary .group.wide { flex-basis: 100%; }
.summary .groups > .note { flex-basis: 100%; }
.summary .group h3 { font-size: 15px; }
.summary .group h4 { font-size: 13px; font-weight: 400; color: var(--sec); margin: 6px 0 0; }
.summary .group h3 span, .summary .group h4 span { color: var(--sec); font-weight: 400; }
.summary .group h3 a.n, .summary .group h4 a.n { font-weight: 400; }
.summary .group h3 .split { font-size: 13px; }
.summary .group .note { font-size: 13px; color: var(--sec); }
.summary .marks { display: flex; flex-wrap: wrap; gap: 6px; }
.summary .marks.small { gap: 3px; }
.summary .marks.tiny { gap: 2px; }
.summary .m { display: block; width: 20px; height: 20px; border-radius: 5px; background: var(--calm); box-shadow: inset 0 0 0 1.5px var(--calm-edge); }
.summary .small .m, .summary .tiny .m { box-shadow: inset 0 0 0 1px var(--calm-edge); }
.summary .small .m { width: 10px; height: 10px; border-radius: 2px; }
.summary .tiny .m { width: 7px; height: 7px; border-radius: 1.5px; }
.summary .round .m { border-radius: 50%; }
.summary .m.look { background: var(--red); box-shadow: 0 0 0 2px var(--card), 0 0 0 3.5px var(--red); }
.summary .m.vuln { background: linear-gradient(135deg, var(--vuln-light) 0 45%, var(--vuln) 45% 100%); box-shadow: inset 0 0 0 1.5px var(--vuln); }
.summary .m.open { background: transparent; border: 1.5px dashed var(--hollow); box-shadow: none; }
.summary .m.theirs { background: transparent; border: 1.5px solid var(--faint); box-shadow: none; }
.summary .small .m.open, .summary .tiny .m.open, .summary .small .m.theirs, .summary .tiny .m.theirs { border-width: 1px; }
.summary a.m:hover { outline: 2px solid var(--ink); outline-offset: 1px; text-decoration: none; }
.summary .legend .m { width: 12px; height: 12px; border-radius: 3px; }
.summary .legend .m.look { box-shadow: 0 0 0 1.5px var(--card), 0 0 0 3px var(--red); }
.summary .means { margin-top: 20px; border-top: 1px solid var(--ln); padding-top: 12px; }
.summary .means p { font-size: 13px; color: var(--sec); }
.summary .means strong { color: var(--ink); font-weight: 600; }

/* What is watched, as bars with their numbers. */
.summary .cover { display: grid; grid-template-columns: minmax(0, 1fr); }
.summary .cover h3 { font-size: 13px; font-weight: 600; color: var(--sec); margin: 14px 0 4px; }
.summary .cover h3:first-child { margin-top: 0; }
.summary .cover > div { display: grid; align-items: center; gap: 6px 16px; min-height: 44px; border-top: 1px solid var(--ln); padding: 8px 0; }
.summary .cover > .plain { grid-template-columns: minmax(0, 1fr) auto; }
.summary .cover > .known { grid-template-columns: minmax(180px, 1.4fr) minmax(100px, 1.4fr) minmax(130px, auto); }
.summary .cover .lbl { font-size: 15px; }
.summary .cover .val { font-size: 13px; color: var(--sec); text-align: right; }
.summary .cover .num { font-size: 15px; font-weight: 600; color: var(--ink); text-align: right; }
.summary .cover .note { grid-column: 1 / -1; font-size: 13px; color: var(--sec); margin-top: -4px; }
.summary .meter { display: block; height: 8px; border-radius: 4px; background: var(--ln); overflow: hidden; }
.summary .meter span { display: block; height: 8px; background: var(--blue); }
.summary .told { border-top: 1px solid var(--ln); padding-top: 10px; }
.summary .told h3 { margin: 16px 0 6px; font-size: 14px; }
.summary .told ul.counts li { margin: 8px 0; }

/* Collapsed rows at the bottom. */
.summary .closed { padding: 0 20px; }
.summary .closed section > details > summary, .summary .closed > p.tech { display: flex; align-items: center; gap: 12px; min-height: 56px;
  list-style: none; color: var(--ink); font-size: 15px; padding: 0; margin: 0; }
.summary .closed section > details > summary::-webkit-details-marker { display: none; }
.summary .closed section > details > summary h2 { font-size: 15px; font-weight: 400; line-height: 20px; flex: 1 1 auto; }
.summary .closed section > details > summary .n { color: var(--sec); font-weight: 400; }
.summary .closed section + section, .summary .closed > p.tech { border-top: 1px solid var(--ln); }
.summary .closed > p.tech { gap: 6px; flex-wrap: wrap; }
.summary .closed section > details[open] { padding-bottom: 16px; }
.summary .closed article.item { margin: 0 0 12px; background: var(--grp); border: 0; border-radius: 10px; padding: 12px 14px; }
.summary .closed article.item h3 { font-size: 15px; }
.summary footer { font-size: 13px; color: var(--sec); }
@media (max-width: 760px) {
  .summary main { padding: 20px 16px 40px; }
  .summary #this-mac { align-items: flex-start; gap: 14px; }
  .summary .glyph { width: 48px; height: 48px; }
  .summary .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .summary .tile:last-child:nth-child(odd) { grid-column: 1 / -1; }
  .summary #this-mac h1 { font-size: 24px; line-height: 30px; }
  .summary .cover > .known { grid-template-columns: minmax(0, 1fr) auto; }
  .summary .cover > .known .lbl { grid-column: 1 / -1; }
}

/* As it happens: program starts and the published rules, src/happens.rs. */
.summary #as-it-happens { background: var(--card); border: 1px solid var(--ln); border-radius: 14px; padding: 24px;
  display: flex; flex-direction: column; gap: 22px; }
.summary #as-it-happens .head { margin-bottom: 0; }
.summary #as-it-happens .head h2 { flex: 0 1 auto; }
.summary #as-it-happens .first { font-size: 15px; color: var(--sec); }
.summary #as-it-happens .first strong { color: var(--ink); font-weight: 600; }
.summary .stats { display: flex; flex-wrap: wrap; gap: 24px; }
.summary .stat { flex: 1 1 200px; display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.summary .stat .st, .summary .stat .ss { font-size: 13px; color: var(--sec); }
.summary .stat .sv { font-size: 28px; font-weight: 700; line-height: 32px; font-variant-numeric: tabular-nums; }
.summary .stat svg.hours { display: block; width: 220px; max-width: 100%; height: 40px; }
.summary .stat .meter { max-width: 220px; height: 6px; border-radius: 3px; }
.summary .stat .meter span { height: 6px; }
.summary .sh { display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 18px; padding-bottom: 8px; }
.summary .sh h3 { font-size: 15px; font-weight: 600; }
.summary .sh .n { font-size: 13px; color: var(--sec); }
.summary .matched .none { font-size: 14px; color: var(--sec); padding: 10px 0; border-top: 1px solid var(--ln); }
.summary #as-it-happens .head .live { margin-left: auto; font-variant-numeric: tabular-nums; }
.summary #as-it-happens[data-moved="yes"] .stats, .summary #as-it-happens[data-moved="yes"] .matched { opacity: .5; }
.summary #as-it-happens [hidden] { display: none; }
/* The level column holds the widest chip, "Informational", whole. */
.summary .rr { display: grid; grid-template-columns: minmax(0, 1fr) 112px 84px 56px 132px; align-items: center; gap: 12px;
  padding: 10px 0; border-top: 1px solid var(--ln); font-size: 14px; }
.summary .rr .rl { min-width: 0; }
.summary .rr .rt { overflow-wrap: anywhere; }
/* The rules of a set that states no level: a group of their own, under its own heading. */
.summary .sh.grp { padding-top: 14px; }
.summary .sh h4 { font-size: 14px; font-weight: 600; }
.summary .rr .rc { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
.summary .rr .rs { text-align: right; font-size: 13px; color: var(--sec); }
.summary .rr .rs a { color: var(--sec); }
.summary .rr .rs a.look { color: var(--red); font-weight: 600; }
.summary .rb { display: block; height: 8px; border-radius: 4px; background: var(--ln); overflow: hidden; }
.summary .rb span { display: block; height: 8px; border-radius: 4px; background: var(--hollow); }
.summary .lv { display: inline-flex; align-items: center; height: 20px; padding: 0 8px; border-radius: 10px;
  font-size: 12px; font-weight: 600; white-space: nowrap; }
.summary .lv-critical { background: var(--sev-critical); color: var(--card); }
.summary .lv-high { background: var(--sev-high); color: var(--card); }
.summary .lv-medium { background: var(--vuln-light); color: var(--ink); }
.summary .lv-low, .summary .lv-informational, .summary .lv-none { background: var(--grp); color: var(--sec); box-shadow: inset 0 0 0 1px var(--ln); }
.summary .matched .all { padding-top: 10px; border-top: 1px solid var(--ln); font-size: 13px; color: var(--sec); }
.summary .covers { display: flex; flex-direction: column; gap: 12px; }
.summary .covers .sh { padding-bottom: 0; }
.summary .covers .legend .m { width: 12px; height: 12px; border-radius: 3px; }
.summary .tactics { display: grid; grid-template-columns: repeat(auto-fill, minmax(86px, 1fr)); gap: 16px 10px; }
.summary .tactic { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
.summary .tactic h4 { font-size: 12px; font-weight: 600; line-height: 15px; min-height: 30px; margin: 0; }
.summary .tactic .sq { display: flex; flex-wrap: wrap; gap: 4px; max-width: 76px; }
.summary .tactic .m { width: 12px; height: 12px; border-radius: 3px; box-shadow: inset 0 0 0 1px var(--calm-edge); }
.summary .tactic .m.look, .summary .covers .legend .m.look { box-shadow: 0 0 0 1.5px var(--card), 0 0 0 3px var(--red); }
.summary .m.hit { background: var(--vuln); box-shadow: none; }
.summary .m.would { background: transparent; border: 1.5px solid var(--hollow); box-shadow: none; }
.summary .tactic .m.open, .summary .tactic .m.would, .summary .covers .legend .m.open, .summary .covers .legend .m.would { border-width: 1px; box-shadow: none; }
.summary .tactic .nm { font-size: 12px; color: var(--sec); font-variant-numeric: tabular-nums; }
.summary .covers > .meta { font-size: 13px; }
@media (max-width: 760px) {
  .summary #as-it-happens { padding: 20px 16px; }
  .summary .rr { grid-template-columns: minmax(0, 1fr) auto auto; }
  .summary .rr .rb { display: none; }
  .summary .rr .rs { grid-column: 1 / -1; text-align: left; margin-top: -6px; }
}
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
            '\u{2029}',
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
            // Default-ignorable: drawn as nothing, though not format characters.
            '\u{34F}',
            '\u{115F}',
            '\u{1160}',
            '\u{3164}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{FFA0}',
            '\u{E0100}',
            '\u{E01EF}',
        ];
        for c in hidden {
            let escaped: String = c.escape_unicode().collect();
            let text = format!("a{c}b");
            assert_eq!(shown(&text), format!("a{escaped}b"), "{escaped}");
            assert_eq!(esc(&text), format!("a{escaped}b"), "{escaped}");
        }
        // A version carrying variation selectors is not shown as clean text.
        assert_eq!(shown("1.2.3\u{FE0F}\u{E0100}"), "1.2.3\\u{fe0f}\\u{e0100}");
        // Everything else is shown as it is, names in any script included.
        let plain = "web-1 сервер 東京 café ✓ \u{2027}\u{2030}\u{FFFC} Ελλάδα مرحبا שלום \
                     नमस्ते 한국어 ไทย ጤና Ꭰ 𝔘 😀";
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

    #[test]
    fn the_changes_page_says_the_same_of_every_run_it_lists_after_a_fold() {
        // The fold keeps every reading of the runs the page lists (`store::listed_runs`), a
        // watcher's readings before the first full check among them: a run that could not read
        // a kind still says so after older readings were folded.
        use crate::store::{
            Cause, Event, Gap, Reading, journal_event, journal_note, put_coverage, put_entity,
        };
        use crate::watched::{AUTOSTART_KIND, PROFILE_KIND, READER};
        let dir = std::env::temp_dir().join(format!(
            "immune-view-fold-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        let mac = "machine:mac";
        // `journaled`: a reading the page lists, that recorded a change; `full`: a full run.
        let write = |conn: &mut rusqlite::Connection, i: i64, journaled: bool, full: bool| {
            let at = 1_900_000_000 + i * 60;
            let run_id = if full {
                format!("{at}-000000000")
            } else {
                format!("{}{at}-000000000", crate::watch::RUN_PREFIX)
            };
            if full {
                journal_note(conn, at, &run_id, "run_started", "").unwrap();
            }
            let tx = conn.transaction().unwrap();
            put_entity(&tx, mac).unwrap();
            let r = |kind| Reading {
                reader: READER,
                scope: mac,
                kind,
                run_id: &run_id,
                at,
                observed_at: at,
            };
            // The shell profiles could not be read; the launch agents were.
            let denied = Gap::of(Cause::Failed);
            put_coverage(&tx, &r(PROFILE_KIND), "none", Some("denied"), &denied).unwrap();
            put_coverage(&tx, &r(AUTOSTART_KIND), "full", None, &Gap::default()).unwrap();
            if journaled {
                let e = Event {
                    kind: "changed",
                    subject: format!("file:{mac}/Library/LaunchAgents/org.example.plist"),
                    predicate: "has_content".to_string(),
                    old: Some(format!("a{i}")),
                    new: Some(format!("b{i}")),
                };
                journal_event(&tx, &r(AUTOSTART_KIND), &e, None).unwrap();
            }
            if full {
                journal_note(&tx, at, &run_id, "report", "").unwrap();
                journal_note(&tx, at, &run_id, "run_finished", "").unwrap();
            }
            tx.commit().unwrap();
        };
        // Readings that changed nothing, which no page lists; then five that the page lists,
        // then three full checks.
        for i in 0..10 {
            write(&mut conn, i, false, false);
        }
        for i in 10..15 {
            write(&mut conn, i, true, false);
        }
        for i in 15..18 {
            write(&mut conn, i, true, true);
        }
        let page = |conn: &rusqlite::Connection| {
            let mut out = String::new();
            super::changes(conn, &mut out).unwrap();
            out
        };
        let before = page(&conn);
        let unknown = "changes unknown where nothing was read";
        assert_eq!(before.matches(unknown).count(), 8);
        // A watcher's reading names the kinds it read, not every watched place.
        let named = esc(&format!(
            "watcher's reading of {AUTOSTART_KIND}, {PROFILE_KIND}:"
        ));
        assert_eq!(before.matches(&named).count(), 5);
        let folded = crate::store::fold(&conn).unwrap();
        let after = page(&conn);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(folded.removed, 16);
        assert_eq!(after, before);
    }
}
