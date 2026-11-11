//! The pages a person lands on: the summary, which answers what the app answers; what is
//! watched on this Mac, kind by kind; and what is beyond it. Every sentence is in plain
//! words: what something means for the owner, and whether he can do something about it or
//! it is a limit of this version. The technical pages are reached from one line at the bottom.
//!
//! Every link on the summary leads to a section that lists exactly what its label says,
//! under a heading that says it, first thing on arrival.
//!
//! Text from the store goes through `esc`, as on every page of the view.

use crate::covered::{self, Count, NOTHING, Uncovered, YOU};
use crate::view::{self, DETAILS, FOOT, Latest, Out, counted, esc, utc, utc_or};
use crate::{beyond, findings, integrity, servers, watched};
use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

/// The person's pages of details, by file name in the folder of details.
pub const THIS_MAC: &str = "this-mac";
pub const BEYOND: &str = "beyond";
pub const TECHNICAL: &str = "technical";

/// At most this many things that need a look are shown in full, so the summary stays small.
const ITEMS_SHOWN: usize = 100;
/// At most this many examples are listed under a thing not covered.
const EXAMPLES_SHOWN: usize = 20;

/// The link back to the summary, on every page of details.
const BACK: &str = "<nav class=\"meta\"><a href=\"../view.html\">← What needs a look</a></nav>\n";

/// What a watcher cannot see, in plain words: `watch::CANNOT_SEE` told for a person.
const WATCHER_CANNOT_SEE: &str = "A watcher does not see who made a change, nor a change undone within a second. A link among the watched files that is pointed somewhere else shows within a minute rather than within seconds.";

/// The anchor of a kind of watched thing: its words in lower case, joined by dashes.
pub fn anchor(what: &str) -> String {
    what.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

/// Words as they begin a line: `Startup items`. A name written in lower case stays so.
fn capital(s: &str) -> String {
    if s.starts_with("npm ") {
        return s.to_string();
    }
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A link to a section of a page of details.
fn link(page: &str, anchor: &str, text: &str) -> String {
    format!(
        "<a href=\"{DETAILS}/{page}.html#{anchor}\">{}</a>",
        esc(text)
    )
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
        "shell startup files" => "Files your terminal runs every time it opens a shell.",
        "SSH files" => "Your SSH settings, and the keys allowed to log in to this Mac.",
        "git hooks in projects" => {
            "Scripts git runs by itself in your projects, for example before a commit."
        }
        "editor tasks that run when a project is opened" => {
            "Tasks an editor runs by itself as soon as a project folder is opened."
        }
        "applications" => "Applications in the Applications folders, with who signed each.",
        "Homebrew packages" => "What Homebrew installed.",
        "npm packages" => "Packages npm installed for every project at once.",
        "app code kept outside the app" => {
            "Code that applications not made by Apple keep in your Library folder, outside the application itself."
        }
        _ => "",
    }
}

/// The summary page: whether this Mac is watched, what needs a look in full, what is
/// watched, what the owner can fix and the limits of this version, and what is beyond this
/// Mac. Built from the state and the result `soc status --json` gives, so the two agree.
pub fn summary(
    conn: &Connection,
    st: &crate::status::State,
    r: &serde_json::Value,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = view::head("What needs a look");
    let headline = match r["needs_a_look_total"].as_i64() {
        Some(0) => "Nothing needs a look".to_string(),
        Some(n) => counted(n, "thing needs a look", "things need a look"),
        None => "What needs a look is not known yet".to_string(),
    };
    writeln!(
        out,
        "<header>\n<h1>{}</h1>\n<p class=\"meta\">This page made {}</p>",
        esc(&headline),
        utc(now)
    )?;
    // Why it is not known yet, in the program's own words.
    for n in r["not_computed"].as_array().into_iter().flatten() {
        if n["section"] == "needs_a_look" {
            let why = capital(n["reason"].as_str().unwrap_or_default());
            writeln!(out, "<p class=\"meta\">{}.</p>", esc(&why))?;
        }
    }
    out.push_str("</header>\n");

    // Whether this Mac is watched, with the watcher and the last full check right there.
    let m = &st.this_mac;
    let (state, class, why) = match m.state {
        "watched" => ("This Mac is watched", "ok", ""),
        "watched_in_part" => (
            "This Mac is watched in part",
            "alert",
            ": something on it could not be read, and what you can fix says what.",
        ),
        _ => (
            "This Mac has not been checked yet",
            "alert",
            ": its first check has not finished.",
        ),
    };
    let watcher = match (m.live, m.live_read_at) {
        (true, Some(t)) => format!(
            "A watcher is running now: a change in what is watched all the time shows within seconds. It last looked {}.",
            utc(t)
        ),
        (true, None) => "A watcher is running now: a change in what is watched all the time shows within seconds.".to_string(),
        (false, Some(t)) => format!(
            "No watcher is running now, so everything is checked every hour. A watcher last looked {}.",
            utc(t)
        ),
        (false, None) => {
            "No watcher is running now, so everything is checked every hour.".to_string()
        }
    };
    let full = match m.checked_at {
        Some(t) => format!("The last full check was {}.", utc(t)),
        None => "No full check has finished yet.".to_string(),
    };
    writeln!(
        out,
        "<section id=\"this-mac\">\n<p class=\"{class}\"><strong>{state}</strong>{why}</p>\n<p>{} {}</p>\n</section>",
        esc(&watcher),
        esc(&full)
    )?;

    out.push_str("<section id=\"needs\">\n");
    for i in st.needs.items.iter().take(ITEMS_SHOWN) {
        view::item(&mut out, i)?;
    }
    if st.needs.items.len() > ITEMS_SHOWN {
        writeln!(
            out,
            "<p class=\"meta\">{} more, the mildest; <span class=\"mono\">soc status --json</span> and <span class=\"mono\">soc findings</span> list them.</p>",
            st.needs.items.len() - ITEMS_SHOWN
        )?;
    }
    out.push_str("</section>\n");

    out.push_str("<section id=\"watched-here\">\n<h2>What is watched on this Mac</h2>\n");
    if m.watched.is_empty() {
        out.push_str("<p class=\"muted\">Nothing has been read on this Mac yet.</p>\n");
    }
    for (how, head) in [
        (
            "live",
            "Watched all the time: a change shows within seconds",
        ),
        (
            "hourly",
            "Checked every hour: a change shows at the next check",
        ),
        (
            "sampled",
            "Looked at often while a watcher runs: what is running right now",
        ),
    ] {
        let of: Vec<&(&str, i64, &str)> = m.watched.iter().filter(|w| w.2 == how).collect();
        if of.is_empty() {
            continue;
        }
        writeln!(out, "<h3>{head}</h3>\n<ul class=\"counts\">")?;
        for (what, n, _) in of {
            let text = format!("{}: {}", capital(what), grouped(*n));
            writeln!(out, "<li>{}</li>", link(THIS_MAC, &anchor(what), &text))?;
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</section>\n");

    // What the owner can fix, then the limits of this version: each in full, never counted
    // as something to look at.
    let watcher_known = m.live || m.live_read_at.is_some();
    for (id, head, who, none) in [
        ("you-can-fix", "You can fix", YOU, "Nothing for you to fix."),
        ("limits", "Limits of this version", NOTHING, "None known."),
    ] {
        writeln!(out, "<section id=\"{id}\">\n<h2>{head}</h2>")?;
        let of: Vec<&Uncovered> = st
            .not_covered
            .iter()
            .filter(|u| u.cause.who == who)
            .collect();
        if of.is_empty() {
            writeln!(out, "<p class=\"muted\">{none}</p>")?;
        }
        for u in of {
            uncovered(&mut out, u)?;
        }
        if who == NOTHING && watcher_known {
            // What a watcher cannot see, and what its sample of running programs cannot,
            // in one paragraph.
            let mut said = WATCHER_CANNOT_SEE.to_string();
            if crate::processes::last_sampled(conn)?.is_some() {
                said.push_str(&format!(
                    " A sample of running programs does not see {}.",
                    listed_or(&crate::processes::PERSON_CANNOT_SEE)
                ));
            }
            writeln!(out, "<p>{}</p>", esc(&said))?;
        }
        out.push_str("</section>\n");
    }

    beyond_summary(conn, &mut out, r)?;

    let answered: Vec<findings::Item> = findings::all(conn, now)?
        .unwrap_or_default()
        .iter()
        .filter(|f| f.state == "expected" || f.state == "seen")
        .filter_map(findings::item)
        .collect();
    if !answered.is_empty() {
        writeln!(
            out,
            "<section id=\"answered\">\n<details>\n<summary>{} the owner has answered</summary>",
            counted(answered.len() as i64, "finding", "findings")
        )?;
        for i in &answered {
            view::item(&mut out, i)?;
        }
        out.push_str("</details>\n</section>\n");
    }
    writeln!(
        out,
        "<footer>\n<p class=\"meta\"><a href=\"{DETAILS}/{TECHNICAL}.html\">Technical details</a>: everything the program keeps, as it keeps it.</p>\n</footer>"
    )?;
    out.push_str(FOOT);
    Ok(out)
}

/// `a`, `a or b`, `a, b or c`.
fn listed_or(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
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
        for a in apart.iter().take(EXAMPLES_SHOWN) {
            writeln!(out, "<li>{}</li>", esc(a))?;
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

/// Projects on this Mac, and servers and other devices, each counted apart.
fn beyond_summary(conn: &Connection, out: &mut String, r: &serde_json::Value) -> Out {
    out.push_str("<section id=\"beyond\">\n<h2>Beyond this Mac</h2>\n<ul class=\"counts\">\n");
    let this = covered::this_machine(conn)?;
    let projects = projects(conn, this.as_deref())?;
    writeln!(
        out,
        "<li>{} <span class=\"muted\">· folders of code kept with git; their git hooks are watched, and the files that say what they depend on are read at every check</span></li>",
        link(
            THIS_MAC,
            "projects",
            &format!("Projects on this Mac: {}", grouped(projects.len() as i64))
        )
    )?;
    // Servers and other devices are said only where there are some: a Mac without servers
    // or a private network is told about its projects alone.
    let e = &r["estate"];
    let n = |key: &str| e[key].as_i64().unwrap_or_default();
    let last = match (
        n("servers_in_last_check"),
        n("servers_checked_in_last_check"),
    ) {
        (0, _) => "the server check has not been run".to_string(),
        (all, checked) => format!("{checked} of {all} checked at the last server check"),
    };
    if n("servers") > 0 {
        writeln!(
            out,
            "<li>{} <span class=\"muted\">· {last}</span><br><span class=\"muted\">Machines you log in to over SSH, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself.</span></li>",
            link(
                BEYOND,
                "servers",
                &format!("Servers: {}", grouped(n("servers")))
            )
        )?;
    }
    if n("other_devices") > 0 {
        writeln!(
            out,
            "<li>{}<br><span class=\"muted\">Other people's computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them.</span></li>",
            link(
                BEYOND,
                "other-devices",
                &format!("Other devices: {}", grouped(n("other_devices")))
            )
        )?;
    }
    // Those the owner's word sets aside while nothing contradicts it, as their page lists them.
    let set_aside = crate::owner::standing(conn)?
        .iter()
        .filter(|s| s.seen.is_none())
        .count() as i64;
    if set_aside > 0 {
        writeln!(
            out,
            "<li>{} <span class=\"muted\">· machines you said are retired or not yours; they are not checked</span></li>",
            link(
                BEYOND,
                "retired",
                &format!("Retired or not yours: {}", grouped(set_aside))
            )
        )?;
    }
    out.push_str("</ul>\n</section>\n");
    Ok(())
}

/// The projects on this Mac, as they are shown, with how many dependencies are known of each.
fn projects(conn: &Connection, this: Option<&str>) -> rusqlite::Result<Vec<(String, i64)>> {
    let Some(this) = this else {
        return Ok(Vec::new());
    };
    let list: Vec<(String, i64)> = conn
        .prepare(
            "SELECT a.subject,
                    (SELECT COUNT(DISTINCT p.subject) FROM assertion p
                     WHERE p.layer = 'live' AND p.predicate = 'part_of' AND p.object = a.subject)
             FROM assertion a
             WHERE a.layer = 'live' AND a.predicate = 'located_on' AND a.object = ?1
               AND a.subject LIKE 'checkout:%'
             GROUP BY a.subject ORDER BY a.subject",
        )?
        .query_map([this], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(list
        .into_iter()
        .map(|(id, n)| (findings::place(&id, Some(this)), n))
        .collect())
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
        "What is watched on this Mac",
        &format!(
            "Last full check {} · this page made {}",
            utc_or(st.this_mac.checked_at, "never"),
            utc(now)
        ),
    );
    let this = covered::this_machine(conn)?;
    let this = this.as_deref();
    for (count, what, _) in covered::WATCHED {
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            anchor(what),
            esc(&capital(what)),
            esc(about(what))
        )?;
        match count {
            Count::Files(as_) => files(conn, &mut out, as_, this)?,
            Count::Installed(kind) => installed(conn, &mut out, kind, this)?,
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

    out.push_str("<section id=\"projects\">\n<h2>Projects</h2>\n<p class=\"muted\">Folders of code kept with git on this Mac, with how many of their dependencies are known from the files that list them.</p>\n");
    let list = projects(conn, this)?;
    if list.is_empty() {
        out.push_str("<p class=\"muted\">None found here.</p>\n");
    } else {
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
    out.push_str(FOOT);
    Ok(out)
}

/// The watched files of one kind: where each is, when it was first seen and when it last
/// changed. Only checksums are kept, never content.
fn files(conn: &Connection, out: &mut String, as_: &str, this: Option<&str>) -> Out {
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
    if first.is_empty() {
        out.push_str("<p class=\"muted\">None found here.</p>\n");
        return Ok(());
    }
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
        view::td(out, "mono", &findings::place(&id, this))?;
        view::td(out, "nowrap", &utc(at))?;
        let last = changed
            .get(&id)
            .map_or("not since first seen".to_string(), |t| utc(*t));
        view::td(out, "nowrap", &last)?;
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

/// The installed things of one kind: name first, who signed it where that is known, version
/// and where it is.
fn installed(conn: &Connection, out: &mut String, kind: &str, this: Option<&str>) -> Out {
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
    if things.is_empty() {
        out.push_str("<p class=\"muted\">None found here.</p>\n");
        return Ok(());
    }
    let mut list: Vec<Installed> = things
        .into_iter()
        .map(|(subject, mut t)| {
            if t.at.is_empty() {
                t.at = findings::place(&subject, this);
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
            t
        })
        .collect();
    list.sort_by_key(|t| t.name.to_lowercase());
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

/// Servers, other devices and machines the owner set aside, each in a section of its own.
pub fn beyond(conn: &Connection, latest: &[Latest], now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = top("Beyond this Mac", &format!("This page made {}", utc(now)));
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

    out.push_str("<section id=\"servers\">\n<h2>Servers</h2>\n<p class=\"muted\">Machines you log in to over SSH, as your SSH settings, the list of machines SSH has connected to and the server check name them, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself.</p>\n");
    if split.servers.is_empty() {
        out.push_str("<p class=\"muted\">None known.</p>\n");
    } else {
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
    out.push_str("</section>\n");

    out.push_str("<section id=\"other-devices\">\n<h2>Other devices</h2>\n<p class=\"muted\">Other people's computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them. Only a Tailscale network is looked at; devices in a network of another kind are not known here.</p>\n");
    if split.other_devices.is_empty() {
        out.push_str("<p class=\"muted\">None seen.</p>\n");
    } else {
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
        view::thead(&mut out, &["Machine", "You said", "Since", "Why"]);
        for s in &standing {
            out.push_str("<tr>");
            view::td(&mut out, "mono", s.name())?;
            view::td(&mut out, "", &s.word.said)?;
            view::td(&mut out, "nowrap", &utc(s.word.made_at))?;
            view::td(&mut out, "", &s.word.reason)?;
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
    // The page of servers is linked from the summary only where there are some.
    out.push_str(&format!(
        "<li><a href=\"{BEYOND}.html\">Beyond this Mac: servers, other devices, and machines you set aside</a></li>\n"
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
