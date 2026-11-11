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
pub const VULNERABILITIES: &str = "vulnerabilities";

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
        "applications" => "Applications in the Applications folders, with who signed each.",
        "Homebrew packages" => "What Homebrew installed.",
        "npm packages" => "Packages npm installed for every project at once.",
        "app code kept outside the app" => {
            "Code that applications not made by Apple keep in your Library folder, outside the application itself."
        }
        covered::DEPENDENCIES => {
            "Packages your projects list in package-lock.json and Cargo.lock, compared at every check with the known vulnerabilities and malicious packages of npm and crates.io."
        }
        _ => crate::autorun::about(what),
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

    let list = indicator_list(conn)?;
    let none = covered::none_here(conn, &view::latest_coverage(conn)?, m)?;
    watched_here(&mut out, m, &none, list)?;
    vulnerabilities_summary(conn, &mut out)?;

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

    // Every answer that hides a finding now, whoever gave it, so that none is given
    // silently.
    let answered = findings::answered(conn, now)?.unwrap_or_default();
    out.push_str("<section id=\"answered\">\n<h2>Answered</h2>\n");
    if answered.is_empty() {
        writeln!(
            out,
            "<p class=\"muted\">Nothing is marked seen or expected now.</p>"
        )?;
    }
    for i in &answered {
        let Some(a) = &i.answer else { continue };
        writeln!(
            out,
            "<article class=\"item answered\" id=\"answered-{}\">\n<h3>{}</h3>",
            esc(&i.id),
            esc(i.words.title)
        )?;
        if let Some(place) = &i.place {
            writeln!(out, "<p class=\"where mono\">{}</p>", esc(place))?;
        }
        let said = match a.until {
            Some(u) => format!("Expected until {}", utc(u)),
            None => "Seen".to_string(),
        };
        writeln!(
            out,
            "<p>{}</p>\n<p class=\"meta\">{}</p>",
            esc(&said),
            esc(view::given_by(a.via))
        )?;
        if let Some(reason) = &a.reason {
            writeln!(out, "<p class=\"said\">{}</p>", esc(reason))?;
        }
        writeln!(
            out,
            "<p class=\"meta mono\">{}</p>\n</article>",
            esc(&format!("soc finding {} reopen", i.id))
        )?;
    }
    out.push_str("</section>\n");
    writeln!(
        out,
        "<footer>\n<p class=\"meta\"><a href=\"{DETAILS}/{TECHNICAL}.html\">Technical details</a>: everything the program keeps, as it keeps it.</p>\n</footer>"
    )?;
    out.push_str(FOOT);
    Ok(out)
}

/// What "watched" means, first under the heading of what is watched.
const WATCHED_MEANS: &str = "Watched means this: the program remembers what each of these things looked like the last time it checked, and tells you when one of them changes in a way listed here. It only tells you. It never blocks, stops or removes anything.";
/// Where what is told shows, and what also notifies.
const TOLD_WHERE: &str = "Everything listed here shows in the panel. What is marked 'Sends a notification' also sends one at once.";
/// A kind of thing that is listed as watched and that no rule speaks about.
const KEPT_AS_LIST: &str = "Kept as a list. Nothing tells you about a change here in this version.";
/// The mark of a rule whose findings notify at once.
const NOTIFIES: &str = "Sends a notification";
/// The rule about a match of a list of indicators, which is about no one kind.
const INDICATOR_RULE: &str = "indicator.match";
/// The rule about a file read for the first time, which is about every watched file.
const FIRST_READ_RULE: &str = "watched.first-read";

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

/// What the owner is told about: each rule's title and what it means, marked where its
/// findings notify at once; for no rule, that the thing is only kept as a list. The summary
/// and the page of what is watched say it the same way.
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

/// What a kind of watched thing is shown with: its count, none found where it was looked
/// for, or running programs when no sample of them was taken.
enum Shown {
    Count(i64),
    None,
    NotSampled,
}

/// Running programs when no sample is there.
const NOT_SAMPLED: &str =
    "Looked at only while the app is open. It is not open now, or has not looked yet.";

/// What is watched on this Mac, group by group, each kind with what the owner is told about
/// it; then the rule about a list of indicators and, last, the rule about every watched file.
/// A kind the last check looked for and found none of (`none`) is listed too, and so are
/// running programs when no sample is there: a rule about a thing appearing matters most
/// when there is none yet.
fn watched_here(
    out: &mut String,
    m: &covered::ThisMac,
    none: &[&'static str],
    list: Option<bool>,
) -> Out {
    writeln!(
        out,
        "<section id=\"watched-here\">\n<h2>What is watched, and what you are told about</h2>\n<p>{}</p>\n<p class=\"muted\">{}</p>",
        esc(WATCHED_MEANS),
        esc(TOLD_WHERE)
    )?;
    if m.watched.is_empty() && none.is_empty() {
        out.push_str("<p class=\"muted\">Nothing has been read on this Mac yet.</p>\n");
    }
    // Every kind to list, in the order of `covered::watched`, with its group.
    let all = covered::watched();
    let mut kinds: Vec<(&str, Shown, &str)> = Vec::new();
    for (_, what, fast) in all.iter().copied() {
        if let Some((_, n, how)) = m.watched.iter().find(|w| w.0 == what) {
            kinds.push((what, Shown::Count(*n), how));
        } else if none.contains(&what) {
            let how = if m.live && fast { "live" } else { "hourly" };
            kinds.push((what, Shown::None, how));
        }
    }
    // Any other kind the status names, as it names it.
    for (what, n, how) in &m.watched {
        if *what != covered::SAMPLED && !all.iter().any(|w| w.1 == *what) {
            kinds.push((what, Shown::Count(*n), how));
        }
    }
    match m.watched.iter().find(|w| w.0 == covered::SAMPLED) {
        Some((what, n, how)) => kinds.push((what, Shown::Count(*n), how)),
        None => kinds.push((covered::SAMPLED, Shown::NotSampled, "sampled")),
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
        let of: Vec<&(&str, Shown, &str)> = kinds.iter().filter(|k| k.2 == how).collect();
        if of.is_empty() {
            continue;
        }
        writeln!(out, "<h3>{head}</h3>\n<ul class=\"counts\">")?;
        for (what, shown, _) in of {
            match shown {
                Shown::Count(n) => {
                    let text = format!("{}: {}", capital(what), grouped(*n));
                    writeln!(out, "<li>{}", link(THIS_MAC, &anchor(what), &text))?;
                }
                Shown::None => {
                    writeln!(out, "<li>{}: none on this Mac now", esc(&capital(what)))?;
                }
                Shown::NotSampled => writeln!(
                    out,
                    "<li>{}<br><span class=\"muted\">{}</span>",
                    esc(&capital(what)),
                    esc(NOT_SAMPLED)
                )?,
            }
            told(out, &covered::rules_about(what))?;
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }
    out.push_str("<h3>A list of signs of a known attack, when you give one</h3>\n");
    told(out, &rule_with(INDICATOR_RULE))?;
    let said = match list {
        Some(true) => "A list was read at the last check.",
        Some(false) => "A list was given but could not be read at the last check.",
        None => "No list has been given, so nothing is compared.",
    };
    writeln!(out, "<p class=\"muted\">{said}</p>")?;
    out.push_str("<h3>Also</h3>\n");
    told(out, &rule_with(FIRST_READ_RULE))?;
    out.push_str("</section>\n");
    Ok(())
}

/// What the summary says first of known vulnerabilities.
const VULNERABILITIES_SAY: &str = "These are published weaknesses in packages your projects depend on. They are listed, not alarmed: most matter only under particular conditions. A package known to be malicious, or a vulnerability attackers are using, is shown at the top as something that needs a look.";
/// At most this many known vulnerabilities are shown on the summary.
const VULNERABILITIES_SHOWN: usize = 10;

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
    this: Option<&str>,
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

/// The section of the summary on known vulnerabilities in packages the projects use: what
/// they are, how many of each label, the most severe few, and the page with all of them.
fn vulnerabilities_summary(conn: &Connection, out: &mut String) -> Out {
    writeln!(
        out,
        "<section id=\"vulnerabilities\">\n<h2>Known vulnerabilities in packages your projects use</h2>\n<p>{}</p>",
        esc(VULNERABILITIES_SAY)
    )?;
    let list = crate::vulnerabilities::affecting(conn)?;
    let t = crate::vulnerabilities::totals(conn)?;
    let all = link(
        VULNERABILITIES,
        "by-project",
        "Known vulnerabilities by project",
    );
    if !t.matched {
        writeln!(
            out,
            "<p class=\"muted\">Not compared yet: no check has compared your projects' packages with the known vulnerabilities.</p>\n<p>{all}</p>\n</section>"
        )?;
        return Ok(());
    }
    if list.is_empty() {
        writeln!(
            out,
            "<p class=\"muted\">None is known in the packages that could be compared. What could not be compared is under Limits of this version.</p>\n<p>{all}</p>\n</section>"
        )?;
        return Ok(());
    }
    out.push_str("<ul class=\"counts\">\n");
    for (label, n) in &t.by_label {
        writeln!(
            out,
            "<li>{}: {}</li>",
            label_words(label),
            grouped(*n as i64)
        )?;
    }
    out.push_str("</ul>\n<div class=\"scroll\"><table class=\"dense\">\n");
    view::thead(out, &["Package", "Project", "Label", "Fixed in", "Record"]);
    let this = covered::this_machine(conn)?;
    for a in list.iter().take(VULNERABILITIES_SHOWN) {
        vulnerability_row(out, a, true, this.as_deref())?;
    }
    out.push_str("</tbody></table></div>\n");
    writeln!(
        out,
        "<p>{}</p>\n</section>",
        link(
            VULNERABILITIES,
            "by-project",
            &format!(
                "Known vulnerabilities by project: {}",
                grouped(list.len() as i64)
            )
        )
    )?;
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
    let this = covered::this_machine(conn)?;
    let list = crate::vulnerabilities::affecting(conn)?;
    if list.is_empty() {
        out.push_str("<p class=\"muted\">None is known.</p>\n");
    }
    let mut projects: BTreeMap<&str, Vec<&crate::vulnerabilities::Affecting>> = BTreeMap::new();
    for a in &list {
        projects.entry(a.checkout.as_str()).or_default().push(a);
    }
    for (checkout, of) in projects {
        writeln!(
            out,
            "<h3 class=\"mono\">{}</h3>\n<div class=\"scroll\"><table class=\"dense\">",
            esc(&findings::place(checkout, this.as_deref()))
        )?;
        view::thead(&mut out, &["Package", "Label", "Fixed in", "Record"]);
        for a in of {
            vulnerability_row(&mut out, a, false, this.as_deref())?;
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
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
    if n("own_devices") > 0 {
        writeln!(
            out,
            "<li>{}<br><span class=\"muted\">{YOUR_DEVICES}</span></li>",
            link(
                BEYOND,
                "your-devices",
                &format!("Your other devices: {}", grouped(n("own_devices")))
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
            Count::Files(as_) => files(conn, &mut out, as_, this)?,
            Count::Installed(kind) => installed(conn, &mut out, kind, this)?,
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
                )?
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

    ways(conn, &mut out, this)?;

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

/// What the section of every known way a project runs code by itself says first.
const WAYS: &str = "Files in a project that make a tool run code by itself during routine work, such as opening the folder or installing its packages. This version reads some of them and watches what they say; the others are only named here, so a change in them goes unseen. Every way known to this version is listed, whether it is in your projects or not.";

/// Every known way a project runs code by itself, from the table in `autorun`: the file, what
/// runs it, whether the tool asks first, whether it is read, and in how many projects here it
/// is. None is left out, present or not.
fn ways(conn: &Connection, out: &mut String, this: Option<&str>) -> Out {
    use crate::autorun::{self, Part, Scope};
    let (read, known) = autorun::counts();
    writeln!(
        out,
        "<section id=\"ways-code-runs\">\n<h2>Ways a project can make code run by itself</h2>\n<p class=\"muted\">{}</p>\n<p>{}</p>",
        esc(WAYS),
        esc(&format!(
            "This version reads {read} of the {known} known ways."
        ))
    )?;
    let in_checkout = this.map(|t| format!("checkout:{t}/%")).unwrap_or_default();
    let holding = |name: &str| -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = ?2 AND object = ?3
               AND subject LIKE ?4",
            params![watched::READER, autorun::HOLDS, name, in_checkout],
            |r| r.get(0),
        )
    };
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    view::thead(
        out,
        &[
            "File",
            "What runs it",
            "Asks first",
            "Read",
            "Projects here",
        ],
    );
    for p in &autorun::POINTS {
        let runs = format!("{} ({})", capital(p.trigger.words()), p.tool);
        let read = match p.part {
            Part::Present => "Not read",
            Part::Entries(_) => "Read: every entry",
            _ => "Read",
        };
        let here = match p.scope {
            Scope::NamedBy(_) => "Not looked for".to_string(),
            Scope::Checkout => grouped(holding(&p.name())?),
        };
        out.push_str("<tr>");
        view::td(out, "mono", &p.name())?;
        view::td(out, "", &runs)?;
        view::td(out, "", p.asks.words())?;
        view::td(out, "", read)?;
        view::td(out, "", &here)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</section>\n");
    Ok(())
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

/// What the owner's other devices are, on the summary and on the page beyond this Mac.
const YOUR_DEVICES: &str = "Phones, tablets and computers on your private network that you do not log in to over SSH. They are not checked: this version looks at this Mac and at servers.";

/// Servers, the owner's other devices, other people's devices and machines the owner set
/// aside, each in a section of its own.
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
    if split.own_devices.is_empty() {
        out.push_str("<p class=\"muted\">None seen.</p>\n");
    } else {
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
        view::thead(
            &mut out,
            &["Machine", "You said", "Since", "Why", "How it was given"],
        );
        for s in &standing {
            out.push_str("<tr>");
            view::td(&mut out, "mono", s.name())?;
            view::td(&mut out, "", &s.word.said)?;
            view::td(&mut out, "nowrap", &utc(s.word.made_at))?;
            view::td(&mut out, "", &s.word.reason)?;
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
    // The page of servers is linked from the summary only where there are some.
    out.push_str(&format!(
        "<li><a href=\"{BEYOND}.html\">Beyond this Mac: servers, your other devices, other people's devices, and machines you set aside</a></li>\n"
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
    fn a_way_read_is_in_every_place_derived_from_the_table_so_adding_a_row_changes_no_code() {
        // Adding a product is adding a row. Every place that tells or acts on what runs by
        // itself takes it from the table: a row read here that one of them missed would be
        // read and never told, or told and never watched live.
        use crate::autorun::{self, POINTS};
        let dir = std::env::temp_dir().join(format!("soc-ways-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
        for p in &POINTS {
            assert!(page.contains(&format!("<td class=\"mono\">{}</td>", esc(&p.name()))));
            if !p.read_here() {
                continue;
            }
            let as_ = p.watched_as().unwrap_or_default();
            let (_, what, line) = p.trigger.watched().unwrap_or_default();
            assert!(!as_.is_empty() && !line.is_empty(), "{}", p.name());
            for path in p.paths {
                assert!(autorun::files().contains(path) && !path.contains('*'));
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
                (p.technique, p.severity, p.confidence),
                "{}",
                p.name()
            );
        }
    }

    /// The section of what is watched for a Mac where every kind is watched, and one kind
    /// that no rule speaks about.
    fn everything_watched() -> String {
        let mut watched: Vec<(&'static str, i64, &'static str)> = covered::watched()
            .into_iter()
            .map(|(_, what, _)| (what, 1, "hourly"))
            .collect();
        watched.push((covered::SAMPLED, 1, "sampled"));
        watched.push(("things of a kind no rule knows", 1, "hourly"));
        let m = covered::ThisMac {
            watched,
            ..covered::ThisMac::unchecked(true)
        };
        let mut out = String::new();
        watched_here(&mut out, &m, &[], None).unwrap();
        out
    }

    /// The same for a Mac where the last check found none of anything, with no watcher.
    fn nothing_found() -> String {
        let none: Vec<&'static str> = covered::watched()
            .into_iter()
            .map(|(_, what, _)| what)
            .collect();
        let mut out = String::new();
        watched_here(&mut out, &covered::ThisMac::unchecked(false), &none, None).unwrap();
        out
    }

    /// Each kind listed, up to where its line ends.
    fn kinds(page: &str) -> Vec<&str> {
        let mut parts: Vec<&str> = page.split("\n</li>\n").collect();
        parts.pop();
        parts
            .into_iter()
            .map(|p| {
                let start = "<ul class=\"counts\">\n";
                p.rfind(start).map_or(p, |i| &p[i + start.len()..])
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
    fn every_rule_is_on_the_page() {
        // The owner reads on the page what he is told about. A rule added later and not
        // placed under a kind, the list of indicators or "Also" would tell him something the
        // page never says it does.
        for page in [everything_watched(), nothing_found()] {
            for r in findings::rules() {
                assert!(page.contains(&esc(r.words.title)), "{}: {page}", r.id);
                assert!(page.contains(&esc(r.words.meaning)), "{}: {page}", r.id);
            }
        }
    }

    #[test]
    fn the_page_never_calls_a_thing_watched_without_saying_what_is_told_about_it() {
        // False calm: a kind listed as watched that no rule can fire about must say so in
        // words, or "watched" promises a warning that never comes.
        let page = everything_watched();
        assert_eq!(kinds(&page).len(), covered::watched().len() + 2, "{page}");
        let empty = nothing_found();
        assert_eq!(kinds(&empty).len(), covered::watched().len() + 1, "{empty}");
        for kind in kinds(&page).into_iter().chain(kinds(&empty)) {
            assert!(kind.starts_with("<li>"), "{kind}");
            let said = kind.contains("<ul class=\"rules\">\n<li>") || kind.contains(KEPT_AS_LIST);
            assert!(said, "{kind}");
        }
        let unknown = &page[page.find("Things of a kind no rule knows").unwrap()..];
        assert!(
            unknown[..unknown.find("</li>").unwrap()].contains(KEPT_AS_LIST),
            "{unknown}"
        );
    }

    #[test]
    fn a_rule_marked_as_sending_a_notification_is_exactly_an_urgent_one() {
        // The page tells the owner which changes notify at once; the app notifies for what
        // is urgent. The two must not disagree.
        let page = everything_watched();
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
