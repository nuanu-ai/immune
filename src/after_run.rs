//! The text for a person of `immune run`, `immune install`, `immune uninstall` and `immune
//! sample`, rendered from the command's message alone for a screen (`screen.rs`), in the layout
//! `overview.rs` set for `immune status`: the answer first, in one line; then what needs the
//! person; then context, one labelled line each; last, the next command after `→`.
//!
//! `immune run` answers with the status the check left, read back from the store (`Status`), so
//! its text is made from that message too: what it raised is told by the findings first seen
//! since the check began, and whether it may say "nothing needs a look" is decided by the
//! status's own rule (`overview::failing`), never by a second one. After the lines that are the
//! run's own (what changed, what was read), it says what the status says of the same store after
//! its headline, from the status's own function (`overview::context`), so a run is never calmer
//! than `immune status`.
//!
//! Text from a source (a path, a name, what a source said of a failure) is escaped as it reaches
//! the screen, before it is measured, cut or styled (`screen.rs`), and is set in a column or
//! beside a label, where its place says it is data.

use crate::contract::v1;
use crate::overview;
use crate::screen::{self, BOLD, Cell, Column, Cut, DIM, GREEN, PLAIN, RED, Screen, Style, YELLOW};
use crate::view;
use std::io::{IsTerminal, Write};

/// The lines of a text, each ended.
fn joined(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

/// A span of seconds as a person reads it: "12 s", "3 min 5 s", "2 h 10 min".
fn duration(seconds: i64) -> String {
    let s = seconds.max(0);
    match s {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min {} s", s / 60, s % 60),
        s => format!("{} h {} min", s / 3600, s % 3600 / 60),
    }
}

/// The findings of one rule, counted: a row of the list of what was found.
struct Group {
    title: String,
    severity: Option<i32>,
    count: u64,
    urgent: u64,
}

/// The fewest columns a value is given beside its label before it goes under it.
const VALUE_ROOM: usize = 12;

/// Whether a screen is too narrow for a column of values `VALUE_ROOM` wide beside labels
/// `width` wide set in by `indent`.
fn narrow(screen: &Screen, indent: usize, width: usize) -> bool {
    screen
        .fits()
        .is_some_and(|w| w < indent + width + 3 + VALUE_ROOM)
}

/// A labelled line as the status sets one, each part in its own style: the value beside the
/// label, or on a screen too narrow for that, under it and set in further, so a count is never
/// broken into pieces of a few columns.
fn beside(screen: &Screen, width: usize, label: &str, parts: &[(String, Style)]) -> Vec<String> {
    let parts: Vec<(&str, Style)> = parts.iter().map(|(t, st)| (t.as_str(), *st)).collect();
    if narrow(screen, 2, width) {
        let mut out = vec![format!("  {}", screen.paint(BOLD, label))];
        out.extend(screen.labelled_parts(4, 0, "", &parts, None, 0));
        out
    } else {
        screen.labelled_parts(2, width, label, &parts, None, 0)
    }
}

/// The rules of the findings first seen at or after `since`, among those the message lists,
/// each counted, in the order the status lists its rules: urgent ones first, then the most
/// severe, then the most findings, then by rule.
fn new_groups(screen: &Screen, n: &v1::NeedsALook, since: i64) -> Vec<Group> {
    let mut groups: Vec<(String, Group)> = Vec::new();
    for item in n.items.iter().filter_map(|i| i.finding.as_ref()) {
        if item.first_seen_at < since {
            continue;
        }
        let r = item.finding.clone().unwrap_or_default();
        let key = r.rule.clone().unwrap_or_else(|| item.short_title.clone());
        let at = match groups.iter().position(|(k, _)| *k == key) {
            Some(at) => at,
            None => {
                let title = overview::short_title(
                    screen,
                    item.rule_title_text.as_deref(),
                    &item.short_title,
                    &item.title,
                );
                groups.push((
                    key,
                    Group {
                        title,
                        severity: r.severity,
                        count: 0,
                        urgent: 0,
                    },
                ));
                groups.len() - 1
            }
        };
        let g = &mut groups[at].1;
        // The most severe of them; not known when one of them is not known.
        g.severity = match (g.severity, r.severity) {
            (Some(a), Some(b)) if overview::rank(Some(b)) > overview::rank(Some(a)) => Some(b),
            (Some(a), Some(_)) => Some(a),
            _ => None,
        };
        g.count += 1;
        g.urgent += u64::from(r.urgent);
    }
    groups.sort_by(|(ka, a), (kb, b)| {
        (b.urgent > 0)
            .cmp(&(a.urgent > 0))
            .then(overview::rank(b.severity).cmp(&overview::rank(a.severity)))
            .then(b.count.cmp(&a.count))
            .then(ka.cmp(kb))
    });
    groups.into_iter().map(|(_, g)| g).collect()
}

/// The rules of every finding that needs a look, as the status counts them.
fn all_groups(screen: &Screen, n: &v1::NeedsALook) -> Vec<Group> {
    n.by_rule
        .iter()
        .map(|g| Group {
            title: overview::short_title(
                screen,
                g.rule_title_text.as_deref(),
                &g.short_title,
                &g.rule,
            ),
            severity: g.severity,
            count: g.count,
            urgent: g.urgent,
        })
        .collect()
}

/// A list of rules under its label: a row each, the first `overview::GROUPS_SHOWN`, then the
/// rest counted in one line, never without how many of them are urgent.
fn groups_section(screen: &Screen, out: &mut Vec<String>, label: &str, groups: &[Group]) {
    out.push(format!("  {}", screen.paint(BOLD, label)));
    let shown = &groups[..groups.len().min(overview::GROUPS_SHOWN)];
    let rows: Vec<Vec<Cell>> = shown
        .iter()
        .map(|g| {
            let (lv, style) = overview::level(g.severity);
            vec![
                Cell::new(lv, style),
                Cell::plain(g.title.clone()),
                Cell::new(overview::grouped(g.count), BOLD),
                Cell::new(overview::urgent_cell(g.count, g.urgent), RED),
            ]
        })
        .collect();
    out.extend(screen.table(
        4,
        &[
            Column::new(Cut::Never),
            Column::new(Cut::End),
            Column::right(Cut::Never),
            Column::new(Cut::Never),
        ],
        None,
        &rows,
    ));
    let rest = &groups[shown.len()..];
    if !rest.is_empty() {
        let more: u64 = rest.iter().map(|g| g.count).sum();
        let urgent: u64 = rest.iter().map(|g| g.urgent).sum();
        let said = format!(
            "… {} more in {}, {}",
            overview::grouped(more),
            overview::count(rest.len() as u64, "kind", "kinds"),
            match urgent {
                0 => "none urgent".to_string(),
                u => format!("{} urgent", overview::grouped(u)),
            }
        );
        let style = if urgent > 0 { RED } else { PLAIN };
        for l in screen::wrap(&said, screen.fits().map(|w| w.saturating_sub(4))) {
            out.push(format!("    {}", screen.paint(style, &l)));
        }
    }
}

/// What the check counted as changed since the check before, by kind of change, with what
/// cannot be known about it.
fn changed(f: &v1::FinishedCheck) -> String {
    let mut said = match &f.since_previous_run {
        None => "nothing to compare with: what this check read is the baseline".to_string(),
        Some(c) => match c.added + c.changed + c.removed {
            0 => "nothing since the last check".to_string(),
            total => format!(
                "{} since the last check: {} added, {} changed, {} removed",
                overview::count(total, "change", "changes"),
                overview::grouped(c.added),
                overview::grouped(c.changed),
                overview::grouped(c.removed)
            ),
        },
    };
    if f.since_previous_run.is_some() && !f.unknown.is_empty() {
        said.push_str(&format!("; {}", f.unknown.join(", ")));
    }
    if f.set_aside > 0 {
        said.push_str(&format!(
            "; {} set aside as no longer read by this version, not counted as removed",
            overview::count(f.set_aside, "fact", "facts")
        ));
    }
    said
}

/// What the store holds of this Mac and its surroundings after the check, counted.
fn read(s: &v1::Status) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(e) = &s.estate {
        parts.push(overview::count(e.checkouts, "project", "projects"));
        parts.push(overview::count(e.components, "package", "packages"));
        parts.push(match e.servers {
            0 => "no servers known".to_string(),
            n => format!(
                "{} known, {} read",
                overview::count(n, "server", "servers"),
                overview::grouped(e.servers_read)
            ),
        });
    }
    if let Some(w) = &s.watched {
        parts.push(format!(
            "{} in watched places",
            overview::count(w.files, "file", "files")
        ));
    }
    if let Some(i) = &s.integrity {
        parts.push(overview::count(i.bundles, "application", "applications"));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// `immune run` for a person, from the status the check left.
pub fn run(s: &v1::Status, screen: &Screen) -> String {
    if !s.store.as_ref().is_some_and(|f| f.exists) {
        return overview::status(s, screen, false);
    }
    let mut out: Vec<String> = Vec::new();
    let finished = s.last_finished_run.as_ref();
    let check = finished.and_then(|f| f.check.as_ref());
    let first = finished.is_some_and(|f| f.first_run);
    let took = check
        .and_then(|c| c.finished_at.map(|end| end - c.started_at))
        .map(|t| format!("took {}", duration(t)));
    let fresh = s.this_mac.as_ref().is_some_and(|m| m.fresh);
    let look = s.needs_a_look.as_ref();
    // What this check raised: the findings first seen since it began, among those listed. The
    // message lists at most some of them and carries no count of those this check opened, so a
    // number of new findings is said only when every finding is listed, and never "none new": a
    // finding opened again keeps the day it was first seen.
    let new = match (look, check) {
        (Some(n), Some(c)) => new_groups(screen, n, c.started_at),
        _ => Vec::new(),
    };
    let new_count: u64 = new.iter().map(|g| g.count).sum();
    let listed = look.map_or(0, |n| n.items.len() as u64);
    let listed_whole = look.is_some_and(|n| listed >= n.total);
    let tail = if first {
        " · the first check of this Mac".to_string()
    } else if new_count > 0 && listed_whole {
        format!(" · {} new in this check", overview::grouped(new_count))
    } else {
        String::new()
    };
    let (answer, style) = match look {
        None => (
            "No run of this build has looked for findings yet".to_string(),
            BOLD,
        ),
        // The status's own rule: calm only when fresh and nothing failed.
        Some(n) if n.total == 0 && fresh && !overview::failing(s) => {
            ("✓ Nothing needs a look".to_string(), GREEN.bold())
        }
        Some(n) if n.total == 0 && fresh => (
            "Nothing needs a look in what could be read".to_string(),
            YELLOW.bold(),
        ),
        Some(n) if n.total == 0 => ("Nothing needed a look at the last check".to_string(), BOLD),
        Some(n) => (
            format!("✗ {}", overview::needing(n.total, n.urgent_total)),
            RED.bold(),
        ),
    };
    let tail = if look.is_some_and(|n| n.total == 0) && !first {
        String::new()
    } else {
        tail
    };
    out.extend(screen.headline(&format!("{answer}{tail}"), style, took.as_deref()));
    // What needs the person: what this check raised, or on the first check all it found. When
    // not every finding is listed, the new ones are those among the listed, and it says so.
    if let Some(n) = look.filter(|n| n.total > 0) {
        let among = format!("New among the {} listed", overview::grouped(listed));
        let (label, groups) = if first {
            ("Found", all_groups(screen, n))
        } else if listed_whole {
            ("New", new)
        } else {
            (among.as_str(), new)
        };
        if !groups.is_empty() {
            out.push(String::new());
            groups_section(screen, &mut out, label, &groups);
        }
    }
    // What the run adds of its own, then all that the status says of the same store after its
    // headline, from the status's own function: never less.
    let mut own: Vec<(&'static str, overview::Parts)> = Vec::new();
    if let Some(f) = finished {
        own.push(("Changed", vec![(changed(f), PLAIN)]));
    }
    if let Some(said) = read(s) {
        own.push(("Read", vec![(said, PLAIN)]));
    }
    out.push(String::new());
    overview::context(s, screen, own, &mut out);
    out.push(String::new());
    let mut next = Vec::new();
    if look.is_some_and(|n| n.total > 0) {
        next.push(("immune findings", "lists every one, most urgent first"));
    }
    next.push(("immune status", "what is watched and what was not read"));
    out.extend(screen.nexts(&next));
    joined(&out)
}

/// The dim line on standard error that says a check is running, while it runs: written only
/// when standard error is a terminal and the screen takes colour, and cleared when this goes.
pub struct Running(bool);

impl Running {
    pub fn start(screen: &Screen) -> Running {
        let on = Running::shown(screen, std::io::stderr().is_terminal());
        if on {
            let mut err = std::io::stderr();
            let _ = write!(err, "{}", screen.paint(DIM, "Checking this Mac…"));
            let _ = err.flush();
        }
        Running(on)
    }

    /// Whether the line is written: standard output a terminal in colour, and standard error a
    /// terminal too, so nothing of it reaches a pipe or a screen without colour.
    fn shown(screen: &Screen, stderr_terminal: bool) -> bool {
        screen.colour && stderr_terminal
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.0 {
            // Back to the start of the line, and the line cleared.
            let mut err = std::io::stderr();
            let _ = write!(err, "\r\u{1b}[2K");
            let _ = err.flush();
        }
    }
}

/// A home folder's path written `~` where a path starts with it.
fn tilde(path: &str, home: Option<&str>) -> String {
    match home.and_then(|h| path.strip_prefix(h)) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

/// Sentences of the core's own, set in by two and broken into lines that fit.
fn sentences(screen: &Screen, out: &mut Vec<String>, text: &str) {
    for l in screen::wrap(text, screen.fits().map(|w| w.saturating_sub(2))) {
        out.push(format!("  {}", screen.paint(PLAIN, &l)));
    }
}

/// One step of what a command did: whether it is done, its label, its value and the value's
/// style.
type Step<'a> = (bool, &'a str, &'a str, Style);

/// Steps, each a line: `✓` green before a step done, the label bold, the value beside it in a
/// column as wide as the widest label.
fn steps(screen: &Screen, out: &mut Vec<String>, list: &[Step]) {
    let width = list
        .iter()
        .map(|(_, label, ..)| screen::columns(label))
        .max()
        .unwrap_or(0);
    for (done, label, value, style) in list {
        out.extend(step(screen, width, *done, label, value, *style));
    }
}

/// A step's line, see `steps`.
fn step(
    screen: &Screen,
    width: usize,
    done: bool,
    label: &str,
    value: &str,
    style: Style,
) -> Vec<String> {
    // On a screen too narrow for a column of values beside the labels, or for a value that does
    // not fit beside its label, such as a path, the value goes under the label, set in further: a
    // path is never broken at a space inside it where it can be helped.
    let shown = screen::columns(&view::shown(value));
    let under = narrow(screen, 4, width)
        || screen
            .fits()
            .is_some_and(|w| shown > w.saturating_sub(4 + width + 3));
    let mut lines = if under {
        let room = screen.fits().map(|w| w.saturating_sub(6));
        let mut lines: Vec<String> = screen::wrap(&view::shown(label), room)
            .iter()
            .map(|l| format!("    {}", screen.paint(BOLD, l)))
            .collect();
        for l in screen::wrap(&view::shown(value), room) {
            lines.push(format!("      {}", screen.paint(style, &l)));
        }
        lines
    } else {
        screen.labelled(4, width, label, value, style, None, 0)
    };
    if done && let Some(first) = lines.first_mut() {
        *first = format!("  {} {}", screen.paint(GREEN, "✓"), &first[4..]);
    }
    lines
}

/// `immune install` and `immune uninstall` for a person: what the command left, as steps,
/// each only as the message says it.
pub fn service(m: &v1::Service, screen: &Screen) -> String {
    // The home folder is where the job's property list is, `~/Library/LaunchAgents`.
    let home = m
        .plist_path_text
        .strip_suffix(&format!("/Library/LaunchAgents/{}.plist", m.label));
    let program = tilde(&m.program_path_text, home);
    let plist = tilde(&m.plist_path_text, home);
    let mut out: Vec<String> = Vec::new();
    let in_place = m.in_place == Some(true);
    if m.installed {
        // The calm mark only when a watcher was seen watching live; a watcher that started and
        // runs its first check is a plain success of the install; one that never started is a
        // failure; unknown is never said as no.
        let headline = match (m.loaded, m.started, m.watching) {
            (true, _, Some(true)) => screen.headline(
                "✓ Immune is installed and watching this Mac",
                GREEN.bold(),
                None,
            ),
            (true, Some(true), _) => screen.headline(
                "Immune is installed and its watcher has started; watching follows its first check",
                BOLD,
                None,
            ),
            (true, Some(false), _) => screen.headline(
                "Immune is installed, but its watcher has not started: check the job and install again",
                RED.bold(),
                None,
            ),
            (true, None, _) => screen.headline(
                "Immune is installed; whether its watcher started is not known",
                YELLOW.bold(),
                None,
            ),
            (false, ..) => screen.headline(
                "Immune is installed, and launchd has not loaded its login job",
                YELLOW.bold(),
                None,
            ),
        };
        out.extend(headline);
        out.push(String::new());
        let core: Step = if in_place {
            (true, "Core run where it is", &program, PLAIN)
        } else {
            (true, "Core in place", &program, PLAIN)
        };
        let mut list = vec![core, (true, "Login job written", &plist, PLAIN)];
        if m.loaded {
            list.push((true, "Loaded by launchd", &m.label, PLAIN));
            let note = m.watcher_note.as_deref().unwrap_or("");
            match (m.started, m.watching) {
                (_, Some(true)) => {
                    list.push((true, "Started", "the watcher holds the store", PLAIN));
                    list.push((true, "Watching", "live", PLAIN));
                }
                (Some(true), _) => {
                    list.push((true, "Started", "the watcher holds the store", PLAIN));
                    list.push((false, "Not watching yet", note, PLAIN));
                }
                (Some(false), _) => list.push((false, "Not started", note, RED)),
                (None, _) => list.push((false, "Started", "not known", YELLOW)),
            }
        } else {
            list.push((false, "Not loaded", &m.label, YELLOW));
        }
        steps(screen, &mut out, &list);
        out.push(String::new());
        let mut said = Vec::new();
        if m.replaced {
            said.push("An earlier installation was there, and this one replaced it.");
        }
        if in_place {
            said.push(
                "The core is run where it was installed, which only an administrator can change, so nothing was copied.",
            );
        }
        said.push(
            "The job is set to start a full check when the core starts and every hour after that.",
        );
        let not_started = m.loaded && m.started == Some(false);
        if not_started {
            said.push(
                "launchd loaded the job and no watcher took the store within 5 seconds. launchctl print gui/$(id -u)/ai.nuanu.immune.watch shows the job's state and its last exit.",
            );
        }
        sentences(screen, &mut out, &said.join(" "));
        out.push(String::new());
        match (m.loaded, m.started, m.watching) {
            (true, _, Some(true)) => {
                out.push(screen.next("immune status", "what has been read so far"));
            }
            (true, Some(true), _) => out.push(screen.next("immune status", "when watching begins")),
            (true, None, _) => {
                out.push(screen.next("immune status", "whether the watcher has started"));
            }
            _ => out.push(screen.next("immune install", "registers the job again")),
        }
    } else if m.replaced {
        out.extend(screen.headline("✓ Immune is uninstalled", GREEN.bold(), None));
        out.push(String::new());
        let loaded: Step = if m.loaded {
            (false, "Still loaded", &m.label, YELLOW)
        } else {
            (true, "Job not loaded", &m.label, PLAIN)
        };
        // A core the job ran where it is was not put there by install, and stays.
        let core: Step = if in_place {
            (false, "Core left where it is", &program, PLAIN)
        } else {
            (true, "No installed core", &program, PLAIN)
        };
        steps(
            screen,
            &mut out,
            &[loaded, (true, "No property list", &plist, PLAIN), core],
        );
        out.push(String::new());
        sentences(
            screen,
            &mut out,
            "The store and the optional event collector were kept.",
        );
        if in_place {
            out.push(String::new());
            sentences(
                screen,
                &mut out,
                "The core is shared by every account of this Mac and is removed with an administrator's password:",
            );
            let word = crate::text::shell_word_or(&m.program_path_text, "<path of the core>");
            out.push(format!(
                "  {}",
                screen.paint(PLAIN, &format!("sudo rm {word}"))
            ));
        }
        out.push(String::new());
        out.push(screen.next("immune install", "installs it again"));
    } else {
        out.extend(screen.headline("Nothing was installed, so nothing was removed", BOLD, None));
        out.push(String::new());
        steps(
            screen,
            &mut out,
            &[
                (false, "No login job", &m.label, PLAIN),
                (false, "No property list", &plist, PLAIN),
                (false, "No installed core", &program, PLAIN),
            ],
        );
        out.push(String::new());
        out.push(screen.next("immune install", "installs it"));
    }
    joined(&out)
}

/// `immune sample` for a person: what it opened, then what it read, counted.
pub fn sample(m: &v1::Sample, screen: &Screen) -> String {
    let p = m.processes.unwrap_or_default();
    let i = m.interpreters.unwrap_or_default();
    let c = m.connections.unwrap_or_default();
    let count = overview::count;
    let unread = p.unreadable + i.arguments_unreadable + c.unreadable;
    let (answer, style) = match m.findings_opened {
        0 if unread > 0 => (
            "No findings opened in what this sample could read".to_string(),
            YELLOW.bold(),
        ),
        0 => (
            "✓ No findings opened by this sample".to_string(),
            GREEN.bold(),
        ),
        n => (
            format!(
                "✗ {} opened by this sample",
                count(n, "finding", "findings")
            ),
            RED.bold(),
        ),
    };
    let mut out: Vec<String> = Vec::new();
    let took = format!("took {} ms", overview::grouped(m.took_ms));
    out.extend(screen.headline(&answer, style, Some(&took)));
    out.push(String::new());
    type Parts = Vec<(String, Style)>;
    let mut lines: Vec<(&str, Parts)> = Vec::new();
    // Each part after the first, put after a comma, only when it counts something.
    let with = |parts: &mut Parts, n: u64, said: String, style: Style| {
        if n > 0 {
            parts.push((", ".to_string(), PLAIN));
            parts.push((said, style));
        }
    };
    let mut processes = vec![(format!("{} read", overview::grouped(p.read)), PLAIN)];
    with(
        &mut processes,
        p.unreadable,
        format!("{} unreadable", overview::grouped(p.unreadable)),
        YELLOW,
    );
    with(
        &mut processes,
        p.ended_while_read,
        format!("{} ended while read", overview::grouped(p.ended_while_read)),
        PLAIN,
    );
    with(
        &mut processes,
        p.other_users,
        format!(
            "{} of other users not read",
            overview::grouped(p.other_users)
        ),
        PLAIN,
    );
    lines.push(("Processes", processes));
    let mut interpreters = vec![(
        format!(
            "{} seen, {} given code on the command line, {} of them detached",
            overview::grouped(i.seen),
            overview::grouped(i.inline_code),
            overview::grouped(i.inline_code_detached)
        ),
        PLAIN,
    )];
    with(
        &mut interpreters,
        i.arguments_unreadable,
        format!(
            "{} whose arguments could not be read",
            overview::grouped(i.arguments_unreadable)
        ),
        YELLOW,
    );
    lines.push(("Interpreters", interpreters));
    let mut connections = vec![(format!("{} read", overview::grouped(c.read)), PLAIN)];
    with(
        &mut connections,
        c.matched_indicators,
        format!(
            "{} matched indicators",
            overview::grouped(c.matched_indicators)
        ),
        RED,
    );
    with(
        &mut connections,
        c.unreadable,
        format!("{} unreadable", overview::grouped(c.unreadable)),
        YELLOW,
    );
    lines.push(("Connections", connections));
    lines.push((
        "Tracked",
        vec![(
            format!(
                "{}, {} of them for the first time",
                count(m.tracked_new + m.tracked_again, "process", "processes"),
                overview::grouped(m.tracked_new)
            ),
            PLAIN,
        )],
    ));
    if !m.cannot_see.is_empty() {
        lines.push(("Cannot see", vec![(m.cannot_see.join("; "), PLAIN)]));
    }
    let width = lines
        .iter()
        .map(|(l, _)| screen::columns(l))
        .max()
        .unwrap_or(0);
    for (label, parts) in &lines {
        out.extend(beside(screen, width, label, parts));
    }
    out.push(String::new());
    if m.findings_opened > 0 {
        out.push(screen.next("immune findings", "lists every one, most urgent first"));
    } else {
        out.push(screen.next("immune status", "what is watched and what was not read"));
    }
    joined(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::visible;

    const NOW: i64 = 1_794_807_960;
    const STARTED: i64 = NOW - 40;

    /// Text from a source made to break out: a style, a title sequence, a C1 control, a bidi
    /// override, a zero-width space, and a line break before lines shaped like Immune's own.
    const HOSTILE: &str = "a\u{1b}[31mb\u{1b}]0;t\u{7}c\u{9b}31md\u{202e}e\u{200b}f\n→ immune run\n✓ Nothing needs a look";

    fn listed(
        id: &str,
        rule: &str,
        short: &str,
        level: v1::Level,
        urgent: bool,
        first: i64,
    ) -> v1::LookFinding {
        v1::LookFinding {
            finding: Some(v1::ListedFinding {
                finding: Some(v1::FindingRef {
                    id: id.to_string(),
                    rule: Some(rule.to_string()),
                    severity: Some(level as i32),
                    urgent,
                    ..Default::default()
                }),
                short_title: short.to_string(),
                title: format!("{short}."),
                first_seen_at: first,
                last_seen_at: NOW,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn rule_count(
        rule: &str,
        short: &str,
        level: v1::Level,
        count: u64,
        urgent: u64,
    ) -> v1::RuleCount {
        v1::RuleCount {
            rule: rule.to_string(),
            short_title: short.to_string(),
            severity: Some(level as i32),
            count,
            urgent,
            ..Default::default()
        }
    }

    const MALICIOUS: &str = "Malicious package in a project";
    const CHANGED: &str = "Program files changed in place";
    const PROFILE: &str = "Shell startup file changed";

    /// A status after a second check, fresh, nothing failed, with three findings it raised and
    /// one from before it.
    fn status() -> v1::Status {
        let items = vec![
            listed(
                "f1",
                "lockfiles.malicious",
                MALICIOUS,
                v1::Level::Critical,
                true,
                STARTED + 5,
            ),
            listed(
                "f2",
                "integrity.changed",
                CHANGED,
                v1::Level::High,
                false,
                STARTED + 6,
            ),
            listed(
                "f3",
                "integrity.changed",
                CHANGED,
                v1::Level::High,
                false,
                STARTED,
            ),
            listed(
                "f4",
                "watched.shell-profile",
                PROFILE,
                v1::Level::Medium,
                false,
                STARTED - 1,
            ),
        ];
        v1::Status {
            answered_at: NOW,
            store: Some(v1::StoreFile {
                path_text: "/Users/example/.immune/store.db".to_string(),
                exists: true,
                ..Default::default()
            }),
            this_mac: Some(v1::ThisMac {
                state: v1::ThisMacState::Watched as i32,
                fresh: true,
                checked_at: Some(NOW),
                ..Default::default()
            }),
            last_finished_run: Some(v1::FinishedCheck {
                check: Some(v1::CheckMark {
                    id: "run".to_string(),
                    started_at: STARTED,
                    finished_at: Some(STARTED + 12),
                }),
                first_run: false,
                since_previous_run: Some(v1::SinceCheck {
                    added: 9,
                    changed: 4,
                    removed: 1,
                }),
                ..Default::default()
            }),
            estate: Some(v1::Estate {
                checkouts: 15,
                components: 70,
                servers: 9,
                servers_read: 7,
                ..Default::default()
            }),
            watched: Some(v1::WatchedPlaces {
                files: 31,
                ..Default::default()
            }),
            needs_a_look: Some(v1::NeedsALook {
                total: 4,
                urgent_total: 1,
                by_rule: vec![
                    rule_count("lockfiles.malicious", MALICIOUS, v1::Level::Critical, 1, 1),
                    rule_count("integrity.changed", CHANGED, v1::Level::High, 2, 0),
                    rule_count("watched.shell-profile", PROFILE, v1::Level::Medium, 1, 0),
                ],
                items,
            }),
            ..Default::default()
        }
    }

    /// A cause of what is not covered that is a failure, about a place from the Mac.
    fn failed_cause(name: &str, reason: &str) -> v1::Uncovered {
        v1::Uncovered {
            id: "watched-not-read".to_string(),
            who: "you".to_string(),
            title: "A watched place could not be read".to_string(),
            count: 1,
            examples_text: vec![name.to_string()],
            examples: vec![v1::UncoveredExample {
                name_text: name.to_string(),
                reason_text: Some(reason.to_string()),
            }],
            class: v1::Cause::Failed as i32,
            holds_on: v1::HoldsOn::ThisMac as i32,
            ..Default::default()
        }
    }

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(visible).collect()
    }

    #[test]
    fn a_run_says_its_answer_then_what_it_raised_then_context_then_the_next_commands() {
        let text = run(&status(), &Screen::pipe());
        let l = lines(&text);
        assert_eq!(
            l[0],
            "✗ 4 things need a look, 1 urgent · 3 new in this check   took 12 s"
        );
        assert_eq!(l[1], "");
        assert_eq!(l[2], "  New");
        assert!(
            l[3].starts_with(&format!("    critical  {MALICIOUS}")) && l[3].ends_with("1  urgent"),
            "{text}"
        );
        assert!(
            l[4].starts_with(&format!("    high      {CHANGED}")) && l[4].ends_with('2'),
            "{text}"
        );
        assert_eq!(l[5], "");
        assert_eq!(
            l[6],
            "  Changed      14 changes since the last check: 9 added, 4 changed, 1 removed"
        );
        assert_eq!(
            l[7],
            "  Read         15 projects, 70 packages, 9 servers known, 7 read, 31 files in watched places"
        );
        // Then what the status says of the same store, in its words.
        assert_eq!(
            l[8],
            "  Watching     no watcher runs now: changes are seen at each check"
        );
        assert_eq!(l[9], "  Coverage     nothing has been read yet");
        assert_eq!(l[10], "");
        assert_eq!(
            l[11],
            "→ immune findings   lists every one, most urgent first"
        );
        // What they do is lined up.
        assert_eq!(
            l[12],
            "→ immune status     what is watched and what was not read"
        );
        assert_eq!(l.len(), 13, "{text}");
        // What was found before this check is not among what it raised.
        assert!(!text.contains(PROFILE), "{text}");
    }

    /// The lines a screen of the store says between what needs a look and the next steps.
    fn context_lines(text: &str) -> Vec<String> {
        let l = lines(text);
        let blanks: Vec<usize> = (0..l.len()).filter(|&i| l[i].is_empty()).collect();
        let [.., from, to] = blanks[..] else {
            panic!("{text}")
        };
        l[from + 1..to].to_vec()
    }

    #[test]
    fn a_run_never_says_less_than_the_status_of_the_same_store_after_its_headline() {
        let calm = || {
            let mut s = status();
            s.needs_a_look = Some(v1::NeedsALook::default());
            s.this_mac.as_mut().unwrap().live = true;
            s.watching = Some(v1::Watcher::default());
            s.coverage = Some(v1::CoverageSummary::default());
            s
        };
        let not_seen = v1::Uncovered {
            id: "program-starts-not-seen".to_string(),
            who: "you".to_string(),
            title: "Program starts on this Mac are not seen".to_string(),
            count: 1,
            class: v1::Cause::NotGiven as i32,
            holds_on: v1::HoldsOn::ThisMac as i32,
            ..Default::default()
        };
        let mut states = vec![("calm", calm())];
        let mut s = calm();
        s.event_level = Some(v1::EventLevel {
            state: v1::CollectorState::NotInstalled as i32,
            in_words: Some(v1::EventLevelWords {
                state: "not installed".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        s.coverage.as_mut().unwrap().not_given = 2;
        s.not_covered = vec![not_seen];
        states.push(("event level not installed, readings not given", s));
        let mut s = calm();
        s.not_covered = vec![failed_cause("~/.zshrc", "Permission denied")];
        s.coverage.as_mut().unwrap().failed = 1;
        states.push(("a failed reading", s));
        let mut s = calm();
        s.watching = None;
        s.this_mac.as_mut().unwrap().live = false;
        states.push(("no watcher", s));
        let mut s = status();
        s.watching = Some(v1::Watcher {
            failed: vec![v1::WatcherFailure {
                what: "fsevents".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        });
        states.push(("a watcher that failed, with findings", s));
        for (name, s) in &states {
            for screen in [
                Screen::pipe(),
                Screen::terminal(80, false),
                Screen::terminal(40, false),
            ] {
                let ran = run(s, &screen);
                let status_text = overview::status(s, &screen, false);
                let said = context_lines(&ran);
                for line in context_lines(&status_text) {
                    assert!(
                        said.contains(&line),
                        "{name}: {line:?}\n{ran}\n{status_text}"
                    );
                }
                // And never calmer in its headline.
                assert!(
                    !ran.starts_with('✓') || status_text.starts_with('✓'),
                    "{name}\n{ran}\n{status_text}"
                );
            }
        }
        // The causes are said in the run, by name.
        let text = run(&states[1].1, &Screen::pipe());
        for said in [
            "You can fix",
            "Program starts on this Mac are not seen",
            "readings their source does not give",
            "not installed",
        ] {
            assert!(text.contains(said), "{said}: {text}");
        }
    }

    #[test]
    fn a_run_reads_calm_only_when_the_status_s_own_rule_allows_it() {
        let mut calm = status();
        calm.needs_a_look = Some(v1::NeedsALook::default());
        let text = run(&calm, &Screen::pipe());
        assert!(
            text.starts_with("✓ Nothing needs a look   took 12 s\n"),
            "{text}"
        );
        // A reading that failed: the status's rule says it is not calm, and the failure is said.
        let mut failed = calm.clone();
        failed.not_covered = vec![failed_cause("~/.zshrc", "Permission denied")];
        let text = run(&failed, &Screen::pipe());
        assert!(
            text.starts_with("Nothing needs a look in what could be read"),
            "{text}"
        );
        assert!(!text.contains('✓'), "{text}");
        assert!(
            text.contains("  Failed\n    A watched place could not be read\n"),
            "{text}"
        );
        assert!(text.contains("~/.zshrc: Permission denied"), "{text}");
        // A status that is not fresh is never calm.
        let mut stale = calm.clone();
        stale.this_mac.as_mut().unwrap().fresh = false;
        assert!(!run(&stale, &Screen::pipe()).contains('✓'));
        // A download that failed is said with its word; whether the headline is calm is the
        // status's own decision, the same in both.
        let mut download = calm;
        download.threats = Some(v1::Threats {
            outcome: v1::FeedOutcome::Failed as i32,
            ..Default::default()
        });
        let text = run(&download, &Screen::pipe());
        let status_text = overview::status(&download, &Screen::pipe(), false);
        assert_eq!(
            text.starts_with('✓'),
            status_text.starts_with('✓'),
            "{text}\n{status_text}"
        );
        assert!(
            text.contains("Downloads    CISA catalogue not downloaded, nothing of it is known yet"),
            "{text}"
        );
    }

    #[test]
    fn a_failure_in_a_run_is_never_dim() {
        let mut s = status();
        s.not_covered = vec![failed_cause("~/.zshrc", "Permission denied")];
        s.threats = Some(v1::Threats {
            outcome: v1::FeedOutcome::Failed as i32,
            ..Default::default()
        });
        let text = run(&s, &Screen::terminal(100, true));
        let failing: Vec<&str> = text
            .lines()
            .filter(|l| {
                l.contains("could not be read")
                    || l.contains("not downloaded")
                    || l.contains("Permission")
            })
            .collect();
        assert_eq!(failing.len(), 3, "{text}");
        for line in failing {
            assert!(!line.contains("\u{1b}[2m"), "{line:?}");
        }
        assert!(
            text.contains("\u{1b}[31mA watched place could not be read\u{1b}[0m"),
            "{text:?}"
        );
        // A machine not reached is said by itself, with nothing else failed.
        let mut unreached = status();
        unreached.coverage = Some(v1::CoverageSummary {
            unreached: vec![v1::Unreached {
                scope_text: "machine:build-box".to_string(),
                since_at: STARTED,
                reason_text: Some("timed out".to_string()),
            }],
            unreached_total: 1,
            ..Default::default()
        });
        let text = run(&unreached, &Screen::pipe());
        assert!(
            text.contains("\n  Coverage ")
                && text.contains("build-box")
                && text.contains("timed out"),
            "{text}"
        );
    }

    #[test]
    fn a_run_counts_as_new_only_what_this_check_first_saw_and_no_number_it_cannot_know() {
        let mut s = status();
        for i in &mut s.needs_a_look.as_mut().unwrap().items {
            i.finding.as_mut().unwrap().first_seen_at = STARTED - 1;
        }
        // None first seen in this check is not "none new": one may have been opened again.
        let text = run(&s, &Screen::pipe());
        assert!(
            text.starts_with("✗ 4 things need a look, 1 urgent   took"),
            "{text}"
        );
        assert!(!text.contains("New") && !text.contains("new"), "{text}");
        // More findings than the message lists: no count of new ones, and the rows say they are
        // those among the listed.
        let mut cut = status();
        cut.needs_a_look.as_mut().unwrap().total = 400;
        let text = run(&cut, &Screen::pipe());
        assert!(
            text.starts_with("✗ 400 things need a look, 1 urgent   took"),
            "{text}"
        );
        assert!(text.contains("\n  New among the 4 listed\n"), "{text}");
        // And none of the listed ones new says nothing of the rest.
        let mut unknown = s;
        unknown.needs_a_look.as_mut().unwrap().total = 400;
        let text = run(&unknown, &Screen::pipe());
        assert!(
            text.starts_with("✗ 400 things need a look, 1 urgent   took"),
            "{text}"
        );
    }

    #[test]
    fn the_rules_a_run_raised_are_ordered_urgent_then_severe_then_most() {
        let mut s = status();
        let items = &mut s.needs_a_look.as_mut().unwrap().items;
        items.push(listed(
            "f5",
            "z.low",
            "Low thing",
            v1::Level::Low,
            false,
            STARTED + 1,
        ));
        items.push(listed(
            "f6",
            "a.low",
            "Other low thing",
            v1::Level::Low,
            false,
            STARTED + 1,
        ));
        // A rule whose findings differ in severity is said at its most severe.
        items.push(listed(
            "f7",
            "a.low",
            "Other low thing",
            v1::Level::Medium,
            false,
            STARTED + 1,
        ));
        items.push(listed(
            "f8",
            "b.high",
            "High urgent",
            v1::Level::High,
            true,
            STARTED + 1,
        ));
        let mut unknown = listed(
            "f9",
            "b.high",
            "High urgent",
            v1::Level::High,
            false,
            STARTED,
        );
        unknown
            .finding
            .as_mut()
            .unwrap()
            .finding
            .as_mut()
            .unwrap()
            .severity = None;
        items.push(unknown);
        s.needs_a_look.as_mut().unwrap().total = 9;
        let text = run(&s, &Screen::pipe());
        // A severity that is not known is taken as the most severe, as the status takes it.
        let order: Vec<&str> = [
            "High urgent",
            MALICIOUS,
            CHANGED,
            "Other low thing",
            "Low thing",
        ]
        .into_iter()
        .collect();
        let at: Vec<usize> = order.iter().map(|t| text.find(t).unwrap()).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{text}");
        // A rule with a finding whose severity is not known is said so, never as its known one.
        assert!(text.contains("    not known  High urgent "), "{text}");
        assert!(
            text.lines()
                .any(|l| l.contains("medium     Other low thing") && l.ends_with(" 2")),
            "{text}"
        );
    }

    #[test]
    fn a_run_lists_six_rules_and_counts_the_rest_with_how_many_are_urgent() {
        let with = |urgent: bool| {
            let mut s = status();
            let items = &mut s.needs_a_look.as_mut().unwrap().items;
            for i in 0..8 {
                let rule = format!("rule.{i}");
                items.push(listed(
                    "f",
                    &rule,
                    &rule,
                    v1::Level::Low,
                    urgent,
                    STARTED + 1,
                ));
            }
            s.needs_a_look.as_mut().unwrap().total = 12;
            s
        };
        let text = run(&with(false), &Screen::pipe());
        assert!(
            text.contains("\n    … 4 more in 4 kinds, none urgent\n"),
            "{text}"
        );
        assert!(
            text.contains("rule.3") && !text.contains("rule.4"),
            "{text}"
        );
        // Urgent ones come first, and those left out are counted with how many are urgent, red.
        let text = run(&with(true), &Screen::terminal(80, true));
        assert!(
            text.contains("    \u{1b}[31m… 5 more in 4 kinds, 3 urgent\u{1b}[0m\n"),
            "{text:?}"
        );
    }

    #[test]
    fn a_first_run_says_it_is_the_first_and_lists_all_it_found() {
        let mut s = status();
        let f = s.last_finished_run.as_mut().unwrap();
        f.first_run = true;
        f.since_previous_run = None;
        let text = run(&s, &Screen::pipe());
        let l = lines(&text);
        assert_eq!(
            l[0],
            "✗ 4 things need a look, 1 urgent · the first check of this Mac   took 12 s"
        );
        assert_eq!(l[2], "  Found");
        assert!(text.contains(PROFILE), "{text}");
        assert!(
            text.contains("nothing to compare with: what this check read is the baseline"),
            "{text}"
        );
        let mut calm = s.clone();
        calm.needs_a_look = Some(v1::NeedsALook::default());
        let text = run(&calm, &Screen::pipe());
        assert!(
            text.starts_with("✓ Nothing needs a look · the first check of this Mac"),
            "{text}"
        );
    }

    #[test]
    fn a_run_says_nothing_the_message_does_not_hold() {
        let mut s = status();
        s.estate = None;
        s.watched = None;
        s.needs_a_look = Some(v1::NeedsALook::default());
        let text = run(&s, &Screen::pipe());
        for absent in [
            "Read",
            "Failed",
            "Not judged",
            "Downloads",
            "Event level",
            "immune findings",
            "New",
        ] {
            assert!(!text.contains(absent), "{absent}: {text}");
        }
        // Without a finished check, no time and no changes are made up.
        s.last_finished_run = None;
        let text = run(&s, &Screen::pipe());
        assert!(
            !text.contains("took") && !text.contains("Changed"),
            "{text}"
        );
    }

    #[test]
    fn a_run_says_what_cannot_be_known_of_its_changes_and_what_was_set_aside() {
        let mut s = status();
        let f = s.last_finished_run.as_mut().unwrap();
        f.unknown = vec!["removals unknown where a reading was partial".to_string()];
        f.set_aside = 2;
        let text = run(&s, &Screen::pipe());
        assert!(
            text.contains(
                "1 removed; removals unknown where a reading was partial; 2 facts set aside as no longer read by this version, not counted as removed"
            ),
            "{text}"
        );
        // With nothing to compare with, what cannot be known of the changes is not said.
        let mut baseline = s.clone();
        let f = baseline.last_finished_run.as_mut().unwrap();
        f.since_previous_run = None;
        f.set_aside = 0;
        let text = run(&baseline, &Screen::pipe());
        assert!(
            text.contains("what this check read is the baseline\n") && !text.contains("partial"),
            "{text}"
        );
        f_none(&mut s);
        assert!(run(&s, &Screen::pipe()).contains("Changed      nothing since the last check"));
    }

    fn f_none(s: &mut v1::Status) {
        let f = s.last_finished_run.as_mut().unwrap();
        f.since_previous_run = Some(v1::SinceCheck::default());
        f.unknown.clear();
        f.set_aside = 0;
    }

    /// No hidden character, no control and no style of a source's reaches the screen: every
    /// escape sequence is one the screen wrote, and no line from a source reads as Immune's own.
    fn assert_inert(text: &str, colour: bool) {
        for c in text.chars() {
            assert!(
                c == '\n' || c == '\u{1b}' || !crate::icu::hidden(c),
                "{c:?} in {text:?}"
            );
        }
        if !colour {
            assert!(!text.contains('\u{1b}'), "{text:?}");
        }
        let mut rest = text;
        while let Some(at) = rest.find('\u{1b}') {
            let after = &rest[at + 1..];
            let end = after.find('m').expect("a style ends with m");
            let codes = &after[..end];
            assert!(
                codes.starts_with('[')
                    && codes[1..]
                        .split(';')
                        .all(|c| ["0", "1", "2", "31", "32", "33", "36"].contains(&c)),
                "{codes:?} in {text:?}"
            );
            rest = &after[end..];
        }
        for line in text.lines().map(visible) {
            assert!(!line.trim_start().starts_with("→ immune run"), "{line}");
            assert!(!line.trim_start().starts_with("✓ Nothing"), "{line}");
        }
    }

    #[test]
    fn source_text_in_a_run_cannot_style_hide_or_start_a_line_of_its_own() {
        let mut s = status();
        s.needs_a_look.as_mut().unwrap().items[0]
            .finding
            .as_mut()
            .unwrap()
            .rule_title_text = Some(HOSTILE.to_string());
        s.not_covered = vec![
            failed_cause(HOSTILE, HOSTILE),
            v1::Uncovered {
                who: "nothing".to_string(),
                title: "Not judged".to_string(),
                class: v1::Cause::NoReader as i32,
                examples_text: vec![HOSTILE.to_string()],
                holds_on: v1::HoldsOn::ThisMac as i32,
                value_text: Some(HOSTILE.to_string()),
                ..Default::default()
            },
        ];
        s.coverage = Some(v1::CoverageSummary {
            failed: 1,
            unreached_total: 1,
            unreached: vec![v1::Unreached {
                scope_text: HOSTILE.to_string(),
                since_at: NOW - 600,
                reason_text: Some(HOSTILE.to_string()),
            }],
            ..Default::default()
        });
        s.vulnerability_data = Some(v1::VulnerabilityData {
            feeds: vec![v1::FeedState {
                ecosystem: "npm".to_string(),
                outcome: v1::FeedOutcome::Failed as i32,
                reason_text: Some(HOSTILE.to_string()),
                ..Default::default()
            }],
            ..Default::default()
        });
        for screen in [
            Screen::pipe(),
            Screen::terminal(80, true),
            Screen::terminal(80, false),
        ] {
            let text = run(&s, &screen);
            assert_inert(&text, screen.colour);
            assert!(text.contains(r"\u{1b}[31m"), "{text}");
        }
    }

    #[test]
    fn source_text_in_install_and_uninstall_cannot_style_hide_or_start_a_line_of_its_own() {
        for installed in [true, false] {
            let m = v1::Service {
                label: crate::service::LABEL.to_string(),
                // The home the property list names is not where the core is: both shown whole.
                program_path_text: format!("/Users/example/{HOSTILE}/bin/immune"),
                plist_path_text: format!(
                    "/Users/{HOSTILE}/Library/LaunchAgents/ai.nuanu.immune.watch.plist"
                ),
                installed,
                loaded: installed,
                replaced: true,
                ..Default::default()
            };
            for screen in [Screen::pipe(), Screen::terminal(80, true)] {
                let text = service(&m, &screen);
                assert_inert(&text, screen.colour);
                assert!(text.contains(r"\u{202e}"), "{text}");
            }
        }
    }

    fn installed() -> v1::Service {
        v1::Service {
            label: crate::service::LABEL.to_string(),
            program_path_text:
                "/Users/example/Library/Application Support/ai.nuanu.immune/bin/immune".to_string(),
            plist_path_text: "/Users/example/Library/LaunchAgents/ai.nuanu.immune.watch.plist"
                .to_string(),
            installed: true,
            loaded: true,
            replaced: true,
            in_place: Some(false),
            started: Some(true),
            watching: Some(true),
            ..Default::default()
        }
    }

    /// The calm mark heads the text only when a watcher was seen watching live.
    #[test]
    fn install_is_calm_only_when_a_watcher_watches() {
        let text = service(&installed(), &Screen::pipe());
        assert!(
            text.starts_with("✓ Immune is installed and watching this Mac\n")
                && text.contains("\n  ✓ Started             the watcher holds the store\n")
                && text.contains("\n  ✓ Watching            live\n")
                && text.ends_with("→ immune status   what has been read so far\n"),
            "{text}"
        );
    }

    /// A watcher that started and runs its first check is a plain success of the install: not
    /// the calm mark of a watched Mac, and not a warning; where to look next is said.
    #[test]
    fn a_started_watcher_on_its_first_check_is_a_plain_success_of_the_install() {
        let first_check = v1::Service {
            watching: Some(false),
            watcher_note: Some(crate::watch::STARTING_WORDS.to_string()),
            ..installed()
        };
        let text = service(&first_check, &Screen::pipe());
        assert!(
            text.starts_with(
                "Immune is installed and its watcher has started; watching follows its first check\n"
            ) && text.contains("\n  ✓ Started             the watcher holds the store\n")
                && text.contains(&format!(
                    "\n    Not watching yet    {}\n",
                    crate::watch::STARTING_WORDS
                ))
                && text.ends_with("→ immune status   when watching begins\n"),
            "{text}"
        );
        let coloured = service(&first_check, &Screen::terminal(200, true));
        assert!(
            coloured.starts_with("\u{1b}[1mImmune is installed and its watcher"),
            "{coloured:?}"
        );
    }

    /// A job launchd loaded whose watcher never started is said as a failure, in red, with what
    /// to do; it is never said to have started.
    #[test]
    fn a_job_whose_watcher_never_started_is_a_failure_with_what_to_do() {
        let never = v1::Service {
            started: Some(false),
            watching: Some(false),
            watcher_note: Some("no watcher runs on the store now".to_string()),
            ..installed()
        };
        let text = service(&never, &Screen::pipe());
        assert!(
            text.starts_with("Immune is installed, but its watcher has not started: check the job and install again\n")
                && text.contains("\n    Not started         no watcher runs on the store now\n")
                && !text.contains("Started ")
                && text.contains("launchctl print gui/$(id -u)/ai.nuanu.immune.watch")
                && text.ends_with("→ immune install   registers the job again\n"),
            "{text}"
        );
        let coloured = service(&never, &Screen::terminal(200, true));
        assert!(
            coloured.starts_with("\u{1b}[1;31mImmune is installed, but"),
            "{coloured:?}"
        );
    }

    /// One that could not be told is said as not known, never as not started.
    #[test]
    fn install_says_unknown_as_not_known_and_never_as_no() {
        let unknown = v1::Service {
            started: None,
            watching: None,
            ..installed()
        };
        let text = service(&unknown, &Screen::pipe());
        assert!(
            text.starts_with("Immune is installed; whether its watcher started is not known\n")
                && text.contains("\n    Started             not known\n")
                && !text.contains("Not started")
                && !text.contains("Not watching"),
            "{text}"
        );
    }

    /// A core run where it is is named as such after install, and after uninstall it is said to
    /// stay where it is, never to be gone.
    #[test]
    fn a_core_run_where_it_is_is_named_and_uninstall_says_it_stays() {
        let in_place = v1::Service {
            program_path_text: "/usr/local/bin/immune".to_string(),
            in_place: Some(true),
            ..installed()
        };
        let text = service(&in_place, &Screen::pipe());
        assert!(
            text.contains("\n  ✓ Core run where it is   /usr/local/bin/immune\n")
                && text.contains("so nothing was copied"),
            "{text}"
        );
        let removed = v1::Service {
            installed: false,
            loaded: false,
            watching: None,
            ..in_place
        };
        let text = service(&removed, &Screen::pipe());
        assert!(
            text.contains("\n    Core left where it is   /usr/local/bin/immune\n")
                && text.contains(
                    "removed with an administrator's password:\n  sudo rm /usr/local/bin/immune\n"
                )
                && !text.contains("No installed core"),
            "{text}"
        );
        // A path is one word when pasted, and one that cannot be pasted exactly is not printed.
        let spaced = v1::Service {
            program_path_text: "/usr/local/bin/im mune; rm -rf ~".to_string(),
            ..removed.clone()
        };
        let text = service(&spaced, &Screen::pipe());
        assert!(
            text.contains("  sudo rm '/usr/local/bin/im mune; rm -rf ~'\n"),
            "{text}"
        );
        let hidden = v1::Service {
            program_path_text: "/usr/local/bin/im\u{202e}mune".to_string(),
            ..removed
        };
        let text = service(&hidden, &Screen::pipe());
        assert!(text.contains("  sudo rm <path of the core>\n"), "{text}");
    }

    #[test]
    fn nothing_is_wider_than_the_terminal_and_no_width_panics() {
        let mut s = status();
        s.not_covered = vec![failed_cause(
            &"~/dev/a-very-long-project-name/".repeat(4),
            &"Permission denied ".repeat(6),
        )];
        s.needs_a_look.as_mut().unwrap().items[0]
            .finding
            .as_mut()
            .unwrap()
            .rule_title_text =
            Some("A published rule whose own title is a great deal longer than forty-four".into());
        let uninstalled = v1::Service {
            installed: false,
            loaded: false,
            ..installed()
        };
        let sample_m = sample_message(1_234_567, 3);
        for width in [120, 80, 40, 20] {
            let screen = Screen::terminal(width, true);
            for text in [
                run(&s, &screen),
                service(&installed(), &screen),
                service(&uninstalled, &screen),
                sample(&sample_m, &screen),
            ] {
                for line in text.lines() {
                    // At 20 columns a row of what is never cut, a level, a count and the word
                    // urgent with the room between them, is wider than the screen; it stays whole.
                    let never_cut = width == 20 && line.contains("urgent");
                    assert!(
                        screen::columns(&visible(line)) <= width || never_cut,
                        "{width}: {line:?}"
                    );
                }
            }
            // Counts and levels are never cut.
            let text = run(&s, &screen);
            assert!(
                text.contains("critical") && text.contains("urgent"),
                "{width}: {text}"
            );
            assert!(sample(&sample_m, &screen).contains("1,234,567"), "{width}");
        }
    }

    #[test]
    fn install_says_only_the_steps_the_message_says_were_done() {
        let not_loaded = v1::Service {
            loaded: false,
            replaced: false,
            ..installed()
        };
        let text = service(&not_loaded, &Screen::pipe());
        assert!(
            text.starts_with("Immune is installed, and launchd has not loaded its login job\n"),
            "{text}"
        );
        assert!(
            !text.contains("Loaded by launchd") && !text.contains("replaced"),
            "{text}"
        );
        assert!(
            text.contains("\n    Not loaded          ai.nuanu.immune.watch\n"),
            "{text}"
        );
        assert!(
            text.ends_with("→ immune install   registers the job again\n"),
            "{text}"
        );
        let text = service(&installed(), &Screen::pipe());
        assert_eq!(
            lines(&text)[..5],
            [
                "✓ Immune is installed and watching this Mac",
                "",
                "  ✓ Core in place       ~/Library/Application Support/ai.nuanu.immune/bin/immune",
                "  ✓ Login job written   ~/Library/LaunchAgents/ai.nuanu.immune.watch.plist",
                "  ✓ Loaded by launchd   ai.nuanu.immune.watch",
            ]
        );
        // A path that does not fit beside its label goes whole under it; one that fits stays.
        let narrow = lines(&service(&installed(), &Screen::terminal(75, false)));
        assert_eq!(narrow[2], "  ✓ Core in place");
        assert_eq!(
            narrow[3],
            "      ~/Library/Application Support/ai.nuanu.immune/bin/immune"
        );
        assert_eq!(
            narrow[4],
            "  ✓ Login job written   ~/Library/LaunchAgents/ai.nuanu.immune.watch.plist"
        );
        assert!(
            text.contains("An earlier installation was there, and this one replaced it."),
            "{text}"
        );
        // The mark of a step done is green beside words that say it.
        let coloured = service(&installed(), &Screen::terminal(100, true));
        assert!(
            coloured.contains("  \u{1b}[32m✓\u{1b}[0m \u{1b}[1mCore in place\u{1b}[0m"),
            "{coloured:?}"
        );
    }

    #[test]
    fn uninstall_says_what_is_left_and_kept_and_nothing_removed_when_nothing_was_there() {
        let removed = v1::Service {
            installed: false,
            loaded: false,
            ..installed()
        };
        let text = service(&removed, &Screen::pipe());
        assert!(text.starts_with("✓ Immune is uninstalled\n"), "{text}");
        assert!(
            text.contains("  ✓ Job not loaded      ai.nuanu.immune.watch\n")
                && text.contains("  ✓ No property list    ~/Library/LaunchAgents/")
                && text.contains("The store and the optional event collector were kept."),
            "{text}"
        );
        let still = service(
            &v1::Service {
                loaded: true,
                ..removed.clone()
            },
            &Screen::pipe(),
        );
        assert!(
            still.contains("\n    Still loaded ") && !still.contains("Job not loaded"),
            "{still}"
        );
        let nothing = service(
            &v1::Service {
                replaced: false,
                ..removed
            },
            &Screen::pipe(),
        );
        assert!(
            nothing.starts_with("Nothing was installed, so nothing was removed\n")
                && !nothing.contains('✓')
                && !nothing.contains("kept")
                && nothing.contains("\n    No login job        ai.nuanu.immune.watch\n"),
            "{nothing}"
        );
    }

    #[test]
    fn a_path_outside_the_home_is_shown_whole() {
        let home = Some("/Users/example");
        assert_eq!(tilde("/Users/examplex/a", home), "/Users/examplex/a");
        assert_eq!(tilde("/Users/example/a", home), "~/a");
        assert_eq!(tilde("/Users/example", home), "~");
        assert_eq!(tilde("/Users/example/a", None), "/Users/example/a");
    }

    fn sample_message(read: u64, opened: u64) -> v1::Sample {
        v1::Sample {
            took_ms: 3,
            processes: Some(v1::SampleProcesses {
                read,
                unreadable: 0,
                ended_while_read: 0,
                other_users: 7,
            }),
            interpreters: Some(v1::SampleInterpreters {
                seen: 4,
                arguments_unreadable: 0,
                inline_code: 3,
                inline_code_detached: 2,
            }),
            connections: Some(v1::SampleConnections {
                read: 2,
                ..Default::default()
            }),
            tracked_new: 1,
            tracked_again: 2,
            findings_opened: opened,
            cannot_see: vec!["processes of other users".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn a_sample_says_first_what_it_opened_with_the_plural_right() {
        let one = sample(&sample_message(5, 1), &Screen::pipe());
        let l = lines(&one);
        assert_eq!(l[0], "✗ 1 finding opened by this sample   took 3 ms");
        assert_eq!(l[2], "  Processes      5 read, 7 of other users not read");
        assert_eq!(
            l[3],
            "  Interpreters   4 seen, 3 given code on the command line, 2 of them detached"
        );
        assert_eq!(l[4], "  Connections    2 read");
        assert_eq!(
            l[5],
            "  Tracked        3 processes, 1 of them for the first time"
        );
        assert_eq!(l[6], "  Cannot see     processes of other users");
        assert_eq!(
            l.last().map(String::as_str),
            Some("→ immune findings   lists every one, most urgent first")
        );
        assert!(sample(&sample_message(5, 2), &Screen::pipe()).starts_with("✗ 2 findings opened"));
        let none = sample(&sample_message(5, 0), &Screen::pipe());
        assert!(
            none.starts_with("✓ No findings opened by this sample"),
            "{none}"
        );
        assert!(none.ends_with("→ immune status   what is watched and what was not read\n"));
        // What could not be read keeps its word, and the headline is not calm.
        let mut unread = sample_message(5, 0);
        unread.processes.as_mut().unwrap().unreadable = 2;
        unread.processes.as_mut().unwrap().ended_while_read = 1;
        unread.interpreters.as_mut().unwrap().arguments_unreadable = 1;
        unread.connections.as_mut().unwrap().unreadable = 1;
        unread.connections.as_mut().unwrap().matched_indicators = 1;
        let text = sample(&unread, &Screen::pipe());
        assert!(
            text.starts_with("No findings opened in what this sample could read"),
            "{text}"
        );
        assert!(
            text.contains("5 read, 2 unreadable, 1 ended while read, 7 of other users not read"),
            "{text}"
        );
        assert!(
            text.contains("2 of them detached, 1 whose arguments could not be read"),
            "{text}"
        );
        assert!(
            text.contains("2 read, 1 matched indicators, 1 unreadable"),
            "{text}"
        );
        // One connection that could not be read is enough to keep the headline from calm.
        let mut one = sample_message(5, 0);
        one.connections.as_mut().unwrap().unreadable = 1;
        assert!(
            sample(&one, &Screen::pipe()).starts_with("No findings opened in what this sample")
        );
        let coloured = sample(&unread, &Screen::terminal(120, true));
        assert!(
            coloured.contains("\u{1b}[33m2 unreadable\u{1b}[0m"),
            "{coloured:?}"
        );
    }

    #[test]
    fn the_running_line_is_only_for_a_terminal_in_colour() {
        assert!(Running::shown(&Screen::terminal(80, true), true));
        assert!(!Running::shown(&Screen::terminal(80, true), false));
        assert!(!Running::shown(&Screen::terminal(80, false), true));
        assert!(!Running::shown(&Screen::pipe(), true));
    }

    #[test]
    fn a_duration_is_said_in_the_largest_units_that_fit() {
        assert_eq!(duration(12), "12 s");
        assert_eq!(duration(60), "1 min 0 s");
        assert_eq!(duration(185), "3 min 5 s");
        assert_eq!(duration(3599), "59 min 59 s");
        assert_eq!(duration(3600), "1 h 0 min");
        assert_eq!(duration(3600 + 600), "1 h 10 min");
        assert_eq!(duration(-3), "0 s");
    }
}
