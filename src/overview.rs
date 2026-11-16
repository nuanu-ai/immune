//! The text for a person of `immune status`, `immune status --coverage` and `immune findings`,
//! rendered from the message alone for a screen (`screen.rs`), in the layout of the core's
//! language for a person (`docs/how-it-works.md`): the answer first, in one line with the count
//! that matters; then what needs the person, most urgent first, grouped where rows would repeat;
//! then context, one labelled line each, with the detail behind a named command; last, the next
//! command after `→`. On a terminal no line is longer than the width; in a pipe nothing is cut,
//! no style is written and times are exact.
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`), and every piece of text is escaped again as it reaches the screen, before
//! it is measured, cut or styled (`screen.rs`). In a column or beside a label it is data by its
//! place and goes without quotes; inside a sentence it keeps them (`text::quoted`).
//!
//! Nothing a status says is calmer than the message: what needs a look is never counted without
//! how many are urgent; a failure, a loss or what is not judged is in the default status or in
//! `--coverage`, and a failure is always in the default status, never dim.

use crate::contract::v1;
use crate::findings::SHORT_MAX;
use crate::screen::{
    self, BOLD, CYAN, Cell, Column, Cut, DIM, GREEN, PLAIN, RED, Screen, Style, YELLOW,
};
use crate::text::{quoted, word};
use crate::view;

/// At most this many findings are listed in the text of `immune findings`; the total is always
/// given.
const FINDINGS_SHOWN: usize = 200;

/// At most this many rules are listed in the text of `immune status`; the rest are counted in
/// one line.
const GROUPS_SHOWN: usize = 6;

/// The causes of what is not covered that are a reading or a download that failed, which nobody
/// can fix: the default status lists them with the failures, not among what is not judged.
const FAILED_CAUSES: [&str; 3] = [
    "could-not-read",
    "vulnerability-list-not-downloaded",
    "vulnerability-data-old",
];

/// `n one` or `n many`, with thousands grouped.
fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
}

/// A text without the period that ends it, for a cell or a value beside a label.
fn unstopped(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// An enum's value in words: the JSON's name with spaces for underscores.
fn words<E: TryFrom<i32> + serde::Serialize>(value: i32) -> String {
    word::<E>(value).replace('_', " ")
}

/// The lines of a text, each ended.
fn joined(lines: &[String]) -> String {
    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// How bad, in the order of `findings::order`: a severity that is absent or that this build
/// does not know first, as the most severe.
fn rank(severity: Option<i32>) -> u8 {
    match severity.and_then(|s| v1::Level::try_from(s).ok()) {
        Some(v1::Level::Critical) => 5,
        Some(v1::Level::High) => 4,
        Some(v1::Level::Medium) => 3,
        Some(v1::Level::Low) => 2,
        Some(v1::Level::Informational) => 1,
        _ => 6,
    }
}

/// A level as a person reads it, and its style: critical red, high yellow, the others plain.
fn level(severity: Option<i32>) -> (String, Style) {
    match severity.map(|s| (s, v1::Level::try_from(s))) {
        None => ("not known".to_string(), PLAIN),
        Some((_, Ok(v1::Level::Critical))) => ("critical".to_string(), RED),
        Some((_, Ok(v1::Level::High))) => ("high".to_string(), YELLOW),
        Some((s, _)) => (words::<v1::Level>(s), PLAIN),
    }
}

/// A rule's name in a list: a published rule's own title, cut on a terminal to the length of a
/// short title, or the core's short title; the long title from a core that gives no short one.
fn short_title(screen: &Screen, rule_title: Option<&str>, short: &str, title: &str) -> String {
    match rule_title {
        Some(t) if screen.terminal => screen::cut_end(&view::shown(t), SHORT_MAX),
        Some(t) => t.to_string(),
        None if short.is_empty() => unstopped(title).to_string(),
        None => short.to_string(),
    }
}

/// The urgent ones of a count, in a cell: `urgent` when all are, how many when some are.
fn urgent_cell(count: u64, urgent: u64) -> String {
    match urgent {
        0 => String::new(),
        u if u >= count => "urgent".to_string(),
        u => format!("{} urgent", grouped(u)),
    }
}

/// How many need a look, never without how many of them are urgent.
fn needing(total: u64, urgent: u64) -> String {
    let (needs, need) = ("thing needs a look", "things need a look");
    format!(
        "{}, {}",
        count(total, needs, need),
        match urgent {
            0 => "none urgent".to_string(),
            u => format!("{} urgent", grouped(u)),
        }
    )
}

/// A machine as a person names it: an entity id's type and machine prefix left out.
fn machine_name(scope: &str) -> &str {
    for prefix in [
        "checkout:machine:",
        "container:machine:",
        "file:machine:",
        "machine:",
    ] {
        if let Some(rest) = scope.strip_prefix(prefix) {
            return rest;
        }
    }
    scope
}

/// The things a cause of what is not covered is about, each with what its source said. The cell
/// joins several texts from sources, so each keeps its own quotation, as today: a name that holds
/// a colon, a semicolon or a quote is never read as a name and a reason, or as two names.
fn examples(u: &v1::Uncovered) -> String {
    u.examples_text
        .iter()
        .enumerate()
        .map(
            |(i, name)| match u.examples.get(i).and_then(|e| e.reason_text.as_deref()) {
                Some(r) => format!("{}: {}", quoted(name), quoted(r)),
                None => quoted(name),
            },
        )
        .chain(u.value_text.as_deref().map(quoted))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The causes of what is not covered a section lists: what the person can fix; what nobody can,
/// on this Mac or on every Mac. A value of `holds_on` this build does not know is this Mac's.
fn causes<'a>(s: &'a v1::Status, who: &'a str, every_mac: Option<bool>) -> Vec<&'a v1::Uncovered> {
    let on_every_mac = |u: &v1::Uncovered| u.holds_on == v1::HoldsOn::EveryMac as i32;
    s.not_covered
        .iter()
        .filter(|u| u.who == who && every_mac.is_none_or(|e| on_every_mac(u) == e))
        .collect()
}

/// How a section of causes is set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Causes {
    /// The status: each title whole, and under it what it is about without quotes: plain names
    /// joined with commas, or one name and its reason a line, at most `PAIRS_SHOWN`.
    Listed,
    /// Each title and what it is about whole, both broken into lines: `--coverage`.
    Whole,
}

/// The pairs of a name and a reason the status lists under a cause before it counts the rest.
const PAIRS_SHOWN: usize = 3;

/// A name from a source, escaped as everywhere, with the one character that separates it from
/// what follows written as an escape too: a comma in a list of names, a colon before a reason.
/// So a name holding ", " or ": " never passes for two names or for a name and a reason, and a
/// line feed in it is already an escape, `\u{a}`, so it never starts a line of its own.
fn name_in(name: &str, separator: char) -> String {
    view::shown(name).replace(separator, &format!("\\u{{{:x}}}", u32::from(separator)))
}

/// What a cause is about, in lines for the status: its names joined with commas, or one name and
/// its reason a line, the first `PAIRS_SHOWN` and then how many more; then what its source said
/// of it as a whole. Every piece is escaped before it is joined; nothing is cut.
fn about_lines(u: &v1::Uncovered) -> (Vec<String>, u64) {
    let reasons: Vec<Option<&str>> = (0..u.examples_text.len())
        .map(|i| u.examples.get(i).and_then(|e| e.reason_text.as_deref()))
        .collect();
    let mut lines = Vec::new();
    // A cause that names nothing counts itself, not things left out of a list.
    let mut more = if u.examples_text.is_empty() {
        0
    } else {
        u.count.saturating_sub(u.examples_text.len() as u64)
    };
    if reasons.iter().any(Option::is_some) {
        for (name, reason) in u.examples_text.iter().zip(&reasons).take(PAIRS_SHOWN) {
            lines.push(match reason {
                Some(r) => format!("{}: {}", name_in(name, ':'), view::shown(r)),
                None => name_in(name, ':'),
            });
        }
        more += u.examples_text.len().saturating_sub(PAIRS_SHOWN) as u64;
    } else if !u.examples_text.is_empty() {
        let names: Vec<String> = u.examples_text.iter().map(|n| name_in(n, ',')).collect();
        lines.push(names.join(", "));
    }
    if let Some(v) = &u.value_text {
        lines.push(view::shown(v));
    }
    (lines, more)
}

/// A section of causes: its label bold on a line, then each cause's title and the things it is
/// about. A failed reading or download is red wherever it is listed.
fn cause_section(
    screen: &Screen,
    out: &mut Vec<String>,
    label: &str,
    list: &[&v1::Uncovered],
    layout: Causes,
) {
    if list.is_empty() {
        return;
    }
    let style = |u: &v1::Uncovered| {
        if FAILED_CAUSES.contains(&u.id.as_str()) {
            RED
        } else {
            PLAIN
        }
    };
    out.push(format!("  {}", screen.paint(BOLD, label)));
    let room = screen.fits().map(|w| w.saturating_sub(6));
    for u in list {
        for l in screen::wrap(
            &view::shown(unstopped(&u.title)),
            screen.fits().map(|w| w.saturating_sub(4)),
        ) {
            out.push(format!("    {}", screen.paint(style(u), &l)));
        }
        let (lines, more) = match layout {
            Causes::Listed => about_lines(u),
            Causes::Whole => (vec![view::shown(&examples(u))], 0),
        };
        for line in lines.iter().filter(|l| !l.is_empty()) {
            // A line of its own for each piece, broken where it is too long and never cut; the
            // lines a break makes are set in further, so they never pass for a piece of their own.
            for (i, l) in screen::wrap(line, room.map(|r| r.saturating_sub(2)))
                .iter()
                .enumerate()
            {
                let indent = if i == 0 { "      " } else { "        " };
                out.push(format!("{indent}{}", screen.paint(PLAIN, l)));
            }
        }
        if more > 0 {
            out.push(format!(
                "      {}   {}",
                screen.paint(PLAIN, &format!("… {} more", grouped(more))),
                screen.paint(CYAN, "immune status --coverage")
            ));
        }
    }
}

/// The state of this Mac and of its watcher, in words, with the style it is shown in: a watcher
/// that failed red, watched in part or not checked yellow.
fn watching(s: &v1::Status) -> (String, Style) {
    let Some(m) = &s.this_mac else {
        return ("whether it is watched is not said".to_string(), YELLOW);
    };
    let state = match v1::ThisMacState::try_from(m.state) {
        Ok(v1::ThisMacState::Watched) => "yes",
        Ok(v1::ThisMacState::WatchedInPart) => "in part",
        _ => "not checked yet",
    };
    let failed: Vec<&str> = s
        .watching
        .as_ref()
        .map(|w| {
            w.failed
                .iter()
                .map(|f| crate::watch::failed_words(&f.what))
                .collect()
        })
        .unwrap_or_default();
    let parts = watching_parts(s);
    let text: Vec<&str> = parts.iter().map(|(t, _)| t.as_str()).collect();
    let style = if !failed.is_empty() {
        RED
    } else if state == "yes" && m.live {
        PLAIN
    } else {
        YELLOW
    };
    (format!("{state}; {}", text.join("; ")), style)
}

/// How this Mac is watched, one clause each, in its own style: whether a watcher runs, and only
/// when it applies, that some places are not watched or nothing was checked yet.
fn watching_parts(s: &v1::Status) -> Vec<(String, Style)> {
    let Some(m) = &s.this_mac else {
        return vec![("whether it is watched is not said".to_string(), YELLOW)];
    };
    let failed: Vec<&str> = s
        .watching
        .as_ref()
        .map(|w| {
            w.failed
                .iter()
                .map(|f| crate::watch::failed_words(&f.what))
                .collect()
        })
        .unwrap_or_default();
    let mut parts = vec![if m.live && failed.is_empty() {
        ("live".to_string(), PLAIN)
    } else if m.live {
        (format!("live, with a failed {}", failed.join(" and ")), RED)
    } else if !failed.is_empty() {
        (
            format!(
                "a watcher runs, but its latest {} failed, so it does not watch live",
                failed.join(" and ")
            ),
            RED,
        )
    } else if s.watching.is_some() {
        (
            "a watcher runs and has not completed its first reading".to_string(),
            YELLOW,
        )
    } else {
        (
            "no watcher runs now: changes are seen at each check".to_string(),
            PLAIN,
        )
    }];
    // What is watched leads, then the watcher.
    match v1::ThisMacState::try_from(m.state) {
        Ok(v1::ThisMacState::Watched) => {}
        Ok(v1::ThisMacState::WatchedInPart) => parts.insert(0, (in_part(s), YELLOW)),
        _ => parts.insert(0, ("not checked yet".to_string(), YELLOW)),
    }
    parts
}

/// "in part", and what is not watched in full, from the message: the kinds of place whose
/// reading was not whole, and program starts when the event level is installed and records
/// none, or lost some.
fn in_part(s: &v1::Status) -> String {
    let full = v1::Completeness::Full as i32;
    let mut what: Vec<String> = s
        .watched
        .iter()
        .flat_map(|w| &w.kinds)
        .filter(|k| k.coverage.is_some_and(|c| c != full))
        .map(|k| k.kind.clone())
        .collect();
    if let Some(l) = &s.event_level {
        let running = l.state == v1::CollectorState::Running as i32;
        let installed = l.state != v1::CollectorState::NotInstalled as i32;
        let lost = l
            .in_words
            .as_ref()
            .is_some_and(|w| !w.notes.is_empty() || !w.caveats.is_empty());
        if installed && !running {
            what.push("program starts".to_string());
        } else if running && lost {
            what.push("some program starts".to_string());
        }
    }
    match what.as_slice() {
        [] => "in part".to_string(),
        [one] => format!("in part: {one} not watched in full"),
        [rest @ .., last] => format!(
            "in part: {} and {last} not watched in full",
            rest.join(", ")
        ),
    }
}

/// Clauses joined with "; ", each in its own style.
fn clauses(parts: Vec<(String, Style)>) -> Vec<(String, Style)> {
    let mut out = Vec::new();
    for (i, (text, style)) in parts.into_iter().enumerate() {
        if i > 0 {
            out.push(("; ".to_string(), PLAIN));
        }
        out.push((text, style));
    }
    out
}

/// Whether the status holds a failure: a reading or a download that failed, a watcher that
/// failed, an event level that is neither running nor simply not installed, a machine not
/// reached, or a run that died. A status with one is never calm, whatever it found.
fn failing(s: &v1::Status) -> bool {
    let failed_cause = causes(s, "nothing", None)
        .iter()
        .any(|u| FAILED_CAUSES.contains(&u.id.as_str()));
    let watcher = s.watching.as_ref().is_some_and(|w| !w.failed.is_empty());
    let level = s.event_level.as_ref().is_some_and(|l| {
        l.state != v1::CollectorState::Running as i32
            && l.state != v1::CollectorState::NotInstalled as i32
    });
    let readings = s
        .coverage
        .as_ref()
        .is_some_and(|c| c.failed > 0 || c.unreached_total > 0);
    let died = s
        .last_run
        .as_ref()
        .is_some_and(|l| l.finished_at.is_none() && !s.running);
    failed_cause || watcher || level || readings || died
}

/// The event level when it is not as it should be (running with nothing lost), in two clauses:
/// its state, and what is wrong, which is yellow, or red for a collector that does not run;
/// `None` when it is as it should be. The detail is in `--coverage`.
fn event_level_short(l: &v1::EventLevel) -> Option<Vec<(String, Style)>> {
    let words = l.in_words.clone().unwrap_or_default();
    let running = l.state == v1::CollectorState::Running as i32;
    if running && words.notes.is_empty() {
        return None;
    }
    if !running {
        let style = if l.state == v1::CollectorState::NotInstalled as i32 {
            YELLOW
        } else {
            RED
        };
        return Some(vec![(words.state, style)]);
    }
    // Each caveat in words, from its stable name and the count the message gives for it over
    // the last day; a caveat this build does not know, by the core's own few words.
    let last_day = |s: &Option<v1::Span>| s.as_ref().map_or(0, |s| s.last_day);
    let mut wrong: Vec<String> = words
        .caveats
        .iter()
        .map(|c| match c.kind.as_str() {
            // A caveat whose count the message does not give is said in the core's words.
            "restarts" => match last_day(&l.unknown_losses) {
                0 => c.short.clone(),
                1 => "the collector restarted once".to_string(),
                2 => "the collector restarted twice".to_string(),
                n => format!("the collector restarted {} times", grouped(n)),
            },
            "lost" => match last_day(&l.lost) {
                0 => c.short.clone(),
                n => format!(
                    "{} lost",
                    count(n, "program start was", "program starts were")
                ),
            },
            "unreadable" => match last_day(&l.unreadable_lines) {
                0 => c.short.clone(),
                n => format!("{} of the log could not be read", count(n, "line", "lines")),
            },
            "deleted_early" => match last_day(&l.files_removed_by_cap) {
                0 => c.short.clone(),
                n => format!("{} of the log deleted early", count(n, "file", "files")),
            },
            "deleted_unread" => match last_day(&l.files_removed_unread) {
                0 => c.short.clone(),
                n => format!("{} of the log deleted unread", count(n, "file", "files")),
            },
            "earlier_collector" => "the collector needs installing again".to_string(),
            _ => c.short.clone(),
        })
        .collect();
    if wrong.is_empty() {
        wrong.push(count(words.notes.len() as u64, "note", "notes"));
    }
    let wrong = match wrong.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{}, and {last}", rest.join(", ")),
        None => String::new(),
    };
    Some(vec![(words.state, PLAIN), (wrong, YELLOW)])
}

/// What the latest check did not read, by kind, a failure yellow; when it read all that this
/// version reads here, that. Readings with nothing to read are not held against the Mac.
fn coverage_parts(c: &v1::CoverageSummary) -> Vec<(String, Style)> {
    let mut parts: Vec<(String, Style)> = Vec::new();
    if c.failed > 0 {
        parts.push((count(c.failed, "reading failed", "readings failed"), YELLOW));
    }
    if c.no_reader > 0 {
        parts.push((
            count(
                c.no_reader,
                "kind of place this version does not read",
                "kinds of place this version does not read",
            ),
            PLAIN,
        ));
    }
    if c.not_given > 0 {
        parts.push((
            count(
                c.not_given,
                "reading its source does not give",
                "readings their source does not give",
            ),
            PLAIN,
        ));
    }
    if c.unreached_total > 0 {
        parts.push((
            count(
                c.unreached_total,
                "machine not reached",
                "machines not reached",
            ),
            YELLOW,
        ));
    }
    if parts.is_empty() {
        return vec![(
            "everything this version reads here was read".to_string(),
            PLAIN,
        )];
    }
    let mut out = Vec::new();
    for (i, p) in parts.into_iter().enumerate() {
        if i > 0 {
            out.push((", ".to_string(), PLAIN));
        }
        out.push(p);
    }
    out
}

/// The full sentence of the event level, as `--coverage` gives it.
fn event_level_long(l: &v1::EventLevel) -> String {
    let words = l.in_words.clone().unwrap_or_default();
    let head = match (
        v1::CollectorState::try_from(l.state),
        l.program_starts.as_ref(),
    ) {
        (Ok(v1::CollectorState::Running), Some(p)) => format!(
            "{}, {} in the last day.",
            words.state,
            count(p.last_day, "program start", "program starts")
        ),
        _ => format!("{}.", words.state),
    };
    let line: Vec<String> = std::iter::once(head).chain(words.notes).collect();
    unstopped(&line.join(" ")).to_string()
}

/// The machines not reached in one line: the first by name, since when and why, and how many
/// more.
fn unreached_short(screen: &Screen, c: &v1::CoverageSummary, now: i64) -> Option<String> {
    let first = c.unreached.first()?;
    let mut said = format!(
        "{} {}",
        machine_name(&first.scope_text),
        screen.since(first.since_at, now)
    );
    if let Some(r) = &first.reason_text {
        said.push_str(&format!(": {r}"));
    }
    let more = c.unreached_total.saturating_sub(1);
    if more > 0 {
        said.push_str(&format!(", and {} more", grouped(more)));
    }
    Some(said)
}

/// What is not judged on this Mac in one line: the places by name, as many as fit, and how many
/// more causes there are; what nobody can fix and is not a failure.
fn not_judged_line(screen: &Screen, s: &v1::Status, room: Option<usize>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut unnamed = 0u64;
    let failed = |u: &v1::Uncovered| FAILED_CAUSES.contains(&u.id.as_str());
    for u in causes(s, "nothing", None)
        .into_iter()
        .filter(|u| !failed(u))
    {
        let on_every_mac = u.holds_on == v1::HoldsOn::EveryMac as i32;
        if u.examples_text.is_empty() || on_every_mac {
            unnamed += 1;
            continue;
        }
        for n in &u.examples_text {
            let n = name_in(n, ',');
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    if names.is_empty() && unnamed == 0 {
        return None;
    }
    if names.is_empty() {
        return Some(count(
            unnamed,
            "limit of this version",
            "limits of this version",
        ));
    }
    let more = |shown: usize| unnamed + (names.len() - shown) as u64;
    let said = |shown: usize| {
        let mut l = names[..shown].join(", ");
        if more(shown) > 0 {
            l.push_str(&format!(" +{}", grouped(more(shown))));
        }
        l
    };
    match (screen.fits(), room) {
        (Some(_), Some(room)) => {
            // As many names as fit; at least one, cut if it must be.
            let mut shown = names.len();
            while shown > 1 && screen::columns(&said(shown)) > room {
                shown -= 1;
            }
            Some(screen::cut_end(&said(shown), room))
        }
        _ => Some(said(names.len())),
    }
}

/// `immune status` for a person. With `coverage`, `immune status --coverage`: everything the
/// last check read and did not read, laid out by the same rules.
pub fn status(s: &v1::Status, screen: &Screen, coverage: bool) -> String {
    let store = s.store.clone().unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if !store.exists {
        out.extend(screen.headline("There is no store yet", BOLD, None));
        out.push(String::new());
        out.extend(screen.labelled(2, 5, "Store", &store.path_text, PLAIN, None, 0));
        out.push(String::new());
        out.push(screen.next("immune run", "makes it"));
        return joined(&out);
    }
    if coverage {
        coverage_text(s, screen, &mut out);
    } else {
        default_text(s, screen, &mut out);
    }
    joined(&out)
}

/// When the latest full check finished, for the right of a first line.
fn checked(screen: &Screen, s: &v1::Status) -> Option<String> {
    s.this_mac
        .as_ref()
        .and_then(|m| m.checked_at)
        .map(|at| format!("checked {}", screen.time(at, s.answered_at)))
}

fn default_text(s: &v1::Status, screen: &Screen, out: &mut Vec<String>) {
    let now = s.answered_at;
    let fresh = s.this_mac.as_ref().is_some_and(|m| m.fresh);
    let right = checked(screen, s);
    let look = s.needs_a_look.as_ref();
    match look {
        None => out.extend(screen.headline(
            "No run of this build has looked for findings yet",
            BOLD,
            right.as_deref(),
        )),
        Some(n) if n.total == 0 && fresh && !failing(s) => {
            out.extend(screen.headline("✓ Nothing needs a look", GREEN.bold(), right.as_deref()))
        }
        Some(n) if n.total == 0 && fresh => out.extend(screen.headline(
            "Nothing needs a look in what could be read",
            YELLOW.bold(),
            right.as_deref(),
        )),
        Some(n) if n.total == 0 => out.extend(screen.headline(
            "Nothing needed a look at the last check",
            BOLD,
            right.as_deref(),
        )),
        Some(n) => out.extend(screen.headline(
            &format!("✗ {}", needing(n.total, n.urgent_total)),
            RED.bold(),
            right.as_deref(),
        )),
    }
    // What needs the person: the rules, most urgent first.
    if let Some(n) = look.filter(|n| n.total > 0 && !n.by_rule.is_empty()) {
        out.push(String::new());
        let shown = &n.by_rule[..n.by_rule.len().min(GROUPS_SHOWN)];
        let rows: Vec<Vec<Cell>> = shown
            .iter()
            .map(|g| {
                let (lv, style) = level(g.severity);
                vec![
                    Cell::new(lv, style),
                    Cell::plain(short_title(
                        screen,
                        g.rule_title_text.as_deref(),
                        &g.short_title,
                        &g.rule,
                    )),
                    Cell::new(grouped(g.count), BOLD),
                    Cell::new(urgent_cell(g.count, g.urgent), RED),
                ]
            })
            .collect();
        out.extend(screen.table(
            2,
            &[
                Column::new(Cut::Never),
                Column::new(Cut::End),
                Column::right(Cut::Never),
                Column::new(Cut::Never),
            ],
            None,
            &rows,
        ));
        let rest = &n.by_rule[shown.len()..];
        if !rest.is_empty() {
            let more: u64 = rest.iter().map(|g| g.count).sum();
            let urgent: u64 = rest.iter().map(|g| g.urgent).sum();
            let indent = 2
                + shown
                    .iter()
                    .map(|g| screen::columns(&level(g.severity).0))
                    .max()
                    .unwrap_or(0)
                + 2;
            let said = format!(
                "… {} more in {}, {}",
                grouped(more),
                count(rest.len() as u64, "kind", "kinds"),
                match urgent {
                    0 => "none urgent".to_string(),
                    u => format!("{} urgent", grouped(u)),
                }
            );
            let room = screen.fits().map(|w| w.saturating_sub(indent));
            for l in screen::wrap(&said, room) {
                let style = if urgent > 0 { RED } else { PLAIN };
                out.push(format!("{}{}", " ".repeat(indent), screen.paint(style, &l)));
            }
        }
    }
    // Context: one labelled line each.
    out.push(String::new());
    // Each value in parts, each part in its own style.
    type Parts = Vec<(String, Style)>;
    let mut lines: Vec<(&str, Parts, Option<&str>)> = Vec::new();
    if let Some(l) = s.last_run.as_ref().filter(|l| l.finished_at.is_none()) {
        let (how, style) = if s.running {
            ("it is running", YELLOW)
        } else {
            ("it died, and nothing it read is in the store", RED)
        };
        lines.push((
            "Last run",
            vec![(
                format!(
                    "started {} and has not finished: {how}",
                    screen.time(l.started_at, now)
                ),
                style,
            )],
            None,
        ));
    }
    if let Some(m) = s.this_mac.as_ref().filter(|m| !m.fresh) {
        lines.push((
            "Not fresh",
            vec![(
                format!(
                    "{}; do not take it for calm until a check finishes",
                    m.stale_reason
                        .as_deref()
                        .unwrap_or("the core does not say why")
                ),
                YELLOW,
            )],
            None,
        ));
    }
    lines.push(("Watching", clauses(watching_parts(s)), None));
    let event_level = s.event_level.as_ref().and_then(event_level_short);
    if let Some(parts) = event_level.clone() {
        lines.push(("Event level", clauses(parts), None));
    }
    // Whether coverage is whole: nothing failed, nothing this version does not read, nothing
    // its source does not give, no machine unreached.
    let coverage_whole = s.coverage.as_ref().is_some_and(|c| {
        c.failed == 0 && c.no_reader == 0 && c.not_given == 0 && c.unreached_total == 0
    });
    match &s.coverage {
        Some(c) => {
            lines.push(("Coverage", coverage_parts(c), None));
            if let Some(said) = unreached_short(screen, c, now) {
                lines.push(("Not reached", vec![(said, RED)], None));
            }
        }
        None => lines.push((
            "Coverage",
            vec![("nothing has been read yet".to_string(), YELLOW)],
            None,
        )),
    }
    let width = lines
        .iter()
        .map(|(l, ..)| screen::columns(l))
        .chain(std::iter::once(screen::columns("Not judged")))
        .max()
        .unwrap_or(0);
    // A value has the whole width after its label; the commands are the next steps at the end.
    let room = screen.fits().map(|w| w.saturating_sub(2 + width + 3));
    let not_judged = not_judged_line(screen, s, room);
    for (label, parts, command) in &lines {
        let parts: Vec<(&str, Style)> = parts.iter().map(|(t, st)| (t.as_str(), *st)).collect();
        out.extend(screen.labelled_parts(2, width, label, &parts, *command, 0));
    }
    let failed: Vec<&v1::Uncovered> = causes(s, "nothing", None)
        .into_iter()
        .filter(|u| FAILED_CAUSES.contains(&u.id.as_str()))
        .collect();
    let fixable = causes(s, "you", None);
    cause_section(screen, out, "Failed", &failed, Causes::Listed);
    cause_section(screen, out, "You can fix", &fixable, Causes::Listed);
    if let Some(said) = &not_judged {
        out.extend(screen.labelled(2, width, "Not judged", said, PLAIN, None, 0));
    }
    // The next steps, each on its own line, only those that apply, at most three.
    out.push(String::new());
    let mut next: Vec<(&str, &str)> = Vec::new();
    match look {
        None => next.push(("immune run", "checks this Mac now")),
        Some(n) if n.total > 0 => {
            next.push(("immune findings", "lists every one, most urgent first"))
        }
        Some(_) => {}
    }
    if s.watching.is_none() {
        next.push(("immune install", "keeps watching between checks"));
    }
    let whole = coverage_whole
        && event_level.is_none()
        && failed.is_empty()
        && fixable.is_empty()
        && not_judged.is_none();
    if !whole || next.is_empty() {
        next.push(("immune status --coverage", "what was read and what was not"));
    }
    for (command, does) in next.into_iter().take(3) {
        out.push(screen.next(command, does));
    }
}

/// What the latest check that finished counted, one labelled part each, in the words today's
/// status said them in one paragraph.
fn counted(screen: &Screen, s: &v1::Status, f: &v1::FinishedCheck) -> Vec<(&'static str, String)> {
    let now = s.answered_at;
    let when = |at: Option<i64>, none: &str| {
        at.map_or_else(|| none.to_string(), |at| screen.time(at, now))
    };
    let mut parts: Vec<(&'static str, String)> = Vec::new();
    if let Some(e) = &s.estate {
        let mut line = format!(
            "{}, {}.",
            count(e.checkouts, "checkout", "checkouts"),
            count(e.components, "component", "components")
        );
        if e.servers == 0 {
            line.push_str(" No servers known");
        } else {
            line.push_str(&format!(
                " {} known, {} offered for the sweep, {} read",
                count(e.servers, "server", "servers"),
                grouped(e.servers_offered),
                grouped(e.servers_read)
            ));
        }
        if e.own_devices > 0 {
            line.push_str(&format!(
                "; {} of your other devices seen in the private network, not read",
                grouped(e.own_devices)
            ));
        }
        if e.other_devices > 0 {
            line.push_str(&format!(
                "; {} seen in the private network, not read",
                count(
                    e.other_devices,
                    "other person's device",
                    "other people's devices"
                )
            ));
        }
        if e.machines_set_aside > 0 {
            line.push_str(&format!(
                "; {} retired or disowned by the owner",
                grouped(e.machines_set_aside)
            ));
        }
        line.push('.');
        if !e.machines_seen_after_owner_word_text.is_empty() {
            let seen: Vec<String> = e
                .machines_seen_after_owner_word_text
                .iter()
                .map(|m| quoted(m))
                .collect();
            line.push_str(&format!(
                " Seen alive after the owner's word: {}.",
                seen.join(", ")
            ));
        }
        parts.push(("Estate", line));
    }
    if let Some(r) = &f.readings {
        let mut gaps = Vec::new();
        if r.machines_unread > 0 {
            gaps.push(format!(
                "{} could not be read",
                count(r.machines_unread, "machine", "machines")
            ));
        }
        if r.partial > 0 {
            gaps.push(format!(
                "{} partial",
                count(r.partial, "reading was", "readings were")
            ));
        }
        if r.failed > 0 {
            gaps.push(format!(
                "{} nothing",
                count(r.failed, "reading read", "readings read")
            ));
        }
        if r.not_repeated > 0 {
            gaps.push(format!(
                "{} not repeated",
                count(
                    r.not_repeated,
                    "earlier reading was",
                    "earlier readings were"
                )
            ));
        }
        if !gaps.is_empty() {
            parts.push(("Gaps", gaps.join("; ")));
        }
    }
    parts.push((
        "Changes",
        match &f.since_previous_run {
            None => "first run".to_string(),
            Some(c) => {
                let counts = format!(
                    "+{} added, {} changed, {} removed",
                    grouped(c.added),
                    grouped(c.changed),
                    grouped(c.removed)
                );
                if !f.unknown.is_empty() {
                    format!("since last run: {counts}; {}", f.unknown.join(", "))
                } else if c.added + c.changed + c.removed == 0 {
                    "none since last run".to_string()
                } else {
                    format!("since last run: {counts}")
                }
            }
        },
    ));
    if f.set_aside > 0 {
        parts.push((
            "Set aside",
            format!(
                "{} as no longer read by this version, not counted as removed",
                count(f.set_aside, "fact", "facts")
            ),
        ));
    }
    parts.push((
        "Watched places",
        match &s.watched {
            None => "never read".to_string(),
            Some(w) => {
                let files = count(w.files, "file", "files");
                let mut said = match (w.first_reading, &w.since_last_reading) {
                    (false, Some(c)) => format!(
                        "{files}, {} new, {} changed, {} gone since the last reading",
                        c.new, c.changed, c.gone
                    ),
                    _ => format!("{files}, first reading, kept as the baseline"),
                };
                let full = v1::Completeness::Full as i32;
                let not_full: Vec<String> = w
                    .kinds
                    .iter()
                    .filter(|k| k.coverage.is_some_and(|c| c != full))
                    .map(|k| {
                        format!(
                            "{} ({})",
                            k.kind,
                            if k.coverage == Some(v1::Completeness::Partial as i32) {
                                "partial"
                            } else {
                                "nothing read"
                            }
                        )
                    })
                    .chain((w.content_not_read > 0).then(|| {
                        format!(
                            "the content of {}",
                            count(w.content_not_read, "file", "files")
                        )
                    }))
                    .collect();
                if !not_full.is_empty() {
                    said.push_str(&format!("; not read in full: {}", not_full.join(", ")));
                }
                let presence: u64 = w.kinds.iter().map(|k| k.presence_only).sum();
                if let Some(note) = w.kinds.iter().find_map(|k| k.presence_only_note.as_ref()) {
                    said.push_str(&format!(
                        "; {} watched only for presence: {note}",
                        count(presence, "entry", "entries")
                    ));
                }
                said
            }
        },
    ));
    parts.push((
        "Installed software",
        match &s.integrity {
            None => "never read".to_string(),
            Some(i) => {
                let counted = format!(
                    "{}, {}, {}",
                    count(i.bundles, "application bundle", "application bundles"),
                    count(i.homebrew_kegs, "Homebrew keg", "Homebrew kegs"),
                    count(
                        i.global_npm_packages,
                        "global npm package",
                        "global npm packages"
                    )
                );
                let mut said = if i.first_reading {
                    format!("{counted}, first reading, kept as the baseline")
                } else {
                    format!(
                        "{counted}, {} changed while the version stayed, since the last reading",
                        i.changed_while_version_stayed
                    )
                };
                if i.bundles_not_verifying > 0 {
                    said.push_str(&format!(
                        "; {} not verify, {} of them since the first reading",
                        count(i.bundles_not_verifying, "bundle does", "bundles do"),
                        i.not_verifying_since_first_reading
                    ));
                }
                let not_full: Vec<String> = i
                    .readings
                    .iter()
                    .filter(|r| r.completeness != v1::Completeness::Full as i32)
                    .map(|r| {
                        format!(
                            "{} ({})",
                            r.kind,
                            if r.completeness == v1::Completeness::Partial as i32 {
                                "partial"
                            } else {
                                "nothing read"
                            }
                        )
                    })
                    .collect();
                if !not_full.is_empty() {
                    said.push_str(&format!("; not read in full: {}", not_full.join(", ")));
                }
                said
            }
        },
    ));
    if let Some(t) = &s.threats {
        let held = |n: u64| count(n, "exploited vulnerability", "exploited vulnerabilities");
        let judged = "matched against nothing in this estate but through the vulnerability records linked to them, so whether any of them affects this estate is not known from it";
        parts.push((
            "CISA catalogue",
            match (v1::FeedOutcome::try_from(t.outcome), t.entries) {
                (Ok(v1::FeedOutcome::Read), Some(n)) if t.first_reading == Some(true) => {
                    format!("{}, first reading, kept as the baseline; {judged}", held(n))
                }
                (Ok(v1::FeedOutcome::Read | v1::FeedOutcome::Unchanged), Some(n)) => format!(
                    "{}, {} new since the last reading{}; {judged}",
                    held(n),
                    grouped(t.new.unwrap_or_default()),
                    match t.gone {
                        Some(g) if g > 0 => format!(", {} left the catalogue", grouped(g)),
                        _ => String::new(),
                    }
                ),
                (Ok(v1::FeedOutcome::Failed), Some(n)) => format!(
                    "not read: {}; what is new is unknown, and the {} it held at its last reading, {}, are {judged}",
                    quoted(t.reason_text.as_deref().unwrap_or_default()),
                    held(n),
                    when(t.read_at, "an unknown time")
                ),
                (Ok(v1::FeedOutcome::Failed), None) => format!(
                    "not read: {}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown",
                    quoted(t.reason_text.as_deref().unwrap_or_default())
                ),
                _ => "never read; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown".to_string(),
            },
        ));
    }
    if let Some(d) = &s.vulnerability_data {
        let clauses: Vec<String> = d
            .feeds
            .iter()
            .map(|f| {
                let held = format!(
                    "{}, {} of them on malicious packages",
                    count(f.records.unwrap_or_default(), "record", "records"),
                    grouped(f.malicious_records.unwrap_or_default())
                );
                let since = f.changed_at.or(f.read_at).map_or_else(
                    || "since an unknown time".to_string(),
                    |at| screen.since(at, now),
                );
                match v1::FeedOutcome::try_from(f.outcome) {
                    Ok(v1::FeedOutcome::NeverRead) => format!("{} never read", f.ecosystem),
                    Ok(v1::FeedOutcome::Read) => match (&f.since_last_reading, f.first_reading) {
                        (_, Some(true)) => {
                            format!(
                                "{}: {held}, first reading, kept as the baseline",
                                f.ecosystem
                            )
                        }
                        (Some(c), _) => format!(
                            "{}: {held}, {} new and {} changed since the last reading{}{}",
                            f.ecosystem,
                            grouped(c.new),
                            grouped(c.changed),
                            if c.withdrawn > 0 {
                                format!(", {} withdrawn", grouped(c.withdrawn))
                            } else {
                                String::new()
                            },
                            if c.gone > 0 {
                                format!(", {} left it", grouped(c.gone))
                            } else {
                                String::new()
                            }
                        ),
                        _ => format!("{}: {held}", f.ecosystem),
                    },
                    Ok(v1::FeedOutcome::Unchanged) => {
                        format!("{}: {held}, unchanged {since}", f.ecosystem)
                    }
                    _ => {
                        let reason = quoted(f.reason_text.as_deref().unwrap_or_default());
                        match f.read_at {
                            Some(at) => format!(
                                "{} not read: {reason}; the {held}, read {}, stay in force",
                                f.ecosystem,
                                screen.time(at, now)
                            ),
                            None => format!(
                                "{} not read: {reason}; nothing of it is known yet",
                                f.ecosystem
                            ),
                        }
                    }
                }
            })
            .collect();
        let mut matched = String::new();
        if let Some(v) = &s.vulnerabilities {
            matched = format!(
                "; matched against the projects' package-lock.json, pnpm-lock.yaml and Cargo.lock: {} in packages they use",
                count(
                    v.affected_records,
                    "known vulnerability",
                    "known vulnerabilities"
                )
            );
            if v.unknown_packages > 0 {
                matched.push_str(&format!(
                    ", and for {} whether one affects them cannot be told",
                    count(v.unknown_packages, "package", "packages")
                ));
            }
        }
        parts.push(("OSV data", format!("{}{matched}", clauses.join("; "))));
    }
    parts
}

/// A table under a label of its own, as `--coverage` sets each.
fn titled_table(
    screen: &Screen,
    out: &mut Vec<String>,
    label: &str,
    columns_of: &[Column],
    head: &[&str],
    rows: &[Vec<Cell>],
) {
    out.push(String::new());
    out.extend(
        screen
            .headline(label, BOLD, None)
            .into_iter()
            .map(|l| format!("  {l}")),
    );
    if rows.is_empty() {
        out.push("    none".to_string());
    } else {
        out.extend(screen.table(4, columns_of, Some(head), rows));
    }
}

fn coverage_text(s: &v1::Status, screen: &Screen, out: &mut Vec<String>) {
    let now = s.answered_at;
    let headline = match &s.coverage {
        Some(c) if c.failed > 0 => format!(
            "{} of {} full, {} failed",
            grouped(c.full),
            count(c.readings, "reading", "readings"),
            grouped(c.failed)
        ),
        Some(c) => format!(
            "{} of {} full",
            grouped(c.full),
            count(c.readings, "reading", "readings")
        ),
        None => "Nothing has been read yet".to_string(),
    };
    let style = match &s.coverage {
        Some(c) if c.failed == 0 => BOLD,
        _ => YELLOW.bold(),
    };
    out.extend(screen.headline(&headline, style, checked(screen, s).as_deref()));
    out.push(String::new());
    let mut lines: Vec<(&str, String, Style)> = Vec::new();
    let store = s.store.clone().unwrap_or_default();
    lines.push(("Store", store.path_text.clone(), PLAIN));
    match &s.last_run {
        None => lines.push(("Last run", "none has started".to_string(), YELLOW)),
        Some(l) => match l.finished_at {
            Some(at) => lines.push((
                "Last run",
                format!(
                    "started {}, finished {}",
                    screen.time(l.started_at, now),
                    screen.time(at, now)
                ),
                PLAIN,
            )),
            None => lines.push((
                "Last run",
                format!(
                    "started {} and has not finished: {}",
                    screen.time(l.started_at, now),
                    if s.running {
                        "it is running"
                    } else {
                        "it died, and nothing it read is in the store"
                    }
                ),
                if s.running { YELLOW } else { RED },
            )),
        },
    }
    match &s.last_finished_run {
        None => lines.push((
            "Last check",
            "none has finished yet, so nothing of a check is counted".to_string(),
            YELLOW,
        )),
        Some(f) => {
            let check = f.check.clone().unwrap_or_default();
            if s.last_run.as_ref().is_some_and(|l| l.id != check.id) {
                lines.push((
                    "Counted",
                    format!(
                        "by the run that finished {}",
                        screen.time(check.finished_at.unwrap_or(check.started_at), now)
                    ),
                    PLAIN,
                ));
            }
            for (label, value) in counted(screen, s, f) {
                lines.push((label, unstopped(&value).to_string(), PLAIN));
            }
        }
    }
    let mut watched: Vec<Vec<Cell>> = Vec::new();
    match &s.this_mac {
        None => lines.push((
            "This Mac",
            "whether it is watched is not said".to_string(),
            YELLOW,
        )),
        Some(m) => {
            let (state, style) = watching(s);
            let state = match state.split_once("; ") {
                Some(("yes", rest)) => format!("watched; {rest}"),
                Some(("in part", rest)) => format!("watched in part; {rest}"),
                _ => state,
            };
            lines.push((
                "This Mac",
                format!(
                    "{state}; last checked {}",
                    m.checked_at
                        .map_or_else(|| "never".to_string(), |at| screen.time(at, now))
                ),
                style,
            ));
            if !m.fresh {
                lines.push((
                    "Not fresh",
                    format!(
                        "{}; do not take it for calm until a check finishes",
                        m.stale_reason
                            .as_deref()
                            .unwrap_or("the core does not say why")
                    ),
                    YELLOW,
                ));
            }
            watched = m
                .watched
                .iter()
                .map(|w| {
                    vec![
                        Cell::plain(w.what.clone()),
                        Cell::new(grouped(w.count), BOLD),
                        Cell::plain(w.how.clone()),
                    ]
                })
                .collect();
        }
    }
    if let Some(l) = &s.event_level {
        let style = match event_level_short(l) {
            Some(parts) if parts.iter().any(|(_, st)| *st == RED) => RED,
            Some(_) => YELLOW,
            None => PLAIN,
        };
        lines.push(("Event level", event_level_long(l), style));
    }
    match &s.needs_a_look {
        None => lines.push((
            "Needs a look",
            "not known yet, no run of this build has looked for findings in this store yet"
                .to_string(),
            BOLD,
        )),
        Some(n) => lines.push((
            "Needs a look",
            needing(n.total, n.urgent_total),
            if n.total > 0 { RED } else { PLAIN },
        )),
    }
    let width = lines
        .iter()
        .map(|(l, ..)| screen::columns(l))
        .max()
        .unwrap_or(0);
    for (label, value, style) in &lines {
        out.extend(screen.labelled(2, width, label, value, *style, None, 0));
    }
    // What is watched on this Mac: each kind of place, how many and how often.
    if !watched.is_empty() {
        titled_table(
            screen,
            out,
            "Watched",
            &[
                Column::new(Cut::End),
                Column::right(Cut::Never),
                Column::new(Cut::Never),
            ],
            &["Place", "How many", "How often"],
            &watched,
        );
    }
    // What is not covered, one section per who and where.
    let sections = [
        ("You can fix", causes(s, "you", None)),
        ("Limits of this version", causes(s, "nothing", Some(true))),
        ("Not judged on this Mac", causes(s, "nothing", Some(false))),
    ];
    for (label, list) in &sections {
        if !list.is_empty() {
            out.push(String::new());
            cause_section(screen, out, label, list, Causes::Whole);
        }
    }
    if let Some(c) = &s.coverage {
        out.push(String::new());
        out.extend(screen.labelled(
            2,
            8,
            "Readings",
            &format!(
                "{} at the latest check: {} full, {} failed, {} with no reader, {} where the source does not give it, {} with nothing to read, {} implied by {}",
                grouped(c.readings),
                grouped(c.full),
                grouped(c.failed),
                grouped(c.no_reader),
                grouped(c.not_given),
                grouped(c.read_nothing),
                grouped(c.implied_by_unreached),
                count(
                    c.unreached_total,
                    "machine that could not be reached",
                    "machines that could not be reached"
                )
            ),
            if c.failed > 0 { YELLOW } else { PLAIN },
            None,
            0,
        ));
        if !c.unreached.is_empty() {
            let rows: Vec<Vec<Cell>> = c
                .unreached
                .iter()
                .map(|u| {
                    vec![
                        Cell::new(machine_name(&u.scope_text), RED),
                        Cell::plain(screen.time(u.since_at, now)),
                        Cell::plain(u.reason_text.clone().unwrap_or_default()),
                    ]
                })
                .collect();
            titled_table(
                screen,
                out,
                "Machines not reached",
                &[
                    Column::new(Cut::Middle),
                    Column::new(Cut::Never),
                    Column::new(Cut::End),
                ],
                &["Machine", "Since", "Why"],
                &rows,
            );
            let more = c.unreached_total.saturating_sub(c.unreached.len() as u64);
            if more > 0 {
                out.push(format!(
                    "    {} not listed",
                    count(more, "more machine", "more machines")
                ));
            }
        }
        let shown: Vec<&v1::ReadingGroup> = c
            .problems
            .iter()
            .filter(|g| g.class != v1::ReadingClass::ReadNothing as i32)
            .collect();
        if !shown.is_empty() {
            let rows: Vec<Vec<Cell>> = shown
                .iter()
                .map(|g| {
                    let failed = g.class == v1::ReadingClass::Failed as i32
                        || v1::ReadingClass::try_from(g.class).is_err()
                        || g.class == v1::ReadingClass::Unspecified as i32;
                    vec![
                        Cell::new(
                            words::<v1::ReadingClass>(g.class),
                            if failed { RED } else { PLAIN },
                        ),
                        Cell::plain(g.reader.clone()),
                        Cell::plain(g.kind.clone()),
                        Cell::new(grouped(g.count), BOLD),
                        Cell::plain(
                            g.examples_text
                                .first()
                                .map(|e| machine_name(e).to_string())
                                .unwrap_or_default(),
                        ),
                        Cell::plain(g.reason_text.clone().unwrap_or_default()),
                    ]
                })
                .collect();
            titled_table(
                screen,
                out,
                "Readings that were not full",
                &[
                    Column::new(Cut::Never),
                    Column::new(Cut::Never),
                    Column::new(Cut::End),
                    Column::right(Cut::Never),
                    Column::new(Cut::Middle).giving(2),
                    Column::new(Cut::End).giving(1),
                ],
                &["Class", "Reader", "What", "Readings", "For example", "Why"],
                &rows,
            );
            let more = c.problems_total.saturating_sub(c.problems.len() as u64);
            if more > 0 {
                out.push(format!(
                    "    {} not listed",
                    count(more, "more group of readings", "more groups of readings")
                ));
            }
        }
    }
    if let Some(list) = s.no_reader_for.as_ref().filter(|l| !l.items.is_empty()) {
        let rows: Vec<Vec<Cell>> = list
            .items
            .iter()
            .map(|r| {
                vec![
                    Cell::plain(r.what.clone()),
                    Cell::plain(r.what_text.clone().unwrap_or_default()),
                    Cell::new(grouped(r.where_count), BOLD),
                ]
            })
            .collect();
        titled_table(
            screen,
            out,
            "No reader in this build for",
            &[
                Column::new(Cut::End),
                Column::new(Cut::End),
                Column::right(Cut::Never),
            ],
            &["What", "Which", "Places"],
            &rows,
        );
    }
    if let Some(w) = &s.watched {
        let rows: Vec<Vec<Cell>> = w
            .changes
            .iter()
            .map(|c| {
                vec![
                    Cell::new(screen.time(c.at, now), DIM),
                    Cell::plain(words::<v1::Change>(c.change)),
                    Cell::plain(c.kind.clone()),
                    Cell::plain(c.path_text.clone()),
                ]
            })
            .collect();
        titled_table(
            screen,
            out,
            &format!(
                "Latest changes in watched places, newest first, {} of {}",
                grouped(rows.len() as u64),
                grouped(w.changes_total)
            ),
            &[
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End).giving(1),
                Column::new(Cut::Middle),
            ],
            &["When", "Change", "Kind", "Path"],
            &rows,
        );
    }
    out.push(String::new());
    out.push(screen.next("immune status --json", "gives all of it, with every list"));
}

/// What tells a finding from its neighbours in a list, as a cell: the package and its releases
/// in their project for a finding about a package, kept whole while the project's folder is cut;
/// what it is about and where for one whose thing no name says; where it is for the others.
fn telling(l: &v1::ListedFinding) -> Cell {
    if let Some(p) = &l.package_text {
        // The project's folder: the lockfile's path without its line or entry, then its folder.
        let file = l
            .where_text
            .split_once('#')
            .map_or(l.where_text.as_str(), |(f, _)| f);
        let folder = file.rsplit_once('/').map_or(file, |(d, _)| d);
        let releases = l.releases_text.join(", ");
        let package = if releases.is_empty() {
            format!("{p} in ")
        } else {
            format!("{p} {releases} in ")
        };
        let keep = screen::columns(&view::shown(&package));
        return Cell::plain(format!("{package}{folder}")).keeping(keep);
    }
    Cell::plain(match &l.thing {
        Some(t) => format!("{t} on {}", l.where_text),
        None => l.where_text.clone(),
    })
}

/// `immune findings` for a person: the open findings, or every one with `all`, grouped under
/// their level, most urgent first.
pub fn findings(f: &v1::Findings, all: bool, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let open = v1::FindingState::Open as i32;
    let state_of = |l: &v1::ListedFinding| l.finding.as_ref().map_or(open, |r| r.state);
    // A state this build does not know is read as open, as the schema says.
    let is_open = |l: &v1::ListedFinding| {
        let s = state_of(l);
        s == open
            || v1::FindingState::try_from(s).is_err()
            || s == v1::FindingState::Unspecified as i32
    };
    let urgent = |l: &v1::ListedFinding| l.finding.as_ref().is_some_and(|r| r.urgent);
    // Open findings first, each part in the answer's order, so a cut never hides an open
    // finding behind a closed one.
    let (mut shown, closed): (Vec<&v1::ListedFinding>, Vec<&v1::ListedFinding>) =
        f.findings.iter().partition(|l| is_open(l));
    let open_count = shown.len() as u64;
    let urgent_count = shown.iter().filter(|l| urgent(l)).count() as u64;
    if all {
        shown.extend(closed);
    }
    let severity = |l: &v1::ListedFinding| l.finding.as_ref().and_then(|r| r.severity);
    // Per level, the most severe first, over the findings listed.
    let mut levels: Vec<(u8, String, Style, u64)> = Vec::new();
    for l in &shown {
        let (word, style) = level(severity(l));
        let r = rank(severity(l));
        match levels.iter_mut().find(|(_, w, ..)| *w == word) {
            Some(entry) => entry.3 += 1,
            None => levels.push((r, word, style, 1)),
        }
    }
    levels.sort_by_key(|a| std::cmp::Reverse(a.0));
    let by_level: Vec<String> = levels
        .iter()
        .map(|(_, w, _, n)| format!("{} {w}", grouped(*n)))
        .collect();
    let urgent_said = match urgent_count {
        0 => "none urgent".to_string(),
        u => format!("{} urgent", grouped(u)),
    };
    let mut answer = if all {
        match shown.len() {
            0 => "No findings".to_string(),
            n => format!(
                "{}, {} open, {urgent_said}",
                count(n as u64, "finding", "findings"),
                grouped(open_count),
            ),
        }
    } else {
        match open_count {
            0 => "No open findings".to_string(),
            n => format!(
                "{}, {urgent_said}",
                count(n, "open finding", "open findings")
            ),
        }
    };
    if !by_level.is_empty() {
        answer.push_str(&format!(": {}", by_level.join(", ")));
    }
    let checked_at = f
        .latest_run_at
        .map(|at| format!("checked {}", screen.time(at, f.answered_at)));
    const NO_CHECK: &str = "No full check has finished. Only findings recorded so far are shown.";
    if open_count > 0 {
        out.extend(screen.headline(&format!("✗ {answer}"), RED.bold(), checked_at.as_deref()));
        if f.latest_run_at.is_none() {
            out.push(screen.paint(YELLOW, NO_CHECK));
        }
    } else if f.latest_run_at.is_some() {
        out.extend(screen.headline(&format!("✓ {answer}"), GREEN.bold(), checked_at.as_deref()));
    } else {
        // Nothing open and nothing has looked: what is missing comes first, never a calm line.
        out.extend(screen.headline(NO_CHECK, YELLOW.bold(), None));
        out.push(screen.paint(PLAIN, &answer));
    }
    if !shown.is_empty() {
        out.push(String::new());
        let listed = &shown[..shown.len().min(FINDINGS_SHOWN)];
        let with_state = listed.iter().any(|l| !is_open(l));
        // Under each level, the most severe first, the findings of one rule under the rule's name,
        // said once: groups with an urgent finding first, then the largest; within a group, the
        // answer's order.
        struct Group<'a> {
            rank: u8,
            level: (String, Style),
            rule: String,
            title: String,
            rows: Vec<&'a v1::ListedFinding>,
        }
        let mut groups: Vec<Group> = Vec::new();
        for l in listed {
            let rule = l
                .finding
                .as_ref()
                .and_then(|r| r.rule.clone())
                .unwrap_or_default();
            let title = short_title(
                screen,
                l.rule_title_text.as_deref(),
                &l.short_title,
                &l.title,
            );
            let level = level(severity(l));
            match groups
                .iter_mut()
                .find(|g| g.rule == rule && g.title == title && g.level.0 == level.0)
            {
                Some(g) => g.rows.push(l),
                None => groups.push(Group {
                    rank: rank(severity(l)),
                    level,
                    rule,
                    title,
                    rows: vec![l],
                }),
            }
        }
        // Then by rule, as the status orders its rules.
        groups.sort_by_key(|g| {
            (
                std::cmp::Reverse(g.rank),
                !g.rows.iter().any(|l| urgent(l)),
                std::cmp::Reverse(g.rows.len()),
                g.rule.clone(),
            )
        });
        // One table for every row, so the columns line up down the page.
        let rows: Vec<Vec<Cell>> = groups
            .iter()
            .flat_map(|g| g.rows.iter())
            .map(|l| {
                let r = l.finding.clone().unwrap_or_default();
                let mut row = vec![Cell::new(r.id.clone(), DIM)];
                if with_state {
                    row.push(Cell::plain(words::<v1::FindingState>(r.state)));
                }
                row.push(telling(l));
                row.push(Cell::new(if r.urgent { "urgent" } else { "" }, RED));
                row
            })
            .collect();
        let mut columns_of = vec![Column::new(Cut::Never)];
        if with_state {
            columns_of.push(Column::new(Cut::Never));
        }
        columns_of.extend([Column::new(Cut::Middle), Column::new(Cut::Never)]);
        let mut lines = screen.table(4, &columns_of, None, &rows).into_iter();
        let mut last_level: Option<String> = None;
        for g in &groups {
            if last_level.as_deref() != Some(g.level.0.as_str()) {
                if last_level.is_some() {
                    out.push(String::new());
                }
                out.push(screen.paint(g.level.1.bold(), &g.level.0));
                last_level = Some(g.level.0.clone());
            }
            let n = grouped(g.rows.len() as u64);
            // A title from a core that gives no short one is a sentence, cut to fit on a terminal.
            let title = match screen.fits() {
                Some(w) => screen::cut_end(
                    &view::shown(&g.title),
                    w.saturating_sub(5 + screen::columns(&n)),
                ),
                None => g.title.clone(),
            };
            out.push(format!(
                "  {}   {}",
                screen.paint(PLAIN, &title),
                screen.paint(BOLD, &n)
            ));
            out.extend(lines.by_ref().take(g.rows.len()));
        }
    }
    if shown.len() > FINDINGS_SHOWN {
        let hidden = &shown[FINDINGS_SHOWN..];
        let urgent = hidden.iter().filter(|l| urgent(l)).count();
        out.push(String::new());
        for l in screen::wrap(
            &format!(
                "Showing the first {FINDINGS_SHOWN}; {} more not shown, {} of them urgent. Use --json or --proto for the full list.",
                grouped(hidden.len() as u64),
                grouped(urgent as u64)
            ),
            screen.fits(),
        ) {
            out.push(screen.paint(if urgent > 0 { RED } else { PLAIN }, &l));
        }
    }
    out.push(String::new());
    out.push(screen.next("immune finding <id>", "shows one and how to answer it"));
    joined(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::visible;

    /// When the invented answers were made, and a check that finished three minutes before.
    const NOW: i64 = 1_794_807_960;
    const CHECKED: i64 = NOW - 180;
    /// A style sequence, a title sequence and a right-to-left override, as a name may hold them.
    const ODD: &str = "shop\u{1b}[31mRED\u{1b}[0m\u{202e}evil\u{1b}]0;owned\u{7}title";
    /// A path longer than any terminal.
    const LONG: &str = "~/Developer/clients/northwind-traders/customer-portal-frontend-monorepo-with-a-very-long-name/package-lock.json#node_modules/@ctrl/tinycolor";

    /// The screens a text is rendered for.
    fn screens() -> Vec<Screen> {
        let mut out = vec![Screen::pipe()];
        for width in [60, 80, 120] {
            out.push(Screen::terminal(width, true));
            out.push(Screen::terminal(width, false));
        }
        out
    }

    fn uncovered(
        id: &str,
        who: &str,
        every_mac: bool,
        title: &str,
        names: &[(&str, Option<&str>)],
    ) -> v1::Uncovered {
        v1::Uncovered {
            id: id.to_string(),
            who: who.to_string(),
            title: title.to_string(),
            holds_on: if every_mac {
                v1::HoldsOn::EveryMac as i32
            } else {
                v1::HoldsOn::ThisMac as i32
            },
            examples_text: names.iter().map(|(n, _)| n.to_string()).collect(),
            examples: names
                .iter()
                .map(|(n, r)| v1::UncoveredExample {
                    name_text: n.to_string(),
                    reason_text: r.map(str::to_string),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn group(rule: &str, level: v1::Level, count: u64, urgent: u64) -> v1::RuleCount {
        v1::RuleCount {
            rule: rule.to_string(),
            short_title: format!("Short title of {rule}"),
            rule_title_text: None,
            severity: Some(level as i32),
            count,
            urgent,
        }
    }

    /// A status of real size: every part a status can carry, counts of seven digits, long paths,
    /// and `odd` in every text from a source.
    fn status_of(odd: &str) -> v1::Status {
        let long = format!("{LONG}/{odd}");
        v1::Status {
            answered_at: NOW,
            store: Some(v1::StoreFile {
                path_text: format!(
                    "/Users/example/Library/Application Support/ai.nuanu.immune/{odd}/store.db"
                ),
                exists: true,
                ..Default::default()
            }),
            last_run: Some(v1::CheckMark {
                id: "run-2".to_string(),
                started_at: NOW - 600,
                finished_at: None,
            }),
            running: false,
            last_finished_run: Some(v1::FinishedCheck {
                check: Some(v1::CheckMark {
                    id: "run-1".to_string(),
                    started_at: CHECKED - 30,
                    finished_at: Some(CHECKED),
                }),
                readings: Some(v1::CheckReadings {
                    partial: 1_234_567,
                    failed: 14,
                    not_repeated: 2,
                    machines_unread: 1,
                }),
                since_previous_run: Some(v1::SinceCheck {
                    added: 1_000_000,
                    changed: 3,
                    removed: 0,
                }),
                unknown: vec!["removals unknown where a reading was partial".to_string()],
                set_aside: 2,
                ..Default::default()
            }),
            estate: Some(v1::Estate {
                checkouts: 1_234_567,
                components: 7_654_321,
                servers: 9,
                servers_offered: 7,
                servers_read: 2,
                machines_set_aside: 2,
                machines_seen_after_owner_word_text: vec![odd.to_string()],
                ..Default::default()
            }),
            watched: Some(v1::WatchedPlaces {
                files: 1_234_567,
                since_last_reading: Some(v1::PlaceCounts {
                    new: 1,
                    changed: 2,
                    gone: 3,
                }),
                kinds: vec![v1::WatchedKind {
                    kind: "authentication module".to_string(),
                    coverage: Some(v1::Completeness::Partial as i32),
                    ..Default::default()
                }],
                changes: (0..50)
                    .map(|i| v1::PlaceChange {
                        at: CHECKED - i,
                        change: v1::Change::New as i32,
                        kind: "script run when a project's packages are installed".to_string(),
                        path_text: format!("{long}/{i}"),
                        ..Default::default()
                    })
                    .collect(),
                changes_total: 1_234_567,
                ..Default::default()
            }),
            threats: Some(v1::Threats {
                outcome: v1::FeedOutcome::Failed as i32,
                entries: Some(1_234_567),
                read_at: Some(NOW - 90_000),
                reason_text: Some(format!("curl: (6) Could not resolve host {odd}")),
                ..Default::default()
            }),
            vulnerability_data: Some(v1::VulnerabilityData {
                matched: true,
                feeds: vec![v1::FeedState {
                    ecosystem: "npm".to_string(),
                    outcome: v1::FeedOutcome::Unchanged as i32,
                    records: Some(1_234_567),
                    malicious_records: Some(4),
                    read_at: Some(CHECKED),
                    ..Default::default()
                }],
            }),
            vulnerabilities: Some(v1::VulnerabilityTotals {
                affected_records: 12,
                unknown_packages: 2,
                ..Default::default()
            }),
            integrity: Some(v1::Integrity {
                bundles: 4,
                homebrew_kegs: 8,
                global_npm_packages: 4,
                bundles_not_verifying: 4,
                not_verifying_since_first_reading: 4,
                ..Default::default()
            }),
            no_reader_for: Some(v1::NoReaderFor {
                items: vec![v1::NoReader {
                    what: "lockfile kind".to_string(),
                    what_text: Some(odd.to_string()),
                    where_count: 1_234_567,
                }],
            }),
            coverage: Some(v1::CoverageSummary {
                readings: 9_999_999,
                full: 9_876_543,
                failed: 1_234_567,
                no_reader: 9,
                problems: vec![v1::ReadingGroup {
                    class: v1::ReadingClass::Failed as i32,
                    reader: "watched-places".to_string(),
                    kind: "PAM policies and modules, and authorization plugins".to_string(),
                    reason_text: Some(format!("could not be read: {long} (Permission denied)")),
                    count: 1_234_567,
                    examples_text: vec![format!("checkout:machine:example-host/{odd}")],
                }],
                problems_total: 3,
                unreached: vec![v1::Unreached {
                    scope_text: format!("machine:{odd}"),
                    since_at: CHECKED - 3600,
                    reason_text: Some("the sweep of this server did not complete".to_string()),
                }],
                unreached_total: 1_234_567,
                ..Default::default()
            }),
            needs_a_look: Some(v1::NeedsALook {
                items: Vec::new(),
                total: 1_234_567,
                urgent_total: 765_432,
                by_rule: vec![
                    v1::RuleCount {
                        rule_title_text: Some(format!(
                            "A published rule whose own title is far longer than a short one {odd}"
                        )),
                        ..group("sigma:a", v1::Level::Critical, 1_000_000, 1_000_000)
                    },
                    group(
                        "lockfiles.exploited-vulnerability",
                        v1::Level::Critical,
                        3,
                        3,
                    ),
                    group("autorun.agent-start", v1::Level::High, 9, 9),
                    group("autorun.folder-open", v1::Level::High, 3, 2),
                    group("indicator.match", v1::Level::High, 2, 2),
                    group("integrity.package-files", v1::Level::High, 2, 2),
                    group("processes.detached-inline-code", v1::Level::High, 2, 2),
                    group("watched.git-hook", v1::Level::Medium, 234_000, 0),
                    v1::RuleCount {
                        severity: None,
                        ..group("kept.rule", v1::Level::Unspecified, 546, 0)
                    },
                ],
            }),
            this_mac: Some(v1::ThisMac {
                state: v1::ThisMacState::WatchedInPart as i32,
                live: false,
                checked_at: Some(CHECKED),
                watched: vec![v1::WatchedThing {
                    what: "startup items".to_string(),
                    count: 1_234_567,
                    how: "hourly".to_string(),
                }],
                fresh: false,
                stale_reason: Some("no full check has finished on this store".to_string()),
                ..Default::default()
            }),
            watching: Some(v1::Watcher {
                failed: vec![v1::WatcherFailure {
                    what: crate::watch::STORE.to_string(),
                    at: CHECKED,
                    detail_text: odd.to_string(),
                }],
                ..Default::default()
            }),
            event_level: Some(v1::EventLevel {
                state: v1::CollectorState::Running as i32,
                program_starts: Some(v1::Span {
                    since_check: 1,
                    last_day: 1_234_567,
                }),
                unknown_losses: Some(v1::Span {
                    since_check: 1,
                    last_day: 1,
                }),
                lost: Some(v1::Span {
                    since_check: 1,
                    last_day: 1_234_567,
                }),
                in_words: Some(v1::EventLevelWords {
                    state: "on".to_string(),
                    notes: vec![
                        "The collector restarted once; program starts in that moment were not seen."
                            .to_string(),
                        "1,234,567 program starts were missed because the collector fell behind."
                            .to_string(),
                    ],
                    caveats: vec![
                        v1::Caveat {
                            kind: "restarts".to_string(),
                            short: "1 restart".to_string(),
                        },
                        v1::Caveat {
                            kind: "lost".to_string(),
                            short: "1,234,567 lost".to_string(),
                        },
                    ],
                }),
                ..Default::default()
            }),
            not_covered: vec![
                uncovered(
                    "servers-not-checked",
                    "you",
                    false,
                    "1,234,567 of your servers were not checked last time.",
                    &[("staging-api", None), (odd, None)],
                ),
                uncovered(
                    "not-permitted",
                    "you",
                    false,
                    "1 file could not be opened because of its permissions.",
                    &[("example-host", Some(&format!("could not be read: {long}")))],
                ),
                uncovered(
                    "could-not-read",
                    "nothing",
                    false,
                    "2 things could not be read at the last check.",
                    &[("example-host", Some("sockets that could not be read: 1"))],
                ),
                uncovered(
                    "not-understood",
                    "nothing",
                    false,
                    "Some files and packages are not understood by this version yet.",
                    &[("poetry.lock", None), (odd, None), ("yarn.lock", None)],
                ),
                uncovered(
                    "vulnerabilities-unknown",
                    "nothing",
                    false,
                    "For 2 of the packages your projects use, this version cannot tell whether a known vulnerability affects them.",
                    &[],
                ),
                uncovered(
                    "persistence-not-read",
                    "nothing",
                    true,
                    "Some places where something can be set to start by itself on this Mac are not checked.",
                    &[],
                ),
            ],
            ..Default::default()
        }
    }

    fn listed(i: usize, level: v1::Level, urgent: bool, where_text: String) -> v1::ListedFinding {
        v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: format!("f{i:010x}"),
                rule: Some("watched.git-hook".to_string()),
                state: v1::FindingState::Open as i32,
                severity: Some(level as i32),
                urgent,
                ..Default::default()
            }),
            title: "A script that git runs by itself in one of your projects was added, changed or removed.".to_string(),
            short_title: "Script git runs by itself changed".to_string(),
            where_text,
            last_seen_at: CHECKED,
            ..Default::default()
        }
    }

    /// A list of real size: tens of findings of every level, long paths, a package, a published
    /// rule, and `odd` in every text from a source.
    fn findings_of(odd: &str) -> v1::Findings {
        let mut list: Vec<v1::ListedFinding> = Vec::new();
        for i in 0..7 {
            list.push(v1::ListedFinding {
                package_text: Some(format!("@ctrl/tinycolor-{odd}")),
                releases_text: vec!["4.1.1".to_string(), "4.1.2".to_string()],
                short_title: "Malicious package in a project".to_string(),
                ..listed(i, v1::Level::Critical, true, format!("{LONG}{i}"))
            });
        }
        list.push(v1::ListedFinding {
            rule_title_text: Some(format!(
                "Osacompile Execution By Potentially Suspicious Process {odd}"
            )),
            short_title: "Program start a published rule marks risky".to_string(),
            ..listed(7, v1::Level::High, true, "example-host".to_string())
        });
        for i in 8..40 {
            list.push(listed(
                i,
                v1::Level::High,
                i % 2 == 0,
                format!("~/dev/{odd}-{i}/.git/hooks/pre-commit"),
            ));
        }
        for i in 40..60 {
            list.push(listed(i, v1::Level::Medium, false, format!("{LONG}/{i}")));
        }
        let mut seen = listed(60, v1::Level::Low, false, "~/.zshrc".to_string());
        if let Some(r) = seen.finding.as_mut() {
            r.state = v1::FindingState::Seen as i32;
        }
        list.push(seen);
        v1::Findings {
            answered_at: NOW,
            latest_run_at: Some(CHECKED),
            findings: list,
            ..Default::default()
        }
    }

    /// Every text a person reads of these answers, on one screen.
    fn texts(screen: &Screen, odd: &str) -> Vec<String> {
        let s = status_of(odd);
        let f = findings_of(odd);
        vec![
            status(&s, screen, false),
            status(&s, screen, true),
            findings(&f, false, screen),
            findings(&f, true, screen),
        ]
    }

    #[test]
    fn no_line_is_longer_than_the_terminal_at_sixty_eighty_and_a_hundred_and_twenty_columns() {
        for screen in screens().into_iter().filter(|s| s.terminal) {
            let width = screen.width.unwrap();
            for text in texts(&screen, ODD) {
                for line in text.lines() {
                    assert!(
                        screen::columns(&visible(line)) <= width,
                        "{width}: {line:?}\n{text}"
                    );
                }
            }
        }
    }

    #[test]
    fn in_a_pipe_there_is_no_escape_byte_nothing_is_cut_and_times_are_exact() {
        let pipe = Screen::pipe();
        let all = texts(&pipe, ODD).concat();
        assert!(!all.contains('\u{1b}'), "{all}");
        // Whole: the longest path, a long reason, a published rule's own title.
        for whole in [
            format!("{LONG}/40"),
            format!("could not be read: {LONG}/{}", view::shown(ODD)),
            format!(
                "Osacompile Execution By Potentially Suspicious Process {}",
                view::shown(ODD)
            ),
        ] {
            assert!(all.contains(&whole), "{whole}\n{all}");
        }
        assert!(all.contains(&view::utc(CHECKED)), "{all}");
        assert!(!all.contains(" ago"), "{all}");
        // And on a terminal the same answers are cut and timed from now.
        let terminal = texts(&Screen::terminal(80, false), ODD).concat();
        assert!(!terminal.contains(&format!("{LONG}/40")));
        assert!(terminal.contains("checked 3 min ago"), "{terminal}");
    }

    /// Whether every escape byte of a text begins a style sequence of the program's own, every
    /// line closes each style it opens, and nothing a name held reached the terminal raw.
    fn styles_are_the_programs_own(text: &str) -> bool {
        let own = |seq: &str| {
            seq.strip_prefix("\u{1b}[")
                .and_then(|s| s.strip_suffix('m'))
                .is_some_and(|codes| {
                    codes
                        .split(';')
                        .all(|c| ["0", "1", "2", "31", "32", "33", "36"].contains(&c))
                })
        };
        text.lines().all(|line| {
            let mut opened = 0i32;
            let mut rest = line;
            while let Some(at) = rest.find('\u{1b}') {
                let after = &rest[at..];
                let Some(end) = after.find('m') else {
                    return false;
                };
                let seq = &after[..=end];
                if !own(seq) || seq.contains(']') {
                    return false;
                }
                opened += if seq == "\u{1b}[0m" { -1 } else { 1 };
                rest = &after[end + 1..];
            }
            opened == 0
        }) && !text.contains('\u{7}')
            && !text.contains('\u{202e}')
            && !text.contains("\u{1b}[31mRED")
            && !text.contains("\u{1b}]")
    }

    #[test]
    fn text_from_a_source_is_written_out_and_never_opens_or_closes_a_style() {
        // A name holding a style sequence, a title sequence and U+202E, given raw and as the
        // core gives it, escaped once already: on every screen it is written out, and every
        // escape byte is the program's own style, opened and closed on the same line.
        for odd in [ODD.to_string(), crate::known::whole(ODD)] {
            for screen in screens() {
                let all = texts(&screen, &odd).concat();
                assert!(styles_are_the_programs_own(&all), "{screen:?}\n{all:?}");
                // A terminal may break a long name between two of its characters; each hidden
                // one is written out whole all the same.
                let shown: &[&str] = if screen.terminal {
                    &[r"\u{1b}", r"\u{202e}", r"\u{7}"]
                } else {
                    &[r"\u{1b}[31m", r"\u{202e}", r"\u{1b}]0;owned\u{7}"]
                };
                for shown in shown {
                    assert!(all.contains(shown), "{screen:?}: {shown}\n{all}");
                }
            }
        }
        // Not vacuous: the program's own styles are there on a screen with colour.
        assert!(
            texts(&Screen::terminal(80, true), ODD)
                .concat()
                .contains("\u{1b}[1;31m")
        );
    }

    #[test]
    fn what_needs_a_look_is_never_counted_without_how_many_are_urgent() {
        assert_eq!(needing(1, 0), "1 thing needs a look, none urgent");
        assert_eq!(
            needing(1_234_567, 765_432),
            "1,234,567 things need a look, 765,432 urgent"
        );
        let text = status(&status_of("x"), &Screen::pipe(), false);
        assert!(
            text.starts_with("✗ 1,234,567 things need a look, 765,432 urgent"),
            "{text}"
        );
        // The rules past the sixth are counted with their urgent ones.
        assert!(
            text.contains("… 234,548 more in 3 kinds, 2 urgent"),
            "{text}"
        );
    }

    #[test]
    fn a_status_lists_six_rules_most_urgent_first_with_their_counts_over_all_findings() {
        let text = status(&status_of("x"), &Screen::pipe(), false);
        let rows: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("Short title of") || l.contains("A published rule"))
            .collect();
        assert_eq!(rows.len(), 6, "{text}");
        assert!(
            rows[0].starts_with("  critical  A published rule"),
            "{text}"
        );
        assert!(rows[0].trim_end().ends_with("1,000,000  urgent"), "{text}");
        // Some of a rule's findings urgent: how many.
        assert!(
            rows[3].contains("autorun.folder-open") && rows[3].trim_end().ends_with("3  2 urgent"),
            "{text}"
        );
        assert!(!text.contains("Short title of watched.git-hook"), "{text}");
    }

    #[test]
    fn a_calm_headline_is_green_only_after_a_fresh_check_that_found_nothing() {
        let screen = Screen::terminal(80, true);
        let mut s = status_of("x");
        s.needs_a_look = Some(v1::NeedsALook::default());
        s.last_run = None;
        if let Some(m) = s.this_mac.as_mut() {
            m.fresh = true;
        }
        // Each failure the status holds, one at a time, keeps it from being calm.
        let clear = |s: &mut v1::Status| {
            s.watching = None;
            s.event_level = None;
            s.not_covered
                .retain(|u| !FAILED_CAUSES.contains(&u.id.as_str()));
            if let Some(c) = s.coverage.as_mut() {
                c.failed = 0;
                c.unreached_total = 0;
                c.unreached.clear();
            }
        };
        clear(&mut s);
        let calm = status(&s, &screen, false);
        assert!(
            calm.starts_with("\u{1b}[1;32m✓ Nothing needs a look\u{1b}[0m"),
            "{calm}"
        );
        let failures: [fn(&mut v1::Status); 5] = [
            |s| s.coverage.as_mut().unwrap().failed = 1,
            |s| s.coverage.as_mut().unwrap().unreached_total = 1,
            |s| {
                s.watching = Some(v1::Watcher {
                    failed: vec![v1::WatcherFailure::default()],
                    ..Default::default()
                })
            },
            |s| {
                s.event_level = Some(v1::EventLevel {
                    state: v1::CollectorState::Failing as i32,
                    ..Default::default()
                })
            },
            |s| {
                s.last_run = Some(v1::CheckMark::default());
                s.running = false;
            },
        ];
        for (i, fail) in failures.iter().enumerate() {
            let mut failing = s.clone();
            fail(&mut failing);
            let said = status(&failing, &screen, false);
            assert!(
                said.starts_with("\u{1b}[1;33mNothing needs a look in what could be read"),
                "{i}: {said}"
            );
        }
        let mut feed = status_of("x");
        feed.needs_a_look = Some(v1::NeedsALook::default());
        feed.last_run = None;
        clear(&mut feed);
        feed.this_mac.as_mut().unwrap().fresh = true;
        feed.not_covered.push(v1::Uncovered {
            id: FAILED_CAUSES[1].to_string(),
            who: "nothing".to_string(),
            ..Default::default()
        });
        assert!(!status(&feed, &screen, false).contains("✓"));
        if let Some(m) = s.this_mac.as_mut() {
            m.fresh = false;
        }
        let stale = status(&s, &screen, false);
        assert!(
            stale.starts_with("\u{1b}[1mNothing needed a look at the last check")
                && stale.contains("Not fresh"),
            "{stale}"
        );
        s.needs_a_look = None;
        let unknown = status(&s, &screen, false);
        assert!(
            unknown.starts_with("\u{1b}[1mNo run of this build has looked for findings yet"),
            "{unknown}"
        );
        assert!(!stale.contains("✓") && !unknown.contains("✓"));
    }

    #[test]
    fn every_failure_is_in_the_default_status_and_none_is_dim() {
        // Wide enough that no value is broken into lines, so each failure is found on one.
        let screen = Screen::terminal(400, true);
        let text = status(&status_of("x"), &screen, false);
        for words in [
            "its latest write to the store failed",
            "Event level",
            "Not reached",
            "2 things could not be read at the last check",
            "has not finished: it died",
            "Not fresh",
            "1,234,567 readings failed",
        ] {
            let line = text
                .lines()
                .find(|l| visible(l).contains(words))
                .unwrap_or_else(|| panic!("{words}\n{text}"));
            assert!(!line.contains("\u{1b}[2m"), "{line:?}");
        }
        // On a narrow terminal a failure keeps every word of its title, broken into lines.
        let mut s = status_of("x");
        s.not_covered.push(v1::Uncovered {
            id: FAILED_CAUSES[1].to_string(),
            who: "nothing".to_string(),
            title: "The list of vulnerabilities attackers are using could not be downloaded since the first check.".to_string(),
            value_text: Some(format!("cannot read {LONG}")),
            ..Default::default()
        });
        let narrow = status(&s, &Screen::terminal(60, true), false);
        let words: Vec<String> = narrow
            .lines()
            .map(|l| visible(l).trim().to_string())
            .collect();
        let words = words.join(" ");
        for u in s
            .not_covered
            .iter()
            .filter(|u| FAILED_CAUSES.contains(&u.id.as_str()))
        {
            assert!(words.contains(unstopped(&u.title)), "{}\n{narrow}", u.title);
        }
        // The event level as it should be has no line; a failed one has.
        let mut s = status_of("x");
        if let Some(l) = s.event_level.as_mut() {
            l.in_words = Some(v1::EventLevelWords {
                state: "on".to_string(),
                ..Default::default()
            });
        }
        assert!(!status(&s, &screen, false).contains("Event level"));
        if let Some(l) = s.event_level.as_mut() {
            l.state = v1::CollectorState::Failing as i32;
        }
        assert!(status(&s, &screen, false).contains("Event level"));
    }

    #[test]
    fn the_coverage_of_a_status_carries_every_part_the_status_used_to_say() {
        let text = status(&status_of("x"), &Screen::pipe(), true);
        for part in [
            "Store",
            "Last run",
            "Counted",
            "Estate",
            "Gaps",
            "Changes",
            "Set aside",
            "Watched places",
            "Installed software",
            "CISA catalogue",
            "OSV data",
            "This Mac",
            "Not fresh",
            "Watched",
            "Event level",
            "Needs a look",
            "You can fix",
            "Limits of this version",
            "Not judged on this Mac",
            "Readings",
            "Machines not reached",
            "Readings that were not full",
            "No reader in this build for",
            "Latest changes in watched places, newest first, 50 of 1,234,567",
        ] {
            assert!(
                text.lines().any(|l| l.trim_start().starts_with(part)),
                "{part}\n{text}"
            );
        }
        // Each list whole, as the message holds it, and what it does not hold counted.
        assert!(text.contains("x/49"), "{text}");
        assert!(
            text.contains("2 more groups of readings not listed"),
            "{text}"
        );
        assert!(
            text.contains("1,234,566 more machines not listed"),
            "{text}"
        );
        // On a terminal too, every cause of what is not judged is there whole, broken into lines.
        let mut s = status_of("x");
        s.not_covered.push(v1::Uncovered {
            id: "not-understood".to_string(),
            who: "nothing".to_string(),
            holds_on: v1::HoldsOn::ThisMac as i32,
            title: "Some files and packages are not understood by this version yet.".to_string(),
            examples_text: (0..5)
                .map(|i| format!("~/dev/project-{i}/poetry.lock"))
                .collect(),
            ..Default::default()
        });
        let narrow = status(&s, &Screen::terminal(80, false), true);
        let bare = |t: &str| t.split_whitespace().collect::<String>();
        let all = bare(&narrow);
        for u in s.not_covered.iter().filter(|u| u.who == "nothing") {
            assert!(
                all.contains(&bare(unstopped(&u.title))),
                "{}\n{narrow}",
                u.title
            );
            assert!(
                all.contains(&bare(&view::shown(&examples(u)))),
                "{}\n{narrow}",
                u.title
            );
        }
    }

    #[test]
    fn findings_are_grouped_under_their_level_most_severe_first_with_state_only_when_needed() {
        let f = findings_of("x");
        let text = findings(&f, false, &Screen::pipe());
        assert!(
            text.starts_with("✗ 60 open findings, 24 urgent: 7 critical, 33 high, 20 medium"),
            "{text}"
        );
        let heads: Vec<&str> = text
            .lines()
            .filter(|l| ["critical", "high", "medium", "low"].contains(l))
            .collect();
        assert_eq!(heads, ["critical", "high", "medium"], "{text}");
        assert!(
            !text.contains("  open  ") && !text.contains("f000000003c"),
            "{text}"
        );
        assert!(
            text.trim_end()
                .ends_with("→ immune finding <id>   shows one and how to answer it"),
            "{text}"
        );
        let all = findings(&f, true, &Screen::pipe());
        assert!(
            all.starts_with("✗ 61 findings, 60 open, 24 urgent"),
            "{all}"
        );
        assert!(
            all.contains("  open  ") && all.contains("  seen  "),
            "{all}"
        );
        assert!(all.contains("\nlow\n"), "{all}");
    }

    #[test]
    fn a_package_finding_is_told_by_its_package_releases_and_project() {
        let text = findings(&findings_of("x"), false, &Screen::pipe());
        assert!(
            text.contains(
                "@ctrl/tinycolor-x 4.1.1, 4.1.2 in ~/Developer/clients/northwind-traders/customer-portal-frontend-monorepo-with-a-very-long-name"
            ),
            "{text}"
        );
        // On a terminal the package and its releases stay whole while the folder is cut.
        let cut = findings(&findings_of("x"), false, &Screen::terminal(120, false));
        assert!(
            cut.contains("@ctrl/tinycolor-x 4.1.1, 4.1.2 in ~/Dev"),
            "{cut}"
        );
    }

    #[test]
    fn a_published_rule_is_named_by_its_own_title_cut_on_a_terminal_and_whole_in_a_pipe() {
        let f = findings_of("x");
        let title = "Osacompile Execution By Potentially Suspicious Process x";
        assert!(findings(&f, false, &Screen::pipe()).contains(title));
        let cut = findings(&f, false, &Screen::terminal(200, false));
        assert!(
            cut.contains(&format!("{}…", &title[..SHORT_MAX - 1])) && !cut.contains(title),
            "{cut}"
        );
    }

    #[test]
    fn a_findings_list_that_reaches_its_text_limit_says_how_many_it_shows() {
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: (1..=201)
                .map(|i| listed(i, v1::Level::Medium, false, format!("~/{i}")))
                .collect(),
            ..Default::default()
        };
        let text = findings(&f, false, &Screen::pipe());
        assert!(
            text.starts_with("✗ 201 open findings, none urgent"),
            "{text}"
        );
        assert!(
            text.contains("f00000000c8") && !text.contains("f00000000c9"),
            "{text}"
        );
        assert!(
            text.contains("Showing the first 200; 1 more not shown, 0 of them urgent."),
            "{text}"
        );
    }

    #[test]
    fn every_finding_as_text_puts_open_ones_first_and_its_cut_says_how_many_hidden_are_urgent() {
        // The answer's order is urgent first across states: closed urgent findings come before
        // open ones that are not urgent. Open ones are shown first all the same.
        let found = |i: usize, state: v1::FindingState, urgent: bool| {
            let mut l = listed(i, v1::Level::High, urgent, format!("~/{i}"));
            if let Some(r) = l.finding.as_mut() {
                r.state = state as i32;
            }
            l
        };
        let closed = (0..150).map(|i| found(i, v1::FindingState::Expected, true));
        let open = (150..300).map(|i| found(i, v1::FindingState::Open, false));
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: closed.chain(open).collect(),
            ..Default::default()
        };
        let text = findings(&f, true, &Screen::pipe());
        assert!(
            text.starts_with("✗ 300 findings, 150 open, none urgent"),
            "{text}"
        );
        // All 150 open ones, then the first 50 closed ones; 100 closed urgent ones are hidden.
        assert!(
            text.contains("f000000012b") && text.contains("f0000000031"),
            "{text}"
        );
        assert!(!text.contains("f0000000032"), "{text}");
        assert!(
            text.contains("Showing the first 200; 100 more not shown, 100 of them urgent."),
            "{text}"
        );
    }

    #[test]
    fn findings_of_one_rule_are_listed_under_its_name_said_once_urgent_groups_first() {
        let of = |i: usize, rule: &str, short: &str, urgent: bool| {
            let mut l = listed(i, v1::Level::High, urgent, format!("~/dev/p{i}/x"));
            if let Some(r) = l.finding.as_mut() {
                r.rule = Some(rule.to_string());
            }
            l.short_title = short.to_string();
            l
        };
        let f = v1::Findings {
            latest_run_at: Some(CHECKED),
            answered_at: NOW,
            findings: vec![
                of(1, "a", "Three that are not urgent", false),
                of(2, "c", "Two that are not urgent", false),
                of(3, "a", "Three that are not urgent", false),
                of(4, "b", "One that is urgent", true),
                of(5, "a", "Three that are not urgent", false),
                of(6, "c", "Two that are not urgent", false),
            ],
            ..Default::default()
        };
        for screen in [Screen::pipe(), Screen::terminal(80, false)] {
            let text = findings(&f, false, &screen);
            let titles: Vec<&str> = text
                .lines()
                .filter(|l| l.starts_with("  ") && !l.starts_with("    "))
                .collect();
            assert_eq!(
                titles,
                [
                    "  One that is urgent   1",
                    "  Three that are not urgent   3",
                    "  Two that are not urgent   2"
                ],
                "{text}"
            );
            // Each title once; under it, its findings only, with no title on their rows.
            for short in ["One that is urgent", "Three that are not urgent"] {
                assert_eq!(text.matches(short).count(), 1, "{text}");
            }
            let rows: Vec<&str> = text.lines().filter(|l| l.starts_with("    f")).collect();
            assert_eq!(rows.len(), 6, "{text}");
            assert!(
                rows[0].contains("f0000000004") && rows[0].ends_with("urgent"),
                "{text}"
            );
            assert!(rows[1].contains("f0000000001") && rows[3].contains("f0000000005"));
        }
        // The room the title took is the place's: a long path keeps more of itself at 80.
        let long = v1::Findings {
            latest_run_at: Some(CHECKED),
            findings: vec![listed(
                1,
                v1::Level::High,
                false,
                format!("{LONG}/package-lock.json"),
            )],
            ..Default::default()
        };
        let text = findings(&long, false, &Screen::terminal(80, false));
        let row = text.lines().find(|l| l.starts_with("    f")).unwrap();
        assert!(screen::columns(row) >= 70, "{text}");
    }

    /// A status with only these causes of what is not covered.
    fn with_causes(causes: Vec<v1::Uncovered>) -> v1::Status {
        let mut s = status_of("x");
        s.not_covered = causes;
        s
    }

    #[test]
    fn what_a_cause_is_about_is_under_it_without_quotes_and_no_name_passes_for_two() {
        let names = v1::Uncovered {
            id: "servers-not-swept".to_string(),
            who: "you".to_string(),
            title: "2 of your servers were not checked last time.".to_string(),
            count: 4,
            examples_text: vec!["staging-api".into(), "old-mail".into(), "a, b".into()],
            ..Default::default()
        };
        let pairs = v1::Uncovered {
            id: "servers-not-opened".to_string(),
            who: "you".to_string(),
            title: "5 servers could not be opened at the last server check.".to_string(),
            count: 5,
            examples_text: vec![
                "db-1".into(),
                "web: new".into(),
                "line\u{a}feed".into(),
                "fourth".into(),
                "fifth".into(),
            ],
            examples: [
                "Permission denied (publickey).",
                "timed out: 22",
                "refused",
                "x",
                "y",
            ]
            .iter()
            .zip(["db-1", "web: new", "line\u{a}feed", "fourth", "fifth"])
            .map(|(r, n)| v1::UncoveredExample {
                name_text: n.to_string(),
                reason_text: Some(r.to_string()),
            })
            .collect(),
            ..Default::default()
        };
        // A cause that names nothing has no list under it, and nothing counted as left out.
        let alone = v1::Uncovered {
            id: "event-level-not-installed".to_string(),
            who: "you".to_string(),
            title: "Program starts on this Mac are not seen.".to_string(),
            count: 1,
            ..Default::default()
        };
        let s = with_causes(vec![names, pairs, alone]);
        for screen in [Screen::pipe(), Screen::terminal(60, false)] {
            let text = status(&s, &screen, false);
            let lines: Vec<&str> = text.lines().collect();
            let at = lines
                .iter()
                .position(|l| *l == "    Program starts on this Mac are not seen")
                .unwrap_or_else(|| panic!("{text}"));
            assert!(!lines[at + 1].starts_with("      "), "{text}");
            // Plain names, joined with commas, no quotes; a comma inside a name is written out.
            assert!(
                lines.contains(&"      staging-api, old-mail, a\\u{2c} b"),
                "{text}"
            );
            assert!(
                lines.contains(&"      … 1 more   immune status --coverage"),
                "{text}"
            );
            // One name and its reason a line, at most three, a colon in a name written out, a
            // line feed in a name an escape on the same line; then how many more.
            let at = lines
                .iter()
                .position(|l| *l == "      db-1: Permission denied (publickey).")
                .unwrap_or_else(|| panic!("{text}"));
            assert_eq!(
                lines[at + 1],
                "      web\\u{3a} new: timed out: 22",
                "{text}"
            );
            assert_eq!(lines[at + 2], "      line\\u{a}feed: refused", "{text}");
            assert_eq!(
                lines[at + 3],
                "      … 2 more   immune status --coverage",
                "{text}"
            );
            assert!(!text.contains("\"db-1\"") && !text.contains("\"staging-api\""));
        }
        // A long reason is broken into lines set in further, never cut.
        let mut long = with_causes(vec![]);
        long.not_covered.push(v1::Uncovered {
            id: "file-permissions".to_string(),
            who: "you".to_string(),
            title: "1 file could not be opened because of its permissions.".to_string(),
            count: 1,
            examples_text: vec!["example-host".into()],
            examples: vec![v1::UncoveredExample {
                name_text: "example-host".into(),
                reason_text: Some(format!("could not be read: {LONG} (Permission denied)")),
            }],
            ..Default::default()
        });
        let text = status(&long, &Screen::terminal(60, false), false);
        let bare: String = text.split_whitespace().collect();
        assert!(
            bare.contains(&format!("{LONG}(Permissiondenied)")),
            "{text}"
        );
        let section = &text[text
            .find("  You can fix")
            .unwrap_or_else(|| panic!("{text}"))..];
        assert!(!section.contains('…'), "{text}");
    }

    #[test]
    fn the_context_lines_say_what_is_true_one_clause_each() {
        let screen = Screen::terminal(200, true);
        let line = |text: &str, label: &str| -> String {
            text.lines()
                .find(|l| visible(l).trim_start().starts_with(label))
                .map(str::to_string)
                .unwrap_or_else(|| panic!("{label}\n{text}"))
        };
        let mut s = status_of("x");
        // No watcher, watched in part: what is not watched leads, then the watcher; no command
        // beside it, and installing one is a next step at the end.
        s.watching = None;
        let text = status(&s, &screen, false);
        let watching = visible(&line(&text, "Watching"));
        assert_eq!(
            watching.trim_end(),
            "  Watching      in part: authentication module and some program starts not watched in full; no watcher runs now: changes are seen at each check",
        );
        assert!(
            visible(&text).contains("\n→ immune install   keeps watching between checks\n"),
            "{text}"
        );
        // Watched in full with no watcher: the watcher clause alone.
        if let Some(m) = s.this_mac.as_mut() {
            m.state = v1::ThisMacState::Watched as i32;
        }
        let text = status(&s, &screen, false);
        assert_eq!(
            visible(&line(&text, "Watching")).trim_end(),
            "  Watching      no watcher runs now: changes are seen at each check"
        );
        // A live watcher on a Mac watched in full: one word, no command.
        s.watching = Some(v1::Watcher::default());
        if let Some(m) = s.this_mac.as_mut() {
            m.live = true;
            m.state = v1::ThisMacState::Watched as i32;
        }
        let text = status(&s, &screen, false);
        assert_eq!(
            visible(&line(&text, "Watching")).trim_end(),
            "  Watching      live"
        );
        assert!(!text.contains("immune install"), "{text}");
        // The event level: its state, then what is wrong in yellow.
        let event = line(&text, "Event level");
        assert!(
            event.contains(
                "on; \u{1b}[33mthe collector restarted once, and 1,234,567 program starts were lost\u{1b}[0m"
            ),
            "{event:?}"
        );
        // Coverage: what is missing, by kind; a failure yellow, never dim.
        let coverage = line(&text, "Coverage");
        assert!(
            coverage.contains("\u{1b}[33m1,234,567 readings failed\u{1b}[0m")
                && !coverage.contains("\u{1b}[2m"),
            "{coverage:?}"
        );
        assert!(!visible(&coverage).contains("full"), "{coverage:?}");
        // Nothing missing: said so, and readings with nothing to read are not held against it.
        if let Some(c) = s.coverage.as_mut() {
            c.failed = 0;
            c.no_reader = 0;
            c.not_given = 0;
            c.unreached_total = 0;
            c.unreached.clear();
            c.read_nothing = 5;
        }
        let text = status(&s, &screen, false);
        assert!(
            visible(&line(&text, "Coverage"))
                .contains("everything this version reads here was read"),
            "{text}"
        );
    }

    #[test]
    fn the_coverage_of_a_status_lists_what_is_watched_as_a_table() {
        let mut s = status_of("x");
        if let Some(m) = s.this_mac.as_mut() {
            m.watched.push(v1::WatchedThing {
                what: "program starts".to_string(),
                count: 35,
                how: "events".to_string(),
            });
        }
        let text = status(&s, &Screen::pipe(), true);
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| *l == "  Watched")
            .unwrap_or_else(|| panic!("{text}"));
        let words = |l: &str| l.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(words(lines[at + 1]), "Place How many How often", "{text}");
        assert_eq!(
            words(lines[at + 2]),
            "startup items 1,234,567 hourly",
            "{text}"
        );
        assert_eq!(words(lines[at + 3]), "program starts 35 events", "{text}");
        // The counts stand to the right, in one column.
        assert_eq!(
            lines[at + 2]
                .find("1,234,567")
                .map(|i| i + "1,234,567".len()),
            lines[at + 3].find("35").map(|i| i + 2),
            "{text}"
        );
        assert!(
            !text.contains("startup items: 1,234,567 (hourly)"),
            "{text}"
        );
    }

    #[test]
    fn the_next_steps_are_at_the_end_each_on_its_own_line_only_when_they_apply() {
        let ends = |text: &str| -> Vec<String> {
            text.lines()
                .filter(|l| l.starts_with('→'))
                .map(str::to_string)
                .collect()
        };
        let findings_step = "→ immune findings   lists every one, most urgent first";
        let install_step = "→ immune install   keeps watching between checks";
        let coverage_step = "→ immune status --coverage   what was read and what was not";
        // Something needs a look, no watcher runs, and coverage is not whole: all three, in order.
        let mut s = status_of("x");
        s.watching = None;
        for screen in [Screen::pipe(), Screen::terminal(80, false)] {
            let text = status(&s, &screen, false);
            assert_eq!(
                ends(&text),
                [findings_step, install_step, coverage_step],
                "{text}"
            );
            // No context line carries a command beside its value.
            for l in text.lines().filter(|l| {
                [
                    "Watching",
                    "Event level",
                    "Coverage",
                    "Not judged",
                    "Not reached",
                ]
                .iter()
                .any(|label| l.trim_start().starts_with(label))
            }) {
                assert!(!l.contains("immune "), "{l}\n{text}");
            }
        }
        // Wholly calm, with a watcher: the one line it had.
        let mut calm = status_of("x");
        calm.needs_a_look = Some(v1::NeedsALook::default());
        calm.watching = Some(v1::Watcher::default());
        calm.event_level = None;
        calm.not_covered.clear();
        if let Some(c) = calm.coverage.as_mut() {
            c.failed = 0;
            c.no_reader = 0;
            c.not_given = 0;
            c.unreached_total = 0;
            c.unreached.clear();
        }
        assert_eq!(
            ends(&status(&calm, &Screen::pipe(), false)),
            [coverage_step]
        );
        // The same with no watcher: installing one is the step.
        calm.watching = None;
        assert_eq!(ends(&status(&calm, &Screen::pipe(), false)), [install_step]);
        // Calm, with a watcher, and one thing not judged: what was not read is the step.
        calm.watching = Some(v1::Watcher::default());
        calm.not_covered.push(v1::Uncovered {
            id: "not-understood".to_string(),
            who: "nothing".to_string(),
            holds_on: v1::HoldsOn::ThisMac as i32,
            title: "Some files are not understood by this version yet.".to_string(),
            examples_text: vec!["poetry.lock".to_string()],
            ..Default::default()
        });
        assert_eq!(
            ends(&status(&calm, &Screen::pipe(), false)),
            [coverage_step]
        );
        calm.watching = None;
        assert_eq!(
            ends(&status(&calm, &Screen::pipe(), false)),
            [install_step, coverage_step]
        );
    }
}
