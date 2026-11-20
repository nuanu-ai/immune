//! The text for a person of `immunity finding <id>` and of an answer to a finding, rendered from
//! the message alone (`Finding`) for a screen (`screen.rs`), in
//! the layout of the core's language for a person (`docs/how-it-works.md`).
//!
//! One finding answers "what is this, is it bad, what do I do": its level and short title with
//! its id, the thing it is about and its state; the core's three sentences; the evidence by its
//! kind; the verdicts and the person's answer when there are any; the rule, the confidence and
//! the technique in one dim line; last, the next commands that apply to its state. An answer says
//! first that it took and what it does. A refusal of either is told as every command tells one
//! (`text::refusal`), with the command typed in its right form (`usage::finding_next`).
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`), and every piece is escaped again as it reaches the screen, before it is
//! measured, cut, broken into lines or styled (`screen.rs`). It is never placed at the start of
//! a line: every line that holds it is indented, so it cannot pass for a line of Immunity Core's own
//! (`✓`, `→ immunity …`, `error:`). Beside a label it goes without quotes.

use crate::contract::v1;
use crate::overview::{count, joined, level, unstopped, words};
use crate::screen::{self, BOLD, CYAN, DIM, GREEN, PLAIN, RED, Screen, Style};
use crate::{findings, view};

/// The labels beside the core's words and the person's answer: "Your answer" is the widest.
const LABEL: usize = 11;
/// The labels of the evidence: "First read" and "About rule" are the widest.
const EVIDENCE_LABEL: usize = 10;
/// The labels of an event's fields and of a verdict's: "Started by" is the widest.
const EVENT_LABEL: usize = 10;
/// The fewest columns a value is given beside its label. On a terminal narrower than that, the
/// label is on a line of its own and the value under it.
const BESIDE: usize = 24;
/// The fewest columns a short title keeps on the first line before it goes to a line of its own.
const TITLE_KEPT: usize = 12;
/// The fewest columns the thing a finding is about keeps beside its state, at least, before the
/// state goes to a line of its own: half the terminal's width when that is more.
const WHERE_KEPT: usize = 20;

/// A labelled field: the label bold after `indent`, the value in its parts' styles beside it,
/// broken into lines under itself on a terminal and never cut. On a terminal too narrow for a
/// value beside its label, the label is on a line of its own and the value under it, two
/// columns in. Each part is escaped before it is measured (`Screen::labelled_parts`).
fn field(
    s: &Screen,
    indent: usize,
    label_width: usize,
    label: &str,
    parts: &[(&str, Style)],
) -> Vec<String> {
    let lead = indent + label_width + 3;
    match s.fits() {
        Some(width) if width < lead + BESIDE => {
            let mut out = Vec::new();
            if !label.is_empty() {
                out.push(format!("{}{}", " ".repeat(indent), s.paint(BOLD, label)));
            }
            // An empty label in a column of `indent - 1` puts the value at `indent + 2`.
            out.extend(s.labelled_parts(0, indent.saturating_sub(1), "", parts, None, 0));
            out
        }
        _ => s.labelled_parts(indent, label_width, label, parts, None, 0),
    }
}

/// A line made of parts in styles of their own, after `indent` (at least 3), broken into lines
/// after the same indent on a terminal. Each part is escaped before it is measured.
fn parts_line(s: &Screen, indent: usize, parts: &[(&str, Style)]) -> Vec<String> {
    s.labelled_parts(0, indent.saturating_sub(3), "", parts, None, 0)
}

/// A sentence of the core's own, broken into lines after `indent` on a terminal, in one style.
fn para(s: &Screen, indent: usize, text: &str, style: Style) -> Vec<String> {
    let text = view::shown(text);
    let room = s.fits().map(|w| w.saturating_sub(indent).max(1));
    screen::wrap(&text, room)
        .iter()
        .map(|l| format!("{}{}", " ".repeat(indent), s.paint(style, l)))
        .map(|l| l.trim_end().to_string())
        .collect()
}

/// A section's head, bold, two columns in.
fn head(s: &Screen, text: &str) -> String {
    format!("  {}", s.paint(BOLD, text))
}

/// The state a finding's reference gives, a value this build does not know read as open, as the
/// schema says.
fn state_of(f: &v1::Finding) -> v1::FindingState {
    match f
        .finding
        .as_ref()
        .and_then(|r| v1::FindingState::try_from(r.state).ok())
    {
        Some(v1::FindingState::Unspecified) | None => v1::FindingState::Open,
        Some(s) => s,
    }
}

/// Whether the finding is the response layer's, raised by a `suspicious` verdict.
fn of_the_response_layer(f: &v1::Finding) -> bool {
    f.finding
        .as_ref()
        .and_then(|r| r.rule.as_deref())
        .is_some_and(|r| r == crate::verdict::RULE || r.starts_with(crate::verdict::PREFIX))
}

/// What a finding is called on its first line: its short title, or its title from a core that
/// gives no short one.
fn short_of(f: &v1::Finding) -> &str {
    if f.short_title.is_empty() {
        unstopped(&f.title)
    } else {
        &f.short_title
    }
}

/// The first line: the mark and the level in the level's colour, `urgent` in red when it is, the
/// short title bold, and the id dim at the right. On a terminal the title is cut to keep the id
/// in sight, and goes to lines of its own, under them, when too little of it would be left; the
/// level and the id are never cut. In a pipe the id follows the title.
fn first_line(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let r = f.finding.clone().unwrap_or_default();
    let (said, style) = match r.severity {
        None => ("severity not known".to_string(), PLAIN),
        Some(_) => level(r.severity),
    };
    let marked = view::shown(&format!("● {said}"));
    let mut fixed = s.paint(style, &marked);
    let mut fixed_w = screen::columns(&marked);
    if r.urgent {
        fixed.push_str(" · ");
        fixed.push_str(&s.paint(RED, "urgent"));
        fixed_w += screen::columns(" · urgent");
    }
    let title = view::shown(short_of(f));
    let id = view::shown(&r.id);
    let (title_w, id_w) = (screen::columns(&title), screen::columns(&id));
    let Some(width) = s.fits() else {
        return vec![format!(
            "{fixed}  {}   {}",
            s.paint(BOLD, &title),
            s.paint(DIM, &id)
        )];
    };
    let room = width.saturating_sub(fixed_w + 2 + 3 + id_w);
    if title_w <= room || room >= TITLE_KEPT {
        let title = screen::cut_end(&title, room);
        let pad = width - fixed_w - 2 - screen::columns(&title) - id_w;
        return vec![format!(
            "{fixed}  {}{}{}",
            s.paint(BOLD, &title),
            " ".repeat(pad),
            s.paint(DIM, &id)
        )];
    }
    let mut out = Vec::new();
    if fixed_w + 3 + id_w <= width {
        out.push(format!(
            "{fixed}{}{}",
            " ".repeat(width - fixed_w - id_w),
            s.paint(DIM, &id)
        ));
    } else {
        out.push(fixed);
        out.push(format!(
            "{}{}",
            " ".repeat(width.saturating_sub(id_w)),
            s.paint(DIM, &id)
        ));
    }
    out.extend(para(s, 2, &title, BOLD));
    out
}

/// Where a finding stands, with its times as the screen shows them.
fn state_said(s: &Screen, f: &v1::Finding) -> String {
    let now = f.answered_at;
    let answer = f.answer.as_ref();
    match state_of(f) {
        v1::FindingState::Expected => match answer.and_then(|a| a.until_at) {
            Some(until) => format!("expected until {}", s.time(until, now)),
            None => "expected".to_string(),
        },
        v1::FindingState::Seen => match answer {
            Some(a) => format!("seen {}", s.time(a.given_at, now)),
            None => "seen".to_string(),
        },
        v1::FindingState::Cleared => {
            format!("cleared, last seen {}", s.time(f.last_seen_at, now))
        }
        _ => {
            let (first, last) = (s.time(f.first_seen_at, now), s.time(f.last_seen_at, now));
            if last == first {
                format!("open, first seen {first}")
            } else {
                format!("open, first seen {first}, last seen {last}")
            }
        }
    }
}

/// The second line: the thing the finding is about, two columns in, cut in the middle on a
/// terminal to keep its state in sight, and its state at the right. Where that would leave the
/// thing less than half the line, the state is on a line of its own, at the right.
fn second_line(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let thing = view::shown(&match &f.thing {
        Some(t) => format!("{t} on {}", f.where_text),
        None => f.where_text.clone(),
    });
    let state = view::shown(&state_said(s, f));
    let Some(width) = s.fits() else {
        return vec![format!("  {thing}   {state}")];
    };
    let (thing_w, state_w) = (screen::columns(&thing), screen::columns(&state));
    let room = width.saturating_sub(2 + 3 + state_w);
    if thing_w <= room || room >= WHERE_KEPT.max(width / 2) {
        let thing = screen::cut_middle(&thing, room);
        let pad = width - 2 - screen::columns(&thing) - state_w;
        return vec![format!(
            "  {}{}{}",
            s.paint(PLAIN, &thing),
            " ".repeat(pad),
            s.paint(PLAIN, &state)
        )];
    }
    let mut out = vec![format!(
        "  {}",
        s.paint(PLAIN, &screen::cut_middle(&thing, width.saturating_sub(2)))
    )];
    if 2 + state_w <= width {
        out.push(format!(
            "{}{}",
            " ".repeat(width - state_w),
            s.paint(PLAIN, &state)
        ));
    } else {
        out.extend(para(s, 2, &state, PLAIN));
    }
    out
}

/// The core's three sentences: what happened, when it is normal, what to do. A title that only
/// says again what the short title said is not said twice.
fn words_lines(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let mut out = Vec::new();
    let same = unstopped(&f.title).eq_ignore_ascii_case(short_of(f));
    for (label, text) in [
        ("What it is", if same { "" } else { f.title.as_str() }),
        ("Meaning", f.meaning.as_str()),
        ("What to do", f.advice.as_str()),
    ] {
        if !text.is_empty() {
            out.extend(field(s, 2, LABEL, label, &[(text, PLAIN)]));
        }
    }
    out
}

/// A command line from its arguments, each escaped as the contract gives it: an argument that
/// holds a space outside a mark, a double quote, or nothing, is set in double quotes with a quote
/// inside written `\"`, so where one argument ends is always seen. A mark (`\cut{…}`) stays as
/// it is.
fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            let marks = crate::secrets::marks(a);
            let inside = |i: usize| marks.iter().any(|(start, end, ..)| *start <= i && i < *end);
            let spaced = a.char_indices().any(|(i, c)| c == ' ' && !inside(i));
            if a.is_empty() || spaced || a.contains('"') {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Who signed a process's program, as far as the event says.
fn signer(p: &v1::Process) -> Option<String> {
    let mut said: Vec<String> = Vec::new();
    if let Some(id) = &p.signing_id_text {
        said.push(id.clone());
    }
    if let Some(team) = &p.team_id_text {
        said.push(format!("team {team}"));
    }
    if p.platform_binary == Some(true) {
        said.push("part of macOS".to_string());
    }
    (!said.is_empty()).then(|| said.join(", "))
}

/// The pids and users of the processes of a group of events, and their parents' pids, each value
/// said once in the order met: `pid 4242, user 501, parent pid 1` for one event.
fn process_ids(of: &[(Option<&v1::Process>, Option<i64>)]) -> Option<String> {
    let distinct = |values: Vec<i64>| {
        let mut out: Vec<i64> = Vec::new();
        for v in values {
            if !out.contains(&v) {
                out.push(v);
            }
        }
        out
    };
    let said = |name: &str, values: Vec<i64>| -> Option<String> {
        let values = distinct(values);
        let listed = values
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        match values.len() {
            0 => None,
            1 => Some(format!("{name} {listed}")),
            _ => Some(format!("{name}s {listed}")),
        }
    };
    let said: Vec<String> = [
        said(
            "pid",
            of.iter()
                .filter_map(|(p, _)| p.and_then(|p| p.pid))
                .collect(),
        ),
        said(
            "user",
            of.iter()
                .filter_map(|(p, _)| p.and_then(|p| p.user_id))
                .collect(),
        ),
        said(
            "parent pid",
            of.iter().filter_map(|(_, parent)| *parent).collect(),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!said.is_empty()).then(|| said.join(", "))
}

/// An event with what differs between two runs of the same thing cleared: when it happened, and
/// the ids of its processes (pids, pid versions, start times, the parent, the responsible
/// process and the process group).
fn without_ids(e: &v1::Event) -> v1::Event {
    use v1::event::Body;
    let clear = |p: &mut v1::Process| {
        (p.pid, p.pid_version, p.started_at, p.started_nanos) = (None, None, None, None);
    };
    let mut e = e.clone();
    match &mut e.body {
        Some(Body::ProgramStart(p)) => {
            (p.happened_at, p.happened_nanos) = (None, None);
            (p.parent_pid, p.parent, p.responsible, p.process_group_id) = (None, None, None, None);
            p.process.as_mut().map(clear);
            p.instigator.as_mut().map(clear);
        }
        Some(Body::FileEvent(f)) => {
            (f.happened_at, f.happened_nanos) = (None, None);
            f.instigator.as_mut().map(clear);
        }
        None => {}
    }
    e
}

/// The events of a finding in groups, each the events equal but for their times and process
/// ids, in the order the first of each was met. Every event is in exactly one group.
fn grouped(events: &[v1::Event]) -> Vec<Vec<&v1::Event>> {
    let mut keys: Vec<v1::Event> = Vec::new();
    let mut out: Vec<Vec<&v1::Event>> = Vec::new();
    for e in events {
        let key = without_ids(e);
        match keys.iter().position(|k| *k == key) {
            Some(i) => out[i].push(e),
            None => {
                keys.push(key);
                out.push(vec![e]);
            }
        }
    }
    out
}

/// The blocks of a finding's events, a blank line before each, repeated events one block.
fn events_lines(s: &Screen, events: &[v1::Event], now: i64) -> Vec<String> {
    let mut out = Vec::new();
    for group in grouped(events) {
        out.push(String::new());
        out.extend(event_lines(s, &group, now));
    }
    out
}

/// A group of events equal but for their times and process ids, as one block: what they are and
/// when, with how many times and the first and the last when there are more than one, then the
/// fields of the first, one a line, and the process ids of all of them in one line.
fn event_lines(s: &Screen, group: &[&v1::Event], now: i64) -> Vec<String> {
    use v1::event::Body;
    let when = |at: Option<i64>| at.map_or("time not known".to_string(), |at| s.time(at, now));
    let times: Vec<i64> = group
        .iter()
        .filter_map(|e| match &e.body {
            Some(Body::ProgramStart(p)) => p.happened_at,
            Some(Body::FileEvent(f)) => f.happened_at,
            None => None,
        })
        .collect();
    let said_when = match (group.len(), times.iter().min(), times.iter().max()) {
        (1, at, _) => when(at.copied()),
        (n, Some(first), Some(last)) => format!(
            "{n} times, first {}, last {}",
            s.time(*first, now),
            s.time(*last, now)
        ),
        (n, _, _) => format!("{n} times, time not known"),
    };
    let headed = |what: &str| parts_line(s, 4, &[(what, BOLD), (" · ", PLAIN), (&said_when, DIM)]);
    let f = |label: &str, value: &str| field(s, 6, EVENT_LABEL, label, &[(value, PLAIN)]);
    let mut out = Vec::new();
    let Some(e) = group.first() else {
        return out;
    };
    match &e.body {
        Some(Body::ProgramStart(p)) => {
            out.extend(headed("Program start"));
            let process = p.process.as_ref();
            out.extend(f(
                "Program",
                process.map_or("not known", |p| p.executable_text.as_str()),
            ));
            if !p.args_text.is_empty() {
                out.extend(f("Command", &command_line(&p.args_text)));
            }
            if let Some(script) = &p.script_text {
                out.extend(f("Script", script));
            }
            if let Some(folder) = &p.working_directory_text {
                out.extend(f("Folder", folder));
            }
            if let Some(by) = &p.instigator {
                out.extend(f("Started by", &by.executable_text));
            }
            if let Some(signed) = process.and_then(signer) {
                out.extend(f("Signer", &signed));
            }
            let ids: Vec<_> = group
                .iter()
                .filter_map(|e| match &e.body {
                    Some(Body::ProgramStart(p)) => Some((p.process.as_ref(), p.parent_pid)),
                    _ => None,
                })
                .collect();
            if let Some(ids) = process_ids(&ids) {
                out.extend(f("Process", &ids));
            }
        }
        Some(Body::FileEvent(e)) => {
            out.extend(headed("File event"));
            out.extend(f("File", &e.path_text));
            match v1::FileAction::try_from(e.action) {
                Ok(v1::FileAction::Create) => out.extend(f("Action", "created")),
                Ok(v1::FileAction::Rename) => {
                    out.extend(f("Action", "renamed"));
                    out.extend(f("From", e.source_text.as_deref().unwrap_or("not known")));
                }
                _ => out.extend(f("Action", "an action this build does not know")),
            }
            if let Some(by) = &e.instigator {
                out.extend(f("Program", &by.executable_text));
                if let Some(signed) = signer(by) {
                    out.extend(f("Signer", &signed));
                }
            }
            let ids: Vec<_> = group
                .iter()
                .filter_map(|e| match &e.body {
                    Some(Body::FileEvent(f)) => Some((f.instigator.as_ref(), None)),
                    _ => None,
                })
                .collect();
            if let Some(ids) = process_ids(&ids) {
                out.extend(f("Process", &ids));
            }
        }
        None => out.push("    An event of a kind this build does not know.".to_string()),
    }
    out
}

/// The reason the latest occurrence of a watched place could not be read, as its `not_read`
/// journal entry gives it.
fn unread(f: &v1::Finding) -> Option<&str> {
    let latest = f.rests_on.last()?;
    f.rests_on
        .iter()
        .rev()
        .take_while(|b| b.run_id == latest.run_id)
        .find(|b| b.entry == "not_read")
        .and_then(|b| b.new_value_text.as_deref())
}

/// What happened to a watched place, in the words a person reads wherever the core says it: the
/// list, the finding and the pages. A value this build does not know is `changed`, as the schema
/// says.
pub fn change_said(change: i32) -> &'static str {
    match v1::Change::try_from(change) {
        Ok(v1::Change::New) => "added",
        Ok(v1::Change::Gone) => "removed",
        Ok(v1::Change::FirstRead) => "read for the first time",
        Ok(v1::Change::NotRead) => "could not be read",
        _ => "changed",
    }
}

/// The evidence of a watched place: what happened to it in words, and when; how it is watched;
/// that its content is not kept; why it could not be read; the places read for the first time.
fn place_lines(s: &Screen, f: &v1::Finding, p: &v1::PlaceChanged) -> Vec<String> {
    let e = |label: &str, parts: &[(&str, Style)]| field(s, 4, EVIDENCE_LABEL, label, parts);
    let change = v1::Change::try_from(p.change).unwrap_or(v1::Change::Unspecified);
    let said = change_said(p.change);
    let at = format!(", {}", s.time(f.last_seen_at, f.answered_at));
    // What could not be read keeps its word, in red, and is never dim.
    let style = if change == v1::Change::NotRead {
        RED
    } else {
        PLAIN
    };
    let mut out = e("Change", &[(said, style), (&at, PLAIN)]);
    if change == v1::Change::NotRead {
        match unread(f) {
            Some(why) => out.extend(e("Why", &[(why, PLAIN)])),
            None => out.extend(e("Why", &[("the store gives no reason", PLAIN)])),
        }
    }
    if p.presence_only == Some(true) {
        out.extend(e("Watched", &[(crate::watched::PRESENCE_ONLY, PLAIN)]));
    } else if matches!(change, v1::Change::New | v1::Change::Changed) {
        out.extend(e(
            "Content",
            &[(
                "not kept: Immunity Core keeps a checksum of it, so the change itself is not shown here",
                PLAIN,
            )],
        ));
    }
    for b in f.rests_on.iter().filter(|b| b.entry == "place_first_read") {
        let place = b
            .subject_text
            .as_deref()
            .map_or("not known".to_string(), |id| findings::place(id, None));
        let things = b
            .new_value_text
            .as_deref()
            .and_then(|n| n.parse::<u64>().ok())
            .map(|n| {
                format!(
                    ", {}",
                    count(n, "thing runs by itself", "things run by themselves")
                )
            })
            .unwrap_or_default();
        out.extend(e("First read", &[(&place, PLAIN), (&things, PLAIN)]));
    }
    out
}

/// The evidence of a package a project depends on: the package and its releases, where they are
/// declared when that is not the place the finding names, each record, and the release each is
/// fixed in, set apart as the thing to do.
fn package_lines(s: &Screen, f: &v1::Finding, p: &v1::VulnerablePackage) -> Vec<String> {
    let e = |label: &str, parts: &[(&str, Style)]| field(s, 4, EVIDENCE_LABEL, label, parts);
    let mut out = Vec::new();
    if let Some(name) = &p.package_text {
        let mut said = name.clone();
        let versions: Vec<&str> = p.releases.iter().map(|r| r.version_text.as_str()).collect();
        if !versions.is_empty() {
            said = format!("{said} {}", versions.join(", "));
        }
        if let Some(eco) = &p.ecosystem {
            said = format!("{said} ({eco})");
        }
        out.extend(e("Package", &[(&said, PLAIN)]));
    }
    // Where each release is declared, said once: the place the finding names is on its second
    // line already.
    for r in p.releases.iter().filter(|r| r.at_text != f.where_text) {
        let at = if p.releases.len() > 1 {
            format!("{} at {}", r.version_text, r.at_text)
        } else {
            r.at_text.clone()
        };
        out.extend(e("Declared", &[(&at, PLAIN)]));
    }
    for r in &p.records {
        let mut said = r.id_text.clone();
        if !r.label.is_empty() {
            said = format!("{said}, {}", r.label);
        }
        said = format!("{said}, from {}", r.source);
        if !r.aliases_text.is_empty() {
            said = format!("{said}; also {}", r.aliases_text.join(", "));
        }
        out.extend(e("Record", &[(&said, PLAIN)]));
        if r.exploited == Some(true) {
            out.extend(e("", &[("CISA lists it as used in attacks", RED.bold())]));
        }
        if let Some(summary) = &r.summary_text {
            out.extend(e("", &[(summary, PLAIN)]));
        }
        if !r.fixed_text.is_empty() {
            out.extend(e("Fixed in", &[(&r.fixed_text.join(", "), GREEN)]));
        }
    }
    out
}

/// The evidence of a published rule's finding: the rule by its own title with its name dim, its
/// author, its set and its file in the set, how many events it matched, and the events kept,
/// newest first, with how many more there are.
fn published_lines(s: &Screen, f: &v1::Finding, p: &v1::PublishedRuleMatched) -> Vec<String> {
    let e = |label: &str, parts: &[(&str, Style)]| field(s, 4, EVIDENCE_LABEL, label, parts);
    let rule = p.rule.clone().unwrap_or_default();
    let mut out = e(
        "Rule",
        &[(&rule.title_text, PLAIN), ("  ", PLAIN), (&rule.name, DIM)],
    );
    if let Some(author) = &rule.author_text {
        out.extend(e("Author", &[(author, PLAIN)]));
    }
    let licence = crate::sigma::SOURCES
        .iter()
        .find(|s| s.name == rule.source)
        .map_or(p.licence.as_str(), |s| s.licence_name);
    let set = format!("{}, under the {licence}", rule.set);
    out.extend(e("Set", &[(&set, PLAIN)]));
    if !rule.file.is_empty() {
        out.extend(e("File", &[(&crate::known::whole(&rule.file), PLAIN)]));
    }
    let (one, many) = if f.kind == findings::PUBLISHED_FILE_KIND {
        ("file event", "file events")
    } else {
        ("program start", "program starts")
    };
    let matched = match p.matches {
        Some(n) => format!("{} since it was raised", count(n, one, many)),
        None => "the store keeps no count of its matches".to_string(),
    };
    out.extend(e("Matched", &[(&matched, PLAIN)]));
    out.extend(events_lines(s, &p.events, f.answered_at));
    let kept = p.events.len() as u64;
    if let Some(more) = p.matches.filter(|n| *n > kept).map(|n| n - kept) {
        out.push(String::new());
        let said = format!("… {} more, not kept", count(more, "", "").trim_end());
        out.extend(para(s, 4, &said, PLAIN));
    }
    out
}

/// What the finding rests on, by its kind; none for a kind this build does not shape.
fn evidence_lines(s: &Screen, f: &v1::Finding) -> Vec<String> {
    use v1::evidence::Body;
    let e = |label: &str, parts: &[(&str, Style)]| field(s, 4, EVIDENCE_LABEL, label, parts);
    let Some(body) = f.evidence.as_ref().and_then(|e| e.body.as_ref()) else {
        return Vec::new();
    };
    let lines = match body {
        Body::PlaceChanged(p) => place_lines(s, f, p),
        Body::ChangedInPlace(p) => match &p.became_text {
            Some(became) => e("Became", &[(became, PLAIN)]),
            None => e(
                "Files",
                &[(
                    "changed while the version stayed the same: one checksum covers them all, so which file changed is not shown",
                    PLAIN,
                )],
            ),
        },
        Body::IndicatorMatched(p) => e(
            "Matched",
            &[(
                p.indicators_text
                    .as_deref()
                    .unwrap_or("not known: the entry that held it is gone"),
                PLAIN,
            )],
        ),
        Body::DetachedProcess(p) => {
            let mut said: Vec<String> = Vec::new();
            if let Some(pid) = p.pid {
                said.push(format!("pid {pid}"));
            }
            if let Some(start) = p.start_micros {
                said.push(format!(
                    "started {}",
                    s.time(start.div_euclid(1_000_000), f.answered_at)
                ));
            }
            if said.is_empty() {
                said.push("not known".to_string());
            }
            e("Process", &[(&said.join(", "), PLAIN)])
        }
        Body::VulnerablePackage(p) => package_lines(s, f, p),
        Body::PublishedRuleMatched(p) => published_lines(s, f, p),
        Body::VerdictGiven(v) => {
            let mut out = e("About rule", &[(&v.rule, PLAIN)]);
            out.extend(events_lines(s, &v.events, f.answered_at));
            out
        }
    };
    let mut out = vec![head(s, "Evidence")];
    out.extend(lines);
    out
}

/// What a verdict about a match whose line had left the event log says of it, in Immunity Core's words.
const EVENT_GONE: &str = "The line of the match it names was no longer in the event log when it came, so Immunity Core did not read that event again or check that the rule matched it.";

/// A verdict's kind as a person reads it, and its style: suspicious red, harmless green.
fn kind_said(kind: i32) -> (String, Style) {
    match v1::VerdictKind::try_from(kind) {
        Ok(v1::VerdictKind::Suspicious) => ("suspicious".to_string(), RED),
        Ok(v1::VerdictKind::Harmless) => ("harmless".to_string(), GREEN),
        _ => ("of a kind this build does not know".to_string(), PLAIN),
    }
}

/// The verdicts of the response layer: what a verdict is, said first in the core's words, then
/// each verdict listed with its kind in its colour, when it came, its reason and its case as
/// source text under labels. A harmless verdict on an open finding says the finding stays open,
/// and the response layer's own finding about the same thing is named by its id last.
fn verdict_lines(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let Some(v) = &f.verdicts else {
        return Vec::new();
    };
    if v.total == 0 && v.verdict_finding.is_none() {
        return Vec::new();
    }
    let mut out = vec![head(s, "Verdicts")];
    let plural = |n: u32, one: &str, many: &str| count(u64::from(n), one, many);
    let what = "The response layer is another program that runs Immunity Core and looks into what its rules found; a verdict is what it concluded, and it never changes Immunity Core's own finding.";
    let intro = if of_the_response_layer(f) {
        let more = v.total.saturating_sub(1);
        match more {
            0 => format!("{what} It judged this suspicious."),
            n => format!(
                "{what} It judged this suspicious, and sent {} since.",
                plural(n, "more verdict", "more verdicts")
            ),
        }
    } else {
        format!(
            "{what} It sent {} about this finding, {} suspicious.",
            plural(v.total, "verdict", "verdicts"),
            match v.suspicious {
                0 => "none".to_string(),
                n => n.to_string(),
            }
        )
    };
    out.extend(para(s, 4, &intro, PLAIN));
    if (v.listed.len() as u64) < u64::from(v.total) && !v.listed.is_empty() {
        out.extend(para(
            s,
            4,
            &format!(
                "Listed here: the first and the latest {}.",
                v.listed.len() - 1
            ),
            PLAIN,
        ));
    }
    let mut harmless = false;
    for r in &v.listed {
        let verdict = r.verdict.clone().unwrap_or_default();
        let (kind, style) = kind_said(verdict.kind);
        harmless |= verdict.kind == v1::VerdictKind::Harmless as i32;
        let levels = match (verdict.severity, verdict.confidence) {
            (Some(sev), Some(conf)) => format!(
                " · {}, confidence {}",
                words::<v1::Level>(sev),
                words::<v1::Level>(conf)
            ),
            _ => String::new(),
        };
        let at = format!(" · {}", s.time(r.recorded_at, f.answered_at));
        let raised = match r.raised && of_the_response_layer(f) {
            true => " · raised this finding",
            false => "",
        };
        out.extend(parts_line(
            s,
            4,
            &[
                (&kind, style.bold()),
                (&levels, PLAIN),
                (&at, DIM),
                (raised, PLAIN),
            ],
        ));
        // The core's own words come before the response layer's text, never after it.
        if r.event_gone {
            out.extend(para(s, 6, EVENT_GONE, PLAIN));
        }
        out.extend(field(
            s,
            6,
            EVENT_LABEL,
            "Reason",
            &[(&verdict.reason_text, PLAIN)],
        ));
        out.extend(field(
            s,
            6,
            EVENT_LABEL,
            "Case",
            &[(&verdict.case_text, PLAIN)],
        ));
    }
    if harmless && state_of(f) == v1::FindingState::Open {
        out.extend(para(
            s,
            4,
            "A harmless verdict changes nothing here: this finding stays open until you answer it.",
            PLAIN,
        ));
    }
    if let Some(other) = &v.verdict_finding {
        let state = words::<v1::FindingState>(other.state);
        out.extend(para(
            s,
            4,
            &format!(
                "The response layer's own finding about the same thing is {}, {state}.",
                other.id
            ),
            PLAIN,
        ));
    }
    out
}

/// Who gave an answer, as a person reads it.
fn given_by(via: i32) -> &'static str {
    view::given_by(match v1::Via::try_from(via) {
        Ok(v1::Via::App) => findings::Via::App,
        Ok(v1::Via::Agent) => findings::Via::Agent,
        Ok(v1::Via::Command) => findings::Via::Command,
        _ => findings::Via::Unknown,
    })
}

/// The kind of an answer in a word, `expected` with when it ends.
fn answer_said(s: &Screen, a: &v1::Answer, now: i64) -> String {
    match (v1::AnswerKind::try_from(a.given), a.until_at) {
        (Ok(v1::AnswerKind::Expected), Some(until)) => {
            format!("expected until {}", s.time(until, now))
        }
        (Ok(v1::AnswerKind::Expected), None) => "expected".to_string(),
        (Ok(v1::AnswerKind::Seen), _) => "seen".to_string(),
        _ => "an answer this build does not know".to_string(),
    }
}

/// The person's answer: what it is, when and how it was given, its reason as source text, and
/// that it no longer hides the finding when it does not.
fn answer_lines(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let Some(a) = &f.answer else {
        return Vec::new();
    };
    // Who gave it follows when it was given; that it is not known is a clause of its own.
    let by = match v1::Via::try_from(a.via) {
        Ok(v1::Via::App | v1::Via::Agent | v1::Via::Command) => format!(" {}", given_by(a.via)),
        _ => format!(", {}", given_by(a.via)),
    };
    let said = format!(
        "{}, given {}{by}",
        answer_said(s, a, f.answered_at),
        s.time(a.given_at, f.answered_at),
    );
    let mut out = field(s, 2, LABEL, "Your answer", &[(&said, PLAIN)]);
    if let Some(reason) = &a.reason_text {
        out.extend(field(s, 2, LABEL, "Reason", &[(reason, PLAIN)]));
    }
    if !a.in_force {
        out.extend(field(
            s,
            2,
            LABEL,
            "",
            &[("It no longer hides this finding.", PLAIN)],
        ));
    }
    out
}

/// The dim line of what the finding's rule is: the rule (a published rule's is named in the
/// evidence, once), the confidence and the technique.
fn rule_line(s: &Screen, f: &v1::Finding) -> Vec<String> {
    let r = f.finding.clone().unwrap_or_default();
    let published = matches!(
        f.evidence.as_ref().and_then(|e| e.body.as_ref()),
        Some(v1::evidence::Body::PublishedRuleMatched(_))
    );
    let mut parts: Vec<String> = Vec::new();
    if let Some(rule) = r.rule.as_deref().filter(|_| !published) {
        parts.push(format!("rule {rule}"));
    }
    if let Some(c) = r.confidence {
        parts.push(format!("confidence {}", words::<v1::Level>(c)));
    }
    if let Some(t) = &f.technique_text {
        parts.push(format!("ATT&CK {t}"));
    }
    if parts.is_empty() {
        return Vec::new();
    }
    para(s, 2, &parts.join(" · "), DIM)
}

/// The next commands, each after `→` in cyan with what it does beside it, the columns of what
/// they do lined up. On a terminal where a command and what it does do not fit on one line,
/// what it does goes on the line under it; a command is one line whatever the width, never
/// broken or cut, since its first line alone would be another command.
fn next_lines(s: &Screen, steps: &[(String, &str)]) -> Vec<String> {
    let arrows: Vec<String> = steps.iter().map(|(c, _)| format!("→ {c}")).collect();
    let fits = |aw: usize, dw: usize| s.fits().is_none_or(|w| aw + 3 + dw <= w);
    // What they do is lined up over the commands that fit on one line with it.
    let column = arrows
        .iter()
        .zip(steps)
        .map(|(a, (_, d))| (screen::columns(a), screen::columns(d)))
        .filter(|(aw, dw)| fits(*aw, *dw))
        .map(|(aw, _)| aw)
        .max()
        .unwrap_or(0);
    let mut out = Vec::new();
    for (arrow, (_, does)) in arrows.iter().zip(steps) {
        let (aw, dw) = (screen::columns(arrow), screen::columns(does));
        match s.fits() {
            None => out.push(format!("{}   {does}", s.paint(CYAN, arrow))),
            Some(_) if fits(aw, dw) => {
                let at = if fits(column, dw) { column } else { aw };
                out.push(format!(
                    "{}{}{does}",
                    s.paint(CYAN, arrow),
                    " ".repeat(at - aw + 3)
                ));
            }
            Some(_) => {
                out.push(s.paint(CYAN, arrow));
                out.extend(para(s, 2, does, PLAIN));
            }
        }
    }
    out
}

/// The commands that apply to the finding's state: `seen` and `expected` for an open one,
/// `reopen` for an answered one, each also with `--with` for a pair; none for a cleared one.
fn steps(f: &v1::Finding) -> Vec<(String, &'static str)> {
    let id = &crate::text::shell_word_or(f.finding.as_ref().map_or("", |r| r.id.as_str()), "<id>");
    let other = f.verdicts.as_ref().and_then(|v| v.verdict_finding.as_ref());
    let mut out = Vec::new();
    match state_of(f) {
        v1::FindingState::Expected | v1::FindingState::Seen => {
            out.push((
                format!("immunity finding {id} reopen"),
                "takes the answer back",
            ));
            if let Some(o) = other {
                out.push((
                    format!(
                        "immunity finding {id} reopen --with {}",
                        crate::text::shell_word_or(&o.id, "<id>")
                    ),
                    "takes back this answer and the response layer's",
                ));
            }
        }
        v1::FindingState::Cleared => {}
        _ => {
            out.push((
                format!("immunity finding {id} seen --reason <text>"),
                "you looked, it is fine",
            ));
            out.push((
                format!("immunity finding {id} expected --reason <text>"),
                "fine and will recur",
            ));
            if let Some(o) = other {
                out.push((
                    format!(
                        "immunity finding {id} seen --with {} --journal-seq {}",
                        crate::text::shell_word_or(&o.id, "<id>"),
                        f.journal_seq
                    ),
                    "answers this and the response layer's finding together",
                ));
            }
        }
    }
    out
}

/// The parts of a text, each followed by a blank line, the empty ones left out.
fn parts_joined(parts: Vec<Vec<String>>) -> String {
    let mut out: Vec<String> = Vec::new();
    for p in parts.into_iter().filter(|p| !p.is_empty()) {
        if !out.is_empty() {
            out.push(String::new());
        }
        out.extend(p);
    }
    joined(&out)
}

/// `immunity finding <id>` for a person.
pub fn finding(f: &v1::Finding, s: &Screen) -> String {
    let mut top = first_line(s, f);
    top.extend(second_line(s, f));
    let mut answered = verdict_lines(s, f);
    if !answered.is_empty() && f.answer.is_some() {
        answered.push(String::new());
    }
    answered.extend(answer_lines(s, f));
    parts_joined(vec![
        top,
        words_lines(s, f),
        evidence_lines(s, f),
        answered,
        rule_line(s, f),
        next_lines(s, &steps(f)),
    ])
}

/// The answer to `immunity finding <id> seen|expected|reopen` for a person: that it took and what
/// it does, as the finding the answer left says, the reason, and the next command. The finding
/// itself is one command away.
pub fn answered(f: &v1::Finding, s: &Screen) -> String {
    let id = f.finding.as_ref().map_or("", |r| r.id.as_str());
    let with = f.answered_with.as_ref();
    // The others of a group, each named with its state; the pair says more of its other below.
    let group = match with {
        Some(_) => &[][..],
        None => f.answered_together.as_slice(),
    };
    let both = match (with, group) {
        (Some(w), _) | (None, [w]) => format!("{id} and {}", w.id),
        (None, []) => id.to_string(),
        (None, others) => format!("{id} and {} other findings", others.len()),
    };
    let now = f.answered_at;
    let mut body: Vec<String> = Vec::new();
    let headline = match &f.answer {
        None => {
            body.push(match f.answered_together.len() {
                0 => "Its answer is taken back, so it needs a look again.".to_string(),
                1 => "Both answers are taken back, so both need a look again.".to_string(),
                n => format!(
                    "All {} answers are taken back, so each needs a look again.",
                    n + 1
                ),
            });
            format!("✓ Reopened {both}")
        }
        Some(a) => {
            match (v1::AnswerKind::try_from(a.given), a.until_at) {
                (Ok(v1::AnswerKind::Expected), Some(_)) => body.push(
                    "It does not count as needing a look until then. If it is found again, during the mark or after it, it opens again once the mark ends."
                        .to_string(),
                ),
                (Ok(v1::AnswerKind::Seen), _) => body.push(
                    "It no longer needs a look. If it is found again, that is a new finding."
                        .to_string(),
                ),
                _ => {}
            }
            if !a.in_force {
                body.push("This answer does not hide it now.".to_string());
            }
            match v1::Via::try_from(a.via) {
                Ok(v1::Via::Agent) => body.push(
                    "Given through your agent. The app shows this answer and can take it back."
                        .to_string(),
                ),
                Ok(v1::Via::App) => body.push("Given in the app.".to_string()),
                _ => {}
            }
            format!("✓ Marked {both} {}", answer_said(s, a, now))
        }
    };
    if let Some(w) = with {
        let whose = if w
            .rule
            .as_deref()
            .is_some_and(|r| r == crate::verdict::RULE || r.starts_with(crate::verdict::PREFIX))
        {
            "the response layer's finding about the same thing"
        } else {
            "Immunity Core's own finding about the same thing"
        };
        body.push(format!(
            "{} is {whose}, now {}; both were recorded together.",
            w.id,
            words::<v1::FindingState>(w.state)
        ));
    }
    if !group.is_empty() {
        let each: Vec<String> = group
            .iter()
            .map(|w| format!("{} now {}", w.id, words::<v1::FindingState>(w.state)))
            .collect();
        body.push(format!(
            "Answered with it: {}. All were recorded together, each as an answer of its own.",
            each.join(", ")
        ));
    }
    let mut top = para(s, 0, &headline, GREEN.bold());
    for b in &body {
        top.extend(para(s, 2, b, PLAIN));
    }
    if let Some(reason) = f.answer.as_ref().and_then(|a| a.reason_text.as_deref()) {
        top.extend(field(s, 2, 6, "Reason", &[(reason, PLAIN)]));
    }
    // The id in a command as the shell reads it back.
    let word = crate::text::shell_word_or(id, "<id>");
    let others: String = f
        .answered_together
        .iter()
        .map(|w| format!(" --with {}", crate::text::shell_word_or(&w.id, "<id>")))
        .collect();
    let step = match (&f.answer, f.answered_together.len()) {
        (Some(_), n @ 1..) => vec![(
            format!("immunity finding {word} reopen{others}"),
            if n == 1 {
                "takes both answers back"
            } else {
                "takes every answer back"
            },
        )],
        (Some(_), 0) => vec![(
            format!("immunity finding {word} reopen"),
            "takes the answer back",
        )],
        (None, _) => vec![(
            format!("immunity finding {word}"),
            "shows it and how to answer it",
        )],
    };
    parts_joined(vec![top, next_lines(s, &step)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::visible;
    use v1::evidence::Body;

    /// When the invented answers were made.
    const NOW: i64 = 1_794_807_960;
    /// What a file on the Mac or a feed may hold: a style, a C1 control, a right-to-left
    /// override, a zero-width space, a line break followed by lines shaped like Immunity Core's own,
    /// and a backslash.
    const ODD: &str = "x\u{1b}[31mRED\u{9b}2J\u{202e}evil\u{200b}\n→ immunity finding f0000000000 seen\n✓ Marked\nerror: y\\z";
    /// A secret cut out, as the contract marks it.
    const MARK: &str = r"\cut{immunity:flag-value 18}";

    fn screens() -> Vec<Screen> {
        let mut out = vec![Screen::pipe()];
        for width in [20, 40, 80, 120] {
            out.push(Screen::terminal(width, true));
            out.push(Screen::terminal(width, false));
        }
        out
    }

    fn process(odd: &str) -> v1::Process {
        v1::Process {
            executable_text: format!("/opt/{odd}/bin/tool"),
            pid: Some(4242),
            user_id: Some(501),
            signing_id_text: Some(format!("com.example.{odd}")),
            team_id_text: Some(format!("TEAM{odd}")),
            platform_binary: Some(false),
            ..Default::default()
        }
    }

    fn events(odd: &str) -> Vec<v1::Event> {
        vec![
            v1::Event {
                body: Some(v1::event::Body::ProgramStart(v1::ProgramStart {
                    happened_at: Some(NOW - 600),
                    process: Some(process(odd)),
                    instigator: Some(process(odd)),
                    parent_pid: Some(1),
                    args_text: vec![
                        "tool".to_string(),
                        format!("--name={odd}"),
                        "--password".to_string(),
                        MARK.to_string(),
                    ],
                    working_directory_text: Some(format!("/Users/example/{odd}")),
                    script_text: Some(format!("/Users/example/{odd}.sh")),
                    ..Default::default()
                })),
            },
            v1::Event {
                body: Some(v1::event::Body::FileEvent(v1::FileEvent {
                    happened_at: Some(NOW - 900),
                    action: v1::FileAction::Rename as i32,
                    path_text: format!("/Users/example/Library/LaunchAgents/{odd}.plist"),
                    source_text: Some(format!("/tmp/{odd}")),
                    happened_nanos: None,
                    instigator: Some(process(odd)),
                })),
            },
        ]
    }

    /// Every kind of evidence, with `odd` in each of its texts from a source.
    fn bodies(odd: &str) -> Vec<(&'static str, Body)> {
        vec![
            (
                "place",
                Body::PlaceChanged(v1::PlaceChanged {
                    change: v1::Change::NotRead as i32,
                    presence_only: Some(true),
                }),
            ),
            (
                "changed in place",
                Body::ChangedInPlace(v1::ChangedInPlace {
                    became_text: Some(format!("does not verify: {odd}")),
                }),
            ),
            (
                "indicator",
                Body::IndicatorMatched(v1::IndicatorMatched {
                    indicators_text: Some(format!("[url:value = '{odd}']")),
                }),
            ),
            (
                "detached",
                Body::DetachedProcess(v1::DetachedProcess {
                    pid: Some(4242),
                    start_micros: Some((NOW - 7200) * 1_000_000),
                }),
            ),
            (
                "package",
                Body::VulnerablePackage(v1::VulnerablePackage {
                    project_text: Some(format!("checkout:{odd}")),
                    ecosystem: Some("npm".to_string()),
                    package_text: Some(format!("left-{odd}")),
                    releases: vec![v1::PackageRelease {
                        version_text: format!("1.0.{odd}"),
                        at_text: format!("~/dev/{odd}/package-lock.json#node_modules/left-pad"),
                    }],
                    records: vec![v1::PackageRecord {
                        id_text: format!("GHSA-{odd}"),
                        aliases_text: vec![format!("CVE-{odd}")],
                        source: "GitHub Advisory Database".to_string(),
                        label: "high".to_string(),
                        exploited: Some(true),
                        summary_text: Some(format!("Summary {odd}")),
                        fixed_text: vec![format!("1.0.9{odd}")],
                    }],
                }),
            ),
            (
                "published",
                Body::PublishedRuleMatched(v1::PublishedRuleMatched {
                    rule: Some(v1::Rule {
                        name: "sigma:00000000-0000-0000-0000-000000000000".to_string(),
                        title_text: format!("Rule title {odd}"),
                        author_text: Some(format!("Author {odd}")),
                        source: "sigma".to_string(),
                        set: "SigmaHQ's rule set".to_string(),
                        ..Default::default()
                    }),
                    matches: Some(1_234_567),
                    events: events(odd),
                    source: "https://example.invalid".to_string(),
                    licence: "DRL-1.1".to_string(),
                }),
            ),
            (
                "verdict given",
                Body::VerdictGiven(v1::VerdictGiven {
                    rule: "watched.shell-profile".to_string(),
                    events: events(odd),
                }),
            ),
        ]
    }

    /// A finding with this evidence, every text from a source holding `odd`: open, urgent, with
    /// a harmless and a suspicious verdict and the response layer's own finding beside it.
    fn finding_of(body: Body, odd: &str) -> v1::Finding {
        let verdict = |kind: v1::VerdictKind| v1::RecordedVerdict {
            verdict: Some(v1::Verdict {
                kind: kind as i32,
                reason_text: format!("reason {odd}"),
                case_text: format!("case {odd}"),
                severity: (kind == v1::VerdictKind::Suspicious).then_some(v1::Level::High as i32),
                confidence: (kind == v1::VerdictKind::Suspicious)
                    .then_some(v1::Level::Medium as i32),
                ..Default::default()
            }),
            recorded_at: NOW - 60,
            ..Default::default()
        };
        v1::Finding {
            answered_at: NOW,
            finding: Some(v1::FindingRef {
                id: "f1e26d7c725".to_string(),
                rule: Some("autorun.agent-start".to_string()),
                about_text: format!("file:machine:example-host/{odd}"),
                state: v1::FindingState::Open as i32,
                severity: Some(v1::Level::High as i32),
                confidence: Some(v1::Level::Low as i32),
                urgent: true,
            }),
            kind: "agent start".to_string(),
            title: "A project on this Mac now tells your coding agent to run a program."
                .to_string(),
            short_title: "Project tells your agent to run a program".to_string(),
            meaning: "Projects use this to give the agent tools.".to_string(),
            advice: "Read what the file named here starts.".to_string(),
            technique_text: Some(format!("T1543{odd}")),
            where_text: format!("~/dev/design-tokens/{odd}/.mcp.json#/mcpServers/helper"),
            first_seen_at: NOW - 7200,
            last_seen_at: NOW - 7200,
            evidence: Some(v1::Evidence { body: Some(body) }),
            rests_on: vec![
                v1::JournalEntry {
                    seq: 319,
                    run_id: "run-1".to_string(),
                    entry: "not_read".to_string(),
                    subject_text: Some(format!("file:machine:example-host/{odd}")),
                    new_value_text: Some(format!("Permission denied {odd}")),
                    ..Default::default()
                },
                v1::JournalEntry {
                    seq: 320,
                    run_id: "run-1".to_string(),
                    entry: "place_first_read".to_string(),
                    subject_text: Some(format!("checkout:machine:example-host/dev/{odd}")),
                    new_value_text: Some("3".to_string()),
                    ..Default::default()
                },
            ],
            verdicts: Some(v1::Verdicts {
                total: 2,
                suspicious: 1,
                listed: vec![
                    verdict(v1::VerdictKind::Harmless),
                    verdict(v1::VerdictKind::Suspicious),
                ],
                verdict_finding: Some(v1::FindingRef {
                    id: "f7a76b7b86f".to_string(),
                    state: v1::FindingState::Open as i32,
                    ..Default::default()
                }),
            }),
            journal_seq: 57,
            ..Default::default()
        }
    }

    /// The same finding answered: expected, through an agent, with `odd` in its reason.
    fn answered_of(mut f: v1::Finding, odd: &str) -> v1::Finding {
        if let Some(r) = f.finding.as_mut() {
            r.state = v1::FindingState::Expected as i32;
        }
        f.answer = Some(v1::Answer {
            given: v1::AnswerKind::Expected as i32,
            via: v1::Via::Agent as i32,
            given_at: NOW - 60,
            reason_text: Some(format!("reason {odd}")),
            until_at: Some(NOW + 14 * 86_400),
            in_force: true,
            ..Default::default()
        });
        f
    }

    /// Every text this module renders, on a screen: each kind of finding read open and
    /// answered, and the answer to it.
    fn texts(s: &Screen, odd: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (_, body) in bodies(odd) {
            let f = finding_of(body, odd);
            out.push(finding(&f, s));
            let a = answered_of(f, odd);
            out.push(finding(&a, s));
            out.push(answered(&a, s));
        }
        out
    }

    /// Whether every escape byte of a text begins a style of the program's own, each closed on
    /// its line, and nothing hidden reached the screen raw.
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
                if !own(&after[..=end]) {
                    return false;
                }
                opened += if &after[..=end] == "\u{1b}[0m" { -1 } else { 1 };
                rest = &after[end + 1..];
            }
            opened == 0
        }) && !text.contains(['\u{9b}', '\u{202e}', '\u{200b}'])
            && !text.contains("\u{1b}[31mRED")
    }

    #[test]
    fn text_from_a_source_never_styles_never_hides_and_never_starts_a_line_of_immunitys_own() {
        for odd in [ODD.to_string(), crate::known::whole(ODD)] {
            for s in screens() {
                for text in texts(&s, &odd) {
                    assert!(styles_are_the_programs_own(&text), "{s:?}\n{text:?}");
                    for line in text.lines().map(visible) {
                        // A line of Immunity Core's own begins at the first column; one that holds
                        // text from a source never does.
                        if line.contains("RED") || line.contains("evil") || line.contains("y\\") {
                            assert!(line.starts_with(' '), "{s:?}: {line:?}\n{text}");
                        }
                        assert!(
                            !line.starts_with("→ immunity finding f0000000000"),
                            "{text}"
                        );
                        assert!(!line.starts_with("error: y"), "{text}");
                        assert!(line != "✓ Marked", "{text}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_line_break_never_falls_inside_a_written_out_character_or_a_mark() {
        for s in screens().into_iter().filter(|s| s.terminal) {
            for text in texts(&s, ODD) {
                for line in text.lines().map(visible) {
                    // Every escape and every mark that begins on a line ends on it.
                    for (i, _) in line.match_indices("\\u{") {
                        assert!(line[i..].contains('}'), "{s:?}: {line:?}");
                    }
                    for (i, _) in line.match_indices("\\cut{") {
                        assert!(line[i..].starts_with(MARK), "{s:?}: {line:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn off_a_terminal_or_without_colour_there_is_no_escape_byte_and_in_a_pipe_nothing_is_cut_and_times_are_exact()
     {
        for s in [Screen::pipe(), Screen::terminal(80, false)] {
            let all = texts(&s, ODD).concat();
            assert!(!all.contains('\u{1b}'), "{s:?}\n{all}");
            // Marks and words stay without colour.
            for kept in [
                "● high",
                "urgent",
                "→ immunity finding f1e26d7c725",
                "✓ Marked",
            ] {
                assert!(all.contains(kept), "{s:?}: {kept}");
            }
        }
        let pipe = texts(&Screen::pipe(), "odd").concat();
        let shown = "~/dev/design-tokens/odd/.mcp.json#/mcpServers/helper";
        assert!(pipe.contains(shown), "{pipe}");
        assert!(pipe.contains(&view::utc(NOW - 7200)), "{pipe}");
        assert!(!pipe.contains(" ago"), "{pipe}");
        let terminal = texts(&Screen::terminal(40, false), "odd").concat();
        assert!(!terminal.contains(shown), "{terminal}");
        assert!(terminal.contains("2 h ago"), "{terminal}");
    }

    #[test]
    fn no_line_but_a_command_is_wider_than_the_terminal_and_a_command_is_one_line() {
        for s in screens().into_iter().filter(|s| s.terminal) {
            let width = s.width.unwrap();
            for text in texts(&s, ODD) {
                for line in text.lines().map(visible) {
                    // A mark wider than the room a narrow terminal leaves stands alone on its
                    // line, whole, rather than be broken; a command is one line whatever the
                    // width, since its first line alone would be another command.
                    let lone_mark = line.trim() == MARK;
                    let command = line.starts_with("→ immunity ");
                    assert!(
                        screen::columns(&line) <= width || lone_mark || command,
                        "{width}: {line:?}\n{text}"
                    );
                }
                // A command an answer needs is whole on its line, never broken before its flags.
                for line in text.lines().map(visible).filter(|l| l.starts_with("→ ")) {
                    if line.contains(" seen") || line.contains(" expected") {
                        assert!(
                            line.contains("--reason <text>") || line.contains("--journal-seq 57"),
                            "{width}: {line:?}\n{text}"
                        );
                    }
                }
                assert!(text.contains("f1e26d7c725"), "{width}\n{text}");
            }
        }
    }

    /// Where each of `wanted` first begins a line of a text.
    fn order_of(text: &str, wanted: &[&str]) -> Vec<usize> {
        wanted
            .iter()
            .map(|w| {
                text.lines()
                    .position(|l| l.trim_start().starts_with(w))
                    .unwrap_or_else(|| panic!("{w} is missing\n{text}"))
            })
            .collect()
    }

    #[test]
    fn one_finding_reads_what_it_is_then_the_evidence_of_its_kind_then_verdicts_and_the_next_commands()
     {
        let s = Screen::terminal(80, false);
        let evidence: &[(&str, &[&str])] = &[
            ("place", &["Change", "Why", "Watched", "First read"]),
            ("changed in place", &["Became"]),
            ("indicator", &["Matched"]),
            ("detached", &["Process"]),
            (
                "package",
                &[
                    "Package", "Declared", "Record", "CISA", "Summary", "Fixed in",
                ],
            ),
            (
                "published",
                &[
                    "Rule",
                    "Author",
                    "Set",
                    "Matched",
                    "Program start",
                    "Command",
                    "File event",
                    "… 1,234,565 more",
                ],
            ),
            (
                "verdict given",
                &[
                    "About rule",
                    "Program start",
                    "Started by",
                    "File event",
                    "From",
                ],
            ),
        ];
        for ((kind, body), (name, labels)) in bodies("odd").into_iter().zip(evidence) {
            assert_eq!(kind, *name);
            let text = finding(&finding_of(body, "odd"), &s);
            let mut wanted = vec![
                "● high · urgent",
                "~/dev/design-tokens",
                "What it is",
                "Meaning",
                "What to do",
                "Evidence",
            ];
            wanted.extend(labels.iter());
            wanted.extend([
                "Verdicts",
                "harmless · 1 min ago",
                "suspicious · high, confidence medium · 1 min ago",
                "A harmless verdict",
                "The response layer's own finding",
                // A published rule is named once, in the evidence.
                if kind == "published" {
                    "confidence low"
                } else {
                    "rule autorun.agent-start"
                },
                "→ immunity finding f1e26d7c725 seen",
                "→ immunity finding f1e26d7c725 expected",
                "→ immunity finding f1e26d7c725 seen --with f7a76b7b86f --journal-seq 57",
            ]);
            let at = order_of(&text, &wanted);
            assert!(
                at.windows(2).all(|w| w[0] < w[1]),
                "{kind}: {wanted:?} {at:?}\n{text}"
            );
            assert!(
                text.lines().next().unwrap().ends_with("f1e26d7c725"),
                "{text}"
            );
        }
    }

    #[test]
    fn nothing_is_said_that_the_message_does_not_hold() {
        let s = Screen::terminal(80, false);
        // A finding with no evidence, no verdict, no answer, no levels and no technique.
        let bare = v1::Finding {
            answered_at: NOW,
            finding: Some(v1::FindingRef {
                id: "f1e26d7c725".to_string(),
                state: v1::FindingState::Cleared as i32,
                ..Default::default()
            }),
            title: "A title.".to_string(),
            where_text: "~/x".to_string(),
            first_seen_at: NOW - 60,
            last_seen_at: NOW - 60,
            ..Default::default()
        };
        let text = finding(&bare, &s);
        for absent in [
            "Evidence",
            "Verdicts",
            "Your answer",
            "ATT&CK",
            "confidence",
            "rule ",
            "→",
            "What it is",
        ] {
            assert!(!text.contains(absent), "{absent}\n{text}");
        }
        // A severity not known is said so, never as a level, and the title stands in for the
        // short title the message lacks.
        assert!(text.starts_with("● severity not known  A title"), "{text}");
        assert!(text.contains("cleared, last seen 1 min ago"), "{text}");
        // No store vocabulary: no journal entries, no entity ids, no enum words with underscores.
        for (_, body) in bodies("odd") {
            let text = finding(&finding_of(body, "odd"), &s);
            for absent in [
                "journal entr",
                "319",
                "file:machine",
                "checkout:machine",
                "not_read",
                "place_first_read",
            ] {
                assert!(!text.contains(absent), "{absent}\n{text}");
            }
        }
    }

    #[test]
    fn a_place_that_could_not_be_read_keeps_its_word_in_red_and_never_dim() {
        let f = finding_of(bodies("odd").remove(0).1, "odd");
        let text = finding(&f, &Screen::terminal(80, true));
        let line = text
            .lines()
            .find(|l| l.contains("could not be read"))
            .unwrap();
        assert!(
            line.contains("\u{1b}[31mcould not be read\u{1b}[0m"),
            "{line:?}"
        );
        assert!(!line.contains("\u{1b}[2m"), "{line:?}");
        assert!(text.contains("Permission denied odd"), "{text}");
        // Without the reason, that the store gives none is said.
        let mut f = f;
        f.rests_on.clear();
        let text = finding(&f, &Screen::pipe());
        assert!(
            text.contains("Why          the store gives no reason"),
            "{text}"
        );
    }

    #[test]
    fn the_next_commands_are_those_the_state_of_the_finding_allows() {
        let s = Screen::pipe();
        let open = finding_of(bodies("odd").remove(1).1, "odd");
        let commands = |f: &v1::Finding| -> Vec<String> {
            finding(f, &s)
                .lines()
                .filter(|l| l.starts_with('→'))
                .map(|l| l.split("   ").next().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            commands(&open),
            [
                "→ immunity finding f1e26d7c725 seen --reason <text>",
                "→ immunity finding f1e26d7c725 expected --reason <text>",
                "→ immunity finding f1e26d7c725 seen --with f7a76b7b86f --journal-seq 57",
            ]
        );
        let answered = answered_of(open.clone(), "odd");
        assert_eq!(
            commands(&answered),
            [
                "→ immunity finding f1e26d7c725 reopen",
                "→ immunity finding f1e26d7c725 reopen --with f7a76b7b86f",
            ]
        );
        let mut cleared = open;
        cleared.finding.as_mut().unwrap().state = v1::FindingState::Cleared as i32;
        assert!(commands(&cleared).is_empty());
    }

    #[test]
    fn an_answer_says_first_that_it_took_then_what_it_does_and_how_to_take_it_back() {
        let s = Screen::pipe();
        let base = finding_of(bodies("odd").remove(1).1, "odd");
        // Expected, through an agent.
        let text = answered(&answered_of(base.clone(), "odd"), &s);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            format!(
                "✓ Marked f1e26d7c725 expected until {}",
                view::utc(NOW + 14 * 86_400)
            )
        );
        assert!(
            lines[1].starts_with("  It does not count as needing a look until then."),
            "{text}"
        );
        assert!(
            text.contains(
                "  Given through your agent. The app shows this answer and can take it back."
            ),
            "{text}"
        );
        assert!(text.contains("  Reason   reason odd"), "{text}");
        assert!(
            text.ends_with("→ immunity finding f1e26d7c725 reopen   takes the answer back\n"),
            "{text}"
        );
        assert!(
            !text.contains("What it is") && !text.contains("Evidence"),
            "{text}"
        );
        // Seen, from the command line, with no reason.
        let mut seen = answered_of(base.clone(), "odd");
        let a = seen.answer.as_mut().unwrap();
        (a.given, a.via, a.until_at, a.reason_text) = (
            v1::AnswerKind::Seen as i32,
            v1::Via::Command as i32,
            None,
            None,
        );
        let text = answered(&seen, &s);
        assert!(
            text.starts_with(
                "✓ Marked f1e26d7c725 seen\n  It no longer needs a look. If it is found again, that is a new finding.\n\n→"
            ),
            "{text}"
        );
        // Reopened.
        let text = answered(&base, &s);
        assert!(
            text.starts_with(
                "✓ Reopened f1e26d7c725\n  Its answer is taken back, so it needs a look again."
            ),
            "{text}"
        );
        assert!(
            text.contains("→ immunity finding f1e26d7c725   shows it"),
            "{text}"
        );
        // A pair: both named, the other said whose it is, both taken back by one command.
        let mut pair = seen.clone();
        pair.answered_with = Some(v1::FindingRef {
            id: "f7a76b7b86f".to_string(),
            rule: Some(crate::verdict::RULE.to_string()),
            state: v1::FindingState::Seen as i32,
            ..Default::default()
        });
        pair.answered_together = pair.answered_with.iter().cloned().collect();
        let text = answered(&pair, &s);
        assert!(
            text.starts_with("✓ Marked f1e26d7c725 and f7a76b7b86f seen\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "f7a76b7b86f is the response layer's finding about the same thing, now seen"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "→ immunity finding f1e26d7c725 reopen --with f7a76b7b86f   takes both answers back"
            ),
            "{text}"
        );
        assert!(!text.contains("Answered with it"), "{text}");
        let mut reopened = pair;
        reopened.answer = None;
        assert!(
            answered(&reopened, &s)
                .starts_with("✓ Reopened f1e26d7c725 and f7a76b7b86f\n  Both answers")
        );
        // A group: the others counted, each named with its state, all taken back by one command
        // that names each.
        let mut group = seen.clone();
        group.answered_together = ["f7a76b7b86f", "f00000000b2"]
            .map(|id| v1::FindingRef {
                id: id.to_string(),
                rule: Some("watched.git-hook".to_string()),
                state: v1::FindingState::Seen as i32,
                ..Default::default()
            })
            .to_vec();
        let text = answered(&group, &s);
        assert!(
            text.starts_with("✓ Marked f1e26d7c725 and 2 other findings seen\n"),
            "{text}"
        );
        assert!(
            text.contains("Answered with it: f7a76b7b86f now seen, f00000000b2 now seen."),
            "{text}"
        );
        assert!(!text.contains("same thing"), "{text}");
        assert!(
            text.contains(
                "→ immunity finding f1e26d7c725 reopen --with f7a76b7b86f --with f00000000b2   takes every answer back"
            ),
            "{text}"
        );
        // Two of one group read as two, with no pair said.
        group.answered_together.truncate(1);
        let text = answered(&group, &s);
        assert!(
            text.starts_with("✓ Marked f1e26d7c725 and f7a76b7b86f seen\n"),
            "{text}"
        );
        assert!(!text.contains("same thing"), "{text}");
        // An answer that does not hide the finding says so.
        let mut stale = answered_of(base, "odd");
        stale.answer.as_mut().unwrap().in_force = false;
        assert!(answered(&stale, &s).contains("This answer does not hide it now."));
    }

    #[test]
    fn a_command_line_shows_where_each_argument_ends_and_keeps_a_mark_whole() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            command_line(&args(&[
                "osascript",
                "-e",
                "do shell script \"x\"",
                "",
                MARK
            ])),
            format!(r#"osascript -e "do shell script \"x\"" "" {MARK}"#)
        );
    }

    #[test]
    fn the_first_lines_keep_the_level_the_id_and_half_the_place_and_cut_only_the_title_and_the_place()
     {
        let mut f = finding_of(bodies("odd").remove(1).1, "odd");
        // On 50 columns the title is cut, and the level and the id stay whole on line one.
        let text = finding(&f, &Screen::terminal(50, false));
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("● high · urgent  Project tells your…  "),
            "{text}"
        );
        assert!(first.ends_with(" f1e26d7c725"), "{text}");
        assert_eq!(screen::columns(first), 50, "{text}");
        // A state seen once is said once.
        assert!(
            text.contains(
                "open, first seen 2 h ago
"
            ),
            "{text}"
        );
        assert!(!text.contains("last seen"), "{text}");
        // A long state leaves the place less than half the line: the state goes under it, at
        // the right, and the place keeps the whole line.
        f.first_seen_at = NOW - 3 * 86_400;
        f.last_seen_at = NOW - 60;
        let s = Screen::terminal(80, false);
        let text = finding(&f, &s);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[1],
            "  ~/dev/design-tokens/odd/.mcp.json#/mcpServers/helper"
        );
        assert!(lines[2].ends_with(", last seen 1 min ago"), "{text}");
        assert_eq!(screen::columns(lines[2]), 80, "{text}");
        // What they do is lined up over the commands that fit with it on one line.
        let at = |l: &str, does: &str| l.find(does).unwrap_or_else(|| panic!("{does}\n{text}"));
        let seen = lines.iter().find(|l| l.contains("seen --reason")).unwrap();
        let expected = lines
            .iter()
            .find(|l| l.contains("expected --reason"))
            .unwrap();
        assert_eq!(
            at(seen, "you looked"),
            at(expected, "fine and will recur"),
            "{text}"
        );
    }

    #[test]
    fn each_detail_is_said_where_the_message_holds_it_and_only_there() {
        let s = Screen::terminal(200, false);
        let with = |body: Body| finding(&finding_of(body, "odd"), &s);
        // An added place: its content is not kept, and is said not to be; a removed one says
        // nothing of content.
        let place = |change: v1::Change, presence_only| {
            with(Body::PlaceChanged(v1::PlaceChanged {
                change: change as i32,
                presence_only,
            }))
        };
        let added = place(v1::Change::New, Some(false));
        assert!(
            added.contains("    Change       added, 2 h ago\n"),
            "{added}"
        );
        assert!(added.contains("    Content      not kept"), "{added}");
        assert!(!added.contains("    Why "), "{added}");
        let gone = place(v1::Change::Gone, None);
        assert!(
            gone.contains("    Change       removed, 2 h ago\n"),
            "{gone}"
        );
        assert!(
            !gone.contains("Content") && !gone.contains("Watched"),
            "{gone}"
        );
        // A program start: who signed it, its process and its parent.
        let published = with(bodies("odd").remove(5).1);
        for said in [
            "      Signer       com.example.odd, team TEAModd\n",
            "      Process      pid 4242, user 501, parent pid 1\n",
            "      Script       /Users/example/odd.sh\n",
        ] {
            assert!(published.contains(said), "{said}\n{published}");
        }
        assert_eq!(
            signer(&v1::Process {
                platform_binary: Some(true),
                ..Default::default()
            }),
            Some("part of macOS".to_string())
        );
        // A process the message does not name is said not to be known.
        let unknown = with(Body::DetachedProcess(v1::DetachedProcess::default()));
        assert!(
            unknown.contains("    Process      not known\n"),
            "{unknown}"
        );
        // Releases declared in two places name each by its version.
        let mut package = bodies("odd").remove(4).1;
        if let Body::VulnerablePackage(p) = &mut package {
            p.releases.push(v1::PackageRelease {
                version_text: "2.0.0".to_string(),
                at_text: "~/dev/b/package-lock.json".to_string(),
            });
        }
        let package = with(package);
        assert!(
            package.contains("    Declared     2.0.0 at ~/dev/b/package-lock.json\n"),
            "{package}"
        );
        // Verdicts: how many are listed when not all are; a verdict that raised the response
        // layer's finding says so only there; a harmless one keeps an open finding open, and
        // says so only while it is open.
        let mut f = finding_of(bodies("odd").remove(1).1, "odd");
        let v = f.verdicts.as_mut().unwrap();
        v.total = 30;
        v.listed[1].raised = true;
        let text = finding(&f, &s);
        assert!(
            text.contains("    Listed here: the first and the latest 1.\n"),
            "{text}"
        );
        assert!(!text.contains("raised this finding"), "{text}");
        assert!(
            text.replace(
                "
    ", " "
            )
            .contains("It sent 30 verdicts about this finding"),
            "{text}"
        );
        let mut own = f.clone();
        own.finding.as_mut().unwrap().rule = Some(crate::verdict::RULE.to_string());
        let text = finding(&own, &s);
        assert!(text.contains(" · raised this finding\n"), "{text}");
        assert!(
            text.replace(
                "
    ", " "
            )
            .contains("It judged this suspicious, and sent 29 more verdicts since."),
            "{text}"
        );
        let answered_text = finding(&answered_of(f.clone(), "odd"), &s);
        assert!(
            !answered_text.contains("A harmless verdict"),
            "{answered_text}"
        );
        // An answer that no longer hides the finding says so.
        let mut stale = answered_of(f.clone(), "odd");
        stale.answer.as_mut().unwrap().in_force = false;
        assert!(finding(&stale, &s).contains("It no longer hides this finding."));
        assert!(
            !answered_text.contains("no longer hides"),
            "{answered_text}"
        );
        // An answer given in the app says so.
        let mut app = answered_of(f.clone(), "odd");
        app.answer.as_mut().unwrap().via = v1::Via::App as i32;
        assert!(answered(&app, &s).contains("\n  Given in the app.\n"));
        assert!(finding(&app, &s).contains("given 1 min ago in the app"));
        // A verdict about a match whose line had left the log says, in Immunity Core's words and
        // before the response layer's reason, that the event was not read again; only that one.
        let mut late = f.clone();
        late.verdicts.as_mut().unwrap().listed[1].event_gone = true;
        let text = finding(&late, &s);
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.starts_with("      The line of the match it names was no longer"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(lines[at - 1].starts_with("    suspicious"), "{text}");
        assert!(lines[at + 1].starts_with("      Reason"), "{text}");
        assert_eq!(
            text.matches("no longer in the event log").count(),
            1,
            "{text}"
        );
        assert!(!finding(&f, &s).contains("no longer in the event log"));
        // Verdicts the message holds none of are not a section.
        f.verdicts = Some(v1::Verdicts::default());
        assert!(!finding(&f, &s).contains("Verdicts"));
    }

    #[test]
    fn repeated_events_are_one_block_and_no_event_the_message_holds_is_dropped() {
        // Five starts of the same program, apart only in their times and process ids, one with
        // another argument, and two file events by the same program, apart in their times and
        // the program's pid.
        let mut events: Vec<v1::Event> = Vec::new();
        for i in 0..5i64 {
            let mut e = events_of_kind(0, &format!("x{i}"));
            if let Some(v1::event::Body::ProgramStart(p)) = &mut e.body {
                p.happened_at = Some(NOW - 600 - i * 60);
                p.process.as_mut().unwrap().pid = Some(4000 + i);
                p.process.as_mut().unwrap().started_at = Some(NOW - 600 - i * 60);
                p.instigator.as_mut().unwrap().pid = Some(3000 + i);
                p.parent_pid = Some(3000 + i);
                p.parent = Some(v1::Identity {
                    pid: Some(3000 + i),
                    pid_version: Some(i),
                });
            }
            events.push(e);
        }
        let mut other = events_of_kind(0, "y");
        if let Some(v1::event::Body::ProgramStart(p)) = &mut other.body {
            p.args_text.push("--other".to_string());
        }
        events.insert(2, other);
        for (tag, pid) in [("z", 5000), ("zz", 5001)] {
            let mut e = events_of_kind(1, tag);
            if let Some(v1::event::Body::FileEvent(f)) = &mut e.body {
                f.instigator.as_mut().unwrap().pid = Some(pid);
            }
            events.push(e);
        }
        let groups = grouped(&events);
        assert_eq!(
            groups.iter().map(Vec::len).collect::<Vec<_>>(),
            [5, 1, 2],
            "{groups:?}"
        );
        assert_eq!(groups.iter().map(Vec::len).sum::<usize>(), events.len());
        let mut f = finding_of(bodies("odd").remove(5).1, "odd");
        if let Some(Body::PublishedRuleMatched(p)) =
            f.evidence.as_mut().and_then(|e| e.body.as_mut())
        {
            p.events = events.clone();
            p.matches = Some(10);
        }
        let text = finding(&f, &Screen::pipe());
        assert_eq!(text.matches("    Program start · ").count(), 2, "{text}");
        // An event alone keeps its own time.
        assert!(
            text.contains(&format!("    Program start · {}\n", view::utc(NOW - 601))),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "    File event · 2 times, first {}, last {}\n",
                view::utc(NOW - 602),
                view::utc(NOW - 601)
            )),
            "{text}"
        );
        assert!(
            text.contains("      Process      pids 5000, 5001, user 501\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "    Program start · 5 times, first {}, last {}\n",
                view::utc(NOW - 840),
                view::utc(NOW - 600)
            )),
            "{text}"
        );
        assert!(
            text.contains(
                "      Process      pids 4000, 4001, 4002, 4003, 4004, user 501, parent pids 3000, 3001, 3002, 3003, 3004\n"
            ),
            "{text}"
        );
        // The count of what is not kept is still the matches less the events the message holds.
        assert!(text.contains("    … 2 more, not kept\n"), "{text}");
        // A verdict's finding groups its events the same way.
        let verdict = finding(
            &finding_of(
                Body::VerdictGiven(v1::VerdictGiven {
                    rule: "watched.shell-profile".to_string(),
                    events,
                }),
                "odd",
            ),
            &Screen::pipe(),
        );
        assert!(verdict.contains("Program start · 5 times"), "{verdict}");
        // Repeated events of which none has a time say so.
        let mut timeless = events_of_kind(1, "z");
        if let Some(v1::event::Body::FileEvent(f)) = &mut timeless.body {
            f.happened_at = None;
        }
        let both = [timeless.clone(), timeless];
        let lines = event_lines(&Screen::pipe(), &grouped(&both)[0], NOW);
        assert_eq!(lines[0], "    File event · 2 times, time not known");
    }

    /// One invented event: a program start (0) or a file event (1), the same for every `tag`
    /// but in its time.
    fn events_of_kind(kind: usize, tag: &str) -> v1::Event {
        let mut e = events("odd").remove(kind);
        let at = Some(NOW - 600 - tag.len() as i64);
        match &mut e.body {
            Some(v1::event::Body::ProgramStart(p)) => p.happened_at = at,
            Some(v1::event::Body::FileEvent(f)) => f.happened_at = at,
            None => {}
        }
        e
    }
}
