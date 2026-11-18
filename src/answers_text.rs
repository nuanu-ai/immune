//! The text for a person of `immunity project`, `immunity program`, `immunity machine`,
//! `immunity vulnerabilities` and `immunity vulnerability <id>`, rendered from the message alone for a
//! screen (`screen.rs`), in the layout of the core's language for a person
//! (`docs/how-it-works.md`): the answer first; then what needs the person, grouped; then context,
//! one labelled line each; last, the next command after `→`. On a terminal no line is longer than
//! the width; in a pipe nothing is cut, no style is written and times are exact.
//!
//! Nothing here is calmer than the message. A reading made by rule about what was asked (a path
//! inside a unit, spelled otherwise, a folder that holds units, a place under none) is said near
//! the top, in a style that is never dim. A presence of `unknown` with the thing set is said as
//! "cannot tell whether it is there now", never as gone. A count of readings always says how many
//! are not full, and each that is not full is said with its reason. The list of vulnerabilities is
//! calm only when its totals allow it; an answer of `unknown` is never said as not affected.
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`), and is escaped again as it reaches the screen, before it is measured, cut or
//! styled (`screen.rs`). No line begins with text from a source: each begins with Immunity Core's own
//! words, an indent or a mark of Immunity Core's, so a name made to look like `✓ Nothing needs a look`
//! can never stand where Immunity Core's own answer stands.
//!
//! The short title of a finding's rule comes from this build's own catalogue of rules, by the
//! rule's id the message gives, as the status's does.

use crate::contract::v1;
use crate::covered::Found;
use crate::overview::{level, rank, short_title, urgent_cell};
use crate::screen::{self, BOLD, Cell, Column, Cut, DIM, GREEN, PLAIN, RED, Screen, Style, YELLOW};
use crate::view;
use std::collections::BTreeMap;

/// At most this many rules are listed in the findings of an answer; the rest are counted.
const GROUPS_SHOWN: usize = 6;
/// A group's finding ids are listed under it when it holds at most this many.
const IDS_SHOWN: usize = 3;
/// At most this many things of a kind are named in a labelled line; the rest are counted.
const NAMED: usize = 6;
/// At most this many readings that are not full are listed; the rest are counted.
const NOT_FULL_SHOWN: usize = 8;
/// At most this many packages that cannot be told, or places not read, are listed.
const ROWS_SHOWN: usize = 10;
/// The widest an item named in a labelled line is on a terminal, cut in the middle.
const ITEM_WIDTH: usize = 40;

/// `n one` or `n many`, with thousands grouped.
fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
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

/// A text with its first letter in capitals.
fn capital(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// A sentence of Immunity Core's own words that may hold text from a source, at `indent`: escaped,
/// broken into lines that fit, and every line after the first two columns further in, so that no
/// text from a source begins a line.
fn sentence(screen: &Screen, indent: usize, text: &str, style: Style) -> Vec<String> {
    let text = view::shown(text);
    let room = screen.fits().map(|w| w.saturating_sub(indent + 2).max(1));
    screen::wrap(&text, room)
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let at = if i == 0 { indent } else { indent + 2 };
            format!("{}{}", " ".repeat(at), screen.paint(style, l))
        })
        .collect()
}

/// Pieces of Immunity Core's own words in styles of their own, joined by ` · ` at `indent`, broken
/// between pieces where the line would pass the width.
fn pieces(screen: &Screen, indent: usize, parts: &[(String, Style)]) -> Vec<String> {
    let mut out = Vec::new();
    let (mut line, mut used) = (" ".repeat(indent), indent);
    for (i, (text, style)) in parts.iter().enumerate() {
        let text = view::shown(text);
        let w = screen::columns(&text);
        if i > 0 {
            match screen.fits() {
                Some(width) if used + 3 + w > width => {
                    out.push(std::mem::take(&mut line));
                    line = " ".repeat(indent);
                    used = indent;
                }
                _ => {
                    line.push_str(" · ");
                    used += 3;
                }
            }
        }
        line.push_str(&screen.paint(*style, &text));
        used += w;
    }
    out.push(line);
    out
}

/// The first line of an answer about one thing: Immunity Core's word for what kind of thing it is, the
/// thing as asked, bold, cut in the middle on a terminal, and the time at the right, dim; where
/// both do not fit, the time goes on a line of its own below. In a pipe the time follows.
fn first_line(screen: &Screen, label: &str, what: &str, right: &str) -> Vec<String> {
    let what = view::shown(what);
    let right = view::shown(right);
    let fixed = screen::columns(label) + 2;
    let start = |what: &str| {
        format!(
            "{}  {}",
            screen.paint(BOLD, label),
            screen.paint(BOLD, what)
        )
    };
    let Some(width) = screen.fits() else {
        return vec![format!("{}   {}", start(&what), screen.paint(DIM, &right))];
    };
    let r = screen::columns(&right);
    let w = screen::columns(&what);
    if fixed + w.min(16) + 3 + r <= width {
        let cut = screen::cut_middle(&what, width - fixed - 3 - r);
        let pad = width - fixed - screen::columns(&cut) - r;
        return vec![format!(
            "{}{}{}",
            start(&cut),
            " ".repeat(pad),
            screen.paint(DIM, &right)
        )];
    }
    let cut = screen::cut_middle(&what, width.saturating_sub(fixed));
    let right = screen::cut_end(&right, width);
    vec![
        start(&cut),
        format!(
            "{}{}",
            " ".repeat(width.saturating_sub(screen::columns(&right))),
            screen.paint(DIM, &right)
        ),
    ]
}

/// A path as ids name it, as a person reads it: under the home folder as `~/…`.
fn path_shown(rel: &str) -> String {
    match rel {
        "." => "~".to_string(),
        r if r.starts_with('/') => r.to_string(),
        r => format!("~/{r}"),
    }
}

/// A thing as a person names it, from its id: a project's or a file's path, a package's or a
/// program's name, a machine's name. The id is escaped text, and what is made of it stays so.
fn name_of(id: &str) -> String {
    if let Some(rest) = id.strip_prefix("machine:") {
        return rest.to_string();
    }
    if id.starts_with("component:") {
        return view::component_name(id).1.to_string();
    }
    if let Some((_, rel)) = crate::known::place_of(id) {
        return path_shown(rel);
    }
    match id.split_once(':') {
        Some((_, rest)) => rest
            .split_once('/')
            .map_or(rest, |(_, after)| after)
            .to_string(),
        None => id.to_string(),
    }
}

/// Whether a finding needs a look: open, or in a state this build does not know, read as open.
fn is_open(f: &v1::FindingRef) -> bool {
    matches!(
        v1::FindingState::try_from(f.state),
        Ok(v1::FindingState::Open | v1::FindingState::Unspecified) | Err(_)
    )
}

/// Whether a reading was full; a value this build does not know is read as not full.
fn full(c: &v1::Coverage) -> bool {
    c.completeness == v1::Completeness::Full as i32
}

/// Whether a reading is a failure, as its cause says: one that is absent, or that this build
/// does not know, is read as a failure.
fn failed(c: &v1::Coverage) -> bool {
    !matches!(
        c.cause.map(v1::Cause::try_from),
        Some(Ok(v1::Cause::NoReader | v1::Cause::NotGiven))
    )
}

/// The short title of a finding's rule, from this build's catalogue: a published rule's own
/// title cut on a terminal, Immunity Core's short title, or the rule's id when this build does not have
/// the rule.
fn rule_title(screen: &Screen, rule: Option<&str>) -> String {
    let Some(rule) = rule else {
        return "a rule this build does not name".to_string();
    };
    let published = crate::finding_answer::rule_title(rule);
    let own = crate::findings::rules()
        .iter()
        .find(|r| r.id == rule)
        .map(|r| r.words.short)
        .or_else(|| {
            (rule == crate::verdict::RULE || rule.starts_with(crate::verdict::PREFIX))
                .then_some(crate::verdict::WORDS.short)
        });
    short_title(screen, published.as_deref(), own.unwrap_or(""), rule)
}

/// The findings that need a look, by rule as the status groups them: urgent first, then the most
/// severe, then the most findings, then by rule.
struct Group<'a> {
    rule: Option<&'a str>,
    worst: Option<i32>,
    urgent: u64,
    ids: Vec<&'a str>,
}

fn groups(findings: &[v1::FindingRef]) -> Vec<Group<'_>> {
    let mut out: Vec<Group> = Vec::new();
    for f in findings.iter().filter(|f| is_open(f)) {
        let rule = f.rule.as_deref();
        let at = match out.iter().position(|g| g.rule == rule) {
            Some(at) => at,
            None => {
                out.push(Group {
                    rule,
                    worst: f.severity,
                    urgent: 0,
                    ids: Vec::new(),
                });
                out.len() - 1
            }
        };
        let g = &mut out[at];
        if rank(f.severity) > rank(g.worst) {
            g.worst = f.severity;
        }
        g.urgent += u64::from(f.urgent);
        g.ids.push(&f.id);
    }
    out.sort_by(|a, b| {
        (b.urgent > 0)
            .cmp(&(a.urgent > 0))
            .then_with(|| rank(b.worst).cmp(&rank(a.worst)))
            .then_with(|| b.ids.len().cmp(&a.ids.len()))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    out
}

/// The findings that need a look as a table, a row a rule with its ids under it when they are
/// few, and the rules past the first few counted.
fn findings_table(screen: &Screen, groups: &[Group]) -> Vec<String> {
    let shown = &groups[..groups.len().min(GROUPS_SHOWN)];
    let rows: Vec<Vec<Cell>> = shown
        .iter()
        .map(|g| {
            let (lv, style) = level(g.worst);
            vec![
                Cell::new(lv, style),
                Cell::plain(rule_title(screen, g.rule)),
                Cell::new(grouped(g.ids.len() as u64), BOLD),
                Cell::new(urgent_cell(g.ids.len() as u64, g.urgent), RED),
            ]
        })
        .collect();
    let lines = screen.table(
        2,
        &[
            Column::new(Cut::Never),
            Column::new(Cut::End),
            Column::right(Cut::Never),
            Column::new(Cut::Never),
        ],
        None,
        &rows,
    );
    let indent = 2
        + shown
            .iter()
            .map(|g| screen::columns(&level(g.worst).0))
            .max()
            .unwrap_or(0)
        + 2;
    let room = screen.fits().map(|w| w.saturating_sub(indent).max(1));
    let mut out = Vec::new();
    for (line, g) in lines.into_iter().zip(shown) {
        out.push(line);
        if g.ids.len() <= IDS_SHOWN {
            for l in screen::wrap(&g.ids.join(", "), room) {
                out.push(format!("{}{}", " ".repeat(indent), screen.paint(DIM, &l)));
            }
        }
    }
    let rest = &groups[shown.len()..];
    if !rest.is_empty() {
        let more: u64 = rest.iter().map(|g| g.ids.len() as u64).sum();
        let urgent: u64 = rest.iter().map(|g| g.urgent).sum();
        let said = format!(
            "… {} more in {}, {}",
            grouped(more),
            count(rest.len() as u64, "kind", "kinds"),
            match urgent {
                0 => "none urgent".to_string(),
                u => format!("{} urgent", grouped(u)),
            }
        );
        let style = if urgent > 0 { RED } else { PLAIN };
        for l in screen::wrap(&said, room) {
            out.push(format!("{}{}", " ".repeat(indent), screen.paint(style, &l)));
        }
    }
    out
}

/// A predicate as the label of its line, in a person's words.
fn predicate_label(p: &str) -> String {
    match p {
        "has_version" => "Version".to_string(),
        "installed_at" => "Installed at".to_string(),
        "known_as" => "Known as".to_string(),
        "signed_by" => "Signed by".to_string(),
        "watched_as" => "Watched as".to_string(),
        "holds_autorun_point" => "Runs by itself".to_string(),
        "runs_os" => "System".to_string(),
        "runs_kernel" => "Kernel".to_string(),
        "runs_platform" => "Platform".to_string(),
        "runs_image" => "Image".to_string(),
        other => capital(&other.replace('_', " ")),
    }
}

/// Facts that are the store's fingerprints of a thing, which say nothing to a person by
/// themselves: what changed in them is a finding.
const FINGERPRINTS: [&str; 4] = ["has_digest", "has_content", "has_seal", "same_as"];

/// The values of one predicate about a subject, in the order the message gives them.
fn values<'a>(k: &'a v1::Known, subject: &str, predicate: &str) -> Vec<&'a str> {
    k.facts
        .iter()
        .filter(|f| f.subject_text == subject && f.predicate == predicate)
        .map(|f| f.object_text.as_str())
        .collect()
}

/// A list of names: how many, the first few, and how many more.
fn named(items: &[String]) -> String {
    let shown = &items[..items.len().min(NAMED)];
    let more = items.len() - shown.len();
    let mut said = format!("{}: {}", grouped(items.len() as u64), shown.join(", "));
    if more > 0 {
        said.push_str(&format!(" +{}", grouped(more as u64)));
    }
    said
}

/// What the store holds of the thing, one labelled line a kind: where it is, its own facts, the
/// other ids it is known by, the things inside it by kind, and the files they were declared in.
fn known_lines(screen: &Screen, k: &v1::Known, what: &str) -> Vec<(String, String)> {
    let mut lines: Vec<(String, String)> = Vec::new();
    let Some(thing) = &k.thing else {
        return lines;
    };
    let mut own: Vec<&str> = vec![thing.id_text.as_str()];
    own.extend(k.same_as.iter().map(|e| e.id_text.as_str()));
    // What it is, when what was asked names it otherwise: its folder, or its name.
    let name = name_of(&thing.id_text);
    if name != view::shown(what) {
        let label = match crate::known::place_of(&thing.id_text) {
            Some(_) => "Where",
            None => "Name",
        };
        lines.push((label.to_string(), name));
    }
    // The thing's own facts, one line a label, in the order the message gives them: a machine
    // it is part of and one it is located on are both where it is.
    let mut said: Vec<(String, Vec<String>)> = Vec::new();
    for f in k
        .facts
        .iter()
        .filter(|f| own.contains(&f.subject_text.as_str()))
    {
        if FINGERPRINTS.contains(&f.predicate.as_str()) {
            continue;
        }
        let (label, value) = match f.predicate.as_str() {
            "located_on" | "part_of" => ("On".to_string(), name_of(&f.object_text)),
            p => (predicate_label(p), f.object_text.clone()),
        };
        match said.iter_mut().find(|(l, _)| *l == label) {
            Some((_, values)) if values.contains(&value) => {}
            Some((_, values)) => values.push(value),
            None => said.push((label, vec![value])),
        }
    }
    for (label, values) in said {
        lines.push((label, values.join(", ")));
    }
    if !k.same_as.is_empty() {
        let names: Vec<String> = k.same_as.iter().map(|e| name_of(&e.id_text)).collect();
        lines.push(("Also known as".to_string(), names.join(", ")));
    }
    // The things inside it, by kind.
    let mut by_type: BTreeMap<u8, (String, Vec<String>)> = BTreeMap::new();
    let folder = crate::known::place_of(&thing.id_text).map(|(_, rel)| rel);
    for p in &k.parts {
        let (at, label) = match p.r#type.as_str() {
            "checkout" => (0, "Projects".to_string()),
            "component" if k.question == v1::Question::Project as i32 => {
                (1, "Packages".to_string())
            }
            "component" => (1, "Programs".to_string()),
            "file" => (2, "Files".to_string()),
            "container" => (3, "Containers".to_string()),
            other => (4, capital(&format!("{other}s"))),
        };
        let mut item = match (
            p.r#type.as_str(),
            crate::known::place_of(&p.id_text),
            folder,
        ) {
            // A file inside the thing's folder, by its path in it.
            ("file", Some((_, rel)), Some(f)) if rel.starts_with(&format!("{f}/")) => {
                rel[f.len() + 1..].to_string()
            }
            _ => name_of(&p.id_text),
        };
        // A long name is cut in the middle on a terminal; what is said of it stays whole.
        if screen.fits().is_some() {
            item = screen::cut_middle(&view::shown(&item), ITEM_WIDTH);
        }
        if let Some(v) = values(k, &p.id_text, "has_version").first() {
            item = format!("{item} {v}");
        }
        if let Some(w) = values(k, &p.id_text, "watched_as").first() {
            item = format!("{item} ({w})");
        }
        by_type
            .entry(at)
            .or_insert_with(|| (label, Vec::new()))
            .1
            .push(item);
    }
    for (_, (label, items)) in by_type {
        lines.push((label, named(&items)));
    }
    // The files the things inside a project were declared in, such as its lockfiles.
    if let (Some(f), true) = (folder, k.question == v1::Question::Project as i32) {
        let mut files: Vec<String> = Vec::new();
        let parts: Vec<&str> = k.parts.iter().map(|p| p.id_text.as_str()).collect();
        for fact in k
            .facts
            .iter()
            .filter(|x| parts.contains(&x.subject_text.as_str()))
        {
            for a in fact
                .assertions
                .iter()
                .filter(|a| a.basis == v1::Basis::Declared as i32)
            {
                let file = a
                    .source_ref_text
                    .split_once('#')
                    .map_or(a.source_ref_text.as_str(), |(file, _)| file);
                if let Some(rel) = file.strip_prefix(&format!("{f}/"))
                    && !files.iter().any(|x| x == rel)
                {
                    files.push(rel.to_string());
                }
            }
        }
        if !files.is_empty() {
            lines.push(("Declared in".to_string(), files.join(", ")));
        }
    }
    lines
}

/// How much of a reading was read, in words.
fn completeness_said(c: &v1::Coverage) -> &'static str {
    match v1::Completeness::try_from(c.completeness) {
        Ok(v1::Completeness::Partial) => "in part",
        Ok(v1::Completeness::None) => "not read",
        _ => "not full",
    }
}

/// Why a reading was not full, in words: its reason, or its cause, and what this build has no
/// reader for.
fn why_said(c: &v1::Coverage) -> String {
    let mut said = match &c.reason_text {
        Some(r) => r.clone(),
        None => match c.cause.map(v1::Cause::try_from) {
            Some(Ok(v1::Cause::NoReader)) => "this version has no reader for it".to_string(),
            Some(Ok(v1::Cause::NotGiven)) => "it was not given to the reader".to_string(),
            Some(Ok(v1::Cause::Failed)) => "the reader could not read it".to_string(),
            _ => "the core does not say why".to_string(),
        },
    };
    let lacks: Vec<String> = c
        .lacks
        .iter()
        .map(|l| match &l.name_text {
            Some(name) => format!("{} {name}", l.what),
            None => l.what.clone(),
        })
        .collect();
    if !lacks.is_empty() {
        said.push_str(&format!("; no reader for {}", lacks.join(", ")));
    }
    said
}

/// Whether a reading is the one made by rule about what was asked: a path inside a unit,
/// spelled otherwise, a folder that holds units, or a place under none.
fn about_asked(k: &v1::Known, c: &v1::Coverage) -> bool {
    let question = v1::Question::try_from(k.question).unwrap_or(v1::Question::Unspecified);
    c.observed_at.is_none()
        && c.reader == crate::known::RULE_READER
        && c.kind == crate::known::unread_kind(question)
}

/// `immunity project`, `immunity program` and `immunity machine` for a person.
pub fn known(k: &v1::Known, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let question = v1::Question::try_from(k.question).unwrap_or(v1::Question::Unspecified);
    let this_mac = question == v1::Question::Machine && k.asked_text.is_empty();
    let (label, what) = match question {
        v1::Question::Project => ("Project", k.asked_text.clone()),
        v1::Question::Program => ("Program", k.asked_text.clone()),
        v1::Question::Machine if this_mac => (
            "This Mac",
            k.thing
                .as_ref()
                .map_or(String::new(), |t| name_of(&t.id_text)),
        ),
        v1::Question::Machine => ("Machine", k.asked_text.clone()),
        v1::Question::Unspecified => ("Asked", k.asked_text.clone()),
    };
    let right = match k.latest_run_at {
        Some(at) => format!("checked {}", screen.time(at, k.answered_at)),
        None => "no check has finished".to_string(),
    };
    out.extend(first_line(screen, label, &what, &right));
    // The answer: whether it is there, then what needs a look.
    let open: Vec<&v1::FindingRef> = k.findings.iter().filter(|f| is_open(f)).collect();
    let urgent = open.iter().filter(|f| f.urgent).count() as u64;
    // Every reading that is not full, those made by rule among them, keeps the answer from calm.
    let not_full_all = k.coverage.iter().filter(|c| !full(c)).count() as u64;
    let not_full: Vec<&v1::Coverage> = k
        .coverage
        .iter()
        .filter(|c| c.observed_at.is_some() && !full(c))
        .collect();
    let asked: Vec<&v1::Coverage> = k.coverage.iter().filter(|c| about_asked(k, c)).collect();
    let by_rule: Vec<&v1::Coverage> = k
        .coverage
        .iter()
        .filter(|c| c.observed_at.is_none() && !about_asked(k, c))
        .collect();
    let presence = v1::Presence::try_from(k.presence).unwrap_or(v1::Presence::Unspecified);
    let asked_why: Vec<String> = asked.iter().map(|c| why_said(c)).collect();
    match (presence, &k.thing) {
        (v1::Presence::Held, _) => {}
        (v1::Presence::Gone, _) => out.extend(sentence(
            screen,
            0,
            "Gone: it was there, and what was read of it is retracted",
            BOLD,
        )),
        (v1::Presence::Unknown, Some(_)) => out.extend(sentence(
            screen,
            0,
            "Cannot tell whether it is there now: the store knows it, and a reading of it was not full",
            YELLOW.bold(),
        )),
        (v1::Presence::Unknown, None) if !asked_why.is_empty() => out.extend(sentence(
            screen,
            0,
            &format!("Not known: {}", asked_why.join("; ")),
            YELLOW.bold(),
        )),
        (v1::Presence::Unknown, None) => out.extend(sentence(
            screen,
            0,
            "Not known: the store holds nothing by this name or at this place",
            YELLOW.bold(),
        )),
        (v1::Presence::Unspecified, _) => out.extend(sentence(
            screen,
            0,
            "Not known: this build cannot read whether it is there",
            YELLOW.bold(),
        )),
    }
    if !open.is_empty() {
        let need = count(
            open.len() as u64,
            "finding needs a look",
            "findings need a look",
        );
        let urgent = match urgent {
            0 => "none urgent".to_string(),
            u => format!("{} urgent", grouped(u)),
        };
        out.extend(screen.headline(&format!("✗ {need}, {urgent}"), RED.bold(), None));
    } else if presence == v1::Presence::Held && not_full_all == 0 {
        out.extend(screen.headline(
            "✓ Nothing needs a look in what was read",
            GREEN.bold(),
            None,
        ));
    } else if presence == v1::Presence::Held {
        out.extend(screen.headline(
            &format!(
                "Not everything could be read, {} not full; no finding is open in what was read",
                count(not_full_all, "reading", "readings")
            ),
            YELLOW.bold(),
            None,
        ));
    }
    // A path answered for the unit that holds it, or spelled otherwise: said near the top.
    if let (Some(thing), false) = (&k.thing, asked_why.is_empty()) {
        out.extend(sentence(
            screen,
            0,
            &format!(
                "Answered for {}: {}",
                name_of(&thing.id_text),
                asked_why.join("; ")
            ),
            YELLOW,
        ));
    }
    let groups = groups(&k.findings);
    if !groups.is_empty() {
        out.push(String::new());
        out.extend(findings_table(screen, &groups));
    }
    // Context: one labelled line each.
    type Parts = Vec<(String, Style)>;
    let mut lines: Vec<(String, Parts)> = known_lines(screen, k, &what)
        .into_iter()
        .map(|(l, v)| (l, vec![(v, PLAIN)]))
        .collect();
    lines.push((
        "Readings".to_string(),
        vec![
            (grouped(k.coverage.len() as u64), PLAIN),
            match not_full_all {
                0 => (", all full".to_string(), PLAIN),
                n => (format!(", {} not full", grouped(n)), YELLOW),
            },
        ],
    ));
    let readings_at = lines.len();
    for (i, c) in by_rule.iter().enumerate() {
        let label = if i == 0 { "Not judged" } else { "" };
        let style = if failed(c) { RED } else { YELLOW };
        lines.push((
            label.to_string(),
            vec![(format!("{}: {}", c.kind, why_said(c)), style)],
        ));
    }
    let mut states: BTreeMap<String, u64> = BTreeMap::new();
    for f in k.findings.iter().filter(|f| !is_open(f)) {
        *states
            .entry(crate::text::word::<v1::FindingState>(f.state))
            .or_default() += 1;
    }
    if !states.is_empty() {
        let said: Vec<String> = states
            .iter()
            .map(|(s, n)| format!("{} {s}", grouped(*n)))
            .collect();
        lines.push(("Not open".to_string(), vec![(said.join(", "), PLAIN)]));
    }
    let width = lines
        .iter()
        .map(|(l, _)| screen::columns(l))
        .max()
        .unwrap_or(0);
    out.push(String::new());
    for (i, (label, parts)) in lines.iter().enumerate() {
        let parts: Vec<(&str, Style)> = parts.iter().map(|(t, s)| (t.as_str(), *s)).collect();
        out.extend(screen.labelled_parts(2, width, label, &parts, None, 0));
        if i + 1 == readings_at {
            out.extend(not_full_lines(screen, k, &not_full));
        }
    }
    if let Some(first) = groups.first().and_then(|g| g.ids.first()) {
        out.push(String::new());
        out.push(screen.next(
            &format!(
                "immunity finding {}",
                crate::text::shell_word_or(first, "<id>")
            ),
            "shows one and how to answer it",
        ));
    }
    joined(&out)
}

/// Each reading that is not full, under the count of readings: its reader, what it looked for,
/// where when that is not the thing itself, how much was read and why. A failure is red, and
/// nothing here is dim.
fn not_full_lines(screen: &Screen, k: &v1::Known, not_full: &[&v1::Coverage]) -> Vec<String> {
    let shown = &not_full[..not_full.len().min(NOT_FULL_SHOWN)];
    let width = shown
        .iter()
        .map(|c| screen::columns(&view::shown(&c.reader)))
        .max()
        .unwrap_or(0);
    let mut own: Vec<&str> = k.thing.iter().map(|t| t.id_text.as_str()).collect();
    own.extend(k.same_as.iter().map(|e| e.id_text.as_str()));
    let mut out = Vec::new();
    let mut cut = false;
    for c in shown {
        let on = if own.contains(&c.scope_text.as_str()) {
            String::new()
        } else {
            format!(" on {}", name_of(&c.scope_text))
        };
        let why = view::shown(&why_said(c));
        let said = view::shown(&format!("{}{on}: {}, ", c.kind, completeness_said(c)));
        // On a terminal a reading takes two lines at most: the first clause of its reason, the
        // rest cut with the mark, escaped before it is cut. The pipe form keeps it whole.
        let said = match screen.fits() {
            Some(screen_width) => {
                let room = screen_width.saturating_sub(4 + width + 3);
                let first = first_clause(&why);
                let clause = if first.len() < why.len() {
                    format!("{first}…")
                } else {
                    why.clone()
                };
                // Room for two lines, less what breaking at spaces may leave unused.
                let room = (2 * room).saturating_sub(room / 4).max(1);
                screen::cut_end(&format!("{said}{clause}"), room)
            }
            None => format!("{said}{why}"),
        };
        cut |= said.ends_with('…');
        let style = if failed(c) { RED } else { YELLOW };
        out.extend(screen.labelled(4, width, &c.reader, &said, style, None, 0));
    }
    let more = not_full.len() - shown.len();
    if more > 0 {
        out.extend(sentence(
            screen,
            4,
            &format!("… {} more not full", grouped(more as u64)),
            YELLOW,
        ));
    }
    if cut {
        out.extend(sentence(
            screen,
            4,
            "Each reason is whole with --json, or in a pipe.",
            PLAIN,
        ));
    }
    out
}

/// The first clause of a reason: up to its first `;`, `:` or full stop followed by a space.
fn first_clause(why: &str) -> &str {
    // A colon introduces what the clause is about, such as the file not read, so it does not end it.
    ["; ", ". "]
        .iter()
        .filter_map(|p| why.find(p))
        .min()
        .map_or(why, |at| &why[..at])
}

/// A record's label as a person reads it, and its style: malicious and critical red, high
/// yellow, the others plain.
fn label_style(label: &str) -> Style {
    match label {
        "malicious" | "critical" => RED,
        "high" => YELLOW,
        _ => PLAIN,
    }
}

/// Why it cannot be told whether a record affects a package, in words.
fn reason_said(reason: &str) -> String {
    match reason {
        crate::vulnerabilities::PLACE_NOT_READ => "its lockfiles were not all read".to_string(),
        crate::vulnerabilities::FEED_NOT_READ => {
            "the vulnerability data is not current".to_string()
        }
        crate::vulnerabilities::NOT_COMPARABLE => "its version cannot be compared".to_string(),
        crate::vulnerabilities::NOT_FROM_REGISTRY => {
            "it does not come from the registry".to_string()
        }
        crate::vulnerabilities::NOT_COVERED => "the data does not cover this version".to_string(),
        crate::vulnerabilities::NO_MATCHER => {
            "no vulnerability data is read for its ecosystem".to_string()
        }
        other => other.replace('_', " "),
    }
}

/// Why a project's lockfiles of an ecosystem were not all read, in words.
fn unread_said(p: &v1::UnreadPlace) -> String {
    let word = match p.lockfiles.as_str() {
        "partial" => "some lockfiles not read",
        "not_read" => "lockfiles not read",
        "no_reader" => "lockfiles of a kind this version does not read",
        "none_found" => return "no lockfile this version reads".to_string(),
        other => return other.replace('_', " "),
    };
    match &p.why_text {
        Some(why) => format!("{word}: {why}"),
        None => word.to_string(),
    }
}

/// The releases a record is fixed in, as the thing to do, green: on a terminal the first and how
/// many more, in a pipe every one.
fn fix_cell(screen: &Screen, fixed: &[String]) -> Cell {
    match fixed {
        [] => Cell::plain("no fix named"),
        [first, rest @ ..] if screen.fits().is_some() && !rest.is_empty() => Cell::new(
            format!("fixed in {first} +{}", grouped(rest.len() as u64)),
            GREEN,
        ),
        all => Cell::new(format!("fixed in {}", all.join(", ")), GREEN),
    }
}

/// `immunity vulnerabilities` for a person.
pub fn vulnerabilities(m: &v1::Vulnerabilities, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let Some(t) = &m.totals else {
        // Nothing was counted: why, in the core's words, and never a 0. No store is said in the
        // one wording every command gives it, with what makes one.
        let why = m
            .not_computed
            .first()
            .map_or(crate::store::NO_STORE_REASON, |n| n.reason.as_str());
        let no_store = why == crate::store::NO_STORE_REASON;
        if no_store {
            out.extend(crate::text::no_store(screen));
        } else {
            out.extend(sentence(
                screen,
                0,
                &format!("Nothing is known yet: {why}"),
                YELLOW.bold(),
            ));
        }
        if !m.declared_note.is_empty() {
            out.push(String::new());
            out.extend(screen.labelled(2, 10, "Speaks for", &m.declared_note, PLAIN, None, 0));
        }
        if !no_store {
            out.push(String::new());
            out.push(screen.next("immunity run", "checks this Mac now"));
        }
        return joined(&out);
    };
    let items: &[v1::AffectedPackage] = m.affected.as_ref().map_or(&[], |a| &a.items);
    let total = m.affected.as_ref().map_or(0, |a| a.total);
    let exploited =
        |a: &v1::AffectedPackage| a.record.as_ref().and_then(|r| r.exploited) == Some(true);
    let mut used: Vec<&str> = items
        .iter()
        .filter(|a| exploited(a))
        .filter_map(|a| a.record.as_ref().map(|r| r.id_text.as_str()))
        .collect();
    used.sort_unstable();
    used.dedup();
    // What is said of the projects as a whole speaks only for those found while not all were.
    let (found, scope) = Found::of(t.projects_found.as_ref());
    // Calm only when a project was compared and nothing at all could not be told.
    let calm = t.projects_compared > 0
        && t.projects_not_read == 0
        && t.projects_without_lockfile == 0
        && t.unknown_packages == 0;
    let (said, style) = if t.affected_records > 0 {
        let mut said = format!(
            "✗ {} {} {}",
            count(
                t.affected_records,
                "known vulnerability",
                "known vulnerabilities"
            ),
            if t.affected_records == 1 {
                "affects"
            } else {
                "affect"
            },
            count(t.affected_projects, "project", "projects")
        );
        if !used.is_empty() {
            let of = if (items.len() as u64) < total {
                " of those listed"
            } else {
                ""
            };
            said.push_str(&format!(
                ", {}{of} used in attacks",
                grouped(used.len() as u64)
            ));
        }
        (said, RED.bold())
    } else if calm {
        match found {
            Found::All => (
                "✓ No known vulnerability affects your projects".to_string(),
                GREEN.bold(),
            ),
            // Every project found was compared: they are the ones counted.
            Found::NotEntered => (
                format!(
                    "✓ No known vulnerability affects the {} found",
                    count(t.projects_compared, "project", "projects")
                ),
                GREEN.bold(),
            ),
            Found::LookedAt => (
                "No known vulnerability affects the projects that were looked at".to_string(),
                BOLD,
            ),
        }
    } else if t.projects_compared == 0 {
        (
            "No project's lockfiles were compared in full with current vulnerability data, so none is known to be affected or not".to_string(),
            YELLOW.bold(),
        )
    } else {
        (
            "None of the known vulnerabilities affects what could be compared; the rest cannot be told".to_string(),
            YELLOW.bold(),
        )
    };
    let read_at = t
        .feeds
        .iter()
        .filter(|f| f.matched)
        .filter_map(|f| f.read_at)
        .max();
    let right = read_at.map(|at| format!("data read {}", screen.time(at, m.answered_at)));
    out.extend(screen.headline(&said, style, right.as_deref()));
    // The opening counts: what was compared, and what was not, always.
    let warn = |n: u64| if n > 0 { YELLOW } else { PLAIN };
    let mut counts = vec![
        (
            format!(
                "{} compared",
                count(t.projects_compared, "project", "projects")
            ),
            PLAIN,
        ),
        (
            format!("{} not wholly read", grouped(t.projects_not_read)),
            warn(t.projects_not_read),
        ),
        (
            format!("{} with no lockfile", grouped(t.projects_without_lockfile)),
            warn(t.projects_without_lockfile),
        ),
    ];
    if t.unknown_packages > 0 {
        counts.push((
            format!(
                "{} cannot be told",
                count(t.unknown_packages, "package", "packages")
            ),
            YELLOW,
        ));
    }
    out.extend(pieces(screen, 2, &counts));
    if let Some(line) = &scope {
        out.extend(sentence(screen, 2, line, PLAIN));
    }
    for f in &t.feeds {
        if let Some(why) = &f.not_current_why {
            out.extend(sentence(
                screen,
                2,
                &format!("The {} data is not current: {why}", f.ecosystem),
                YELLOW,
            ));
        }
    }
    // What affects them: used in attacks first, then the others.
    let (attacks, other): (Vec<&v1::AffectedPackage>, Vec<&v1::AffectedPackage>) =
        items.iter().partition(|a| exploited(a));
    let heads = [
        ("Used in attacks", RED.bold()),
        if attacks.is_empty() {
            ("Affected", RED.bold())
        } else {
            ("Other", BOLD)
        },
    ];
    let cells: Vec<Vec<Cell>> = attacks
        .iter()
        .chain(&other)
        .map(|a| {
            let r = a.record.clone().unwrap_or_default();
            let versions: Vec<&str> = a.releases.iter().map(|x| x.version_text.as_str()).collect();
            vec![
                Cell::new(r.label.clone(), label_style(&r.label)),
                Cell::plain(r.id_text.clone()),
                Cell::plain(format!("{} {}", a.package_text, versions.join(", "))),
                Cell::plain(a.project_text.clone()),
                fix_cell(screen, &r.fixed_text),
            ]
        })
        .collect();
    // One table, so the columns of both groups line up: a row a line where every row fits whole;
    // else a row takes two lines, the level, the id and the package on the first, the project
    // and the fix on the second under the package. The level and the id are never cut.
    let width_of = |i: usize| {
        cells
            .iter()
            .map(|r| screen::columns(&view::shown(&r[i].text)))
            .max()
            .unwrap_or(0)
    };
    let whole = 4 + (0..5).map(width_of).sum::<usize>() + 2 * 4;
    let lines: Vec<String> = if screen.fits().is_none_or(|w| whole <= w) {
        screen.table(
            4,
            &[
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End),
                Column::new(Cut::Middle),
                Column::new(Cut::End),
            ],
            None,
            &cells,
        )
    } else {
        let firsts: Vec<Vec<Cell>> = cells.iter().map(|r| r[..3].to_vec()).collect();
        let seconds: Vec<Vec<Cell>> = cells.iter().map(|r| r[3..].to_vec()).collect();
        let under = 4 + width_of(0) + 2 + width_of(1) + 2;
        let firsts = screen.table(
            4,
            &[
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End),
            ],
            None,
            &firsts,
        );
        let seconds = screen.table(
            under,
            &[Column::new(Cut::Middle), Column::new(Cut::End)],
            None,
            &seconds,
        );
        firsts
            .into_iter()
            .zip(seconds)
            .flat_map(|(a, b)| [a, b])
            .collect()
    };
    // A row's lines, one or two each.
    let per_row = if cells.is_empty() {
        1
    } else {
        lines.len() / cells.len()
    };
    let lines = &lines[..];
    let (first, rest) = lines.split_at(attacks.len() * per_row);
    for ((head, style), rows) in heads.iter().zip([first, rest]) {
        if rows.is_empty() {
            continue;
        }
        out.push(String::new());
        out.push(format!("  {}", screen.paint(*style, head)));
        out.extend(rows.iter().cloned());
    }
    if (items.len() as u64) < total {
        out.extend(sentence(
            screen,
            4,
            &format!(
                "… {} more not listed here",
                grouped(total - items.len() as u64)
            ),
            PLAIN,
        ));
    }
    // The packages for which it cannot be told, by name, and why.
    if let Some(u) = m.unknown.as_ref().filter(|u| u.total > 0) {
        out.push(String::new());
        out.push(format!(
            "  {}  {}",
            screen.paint(YELLOW.bold(), "Cannot be told"),
            count(u.total, "package", "packages")
        ));
        let rows: Vec<Vec<Cell>> = u
            .items
            .iter()
            .take(ROWS_SHOWN)
            .map(|p| {
                vec![
                    Cell::plain(p.project_text.clone()),
                    Cell::plain(p.package_text.clone()),
                    Cell::new(p.ecosystem.clone(), DIM),
                    Cell::new(reason_said(&p.reason), YELLOW),
                ]
            })
            .collect();
        out.extend(screen.table(
            4,
            &[
                Column::new(Cut::Middle).giving(1),
                Column::new(Cut::End),
                Column::new(Cut::Never),
                Column::new(Cut::End),
            ],
            None,
            &rows,
        ));
        let left = u.total.saturating_sub(rows.len() as u64);
        if left > 0 {
            let reasons: Vec<String> = t
                .unknown_packages_by_reason
                .iter()
                .map(|c| format!("{} {}", reason_said(&c.name), grouped(c.count)))
                .collect();
            out.extend(sentence(
                screen,
                4,
                &format!(
                    "… {} more not listed here; all of them by reason: {}",
                    grouped(left),
                    reasons.join(", ")
                ),
                YELLOW,
            ));
        }
    }
    // The projects whose lockfiles were not all read, and those with none this version reads.
    if let Some(u) = m.unread.as_ref().filter(|u| u.total > 0) {
        out.push(String::new());
        out.push(format!(
            "  {}  {}",
            screen.paint(YELLOW.bold(), "Not read"),
            count(u.total, "place", "places")
        ));
        let rows: Vec<Vec<Cell>> = u
            .items
            .iter()
            .take(ROWS_SHOWN)
            .map(|p| {
                let ecosystem = if p.ecosystem == "any" {
                    String::new()
                } else {
                    p.ecosystem.clone()
                };
                vec![
                    Cell::plain(p.project_text.clone()),
                    Cell::new(ecosystem, DIM),
                    Cell::new(unread_said(p), YELLOW),
                ]
            })
            .collect();
        out.extend(screen.table(
            4,
            &[
                Column::new(Cut::Middle).giving(1),
                Column::new(Cut::Never),
                Column::new(Cut::End),
            ],
            None,
            &rows,
        ));
        let left = u.total.saturating_sub(rows.len() as u64);
        if left > 0 {
            out.extend(sentence(
                screen,
                4,
                &format!("… {} more not listed here", grouped(left)),
                YELLOW,
            ));
        }
    }
    out.push(String::new());
    out.extend(screen.labelled(2, 10, "Speaks for", &m.declared_note, PLAIN, None, 0));
    if let Some(r) = attacks
        .iter()
        .chain(&other)
        .next()
        .and_then(|a| a.record.as_ref())
    {
        out.push(String::new());
        out.push(screen.next(
            &format!(
                "immunity vulnerability {}",
                crate::text::shell_word_or(&r.id_text, "<id>")
            ),
            "one record in every project",
        ));
    }
    joined(&out)
}

/// What a record says of one project, as one class: affected, cannot be told, not affected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Said {
    Affected,
    Untold,
    NotAffected,
}

/// A package's answer as a class; a value this build does not know cannot be told.
fn said_of(answer: Option<i32>) -> Said {
    match answer.map(v1::PackageAnswer::try_from) {
        Some(Ok(v1::PackageAnswer::Affected)) => Said::Affected,
        Some(Ok(v1::PackageAnswer::NotAffected)) => Said::NotAffected,
        _ => Said::Untold,
    }
}

/// Why a record does not affect a package, in words: by OpenVEX's justification, and how sure.
fn not_affected_said(openvex: Option<&str>, certainty: Option<&str>) -> String {
    match (certainty, openvex) {
        (Some("no_signs"), _) => "no signs: no record names it".to_string(),
        (_, Some("fixed")) => "at or above a fix".to_string(),
        (_, Some("vulnerable_code_not_present")) => "not in the affected range".to_string(),
        (_, Some("component_not_present")) => "does not use the package".to_string(),
        (_, Some(other)) => other.replace('_', " "),
        (_, None) => "not affected".to_string(),
    }
}

/// One row of a record's answer: the project, what it declares, the answer in words, and when it
/// is affected the releases it is fixed in.
struct Row {
    said: Said,
    project: String,
    what: String,
    answer: String,
    fixed: Vec<String>,
}

/// An answer in words, for what is not affected: why not, or why it cannot be told.
fn answer_said(
    said: Said,
    openvex: Option<&str>,
    certainty: Option<&str>,
    reason: Option<&str>,
) -> String {
    match said {
        Said::Affected => String::new(),
        Said::NotAffected => not_affected_said(openvex, certainty),
        Said::Untold => reason.map_or("cannot be told".to_string(), reason_said),
    }
}

/// The rows of the answers in each place: one a package the record names, or one for the place,
/// with the ecosystem, when it names none of its packages.
fn rows_of(answers: &[v1::PlaceAnswer]) -> Vec<Row> {
    let mut out = Vec::new();
    for a in answers {
        if a.packages.is_empty() {
            let said = said_of(a.answer);
            out.push(Row {
                said,
                project: a.project_text.clone(),
                what: a.ecosystem.clone(),
                answer: answer_said(
                    said,
                    a.openvex.as_deref(),
                    a.certainty.as_deref(),
                    a.reason.as_deref(),
                ),
                fixed: Vec::new(),
            });
        }
        for p in &a.packages {
            let said = said_of(Some(p.answer));
            let versions: Vec<&str> = p
                .entries
                .iter()
                .filter(|e| said != Said::Affected || e.affected)
                .filter_map(|e| e.version_text.as_deref())
                .collect();
            out.push(Row {
                said,
                project: a.project_text.clone(),
                what: format!("{} {}", p.package_text, versions.join(", "))
                    .trim_end()
                    .to_string(),
                answer: answer_said(
                    said,
                    p.openvex.as_deref(),
                    p.certainty.as_deref(),
                    p.reason.as_deref(),
                ),
                fixed: p.fixed_text.clone(),
            });
        }
    }
    out
}

/// The rows grouped so that what cannot be told is never below what is not affected: affected,
/// then cannot be told, then not affected, each under its heading, in one table so the columns
/// line up.
fn answer_rows(screen: &Screen, rows: &[Row]) -> Vec<String> {
    let groups = [
        (Said::Affected, "Affected", RED.bold()),
        (Said::Untold, "Cannot be told", YELLOW.bold()),
        (Said::NotAffected, "Not affected", BOLD),
    ];
    let ordered: Vec<&Row> = groups
        .iter()
        .flat_map(|(said, ..)| rows.iter().filter(move |r| r.said == *said))
        .collect();
    let cells: Vec<Vec<Cell>> = ordered
        .iter()
        .map(|r| {
            vec![
                Cell::plain(r.project.clone()),
                Cell::plain(r.what.clone()),
                match r.said {
                    Said::Affected => fix_cell(screen, &r.fixed),
                    Said::Untold => Cell::new(r.answer.clone(), YELLOW),
                    Said::NotAffected => Cell::plain(r.answer.clone()),
                },
            ]
        })
        .collect();
    let mut lines = screen
        .table(
            6,
            &[
                Column::new(Cut::Middle).giving(1),
                Column::new(Cut::End).giving(1),
                Column::new(Cut::End),
            ],
            None,
            &cells,
        )
        .into_iter();
    let mut out = Vec::new();
    for (said, head, style) in groups {
        let n = rows.iter().filter(|r| r.said == said).count();
        if n == 0 {
            continue;
        }
        out.push(format!("    {}", screen.paint(style, head)));
        out.extend(lines.by_ref().take(n));
    }
    out
}

/// `immunity vulnerability <id>` for a person.
pub fn vulnerability(m: &v1::Vulnerability, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let (attacks, attacks_style) = match m.in_catalogue {
        Some(true) => ("used in attacks", RED.bold()),
        Some(false) => ("not on the list of those used in attacks", PLAIN),
        None => (
            "whether it is used in attacks is not known: the list was not read",
            YELLOW,
        ),
    };
    let id = view::shown(&m.id_text);
    match screen.fits() {
        Some(width) => {
            let line = format!("Vulnerability {id}   {attacks}");
            if screen::columns(&line) <= width {
                out.push(format!(
                    "{} {}   {}",
                    screen.paint(BOLD, "Vulnerability"),
                    screen.paint(BOLD, &id),
                    screen.paint(attacks_style, attacks)
                ));
            } else {
                out.push(format!(
                    "{} {}",
                    screen.paint(BOLD, "Vulnerability"),
                    screen.paint(BOLD, &id)
                ));
                out.extend(sentence(screen, 2, attacks, attacks_style));
            }
        }
        None => out.push(format!("Vulnerability {id}   {attacks}")),
    }
    // Every answer, those from the place for an id no record names and those of each record
    // that is answered.
    let top = rows_of(&m.answers);
    let records: Vec<(&v1::RecordAnswers, Vec<Row>)> = m
        .records
        .iter()
        .map(|r| {
            let rows = if r.answered {
                rows_of(&r.answers)
            } else {
                Vec::new()
            };
            (r, rows)
        })
        .collect();
    // A project is as bad as its worst answer: affected, then cannot be told.
    let mut worst: BTreeMap<&str, Said> = BTreeMap::new();
    for r in top.iter().chain(records.iter().flat_map(|(_, rows)| rows)) {
        let e = worst.entry(&r.project).or_insert(r.said);
        *e = (*e).min(r.said);
    }
    let of = |s: Said| worst.values().filter(|w| **w == s).count() as u64;
    let (found, scope) = Found::of(m.projects_found.as_ref());
    let (affected, untold, not_affected) =
        (of(Said::Affected), of(Said::Untold), of(Said::NotAffected));
    match m.data.map(v1::RecordData::try_from) {
        // No store, in the one wording every command gives it, with what makes one.
        None => out.extend(crate::text::no_store(screen)),
        Some(Ok(v1::RecordData::Held)) => {
            let (said, style) = if affected > 0 {
                let mut said = format!("✗ Affects {}", count(affected, "project", "projects"));
                if untold > 0 {
                    said.push_str(&format!("; cannot be told for {}", grouped(untold)));
                }
                (said, RED.bold())
            } else if untold > 0 {
                let mut said = format!(
                    "Cannot be told for {}",
                    count(untold, "project", "projects")
                );
                if not_affected > 0 {
                    said.push_str(&format!("; {} not affected", grouped(not_affected)));
                }
                (said, YELLOW.bold())
            } else if not_affected > 0 {
                let n = count(not_affected, "project", "projects");
                match found {
                    Found::All => (
                        format!("✓ Affects none of the {n} whose lockfiles were compared"),
                        GREEN.bold(),
                    ),
                    Found::NotEntered => (
                        format!("✓ Affects none of the {n} found whose lockfiles were compared"),
                        GREEN.bold(),
                    ),
                    Found::LookedAt => (
                        format!("Affects none of the {n} looked at whose lockfiles were compared"),
                        BOLD,
                    ),
                }
            } else {
                (
                    "Cannot be told: no project's lockfiles were compared with it".to_string(),
                    YELLOW.bold(),
                )
            };
            out.extend(sentence(screen, 0, &said, style));
        }
        // An id no record names: the core's sentence, never calmer than any answer.
        _ => {
            let style = if affected > 0 {
                RED.bold()
            } else if untold > 0 || worst.is_empty() {
                YELLOW.bold()
            } else {
                BOLD
            };
            out.extend(sentence(
                screen,
                0,
                m.said
                    .as_deref()
                    .unwrap_or("Nothing can be said of this id"),
                style,
            ));
        }
    }
    // Under an answer about the projects, the scope it speaks for when not all were found.
    let about_projects = matches!(
        m.data.map(v1::RecordData::try_from),
        Some(Ok(v1::RecordData::Held | v1::RecordData::NoRecord))
    );
    if let Some(line) = scope.filter(|_| about_projects) {
        out.extend(sentence(screen, 2, &line, PLAIN));
    }
    if !top.is_empty() {
        out.push(String::new());
        out.extend(answer_rows(screen, &top));
    }
    for (r, rows) in &records {
        out.push(String::new());
        let summary = r.summary_text.as_deref().unwrap_or_default();
        let head = format!("{}  {}", view::shown(&r.record_text), view::shown(summary));
        let head = match screen.fits() {
            Some(width) => screen::cut_end(&head, width.saturating_sub(2)),
            None => head,
        };
        out.push(format!("  {}", screen.paint(BOLD, &head)));
        out.extend(sentence(
            screen,
            2,
            &format!(
                "{}, {} data, modified {}",
                r.record_source, r.ecosystem, r.modified_text
            ),
            DIM,
        ));
        if !r.answered {
            out.extend(sentence(
                screen,
                4,
                r.said.as_deref().unwrap_or("It is not answered"),
                YELLOW,
            ));
            continue;
        }
        out.extend(answer_rows(screen, rows));
    }
    out.push(String::new());
    out.extend(screen.labelled(2, 10, "Speaks for", &m.declared_note, PLAIN, None, 0));
    if m.data.is_some() {
        out.push(String::new());
        out.push(screen.next(
            "immunity vulnerabilities",
            "every known vulnerability in your projects",
        ));
    }
    joined(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::known::whole;
    use crate::screen::visible;

    /// The words that say a thing is calm, each allowed only where the message says it.
    const CALM: [&str; 5] = [
        "gone",
        "not there",
        "not affected",
        "nothing needs",
        "no known",
    ];

    /// Text from a source made to break out: a style, a title sequence, a C1 control, a bidi
    /// override, a zero-width space, line breaks, and lines that read as Immunity Core's own.
    const HOSTILE: &str = "x\u{1b}[31my\u{1b}]0;t\u{7}\u{9b}2J\u{202e}\u{200b}\n✓ Nothing needs a look\n→ immunity run";

    /// Every screen a text is checked on: a pipe, terminals of several widths, with and
    /// without colour.
    fn screens() -> Vec<Screen> {
        vec![
            Screen::pipe(),
            Screen::terminal(120, true),
            Screen::terminal(80, true),
            Screen::terminal(80, false),
            Screen::terminal(40, true),
            Screen::terminal(20, false),
        ]
    }

    /// The calm words a text holds.
    fn calm_in(text: &str) -> Vec<&'static str> {
        let lower = visible(text).to_lowercase();
        CALM.into_iter().filter(|w| lower.contains(w)).collect()
    }

    fn reading(kind: &str, completeness: v1::Completeness, reason: Option<&str>) -> v1::Coverage {
        v1::Coverage {
            reader: "lockfiles".to_string(),
            kind: kind.to_string(),
            scope_text: "checkout:machine:example-host/dev/shop".to_string(),
            completeness: completeness as i32,
            reason_text: reason.map(str::to_string),
            cause: (completeness != v1::Completeness::Full).then_some(v1::Cause::NoReader as i32),
            observed_at: Some(1_794_800_000),
            lacks: Vec::new(),
        }
    }

    /// The reading made by rule about what was asked, as `known::by_rule` makes it.
    fn asked(question: v1::Question, reason: &str) -> v1::Coverage {
        v1::Coverage {
            reader: crate::known::RULE_READER.to_string(),
            kind: crate::known::unread_kind(question).to_string(),
            scope_text: "machine:example-host".to_string(),
            completeness: v1::Completeness::None as i32,
            reason_text: Some(reason.to_string()),
            cause: Some(v1::Cause::NotGiven as i32),
            observed_at: None,
            lacks: Vec::new(),
        }
    }

    fn finding(id: &str, rule: &str, severity: v1::Level, urgent: bool) -> v1::FindingRef {
        v1::FindingRef {
            id: id.to_string(),
            rule: Some(rule.to_string()),
            about_text: "component:checkout:machine:example-host/dev/shop/npm/ansi-regex"
                .to_string(),
            state: v1::FindingState::Open as i32,
            severity: Some(severity as i32),
            confidence: Some(v1::Level::High as i32),
            urgent,
        }
    }

    fn project(asked: &str, presence: v1::Presence, thing: bool) -> v1::Known {
        v1::Known {
            format: 1,
            asked_text: asked.to_string(),
            answered_at: 1_794_807_960,
            presence: presence as i32,
            thing: thing.then(|| v1::Entity {
                id_text: "checkout:machine:example-host/dev/shop".to_string(),
                r#type: "checkout".to_string(),
            }),
            question: v1::Question::Project as i32,
            latest_run_at: Some(1_794_800_000),
            coverage: vec![reading(
                "lockfile dependencies",
                v1::Completeness::Full,
                None,
            )],
            ..Default::default()
        }
    }

    #[test]
    fn what_was_asked_is_said_near_the_top_never_dim_and_with_no_calm_word() {
        // A path inside a project, one spelled otherwise, a folder that holds projects, and a
        // place under none: each says why near the top, never dim, and the text holds no calm
        // word. A presence of unknown with the thing set says it cannot tell, never gone.
        let inside = "a single path inside a project is not judged on its own: the answer is about the project that holds it";
        let spelled =
            "the path is spelled otherwise than the store holds it, in case or Unicode form";
        let holder = "this folder is not a project the store knows, and it holds 7 projects: ask about one of them by its id or its path";
        let none = "no reading opened this place for this answer: no project the store knows is at it or holds it";
        let mut cases: Vec<(v1::Known, &str)> = Vec::new();
        for (reason, presence, thing) in [
            (inside, v1::Presence::Held, true),
            (spelled, v1::Presence::Held, true),
            (holder, v1::Presence::Unknown, false),
            (none, v1::Presence::Unknown, false),
        ] {
            let mut k = project("~/dev/shop/x", presence, thing);
            k.coverage.push(asked(v1::Question::Project, reason));
            cases.push((k, reason));
        }
        let mut unknown = project("~/dev/shop", v1::Presence::Unknown, true);
        unknown.coverage[0] = reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some("a lockfile could not be read"),
        );
        cases.push((unknown, "Cannot tell whether it is there now"));
        for (k, said) in &cases {
            let text = known(k, &Screen::pipe());
            let top: String = text.lines().take(3).collect::<Vec<_>>().join(" ");
            assert!(top.contains(said), "{text}");
            for screen in screens() {
                let text = known(k, &screen);
                assert_eq!(calm_in(&text), Vec::<&str>::new(), "{text}");
                assert!(!text.contains('✓'), "{text}");
                // The lines that say it are never dim.
                for line in text.lines().skip(1).take(4) {
                    assert!(!line.contains("\u{1b}[2m"), "{line:?}");
                }
            }
        }
    }

    #[test]
    fn on_a_terminal_a_reading_not_full_takes_two_lines_at_most_and_the_pipe_keeps_its_reason_whole()
     {
        let long = format!(
            "the file could not be verified: {}; and more after it",
            "a source's long words ".repeat(12)
        );
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.coverage.push(reading(
            "package integrity",
            v1::Completeness::Partial,
            Some(&format!("x\u{1b}[31m{long}")),
        ));
        let text = known(&k, &Screen::terminal(80, false));
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("package integrity"))
            .unwrap_or_else(|| panic!("{text}"));
        // The first clause, cut with the mark, and the next line is no longer the reason.
        assert!(
            lines[at].contains("in part, x\\u{1b}[31mthe file could"),
            "{text}"
        );
        assert!(lines[at..at + 2].concat().contains('…'), "{text}");
        assert!(!text.contains("and more after it"), "{text}");
        assert!(lines.iter().all(|l| screen::columns(l) <= 80), "{text}");
        assert!(
            text.contains("Each reason is whole with --json, or in a pipe."),
            "{text}"
        );
        // In a pipe the reason is whole and nothing is said about where it is.
        let piped = known(&k, &Screen::pipe());
        assert!(piped.contains("and more after it"), "{piped}");
        assert!(!piped.contains("whole with --json"), "{piped}");
        // A short reason is not cut and says nothing more.
        let mut short = project("~/dev/shop", v1::Presence::Held, true);
        short.coverage.push(reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some("not supported yet"),
        ));
        let text = known(&short, &Screen::terminal(80, false));
        assert!(text.contains("in part, not supported yet\n"), "{text}");
        assert!(!text.contains("whole with --json"), "{text}");
        // The first clause keeps what its colon names; what follows the clause is cut.
        let mut named = project("~/dev/shop", v1::Presence::Held, true);
        named.coverage.push(reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some("not supported yet: yarn.lock; no reader for lockfile kind yarn.lock"),
        ));
        let text = known(&named, &Screen::terminal(80, false));
        assert!(
            text.contains("in part, not supported yet: yarn.lock…\n"),
            "{text}"
        );
    }

    #[test]
    fn a_count_of_readings_says_how_many_are_not_full_and_each_is_said_with_its_reason() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.coverage.push(reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some("not supported yet: yarn.lock"),
        ));
        let text = known(&k, &Screen::pipe());
        assert!(text.contains("Readings   2, 1 not full"), "{text}");
        assert!(
            text.contains("lockfile dependencies: in part, not supported yet: yarn.lock"),
            "{text}"
        );
        // A partial reading keeps the answer from calm.
        assert!(
            text.contains("Not everything could be read, 1 reading not full"),
            "{text}"
        );
        assert!(!text.contains('✓'), "{text}");
        assert_eq!(calm_in(&text), Vec::<&str>::new(), "{text}");
        // All full: calm, and the count says so.
        let calm = known(
            &project("~/dev/shop", v1::Presence::Held, true),
            &Screen::pipe(),
        );
        assert!(
            calm.contains("✓ Nothing needs a look in what was read"),
            "{calm}"
        );
        assert!(calm.contains("1, all full"), "{calm}");
        // A reading made by rule that is not full, such as a machine never visited, is counted
        // and keeps the answer from calm.
        let mut never = project("web-1", v1::Presence::Held, true);
        never.question = v1::Question::Machine as i32;
        never.coverage.push(v1::Coverage {
            reader: "servers".to_string(),
            kind: "sweep visit".to_string(),
            reason_text: Some("the server check has never visited this machine".to_string()),
            ..asked(v1::Question::Machine, "")
        });
        let text = known(&never, &Screen::pipe());
        assert!(!text.contains('✓'), "{text}");
        assert!(text.contains("2, 1 not full"), "{text}");
        assert!(
            text.contains(
                "Not judged   sweep visit: the server check has never visited this machine"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_thing_gone_is_said_gone_and_one_this_build_cannot_read_is_not_known() {
        let text = known(
            &project("~/dev/shop", v1::Presence::Gone, true),
            &Screen::pipe(),
        );
        assert_eq!(
            text.lines().nth(1),
            Some("Gone: it was there, and what was read of it is retracted"),
            "{text}"
        );
        assert!(!text.contains('✓'), "{text}");
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.presence = 99;
        let text = known(&k, &Screen::pipe());
        assert!(text.contains("Not known: this build cannot read"), "{text}");
        assert!(!text.contains('✓'), "{text}");
        // Unknown and nothing by that name: no thing, no calm.
        let text = known(
            &project("~/dev/none", v1::Presence::Unknown, false),
            &Screen::pipe(),
        );
        assert!(
            text.contains("Not known: the store holds nothing by this name"),
            "{text}"
        );
        assert!(!text.contains('✓'), "{text}");
    }

    #[test]
    fn findings_are_grouped_by_rule_with_the_level_words_of_the_status_and_their_ids() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.findings = vec![
            finding(
                "f0000000001",
                crate::findings::MALICIOUS_PACKAGE,
                v1::Level::Critical,
                true,
            ),
            finding(
                "f0000000002",
                "autorun.folder-open",
                v1::Level::Medium,
                false,
            ),
            finding("f0000000003", "autorun.folder-open", v1::Level::High, true),
            v1::FindingRef {
                state: v1::FindingState::Seen as i32,
                ..finding("f0000000004", "autorun.folder-open", v1::Level::High, true)
            },
        ];
        let text = known(&k, &Screen::pipe());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[1], "✗ 3 findings need a look, 2 urgent", "{text}");
        assert!(
            lines[3].starts_with("  critical  Malicious package in a project"),
            "{text}"
        );
        assert!(lines[3].ends_with("1  urgent"), "{text}");
        assert_eq!(lines[4].trim(), "f0000000001", "{text}");
        // A group's level is its worst.
        assert!(lines[5].starts_with("  high      "), "{text}");
        assert!(lines[5].ends_with("2  1 urgent"), "{text}");
        assert_eq!(lines[6].trim(), "f0000000002, f0000000003", "{text}");
        // An answered finding is counted apart, never as one that needs a look.
        assert!(text.contains("Not open   1 seen"), "{text}");
        assert!(
            text.ends_with("→ immunity finding f0000000001   shows one and how to answer it\n"),
            "{text}"
        );
        // No entity id and no raw word of the store.
        for raw in ["checkout:", "component:", "facts in force", "held", "_"] {
            assert!(!text.contains(raw), "{raw}: {text}");
        }
        // Many of one rule: counted, their ids left to the next command.
        k.findings = (0..4)
            .map(|i| finding(&format!("f000000000{i}"), "x.y", v1::Level::Low, false))
            .collect();
        let text = known(&k, &Screen::pipe());
        assert!(text.contains("  low  x.y  4\n"), "{text}");
        assert!(!text.contains("f0000000001,"), "{text}");
    }

    #[test]
    fn rules_past_the_first_few_are_counted_with_how_many_are_urgent() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        for (urgent, said) in [
            (false, "… 2 more in 2 kinds, none urgent"),
            (true, "… 2 more in 2 kinds, 2 urgent"),
        ] {
            k.findings = (0..8)
                .map(|i| {
                    finding(
                        &format!("f{i:010}"),
                        &format!("r.{i}"),
                        v1::Level::High,
                        urgent,
                    )
                })
                .collect();
            let text = known(&k, &Screen::pipe());
            assert!(text.contains(said), "{text}");
        }
        // An urgent one is listed before one that is not, whatever its level.
        k.findings[7].severity = Some(v1::Level::Low as i32);
        k.findings[7].urgent = false;
        k.findings[6].urgent = false;
        k.findings[5].severity = Some(v1::Level::Critical as i32);
        k.findings[5].urgent = false;
        let text = known(&k, &Screen::pipe());
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[3].contains("r.0"), "{text}");
        assert!(
            lines[13].contains("critical") && lines[13].contains("r.5"),
            "{text}"
        );
        assert!(text.contains("… 2 more in 2 kinds, none urgent"), "{text}");
    }

    #[test]
    fn what_the_store_holds_is_said_in_a_person_s_words() {
        let mut k = project("~/dev/shop/web", v1::Presence::Held, true);
        let part = "component:checkout:machine:example-host/dev/shop/npm/@scope/left-pad";
        let file = "file:machine:example-host/dev/shop/.vscode/tasks.json";
        k.parts = vec![
            v1::Entity {
                id_text: part.to_string(),
                r#type: "component".to_string(),
            },
            v1::Entity {
                id_text: file.to_string(),
                r#type: "file".to_string(),
            },
        ];
        let fact = |s: &str, p: &str, o: &str| v1::Fact {
            subject_text: s.to_string(),
            predicate: p.to_string(),
            object_text: o.to_string(),
            assertions: vec![v1::Assertion {
                basis: v1::Basis::Declared as i32,
                source_ref_text: "dev/shop/package-lock.json#node_modules/@scope/left-pad"
                    .to_string(),
                ..Default::default()
            }],
        };
        let shop = "checkout:machine:example-host/dev/shop";
        k.facts = vec![
            fact(part, "has_version", "1.3.0"),
            fact(part, "part_of", shop),
            fact(
                file,
                "watched_as",
                "task run when the project folder is opened",
            ),
            fact(shop, "located_on", "machine:example-host"),
            fact(shop, "part_of", "machine:example-host"),
            fact(shop, "holds_autorun_point", ".vscode/tasks.json"),
            fact(shop, "has_digest", "sha256:0"),
        ];
        let text = known(&k, &Screen::pipe());
        for said in [
            "Where            ~/dev/shop\n",
            "On               example-host\n",
            "Runs by itself   .vscode/tasks.json\n",
            "Packages         1: @scope/left-pad 1.3.0\n",
            "Files            1: .vscode/tasks.json (task run when the project folder is opened)\n",
            "Declared in      package-lock.json\n",
        ] {
            assert!(text.contains(said), "{said}{text}");
        }
        assert!(!text.contains("sha256"), "{text}");
        // Past the first few, a kind is counted.
        k.parts = (0..8)
            .map(|i| v1::Entity {
                id_text: format!("component:{shop}/npm/p{i}"),
                r#type: "component".to_string(),
            })
            .collect();
        let text = known(&k, &Screen::pipe());
        assert!(text.contains("8: p0, p1, p2, p3, p4, p5 +2\n"), "{text}");
        // This Mac, asked with no name, is named by the store's name for it, and a program
        // asked by its id by its name.
        let mut mac = project("", v1::Presence::Held, true);
        mac.question = v1::Question::Machine as i32;
        mac.thing = Some(v1::Entity {
            id_text: "machine:example-host".to_string(),
            r#type: "machine".to_string(),
        });
        mac.same_as = vec![v1::Entity {
            id_text: "machine:web-1".to_string(),
            r#type: "machine".to_string(),
        }];
        let text = known(&mac, &Screen::pipe());
        assert!(
            text.starts_with("This Mac  example-host   checked "),
            "{text}"
        );
        assert!(text.contains("Also known as   web-1\n"), "{text}");
        assert!(!text.contains("Name "), "{text}");
        let mut app = project(
            "component:machine:example-host/macos-app/org.example.editor",
            v1::Presence::Held,
            true,
        );
        app.question = v1::Question::Program as i32;
        app.thing = Some(v1::Entity {
            id_text: app.asked_text.clone(),
            r#type: "component".to_string(),
        });
        let text = known(&app, &Screen::pipe());
        assert!(text.starts_with("Program  component:"), "{text}");
        assert!(text.contains("Name       org.example.editor\n"), "{text}");
    }

    #[test]
    fn text_from_a_source_cannot_style_hide_or_pose_as_immunity_s_own_lines() {
        let h = whole(HOSTILE);
        let mut k = project(&h, v1::Presence::Unknown, true);
        let thing = format!("checkout:machine:example-host/dev/{h}");
        k.thing = Some(v1::Entity {
            id_text: thing.clone(),
            r#type: "checkout".to_string(),
        });
        k.same_as = vec![v1::Entity {
            id_text: format!("machine:{h}"),
            r#type: "machine".to_string(),
        }];
        k.parts = vec![v1::Entity {
            id_text: format!("component:{thing}/npm/{h}"),
            r#type: "component".to_string(),
        }];
        k.facts = vec![v1::Fact {
            subject_text: thing.clone(),
            predicate: "known_as".to_string(),
            object_text: h.clone(),
            assertions: Vec::new(),
        }];
        let mut c = reading(&h, v1::Completeness::Partial, Some(&h));
        c.reader = h.clone();
        c.scope_text = h.clone();
        c.lacks = vec![v1::Lack {
            what: "lockfile kind".to_string(),
            name_text: Some(h.clone()),
        }];
        k.coverage = vec![c, asked(v1::Question::Project, &h)];
        k.findings = vec![v1::FindingRef {
            state: v1::FindingState::Seen as i32,
            ..finding("f0000000001", &h, v1::Level::High, false)
        }];
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                projects_not_read: 1,
                feeds: vec![v1::FeedFreshness {
                    ecosystem: h.clone(),
                    not_current_why: Some(h.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            affected: Some(v1::AffectedPackages {
                items: vec![v1::AffectedPackage {
                    project_text: h.clone(),
                    package_text: h.clone(),
                    releases: vec![v1::PackageRelease {
                        version_text: h.clone(),
                        at_text: h.clone(),
                    }],
                    record: Some(v1::PackageRecord {
                        id_text: h.clone(),
                        label: h.clone(),
                        fixed_text: vec![h.clone()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                total: 1,
            }),
            unknown: Some(v1::UnknownPackages {
                items: vec![v1::UnknownPackage {
                    project_text: h.clone(),
                    ecosystem: h.clone(),
                    package_text: h.clone(),
                    reason: h.clone(),
                }],
                total: 1,
            }),
            unread: Some(v1::UnreadPlaces {
                items: vec![v1::UnreadPlace {
                    project_text: h.clone(),
                    ecosystem: h.clone(),
                    lockfiles: "partial".to_string(),
                    why_text: Some(h.clone()),
                }],
                total: 1,
            }),
            declared_note: h.clone(),
            ..Default::default()
        };
        let place = v1::PlaceAnswer {
            project_text: h.clone(),
            ecosystem: h.clone(),
            packages: vec![v1::PackageAnswerOf {
                package_text: h.clone(),
                answer: v1::PackageAnswer::Unknown as i32,
                entries: vec![v1::DeclaredRelease {
                    version_text: Some(h.clone()),
                    ..Default::default()
                }],
                reason: Some(h.clone()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let one = v1::Vulnerability {
            id_text: h.clone(),
            data: Some(v1::RecordData::Held as i32),
            records: vec![v1::RecordAnswers {
                record_text: h.clone(),
                record_source: h.clone(),
                ecosystem: h.clone(),
                modified_text: h.clone(),
                summary_text: Some(h.clone()),
                answered: true,
                answers: vec![place],
                ..Default::default()
            }],
            declared_note: h.clone(),
            ..Default::default()
        };
        let no_record = v1::Vulnerability {
            id_text: h.clone(),
            data: Some(v1::RecordData::NoRecord as i32),
            said: Some("No record names it.".to_string()),
            records: vec![v1::RecordAnswers {
                record_text: h.clone(),
                answered: false,
                said: Some("The record was withdrawn.".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        for screen in screens() {
            for text in [
                known(&k, &screen),
                vulnerabilities(&m, &screen),
                vulnerability(&one, &screen),
                vulnerability(&no_record, &screen),
            ] {
                let shown = visible(&text);
                // Every escape sequence is one this renderer wrote; nothing hidden is left.
                assert!(!shown.contains('\u{1b}'), "{text}");
                assert!(
                    shown.chars().all(|c| c == '\n' || !crate::icu::hidden(c)),
                    "{text:?}"
                );
                if !screen.colour {
                    assert!(!text.contains('\u{1b}'), "{text}");
                }
                // No line of text from a source stands where Immunity Core's own words stand.
                for line in shown.lines() {
                    for own in ["✓", "✗", "→ immunity run", "x\\u{1b}", "Nothing needs"] {
                        assert!(!line.starts_with(own), "{own}: {line:?}\n{text}");
                    }
                }
            }
        }
    }

    #[test]
    fn no_line_is_wider_than_the_terminal_and_ids_levels_and_counts_are_never_cut() {
        let long = format!("~/dev/{}", "a-very-long-folder-name/".repeat(6));
        let mut k = project(&long, v1::Presence::Held, true);
        k.findings = vec![finding(
            "f0123456789",
            crate::findings::EXPLOITED_VULNERABILITY,
            v1::Level::Critical,
            true,
        )];
        k.coverage.push(reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some(&"a reason that goes on ".repeat(8)),
        ));
        k.coverage
            .push(asked(v1::Question::Project, &"inside ".repeat(20)));
        let one = vulnerability_of(&long);
        let list = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                affected_records: 1,
                affected_projects: 1,
                projects_compared: 1_234_567,
                projects_not_read: 1_234_567,
                projects_without_lockfile: 1_234_567,
                unknown_packages: 1_234_567,
                ..Default::default()
            }),
            ..Default::default()
        };
        for width in [120, 80, 40, 20] {
            let screen = Screen::terminal(width, true);
            let text = known(&k, &screen);
            assert!(
                text.contains("f0123456789") && text.contains("critical"),
                "{text}"
            );
            let words = vulnerability(&one, &screen);
            assert!(words.contains("GHSA-0000-0000-0000"), "{words}");
            let counts = vulnerabilities(&list, &screen);
            assert!(counts.contains("1,234,567 not wholly read"), "{counts}");
            if width < 40 {
                continue;
            }
            for line in text.lines().chain(words.lines()).chain(counts.lines()) {
                assert!(
                    screen::columns(&visible(line)) <= width,
                    "{width}: {line:?}"
                );
            }
        }
    }

    /// An answer for one record: one project affected, one that cannot be told for one of its
    /// ecosystems and is not affected in the other, and one not affected.
    fn vulnerability_of(project: &str) -> v1::Vulnerability {
        let package = |answer: v1::PackageAnswer| v1::PackageAnswerOf {
            package_text: "dset".to_string(),
            answer: answer as i32,
            entries: vec![
                v1::DeclaredRelease {
                    version_text: Some("3.1.1".to_string()),
                    affected: answer == v1::PackageAnswer::Affected,
                    ..Default::default()
                },
                v1::DeclaredRelease {
                    version_text: Some("3.1.2".to_string()),
                    ..Default::default()
                },
            ],
            fixed_text: vec!["3.1.2".to_string()],
            reason: (answer == v1::PackageAnswer::Unknown)
                .then(|| crate::vulnerabilities::NOT_COMPARABLE.to_string()),
            certainty: (answer == v1::PackageAnswer::NotAffected).then(|| "known".to_string()),
            openvex: (answer == v1::PackageAnswer::NotAffected).then(|| "fixed".to_string()),
            ..Default::default()
        };
        let place = |p: &str, eco: &str, answer: v1::PackageAnswer| v1::PlaceAnswer {
            project_text: p.to_string(),
            ecosystem: eco.to_string(),
            packages: vec![package(answer)],
            ..Default::default()
        };
        v1::Vulnerability {
            format: 1,
            id_text: "GHSA-0000-0000-0000".to_string(),
            in_catalogue: Some(false),
            data: Some(v1::RecordData::Held as i32),
            projects_found: Some(v1::ProjectsFound {
                all: true,
                ..Default::default()
            }),
            records: vec![v1::RecordAnswers {
                record_text: "GHSA-0000-0000-0000".to_string(),
                record_source: "GitHub Advisory Database".to_string(),
                ecosystem: "npm".to_string(),
                summary_text: Some("Prototype pollution".to_string()),
                answered: true,
                answers: vec![
                    place(project, "npm", v1::PackageAnswer::Affected),
                    place("~/dev/odd", "npm", v1::PackageAnswer::Unknown),
                    place("~/dev/odd", "crates.io", v1::PackageAnswer::NotAffected),
                    place("~/dev/blog", "npm", v1::PackageAnswer::NotAffected),
                ],
                ..Default::default()
            }],
            declared_note: "This speaks for what the lockfiles declare.".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn an_answer_that_cannot_be_told_is_never_said_as_not_affected_and_comes_before_them() {
        let text = vulnerability(&vulnerability_of("~/dev/shop"), &Screen::pipe());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "Vulnerability GHSA-0000-0000-0000   not on the list of those used in attacks"
        );
        // ~/dev/odd cannot be told in npm: it is counted as cannot be told, though it is not
        // affected in crates.io.
        assert_eq!(
            lines[1], "✗ Affects 1 project; cannot be told for 1",
            "{text}"
        );
        let affected = text
            .find("    Affected\n")
            .unwrap_or_else(|| panic!("{text}"));
        let untold = text
            .find("    Cannot be told\n")
            .unwrap_or_else(|| panic!("{text}"));
        let calm = text
            .find("    Not affected\n")
            .unwrap_or_else(|| panic!("{text}"));
        assert!(affected < untold && untold < calm, "{text}");
        assert!(
            text.contains("~/dev/odd   dset 3.1.1, 3.1.2  its version cannot be compared"),
            "{text}"
        );
        // An affected row names the releases the record affects and the fix.
        assert!(
            text.contains("~/dev/shop  dset 3.1.1         fixed in 3.1.2"),
            "{text}"
        );
        assert!(
            text.contains("dset 3.1.1, 3.1.2  at or above a fix"),
            "{text}"
        );
        // Without the affected project, the opening says what cannot be told first.
        let mut m = vulnerability_of("~/dev/shop");
        m.records[0].answers.remove(0);
        let text = vulnerability(&m, &Screen::pipe());
        assert_eq!(
            text.lines().nth(1),
            Some("Cannot be told for 1 project; 1 not affected"),
            "{text}"
        );
        assert!(!text.contains('✓'), "{text}");
        // Every one not affected, as known: the one calm sentence.
        m.records[0].answers.remove(0);
        let text = vulnerability(&m, &Screen::pipe());
        assert_eq!(
            text.lines().nth(1),
            Some("✓ Affects none of the 2 projects whose lockfiles were compared"),
            "{text}"
        );
        // No raw word of the store reaches a person.
        for raw in [
            "not_affected",
            "component_not_present",
            "place_not_read",
            "_",
        ] {
            assert!(!text.contains(raw), "{raw}: {text}");
        }
        // No project compared: cannot be told, never calm.
        m.records[0].answers.clear();
        let text = vulnerability(&m, &Screen::pipe());
        assert!(
            text.contains("Cannot be told: no project's lockfiles were compared with it"),
            "{text}"
        );
        // A record that is not answered says why, in the core's words.
        m.records[0].answered = false;
        m.records[0].said = Some("The record was withdrawn.".to_string());
        let text = vulnerability(&m, &Screen::pipe());
        assert!(text.contains("    The record was withdrawn.\n"), "{text}");
    }

    #[test]
    fn a_vulnerability_says_whether_it_is_used_in_attacks_and_what_no_record_and_no_store_mean() {
        let mut m = vulnerability_of("~/dev/shop");
        m.in_catalogue = None;
        let text = vulnerability(&m, &Screen::pipe());
        assert!(
            text.contains("whether it is used in attacks is not known"),
            "{text}"
        );
        m.in_catalogue = Some(true);
        let text = vulnerability(&m, &Screen::pipe());
        assert!(
            text.starts_with("Vulnerability GHSA-0000-0000-0000   used in attacks\n"),
            "{text}"
        );
        assert!(
            text.ends_with(
                "→ immunity vulnerabilities   every known vulnerability in your projects\n"
            ),
            "{text}"
        );
        // On a narrow terminal the word goes on a line of its own, whole.
        let text = vulnerability(&m, &Screen::terminal(40, false));
        assert!(text.starts_with("Vulnerability GHSA-0000-0000-0000\n  used in attacks\n"));
        // An id no record names: the core's sentence, and each place's answer with how sure.
        let place = |p: &str, answer: v1::PackageAnswer| v1::PlaceAnswer {
            project_text: p.to_string(),
            ecosystem: "npm".to_string(),
            answer: Some(answer as i32),
            ..Default::default()
        };
        let mut no_record = v1::Vulnerability {
            data: Some(v1::RecordData::NoRecord as i32),
            said: Some("The catalogue holds this id, and no record names it.".to_string()),
            in_catalogue: Some(true),
            answers: vec![
                v1::PlaceAnswer {
                    certainty: Some("no_signs".to_string()),
                    ..place("~/dev/blog", v1::PackageAnswer::NotAffected)
                },
                v1::PlaceAnswer {
                    reason: Some(crate::vulnerabilities::PLACE_NOT_READ.to_string()),
                    ..place("~/dev/yarn", v1::PackageAnswer::Unknown)
                },
                place("~/dev/what", v1::PackageAnswer::Unspecified),
            ],
            ..Default::default()
        };
        let text = vulnerability(&no_record, &Screen::pipe());
        assert!(
            text.lines().nth(1) == Some("The catalogue holds this id, and no record names it."),
            "{text}"
        );
        assert!(
            text.contains("~/dev/blog  npm  no signs: no record names it\n"),
            "{text}"
        );
        assert!(
            text.contains("~/dev/yarn  npm  its lockfiles were not all read"),
            "{text}"
        );
        assert!(text.contains("~/dev/what  npm  cannot be told"), "{text}");
        assert!(
            text.find("Cannot be told") < text.find("Not affected"),
            "{text}"
        );
        // Its style follows the worst answer: yellow while one cannot be told, plain when
        // none does.
        let painted = vulnerability(&no_record, &Screen::terminal(200, true));
        assert!(painted.contains("\u{1b}[1;33mThe catalogue"), "{painted}");
        no_record.answers.truncate(1);
        let painted = vulnerability(&no_record, &Screen::terminal(200, true));
        assert!(painted.contains("\u{1b}[1mThe catalogue"), "{painted}");
        no_record.answers[0] = place("~/dev/shop", v1::PackageAnswer::Affected);
        let painted = vulnerability(&no_record, &Screen::terminal(200, true));
        assert!(painted.contains("\u{1b}[1;31mThe catalogue"), "{painted}");
        // No store: nothing is known, and never "not on the list".
        let text = vulnerability(&v1::Vulnerability::default(), &Screen::pipe());
        assert!(text.contains("\nThere is no store here yet.\n"), "{text}");
        assert!(text.contains("is not known"), "{text}");
        assert!(text.contains("immunity run makes one"), "{text}");
        // Nor is anything said of which projects were found, which is about none.
        assert!(!text.contains("was found"), "{text}");
    }

    #[test]
    fn why_a_record_does_not_affect_or_cannot_be_told_is_said_in_words() {
        for (openvex, certainty, said) in [
            (Some("fixed"), Some("known"), "at or above a fix"),
            (
                Some("vulnerable_code_not_present"),
                Some("known"),
                "not in the affected range",
            ),
            (
                Some("component_not_present"),
                Some("known"),
                "does not use the package",
            ),
            (Some("a_new_word"), Some("known"), "a new word"),
            (None, Some("no_signs"), "no signs: no record names it"),
            (None, None, "not affected"),
        ] {
            assert_eq!(not_affected_said(openvex, certainty), said);
        }
        for (reason, said) in [
            (
                crate::vulnerabilities::PLACE_NOT_READ,
                "its lockfiles were not all read",
            ),
            (
                crate::vulnerabilities::FEED_NOT_READ,
                "the vulnerability data is not current",
            ),
            (
                crate::vulnerabilities::NOT_COMPARABLE,
                "its version cannot be compared",
            ),
            (
                crate::vulnerabilities::NOT_FROM_REGISTRY,
                "it does not come from the registry",
            ),
            (
                crate::vulnerabilities::NOT_COVERED,
                "the data does not cover this version",
            ),
            (
                crate::vulnerabilities::NO_MATCHER,
                "no vulnerability data is read for its ecosystem",
            ),
            ("a_new_reason", "a new reason"),
        ] {
            assert_eq!(reason_said(reason), said);
        }
    }

    fn totals(t: v1::VulnerabilityTotals) -> String {
        let m = v1::Vulnerabilities {
            totals: Some(t),
            ..Default::default()
        };
        vulnerabilities(&m, &Screen::pipe())
    }

    #[test]
    fn the_list_is_calm_only_when_its_totals_allow_it_and_counts_what_was_not_read() {
        let all = Some(v1::ProjectsFound {
            all: true,
            ..Default::default()
        });
        let calm = totals(v1::VulnerabilityTotals {
            projects_compared: 3,
            projects_found: all,
            ..Default::default()
        });
        assert!(
            calm.starts_with("✓ No known vulnerability affects your projects\n"),
            "{calm}"
        );
        // From an older core, whether every project was found is not known: never the mark.
        let older = totals(v1::VulnerabilityTotals {
            projects_compared: 3,
            ..Default::default()
        });
        assert!(
            older.starts_with("No known vulnerability affects the projects that were looked at\n")
                && older.contains("Whether every project was found is not known."),
            "{older}"
        );
        assert!(
            calm.contains("\n  3 projects compared · 0 not wholly read · 0 with no lockfile\n"),
            "{calm}"
        );
        for (t, first) in [
            (
                v1::VulnerabilityTotals::default(),
                "No project's lockfiles were compared",
            ),
            (
                v1::VulnerabilityTotals {
                    projects_compared: 3,
                    projects_not_read: 1,
                    ..Default::default()
                },
                "None of the known vulnerabilities affects what could be compared",
            ),
            (
                v1::VulnerabilityTotals {
                    projects_compared: 3,
                    projects_without_lockfile: 2,
                    ..Default::default()
                },
                "None of the known vulnerabilities affects what could be compared",
            ),
            (
                v1::VulnerabilityTotals {
                    projects_compared: 3,
                    unknown_packages: 1,
                    ..Default::default()
                },
                "None of the known vulnerabilities affects what could be compared",
            ),
        ] {
            let text = totals(t.clone());
            assert!(text.starts_with(first), "{text}");
            assert_eq!(calm_in(&text), Vec::<&str>::new(), "{text}");
            assert!(!text.contains('✓'), "{text}");
            let second = text.lines().nth(1).unwrap_or_default();
            assert!(
                second.contains(&format!("{} not wholly read", t.projects_not_read))
                    && second
                        .contains(&format!("{} with no lockfile", t.projects_without_lockfile)),
                "{text}"
            );
            assert_eq!(
                second.contains("cannot be told"),
                t.unknown_packages > 0,
                "{text}"
            );
        }
        // A feed not current is said, and the time the data was read is at the right.
        let text = totals(v1::VulnerabilityTotals {
            projects_compared: 1,
            feeds: vec![
                v1::FeedFreshness {
                    ecosystem: "crates.io".to_string(),
                    matched: true,
                    not_current_why: Some("it has never been read".to_string()),
                    ..Default::default()
                },
                v1::FeedFreshness {
                    ecosystem: "npm".to_string(),
                    matched: true,
                    read_at: Some(1_794_800_000),
                    current: true,
                    ..Default::default()
                },
                v1::FeedFreshness {
                    matched: false,
                    read_at: Some(1_794_900_000),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        assert!(
            text.contains("  The crates.io data is not current: it has never been read\n"),
            "{text}"
        );
        assert!(
            text.lines()
                .next()
                .unwrap()
                .ends_with(&format!("data read {}", view::utc(1_794_800_000))),
            "{text}"
        );
        // Nothing counted: why, and never a 0.
        let m = v1::Vulnerabilities {
            not_computed: vec![v1::NotComputed {
                section: "totals".to_string(),
                reason: "the lockfiles were never matched".to_string(),
            }],
            declared_note: "What the lockfiles declare.".to_string(),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &Screen::pipe());
        assert!(
            text.starts_with("Nothing is known yet: the lockfiles were never matched\n"),
            "{text}"
        );
        assert!(!text.contains('0'), "{text}");
        // What every answer speaks for is still said.
        assert!(
            text.contains("\n  Speaks for   What the lockfiles declare.\n"),
            "{text}"
        );
        // No store, in the one wording every command gives it, and nothing after it to run.
        let text = vulnerabilities(&v1::Vulnerabilities::default(), &Screen::pipe());
        assert_eq!(
            text,
            "There is no store here yet.\nimmunity run makes one, or immunity on, which also keeps it checked.\n"
        );
    }

    #[test]
    fn a_row_that_does_not_fit_whole_takes_two_lines_and_the_id_and_package_stay_whole() {
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                affected_records: 1,
                affected_packages: 1,
                affected_projects: 1,
                projects_compared: 1,
                ..Default::default()
            }),
            affected: Some(v1::AffectedPackages {
                items: vec![v1::AffectedPackage {
                    project_text: "~/dev/a-project-with-a-rather-long-name".to_string(),
                    ecosystem: "npm".to_string(),
                    package_text: "react-server-dom-webpack".to_string(),
                    releases: vec![v1::PackageRelease {
                        version_text: "19.0.0".to_string(),
                        at_text: "~/dev/x/package-lock.json".to_string(),
                    }],
                    record: Some(v1::PackageRecord {
                        id_text: "GHSA-fv66-9v8q-g76r".to_string(),
                        label: "critical".to_string(),
                        fixed_text: vec!["19.0.1".into(), "19.1.2".into(), "19.2.1".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                total: 1,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &Screen::terminal(80, false));
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("GHSA-fv66-9v8q-g76r"))
            .unwrap_or_else(|| panic!("{text}"));
        // The level, the id and the package with its version, whole, on the first line.
        let first = lines[at];
        assert!(
            first
                .trim_end()
                .ends_with("GHSA-fv66-9v8q-g76r  react-server-dom-webpack 19.0.0"),
            "{text}"
        );
        // The project and the fix on the second, under the package.
        let second = lines[at + 1];
        let under = first.find("react-server").unwrap();
        assert_eq!(&second[..under], " ".repeat(under), "{text}");
        // The project gives way, in its middle, only to what is left of the second line.
        assert!(
            second.contains("~/dev/a-project-") && second.contains("ong-name"),
            "{text}"
        );
        assert!(second.contains("fixed in 19.0.1"), "{text}");
        assert!(lines.iter().all(|l| screen::columns(l) <= 80), "{text}");
        // Where the row fits whole, one line.
        let wide = vulnerabilities(&m, &Screen::terminal(140, false));
        let row = wide
            .lines()
            .find(|l| l.contains("GHSA-fv66-9v8q-g76r"))
            .unwrap();
        assert!(
            row.contains("a-project-with-a-rather-long-name") && row.contains("fixed in"),
            "{wide}"
        );
    }

    #[test]
    fn rows_of_two_lines_stay_under_their_own_group_used_in_attacks_or_other() {
        let item = |id: &str, exploited: bool| v1::AffectedPackage {
            project_text: "~/dev/a-project-with-a-rather-long-name".to_string(),
            ecosystem: "npm".to_string(),
            package_text: "react-server-dom-webpack".to_string(),
            releases: vec![v1::PackageRelease {
                version_text: "19.0.0".to_string(),
                at_text: "~/dev/x/package-lock.json".to_string(),
            }],
            record: Some(v1::PackageRecord {
                id_text: id.to_string(),
                label: "critical".to_string(),
                exploited: Some(exploited),
                fixed_text: vec!["19.0.1".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                affected_records: 2,
                affected_packages: 1,
                affected_projects: 1,
                projects_compared: 1,
                ..Default::default()
            }),
            affected: Some(v1::AffectedPackages {
                items: vec![
                    item("GHSA-aaaa-aaaa-aaaa", true),
                    item("GHSA-bbbb-bbbb-bbbb", false),
                ],
                total: 2,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &Screen::terminal(80, false));
        let lines: Vec<&str> = text.lines().collect();
        let at = |w: &str| lines.iter().position(|l| l.contains(w)).unwrap();
        // Each group's head, its row's first line, then its second line.
        assert_eq!(at("GHSA-aaaa"), at("Used in attacks") + 1, "{text}");
        assert!(
            lines[at("GHSA-aaaa") + 1].contains("fixed in 19.0.1"),
            "{text}"
        );
        assert_eq!(at("GHSA-bbbb"), at("Other") + 1, "{text}");
        assert!(
            lines[at("GHSA-bbbb") + 1].contains("fixed in 19.0.1"),
            "{text}"
        );
    }

    #[test]
    fn the_list_names_what_affects_with_its_fix_and_what_cannot_be_told_in_words() {
        let item = |id: &str, exploited: Option<bool>, fixed: &[&str]| v1::AffectedPackage {
            project_text: "~/dev/shop".to_string(),
            ecosystem: "npm".to_string(),
            package_text: "react-server-dom-webpack".to_string(),
            releases: vec![v1::PackageRelease {
                version_text: "19.0.0".to_string(),
                at_text: "~/dev/shop/package-lock.json".to_string(),
            }],
            record: Some(v1::PackageRecord {
                id_text: id.to_string(),
                label: "critical".to_string(),
                exploited,
                fixed_text: fixed.iter().map(|f| f.to_string()).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let unknown: Vec<v1::UnknownPackage> = (0..12)
            .map(|i| v1::UnknownPackage {
                project_text: "~/dev/odd".to_string(),
                ecosystem: "npm".to_string(),
                package_text: format!("pkg-{i:02}"),
                reason: crate::vulnerabilities::NOT_COMPARABLE.to_string(),
            })
            .collect();
        let mut m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                affected_records: 2,
                affected_projects: 1,
                projects_compared: 1,
                unknown_packages: 12,
                unknown_packages_by_reason: vec![v1::Count {
                    name: crate::vulnerabilities::NOT_COMPARABLE.to_string(),
                    count: 12,
                }],
                ..Default::default()
            }),
            affected: Some(v1::AffectedPackages {
                items: vec![
                    item("MAL-0002", Some(false), &[]),
                    item("GHSA-0001", Some(true), &["19.0.1", "19.1.2"]),
                    item("GHSA-0001", Some(true), &["19.0.1", "19.1.2"]),
                ],
                total: 4,
            }),
            unknown: Some(v1::UnknownPackages {
                items: unknown,
                total: 12,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &Screen::pipe());
        assert!(
            text.starts_with(
                "✗ 2 known vulnerabilities affect 1 project, 1 of those listed used in attacks"
            ),
            "{text}"
        );
        let attacks = text
            .find("\n  Used in attacks\n")
            .unwrap_or_else(|| panic!("{text}"));
        let other = text.find("\n  Other\n").unwrap_or_else(|| panic!("{text}"));
        let first = text.find("GHSA-0001").unwrap();
        assert!(attacks < first && first < other, "{text}");
        assert!(text.contains("fixed in 19.0.1, 19.1.2"), "{text}");
        assert!(text.contains("no fix named"), "{text}");
        assert!(text.contains("    … 1 more not listed here\n"), "{text}");
        // On a terminal the first fix and how many more.
        let wide = vulnerabilities(&m, &Screen::terminal(120, false));
        assert!(wide.contains("fixed in 19.0.1 +1"), "{wide}");
        // The first ten that cannot be told are named, the rest counted with every reason, in
        // words.
        assert!(text.contains("Cannot be told  12 packages\n"), "{text}");
        assert!(text.contains("pkg-09"), "{text}");
        assert!(!text.contains("pkg-10"), "{text}");
        assert!(
            text.contains(
                "… 2 more not listed here; all of them by reason: its version cannot be compared 12"
            ),
            "{text}"
        );
        assert!(
            !text.contains(crate::vulnerabilities::NOT_COMPARABLE),
            "{text}"
        );
        assert!(
            text.ends_with("→ immunity vulnerability GHSA-0001   one record in every project\n"),
            "{text}"
        );
        // With every row listed and none used in attacks: one section, and no "of those listed".
        m.affected = Some(v1::AffectedPackages {
            items: vec![item("MAL-0002", None, &[])],
            total: 1,
        });
        let text = vulnerabilities(&m, &Screen::pipe());
        assert!(text.contains("\n  Affected\n    critical"), "{text}");
        assert!(
            !text.contains("Other") && !text.contains("used in attacks"),
            "{text}"
        );
        assert!(!text.contains("more not listed here\n"), "{text}");
        m.affected = Some(v1::AffectedPackages {
            items: vec![item("GHSA-0001", Some(true), &["1"])],
            total: 1,
        });
        let text = vulnerabilities(&m, &Screen::pipe());
        assert!(text.contains(", 1 used in attacks"), "{text}");
        assert!(!text.contains("\n  Other\n"), "{text}");
    }

    #[test]
    fn a_place_not_read_and_a_project_with_no_lockfile_are_named_with_why() {
        let place = |p: &str, eco: &str, lockfiles: &str, why: Option<&str>| v1::UnreadPlace {
            project_text: p.to_string(),
            ecosystem: eco.to_string(),
            lockfiles: lockfiles.to_string(),
            why_text: why.map(str::to_string),
        };
        let mut items = vec![
            place(
                "~/dev/notes",
                "any",
                "none_found",
                Some("no lockfile was found"),
            ),
            place(
                "~/dev/yarn",
                "npm",
                "partial",
                Some("not supported yet: yarn.lock"),
            ),
            place("~/dev/go", "go", "no_reader", None),
            place("~/dev/shut", "any", "not_read", None),
            place("~/dev/new", "npm", "some_new_word", None),
        ];
        items.extend((0..8).map(|i| place(&format!("~/dev/p{i}"), "npm", "partial", None)));
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                projects_not_read: 12,
                projects_without_lockfile: 1,
                projects_compared: 1,
                ..Default::default()
            }),
            unread: Some(v1::UnreadPlaces { items, total: 13 }),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &Screen::pipe());
        for said in [
            "  Not read  13 places\n",
            "    ~/dev/notes       no lockfile this version reads\n",
            "    ~/dev/yarn   npm  some lockfiles not read: not supported yet: yarn.lock\n",
            "    ~/dev/go     go   lockfiles of a kind this version does not read\n",
            "    ~/dev/shut        lockfiles not read\n",
            "    ~/dev/new    npm  some new word\n",
            "    ~/dev/p4     npm  some lockfiles not read\n",
            "    … 3 more not listed here\n",
        ] {
            assert!(text.contains(said), "{said}{text}");
        }
        assert!(!text.contains("~/dev/p5"), "{text}");
        assert_eq!(calm_in(&text), Vec::<&str>::new(), "{text}");
    }

    #[test]
    fn a_finding_in_a_state_this_build_does_not_know_needs_a_look() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        for state in [v1::FindingState::Unspecified as i32, 99] {
            k.findings = vec![v1::FindingRef {
                state,
                ..finding("f0000000001", "x.y", v1::Level::High, false)
            }];
            let text = known(&k, &Screen::pipe());
            assert!(
                text.contains("✗ 1 finding needs a look, none urgent"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_failure_is_red_a_limit_yellow_and_a_level_coloured_as_the_status_colours_it() {
        let screen = Screen::terminal(200, true);
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        let mut failed = reading("failed reading", v1::Completeness::Partial, Some("x"));
        failed.cause = Some(v1::Cause::Failed as i32);
        let limit = reading("limited reading", v1::Completeness::Partial, Some("y"));
        k.coverage = vec![failed, limit];
        let text = known(&k, &screen);
        assert!(
            text.contains("\u{1b}[31mfailed reading: in part, x"),
            "{text}"
        );
        assert!(
            text.contains("\u{1b}[33mlimited reading: in part, y"),
            "{text}"
        );
        let item = |label: &str| v1::AffectedPackage {
            project_text: "~/dev/shop".to_string(),
            package_text: "p".to_string(),
            record: Some(v1::PackageRecord {
                id_text: format!("ID-{label}"),
                label: label.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                affected_records: 4,
                projects_not_read: 1,
                ..Default::default()
            }),
            affected: Some(v1::AffectedPackages {
                items: ["malicious", "critical", "high", "moderate"]
                    .map(item)
                    .to_vec(),
                total: 4,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m, &screen);
        assert!(text.contains("\u{1b}[31mmalicious\u{1b}[0m"), "{text}");
        assert!(text.contains("\u{1b}[31mcritical\u{1b}[0m"), "{text}");
        assert!(text.contains("\u{1b}[33mhigh\u{1b}[0m"), "{text}");
        assert!(text.contains("    moderate "), "{text}");
        // What was not read is yellow in the opening counts; a zero is plain.
        assert!(
            text.contains("\u{1b}[33m1 not wholly read\u{1b}[0m"),
            "{text}"
        );
        assert!(text.contains(" · 0 with no lockfile\n"), "{text}");
    }

    #[test]
    fn past_the_first_readings_not_full_the_rest_are_counted() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.coverage = (0..10)
            .map(|i| reading(&format!("kind {i}"), v1::Completeness::Partial, Some("z")))
            .collect();
        let text = known(&k, &Screen::pipe());
        assert!(text.contains("kind 7: in part, z"), "{text}");
        assert!(!text.contains("kind 8:"), "{text}");
        assert!(text.contains("    … 2 more not full\n"), "{text}");
    }

    #[test]
    fn on_a_terminal_a_long_name_is_cut_in_the_middle_and_the_time_stays_on_the_first_line() {
        let long = format!("~/dev/{}end", "a-long-folder-name/".repeat(5));
        let mut k = project(&long, v1::Presence::Held, true);
        k.parts = vec![v1::Entity {
            id_text: format!(
                "file:machine:example-host/elsewhere/{}x.json",
                "n/".repeat(30)
            ),
            r#type: "file".to_string(),
        }];
        let screen = Screen::terminal(80, false);
        let text = known(&k, &screen);
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("Project  ~/dev/a-long") && first.contains('…'),
            "{text}"
        );
        assert!(first.contains("end ") && first.ends_with(" ago"), "{text}");
        let files = text
            .lines()
            .find(|l| l.contains("1: ~/elsewhere/n/n/"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(files.contains('…') && files.ends_with("x.json"), "{text}");
        // In a pipe, whole.
        let text = known(&k, &Screen::pipe());
        assert!(
            text.contains(&long) && text.contains("n/n/n/n/n/x.json"),
            "{text}"
        );
    }

    #[test]
    fn up_to_three_ids_of_a_rule_are_listed_and_answered_ones_are_counted_by_state() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        k.findings = (1..=3)
            .map(|i| finding(&format!("f000000000{i}"), "x.y", v1::Level::Low, false))
            .collect();
        for i in 4..=5 {
            k.findings.push(v1::FindingRef {
                state: v1::FindingState::Seen as i32,
                ..finding(&format!("f000000000{i}"), "x.y", v1::Level::Low, false)
            });
        }
        let text = known(&k, &Screen::pipe());
        assert!(
            text.contains("f0000000001, f0000000002, f0000000003\n"),
            "{text}"
        );
        assert!(text.contains("Not open   2 seen"), "{text}");
    }

    #[test]
    fn what_this_version_has_no_reader_for_is_said_with_the_reason() {
        let mut k = project("~/dev/shop", v1::Presence::Held, true);
        let mut c = reading(
            "lockfile dependencies",
            v1::Completeness::Partial,
            Some("one was skipped"),
        );
        c.lacks = vec![
            v1::Lack {
                what: "lockfile kind".to_string(),
                name_text: Some("bun.lockb".to_string()),
            },
            v1::Lack {
                what: "ecosystem".to_string(),
                name_text: None,
            },
        ];
        k.coverage = vec![c];
        let text = known(&k, &Screen::pipe());
        assert!(
            text.contains(
                "in part, one was skipped; no reader for lockfile kind bun.lockb, ecosystem"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_machine_asked_by_name_is_labelled_machine_and_the_reading_by_rule_is_said_once() {
        let mut k = project("web-1", v1::Presence::Held, true);
        k.question = v1::Question::Machine as i32;
        k.coverage
            .push(asked(v1::Question::Machine, "asked by another name"));
        let text = known(&k, &Screen::pipe());
        assert!(text.starts_with("Machine  web-1"), "{text}");
        assert!(text.contains("Answered for "), "{text}");
        assert_eq!(text.matches("asked by another name").count(), 1, "{text}");
        // A reading that was observed is never the one made by rule, whatever its reader.
        let mut observed = asked(v1::Question::Machine, "an observed reading");
        observed.observed_at = Some(1_794_800_000);
        k.coverage = vec![observed];
        let text = known(&k, &Screen::pipe());
        assert!(!text.contains("Answered for"), "{text}");
        assert!(text.contains("an observed reading"), "{text}");
    }
}
