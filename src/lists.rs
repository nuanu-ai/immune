//! The text for a person of `immunity matches`, `immunity rules` (with `--all` and `--over-log`),
//! `immunity servers` and `immunity owner` with its statements, for a screen (`screen.rs`), in the
//! layout of the core's language for a person (`docs/how-it-works.md`): the answer first, in one
//! line with the count that matters; then what the person came for, grouped where rows would
//! repeat; then context, one labelled line each; last, the next command after `→`. The text of a
//! command of the contract is rendered from its message alone; `immunity servers` is not one, and
//! renders what it read (`Servers`).
//!
//! Text from a source (a published rule's title, a server's name, a path, a program, a reason a
//! person or an agent gave) is in a message's `_text` fields, already escaped one to one
//! (`known::whole`), and is escaped again as it reaches the screen, before it is measured, cut,
//! wrapped or styled (`screen.rs`). No line begins with it: a line that holds it begins with
//! Immunity Core's own words or with spaces, so it can never pass for a line of Immunity Core's own (`✓`,
//! `→ immunity …`). In a column or beside a label it is data by its place and goes without quotes;
//! inside a sentence it keeps them (`text::quoted`).
//!
//! Nothing here is calmer than the message: what was lost and what is not evaluated is in the
//! default text whenever the message holds it, in words, and never dim.

use crate::contract::v1;
use crate::findings::SHORT_MAX;
use crate::screen::{
    self, BOLD, CYAN, Cell, Column, Cut, DIM, GREEN, PLAIN, RED, Screen, Style, YELLOW,
};
use crate::text::{quoted, word};
use crate::view;
use std::collections::BTreeMap;

/// `n one` or `n many`, with thousands grouped.
fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
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

/// A first line that may hold text from a source: escaped, then broken to the width, every line
/// after the first indented by two, so that nothing from a source ever begins a line.
fn opening(screen: &Screen, text: &str, style: Style) -> Vec<String> {
    let text = view::shown(text);
    let Some(width) = screen.fits() else {
        return vec![screen.paint(style, &text)];
    };
    let lines = screen::wrap(&text, Some(width));
    let first = lines[0].clone();
    let rest = text
        .strip_prefix(first.as_str())
        .map(|r| r.trim_start_matches(' ').to_string())
        .unwrap_or_else(|| lines[1..].join(" "));
    let mut out = vec![screen.paint(style, &first)];
    if !rest.is_empty() {
        for l in screen::wrap(&rest, Some(width.saturating_sub(2))) {
            out.push(format!("  {}", screen.paint(style, &l)));
        }
    }
    out
}

/// A sentence of Immunity Core's own under a first line, indented by two and broken to the width.
fn under(screen: &Screen, text: &str, style: Style) -> Vec<String> {
    let text = view::shown(text);
    screen::wrap(&text, screen.fits().map(|w| w.saturating_sub(2)))
        .into_iter()
        .map(|l| format!("  {}", screen.paint(style, &l)))
        .collect()
}

/// A published rule's level: its rank, the most severe highest, its word and its style. A rule of
/// a set that states no level ranks below every level, as a group of its own; a level this build
/// does not know ranks as the highest, as the contract says.
fn rule_level(level: i32) -> (u8, String, Style) {
    match v1::Level::try_from(level) {
        Ok(v1::Level::Critical) => (5, "critical".into(), RED),
        Ok(v1::Level::High) => (4, "high".into(), YELLOW),
        Ok(v1::Level::Medium) => (3, "medium".into(), PLAIN),
        Ok(v1::Level::Low) => (2, "low".into(), PLAIN),
        Ok(v1::Level::Informational) => (1, "informational".into(), PLAIN),
        // In a column headed "Level": the set states none.
        Ok(v1::Level::NotStated) => (0, "not stated".into(), PLAIN),
        _ => (6, "not known".into(), RED),
    }
}

/// A published rule's title in a list: on a terminal cut to the length of a short title, in a pipe
/// whole. Its own title is source text, escaped before it is cut. Rules of different sets can
/// share a title: where another rule of the same listing (`among`) has this one's title, its set
/// follows in words, so the two are told apart.
fn title(screen: &Screen, rule: &v1::Rule, among: &[&v1::Rule]) -> String {
    let own = if screen.terminal {
        screen::cut_end(&view::shown(&rule.title_text), SHORT_MAX)
    } else {
        rule.title_text.clone()
    };
    if among
        .iter()
        .any(|o| o.title_text == rule.title_text && o.set != rule.set)
    {
        format!("{own} ({})", rule.set)
    } else {
        own
    }
}

/// Why a rule is not evaluated, in words: one rule, and many.
fn reason_words(reason: i32) -> (&'static str, &'static str) {
    use v1::UnevaluatedReason as R;
    match R::try_from(reason) {
        Ok(R::NeedsEvents) => (
            "needs events this version does not collect",
            "need events this version does not collect",
        ),
        Ok(R::NeedsFields) => (
            "needs fields the events do not give",
            "need fields the events do not give",
        ),
        Ok(R::KeywordSearch) => (
            "searches whole messages for keywords",
            "search whole messages for keywords",
        ),
        Ok(R::NotParsed) => ("could not be read", "could not be read"),
        Ok(R::InPart) => ("is evaluated only in part", "are evaluated only in part"),
        Ok(R::NotCollected) => (
            "needs what the collector here does not record",
            "need what the collector here does not record",
        ),
        Ok(R::Sequence) => (
            "correlates a sequence of events",
            "correlate a sequence of events",
        ),
        Ok(R::NotEql) => (
            "is not written in EQL, the language translated",
            "are not written in EQL, the language translated",
        ),
        Ok(R::BackslashInWildcard) => (
            "has a backslash in a wildcard pattern",
            "have a backslash in a wildcard pattern",
        ),
        Ok(R::SpansKinds) => (
            "is about program starts and file events at once",
            "are about program starts and file events at once",
        ),
        Ok(R::NeverTrue) => (
            "could never be true over the events here",
            "could never be true over the events here",
        ),
        Ok(R::Regex) => (
            "needs a regular expression of EQL's",
            "need a regular expression of EQL's",
        ),
        Ok(R::Unsupported) => (
            "uses a function of EQL's that is not translated",
            "use a function of EQL's that is not translated",
        ),
        Ok(R::Function) => (
            "compares one field with another",
            "compare one field with another",
        ),
        _ => (
            "is not evaluated for a reason this version does not name",
            "are not evaluated for a reason this version does not name",
        ),
    }
}

/// Counts by reason, the most first, each with its words for that count.
fn by_reason(reasons: impl Iterator<Item = i32>) -> Vec<(u64, &'static str)> {
    let mut counted: BTreeMap<(&'static str, &'static str), u64> = BTreeMap::new();
    for r in reasons {
        *counted.entry(reason_words(r)).or_default() += 1;
    }
    let mut out: Vec<(u64, &'static str)> = counted
        .into_iter()
        .map(|((one, many), n)| (n, if n == 1 { one } else { many }))
        .collect();
    out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    out
}

// ---- `immunity matches` ----

/// The reasons rules are not evaluated that the text of `immunity matches` names; the rest are
/// counted.
const REASONS_SHOWN: usize = 3;

/// What became of a match among the response layer's verdicts: suspicious when any said so,
/// harmless when all that were given did, nothing when none was given.
fn verdict_of(m: &v1::RuleMatch) -> Option<&'static str> {
    let v = m.verdicts.as_ref()?;
    if v.suspicious > 0 {
        Some("suspicious")
    } else if v.total > 0 {
        Some("harmless")
    } else {
        None
    }
}

/// The verdicts of a group of matches, in a cell: the word for one match, counts for several.
fn verdicts_cell(matches: &[&v1::RuleMatch]) -> Cell {
    let kinds: Vec<&str> = matches.iter().filter_map(|m| verdict_of(m)).collect();
    let suspicious = kinds.iter().filter(|k| **k == "suspicious").count() as u64;
    let harmless = kinds.len() as u64 - suspicious;
    let style = if suspicious > 0 { RED } else { PLAIN };
    let text = match (matches.len(), suspicious, harmless) {
        (_, 0, 0) => String::new(),
        (1, _, _) => kinds[0].to_string(),
        (_, s, 0) => format!("{} suspicious", grouped(s)),
        (_, 0, h) => format!("{} harmless", grouped(h)),
        (_, s, h) => format!("{} suspicious, {} harmless", grouped(s), grouped(h)),
    };
    Cell::new(text, style)
}

/// When the event of a match happened, in seconds since the epoch, where the log says.
fn happened(m: &v1::RuleMatch) -> Option<i64> {
    use v1::event::Body;
    match m.event.as_ref()?.body.as_ref()? {
        Body::ProgramStart(s) => s.happened_at,
        Body::FileEvent(f) => f.happened_at,
    }
}

/// The program that acted: the one started, or the one that made or renamed the file.
fn program(m: &v1::RuleMatch) -> String {
    use v1::event::Body;
    let p = match m.event.as_ref().and_then(|e| e.body.as_ref()) {
        Some(Body::ProgramStart(s)) => s.process.as_ref(),
        Some(Body::FileEvent(f)) => f.instigator.as_ref(),
        None => None,
    };
    p.map_or_else(|| "not known".to_string(), |p| p.executable_text.clone())
}

/// What was lost of what the stretch should hold, in a person's words; empty when nothing was.
fn lost_said(s: &v1::Stretch) -> Vec<String> {
    let mut said = Vec::new();
    if s.program_starts_lost > 0 {
        said.push(format!(
            "{} not recorded by the collector",
            count(
                s.program_starts_lost,
                "program start was",
                "program starts were"
            )
        ));
    }
    if s.file_events_lost > 0 {
        said.push(format!(
            "{} not recorded by the collector",
            count(s.file_events_lost, "file event was", "file events were")
        ));
    }
    let restarts = s.program_starts_unknown_losses + s.file_events_unknown_losses;
    if restarts > 0 {
        said.push(format!(
            "it restarted {}, losing an unknown number of events",
            match restarts {
                1 => "once".to_string(),
                n => format!("{} times", grouped(n)),
            }
        ));
    }
    if s.unreadable_lines > 0 {
        said.push(format!(
            "{} not be read",
            count(s.unreadable_lines, "line could", "lines could")
        ));
    }
    if s.unreadable_file_events > 0 {
        said.push(format!(
            "{} not be made out",
            count(
                s.unreadable_file_events,
                "file event could",
                "file events could"
            )
        ));
    }
    if s.gone {
        said.push(
            "lines were deleted before they were read, and nothing in them was evaluated"
                .to_string(),
        );
    }
    said
}

/// A collector's state in words; one this version does not know said as such.
fn collector_word(state: i32) -> String {
    match v1::CollectorState::try_from(state) {
        Ok(v1::CollectorState::Unspecified) | Err(_) => {
            "in a state this version cannot judge".to_string()
        }
        Ok(_) => words::<v1::CollectorState>(state),
    }
}

/// The collector's state in words and its style, with what else this answer says of it.
fn collector_said(screen: &Screen, c: &v1::Collector, now: i64) -> Vec<(String, Style)> {
    use v1::CollectorState as S;
    let wrote = c
        .written_at
        .map(|at| format!(", last wrote {}", screen.time(at, now)));
    let mut parts: Vec<(String, Style)> = vec![match S::try_from(c.state) {
        Ok(S::Running) => (
            format!("running{}", wrote.clone().unwrap_or_default()),
            PLAIN,
        ),
        Ok(S::NotInstalled) => ("not installed, so nothing is recorded".to_string(), YELLOW),
        Ok(S::Refused) => (
            "refused: macOS does not give eslogger Full Disk Access".to_string(),
            RED,
        ),
        Ok(S::Failing) => ("failing: its scripts print errors".to_string(), RED),
        Ok(S::Silent) => (
            format!(
                "silent: nothing was written for 15 minutes{}",
                wrote.clone().unwrap_or_default()
            ),
            RED,
        ),
        _ => (collector_word(c.state), RED),
    }];
    if let Some(said) = &c.said_text {
        parts.push((
            format!(
                "; {} said {}",
                c.said_by.as_deref().unwrap_or("it"),
                quoted(said)
            ),
            RED,
        ));
    }
    if c.state == S::Running as i32 && !c.file_events_collected {
        parts.push((
            "; it records program starts, not file events".to_string(),
            YELLOW,
        ));
    }
    for a in &c.no_longer_arriving {
        parts.push((
            format!(
                "; {} has not arrived {}",
                a.name,
                screen.since(a.since, now)
            ),
            YELLOW,
        ));
    }
    if c.foreign_files > 0 {
        parts.push((
            format!(
                "; {} in its folder not its own, and not read",
                count(c.foreign_files, "file is", "files are")
            ),
            YELLOW,
        ));
    }
    if let Some(state) = c.status_state.filter(|s| *s != c.state) {
        parts.push((
            format!(
                "; immunity status, from its reading {}, says {}",
                c.status_read_at
                    .map_or("at a time it does not give".to_string(), |at| screen
                        .time(at, now)),
                collector_word(state)
            ),
            PLAIN,
        ));
    }
    parts
}

/// `immunity matches` for a person: the matches grouped by rule, or with `single` one row each;
/// then what was read and lost, the collector and the rules not evaluated, from the message
/// alone.
pub fn matches(m: &v1::Matches, single: bool, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let now = m.answered_at;
    let n = m.matches.len() as u64;
    let rank = |r: &v1::RuleMatch| rule_level(r.rule.as_ref().map_or(0, |x| x.level)).0;
    let high = m.matches.iter().filter(|r| rank(r) >= 4).count() as u64;
    let critical = m.matches.iter().any(|r| rank(r) == 5);
    let span = if m.after.is_some() {
        "after the place given"
    } else {
        "in the last day"
    };
    let s = m.stretch.clone().unwrap_or_default();
    let c = m.collector.clone().unwrap_or_default();
    let lost = lost_said(&s);
    let quiet = c.state == v1::CollectorState::Running as i32
        && lost.is_empty()
        && c.file_events_collected
        && m.unevaluated.is_empty();
    let answer = match (n, high) {
        (0, _) => format!("No rule matched {span}"),
        (_, 0) => format!("{} {span}", count(n, "rule match", "rule matches")),
        (_, h) => format!(
            "{} {span}, {} of them of a {} level",
            count(n, "rule match", "rule matches"),
            grouped(h),
            if critical { "high or critical" } else { "high" }
        ),
    };
    let right = c
        .written_at
        .map(|at| format!("log written {}", screen.time(at, now)));
    match (n, quiet) {
        (0, true) => {
            out.extend(screen.headline(&format!("✓ {answer}"), GREEN.bold(), right.as_deref()))
        }
        _ => out.extend(screen.headline(&answer, BOLD, right.as_deref())),
    }
    if n > 0 {
        out.push(String::new());
        if single {
            out.extend(single_rows(m, screen));
        } else {
            out.extend(grouped_rows(m, screen));
        }
    }
    if m.more {
        out.push(String::new());
        out.extend(under(
            screen,
            "More are left past the limit of this answer; --json gives the place to read on from.",
            PLAIN,
        ));
    }
    // Context: what was read and lost, the collector, and what the rules cannot judge.
    out.push(String::new());
    let label = 10;
    let read = format!(
        "{} and {}",
        count(s.program_starts, "program start", "program starts"),
        count(s.file_events, "file event", "file events")
    );
    out.extend(screen.labelled(2, label, "Read", &read, PLAIN, None, 0));
    let lost_value = if lost.is_empty() {
        ("nothing".to_string(), PLAIN)
    } else {
        (lost.join("; "), YELLOW)
    };
    out.extend(screen.labelled(2, label, "Lost", &lost_value.0, lost_value.1, None, 0));
    let parts = collector_said(screen, &c, now);
    let parts: Vec<(&str, Style)> = parts.iter().map(|(t, s)| (t.as_str(), *s)).collect();
    out.extend(screen.labelled_parts(2, label, "Collector", &parts, None, 0));
    if !m.unevaluated.is_empty() {
        let in_part = m
            .unevaluated
            .iter()
            .filter(|u| u.reason == v1::UnevaluatedReason::InPart as i32)
            .count() as u64;
        let not = m.unevaluated.len() as u64 - in_part;
        let in_part_reason = v1::UnevaluatedReason::InPart as i32;
        let reasons = by_reason(
            m.unevaluated
                .iter()
                .map(|u| u.reason)
                .filter(|r| *r != in_part_reason),
        );
        // The three reasons that count most; the rest are counted, and `immunity rules` names them.
        let mut said: Vec<String> = reasons
            .iter()
            .take(REASONS_SHOWN)
            .map(|(n, w)| format!("{} {w}", grouped(*n)))
            .collect();
        let rest = reasons.len().saturating_sub(REASONS_SHOWN) as u64;
        if rest > 0 {
            said.push(count(rest, "other reason", "other reasons"));
        }
        let value = format!(
            "{} not evaluated and {} only in part: {}",
            count(not, "rule is", "rules are"),
            grouped(in_part),
            said.join(", ")
        );
        out.extend(screen.labelled(2, label, "Not judged", &value, PLAIN, None, 0));
    }
    out.push(String::new());
    let mut next = vec![(
        "immunity matches --json",
        "every match with its event, for a program",
    )];
    if !m.unevaluated.is_empty() {
        next.push(("immunity rules", "every reason a rule is not evaluated"));
    }
    out.extend(screen.nexts(&next));
    joined(&out)
}

/// The matches grouped by rule: the most severe level first, then the most matches.
fn grouped_rows(m: &v1::Matches, screen: &Screen) -> Vec<String> {
    let mut groups: Vec<(&v1::Rule, Vec<&v1::RuleMatch>)> = Vec::new();
    let none = v1::Rule::default();
    for r in &m.matches {
        let rule = r.rule.as_ref().unwrap_or(&none);
        match groups.iter_mut().find(|(g, _)| g.name == rule.name) {
            Some((_, list)) => list.push(r),
            None => groups.push((rule, vec![r])),
        }
    }
    groups.sort_by(|a, b| {
        rule_level(b.0.level)
            .0
            .cmp(&rule_level(a.0.level).0)
            .then(b.1.len().cmp(&a.1.len()))
            .then(a.0.title_text.cmp(&b.0.title_text))
    });
    let among: Vec<&v1::Rule> = groups.iter().map(|(r, _)| *r).collect();
    let rows: Vec<Vec<Cell>> = groups
        .iter()
        .map(|(rule, list)| {
            let (_, word, style) = rule_level(rule.level);
            let last = list.iter().filter_map(|r| happened(r)).max();
            vec![
                Cell::new(word, style),
                Cell::plain(title(screen, rule, &among)),
                Cell::new(grouped(list.len() as u64), BOLD),
                Cell::new(
                    last.map_or("not known".to_string(), |at| screen.time(at, m.answered_at)),
                    DIM,
                ),
                verdicts_cell(list),
            ]
        })
        .collect();
    let cols = [
        Column::new(Cut::Never),
        Column::new(Cut::End),
        Column::right(Cut::Never),
        Column::new(Cut::Never),
        Column::new(Cut::Never),
    ];
    let head = ["Level", "Rule", "Matches", "Last", "Verdict"];
    screen.table(2, &cols, Some(&head), &rows)
}

/// Every match one row, in the order of the log: when, the rule, its level and the program that
/// acted.
fn single_rows(m: &v1::Matches, screen: &Screen) -> Vec<String> {
    let none = v1::Rule::default();
    let among: Vec<&v1::Rule> = m.matches.iter().filter_map(|r| r.rule.as_ref()).collect();
    let rows: Vec<Vec<Cell>> = m
        .matches
        .iter()
        .map(|r| {
            let rule = r.rule.as_ref().unwrap_or(&none);
            let (_, word, style) = rule_level(rule.level);
            vec![
                Cell::new(
                    happened(r)
                        .map_or("not known".to_string(), |at| screen.time(at, m.answered_at)),
                    DIM,
                ),
                Cell::new(word, style),
                Cell::plain(title(screen, rule, &among)),
                Cell::plain(program(r)),
                verdicts_cell(&[r]),
            ]
        })
        .collect();
    let cols = [
        Column::new(Cut::Never),
        Column::new(Cut::Never),
        Column::new(Cut::End),
        Column::new(Cut::Middle),
        Column::new(Cut::Never),
    ];
    let head = ["When", "Level", "Rule", "Program", "Verdict"];
    screen.table(2, &cols, Some(&head), &rows)
}

// ---- `immunity rules` ----

/// Whether every source is a published set: a set of Immunity Core's own records no commit.
fn all_published(m: &v1::Rules) -> bool {
    m.sources.iter().all(|s| !s.commit.is_empty())
}

/// The first line of `immunity rules`: how many rules are evaluated in full, in part and not.
fn rules_answer(m: &v1::Rules) -> String {
    let t = m.totals.unwrap_or_default();
    let (one, many) = if all_published(m) {
        ("published rule", "published rules")
    } else {
        ("rule", "rules")
    };
    format!(
        "Immunity Core evaluates {} in full and {} in part; {} it cannot yet",
        count(t.evaluated, one, many),
        grouped(t.in_part),
        grouped(t.not_evaluated)
    )
}

/// What the rules do on this Mac now, in words, and its style.
fn watching_said(r: &v1::RulesNow) -> (String, Style) {
    match (r.watching, r.watching_rules) {
        (None, _) => (
            "whether the event level is on is not known yet: it has not been read, so no rule is known to watch".to_string(),
            YELLOW,
        ),
        (Some(true), Some(n)) => {
            let files = r.watching_file_rules.unwrap_or(0);
            let mut s = format!(
                "{} this Mac: {} every program start and {} every file created or renamed; {} more in part",
                count(n, "rule watches", "rules watch"),
                grouped(n.saturating_sub(files)),
                grouped(files),
                grouped(r.in_part)
            );
            if r.file_events_collected != Some(true) {
                s.push_str(&format!(
                    "; {} not watching, since the collector here records program starts only",
                    count(r.file_rules, "rule for files is", "rules for files are")
                ));
            }
            (s, PLAIN)
        }
        _ => (
            "the event level is not on, so no rule is watching".to_string(),
            YELLOW,
        ),
    }
}

/// What the rules could not judge over the last day, as the core says it (`judged_note`), on a
/// line of its own beside its label, in the colour of a warning: `Lost` when some events were
/// not read, `Not running` when the event level is not running. None when everything was judged.
fn judged_said(r: &v1::RulesNow) -> Option<(&'static str, String)> {
    let note = r.judged_note.as_deref()?;
    let label = if r.judged == v1::Judged::Part as i32 {
        "Lost"
    } else {
        "Not running"
    };
    // A value beside a label, as the others: no capital, no full stop.
    let mut said = note.trim_end_matches('.').to_string();
    if let Some(first) = said.get(..1) {
        let lower = first.to_lowercase();
        said.replace_range(..1, &lower);
    }
    Some((label, said))
}

/// The matches of the last day as the message counts them: how many, then the rules that matched,
/// the most first, by title and count, a rule this build does not ship by its id and said so, and
/// how many more rules matched than the message lists; or why it is not known. Every number is the
/// message's own, never a sum over a part of it.
fn matched_said(screen: &Screen, m: &v1::Rules) -> (String, Style) {
    let now = m.now.clone().unwrap_or_default();
    let Some(matches) = now.matches_last_day else {
        let why = m
            .not_computed
            .iter()
            .find(|n| n.section == "matches")
            .map_or("no reading of the event level yet", |n| n.reason.as_str());
        return (format!("not known: {why}"), YELLOW);
    };
    if matches == 0 && now.matched_last_day.is_empty() {
        return ("nothing".to_string(), PLAIN);
    }
    let among: Vec<&v1::Rule> = now
        .matched_last_day
        .iter()
        .filter_map(|r| r.rule.as_ref())
        .collect();
    let mut said: Vec<String> = now
        .matched_last_day
        .iter()
        .map(|r| match &r.rule {
            Some(rule) => format!("{} {}", title(screen, rule, &among), grouped(r.matches)),
            None => format!("{} {}, not in this build", r.id_text, grouped(r.matches)),
        })
        .collect();
    let rules = now
        .matched_last_day_total
        .unwrap_or(now.matched_last_day.len() as u64);
    let more = rules.saturating_sub(now.matched_last_day.len() as u64);
    if more > 0 {
        let rules = if more == 1 { "rule" } else { "rules" };
        said.push(format!("and {} more {rules}", grouped(more)));
    }
    let head = count(matches, "match", "matches");
    (format!("{head}: {}", said.join(", ")), PLAIN)
}

/// The drill: how many of its invented program starts raise the rule it names.
fn drill_said(m: &v1::Rules) -> Option<String> {
    let first = m.drill.first()?;
    let raised = m.drill.iter().filter(|d| d.raised).count();
    let title = m
        .evaluated
        .iter()
        .chain(&m.in_part)
        .filter_map(|r| r.rule.as_ref())
        .find(|r| r.id_text == first.must_raise)
        .map_or(first.must_raise.clone(), |r| r.title_text.clone());
    Some(format!(
        "Atomic Red Team T1027.001: {raised} of {} program starts raise {title}",
        m.drill.len()
    ))
}

/// A rule's state in the full list, its style, and why: in full; in part, with what never
/// matches; or not evaluated, with the reason.
fn state_said(r: &v1::ShippedRule, part: Part) -> (&'static str, Style, String) {
    let given_by = match r.events.as_deref() {
        Some(crate::sigma::FILE_CATEGORY) => "a file event",
        _ => "a program start",
    };
    match part {
        Part::Full => ("in full", GREEN, String::new()),
        Part::Partly => {
            let said: Vec<String> = r
                .never_matches
                .iter()
                .map(|b| match (&b.selection_text, b.fields_text.is_empty()) {
                    (Some(sel), _) => format!(
                        "{sel} needs {}, which {given_by} does not give",
                        b.fields_text.join(", ")
                    ),
                    (None, false) => format!(
                        "an alternative needs {}, which {given_by} does not give",
                        b.fields_text.join(", ")
                    ),
                    (None, true) => format!(
                        "an alternative was left out in translation: {}",
                        translated(b.left_out_text.as_deref().unwrap_or(""))
                    ),
                })
                .collect();
            ("in part", YELLOW, said.join("; "))
        }
        Part::Not => {
            let mut said = reason_words(r.reason.unwrap_or(0)).0.to_string();
            // What the translation said repeats the fields when it names them.
            let translation = r
                .detail_text
                .as_deref()
                .filter(|_| r.fields_text.is_empty())
                .map(translated);
            let detail: Vec<&str> = [r.events_text.as_deref(), r.said_text.as_deref()]
                .into_iter()
                .flatten()
                .chain(r.fields_text.iter().map(String::as_str))
                .chain(translation.as_deref())
                .collect();
            if !detail.is_empty() {
                said.push_str(&format!(" ({})", detail.join(", ")));
            }
            let said = match said.strip_prefix("is not evaluated ") {
                Some(rest) => rest.to_string(),
                None => said,
            };
            ("not evaluated", PLAIN, said)
        }
    }
}

/// What a translation said of a rule, its reasons in words: a piece that begins with a reason's
/// name of more than one word, as `needs_fields process.parent.name`, begins with the reason's
/// words instead. A name of one word reads as a word already.
fn translated(said: &str) -> String {
    said.split("; ")
        .map(|piece| {
            let (head, rest) = piece.split_once(' ').unwrap_or((piece, ""));
            let reason = (1..=14)
                .filter(|_| head.contains('_'))
                .find(|r| word::<v1::UnevaluatedReason>(*r) == head);
            match reason {
                Some(r) if rest.is_empty() => reason_words(r).0.to_string(),
                Some(r) => format!("{}: {rest}", reason_words(r).0),
                None => piece.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Clone, Copy)]
enum Part {
    Full,
    Partly,
    Not,
}

/// `immunity rules` for a person: the summary, or with `all` every rule one per line.
pub fn rules(m: &v1::Rules, all: bool, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    out.extend(screen.headline(&rules_answer(m), BOLD, None));
    out.push(String::new());
    if all {
        out.extend(every_rule(m, screen));
        out.push(String::new());
        out.push(screen.next("immunity rules", "the summary"));
        return joined(&out);
    }
    let rows: Vec<Vec<Cell>> = m
        .sources
        .iter()
        .map(|s| {
            let t = s.totals.unwrap_or_default();
            vec![
                Cell::plain(s.set.clone()),
                Cell::plain(grouped(t.evaluated)),
                Cell::plain(grouped(t.in_part)),
                Cell::plain(grouped(t.not_evaluated)),
            ]
        })
        .collect();
    out.extend(screen.table(
        2,
        &[
            Column::new(Cut::End),
            Column::right(Cut::Never),
            Column::right(Cut::Never),
            Column::right(Cut::Never),
        ],
        Some(&["Source", "In full", "In part", "Not evaluated"]),
        &rows,
    ));
    out.push(String::new());
    let label = 23;
    let now = m.now.clone().unwrap_or_default();
    let (watching, style) = watching_said(&now);
    out.extend(screen.labelled(2, label, "Watching", &watching, style, None, 0));
    if let Some((what, said)) = judged_said(&now) {
        out.extend(screen.labelled(2, label, what, &said, YELLOW, None, 0));
    }
    let (matched, style) = matched_said(screen, m);
    out.extend(screen.labelled(
        2,
        label,
        "Matched in the last day",
        &matched,
        style,
        None,
        0,
    ));
    let silent: Vec<&str> = m
        .sources
        .iter()
        .filter(|s| !s.states_levels)
        .map(|s| s.set.as_str())
        .collect();
    if !silent.is_empty() {
        out.extend(screen.labelled(
            2,
            label,
            "No level stated",
            &format!(
                "{} state no level, so a match of theirs raises no finding by itself",
                silent.join(" and ")
            ),
            PLAIN,
            None,
            0,
        ));
    }
    if let Some(drill) = drill_said(m) {
        out.extend(screen.labelled(2, label, "Drill", &drill, PLAIN, None, 0));
    }
    if !m.not_evaluated.is_empty() {
        out.push(String::new());
        out.push(screen.paint(BOLD, "Not evaluated, by reason"));
        let rows: Vec<Vec<Cell>> = by_reason(m.not_evaluated.iter().map(|r| r.reason.unwrap_or(0)))
            .into_iter()
            .map(|(n, w)| vec![Cell::new(grouped(n), BOLD), Cell::plain(w)])
            .collect();
        out.extend(screen.table(
            2,
            &[Column::right(Cut::Never), Column::new(Cut::End)],
            None,
            &rows,
        ));
    }
    out.push(String::new());
    out.extend(screen.nexts(&[
        ("immunity rules --all", "every rule, one per line"),
        ("immunity rules --over-log", "what matched in the event log"),
    ]));
    joined(&out)
}

/// Every rule one per line: evaluated in full, in part, then not, each in the message's order.
fn every_rule(m: &v1::Rules, screen: &Screen) -> Vec<String> {
    let parts = [
        (Part::Full, &m.evaluated),
        (Part::Partly, &m.in_part),
        (Part::Not, &m.not_evaluated),
    ];
    let among: Vec<&v1::Rule> = parts
        .iter()
        .flat_map(|(_, list)| list.iter().filter_map(|r| r.rule.as_ref()))
        .collect();
    let rows: Vec<Vec<Cell>> = parts
        .iter()
        .flat_map(|(part, list)| list.iter().map(move |r| (*part, r)))
        .map(|(part, r)| {
            let (level, style) = r
                .rule
                .as_ref()
                .map_or(("not known".to_string(), RED), |rule| {
                    let (_, w, s) = rule_level(rule.level);
                    (w, s)
                });
            let name = r
                .rule
                .as_ref()
                .map_or(r.file.clone(), |rule| title(screen, rule, &among));
            let (state, state_style, why) = state_said(r, part);
            vec![
                Cell::new(level, style),
                Cell::plain(name),
                Cell::new(
                    r.matches_last_day
                        .filter(|n| *n > 0)
                        .map(grouped)
                        .unwrap_or_default(),
                    BOLD,
                ),
                Cell::new(state, state_style),
                Cell::plain(why),
            ]
        })
        .collect();
    screen.table(
        2,
        &[
            Column::new(Cut::Never),
            Column::new(Cut::End),
            Column::right(Cut::Never),
            Column::new(Cut::Never),
            Column::new(Cut::End).giving(1),
        ],
        Some(&["Level", "Rule", "Last day", "State", "Why"]),
        &rows,
    )
}

/// `immunity rules --over-log` for a person: per rule that matched, its level and count; what was
/// read and lost; never a command line.
pub fn replay(m: &v1::Replay, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    if m.outcome != v1::ReplayOutcome::Read as i32 {
        out.extend(screen.headline(
            "The event level is not installed here, so there is no log to replay.",
            BOLD,
            None,
        ));
        return joined(&out);
    }
    let total = m.matches_total.unwrap_or_default();
    let answer = match total {
        0 => "The rules matched nothing in the event log on disk".to_string(),
        n => format!(
            "The rules matched {} in the event log on disk",
            count(n, "time", "times")
        ),
    };
    out.extend(screen.headline(&answer, BOLD, None));
    if !m.matched.is_empty() {
        out.push(String::new());
        let none = v1::Rule::default();
        let among: Vec<&v1::Rule> = m.matched.iter().filter_map(|h| h.rule.as_ref()).collect();
        let rows: Vec<Vec<Cell>> = m
            .matched
            .iter()
            .map(|h| {
                let rule = h.rule.as_ref().unwrap_or(&none);
                let (_, word, style) = rule_level(rule.level);
                vec![
                    Cell::new(word, style),
                    Cell::plain(title(screen, rule, &among)),
                    Cell::new(grouped(h.matches), BOLD),
                ]
            })
            .collect();
        out.extend(screen.table(
            2,
            &[
                Column::new(Cut::Never),
                Column::new(Cut::End),
                Column::right(Cut::Never),
            ],
            Some(&["Level", "Rule", "Matches"]),
            &rows,
        ));
    }
    out.push(String::new());
    let read = format!(
        "{} and {}; nothing was stored",
        count(
            m.program_starts.unwrap_or_default(),
            "program start",
            "program starts"
        ),
        count(
            m.file_events.unwrap_or_default(),
            "file event",
            "file events"
        )
    );
    out.extend(screen.labelled(2, 4, "Read", &read, PLAIN, None, 0));
    let stretch = v1::Stretch {
        program_starts_lost: m.lost.unwrap_or_default(),
        program_starts_unknown_losses: m.unknown_losses.unwrap_or_default(),
        file_events_lost: m.file_events_lost.unwrap_or_default(),
        unreadable_lines: m.unreadable_lines.unwrap_or_default(),
        unreadable_file_events: m.unreadable_file_events.unwrap_or_default(),
        ..Default::default()
    };
    let lost = lost_said(&stretch);
    let (value, style) = if lost.is_empty() {
        ("nothing".to_string(), PLAIN)
    } else {
        (lost.join("; "), YELLOW)
    };
    out.extend(screen.labelled(2, 4, "Lost", &value, style, None, 0));
    joined(&out)
}

// ---- `immunity owner` ----

/// Through what a statement came, in a word, and its style: one an agent made stands out, so the
/// person can take it back.
fn via_said(via: i32) -> (&'static str, Style) {
    match v1::Via::try_from(via) {
        Ok(v1::Via::App) => ("the app", PLAIN),
        Ok(v1::Via::Agent) => ("your agent", YELLOW),
        Ok(v1::Via::Command) => ("command line", PLAIN),
        _ => ("not recorded", YELLOW),
    }
}

/// `immunity owner` for a person: the statements that stand, and what contradicts them.
pub fn statements(m: &v1::Statements, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let n = m.statements.len() as u64;
    let mut answer = match n {
        0 => "No statement stands".to_string(),
        n => count(n, "statement stands", "statements stand"),
    };
    if m.withdrawn > 0 {
        answer.push_str(&format!(
            "; {} withdrawn and kept",
            count(m.withdrawn, "was", "were")
        ));
    }
    out.extend(screen.headline(&answer, BOLD, None));
    if n > 0 {
        out.push(String::new());
        let rows: Vec<Vec<Cell>> = m
            .statements
            .iter()
            .map(|s| {
                let (via, via_style) = via_said(s.via);
                vec![
                    Cell::plain(s.machine_text.clone()),
                    Cell::plain(s.said.clone()),
                    Cell::new(via, via_style),
                    Cell::new(screen.time(s.at, m.answered_at), DIM),
                    Cell::plain(s.reason_text.clone()),
                    Cell::plain(s.names_text.join(", ")),
                ]
            })
            .collect();
        out.extend(screen.table(
            2,
            &[
                Column::new(Cut::Middle),
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End),
                Column::new(Cut::End),
            ],
            Some(&[
                "Machine",
                "Said",
                "Through",
                "Since",
                "Reason",
                "Also known as",
            ]),
            &rows,
        ));
        let seen: Vec<&v1::Statement> = m
            .statements
            .iter()
            .filter(|s| s.seen_after.is_some())
            .collect();
        if !seen.is_empty() {
            out.push(String::new());
            for s in seen {
                let e = s.seen_after.clone().unwrap_or_default();
                let value = format!(
                    "{} was seen alive after it, {}: {}",
                    s.machine_text,
                    screen.time(e.at, m.answered_at),
                    e.what_text
                );
                out.extend(screen.labelled(2, 12, "Contradicted", &value, RED, None, 0));
            }
        }
    }
    out.push(String::new());
    let mut next = Vec::new();
    if n > 0 {
        next.push(("immunity owner <name> withdraw", "takes a statement back"));
    }
    next.push((
        "immunity owner <name> retired --reason <text>",
        "sets a machine aside",
    ));
    out.extend(screen.nexts(&next));
    joined(&out)
}

/// `immunity owner <name> retired|not-mine|withdraw` for a person: what was said or withdrawn on
/// the first line, what it changed under it, and how to take it back.
pub fn statement_made(m: &v1::StatementMade, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut undo: Option<(&str, &str)> = None;
    match &m.done {
        Some(v1::statement_made::Done::Said(s)) => {
            out.extend(opening(
                screen,
                &format!("✓ Said: {} is {}", quoted(&m.machine_text), s.said),
                GREEN.bold(),
            ));
            out.extend(under(
                screen,
                &format!("Its reason: {}", quoted(&s.reason_text)),
                PLAIN,
            ));
            if !s.reason_cuts.is_empty() {
                out.extend(under(
                    screen,
                    "Its reason held what Immunity Core recognises as a secret, and is kept with it cut.",
                    PLAIN,
                ));
            }
            if s.replaced > 0 {
                out.extend(under(
                    screen,
                    "It replaces the statement that stood about the same machine, which is kept.",
                    PLAIN,
                ));
            }
            undo = Some(("immunity owner <name> withdraw", "takes it back"));
        }
        Some(v1::statement_made::Done::Withdrawn(w)) => {
            for s in &w.statements {
                out.extend(opening(
                    screen,
                    &format!(
                        "✓ Withdrawn: the statement that {} is {} no longer stands, and is kept.",
                        quoted(&s.machine_text),
                        s.said
                    ),
                    GREEN.bold(),
                ));
            }
            undo = Some((
                "immunity owner <name> retired --reason <text>",
                "says it again",
            ));
        }
        None => {}
    }
    let names: Vec<String> = m.names_text.iter().map(|n| quoted(n)).collect();
    out.extend(under(
        screen,
        &format!(
            "It covers the machine under every name: {}.",
            names.join(", ")
        ),
        PLAIN,
    ));
    match m
        .sweep
        .as_ref()
        .map(|s| (s.servers, s.problem_text.as_deref()))
    {
        Some((Some(n), _)) => out.extend(under(
            screen,
            &format!(
                "The sweep script was written again: it visits {}.",
                count(n, "server", "servers")
            ),
            PLAIN,
        )),
        Some((None, problem)) => out.extend(under(
            screen,
            &format!(
                "✗ The sweep script could not be written again: {}.",
                quoted(problem.unwrap_or_default())
            ),
            RED,
        )),
        None => {}
    }
    if let Some((command, does)) = undo {
        out.push(String::new());
        out.push(screen.next(command, does));
    }
    joined(&out)
}

// ---- `immunity servers` ----

/// A server as `immunity servers` lists it. Every name in it is already shown as a name is
/// (`known::whole`), and the reasons in `sweep` and `last_file` were cut where they were put
/// together.
pub struct Server {
    pub name: String,
    pub known_from: String,
    pub sweep: String,
    pub last_file: String,
    pub others: String,
}

/// A machine the owner set aside, as `immunity servers` lists it; names already shown as names.
pub struct SetAside {
    pub machine: String,
    pub said: String,
    pub at: i64,
    pub reason: String,
    pub others: String,
}

/// What `immunity servers` read and wrote, to be rendered: it is not a command of the contract.
pub struct Servers {
    pub offered: Vec<Server>,
    pub rest: Vec<Server>,
    pub set_aside: Vec<SetAside>,
    /// The owner's other devices: name, system, other names.
    pub own: Vec<[String; 3]>,
    /// Other users' devices: name, other names.
    pub theirs: Vec<[String; 2]>,
    /// What each source gave, a line each, in Immunity Core's words with reasons cut.
    pub said: Vec<String>,
    /// The counts, in one sentence.
    pub summary: String,
    pub owner_word: Option<String>,
    /// How many aliases of offered machines the sweep does not visit.
    pub spare: u64,
    pub never_read: u64,
    /// The folder the scripts were written to, shown as a name, and the command that runs the
    /// sweep.
    pub folder: String,
    pub sweep_command: String,
}

/// A source's line, its first letter a capital; `ssh` is written `SSH`.
fn capital(line: &str) -> String {
    if let Some(rest) = line.strip_prefix("ssh ") {
        return format!("SSH {rest}");
    }
    let mut c = line.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// `immunity servers` for a person: the servers by section, what each source gave, the counts,
/// what was written, and the commands that read the servers.
pub fn servers(s: &Servers, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let known = s.offered.len() + s.rest.len();
    out.extend(screen.headline(
        &format!(
            "{} known, {} offered for the sweep, {} never read",
            count(known as u64, "server", "servers"),
            grouped(s.offered.len() as u64),
            grouped(s.never_read)
        ),
        BOLD,
        None,
    ));
    let server_cols = [
        Column::new(Cut::Middle),
        Column::new(Cut::End),
        Column::new(Cut::End),
        Column::new(Cut::End),
        Column::new(Cut::End).giving(1),
    ];
    let section = |out: &mut Vec<String>,
                   title: String,
                   head: &[&str],
                   cols: &[Column],
                   rows: Vec<Vec<Cell>>| {
        out.push(String::new());
        out.push(screen.paint(BOLD, &title));
        if rows.is_empty() {
            out.push("  none".to_string());
        } else {
            out.extend(screen.table(2, cols, Some(head), &rows));
        }
    };
    let server_rows = |list: &[Server]| -> Vec<Vec<Cell>> {
        list.iter()
            .map(|r| {
                vec![
                    Cell::plain(r.name.clone()),
                    Cell::plain(r.known_from.clone()),
                    Cell::plain(r.sweep.clone()),
                    Cell::plain(r.last_file.clone()),
                    Cell::plain(r.others.clone()),
                ]
            })
            .collect()
    };
    let server_head = [
        "Server",
        "Known from",
        "Sweep",
        "Last file",
        "Also known as",
    ];
    section(
        &mut out,
        format!(
            "Offered for the sweep: {}",
            count(s.offered.len() as u64, "server", "servers")
        ),
        &server_head,
        &server_cols,
        server_rows(&s.offered),
    );
    section(
        &mut out,
        format!(
            "Known and not offered: {}",
            count(s.rest.len() as u64, "server", "servers")
        ),
        &server_head,
        &server_cols,
        server_rows(&s.rest),
    );
    if !s.set_aside.is_empty() {
        let rows = s
            .set_aside
            .iter()
            .map(|w| {
                vec![
                    Cell::plain(w.machine.clone()),
                    Cell::plain(w.said.clone()),
                    Cell::new(view::utc(w.at), DIM),
                    Cell::plain(w.reason.clone()),
                    Cell::plain(w.others.clone()),
                ]
            })
            .collect();
        section(
            &mut out,
            format!(
                "Retired or disowned by the owner, not counted as servers: {}",
                count(s.set_aside.len() as u64, "machine", "machines")
            ),
            &["Machine", "Said", "Since", "Reason", "Also known as"],
            &[
                Column::new(Cut::Middle),
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End).giving(1),
                Column::new(Cut::End).giving(2),
            ],
            rows,
        );
    }
    // Shown with a count, so that nothing the tailnet holds disappears silently.
    section(
        &mut out,
        format!(
            "Your other devices on the tailnet, not counted as servers: {}",
            count(s.own.len() as u64, "device", "devices")
        ),
        &["Device", "System", "Also known as"],
        &[
            Column::new(Cut::Middle),
            Column::new(Cut::End),
            Column::new(Cut::End).giving(1),
        ],
        s.own
            .iter()
            .map(|r| r.iter().map(|c| Cell::plain(c.clone())).collect())
            .collect(),
    );
    section(
        &mut out,
        format!(
            "Other users' devices on the tailnet, not counted as servers: {}",
            count(s.theirs.len() as u64, "device", "devices")
        ),
        &["Device", "Also known as"],
        &[Column::new(Cut::Middle), Column::new(Cut::End).giving(1)],
        s.theirs
            .iter()
            .map(|r| r.iter().map(|c| Cell::plain(c.clone())).collect())
            .collect(),
    );
    out.push(String::new());
    for line in &s.said {
        out.extend(under(screen, &format!("{}.", capital(line)), PLAIN));
    }
    out.extend(under(screen, &s.summary, PLAIN));
    if let Some(line) = &s.owner_word {
        out.extend(under(screen, line, PLAIN));
    }
    if s.spare > 0 {
        out.extend(under(
            screen,
            &format!(
                "The sweep visits each offered server once, through one alias; {} not visited.",
                count(
                    s.spare,
                    "alias of the same machine is",
                    "aliases of the same machines are"
                )
            ),
            PLAIN,
        ));
    }
    out.push(String::new());
    out.extend(opening(
        screen,
        &format!(
            "Wrote probe.sh and sweep.sh to {}. Nothing was run.",
            s.folder
        ),
        PLAIN,
    ));
    out.push(String::new());
    // The command is never cut: it is what the person runs.
    out.push(screen.paint(CYAN, &format!("→ {}", s.sweep_command)));
    out.extend(under(
        screen,
        &format!(
            "reads the offered servers. Name aliases after it to visit only those again, such as those that failed. To choose which alias the sweep uses, add the others to {} in the same folder, one per line, then run immunity run.",
            crate::sweep::SKIP
        ),
        PLAIN,
    ));
    out.push(screen.next(
        "immunity owner <name> retired --reason <text>",
        "sets a server aside",
    ));
    joined(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::visible;

    const NOW: i64 = 1_794_807_960;
    /// A style sequence, a title sequence, a C1 control, a right-to-left override, a zero-width
    /// space, a line break and a line shaped like Immunity Core's own, as a source may hold them.
    const ODD: &str = "x\u{1b}[31mRED\u{1b}[0m\u{9b}31m\u{202e}evil\u{200b}\u{1b}]0;owned\u{7}\n→ immunity rules --all   every rule\n✓ Nothing needs a look";

    /// The screens a text is rendered for, those that cut first.
    fn screens() -> Vec<Screen> {
        let mut out = vec![Screen::pipe()];
        for width in [20, 40, 80, 120] {
            out.push(Screen::terminal(width, true));
            out.push(Screen::terminal(width, false));
        }
        out
    }

    /// Text as the contract carries it from a source: escaped one to one.
    fn src(s: &str) -> String {
        crate::known::whole(s)
    }

    fn rule(id: &str, title: &str, level: v1::Level) -> v1::Rule {
        v1::Rule {
            name: format!("sigma:{id}"),
            file: format!("macos/{id}.yml"),
            id_text: id.to_string(),
            title_text: src(title),
            level: level as i32,
            source: "sigma".to_string(),
            set: "SigmaHQ's rule set".to_string(),
            ..Default::default()
        }
    }

    fn start(at: i64, exe: &str) -> v1::Event {
        v1::Event {
            body: Some(v1::event::Body::ProgramStart(v1::ProgramStart {
                happened_at: Some(at),
                process: Some(v1::Process {
                    executable_text: src(exe),
                    ..Default::default()
                }),
                args_text: vec![src(ODD)],
                ..Default::default()
            })),
        }
    }

    fn a_match(r: &v1::Rule, at: i64, exe: &str) -> v1::RuleMatch {
        v1::RuleMatch {
            position: format!("20261116T04-330625740-{at}"),
            rule: Some(r.clone()),
            event: Some(start(at, exe)),
            raised: v1::Raised::BelowHigh as i32,
            ..Default::default()
        }
    }

    /// A day of matches: three rules, one of a high level with a finding and a suspicious
    /// verdict, losses of every kind, a collector that said something, and rules not evaluated
    /// for every reason; `odd` in every text from a source.
    fn matches_of(odd: &str) -> v1::Matches {
        let high = rule(
            "5de06a6f",
            &format!("OSACompile Run-Only {odd}"),
            v1::Level::High,
        );
        let medium = rule("a1b2c3d4", "Binary Padding - MacOS", v1::Level::Medium);
        let silent = rule("e5f6a7b8", odd, v1::Level::NotStated);
        let mut flagged = a_match(&high, NOW - 3600, &format!("/usr/bin/osacompile{odd}"));
        flagged.raised = v1::Raised::Finding as i32;
        flagged.findings = vec![v1::FindingRef {
            id: "f0123456789".to_string(),
            ..Default::default()
        }];
        flagged.verdicts = Some(v1::Verdicts {
            total: 1,
            suspicious: 1,
            ..Default::default()
        });
        let mut harmless = a_match(&medium, NOW - 600, "/bin/dd");
        harmless.verdicts = Some(v1::Verdicts {
            total: 1,
            ..Default::default()
        });
        let mut list = vec![flagged, harmless];
        for i in 0..3 {
            list.push(a_match(&medium, NOW - 900 - i, "/usr/bin/truncate"));
        }
        list.push(a_match(&silent, NOW - 120, odd));
        let reasons = (1..=14).chain([0, 99]);
        v1::Matches {
            format: 1,
            answered_at: NOW,
            matches: list,
            continue_after: Some("0343abcdef".to_string()),
            more: true,
            stretch: Some(v1::Stretch {
                program_starts: 1_204_331,
                file_events: 37,
                program_starts_lost: 34,
                program_starts_unknown_losses: 1,
                file_events_lost: 2,
                unreadable_lines: 3,
                unreadable_file_events: 4,
                gone: true,
                ..Default::default()
            }),
            collector: Some(v1::Collector {
                state: v1::CollectorState::Failing as i32,
                said_by: Some("eslogger".to_string()),
                said_text: Some(src(odd)),
                written_at: Some(NOW - 240),
                status_state: Some(v1::CollectorState::Running as i32),
                status_read_at: Some(NOW - 7200),
                foreign_files: 2,
                no_longer_arriving: vec![v1::NoLongerArriving {
                    name: "script".to_string(),
                    since: NOW - 4000,
                }],
                ..Default::default()
            }),
            unevaluated: reasons
                .map(|r| v1::Unevaluated {
                    file: format!("rules/{r}.yml"),
                    title_text: Some(src(odd)),
                    detail_text: Some(src(odd)),
                    reason: r,
                    ..Default::default()
                })
                .collect(),
            store_id: Some("0123456789abcdef0123456789abcdef".to_string()),
            ..Default::default()
        }
    }

    fn rules_of(odd: &str) -> v1::Rules {
        let shipped = |r: v1::Rule, n: Option<u64>| v1::ShippedRule {
            set: r.set.clone(),
            source: r.source.clone(),
            file: src(&r.file),
            rule: Some(r),
            matches_last_day: n,
            ..Default::default()
        };
        let mut not = Vec::new();
        for (i, reason) in [(0, 1), (1, 7), (2, 7), (3, 2), (4, 99)] {
            let mut r = shipped(
                rule(&format!("n{i}"), &format!("Not {odd}"), v1::Level::Low),
                None,
            );
            r.reason = Some(reason);
            r.detail_text = Some(src(odd));
            r.fields_text = vec![src(odd)];
            not.push(r);
        }
        let mut part = shipped(rule("p0", odd, v1::Level::Critical), Some(2));
        part.never_matches = vec![v1::NeverMatches {
            selection_text: Some(src(odd)),
            fields_text: vec![src(odd)],
            left_out_text: None,
        }];
        let source = |set: &str, levels: bool, e: u64, p: u64, n: u64| v1::RuleSet {
            name: set.to_lowercase(),
            set: src(set),
            states_levels: levels,
            commit: "d7c9da10c170aa".to_string(),
            totals: Some(v1::RuleTotals {
                shipped: e + p,
                evaluated: e,
                in_part: p,
                not_evaluated: n,
                ..Default::default()
            }),
            ..Default::default()
        };
        let evaluated = vec![
            shipped(
                rule("e0", "Binary Padding - MacOS", v1::Level::High),
                Some(4),
            ),
            shipped(rule("e1", odd, v1::Level::Medium), Some(1)),
            shipped(rule("e2", "Quiet one", v1::Level::NotStated), Some(0)),
        ];
        v1::Rules {
            format: 1,
            answered_at: NOW,
            sources: vec![
                source("SigmaHQ's rule set", true, 2, 1, 3),
                source(&format!("Behaviour {odd}"), false, 1, 0, 2),
            ],
            totals: Some(v1::RuleTotals {
                evaluated: 3,
                in_part: 1,
                not_evaluated: 5,
                ..Default::default()
            }),
            not_evaluated: not,
            now: Some(v1::RulesNow {
                watching: Some(true),
                watching_rules: Some(3),
                watching_file_rules: Some(1),
                file_rules: 1,
                in_part: 1,
                file_events_collected: Some(false),
                judged: v1::Judged::Part as i32,
                judged_note: Some("Over the last day some program starts were lost.".into()),
                matches_last_day: Some(7),
                matched_last_day: [("e0", 4), ("p0", 2), ("e1", 1)]
                    .into_iter()
                    .map(|(id, n)| {
                        let r = [&evaluated[..], &[part.clone()]]
                            .concat()
                            .into_iter()
                            .find_map(|s| s.rule.filter(|r| r.id_text == id))
                            .unwrap();
                        v1::RuleMatches {
                            id_text: r.id_text.clone(),
                            rule: Some(r),
                            matches: n,
                        }
                    })
                    .collect(),
                matched_last_day_total: Some(3),
                ..Default::default()
            }),
            evaluated,
            in_part: vec![part],
            ..Default::default()
        }
    }

    fn statements_of(odd: &str) -> v1::Statements {
        v1::Statements {
            format: 1,
            answered_at: NOW,
            statements: vec![
                v1::Statement {
                    machine_text: src(&format!("old-box{odd}")),
                    said: "retired".to_string(),
                    via: v1::Via::Agent as i32,
                    at: NOW - 86_400 * 3,
                    reason_text: src(odd),
                    names_text: vec![src(odd), src("203.0.113.8")],
                    seen_after: Some(v1::SeenAfter {
                        at: NOW - 60,
                        what_text: src(odd),
                    }),
                    ..Default::default()
                },
                v1::Statement {
                    machine_text: src("web-1"),
                    said: "not mine".to_string(),
                    via: v1::Via::Command as i32,
                    at: NOW - 7200,
                    reason_text: src("Handed over to a client"),
                    ..Default::default()
                },
            ],
            withdrawn: 1,
            ..Default::default()
        }
    }

    fn said_of(odd: &str) -> v1::StatementMade {
        v1::StatementMade {
            format: 1,
            answered_at: NOW,
            machine_text: src(&format!("web-1 {odd}")),
            names_text: vec![src("web-1"), src(odd)],
            done: Some(v1::statement_made::Done::Said(v1::Said {
                said: "retired".to_string(),
                at: NOW,
                reason_text: src(odd),
                replaced: 1,
                reason_cuts: vec![v1::Cut::default()],
            })),
            sweep: Some(v1::SweepWritten {
                servers: None,
                problem_text: Some(src(odd)),
            }),
            ..Default::default()
        }
    }

    fn servers_of(odd: &str) -> Servers {
        let server = |name: &str| Server {
            name: src(name),
            known_from: "ssh configuration, known hosts".to_string(),
            sweep: "visited".to_string(),
            last_file: format!("read, taken 2026-11-16 05:44 UTC; {}", src(odd)),
            others: src(&format!("10.0.0.5, {odd}")),
        };
        Servers {
            offered: vec![server("web-1"), server(&format!("build{odd}"))],
            rest: vec![server(odd)],
            set_aside: vec![SetAside {
                machine: src(odd),
                said: "retired".to_string(),
                at: NOW - 3600,
                reason: src(odd),
                others: src(odd),
            }],
            own: vec![[src(odd), "iOS".to_string(), src(odd)]],
            theirs: vec![[src(odd), src(odd)]],
            said: vec![
                "ssh configuration: 3 servers".to_string(),
                format!("tailnet peers: not read, {}", src(odd)),
            ],
            summary: "3 servers known, 0 of them under several names.".to_string(),
            owner_word: Some("The owner's word: 1 machine retired or disowned.".to_string()),
            spare: 2,
            never_read: 1,
            folder: src(&format!("/Users/example/.immunity/sweep{odd}")),
            sweep_command: format!(
                "sh '{}'",
                src(&format!("/Users/example/.immunity/sweep{odd}/sweep.sh"))
            ),
        }
    }

    /// Every text of this module for `odd`, on `screen`, each with its name.
    fn every_text(odd: &str, screen: &Screen) -> Vec<(&'static str, String)> {
        let replay = v1::Replay {
            outcome: v1::ReplayOutcome::Read as i32,
            answered_at: NOW,
            matches_total: Some(5),
            program_starts: Some(12),
            lost: Some(3),
            matched: vec![v1::ReplayMatch {
                rule: Some(rule("r", odd, v1::Level::NotStated)),
                status: "test".to_string(),
                matches: 5,
            }],
            ..Default::default()
        };
        let mut withdrawn = said_of(odd);
        withdrawn.done = Some(v1::statement_made::Done::Withdrawn(v1::Withdrawn {
            statements: vec![v1::WithdrawnStatement {
                machine_text: src(odd),
                said: "retired".to_string(),
            }],
        }));
        let out = vec![
            ("matches", matches(&matches_of(odd), false, screen)),
            ("matches --limit", matches(&matches_of(odd), true, screen)),
            ("rules", rules(&rules_of(odd), false, screen)),
            ("rules --all", rules(&rules_of(odd), true, screen)),
            ("replay", self::replay(&replay, screen)),
            (
                "replay not installed",
                self::replay(&v1::Replay::default(), screen),
            ),
            ("owner", statements(&statements_of(odd), screen)),
            ("owner said", statement_made(&said_of(odd), screen)),
            ("owner withdrawn", statement_made(&withdrawn, screen)),
            ("servers", servers(&servers_of(odd), screen)),
        ];
        out
    }

    #[test]
    fn text_from_a_source_never_opens_a_style_starts_a_line_or_reaches_the_screen_raw() {
        for screen in screens() {
            for (name, text) in every_text(ODD, &screen) {
                // Every escape sequence is one this module wrote: a style opened or closed.
                for (i, _) in text.match_indices('\u{1b}') {
                    let rest = &text[i..];
                    let end = rest.find('m').unwrap_or(rest.len());
                    let seq = &rest[..=end.min(rest.len() - 1)];
                    assert!(
                        seq == "\u{1b}[0m"
                            || seq[2..seq.len() - 1]
                                .split(';')
                                .all(|c| { ["1", "2", "31", "32", "33", "36"].contains(&c) }),
                        "{name} {screen:?}: {seq:?}"
                    );
                }
                for c in text.chars() {
                    assert!(
                        c == '\n' || c == '\u{1b}' || !crate::icu::hidden(c),
                        "{name} {screen:?}: {c:?} reached the screen"
                    );
                }
                // The line shaped like Immunity Core's own is written out inside the text it came in,
                // never at the start of a line.
                for line in text.lines().map(visible) {
                    assert!(!line.starts_with("x\\u{1b}"), "{name}: {line}");
                    if line.starts_with("→ immunity") {
                        assert!(!line.contains("\\u{a}"), "{name} {screen:?}: {line}");
                    }
                    assert!(!line.starts_with("→ immunity rules --all   every rule\\u"));
                    assert!(!line.starts_with("✓ Nothing"), "{name}: {line}");
                }
                // Off a terminal and without colour no escape is written.
                if !screen.colour {
                    assert!(!text.contains('\u{1b}'), "{name} {screen:?}");
                }
            }
        }
    }

    #[test]
    fn no_line_is_wider_than_a_terminal_of_eighty_or_more_and_none_panics_at_twenty() {
        for screen in screens() {
            for (name, text) in every_text(ODD, &screen) {
                let Some(width) = screen.fits().filter(|w| *w >= 80) else {
                    continue;
                };
                for line in text.lines() {
                    // The sweep's command is never cut: a person runs it whole.
                    if visible(line).starts_with("→ sh ") {
                        continue;
                    }
                    assert!(
                        screen::columns(&visible(line)) <= width,
                        "{name} at {width}: {}",
                        visible(line)
                    );
                }
            }
        }
    }

    #[test]
    fn in_a_pipe_nothing_is_cut_and_times_are_exact() {
        let text = matches(&matches_of(ODD), false, &Screen::pipe());
        assert!(text.contains(&view::shown(&src(&format!("OSACompile Run-Only {ODD}")))));
        assert!(text.contains(&view::utc(NOW - 3600)), "{text}");
        assert!(
            text.lines()
                .next()
                .unwrap()
                .ends_with(&format!("   log written {}", view::utc(NOW - 240))),
            "{text}"
        );
        assert!(!text.contains(" ago"), "{text}");
        let all = rules(&rules_of(ODD), true, &Screen::pipe());
        assert!(
            all.contains(&format!(
                "not evaluated  correlates a sequence of events ({})",
                view::shown(&src(ODD))
            )),
            "{all}"
        );
    }

    #[test]
    fn the_matches_by_rule_add_up_to_the_headline_and_the_high_ones_are_counted() {
        let m = matches_of("odd");
        let text = matches(&m, false, &Screen::pipe());
        let first = text.lines().next().unwrap();
        assert!(
            first.starts_with("6 rule matches in the last day, 1 of them of a high level"),
            "{first}"
        );
        let counted: u64 = text
            .lines()
            .skip(3)
            .take_while(|l| !l.is_empty())
            .map(|l| {
                let cells: Vec<&str> = l.split("  ").filter(|c| !c.is_empty()).collect();
                cells[2].trim().parse::<u64>().unwrap()
            })
            .sum();
        assert_eq!(counted, 6, "{text}");
        // A critical one is said as such, and one place given reads as after it.
        let mut m = m;
        m.matches[0].rule.as_mut().unwrap().level = v1::Level::Critical as i32;
        m.after = Some("0343".to_string());
        let first = matches(&m, false, &Screen::pipe());
        assert!(
            first.starts_with(
                "6 rule matches after the place given, 1 of them of a high or critical level"
            ),
            "{first}"
        );
    }

    #[test]
    fn a_match_is_grouped_under_its_rule_with_its_verdict_and_finding_and_alone_with_limit() {
        let text = matches(&matches_of("odd"), false, &Screen::pipe());
        let row = |name: &str| {
            text.lines()
                .find(|l| l.contains(name))
                .unwrap_or_else(|| panic!("{name}: {text}"))
                .to_string()
        };
        let osa = row("OSACompile");
        assert!(
            osa.starts_with("  high ")
                && osa.ends_with("  suspicious")
                && !osa.contains("f0123456789"),
            "{osa}"
        );
        let padding = row("Binary Padding");
        assert!(
            padding.contains("  4  ") && padding.contains("1 harmless"),
            "{padding}"
        );
        assert!(row("not stated").contains("  1  "), "{text}");
        let single = matches(&matches_of("odd"), true, &Screen::pipe());
        assert_eq!(single.matches("Binary Padding").count(), 4, "{single}");
        assert!(single.contains("/usr/bin/truncate"), "{single}");
    }

    #[test]
    fn what_was_lost_is_in_the_default_text_whenever_the_message_holds_it_and_never_dim() {
        let m = matches_of("odd");
        let coloured = matches(&m, false, &Screen::terminal(120, true));
        let lost: Vec<&str> = coloured
            .lines()
            .skip_while(|l| !visible(l).trim_start().starts_with("Lost"))
            .take_while(|l| !visible(l).trim_start().starts_with("Collector"))
            .collect();
        assert!(
            !lost.is_empty() && lost.iter().all(|l| !l.contains("\u{1b}[2m")),
            "{lost:?}"
        );
        assert!(coloured.contains("2 h ago"), "{coloured}");
        let text = matches(&m, false, &Screen::pipe());
        for said in [
            "34 program starts were not recorded",
            "2 file events were not recorded",
            "it restarted once",
            "3 lines could not be read",
            "4 file events could not be made out",
            "lines were deleted before they were read",
        ] {
            assert!(text.contains(said), "{said}: {text}");
        }
        assert!(
            text.contains("failing") && coloured.contains("script has not arrived for 1 h"),
            "{text}"
        );
        assert!(
            text.contains("2 files are in its folder not its own"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "immunity status, from its reading {}, says running",
                view::utc(NOW - 7200)
            )),
            "{text}"
        );
        assert!(
            text.contains("More are left") && text.contains("--json"),
            "{text}"
        );
        assert!(!text.contains("0343abcdef"), "{text}");
        // Nothing lost is said too, and the rules not evaluated in words.
        let mut quiet = m.clone();
        quiet.stretch = Some(v1::Stretch::default());
        let text = matches(&quiet, false, &Screen::pipe());
        assert!(text.contains("  Lost         nothing"), "{text}");
        assert!(
            text.contains("15 rules are not evaluated and 1 only in part: 2 are not evaluated for a reason this version does not name, 1 "),
            "{text}"
        );
        assert!(text.contains(", 11 other reasons"), "{text}");
        // The replay says its losses the same way.
        let r = v1::Replay {
            outcome: v1::ReplayOutcome::Read as i32,
            lost: Some(3),
            unknown_losses: Some(2),
            ..Default::default()
        };
        let text = replay(&r, &Screen::pipe());
        assert!(
            text.contains("3 program starts were not recorded")
                && text.contains("restarted 2 times"),
            "{text}"
        );
    }

    #[test]
    fn no_match_is_calm_only_when_the_collector_ran_lost_nothing_and_every_rule_was_evaluated() {
        let mut m = v1::Matches {
            answered_at: NOW,
            collector: Some(v1::Collector {
                state: v1::CollectorState::Running as i32,
                file_events_collected: true,
                ..Default::default()
            }),
            stretch: Some(v1::Stretch::default()),
            ..Default::default()
        };
        assert!(matches(&m, false, &Screen::pipe()).starts_with("✓ No rule matched"));
        m.unevaluated.push(v1::Unevaluated::default());
        assert!(matches(&m, false, &Screen::pipe()).starts_with("No rule matched"));
        m.unevaluated.clear();
        m.stretch.as_mut().unwrap().gone = true;
        assert!(matches(&m, false, &Screen::pipe()).starts_with("No rule matched"));
        m.stretch = Some(v1::Stretch::default());
        m.collector.as_mut().unwrap().file_events_collected = false;
        assert!(matches(&m, false, &Screen::pipe()).starts_with("No rule matched"));
        m.collector.as_mut().unwrap().file_events_collected = true;
        m.collector.as_mut().unwrap().state = v1::CollectorState::Silent as i32;
        assert!(matches(&m, false, &Screen::pipe()).starts_with("No rule matched"));
    }

    #[test]
    fn no_raw_enum_word_and_no_store_id_reaches_the_text() {
        let mut m = matches_of("odd");
        let mut texts = Vec::new();
        for state in 0..=7 {
            m.collector.as_mut().unwrap().state = state;
            m.collector.as_mut().unwrap().status_state = Some(7 - state);
            for raised in 0..=7 {
                m.matches[0].raised = raised;
                texts.push(matches(&m, false, &Screen::pipe()));
            }
        }
        let mut r = rules_of("odd");
        for level in 0..=7 {
            r.evaluated[0].rule.as_mut().unwrap().level = level;
            texts.push(rules(&r, true, &Screen::pipe()));
            texts.push(rules(&r, false, &Screen::pipe()));
        }
        let mut s = statements_of("odd");
        for via in 0..=5 {
            s.statements[0].via = via;
            texts.push(statements(&s, &Screen::pipe()));
        }
        for text in texts {
            for w in text.split(|c: char| c.is_whitespace() || ",;:()".contains(c)) {
                assert!(!w.contains('_') || w == "continue_after", "{w}: {text}");
            }
            assert!(!text.contains("0123456789abcdef0123"), "{text}");
            assert!(!text.contains("20261116T04-"), "{text}");
            assert!(!text.contains("sigma:"), "{text}");
            assert!(!text.contains("unspecified"), "{text}");
        }
    }

    #[test]
    fn the_rules_by_source_and_by_reason_add_up_to_the_headline() {
        let m = rules_of("odd");
        let text = rules(&m, false, &Screen::pipe());
        assert!(
            text.starts_with(
                "Immunity Core evaluates 3 published rules in full and 1 in part; 5 it cannot yet\n"
            ),
            "{text}"
        );
        let mut sums = [0u64; 3];
        let mut reasons = 0;
        let mut in_reasons = false;
        for line in text.lines() {
            if line == "Not evaluated, by reason" {
                in_reasons = true;
                continue;
            }
            let cells: Vec<&str> = line
                .split("  ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            if in_reasons {
                if line.is_empty() {
                    in_reasons = false;
                    continue;
                }
                reasons += cells[0].parse::<u64>().unwrap();
            } else if cells.len() == 4 && cells[1].parse::<u64>().is_ok() {
                for (s, c) in sums.iter_mut().zip(&cells[1..]) {
                    *s += c.parse::<u64>().unwrap();
                }
            }
        }
        assert_eq!((sums, reasons), ([3, 1, 5], 5), "{text}");
        assert!(text.contains("2  correlate a sequence of events"), "{text}");
        // What matched lately, the most first, and what the event level does now.
        assert!(
            text.contains("Binary Padding - MacOS 4, odd 2, odd 1"),
            "{text}"
        );
        assert!(
            text.contains("3 rules watch this Mac: 2 every program start and 1 every file"),
            "{text}"
        );
        assert!(
            text.contains(
                "Lost                      over the last day some program starts were lost\n"
            ),
            "{text}"
        );
        assert!(text.contains("Behaviour odd state no level"), "{text}");
        // An Immunity Core's own set records no commit, so its rules are not all published.
        let mut own = m.clone();
        own.sources[1].commit.clear();
        assert!(
            rules(&own, false, &Screen::pipe())
                .starts_with("Immunity Core evaluates 3 rules in full")
        );
    }

    #[test]
    fn a_collector_that_runs_says_what_it_does_not_record_and_what_the_status_says_otherwise() {
        let mut m = matches_of("odd");
        let c = m.collector.as_mut().unwrap();
        c.state = v1::CollectorState::Running as i32;
        c.said_text = None;
        c.file_events_collected = false;
        c.status_state = Some(v1::CollectorState::Running as i32);
        let text = matches(&m, false, &Screen::pipe());
        assert!(
            text.contains("  Collector    running, last wrote ")
                && text.contains("; it records program starts, not file events")
                && !text.contains("immunity status, from its reading"),
            "{text}"
        );
        m.collector.as_mut().unwrap().file_events_collected = true;
        assert!(!matches(&m, false, &Screen::pipe()).contains("not file events"));
        // A collector that is not installed records nothing, so it is never said to record
        // program starts.
        let c = m.collector.as_mut().unwrap();
        c.state = v1::CollectorState::NotInstalled as i32;
        c.file_events_collected = false;
        let text = matches(&m, false, &Screen::pipe());
        assert!(
            text.contains("not installed, so nothing is recorded")
                && !text.contains("it records program starts"),
            "{text}"
        );
    }

    #[test]
    fn rules_judged_only_in_part_say_what_was_lost_on_a_line_of_its_own_in_the_colour_of_a_warning()
    {
        // The count of the rules that watch is plain; what was lost is its own line, yellow.
        let text = rules(&rules_of("odd"), false, &Screen::terminal(200, true));
        let watching = text.lines().find(|l| l.contains("Watching")).unwrap();
        assert!(!watching.contains("\u{1b}[33m"), "{watching:?}");
        let lost = text.lines().find(|l| l.contains("Lost")).unwrap();
        assert!(
            lost.contains("\u{1b}[33mover the last day some program starts were lost\u{1b}[0m"),
            "{lost:?}"
        );
        // Not running is said under its own word.
        let mut m = rules_of("odd");
        m.now.as_mut().unwrap().judged = v1::Judged::None as i32;
        let text = rules(&m, false, &Screen::pipe());
        assert!(text.contains("\n  Not running   "), "{text}");
        // Nothing lost, no such line.
        let mut m = rules_of("odd");
        m.now.as_mut().unwrap().judged_note = None;
        m.now.as_mut().unwrap().file_events_collected = Some(true);
        let text = rules(&m, false, &Screen::terminal(200, true));
        assert!(!text.contains("Lost"), "{text}");
    }

    #[test]
    fn in_the_full_list_a_long_reason_gives_way_before_a_rule_s_title() {
        let mut m = rules_of("odd");
        m.not_evaluated[0].rule.as_mut().unwrap().title_text = src("Curl Execution via Env Binary");
        m.not_evaluated[0].detail_text = Some(src(&"a long word of the translation ".repeat(8)));
        m.not_evaluated[0].fields_text.clear();
        let text = rules(&m, true, &Screen::terminal(80, false));
        let row = text
            .lines()
            .find(|l| l.contains("Curl Execution via Env Binary"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(screen::columns(row) <= 80 && row.ends_with('…'), "{row}");
    }

    #[test]
    fn whether_the_rules_watch_is_said_and_never_as_watching_when_it_is_not_known() {
        let mut m = rules_of("odd");
        m.now = Some(v1::RulesNow::default());
        m.not_computed.push(v1::NotComputed {
            section: "matches".to_string(),
            reason: "there is no store yet".to_string(),
        });
        let text = rules(&m, false, &Screen::pipe());
        assert!(
            text.contains("whether the event level is on is not known yet"),
            "{text}"
        );
        assert!(text.contains("not known: there is no store yet"), "{text}");
        m.now = Some(v1::RulesNow {
            watching: Some(false),
            matches_last_day: Some(0),
            ..Default::default()
        });
        let text = rules(&m, false, &Screen::pipe());
        assert!(
            text.contains("the event level is not on, so no rule is watching"),
            "{text}"
        );
        let mut quiet = m.clone();
        for r in quiet.evaluated.iter_mut().chain(quiet.in_part.iter_mut()) {
            r.matches_last_day = Some(0);
        }
        assert!(
            rules(&quiet, false, &Screen::pipe()).contains("Matched in the last day   nothing")
        );
    }

    #[test]
    fn rules_count_matches_as_the_message_does_and_name_a_matched_rule_this_build_does_not_ship() {
        let mut m = rules_of("odd");
        let now = m.now.as_mut().unwrap();
        // A rule this build no longer ships matched, and more rules matched than are listed.
        now.matches_last_day = Some(19);
        now.matched_last_day.push(v1::RuleMatches {
            id_text: "sigma:0000-gone".to_string(),
            rule: None,
            matches: 12,
        });
        now.matched_last_day_total = Some(6);
        let text = rules(&m, false, &Screen::pipe());
        let line = text
            .lines()
            .find(|l| l.starts_with("  Matched in the last day"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(
            line.contains("19 matches: Binary Padding - MacOS 4"),
            "{line}"
        );
        assert!(
            line.contains("sigma:0000-gone 12, not in this build, and 2 more rules"),
            "{line}"
        );
        // One more rule, in the singular.
        m.now.as_mut().unwrap().matched_last_day_total = Some(5);
        let text = rules(&m, false, &Screen::pipe());
        assert!(text.contains(", and 1 more rule\n"), "{text}");
        // Matches of rules none of which this build evaluates are never "nothing".
        let mut gone = rules_of("odd");
        let now = gone.now.as_mut().unwrap();
        now.matches_last_day = Some(7);
        now.matched_last_day = vec![v1::RuleMatches {
            id_text: "sigma:0000-gone".to_string(),
            rule: None,
            matches: 7,
        }];
        now.matched_last_day_total = Some(1);
        for r in gone.evaluated.iter_mut().chain(gone.in_part.iter_mut()) {
            r.matches_last_day = Some(0);
        }
        let text = rules(&gone, false, &Screen::pipe());
        assert!(
            text.contains(
                "Matched in the last day   7 matches: sigma:0000-gone 7, not in this build"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_full_list_names_every_rule_with_its_level_state_and_matches() {
        let m = rules_of("odd");
        let text = rules(&m, true, &Screen::pipe());
        let rows = text
            .lines()
            .filter(|l| l.starts_with("  ") && !l.contains("Level"))
            .count();
        assert_eq!(rows, 3 + 1 + 5, "{text}");
        assert!(
            text.lines().any(|l| l.starts_with("  high ")
                && l.contains("Binary Padding - MacOS")
                && l.ends_with(" 4  in full")),
            "{text}"
        );
        assert!(
            text.contains("in part        odd needs odd, which a program start does not give"),
            "{text}"
        );
        assert!(
            text.contains("not evaluated  needs events this version does not collect"),
            "{text}"
        );
        assert!(
            text.contains("not evaluated  for a reason this version does not name"),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("  not stated  Quiet one")),
            "{text}"
        );
    }

    #[test]
    fn what_a_translation_said_names_its_reasons_in_words_and_keeps_the_rest() {
        assert_eq!(
            translated("needs_fields process.parent.name; backslash_in_wildcard file.path: x"),
            "needs fields the events do not give: process.parent.name; has a backslash in a wildcard pattern: file.path: x"
        );
        assert_eq!(
            translated("not_eql"),
            "is not written in EQL, the language translated"
        );
        assert_eq!(translated("regex match~(x)"), "regex match~(x)");
        assert_eq!(
            translated("Sequence of two events"),
            "Sequence of two events"
        );
    }

    #[test]
    fn the_replay_lists_rules_by_level_and_says_when_there_is_no_log() {
        let r = v1::Replay {
            outcome: v1::ReplayOutcome::Read as i32,
            matches_total: Some(5),
            program_starts: Some(12),
            matched: vec![v1::ReplayMatch {
                rule: Some(rule("r", "Binary Padding - MacOS", v1::Level::High)),
                status: "test".to_string(),
                matches: 5,
            }],
            ..Default::default()
        };
        let text = replay(&r, &Screen::pipe());
        assert!(
            text.starts_with("The rules matched 5 times in the event log on disk\n"),
            "{text}"
        );
        assert!(
            text.contains("  high   Binary Padding - MacOS        5"),
            "{text}"
        );
        assert!(
            text.contains("12 program starts and 0 file events; nothing was stored"),
            "{text}"
        );
        let none = replay(&v1::Replay::default(), &Screen::pipe());
        assert_eq!(
            none,
            "The event level is not installed here, so there is no log to replay.\n"
        );
    }

    #[test]
    fn a_statement_made_is_confirmed_on_its_first_line_with_what_it_changed_and_how_to_undo_it() {
        let text = statement_made(&said_of("odd"), &Screen::pipe());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "✓ Said: \"web-1 odd\" is retired", "{text}");
        for said in [
            "  Its reason: \"odd\"",
            "  Its reason held what Immunity Core recognises as a secret",
            "  It replaces the statement that stood",
            "  It covers the machine under every name: \"web-1\", \"odd\".",
            "  ✗ The sweep script could not be written again: \"odd\".",
        ] {
            assert!(text.contains(said), "{said}: {text}");
        }
        assert_eq!(
            lines.last().unwrap(),
            &"→ immunity owner <name> withdraw   takes it back"
        );
        let mut ok = said_of("odd");
        ok.sweep = Some(v1::SweepWritten {
            servers: Some(1),
            problem_text: None,
        });
        assert!(
            statement_made(&ok, &Screen::pipe())
                .contains("  The sweep script was written again: it visits 1 server.")
        );
    }

    #[test]
    fn the_statements_that_stand_show_who_gave_each_and_what_contradicts_it() {
        let text = statements(&statements_of("odd"), &Screen::pipe());
        assert!(
            text.starts_with("2 statements stand; 1 was withdrawn and kept\n"),
            "{text}"
        );
        assert!(text.contains("your agent"), "{text}");
        // One an agent made stands out, in its words and in colour.
        let coloured = statements(&statements_of("odd"), &Screen::terminal(120, true));
        assert!(coloured.contains("\u{1b}[33myour agent"), "{coloured}");
        assert!(
            text.contains("Contradicted   old-boxodd was seen alive after it"),
            "{text}"
        );
        let none = statements(&v1::Statements::default(), &Screen::pipe());
        assert!(none.starts_with("No statement stands\n"), "{none}");
        assert!(
            none.contains("→ immunity owner <name> retired --reason <text>"),
            "{none}"
        );
        assert!(!none.contains("withdraw"), "{none}");
    }

    #[test]
    fn servers_say_the_folder_once_and_the_sweep_command_whole() {
        let mut s = servers_of("odd");
        s.folder = "/Users/example/.immunity/sweep".to_string();
        s.sweep_command = "sh '/Users/example/.immunity/sweep/sweep.sh'".to_string();
        let text = servers(&s, &Screen::terminal(40, false));
        assert_eq!(
            text.matches("/Users/example/.immunity/sweep").count(),
            2,
            "{text}"
        );
        assert!(
            text.contains("\n→ sh '/Users/example/.immunity/sweep/sweep.sh'\n"),
            "{text}"
        );
        assert!(text.contains("SSH configuration: 3 servers."), "{text}");
        assert!(text.contains("Tailnet peers: not read"), "{text}");
        let piped = servers(&s, &Screen::pipe());
        assert!(piped.contains("Nothing was run."), "{piped}");
        assert!(
            piped.starts_with("3 servers known, 2 offered for the sweep, 1 never read\n"),
            "{piped}"
        );
        assert!(
            piped.contains("\n  web-1     ssh configuration, known hosts  visited  "),
            "{piped}"
        );
    }
}
