//! The text for a person of each message of the contract, rendered from the message alone: no
//! store is asked and nothing else is read, so a person, an agent and a program are told the
//! same thing (`answer.rs`).
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`): a line break or a hidden character is written `\u{...}`, and so is the
//! backslash. In the text it is set in double quotes with a double quote inside written `\"`, or
//! in a column of its own, so nothing in it can end a line or a quotation and go on in the
//! program's own words. Words without the suffix are the core's own vocabulary.

use crate::contract::v1;
use crate::{findings, sigma, verdict, view};
use std::fmt::Write;

/// At most this many findings are listed in the text of `immune findings`; the total is always
/// given.
const FINDINGS_SHOWN: usize = 200;

/// Text from a source as data: in double quotes, a quote inside escaped, and anything hidden
/// written out.
pub fn quoted(s: &str) -> String {
    format!("\"{}\"", view::shown(&s.replace('"', "\\\"")))
}

/// An enum's value as the JSON names it, the store's own word: `unspecified` for a value this
/// build does not know.
pub fn word<E: TryFrom<i32> + serde::Serialize>(value: i32) -> String {
    E::try_from(value)
        .ok()
        .and_then(|e| serde_json::to_value(e).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unspecified".to_string())
}

/// A finding's severity as a word; said as not known when it is absent, never as a level.
fn severity(s: Option<i32>) -> String {
    s.map_or_else(|| "not known".to_string(), word::<v1::Level>)
}

/// `n one` or `n many`, with thousands grouped.
fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// Rows under a head, in columns. Each cell is shown with anything hidden written out.
pub fn table(head: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "  none\n".to_string();
    }
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(|cell| view::shown(cell)).collect())
        .collect();
    let mut widths: Vec<usize> = head.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        let _ = writeln!(out, "  {}", parts.join("  ").trim_end());
    };
    line(head.to_vec());
    for row in &rows {
        line(row.iter().map(String::as_str).collect());
    }
    out
}

/// A line of the program's own words, with anything hidden written out.
fn say(out: &mut String, line: &str) {
    let _ = writeln!(out, "{}", view::shown(line));
}

/// A time of seconds since the epoch, or the word given when there is none.
fn when(at: Option<i64>, none: &str) -> String {
    view::utc_or(at, none)
}

/// An event's time to the fraction of a second the log gives: microseconds when it gives no
/// finer, as `eslogger` writes them.
fn instant(at: Option<i64>, nanos: Option<u32>) -> String {
    let Some(at) = at else {
        return "unknown".to_string();
    };
    let whole = view::iso(at);
    let base = whole.trim_end_matches('Z');
    match nanos.unwrap_or(0) {
        n if n % 1000 == 0 => format!("{base}.{:06}Z", n / 1000),
        n => format!("{base}.{n:09}Z"),
    }
}

/// A finding by reference, in one line: its id, state, severity and rule, and what it is about.
fn finding_ref(f: &v1::FindingRef) -> String {
    format!(
        "{}  {}  {}{}  {}{}  about {}",
        f.id,
        word::<v1::FindingState>(f.state),
        f.severity
            .map_or_else(|| "severity not known".to_string(), word::<v1::Level>),
        f.confidence
            .map(|c| format!(" (confidence {})", word::<v1::Level>(c)))
            .unwrap_or_default(),
        f.rule.as_deref().unwrap_or("no rule named"),
        if f.urgent { "  urgent" } else { "" },
        quoted(&f.about_text)
    )
}

/// `immune project`, `immune program` and `immune machine`: what the thing is, whether the store
/// knows it, its facts in short, the coverage with what was not read and why, and its findings
/// by id.
pub fn known(k: &v1::Known) -> String {
    let mut out = String::new();
    let presence = match v1::Presence::try_from(k.presence) {
        Ok(v1::Presence::Held) => "is held: the store has facts in force about it",
        Ok(v1::Presence::Gone) => "is gone: it was there, and what was read of it is retracted",
        Ok(v1::Presence::Unknown) => "is unknown: the store has never heard of it",
        _ => "is of a presence this build does not know, so read it as not known",
    };
    let question = word::<v1::Question>(k.question);
    say(
        &mut out,
        &format!("The {question} {} {presence}.", quoted(&k.asked_text)),
    );
    let entity = |e: &v1::Entity| format!("{} ({})", quoted(&e.id_text), e.r#type);
    if let Some(thing) = &k.thing {
        say(&mut out, &format!("It is {}.", entity(thing)));
    }
    if !k.same_as.is_empty() {
        let ids: Vec<String> = k.same_as.iter().map(entity).collect();
        say(&mut out, &format!("Also known as {}.", ids.join(", ")));
    }
    if !k.parts.is_empty() {
        say(
            &mut out,
            &format!("{}:", count(k.parts.len() as u64, "part", "parts")),
        );
        for p in &k.parts {
            say(&mut out, &format!("  {}", entity(p)));
        }
    }
    say(
        &mut out,
        &format!(
            "{}{}",
            count(k.facts.len() as u64, "fact in force", "facts in force"),
            if k.facts.is_empty() { "." } else { ":" }
        ),
    );
    for f in &k.facts {
        let by: Vec<String> = f
            .assertions
            .iter()
            .map(|a| {
                format!(
                    "{} ({}), {} {}, from {}",
                    a.reader,
                    a.kind,
                    word::<v1::Basis>(a.basis),
                    view::utc(a.observed_at),
                    quoted(&a.source_ref_text)
                )
            })
            .collect();
        say(
            &mut out,
            &format!(
                "  {} {} {}; read by {}",
                quoted(&f.subject_text),
                f.predicate,
                quoted(&f.object_text),
                by.join("; ")
            ),
        );
    }
    // What was not read first: it is what an answer of "nothing here" would hide.
    let full = |c: &v1::Coverage| c.completeness == v1::Completeness::Full as i32;
    let not_full = k.coverage.iter().filter(|c| !full(c)).count();
    say(
        &mut out,
        &format!(
            "{}, {not_full} not full{}",
            count(k.coverage.len() as u64, "reading", "readings"),
            if k.coverage.is_empty() { "." } else { ":" }
        ),
    );
    let mut coverage: Vec<&v1::Coverage> = k.coverage.iter().collect();
    coverage.sort_by_key(|c| full(c));
    for c in coverage {
        let mut line = format!(
            "  {}: {} ({}) for {}, {}",
            word::<v1::Completeness>(c.completeness),
            c.reader,
            c.kind,
            quoted(&c.scope_text),
            match c.observed_at {
                Some(at) => format!("read {}", view::utc(at)),
                None => "never read".to_string(),
            }
        );
        if let Some(cause) = c.cause {
            let _ = write!(line, ", cause {}", word::<v1::Cause>(cause));
        }
        if let Some(reason) = &c.reason_text {
            let _ = write!(line, ": {}", quoted(reason));
        }
        if !c.lacks.is_empty() {
            let lacks: Vec<String> = c
                .lacks
                .iter()
                .map(|l| match &l.name_text {
                    Some(name) => format!("{} {}", l.what, quoted(name)),
                    None => l.what.clone(),
                })
                .collect();
            let _ = write!(line, "; no reader for {}", lacks.join(", "));
        }
        say(&mut out, &line);
    }
    say(
        &mut out,
        &format!(
            "{}{}",
            count(k.findings.len() as u64, "finding", "findings"),
            if k.findings.is_empty() { "." } else { ":" }
        ),
    );
    for f in &k.findings {
        say(&mut out, &format!("  {}", finding_ref(f)));
    }
    say(
        &mut out,
        &format!(
            "Latest finished run: {}.",
            when(k.latest_run_at, "none has finished")
        ),
    );
    out
}

/// What a finding is, in a row: what it is about, in the core's words, where it says, then its
/// title.
fn what(title: &str, thing: Option<&str>) -> String {
    match thing {
        Some(t) => format!("{t}: {title}"),
        None => title.to_string(),
    }
}

/// A quoted value, or the core's word when the message does not give one.
fn quoted_or_unknown(s: Option<&str>) -> String {
    s.map(quoted).unwrap_or_else(|| "unknown".to_string())
}

fn executable(p: Option<&v1::Process>) -> String {
    quoted_or_unknown(p.map(|p| p.executable_text.as_str()))
}

/// An event in one line. A finding shows the circumstances of a start as well.
fn event(e: Option<&v1::Event>, detailed: bool) -> String {
    use v1::event::Body;
    match e.and_then(|e| e.body.as_ref()) {
        Some(Body::ProgramStart(s)) => {
            let exe = executable(s.process.as_ref());
            let args: Vec<String> = s.args_text.iter().map(|a| quoted(a)).collect();
            let at = instant(s.happened_at, s.happened_nanos);
            let args = args.join(" ");
            if !detailed {
                return format!("{at} started {exe} {args}");
            }
            let process = s.process.as_ref();
            let pid = process
                .and_then(|p| p.pid)
                .map_or("unknown".to_string(), |p| p.to_string());
            let signed = quoted_or_unknown(process.and_then(|p| p.signing_id_text.as_deref()));
            let by = executable(s.instigator.as_ref());
            let cwd = quoted_or_unknown(s.working_directory_text.as_deref());
            format!("{at} {exe}: {args} · started by {by} · in {cwd} · pid {pid} · signed {signed}")
        }
        Some(Body::FileEvent(f)) => {
            let how = match v1::FileAction::try_from(f.action) {
                Ok(v1::FileAction::Create) => "created".to_string(),
                Ok(v1::FileAction::Rename) => {
                    format!(
                        "renamed from {}",
                        quoted_or_unknown(f.source_text.as_deref())
                    )
                }
                _ => "unknown file action".to_string(),
            };
            format!(
                "{} {}: {how} by {}",
                instant(f.happened_at, f.happened_nanos),
                quoted(&f.path_text),
                executable(f.instigator.as_ref())
            )
        }
        None => "an event of a kind this build does not know".to_string(),
    }
}

/// `immune matches`: one line a match with its rule, level and what the core did, then the
/// tally of what was read and lost, the collector's state and the place to read on from.
pub fn matches(m: &v1::Matches) -> String {
    let mut out = String::new();
    say(
        &mut out,
        &format!(
            "{}{} after {}{}",
            count(m.matches.len() as u64, "match", "matches"),
            if m.more {
                ", and more are left past the limit,"
            } else {
                ""
            },
            m.after.as_deref().unwrap_or("the oldest line kept"),
            if m.matches.is_empty() { "." } else { ":" }
        ),
    );
    for r in &m.matches {
        let rule = r.rule.clone().unwrap_or_default();
        let raised = word::<v1::Raised>(r.raised);
        let found: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        say(
            &mut out,
            &format!(
                "  {}  {}  {}  {}{}  {}",
                r.position,
                rule.name,
                word::<v1::Level>(rule.level),
                raised,
                if found.is_empty() {
                    String::new()
                } else {
                    format!(" {}", found.join(", "))
                },
                event(r.event.as_ref(), false)
            ),
        );
    }
    let s = m.stretch.clone().unwrap_or_default();
    say(
        &mut out,
        &format!(
            "Read: {}, {}, {}.",
            count(s.program_starts, "program start", "program starts"),
            count(s.file_events, "file event", "file events"),
            count(s.other, "other message", "other messages")
        ),
    );
    let lost = [
        (
            s.unreadable_lines,
            "line could not be read",
            "lines could not be read",
        ),
        (
            s.unreadable_file_events,
            "file event could not be read",
            "file events could not be read",
        ),
        (
            s.program_starts_lost,
            "program start is missing from eslogger's numbering",
            "program starts are missing from eslogger's numbering",
        ),
        (
            s.file_events_lost,
            "file event is missing from eslogger's numbering",
            "file events are missing from eslogger's numbering",
        ),
        (
            s.program_starts_unknown_losses + s.file_events_unknown_losses,
            "restart of the numbering lost an unknown number of events",
            "restarts of the numbering each lost an unknown number of events",
        ),
    ];
    let said: Vec<String> = lost
        .iter()
        .filter(|(n, ..)| *n > 0)
        .map(|(n, one, many)| count(*n, one, many))
        .collect();
    if said.is_empty() && !s.gone {
        say(&mut out, "Lost: nothing.");
    } else if !said.is_empty() {
        say(&mut out, &format!("Lost: {}.", said.join("; ")));
    }
    if s.gone {
        say(
            &mut out,
            &format!(
                "Lines not read yet were deleted before they were read; the log is kept from {}.",
                s.kept_from
                    .as_deref()
                    .unwrap_or("a position this answer does not give")
            ),
        );
    }
    let c = m.collector.clone().unwrap_or_default();
    let mut line = format!("Collector: {}", word::<v1::CollectorState>(c.state));
    if let Some(said_text) = &c.said_text {
        let _ = write!(
            line,
            ", {} said {}",
            c.said_by.as_deref().unwrap_or("it"),
            quoted(said_text)
        );
    }
    let _ = write!(
        line,
        "; last written {}; file events {}.",
        when(c.written_at, "never"),
        if c.file_events_collected {
            "collected"
        } else {
            "not collected"
        }
    );
    say(&mut out, &line);
    if let Some(state) = c.status_state {
        say(
            &mut out,
            &format!(
                "immune status says {}, from its reading {}.",
                word::<v1::CollectorState>(state),
                when(c.status_read_at, "at a time it does not give")
            ),
        );
    }
    let mut fields = Vec::new();
    for (list, said) in [
        (&c.not_kept, "not kept"),
        (&c.kept_never_filled, "kept, never filled"),
        (&c.not_yet_known, "not yet known"),
    ] {
        if !list.is_empty() {
            fields.push(format!("{said}: {}", list.join(", ")));
        }
    }
    if !c.arriving.is_empty() {
        let arriving: Vec<String> = c
            .arriving
            .iter()
            .map(|a| format!("{} since {}", a.name, view::utc(a.since)))
            .collect();
        fields.push(format!("arriving: {}", arriving.join(", ")));
    }
    if !c.no_longer_arriving.is_empty() {
        let stopped: Vec<String> = c
            .no_longer_arriving
            .iter()
            .map(|a| format!("{} since {}", a.name, view::utc(a.since)))
            .collect();
        fields.push(format!("no longer arriving: {}", stopped.join(", ")));
    }
    if !fields.is_empty() {
        say(&mut out, &format!("Fields: {}.", fields.join("; ")));
    }
    if c.foreign_files > 0 {
        say(
            &mut out,
            &format!(
                "{} in the log folder not the collector's.",
                count(c.foreign_files, "file is", "files are")
            ),
        );
    }
    let mut reasons: std::collections::BTreeMap<String, u64> = Default::default();
    for u in &m.unevaluated {
        *reasons
            .entry(word::<v1::UnevaluatedReason>(u.reason))
            .or_default() += 1;
    }
    let reasons: Vec<String> = reasons.iter().map(|(r, n)| format!("{r} {n}")).collect();
    say(
        &mut out,
        &format!(
            "Not evaluated, or in part: {}{}.",
            count(m.unevaluated.len() as u64, "rule", "rules"),
            if reasons.is_empty() {
                String::new()
            } else {
                format!(", by reason: {}", reasons.join(", "))
            }
        ),
    );
    match &m.continue_after {
        Some(place) => say(&mut out, &format!("Continue after: {place}")),
        None => say(
            &mut out,
            "No place to read on from: the collector is not installed.",
        ),
    }
    out
}

/// `immune findings`: the open findings, or every one with `all`, the most severe first, with
/// when each was last seen and where.
pub fn findings(f: &v1::Findings, all: bool) -> String {
    let mut out = String::new();
    if f.latest_run_at.is_none() {
        say(
            &mut out,
            "No full check has finished. Only findings recorded so far are shown.",
        );
    }
    let open = v1::FindingState::Open as i32;
    let is_open = |l: &v1::ListedFinding| l.finding.as_ref().is_some_and(|r| r.state == open);
    // Open findings first, each part in the answer's order, so a cut never hides an open
    // finding behind a closed one.
    let (mut shown, closed): (Vec<&v1::ListedFinding>, Vec<&v1::ListedFinding>) =
        f.findings.iter().partition(|l| is_open(l));
    if all {
        shown.extend(closed);
    }
    let (one, many) = if all {
        ("finding", "findings")
    } else {
        ("open finding", "open findings")
    };
    say(
        &mut out,
        &format!("{}.", count(shown.len() as u64, one, many)),
    );
    let rows: Vec<Vec<String>> = shown
        .iter()
        .take(FINDINGS_SHOWN)
        .map(|l| {
            let r = l.finding.clone().unwrap_or_default();
            vec![
                r.id.clone(),
                word::<v1::FindingState>(r.state),
                finding_level(Some(&r)),
                view::utc(l.last_seen_at),
                what(&l.title, l.thing.as_deref()),
                quoted(&l.where_text),
            ]
        })
        .collect();
    out.push_str(&table(
        &["Id", "State", "Level", "Last seen", "What", "Where"],
        &rows,
    ));
    if let Some(at) = f.latest_run_at {
        say(
            &mut out,
            &format!("Latest full check finished {}.", view::utc(at)),
        );
    }
    if shown.len() > FINDINGS_SHOWN {
        let hidden = &shown[FINDINGS_SHOWN..];
        let urgent = hidden
            .iter()
            .filter(|l| l.finding.as_ref().is_some_and(|r| r.urgent))
            .count();
        say(
            &mut out,
            &format!(
                "Showing the first {FINDINGS_SHOWN}; {} more not shown, {} of them urgent. Use --json or --proto for the full list.",
                grouped(hidden.len() as u64),
                grouped(urgent as u64)
            ),
        );
    }
    say(
        &mut out,
        "`immune finding <id>` shows one; expected and seen are the owner's answers.",
    );
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

/// A verdict as text for a person: the core's words, then the reason and case quoted, whole.
fn verdict_line(r: &v1::RecordedVerdict) -> String {
    let v = r.verdict.clone().unwrap_or_default();
    let levels = match (v.severity, v.confidence) {
        (Some(s), Some(c)) => format!(
            ", severity {}, confidence {}",
            word::<v1::Level>(s),
            word::<v1::Level>(c)
        ),
        _ => String::new(),
    };
    format!(
        "A {} verdict of the response layer, {}{levels}. Its reason: {}. Its case: {}.",
        word::<v1::VerdictKind>(v.kind),
        view::utc(r.recorded_at),
        quoted(&v.reason_text),
        quoted(&v.case_text)
    )
}

/// What the response layer said of a finding, counted: for a finding the response layer raised,
/// that it judged it suspicious and how many came after.
fn verdicts_said(rule: Option<&str>, v: &v1::Verdicts) -> Option<String> {
    let plural = |n: u32, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    if v.total == 0 {
        return None;
    }
    Some(if rule == Some(verdict::RULE) {
        if v.total > 1 {
            format!(
                "The response layer judged this suspicious, and sent {} since.",
                plural(v.total - 1, "more verdict")
            )
        } else {
            "The response layer judged this suspicious.".to_string()
        }
    } else {
        format!(
            "{} from the response layer, {} suspicious.",
            plural(v.total, "verdict"),
            v.suspicious
        )
    })
}

/// A published rule's finding: the rule with its authors and its set, how many events it matched
/// and the latest of them.
fn published(out: &mut String, kind: &str, p: &v1::PublishedRuleMatched) {
    let rule = p.rule.clone().unwrap_or_default();
    let licence = sigma::SOURCES
        .iter()
        .find(|s| s.name == rule.source)
        .map_or(p.licence.as_str(), |s| s.licence_name);
    say(
        out,
        &format!(
            "Rule: {}, by {}; from {} under the {licence}, {}.",
            quoted(&rule.title_text),
            quoted_or_unknown(rule.author_text.as_deref()),
            rule.set,
            quoted(&crate::known::whole(&rule.file))
        ),
    );
    let (one, many) = if kind == findings::PUBLISHED_FILE_KIND {
        ("file event", "file events")
    } else {
        ("program start", "program starts")
    };
    match p.matches {
        Some(n) => say(
            out,
            &format!(
                "It matched {} since this finding was raised.",
                count(n, one, many)
            ),
        ),
        None => say(out, "The store has no count of matches for this finding."),
    }
    if !p.events.is_empty() {
        say(out, "Latest matching events:");
        for e in &p.events {
            say(out, &format!("  {}", event(Some(e), true)));
        }
    }
}

/// The reason for the latest loss of coverage of a watched place.
fn unread(f: &v1::Finding) -> Option<&v1::JournalEntry> {
    let latest = f.rests_on.last()?;
    f.rests_on
        .iter()
        .rev()
        .take_while(|b| b.run_id == latest.run_id)
        .find(|b| b.entry == "not_read")
}

fn package(out: &mut String, p: &v1::VulnerablePackage) {
    if let Some(name) = &p.package_text {
        say(out, &format!("Package: {}.", quoted(name)));
    }
    for r in &p.releases {
        say(
            out,
            &format!(
                "  Release {} declared at {}.",
                quoted(&r.version_text),
                quoted(&r.at_text)
            ),
        );
    }
    for r in &p.records {
        let mut line = format!("  Record {} from {}", quoted(&r.id_text), r.source);
        if let Some(summary) = &r.summary_text {
            let _ = write!(line, ": {}", quoted(summary));
        }
        if !r.fixed_text.is_empty() {
            let fixed: Vec<String> = r.fixed_text.iter().map(|v| quoted(v)).collect();
            let _ = write!(line, " (fixed in {})", fixed.join(", "));
        }
        say(out, &format!("{line}."));
    }
}

fn evidence(out: &mut String, f: &v1::Finding, body: &v1::evidence::Body) {
    use v1::evidence::Body;
    match body {
        Body::PlaceChanged(p) => {
            if p.presence_only == Some(true) {
                say(
                    out,
                    &format!(
                        "Watched only for presence: {}.",
                        crate::watched::PRESENCE_ONLY
                    ),
                );
            }
            if p.change == v1::Change::NotRead as i32 {
                if let Some(reason) = unread(f).and_then(|b| b.new_value_text.as_deref()) {
                    say(
                        out,
                        &format!("The place could not be read: {}.", quoted(reason)),
                    );
                } else {
                    say(
                        out,
                        "The place could not be read. The store gives no reason.",
                    );
                }
            }
            for b in f.rests_on.iter().filter(|b| b.entry == "place_first_read") {
                let place = quoted_or_unknown(b.subject_text.as_deref());
                let line = match b
                    .new_value_text
                    .as_deref()
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    Some(n) => format!(
                        "First read: {place}. {}.",
                        count(n, "thing runs by itself", "things run by themselves")
                    ),
                    None => format!("First read: {place}."),
                };
                say(out, &line);
            }
        }
        Body::ChangedInPlace(p) => {
            if let Some(value) = &p.became_text {
                say(out, &format!("What it became: {}.", quoted(value)));
            }
            if p.became_text.is_none()
                && let Some(b) =
                    f.rests_on.iter().rev().find(|b| {
                        b.entry == "changed" && b.predicate.as_deref() == Some("has_digest")
                    })
            {
                let before = quoted_or_unknown(b.old_value_text.as_deref());
                let after = quoted_or_unknown(b.new_value_text.as_deref());
                say(out, &format!("Digest: {before} became {after}."));
            }
        }
        Body::IndicatorMatched(p) => {
            if let Some(value) = &p.indicators_text {
                say(out, &format!("Matched indicators: {}.", quoted(value)));
            }
        }
        Body::DetachedProcess(p) => {
            if let Some(pid) = p.pid {
                let mut line = format!("Process id: {pid}");
                if let Some(start) = p.start_micros {
                    let at = start.div_euclid(1_000_000);
                    let nanos = start.rem_euclid(1_000_000) as u32 * 1_000;
                    let _ = write!(line, ", started {}", instant(Some(at), Some(nanos)));
                }
                say(out, &format!("{line}."));
            }
        }
        Body::VulnerablePackage(p) => package(out, p),
        Body::PublishedRuleMatched(p) => published(out, &f.kind, p),
        Body::VerdictGiven(v) => {
            say(out, &format!("Rule the verdict is about: {}.", v.rule));
            for e in &v.events {
                say(out, &format!("  {}", event(Some(e), true)));
            }
        }
    }
}

/// `immune finding <id>`: one finding whole, as a person reads it.
pub fn finding(f: &v1::Finding) -> String {
    let mut out = String::new();
    let r = f.finding.clone().unwrap_or_default();
    say(&mut out, &format!("Finding {}: {}", r.id, f.title));
    say(&mut out, &f.meaning);
    say(&mut out, &f.advice);
    let mut facts = vec![
        format!("rule {}", r.rule.as_deref().unwrap_or_default()),
        format!("severity {}", severity(r.severity)),
    ];
    if let Some(c) = r.confidence {
        facts.push(format!("confidence {}", word::<v1::Level>(c)));
    }
    if let Some(t) = &f.technique_text {
        facts.push(format!("ATT&CK {}", quoted(t)));
    }
    say(&mut out, &format!("{}.", facts.join(", ")));
    use v1::evidence::Body;
    let body = f.evidence.as_ref().and_then(|e| e.body.as_ref());
    let change = match body {
        Some(Body::PlaceChanged(p)) => Some(match v1::Change::try_from(p.change) {
            Ok(v1::Change::Unspecified) | Err(_) => "changed".to_string(),
            Ok(_) => word::<v1::Change>(p.change).replace('_', " "),
        }),
        _ => None,
    };
    say(
        &mut out,
        &format!(
            "State: {}. First seen {}, last seen {}{}.",
            word::<v1::FindingState>(r.state),
            view::utc(f.first_seen_at),
            view::utc(f.last_seen_at),
            change
                .map(|c| format!(", latest change: {c}"))
                .unwrap_or_default()
        ),
    );
    if let Some(a) = &f.answer {
        say(
            &mut out,
            &format!(
                "Answered {} {}{}{}.",
                view::utc(a.given_at),
                given_by(a.via),
                a.until_at
                    .map(|u| format!(", expected until {}", view::utc(u)))
                    .unwrap_or_default(),
                a.reason_text
                    .as_deref()
                    .map(|r| format!(": {}", quoted(r)))
                    .unwrap_or_default()
            ),
        );
    }
    if let Some(w) = &f.answered_with {
        say(
            &mut out,
            &format!(
                "Given the same answer: {}, rule {}, now {}.",
                w.id,
                w.rule.as_deref().unwrap_or_default(),
                word::<v1::FindingState>(w.state)
            ),
        );
    }
    if let Some(v) = &f.verdicts {
        if let Some(said) = verdicts_said(r.rule.as_deref(), v) {
            say(&mut out, &said);
        }
        if let Some(standing) = &v.verdict_finding {
            say(
                &mut out,
                &format!(
                    "The response layer's finding about the same: {}.",
                    standing.id
                ),
            );
        }
        for listed in &v.listed {
            say(&mut out, &verdict_line(listed));
        }
    }
    if let Some(thing) = &f.thing {
        say(&mut out, &format!("About: {thing}."));
    }
    say(&mut out, &format!("Where: {}.", quoted(&f.where_text)));
    if let Some(body) = body {
        evidence(&mut out, f, body);
    }
    let seqs: Vec<String> = f.rests_on.iter().map(|b| b.seq.to_string()).collect();
    say(
        &mut out,
        &format!(
            "Rests on {}: {}.",
            count(f.rests_on.len() as u64, "journal entry", "journal entries"),
            seqs.join(", ")
        ),
    );
    out
}

/// The most rows of a table `immune status` prints; the JSON lists more.
const STATUS_ROWS: usize = 10;

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
}

/// The summary of what the latest check that finished counted, in sentences, from the status.
fn counted_sentences(s: &v1::Status, f: &v1::FinishedCheck) -> String {
    let mut line = String::new();
    if let Some(e) = &s.estate {
        line.push_str(&format!(
            "{}, {}.",
            count(e.checkouts, "checkout", "checkouts"),
            count(e.components, "component", "components")
        ));
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
            let gaps = gaps.join("; ");
            line.push(' ');
            line.push_str(&gaps[..1].to_uppercase());
            line.push_str(&gaps[1..]);
            line.push('.');
        }
    }
    line.push(' ');
    match &f.since_previous_run {
        None => line.push_str("First run."),
        Some(c) => {
            let counts = format!(
                "+{} added, {} changed, {} removed",
                grouped(c.added),
                grouped(c.changed),
                grouped(c.removed)
            );
            line.push_str(&if !f.unknown.is_empty() {
                format!("Since last run: {counts}; {}.", f.unknown.join(", "))
            } else if c.added + c.changed + c.removed == 0 {
                "Since last run: no changes.".to_string()
            } else {
                format!("Since last run: {counts}.")
            });
        }
    }
    if f.set_aside > 0 {
        line.push_str(&format!(
            " {} set aside as no longer read by this version, not counted as removed.",
            count(f.set_aside, "fact", "facts")
        ));
    }
    line.push(' ');
    line.push_str(&match &s.watched {
        None => "Watched places: never read.".to_string(),
        Some(w) => {
            let files = count(w.files, "file", "files");
            let mut said = match (w.first_reading, &w.since_last_reading) {
                (false, Some(c)) => format!(
                    "Watched places: {files}, {} new, {} changed, {} gone since the last reading",
                    c.new, c.changed, c.gone
                ),
                _ => format!("Watched places: {files}, first reading, kept as the baseline"),
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
            said.push('.');
            said
        }
    });
    line.push(' ');
    line.push_str(&match &s.integrity {
        None => "Installed software: never read.".to_string(),
        Some(i) => {
            let counted = format!(
                "Installed software: {}, {}, {}",
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
            said.push('.');
            said
        }
    });
    if let Some(t) = &s.threats {
        let held = |n: u64| count(n, "exploited vulnerability", "exploited vulnerabilities");
        let judged = "matched against nothing in this estate but through the vulnerability records linked to them, so whether any of them affects this estate is not known from it";
        line.push(' ');
        line.push_str(&match (v1::FeedOutcome::try_from(t.outcome), t.entries) {
            (Ok(v1::FeedOutcome::Read), Some(n)) if t.first_reading == Some(true) => {
                format!("CISA catalogue: {}, first reading, kept as the baseline; {judged}.", held(n))
            }
            (Ok(v1::FeedOutcome::Read | v1::FeedOutcome::Unchanged), Some(n)) => format!(
                "CISA catalogue: {}, {} new since the last reading{}; {judged}.",
                held(n),
                grouped(t.new.unwrap_or_default()),
                match t.gone {
                    Some(g) if g > 0 => format!(", {} left the catalogue", grouped(g)),
                    _ => String::new(),
                }
            ),
            (Ok(v1::FeedOutcome::Failed), Some(n)) => format!(
                "CISA catalogue not read: {}; what is new is unknown, and the {} it held at its last reading, {}, are {judged}.",
                quoted(t.reason_text.as_deref().unwrap_or_default()),
                held(n),
                when(t.read_at, "an unknown time")
            ),
            (Ok(v1::FeedOutcome::Failed), None) => format!(
                "CISA catalogue not read: {}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown.",
                quoted(t.reason_text.as_deref().unwrap_or_default())
            ),
            _ => "CISA catalogue: never read; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown.".to_string(),
        });
    }
    if let Some(d) = &s.vulnerability_data {
        let clauses: Vec<String> = d
            .feeds
            .iter()
            .map(|f| {
                // Every clause that says it is for a feed read whole, which has its counts.
                let held = format!(
                    "{}, {} of them on malicious packages",
                    count(f.records.unwrap_or_default(), "record", "records"),
                    grouped(f.malicious_records.unwrap_or_default())
                );
                let since = when(f.changed_at.or(f.read_at), "an unknown time");
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
                        format!("{}: {held}, unchanged since {since}", f.ecosystem)
                    }
                    _ => {
                        let reason = quoted(f.reason_text.as_deref().unwrap_or_default());
                        match f.read_at {
                            Some(at) => format!(
                                "{} not read: {reason}; the {held}, read {}, stay in force",
                                f.ecosystem,
                                view::utc(at)
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
        line.push_str(&format!(
            " Vulnerability data from OSV: {}{matched}.",
            clauses.join("; ")
        ));
    }
    line
}

/// `immune status`: what the last finished check left, for a person, from the message alone.
/// What a person sees first is whether this Mac is in order; every list is cut short here and
/// whole in the message.
pub fn status(s: &v1::Status) -> String {
    let mut out = String::new();
    let store = s.store.clone().unwrap_or_default();
    say(&mut out, &format!("Store: {}.", quoted(&store.path_text)));
    if !store.exists {
        say(&mut out, "There is no store yet; `immune run` makes it.");
        return out;
    }
    match &s.last_run {
        None => say(&mut out, "No run has started."),
        Some(l) => match l.finished_at {
            Some(at) => say(
                &mut out,
                &format!(
                    "Last run: started {}, finished {}.",
                    view::utc(l.started_at),
                    view::utc(at)
                ),
            ),
            None => say(
                &mut out,
                &format!(
                    "The latest run started {} and has not finished: {}.",
                    view::utc(l.started_at),
                    if s.running {
                        "it is running"
                    } else {
                        "it died, and nothing it read is in the store"
                    }
                ),
            ),
        },
    }
    // Every part the message carries is rendered: no branch ends the text before a part that is
    // there, so the text never says less than the answer it renders.
    match &s.last_finished_run {
        None => say(
            &mut out,
            "No run has finished yet, so nothing of a check is counted.",
        ),
        Some(f) => {
            let check = f.check.clone().unwrap_or_default();
            if s.last_run.as_ref().is_some_and(|l| l.id != check.id) {
                say(
                    &mut out,
                    &format!(
                        "The numbers below are what the run that finished {} left.",
                        view::utc(check.finished_at.unwrap_or(check.started_at))
                    ),
                );
            }
            say(&mut out, &counted_sentences(s, f));
        }
    }
    this_mac_said(&mut out, s);
    if let Some(l) = &s.event_level {
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
        say(&mut out, &format!("Event level: {}", line.join(" ")));
    }
    match &s.needs_a_look {
        None => say(
            &mut out,
            "Needs a look: not known yet, no run of this build has looked for findings in this store yet.",
        ),
        Some(n) => {
            let urgent = match n.urgent_total {
                0 => String::new(),
                u => format!(", {} of them urgent", grouped(u)),
            };
            say(
                &mut out,
                &format!("Needs a look: {}{urgent}.", grouped(n.total)),
            );
            let listed: Vec<&v1::ListedFinding> =
                n.items.iter().filter_map(|i| i.finding.as_ref()).collect();
            let rows: Vec<Vec<String>> = listed
                .iter()
                .take(STATUS_ROWS)
                .map(|l| {
                    vec![
                        view::utc(l.last_seen_at),
                        finding_level(l.finding.as_ref()),
                        what(&l.title, l.thing.as_deref()),
                        quoted(&l.where_text),
                        l.finding.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
                    ]
                })
                .collect();
            if !rows.is_empty() {
                out.push_str(&table(
                    &["Last seen", "Level", "What", "Where", "Id"],
                    &rows,
                ));
            }
            if n.total > rows.len() as u64 {
                // How many urgent ones are not shown: over all of them, from the count, never
                // from the rows the answer holds.
                let urgent_shown = listed
                    .iter()
                    .take(STATUS_ROWS)
                    .filter(|l| l.finding.as_ref().is_some_and(|r| r.urgent))
                    .count() as u64;
                say(
                    &mut out,
                    &format!(
                        "{} more are not listed here, {} of them urgent; `immune findings` lists every one.",
                        grouped(n.total - rows.len() as u64),
                        grouped(n.urgent_total.saturating_sub(urgent_shown))
                    ),
                );
            }
        }
    }
    // What nobody can fix is a limit of this version only when it holds on every Mac; what a
    // reading of this Mac raised is told as not judged here.
    let every_mac = |u: &v1::Uncovered| u.holds_on == v1::HoldsOn::EveryMac as i32;
    for (who, on_every_mac, head) in [
        ("you", None, "You can fix"),
        ("nothing", Some(true), "Limit of this version"),
        ("nothing", Some(false), "Not judged on this Mac"),
    ] {
        for u in s
            .not_covered
            .iter()
            .filter(|u| u.who == who && on_every_mac.is_none_or(|e| every_mac(u) == e))
        {
            // Told apart from the words, as data: the examples, each with what its source said
            // of it, and the value a source gave. The words never hold a name taken from the Mac.
            let shown: Vec<String> = u
                .examples_text
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    let reason = u.examples.get(i).and_then(|e| e.reason_text.as_deref());
                    match reason {
                        Some(r) => format!("{}: {}", quoted(name), quoted(r)),
                        None => quoted(name),
                    }
                })
                .chain(u.value_text.as_deref().map(quoted))
                .collect();
            let also = if shown.is_empty() {
                String::new()
            } else {
                format!(" ({})", shown.join("; "))
            };
            say(&mut out, &format!("{head}: {}{also}", u.title));
        }
    }
    if let Some(c) = &s.coverage {
        say(
            &mut out,
            &format!(
                "Coverage at the latest {}: {} full, {} failed, {} with no reader, {} where the source does not give it, {} with nothing to read, {} implied by {}.",
                count(c.readings, "reading", "readings"),
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
        );
        let rows: Vec<Vec<String>> = c
            .unreached
            .iter()
            .take(STATUS_ROWS)
            .map(|u| {
                vec![
                    u.scope_text.clone(),
                    view::utc(u.since_at),
                    u.reason_text.clone().unwrap_or_default(),
                ]
            })
            .collect();
        if !rows.is_empty() {
            out.push_str(&table(&["Not reached", "Since", "Why"], &rows));
        }
        let shown: Vec<&v1::ReadingGroup> = c
            .problems
            .iter()
            .filter(|g| g.class != v1::ReadingClass::ReadNothing as i32)
            .collect();
        let rows: Vec<Vec<String>> = shown
            .iter()
            .take(STATUS_ROWS)
            .map(|g| {
                vec![
                    word::<v1::ReadingClass>(g.class).replace('_', " "),
                    g.reader.clone(),
                    g.kind.clone(),
                    g.count.to_string(),
                    // Text from the Mac, as data.
                    g.examples_text
                        .first()
                        .map(|e| quoted(e))
                        .unwrap_or_default(),
                    g.reason_text.as_deref().map(quoted).unwrap_or_default(),
                ]
            })
            .collect();
        if !rows.is_empty() {
            out.push_str(&table(
                &["Class", "Reader", "What", "Readings", "For example", "Why"],
                &rows,
            ));
        }
        if shown.len() > rows.len() {
            say(
                &mut out,
                &format!(
                    "{} more; `immune status --json` lists them.",
                    count(
                        (shown.len() - rows.len()) as u64,
                        "group of readings",
                        "groups of readings"
                    )
                ),
            );
        }
    }
    if let Some(list) = s.no_reader_for.as_ref().filter(|l| !l.items.is_empty()) {
        say(&mut out, "This build has no reader for:");
        let rows: Vec<Vec<String>> = list
            .items
            .iter()
            .take(STATUS_ROWS)
            .map(|r| {
                vec![
                    r.what.clone(),
                    r.what_text.as_deref().map(quoted).unwrap_or_default(),
                    r.where_count.to_string(),
                ]
            })
            .collect();
        out.push_str(&table(&["What", "Which", "Places"], &rows));
    }
    if let Some(w) = &s.watched {
        let rows: Vec<Vec<String>> = w
            .changes
            .iter()
            .take(STATUS_ROWS)
            .map(|c| {
                vec![
                    view::utc(c.at),
                    word::<v1::Change>(c.change),
                    c.kind.clone(),
                    c.path_text.clone(),
                ]
            })
            .collect();
        say(
            &mut out,
            &format!(
                "Latest changes in watched places, newest first, {} of {}:",
                rows.len(),
                w.changes_total
            ),
        );
        out.push_str(&table(&["When", "Change", "Kind", "Path"], &rows));
    }
    say(
        &mut out,
        "All of it, with every list, is in `immune status --json`.",
    );
    out
}

/// A finding's severity, and whether it is urgent, as one cell.
fn finding_level(r: Option<&v1::FindingRef>) -> String {
    r.map_or_else(String::new, |r| {
        format!(
            "{}{}",
            severity(r.severity),
            if r.urgent { ", urgent" } else { "" }
        )
    })
}

/// Whether this Mac is watched, and whether what the status says is fresh.
fn this_mac_said(out: &mut String, s: &v1::Status) {
    let Some(m) = &s.this_mac else {
        say(out, "This Mac: whether it is watched is not said.");
        return;
    };
    let state = match v1::ThisMacState::try_from(m.state) {
        Ok(v1::ThisMacState::Watched) => "watched",
        Ok(v1::ThisMacState::WatchedInPart) => "watched in part",
        _ => "not checked yet",
    };
    let failed: Vec<String> = s
        .watching
        .as_ref()
        .map(|w| {
            w.failed
                .iter()
                .map(|f| crate::watch::failed_words(&f.what).to_string())
                .collect()
        })
        .unwrap_or_default();
    let live = if m.live {
        "a watcher runs now".to_string()
    } else if !failed.is_empty() {
        format!(
            "a watcher runs, but its latest {} failed, so it does not watch live",
            failed.join(" and ")
        )
    } else {
        "no watcher runs now".to_string()
    };
    say(
        out,
        &format!(
            "This Mac: {state}; {live}; last checked {}.",
            when(m.checked_at, "never")
        ),
    );
    if !m.fresh {
        say(
            out,
            &format!(
                "Not fresh: {}. Do not take it for calm until a check finishes.",
                m.stale_reason
                    .as_deref()
                    .unwrap_or("the core does not say why")
            ),
        );
    }
    let watched: Vec<String> = m
        .watched
        .iter()
        .map(|w| format!("{}: {} ({})", w.what, grouped(w.count), w.how))
        .collect();
    if !watched.is_empty() {
        say(out, &format!("Watched: {}.", watched.join(", ")));
    }
}

/// A rule's level as a person reads it: `no level stated` for a rule whose set states none.
fn level_said(level: i32) -> String {
    match v1::Level::try_from(level) {
        Ok(v1::Level::NotStated) => sigma::NO_LEVEL.to_string(),
        _ => word::<v1::Level>(level),
    }
}

/// A rule by its title and its set in words, as every listing for a person names it.
fn rule_label(r: &v1::ShippedRule) -> String {
    match &r.rule {
        Some(rule) => format!("{} ({})", rule.title_text, rule.set),
        None => format!("{} ({})", r.file, r.set),
    }
}

/// Why a rule is not evaluated, in the core's words.
fn reason_said(r: &v1::ShippedRule) -> String {
    let given_by = match r.events.as_deref() {
        Some(sigma::FILE_CATEGORY) => "a file event",
        _ => "a program start",
    };
    use v1::UnevaluatedReason as R;
    let said = match r.reason.map(R::try_from) {
        Some(Ok(R::NeedsEvents)) => format!(
            "needs {} events",
            r.events_text.as_deref().unwrap_or_default()
        ),
        Some(Ok(R::NeedsFields)) => format!(
            "needs {}, which {given_by} does not give",
            r.fields_text.join(", ")
        ),
        Some(Ok(R::KeywordSearch)) => "searches whole messages for keywords".into(),
        Some(Ok(R::NotParsed)) => format!(
            "could not be read: {}",
            r.said_text.as_deref().unwrap_or_default()
        ),
        Some(Ok(R::Sequence)) => {
            "correlates a sequence of events, which is not translated".into()
        }
        Some(Ok(R::NotEql)) => "is not written in EQL, the only language translated".into(),
        Some(Ok(R::BackslashInWildcard)) => {
            "has a backslash in a wildcard pattern, whose meaning in Elasticsearch is not documented".into()
        }
        Some(Ok(R::SpansKinds)) => "is about program starts and file events at once".into(),
        Some(Ok(R::NeverTrue)) => "could never be true over the events here".into(),
        Some(Ok(R::Regex)) => {
            "needs a regular expression in EQL's syntax, which is not translated".into()
        }
        Some(Ok(R::Unsupported)) => "uses a function of EQL's that is not translated".into(),
        Some(Ok(R::Function)) => {
            "compares one field with another, which a Sigma rule cannot".into()
        }
        _ => "is not evaluated for a reason this build does not name".into(),
    };
    match &r.detail_text {
        Some(d) => format!("{said} ({d})"),
        None => said,
    }
}

/// `immune rules`: where the rules come from, whether they watch now, and each rule by its place
/// and level, from the message alone.
pub fn rules(m: &v1::Rules) -> String {
    let mut out = String::new();
    let sources: Vec<String> = m
        .sources
        .iter()
        .map(|s| {
            let t = s.totals.unwrap_or_default();
            let at = match &s.commit_date {
                Some(date) => format!("at {} of {date}", s.commit.get(..12).unwrap_or(&s.commit)),
                None => format!("at {}", s.commit.get(..12).unwrap_or(&s.commit)),
            };
            let levels = if s.states_levels {
                ""
            } else {
                ", none with a level stated"
            };
            if s.translated {
                format!(
                    "{} from {} {at}, {} of them translated into Sigma and shipped, {} not taken{levels}",
                    t.shipped + t.not_taken,
                    s.set,
                    t.shipped,
                    t.not_taken
                )
            } else {
                format!("{} from {} {at}, all shipped{levels}", t.shipped, s.set)
            }
        })
        .collect();
    let head = format!("Published rules for macOS: {}.", sources.join("; "));
    let now = m.now.clone().unwrap_or_default();
    say(&mut out, &rules_said(&head, &now));
    let row = |r: &v1::ShippedRule| {
        let matched = match r.matches_last_day {
            Some(n) if n > 0 => format!(" · matched {} in the last day", count(n, "time", "times")),
            _ => String::new(),
        };
        let level = r
            .rule
            .as_ref()
            .map_or("?".to_string(), |rule| level_said(rule.level));
        format!("  {level:<15} {}{matched}", rule_label(r))
    };
    let not_stated = |r: &v1::ShippedRule| {
        r.rule
            .as_ref()
            .is_some_and(|x| x.level == v1::Level::NotStated as i32)
    };
    // The rules of a set that states no level come after the rest under their own heading, as
    // a group and never as a rank.
    let group = |out: &mut String,
                 rules: &[v1::ShippedRule],
                 more: &dyn Fn(&mut String, &v1::ShippedRule)| {
        let silent = rules.iter().filter(|r| not_stated(r)).count();
        let mut headed = false;
        for r in rules {
            if not_stated(r) && !headed {
                headed = true;
                say(
                    out,
                    &format!(
                        "  {}: {silent}",
                        crate::pages::capital(sigma::NO_LEVEL_GROUP)
                    ),
                );
            }
            say(out, &row(r));
            more(out, r);
        }
    };
    let process = m
        .evaluated
        .iter()
        .filter(|r| r.events.as_deref() == Some(m.events.as_str()))
        .count();
    say(
        &mut out,
        &format!(
            "Evaluated in full: {}, {} on every program start and {} on every file created or renamed",
            m.evaluated.len(),
            process,
            m.evaluated.len() - process
        ),
    );
    group(&mut out, &m.evaluated, &|_, _| {});
    say(
        &mut out,
        &format!(
            "Evaluated in part, some alternatives never match here: {}",
            m.in_part.len()
        ),
    );
    group(&mut out, &m.in_part, &|out, r| {
        let given_by = match r.events.as_deref() {
            Some(sigma::FILE_CATEGORY) => "a file event",
            _ => "a program start",
        };
        for b in &r.never_matches {
            let said = match (&b.selection_text, b.fields_text.is_empty()) {
                (Some(selection), _) => format!(
                    "{selection} needs {}, which {given_by} does not give",
                    b.fields_text.join(", ")
                ),
                (None, false) => format!(
                    "an alternative of the upstream rule needs {}, which {given_by} does not give",
                    b.fields_text.join(", ")
                ),
                (None, true) => format!(
                    "an alternative of the upstream rule was left out in translation: {}",
                    b.left_out_text.as_deref().unwrap_or("")
                ),
            };
            say(out, &format!("      {said}"));
        }
    });
    say(
        &mut out,
        &format!("Not evaluated: {}", m.not_evaluated.len()),
    );
    group(&mut out, &m.not_evaluated, &|out, r| {
        say(out, &format!("      {}", reason_said(r)));
    });
    let raised = m.drill.iter().filter(|d| d.raised).count();
    let must = m
        .drill
        .first()
        .map(|d| d.must_raise.clone())
        .unwrap_or_default();
    let title = m
        .evaluated
        .iter()
        .chain(&m.in_part)
        .filter_map(|r| r.rule.as_ref())
        .find(|r| r.id_text == must)
        .map_or(must.clone(), |r| r.title_text.clone());
    say(
        &mut out,
        &format!(
            "Drill, Atomic Red Team T1027.001: {raised} of {} program starts raise {title}.",
            m.drill.len()
        ),
    );
    out
}

/// What the rules do here now, after where they come from: the sentence the status's page and
/// `immune rules` share.
pub fn rules_said(head: &str, r: &v1::RulesNow) -> String {
    let (Some(true), Some(watching_rules)) = (r.watching, r.watching_rules) else {
        // Before any reading of the event level, whether it is on is not known.
        let state = if r.watching.is_none() {
            "Whether it is on is not known yet: it has not been read, so none of them is known to be watching."
        } else {
            "It is not on, so none of them is watching."
        };
        return format!(
            "{head} Once the event level is on, every program start on this Mac is checked against them. {state}"
        );
    };
    let watching_file_rules = r.watching_file_rules.unwrap_or(0);
    let matched = count(r.matches_last_day.unwrap_or(0), "time", "times");
    let mut said = if r.file_events_collected == Some(true) {
        format!(
            "{head} The event level is on, so {} of them are watching this Mac: {} every program start and {} every file created or renamed; {} more are checked in part. In the last day they matched {matched}.",
            watching_rules,
            watching_rules - watching_file_rules,
            watching_file_rules,
            r.in_part
        )
    } else {
        format!(
            "{head} The event level is on, so {} of them are watching every program start on this Mac, and {} more are checked in part. The {} rules for files created or renamed are not watching: the collector installed here records program starts only, and installing the event level again adds file events. In the last day they matched {matched}.",
            watching_rules, r.in_part, r.file_rules
        )
    };
    if let Some(note) = &r.judged_note {
        said.push(' ');
        said.push_str(note);
    }
    said
}

/// `immune rules --over-log`: per rule that matched, its level and count, never a command line.
pub fn replay(m: &v1::Replay) -> String {
    let mut out = String::new();
    if m.outcome != v1::ReplayOutcome::Read as i32 {
        say(
            &mut out,
            "The event level is not installed here, so there is no log to replay.",
        );
        return out;
    }
    say(
        &mut out,
        &format!(
            "The event log on disk holds {} and {}; the rules matched {}. Nothing was stored.",
            count(
                m.program_starts.unwrap_or_default(),
                "program start",
                "program starts"
            ),
            count(
                m.file_events.unwrap_or_default(),
                "file event",
                "file events"
            ),
            count(m.matches_total.unwrap_or_default(), "time", "times")
        ),
    );
    let not_stated = |h: &v1::ReplayMatch| {
        h.rule
            .as_ref()
            .is_some_and(|r| r.level == v1::Level::NotStated as i32)
    };
    let silent = m.matched.iter().filter(|h| not_stated(h)).count();
    let mut headed = false;
    for h in &m.matched {
        if not_stated(h) && !headed {
            headed = true;
            say(
                &mut out,
                &format!(
                    "  {}: {silent}",
                    crate::pages::capital(sigma::NO_LEVEL_GROUP)
                ),
            );
        }
        let rule = h.rule.clone().unwrap_or_default();
        say(
            &mut out,
            &format!(
                "  {:<15} {:>7}  {} ({})",
                level_said(rule.level),
                h.matches,
                rule.title_text,
                rule.set
            ),
        );
    }
    out
}

/// `immune vulnerabilities`: what cannot be told first, then the "affects" answers.
pub fn vulnerabilities(m: &v1::Vulnerabilities) -> String {
    let mut out = String::new();
    // Every part the message carries is rendered, whatever is missing beside it.
    match &m.totals {
        // Nothing was counted: why, in the core's words, and never a 0.
        None => {
            let why = m
                .not_computed
                .first()
                .map_or("there is no store", |n| n.reason.as_str());
            say(&mut out, &format!("Nothing is known yet: {why}."));
        }
        // Packages whose answer cannot be told are said in the first sentence, so that nothing
        // reads as calm where the data it needs was not read.
        Some(t) => {
            say(
                &mut out,
                &format!(
                    "{} in packages your projects use; for {} whether one affects them cannot be told; {} known not to affect them.",
                    count(
                        t.affected_records,
                        "known vulnerability",
                        "known vulnerabilities"
                    ),
                    count(t.unknown_packages, "package", "packages"),
                    grouped(t.not_affected_known)
                ),
            );
            for f in &t.feeds {
                if let Some(why) = &f.not_current_why {
                    say(
                        &mut out,
                        &format!("The {} data is not current: {why}.", f.ecosystem),
                    );
                }
            }
        }
    }
    let rows: Vec<Vec<String>> = m
        .affected
        .iter()
        .flat_map(|a| &a.items)
        .map(|a| {
            let r = a.record.clone().unwrap_or_default();
            let releases: Vec<String> = a
                .releases
                .iter()
                .map(|x| format!("{} {}", x.version_text, x.at_text))
                .collect();
            vec![
                r.label.clone(),
                format!("{} ({})", r.id_text, r.source),
                format!("{} {}", a.package_text, releases.join(", ")),
                a.project_text.clone(),
                r.fixed_text.join(", "),
            ]
        })
        .collect();
    if !rows.is_empty() {
        out.push_str(&table(
            &["Label", "Record", "Package", "Project", "Fixed in"],
            &rows,
        ));
    }
    let reasons: Vec<String> = m
        .totals
        .iter()
        .flat_map(|t| &t.unknown_by_reason)
        .map(|c| format!("{} {}", c.name, c.count))
        .collect();
    if !reasons.is_empty() {
        say(
            &mut out,
            &format!("Cannot be told, by reason: {}.", reasons.join(", ")),
        );
    }
    say(&mut out, &m.declared_note);
    out
}

/// `immune vulnerability <id>`: the answer in every place, record by record.
pub fn vulnerability(m: &v1::Vulnerability) -> String {
    let mut out = String::new();
    // Every part the message carries is rendered: no branch ends the text before one.
    match m.data.map(v1::RecordData::try_from) {
        Some(Ok(v1::RecordData::Held)) => {}
        None => say(
            &mut out,
            "Nothing is known yet: there is no store; `immune run` makes it.",
        ),
        _ => say(&mut out, m.said.as_deref().unwrap_or_default()),
    }
    say(
        &mut out,
        match m.in_catalogue {
            Some(true) => "It is on the list of vulnerabilities attackers are using.",
            Some(false) => "It is not on the list of vulnerabilities attackers are using.",
            None => {
                "Whether it is on the list of vulnerabilities attackers are using is not known: the list was not read."
            }
        },
    );
    place_answers(&mut out, &m.answers, "");
    for r in &m.records {
        say(
            &mut out,
            &format!(
                "{} from {}, {}, modified {}:",
                quoted(&r.record_text),
                r.record_source,
                r.ecosystem,
                quoted(&r.modified_text)
            ),
        );
        if !r.answered {
            say(
                &mut out,
                &format!("  {}", r.said.as_deref().unwrap_or_default()),
            );
            continue;
        }
        place_answers(&mut out, &r.answers, "  ");
    }
    say(&mut out, &m.declared_note);
    out
}

/// The answer in each place, a line for each package the record names, or one for the place.
fn place_answers(out: &mut String, answers: &[v1::PlaceAnswer], indent: &str) {
    let answer = |a: Option<i32>| word::<v1::PackageAnswer>(a.unwrap_or_default());
    for a in answers {
        let project = quoted(&a.project_text);
        if a.packages.is_empty() {
            say(
                out,
                &format!(
                    "{indent}{project}: {}{}",
                    answer(a.answer),
                    a.reason
                        .as_deref()
                        .map(|r| format!(", {r}"))
                        .unwrap_or_default()
                ),
            );
        }
        for p in &a.packages {
            say(
                out,
                &format!(
                    "{indent}{project}: {} {} ({})",
                    quoted(&p.package_text),
                    answer(Some(p.answer)),
                    quoted(&p.detail_text)
                ),
            );
        }
    }
}

/// `immune sample`: counts only.
pub fn sample(m: &v1::Sample) -> String {
    let p = m.processes.unwrap_or_default();
    let i = m.interpreters.unwrap_or_default();
    let c = m.connections.unwrap_or_default();
    let mut out = String::new();
    say(
        &mut out,
        &format!(
            "Sample: {} processes read, {} unreadable, {} of other users not read; {} interpreters, \
             {} given code on the command line, {} of them detached; {} connections. \
             Tracking {} new, {} again; {} findings opened. Took {} ms.",
            p.read,
            p.unreadable,
            p.other_users,
            i.seen,
            i.inline_code,
            i.inline_code_detached,
            c.read,
            m.tracked_new,
            m.tracked_again,
            m.findings_opened,
            m.took_ms
        ),
    );
    say(
        &mut out,
        &format!("A sample cannot see: {}.", m.cannot_see.join("; ")),
    );
    out
}

/// `immune owner`: the statements that stand.
pub fn statements(m: &v1::Statements) -> String {
    let mut out = String::new();
    say(
        &mut out,
        &format!(
            "The owner's word: {}.",
            count(
                m.statements.len() as u64,
                "statement stands",
                "statements stand"
            )
        ),
    );
    let rows: Vec<Vec<String>> = m
        .statements
        .iter()
        .map(|s| {
            vec![
                s.machine_text.clone(),
                s.said.clone(),
                view::utc(s.at),
                s.reason_text.clone(),
                s.names_text.join(", "),
                s.seen_after.as_ref().map_or("nothing".to_string(), |e| {
                    format!(
                        "contradicted: {}, {}",
                        view::utc(e.at),
                        quoted(&e.what_text)
                    )
                }),
            ]
        })
        .collect();
    out.push_str(&table(
        &[
            "Machine",
            "Said",
            "Since",
            "Reason",
            "Also known as",
            "Seen alive after it",
        ],
        &rows,
    ));
    if m.withdrawn > 0 {
        say(
            &mut out,
            &format!(
                "{} withdrawn and kept.",
                count(m.withdrawn, "statement was", "statements were")
            ),
        );
    }
    out
}

/// `immune owner <name> retired|not-mine|withdraw`: what was said or withdrawn, and the sweep
/// script written again.
pub fn statement_made(m: &v1::StatementMade) -> String {
    let mut out = String::new();
    match &m.done {
        Some(v1::statement_made::Done::Said(s)) => {
            say(
                &mut out,
                &format!(
                    "Said: {} is {}, {}: {}",
                    quoted(&m.machine_text),
                    s.said,
                    view::utc(s.at),
                    quoted(&s.reason_text)
                ),
            );
            if !s.reason_cuts.is_empty() {
                say(
                    &mut out,
                    "Its reason held what Immune recognises as a secret, and is kept with it cut.",
                );
            }
            if s.replaced > 0 {
                say(
                    &mut out,
                    "It replaces the statement that stood about the same machine, which is kept.",
                );
            }
        }
        Some(v1::statement_made::Done::Withdrawn(w)) => {
            for s in &w.statements {
                say(
                    &mut out,
                    &format!(
                        "Withdrawn: the statement that {} is {} no longer stands, and is kept.",
                        quoted(&s.machine_text),
                        s.said
                    ),
                );
            }
        }
        None => {}
    }
    let names: Vec<String> = m.names_text.iter().map(|n| quoted(n)).collect();
    say(
        &mut out,
        &format!(
            "It covers the machine under every name: {}.",
            names.join(", ")
        ),
    );
    match m
        .sweep
        .as_ref()
        .map(|s| (s.servers, s.problem_text.as_deref()))
    {
        Some((Some(n), _)) => say(
            &mut out,
            &format!(
                "The sweep script was written again: it visits {}.",
                count(n, "server", "servers")
            ),
        ),
        Some((None, problem)) => say(
            &mut out,
            &format!(
                "The sweep script could not be written again: {}.",
                quoted(problem.unwrap_or_default())
            ),
        ),
        None => {}
    }
    out
}

/// A failure, as a person reads it on stderr: the core's words, what it quotes, the ids a
/// question fits, and a call that would be right.
pub fn failure(f: &v1::Failure) -> String {
    let mut out = String::new();
    for e in &f.errors {
        match &e.detail_text {
            Some(detail) => say(
                &mut out,
                &format!("immune: {}: {}", e.message, quoted(detail)),
            ),
            None => say(&mut out, &format!("immune: {}", e.message)),
        }
        for id in &e.ids_text {
            say(&mut out, &format!("  {}", quoted(id)));
        }
        if let Some(example) = &e.example {
            say(&mut out, &format!("For example: {example}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_from_a_source_never_ends_its_quotation_or_its_line() {
        // A value made to read as the program's own words after a closed quotation, on a line
        // of its own: escaped one to one as the contract escapes it, then quoted.
        let made = crate::known::whole("x\"\nThe store knows nothing more.");
        let shown = quoted(&made);
        assert_eq!(shown, r#""x\"\u{a}The store knows nothing more.""#);
        assert!(!shown.contains('\n'));
    }

    #[test]
    fn a_findings_list_that_reaches_its_text_limit_says_how_many_it_shows() {
        let found = |i| v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: format!("id-{i:04}"),
                state: v1::FindingState::Open as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: (1..=201).map(found).collect(),
            ..Default::default()
        };
        let text = findings(&f, false);
        assert!(text.starts_with("201 open findings."), "{text}");
        assert!(text.contains("id-0200"), "{text}");
        assert!(!text.contains("id-0201"), "{text}");
        assert!(
            text.contains("Showing the first 200; 1 more not shown, 0 of them urgent."),
            "{text}"
        );
        assert!(
            text.contains("Latest full check finished 1970-01-01 00:00 UTC."),
            "{text}"
        );
    }

    #[test]
    fn every_finding_as_text_puts_open_ones_first_and_its_cut_says_how_many_hidden_are_urgent() {
        // The answer's order is urgent first across states: closed urgent findings come before
        // open ones that are not urgent. Open ones are shown first all the same.
        let found = |i: usize, state: v1::FindingState, urgent: bool| v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: format!("id-{i:04}"),
                state: state as i32,
                urgent,
                ..Default::default()
            }),
            ..Default::default()
        };
        let closed = (0..150).map(|i| found(i, v1::FindingState::Expected, true));
        let open = (150..300).map(|i| found(i, v1::FindingState::Open, false));
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: closed.chain(open).collect(),
            ..Default::default()
        };
        let text = findings(&f, true);
        assert!(text.starts_with("300 findings."), "{text}");
        // All 150 open ones, then the first 50 closed ones; 100 closed urgent ones are hidden.
        assert!(
            text.contains("id-0299") && text.contains("id-0049"),
            "{text}"
        );
        assert!(!text.contains("id-0050"), "{text}");
        assert!(
            text.contains("Showing the first 200; 100 more not shown, 100 of them urgent."),
            "{text}"
        );
    }

    #[test]
    fn the_text_of_an_id_no_record_names_still_gives_the_answer_in_each_place_and_the_catalogue() {
        // An id on the catalogue that no record names: the message carries an answer per place,
        // and the text renders it after what the data could not say.
        let m = v1::Vulnerability {
            data: Some(v1::RecordData::NoRecord as i32),
            said: Some("No record names it.".to_string()),
            in_catalogue: Some(true),
            answers: vec![v1::PlaceAnswer {
                project_text: "~/dev/shop".to_string(),
                answer: Some(v1::PackageAnswer::Unknown as i32),
                ..Default::default()
            }],
            declared_note: "Declared.".to_string(),
            ..Default::default()
        };
        let text = vulnerability(&m);
        assert!(text.contains("No record names it."), "{text}");
        assert!(text.contains("\"~/dev/shop\": "), "{text}");
        assert!(
            text.contains("It is on the list of vulnerabilities attackers are using."),
            "{text}"
        );
        assert!(text.contains("Declared."), "{text}");
        // Without a store, what the catalogue says is not known, and never "not on it".
        let text = vulnerability(&v1::Vulnerability::default());
        assert!(text.contains("is not known"), "{text}");
    }

    #[test]
    fn the_status_text_says_how_many_of_the_findings_it_does_not_show_are_urgent() {
        // Ten rows are shown; of the 120 not shown, the urgent ones are counted from Immune's
        // count over all of them, including those the message itself does not list.
        let look = |i: usize, urgent: bool| v1::LookFinding {
            finding: Some(v1::ListedFinding {
                finding: Some(v1::FindingRef {
                    id: format!("id-{i:04}"),
                    severity: Some(v1::Level::High as i32),
                    urgent,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let s = v1::Status {
            store: Some(v1::StoreFile {
                exists: true,
                ..Default::default()
            }),
            needs_a_look: Some(v1::NeedsALook {
                items: (0..100).map(|i| look(i, i < 12)).collect(),
                total: 130,
                urgent_total: 15,
            }),
            ..Default::default()
        };
        let text = status(&s);
        assert!(
            text.contains("id-0009") && !text.contains("id-0010"),
            "{text}"
        );
        assert!(text.contains("  high, urgent  "), "{text}");
        assert!(
            text.contains("120 more are not listed here, 5 of them urgent;"),
            "{text}"
        );
    }

    #[test]
    fn a_finding_keeps_an_unread_place_visible_without_a_reason_and_treats_unknown_change_as_changed()
     {
        for (change, expected) in [
            (
                v1::Change::NotRead as i32,
                "The place could not be read. The store gives no reason.",
            ),
            (v1::Change::Unspecified as i32, "latest change: changed."),
            (i32::MAX, "latest change: changed."),
        ] {
            let message = v1::Finding {
                evidence: Some(v1::Evidence {
                    body: Some(v1::evidence::Body::PlaceChanged(v1::PlaceChanged {
                        change,
                        presence_only: None,
                    })),
                }),
                ..Default::default()
            };
            let text = finding(&message);
            assert!(text.contains(expected), "{text}");
        }
    }
}
