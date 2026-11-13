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
fn word<E: TryFrom<i32> + serde::Serialize>(value: i32) -> String {
    E::try_from(value)
        .ok()
        .and_then(|e| serde_json::to_value(e).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unspecified".to_string())
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
        word::<v1::Level>(f.severity),
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
    let shown: Vec<&v1::ListedFinding> = f
        .findings
        .iter()
        .filter(|l| all || l.finding.as_ref().is_some_and(|r| r.state == open))
        .collect();
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
                r.id,
                word::<v1::FindingState>(r.state),
                view::utc(l.last_seen_at),
                l.title.clone(),
                quoted(&l.where_text),
            ]
        })
        .collect();
    out.push_str(&table(
        &["Id", "State", "Last seen", "What", "Where"],
        &rows,
    ));
    if let Some(at) = f.latest_run_at {
        say(
            &mut out,
            &format!("Latest full check finished {}.", view::utc(at)),
        );
    }
    if shown.len() > FINDINGS_SHOWN {
        say(
            &mut out,
            &format!(
                "Showing the first {FINDINGS_SHOWN}. Use --json or --proto for the full list."
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
        format!("severity {}", word::<v1::Level>(r.severity)),
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
        assert!(text.contains("Showing the first 200."), "{text}");
        assert!(
            text.contains("Latest full check finished 1970-01-01 00:00 UTC."),
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
