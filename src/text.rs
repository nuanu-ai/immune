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
use crate::screen::{Screen, Step};
use crate::{store, view};
use std::fmt::Write;

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
        Ok(v1::Presence::Unknown) if k.thing.is_some() => {
            "is unknown: the store knows it and cannot tell whether it is there now, since a reading of it was not full"
        }
        Ok(v1::Presence::Unknown) => {
            "is unknown: the store holds nothing by this name or at this place"
        }
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

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
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

/// How many projects have no lockfile this version reads, as one counted item.
fn without_lockfile(n: u64) -> String {
    format!(
        "{} no lockfile this version reads",
        if n == 1 {
            "1 project has".to_string()
        } else {
            format!("{} projects have", grouped(n))
        }
    )
}

/// What the line about known vulnerabilities adds when not every project was wholly read: how
/// many were not, beside the count of known vulnerabilities, so that it never reads as all.
pub fn not_wholly_read(not_read: u64, no_lockfile: u64) -> String {
    let mut out = String::new();
    if not_read > 0 {
        out.push_str(&format!(
            ", and the lockfiles of {} were not all read",
            count(not_read, "project", "projects")
        ));
    }
    if no_lockfile > 0 {
        out.push_str(&format!(", and {}", without_lockfile(no_lockfile)));
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
                .map_or(store::NO_STORE_REASON, |n| n.reason.as_str());
            if why == store::NO_STORE_REASON {
                for line in no_store(&Screen::pipe()) {
                    say(&mut out, &line);
                }
            } else {
                say(&mut out, &format!("Nothing is known yet: {why}."));
            }
        }
        // What cannot be told opens the first sentence: the projects whose lockfiles were not
        // all read, those with no lockfile this version reads, then the packages whose answer
        // cannot be told. Only then what is known, so nothing reads as calm where the data it
        // needs was not read; "no known vulnerability" opens it only when at least one project
        // was compared and nothing at all could not be told. Records, packages and the rows of
        // the table are each counted as what they are.
        Some(t) => {
            let mut not_told: Vec<String> = Vec::new();
            if t.projects_not_read > 0 {
                not_told.push(format!(
                    "The lockfiles of {} were not all read",
                    count(t.projects_not_read, "project", "projects")
                ));
            }
            if t.projects_without_lockfile > 0 {
                not_told.push(without_lockfile(t.projects_without_lockfile));
            }
            if t.unknown_packages > 0 {
                not_told.push(format!(
                    "for {} whether a known vulnerability affects them cannot be told",
                    count(t.unknown_packages, "package", "packages")
                ));
            }
            let affecting = if t.affected_records > 0 {
                format!(
                    "{} {} {} in {}",
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
                    count(t.affected_packages, "package", "packages"),
                    count(t.affected_projects, "project", "projects")
                )
            } else if t.projects_compared == 0 {
                "no project's lockfiles were compared in full with current vulnerability data, so none is known to be affected or not".to_string()
            } else if not_told.is_empty() {
                "No known vulnerability affects the packages your projects use".to_string()
            } else {
                "none is known to affect the others".to_string()
            };
            not_told.push(affecting);
            let first = not_told.join("; ");
            let mut letters = first.chars();
            let first: String = letters
                .next()
                .map(|c| c.to_uppercase().chain(letters).collect())
                .unwrap_or_default();
            // "Known not to affect" is said only of what was compared.
            let known = if t.projects_compared > 0 || t.not_affected_known > 0 {
                format!(
                    "; {} known not to affect them",
                    grouped(t.not_affected_known)
                )
            } else {
                String::new()
            };
            say(&mut out, &format!("{first}{known}."));
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
        let total = m.affected.as_ref().map_or(0, |a| a.total);
        let shown = if (rows.len() as u64) < total {
            format!(", the first {} of them listed", grouped(rows.len() as u64))
        } else {
            String::new()
        };
        say(
            &mut out,
            &format!(
                "A row for each package in a project and each vulnerability that affects it: {}{shown}.",
                count(total, "row", "rows")
            ),
        );
        out.push_str(&table(
            &["Label", "Record", "Package", "Project", "Fixed in"],
            &rows,
        ));
    }
    // The projects whose lockfiles were not all read, the first few when there are many.
    if let Some(u) = m.unread.as_ref().filter(|u| u.total > 0) {
        say(
            &mut out,
            &format!(
                "Not every lockfile was read in {}{}, so what they declare is not all known; a row for each project and ecosystem, {} in all:",
                count(
                    m.totals.as_ref().map_or(0, |t| t.projects_not_read),
                    "project",
                    "projects"
                ),
                match m.totals.as_ref().map_or(0, |t| t.projects_without_lockfile) {
                    0 => String::new(),
                    n => format!(", and {}", without_lockfile(n)),
                },
                grouped(u.total)
            ),
        );
        let rows: Vec<Vec<String>> = u
            .items
            .iter()
            .take(UNKNOWN_SHOWN)
            .map(|p| {
                vec![
                    p.project_text.clone(),
                    p.ecosystem.clone(),
                    p.why_text.clone().unwrap_or_else(|| p.lockfiles.clone()),
                ]
            })
            .collect();
        out.push_str(&table(&["Project", "Ecosystem", "Why"], &rows));
        let left = u.total.saturating_sub(rows.len() as u64);
        if left > 0 {
            say(
                &mut out,
                &format!("{} more not listed here.", grouped(left)),
            );
        }
    }
    // The packages that cannot be told, by name, the first few when there are many.
    if let Some(u) = m.unknown.as_ref().filter(|u| u.total > 0) {
        say(
            &mut out,
            &format!(
                "Whether a known vulnerability affects them cannot be told for {}:",
                count(u.total, "package", "packages")
            ),
        );
        let rows: Vec<Vec<String>> = u
            .items
            .iter()
            .take(UNKNOWN_SHOWN)
            .map(|p| {
                vec![
                    p.project_text.clone(),
                    format!("{} {}", p.ecosystem, p.package_text),
                    p.reason.clone(),
                ]
            })
            .collect();
        out.push_str(&table(&["Project", "Package", "Why"], &rows));
        let left = u.total.saturating_sub(rows.len() as u64);
        if left > 0 {
            let reasons: Vec<String> = m
                .totals
                .iter()
                .flat_map(|t| &t.unknown_packages_by_reason)
                .map(|c| format!("{} {}", c.name, c.count))
                .collect();
            say(
                &mut out,
                &format!(
                    "{} more not listed here; all of them by reason: {}.",
                    grouped(left),
                    reasons.join(", ")
                ),
            );
        }
    }
    say(&mut out, &m.declared_note);
    out
}

/// At most this many packages that cannot be told are named in the text of
/// `immune vulnerabilities`; the total is always given.
const UNKNOWN_SHOWN: usize = 10;

/// `immune vulnerability <id>`: the answer in every place, record by record.
pub fn vulnerability(m: &v1::Vulnerability) -> String {
    let mut out = String::new();
    // Every part the message carries is rendered: no branch ends the text before one.
    match m.data.map(v1::RecordData::try_from) {
        Some(Ok(v1::RecordData::Held)) => {}
        None => {
            for line in no_store(&Screen::pipe()) {
                say(&mut out, &line);
            }
        }
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

/// The answer in each place, a line for each package the record names, or one for the place. A
/// place is a project's lockfiles of one ecosystem, so the ecosystem is named on each line: one
/// project has a line for each.
fn place_answers(out: &mut String, answers: &[v1::PlaceAnswer], indent: &str) {
    let answer = |a: Option<i32>| word::<v1::PackageAnswer>(a.unwrap_or_default());
    for a in answers {
        let project = format!("{} {}", quoted(&a.project_text), a.ecosystem);
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

/// What `immune install` or `immune uninstall` left: where the core runs from and what to ask
/// next, or what was removed and what was kept.
pub fn service(m: &v1::Service) -> String {
    let mut out = String::new();
    if m.installed {
        say(
            &mut out,
            &format!(
                "The core is installed at {}, and launchd has loaded its login job {}.",
                quoted(&m.program_path_text),
                m.label
            ),
        );
        say(
            &mut out,
            "The job is set to start a full check when the core starts and every hour after that.",
        );
        say(&mut out, "immune status says what has been read.");
    } else if m.replaced {
        say(
            &mut out,
            &format!(
                "The login job {} is not loaded, and no property list or installed core of it is left.",
                m.label
            ),
        );
        say(
            &mut out,
            "The store and the optional event collector were kept.",
        );
    } else {
        say(
            &mut out,
            &format!(
                "Nothing was installed: no login job {}, property list or installed core was found.",
                m.label
            ),
        );
    }
    out
}

/// What an answer tells a person when there is no store at the path, in the words a failure
/// gives (`store::NO_STORE`): the sentence, then what makes one. Every command says it so.
pub fn no_store(screen: &Screen) -> Vec<String> {
    let mut first = store::NO_STORE.to_string();
    first[..1].make_ascii_uppercase();
    let mut out = vec![screen.paint(crate::screen::BOLD, &format!("{first}."))];
    out.extend(screen.marked(store::NO_STORE_FIX, screen.fits()));
    out
}

/// A failure, as a person reads it on stderr: each of its errors in the one form of an error.
pub fn failure(f: &v1::Failure, screen: &Screen) -> String {
    f.errors.iter().map(|e| error(e, screen)).collect()
}

/// A refusal of a command the person typed, told as `error` tells it but with `next`, the
/// command to run next made from what was typed (`usage::finding_next`), in place of the
/// example the message carries for an agent.
pub fn refusal(f: &v1::Failure, next: &str, screen: &Screen) -> String {
    f.errors
        .iter()
        .map(|e| told(e, Some(next), screen))
        .collect()
}

/// One error of a failure in the one form of an error (`Screen::error`), rendered from the
/// error alone: its cause in Immune's words, what to do, and what it quotes under a label. The
/// two conditions of a store that every command meets, none at the path and one of another
/// format, are worded once (`store::NO_STORE`, `store::OTHER_FORMAT`), whichever command met
/// them; their exit codes and the message itself are as each command gives them.
pub fn error(e: &v1::Error, screen: &Screen) -> String {
    told(e, None, screen)
}

/// One error, with the command to run next when the caller made one from what was typed.
fn told(e: &v1::Error, next: Option<&str>, screen: &Screen) -> String {
    let detail = e.detail_text.as_deref().unwrap_or_default();
    let condition = match e.code.as_str() {
        // `immune owner` names the path alone, under a code of its own.
        "no_store" => store::Condition::Absent(detail),
        "store_unreadable" | "command_failed" => store::condition(detail),
        _ => store::Condition::Other,
    };
    match condition {
        store::Condition::Absent(path) => {
            return screen.error(
                store::NO_STORE,
                &[Step::Words(store::NO_STORE_FIX.to_string())],
                &[("Store", path)],
            );
        }
        store::Condition::OtherFormat(path) => {
            return screen.error(
                store::OTHER_FORMAT,
                &[Step::Words(store::OTHER_FORMAT_FIX.to_string())],
                &[("Store", path)],
            );
        }
        store::Condition::Other => {}
    }
    if e.code == "run_in_progress" {
        return screen.error(
            "another check is running on this store",
            &[Step::Words(
                "Nothing was done. Try again when it ends, or see it with: `immune status`"
                    .to_string(),
            )],
            &[],
        );
    }
    // The message is the cause, and what was done about it, after "; nothing was", a step.
    let (cause, done) = match e.message.split_once("; nothing was ") {
        Some((cause, done)) => (cause, Some(format!("Nothing was {done}."))),
        None => (e.message.as_str(), None),
    };
    let mut steps: Vec<Step> = done.into_iter().map(Step::Words).collect();
    let label = match e.code.as_str() {
        "changed_since_read" => "Finding",
        code if code.ends_with("_unreadable")
            || code.ends_with("_failed")
            || code.ends_with("_unchecked") =>
        {
            "Reason"
        }
        _ => "Given",
    };
    // What failed to be read or done is not helped by running a command again.
    if let Some(next) = next {
        steps.push(Step::Command(next.to_string()));
    } else if label != "Reason"
        && let Some(example) = e.example.as_deref().and_then(example_for_a_person)
    {
        steps.push(Step::Words(example));
    }
    let mut quoted: Vec<(&str, &str)> = Vec::new();
    if !detail.is_empty() {
        quoted.push((label, detail));
    }
    for (i, id) in e.ids_text.iter().enumerate() {
        quoted.push((if i == 0 { "Fits" } else { "" }, id));
    }
    screen.error(cause, &steps, &quoted)
}

/// An error's example as a person is shown it: without `--json` and `--proto`, a form the
/// person did not ask for, and only where it says more than a command again, as "ask for one
/// of them by its id, as in: …" does. A bare command line is the command that failed, or
/// another, and is left out.
fn example_for_a_person(example: &str) -> Option<String> {
    let plain = example.replace(" --json", "").replace(" --proto", "");
    let says_more = plain.split(' ').any(|w| {
        w.len() >= 3
            && w.bytes().all(|b| b.is_ascii_lowercase())
            && w != "immune"
            && !crate::usage::is_command(w)
    });
    says_more.then_some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code a failure of the binary can carry, from the reference's tables and the source.
    const CODES: &[&str] = &[
        "another_job",
        "another_store",
        "busy",
        "case_too_long",
        "changed_since_read",
        "command_failed",
        "empty_case",
        "empty_reason",
        "finding_closed",
        "finding_not_answered",
        "holds_secret",
        "home_not_absolute",
        "journal_seq_ahead",
        "log_unreadable",
        "match_gone",
        "no_login_session",
        "no_statement",
        "no_store",
        "no_such_match",
        "not_a_file",
        "not_a_folder",
        "not_a_machine",
        "not_a_program",
        "not_a_project",
        "not_a_verdict",
        "not_installed",
        "not_removed",
        "not_staged",
        "not_the_pair",
        "reason_too_long",
        "run_as_root",
        "run_failed",
        "run_in_progress",
        "sample_failed",
        "secrets_unchecked",
        "several_machines",
        "several_programs",
        "source_not_a_file",
        "spelled_otherwise",
        "stop_failed",
        "store_unreadable",
        "symbolic_link",
        "too_large",
        "unknown_finding",
        "unknown_machine",
        "unreadable",
        "usage",
        "watch_failed",
        "watch_in_progress",
    ];

    #[test]
    fn every_refusal_is_told_as_one_error_with_one_cause_and_never_the_usage() {
        for code in CODES {
            let e = crate::answer::error(
                code,
                "a cause in the core's words; nothing was changed",
                "ask for one of them by its id, as in: immune project <id> --json",
                "a detail",
            );
            for screen in [Screen::pipe(), Screen::terminal(80, false)] {
                let said = error(&e, &screen);
                let lines: Vec<&str> = said.lines().collect();
                assert!(lines[0].starts_with("error: "), "{code}: {said}");
                assert!(
                    lines[1..].iter().all(|l| l.starts_with("  ")),
                    "{code}: {said}"
                );
                assert!(
                    !said.contains("usage:") && !said.contains("--json"),
                    "{code}: {said}"
                );
                assert!(lines.len() <= 5, "{code}: {said}");
            }
        }
    }

    #[test]
    fn a_failure_says_what_was_done_and_its_example_only_where_it_says_more_than_a_command() {
        let said = |code: &str, example: &str| {
            error(
                &crate::answer::error(code, "a cause; nothing was recorded", example, "what"),
                &Screen::pipe(),
            )
        };
        assert_eq!(
            said(
                "not_a_project",
                "immune program asks about a program --json"
            ),
            "error: a cause\n  Nothing was recorded.\n  immune program asks about a program\n  \
             Given   what\n"
        );
        // A command again, or another command, is no help.
        assert_eq!(
            said("not_a_project", "immune status --json --store <file>"),
            "error: a cause\n  Nothing was recorded.\n  Given   what\n"
        );
        // Nor anything for what could not be read or done, whatever its example says.
        assert_eq!(
            said("run_failed", "immune finding <id> seen"),
            "error: a cause\n  Nothing was recorded.\n  Reason   what\n"
        );
    }

    #[test]
    fn hostile_text_in_a_failure_s_detail_cannot_forge_a_line_or_a_style() {
        let hostile = format!(
            "x\u{1b}[31mred\u{9b}31m\u{202e}evil\u{200b}\nerror: forged\n→ immune install{}error: forged too",
            " ".repeat(90)
        );
        for code in ["store_unreadable", "run_failed", "unknown_finding", "usage"] {
            let e = crate::answer::error(code, "a cause", "", &hostile);
            for screen in [
                Screen::pipe(),
                Screen::terminal(80, true),
                Screen::terminal(30, true),
            ] {
                let said = error(&e, &screen);
                let visible = crate::screen::visible(&said);
                let starts = |w: &str| visible.lines().filter(|l| l.starts_with(w)).count();
                assert_eq!(starts("error:"), 1, "{said}");
                assert_eq!(starts("→"), 0, "{said}");
                assert!(
                    !visible.chars().any(|c| c != '\n' && crate::icu::hidden(c)),
                    "{said:?}"
                );
                // Every escape is one this module wrote: a style, opened and closed.
                assert_eq!(
                    said.matches('\u{1b}').count(),
                    said.matches("\u{1b}[0m").count() * 2,
                    "{said:?}"
                );
            }
            assert!(!error(&e, &Screen::pipe()).contains('\u{1b}'));
        }
    }

    #[test]
    fn no_store_and_another_format_are_worded_once_whatever_command_met_them() {
        let none = crate::store::absent(std::path::Path::new("/x/store.db"));
        let older = "the store at /x/store.db is from an older format (5); this version uses \
                     format 6 and does not convert old stores. Nothing was changed.";
        let cases = [
            (
                "store_unreadable",
                "the store cannot be read; nothing was changed",
                none.clone(),
            ),
            (
                "store_unreadable",
                "the store cannot be read, so what became of a match cannot be told; nothing was evaluated",
                none.clone(),
            ),
            (
                "no_store",
                "there is no store at the path given; `immune run` makes it",
                "/x/store.db".to_string(),
            ),
            (
                "command_failed",
                "immune view could not finish",
                format!("the store cannot be read: {none}"),
            ),
        ];
        for (code, message, detail) in &cases {
            let said = error(
                &crate::answer::error(code, message, "", detail),
                &Screen::pipe(),
            );
            assert_eq!(
                said,
                "error: there is no store here yet\n  immune run makes one, or immune install, \
                 which also keeps it checked.\n  Store   /x/store.db\n",
                "{code}"
            );
        }
        let newer = "the store at /x/store.db is from a newer format (7) than this version \
                     knows (6). Nothing was changed.";
        for (code, detail) in [
            ("store_unreadable", older),
            ("command_failed", older),
            ("store_unreadable", newer),
        ] {
            let said = error(
                &crate::answer::error(code, "m", "", detail),
                &Screen::pipe(),
            );
            assert!(
                said.starts_with("error: this store was made by another build of Immune\n  It was left unchanged."),
                "{said}"
            );
            assert!(said.ends_with("  Store   /x/store.db\n"), "{said}");
        }
    }

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
    fn the_text_of_an_id_no_record_names_still_gives_the_answer_in_each_place_and_the_catalogue() {
        // An id on the catalogue that no record names: the message carries an answer per place,
        // and the text renders it after what the data could not say.
        let m = v1::Vulnerability {
            data: Some(v1::RecordData::NoRecord as i32),
            said: Some("No record names it.".to_string()),
            in_catalogue: Some(true),
            answers: vec![v1::PlaceAnswer {
                project_text: "~/dev/shop".to_string(),
                ecosystem: "npm".to_string(),
                answer: Some(v1::PackageAnswer::Unknown as i32),
                ..Default::default()
            }],
            declared_note: "Declared.".to_string(),
            ..Default::default()
        };
        let text = vulnerability(&m);
        assert!(text.contains("No record names it."), "{text}");
        // A project has a line for each ecosystem, so each line names its ecosystem.
        assert!(text.contains("\"~/dev/shop\" npm: unknown"), "{text}");
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
    fn the_list_of_vulnerabilities_names_the_first_packages_that_cannot_be_told_and_counts_the_rest()
     {
        // Twelve packages cannot be told: the first ten are named, and the two left are counted
        // with every reason, so none is hidden behind a number alone.
        let unknown: Vec<v1::UnknownPackage> = (0..12)
            .map(|i| v1::UnknownPackage {
                project_text: "~/dev/shop".to_string(),
                ecosystem: "npm".to_string(),
                package_text: format!("pkg-{i:02}"),
                reason: "version_cannot_be_compared".to_string(),
            })
            .collect();
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                unknown_packages: 12,
                unknown_packages_by_reason: vec![v1::Count {
                    name: "version_cannot_be_compared".to_string(),
                    count: 12,
                }],
                ..Default::default()
            }),
            unknown: Some(v1::UnknownPackages {
                items: unknown,
                total: 12,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m);
        assert!(text.contains("cannot be told for 12 packages:"), "{text}");
        assert!(text.contains("npm pkg-09"), "{text}");
        assert!(!text.contains("pkg-10"), "{text}");
        assert!(
            text.contains(
                "2 more not listed here; all of them by reason: version_cannot_be_compared 12."
            ),
            "{text}"
        );
        // Rows the message does not carry are counted, never dropped from the count.
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals::default()),
            affected: Some(v1::AffectedPackages {
                items: vec![v1::AffectedPackage::default()],
                total: 3,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m);
        assert!(
            text.contains("affects it: 3 rows, the first 1 of them listed."),
            "{text}"
        );
    }

    #[test]
    fn the_list_of_vulnerabilities_opens_with_what_cannot_be_told_and_is_calm_only_when_nothing_is()
    {
        let first = |t: v1::VulnerabilityTotals| {
            let m = v1::Vulnerabilities {
                totals: Some(t),
                ..Default::default()
            };
            vulnerabilities(&m)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        };
        // Nothing that cannot be told, and a project compared: the calm sentence.
        assert_eq!(
            first(v1::VulnerabilityTotals {
                projects_compared: 1,
                ..Default::default()
            }),
            "No known vulnerability affects the packages your projects use; 0 known not to affect them."
        );
        // Nothing compared: never calm, and nothing said to be known not to affect.
        let nothing = "No project's lockfiles were compared in full with current vulnerability data, so none is known to be affected or not.";
        assert_eq!(first(v1::VulnerabilityTotals::default()), nothing);
        assert_eq!(
            first(v1::VulnerabilityTotals {
                projects_not_read: 1,
                places_not_read: 1,
                ..Default::default()
            }),
            format!(
                "The lockfiles of 1 project were not all read; n{}",
                &nothing[1..]
            )
        );
        // Packages that cannot be told, lockfiles not all read, projects with no lockfile: each
        // first, one counted item each, and never the calm sentence after them.
        assert_eq!(
            first(v1::VulnerabilityTotals {
                unknown_packages: 12,
                projects_compared: 3,
                ..Default::default()
            }),
            "For 12 packages whether a known vulnerability affects them cannot be told; none is known to affect the others; 0 known not to affect them."
        );
        assert_eq!(
            first(v1::VulnerabilityTotals {
                projects_not_read: 1,
                places_not_read: 1,
                projects_without_lockfile: 40,
                projects_compared: 2,
                not_affected_known: 7,
                ..Default::default()
            }),
            "The lockfiles of 1 project were not all read; 40 projects have no lockfile this version reads; none is known to affect the others; 7 known not to affect them."
        );
        // What affects them comes after what cannot be told.
        assert!(
            first(v1::VulnerabilityTotals {
                unknown_packages: 1,
                affected_records: 2,
                affected_packages: 2,
                affected_projects: 1,
                ..Default::default()
            })
            .starts_with(
                "For 1 package whether a known vulnerability affects them cannot be told; 2 known vulnerabilities affect"
            )
        );
        // The places not all read are named, a project with no package read among them.
        let m = v1::Vulnerabilities {
            totals: Some(v1::VulnerabilityTotals {
                projects_not_read: 1,
                places_not_read: 1,
                ..Default::default()
            }),
            unread: Some(v1::UnreadPlaces {
                items: vec![v1::UnreadPlace {
                    project_text: "~/dev/yarn-only".to_string(),
                    ecosystem: "npm".to_string(),
                    lockfiles: "partial".to_string(),
                    why_text: None,
                }],
                total: 1,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m);
        assert!(text.contains("~/dev/yarn-only"), "{text}");
        // Twelve places: the first ten are named and the rest counted.
        let m = v1::Vulnerabilities {
            unread: Some(v1::UnreadPlaces {
                items: (0..12)
                    .map(|i| v1::UnreadPlace {
                        project_text: format!("~/dev/p{i:02}"),
                        ecosystem: "npm".to_string(),
                        lockfiles: "partial".to_string(),
                        why_text: None,
                    })
                    .collect(),
                total: 12,
            }),
            ..Default::default()
        };
        let text = vulnerabilities(&m);
        assert!(text.contains("~/dev/p09"), "{text}");
        assert!(!text.contains("~/dev/p10"), "{text}");
        assert!(text.contains("2 more not listed here."), "{text}");
    }
}
