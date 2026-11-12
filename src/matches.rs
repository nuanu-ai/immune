//! `immune matches`: every match of the published rules over the collector's log, of every
//! level, each with the event it matched, printed as the contract's `Matches` message
//! (`contract/immune/v1/matches.proto`). The response layer reads it to look into what the core
//! is not sure of.
//!
//! Nothing is written to the store. The queue is the day's log read again from the caller's
//! place by `events::queue`, which evaluates every event with the same call the core's own
//! reading makes (`Into::judge` in `src/events.rs`), so the two cannot disagree about what
//! matched. The place is the one the core's own reading keeps for itself, per log file its
//! identity and how far it was read, printed as an opaque token (`events::Place`). The store is
//! only read: whether the core's own reading has read a line yet, which finding its match went
//! to, and the collector's state as `immune status` serves it.
//!
//! No false calm. An answer with no matches says how many lines were read and evaluated, how
//! many could not be, what eslogger's numbering says was lost, whether lines were deleted
//! before they were read, the collector's state, and which rules judge nothing here and why. A
//! collector that is not installed is an answer that says so, not a failure. A store that is not
//! there, or cannot be read, is a failure: without it the answer could not say what became of a
//! match.
//!
//! Which finding a match went to is what the core's own reading recorded when it read the line
//! (`rule_line`), never a guess.

use crate::contract::{v1, value_of};
use crate::events::{self, Evidence, Hit, LineAt, Place, Queue, Stretch, WentTo};
use crate::sigma::{Kind, Meta, Placement, Reason, Rules};
use crate::{findings, known, status, store, view};
use prost::Message;
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// The version of the contract this build prints.
const FORMAT: u32 = 1;
/// How many matches one answer holds unless `--limit` says otherwise. A match of a program
/// start is about a kilobyte of JSON and half that in binary, measured on invented logs, so the
/// default answer is about a megabyte; `events::BYTES` keeps one with very long command lines
/// small too.
pub const LIMIT: usize = 1000;

const AFTER: &str = "--after takes the place an answer of immune matches printed in continue_after, whole and as printed";

/// Why rules for file events judge nothing while the collector is not installed.
const NOT_INSTALLED: &str = "the event level is not installed";

/// `immune matches`.
pub struct MatchesArgs {
    pub store: PathBuf,
    pub json: bool,
    /// The place given with `--after`, as given, and as read.
    pub after: Option<(String, Place)>,
    pub limit: usize,
    /// The folder `/Library` is resolved under: `/` unless a test gives another.
    pub system_root: PathBuf,
}

/// Reads the arguments after `matches`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<MatchesArgs, String> {
    let (mut store, mut form, mut after, mut limit, mut root) = (None, None, None, LIMIT, None);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            "--system-root" => root = Some(crate::value(&mut it, &arg)?.into()),
            _ if known::take_form(&arg, &mut form)? => {}
            "--after" => {
                let p = crate::value(&mut it, &arg)?;
                let place = Place::parse(&p).ok_or(AFTER)?;
                after = Some((p, place));
            }
            "--limit" => {
                limit = crate::value(&mut it, &arg)?
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--limit takes a whole number of at least 1")?;
            }
            _ => return Err(format!("unexpected argument: {arg}")),
        }
    }
    Ok(MatchesArgs {
        store: store.map_or_else(crate::default_store, Ok)?,
        json: form == Some(known::Form::Json),
        after,
        limit,
        system_root: root.unwrap_or_else(|| PathBuf::from("/")),
    })
}

/// Why an answer could not be given.
enum Failure {
    Store(String),
    Log(String),
}

/// Answers `immune matches`: the message on stdout, binary or JSON, or a failure: nothing on
/// stdout in binary, the envelope with `--json`, and the exit codes the report commands use.
pub fn matches_cmd(args: &MatchesArgs) -> ExitCode {
    let answer = match read(args, crate::now_secs()) {
        Ok(answer) => answer,
        Err(Failure::Store(why)) => {
            return fail(
                args.json,
                "store_unreadable",
                "the store cannot be read, so what became of a match cannot be told; nothing was evaluated",
                why,
                crate::EXIT_STORE,
            );
        }
        Err(Failure::Log(why)) => {
            return fail(
                args.json,
                "log_unreadable",
                "the event log could not be read, so nothing was evaluated",
                why,
                1,
            );
        }
    };
    if args.json {
        match serde_json::to_string(&answer) {
            Ok(line) => println!("{line}"),
            Err(e) => {
                return fail(
                    true,
                    "store_unreadable",
                    "the answer could not be printed",
                    e.to_string(),
                    crate::EXIT_STORE,
                );
            }
        }
    } else if std::io::stdout()
        .write_all(&answer.encode_to_vec())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn fail(json: bool, code: &str, message: &str, why: String, exit: u8) -> ExitCode {
    if json {
        let failure = status::failure(
            Some("matches"),
            code,
            message,
            "immune matches --json",
            &why,
        );
        println!("{}", known::envelope(failure));
    } else {
        eprintln!("immune: {message}: {}", view::shown(&why));
    }
    ExitCode::from(exit)
}

/// What the store says about the log, read in one transaction.
struct Held {
    /// Where the core's own reading has read each log file up to.
    read_to: BTreeMap<String, (u64, u64)>,
    /// The collector's state as the latest reading left it, and when.
    state: Option<(String, i64)>,
    /// The findings by id, as a match names them.
    findings: BTreeMap<String, v1::FindingRef>,
}

fn read(args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
    if !args.store.is_file() {
        return Err(Failure::Store(format!(
            "there is no store at {}; `immune run` makes it",
            args.store.display()
        )));
    }
    let unreadable = |e: &dyn std::fmt::Display| Failure::Store(e.to_string());
    let conn = store::open_read_only(&args.store).map_err(|e| unreadable(&e))?;
    let tx = conn.unchecked_transaction().map_err(|e| unreadable(&e))?;
    let held = Held {
        read_to: events::read_up_to(&tx).map_err(|e| unreadable(&e))?,
        state: events::state_read(&tx).map_err(|e| unreadable(&e))?,
        findings: finding_refs(&tx, now).map_err(|e| unreadable(&e))?,
    };
    let after = args.after.as_ref();
    let queue = events::queue(&args.system_root, after.map(|(_, p)| p), args.limit, now);
    let mut answer = v1::Matches {
        format: FORMAT,
        answered_at: now,
        after: after.map(|(text, _)| text.clone()),
        store_id: store::id(&tx).map_err(|e| unreadable(&e))?,
        ..Default::default()
    };
    let status_state = |c: &mut v1::Collector| {
        c.status_state = held
            .state
            .as_ref()
            .map(|(s, _)| value_of::<v1::CollectorState>(s));
        c.status_read_at = held.state.as_ref().map(|(_, at)| *at);
    };
    match queue {
        Queue::Failed(why) => return Err(Failure::Log(why)),
        Queue::NotInstalled { gone } => {
            let mut collector = v1::Collector {
                state: v1::CollectorState::NotInstalled as i32,
                ..Default::default()
            };
            status_state(&mut collector);
            answer.collector = Some(collector);
            answer.stretch = Some(v1::Stretch {
                gone,
                ..Default::default()
            });
            answer.unevaluated = unevaluated(&Err(NOT_INSTALLED.to_string()));
        }
        Queue::Read(s) => {
            let mut collector = collector(&s);
            status_state(&mut collector);
            for hit in &s.hits {
                let event = event(&hit.event);
                for (file, meta) in &hit.matched {
                    let (raised, findings) =
                        raised(&tx, &held, hit, meta).map_err(|e| unreadable(&e))?;
                    answer.matches.push(v1::RuleMatch {
                        position: hit.at.to_string(),
                        rule: Some(rule(file, meta)),
                        event: Some(event.clone()),
                        raised: raised as i32,
                        findings,
                    });
                }
            }
            answer.collector = Some(collector);
            answer.stretch = Some(stretch(&s));
            answer.unevaluated = unevaluated(&s.collects.clone().map_err(|(_, why)| why));
            answer.continue_after = Some(s.place.to_string());
            answer.more = s.more;
        }
    }
    Ok(answer)
}

/// What became of a match among the findings, and the findings it went to.
fn raised(
    conn: &Connection,
    held: &Held,
    hit: &Hit,
    meta: &Meta,
) -> rusqlite::Result<(v1::Raised, Vec<v1::FindingRef>)> {
    if !meta.level.raises() {
        return Ok((v1::Raised::BelowHigh, Vec::new()));
    }
    let at: &LineAt = &hit.at;
    let read = held
        .read_to
        .get(&at.file)
        .is_some_and(|(inode, to)| *inode == at.inode && at.offset < *to);
    if !read {
        return Ok((v1::Raised::NotReadYet, Vec::new()));
    }
    Ok(match events::went_to(conn, at, &meta.finding_rule)? {
        WentTo::Finding(id) => {
            // Every finding of a shipped rule is among them; the id alone stands for one that
            // is not.
            let finding = held.findings.get(&id).cloned();
            let finding = finding.unwrap_or(v1::FindingRef {
                id,
                ..Default::default()
            });
            (v1::Raised::Finding, vec![finding])
        }
        WentTo::None => (v1::Raised::NoFinding, Vec::new()),
        WentTo::Unrecorded => (v1::Raised::Unrecorded, Vec::new()),
    })
}

/// Every finding in the store, by id, as `immune project` and the others name one.
fn finding_refs(conn: &Connection, now: i64) -> rusqlite::Result<BTreeMap<String, v1::FindingRef>> {
    let Some(found) = findings::all(conn, now)? else {
        return Ok(BTreeMap::new());
    };
    Ok(found
        .iter()
        .filter_map(findings::item)
        .map(|i| (i.id.clone(), known::finding_ref(&i)))
        .collect())
}

/// When an event happened, as seconds and nanoseconds.
fn happened(e: &Evidence) -> Option<(i64, u32)> {
    events::instant(match e {
        Evidence::Start(s) => &s.timestamp,
        Evidence::File(f) => &f.timestamp,
    })
}

/// Text from the Mac or from a rule, whole, with hidden characters escaped. Every `_text` value
/// of the answer passes through here.
fn whole(s: &str) -> String {
    known::whole(s)
}

pub fn rule(file: &str, m: &Meta) -> v1::Rule {
    v1::Rule {
        name: m.finding_rule.clone(),
        file: file.to_string(),
        id_text: whole(&m.id),
        title_text: whole(&m.title),
        level: value_of::<v1::Level>(m.level.as_str()),
        techniques_text: m.techniques.iter().map(|t| whole(t)).collect(),
        author_text: m.author.as_deref().map(whole),
    }
}

/// A process the log gives only the program of.
fn program(executable: &str) -> v1::Process {
    v1::Process {
        executable_text: whole(executable),
        ..Default::default()
    }
}

/// An event as the contract gives it: every field the log holds, each whole.
pub fn event(e: &Evidence) -> v1::Event {
    use v1::event::Body;
    let when = happened(e);
    let (happened_at, happened_nanos) = (when.map(|w| w.0), when.map(|w| w.1));
    v1::Event {
        body: Some(match e {
            Evidence::Start(s) => Body::ProgramStart(v1::ProgramStart {
                happened_at,
                happened_nanos,
                process: Some(v1::Process {
                    executable_text: whole(&s.executable),
                    pid: Some(s.pid),
                    user_id: s.user_id,
                    signing_id_text: s.signing_id.as_deref().map(whole),
                    team_id_text: s.team_id.as_deref().map(whole),
                    platform_binary: s.platform_binary,
                }),
                instigator: s.parent_executable.as_deref().map(program),
                parent_pid: s.parent_pid,
                args_text: s.args.iter().map(|a| whole(a)).collect(),
                working_directory_text: s.working_directory.as_deref().map(whole),
            }),
            Evidence::File(f) => Body::FileEvent(v1::FileEvent {
                happened_at,
                happened_nanos,
                action: value_of::<v1::FileAction>(f.action),
                path_text: whole(&f.path),
                source_text: f.source.as_deref().map(whole),
                instigator: Some(program(&f.executable)),
            }),
        }),
    }
}

fn stretch(s: &Stretch) -> v1::Stretch {
    let n = |v: i64| v.max(0) as u64;
    v1::Stretch {
        program_starts: n(s.tally.starts),
        file_events: n(s.file_tally.files),
        other: n(s.tally.other),
        unreadable_lines: n(s.tally.unreadable),
        unreadable_file_events: n(s.file_tally.unreadable),
        program_starts_lost: n(s.tally.lost),
        program_starts_unknown_losses: n(s.tally.unknown_gaps),
        file_events_lost: n(s.file_tally.lost),
        file_events_unknown_losses: n(s.file_tally.unknown_gaps),
        gone: s.gone,
        kept_from: s.kept_from.as_ref().map(LineAt::to_string),
    }
}

fn collector(s: &Stretch) -> v1::Collector {
    v1::Collector {
        state: value_of::<v1::CollectorState>(s.state),
        said_by: s.said.as_ref().map(|(by, _)| by.to_string()),
        said_text: s.said.as_ref().map(|(_, said)| whole(said)),
        written_at: s.written,
        file_events_collected: s.collects.is_ok(),
        foreign_files: s.foreign,
        ..Default::default()
    }
}

/// The shipped rules that judge nothing here, or only in part, each with why, in the order they
/// are shipped. `collects` is whether file events are collected here, or why not.
fn unevaluated(collects: &Result<(), String>) -> Vec<v1::Unevaluated> {
    use v1::UnevaluatedReason as Why;
    let not_collected = collects.as_ref().err();
    let texts = |items: &[String]| items.iter().map(|s| whole(s)).collect();
    Rules::shipped()
        .rules
        .iter()
        .filter_map(|l| {
            // For a rule a translated set did not take, what the translation said of it.
            let said = l.detail.map(str::to_string);
            let (why, fields, detail): (Why, Vec<String>, Option<String>) =
                match (&l.placement, not_collected) {
                    (Placement::NotEvaluated(r), _) => match r {
                        Reason::NeedsEvents(c) => (Why::NeedsEvents, Vec::new(), Some(c.clone())),
                        Reason::NeedsFields(f) => (Why::NeedsFields, texts(f), said),
                        Reason::KeywordSearch => (Why::KeywordSearch, Vec::new(), None),
                        Reason::NotParsed(s) => (Why::NotParsed, Vec::new(), Some(s.clone())),
                        Reason::Sequence => (Why::Sequence, Vec::new(), said),
                        Reason::NotEql => (Why::NotEql, Vec::new(), said),
                        Reason::BackslashInWildcard => (Why::BackslashInWildcard, Vec::new(), said),
                        Reason::SpansKinds => (Why::SpansKinds, Vec::new(), said),
                    },
                    (_, Some(why)) if l.kind == Some(Kind::File) => {
                        (Why::NotCollected, Vec::new(), Some(why.clone()))
                    }
                    (Placement::InPart(branches), _) => {
                        let mut fields: Vec<String> =
                            branches.iter().flat_map(|b| b.fields.clone()).collect();
                        fields.sort();
                        fields.dedup();
                        // What a translation left out that is not a missing field, such as a
                        // pattern it could not carry, as it wrote it.
                        let left: Vec<&str> = branches
                            .iter()
                            .filter(|b| b.fields.is_empty())
                            .filter_map(|b| b.said.as_deref())
                            .collect();
                        let detail = (!left.is_empty()).then(|| left.join("; "));
                        (Why::InPart, texts(&fields), detail)
                    }
                    (Placement::Evaluated, _) => return None,
                };
            let meta = l.meta.as_ref();
            Some(v1::Unevaluated {
                file: l.file.to_string(),
                name: meta.map(|m| m.finding_rule.clone()),
                id_text: meta.map(|m| whole(&m.id)),
                title_text: meta.map(|m| whole(&m.title)),
                level: meta.map(|m| value_of::<v1::Level>(m.level.as_str())),
                reason: why as i32,
                fields_text: fields,
                detail_text: detail.map(|d| whole(&d)),
            })
        })
        .collect()
}
