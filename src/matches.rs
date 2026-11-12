//! `immune matches`: every match of the published rules over the collector's log, of every
//! level, each with the event it matched, printed as the contract's `Matches` message
//! (`contract/immune/v1/matches.proto`). The response layer reads it to look into what the core
//! is not sure of.
//!
//! Nothing is written to the store, per event, per match or at all. The queue is the day's log
//! read again from the caller's position by `events::queue`, which evaluates every event with
//! the same call the core's own reading makes (`Into::judge` in `src/events.rs`), so the two
//! cannot disagree about what matched. The store is only read: whether the core's own reading
//! has read a line yet, which finding a high rule's match went to, and the collector's state as
//! `immune status` serves it.
//!
//! No false calm. An answer with no matches says how many lines were read and evaluated, how
//! many could not be, what eslogger's numbering says was lost, whether lines were deleted
//! before they were read, the collector's state, and which rules judge nothing here and why. A
//! collector that is not installed is an answer that says so, not a failure.
//!
//! Which finding a match went to. The store keeps no event, so a match is tied to a finding by
//! time: a rule raises one finding per Mac, and a new one only after the owner closes the last,
//! so the findings of a rule follow one another, each seen from `first_seen_at` to
//! `last_seen_at`, the times of the readings that matched it. The reading that read an event
//! came after the event, so it went to a finding last seen no earlier than the event. When only
//! one finding of the rule was last seen at or after the event's second, that is the one;
//! otherwise the answer says it cannot tell. A clock set back between the event and its reading
//! would mislead this.

use crate::contract::{v1, value_of};
use crate::events::{self, Evidence, Hit, Position, Queue, Stretch};
use crate::sigma::{Kind, Meta, Placement, Reason, Rules};
use crate::{Stop, status, store, view};
use prost::Message;
use rusqlite::{Connection, params};
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

const AFTER: &str =
    "--after takes a position as immune matches prints it, <hour>:<offset>, as in 20261004T00:4096";

/// `immune matches`.
pub struct MatchesArgs {
    pub store: PathBuf,
    pub json: bool,
    pub after: Option<Position>,
    pub limit: usize,
    /// The folder `/Library` is resolved under: `/` unless a test gives another.
    pub system_root: PathBuf,
}

/// Reads the arguments after `matches`.
pub fn parse(mut it: impl Iterator<Item = String>) -> Result<MatchesArgs, String> {
    let (mut store, mut json, mut after, mut limit, mut root) = (None, false, None, LIMIT, None);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--store" => store = Some(crate::value(&mut it, &arg)?.into()),
            "--system-root" => root = Some(crate::value(&mut it, &arg)?.into()),
            "--json" => json = true,
            "--after" => {
                let p = crate::value(&mut it, &arg)?;
                after = Some(Position::parse(&p).ok_or(AFTER)?);
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
        json,
        after,
        limit,
        system_root: root.unwrap_or_else(|| PathBuf::from("/")),
    })
}

/// Why an answer could not be given.
enum Failure {
    Store(Stop),
    Log(String),
}

/// Answers `immune matches`: the message on stdout, binary or JSON, or a failure the way the
/// report commands give one.
pub fn matches_cmd(args: &MatchesArgs) -> ExitCode {
    let answer = match read(args, crate::now_secs()) {
        Ok(answer) => answer,
        Err(Failure::Store(e)) => return crate::store_failed(args.json, "matches", &e),
        Err(Failure::Log(why)) => {
            if args.json {
                crate::print_json(&status::failure(
                    Some("matches"),
                    "log_unreadable",
                    "the event log could not be read, so nothing was evaluated",
                    "immune matches --json",
                    &why,
                ));
            } else {
                eprintln!(
                    "immune: the event log could not be read: {}",
                    view::shown(&why)
                );
            }
            return ExitCode::FAILURE;
        }
    };
    if args.json {
        match serde_json::to_string(&answer) {
            Ok(line) => println!("{line}"),
            Err(e) => {
                return crate::store_failed(true, "matches", &Stop::Store(e.to_string()));
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

/// What the store says about the log, read in one transaction.
#[derive(Default)]
struct Held {
    /// This Mac as the store names it: what a finding from a published rule is about.
    machine: Option<String>,
    /// Where the core's own reading has read each log file up to.
    read_to: BTreeMap<String, (u64, u64)>,
    /// The collector's state as the latest reading left it, and when.
    state: Option<(String, i64)>,
}

fn read(args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
    let unreadable = |e: &dyn std::fmt::Display| Failure::Store(Stop::Store(e.to_string()));
    // No store is a store that has read nothing: every high match is not read yet.
    let conn = if args.store.is_file() {
        Some(store::open_read_only(&args.store).map_err(|e| unreadable(&e))?)
    } else {
        None
    };
    let tx = match &conn {
        Some(c) => Some(c.unchecked_transaction().map_err(|e| unreadable(&e))?),
        None => None,
    };
    let held = match &tx {
        Some(tx) => Held {
            machine: crate::covered::this_machine(tx).map_err(|e| unreadable(&e))?,
            read_to: events::read_up_to(tx).map_err(|e| unreadable(&e))?,
            state: events::state_read(tx).map_err(|e| unreadable(&e))?,
        },
        None => Held::default(),
    };
    let queue = events::queue(&args.system_root, args.after.as_ref(), args.limit, now);
    let mut answer = v1::Matches {
        format: FORMAT,
        answered_at: now,
        after: args.after.as_ref().map(Position::to_string),
        continue_after: args.after.as_ref().map(Position::to_string),
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
        // Uninstalling deletes the log: what came after a position is gone.
        Queue::NotInstalled => {
            let mut collector = v1::Collector {
                state: v1::CollectorState::NotInstalled as i32,
                ..Default::default()
            };
            status_state(&mut collector);
            answer.collector = Some(collector);
            answer.stretch = Some(v1::Stretch {
                gone: args.after.is_some(),
                ..Default::default()
            });
            answer.unevaluated = unevaluated(None);
        }
        Queue::Read(s) => {
            for hit in &s.hits {
                let event = event(&hit.event);
                for (file, meta) in &hit.matched {
                    let (raised, finding_id) =
                        raised(tx.as_deref(), &held, hit, meta).map_err(|e| unreadable(&e))?;
                    answer.matches.push(v1::RuleMatch {
                        position: hit.at.to_string(),
                        rule: Some(rule(file, meta)),
                        event: Some(event.clone()),
                        raised: raised as i32,
                        finding_id,
                    });
                }
            }
            let mut collector = collector(&s);
            status_state(&mut collector);
            answer.collector = Some(collector);
            answer.stretch = Some(stretch(&s));
            answer.unevaluated = unevaluated(Some(&s.collects));
            answer.continue_after = s.last.as_ref().map(Position::to_string);
            answer.more = s.more;
        }
    }
    Ok(answer)
}

/// What became of a match among the findings, and the finding when it can be told.
fn raised(
    conn: Option<&Connection>,
    held: &Held,
    hit: &Hit,
    meta: &Meta,
) -> rusqlite::Result<(v1::Raised, Option<String>)> {
    if !meta.level.raises() {
        return Ok((v1::Raised::BelowHigh, None));
    }
    let read = held
        .read_to
        .get(&hit.at.file())
        .is_some_and(|(inode, to)| *inode == hit.inode && hit.at.offset < *to);
    if !read {
        return Ok((v1::Raised::NotReadYet, None));
    }
    let (Some(conn), Some(machine)) = (conn, &held.machine) else {
        return Ok((v1::Raised::Untold, None));
    };
    // The reading that read the event came after it, so its finding was last seen no earlier
    // than the event's second. A time that cannot be read leaves every finding of the rule.
    let since = happened(&hit.event).map_or(i64::MIN, |(secs, _)| secs);
    let ids: Vec<String> = conn
        .prepare(
            "SELECT id FROM finding WHERE rule = ?1 AND about = ?2 AND last_seen_at >= ?3
             LIMIT 2",
        )?
        .query_map(params![meta.finding_rule, machine, since], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(match <[String; 1]>::try_from(ids) {
        Ok([id]) => (v1::Raised::Finding, Some(id)),
        Err(_) => (v1::Raised::Untold, None),
    })
}

/// When an event happened, as seconds and nanoseconds.
fn happened(e: &Evidence) -> Option<(i64, u32)> {
    events::instant(match e {
        Evidence::Start(s) => &s.timestamp,
        Evidence::File(f) => &f.timestamp,
    })
}

/// Text from the Mac or from a rule, whole, with hidden characters escaped.
fn whole(s: &str) -> String {
    view::shown(s)
}

fn rule(file: &str, m: &Meta) -> v1::Rule {
    v1::Rule {
        file: file.to_string(),
        id_text: whole(&m.id),
        title_text: whole(&m.title),
        level: value_of::<v1::Level>(m.level.as_str()),
        techniques_text: m.techniques.iter().map(|t| whole(t)).collect(),
        author_text: m.author.as_deref().map(whole),
    }
}

/// An event as the contract gives it: every field the log holds, each whole.
fn event(e: &Evidence) -> v1::Event {
    let when = happened(e);
    let (happened_at, happened_nanos) = (when.map(|w| w.0), when.map(|w| w.1));
    match e {
        Evidence::Start(s) => v1::Event {
            kind: v1::EventKind::ProgramStart as i32,
            program_start: Some(v1::ProgramStart {
                happened_at,
                happened_nanos,
                executable_text: whole(&s.executable),
                args_text: s.args.iter().map(|a| whole(a)).collect(),
                working_directory_text: s.working_directory.as_deref().map(whole),
                pid: s.pid,
                user_id: s.user_id,
                parent_pid: s.parent_pid,
                parent_executable_text: s.parent_executable.as_deref().map(whole),
                signing_id_text: s.signing_id.as_deref().map(whole),
                team_id_text: s.team_id.as_deref().map(whole),
                platform_binary: s.platform_binary,
            }),
            file_event: None,
        },
        Evidence::File(f) => v1::Event {
            kind: v1::EventKind::FileEvent as i32,
            program_start: None,
            file_event: Some(v1::FileEvent {
                happened_at,
                happened_nanos,
                action: value_of::<v1::FileAction>(f.action),
                path_text: whole(&f.path),
                source_text: f.source.as_deref().map(whole),
                executable_text: whole(&f.executable),
            }),
        },
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
        kept_from: s.kept_from.as_ref().map(Position::to_string),
    }
}

fn collector(s: &Stretch) -> v1::Collector {
    v1::Collector {
        state: value_of::<v1::CollectorState>(s.state),
        said_by: s.said.as_ref().map(|(by, _)| by.to_string()),
        said_text: s.said.as_ref().map(|(_, said)| status::text_string(said)),
        written_at: s.written,
        file_events_collected: s.collects.is_ok(),
        ..Default::default()
    }
}

/// The shipped rules that judge nothing here, or only in part, each with why, in the order they
/// are shipped. `collects` is whether the collector here records file events, `None` when there
/// is no collector to ask.
fn unevaluated(collects: Option<&Result<(), (store::Cause, String)>>) -> Vec<v1::Unevaluated> {
    use v1::UnevaluatedReason as Why;
    let not_collected = collects.and_then(|c| c.as_ref().err()).map(|(_, why)| why);
    let texts = |items: &[String]| items.iter().map(|s| status::text_string(s)).collect();
    Rules::shipped()
        .rules
        .iter()
        .filter_map(|l| {
            let (why, fields, detail): (Why, Vec<String>, Option<&String>) =
                match (&l.placement, not_collected) {
                    (Placement::NotEvaluated(r), _) => match r {
                        Reason::NeedsEvents(c) => (Why::NeedsEvents, Vec::new(), Some(c)),
                        Reason::NeedsFields(f) => (Why::NeedsFields, texts(f), None),
                        Reason::KeywordSearch => (Why::KeywordSearch, Vec::new(), None),
                        Reason::NotParsed(said) => (Why::NotParsed, Vec::new(), Some(said)),
                    },
                    (_, Some(why)) if l.kind == Some(Kind::File) => {
                        (Why::NotCollected, Vec::new(), Some(why))
                    }
                    (Placement::InPart(branches), _) => {
                        let mut fields: Vec<String> =
                            branches.iter().flat_map(|b| b.fields.clone()).collect();
                        fields.sort();
                        fields.dedup();
                        (Why::InPart, texts(&fields), None)
                    }
                    (Placement::Evaluated, _) => return None,
                };
            let meta = l.meta.as_ref();
            Some(v1::Unevaluated {
                file: l.file.to_string(),
                id_text: meta.map(|m| whole(&m.id)),
                title_text: meta.map(|m| whole(&m.title)),
                level: meta.map(|m| value_of::<v1::Level>(m.level.as_str())),
                reason: why as i32,
                fields_text: fields,
                detail_text: detail.map(|d| status::text_string(d)),
            })
        })
        .collect()
}
