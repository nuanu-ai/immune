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
use crate::events::{
    self, Arrival, Arrivals, Evidence, Hit, Lacked, LineAt, Place, Queue, Stretch, WentTo,
};
use crate::secrets::Args;
use crate::sigma::{Kind, Meta, Placement, Reason, Rules};
use crate::{answer, findings, known, store, verdict};
use rusqlite::Connection;
use std::collections::BTreeMap;
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
    pub form: answer::Form,
    /// The place given with `--after`, as given, and as read.
    pub after: Option<(String, Place)>,
    pub limit: usize,
    /// The folder `/Library` is resolved under: `/` unless a test gives another.
    pub system_root: PathBuf,
}

/// Reads the arguments after `matches`.
pub fn parse(
    it: impl Iterator<Item = String>,
    options: &mut answer::Options,
) -> Result<MatchesArgs, String> {
    let (mut after, mut limit, mut root) = (None, LIMIT, None);
    options.read(it, |arg, it| {
        match arg.as_str() {
            "--system-root" => root = Some(crate::value(it, &arg)?.into()),
            "--after" => {
                let p = crate::value(it, &arg)?;
                let place = Place::parse(&p).ok_or(AFTER)?;
                after = Some((p, place));
            }
            "--limit" => {
                limit = crate::value(it, &arg)?
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("--limit takes a whole number of at least 1")?;
            }
            _ => return Err(format!("unexpected argument: {arg}")),
        }
        Ok(())
    })?;
    Ok(MatchesArgs {
        store: options.store()?,
        form: options.form(),
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

/// Answers `immune matches` in the form asked, or fails as every command of the contract does,
/// with the exit codes the report commands use.
pub fn matches_cmd(args: &MatchesArgs) -> ExitCode {
    let (code, message, why, exit) = match read(args, crate::now_secs()) {
        Ok(m) => return answer::print("matches", args.form, &m, crate::text::matches),
        Err(Failure::Store(why)) => (
            "store_unreadable",
            "the store cannot be read, so what became of a match cannot be told; nothing was evaluated",
            why,
            crate::EXIT_STORE,
        ),
        Err(Failure::Log(why)) => (
            "log_unreadable",
            "the event log could not be read, so nothing was evaluated",
            why,
            1,
        ),
    };
    let error = answer::error(code, message, "immune matches --json", &why);
    answer::fail("matches", args.form, error, exit)
}

/// What the store says about the log, read in one transaction.
struct Held {
    /// Where the core's own reading has read each log file up to.
    read_to: BTreeMap<String, (u64, u64)>,
    /// The collector's state as the latest reading left it, and when.
    state: Option<(String, i64)>,
    /// The findings by id, as a match names them.
    findings: BTreeMap<String, v1::FindingRef>,
    /// What arrives, as the latest reading stored it: not yet known before any.
    arrivals: Arrivals,
}

fn read(args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
    read_with(Rules::shipped(), args, now)
}

/// `read`, naming in `unevaluated` these rules. Matching itself is the shipped rules'.
fn read_with(rules: &Rules, args: &MatchesArgs, now: i64) -> Result<v1::Matches, Failure> {
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
        arrivals: events::arrivals(&tx).map_err(|e| unreadable(&e))?,
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
            answer.unevaluated = unevaluated(rules, &Err(NOT_INSTALLED.to_string()), None, None);
        }
        Queue::Read(s) => {
            let mut collector = collector(&s, &held.arrivals);
            status_state(&mut collector);
            for hit in &s.hits {
                let event = event(&hit.event);
                for (file, meta) in &hit.matched {
                    let (raised, mut findings) =
                        raised(&tx, &held, hit, meta).map_err(|e| unreadable(&e))?;
                    let position = hit.at.to_string();
                    // The response layer's verdicts about the match, read by the match; the
                    // finding its latest suspicious one went to is named after the core's.
                    let said = verdict::listed(
                        &tx,
                        "position = ?1 AND rule = ?2",
                        &[&position, &meta.name],
                    )
                    .map_err(|e| unreadable(&e))?;
                    if let Some(f) = said.2.iter().rev().find_map(|v| v.finding.as_ref())
                        && let Some(r) = held.findings.get(f)
                    {
                        findings.push(r.clone());
                    }
                    answer.matches.push(v1::RuleMatch {
                        verdicts: verdict::verdicts(
                            said,
                            answer.store_id.as_deref(),
                            &held.findings,
                            None,
                        ),
                        position,
                        rule: Some(rule(file, meta)),
                        event: Some(event.clone()),
                        raised: raised as i32,
                        findings,
                    });
                }
            }
            answer.collector = Some(collector);
            answer.stretch = Some(stretch(&s));
            answer.unevaluated = unevaluated(
                rules,
                &s.collects.clone().map_err(|(_, why)| why),
                Some(&held.arrivals),
                Some(&s.lacked),
            );
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
    // A rule raises by its level; one whose set states none has a value of its own, so that
    // `below_high` keeps the meaning it had.
    if meta.level.is_none() {
        return Ok((v1::Raised::LevelNotStated, Vec::new()));
    }
    if !meta.raises() {
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
    Ok(match events::went_to(conn, at, &meta.name)? {
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

/// A rule's level as the contract gives it: `not_stated` for a rule whose set states none.
/// A reader built before that value was added reads it as one it does not know, so as the
/// highest level; whether the match raised a finding is `raised`'s to say, never the level's.
fn level(m: &Meta) -> i32 {
    m.level_name()
        .map_or(v1::Level::NotStated as i32, value_of::<v1::Level>)
}

pub fn rule(file: &str, m: &Meta) -> v1::Rule {
    v1::Rule {
        name: m.name.clone(),
        file: file.to_string(),
        id_text: whole(&m.id),
        title_text: whole(&m.title),
        level: level(m),
        techniques_text: m.techniques.iter().map(|t| whole(t)).collect(),
        author_text: m.author.as_deref().map(whole),
        source: m.source.name.to_string(),
        set: m.source.set.to_string(),
    }
}

/// A process the log gives the program of, and who it is as far as the log says.
fn program(executable: &str, who: &events::Identity) -> v1::Process {
    let started = who.started.as_deref().and_then(events::instant);
    v1::Process {
        executable_text: whole(executable),
        pid: who.pid,
        pid_version: who.pid_version,
        started_at: started.map(|s| s.0),
        started_nanos: started.map(|s| s.1),
        ..Default::default()
    }
}

/// Code-signing flags as the contract gives them: the kernel's 32 bits, or absent.
fn flags(f: Option<i64>) -> Option<u32> {
    f.and_then(|f| u32::try_from(f).ok())
}

/// An event as the contract gives it: every field the log holds, each whole, but for the
/// secrets cut out of the arguments.
pub fn event(e: &Evidence) -> v1::Event {
    let args = match e {
        Evidence::Start(s) => Args::raw(&s.args),
        Evidence::File(_) => Args(Vec::new()),
    };
    event_cut(e, &args)
}

/// The same, with a program start's arguments as given, already cut: a stored row's are read
/// back from the store (`finding_answer`). The start's own `args` are not read.
pub fn event_cut(e: &Evidence, args: &Args) -> v1::Event {
    use v1::event::Body;
    let when = happened(e);
    let (happened_at, happened_nanos) = (when.map(|w| w.0), when.map(|w| w.1));
    v1::Event {
        body: Some(match e {
            Evidence::Start(s) => Body::ProgramStart(v1::ProgramStart {
                happened_at,
                happened_nanos,
                process: Some(v1::Process {
                    pid: Some(s.pid),
                    user_id: s.user_id,
                    signing_id_text: s.signing_id.as_deref().map(whole),
                    team_id_text: s.team_id.as_deref().map(whole),
                    platform_binary: s.platform_binary,
                    codesigning_flags: flags(s.who.codesigning_flags),
                    ..program(
                        &s.executable,
                        &events::Identity {
                            pid: Some(s.pid),
                            pid_version: s.who.pid_version,
                            started: s.who.started.clone(),
                        },
                    )
                }),
                instigator: s.parent_executable.as_deref().map(|p| v1::Process {
                    codesigning_flags: flags(s.who.instigator_codesigning_flags),
                    ..program(p, &s.who.instigator)
                }),
                parent_pid: s.parent_pid,
                args_text: args.shown(whole),
                cuts: args
                    .cuts()
                    .into_iter()
                    .map(|c| v1::Cut {
                        argument: c.argument as u32,
                        kind: c.kind,
                        length: c.length as u64,
                    })
                    .collect(),
                working_directory_text: s.working_directory.as_deref().map(whole),
                parent: s.who.parent.pid.map(|pid| v1::Identity {
                    pid: Some(pid),
                    pid_version: s.who.parent.pid_version,
                }),
                script_text: s.who.script.as_deref().map(whole),
            }),
            Evidence::File(f) => Body::FileEvent(v1::FileEvent {
                happened_at,
                happened_nanos,
                action: value_of::<v1::FileAction>(f.action),
                path_text: whole(&f.path),
                source_text: f.source.as_deref().map(whole),
                instigator: Some(v1::Process {
                    signing_id_text: f.signing_id.as_deref().map(whole),
                    ..program(&f.executable, &f.instigator)
                }),
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

/// The collector as the stretch found it. What arrives is the core's latest reading's
/// (`arrivals`), as of `status_read_at`: a stretch read from a place may stop anywhere, and only
/// the core reads every file to its end and so knows which one is being written.
fn collector(s: &Stretch, arrivals: &Arrivals) -> v1::Collector {
    v1::Collector {
        state: value_of::<v1::CollectorState>(s.state),
        said_by: s.said.as_ref().map(|(by, _)| by.to_string()),
        said_text: s
            .said
            .as_ref()
            .map(|(_, said)| crate::secrets::text(said, whole)),
        written_at: s.written,
        file_events_collected: s.collects.is_ok(),
        foreign_files: s.foreign,
        not_kept: named(arrivals, Arrival::NotKept),
        kept_never_filled: named(arrivals, Arrival::Kept(None)),
        not_yet_known: named(arrivals, Arrival::Unknown),
        arriving: arrivals
            .arriving()
            .into_iter()
            .map(|(name, since)| v1::Arriving {
                name: name.to_string(),
                since,
            })
            .collect(),
        no_longer_arriving: arrivals
            .no_longer()
            .into_iter()
            .map(|(name, since)| v1::NoLongerArriving {
                name: name.to_string(),
                since,
            })
            .collect(),
        ..Default::default()
    }
}

/// The names of what a collector may keep that the lines say this of.
fn named(arrivals: &Arrivals, state: Arrival) -> Vec<String> {
    arrivals
        .named(|a| a == state)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The rules that judge nothing here, or only in part, each with why, in the order they are
/// shipped. `collects` is whether file events are collected here, or why not; `arrivals` what
/// the core's latest reading says of what a collector may keep, so that a rule that reads one
/// that does not arrive judges nothing; `lacked` what the lines this answer judged did not give,
/// so that a rule that was not asked about some of them, or was asked without what it reads, is
/// named whatever the store says. Both `None` when no collector is installed.
///
/// What this list says rests on the lines read: the store can only add to it. A reading older
/// than the lines, after a downgrade with the app closed, or a store an earlier build left, never
/// makes a stretch whose lines lack a field look judged.
fn unevaluated(
    rules: &Rules,
    collects: &Result<(), String>,
    arrivals: Option<&Arrivals>,
    lacked: Option<&Lacked>,
) -> Vec<v1::Unevaluated> {
    let not_arriving = arrivals.map_or(0, Arrivals::not_arriving);
    let lacked_of = |kind: Option<Kind>| kind.zip(lacked).map_or(0, |(k, l)| l.of(k));
    use v1::UnevaluatedReason as Why;
    let not_collected = collects.as_ref().err();
    let texts = |items: &[String]| items.iter().map(|s| whole(s)).collect();
    rules
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
                        Reason::NeverTrue => (Why::NeverTrue, Vec::new(), said),
                        Reason::Regex => (Why::Regex, Vec::new(), said),
                        Reason::Unsupported => (Why::Unsupported, Vec::new(), said),
                        Reason::Function => (Why::Function, Vec::new(), said),
                    },
                    (_, Some(why)) if l.kind == Some(Kind::File) => {
                        (Why::NotCollected, Vec::new(), Some(why.clone()))
                    }
                    _ if l.silenced_by(not_arriving) => (
                        Why::NotCollected,
                        texts(&l.needs_fields),
                        arrivals
                            .and_then(|a| a.worst(l.needs & not_arriving).why())
                            .map(str::to_string),
                    ),
                    _ if l.silenced_by(lacked_of(l.kind)) => (
                        Why::NotCollected,
                        texts(&l.needs_fields),
                        Some(events::NOT_IN_LINES.to_string()),
                    ),
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
                name: meta.map(|m| m.name.clone()),
                id_text: meta.map(|m| whole(&m.id)),
                title_text: meta.map(|m| whole(&m.title)),
                level: meta.map(level),
                reason: why as i32,
                fields_text: fields,
                detail_text: detail.map(|d| whole(&d)),
                source: l.source.name.to_string(),
                set: l.source.set.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{NEVER_FILLED, NO_LONGER, NOT_KEPT, NOT_YET_KNOWN};

    /// A reading of the log under `root` by the core, as `immune run` makes one, into `store`.
    fn core_reads(store: &std::path::Path, root: &std::path::Path) {
        let mut conn = crate::store::open(store).unwrap();
        let tx = conn.transaction().unwrap();
        crate::store::put_entity(&tx, "machine:mac").unwrap();
        events::read(&tx, "events-1", "machine:mac", root, 1_791_090_000).unwrap();
        tx.commit().unwrap();
    }

    /// A start of `dd if=/dev/zero bs=1 count=1`, which "Binary Padding - MacOS", marked high,
    /// matches: as a collector that keeps who each process is writes it, with its start time
    /// given or null, or as an earlier collector wrote it.
    fn dd(seq: u64, form: &str) -> String {
        let kept = format!(
            r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/sh"}},"audit_token":{{"pid":401,"pidversion":9401}},"start_time":"2026-10-04T00:00:01.900000Z","codesigning_flags":570522385}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example"}},"script":{{"path":"/Users/example/run.sh"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501,"pidversion":9402}},"start_time":"2026-10-04T00:00:01.900000Z","parent_audit_token":{{"pid":401,"pidversion":9300}},"ppid":401,"signing_id":"com.apple.dd","team_id":null,"is_platform_binary":true,"codesigning_flags":570522304}}}}}}}}"#
        );
        let line = match form {
            "kept" => kept,
            "null" => kept.replace(
                r#""start_time":"2026-10-04T00:00:01.900000Z","parent_audit_token""#,
                r#""start_time":null,"parent_audit_token""#,
            ),
            _ => format!(
                r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/sh"}}}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.apple.dd","team_id":null,"is_platform_binary":true}}}}}}}}"#
            ),
        };
        line + "\n"
    }

    /// A file created by `curl`, as a collector that keeps who acted and its signer writes it,
    /// or as an earlier collector wrote it.
    fn created(form: &str) -> String {
        let who = match form {
            "old" => "",
            _ => {
                r#","audit_token":{"pid":403,"pidversion":9403},"start_time":"2026-10-04T00:00:01.900000Z","signing_id":"com.example.tool","codesigning_flags":570522385"#
            }
        };
        format!(
            r#"{{"schema_version":1,"seq_num":1,"time":"2026-10-04T00:00:03.000003Z","process":{{"executable":{{"path":"/usr/bin/curl"}}{who}}},"event":{{"create":{{"destination":"/Users/example/a"}}}}}}"#
        ) + "
"
    }

    /// Writes `text` as the log file `name` under `root`, last written `ago` seconds before
    /// the reading.
    fn log_file(root: &std::path::Path, name: &str, text: &str, ago: u64) {
        let path = root.join(events::LOG).join(name);
        std::fs::write(&path, text).unwrap();
        let f = std::fs::File::options().append(true).open(&path).unwrap();
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_791_090_000 - ago);
        f.set_modified(at).unwrap();
    }

    #[test]
    fn paging_tells_what_arrives_as_the_core_s_latest_reading_stored_it() {
        // No false calm. A stretch read from a place stops at its limit anywhere in the log, so
        // a file no longer written can be the last it read: after a downgrade, the later
        // collector's file, which sorts after the earlier one's; after a clock set back, the
        // file written with the clock ahead. What `collector` and `unevaluated` say arrives is
        // the core's latest reading, on every page.
        let rules = crate::sigma::testing::process_kept();
        for (tag, files, said) in [
            (
                "downgrade",
                [
                    ("exec-20261004T000013-20261004T000000.jsonl", "kept", 200),
                    ("exec-20261004T00.jsonl", "old", 100),
                ],
                (
                    vec!["identity".to_string(), "script".into(), "signature".into()],
                    vec![],
                    1,
                ),
            ),
            (
                "clock",
                [
                    ("exec-20261004T000013-20261004T050000.jsonl", "kept", 200),
                    ("exec-20261004T000013-20261004T010000.jsonl", "null", 100),
                ],
                (vec![], vec!["identity"], 0),
            ),
        ] {
            let dir = std::env::temp_dir()
                .join(format!("immune-matches-page-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let root = dir.join("root");
            std::fs::create_dir_all(root.join(events::LOG)).unwrap();
            let plist = root.join(events::PLIST);
            std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
            std::fs::write(&plist, "<plist/>").unwrap();
            for (n, (name, form, ago)) in files.iter().enumerate() {
                let seq = 10 * n as u64;
                // The file being written: who the program started is arrived, then stopped.
                let first = if *form == "null" { "kept" } else { form };
                let text =
                    dd(seq + 1, first) + &dd(seq + 2, form) + &dd(seq + 3, form) + &created(form);
                log_file(&root, name, &text, *ago);
            }
            let store = dir.join("store.db");
            core_reads(&store, &root);
            let mut after = None;
            let mut pages = 0;
            loop {
                let args = MatchesArgs {
                    store: store.clone(),
                    form: answer::Form::Json,
                    after: after.take(),
                    limit: 1,
                    system_root: root.clone(),
                };
                let answer = read_with(&rules, &args, 1_791_090_000).ok().unwrap();
                pages += 1;
                let c = answer.collector.as_ref().unwrap();
                let stopped: Vec<&str> = c
                    .no_longer_arriving
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect();
                assert_eq!(
                    (&c.not_kept, stopped),
                    (&said.0, said.1.clone()),
                    "{tag} page {pages}"
                );
                assert!(
                    c.arriving.iter().all(|a| a.name != "identity"),
                    "{tag} page {pages}: {:?}",
                    c.arriving
                );
                assert_eq!(answer.unevaluated.len(), said.2, "{tag} page {pages}");
                if !answer.more {
                    break;
                }
                let place = answer.continue_after.unwrap();
                after = Some((place.clone(), Place::parse(&place).unwrap()));
            }
            assert!(pages > 6, "{tag}: {pages} pages");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A system root with the collector installed and established to record file events.
    fn installed_root(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("immune-matches-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        std::fs::create_dir_all(root.join(events::LOG)).unwrap();
        let plist = root.join(events::PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let collects = r#"["/usr/bin/eslogger","exec","create","rename"]"#;
        std::fs::write(root.join(events::COLLECTS), collects).unwrap();
        (dir, root)
    }

    fn ask(
        rules: &Rules,
        store: &std::path::Path,
        root: &std::path::Path,
        after: Option<&str>,
    ) -> v1::Matches {
        let args = MatchesArgs {
            store: store.to_path_buf(),
            form: answer::Form::Json,
            after: after.map(|p| (p.to_string(), Place::parse(p).unwrap())),
            limit: LIMIT,
            system_root: root.to_path_buf(),
        };
        read_with(rules, &args, 1_791_090_000).ok().unwrap()
    }

    /// `git status`, which no shipped rule matches, in the forms `dd` writes.
    fn git(seq: u64, form: &str) -> String {
        dd(seq, form)
            .replace(
                r#""args":["dd","if=/dev/zero","bs=1","count=1"]"#,
                r#""args":["git","status"]"#,
            )
            .replace(r#""path":"/bin/dd""#, r#""path":"/usr/bin/git""#)
    }

    /// Quiet as `matches.proto` defines it: nothing matched, and nothing says what was not seen.
    fn quiet(a: &v1::Matches) -> bool {
        let c = a.collector.as_ref().unwrap();
        let s = a.stretch.as_ref().unwrap();
        a.matches.is_empty()
            && c.state == v1::CollectorState::Running as i32
            && c.file_events_collected
            && s.program_starts > 0
            && s.program_starts_lost == 0
            && s.program_starts_unknown_losses == 0
            && s.file_events_lost == 0
            && s.file_events_unknown_losses == 0
            && s.unreadable_lines == 0
            && s.unreadable_file_events == 0
            && !s.gone
            && a.unevaluated.is_empty()
    }

    /// The rule of `process_kept`, which reads the script, as `unevaluated` names it: why, and
    /// in which words.
    fn named(a: &v1::Matches) -> Vec<(i32, Option<&str>)> {
        a.unevaluated
            .iter()
            .map(|u| (u.reason, u.detail_text.as_deref()))
            .collect()
    }

    #[test]
    fn a_quiet_answer_rests_on_the_lines_it_read_and_not_on_an_older_reading_of_the_core() {
        // No false calm. The core read while the later collector wrote, so the store says the
        // script arrives. Then the earlier collector is put back, or the app stays closed, and
        // the core reads nothing more. An answer over the earlier collector's starts, which lack
        // the script's key, names the rule that reads it, since that rule was asked about none
        // of them, while `collector` goes on giving the store's reading at `status_read_at`. The
        // same for a file event without its signer and a rule that reads the signer. An answer
        // over lines that give it is quiet again: what is named is of the lines read.
        let rules = crate::sigma::testing::process_kept();
        let (dir, root) = installed_root("stale");
        let later = "exec-20261004T000013-20261004T000000.jsonl";
        let text = git(1, "kept") + &git(2, "kept") + &created("kept");
        log_file(&root, later, &text, 300);
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let first = ask(&rules, &store, &root, None);
        assert!(first.unevaluated.is_empty(), "{:?}", first.unevaluated);
        assert!(ask(&signer(), &store, &root, None).unevaluated.is_empty());
        let earlier = git(3, "old") + &git(4, "old") + &created("old");
        log_file(&root, "exec-20261004T00.jsonl", &earlier, 100);
        let place = first.continue_after.clone().unwrap();
        let not_in_lines = [(
            v1::UnevaluatedReason::NotCollected as i32,
            Some(events::NOT_IN_LINES),
        )];
        let next = ask(&rules, &store, &root, Some(&place));
        let c = next.collector.as_ref().unwrap();
        let arriving: Vec<&str> = c.arriving.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(arriving, ["identity", "script", "signature"]);
        assert_eq!(c.status_read_at, Some(1_791_090_000));
        assert!(!quiet(&next));
        assert_eq!(named(&next), not_in_lines);
        let files = ask(&signer(), &store, &root, Some(&place));
        assert_eq!(named(&files), not_in_lines);
        let place = next.continue_after.clone().unwrap();
        let text = text + &git(5, "kept") + &git(6, "kept");
        log_file(&root, later, &text, 50);
        let after = ask(&rules, &store, &root, Some(&place));
        assert_eq!(after.stretch.as_ref().unwrap().program_starts, 2);
        assert!(quiet(&after), "{:?}", after.unevaluated);
        assert!(
            ask(&signer(), &store, &root, Some(&place))
                .unevaluated
                .is_empty()
        );
        // Each kind speaks for its own rules: starts that give everything and one file event
        // without its signer name the rule that reads the signer, and not the one about starts.
        let place = after.continue_after.clone().unwrap();
        let text = text + &git(7, "kept") + &created("old");
        log_file(&root, later, &text, 20);
        let mixed = ask(&rules, &store, &root, Some(&place));
        assert!(mixed.unevaluated.is_empty(), "{:?}", mixed.unevaluated);
        assert_eq!(
            named(&ask(&signer(), &store, &root, Some(&place))),
            not_in_lines
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_an_earlier_build_left_tells_what_it_said_arrived_as_not_yet_known() {
        // The build before this one told a field arriving for ever after one value. Its row,
        // the script kept and filled, is not taken for arriving: the answer says not yet known
        // and names the rule that reads it, and is never quiet.
        let rules = crate::sigma::testing::process_kept();
        let (dir, root) = installed_root("old-store");
        log_file(
            &root,
            "exec-20261004T00.jsonl",
            &(git(1, "old") + &git(2, "old")),
            100,
        );
        let store = dir.join("store.db");
        let conn = crate::store::open(&store).unwrap();
        conn.execute_batch(
            "CREATE TABLE event_arrival (kind TEXT NOT NULL, keep TEXT NOT NULL,
                 kept INTEGER NOT NULL, filled INTEGER, PRIMARY KEY (kind, keep));
             INSERT INTO event_arrival VALUES ('program_start', 'script', 1, 5);",
        )
        .unwrap();
        drop(conn);
        let a = ask(&rules, &store, &root, None);
        let c = a.collector.as_ref().unwrap();
        assert!(c.arriving.is_empty(), "{:?}", c.arriving);
        assert!(c.not_yet_known.contains(&"script".to_string()));
        assert!(!quiet(&a));
        assert_eq!(
            named(&a),
            [(
                v1::UnevaluatedReason::NotCollected as i32,
                Some(NOT_YET_KNOWN)
            )]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_group_filled_on_some_lines_by_nature_is_judged_by_the_core_s_latest_reading_alone() {
        // The limit as it stands, pinned so that a change that closes it has a test to turn
        // round. One start without a script cannot tell no script by nature from a field the
        // collector stopped filling, so only the core's reading, counting its bound, tells the
        // second. Until it has, an answer over 1,500 starts with the script null is quiet; once
        // it has, the rule that reads the script is named as no longer watching. No shipped rule
        // reads such a group (`events::tests::every_kept_field_a_shipped_rule_reads_is_...`);
        // the test set ties the script to the working directory.
        let rules = crate::sigma::testing::process_kept();
        let (dir, root) = installed_root("script-null");
        let text = git(1, "kept") + &git(2, "kept");
        log_file(
            &root,
            "exec-20261004T000013-20261004T000000.jsonl",
            &text,
            300,
        );
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let place = ask(&rules, &store, &root, None).continue_after.unwrap();
        let null = |seq: u64| {
            git(seq, "kept")
                .replace(
                    r#""script":{"path":"/Users/example/run.sh"}"#,
                    r#""script":null"#,
                )
                .replace(
                    r#""cwd":{"path":"/Users/example"}"#,
                    r#""cwd":{"path":"/tmp"}"#,
                )
        };
        assert!(null(3).contains(r#""script":null"#) && null(3).contains(r#""path":"/tmp""#));
        let text: String = (3..1503).map(null).collect();
        log_file(
            &root,
            "exec-20261004T000013-20261004T010000.jsonl",
            &text,
            100,
        );
        let before = ask(&rules, &store, &root, Some(&place));
        assert_eq!(before.stretch.as_ref().unwrap().program_starts, 1500);
        assert!(quiet(&before), "{:?}", before.unevaluated);
        core_reads(&store, &root);
        let after = ask(&rules, &store, &root, Some(&place));
        let stopped = &after.collector.as_ref().unwrap().no_longer_arriving;
        assert_eq!(
            stopped.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["script"]
        );
        assert_eq!(
            named(&after),
            [(v1::UnevaluatedReason::NotCollected as i32, Some(NO_LONGER))]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_event_whose_signer_is_null_or_absent_names_the_rule_that_reads_it_whatever_the_store_says()
     {
        // The signer of file events is filled on every line, so one line without it, null or
        // without its key, names the rule that reads it while the store says it arrives.
        let rules = signer();
        let (dir, root) = installed_root("signer-null");
        let text = git(1, "kept") + &created("kept");
        log_file(
            &root,
            "exec-20261004T000013-20261004T000000.jsonl",
            &text,
            300,
        );
        let store = dir.join("store.db");
        core_reads(&store, &root);
        let first = ask(&rules, &store, &root, None);
        assert!(first.unevaluated.is_empty(), "{:?}", first.unevaluated);
        let place = first.continue_after.unwrap();
        let signed = r#""signing_id":"com.example.tool""#;
        let null = created("kept").replace(signed, r#""signing_id":null"#);
        let absent = created("kept").replace(&format!(",{signed}"), "");
        for (what, line) in [("null", null), ("absent", absent)] {
            assert!(!line.contains(signed), "{what}");
            let text = git(3, "kept") + &line;
            log_file(
                &root,
                "exec-20261004T000013-20261004T010000.jsonl",
                &text,
                100,
            );
            let a = ask(&rules, &store, &root, Some(&place));
            assert_eq!(a.stretch.as_ref().unwrap().file_events, 1, "{what}");
            assert_eq!(
                named(&a),
                [(
                    v1::UnevaluatedReason::NotCollected as i32,
                    Some(events::NOT_IN_LINES)
                )],
                "{what}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    use crate::sigma::ELASTIC;

    /// One rule of Elastic's, about file events, that reads the signer of the program that acted.
    fn signer() -> Rules {
        let text = format!(
            "title: Invented\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\n\
             level: high\nlogsource: {{\"product\": \"macos\", \"category\": \"file_event\"}}\n\
             detection:\n  s1: {{\"process.code_signature.signing_id|cased\": [\"com.example\"]}}\n  condition: s1\n{}",
            crate::sigma::testing::record_of(&ELASTIC, "\"high\"", "")
        );
        Rules::load_as(
            &ELASTIC,
            &[("signer.yml", Box::leak(text.into_boxed_str()))],
        )
    }

    #[test]
    fn a_rule_that_reads_what_does_not_arrive_is_handed_over_as_judging_nothing_with_which() {
        // The response layer reads a quiet queue as calm only for the rules that judge: a rule
        // that reads what no line gives a value for is listed, with the field and which of the
        // three it is, and is not once values arrive.
        let rules = signer();
        let on = Arrival::Kept(Some(1));
        let sig = |a| Arrivals::from([on, on, a, on, a]);
        for (state, why) in [
            (Arrival::NotKept, NOT_KEPT),
            (Arrival::Kept(None), NEVER_FILLED),
            (Arrival::Unknown, NOT_YET_KNOWN),
            (Arrival::NoLonger(1), NO_LONGER),
        ] {
            let listed = unevaluated(&rules, &Ok(()), Some(&sig(state)), None);
            assert_eq!(listed.len(), 1);
            assert_eq!(
                (
                    listed[0].reason,
                    listed[0].fields_text.clone(),
                    listed[0].detail_text.as_deref()
                ),
                (
                    v1::UnevaluatedReason::NotCollected as i32,
                    vec!["process.code_signature.signing_id".to_string()],
                    Some(why)
                )
            );
        }
        let identity = Arrivals::from([Arrival::NotKept, on, on, Arrival::NotKept, on]);
        assert!(unevaluated(&rules, &Ok(()), Some(&identity), None).is_empty());
        assert!(unevaluated(&rules, &Ok(()), Some(&sig(on)), None).is_empty());
    }

    #[test]
    fn the_queue_hands_over_a_rule_that_reads_what_its_lines_do_not_give_as_judging_nothing() {
        // The answer itself, not only its part: whether a rule judges is decided by what the
        // lines the core's reading read carry, never by a record. Before the core has read,
        // nothing is known; a log an earlier collector wrote lacks the field, a later
        // collector's carries it empty, and only a line that gives it a value lets the rule
        // judge; each is said in the collector's lists.
        let dir =
            std::env::temp_dir().join(format!("immune-matches-arrival-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("root");
        std::fs::create_dir_all(root.join(events::LOG)).unwrap();
        let plist = root.join(events::PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "<plist/>").unwrap();
        let start = |seq: u64, extra: &str| {
            format!(
                r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/zsh"}}}},"event":{{"exec":{{"args":["git","status"],"cwd":{{"path":"/Users/example/dev/site"}},{extra}"target":{{"executable":{{"path":"/usr/bin/git"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.apple.git","team_id":null,"is_platform_binary":true}}}}}}}}
"#
            )
        };
        let log = root.join(events::LOG).join("exec-20261004T00.jsonl");
        // A program start as an earlier collector wrote it: no script, no start time.
        std::fs::write(&log, start(1, "")).unwrap();
        drop(crate::store::open(&dir.join("store.db")).unwrap());
        let core = || core_reads(&dir.join("store.db"), &root);
        let args = MatchesArgs {
            store: dir.join("store.db"),
            form: answer::Form::Json,
            after: None,
            limit: LIMIT,
            system_root: root.clone(),
        };
        let rules = crate::sigma::testing::process_kept();
        let unevaluated_why = |answer: &v1::Matches| {
            assert_eq!(answer.unevaluated.len(), 1, "{:?}", answer.unevaluated);
            let u = &answer.unevaluated[0];
            assert_eq!(
                (u.reason, u.fields_text.clone()),
                (
                    v1::UnevaluatedReason::NotCollected as i32,
                    vec!["process.working_directory".to_string()],
                )
            );
            u.detail_text.clone()
        };
        let answer = read_with(&rules, &args, 1_791_000_000).ok().unwrap();
        let c = answer.collector.as_ref().unwrap();
        assert_eq!(c.not_yet_known, ["identity", "script", "signature"]);
        assert!(c.not_kept.is_empty() && c.arriving.is_empty());
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NOT_YET_KNOWN));
        core();
        let answer = read_with(&rules, &args, 1_791_000_000).ok().unwrap();
        let c = answer.collector.as_ref().unwrap();
        assert_eq!(c.not_kept, ["identity", "script", "signature"]);
        assert!(c.kept_never_filled.is_empty() && c.arriving.is_empty());
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NOT_KEPT));
        // A later collector's line that carries the script empty: kept, never filled.
        std::fs::write(&log, start(1, "") + &start(2, r#""script":null,"#)).unwrap();
        core();
        let answer = read_with(&rules, &args, 1_791_000_000).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().kept_never_filled,
            ["script"]
        );
        assert_eq!(unevaluated_why(&answer).as_deref(), Some(NEVER_FILLED));
        // A line that gives it a value: it arrives, since that line, and the rule judges.
        std::fs::write(
            &log,
            start(1, "")
                + &start(2, r#""script":null,"#)
                + &start(3, r#""script":{"path":"/Users/example/x.sh"},"#),
        )
        .unwrap();
        core();
        let answer = read_with(&rules, &args, 1_791_000_000).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().arriving,
            [v1::Arriving {
                name: "script".into(),
                since: 1_791_072_002
            }]
        );
        // This answer read the earlier collector's start too, which the rule was not asked
        // about, and says so.
        assert_eq!(
            unevaluated_why(&answer).as_deref(),
            Some(events::NOT_IN_LINES)
        );
        // An answer that reads on from a place where nothing new was written says what the
        // core's reading stored, and names nothing.
        let place = answer.continue_after.clone().unwrap();
        let again = read_with(
            &rules,
            &MatchesArgs {
                store: args.store.clone(),
                form: answer::Form::Json,
                after: Some((place.clone(), Place::parse(&place).unwrap())),
                limit: LIMIT,
                system_root: root.clone(),
            },
            1_791_000_000,
        )
        .ok()
        .unwrap();
        assert!(again.unevaluated.is_empty(), "{:?}", again.unevaluated);
        // With no collector the state says nothing is judged, and no rule about program
        // starts is put down to what a collector that is not there keeps.
        std::fs::remove_file(&plist).unwrap();
        let answer = read_with(&rules, &args, 1_791_000_000).ok().unwrap();
        assert_eq!(
            answer.collector.as_ref().unwrap().state,
            v1::CollectorState::NotInstalled as i32
        );
        assert!(answer.unevaluated.is_empty(), "{:?}", answer.unevaluated);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
