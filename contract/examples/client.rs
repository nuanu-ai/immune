//! A small client of Immunity Core's contract: the loop `contract/README.md` describes, run with the
//! typed messages of this crate and nothing else. Start from it.
//!
//! ```sh
//! cargo run -p immunity-contract --example client -- --immunity <path to immunity> --store <path> \
//!     [--after <place>] [--judge-first] [-- <more arguments for matches and verdict>]
//! ```
//!
//! It reads the rule matches and the findings, and with `--judge-first` it sends one verdict
//! about the first match. A verdict is written into the store, so run it on a store made to try
//! it. Arguments after `--` go to `immunity matches` and `immunity verdict`, the two commands that
//! read the event log, such as `--system-root <dir>`; `immunity findings` takes none of them.

use immunity_contract::prost::Message;
use immunity_contract::v1;
use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};

struct Args {
    immunity: String,
    store: String,
    after: Option<String>,
    judge_first: bool,
    extra: Vec<String>,
}

fn parse() -> Result<Args, String> {
    let (mut immunity, mut store, mut after, mut judge_first) = (None, None, None, false);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--immunity" => immunity = it.next(),
            "--store" => store = it.next(),
            "--after" => after = it.next(),
            "--judge-first" => judge_first = true,
            "--" => break,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let extra = it.collect();
    let immunity = immunity.ok_or("--immunity <path to the immunity binary> is required")?;
    // Without --store the core would use the person's own store. A client that is being tried
    // must never write a verdict there, so it names the store or does nothing.
    let store = store.ok_or("--store <path> is required: this client never uses the default store, so trying it cannot touch a real one")?;
    Ok(Args {
        immunity,
        store,
        after,
        judge_first,
        extra,
    })
}

/// Why a command of the contract did not answer.
enum Error {
    /// The core's own `Failure`: a stable `code` to act on.
    Failure(v1::Failure),
    /// The command could not be run, or printed something that is not a message.
    Broken(String),
}

/// Runs `immunity <args> --store <store> --proto` and decodes its answer as `T`.
///
/// The exit code is read first. On 0, stdout holds `T`; on any other, it holds `Failure`.
/// `Failure`'s fields are numbered from 1000, which every answer reserves, so the bytes of one
/// decode as the other with format 0: decoding cannot tell them apart, the exit code does.
fn call<T: Message + Default>(
    a: &Args,
    args: &[&str],
    log: bool,
    input: Option<&[u8]>,
) -> Result<T, Error> {
    let mut cmd = Command::new(&a.immunity);
    cmd.args(args).arg("--store").arg(&a.store).arg("--proto");
    if log {
        cmd.args(&a.extra);
    }
    let stdin = if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    cmd.stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Broken(format!("cannot run {:?}: {e}", a.immunity)))?;
    if let Some(bytes) = input {
        // One message, written whole; dropping the pipe closes it, so the core reads to its end.
        let mut pipe = child.stdin.take().expect("stdin is piped");
        pipe.write_all(bytes)
            .map_err(|e| Error::Broken(format!("cannot write: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Broken(format!("cannot wait: {e}")))?;
    if out.status.success() {
        return T::decode(out.stdout.as_slice()).map_err(|e| Error::Broken(e.to_string()));
    }
    match v1::Failure::decode(out.stdout.as_slice()) {
        Ok(f) if !f.errors.is_empty() => Err(Error::Failure(f)),
        _ => Err(Error::Broken(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )),
    }
}

/// What a client does on a failure: act on `code`, never on the wording of `message`.
fn explain(e: &Error) -> String {
    let f = match e {
        Error::Broken(why) => return format!("broken: {why}"),
        Error::Failure(f) => f,
    };
    let code = f.errors.first().map_or("", |e| e.code.as_str());
    let then = match code {
        // The id was already used for a message that differs. Nothing was recorded. If this
        // is a real decision and not a retry, send it again under a new id.
        "verdict_id_reused" => "nothing was recorded; send a real decision again under a new id",
        // A harmless verdict about a line the log no longer holds: there is no match to keep it
        // beside. The log keeps about a day, so judge sooner, or say it about the finding.
        "match_gone" => "the line has left the log; a harmless verdict about it is not kept",
        _ => "see the reference for this code",
    };
    format!("failure {:?} of {:?}: {then}", code, f.operation)
}

/// A token nobody can guess, for `verdict_id`: 16 random bytes as hex. A UUID does as well.
fn new_verdict_id() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn name<E: TryFrom<i32>>(value: i32, words: fn(&E) -> &'static str) -> String {
    // A value this crate does not know is something the client cannot judge, never a default.
    E::try_from(value).map_or_else(|_| format!("unknown {value}"), |e| words(&e).to_string())
}

fn run(a: &Args) -> Result<(), Error> {
    // 1. The matches since the place the last run kept, page by page while `more` says so.
    let mut after = a.after.clone();
    let (mut all, mut store_id) = (Vec::new(), None);
    loop {
        let mut args = vec!["matches"];
        if let Some(place) = &after {
            args.extend(["--after", place.as_str()]);
        }
        let m: v1::Matches = call(a, &args, true, None)?;
        if m.format != 1 {
            return Err(Error::Broken(format!("format {} is not 1", m.format)));
        }
        for r in &m.matches {
            let rule = r.rule.clone().unwrap_or_default();
            // Text fields are data from the Mac, which an attacker may have written: printed
            // quoted, never as words of this client.
            let program = match r.event.as_ref().and_then(|e| e.body.as_ref()) {
                Some(v1::event::Body::ProgramStart(s)) => s.process.as_ref(),
                Some(v1::event::Body::FileEvent(f)) => f.instigator.as_ref(),
                None => None,
            }
            .map(|p| p.executable_text.as_str());
            let raised = match v1::Raised::try_from(r.raised) {
                Ok(v1::Raised::Finding) => "finding".to_string(),
                _ => format!("no finding ({})", name(r.raised, v1::Raised::as_str_name)),
            };
            println!(
                "match {} rule {} level {} title {:?}: {raised}; program {:?}",
                r.position,
                rule.name,
                name(rule.level, v1::Level::as_str_name),
                rule.title_text,
                program.unwrap_or("not given"),
            );
        }
        // An empty page is calm only when the collector runs and nothing was lost or left
        // unevaluated: `matches.proto` lists the conditions.
        let state = m.collector.as_ref().map_or(0, |c| c.state);
        println!(
            "collector {}, {} rules unevaluated or in part",
            name(state, v1::CollectorState::as_str_name),
            m.unevaluated.len()
        );
        all.extend(m.matches);
        store_id = m.store_id.or(store_id);
        // Keep the place whole and pass it back; never parse it.
        after = m.continue_after.or(after);
        if !m.more || after.is_none() {
            break;
        }
    }
    if let Some(place) = &after {
        println!("continue_after {place}");
    }

    // 2. The findings. A state this crate does not know reads as open, as the schema says.
    let f: v1::Findings = call(a, &["findings"], false, None)?;
    use v1::FindingState::{Cleared, Expected, Seen};
    let open: Vec<_> = f
        .findings
        .iter()
        .filter_map(|l| l.finding.as_ref())
        .filter(|r| !matches!(r.state.try_into(), Ok(Expected | Seen | Cleared)))
        .collect();
    let urgent = open.iter().filter(|r| r.urgent).count();
    println!("findings {} open, {urgent} urgent", open.len());

    // 3. One verdict about the first match, sent twice, then once changed under the same id.
    if !a.judge_first {
        return Ok(());
    }
    let Some(first) = all.first() else {
        println!("no match to judge");
        return Ok(());
    };
    let verdict_id = new_verdict_id().map_err(|e| Error::Broken(e.to_string()))?;
    let mut verdict = v1::Verdict {
        format: 1,
        // The store the matches were read from; a verdict for another store is refused.
        store_id: store_id.unwrap_or_default(),
        about: Some(v1::verdict::About::Match(v1::AboutMatch {
            position: first.position.clone(),
            rule: first
                .rule
                .as_ref()
                .map(|r| r.name.clone())
                .unwrap_or_default(),
        })),
        kind: v1::VerdictKind::Suspicious as i32,
        reason_text: "the example client judged the first match it read".to_string(),
        case_text: "example-1".to_string(),
        severity: Some(v1::Level::High as i32),
        confidence: Some(v1::Level::Medium as i32),
        verdict_id: Some(verdict_id),
    };
    // A retry after a timeout or a crash sends the same bytes: the core answers with what it
    // recorded the first time, `already_recorded` true, and records nothing.
    for _ in 0..2 {
        let r: v1::VerdictRecorded = call(a, &["verdict"], true, Some(&verdict.encode_to_vec()))?;
        let recorded = r.recorded.unwrap_or_default();
        let finding = recorded.finding.unwrap_or_default();
        println!(
            "verdict recorded at {} in finding {} ({}), already_recorded {}",
            recorded.recorded_at,
            finding.id,
            name(finding.state, v1::FindingState::as_str_name),
            r.already_recorded
        );
    }
    // The same id on a message that differs is refused, so a mistake never passes as a retry.
    verdict.reason_text.push_str(", and changed its mind");
    match call::<v1::VerdictRecorded>(a, &["verdict"], true, Some(&verdict.encode_to_vec())) {
        Err(e @ Error::Failure(_)) => println!("{}", explain(&e)),
        Err(e) => return Err(e),
        Ok(_) => {
            return Err(Error::Broken(
                "a changed message under the same id was recorded".into(),
            ));
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("client: {why}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("client: {}", explain(&e));
            ExitCode::FAILURE
        }
    }
}
