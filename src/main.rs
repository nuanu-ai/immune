//! soc: read what is installed, keep it as facts, report what changed. One line.

mod brew;
mod lifecycle;
mod store;

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Event, Reading};

const MACHINE_NAME: &str = "mac";
const USAGE: &str = "usage: soc [--store <path>] [--brew-input <file>]";

struct Args {
    store: PathBuf,
    brew_input: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        store: PathBuf::from("private/store/store.db"),
        brew_input: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let value = it.next();
        match (arg.as_str(), value) {
            ("--store", Some(v)) => args.store = v.into(),
            ("--brew-input", Some(v)) => args.brew_input = Some(v.into()),
            _ => return Err(format!("unexpected argument: {arg}")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("soc: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("soc: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<String, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let at = now.as_secs() as i64;
    let run_id = format!("{}-{:09}", now.as_secs(), now.subsec_nanos());

    // Raw input is kept next to the store so that the store can be rebuilt from it.
    let home = match args.store.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    std::fs::create_dir_all(&home)?;
    let mut conn = store::open(&args.store)?;
    store::journal_note(&conn, at, &run_id, "run_started", "")?;

    let machine = format!("machine:{MACHINE_NAME}");
    let reading = Reading {
        reader: brew::READER,
        scope: &machine,
        kind: brew::KIND,
        run_id: &run_id,
        at,
    };
    let input = brew::read(args.brew_input.as_deref());
    if let Ok(raw) = &input {
        let dir = home.join("raw").join(&run_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{}.txt", brew::READER)), raw)?;
    }

    let tx = conn.transaction()?;
    store::put_entity(&tx, &machine)?;
    let first_run = !store::read_before(&tx, &reading)?;
    let line = match &input {
        Ok(raw) => {
            let raw_file = format!("raw/{run_id}/{}.txt", brew::READER);
            for s in brew::statements(raw, &machine, &raw_file) {
                store::put_draft(&tx, &reading, brew::BASIS, &s)?;
            }
            store::put_coverage(&tx, &reading, "full", None)?;
            let events = lifecycle::promote(&tx, &reading)?;
            for e in &events {
                store::journal_event(&tx, &reading, e)?;
            }
            let count = store::live_components(&tx, &reading)?;
            let since = if first_run {
                "First run.".to_string()
            } else {
                since_last_run(&events)
            };
            format!(
                "{MACHINE_NAME}: {count} components ({}). {since}",
                brew::READER
            )
        }
        Err(reason) => {
            store::put_coverage(&tx, &reading, "none", Some(reason))?;
            let count = store::live_components(&tx, &reading)?;
            format!(
                "{MACHINE_NAME}: {} could not be read ({reason}). Changes unknown, nothing retracted; \
                 {count} components ({}) kept from earlier runs.",
                brew::KIND,
                brew::READER
            )
        }
    };
    store::journal_note(&tx, at, &run_id, "report", &line)?;
    store::journal_note(&tx, at, &run_id, "run_finished", "")?;
    tx.commit()?;
    Ok(line)
}

/// Counts things, not assertions: a new component is one addition however many
/// assertions it brings.
fn since_last_run(events: &[Event]) -> String {
    let count = |kind: &str| {
        events
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    };
    let (added, changed, removed) = (count("added"), count("changed"), count("removed"));
    if added + changed + removed == 0 {
        return "Since last run: no changes.".to_string();
    }
    format!("Since last run: +{added} added, {changed} changed, {removed} removed.")
}
