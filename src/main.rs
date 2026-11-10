//! soc: read what is installed, keep it as facts, report what changed. One line.
//! `soc view` writes a page that shows what is in the store.

mod brew;
mod lifecycle;
mod store;
mod view;

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Event, Reading};

const MACHINE_NAME: &str = "mac";
const DEFAULT_STORE: &str = "private/store/store.db";
const USAGE: &str = "usage: soc run [--store <path>] [--brew-input <file>]
       soc view [--store <path>] [--no-open]";

enum Cmd {
    Run(Args),
    View(ViewArgs),
}

struct Args {
    store: PathBuf,
    brew_input: Option<PathBuf>,
}

struct ViewArgs {
    store: PathBuf,
    open: bool,
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let cmd = it.next().ok_or("no command given")?;
    let mut store = PathBuf::from(DEFAULT_STORE);
    match cmd.as_str() {
        "run" => {
            let mut brew_input = None;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = value(&mut it, &arg)?.into(),
                    "--brew-input" => brew_input = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            Ok(Cmd::Run(Args { store, brew_input }))
        }
        "view" => {
            let mut open = true;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = value(&mut it, &arg)?.into(),
                    "--no-open" => open = false,
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            Ok(Cmd::View(ViewArgs { store, open }))
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

fn value(it: &mut impl Iterator<Item = String>, arg: &str) -> Result<String, String> {
    it.next().ok_or(format!("{arg} needs a value"))
}

fn main() -> ExitCode {
    let cmd = match parse_args(std::env::args().skip(1)) {
        Ok(cmd) => cmd,
        Err(e) => {
            eprintln!("soc: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match cmd {
        Cmd::Run(args) => run(&args).map(|line| println!("{line}")),
        Cmd::View(args) => view(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soc: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The store's folder: raw input and the view live next to the store.
fn home(store: &Path) -> PathBuf {
    match store.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Writes the page next to the store, prints its path and opens it. Never writes to the store.
fn view(args: &ViewArgs) -> Result<(), Box<dyn Error>> {
    if !args.store.is_file() {
        return Err(format!("no store at {}", args.store.display()).into());
    }
    let conn = store::open_read_only(&args.store)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let html = view::page(&conn, &args.store.display().to_string(), now)?;
    drop(conn);

    let path = std::path::absolute(home(&args.store).join("view.html"))?;
    std::fs::write(&path, html)?;
    println!("{}", path.display());
    if args.open {
        let status = std::process::Command::new("open").arg(&path).status()?;
        if !status.success() {
            return Err(format!("open failed, {status}").into());
        }
    }
    Ok(())
}

fn run(args: &Args) -> Result<String, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let at = now.as_secs() as i64;
    let run_id = format!("{}-{:09}", now.as_secs(), now.subsec_nanos());

    // Raw input is kept next to the store so that the store can be rebuilt from it.
    let home = home(&args.store);
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
