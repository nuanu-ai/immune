//! soc: read what is installed, keep it as facts, report what changed. One line.
//! `soc view` writes a page that shows what is in the store.

mod brew;
mod lifecycle;
mod lockfiles;
mod servers;
mod store;
mod view;

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Event, Reading, Statement};

const MACHINE_NAME: &str = "mac";
const DEFAULT_STORE: &str = "private/store/store.db";
const DEFAULT_SERVERS: &str = "private/map/servers";
const USAGE: &str = "usage: soc run [--store <path>] [--brew-input <file>] [--servers-input <dir>]
               [--checkouts-root <dir>]
       soc view [--store <path>] [--no-open]";

enum Cmd {
    Run(Args),
    View(ViewArgs),
}

struct Args {
    store: PathBuf,
    brew_input: Option<PathBuf>,
    /// Files the owner's read-only sweep wrote, one per server.
    servers_input: PathBuf,
    /// Where local checkouts are looked for; `$HOME/Dev` by default.
    checkouts_root: PathBuf,
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
            let mut servers_input = PathBuf::from(DEFAULT_SERVERS);
            let mut checkouts_root = None;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = value(&mut it, &arg)?.into(),
                    "--brew-input" => brew_input = Some(value(&mut it, &arg)?.into()),
                    "--servers-input" => servers_input = value(&mut it, &arg)?.into(),
                    "--checkouts-root" => checkouts_root = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let checkouts_root = match checkouts_root {
                Some(root) => root,
                None => std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join("Dev"))
                    .ok_or("HOME is not set; give --checkouts-root")?,
            };
            Ok(Cmd::Run(Args {
                store,
                brew_input,
                servers_input,
                checkouts_root,
            }))
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

    let tx = conn.transaction()?;
    let first_run = !store::any_run_finished(&tx)?;
    let mut run = Run {
        tx: &tx,
        home: &home,
        run_id: &run_id,
        at,
        events: Vec::new(),
        notes: Vec::new(),
        readers: 0,
    };
    read_brew(&mut run, args.brew_input.as_deref())?;
    read_servers(&mut run, &args.servers_input)?;
    read_lockfiles(&mut run, &args.checkouts_root)?;

    let totals = store::totals(&tx, &run_id)?;
    let line = report(&run, &totals, first_run);
    store::journal_note(&tx, at, &run_id, "report", &line)?;
    store::journal_note(&tx, at, &run_id, "run_finished", "")?;
    tx.commit()?;
    Ok(line)
}

/// One run in progress: where it writes and what it has seen so far.
struct Run<'a> {
    tx: &'a rusqlite::Transaction<'a>,
    home: &'a Path,
    run_id: &'a str,
    at: i64,
    events: Vec<Event>,
    /// Sentences for the end of the report line: inputs that were not there.
    notes: Vec<String>,
    /// Readers that had input to read.
    readers: usize,
}

impl Run<'_> {
    /// Writes one reading's statements and coverage and moves it through the lifecycle.
    fn apply(
        &mut self,
        r: &Reading,
        basis: &str,
        completeness: &str,
        reason: Option<&str>,
        statements: &[Statement],
    ) -> rusqlite::Result<()> {
        if completeness != "none" {
            for s in statements {
                store::put_draft(self.tx, r, basis, s)?;
            }
        }
        store::put_coverage(self.tx, r, completeness, reason)?;
        let events = lifecycle::promote(self.tx, r, completeness)?;
        for e in &events {
            store::journal_event(self.tx, r, e)?;
        }
        self.events.extend(events);
        Ok(())
    }

    /// Saves raw input unless it equals the last saved copy of the same input, and returns
    /// the path that assertions point at, relative to the store's folder.
    fn keep_raw(&self, reader: &str, input: &str, bytes: &[u8]) -> Result<String, Box<dyn Error>> {
        if let Some(path) = store::last_raw(self.tx, reader, input)?
            && std::fs::read(self.home.join(&path)).is_ok_and(|saved| saved == bytes)
        {
            return Ok(path);
        }
        let path = format!("raw/{}/{input}", self.run_id);
        let file = self.home.join(&path);
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&file, bytes)?;
        store::set_raw(self.tx, reader, input, &path, self.run_id)?;
        Ok(path)
    }
}

fn read_brew(run: &mut Run, input: Option<&Path>) -> Result<(), Box<dyn Error>> {
    run.readers += 1;
    let machine = format!("machine:{MACHINE_NAME}");
    store::put_entity(run.tx, &machine)?;
    let (at, run_id) = (run.at, run.run_id.to_string());
    let reading = Reading {
        reader: brew::READER,
        scope: &machine,
        kind: brew::KIND,
        run_id: &run_id,
        at,
        observed_at: at,
    };
    match brew::read(input) {
        Ok(raw) => {
            let raw_file = run.keep_raw(brew::READER, "brew.txt", raw.as_bytes())?;
            let statements = brew::statements(&raw, &machine, &raw_file);
            run.apply(&reading, brew::BASIS, "full", None, &statements)?;
        }
        Err(reason) => {
            run.apply(&reading, brew::BASIS, "none", Some(&reason), &[])?;
            run.notes
                .push(format!("Homebrew on {MACHINE_NAME}: {reason}."));
        }
    }
    Ok(())
}

fn read_servers(run: &mut Run, dir: &Path) -> Result<(), Box<dyn Error>> {
    if !dir.is_dir() {
        run.notes.push(format!(
            "No server files: {} is not a folder.",
            dir.display()
        ));
        return Ok(());
    }
    run.readers += 1;
    let run_id = run.run_id.to_string();
    for input in servers::inputs(dir)? {
        let machine = format!("machine:{}", input.name);
        store::put_entity(run.tx, &machine)?;
        let readings = match &input.raw {
            Some(bytes) => {
                let raw_file = run.keep_raw(
                    servers::READER,
                    &format!("servers/{}.txt", input.name),
                    bytes,
                )?;
                servers::readings(&machine, &String::from_utf8_lossy(bytes), &raw_file)
            }
            None => servers::unreadable(),
        };
        for o in readings {
            let reading = Reading {
                reader: servers::READER,
                scope: &machine,
                kind: o.kind,
                run_id: &run_id,
                at: run.at,
                observed_at: input.modified,
            };
            run.apply(
                &reading,
                servers::BASIS,
                o.completeness,
                o.reason.as_deref(),
                &o.statements,
            )?;
        }
    }
    Ok(())
}

fn read_lockfiles(run: &mut Run, root: &Path) -> Result<(), Box<dyn Error>> {
    if !root.is_dir() {
        run.notes
            .push(format!("No checkouts: {} is not a folder.", root.display()));
        return Ok(());
    }
    run.readers += 1;
    let machine = format!("machine:{MACHINE_NAME}");
    store::put_entity(run.tx, &machine)?;
    let run_id = run.run_id.to_string();
    let (checkouts, unreadable) = lockfiles::checkouts(root);
    if unreadable > 0 {
        run.notes.push(format!(
            "{} under the checkouts root could not be listed.",
            things(unreadable as i64, "folder", "folders")
        ));
    }
    // Lockfiles are under version control: the raw input is where they are and at which commit.
    let mut manifest = String::new();
    for checkout in &checkouts {
        let id = format!("checkout:{machine}/{}", checkout.rel);
        store::put_entity(run.tx, &id)?;
        let Some(o) = lockfiles::read(checkout, &id, &machine) else {
            continue;
        };
        let commit = lockfiles::commit(&checkout.path);
        for (path, size) in &o.lockfiles {
            manifest.push_str(&format!("{path}\t{size}\t{commit}\n"));
        }
        let reading = Reading {
            reader: lockfiles::READER,
            scope: &id,
            kind: lockfiles::KIND,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        run.apply(
            &reading,
            lockfiles::BASIS,
            o.completeness,
            o.reason.as_deref(),
            &o.statements,
        )?;
    }
    let dir = run.home.join("raw").join(&run_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("lockfiles.txt"), manifest)?;
    Ok(())
}

/// The one line. It never says "no changes" unless every reading this run was full and
/// every scope read before was read again.
fn report(run: &Run, t: &store::Totals, first_run: bool) -> String {
    let mut line = format!(
        "{}, {}, {}, {}.",
        things(run.readers as i64, "reader", "readers"),
        things(t.machines, "machine", "machines"),
        things(t.checkouts, "checkout", "checkouts"),
        things(t.components, "component", "components"),
    );
    let mut gaps = Vec::new();
    if t.machines_unread > 0 {
        gaps.push(format!(
            "{} could not be read",
            things(t.machines_unread, "machine", "machines")
        ));
    }
    if t.partial > 0 {
        gaps.push(format!(
            "{} partial",
            things(t.partial, "reading was", "readings were")
        ));
    }
    if t.none > 0 {
        gaps.push(format!(
            "{} nothing",
            things(t.none, "reading read", "readings read")
        ));
    }
    if t.not_repeated > 0 {
        gaps.push(format!(
            "{} not repeated",
            things(
                t.not_repeated,
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
    line.push(' ');
    line.push_str(&if first_run {
        "First run.".to_string()
    } else {
        since_last_run(&run.events, t)
    });
    for note in &run.notes {
        line.push(' ');
        line.push_str(note);
    }
    line
}

/// Counts things, not assertions: a new component is one addition however many
/// assertions it brings.
fn since_last_run(events: &[Event], t: &store::Totals) -> String {
    let count = |kind: &str| {
        events
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.subject.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    };
    let (added, changed, removed) = (count("added"), count("changed"), count("removed"));
    let counts = format!(
        "+{} added, {} changed, {} removed",
        grouped(added as i64),
        grouped(changed as i64),
        grouped(removed as i64)
    );
    let mut unknown = Vec::new();
    if t.partial > 0 {
        unknown.push("removals unknown where a reading was partial");
    }
    if t.none > 0 || t.not_repeated > 0 {
        unknown.push("changes unknown where nothing was read");
    }
    if !unknown.is_empty() {
        return format!("Since last run: {counts}; {}.", unknown.join(", "));
    }
    if added + changed + removed == 0 {
        return "Since last run: no changes.".to_string();
    }
    format!("Since last run: {counts}.")
}

/// `1 machine`, `17,204 components`.
fn things(n: i64, one: &str, many: &str) -> String {
    format!("{} {}", grouped(n), if n == 1 { one } else { many })
}

/// `17204` as `17,204`.
fn grouped(n: i64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) && c.is_ascii_digit() {
            out.push(',');
        }
        out.push(c);
    }
    out
}
