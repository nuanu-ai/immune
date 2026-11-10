//! soc: read what is installed, keep it as facts, report what changed. One line.
//! `soc view` writes a page that shows what is in the store. `soc servers` shows which
//! servers this machine knows and writes the read-only sweep for the owner to run.
//!
//! The program never connects to a server and never runs ssh.

mod agent_folders;
mod brew;
mod checkouts;
mod known_hosts;
mod lifecycle;
mod lockfiles;
mod resolver;
mod servers;
mod ssh_config;
mod store;
mod sweep;
mod tailnet;
mod traces;
mod view;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Event, Reading, Statement};

/// The store's folder inside the home folder, where every default path points.
const STORE_FOLDER: &str = "Library/Application Support/personal-soc";
const USAGE: &str = "usage: soc run [--store <path>] [--machine-name <name>] [--brew <path>]
               [--brew-input <file>] [--servers-input <dir>] [--checkouts-root <dir>]
               [--sessions-root <dir>] [--tailscale <path>]
       soc servers [--store <path>] [--tailscale <path>]
       soc view [--store <path>] [--no-open]";

enum Cmd {
    Run(Args),
    Servers(ServersArgs),
    View(ViewArgs),
}

struct Args {
    store: PathBuf,
    /// The name of this machine in ids.
    machine: String,
    /// The one place to look for brew instead of PATH and the standard places.
    brew: Option<PathBuf>,
    brew_input: Option<PathBuf>,
    /// Files the owner's read-only sweep wrote, one per server. `None`: the `sweep`
    /// folder next to the store.
    servers_input: Option<PathBuf>,
    /// The home folder: checkout ids are relative to it, and the ssh files are in it.
    home: PathBuf,
    /// The one folder to look for checkouts in instead of the home folder.
    checkouts_root: Option<PathBuf>,
    /// The folder of agent sessions instead of Claude Code's own.
    sessions_root: Option<PathBuf>,
    /// The one place to look for tailscale instead of the usual ones.
    tailscale: Option<PathBuf>,
}

struct ServersArgs {
    store: PathBuf,
    home: PathBuf,
    tailscale: Option<PathBuf>,
}

struct ViewArgs {
    store: PathBuf,
    open: bool,
}

fn user_home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())
}

fn default_store() -> Result<PathBuf, String> {
    Ok(user_home()?.join(STORE_FOLDER).join("store.db"))
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let cmd = it.next().ok_or("no command given")?;
    let mut store = None;
    match cmd.as_str() {
        "run" => {
            let (mut machine, mut brew, mut brew_input) = (None, None, None);
            let (mut servers_input, mut checkouts_root, mut tailscale) = (None, None, None);
            let mut sessions_root = None;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--tailscale" => tailscale = Some(value(&mut it, &arg)?.into()),
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--machine-name" => machine = Some(value(&mut it, &arg)?),
                    "--brew" => brew = Some(value(&mut it, &arg)?.into()),
                    "--brew-input" => brew_input = Some(value(&mut it, &arg)?.into()),
                    "--servers-input" => servers_input = Some(value(&mut it, &arg)?.into()),
                    "--checkouts-root" => checkouts_root = Some(value(&mut it, &arg)?.into()),
                    "--sessions-root" => sessions_root = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            if machine.as_deref() == Some("") {
                return Err("--machine-name needs a name".to_string());
            }
            Ok(Cmd::Run(Args {
                store: store.map_or_else(default_store, Ok)?,
                machine: machine.unwrap_or_else(machine_name),
                brew,
                brew_input,
                servers_input,
                checkouts_root,
                sessions_root,
                home: user_home()?,
                tailscale,
            }))
        }
        "servers" => {
            let mut tailscale = None;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--tailscale" => tailscale = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            Ok(Cmd::Servers(ServersArgs {
                store: store.map_or_else(default_store, Ok)?,
                home: user_home()?,
                tailscale,
            }))
        }
        "view" => {
            let mut open = true;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--no-open" => open = false,
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            Ok(Cmd::View(ViewArgs { store, open }))
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

/// The name this Mac gives itself on the local network, else its short host name.
fn machine_name() -> String {
    let asks: [(&str, &[&str]); 2] = [
        ("scutil", &["--get", "LocalHostName"]),
        ("hostname", &["-s"]),
    ];
    for (program, args) in asks {
        if let Ok(out) = Command::new(program).args(args).output()
            && out.status.success()
        {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "this-mac".to_string()
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
        Cmd::Servers(args) => servers_cmd(&args),
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
        let status = Command::new("open").arg(&path).status()?;
        if !status.success() {
            return Err(format!("open failed, {status}").into());
        }
    }
    Ok(())
}

/// One server as `soc servers` lists it.
struct ServerRow {
    name: String,
    others: Vec<String>,
    traces: Vec<&'static str>,
    sweep: String,
    file: String,
    /// The aliases the sweep may use, in the order of the ssh configuration. It visits the
    /// first of them that is not in `skip.txt` when it runs.
    offered: Vec<String>,
    read: bool,
}

/// Where `soc servers` says a machine known only from its sweep file is known from.
const SWEEP_FILE: &str = "sweep file";

/// Finds the servers this machine knows, prints them, and writes the probe and the sweep
/// script next to the store. Reads local files only; never writes to the store and never
/// runs ssh.
fn servers_cmd(args: &ServersArgs) -> Result<(), Box<dyn Error>> {
    let dir = home(&args.store).join("sweep");
    let traces = [
        (
            ssh_config::READER,
            ssh_config::KIND,
            ssh_config::BASIS,
            ssh_config::read(&args.home),
        ),
        (
            known_hosts::READER,
            known_hosts::KIND,
            known_hosts::BASIS,
            known_hosts::read(&args.home),
        ),
        (
            tailnet::READER,
            tailnet::KIND,
            tailnet::BASIS,
            tailnet::read(args.tailscale.as_deref(), &args.home),
        ),
    ];
    let mut known = Vec::new();
    let mut traces_of: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    let mut names_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Aliases in the order of the ssh configuration.
    let mut aliases: Vec<String> = Vec::new();
    let (mut said, mut third_party) = (Vec::new(), 0);
    let mut add = |id: &str, reader: &str, kind: &'static str, basis: &str, value: &str| {
        let list = traces_of.entry(id.to_string()).or_default();
        if !list.contains(&kind) {
            list.push(kind);
        }
        if value.is_empty() {
            return;
        }
        known.push(resolver::Known {
            entity: id.to_string(),
            value: value.to_string(),
            basis: basis.to_string(),
            reader: reader.to_string(),
        });
        names_of
            .entry(id.to_string())
            .or_default()
            .insert(value.to_string());
    };
    for (reader, kind, basis, found) in &traces {
        match found {
            traces::Found::Absent(note) => said.push(format!("{kind}: nothing to read, {note}")),
            traces::Found::Failed(reason) => {
                said.push(format!("{kind}: could not be read, {reason}"));
            }
            traces::Found::Read(seen) => {
                let mut line = format!(
                    "{kind}: {}",
                    things(seen.hosts.len() as i64, "server", "servers")
                );
                if let Some(partial) = &seen.partial {
                    line.push_str(&format!(", {partial}"));
                }
                if seen.third_party > 0 {
                    line.push_str(&format!(", {} left out as code hosting", seen.third_party));
                }
                said.push(line);
                third_party += seen.third_party;
                for host in &seen.hosts {
                    let id = format!("machine:{}", host.name);
                    add(&id, reader, kind, basis, "");
                    for (value, _) in &host.known_as {
                        add(&id, reader, kind, basis, value);
                    }
                    if *kind == ssh_config::KIND {
                        aliases.push(host.name.clone());
                    }
                }
            }
        }
    }
    // Servers the sweep has read, each under the name of its file, with the names and
    // addresses it gives itself: the same machines `soc run` knows from these files.
    if dir.is_dir() {
        match servers::inputs(&dir) {
            Err(e) => said.push(format!("{SWEEP_FILE}s: could not be read, {e}")),
            Ok(inputs) => {
                said.push(format!(
                    "{SWEEP_FILE}s: {}",
                    things(inputs.len() as i64, "server", "servers")
                ));
                for input in inputs {
                    let id = format!("machine:{}", input.name);
                    add(&id, servers::READER, SWEEP_FILE, servers::BASIS, "");
                    let text = String::from_utf8_lossy(input.raw.as_deref().unwrap_or_default());
                    for o in servers::readings(&id, &text, "") {
                        for s in o.statements.iter().filter(|s| s.predicate == "known_as") {
                            add(&id, servers::READER, SWEEP_FILE, servers::BASIS, &s.object);
                        }
                    }
                }
            }
        }
    }
    let pairs: Vec<(String, String)> = resolver::links(&known)
        .into_iter()
        .map(|l| (l.a, l.b))
        .collect();
    let groups = resolver::groups(traces_of.keys().cloned(), &pairs);
    let skip = sweep::skip_list(&dir);

    let mut rows = Vec::new();
    for group in &groups {
        let members: Vec<&str> = group
            .iter()
            .map(|m| m.strip_prefix("machine:").unwrap_or(m))
            .collect();
        let with_alias: Vec<&str> = aliases
            .iter()
            .map(String::as_str)
            .filter(|a| members.contains(a))
            .collect();
        let offered: Vec<String> = with_alias
            .iter()
            .filter(|a| sweep::not_offered(a, &skip).is_none())
            .map(|a| a.to_string())
            .collect();
        let sweep = if let Some(first) = offered.first() {
            let rest: Vec<String> = with_alias
                .iter()
                .filter(|a| *a != first)
                .map(|a| match sweep::not_offered(a, &skip) {
                    Some(why) => format!("{a} ({why})"),
                    None => a.to_string(),
                })
                .collect();
            let mut sweep = format!("visits {first}");
            if !rest.is_empty() {
                sweep.push_str(&format!("; same machine, not visited: {}", rest.join(", ")));
            }
            sweep
        } else if let Some(alias) = with_alias.first() {
            format!(
                "not offered: {}",
                sweep::not_offered(alias, &skip).unwrap_or("")
            )
        } else {
            "not offered: no ssh alias".to_string()
        };
        let name = offered
            .first()
            .map(String::as_str)
            .or(with_alias.first().copied())
            .unwrap_or(members[0])
            .to_string();
        let mut others: BTreeSet<String> = group
            .iter()
            .flat_map(|m| names_of.get(m).into_iter().flatten().cloned())
            .collect();
        others.extend(members.iter().map(|m| m.to_string()));
        others.remove(&name);
        let mut traces: Vec<&'static str> = Vec::new();
        for m in group {
            for t in traces_of.get(m).into_iter().flatten() {
                if !traces.contains(t) {
                    traces.push(t);
                }
            }
        }
        let (file, read) = last_file(&dir, &members);
        rows.push(ServerRow {
            name,
            others: others.into_iter().collect(),
            traces,
            sweep,
            file,
            offered,
            read,
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    let (offered, rest): (Vec<&ServerRow>, Vec<&ServerRow>) =
        rows.iter().partition(|r| !r.offered.is_empty());
    let table = |title: String, rows: &[&ServerRow]| {
        println!("{title}");
        let cells: Vec<Vec<String>> = rows
            .iter()
            .map(|r| {
                vec![
                    r.name.clone(),
                    r.traces.join(", "),
                    r.sweep.clone(),
                    r.file.clone(),
                    r.others.join(", "),
                ]
            })
            .collect();
        print_table(
            &[
                "Server",
                "Known from",
                "Sweep",
                "Last file",
                "Also known as",
            ],
            &cells,
        );
        println!();
    };
    table(
        format!(
            "Offered for the sweep: {}",
            things(offered.len() as i64, "server", "servers")
        ),
        &offered,
    );
    table(
        format!(
            "Known and not offered: {}",
            things(rest.len() as i64, "server", "servers")
        ),
        &rest,
    );

    let machines: Vec<Vec<String>> = offered.iter().map(|r| r.offered.clone()).collect();
    sweep::write(&dir, &machines)?;
    for line in &said {
        println!("{}{}.", line[..1].to_uppercase(), &line[1..]);
    }
    println!(
        "{} known, {} of them under several names, {} offered for the sweep, {} left out as code hosting, {} known and never read.",
        things(rows.len() as i64, "server", "servers"),
        groups.iter().filter(|g| g.len() > 1).count(),
        offered.len(),
        third_party,
        rows.iter().filter(|r| !r.read).count()
    );
    let spare: usize = machines.iter().map(|m| m.len() - 1).sum();
    if spare > 0 {
        println!(
            "The sweep visits each offered server once, through one alias; {} not visited.",
            things(
                spare as i64,
                "alias of the same machine is",
                "aliases of the same machines are"
            )
        );
    }
    println!(
        "Wrote probe.sh and sweep.sh to {}. Nothing was run.",
        dir.display()
    );
    println!("To read the offered servers, run:");
    println!("  sh {}", sweep::quoted(&dir.join("sweep.sh")));
    println!(
        "To leave a server out, add its alias to {}, one per line. Then run `soc run`.",
        dir.join(sweep::SKIP).display()
    );
    Ok(())
}

/// The sweep file of a server under any of its names: when it was taken, or that it is
/// incomplete. And whether it was read.
fn last_file(dir: &Path, names: &[&str]) -> (String, bool) {
    let mut seen = None;
    for name in names {
        let path = dir.join(format!("{name}.txt"));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        if !text.lines().any(|l| l.trim() == "##end") {
            seen.get_or_insert(("incomplete".to_string(), false));
            continue;
        }
        let at = servers::taken_at(&text).or_else(|| {
            let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
            Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
        });
        return (
            format!(
                "read, taken {}",
                at.map_or("at an unknown time".to_string(), view::utc)
            ),
            true,
        );
    }
    seen.unwrap_or(("never read".to_string(), false))
}

/// A plain text table with columns as wide as their widest cell.
fn print_table(head: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("  none");
        return;
    }
    let mut widths: Vec<usize> = head.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        println!("  {}", parts.join("  ").trim_end());
    };
    line(head.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
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
    let machine = format!("machine:{}", args.machine);
    store::put_entity(&tx, &machine)?;
    let mut run = Run {
        tx: &tx,
        home: &home,
        run_id: &run_id,
        at,
        machine: &machine,
        events: Vec::new(),
        notes: Vec::new(),
        readers: 0,
    };
    read_brew(&mut run, args)?;
    let servers = args.servers_input.clone();
    read_servers(&mut run, servers.as_deref())?;
    let walked = read_checkouts(&mut run, args)?;
    let from_agents = read_agent_folders(&mut run, args)?;
    if walked.is_some() || !from_agents.is_empty() {
        // One checkout found by both readers is read once.
        let mut found = walked.unwrap_or_default();
        let known: BTreeSet<String> = found.iter().map(|c| c.rel.clone()).collect();
        found.extend(from_agents.into_iter().filter(|c| !known.contains(&c.rel)));
        read_lockfiles(&mut run, &found)?;
    }
    read_traces(&mut run, args)?;
    resolve(&mut run)?;

    let totals = store::totals(&tx, &run_id)?;
    let counts = server_counts(&tx, &machine, &sweep::skip_list(&home.join("sweep")))?;
    let line = report(&run, &totals, &counts, first_run);
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
    /// This machine's id.
    machine: &'a str,
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
        let with_basis: Vec<(&str, &Statement)> = statements.iter().map(|s| (basis, s)).collect();
        self.apply_each(r, completeness, reason, &with_basis)
    }

    /// The same, for statements that each have their own basis.
    fn apply_each(
        &mut self,
        r: &Reading,
        completeness: &str,
        reason: Option<&str>,
        statements: &[(&str, &Statement)],
    ) -> rusqlite::Result<()> {
        if completeness != "none" {
            for (basis, s) in statements {
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

fn read_brew(run: &mut Run, args: &Args) -> Result<(), Box<dyn Error>> {
    let (at, run_id, machine) = (run.at, run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader: brew::READER,
        scope: &machine,
        kind: brew::KIND,
        run_id: &run_id,
        at,
        observed_at: at,
    };
    match brew::read(args.brew_input.as_deref(), args.brew.as_deref()) {
        brew::Found::Output(raw) => {
            run.readers += 1;
            let raw_file = run.keep_raw(brew::READER, "brew.txt", raw.as_bytes())?;
            let statements = brew::statements(&raw, &machine, &raw_file);
            run.apply(&reading, brew::BASIS, "full", None, &statements)?;
        }
        // Read in full: there is nothing, so what was there before is gone.
        brew::Found::NotInstalled => {
            run.apply(
                &reading,
                brew::BASIS,
                "full",
                Some(brew::NOT_INSTALLED),
                &[],
            )?;
            run.notes
                .push("Homebrew is not installed, nothing to read.".to_string());
        }
        brew::Found::Failed(reason) => {
            run.readers += 1;
            run.apply(&reading, brew::BASIS, "none", Some(&reason), &[])?;
            run.notes
                .push(format!("Homebrew could not be read: {reason}."));
        }
    }
    Ok(())
}

/// `dir` is the folder given on the command line; without one, the sweep folder next to
/// the store, which is there only once a sweep has been run.
fn read_servers(run: &mut Run, dir: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let default = run.home.join("sweep");
    let Some(dir) = dir.or(Some(&default)).filter(|d| d.is_dir()) else {
        run.notes.push(match dir {
            Some(dir) => format!("No server files: {} is not a folder.", dir.display()),
            None => "No server sweep has been run.".to_string(),
        });
        return Ok(());
    };
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
            None => servers::unreadable(&machine),
        };
        for o in readings {
            store::put_entity(run.tx, &o.scope)?;
            let reading = Reading {
                reader: servers::READER,
                scope: &o.scope,
                kind: o.kind,
                run_id: &run_id,
                at: run.at,
                observed_at: input
                    .raw
                    .as_deref()
                    .and_then(|b| servers::taken_at(&String::from_utf8_lossy(b)))
                    .unwrap_or(input.modified),
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

/// Which checkouts are on this machine. `None` when the root is not a folder: then
/// nothing was looked at and nothing is said. A folder given instead of the home folder is
/// read partially: what is outside it was not looked at and must not be retracted.
fn read_checkouts(
    run: &mut Run,
    args: &Args,
) -> Result<Option<Vec<checkouts::Checkout>>, Box<dyn Error>> {
    let (root, home) = (
        args.checkouts_root.as_ref().unwrap_or(&args.home),
        &args.home,
    );
    if !root.is_dir() {
        run.notes
            .push(format!("No checkouts: {} is not a folder.", root.display()));
        return Ok(None);
    }
    run.readers += 1;
    let walk = checkouts::walk(root, home);
    let mut raw = String::new();
    for c in &walk.checkouts {
        raw.push_str(&format!("checkout\t{}\n", c.rel));
    }
    for folder in &walk.unlisted {
        raw.push_str(&format!("not listed\t{folder}\n"));
    }
    let raw_file = run.keep_raw(checkouts::READER, "checkouts.txt", raw.as_bytes())?;
    let machine = run.machine.to_string();
    let statements: Vec<Statement> = walk
        .checkouts
        .iter()
        .enumerate()
        .map(|(i, c)| Statement {
            subject: format!("checkout:{machine}/{}", c.rel),
            predicate: "located_on",
            object: machine.clone(),
            source_ref: format!("{raw_file}:{}", i + 1),
        })
        .collect();
    let unlisted = (!walk.unlisted.is_empty())
        .then(|| format!("could not be listed: {}", walk.unlisted.join(", ")));
    if let Some(unlisted) = &unlisted {
        run.notes.push(format!("Folders that {unlisted}."));
    }
    let given = args
        .checkouts_root
        .is_some()
        .then(|| checkouts::ONLY_GIVEN.to_string());
    let reasons: Vec<String> = given.into_iter().chain(unlisted).collect();
    let reason = (!reasons.is_empty()).then(|| reasons.join("; "));
    let run_id = run.run_id.to_string();
    let reading = Reading {
        reader: checkouts::READER,
        scope: &machine,
        kind: checkouts::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    let completeness = if reason.is_some() { "partial" } else { "full" };
    run.apply(
        &reading,
        checkouts::BASIS,
        completeness,
        reason.as_deref(),
        &statements,
    )?;
    Ok(Some(walk.checkouts))
}

/// Checkouts in the folders agents worked in. The candidates are the working folders in the
/// sessions and the checkouts this reader already holds, each checked on disk, so a checkout
/// stays while it is there however long ago its session was deleted.
fn read_agent_folders(
    run: &mut Run,
    args: &Args,
) -> Result<Vec<checkouts::Checkout>, Box<dyn Error>> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader: agent_folders::READER,
        scope: &machine,
        kind: agent_folders::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    let dir = args
        .sessions_root
        .clone()
        .unwrap_or_else(|| args.home.join(agent_folders::SESSIONS));
    let sessions = match agent_folders::sessions(&dir) {
        agent_folders::Found::Failed(reason) => {
            run.readers += 1;
            run.apply(&reading, agent_folders::BASIS, "none", Some(&reason), &[])?;
            run.notes
                .push(format!("Agent sessions could not be read: {reason}."));
            return Ok(Vec::new());
        }
        agent_folders::Found::Absent => None,
        agent_folders::Found::Read(sessions) => {
            run.readers += 1;
            Some(sessions)
        }
    };
    let home = std::fs::canonicalize(&args.home).unwrap_or_else(|_| args.home.clone());
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    for folder in sessions.iter().flat_map(|s| &s.folders) {
        match agent_folders::checkout_of(folder, &home) {
            agent_folders::OnDisk::Checkout(path) => {
                found.insert(checkouts::rel(&home, &path), path);
            }
            agent_folders::OnDisk::Nothing => {}
            agent_folders::OnDisk::Unknown => {
                unknown.insert(folder.clone());
            }
        }
    }
    let prefix = format!("checkout:{machine}/");
    let mut kept = 0;
    for id in store::live_subjects(run.tx, agent_folders::READER)? {
        let Some(rel) = id.strip_prefix(&prefix) else {
            continue;
        };
        if found.contains_key(rel) {
            continue;
        }
        let path = if rel.starts_with('/') {
            PathBuf::from(rel)
        } else {
            args.home.join(rel)
        };
        match agent_folders::still_there(&path) {
            Some(true) => {
                found.insert(rel.to_string(), path);
            }
            Some(false) => {}
            // Not known to be gone: the reading is partial, so it stays as it was.
            None => kept += 1,
        }
    }

    let mut raw = String::new();
    for rel in found.keys() {
        raw.push_str(&format!("checkout\t{rel}\n"));
    }
    let raw_file = run.keep_raw(agent_folders::READER, "agent-folders.txt", raw.as_bytes())?;
    let statements: Vec<Statement> = found
        .keys()
        .enumerate()
        .map(|(i, rel)| Statement {
            subject: format!("{prefix}{rel}"),
            predicate: "located_on",
            object: machine.clone(),
            source_ref: format!("{raw_file}:{}", i + 1),
        })
        .collect();
    let mut reasons = Vec::new();
    let count = |n: usize, one: &str, many: &str| things(n as i64, one, many);
    if let Some(s) = &sessions {
        if s.unreadable > 0 {
            reasons.push(format!(
                "{} of {} could not be read",
                s.unreadable,
                count(s.files, "session file", "session files")
            ));
        }
        if s.unlisted > 0 {
            reasons.push(format!(
                "{} could not be listed",
                count(s.unlisted, "session folder", "session folders")
            ));
        }
        if s.unparsed > 0 {
            reasons.push(format!(
                "{} with a working folder could not be parsed",
                count(s.unparsed, "line", "lines")
            ));
        }
    }
    if !unknown.is_empty() {
        reasons.push(format!(
            "{} could not be looked at",
            count(unknown.len(), "working folder", "working folders")
        ));
    }
    if kept > 0 {
        reasons.push(format!(
            "{} could not be checked and {} kept",
            count(kept, "checkout", "checkouts"),
            if kept == 1 { "is" } else { "are" }
        ));
    }
    let (completeness, reason) = match (reasons.is_empty(), &sessions) {
        (false, _) => ("partial", Some(reasons.join("; "))),
        (true, None) => ("full", Some(agent_folders::NOT_HERE.to_string())),
        (true, Some(_)) => ("full", None),
    };
    run.apply(
        &reading,
        agent_folders::BASIS,
        completeness,
        reason.as_deref(),
        &statements,
    )?;
    Ok(found
        .into_iter()
        .map(|(rel, path)| checkouts::Checkout { rel, path })
        .collect())
}

/// The three local traces of servers, each its own reading of this machine.
fn read_traces(run: &mut Run, args: &Args) -> Result<(), Box<dyn Error>> {
    let traces = [
        (
            ssh_config::READER,
            ssh_config::KIND,
            ssh_config::BASIS,
            ssh_config::read(&args.home),
        ),
        (
            known_hosts::READER,
            known_hosts::KIND,
            known_hosts::BASIS,
            known_hosts::read(&args.home),
        ),
        (
            tailnet::READER,
            tailnet::KIND,
            tailnet::BASIS,
            tailnet::read(args.tailscale.as_deref(), &args.home),
        ),
    ];
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    for (reader, kind, basis, found) in traces {
        let reading = Reading {
            reader,
            scope: &machine,
            kind,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        match found {
            // Read in full: there is nothing, so what was there before is gone.
            traces::Found::Absent(note) => run.apply(&reading, basis, "full", Some(note), &[])?,
            traces::Found::Read(seen) => {
                run.readers += 1;
                let input = format!("{reader}.txt");
                let raw_file = run.keep_raw(reader, &input, seen.extract.as_bytes())?;
                let statements = seen.statements(&raw_file);
                let completeness = if seen.partial.is_some() {
                    "partial"
                } else {
                    "full"
                };
                run.apply(
                    &reading,
                    basis,
                    completeness,
                    seen.partial.as_deref(),
                    &statements,
                )?;
            }
            traces::Found::Failed(reason) => {
                run.readers += 1;
                run.apply(&reading, basis, "none", Some(&reason), &[])?;
                run.notes
                    .push(format!("The {kind} could not be read: {reason}."));
            }
        }
    }
    Ok(())
}

/// Links machines that are one machine under several names. The links are a full reading
/// of the live store on every run, so a link whose evidence is gone is retracted.
fn resolve(run: &mut Run) -> Result<(), Box<dyn Error>> {
    let links = resolver::links(&store::live_known_as(run.tx)?);
    let statements: Vec<(&str, Statement)> = links
        .iter()
        .map(|l| {
            (
                l.basis.as_str(),
                Statement {
                    subject: l.a.clone(),
                    predicate: "same_as",
                    object: l.b.clone(),
                    source_ref: format!("known_as {}", l.shared.join(", ")),
                },
            )
        })
        .collect();
    let refs: Vec<(&str, &Statement)> = statements.iter().map(|(b, s)| (*b, s)).collect();
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader: resolver::READER,
        scope: &machine,
        kind: resolver::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    run.apply_each(&reading, "full", None, &refs)?;
    Ok(())
}

/// Servers in the store, each counted once however many names it has.
struct ServerCounts {
    known: usize,
    offered: usize,
    read: usize,
}

fn server_counts(
    conn: &rusqlite::Connection,
    machine: &str,
    skip: &BTreeSet<String>,
) -> rusqlite::Result<ServerCounts> {
    let aliases = store::live_subjects(conn, ssh_config::READER)?;
    let read = store::scopes_read(conn, servers::READER)?;
    let offered = |id: &String| {
        aliases.contains(id)
            && sweep::not_offered(id.strip_prefix("machine:").unwrap_or(id), skip).is_none()
    };
    let mut counts = ServerCounts {
        known: 0,
        offered: 0,
        read: 0,
    };
    for group in store::machine_groups(conn)? {
        if group.iter().any(|m| m == machine) {
            continue;
        }
        counts.known += 1;
        counts.offered += usize::from(group.iter().any(offered));
        counts.read += usize::from(group.iter().any(|m| read.contains(m)));
    }
    Ok(counts)
}

fn read_lockfiles(run: &mut Run, found: &[checkouts::Checkout]) -> Result<(), Box<dyn Error>> {
    run.readers += 1;
    let run_id = run.run_id.to_string();
    // Lockfiles are under version control: the raw input is where they are and at which commit.
    let mut manifest = String::new();
    for checkout in found {
        let id = format!("checkout:{}/{}", run.machine, checkout.rel);
        let Some(o) = lockfiles::read(checkout, &id) else {
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
fn report(run: &Run, t: &store::Totals, s: &ServerCounts, first_run: bool) -> String {
    let mut line = format!(
        "{}, {}, {}, {}.",
        things(run.readers as i64, "reader", "readers"),
        things(t.machines, "machine", "machines"),
        things(t.checkouts, "checkout", "checkouts"),
        things(t.components, "component", "components"),
    );
    if s.known == 0 {
        line.push_str(" No servers known.");
    } else {
        line.push_str(&format!(
            " {} known, {} offered for the sweep, {} read.",
            things(s.known as i64, "server", "servers"),
            grouped(s.offered as i64),
            grouped(s.read as i64)
        ));
    }
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
