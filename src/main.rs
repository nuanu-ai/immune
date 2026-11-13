//! Immune: read what is installed, keep it as facts, report what changed. One line.
//! `immune view` writes a page that shows what is in the store. `immune servers` shows which
//! servers this machine knows and writes the read-only sweep for the owner to run.
//! `immune owner` keeps the owner's word: that a machine is retired or not theirs. `immune status`
//! says what the last finished run left, read-only; with `--json`, `immune status` and `immune run`
//! answer in one machine-readable envelope.
//!
//! The program never connects to a server and never runs ssh. Its requests to the network
//! are the threat list and the vulnerability data of npm and crates.io, each fetched whole
//! with the system curl.

mod agent_folders;
mod autorun;
mod baseline;
mod beyond;
mod brew;
mod checkouts;
mod codesign;
mod contract;
mod covered;
mod events;
mod finding_answer;
mod findings;
mod fsevents;
mod guarded;
mod happens;
mod icu;
mod indicators;
mod integrity;
mod json5;
mod jsonc;
mod known;
mod known_hosts;
mod lifecycle;
mod lockfiles;
mod machine;
mod map;
mod matches;
mod osv;
mod owner;
mod pages;
mod processes;
mod program;
mod project;
mod resolver;
mod servers;
mod sha256;
mod sigma;
mod ssh_config;
mod status;
mod store;
mod sweep;
mod tailnet;
mod threats;
mod tools;
mod traces;
mod view;
mod vulnerabilities;
mod watch;
mod watched;
mod worktrees;

use baseline::Verdict;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Cause, Event, Gap, Lack, Reading, Statement};

/// The store's folder inside the home folder, where every default path points.
const STORE_FOLDER: &str = "Library/Application Support/ai.nuanu.immune";
const USAGE: &str = "usage: immune run [--store <path>] [--machine-name <name>] [--brew <path>]
                  [--brew-input <file>] [--servers-input <dir>] [--checkouts-root <dir>]
                  [--sessions-root <dir>] [--tailscale <path>]
                  [--threats-input <file>] [--osv-crates-input <file>]
                  [--osv-npm-input <file>] [--curl <path>] [--system-root <dir>]
                  [--indicators <file>] [--json]
       immune status [--store <path>] [--json]
       immune findings [--all] [--store <path>] [--json | --proto]
           every finding, in every state, as one protobuf message or the same as
           JSON; for a person the open ones, or every one with --all
       immune finding <id> [--store <path>] [--json | --proto]
           one finding whole: its words, evidence, journal entries and answer
       immune finding <id> expected --reason <text> [--days <n>] [--via app|agent]
                      [--store <path>] [--json]
       immune finding <id> seen [--reason <text>] [--via app|agent] [--store <path>] [--json]
       immune finding <id> reopen [--via app|agent] [--store <path>] [--json]
           expected and seen are the owner's answers: they hide the finding from him.
           reopen takes an answer back. --via says who gave it; without it, the command
           line. Answer a finding only after the owner has agreed in this conversation,
           having been told what it is and what the options are. Pass --via agent and
           the reason the owner agreed to. The app shows every answer given this way.
       immune servers [--store <path>] [--tailscale <path>]
       immune view [--store <path>] [--no-open] [--if-stale]
           writes every page and prints their paths, the summary first; with
           --if-stale, writes only when something they show changed since they were
           made, or they are an hour old, and prints the same paths
       immune owner [<name> retired|not-mine --reason <text> | <name> withdraw]
                    [--via app|agent] [--store <path>] [--tailscale <path>] [--json]
           retired and not-mine set a machine aside: it is no longer checked. --via says
           who gave it; without it, the command line. An agent gives one only after the
           owner has said so in this conversation, with --via agent and their reason.
       immune vulnerabilities [--store <path>] [--json]
           known vulnerabilities that affect packages the projects' lockfiles declare
       immune vulnerability <record id or CVE id> [--store <path>] [--json]
           the answer for one vulnerability in every project, with what it rests on
       immune project <path or checkout id> [--store <path>] [--json | --proto]
           what the store knows of one project: its facts, what was read and what was
           not, its findings; one protobuf message, or the same message as JSON
       immune program <path, name or id> [--store <path>] [--json | --proto]
           the same for one program installed on this Mac: an application, a Homebrew
           package or keg, a global npm package
       immune machine [<name or id>] [--store <path>] [--json | --proto]
           the same for this Mac, or for another machine the store knows; its parts
           one level deep
       immune rules [--store <path>] [--json]
           the shipped Sigma rules for macOS: which are evaluated on every program
           start, which in part, and which not, with the reason; whether they watch
           and how many times each matched in the last day and week
       immune rules --over-log [--system-root <dir>] [--json]
           evaluates the rules over the event log on disk now, without the store, and
           prints per rule that matched its level and count, never a command line
       immune matches [--after <place>] [--limit <n>] [--store <path>]
                      [--system-root <dir>] [--json | --proto]
           every rule match over the event log, of every level, each with the event
           it matched, command lines whole; what was read, lost and not evaluated; and
           the position to read on from; one protobuf message, or the same as JSON
       immune sample [--store <path>] [--sample-input <file>] [--json]
       immune watch [--store <path>] [--system-root <dir>] [--sample-input <file>]
                    [--sample-every <seconds>] [--events-every <seconds>]
                    [--alive-every <seconds>]
                    one JSON line per event: watching, read, sample, program_starts,
                    alive, problem; a problem's code and detail_text sit beside event, flat;
                    program starts are read every 10 seconds by default
                 exits 5 when another watcher has the store";

enum Cmd {
    Run(Box<Args>),
    Status(StatusArgs),
    Servers(ServersArgs),
    View(ViewArgs),
    Owner(OwnerArgs),
    Findings(FindingsArgs),
    Finding(FindingArgs),
    Watch(watch::WatchArgs),
    Sample(SampleArgs),
    Vulnerabilities(VulnerabilityArgs),
    Vulnerability(VulnerabilityArgs),
    Rules(RulesArgs),
    Project(project::ProjectArgs),
    Program(program::ProgramArgs),
    Machine(machine::MachineArgs),
    Matches(matches::MatchesArgs),
}

/// `immune rules`: the shipped rules with what the store says they did, or with `over_log` a
/// replay of the event log under that system root.
struct RulesArgs {
    store: PathBuf,
    json: bool,
    over_log: Option<PathBuf>,
}

/// `immune vulnerabilities`, and `immune vulnerability <id>` with the id.
struct VulnerabilityArgs {
    store: PathBuf,
    json: bool,
    id: Option<String>,
}

/// `immune findings`: every finding as the contract's message, in the form named; for a person
/// the open findings, or every one with `--all`.
struct FindingsArgs {
    store: PathBuf,
    form: Option<known::Form>,
    all: bool,
}

/// `immune finding <id>`: one finding with what it rests on, or the owner's answer to it.
struct FindingArgs {
    store: PathBuf,
    /// The answer's envelope as JSON: `--json` with an answer.
    json: bool,
    /// The form of the contract's message, when the finding is only read.
    form: Option<known::Form>,
    id: String,
    act: Option<findings::Act>,
    via: findings::Via,
}

/// How long an `expected` mark lasts unless the owner says otherwise.
const EXPECTED_DAYS: i64 = 30;

struct Args {
    store: PathBuf,
    /// The name of this machine in ids.
    machine: String,
    /// The one place to look for brew instead of the standard places and PATH.
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
    /// A saved copy of the threat catalogue to read instead of fetching it.
    threats_input: Option<PathBuf>,
    /// Saved archives of the vulnerability data to read instead of fetching them: crates.io's
    /// and npm's.
    osv_crates_input: Option<PathBuf>,
    osv_npm_input: Option<PathBuf>,
    /// The curl to fetch the catalogue and the vulnerability data with instead of the system's.
    curl: Option<PathBuf>,
    /// The folder that `/Library` and `/etc` are resolved under for watched places: `/`
    /// unless a test gives another.
    system_root: PathBuf,
    /// The list of indicators. `None`: `indicators.json` next to the store.
    indicators: Option<PathBuf>,
    /// Answer in the machine-readable envelope instead of the report line.
    json: bool,
}

/// `immune status`: what the last finished run left, read without writing anything.
struct StatusArgs {
    store: PathBuf,
    json: bool,
}

struct ServersArgs {
    store: PathBuf,
    home: PathBuf,
    tailscale: Option<PathBuf>,
}

/// `immune owner`: without a statement, lists those that stand. Making or withdrawing one
/// writes the sweep script again, so it needs what `immune servers` needs.
struct OwnerArgs {
    servers: ServersArgs,
    act: Option<(String, Act)>,
    /// Who makes or withdraws the statement: in the app, the owner's agent, or the command
    /// line when neither is named.
    via: findings::Via,
    json: bool,
}

enum Act {
    Say(&'static str, String),
    Withdraw,
}

struct ViewArgs {
    store: PathBuf,
    open: bool,
    /// Write only when the pages are not current (`--if-stale`).
    if_stale: bool,
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
            let (mut sessions_root, mut threats_input, mut curl) = (None, None, None);
            let (mut system_root, mut json, mut indicators) = (None, false, None);
            let (mut osv_crates_input, mut osv_npm_input) = (None, None);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--json" => json = true,
                    "--osv-crates-input" => osv_crates_input = Some(value(&mut it, &arg)?.into()),
                    "--osv-npm-input" => osv_npm_input = Some(value(&mut it, &arg)?.into()),
                    "--tailscale" => tailscale = Some(value(&mut it, &arg)?.into()),
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--machine-name" => machine = Some(value(&mut it, &arg)?),
                    "--brew" => brew = Some(value(&mut it, &arg)?.into()),
                    "--brew-input" => brew_input = Some(value(&mut it, &arg)?.into()),
                    "--servers-input" => servers_input = Some(value(&mut it, &arg)?.into()),
                    "--checkouts-root" => checkouts_root = Some(value(&mut it, &arg)?.into()),
                    "--sessions-root" => sessions_root = Some(value(&mut it, &arg)?.into()),
                    "--threats-input" => threats_input = Some(value(&mut it, &arg)?.into()),
                    "--curl" => curl = Some(value(&mut it, &arg)?.into()),
                    "--system-root" => system_root = Some(value(&mut it, &arg)?.into()),
                    "--indicators" => indicators = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            if machine.as_deref() == Some("") {
                return Err("--machine-name needs a name".to_string());
            }
            Ok(Cmd::Run(Box::new(Args {
                store: store.map_or_else(default_store, Ok)?,
                machine: machine.unwrap_or_else(machine_name),
                brew,
                brew_input,
                servers_input,
                checkouts_root,
                sessions_root,
                home: user_home()?,
                tailscale,
                threats_input,
                osv_crates_input,
                osv_npm_input,
                curl,
                system_root: system_root.unwrap_or_else(|| PathBuf::from("/")),
                indicators,
                json,
            })))
        }
        "status" => {
            let mut json = false;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--json" => json = true,
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            Ok(Cmd::Status(StatusArgs { store, json }))
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
            let (mut open, mut if_stale) = (true, false);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--no-open" => open = false,
                    "--if-stale" => if_stale = true,
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            Ok(Cmd::View(ViewArgs {
                store,
                open,
                if_stale,
            }))
        }
        "owner" => {
            let (mut tailscale, mut reason, mut words) = (None, None, Vec::new());
            let (mut via, mut json) = (None, false);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--tailscale" => tailscale = Some(value(&mut it, &arg)?.into()),
                    "--reason" => reason = Some(value(&mut it, &arg)?),
                    "--json" => json = true,
                    "--via" => via = Some(via_value(&mut it, &arg)?),
                    _ if arg.starts_with("--") => {
                        return Err(format!("unexpected argument: {arg}"));
                    }
                    _ => words.push(arg),
                }
            }
            let act = match (words.as_slice(), reason) {
                ([], None) if via.is_none() => None,
                ([], _) => {
                    return Err(
                        "--reason and --via go with a statement: <name> retired, not-mine or withdraw"
                            .to_string(),
                    );
                }
                ([name, verb], None) if verb == "withdraw" => Some((name.clone(), Act::Withdraw)),
                ([_, verb], Some(_)) if verb == "withdraw" => {
                    return Err("a withdrawal takes no reason".to_string());
                }
                ([name, verb], reason) => {
                    let said = match verb.as_str() {
                        "retired" => owner::RETIRED,
                        "not-mine" => owner::NOT_MINE,
                        other => {
                            return Err(format!(
                                "the owner can say retired or not-mine, or withdraw, not {other}"
                            ));
                        }
                    };
                    // Whoever gives it, and an agent above all, a statement says why.
                    let reason = reason.unwrap_or_default();
                    if reason.trim().is_empty() {
                        return Err("a statement needs a reason: --reason <text>".to_string());
                    }
                    Some((name.clone(), Act::Say(said, reason)))
                }
                _ => return Err("immune owner takes a name and what the owner says".to_string()),
            };
            Ok(Cmd::Owner(OwnerArgs {
                servers: ServersArgs {
                    store: store.map_or_else(default_store, Ok)?,
                    home: user_home()?,
                    tailscale,
                },
                act,
                via: via.unwrap_or(findings::Via::Command),
                json,
            }))
        }
        "findings" => {
            let (mut form, mut all) = (None, false);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--all" => all = true,
                    _ if known::take_form(&arg, &mut form)? => {}
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            Ok(Cmd::Findings(FindingsArgs { store, form, all }))
        }
        "finding" => {
            let (mut form, mut reason, mut days, mut words) = (None, None, None, Vec::new());
            let mut via = None;
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    _ if known::take_form(&arg, &mut form)? => {}
                    "--reason" => reason = Some(value(&mut it, &arg)?),
                    "--days" => days = Some(value(&mut it, &arg)?),
                    "--via" => via = Some(via_value(&mut it, &arg)?),
                    _ if arg.starts_with("--") => {
                        return Err(format!("unexpected argument: {arg}"));
                    }
                    _ => words.push(arg),
                }
            }
            // An agent answers only with the reason the owner agreed to, so that what was
            // quieted through it always says why.
            let blank = |r: &Option<String>| r.as_deref().is_none_or(|r| r.trim().is_empty());
            let answering = matches!(words.as_slice(), [_, v] if v == "expected" || v == "seen");
            if via == Some(findings::Via::Agent) && answering && blank(&reason) {
                return Err(
                    "an answer through an agent needs the reason the owner agreed to: --reason <text>"
                        .to_string(),
                );
            }
            let act = match (words.as_slice(), reason, days) {
                ([_], None, None) if via.is_none() => None,
                ([_], ..) => {
                    return Err(
                        "--reason, --days and --via go with an answer: expected, seen or reopen"
                            .to_string(),
                    );
                }
                ([_, verb], Some(reason), days) if verb == "expected" => {
                    if reason.trim().is_empty() {
                        return Err("expected needs a reason: --reason <text>".to_string());
                    }
                    let days = match days {
                        None => EXPECTED_DAYS,
                        Some(d) => d
                            .parse::<i64>()
                            .ok()
                            .filter(|d| (1..=3650).contains(d))
                            .ok_or("--days takes a number of days from 1 to 3650")?,
                    };
                    Some(findings::Act::Answer(findings::Answer::Expected {
                        reason,
                        days,
                    }))
                }
                ([_, verb], None, _) if verb == "expected" => {
                    return Err("expected needs a reason: --reason <text>".to_string());
                }
                ([_, verb], reason, None) if verb == "seen" => {
                    let reason = reason.filter(|r| !r.trim().is_empty());
                    Some(findings::Act::Answer(findings::Answer::Seen { reason }))
                }
                ([_, verb], ..) if verb == "seen" => {
                    return Err("seen takes no days".to_string());
                }
                ([_, verb], None, None) if verb == "reopen" => Some(findings::Act::Reopen),
                ([_, verb], ..) if verb == "reopen" => {
                    return Err("reopen takes no reason and no days".to_string());
                }
                ([_, verb], ..) => {
                    return Err(format!(
                        "the owner can answer expected or seen, or reopen, not {verb}"
                    ));
                }
                _ => {
                    return Err(
                        "immune finding takes an id, as in: immune finding f0123456789 seen"
                            .to_string(),
                    );
                }
            };
            // An answer prints the report's envelope, with --json; only reading a finding is a
            // command of the contract.
            if act.is_some() && form == Some(known::Form::Proto) {
                return Err(
                    "--proto is for reading a finding; an answer prints its envelope with --json"
                        .to_string(),
                );
            }
            Ok(Cmd::Finding(FindingArgs {
                store: store.map_or_else(default_store, Ok)?,
                json: form == Some(known::Form::Json),
                form,
                id: words[0].clone(),
                act,
                via: via.unwrap_or(findings::Via::Command),
            }))
        }
        "vulnerabilities" | "vulnerability" => {
            let (mut json, mut words) = (false, Vec::new());
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--json" => json = true,
                    _ if arg.starts_with("--") => {
                        return Err(format!("unexpected argument: {arg}"));
                    }
                    _ => words.push(arg),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            match (cmd.as_str(), words.as_slice()) {
                ("vulnerabilities", []) => Ok(Cmd::Vulnerabilities(VulnerabilityArgs {
                    store,
                    json,
                    id: None,
                })),
                ("vulnerability", [id]) => Ok(Cmd::Vulnerability(VulnerabilityArgs {
                    store,
                    json,
                    id: Some(id.clone()),
                })),
                ("vulnerability", _) => Err(
                    "immune vulnerability takes one record id or CVE id, as in: immune vulnerability CVE-2023-4863"
                        .to_string(),
                ),
                _ => Err("immune vulnerabilities takes no id; immune vulnerability <id> does".to_string()),
            }
        }
        "watch" => watch::parse(it).map(Cmd::Watch),
        "project" => project::parse(it).map(Cmd::Project),
        "program" => program::parse(it).map(Cmd::Program),
        "machine" => machine::parse(it).map(Cmd::Machine),
        "matches" => matches::parse(it).map(Cmd::Matches),
        "rules" => {
            let (mut json, mut over_log, mut system_root) = (false, false, None);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--json" => json = true,
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--over-log" => over_log = true,
                    "--system-root" => system_root = Some(value(&mut it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            if system_root.is_some() && !over_log {
                return Err("--system-root is for immune rules --over-log".to_string());
            }
            Ok(Cmd::Rules(RulesArgs {
                store: store.map_or_else(default_store, Ok)?,
                json,
                over_log: over_log.then(|| system_root.unwrap_or_else(|| PathBuf::from("/"))),
            }))
        }
        "sample" => {
            let (mut json, mut input) = (false, None);
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--store" => store = Some(value(&mut it, &arg)?.into()),
                    "--sample-input" => input = Some(value(&mut it, &arg)?.into()),
                    "--json" => json = true,
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
            }
            let store = store.map_or_else(default_store, Ok)?;
            Ok(Cmd::Sample(SampleArgs { store, json, input }))
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

/// The name this Mac gives itself on the local network, else its short host name.
fn machine_name() -> String {
    let asks: [(&str, &[&str]); 2] = [
        (tools::SCUTIL, &["--get", "LocalHostName"]),
        (tools::HOSTNAME, &["-s"]),
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

/// The value of `--via`: who gives an answer or a statement.
fn via_value(it: &mut impl Iterator<Item = String>, arg: &str) -> Result<findings::Via, String> {
    match value(it, arg)?.as_str() {
        "app" => Ok(findings::Via::App),
        "agent" => Ok(findings::Via::Agent),
        _ => Err("--via takes app or agent".to_string()),
    }
}

/// Misuse of the command line.
const EXIT_USAGE: u8 = 2;
/// The store is there and cannot be read.
const EXIT_STORE: u8 = 3;
/// Another run holds the store.
const EXIT_RUN_IN_PROGRESS: u8 = 4;

/// A failure an agent can act on, with its own code and exit code.
#[derive(Debug)]
enum Stop {
    /// The store cannot be opened or read, with what was said.
    Store(String),
    /// Another run holds the run lock.
    RunInProgress,
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Stop::Store(e) => write!(f, "the store cannot be read: {e}"),
            Stop::RunInProgress => {
                write!(
                    f,
                    "another run is in progress on this store; nothing was done"
                )
            }
        }
    }
}

impl Error for Stop {}

/// Prints one machine-readable envelope on stdout, the only thing on stdout in that form.
fn print_json(v: &serde_json::Value) {
    println!("{v}");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse_args(args.iter().cloned()) {
        Ok(cmd) => cmd,
        Err(e) => {
            // `immune watch` answers only in machine-readable lines.
            let op = args.first().map(String::as_str);
            if args.iter().any(|a| a == "--json") || op == Some("watch") {
                let op = op.filter(|o| {
                    [
                        "run",
                        "status",
                        "findings",
                        "finding",
                        "sample",
                        "watch",
                        "owner",
                        "vulnerabilities",
                        "vulnerability",
                        "rules",
                        "project",
                        "program",
                        "machine",
                        "matches",
                    ]
                    .contains(o)
                });
                let example = match op {
                    Some("rules") => "immune rules --json",
                    Some("run") => "immune run --json",
                    Some("vulnerabilities") => "immune vulnerabilities --json",
                    Some("vulnerability") => "immune vulnerability CVE-2023-4863 --json",
                    Some("findings") => "immune findings --json",
                    Some("finding") => "immune finding f0123456789 --json",
                    Some("watch") => "immune watch",
                    Some("sample") => "immune sample --json",
                    Some("owner") => "immune owner --json",
                    Some("project") => "immune project ~/<folder> --json",
                    Some("program") => "immune program /Applications/<name>.app --json",
                    Some("machine") => "immune machine --json",
                    Some("matches") => "immune matches --json",
                    _ => "immune status --json",
                };
                let v = status::failure(
                    op,
                    "usage",
                    "the command line is not one Immune understands; the usage is on stderr",
                    example,
                    &e,
                );
                // A command of the contract fails in its own envelope, which no reader
                // takes for an answer. `immune finding` is one when it only reads.
                let answering = args
                    .iter()
                    .skip(2)
                    .any(|a| ["expected", "seen", "reopen"].contains(&a.as_str()));
                match op {
                    Some("project" | "program" | "machine" | "matches" | "findings") => {
                        print_json(&known::envelope(v))
                    }
                    Some("finding") if !answering => print_json(&known::envelope(v)),
                    _ => print_json(&v),
                }
            }
            eprintln!("immune: {}\n{USAGE}", view::shown(&e));
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match cmd {
        Cmd::Run(args) if args.json => return run_json(&args),
        Cmd::Status(args) if args.json => return status_json(&args.store),
        Cmd::Watch(args) => return watch::watch(&args),
        Cmd::Run(args) => match run(&args) {
            Ok((line, watched)) => {
                say(&line);
                if !watched.is_empty() {
                    say("Watched places:");
                    print_table(&["Change", "Kind", "Path", "Why"], &watched);
                }
                Ok(())
            }
            // A second run used to fail with "database is locked"; it now says why.
            Err(e) if matches!(e.downcast_ref(), Some(Stop::RunInProgress)) => {
                eprintln!("immune: {e}");
                return ExitCode::from(EXIT_RUN_IN_PROGRESS);
            }
            Err(e) => Err(e),
        },
        Cmd::Status(args) => match status_text(&args.store) {
            Err(e) => {
                eprintln!("immune: {}", view::shown(&e.to_string()));
                return ExitCode::from(EXIT_STORE);
            }
            ok => ok.map_err(Into::into),
        },
        Cmd::Servers(args) => servers_cmd(&args),
        Cmd::View(args) => view(&args),
        Cmd::Owner(args) => return owner_cmd(&args),
        Cmd::Findings(args) => return findings_cmd(&args),
        Cmd::Finding(args) => return finding_cmd(&args),
        Cmd::Sample(args) => return sample_cmd(&args),
        Cmd::Vulnerabilities(args) | Cmd::Vulnerability(args) => {
            return vulnerabilities_cmd(&args);
        }
        Cmd::Rules(args) => return rules_cmd(&args),
        Cmd::Project(args) => return project::project_cmd(&args),
        Cmd::Program(args) => return program::program_cmd(&args),
        Cmd::Machine(args) => return machine::machine_cmd(&args),
        Cmd::Matches(args) => return matches::matches_cmd(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("immune: {}", view::shown(&e.to_string()));
            ExitCode::FAILURE
        }
    }
}

// ---- `immune sample`: one sample of this user's processes and connections, see
// `processes.rs`. ----

/// `immune sample`.
struct SampleArgs {
    store: PathBuf,
    json: bool,
    /// A reading made of invented processes instead of the system's.
    input: Option<PathBuf>,
}

/// Makes the store's folder, or says which folder could not be made: the error alone names
/// no path.
fn store_folder(folder: &Path) -> Result<(), String> {
    std::fs::create_dir_all(folder)
        .map_err(|e| format!("cannot make the store's folder {}: {e}", folder.display()))
}

/// Takes one sample under the run lock, records what the rule tracks and raises what it finds.
fn sample(args: &SampleArgs) -> Result<processes::Report, Box<dyn Error>> {
    let home = home(&args.store);
    store_folder(&home)?;
    let _lock = store::lock_run(&home)?.ok_or(Stop::RunInProgress)?;
    let (report, _) = sample_held(
        &args.store,
        args.input.as_deref(),
        &mut processes::Signers::default(),
    )?;
    Ok(report)
}

/// One sample, with the run lock held by the caller: of the system, or of the reading in
/// `input`. Returns its report and how many things need a look after it. `immune sample` and
/// the watcher both take their samples here.
pub fn sample_held(
    path: &Path,
    input: Option<&Path>,
    signers: &mut processes::Signers,
) -> Result<(processes::Report, usize), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let run_id = format!(
        "{}{}-{:09}",
        processes::RUN_PREFIX,
        now.as_secs(),
        now.subsec_nanos()
    );
    let mut conn = store::open(path).map_err(|e| Stop::Store(e.to_string()))?;
    let took = std::time::Instant::now();
    let reading = match input {
        Some(file) => processes::Reading::from_json(&std::fs::read_to_string(file)?)?,
        None => processes::read_system(now.as_secs() as i64),
    };
    let tx = conn.transaction()?;
    // The machine the readings of this Mac are scoped to, so the sample is of the same one.
    let machine =
        covered::this_machine(&tx)?.unwrap_or_else(|| format!("machine:{}", machine_name()));
    store::put_entity(&tx, &machine)?;
    let at = processes::At {
        run_id: &run_id,
        machine: &machine,
        home: &user_home()?,
        folder: &home(path),
    };
    let report = processes::take(&tx, &at, reading, took, signers)?;
    let needs = status::needs(&tx, report.sample.at)?.items.len();
    tx.commit()?;
    Ok((report, needs))
}

fn sample_cmd(args: &SampleArgs) -> ExitCode {
    match (sample(args), args.json) {
        (Ok(report), true) => print_json(&status::envelope("sample", report.json())),
        (Ok(report), false) => {
            say(&report.line());
            say(&format!(
                "A sample cannot see: {}.",
                processes::CANNOT_SEE.join("; ")
            ));
        }
        (Err(e), json) => {
            let stop = e.downcast_ref::<Stop>();
            if json {
                return match stop {
                    Some(stop) => fail_json("sample", stop),
                    None => {
                        print_json(&status::failure(
                            Some("sample"),
                            "sample_failed",
                            "the sample failed and nothing was committed to the store",
                            "immune sample --json",
                            &e.to_string(),
                        ));
                        ExitCode::FAILURE
                    }
                };
            }
            eprintln!("immune: {}", view::shown(&e.to_string()));
            return ExitCode::from(match stop {
                Some(Stop::RunInProgress) => EXIT_RUN_IN_PROGRESS,
                Some(Stop::Store(_)) => EXIT_STORE,
                None => 1,
            });
        }
    }
    ExitCode::SUCCESS
}

// ---- End of `immune sample`. ----

/// The event level at a full run: program starts as Apple's eslogger recorded them, judged by
/// the published rules, see `events.rs`. A reading that failed is coverage with its reason,
/// never a failed run. Returns how many findings the rules opened.
fn read_events(run: &mut Run, args: &Args) -> Result<usize, Box<dyn Error>> {
    let outcome = events::read(run.tx, run.run_id, run.machine, &args.system_root, run.at)?;
    if outcome.state != events::NOT_INSTALLED {
        run.readers += 1;
    }
    Ok(outcome.opened)
}

/// What one reading of the event level by the watcher came to: the program starts it took,
/// whether it changed the level's state, the level as it left it, and why it failed.
pub struct EventsRead {
    pub starts: i64,
    pub changed: bool,
    pub level: Option<events::Level>,
    pub failed: Option<String>,
    pub at: i64,
}

/// One reading of the event level, with the run lock held by the caller: what the watcher
/// does at every `--events-every`. It commits what it read, the state and the coverage, and
/// returns the reason when the reading failed, so that the watcher records the failure.
pub fn read_events_held(path: &Path, system_root: &Path) -> Result<EventsRead, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let at = now.as_secs() as i64;
    let run_id = format!(
        "{}{}-{:09}",
        events::RUN_PREFIX,
        now.as_secs(),
        now.subsec_nanos()
    );
    let mut conn = store::open(path).map_err(|e| Stop::Store(e.to_string()))?;
    let tx = conn.transaction()?;
    let machine =
        covered::this_machine(&tx)?.unwrap_or_else(|| format!("machine:{}", machine_name()));
    store::put_entity(&tx, &machine)?;
    let before = events::state(&tx)?;
    let outcome = events::read(&tx, &run_id, &machine, system_root, at)?;
    tx.commit()?;
    Ok(EventsRead {
        starts: outcome.starts,
        changed: before.as_deref() != Some(outcome.state),
        level: events::level(&conn, at)?,
        failed: outcome.failed,
        at,
    })
}

/// A published rule's finding for a person, from its `published_rule` detail: the rule with
/// its authors and licence, and the latest events it matched, program starts or, for a rule
/// about file events, files created or renamed. Every value is already text from a source
/// shown inert.
fn published_rule_lines(d: &serde_json::Value) -> Vec<String> {
    let s = |v: &serde_json::Value| v.as_str().unwrap_or("unknown").to_string();
    let files = d["events"] == sigma::FILE_CATEGORY;
    let mut lines = vec![format!(
        "Rule: {}, by {}; from {} under the {}, {}.",
        s(&d["title_text"]),
        s(&d["author_text"]),
        s(&d["source_name"]),
        s(&d["licence_name"]),
        s(&d["file"])
    )];
    let (one, many) = if files {
        ("file event", "file events")
    } else {
        ("program start", "program starts")
    };
    lines.push(format!(
        "It matched {} since this finding was raised; the latest:",
        things(d["matches"].as_i64().unwrap_or(0), one, many)
    ));
    for e in d["evidence"].as_array().into_iter().flatten() {
        if files {
            let how = match e["source_text"].as_str() {
                Some(from) => format!("renamed from {from}"),
                None => "created".to_string(),
            };
            lines.push(format!(
                "  {} {}: {how} by {}",
                s(&e["timestamp_text"]),
                s(&e["file_text"]),
                s(&e["executable_text"])
            ));
            continue;
        }
        let args: Vec<String> = e["args_text"]
            .as_array()
            .into_iter()
            .flatten()
            .map(s)
            .collect();
        lines.push(format!(
            "  {} {}: {} · started by {} · in {} · pid {} · signed {}",
            s(&e["timestamp_text"]),
            s(&e["executable_text"]),
            args.join(" "),
            s(&e["parent_executable_text"]),
            s(&e["working_directory_text"]),
            e["pid"],
            s(&e["signing_id_text"])
        ));
    }
    lines
}

// ---- `immune rules`: the published rules, what they did, and a replay over the log. ----

/// `immune rules`: the shipped rules, placed, with whether they watch and how many times each
/// matched, from the store read without writing. A store that is not there, or holds no
/// reading of the event level, gives no counts and says why in `not_computed`. With `--json` it
/// also carries the catalogue: the core's own rules and the causes of what is not covered, with
/// their words.
fn rules_cmd(args: &RulesArgs) -> ExitCode {
    if let Some(root) = &args.over_log {
        return replay_cmd(root, args.json);
    }
    let rules = sigma::Rules::shipped();
    let level = match read_level(&args.store) {
        Ok(level) => level,
        Err(e) => return store_failed(args.json, "rules", &e),
    };
    let section = status::rules_section(level.as_ref());
    if args.json {
        let mut v = rules.summary_json();
        for key in [
            "watching",
            "watching_rules",
            "file_events_collected",
            "not_watching",
            "judged",
            "judged_note",
            "matches_last_day",
        ] {
            v[key] = section[key].clone();
        }
        match &level {
            Some(l) => {
                v["matches_last_week"] =
                    serde_json::json!(l.matches_last_week.values().sum::<i64>());
                for key in ["evaluated", "in_part"] {
                    for r in v[key].as_array_mut().into_iter().flatten() {
                        let id = r["id_text"].as_str().unwrap_or_default().to_string();
                        r["matches_last_day"] =
                            serde_json::json!(l.matches_last_day.get(&id).unwrap_or(&0));
                        r["matches_last_week"] =
                            serde_json::json!(l.matches_last_week.get(&id).unwrap_or(&0));
                    }
                }
                v["not_computed"] = serde_json::json!([]);
            }
            None => {
                let reason = if args.store.exists() {
                    "program starts have not been looked for yet; the next check does"
                } else {
                    "there is no store yet; `immune run` makes it"
                };
                v["matches_last_day"] = serde_json::Value::Null;
                v["not_computed"] = serde_json::json!([{ "section": "matches", "reason": reason }]);
            }
        }
        // Every rule of the core's own and every cause of what is not covered, with its words, for
        // an agent to learn what each can say.
        v["catalogue"] = findings::catalogue_json();
        print_json(&status::envelope("rules", v));
        return ExitCode::SUCCESS;
    }
    // The sets the rules come from open both the summary and the status's sentence, which
    // says them once.
    let lines = rules.summary_lines(level.as_ref().map(|l| &l.matches_last_day));
    say(&crate::pages::rules_said(&section));
    lines.into_iter().skip(1).for_each(|l| say(&l));
    ExitCode::SUCCESS
}

/// The event level as the store holds it, read without writing; `None` when there is no store
/// or no reading of the level.
fn read_level(store: &Path) -> Result<Option<events::Level>, Stop> {
    if !store.exists() {
        return Ok(None);
    }
    let conn = store::open_read_only(store).map_err(|e| Stop::Store(e.to_string()))?;
    events::level(&conn, now_secs()).map_err(|e| Stop::Store(e.to_string()))
}

/// `immune rules --over-log`: the rules evaluated over the event log on disk now, from the start
/// of every file, the store neither read nor written. Per rule that matched, its level and how
/// many starts matched; never a command line, a path or an argument. A level that is not
/// installed is not applicable, not a failure.
fn replay_cmd(root: &Path, json: bool) -> ExitCode {
    let match_json = |h: &events::Hits| {
        serde_json::json!({
            "name": h.meta.name,
            "source": h.meta.source.name,
            "set": h.meta.source.set,
            "id_text": status::text(&h.meta.id),
            "title_text": status::text(&h.meta.title),
            "level": h.meta.level_name(),
            "status": h.meta.status.as_str(),
            "matches": h.count,
        })
    };
    match events::replay(root, now_secs()) {
        events::Replay::NotInstalled => {
            if json {
                print_json(&status::envelope(
                    "rules",
                    serde_json::json!({ "over_log": "not_applicable", "reason": "the event level is not installed" }),
                ));
            } else {
                say("The event level is not installed here, so there is no log to replay.");
            }
            ExitCode::SUCCESS
        }
        events::Replay::Failed(why) => {
            if json {
                print_json(&status::failure(
                    Some("rules"),
                    "log_unreadable",
                    "the event log could not be read, so nothing was evaluated",
                    "immune rules --over-log --json",
                    &why,
                ));
            } else {
                eprintln!(
                    "immune: the event log could not be read: {}",
                    view::shown(&why)
                );
            }
            ExitCode::FAILURE
        }
        events::Replay::Read {
            tally,
            file_tally,
            matched,
        } => {
            // From the most severe down, then by count; the rules of a set that states no level
            // after them as a group of their own, by count, never ranked among the levels.
            let mut hits: Vec<&events::Hits> = matched.rules.values().collect();
            hits.sort_by(|a, b| {
                (a.meta.level.is_none(), std::cmp::Reverse(a.meta.level))
                    .cmp(&(b.meta.level.is_none(), std::cmp::Reverse(b.meta.level)))
                    .then_with(|| b.count.cmp(&a.count))
                    .then_with(|| a.meta.id.cmp(&b.meta.id))
            });
            let total: i64 = hits.iter().map(|h| h.count).sum();
            if json {
                print_json(&status::envelope(
                    "rules",
                    serde_json::json!({
                        "over_log": "read",
                        "program_starts": tally.starts,
                        "unreadable_lines": tally.unreadable,
                        "lost": tally.lost,
                        "unknown_losses": tally.unknown_gaps,
                        "file_events": file_tally.files,
                        "file_events_lost": file_tally.lost,
                        "unreadable_file_events": file_tally.unreadable,
                        "matches_total": total,
                        "matched": hits.iter().map(|h| match_json(h)).collect::<Vec<_>>(),
                    }),
                ));
            } else {
                say(&format!(
                    "The event log on disk holds {} and {}; the rules matched {}. Nothing was stored.",
                    things(tally.starts, "program start", "program starts"),
                    things(file_tally.files, "file event", "file events"),
                    sigma::times(total)
                ));
                let no_level = hits.iter().filter(|h| h.meta.level.is_none()).count();
                for (i, h) in hits.iter().enumerate() {
                    // The group's heading, before its first rule: they come last.
                    if no_level > 0 && i == hits.len() - no_level {
                        say(&format!(
                            "  {}: {no_level}",
                            crate::pages::capital(sigma::NO_LEVEL_GROUP)
                        ));
                    }
                    say(&format!(
                        "  {:<15} {:>7}  {}",
                        sigma::level_said(h.meta.level),
                        h.count,
                        h.meta.label()
                    ));
                }
            }
            ExitCode::SUCCESS
        }
    }
}

// ---- End of `immune rules`. ----

/// Now, in UTC seconds.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// What `immune status` shows, read-only and in one read transaction, so that every number is of
/// one state of the store: a run that commits meanwhile waits for it, and it never sees half
/// a run. `None` when there is no store. `now` is the one moment the whole answer is of, so
/// that what the state counts up to and when the answer says it was made are the same second.
fn read_status(store: &Path, now: i64) -> Result<Option<status::State>, Stop> {
    if !store.exists() {
        return Ok(None);
    }
    let unreadable = |e: Box<dyn Error>| Stop::Store(e.to_string());
    let conn = store::open_read_only(store).map_err(unreadable)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Stop::Store(e.to_string()))?;
    status::state(&tx, &home(store), now)
        .map(Some)
        .map_err(unreadable)
}

/// Whether a run is in progress on the store, and what the store holds.
fn read_all(store: &Path, now: i64) -> Result<(bool, Option<status::State>), Stop> {
    let running = store::run_in_progress(&home(store)).map_err(|e| Stop::Store(e.to_string()))?;
    Ok((running, read_status(store, now)?))
}

/// Answers `immune status --json`, or `immune run --json` once the run finished.
fn answer_json(operation: &str, store: &Path) -> ExitCode {
    let now = now_secs();
    match read_all(store, now) {
        Ok((running, state)) => {
            let path = std::path::absolute(store).unwrap_or_else(|_| store.to_path_buf());
            let result = status::result(state.as_ref(), running, &path, now);
            print_json(&status::envelope(operation, result));
            ExitCode::SUCCESS
        }
        Err(e) => fail_json(operation, &e),
    }
}

fn fail_json(operation: &str, e: &Stop) -> ExitCode {
    let (v, exit) = failure_of(operation, e);
    print_json(&v);
    ExitCode::from(exit)
}

/// The failure envelope for a stop, and the exit code that goes with it.
fn failure_of(operation: &str, e: &Stop) -> (serde_json::Value, u8) {
    let (code, message, example, detail, exit) = match e {
        Stop::Store(detail) => (
            "store_unreadable",
            "the store cannot be read; nothing was changed",
            "immune status --json --store <file>",
            detail.as_str(),
            EXIT_STORE,
        ),
        Stop::RunInProgress => (
            "run_in_progress",
            "another run is in progress on this store; nothing was done",
            "immune status --json",
            "",
            EXIT_RUN_IN_PROGRESS,
        ),
    };
    (
        status::failure(Some(operation), code, message, example, detail),
        exit,
    )
}

fn status_json(store: &Path) -> ExitCode {
    answer_json("status", store)
}

/// `immune run --json`: the run, then the same answer as `immune status --json`, read back from the
/// store it committed, so the two cannot differ.
fn run_json(args: &Args) -> ExitCode {
    match run(args) {
        Ok(_) => answer_json("run", &args.store),
        Err(e) => match e.downcast_ref::<Stop>() {
            Some(stop) => fail_json("run", stop),
            None => {
                print_json(&status::failure(
                    Some("run"),
                    "run_failed",
                    "the run failed and nothing it read was committed to the store",
                    "immune run --json",
                    &e.to_string(),
                ));
                ExitCode::FAILURE
            }
        },
    }
}

/// What needs a look, the number the report line, the app and the page show, and the
/// newest of them.
fn needs_text(needs: &findings::Needs) {
    if needs.findings_unknown {
        say(&format!("Needs a look: not known yet, {NO_FINDINGS_YET}."));
        return;
    }
    say(&format!(
        "Needs a look: {}.",
        grouped(needs.items.len() as i64)
    ));
    let rows: Vec<Vec<String>> = needs
        .items
        .iter()
        .take(STATUS_ROWS)
        .map(|i| {
            vec![
                i.last_seen.map(view::utc).unwrap_or_default(),
                i.words.title.to_string(),
                i.place.clone().unwrap_or_default(),
                i.id.clone(),
            ]
        })
        .collect();
    if !rows.is_empty() {
        print_table(&["Last seen", "What", "Where", "Id"], &rows);
    }
    if needs.items.len() > rows.len() {
        say(&format!(
            "{} more; `immune status --json` lists them.",
            grouped((needs.items.len() - rows.len()) as i64)
        ));
    }
}

/// Whether this Mac is watched, and what, in the words of `this_mac`.
fn this_mac_text(m: &covered::ThisMac) {
    let state = match m.state {
        "watched" => "watched",
        "watched_in_part" => "watched in part",
        _ => "not checked yet",
    };
    let live = if m.live {
        "a watcher runs now".to_string()
    } else if !m.failed.is_empty() {
        format!(
            "a watcher runs, but its latest {} failed, so it does not watch live",
            covered::watcher_failed(m)
        )
    } else {
        "no watcher runs now".to_string()
    };
    say(&format!(
        "This Mac: {state}; {live}; last checked {}.",
        m.checked_at.map_or("never".to_string(), view::utc)
    ));
    let watched: Vec<String> = m
        .watched
        .iter()
        .map(|(what, n, how)| format!("{what}: {} ({how})", grouped(*n)))
        .collect();
    if !watched.is_empty() {
        say(&format!("Watched: {}.", watched.join(", ")));
    }
}

/// What is not covered, one line each, quiet: never a count of things to look at. What the
/// owner can fix comes first; then the limits of this version.
fn not_covered_text(list: &[covered::Uncovered]) {
    for (who, head) in [
        (covered::YOU, "You can fix"),
        (covered::NOTHING, "Limit of this version"),
    ] {
        for u in list.iter().filter(|u| u.cause.who == who) {
            let apart = u.apart();
            let also = if apart.is_empty() {
                String::new()
            } else {
                let shown: Vec<&str> = apart.into_iter().take(covered::EXAMPLES).collect();
                format!(" ({})", shown.join("; "))
            };
            say(&format!("{head}: {}{also}", u.title()));
        }
    }
}

/// `immune status`: a short summary of what `immune status --json` gives, for a person.
fn status_text(store: &Path) -> Result<(), Stop> {
    let (running, state) = read_all(store, now_secs())?;
    say(&format!("Store: {}.", store.display()));
    let Some(st) = state else {
        say("There is no store yet; `immune run` makes it.");
        return Ok(());
    };
    match &st.last {
        None => say("No run has started."),
        Some(l) => match l.finished_at {
            Some(at) => say(&format!(
                "Last run: started {}, finished {}.",
                view::utc(l.started_at),
                view::utc(at)
            )),
            None => say(&format!(
                "The latest run started {} and has not finished: {}.",
                view::utc(l.started_at),
                if running {
                    "it is running"
                } else {
                    "it died, and nothing it read is in the store"
                }
            )),
        },
    }
    let Some(s) = &st.summary else {
        say("No run has finished yet, so nothing is counted.");
        return Ok(());
    };
    if st.last.as_ref().is_some_and(|l| l.id != s.run.id) {
        say(&format!(
            "The numbers below are what the run that finished {} left.",
            view::utc(s.run.finished_at.unwrap_or(s.run.started_at))
        ));
    }
    say(&summary_sentences(s));
    this_mac_text(&st.this_mac);
    if let Some(l) = &st.event_level {
        say(&format!("Event level: {}", events::words(l).line()));
    }
    needs_text(&st.needs);
    not_covered_text(&st.not_covered);
    let p = &st.problems;
    let class = |c: &str| grouped(p.classes.get(c).copied().unwrap_or_default() as i64);
    say(&format!(
        "Coverage at the latest {}: {} full, {} failed, {} with no reader, {} where the source does not give it, {} with nothing to read, {} implied by {}.",
        things(p.readings as i64, "reading", "readings"),
        grouped(p.full as i64),
        class("failed"),
        class("no_reader"),
        class("not_given"),
        class("read_nothing"),
        grouped(p.implied as i64),
        things(
            p.unreached.len() as i64,
            "machine that could not be reached",
            "machines that could not be reached"
        )
    ));
    if !p.unreached.is_empty() {
        let rows: Vec<Vec<String>> = p
            .unreached
            .iter()
            .take(STATUS_ROWS)
            .map(|u| {
                vec![
                    u.scope.clone(),
                    view::utc(u.since),
                    u.reason.clone().unwrap_or_default(),
                ]
            })
            .collect();
        print_table(&["Not reached", "Since", "Why"], &rows);
    }
    // The same groups as `immune status --json`: one line for many readings with one reason.
    let groups: Vec<Vec<String>> = p
        .groups
        .iter()
        .filter(|g| g.class != "read_nothing")
        .take(STATUS_ROWS)
        .map(|g| {
            vec![
                g.class.replace('_', " "),
                g.reader.clone(),
                g.kind.clone(),
                g.scopes.len().to_string(),
                g.scopes[0].clone(),
                g.reason.clone().unwrap_or_default(),
            ]
        })
        .collect();
    if !groups.is_empty() {
        print_table(
            &["Class", "Reader", "What", "Readings", "For example", "Why"],
            &groups,
        );
    }
    let shown = p
        .groups
        .iter()
        .filter(|g| g.class != "read_nothing")
        .count();
    if shown > groups.len() {
        say(&format!(
            "{} more; `immune status --json` lists them.",
            things(
                (shown - groups.len()) as i64,
                "group of readings",
                "groups of readings"
            )
        ));
    }
    if let Some(list) = s.no_reader_for.as_ref().filter(|l| !l.is_empty()) {
        say("This build has no reader for:");
        let rows: Vec<Vec<String>> = list
            .iter()
            .take(STATUS_ROWS)
            .map(|n| {
                vec![
                    n.what.clone(),
                    n.name.clone().unwrap_or_default(),
                    n.places.to_string(),
                ]
            })
            .collect();
        print_table(&["What", "Which", "Places"], &rows);
    }
    let changes: Vec<Vec<String>> = s
        .changes
        .iter()
        .rev()
        .take(STATUS_ROWS)
        .map(|c| {
            vec![
                view::utc(c.at),
                c.change.to_string(),
                c.kind.clone(),
                c.path.clone(),
            ]
        })
        .collect();
    say(&format!(
        "Latest changes in watched places, newest first, {} of {}:",
        changes.len(),
        s.changes.len()
    ));
    print_table(&["When", "Change", "Kind", "Path"], &changes);
    say("All of it, with every list, is in `immune status --json`.");
    Ok(())
}

/// The most rows of a table `immune status` prints.
const STATUS_ROWS: usize = 10;

/// Prints one line. Text from a source never reaches the terminal raw: it could reorder or
/// hide the text around it.
fn say(line: &str) {
    println!("{}", view::shown(line));
}

/// The store's folder: raw input and the view live next to the store.
fn home(store: &Path) -> PathBuf {
    match store.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Writes the page next to the store, prints its path and opens it. Never writes to the store.
/// At most this many findings are listed by `immune findings`; the total is always given.
const FINDINGS_SHOWN: usize = 200;

/// Every finding in the store as it stands at `now`; `None` when there is no store or no run
/// of this build has looked for findings in it.
fn read_findings(store: &Path, now: i64) -> Result<Option<Vec<findings::Found>>, Stop> {
    if !store.exists() {
        return Ok(None);
    }
    let unreadable = |e: Box<dyn Error>| Stop::Store(e.to_string());
    let conn = store::open_read_only(store).map_err(unreadable)?;
    findings::all(&conn, now).map_err(|e| Stop::Store(e.to_string()))
}

/// A refusal in the form the command was asked in, with the exit code given.
fn refuse(json: bool, op: &str, code: &str, message: &str, example: &str, exit: u8) -> ExitCode {
    if json {
        print_json(&status::failure(Some(op), code, message, example, ""));
    } else {
        eprintln!("immune: {message}. {example}");
    }
    ExitCode::from(exit)
}

fn store_failed(json: bool, op: &str, e: &Stop) -> ExitCode {
    if json {
        return fail_json(op, e);
    }
    eprintln!("immune: {}", view::shown(&e.to_string()));
    ExitCode::from(EXIT_STORE)
}

const NO_FINDINGS_YET: &str = "no run of this build has looked for findings in this store yet";

/// `immune findings`: every finding as the contract's `Findings`; for a person the open
/// findings, or every one, with when each was last seen and where.
fn findings_cmd(args: &FindingsArgs) -> ExitCode {
    if let Some(form) = args.form {
        return known::command(
            "findings",
            &args.store,
            form == known::Form::Json,
            |conn, now| finding_answer::list(conn, now).map(Ok),
        );
    }
    let now = now_secs();
    let found = match read_findings(&args.store, now) {
        Ok(found) => found,
        Err(e) => return store_failed(false, "findings", &e),
    };
    let items: Option<Vec<findings::Item>> = found.map(|all| {
        let mut items: Vec<findings::Item> = all
            .iter()
            .filter(|f| args.all || f.state == "open")
            .filter_map(findings::item)
            .collect();
        findings::order(&mut items);
        items
    });
    let Some(items) = items else {
        say(&format!("No findings: {NO_FINDINGS_YET}."));
        return ExitCode::SUCCESS;
    };
    say(&format!(
        "{}.",
        things(
            items.len() as i64,
            if args.all { "finding" } else { "open finding" },
            if args.all {
                "findings"
            } else {
                "open findings"
            }
        )
    ));
    let rows: Vec<Vec<String>> = items
        .iter()
        .take(FINDINGS_SHOWN)
        .map(|i| {
            vec![
                i.id.clone(),
                i.state.clone(),
                i.last_seen.map(view::utc).unwrap_or_default(),
                i.words.title.to_string(),
                i.place.clone().unwrap_or_default(),
            ]
        })
        .collect();
    print_table(&["Id", "State", "Last seen", "What", "Where"], &rows);
    say("`immune finding <id>` shows one; expected and seen are the owner's answers.");
    ExitCode::SUCCESS
}

/// `immune vulnerabilities` and `immune vulnerability <id>`: the answers matching gave, read only.
fn vulnerabilities_cmd(args: &VulnerabilityArgs) -> ExitCode {
    let op = if args.id.is_some() {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let now = now_secs();
    if !args.store.exists() {
        if args.json {
            print_json(&status::envelope(
                op,
                serde_json::json!({ "not_computed": [{ "section": op, "reason": "there is no store yet; `immune run` makes it" }] }),
            ));
        } else {
            say("Nothing is known yet: there is no store; `immune run` makes it.");
        }
        return ExitCode::SUCCESS;
    }
    let read = (|| -> Result<serde_json::Value, Box<dyn Error>> {
        let conn = store::open_read_only(&args.store)?;
        Ok(match &args.id {
            Some(id) => vulnerabilities::one_json(&conn, id, now)?,
            None => vulnerabilities::list_json(&conn, now)?,
        })
    })();
    let r = match read {
        Ok(r) => r,
        Err(e) => return store_failed(args.json, op, &Stop::Store(e.to_string())),
    };
    if args.json {
        print_json(&status::envelope(op, r));
        return ExitCode::SUCCESS;
    }
    let s = |v: &serde_json::Value| view::shown(v.as_str().unwrap_or_default());
    match &args.id {
        None => {
            let t = &r["totals"];
            // Packages whose answer cannot be told are said in the first sentence, so that
            // nothing reads as calm where the data it needs was not read.
            say(&format!(
                "{} in packages your projects use; for {} whether one affects them cannot be told; {} known not to affect them.",
                things(
                    t["affected_records"].as_i64().unwrap_or_default(),
                    "known vulnerability",
                    "known vulnerabilities"
                ),
                things(
                    t["unknown_packages"].as_i64().unwrap_or_default(),
                    "package",
                    "packages"
                ),
                grouped(t["not_affected_known"].as_i64().unwrap_or_default()),
            ));
            for f in r["feeds"].as_array().into_iter().flatten() {
                if let Some(why) = f["not_current_why"].as_str() {
                    say(&format!(
                        "The {} data is not current: {why}.",
                        s(&f["ecosystem"])
                    ));
                }
            }
            let rows: Vec<Vec<String>> = r["affected"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| {
                    let releases: Vec<String> = a["releases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|x| format!("{} {}", s(&x["version_text"]), s(&x["at_text"])))
                        .collect();
                    let fixed: Vec<String> = a["fixed_text"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(s)
                        .collect();
                    vec![
                        s(&a["label"]),
                        format!("{} ({})", s(&a["record"]), s(&a["record_source"])),
                        format!("{} {}", s(&a["package_text"]), releases.join(", ")),
                        s(&a["project_text"]),
                        fixed.join(", "),
                    ]
                })
                .collect();
            if !rows.is_empty() {
                print_table(
                    &["Label", "Record", "Package", "Project", "Fixed in"],
                    &rows,
                );
            }
            let reasons: Vec<String> = t["unknown_by_reason"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, n)| format!("{k} {n}"))
                .collect();
            if !reasons.is_empty() {
                say(&format!(
                    "Cannot be told, by reason: {}.",
                    reasons.join(", ")
                ));
            }
            say(vulnerabilities::DECLARED);
        }
        Some(_) => {
            match r["data"].as_str() {
                Some("held") => {}
                _ => {
                    say(r["said"].as_str().unwrap_or_default());
                    return ExitCode::SUCCESS;
                }
            }
            for rec in r["records"].as_array().into_iter().flatten() {
                say(&format!(
                    "{} from {}, {}, modified {}:",
                    s(&rec["record"]),
                    s(&rec["record_source"]),
                    s(&rec["ecosystem"]),
                    s(&rec["modified"])
                ));
                if rec["answered"] == false {
                    say(&format!("  {}", s(&rec["said"])));
                    continue;
                }
                for a in rec["answers"].as_array().into_iter().flatten() {
                    let project = s(&a["project_text"]);
                    match a["packages"].as_array() {
                        Some(packages) => {
                            for p in packages {
                                say(&format!(
                                    "  {project}: {} {} ({})",
                                    s(&p["package_text"]),
                                    s(&p["answer"]),
                                    s(&p["detail_text"])
                                ));
                            }
                        }
                        None => say(&format!(
                            "  {project}: {}{}",
                            s(&a["answer"]),
                            a["reason"]
                                .as_str()
                                .map(|r| format!(", {r}"))
                                .unwrap_or_default()
                        )),
                    }
                }
            }
            say(vulnerabilities::DECLARED);
        }
    }
    ExitCode::SUCCESS
}

/// `immune finding <id>`: one finding with what it rests on, or the owner's answer to it.
fn finding_cmd(args: &FindingArgs) -> ExitCode {
    if let (None, Some(form)) = (&args.act, args.form) {
        return known::command(
            "finding",
            &args.store,
            form == known::Form::Json,
            |conn, now| finding_answer::one(conn, &args.id, now),
        );
    }
    let unknown = |json: bool| {
        refuse(
            json,
            "finding",
            "unknown_finding",
            "the store has no finding with this id; nothing was changed",
            "immune findings --all lists every finding with its id; then: immune finding <id> seen",
            EXIT_USAGE,
        )
    };
    let now = now_secs();
    if let Some(act) = &args.act {
        if !args.store.is_file() {
            return unknown(args.json);
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let run_id = format!("owner-{now}-{nanos:09}");
        let answered = (|| -> Result<(), Box<dyn Error>> {
            let mut conn = store::open(&args.store).map_err(|e| Stop::Store(e.to_string()))?;
            let tx = conn.transaction()?;
            match act {
                findings::Act::Answer(a) => {
                    findings::answer(&tx, &args.id, a, args.via, now, &run_id)?;
                }
                findings::Act::Reopen => findings::reopen(&tx, &args.id, args.via, now, &run_id)?,
            }
            tx.commit()?;
            Ok(())
        })();
        if let Err(e) = answered {
            return match e.downcast_ref::<findings::RefusedError>() {
                Some(findings::RefusedError(findings::Refused::Unknown)) => unknown(args.json),
                Some(refused @ findings::RefusedError(findings::Refused::NotAnswered(_))) => {
                    refuse(
                        args.json,
                        "finding",
                        "finding_not_answered",
                        &format!("{refused}; nothing was changed"),
                        "immune findings --all lists every finding with its state",
                        EXIT_USAGE,
                    )
                }
                Some(refused) => refuse(
                    args.json,
                    "finding",
                    "finding_closed",
                    &format!("{refused}; nothing was changed"),
                    "immune findings lists the open findings",
                    EXIT_USAGE,
                ),
                None => match e.downcast_ref::<Stop>() {
                    Some(stop) => store_failed(args.json, "finding", stop),
                    None => store_failed(args.json, "finding", &Stop::Store(e.to_string())),
                },
            };
        }
    }
    let found = match read_findings(&args.store, now) {
        Ok(found) => found.unwrap_or_default(),
        Err(e) => return store_failed(args.json, "finding", &e),
    };
    let Some(item) = found
        .iter()
        .find(|f| f.id == args.id)
        .and_then(findings::item)
    else {
        return unknown(args.json);
    };
    let basis = match store::open_read_only(&args.store)
        .map_err(|e| e.to_string())
        .and_then(|c| findings::basis(&c, &args.id).map_err(|e| e.to_string()))
    {
        Ok(b) => b,
        Err(e) => return store_failed(args.json, "finding", &Stop::Store(e)),
    };
    if args.json {
        let mut v = findings::item_json(&item);
        v["rests_on"] = serde_json::Value::Array(
            basis
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "journal_seq": b.seq,
                        "at": view::iso(b.at),
                        "run_id": b.run_id,
                        "entry": b.entry,
                        "predicate": b.predicate,
                        "subject_text": b.subject.as_deref().map(status::text),
                    })
                })
                .collect(),
        );
        let r = serde_json::json!({ "finding": v, "answers_note": findings::ANSWERS_NOTE });
        print_json(&status::envelope("finding", r));
        return ExitCode::SUCCESS;
    }
    say(&format!("Finding {}: {}", item.id, item.words.title));
    say(item.words.meaning);
    say(item.words.advice);
    let mut facts = vec![
        format!("rule {}", item.rule.unwrap_or_default()),
        format!("severity {}", item.severity),
        format!("confidence {}", item.confidence.unwrap_or_default()),
    ];
    if let Some(t) = item.technique {
        facts.push(format!("ATT&CK {t}"));
    }
    say(&format!("{}.", facts.join(", ")));
    say(&format!(
        "State: {}. First seen {}, last seen {}{}.",
        item.state,
        item.first_seen.map(view::utc).unwrap_or_default(),
        item.last_seen.map(view::utc).unwrap_or_default(),
        item.change
            .as_deref()
            .map(|c| format!(", latest change: {c}"))
            .unwrap_or_default()
    ));
    if let Some(a) = &item.answer {
        say(&format!(
            "Answered {} {}{}{}.",
            view::utc(a.at),
            view::given_by(a.via),
            a.until
                .map(|u| format!(", expected until {}", view::utc(u)))
                .unwrap_or_default(),
            a.reason
                .as_deref()
                .map(|r| format!(": {}", view::shown(r)))
                .unwrap_or_default()
        ));
    }
    say(&format!(
        "Where: {}.",
        view::shown(item.place.as_deref().unwrap_or_default())
    ));
    if let Some(d) = &item.detail {
        published_rule_lines(d).iter().for_each(|l| say(l));
    }
    let seqs: Vec<String> = basis.iter().map(|b| b.seq.to_string()).collect();
    say(&format!(
        "Rests on {}: {}.",
        things(basis.len() as i64, "journal entry", "journal entries"),
        seqs.join(", ")
    ));
    ExitCode::SUCCESS
}

fn view(args: &ViewArgs) -> Result<(), Box<dyn Error>> {
    if !args.store.is_file() {
        return Err(format!("no store at {}", args.store.display()).into());
    }
    let written = if args.if_stale {
        match current_view(&args.store, now_secs())? {
            Current::Yes(pages) => pages,
            Current::Events(pages) => write_event_pages(&args.store, pages)?,
            Current::No => write_view(&args.store)?,
        }
    } else {
        write_view(&args.store)?
    };
    for path in &written {
        println!("{}", path.display());
    }
    if args.open {
        let status = Command::new(tools::OPEN).arg(&written[0]).status()?;
        if !status.success() {
            return Err(format!("open failed, {status}").into());
        }
    }
    Ok(())
}

/// Writes every page of the view and returns their paths, the summary first: the path given
/// first is the page to open. Every link of the summary leads to a page written here.
fn write_view(store: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let now = now_secs();
    let folder = home(store);
    // Taken before the pages are read, so that they hold at least what it names.
    let (basis, events_basis) = {
        let conn = store::open_read_only(store)?;
        (view::basis(&conn, &folder)?, events::basis(&conn)?)
    };
    // The summary is built from what `immune status --json` answers, read the same way.
    let (running, state) = read_all(store, now)?;
    let state = state.ok_or("the store is gone")?;
    let absolute = std::path::absolute(store)?;
    let result = status::result(Some(&state), running, &absolute, now);
    let conn = store::open_read_only(store)?;
    let pages = view::pages(&conn, &state, &result, &store.display().to_string(), now)?;
    drop(conn);
    std::fs::create_dir_all(folder.join(view::DETAILS))?;
    let mut written = Vec::new();
    let mut names = Vec::new();
    for (rel, html) in pages {
        let path = std::path::absolute(folder.join(&rel))?;
        std::fs::write(&path, html)?;
        written.push(path);
        names.push(rel);
    }
    std::fs::write(folder.join(happens::SCRIPT_FILE), happens::SCRIPT)?;
    // Last, so that pages cut short by a failure are never named as current.
    let made = serde_json::json!({
        "basis": basis,
        "events": events_basis,
        "made_at": now,
        "pages": names,
    });
    std::fs::write(folder.join(view::MADE), made.to_string())?;
    Ok(written)
}

/// Writes again only the pages that show what the event level counts (`view::event_pages`),
/// when nothing else they rest on moved, and returns every page, the summary first.
fn write_event_pages(store: &Path, pages: Vec<PathBuf>) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let now = now_secs();
    let folder = home(store);
    let events_basis = events::basis(&store::open_read_only(store)?)?;
    let (running, state) = read_all(store, now)?;
    let state = state.ok_or("the store is gone")?;
    let absolute = std::path::absolute(store)?;
    let result = status::result(Some(&state), running, &absolute, now);
    let conn = store::open_read_only(store)?;
    let written = view::event_pages(&conn, &state, &result, now)?;
    drop(conn);
    for (rel, html) in written {
        std::fs::write(folder.join(rel), html)?;
    }
    let mut made: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(folder.join(view::MADE))?)?;
    made["events"] = events_basis.into();
    std::fs::write(folder.join(view::MADE), made.to_string())?;
    Ok(pages)
}

/// Whether the pages are current, see `current_view`.
enum Current {
    /// Current: every page, the summary first.
    Yes(Vec<PathBuf>),
    /// Current but for what the event level counts: the summary and the rules page are written
    /// again. Every page, the summary first.
    Events(Vec<PathBuf>),
    /// Every page must be written.
    No,
}

/// Whether the pages are current at `now`: every one is there, they are younger than
/// `view::CURRENT_FOR`, and their basis has not moved since they were made. When only the
/// event level's basis moved, the pages that show it are written again, not every page.
fn current_view(store: &Path, now: i64) -> Result<Current, Box<dyn Error>> {
    let folder = home(store);
    let Ok(text) = std::fs::read_to_string(folder.join(view::MADE)) else {
        return Ok(Current::No);
    };
    let made: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let (Some(basis), Some(at), Some(pages)) = (
        made["basis"].as_str(),
        made["made_at"].as_i64(),
        made["pages"].as_array(),
    ) else {
        return Ok(Current::No);
    };
    if !(at..at + view::CURRENT_FOR).contains(&now) {
        return Ok(Current::No);
    }
    let mut paths = Vec::new();
    for page in pages {
        let path = std::path::absolute(folder.join(page.as_str().unwrap_or_default()))?;
        if !path.is_file() {
            return Ok(Current::No);
        }
        paths.push(path);
    }
    let conn = store::open_read_only(store)?;
    if view::basis(&conn, &folder)? != basis {
        return Ok(Current::No);
    }
    if made["events"].as_str() != Some(events::basis(&conn)?.as_str()) {
        return Ok(Current::Events(paths));
    }
    Ok(Current::Yes(paths))
}

/// One server as `immune servers` lists it.
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

/// Where `immune servers` says a machine known only from its sweep file is known from.
const SWEEP_FILE: &str = "sweep file";

/// What `immune servers` finds: the servers, the devices that are not servers, the machines
/// the owner set aside, and the sweep to write.
struct Survey {
    dir: PathBuf,
    rows: Vec<ServerRow>,
    /// Other users' devices: the name and what else it is known as.
    theirs: Vec<Vec<String>>,
    /// The owner's other devices: the name, the system the tailnet gives and what else it is
    /// known as.
    own: Vec<Vec<String>>,
    /// Every statement that stands. Those not contradicted are not servers.
    standing: Vec<owner::Standing>,
    said: Vec<String>,
    third_party: usize,
    several_names: usize,
    /// Each machine the sweep visits, as its aliases.
    machines: Vec<Vec<String>>,
}

/// The owner's statements that stand, from the store if there is one.
fn owner_word(store: &Path) -> Result<Vec<owner::Standing>, Box<dyn Error>> {
    if !store.is_file() {
        return Ok(Vec::new());
    }
    let conn = store::open_read_only(store)?;
    Ok(owner::standing(&conn)?)
}

/// Whether the tailnet's name for a system is one the server check cannot read at all.
fn device(platform: Option<&str>) -> bool {
    tailnet::system(platform) == tailnet::System::Device
}

/// Finds the servers this machine knows from local files and the owner's word. Never writes
/// and never runs ssh.
fn survey(args: &ServersArgs) -> Result<Survey, Box<dyn Error>> {
    let dir = home(&args.store).join("sweep");
    let standing = owner_word(&args.store)?;
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
    // Entities a trace says are another user's device, and those it says are the owner's
    // own with a system the server check cannot read, with that system.
    let mut someone_elses: BTreeSet<String> = BTreeSet::new();
    let mut own_devices: BTreeMap<String, String> = BTreeMap::new();
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
            traces::Found::Guarded(folder) => said.push(format!(
                "{kind}: not read, it leads into {}, which macOS asks permission for",
                guarded::shown(folder, &args.home)
            )),
            traces::Found::Read(seen) => {
                let n = seen.hosts.len() as i64;
                let mut line = if *kind == tailnet::KIND {
                    format!("{kind}: {}", things(n, "peer", "peers"))
                } else {
                    format!("{kind}: {}", things(n, "server", "servers"))
                };
                let relation = |r: &'static str| {
                    seen.hosts
                        .iter()
                        .filter(move |h| h.relation.map(|x| x.0) == Some(r))
                };
                let theirs = relation(tailnet::OTHER_USER).count();
                if theirs > 0 {
                    line.push_str(&format!(", {theirs} of them other users' devices"));
                }
                let own = relation(tailnet::OWN)
                    .filter(|h| device(h.platform.as_ref().map(|p| p.0.as_str())))
                    .count();
                if own > 0 {
                    line.push_str(&format!(
                        ", {} of them phones, tablets or computers of yours",
                        own
                    ));
                }
                if *kind == tailnet::KIND {
                    let no_system = seen.hosts.iter().filter(|h| h.platform.is_none()).count();
                    if no_system > 0 {
                        line.push_str(&format!(
                            ", {no_system} whose system the tailnet does not give"
                        ));
                    }
                }
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
                    match (host.relation.map(|r| r.0), &host.platform) {
                        (Some(tailnet::OTHER_USER), _) => {
                            someone_elses.insert(id.clone());
                        }
                        (Some(tailnet::OWN), Some((p, _))) if device(Some(p)) => {
                            own_devices.insert(id.clone(), p.clone());
                        }
                        _ => {}
                    }
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
    // addresses it gives itself: the same machines `immune run` knows from these files.
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
                    let raw = input.file.as_ref().and_then(|f| f.raw.as_deref());
                    let text = String::from_utf8_lossy(raw.unwrap_or_default());
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
    // The owner's word covers a machine under every name: a group that holds any entity of
    // the machine the statement names. One that is not contradicted is set aside.
    let word_of = |group: &[String]| standing.iter().find(|s| group.iter().any(|m| s.covers(m)));
    let set_aside = |group: &Vec<String>| word_of(group).is_some_and(|s| s.seen.is_none());
    // Another user's device known from the tailnet alone is not a server. Known from any
    // other trace as well, it is one the owner uses as a server. `beyond.rs` tells them
    // apart the same way from the store.
    // The owner's own device whose system the server check cannot read is not a server
    // either, on the same condition.
    let tailnet_only = |m: &String| traces_of.get(m).is_some_and(|t| *t == [tailnet::KIND]);
    let (devices, groups): (Vec<Vec<String>>, Vec<Vec<String>>) =
        resolver::groups(traces_of.keys().cloned(), &pairs)
            .into_iter()
            .filter(|g| !set_aside(g))
            .partition(|g| {
                g.iter()
                    .all(|m| someone_elses.contains(m) && tailnet_only(m))
            });
    let (own, groups): (Vec<Vec<String>>, Vec<Vec<String>>) = groups.into_iter().partition(|g| {
        g.iter()
            .all(|m| own_devices.contains_key(m) && tailnet_only(m))
    });
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
        // A machine seen alive after the owner's word is a server again, and still not
        // visited: the owner said it is not theirs to visit.
        let word = word_of(group);
        let offered: Vec<String> = with_alias
            .iter()
            .filter(|a| word.is_none() && sweep::not_offered(a, &skip).is_none())
            .map(|a| a.to_string())
            .collect();
        let sweep = if let Some(w) = word {
            format!(
                "not offered: {}; seen alive after it: {}",
                w.summary(),
                w.contradiction().unwrap_or_default()
            )
        } else if let Some(first) = offered.first() {
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

    // Groups come sorted by their first member, which names the device.
    let theirs: Vec<Vec<String>> = devices
        .iter()
        .map(|group| {
            let name = group[0].strip_prefix("machine:").unwrap_or(&group[0]);
            let mut others: BTreeSet<&String> = group
                .iter()
                .flat_map(|m| names_of.get(m).into_iter().flatten())
                .collect();
            others.retain(|o| *o != name);
            let others: Vec<&str> = others.into_iter().map(String::as_str).collect();
            vec![name.to_string(), others.join(", ")]
        })
        .collect();
    let own: Vec<Vec<String>> = own
        .iter()
        .map(|group| {
            let name = group[0].strip_prefix("machine:").unwrap_or(&group[0]);
            let system = own_devices.get(&group[0]).cloned().unwrap_or_default();
            let mut others: BTreeSet<&String> = group
                .iter()
                .flat_map(|m| names_of.get(m).into_iter().flatten())
                .collect();
            others.retain(|o| *o != name);
            let others: Vec<&str> = others.into_iter().map(String::as_str).collect();
            vec![name.to_string(), system, others.join(", ")]
        })
        .collect();
    let machines: Vec<Vec<String>> = rows
        .iter()
        .filter(|r| !r.offered.is_empty())
        .map(|r| r.offered.clone())
        .collect();
    let several_names = groups.iter().filter(|g| g.len() > 1).count();
    Ok(Survey {
        dir,
        rows,
        theirs,
        own,
        standing,
        said,
        third_party,
        several_names,
        machines,
    })
}

/// Prints the servers this machine knows, and writes the probe and the sweep script next
/// to the store. Reads local files and the store; never writes to the store and never runs
/// ssh.
fn servers_cmd(args: &ServersArgs) -> Result<(), Box<dyn Error>> {
    let s = survey(args)?;
    let (offered, rest): (Vec<&ServerRow>, Vec<&ServerRow>) =
        s.rows.iter().partition(|r| !r.offered.is_empty());
    let table = |title: String, rows: &[&ServerRow]| {
        say(&title);
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
    let set_aside: Vec<&owner::Standing> = s.standing.iter().filter(|w| w.seen.is_none()).collect();
    if !set_aside.is_empty() {
        say(&format!(
            "Retired or disowned by the owner, not counted as servers: {}",
            things(set_aside.len() as i64, "machine", "machines")
        ));
        print_table(&WORD_HEAD, &word_rows(&set_aside));
        println!();
    }
    // Shown with a count, so that nothing the tailnet holds disappears silently.
    say(&format!(
        "Your other devices on the tailnet, not counted as servers: {}",
        things(s.own.len() as i64, "device", "devices")
    ));
    print_table(&["Device", "System", "Also known as"], &s.own);
    println!();
    say(&format!(
        "Other users' devices on the tailnet, not counted as servers: {}",
        things(s.theirs.len() as i64, "device", "devices")
    ));
    print_table(&["Device", "Also known as"], &s.theirs);
    println!();

    sweep::write(&s.dir, &s.machines)?;
    for line in &s.said {
        say(&format!("{}{}.", line[..1].to_uppercase(), &line[1..]));
    }
    say(&format!(
        "{} known, {} of them under several names, {} offered for the sweep, {} left out as code hosting, {} as your other devices, {} as other users' devices, {} known and never read.",
        things(s.rows.len() as i64, "server", "servers"),
        s.several_names,
        offered.len(),
        s.third_party,
        s.own.len(),
        s.theirs.len(),
        s.rows.iter().filter(|r| !r.read).count()
    ));
    if let Some(line) = word_line(&s.standing) {
        say(&line);
    }
    let spare: usize = s.machines.iter().map(|m| m.len() - 1).sum();
    if spare > 0 {
        say(&format!(
            "The sweep visits each offered server once, through one alias; {} not visited.",
            things(
                spare as i64,
                "alias of the same machine is",
                "aliases of the same machines are"
            )
        ));
    }
    say(&format!(
        "Wrote probe.sh and sweep.sh to {}. Nothing was run.",
        s.dir.display()
    ));
    say("To read the offered servers, run:");
    say(&format!("  sh {}", sweep::quoted(&s.dir.join("sweep.sh"))));
    say(
        "To say a server is retired or not yours, run `immune owner <name> retired --reason <text>`.",
    );
    say(&format!(
        "To visit only some of them again, such as those that failed, name their aliases: sh {} <alias>...",
        sweep::quoted(&s.dir.join("sweep.sh"))
    ));
    say(&format!(
        "To choose which alias the sweep uses, add the others to {}, one per line. Then run `immune run`.",
        s.dir.join(sweep::SKIP).display()
    ));
    Ok(())
}

/// The columns of a statement as `immune servers` and `immune owner` print it.
const WORD_HEAD: [&str; 5] = ["Machine", "Said", "Since", "Reason", "Also known as"];

fn word_rows(words: &[&owner::Standing]) -> Vec<Vec<String>> {
    words
        .iter()
        .map(|w| {
            vec![
                w.name().to_string(),
                w.word.said.clone(),
                view::utc(w.word.made_at),
                w.word.reason.clone(),
                w.names[1..].join(", "),
            ]
        })
        .collect()
}

/// How many machines the owner set aside, and which of them were seen alive after it.
fn word_line(standing: &[owner::Standing]) -> Option<String> {
    if standing.is_empty() {
        return None;
    }
    let seen: Vec<&str> = standing
        .iter()
        .filter(|s| s.seen.is_some())
        .map(|s| s.name())
        .collect();
    let mut line = format!(
        "The owner's word: {} retired or disowned",
        things(standing.len() as i64, "machine", "machines")
    );
    if !seen.is_empty() {
        line.push_str(&format!(
            "; seen alive after it and counted again: {}",
            seen.join(", ")
        ));
    }
    line.push('.');
    Some(line)
}

/// A statement in the machine-readable form. The machine's names are the owner's or a
/// source's text, so they are only in `_text` fields.
fn statement_json(s: &owner::Standing) -> serde_json::Value {
    serde_json::json!({
        "machine_text": status::text(s.name()),
        "entity_text": status::text(&s.word.entity),
        "said": s.word.said,
        "via": s.word.via.literal(),
        "at": view::iso(s.word.made_at),
        "reason_text": status::text(&s.word.reason),
        "names_text": s.names[1..].iter().map(|n| status::text(n)).collect::<Vec<_>>(),
        "seen_after": s.seen.as_ref().map(|e| serde_json::json!({
            "at": view::iso(e.at),
            "what_text": status::text(&e.what),
        })),
    })
}

/// Makes or withdraws a statement, or lists those that stand.
fn owner_cmd(args: &OwnerArgs) -> ExitCode {
    let refused = |code: &str, message: String, example: &str, exit: u8| {
        refuse(args.json, "owner", code, &message, example, exit)
    };
    let store_path = &args.servers.store;
    if !store_path.is_file() {
        return refused(
            "no_store",
            format!(
                "there is no store at {}; `immune run` makes it",
                store_path.display()
            ),
            "immune run --json",
            EXIT_STORE,
        );
    }
    let failed =
        |e: &dyn std::fmt::Display| store_failed(args.json, "owner", &Stop::Store(e.to_string()));
    let Some((name, act)) = &args.act else {
        let listed = store::open_read_only(store_path)
            .and_then(|conn| Ok((owner::standing(&conn)?, owner::withdrawn(&conn)?)));
        let (standing, withdrawn) = match listed {
            Ok(l) => l,
            Err(e) => return failed(&e),
        };
        if args.json {
            let r = serde_json::json!({
                "statements": standing.iter().map(statement_json).collect::<Vec<_>>(),
                "statements_total": standing.len(),
                "withdrawn": withdrawn,
            });
            print_json(&status::envelope("owner", r));
            return ExitCode::SUCCESS;
        }
        say(&format!(
            "The owner's word: {}.",
            things(
                standing.len() as i64,
                "statement stands",
                "statements stand"
            )
        ));
        let mut rows = word_rows(&standing.iter().collect::<Vec<_>>());
        for (row, s) in rows.iter_mut().zip(&standing) {
            row.push(
                s.contradiction()
                    .map_or("nothing".to_string(), |c| format!("contradicted: {c}")),
            );
        }
        let mut head = WORD_HEAD.to_vec();
        head.push("Seen alive after it");
        print_table(&head, &rows);
        if withdrawn > 0 {
            say(&format!(
                "{} withdrawn and kept.",
                things(withdrawn, "statement was", "statements were")
            ));
        }
        return ExitCode::SUCCESS;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let at = now.as_secs() as i64;
    let run_id = format!("owner-{}-{:09}", now.as_secs(), now.subsec_nanos());
    let mut conn = match store::open(store_path) {
        Ok(c) => c,
        Err(e) => return failed(&e),
    };
    let (entity, machine) = match owner::find(&conn, name) {
        Ok(owner::Found::One(entity, machine)) => (entity, machine),
        Ok(owner::Found::Unknown) => {
            return refused(
                "unknown_machine",
                format!(
                    "the store knows no machine as {}; nothing was said",
                    view::shown(name)
                ),
                "immune servers lists the machines the store knows",
                EXIT_USAGE,
            );
        }
        Ok(owner::Found::Several(groups)) => {
            let list: Vec<String> = groups
                .iter()
                .map(|g| {
                    let names: Vec<&str> = g.iter().map(|m| owner::bare(m)).collect();
                    names.join(" = ")
                })
                .collect();
            return refused(
                "several_machines",
                format!(
                    "{} fits {} machines that are not known to be one: {}. Name one of them; nothing was said",
                    view::shown(name),
                    list.len(),
                    view::shown(&list.join("; "))
                ),
                "immune owner <full machine id> retired --reason <text>",
                EXIT_USAGE,
            );
        }
        Err(e) => return failed(&e),
    };
    let names: Vec<&str> = machine.iter().map(|m| owner::bare(m)).collect();
    let mut lines = Vec::new();
    let mut r = serde_json::json!({
        "machine_text": status::text(owner::bare(&entity)),
        "names_text": names.iter().map(|n| status::text(n)).collect::<Vec<_>>(),
        "via": args.via.literal(),
    });
    match act {
        Act::Say(said, reason) => {
            let replaced = match owner::say(
                &mut conn, &entity, &machine, said, reason, args.via, at, &run_id,
            ) {
                Ok(n) => n,
                Err(e) => return failed(&e),
            };
            lines.push(format!(
                "Said: {} is {said}, {}: {reason}",
                owner::bare(&entity),
                view::utc(at)
            ));
            if replaced > 0 {
                lines.push(
                    "It replaces the statement that stood about the same machine, which is kept."
                        .to_string(),
                );
            }
            r["done"] = serde_json::json!("said");
            r["said"] = serde_json::json!(said);
            r["at"] = serde_json::json!(view::iso(at));
            r["reason_text"] = status::text(reason);
            r["replaced"] = serde_json::json!(replaced);
        }
        Act::Withdraw => {
            let withdrawn = match owner::withdraw(&mut conn, &machine, args.via, at, &run_id) {
                Ok(w) => w,
                Err(e) => return failed(&e),
            };
            if withdrawn.is_empty() {
                return refused(
                    "no_statement",
                    format!(
                        "no statement stands about {}; nothing was withdrawn",
                        view::shown(name)
                    ),
                    "immune owner --json lists the statements that stand",
                    EXIT_USAGE,
                );
            }
            for (entity, said) in &withdrawn {
                lines.push(format!(
                    "Withdrawn: the statement that {} is {said} no longer stands, and is kept.",
                    owner::bare(entity)
                ));
            }
            r["done"] = serde_json::json!("withdrawn");
            r["withdrawn"] = withdrawn
                .iter()
                .map(|(e, said)| {
                    serde_json::json!({ "machine_text": status::text(owner::bare(e)), "said": said })
                })
                .collect();
        }
    }
    lines.push(format!(
        "It covers the machine under every name: {}.",
        names.join(", ")
    ));
    drop(conn);
    match rewrite_sweep(&args.servers) {
        Ok(n) => {
            lines.push(format!(
                "The sweep script was written again: it visits {}.",
                things(n as i64, "server", "servers")
            ));
            r["sweep"] = serde_json::json!({ "servers": n });
        }
        Err(e) => {
            let problem = format!("the owner's word was kept, but {e}");
            if !args.json {
                for line in &lines {
                    say(line);
                }
                eprintln!("immune: {}", view::shown(&problem));
                return ExitCode::FAILURE;
            }
            r["sweep"] =
                serde_json::json!({ "servers": null, "problem_text": status::text(&problem) });
        }
    }
    if args.json {
        print_json(&status::envelope("owner", r));
    } else {
        for line in &lines {
            say(line);
        }
    }
    ExitCode::SUCCESS
}

/// Writes the sweep script again after the owner's word changed, the way `immune servers`
/// writes it, so that no script on disk visits a machine the owner set aside. A script that
/// cannot be written again is removed. Returns how many servers it visits.
fn rewrite_sweep(args: &ServersArgs) -> Result<usize, Box<dyn Error>> {
    let written = survey(args).and_then(|s| {
        sweep::write(&s.dir, &s.machines)?;
        Ok(s.machines.len())
    });
    written.map_err(|e| {
        let script = home(&args.store).join("sweep").join("sweep.sh");
        let _ = std::fs::remove_file(&script);
        let left = if script.exists() {
            format!("delete {} before you run it", script.display())
        } else {
            "no sweep script is left; run `immune servers`".to_string()
        };
        format!("the sweep script could not be written again ({e}); {left}").into()
    })
}

/// The sweep file of a server under any of its names: when it was taken, or that it is
/// incomplete, and when and why its latest visit failed. And whether it was read.
fn last_file(dir: &Path, names: &[&str]) -> (String, bool) {
    let (said, read) = last_reading(dir, names);
    match names.iter().find_map(|n| servers::failure(dir, n)) {
        Some(f) => (
            format!("{said}; {}", sweep::failed_visit(f.at, &f.reason)),
            read,
        ),
        None => (said, read),
    }
}

fn last_reading(dir: &Path, names: &[&str]) -> (String, bool) {
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

/// A plain text table with columns as wide as their widest cell, as the cells are shown.
fn print_table(head: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("  none");
        return;
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
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        println!("  {}", parts.join("  ").trim_end());
    };
    line(head.to_vec());
    for row in &rows {
        line(row.iter().map(String::as_str).collect());
    }
}

/// Runs every reader and returns the report line, and the watched places that changed or
/// could not be read, as change, kind, path and why.
fn run(args: &Args) -> Result<(String, Rows), Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let at = now.as_secs() as i64;
    let run_id = format!("{}-{:09}", now.as_secs(), now.subsec_nanos());

    // Raw input is kept next to the store so that the store can be rebuilt from it.
    let home = home(&args.store);
    store_folder(&home)?;
    // The vulnerability data and the threat catalogue are asked for before the run lock is
    // taken, so that a download of minutes holds up no watcher's reading and no status. What
    // is asked comes from the feeds' own readings only, read first from the store opened to
    // read. A second run stops here, at the lock on the downloads, and writes nothing.
    // A store this build cannot use is refused before anything is written next to it.
    let read_only = match args.store.exists() {
        true => Some(store::open_read_only(&args.store).map_err(|e| Stop::Store(e.to_string()))?),
        false => None,
    };
    let _fetching = osv::lock_fetch(&home)
        .map_err(|e| format!("cannot write in the store's folder {}: {e}", home.display()))?
        .ok_or(Stop::RunInProgress)?;
    let feeds = get_feeds(read_only.as_ref(), args, &home, at)?;
    let catalogue = get_catalogue(read_only.as_ref(), args)?;
    drop(read_only);
    // Held until the run returns: a second run stops here and writes nothing. A watcher's
    // reading, `immune watch`, is waited out.
    let _lock = store::lock_run_past_watcher(&home)?.ok_or(Stop::RunInProgress)?;
    let mut conn = store::open(&args.store).map_err(|e| Stop::Store(e.to_string()))?;
    store::journal_note(&conn, at, &run_id, "run_started", "")?;

    let tx = conn.transaction()?;
    // The store keeps this Mac's id; its name now is kept beside it.
    let machine = store::this_mac(&tx, &args.machine)?;
    store::put_entity(&tx, &machine)?;
    let mut run = Run {
        tx: &tx,
        home: &home,
        run_id: &run_id,
        at,
        machine: &machine,
        notes: Vec::new(),
        readers: 0,
    };
    read_brew(&mut run, args)?;
    let servers = args.servers_input.clone();
    read_servers(&mut run, servers.as_deref())?;
    let walked = read_checkouts(&mut run, args)?;
    let from_agents = read_agent_folders(&mut run, args)?;
    let any_checkouts = walked.is_some() || !from_agents.is_empty();
    // One checkout found by both readers is read once.
    let mut found = walked.unwrap_or_default();
    let known: BTreeSet<String> = found.iter().map(|c| c.rel.clone()).collect();
    found.extend(from_agents.into_iter().filter(|c| !known.contains(&c.rel)));
    if any_checkouts {
        read_lockfiles(&mut run, args, &found)?;
    }
    let (watched, mut opened) = watch_places(&mut run, args, &found)?;
    read_other_autoruns(&mut run, &args.home, &found)?;
    let mut changed = read_integrity(&mut run, args)?;
    changed.extend(read_indicators(&mut run, args, &found)?);
    opened += findings::detect(run.tx, run.run_id, run.at, &changed)?;
    opened += read_events(&mut run, args)?;
    read_traces(&mut run, args)?;
    resolve(&mut run)?;
    read_threats(&run, catalogue)?;
    read_feeds(&run, feeds)?;
    opened += match_dependencies(&run)?;

    // What the line counts is read back from what the run wrote, by the code `immune status`
    // reads it with after the run.
    let mark = status::RunMark {
        id: run_id.clone(),
        started_at: at,
        finished_at: None,
    };
    let summary = status::summary(&tx, mark, &home)?;
    // What needs a look is counted by the code `immune status` counts it with, at the run's time.
    let latest = view::latest_coverage(&tx)?;
    let problems = status::problems(&tx, &latest)?;
    let needs = findings::needs(&tx, at)?;
    // What is not covered is one clause, never a count of things to look at.
    let not_covered = covered::not_covered(&tx, &latest, &problems, summary.catalogue.as_ref())?;
    let mut said = needs_sentence(needs.items.len(), opened);
    if let Some(clause) = covered::clause(&not_covered) {
        said.push(' ');
        said.push_str(&clause);
    }
    let line = report(run.readers, &run.notes, &summary, &said);
    store::journal_note(&tx, at, &run_id, "report", &line)?;
    // The time the run finished, so that its start and its end are both in the journal.
    store::journal_note(&tx, now_secs(), &run_id, "run_finished", "")?;
    tx.commit()?;
    Ok((line, watched))
}

/// One run in progress: where it writes and what it has seen so far.
struct Run<'a> {
    tx: &'a rusqlite::Transaction<'a>,
    home: &'a Path,
    run_id: &'a str,
    at: i64,
    /// This machine's id.
    machine: &'a str,
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
        gap: &Gap,
        statements: &[Statement],
    ) -> rusqlite::Result<()> {
        let with_basis: Vec<(&str, &Statement)> = statements.iter().map(|s| (basis, s)).collect();
        self.apply_each(r, completeness, reason, gap, &with_basis)
    }

    /// The same, for statements that each have their own basis.
    fn apply_each(
        &mut self,
        r: &Reading,
        completeness: &str,
        reason: Option<&str>,
        gap: &Gap,
        statements: &[(&str, &Statement)],
    ) -> rusqlite::Result<()> {
        let reading = Applied {
            completeness,
            reason,
            gap,
            compared: completeness,
        };
        self.apply_judged(r, &reading, statements, &mut |_| Ok(Verdict::Change))?;
        Ok(())
    }

    /// The same, for a reading of where checkouts are: a checkout found is judged as
    /// `baseline::found_checkout` says, and one that is gone is a change.
    fn apply_found(
        &mut self,
        r: &Reading,
        basis: &str,
        completeness: &str,
        reason: Option<&str>,
        gap: &Gap,
        statements: &[Statement],
    ) -> rusqlite::Result<()> {
        let with_basis: Vec<(&str, &Statement)> = statements.iter().map(|s| (basis, s)).collect();
        let reading = Applied {
            completeness,
            reason,
            gap,
            compared: completeness,
        };
        let (tx, run_id) = (self.tx, r.run_id);
        let prefix = format!("checkout:{}/", self.machine);
        self.apply_judged(r, &reading, &with_basis, &mut |e| match (
            e.kind,
            e.subject.strip_prefix(&prefix),
        ) {
            ("added", Some(rel)) => baseline::found_checkout(tx, run_id, rel),
            _ => Ok(Verdict::Change),
        })?;
        Ok(())
    }

    /// The same, judging each difference before it is journaled (`baseline.rs`): one that is
    /// not a change is journaled as a first reading. Returns every difference with its verdict.
    fn apply_judged(
        &mut self,
        r: &Reading,
        a: &Applied,
        statements: &[(&str, &Statement)],
        judge: &mut dyn FnMut(&Event) -> rusqlite::Result<Verdict>,
    ) -> rusqlite::Result<Vec<(Event, Verdict)>> {
        if a.compared != "none" {
            for (basis, s) in statements {
                store::put_draft(self.tx, r, basis, s)?;
            }
        }
        store::put_coverage(self.tx, r, a.completeness, a.reason, a.gap)?;
        let mut out = Vec::new();
        for e in lifecycle::promote(self.tx, r, a.compared)? {
            let verdict = judge(&e)?;
            store::journal_event(self.tx, r, &e, verdict.text())?;
            out.push((e, verdict));
        }
        Ok(out)
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
    let mut met = Vec::new();
    match brew::read(args.brew_input.as_deref(), args.brew.as_deref(), &args.home) {
        // Not found, and PATH names a folder macOS asks permission for: what was known stays.
        brew::Found::NotLookedInto(folders) => {
            run.readers += 1;
            let shown: Vec<String> = folders
                .iter()
                .map(|g| guarded::shown(g, &args.home))
                .collect();
            let reason = format!(
                "{}Homebrew was not found elsewhere, and PATH names {}, which macOS asks permission for",
                guarded::NOT_LOOKED_INTO,
                shown.join(", ")
            );
            run.apply(
                &reading,
                brew::BASIS,
                "none",
                Some(&reason),
                &Gap::of(Cause::NotGiven),
                &[],
            )?;
            met = folders;
        }
        brew::Found::Output(raw) => {
            run.readers += 1;
            let raw_file = run.keep_raw(brew::READER, brew::RAW, raw.as_bytes())?;
            let (statements, partial) = brew::statements(&raw, &machine, &raw_file);
            let completeness = if partial.is_some() { "partial" } else { "full" };
            // A package Homebrew names no tap for: the source does not give what it is.
            let gap = Gap::when(partial.is_some().then_some(Cause::NotGiven));
            run.apply(
                &reading,
                brew::BASIS,
                completeness,
                partial.as_deref(),
                &gap,
                &statements,
            )?;
        }
        // Read in full: there is nothing, so what was there before is gone.
        brew::Found::NotInstalled => {
            run.apply(
                &reading,
                brew::BASIS,
                "full",
                Some(brew::NOT_INSTALLED),
                &Gap::default(),
                &[],
            )?;
            run.notes
                .push("Homebrew is not installed, nothing to read.".to_string());
        }
        brew::Found::Failed(reason) => {
            run.readers += 1;
            let gap = Gap::of(Cause::Failed);
            run.apply(&reading, brew::BASIS, "none", Some(&reason), &gap, &[])?;
            run.notes
                .push(format!("Homebrew could not be read: {reason}."));
        }
    }
    not_looked_into_when_met(run, brew::READER, &met, &args.home)?;
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
        let raw = input.file.as_ref().and_then(|f| f.raw.as_deref());
        let text = raw.map(String::from_utf8_lossy);
        let complete = text.as_deref().is_some_and(servers::complete);
        let file_at = text
            .as_deref()
            .and_then(servers::taken_at)
            .or(input.file.as_ref().map(|f| f.modified))
            .unwrap_or_default();
        let raw_file = match raw {
            Some(bytes) => Some(run.keep_raw(
                servers::READER,
                &format!("servers/{}.txt", input.name),
                bytes,
            )?),
            None => None,
        };
        // The visit goes first: the latest reading of the server is then what the probe
        // read, which the owner's word takes as a sign of life. A complete reading stands
        // whatever happened later; a failed visit is told beside it.
        let failed = input.failed.as_ref();
        let visit = match (failed, complete) {
            (Some(f), _) => servers::visit(&machine, Some(&f.reason)),
            (None, true) => servers::visit(&machine, None),
            (None, false) => servers::visit(&machine, Some(servers::NOT_COMPLETE)),
        };
        let (found, found_at) = match (&text, failed) {
            (Some(text), f) if complete || f.is_none() => (
                servers::readings(&machine, text, raw_file.as_deref().unwrap_or("")),
                file_at,
            ),
            (_, Some(f)) => (servers::visit_failed(&machine, &f.reason), f.at),
            (_, None) => (servers::unreadable(&machine), file_at),
        };
        let visit_at = failed.map_or(file_at, |f| f.at);
        let readings =
            std::iter::once((visit, visit_at)).chain(found.into_iter().map(|o| (o, found_at)));
        for (o, observed_at) in readings {
            store::put_entity(run.tx, &o.scope)?;
            let reading = Reading {
                reader: servers::READER,
                scope: &o.scope,
                kind: o.kind,
                run_id: &run_id,
                at: run.at,
                observed_at,
            };
            run.apply(
                &reading,
                servers::BASIS,
                o.completeness,
                o.reason.as_deref(),
                &o.gap,
                &o.statements,
            )?;
        }
        if let Some(f) = failed {
            let last = store::last_read(run.tx, servers::READER, &machine)?;
            run.notes.push(format!(
                "{} {}; {}",
                input.name,
                last.map_or("was never read".to_string(), |t| format!(
                    "was last read {}",
                    view::utc(t)
                )),
                sweep::failed_visit(f.at, &f.reason)
            ));
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
    let machine = run.machine.to_string();
    // A checkout the store holds in a folder the walk did not enter is not known to be gone,
    // nor is one still there in another form, as a link where its folder was: it is kept as
    // it was, and nothing inside it is read.
    let prefix = format!("checkout:{machine}/");
    let kept: Vec<String> = store::live_subjects(run.tx, checkouts::READER)?
        .into_iter()
        .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
        .filter(|rel| {
            let path = home.join(rel);
            walk.guarded.iter().any(|g| path.starts_with(g)) || checkouts::is_moved(&path)
        })
        .collect();
    let mut raw = String::new();
    for c in &walk.checkouts {
        raw.push_str(&format!("checkout\t{}\n", c.rel));
    }
    for rel in &kept {
        raw.push_str(&format!("kept, not looked into\t{rel}\n"));
    }
    for folder in &walk.unlisted {
        raw.push_str(&format!("not listed\t{folder}\n"));
    }
    let raw_file = run.keep_raw(checkouts::READER, "checkouts.txt", raw.as_bytes())?;
    let statements: Vec<Statement> = walk
        .checkouts
        .iter()
        .map(|c| &c.rel)
        .chain(&kept)
        .enumerate()
        .map(|(i, rel)| Statement {
            subject: format!("{prefix}{rel}"),
            predicate: "located_on",
            object: machine.clone(),
            source_ref: format!("{raw_file}:{}", i + 1),
        })
        .collect();
    not_looked_into(run, checkouts::READER, &walk.guarded, home)?;
    let unlisted = (!walk.unlisted.is_empty())
        .then(|| format!("could not be listed: {}", walk.unlisted.join(", ")));
    if let Some(unlisted) = &unlisted {
        run.notes.push(format!("Folders that {unlisted}."));
    }
    let given = args
        .checkouts_root
        .is_some()
        .then(|| checkouts::ONLY_GIVEN.to_string());
    // A folder that could not be listed failed; a walk limited to the folder given read
    // what it was given, which does not hold the rest of the home folder. The worse is the
    // reading's cause.
    let gap = Gap::when(Cause::worst(
        given
            .iter()
            .map(|_| Cause::NotGiven)
            .chain(unlisted.iter().map(|_| Cause::Failed)),
    ));
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
    run.apply_found(
        &reading,
        checkouts::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &statements,
    )?;
    // The folders the walk listed in full and those it found in them: a checkout found later
    // in a folder listed before is new (`baseline.rs`).
    baseline::record(
        run.tx,
        checkouts::READER,
        checkouts::KIND,
        &run_id,
        run.at,
        &walk.listed,
        &walk.seen,
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
    let home = std::fs::canonicalize(&args.home).unwrap_or_else(|_| args.home.clone());
    let homes = [args.home.as_path(), home.as_path()];
    let held = agent_folders::held(run.tx)?;
    let sessions = match agent_folders::sessions(&dir, &homes, &held, SystemTime::now()) {
        // Its sessions lead into a folder macOS asks permission for: not read, and what was
        // known from them stays as it was.
        agent_folders::Found::Guarded(folder) => {
            run.readers += 1;
            let reason = format!(
                "{}{}",
                guarded::NOT_LOOKED_INTO,
                guarded::leads_into(&folder, &args.home)
            );
            let gap = Gap::of(Cause::NotGiven);
            run.apply(
                &reading,
                agent_folders::BASIS,
                "none",
                Some(&reason),
                &gap,
                &[],
            )?;
            not_looked_into(run, agent_folders::READER, &[folder], &args.home)?;
            return Ok(Vec::new());
        }
        agent_folders::Found::Failed(reason) => {
            run.readers += 1;
            let gap = Gap::of(Cause::Failed);
            run.apply(
                &reading,
                agent_folders::BASIS,
                "none",
                Some(&reason),
                &gap,
                &[],
            )?;
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
    // Where each file was read up to, in the run's transaction: committed with the facts
    // derived from it or not at all.
    if let Some(s) = &sessions {
        agent_folders::keep(run.tx, &s.held)?;
    }
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut unknown = BTreeSet::new();
    // Folders macOS asks permission for are not looked into, as in the walk, whatever name
    // led to them: a working folder or a held checkout is made real without entering one.
    let mut guarded: BTreeSet<PathBuf> = sessions
        .iter()
        .flat_map(|s| s.guarded.iter().cloned())
        .collect();
    for folder in sessions.iter().flat_map(|s| &s.folders) {
        match agent_folders::checkout_of(folder, &home, &homes) {
            agent_folders::OnDisk::Checkout(path) => {
                found.insert(checkouts::rel(&home, &path), path);
            }
            agent_folders::OnDisk::Nothing => {}
            agent_folders::OnDisk::Unknown => {
                unknown.insert(folder.clone());
            }
            agent_folders::OnDisk::Guarded(g) => {
                guarded.insert(g);
            }
        }
    }
    let prefix = format!("checkout:{machine}/");
    let mut kept = 0;
    // Held checkouts in a guarded folder: kept as they were, nothing inside them read.
    let mut carried = BTreeSet::new();
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
        let there = match guarded::real(&path, &homes) {
            guarded::Real::Guarded(g) => {
                guarded.insert(g);
                carried.insert(rel.to_string());
                continue;
            }
            guarded::Real::At(real) => agent_folders::still_there(&real),
            guarded::Real::Failed(_) => agent_folders::still_there(&path),
        };
        match there {
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
    for rel in &carried {
        raw.push_str(&format!("kept, not looked into\t{rel}\n"));
    }
    let raw_file = run.keep_raw(agent_folders::READER, "agent-folders.txt", raw.as_bytes())?;
    let guarded: Vec<PathBuf> = guarded.into_iter().collect();
    not_looked_into(run, agent_folders::READER, &guarded, &args.home)?;
    let statements: Vec<Statement> = found
        .keys()
        .chain(&carried)
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
    // Every reason above is a session, a folder or a checkout that could not be read; a
    // session file that leads into a folder macOS asks permission for was not given.
    let failed = !reasons.is_empty();
    if let Some(s) = sessions.as_ref().filter(|s| !s.guarded.is_empty()) {
        let folders: Vec<String> = s
            .guarded
            .iter()
            .map(|g| guarded::leads_into(g, &args.home))
            .collect();
        reasons.push(format!(
            "session files not looked into: {}",
            folders.join("; ")
        ));
    }
    let cause = if failed {
        Cause::Failed
    } else {
        Cause::NotGiven
    };
    let (completeness, reason, gap) = match (reasons.is_empty(), &sessions) {
        (false, _) => ("partial", Some(reasons.join("; ")), Gap::of(cause)),
        (true, None) => (
            "full",
            Some(agent_folders::NOT_HERE.to_string()),
            Gap::default(),
        ),
        (true, Some(_)) => ("full", None, Gap::default()),
    };
    run.apply_found(
        &reading,
        agent_folders::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &statements,
    )?;
    Ok(found
        .into_iter()
        .map(|(rel, path)| checkouts::Checkout { rel, path })
        .collect())
}

/// `not_looked_into` for a reader that seldom meets a guarded folder: written when it did,
/// and once more when it no longer does, so that what the latest run did is what is said.
fn not_looked_into_when_met(
    run: &mut Run,
    reader: &'static str,
    folders: &[PathBuf],
    home: &Path,
) -> rusqlite::Result<()> {
    let held: bool = run.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM coverage c WHERE c.reader = ?1 AND c.kind = ?2
           AND c.id = (SELECT MAX(l.id) FROM coverage l WHERE l.reader = ?1 AND l.kind = ?2)
           AND c.completeness != 'full')",
        rusqlite::params![reader, guarded::KIND],
        |r| r.get(0),
    )?;
    if folders.is_empty() && !held {
        return Ok(());
    }
    not_looked_into(run, reader, folders, home)
}

/// The reading of what a reader did not look into because macOS would have asked the owner's
/// permission: none, with the folders named, or full when it entered none of them.
fn not_looked_into(
    run: &mut Run,
    reader: &'static str,
    folders: &[PathBuf],
    home: &Path,
) -> rusqlite::Result<()> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader,
        scope: &machine,
        kind: guarded::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    if folders.is_empty() {
        return run.apply(&reading, "observed", "full", None, &Gap::default(), &[]);
    }
    let shown: Vec<String> = folders.iter().map(|g| guarded::shown(g, home)).collect();
    let reason = format!("{}{}", guarded::NOT_LOOKED_INTO, shown.join(", "));
    run.apply(
        &reading,
        "observed",
        "none",
        Some(&reason),
        &Gap::of(Cause::NotGiven),
        &[],
    )
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
        let found_guarded = match &found {
            traces::Found::Read(seen) => seen.guarded.clone(),
            _ => Vec::new(),
        };
        match found {
            // Read in full: there is nothing, so what was there before is gone.
            traces::Found::Absent(note) => {
                run.apply(&reading, basis, "full", Some(note), &Gap::default(), &[])?
            }
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
                    &seen.gap,
                    &statements,
                )?;
            }
            traces::Found::Failed(reason) => {
                run.readers += 1;
                let gap = Gap::of(Cause::Failed);
                run.apply(&reading, basis, "none", Some(&reason), &gap, &[])?;
                run.notes
                    .push(format!("The {kind} could not be read: {reason}."));
            }
            // Its file leads into a folder macOS asks permission for: not read, and what was
            // known from it stays as it was.
            traces::Found::Guarded(folder) => {
                let reason = format!(
                    "{}{}",
                    guarded::NOT_LOOKED_INTO,
                    guarded::shown(&folder, &args.home)
                );
                let gap = Gap::of(Cause::NotGiven);
                run.apply(&reading, basis, "none", Some(&reason), &gap, &[])?;
                not_looked_into(run, reader, &[folder], &args.home)?;
                continue;
            }
        }
        not_looked_into_when_met(run, reader, &found_guarded, &args.home)?;
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
    run.apply_each(&reading, "full", None, &Gap::default(), &refs)?;
    Ok(())
}

/// Servers in the store, each counted once however many names it has, and the other devices
/// beside them: `beyond.rs` tells them apart. A machine the owner retired or disowned is
/// neither, unless it was seen alive after the statement.
struct ServerCounts {
    known: usize,
    offered: usize,
    read: usize,
    /// Servers the latest server check has a visit of, and of them those it read.
    in_last_check: usize,
    checked_in_last_check: usize,
    /// The owner's own phones, tablets and computers in the private network.
    own_devices: usize,
    /// Other people's computers and phones seen in the private network.
    other_devices: usize,
    /// Servers known only from the private network, which gives no system for them.
    system_not_given: usize,
    /// Machines under a statement of the owner's that stands.
    set_aside: usize,
    /// Those of them seen alive after the statement.
    seen: Vec<String>,
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
    // The latest visit of each server, and whether it read the server.
    let visits: BTreeMap<String, bool> = conn
        .prepare(
            "SELECT scope, completeness = 'full' FROM coverage
             WHERE reader = ?1 AND kind = ?2
               AND id IN (SELECT MAX(id) FROM coverage WHERE reader = ?1 AND kind = ?2
                          GROUP BY scope)",
        )?
        .query_map([servers::READER, servers::VISIT], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let standing = owner::standing(conn)?;
    let beyond = beyond::split(conn, machine)?;
    let mut counts = ServerCounts {
        known: beyond.servers.len(),
        offered: 0,
        read: 0,
        in_last_check: 0,
        checked_in_last_check: 0,
        own_devices: beyond.own_devices.len(),
        other_devices: beyond.other_devices.len(),
        system_not_given: beyond.system_not_given,
        set_aside: standing.len(),
        seen: standing
            .iter()
            .filter(|s| s.seen.is_some())
            .map(|s| s.name().to_string())
            .collect(),
    };
    for group in &beyond.servers {
        let word = standing.iter().find(|s| group.iter().any(|m| s.covers(m)));
        counts.offered += usize::from(word.is_none() && group.iter().any(offered));
        counts.read += usize::from(group.iter().any(|m| read.contains(m)));
        let visited: Vec<bool> = group
            .iter()
            .filter_map(|m| visits.get(m).copied())
            .collect();
        counts.in_last_check += usize::from(!visited.is_empty());
        counts.checked_in_last_check += usize::from(visited.contains(&true));
    }
    Ok(counts)
}

fn read_lockfiles(
    run: &mut Run,
    args: &Args,
    found: &[checkouts::Checkout],
) -> Result<(), Box<dyn Error>> {
    run.readers += 1;
    let run_id = run.run_id.to_string();
    let real_home = std::fs::canonicalize(&args.home).unwrap_or_else(|_| args.home.clone());
    let homes = [args.home.as_path(), real_home.as_path()];
    // A git folder in a folder macOS asks permission for is not entered: the commit is not
    // known, and the folder is named.
    let mut guarded = BTreeSet::new();
    // Lockfiles are under version control: the raw input is where they are and at which commit.
    let mut manifest = String::new();
    for checkout in found {
        let id = format!("checkout:{}/{}", run.machine, checkout.rel);
        let Some(o) = lockfiles::read(checkout, &id) else {
            continue;
        };
        let commit = lockfiles::commit(&checkout.path, &homes).unwrap_or_else(|g| {
            guarded.insert(g);
            "unknown".to_string()
        });
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
            &o.gap,
            &o.statements,
        )?;
    }
    let guarded: Vec<PathBuf> = guarded.into_iter().collect();
    not_looked_into_when_met(run, lockfiles::READER, &guarded, &args.home)?;
    let dir = run.home.join("raw").join(&run_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("lockfiles.txt"), manifest)?;
    Ok(())
}

/// How one reading is written: its coverage, and how its statements are compared with what is
/// live. A reading of which entries are there is compared as a whole reading even when some of
/// its units could not be read, since what it knew of those is made again (`kept`): what is
/// gone from a unit read in full is then gone.
struct Applied<'a> {
    completeness: &'a str,
    reason: Option<&'a str>,
    gap: &'a Gap,
    compared: &'a str,
}

/// Rows of a table as the run prints it after the report line.
type Rows = Vec<Vec<String>>;

/// One reading of which entries a kind of place holds in one scope.
struct Placed {
    scope: String,
    watched_as: &'static str,
    kind: String,
    look: watched::Look,
    /// Why the checkout's hooks were not looked at where they were: its `.git` is a file, or
    /// the checkout itself is no longer a folder there.
    elsewhere: Option<String>,
    /// The completeness and reason the reading says, where its reader gives them.
    coverage: Option<(&'static str, Option<String>)>,
    /// What the reading held about checkouts it did not look into, made again as it was.
    kept: Vec<Statement>,
    /// The checkouts it looks into, by their paths as ids name them: the one whose hooks it
    /// reads, or every checkout for a reading over checkouts.
    checkouts: Vec<String>,
}

/// A reading of this machine over its checkouts speaks only for the checkouts it looked into.
/// What the store holds about the others, in a folder macOS asks permission for, outside the
/// folder a run was pointed at, or not checked, is kept as it was: read as gone by one
/// reading, it would be read as new by the next, a finding about every project there.
struct Visited {
    /// The checkouts the store holds on this machine, by their path as ids name them.
    held: BTreeSet<String>,
    /// The checkouts the reading looked into.
    looked: BTreeSet<String>,
    /// Whether checkouts were ever looked for on this machine, by this run or before it.
    looked_for: bool,
}

impl Visited {
    fn of(
        tx: &rusqlite::Transaction,
        machine: &str,
        looked: &[checkouts::Checkout],
    ) -> rusqlite::Result<Visited> {
        let prefix = format!("checkout:{machine}/");
        let held = tx
            .prepare(
                "SELECT DISTINCT subject FROM assertion
                 WHERE layer = 'live' AND predicate = 'located_on'
                   AND substr(subject, 1, length(?1)) = ?1",
            )?
            .query_map([&prefix], |r| r.get::<_, String>(0))?
            .map(|id| id.map(|id| id[prefix.len()..].to_string()))
            .collect::<rusqlite::Result<_>>()?;
        let looked_for = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM coverage WHERE scope = ?1 AND reader IN (?2, ?3))",
            rusqlite::params![machine, checkouts::READER, agent_folders::READER],
            |r| r.get(0),
        )?;
        Ok(Visited {
            held,
            looked: looked.iter().map(|c| c.rel.clone()).collect(),
            looked_for,
        })
    }

    /// Whether a file, by its path as ids name it, is in a checkout the reading did not look
    /// into: the deepest checkout whose folder holds it.
    fn unvisited(&self, path: &str) -> bool {
        self.held
            .iter()
            .chain(&self.looked)
            .filter(|rel| {
                path.strip_prefix(rel.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            })
            .max_by_key(|rel| rel.len())
            .is_some_and(|rel| !self.looked.contains(rel))
    }
}

/// The entries a reading holds live about files whose paths, as ids name them, `keep` says
/// were not read now: the statements to make again, with what they rested on.
fn kept(
    tx: &rusqlite::Transaction,
    r: &Reading,
    keep: impl Fn(&str) -> bool,
) -> rusqlite::Result<Vec<Statement>> {
    let prefix = format!("file:{}/", r.scope);
    let machine_prefix = r
        .scope
        .split_once('/')
        .map(|(machine, _)| machine.strip_prefix("checkout:").unwrap_or(machine))
        .map(|machine| format!("file:{machine}/"));
    let mut kept = Vec::new();
    let mut stmt = tx.prepare(
        "SELECT subject, predicate, object, source_ref FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![r.reader, r.scope, r.kind], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    for row in rows {
        let (subject, predicate, object, source_ref): (String, String, String, String) = row?;
        let predicate = match predicate.as_str() {
            "watched_as" => "watched_as",
            "located_on" => "located_on",
            _ => continue,
        };
        let path = subject.strip_prefix(&prefix).or_else(|| {
            machine_prefix
                .as_deref()
                .and_then(|m| subject.strip_prefix(m))
        });
        if path.is_some_and(&keep) {
            kept.push(Statement {
                subject,
                predicate,
                object,
                source_ref,
            });
        }
    }
    Ok(kept)
}

/// Reads the watched places, moves what they hold through the lifecycle and raises what the
/// rules find, all in the run's transaction. `immune run` calls it among the other readers; a
/// small run of the watched places alone calls it with nothing else. Returns the rows printed
/// under the report line and how many findings it opened.
fn watch_places(
    run: &mut Run,
    args: &Args,
    checkouts: &[checkouts::Checkout],
) -> Result<(Rows, usize), Box<dyn Error>> {
    let (rows, seen) = read_watched(run, args, checkouts)?;
    let mut opened = findings::detect(run.tx, run.run_id, run.at, &seen)?;
    opened += usize::from(findings::first_read(
        run.tx,
        run.run_id,
        run.at,
        run.machine,
    )?);
    Ok((rows, opened))
}

/// Reads the watched places of this machine and the hooks of every checkout the run holds.
/// Which entries a place holds is one reading per kind and scope; the content of each file is
/// a reading of its own, scoped to the file, so a file that cannot be read changes nothing
/// about it and nothing else. Each difference is judged by `baseline.rs`: a change, the
/// baseline, or read for the first time. Returns the rows the run prints after its line:
/// change, kind, path and why, where paths are text from the machine; and what changed, for
/// the rules. What the line counts is read back from the store by `status::summary`.
fn read_watched(
    run: &mut Run,
    args: &Args,
    checkouts: &[checkouts::Checkout],
) -> Result<(Rows, Vec<findings::Observed>), Box<dyn Error>> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let mut rows: Rows = Vec::new();
    let mut seen = Vec::new();
    let mut observe = |change: &'static str, place: &str, file: &str| {
        seen.push(findings::Observed {
            change,
            place: place.to_string(),
            file: file.to_string(),
        });
    };
    let roots = watched::Roots {
        home: &args.home,
        system: &args.system_root,
    };
    let rels: Vec<String> = checkouts.iter().map(|c| c.rel.clone()).collect();
    let mut placed = Vec::new();
    for (watched_as, kind) in watched::kinds() {
        if kind == watched::HOOK_KIND {
            continue;
        }
        placed.push(Placed {
            scope: machine.clone(),
            watched_as,
            kind: kind.to_string(),
            look: watched::look_machine(&roots, kind),
            elsewhere: None,
            coverage: None,
            kept: Vec::new(),
            checkouts: Vec::new(),
        });
    }
    for c in checkouts {
        let scope = format!("checkout:{machine}/{}", c.rel);
        let (look, elsewhere) = match watched::look_checkout(&c.path, &c.rel, &args.home) {
            watched::Hooks::GitFile => (
                watched::Look::default(),
                Some(watched::GIT_FILE.to_string()),
            ),
            watched::Hooks::Looked(look) => (look, None),
        };
        // Every checkout is read, those with no hooks too: the first hook planted in a
        // checkout the store already held is then new, not the baseline. Hooks kept elsewhere
        // were not looked at.
        placed.push(Placed {
            scope,
            watched_as: watched::HOOK,
            kind: watched::HOOK_KIND.to_string(),
            look,
            elsewhere,
            coverage: None,
            kept: Vec::new(),
            checkouts: vec![c.rel.clone()],
        });
    }
    // A checkout the store holds that is still there in another form, as a link where its
    // folder was: it is not gone, and its hooks are not looked at through the link.
    for rel in checkouts::moved(run.tx, &machine, &args.home, &rels)? {
        let why = format!("{rel} {}", checkouts::MOVED);
        placed.push(Placed {
            scope: format!("checkout:{machine}/{rel}"),
            watched_as: watched::HOOK,
            kind: watched::HOOK_KIND.to_string(),
            look: watched::Look::default(),
            elsewhere: Some(why),
            coverage: None,
            kept: Vec::new(),
            checkouts: vec![rel],
        });
    }
    // Each way code runs by itself that is read here, in every checkout or in the home
    // folder, as one reading of this machine. Before checkouts were ever looked for on this
    // machine a reading over them would look into none and say that it read every checkout,
    // so it is not made then; and what is held about a checkout not looked into is kept as
    // it was.
    let visited = Visited::of(run.tx, &machine, checkouts)?;
    for point in autorun::POINTS.iter().filter(|p| p.read_here()) {
        let (looked, kept, over) = match point.scope {
            autorun::Scope::Home => (
                autorun::look_all(point, [(args.home.as_path(), "")].into_iter(), &args.home),
                Vec::new(),
                Vec::new(),
            ),
            _ if !visited.looked_for => continue,
            _ => {
                let reading = Reading {
                    reader: watched::READER,
                    scope: &machine,
                    kind: &point.kind(),
                    run_id: &run_id,
                    at: run.at,
                    observed_at: run.at,
                };
                (
                    autorun::look_all(
                        point,
                        checkouts.iter().map(|c| (c.path.as_path(), c.rel.as_str())),
                        &args.home,
                    ),
                    kept(run.tx, &reading, |path| visited.unvisited(path))?,
                    rels.clone(),
                )
            }
        };
        placed.push(Placed {
            scope: machine.clone(),
            watched_as: point.watched_as().unwrap_or_default(),
            kind: point.kind(),
            coverage: Some(looked.coverage(point)),
            look: looked.look,
            elsewhere: None,
            kept,
            checkouts: over,
        });
    }

    // The raw copy: kind, path, checksum and link target, one line per entry; never content.
    let mut raw = String::new();
    let mut lines: Vec<Vec<usize>> = Vec::new();
    let mut n = 0;
    for p in &placed {
        let mut mine = Vec::new();
        for e in &p.look.entries {
            let content = match &e.content {
                watched::Content::Unread(_, why) => format!("not read: {why}"),
                other => other.literal().unwrap_or_default(),
            };
            let link = e.link.as_deref().unwrap_or_default();
            raw.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                e.watched_as,
                watched::field(&e.path),
                watched::field(&content),
                watched::field(link)
            ));
            n += 1;
            mine.push(n);
        }
        lines.push(mine);
    }
    let raw_file = run.keep_raw(watched::READER, watched::RAW, raw.as_bytes())?;
    // A place new in a new worktree, the same as in another checkout of its repository as this
    // reading read it, raises no finding (`worktrees.rs`).
    let siblings = worktrees::Siblings::of(run.tx, &machine, &run_id, checkouts, &args.home)?;
    let read: BTreeMap<&str, &watched::Entry> = placed
        .iter()
        .flat_map(|p| &p.look.entries)
        .map(|e| (e.path.as_str(), e))
        .collect();
    let first_check = !baseline::checked_before(run.tx, &run_id)?;
    // What was read for the first time, by the place that holds it and what it is watched as.
    let mut first_reads: BTreeMap<(String, &'static str), usize> = BTreeMap::new();

    for (p, mine) in placed.iter().zip(&lines) {
        let reading = Reading {
            reader: watched::READER,
            scope: &p.scope,
            kind: &p.kind,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        let tx = run.tx;
        let judge = baseline::Judge {
            tx,
            reader: watched::READER,
            kind: &p.kind,
            run_id: &run_id,
            first_check,
            checkouts: &p.checkouts,
        };
        let file_id = |path: &str| format!("file:{machine}/{path}");
        let prefix = format!("file:{machine}/");
        let path_of = |id: &str| id.strip_prefix(&prefix).unwrap_or(id).to_string();
        // The place a thing read for the first time is told by: its checkout, the folder that
        // was listed, or its file.
        let group = |path: &str| {
            let unit = baseline::unit_of(path);
            if let Some(c) = judge.checkout_of(unit) {
                return c.to_string();
            }
            let folder = baseline::parent(unit);
            if p.look.read.iter().any(|r| r == folder) {
                folder.to_string()
            } else {
                unit.to_string()
            }
        };
        let mut statements = Vec::new();
        for (e, line) in p.look.entries.iter().zip(mine) {
            let source_ref = format!("{raw_file}:{line}");
            statements.push(Statement {
                subject: file_id(&e.path),
                predicate: "watched_as",
                object: e.watched_as.to_string(),
                source_ref: source_ref.clone(),
            });
            statements.push(Statement {
                subject: file_id(&e.path),
                predicate: "located_on",
                object: p.scope.clone(),
                source_ref,
            });
        }
        statements.extend(p.kept.iter().map(|s| Statement {
            subject: s.subject.clone(),
            predicate: s.predicate,
            object: s.object.clone(),
            source_ref: s.source_ref.clone(),
        }));
        // A unit that could not be read, or was not looked into, keeps what was known of it,
        // so that the rest of the reading is compared whole: what is gone from a unit read in
        // full is gone, whatever failed elsewhere. Hooks kept elsewhere keep all of theirs.
        let unread: Vec<&str> = p
            .look
            .failed
            .iter()
            .chain(&p.look.unreached)
            .map(|(path, _)| baseline::unit_of(path))
            .collect();
        statements.extend(kept(tx, &reading, |path| {
            p.elsewhere.is_some() || unread.iter().any(|u| baseline::under(path, u))
        })?);
        let (completeness, reason) = if let Some(why) = &p.elsewhere {
            ("partial", Some(why.clone()))
        } else if p.kind == watched::HOOK_KIND && p.look.entries.is_empty() {
            match p.look.completeness() {
                ("full", _) => ("full", Some(watched::NO_HOOKS.to_string())),
                other => other,
            }
        } else if let Some(coverage) = &p.coverage {
            coverage.clone()
        } else {
            p.look.completeness()
        };
        // A place that could not be looked at failed; one that leads into a folder macOS asks
        // permission for was not given; hooks kept elsewhere have no reader.
        let gap = if p.elsewhere.as_deref() != Some(watched::GIT_FILE) && p.elsewhere.is_some() {
            Gap::of(Cause::Failed)
        } else if p.elsewhere.is_some() {
            Gap {
                cause: Some(Cause::NoReader),
                lacks: vec![Lack::new(watched::HOOKS_ELSEWHERE, None)],
            }
        } else {
            Gap::when((completeness != "full").then(|| p.look.cause()))
        };
        let with_basis: Vec<(&str, &Statement)> =
            statements.iter().map(|s| (watched::BASIS, s)).collect();
        let applied = Applied {
            completeness,
            reason: reason.as_deref(),
            gap: &gap,
            compared: "full",
        };
        let mut judged: HashMap<String, Verdict> = HashMap::new();
        let events = run.apply_judged(&reading, &applied, &with_basis, &mut |e| {
            if e.kind != "added" {
                return Ok(Verdict::Change);
            }
            if let Some(v) = judged.get(&e.subject) {
                return Ok(*v);
            }
            let v = judge.verdict(&path_of(&e.subject))?;
            judged.insert(e.subject.clone(), v);
            Ok(v)
        })?;
        let mut new = BTreeSet::new();
        for (e, verdict) in events {
            match (verdict, e.kind, e.predicate.as_str()) {
                (Verdict::Change, "added", "watched_as") => {
                    let path = path_of(&e.subject);
                    let same = siblings.same_as(&path, &read);
                    let why = match &same {
                        Some((checkout, there)) => {
                            let content = read.get(path.as_str()).and_then(|e| e.content.literal());
                            let ids = (format!("checkout:{machine}/{checkout}"), file_id(there));
                            worktrees::journal(
                                run.tx, &reading, &e.subject, content, &ids.0, &ids.1,
                            )?;
                            format!("the same as in {checkout}")
                        }
                        None => {
                            observe("new", p.watched_as, &e.subject);
                            String::new()
                        }
                    };
                    rows.push(vec!["new".to_string(), p.watched_as.to_string(), path, why]);
                    new.insert(e.subject);
                }
                (_, "removed", "watched_as") => {
                    let place = e.old.unwrap_or_default();
                    observe("gone", &place, &e.subject);
                    rows.push(vec![
                        "gone".to_string(),
                        place,
                        path_of(&e.subject),
                        String::new(),
                    ]);
                }
                (Verdict::FirstRead, "added", "watched_as") => {
                    // The same as in another checkout of its repository, which the store
                    // reads: nothing to tell, and the journal says where it is the same.
                    let path = path_of(&e.subject);
                    if let Some((checkout, there)) = siblings.same_as(&path, &read) {
                        let content = read.get(path.as_str()).and_then(|e| e.content.literal());
                        let ids = (format!("checkout:{machine}/{checkout}"), file_id(&there));
                        worktrees::journal(run.tx, &reading, &e.subject, content, &ids.0, &ids.1)?;
                        continue;
                    }
                    *first_reads.entry((group(&path), p.watched_as)).or_default() += 1;
                }
                _ => {}
            }
        }
        // What is there and could not be read, or leads where it is not looked into, is judged
        // by the same three cases as what was read, once while it stays so. Losing sight of a
        // unit read before is a change, and so is a thing new to a listing or in a new
        // checkout: found by the rule of its kind, with why. What was known of it is kept, so
        // reading it again later brings what changed meanwhile as changes. Hooks no longer
        // where they were are lost sight of when they were read there before; a new worktree's
        // hooks were never here.
        let hooks = p.checkouts.first().map(|c| format!("{c}/.git/hooks"));
        let unread_now: Vec<(String, String)> = match (&p.elsewhere, &hooks) {
            (Some(why), Some(unit)) if judge.read_before(unit)? => {
                vec![(unit.clone(), why.clone())]
            }
            (Some(_), _) => Vec::new(),
            (None, _) => p
                .look
                .failed
                .iter()
                .chain(&p.look.unreached)
                .cloned()
                .collect(),
        };
        for (path, why) in &unread_now {
            let unit = baseline::unit_of(path);
            if baseline::judged_unread(tx, watched::READER, &p.kind, unit, &run_id)? {
                continue;
            }
            let id = file_id(unit);
            match judge.verdict(path)? {
                Verdict::Change => {
                    lost_sight(run.tx, &reading, &id, why)?;
                    observe(findings::NOT_READ, p.watched_as, &id);
                }
                Verdict::FirstRead => {
                    *first_reads.entry((group(path), p.watched_as)).or_default() += 1;
                }
                Verdict::Baseline => {}
            }
        }
        for (path, why) in &p.look.failed {
            rows.push(vec![
                "not read".to_string(),
                p.watched_as.to_string(),
                path.clone(),
                why.clone(),
            ]);
        }
        for (path, why) in &p.look.unreached {
            rows.push(vec![
                "not read".to_string(),
                p.watched_as.to_string(),
                path.clone(),
                format!("{}{why}", guarded::NOT_LOOKED_INTO),
            ]);
        }

        for (e, line) in p.look.entries.iter().zip(mine) {
            let id = file_id(&e.path);
            let source_ref = format!("{raw_file}:{line}");
            let mut statements = Vec::new();
            if let Some(literal) = e.content.literal() {
                statements.push(Statement {
                    subject: id.clone(),
                    predicate: "has_content",
                    object: literal,
                    source_ref: source_ref.clone(),
                });
            }
            if let Some(link) = &e.link {
                statements.push(Statement {
                    subject: id.clone(),
                    predicate: "links_to",
                    object: link.clone(),
                    source_ref,
                });
            }
            let (completeness, reason, gap) = match &e.content {
                // A link into a folder macOS asks permission for: where it points is read,
                // what it leads to is not, and what was known of that stays.
                watched::Content::Unread(Cause::NotGiven, why) if e.link.is_some() => {
                    ("partial", Some(why.as_str()), Gap::of(Cause::NotGiven))
                }
                watched::Content::Unread(cause, why) => {
                    let mut gap = Gap::of(*cause);
                    if *cause == Cause::NoReader {
                        gap.lacks.push(Lack::new(watched::OVER_CAP, None));
                    }
                    ("none", Some(why.as_str()), gap)
                }
                _ => ("full", None, Gap::default()),
            };
            let reading = Reading {
                scope: &id,
                kind: watched::CONTENT,
                ..reading
            };
            let read_before =
                store::read_before(tx, watched::READER, &id, watched::CONTENT, &run_id)?;
            let lost = completeness != "full"
                && store::read_full_before(tx, watched::READER, &id, watched::CONTENT, &run_id)?;
            // The content of a file judged in this reading is judged with it; content read for
            // the first time in a file read before was read for the first time.
            let entry = judged.get(&id).copied();
            let applied = Applied {
                completeness,
                reason,
                gap: &gap,
                compared: completeness,
            };
            let events = run.apply_judged(
                &reading,
                &applied,
                &statements
                    .iter()
                    .map(|s| (watched::BASIS, s))
                    .collect::<Vec<_>>(),
                &mut |ev| {
                    Ok(match (ev.kind, entry) {
                        ("added", Some(v)) => v,
                        ("added", None) if !read_before => Verdict::FirstRead,
                        _ => Verdict::Change,
                    })
                },
            )?;
            if events.iter().any(|(_, v)| *v == Verdict::FirstRead) && entry.is_none() {
                *first_reads
                    .entry((group(&e.path), e.watched_as))
                    .or_default() += 1;
            }
            if events.iter().any(|(_, v)| *v == Verdict::Change) && !new.contains(&id) {
                observe("changed", e.watched_as, &id);
                rows.push(vec![
                    "changed".to_string(),
                    e.watched_as.to_string(),
                    e.path.clone(),
                    String::new(),
                ]);
            }
            if completeness == "full" {
                baseline::read_again(tx, watched::READER, watched::CONTENT, &id)?;
            } else if lost
                && !baseline::judged_unread(tx, watched::READER, watched::CONTENT, &id, &run_id)?
            {
                lost_sight(run.tx, &reading, &id, reason.unwrap_or_default())?;
                observe(findings::NOT_READ, e.watched_as, &id);
            }
            if let Some(why) = reason {
                rows.push(vec![
                    "not read".to_string(),
                    e.watched_as.to_string(),
                    e.path.clone(),
                    why.to_string(),
                ]);
            }
        }
        baseline::record(
            run.tx,
            watched::READER,
            &p.kind,
            &run_id,
            run.at,
            &p.look.read,
            &p.look.seen,
        )?;
    }
    // One line per place read for the first time, and one journal entry for each, which the
    // finding that tells them rests on.
    let mut per_place: BTreeMap<&str, usize> = BTreeMap::new();
    for ((place, watched_as), n) in &first_reads {
        *per_place.entry(place.as_str()).or_default() += n;
        rows.push(vec![
            "first read".to_string(),
            watched_as.to_string(),
            place.clone(),
            format!(
                "{} kept as the baseline",
                things(*n as i64, "thing", "things")
            ),
        ]);
    }
    for (place, n) in per_place {
        let id = if rels.iter().any(|r| r == place) {
            format!("checkout:{machine}/{place}")
        } else {
            format!("file:{machine}/{place}")
        };
        run.tx.execute(
            "INSERT INTO journal (at, run_id, entry, reader, scope, subject, new_value)
             VALUES (?1, ?2, 'place_first_read', ?3, ?4, ?5, ?6)",
            rusqlite::params![run.at, run_id, watched::READER, machine, id, n.to_string()],
        )?;
    }
    let mut guarded: Vec<PathBuf> = placed
        .iter()
        .flat_map(|p| p.look.guarded.iter().cloned())
        .collect();
    guarded.sort();
    guarded.dedup();
    not_looked_into_when_met(run, watched::READER, &guarded, &args.home)?;
    if placed.iter().any(|p| {
        !p.look.entries.is_empty()
            || !p.look.failed.is_empty()
            || !p.look.unreached.is_empty()
            || p.elsewhere.is_some()
    }) {
        run.readers += 1;
    }
    Ok((rows, seen))
}

/// Journals that a unit an earlier run read in full is there and could not be read now, with
/// why: what a finding about it rests on.
fn lost_sight(
    tx: &rusqlite::Transaction,
    r: &Reading,
    id: &str,
    why: &str,
) -> rusqlite::Result<()> {
    store::put_entity(tx, id)?;
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, new_value)
         VALUES (?1, ?2, 'not_read', ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![r.at, r.run_id, r.reader, r.scope, r.kind, id, why],
    )?;
    Ok(())
}

fn not_full_words(completeness: &str) -> &'static str {
    if completeness == "partial" {
        "partial"
    } else {
        "nothing read"
    }
}

/// One sentence about watched places for the report line. Paths are never in it.
fn watched_sentence(w: Option<&status::Watched>) -> String {
    let Some(w) = w else {
        return "Watched places: never read.".to_string();
    };
    let mut not_full: Vec<String> = w
        .kinds_not_full
        .iter()
        .map(|(kind, completeness)| format!("{kind} ({})", not_full_words(completeness)))
        .collect();
    for (completeness, n) in &w.hooks_not_full {
        not_full.push(format!(
            "hooks in {} ({})",
            things(*n as i64, "checkout", "checkouts"),
            not_full_words(completeness)
        ));
    }
    if w.unread > 0 {
        not_full.push(format!(
            "the content of {}",
            things(w.unread as i64, "file", "files")
        ));
    }
    let files = things(w.files, "file", "files");
    let mut s = if w.first {
        format!("Watched places: {files}, first reading, kept as the baseline")
    } else {
        format!(
            "Watched places: {files}, {} new, {} changed, {} gone since the last reading",
            w.new, w.changed, w.gone
        )
    };
    if !not_full.is_empty() {
        s.push_str(&format!("; not read in full: {}", not_full.join(", ")));
    }
    s.push('.');
    s
}

// ---- Integrity of what is installed: see src/integrity.rs. ----

/// Reads application bundles, Homebrew kegs, global npm packages and applications' code under
/// Application Support, one reading per kind scoped to this machine. A first reading of a kind
/// is its baseline, which `immune status` counts as nothing new. Returns what changed while its
/// version stayed, for the rules.
fn read_integrity(run: &mut Run, args: &Args) -> Result<Vec<findings::Observed>, Box<dyn Error>> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let roots = integrity::Roots {
        home: &args.home,
        system: &args.system_root,
        store: &args.store,
    };
    let kinds = integrity::read(run.tx, &roots, &machine)?;
    let (raw, lines) = integrity::raw(&kinds);
    let raw_file = run.keep_raw(integrity::READER, integrity::RAW, raw.as_bytes())?;
    for (k, lines) in kinds.iter().zip(&lines) {
        let reading = Reading {
            reader: integrity::READER,
            scope: &machine,
            kind: k.kind,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        let (completeness, reason, gap) = k.coverage();
        let statements = k.statements(&raw_file, lines);
        run.apply(
            &reading,
            integrity::BASIS,
            completeness,
            Some(&reason),
            &gap,
            &statements,
        )?;
    }
    if kinds.iter().any(|k| k.present > 0) {
        run.readers += 1;
    }
    let mut guarded: Vec<PathBuf> = kinds.iter().flat_map(|k| k.guarded.clone()).collect();
    guarded.sort();
    guarded.dedup();
    not_looked_into_when_met(run, integrity::READER, &guarded, &args.home)?;
    Ok(integrity::observed(run.tx, &run_id)?)
}

// ---- End of integrity of what is installed. ----

// ---- What runs by itself and indicators: see src/autorun.rs and src/indicators.rs. ----

/// Which known ways a project runs code by itself each checkout holds, and which places of
/// the home folder this machine holds, read here or not, as one reading of this machine; and
/// apart, as before, the ways present that this build does not read, each with how many
/// checkouts hold it, and the places of the home folder. With none present each of those is
/// read in full.
fn read_other_autoruns(
    run: &mut Run,
    home: &Path,
    found: &[checkouts::Checkout],
) -> Result<(), Box<dyn Error>> {
    let (run_id, machine, at) = (run.run_id.to_string(), run.machine.to_string(), run.at);
    let mut present: BTreeMap<String, usize> = BTreeMap::new();
    let mut statements = Vec::new();
    for c in found {
        let checkout = format!("checkout:{machine}/{}", c.rel);
        for point in autorun::present(&c.path, autorun::Scope::Checkout, home) {
            statements.push(Statement {
                subject: checkout.clone(),
                predicate: autorun::HOLDS,
                object: point.name(),
                source_ref: c.rel.clone(),
            });
            if !point.read() {
                *present.entry(point.name()).or_default() += 1;
            }
        }
    }
    let mut in_home = Vec::new();
    for point in autorun::present(home, autorun::Scope::Home, home) {
        statements.push(Statement {
            subject: machine.clone(),
            predicate: autorun::HOLDS,
            object: point.name(),
            source_ref: "~".to_string(),
        });
        if !point.read() {
            in_home.push(point.name());
        }
    }
    let on_machine = |kind| Reading {
        reader: watched::READER,
        scope: &machine,
        kind,
        run_id: &run_id,
        at,
        observed_at: at,
    };
    // Which ways each checkout holds is not a finding; its first reading is journaled as one.
    let present_kind = on_machine(autorun::PRESENT_KIND);
    let read_before = store::read_before(
        run.tx,
        present_kind.reader,
        present_kind.scope,
        present_kind.kind,
        present_kind.run_id,
    )?;
    let with_basis: Vec<(&str, &Statement)> =
        statements.iter().map(|s| (watched::BASIS, s)).collect();
    let applied = Applied {
        completeness: "full",
        reason: None,
        gap: &Gap::default(),
        compared: "full",
    };
    // The ways a checkout found in this run holds are judged as finding it was.
    let tx = run.tx;
    run.apply_judged(&present_kind, &applied, &with_basis, &mut |e| {
        if !read_before {
            return Ok(Verdict::Baseline);
        }
        if e.kind != "added" {
            return Ok(Verdict::Change);
        }
        Ok(baseline::found_as(tx, run_id.as_str(), &e.subject)?.unwrap_or(Verdict::Change))
    })?;
    let (completeness, reason, gap) = if present.is_empty() {
        ("full", None, Gap::default())
    } else {
        let named: Vec<String> = present
            .iter()
            .map(|(name, n)| format!("{name} in {}", things(*n as i64, "checkout", "checkouts")))
            .collect();
        let lacks = present
            .keys()
            .map(|name| Lack::new(autorun::OTHER_WAY, Some(name)))
            .collect();
        let gap = Gap {
            cause: Some(Cause::NoReader),
            lacks,
        };
        ("none", Some(format!("not read: {}", named.join("; "))), gap)
    };
    run.apply(
        &on_machine(autorun::OTHERS_KIND),
        watched::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &[],
    )?;
    let (completeness, reason, gap) = if in_home.is_empty() {
        ("full", None, Gap::default())
    } else {
        let gap = Gap {
            cause: Some(Cause::NoReader),
            lacks: in_home
                .iter()
                .map(|name| Lack::new(autorun::OTHER_HOME, Some(name)))
                .collect(),
        };
        (
            "none",
            Some(format!("not read: {}", in_home.join("; "))),
            gap,
        )
    };
    run.apply(
        &on_machine(autorun::HOME_OTHERS_KIND),
        watched::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &[],
    )?;
    Ok(())
}

/// Reads the list of indicators and matches it. The list is the file given, else the one
/// next to the store; neither there means not applicable, and nothing is written. A list
/// that cannot be read fails and the one read before is matched. Returns the files that
/// match an indicator they did not match before, for the rule.
fn read_indicators(
    run: &mut Run,
    args: &Args,
    found: &[checkouts::Checkout],
) -> Result<Vec<findings::Observed>, Box<dyn Error>> {
    let path = args
        .indicators
        .clone()
        .unwrap_or_else(|| run.home.join(indicators::LIST));
    if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(Vec::new());
    }
    run.readers += 1;
    let (run_id, machine, at) = (run.run_id.to_string(), run.machine.to_string(), run.at);
    let on_machine = |kind: &'static str| Reading {
        reader: indicators::READER,
        scope: &machine,
        kind,
        run_id: &run_id,
        at,
        observed_at: at,
    };
    let given = autorun::read_capped(&path, indicators::CAP)
        .and_then(|bytes| Ok((indicators::parse(&bytes)?, bytes)));
    let (list, raw) = match given {
        Ok((list, bytes)) => {
            let raw = run.keep_raw(indicators::READER, indicators::LIST, &bytes)?;
            let note = format!("{} entries", list.entries);
            run.apply(
                &on_machine(indicators::LIST_KIND),
                indicators::BASIS,
                "full",
                Some(&note),
                &Gap::default(),
                &[],
            )?;
            (list, raw)
        }
        Err(why) => {
            let before = store::last_raw(run.tx, indicators::READER, indicators::LIST)?;
            let previous = before.and_then(|raw| {
                let bytes = std::fs::read(run.home.join(&raw)).ok()?;
                Some((indicators::parse(&bytes).ok()?, raw))
            });
            let then = if previous.is_some() {
                "the list read before is matched"
            } else {
                "no list was read before"
            };
            run.apply(
                &on_machine(indicators::LIST_KIND),
                indicators::BASIS,
                "none",
                Some(&format!("{why}; {then}")),
                &Gap::of(Cause::Failed),
                &[],
            )?;
            match previous {
                Some(p) => p,
                None => return Ok(Vec::new()),
            }
        }
    };

    // What matches, as file id and indicator: hashes against watched files, the network
    // kinds against the texts read in checkouts.
    let mut matches = indicators::match_hashes(run.tx, &list)?;
    let mut failed = Vec::new();
    for c in found {
        let mut texts = lockfiles::read_as_text(&c.path);
        if std::fs::symlink_metadata(c.path.join(autorun::TASKS)).is_ok() {
            texts.push(autorun::TASKS.to_string());
        }
        for rel in texts {
            let shown = format!("{}/{rel}", c.rel);
            match autorun::read_capped(&c.path.join(&rel), indicators::CAP) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    for i in indicators::match_text(&text, &list) {
                        matches.push((format!("file:{machine}/{shown}"), i));
                    }
                }
                Err(why) => failed.push(format!("{shown} ({why})")),
            }
        }
    }
    let before: BTreeSet<(String, String)> = run
        .tx
        .prepare(
            "SELECT subject, object FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'matches_indicator'",
        )?
        .query_map([indicators::READER], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let statements: Vec<Statement> = matches
        .iter()
        .map(|(file, i)| Statement {
            subject: file.clone(),
            predicate: "matches_indicator",
            object: i.literal(),
            source_ref: raw.clone(),
        })
        .collect();
    let (completeness, reason, gap) = if failed.is_empty() {
        ("full", None, Gap::default())
    } else {
        let reason = format!("could not be read: {}", failed.join("; "));
        ("partial", Some(reason), Gap::of(Cause::Failed))
    };
    run.apply(
        &on_machine(indicators::MATCH_KIND),
        indicators::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &statements,
    )?;
    let lacks = indicators::lacks(&list);
    let (completeness, reason, gap) = if lacks.is_empty() {
        ("full", None, Gap::default())
    } else {
        let names: Vec<&str> = lacks.iter().filter_map(|l| l.name.as_deref()).collect();
        let reason = format!("not matched: {}", names.join("; "));
        let cause = Some(Cause::NoReader);
        ("none", Some(reason), Gap { cause, lacks })
    };
    run.apply(
        &on_machine(indicators::UNMATCHED_KIND),
        indicators::BASIS,
        completeness,
        reason.as_deref(),
        &gap,
        &[],
    )?;

    // A file is found once in a run, however many indicators it newly matches.
    let new: BTreeSet<&String> = statements
        .iter()
        .filter(|s| !before.contains(&(s.subject.clone(), s.object.clone())))
        .map(|s| &s.subject)
        .collect();
    Ok(new
        .into_iter()
        .map(|file| findings::Observed {
            change: "new",
            place: indicators::MATCHED.to_string(),
            file: file.clone(),
        })
        .collect())
}

// ---- End of what runs by itself and indicators. ----

/// Asks for the threat catalogue, or takes the file given for it. Run before the run lock is
/// taken, with the store open only to read, or with no store yet: the ETag to ask with is
/// read first, and the download touches nothing in the store.
fn get_catalogue(
    conn: Option<&rusqlite::Connection>,
    args: &Args,
) -> Result<threats::Fetched, Box<dyn Error>> {
    Ok(match &args.threats_input {
        Some(path) => threats::read_file(path),
        None => {
            let curl = args.curl.as_deref().unwrap_or(Path::new(threats::CURL));
            threats::fetch(curl, threats::last_etag(conn)?.as_deref())
        }
    })
}

/// Brings the threat list in line with the catalogue got. A catalogue that could not be
/// fetched or parsed changes nothing: no threat is added or marked gone.
fn read_threats(run: &Run, fetched: threats::Fetched) -> Result<(), Box<dyn Error>> {
    let (tx, run_id, at) = (run.tx, run.run_id, run.at);
    let last = threats::last_good(tx)?;
    let failed = |reason: String, sha256, raw_path| -> Result<(), Box<dyn Error>> {
        let reading = threats::Reading {
            outcome: "failed",
            reason: Some(reason),
            sha256,
            raw_path,
            ..threats::Reading::default()
        };
        threats::put_reading(tx, run_id, at, &reading)?;
        Ok(())
    };
    match fetched {
        threats::Fetched::Failed(reason) => failed(reason, None, None),
        threats::Fetched::Unchanged => {
            let total = threats::held(tx)?;
            let (_, before) = last.unwrap_or_default();
            let reading = threats::Reading {
                outcome: "unchanged",
                entries: Some(total),
                ..before
            };
            threats::put_reading(tx, run_id, at, &reading)?;
            Ok(())
        }
        threats::Fetched::Body { bytes, etag } => {
            let raw_path = run.keep_raw(threats::SOURCE, threats::RAW, &bytes)?;
            let sha256 = sha256::hex(&bytes);
            let entries = match threats::parse(&bytes) {
                Ok(entries) => entries,
                Err(reason) => return failed(reason, Some(sha256), Some(raw_path)),
            };
            threats::record(tx, run_id, at, &entries)?;
            let reading = threats::Reading {
                outcome: "read",
                reason: None,
                etag,
                sha256: Some(sha256),
                raw_path: Some(raw_path),
                entries: Some(entries.len()),
            };
            threats::put_reading(tx, run_id, at, &reading)?;
            Ok(())
        }
    }
}

/// Asks for each feed of vulnerability data, or takes the archive given for it.
fn get_feeds(
    conn: Option<&rusqlite::Connection>,
    args: &Args,
    home: &Path,
    now: i64,
) -> Result<Vec<osv::Got>, Box<dyn Error>> {
    let curl = args.curl.as_deref().unwrap_or(Path::new(threats::CURL));
    let inputs = [&args.osv_crates_input, &args.osv_npm_input];
    let mut got = Vec::new();
    for (feed, input) in osv::FEEDS.iter().zip(inputs) {
        got.push(osv::get(conn, feed, input.as_deref(), curl, home, now)?);
    }
    Ok(got)
}

/// Brings the advisories in line with what was got for each feed. A feed that could not be
/// read changes nothing, and the data read before stays in force.
fn read_feeds(run: &Run, got: Vec<osv::Got>) -> Result<(), Box<dyn Error>> {
    for (feed, got) in osv::FEEDS.iter().zip(got) {
        osv::record(run.tx, run.run_id, run.at, run.home, feed, got)?;
    }
    Ok(())
}

/// Matches the packages the projects' lockfiles hold against the vulnerability data, and holds
/// the findings of what is urgent: a malicious package, or a vulnerability attackers are using.
/// Every other match is an answer in a list and raises nothing. Returns how many findings it
/// opened.
fn match_dependencies(run: &Run) -> Result<usize, Box<dyn Error>> {
    let matched = vulnerabilities::match_all(run.tx, run.run_id, run.at)?;
    let linked: BTreeSet<String> = {
        let mut stmt = run
            .tx
            .prepare("SELECT DISTINCT advisory FROM vulnerability_linked")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut held: BTreeMap<&str, Vec<(String, Vec<i64>)>> = BTreeMap::new();
    for (component, records) in &matched.affected {
        let malicious: Vec<&(String, String, Vec<String>)> =
            records.iter().filter(|r| r.1 == "malicious").collect();
        let rule = if !malicious.is_empty() {
            // npm's placeholder for a name it removed as malicious: the name is the finding,
            // not code that runs.
            let placeholder = malicious
                .iter()
                .all(|r| r.2.iter().all(|v| v == "0.0.1-security"));
            if placeholder {
                findings::MALICIOUS_NAME_REMOVED
            } else {
                findings::MALICIOUS_PACKAGE
            }
        } else if records.iter().any(|r| linked.contains(&r.0)) {
            findings::EXPLOITED_VULNERABILITY
        } else {
            continue;
        };
        // What it rests on: the journal entries of the component's releases, and the latest
        // reading of the data.
        let basis: Vec<i64> = run
            .tx
            .prepare(
                "SELECT MAX(seq) FROM journal
                 WHERE subject = ?1 AND entry IN ('added', 'changed') AND predicate = 'has_version'
                 UNION
                 SELECT MAX(seq) FROM journal WHERE entry = 'advisories_read'",
            )?
            .query_map([component], |r| r.get::<_, Option<i64>>(0))?
            .filter_map(|r| r.transpose())
            .collect::<rusqlite::Result<_>>()?;
        held.entry(rule)
            .or_default()
            .push((component.clone(), basis));
    }
    let mut opened = 0;
    for rule in [
        findings::MALICIOUS_PACKAGE,
        findings::MALICIOUS_NAME_REMOVED,
        findings::EXPLOITED_VULNERABILITY,
    ] {
        let now = held.remove(rule).unwrap_or_default();
        opened += findings::hold(run.tx, rule, &now, run.run_id, run.at)?;
    }
    Ok(opened)
}

/// One sentence about the vulnerability data for the report line, with what matching found.
fn feeds_sentence(states: &[osv::State], run_id: &str, t: &vulnerabilities::Totals) -> String {
    let clauses: Vec<String> = states.iter().map(|s| feed_clause(s, run_id)).collect();
    let mut matched = format!(
        "matched against the projects' package-lock.json, pnpm-lock.yaml and Cargo.lock: {} in packages they use",
        things(
            t.records as i64,
            "known vulnerability",
            "known vulnerabilities"
        )
    );
    if t.packages_unknown > 0 {
        matched.push_str(&format!(
            ", and for {} whether one affects them cannot be told",
            things(t.packages_unknown as i64, "package", "packages")
        ));
    }
    format!(
        "Vulnerability data from OSV: {}; {matched}.",
        clauses.join("; ")
    )
}

fn feed_clause(s: &osv::State, run_id: &str) -> String {
    let ecosystem = s.feed.ecosystem;
    let held = format!(
        "{}, {} of them on malicious packages",
        things(s.records as i64, "record", "records"),
        grouped(s.malicious as i64)
    );
    let Some((_, _, outcome, reason)) = &s.latest else {
        return format!("{ecosystem} never read");
    };
    let since = view::utc_or(s.changed_at.or(s.good_at), "an unknown time");
    match outcome.as_str() {
        "failed" => {
            let reason = reason.as_deref().unwrap_or_default();
            match s.good_at {
                Some(at) => format!(
                    "{ecosystem} not read: {reason}; the {held}, read {}, stay in force",
                    view::utc(at)
                ),
                None => format!("{ecosystem} not read: {reason}; nothing of it is known yet"),
            }
        }
        // Not asked in this run: its last good reading is recent enough.
        _ if !s.asked_in(run_id) => format!(
            "{ecosystem}: {held}, unchanged since {since}, asked for {}",
            s.feed.asked
        ),
        "unchanged" => format!("{ecosystem}: {held}, unchanged since {since}"),
        _ => match &s.counts {
            Some(c) if c.first => {
                format!("{ecosystem}: {held}, first reading, kept as the baseline")
            }
            Some(c) => {
                let mut said = format!(
                    "{ecosystem}: {held}, {} new and {} changed since the last reading",
                    grouped(c.new as i64),
                    grouped(c.changed as i64)
                );
                if c.withdrawn > 0 {
                    said.push_str(&format!(", {} withdrawn", grouped(c.withdrawn as i64)));
                }
                if c.gone > 0 {
                    said.push_str(&format!(", {} left it", grouped(c.gone as i64)));
                }
                said
            }
            None => format!("{ecosystem}: {held}"),
        },
    }
}

/// One sentence about the threat catalogue for the report line. What its entries are
/// compared with follows the store, `vulnerabilities::catalogue_compared`: nothing in the
/// report may read as "does not affect me" where they are not compared.
fn catalogue_sentence(c: Option<&status::Catalogue>, compared: &[&str]) -> String {
    use status::Catalogue;
    let judged = vulnerabilities::catalogue_said(compared);
    let Some(c) = c else {
        return "CISA catalogue: never read; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown.".to_string();
    };
    let held = |n: usize| {
        things(
            n as i64,
            "exploited vulnerability",
            "exploited vulnerabilities",
        )
    };
    match c {
        Catalogue::Read {
            total, first: true, ..
        } => format!(
            "CISA catalogue: {}, first reading, kept as the baseline; {judged}.",
            held(*total)
        ),
        Catalogue::Read {
            total, new, gone, ..
        } => {
            let mut s = format!(
                "CISA catalogue: {}, {} new since the last reading",
                held(*total),
                grouped(*new as i64)
            );
            if *gone > 0 {
                s.push_str(&format!(", {} left the catalogue", grouped(*gone as i64)));
            }
            format!("{s}; {judged}.")
        }
        Catalogue::Unchanged { total, .. } => format!(
            "CISA catalogue: {}, unchanged, 0 new since the last reading; {judged}.",
            held(*total)
        ),
        Catalogue::Failed {
            reason,
            last: Some((at, total)),
            ..
        } => format!(
            "CISA catalogue not read: {reason}; what is new is unknown, and the {} it held at its last reading, {}, are {judged}.",
            held(*total),
            view::utc(*at)
        ),
        Catalogue::Failed {
            reason, last: None, ..
        } => format!(
            "CISA catalogue not read: {reason}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown."
        ),
    }
}

/// The one line: how many readers had input, what the run left, and its notes. It never says
/// "no changes" unless every reading this run was full and every scope read before was read
/// again.
/// How many things need a look, the number `immune status` and the app show, and how many
/// findings this run opened.
fn needs_sentence(total: usize, opened: usize) -> String {
    if total == 0 {
        return "Nothing needs a look.".to_string();
    }
    let new = if opened == 0 {
        "none new in this run".to_string()
    } else {
        format!("{} new in this run", grouped(opened as i64))
    };
    format!(
        "{} a look, {new}.",
        things(total as i64, "thing needs", "things need")
    )
}

fn report(readers: usize, notes: &[String], s: &status::Summary, needs: &str) -> String {
    let mut line = format!(
        "{}, {} {needs}",
        things(readers as i64, "reader", "readers"),
        summary_sentences(s)
    );
    for note in notes {
        line.push(' ');
        line.push_str(note);
    }
    line
}

/// What a finished run left, in the words of the report line; `immune status` says the same.
fn summary_sentences(s: &status::Summary) -> String {
    let (t, servers) = (&s.totals, &s.servers);
    // Servers and other devices are counted apart, never as one number of machines.
    let mut line = format!(
        "{}, {}.",
        things(t.checkouts, "checkout", "checkouts"),
        things(t.components, "component", "components"),
    );
    if servers.known == 0 {
        line.push_str(" No servers known");
    } else {
        line.push_str(&format!(
            " {} known, {} offered for the sweep, {} read",
            things(servers.known as i64, "server", "servers"),
            grouped(servers.offered as i64),
            grouped(servers.read as i64)
        ));
    }
    if servers.own_devices > 0 {
        line.push_str(&format!(
            "; {} of your other devices seen in the private network, not read",
            grouped(servers.own_devices as i64)
        ));
    }
    if servers.other_devices > 0 {
        line.push_str(&format!(
            "; {} seen in the private network, not read",
            things(
                servers.other_devices as i64,
                "other person's device",
                "other people's devices"
            )
        ));
    }
    if servers.set_aside > 0 {
        line.push_str(&format!(
            "; {} retired or disowned by the owner",
            grouped(servers.set_aside as i64)
        ));
    }
    line.push('.');
    if !servers.seen.is_empty() {
        line.push_str(&format!(
            " Seen alive after the owner's word: {}.",
            servers.seen.join(", ")
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
    line.push_str(&if s.first_run {
        "First run.".to_string()
    } else {
        since_last_run(&s.since, t)
    });
    line.push(' ');
    line.push_str(&watched_sentence(s.watched.as_ref()));
    line.push(' ');
    line.push_str(&integrity::sentence(s.integrity.as_ref()));
    line.push(' ');
    line.push_str(&catalogue_sentence(
        s.catalogue.as_ref(),
        &s.vulnerabilities.catalogue_compared,
    ));
    line.push(' ');
    line.push_str(&feeds_sentence(&s.feeds, &s.run.id, &s.vulnerabilities));
    // What this build cannot read here is part of every report: in the clause of what is not
    // covered, and named by `immune status`.
    line
}

fn since_last_run(since: &status::Since, t: &store::Totals) -> String {
    let (added, changed, removed) = (since.added, since.changed, since.removed);
    let counts = format!(
        "+{} added, {} changed, {} removed",
        grouped(added as i64),
        grouped(changed as i64),
        grouped(removed as i64)
    );
    let unknown = status::unknown(t);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_kept_is_of_the_deepest_checkout_holding_a_file_and_never_of_one_no_longer_held() {
        // A reading keeps what it did not look into, and only that: a project inside one it
        // looked into is not, and neither is a project gone from the store whose name begins
        // as one kept does, or its entries would stay forever.
        let set = |rels: &[&str]| rels.iter().map(|r| r.to_string()).collect();
        let v = Visited {
            held: set(&["dev/shop", "dev/shop/vendor/lib", "Documents/notes"]),
            looked: set(&["dev/shop"]),
            looked_for: true,
        };
        assert!(v.unvisited("Documents/notes/package.json"));
        assert!(v.unvisited("dev/shop/vendor/lib/package.json"));
        assert!(!v.unvisited("dev/shop/package.json"));
        assert!(!v.unvisited("Documents/notes-old/package.json"));
        let v = Visited {
            looked: set(&["dev/shop/vendor/lib"]),
            ..v
        };
        assert!(!v.unvisited("dev/shop/vendor/lib/package.json"));
        assert!(v.unvisited("dev/shop/package.json"));
    }

    #[test]
    fn where_sessions_were_read_up_to_is_committed_with_the_run_or_not_at_all() {
        // A position kept apart from the facts read before it would, after a run that failed,
        // stand for lines whose facts were never written.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "immune-session-commit-{}-{nanos}",
            std::process::id()
        ));
        let sessions = dir.join("sessions");
        std::fs::create_dir_all(sessions.join("-invented-project")).unwrap();
        std::fs::write(
            sessions.join("-invented-project/s1.jsonl"),
            "{\"type\":\"user\",\"cwd\":\"/invented/work\"}\n",
        )
        .unwrap();
        let store_path = dir.join("store.db");
        let args = Args {
            store: store_path.clone(),
            machine: "mac".to_string(),
            brew: None,
            brew_input: None,
            servers_input: None,
            home: dir.join("home"),
            checkouts_root: None,
            sessions_root: Some(sessions),
            tailscale: None,
            threats_input: None,
            osv_crates_input: None,
            osv_npm_input: None,
            curl: None,
            system_root: dir.join("no-system"),
            indicators: None,
            json: false,
        };
        let count = |conn: &rusqlite::Connection| -> i64 {
            conn.query_row("SELECT COUNT(*) FROM session_file", [], |r| r.get(0))
                .unwrap()
        };
        let mut conn = store::open(&store_path).unwrap();
        {
            let tx = conn.transaction().unwrap();
            store::put_entity(&tx, "machine:mac").unwrap();
            let mut run = Run {
                tx: &tx,
                home: &dir,
                run_id: "run-1",
                at: 1,
                machine: "machine:mac",
                events: Vec::new(),
                notes: Vec::new(),
                readers: 0,
            };
            read_agent_folders(&mut run, &args).unwrap();
            assert_eq!(count(&tx), 1);
            // Not visible outside the run's transaction before it commits.
            let other = store::open_read_only(&store_path).unwrap();
            assert_eq!(count(&other), 0);
            // The run fails here: its transaction is dropped without a commit.
        }
        assert_eq!(count(&conn), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
