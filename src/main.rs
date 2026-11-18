//! Immune: read what is installed, keep it as facts, report what changed. One line.
//! `immune view` writes a page that shows what is in the store. `immune servers` shows which
//! servers this machine knows and writes the read-only sweep for the owner to run.
//! `immune owner` keeps the owner's word: that a machine is retired or not theirs. `immune status`
//! says what the last finished run left, read-only. Every command but `servers`, `view` and
//! `watch` answers with one message of the contract: text for a person, `--json` or `--proto`.
//!
//! The program never connects to a server and never runs ssh. Its requests to the network
//! are the threat list and the vulnerability data of npm and crates.io, each fetched whole
//! with the system curl.

mod after_run;
mod agent_folders;
mod answer;
mod answers_text;
mod autorun;
mod background;
mod baseline;
mod beyond;
mod brew;
mod checkouts;
mod codesign;
mod contract;
mod covered;
mod events;
mod finding_answer;
mod finding_text;
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
mod lists;
mod lockfiles;
mod look;
mod machine;
mod managers;
mod map;
mod matches;
mod osv;
mod overview;
mod owner;
mod pages;
mod plist;
mod processes;
mod program;
mod project;
mod resolver;
mod screen;
mod secrets;
mod servers;
mod service;
mod sha256;
mod sigma;
mod spelling;
mod ssh_config;
mod status;
mod store;
mod sweep;
mod tailnet;
mod text;
mod threats;
mod tools;
mod traces;
mod usage;
mod verdict;
mod view;
mod vulnerabilities;
mod watch;
mod watched;
mod worktrees;

/// The tests' own folders under the temporary folder, removed when a test ends; shared with
/// the integration tests.
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

use baseline::{Unit, Verdict};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Cause, Event, Gap, Lack, Reading, Statement};

/// The store's folder inside the home folder, where every default path points.
const STORE_FOLDER: &str = "Library/Application Support/ai.nuanu.immune";
/// The default store's name in `STORE_FOLDER`.
const STORE_FILE: &str = "store.db";

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
    Verdict(verdict::VerdictArgs),
    Service(service::ServiceArgs),
}

/// `immune rules`: the shipped rules with what the store says they did, or with `over_log` a
/// replay of the event log under that system root.
struct RulesArgs {
    store: PathBuf,
    form: answer::Form,
    over_log: Option<PathBuf>,
    /// Every rule one per line in the text for a person, in place of the summary.
    all: bool,
}

/// `immune vulnerabilities`, and `immune vulnerability <id>` with the id.
struct VulnerabilityArgs {
    store: PathBuf,
    form: answer::Form,
    id: Option<String>,
}

/// `immune findings`: every finding as the contract's message, in the form named; for a person
/// the open findings, or every one with `--all`.
struct FindingsArgs {
    store: PathBuf,
    form: answer::Form,
    all: bool,
}

/// `immune finding <id>`: one finding with what it rests on, or the owner's answer to it.
struct FindingArgs {
    store: PathBuf,
    /// The form of the contract's `Finding`, read or as an answer left it.
    form: answer::Form,
    id: String,
    act: Option<findings::Act>,
    via: findings::Via,
    /// The other finding of the pair, named with `--with`, given the same answer in the same
    /// transaction (`findings::pair`).
    with: Option<String>,
    /// The `journal_seq` of the answer the findings were read in, `--journal-seq`: the answer is
    /// refused when anything joined them after it (`findings::unchanged`).
    journal_seq: Option<i64>,
    /// The words typed after `finding`, for the command a refusal gives a person to run next
    /// (`usage::finding_next`).
    typed: Vec<String>,
}

enum FindingVerb {
    Expected,
    Seen,
    Reopen,
}

/// How long an `expected` mark lasts unless the owner says otherwise.
const EXPECTED_DAYS: i64 = 30;

struct Args {
    store: PathBuf,
    /// The name of this machine in ids.
    machine: String,
    /// The one place to look for brew instead of the standard places.
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
    /// The form of the status it answers with once the check finished; the report line and
    /// the table of watched places for a person.
    form: answer::Form,
}

/// `immune status`: what the last finished run left, read without writing anything.
struct StatusArgs {
    store: PathBuf,
    form: answer::Form,
    /// For a person, what was read and what was not, whole; a message is the same with it.
    coverage: bool,
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
    form: answer::Form,
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
    Ok(user_home()?.join(STORE_FOLDER).join(STORE_FILE))
}

fn parse_args(
    cmd: Option<&str>,
    mut it: impl Iterator<Item = String>,
    options: &mut answer::Options,
    finding_write: &mut bool,
) -> Result<Cmd, String> {
    let cmd = cmd.ok_or("no command given")?;
    // The commands are those the help lists, so none can be added without its line there.
    if !usage::is_command(cmd) {
        return Err(format!("unknown command: {cmd}"));
    }
    let mut store = None;
    match cmd {
        "run" => {
            let (mut machine, mut brew, mut brew_input) = (None, None, None);
            let (mut servers_input, mut checkouts_root, mut tailscale) = (None, None, None);
            let (mut sessions_root, mut threats_input, mut curl) = (None, None, None);
            let (mut system_root, mut indicators) = (None, None);
            let (mut osv_crates_input, mut osv_npm_input) = (None, None);
            options.read(it, |arg, it| {
                match arg.as_str() {
                    "--osv-crates-input" => osv_crates_input = Some(value(it, &arg)?.into()),
                    "--osv-npm-input" => osv_npm_input = Some(value(it, &arg)?.into()),
                    "--tailscale" => tailscale = Some(value(it, &arg)?.into()),
                    "--machine-name" => machine = Some(value(it, &arg)?),
                    "--brew" => brew = Some(value(it, &arg)?.into()),
                    "--brew-input" => brew_input = Some(value(it, &arg)?.into()),
                    "--servers-input" => servers_input = Some(value(it, &arg)?.into()),
                    "--checkouts-root" => checkouts_root = Some(value(it, &arg)?.into()),
                    "--sessions-root" => sessions_root = Some(value(it, &arg)?.into()),
                    "--threats-input" => threats_input = Some(value(it, &arg)?.into()),
                    "--curl" => curl = Some(value(it, &arg)?.into()),
                    "--system-root" => system_root = Some(value(it, &arg)?.into()),
                    "--indicators" => indicators = Some(value(it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
                Ok(())
            })?;
            if machine.as_deref() == Some("") {
                return Err("--machine-name needs a name".to_string());
            }
            Ok(Cmd::Run(Box::new(Args {
                store: options.store()?,
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
                form: options.form(),
            })))
        }
        "status" => {
            let mut coverage = false;
            options.read(it, |arg, _| match arg.as_str() {
                "--coverage" => {
                    coverage = true;
                    Ok(())
                }
                _ => Err(format!("unexpected argument: {arg}")),
            })?;
            Ok(Cmd::Status(StatusArgs {
                store: options.store()?,
                form: options.form(),
                coverage,
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
            let (mut tailscale, mut reason, mut words, mut via) = (None, None, Vec::new(), None);
            options.read(it, |arg, it| {
                match arg.as_str() {
                    "--tailscale" => tailscale = Some(value(it, &arg)?.into()),
                    "--reason" => reason = Some(value(it, &arg)?),
                    "--via" => via = Some(via_once(via, it, &arg)?),
                    _ if arg.starts_with("--") => {
                        return Err(format!("unexpected argument: {arg}"));
                    }
                    _ => words.push(arg),
                }
                Ok(())
            })?;
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
                    store: options.store()?,
                    home: user_home()?,
                    tailscale,
                },
                act,
                via: via.unwrap_or(findings::Via::Command),
                form: options.form(),
            }))
        }
        "findings" => {
            let mut all = false;
            options.read(it, |arg, _| match arg.as_str() {
                "--all" => {
                    all = true;
                    Ok(())
                }
                _ => Err(format!("unexpected argument: {arg}")),
            })?;
            Ok(Cmd::Findings(FindingsArgs {
                store: options.store()?,
                form: options.form(),
                all,
            }))
        }
        "finding" => {
            let typed: Vec<String> = it.collect();
            let (mut reason, mut days, mut via, mut words) = (None, None, None, Vec::new());
            let (mut with, mut seq) = (None, None);
            let parsed = options.read(typed.clone().into_iter(), |arg, it| {
                match arg.as_str() {
                    "--reason" => reason = Some(value(it, &arg)?),
                    "--days" => days = Some(value(it, &arg)?),
                    // Each names one thing, so a second is a misuse: the last would win, and
                    // the first named would be left as it was without a word. A second `--via`
                    // would turn an agent's answer into the app's, which needs no read.
                    "--via" => via = Some(via_once(via, it, &arg)?),
                    "--with" => once(&mut with, it, &arg)?,
                    "--journal-seq" => once(&mut seq, it, &arg)?,
                    _ if arg.starts_with("--") => {
                        return Err(format!("unexpected argument: {arg}"));
                    }
                    _ => words.push(arg),
                }
                Ok(())
            });
            let verb = match words.get(1).map(String::as_str) {
                Some("expected") => Some(FindingVerb::Expected),
                Some("seen") => Some(FindingVerb::Seen),
                Some("reopen") => Some(FindingVerb::Reopen),
                _ => None,
            };
            *finding_write = verb.is_some();
            parsed?;
            let verb = match words.as_slice() {
                [_] => None,
                [_, word] => Some(verb.ok_or_else(|| {
                    format!("the owner can answer expected or seen, or reopen, not {word}")
                })?),
                _ => {
                    return Err(
                        "immune finding takes an id, as in: immune finding f0123456789 seen"
                            .to_string(),
                    );
                }
            };
            // An agent answers only with the reason the owner agreed to, so that what was
            // quieted through it always says why.
            let blank = reason.as_deref().is_none_or(|r| r.trim().is_empty());
            if via == Some(findings::Via::Agent)
                && matches!(verb, Some(FindingVerb::Expected | FindingVerb::Seen))
                && blank
            {
                return Err(
                    "an answer through an agent needs the reason the owner agreed to: --reason <text>"
                        .to_string(),
                );
            }
            // Where an answer must name the read it rests on (`--journal-seq`), so that nothing
            // that joined since is quieted unseen. Required for an answer to two findings, for
            // any answer through an agent, which always reads before it answers and whose read
            // and answer are a conversation apart, and for any answer from the app, which answers
            // on a card drawn from a read. Still optional from the command line. `reopen` quiets
            // nothing and needs none.
            let quiets = matches!(verb, Some(FindingVerb::Expected | FindingVerb::Seen));
            if with.is_some() && quiets && seq.is_none() {
                return Err(
                    "an answer with --with needs --journal-seq <n>, the journal_seq of the answer in which both findings were read"
                        .to_string(),
                );
            }
            if via == Some(findings::Via::Agent) && quiets && seq.is_none() {
                return Err(
                    "an answer through an agent needs --journal-seq <n>, the journal_seq of the answer (immune finding <id> --json) in which the owner was shown the finding"
                        .to_string(),
                );
            }
            if via == Some(findings::Via::App) && quiets && seq.is_none() {
                return Err(
                    "an answer from the app needs --journal-seq <n>, the journal_seq of the answer (immune finding <id> --json or immune status --json) the person answered on"
                        .to_string(),
                );
            }
            let journal_seq = match seq.as_deref() {
                None => None,
                Some(s) => Some(
                    s.parse::<i64>()
                        .ok()
                        .filter(|s| *s >= 0)
                        .ok_or("--journal-seq takes the journal_seq an answer gave, a number")?,
                ),
            };
            let act = match (verb, reason, days) {
                (None, None, None) if via.is_none() && with.is_none() && seq.is_none() => None,
                (None, ..) => {
                    return Err(
                        "--reason, --days, --via, --with and --journal-seq go with an answer: expected, seen or reopen"
                            .to_string(),
                    );
                }
                (Some(FindingVerb::Expected), Some(reason), days) if !blank => {
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
                (Some(FindingVerb::Expected), ..) => {
                    return Err("expected needs a reason: --reason <text>".to_string());
                }
                (Some(FindingVerb::Seen), reason, None) => {
                    let reason = reason.filter(|r| !r.trim().is_empty());
                    Some(findings::Act::Answer(findings::Answer::Seen { reason }))
                }
                (Some(FindingVerb::Seen), ..) => {
                    return Err("seen takes no days".to_string());
                }
                (Some(FindingVerb::Reopen), None, None) => Some(findings::Act::Reopen),
                (Some(FindingVerb::Reopen), ..) => {
                    return Err("reopen takes no reason and no days".to_string());
                }
            };
            Ok(Cmd::Finding(FindingArgs {
                store: options.store()?,
                form: options.form(),
                id: words[0].clone(),
                act,
                via: via.unwrap_or(findings::Via::Command),
                with,
                journal_seq,
                typed,
            }))
        }
        "vulnerabilities" | "vulnerability" => {
            let mut words = Vec::new();
            options.read(it, |arg, _| {
                if arg.starts_with("--") {
                    return Err(format!("unexpected argument: {arg}"));
                }
                words.push(arg);
                Ok(())
            })?;
            let (store, form) = (options.store()?, options.form());
            match (cmd, words.as_slice()) {
                ("vulnerabilities", []) => Ok(Cmd::Vulnerabilities(VulnerabilityArgs {
                    store,
                    form,
                    id: None,
                })),
                ("vulnerability", [id]) => Ok(Cmd::Vulnerability(VulnerabilityArgs {
                    store,
                    form,
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
        "project" => project::parse(it, options).map(Cmd::Project),
        "program" => program::parse(it, options).map(Cmd::Program),
        "machine" => machine::parse(it, options).map(Cmd::Machine),
        "matches" => matches::parse(it, options).map(Cmd::Matches),
        "verdict" => verdict::parse(it, options).map(Cmd::Verdict),
        "on" => service::parse(service::Verb::On, it, options).map(Cmd::Service),
        "off" => service::parse(service::Verb::Off, it, options).map(Cmd::Service),
        "rules" => {
            let (mut over_log, mut system_root, mut all) = (false, None, false);
            options.read(it, |arg, it| {
                match arg.as_str() {
                    "--over-log" => over_log = true,
                    "--all" => all = true,
                    "--system-root" => system_root = Some(value(it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
                Ok(())
            })?;
            if system_root.is_some() && !over_log {
                return Err("--system-root is for immune rules --over-log".to_string());
            }
            if all && over_log {
                return Err(
                    "--all lists the shipped rules and does not go with --over-log".to_string(),
                );
            }
            Ok(Cmd::Rules(RulesArgs {
                store: options.store()?,
                form: options.form(),
                over_log: over_log.then(|| system_root.unwrap_or_else(|| PathBuf::from("/"))),
                all,
            }))
        }
        "sample" => {
            let mut input = None;
            options.read(it, |arg, it| {
                match arg.as_str() {
                    "--sample-input" => input = Some(value(it, &arg)?.into()),
                    _ => return Err(format!("unexpected argument: {arg}")),
                }
                Ok(())
            })?;
            Ok(Cmd::Sample(SampleArgs {
                store: options.store()?,
                form: options.form(),
                input,
            }))
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

/// The machine the store's readings of this Mac are scoped to, and on a store no full run or
/// watcher has read yet, this Mac by its name as a run names it. A sample, the watcher's
/// reading of the event level and a verdict that raises a finding of a match all take it from
/// here, so what they record is about one Mac.
pub fn this_machine_or_named(conn: &rusqlite::Connection) -> rusqlite::Result<String> {
    Ok(covered::this_machine(conn)?.unwrap_or_else(|| format!("machine:{}", machine_name())))
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

/// The value of a flag that may be given once, with a value that is not empty.
fn once(
    slot: &mut Option<String>,
    it: &mut impl Iterator<Item = String>,
    arg: &str,
) -> Result<(), String> {
    let v = value(it, arg)?;
    if v.is_empty() {
        return Err(format!("{arg} needs a value that is not empty"));
    }
    if slot.replace(v).is_some() {
        return Err(format!("{arg} is given once"));
    }
    Ok(())
}

/// The value of `--via`: who gives an answer or a statement.
fn via_value(it: &mut impl Iterator<Item = String>, arg: &str) -> Result<findings::Via, String> {
    match value(it, arg)?.as_str() {
        "app" => Ok(findings::Via::App),
        "agent" => Ok(findings::Via::Agent),
        _ => Err("--via takes app or agent".to_string()),
    }
}

/// The value of `--via`, given once: a second says two things of who gave it.
fn via_once(
    before: Option<findings::Via>,
    it: &mut impl Iterator<Item = String>,
    arg: &str,
) -> Result<findings::Via, String> {
    let via = via_value(it, arg)?;
    if before.is_some() {
        return Err(format!("{arg} is given once"));
    }
    Ok(via)
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Asked for, the help is the answer: on stdout, with exit 0. The whole of it alone, or one
    // command's as `immune help <command>` or `immune <command> --help`.
    let help = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--help" | "-h" | "help"] => Some(usage::help(&screen::Screen::of_stdout())),
        ["help", name] | [name, "--help" | "-h"] => {
            usage::command_help(name, &screen::Screen::of_stdout())
        }
        _ => None,
    };
    if let Some(help) = help {
        print!("{help}");
        return ExitCode::SUCCESS;
    }
    // Help asked for a word that is not a command: that word is named, not `help`.
    if let ["help", name] = args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        eprint!(
            "{}",
            usage::unknown(Some(name), &screen::Screen::of_stderr())
        );
        return ExitCode::from(EXIT_USAGE);
    }
    if args.first().is_some_and(|arg| arg == background::CHECK_ARG) {
        let [_, parent, op, ..] = args.as_slice() else {
            return ExitCode::from(EXIT_USAGE);
        };
        if op != "run" {
            return ExitCode::from(EXIT_USAGE);
        }
        if let Err(e) = background::supervise(parent) {
            eprintln!("immune: {e}");
            return ExitCode::FAILURE;
        }
        args.drain(..2);
    }
    let op = args.first().map(String::as_str);
    let mut options = answer::Options::default();
    let mut finding_write = false;
    let cmd = match parse_args(
        op,
        args.iter().skip(1).cloned(),
        &mut options,
        &mut finding_write,
    ) {
        Ok(cmd) => cmd,
        Err(e) => {
            // Every command but `immune servers`, `immune view` and `immune watch` answers with a
            // message of the contract, and is refused with `Failure` in the form named.
            let contract = match op {
                Some("project") => Some("immune project ~/<folder> --json"),
                Some("program") => Some("immune program /Applications/<name>.app --json"),
                Some("machine") => Some("immune machine --json"),
                Some("matches") => Some("immune matches --json"),
                Some("findings") => Some("immune findings --json"),
                Some("finding") if !finding_write => Some("immune finding f0123456789 --json"),
                Some("finding") => Some("immune finding f0123456789 seen --json"),
                Some("verdict") => Some("immune verdict --json < verdict.json"),
                Some("status") => Some("immune status --json"),
                Some("run") => Some("immune run --json"),
                Some("rules") => Some("immune rules --json"),
                Some("vulnerabilities") => Some("immune vulnerabilities --json"),
                Some("vulnerability") => Some("immune vulnerability CVE-2023-4863 --json"),
                Some("owner") => Some("immune owner --json"),
                Some("sample") => Some("immune sample --json"),
                Some("on") => Some("immune on --json"),
                Some("off") => Some("immune off --json"),
                _ => None,
            };
            // For a person, the cause and the command as typed in its right form, never the whole
            // usage; no command, or a word that is none, also lists the commands in one line each.
            let screen = screen::Screen::of_stderr();
            let Some(op) = op.filter(|op| usage::is_command(op)) else {
                eprint!("{}", usage::unknown(op, &screen));
                return ExitCode::from(EXIT_USAGE);
            };
            let typed = &args[1..];
            let text = || usage::misuse(op, typed, &e, &screen);
            if let Some(example) = contract {
                let error = answer::error(
                    "usage",
                    "the command line is not one Immune understands; the usage is on stderr",
                    example,
                    &e,
                );
                let form = options.form();
                let exit = answer::fail_as(op, form, error, EXIT_USAGE, |_| text());
                // In a machine form the message says the usage is on stderr, and it is: what was
                // wrong with the command typed, then the command's own help.
                if form != answer::Form::Text {
                    eprint!("{}", text());
                    if let Some(help) = usage::command_help(op, &screen) {
                        eprint!("\n{help}");
                    }
                }
                return exit;
            }
            // `immune watch` answers only in machine-readable lines.
            if op == "watch" {
                print_json(&status::failure(
                    Some(op),
                    "usage",
                    "the command line is not one Immune understands; the usage is on stderr",
                    "immune watch",
                    &e,
                ));
            }
            eprint!("{}", text());
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match cmd {
        Cmd::Run(args) => return run_cmd(&args),
        Cmd::Status(args) => return status_cmd("status", &args.store, args.form, args.coverage),
        Cmd::Watch(args) => return watch::watch(&args),
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
        Cmd::Verdict(args) => return verdict::verdict_cmd(&args),
        Cmd::Service(args) => return service::service_cmd(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `immune servers` and `immune view` fail in the one form of an error, the store's
            // two conditions in the one wording every command gives them; what the failure
            // repeats of what it was given is cut.
            let error = contract::v1::Error {
                code: "command_failed".to_string(),
                message: format!("immune {} could not finish", op.unwrap_or_default()),
                detail_text: Some(secrets::said(&e.to_string())),
                ..Default::default()
            };
            eprint!("{}", text::error(&error, &screen::Screen::of_stderr()));
            ExitCode::FAILURE
        }
    }
}

// ---- `immune sample`: one sample of this user's processes and connections, see
// `processes.rs`. ----

/// `immune sample`.
struct SampleArgs {
    store: PathBuf,
    form: answer::Form,
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
    // `immune sample` makes the store where there is none; a watcher's sample only opens it.
    drop(store::open_or_make(&args.store).map_err(|e| Stop::Store(e.to_string()))?);
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
    let machine = this_machine_or_named(&tx)?;
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
    match sample(args) {
        Ok(report) => {
            let mut m = report.message();
            m.answered_at = now_secs();
            m.store_id = store::open_read_only(&args.store)
                .ok()
                .and_then(|c| store::id(&c).ok());
            answer::print("sample", args.form, &m, |m| {
                after_run::sample(m, &screen::Screen::of_stdout())
            })
        }
        Err(e) => {
            let (error, exit) = match e.downcast_ref::<Stop>() {
                Some(stop) => answer::stopped(stop, "immune sample --json"),
                None => (
                    answer::error(
                        "sample_failed",
                        "the sample failed and nothing was committed to the store",
                        "immune sample --json",
                        &e.to_string(),
                    ),
                    1,
                ),
            };
            answer::fail("sample", args.form, error, exit)
        }
    }
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
    let machine = this_machine_or_named(&tx)?;
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

// ---- `immune rules`: the published rules, what they did, and a replay over the log. ----

/// `immune rules`: the shipped rules, placed, with whether they watch and how many times each
/// matched, from the store read without writing, and the catalogue: the core's own rules and the
/// causes of what is not covered, with their words. A store that is not there, or holds no
/// reading of the event level, gives no counts and says why in `not_computed`.
fn rules_cmd(args: &RulesArgs) -> ExitCode {
    if let Some(root) = &args.over_log {
        return replay_cmd(root, args.form);
    }
    let now = now_secs();
    let read = (|| -> Result<(Option<events::Level>, Option<String>), Stop> {
        if !args.store.exists() {
            return Ok((None, None));
        }
        let unreadable = |e: rusqlite::Error| Stop::Store(e.to_string());
        let conn = store::open_read_only(&args.store).map_err(|e| Stop::Store(e.to_string()))?;
        Ok((
            events::level(&conn, now).map_err(unreadable)?,
            Some(store::id(&conn).map_err(unreadable)?),
        ))
    })();
    let (level, store_id) = match read {
        Ok(read) => read,
        Err(e) => {
            let (error, exit) = answer::stopped(&e, "immune rules --json");
            return answer::fail("rules", args.form, error, exit);
        }
    };
    let mut m = sigma::Rules::shipped().message(
        level
            .as_ref()
            .map(|l| (&l.matches_last_day, &l.matches_last_week)),
    );
    m.format = 1;
    m.answered_at = now;
    m.store_id = store_id;
    m.now = Some(status::rules_now(level.as_ref()));
    m.matches_last_week = level
        .as_ref()
        .map(|l| l.matches_last_week.values().sum::<i64>().max(0) as u64);
    if level.is_none() {
        let reason = if args.store.exists() {
            "program starts have not been looked for yet; the next check does"
        } else {
            store::NO_STORE_REASON
        };
        m.not_computed.push(contract::v1::NotComputed {
            section: "matches".to_string(),
            reason: reason.to_string(),
        });
    }
    // Every rule of the core's own and every cause of what is not covered, with its words, for an
    // agent to learn what each can say.
    m.catalogue = Some(findings::catalogue());
    answer::print("rules", args.form, &m, |m| {
        lists::rules(m, args.all, &screen::Screen::of_stdout())
    })
}

/// `immune rules --over-log`: the rules evaluated over the event log on disk now, from the start
/// of every file, the store neither read nor written. Per rule that matched, its level and how
/// many starts matched; never a command line, a path or an argument. A level that is not
/// installed is not applicable, not a failure.
fn replay_cmd(root: &Path, form: answer::Form) -> ExitCode {
    use contract::v1;
    let mut m = v1::Replay {
        format: 1,
        answered_at: now_secs(),
        ..Default::default()
    };
    match events::replay(root, now_secs()) {
        events::Replay::NotInstalled => {
            m.outcome = v1::ReplayOutcome::NotApplicable as i32;
            m.reason = Some("the event level is not installed".to_string());
        }
        events::Replay::Failed(why) => {
            let error = answer::error(
                "log_unreadable",
                "the event log could not be read, so nothing was evaluated",
                "immune rules --over-log --json",
                &why,
            );
            return answer::fail("rules", form, error, 1);
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
            let n = |x: i64| x.max(0) as u64;
            m.outcome = v1::ReplayOutcome::Read as i32;
            m.program_starts = Some(n(tally.starts));
            m.unreadable_lines = Some(n(tally.unreadable));
            m.lost = Some(n(tally.lost));
            m.unknown_losses = Some(n(tally.unknown_gaps));
            m.file_events = Some(n(file_tally.files));
            m.file_events_lost = Some(n(file_tally.lost));
            m.unreadable_file_events = Some(n(file_tally.unreadable));
            m.matches_total = Some(hits.iter().map(|h| n(h.count)).sum());
            m.matched = hits
                .iter()
                .map(|h| v1::ReplayMatch {
                    rule: Some(matches::rule(
                        sigma::Rules::shipped()
                            .by_id(&h.meta.id)
                            .map_or("", |l| l.file),
                        h.meta,
                    )),
                    status: h.meta.status.as_str().to_string(),
                    matches: n(h.count),
                })
                .collect();
        }
    }
    answer::print("rules", form, &m, |m| {
        lists::replay(m, &screen::Screen::of_stdout())
    })
}

// ---- End of `immune rules`. ----

/// Now, in UTC seconds.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The contract's `Status` for `store` at `now`, read in one read transaction, so that every
/// number is of one state of the store: a run that commits meanwhile waits for it, and it never
/// sees half a run. Without a store it is the answer that there is none; a store that cannot be
/// read, or that a newer build wrote, is a failure.
fn status_answer(store: &Path, now: i64) -> Result<contract::v1::Status, Stop> {
    if !store.exists() {
        // No journal holds a start, so no check of this store is said to be running.
        let path = std::path::absolute(store).unwrap_or_else(|_| store.to_path_buf());
        return status::message(None, None, false, &path, now)
            .map_err(|e| Stop::Store(e.to_string()));
    }
    status_read(store, now).map(|(_, m)| m)
}

/// What the store holds and the contract's `Status` built from it, of one state of the store.
fn status_read(store: &Path, now: i64) -> Result<(status::State, contract::v1::Status), Stop> {
    let unreadable = |e: Box<dyn Error>| Stop::Store(e.to_string());
    let path = std::path::absolute(store).unwrap_or_else(|_| store.to_path_buf());
    let conn = store::open_read_only(store).map_err(unreadable)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Stop::Store(e.to_string()))?;
    let st = status::state(&tx, &home(store), now).map_err(unreadable)?;
    // Running is said only of the latest start this state of the store holds, by its own lock.
    let running = match &st.last {
        Some(l) => osv::check_in_progress(&home(store), &l.id).map_err(|e| unreadable(e.into()))?,
        None => false,
    };
    let m = status::message(Some(&tx), Some(&st), running, &path, now).map_err(unreadable)?;
    Ok((st, m))
}

/// `immune status`, and `immune run` once its check finished: the contract's `Status` in the
/// form asked.
fn status_cmd(op: &str, store: &Path, form: answer::Form, coverage: bool) -> ExitCode {
    match status_answer(store, now_secs()) {
        Ok(m) => answer::print(op, form, &m, |m| {
            overview::status(m, &screen::Screen::of_stdout(), coverage)
        }),
        Err(e) => {
            let (error, exit) = answer::stopped(&e, "immune status --json --store <file>");
            answer::fail(op, form, error, exit)
        }
    }
}

/// `immune run`: the check, then the same answer as `immune status`, read back from the store it
/// committed, so the two cannot differ; for a person that answer told as the run's
/// (`after_run::run`), with a line on standard error while the check runs.
fn run_cmd(args: &Args) -> ExitCode {
    let text = args.form == answer::Form::Text;
    let running = text.then(|| after_run::Running::start(&screen::Screen::of_stdout()));
    let done = run(args);
    drop(running);
    match done {
        Ok(_) if !text => status_cmd("run", &args.store, args.form, false),
        Ok(_) => match status_answer(&args.store, now_secs()) {
            Ok(m) => answer::print("run", args.form, &m, |m| {
                after_run::run(m, &screen::Screen::of_stdout())
            }),
            Err(e) => {
                let (error, exit) = answer::stopped(&e, "immune run --json");
                answer::fail("run", args.form, error, exit)
            }
        },
        Err(e) => match e.downcast_ref::<Stop>() {
            Some(stop) => {
                let (error, exit) = answer::stopped(stop, "immune run --json");
                answer::fail("run", args.form, error, exit)
            }
            None => answer::fail(
                "run",
                args.form,
                answer::error(
                    "run_failed",
                    "the run failed and nothing it read was committed to the store",
                    "immune run --json",
                    &e.to_string(),
                ),
                1,
            ),
        },
    }
}

/// The store's folder: raw input and the view live next to the store.
fn home(store: &Path) -> PathBuf {
    match store.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// `immune findings`: every finding as the contract's `Findings`; for a person the open
/// findings, or every one, with when each was last seen and where.
fn findings_cmd(args: &FindingsArgs) -> ExitCode {
    known::command(
        "findings",
        &args.store,
        args.form,
        |conn, now| finding_answer::list(conn, now).map(Ok),
        |m| overview::findings(m, args.all, &screen::Screen::of_stdout()),
    )
}

/// `immune vulnerabilities` and `immune vulnerability <id>`: the answers matching gave, read
/// only, as the contract's `Vulnerabilities` and `Vulnerability`. Without a store there is
/// nothing to count, and the answer says so.
fn vulnerabilities_cmd(args: &VulnerabilityArgs) -> ExitCode {
    let op = if args.id.is_some() {
        "vulnerability"
    } else {
        "vulnerabilities"
    };
    let failed = |detail: String| {
        let (error, exit) = answer::stopped(&Stop::Store(detail), "immune vulnerabilities --json");
        answer::fail(op, args.form, error, exit)
    };
    let now = now_secs();
    let conn = match args.store.exists() {
        false => None,
        true => match store::open_read_only(&args.store) {
            Ok(conn) => Some(conn),
            Err(e) => return failed(e.to_string()),
        },
    };
    match &args.id {
        None => match vulnerabilities::list(conn.as_ref(), now) {
            Ok(m) => answer::print(op, args.form, &m, |m| {
                answers_text::vulnerabilities(m, &screen::Screen::of_stdout())
            }),
            Err(e) => failed(e.to_string()),
        },
        Some(id) => match vulnerabilities::one(conn.as_ref(), id, now) {
            Ok(m) => answer::print(op, args.form, &m, |m| {
                answers_text::vulnerability(m, &screen::Screen::of_stdout())
            }),
            Err(e) => failed(e.to_string()),
        },
    }
}

/// `immune finding <id>`: one finding with what it rests on; after the owner's answer to it, the
/// same finding as it stands then. A refusal and a failure are the contract's `Failure`.
fn finding_cmd(args: &FindingArgs) -> ExitCode {
    // An id the store has no finding for that is not the shape of one is told as such, and not
    // only as one the store lacks. It is checked after the store, so that every finding the
    // store holds is read and answered whatever its id.
    const NOT_AN_ID: &str = "this is not a finding's id: an id is f and ten hexadecimal digits, as immune findings lists them";
    let not_an_id = !findings::is_finding_id(&args.id);
    let read = || {
        let next = usage::finding_next(&args.typed, usage::FindingNext::List);
        known::command_told(
            "finding",
            &args.store,
            args.form,
            |conn, now| {
                finding_answer::one(conn, &args.id, None, now).map(|one| {
                    one.map_err(|refused| match not_an_id {
                        true => known::Refused {
                            message: NOT_AN_ID,
                            ..refused
                        },
                        false => refused,
                    })
                })
            },
            |m| finding_text::finding(m, &screen::Screen::of_stdout()),
            |f| text::refusal(f, &next, &screen::Screen::of_stderr()),
        )
    };
    let Some(act) = &args.act else {
        return read();
    };
    let store_failed = |e: &Stop| {
        let (error, exit) = answer::stopped(e, "immune finding <id> seen");
        answer::fail("finding", args.form, error, exit)
    };
    // No store is told as every command of the contract tells it, with exit code 3.
    if !args.store.is_file() {
        return store_failed(&Stop::Store(store::absent(&args.store)));
    }
    let now = now_secs();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let run_id = format!("owner-{now}-{nanos:09}");
    // It writes as `immune verdict` does: under the run lock, with the write lock from the
    // start of its transaction, and a store another writer holds is asked again.
    let busy = |r: verdict::Refusal| {
        let error = answer::error(r.code, r.message, "immune finding <id> seen", &r.detail);
        answer::fail("finding", args.form, error, r.exit)
    };
    let (lock, mut conn) = match verdict::writing(&args.store) {
        Ok(held) => held,
        Err(r) => return busy(r),
    };
    // Everything that can refuse is decided in the transaction, and the answer printed is read in
    // it too, before the commit: a command that is refused, by a check or by the read, has
    // written nothing, and one that wrote cannot be refused afterwards.
    let answered = (|| -> Result<Result<contract::v1::Finding, known::Refused>, Box<dyn Error>> {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // With `--with`, the same answer to the other finding of the pair, in the same
        // transaction: both are recorded or neither is. Each keeps its own answer, as one given
        // alone; the shared run id says they were given together.
        let mut ids = vec![args.id.as_str()];
        if let Some(with) = &args.with {
            findings::pair(&tx, &args.id, with, now)?;
            ids.push(with);
        }
        // An answer that names what it was read at is refused when anything joined either
        // finding since that the answer did not already take in, before it writes anything.
        if let Some(seq) = args.journal_seq {
            findings::unchanged(&tx, &ids, seq, act, now)?;
        }
        let act_on = |id: &str| match act {
            findings::Act::Answer(a) => findings::answer(&tx, id, a, args.via, now, &run_id),
            findings::Act::Reopen => findings::reopen(&tx, id, args.via, now, &run_id),
        };
        act_on(&args.id)?;
        if let Some(with) = &args.with {
            act_on(with).map_err(findings::of_with)?;
        }
        // The answer names the other finding as the command left it. It is read before the
        // commit, and a read that refuses commits nothing. No test reaches that branch: the
        // write and the read take a finding by the same predicate (`findings::shown`), so a
        // finding the write accepts the read shows. The branch stays so that a later difference
        // between the two refuses with nothing written, never after a commit.
        let left = finding_answer::one(&tx, &args.id, args.with.as_deref(), now)?;
        if left.is_ok() {
            tx.commit()?;
        }
        Ok(left)
    })();
    // A refusal about the finding named by `--with` quotes its id, and has the code it would
    // have about the finding the answer is for.
    let refusal = |r: findings::Refused| {
        let message = match r {
            findings::Refused::Unknown if not_an_id => NOT_AN_ID.to_string(),
            _ => format!("{r}; nothing was changed"),
        };
        let (about, detail) = match &r {
            findings::Refused::With(about) => (&**about, args.with.as_deref()),
            findings::Refused::NotPair => (&r, args.with.as_deref()),
            findings::Refused::ChangedSinceRead(id) => (&r, Some(id.as_str())),
            _ => (&r, None),
        };
        // For a person, the command to run next is the one typed in its right form: the
        // finding read again where what changed has to be seen first, the answer taken back
        // where it was given, and the other finding left for the person to name where that one
        // was refused (`usage::finding_next`).
        use usage::FindingNext as Next;
        let with_refused = matches!(r, findings::Refused::With(_) | findings::Refused::NotPair);
        let (code, example, next) = match about {
            findings::Refused::ChangedSinceRead(_) => (
                "changed_since_read",
                "immune finding <id> --json, then answer with its journal_seq: immune finding <id> seen --with <other id> --journal-seq <n>",
                Next::Read,
            ),
            findings::Refused::ReadAhead => (
                "journal_seq_ahead",
                "immune finding <id> --json gives the journal_seq to answer with",
                Next::Read,
            ),
            findings::Refused::Unknown => (
                "unknown_finding",
                "immune findings --all lists every finding with its id; then: immune finding <id> seen",
                if with_refused {
                    Next::OtherId
                } else {
                    Next::List
                },
            ),
            findings::Refused::NotPair => (
                "not_the_pair",
                "immune finding <id> --json names the response layer's finding about the same rule and thing in verdicts.verdict_finding",
                Next::OtherId,
            ),
            findings::Refused::NotAnswered(_) => (
                "finding_not_answered",
                "immune findings --all lists every finding with its state",
                if with_refused {
                    Next::OtherId
                } else {
                    Next::Read
                },
            ),
            findings::Refused::Closed(state) => (
                "finding_closed",
                "immune findings lists the open findings",
                match state.as_str() {
                    _ if with_refused => Next::OtherId,
                    "seen" => Next::Reopen,
                    _ => Next::Read,
                },
            ),
            _ => (
                "finding_closed",
                "immune findings lists the open findings",
                Next::Read,
            ),
        };
        let error = answer::error(code, &message, example, detail.unwrap_or_default());
        let next = usage::finding_next(&args.typed, next);
        answer::fail_as("finding", args.form, error, EXIT_USAGE, |f| {
            text::refusal(f, &next, &screen::Screen::of_stderr())
        })
    };
    drop(conn);
    drop(lock);
    match answered {
        Ok(Ok(m)) => answer::print("finding", args.form, &m, |m| {
            finding_text::answered(m, &screen::Screen::of_stdout())
        }),
        Ok(Err(refused)) => answer::fail("finding", args.form, refused.error(), EXIT_USAGE),
        Err(e) => match e.downcast::<findings::RefusedError>() {
            Ok(r) => refusal(r.0),
            Err(e) => match e.downcast::<rusqlite::Error>() {
                Ok(e) => match verdict::Refusal::from(*e) {
                    r if r.code == "run_in_progress" => busy(r),
                    r => store_failed(&Stop::Store(r.detail)),
                },
                Err(e) => match e.downcast_ref::<Stop>() {
                    Some(stop) => store_failed(stop),
                    None => store_failed(&Stop::Store(e.to_string())),
                },
            },
        },
    }
}

fn view(args: &ViewArgs) -> Result<(), Box<dyn Error>> {
    if !args.store.is_file() {
        return Err(store::absent(&args.store).into());
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
    let (state, result) = status_read(store, now)?;
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
    let (state, result) = status_read(store, now)?;
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
            traces::Found::Failed(reason) => said.push(trace_failed(kind, reason)),
            traces::Found::Off(why) => said.push(format!("{kind}: not read, {why}")),
            traces::Found::Guarded(folder) => said.push(format!(
                "{kind}: not read, it leads into {}, which macOS asks permission for",
                known::whole(&guarded::shown(folder, &args.home))
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
                    line.push_str(&format!(", {}", secrets::said(partial)));
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
            Err(e) => said.push(format!(
                "{SWEEP_FILE}s: could not be read, {}",
                secrets::said(&e)
            )),
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
                known::whole(&w.contradiction().unwrap_or_default())
            )
        } else if let Some(first) = offered.first() {
            let rest: Vec<String> = with_alias
                .iter()
                .filter(|a| *a != first)
                .map(|a| match sweep::not_offered(a, &skip) {
                    Some(why) => format!("{} ({why})", known::whole(a)),
                    None => known::whole(a),
                })
                .collect();
            // The alias visited is the server's name in the row, so it is not said again.
            let mut sweep = "visited".to_string();
            if !rest.is_empty() {
                sweep.push_str(&format!("; not again as {}", rest.join(", ")));
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
    sweep::write(&s.dir, &s.machines)?;
    let (offered, rest): (Vec<&ServerRow>, Vec<&ServerRow>) =
        s.rows.iter().partition(|r| !r.offered.is_empty());
    // The sweep and the last file are put together with names and cut reasons already shown
    // (`survey`, `last_file`); a name alone is shown here.
    let listed = |rows: &[&ServerRow]| -> Vec<lists::Server> {
        rows.iter()
            .map(|r| lists::Server {
                name: known::whole(&r.name),
                known_from: r.traces.join(", "),
                sweep: r.sweep.clone(),
                last_file: r.file.clone(),
                others: known::whole(&r.others.join(", ")),
            })
            .collect()
    };
    let shown = lists::Servers {
        offered: listed(&offered),
        rest: listed(&rest),
        set_aside: s
            .standing
            .iter()
            .filter(|w| w.seen.is_none())
            .map(|w| lists::SetAside {
                machine: known::whole(w.name()),
                said: w.word.said.clone(),
                at: w.word.made_at,
                reason: w.word.reason.said(),
                others: known::whole(&w.names[1..].join(", ")),
            })
            .collect(),
        own: names(&s.own)
            .into_iter()
            .map(|r| [r[0].clone(), r[1].clone(), r[2].clone()])
            .collect(),
        theirs: names(&s.theirs)
            .into_iter()
            .map(|r| [r[0].clone(), r[1].clone()])
            .collect(),
        said: s.said.clone(),
        summary: format!(
            "{} known, {} of them under several names, {} offered for the sweep, {} left out as code hosting, {} as your other devices, {} as other users' devices, {} known and never read.",
            things(s.rows.len() as i64, "server", "servers"),
            s.several_names,
            offered.len(),
            s.third_party,
            s.own.len(),
            s.theirs.len(),
            s.rows.iter().filter(|r| !r.read).count()
        ),
        owner_word: word_line(&s.standing),
        spare: s.machines.iter().map(|m| m.len() as u64 - 1).sum(),
        never_read: s.rows.iter().filter(|r| !r.read).count() as u64,
        folder: known::whole(&s.dir.display().to_string()),
        // The script's path as the shell reads it back, or where it is when that cannot be shown.
        sweep_command: format!(
            "sh {}",
            s.dir
                .join("sweep.sh")
                .to_str()
                .and_then(text::shell_word)
                .unwrap_or_else(|| "<folder>/sweep.sh".to_string())
        ),
    };
    print!("{}", lists::servers(&shown, &screen::Screen::of_stdout()));
    Ok(())
}

/// Rows of names alone, as every surface shows a name: a backslash written `\u{5c}`, so none
/// reads as a mark (`known::whole`).
fn names(rows: &[Vec<String>]) -> Vec<Vec<String>> {
    rows.iter()
        .map(|row| row.iter().map(|cell| known::whole(cell)).collect())
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

/// Makes or withdraws a statement, or lists those that stand: the contract's `StatementMade` or
/// `Statements`, in the form asked. A refusal and a failure are its `Failure`.
fn owner_cmd(args: &OwnerArgs) -> ExitCode {
    use contract::{v1, value_of};
    // A refusal's message is the core's own words; what was asked, which may hold a secret, is
    // its `detail_text`, cut in every form.
    let refused = |code: &str, message: &str, example: &str, detail: &str, exit: u8| {
        answer::fail(
            "owner",
            args.form,
            answer::error(code, message, example, detail),
            exit,
        )
    };
    let failed = |e: &dyn std::fmt::Display| {
        let (error, exit) = answer::stopped(&Stop::Store(e.to_string()), "immune owner --json");
        answer::fail("owner", args.form, error, exit)
    };
    let store_path = &args.servers.store;
    if !store_path.is_file() {
        return refused(
            "no_store",
            "there is no store at the path given; `immune run` makes it",
            "immune run --json",
            &store_path.display().to_string(),
            EXIT_STORE,
        );
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let at = now.as_secs() as i64;
    let Some((name, act)) = &args.act else {
        let listed = store::open_read_only(store_path).and_then(|conn| {
            Ok((
                owner::standing(&conn)?,
                owner::withdrawn(&conn)?,
                Some(store::id(&conn)?),
            ))
        });
        let (standing, withdrawn, store_id) = match listed {
            Ok(l) => l,
            Err(e) => return failed(&e),
        };
        let m = v1::Statements {
            format: 1,
            answered_at: at,
            store_id,
            statements: standing.iter().map(owner::statement).collect(),
            withdrawn: withdrawn.max(0) as u64,
        };
        return answer::print("owner", args.form, &m, |m| {
            lists::statements(m, &screen::Screen::of_stdout())
        });
    };
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
                "the store knows no machine by the name asked; nothing was said",
                "immune servers lists the machines the store knows",
                name,
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
                "the name asked fits several machines that are not known to be one; name one of them; nothing was said",
                "immune owner <full machine id> retired --reason <text>",
                &format!("{name} fits: {}", list.join("; ")),
                EXIT_USAGE,
            );
        }
        Err(e) => return failed(&e),
    };
    let mut m = v1::StatementMade {
        format: 1,
        answered_at: at,
        store_id: store::id(&conn).ok(),
        machine_text: known::whole(owner::bare(&entity)),
        names_text: machine
            .iter()
            .map(|n| known::whole(owner::bare(n)))
            .collect(),
        via: value_of::<v1::Via>(args.via.literal()),
        ..Default::default()
    };
    match act {
        Act::Say(said, reason) => {
            let (replaced, reason) = match owner::say(
                &mut conn, &entity, &machine, said, reason, args.via, at, &run_id,
            ) {
                Ok(n) => n,
                Err(e) => return failed(&e),
            };
            m.done = Some(v1::statement_made::Done::Said(v1::Said {
                said: said.to_string(),
                at,
                reason_text: reason.said(),
                reason_cuts: answer::reason_cuts(&reason),
                replaced: replaced as u64,
            }));
        }
        Act::Withdraw => {
            let withdrawn = match owner::withdraw(&mut conn, &machine, args.via, at, &run_id) {
                Ok(w) => w,
                Err(e) => return failed(&e),
            };
            if withdrawn.is_empty() {
                return refused(
                    "no_statement",
                    "no statement stands about the machine asked; nothing was withdrawn",
                    "immune owner --json lists the statements that stand",
                    name,
                    EXIT_USAGE,
                );
            }
            m.done = Some(v1::statement_made::Done::Withdrawn(v1::Withdrawn {
                statements: withdrawn
                    .iter()
                    .map(|(e, said)| v1::WithdrawnStatement {
                        machine_text: known::whole(owner::bare(e)),
                        said: said.clone(),
                    })
                    .collect(),
            }));
        }
    }
    drop(conn);
    m.sweep = Some(match rewrite_sweep(&args.servers) {
        Ok(n) => v1::SweepWritten {
            servers: Some(n as u64),
            problem_text: None,
        },
        Err(e) => v1::SweepWritten {
            servers: None,
            // What the failure said was cut where it was put together (`rewrite_sweep`).
            problem_text: Some(format!("the owner's word was kept, but {e}")),
        },
    });
    // The word is kept either way; a sweep script that could not be written again is a failure
    // a person is told on stderr as well, after what was done.
    let problem = m.sweep.as_ref().and_then(|s| s.problem_text.clone());
    let exit = answer::print("owner", args.form, &m, |m| {
        lists::statement_made(m, &screen::Screen::of_stdout())
    });
    if let Some(problem) = problem.filter(|_| args.form == answer::Form::Text) {
        eprintln!("immune: {problem}");
        return ExitCode::FAILURE;
    }
    exit
}

/// Writes the sweep script again after the owner's word changed, the way `immune servers`
/// writes it, so that no script on disk visits a machine the owner set aside. A script that
/// cannot be written again is removed. Returns how many servers it visits. A failure's words
/// are shown as they are: what the failure repeats is cut in them, and the path written as the
/// contract writes a name.
fn rewrite_sweep(args: &ServersArgs) -> Result<usize, Box<dyn Error>> {
    let written = survey(args).and_then(|s| {
        sweep::write(&s.dir, &s.machines)?;
        Ok(s.machines.len())
    });
    written.map_err(|e| {
        let script = home(&args.store).join("sweep").join("sweep.sh");
        let _ = std::fs::remove_file(&script);
        let left = if script.exists() {
            format!(
                "delete {} before you run it",
                known::whole(&script.display().to_string())
            )
        } else {
            "no sweep script is left; run `immune servers`".to_string()
        };
        format!(
            "the sweep script could not be written again ({}); {left}",
            secrets::said(&e.to_string())
        )
        .into()
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

/// The run lock for a full check, waiting up to `wait` for a reading or a command that holds the
/// store. The check holds the downloads, so no other full check is running: one that cannot take
/// the store is a failed run (`run_failed`), never another run in progress.
fn take_store(home: &Path, wait: std::time::Duration) -> Result<std::fs::File, Box<dyn Error>> {
    Ok(store::lock_run_for_check(home, wait)?
        .ok_or("the store was held by a reading or a command longer than a check waits")?)
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
    let _check = osv::lock_check(&home, &run_id)?;
    // The check has started, downloads and all: its start is written now, under the run lock
    // for that write alone, so that a status says from the first minute when it started.
    {
        let _lock = take_store(&home, store::CHECK_WAIT)?;
        let conn = store::open_or_make(&args.store).map_err(|e| Stop::Store(e.to_string()))?;
        store::journal_note(&conn, at, &run_id, "run_started", "")?;
    }
    let feeds = get_feeds(read_only.as_ref(), args, &home, at)?;
    let catalogue = get_catalogue(read_only.as_ref(), args)?;
    drop(read_only);
    // Held until the run returns. Whoever holds it now is a reading or a command, waited out.
    let _lock = take_store(&home, store::CHECK_WAIT)?;
    let mut conn = store::open_or_make(&args.store).map_err(|e| Stop::Store(e.to_string()))?;

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
    let (walked, walk_failure) = read_checkouts(&mut run, args)?;
    let from_agents = read_agent_folders(&mut run, args)?;
    let any_checkouts = walked.is_some() || !from_agents.is_empty();
    // One checkout found by both readers is read once.
    let mut found = walked.unwrap_or_default();
    let known: BTreeSet<String> = found.iter().map(|c| c.rel.clone()).collect();
    found.extend(from_agents.into_iter().filter(|c| !known.contains(&c.rel)));
    if any_checkouts {
        read_lockfiles(&mut run, args, &found)?;
    }
    let (watched, mut opened) = watch_places(&mut run, args, &found, None, walk_failure)?;
    // What was set aside as no longer read, by this run or by a watcher since the last run's
    // line, is said once, here: a watcher's own line is not where a person is told.
    let set_aside = lifecycle::set_aside(run.tx, run.run_id, Some(watched::READER))?;
    if set_aside > 0 {
        run.notes.push(format!(
            "No longer read by this version: what no row of its table of autorun points \
             names, {} set aside and not counted as removed.",
            things(set_aside as i64, "fact", "facts")
        ));
    }
    read_other_autoruns(&mut run, &args.home, &found, walk_failure)?;
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
    // The readings no page or answer asks for one by one any more are folded, under the run
    // lock still held; what the run did is committed, whatever comes of that.
    store::tidy(&conn);
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
        reading: &Applied,
        statements: &[Statement],
    ) -> rusqlite::Result<()> {
        let with_basis: Vec<(&str, &Statement)> = statements.iter().map(|s| (basis, s)).collect();
        let (tx, run_id) = (self.tx, r.run_id);
        let prefix = format!("checkout:{}/", self.machine);
        self.apply_judged(r, reading, &with_basis, &mut |e| match (
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
    match brew::read(args.brew_input.as_deref(), args.brew.as_deref(), &args.home) {
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
        // Not at the places this version looks: lost sight of when an earlier check read it,
        // else not installed, read in full with nothing there.
        brew::Found::NotInstalled => {
            let places = match args.brew.as_deref() {
                Some(at) => vec![at.display().to_string()],
                None => brew::places(),
            };
            if !tool_not_found(
                run,
                &reading,
                brew::BASIS,
                brew::NOT_INSTALLED,
                brew::NAME,
                &places,
            )? {
                run.notes
                    .push("Homebrew is not installed, nothing to read.".to_string());
            }
        }
        brew::Found::Failed(reason) => {
            run.readers += 1;
            let gap = Gap::of(Cause::Failed);
            run.apply(&reading, brew::BASIS, "none", Some(&reason), &gap, &[])?;
            run.notes.push(not_read_note("Homebrew", &reason));
        }
    }
    // Homebrew is looked for only at its two places, which no folder macOS asks permission
    // for holds; an earlier reading that met one is closed.
    not_looked_into_when_met(run, brew::READER, &[], &args.home)?;
    Ok(())
}

/// A tool this version looks for at fixed places and did not find there. With nothing its
/// reader wrote in force in the store, it is not installed: read in full, nothing there. With
/// facts its reader wrote still in force, an earlier check read it from somewhere this version
/// does not look: the reading is `none`, its reason names the places looked and says it was
/// read before, and the facts are kept. The store decides, not the caller's environment, so the
/// answer is the same whoever starts the check. Returns whether it was lost sight of.
fn tool_not_found(
    run: &mut Run,
    reading: &Reading,
    basis: &str,
    absent: &str,
    name: &str,
    places: &[String],
) -> rusqlite::Result<bool> {
    let held: bool = run.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM assertion
                        WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3)",
        rusqlite::params![reading.reader, reading.scope, reading.kind],
        |r| r.get(0),
    )?;
    if !held {
        run.apply(reading, basis, "full", Some(absent), &Gap::default(), &[])?;
        return Ok(false);
    }
    let reason = format!("{name}{}{}", tools::READ_BEFORE, places.join(", "));
    let gap = Gap::of(Cause::NotGiven);
    run.apply(reading, basis, "none", Some(&reason), &gap, &[])?;
    // The places are names of places, never cut: written as the contract writes a name, so no
    // backslash in one reads as a mark in the run's line (`known::whole`).
    let shown: Vec<String> = places.iter().map(|p| known::whole(p)).collect();
    run.notes.push(format!(
        "{name}{}{}; what was read from it is kept, not counted as removed.",
        tools::READ_BEFORE,
        shown.join(", ")
    ));
    Ok(true)
}

/// Retires the kinds of a reader this version no longer reads (`lifecycle::retire`), and says
/// so once in the run's line, in its own words: never as something removed.
fn retire(run: &mut Run, reader: &'static str, kinds: &[(&str, &str)]) -> rusqlite::Result<()> {
    let run_id = run.run_id.to_string();
    for (kind, why) in kinds {
        let reading = Reading {
            reader,
            scope: "",
            kind,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        let (facts, scopes) = lifecycle::retire(run.tx, &reading, why)?;
        if scopes > 0 {
            run.notes.push(format!(
                "No longer read by this version: {kind}, {} set aside and not counted as removed.",
                things(facts as i64, "fact", "facts")
            ));
        }
    }
    Ok(())
}

/// `dir` is the folder given on the command line; without one, the sweep folder next to
/// the store, which is there only once a sweep has been run.
fn read_servers(run: &mut Run, dir: Option<&Path>) -> Result<(), Box<dyn Error>> {
    retire(run, servers::READER, &servers::RETIRED)?;
    let default = run.home.join("sweep");
    let Some(dir) = dir.or(Some(&default)).filter(|d| d.is_dir()) else {
        run.notes.push(match dir {
            Some(dir) => format!(
                "No server files: {} is not a folder.",
                known::whole(&dir.display().to_string())
            ),
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
            run.notes.push(visit_note(&input.name, last, f));
        }
    }
    Ok(())
}

/// What the run's line says of a server whose latest visit failed. The reason is cut on its own
/// (`sweep::failed_visit`): the line is put together from cut pieces and never cut whole, which
/// could take the core's words with it. The name is a name, never cut, and written as the
/// contract writes one, so no backslash in it reads as a mark (`known::whole`).
fn visit_note(name: &str, last: Option<i64>, f: &servers::Failure) -> String {
    format!(
        "{} {}; {}",
        known::whole(name),
        last.map_or("was never read".to_string(), |t| format!(
            "was last read {}",
            view::utc(t)
        )),
        sweep::failed_visit(f.at, &f.reason)
    )
}

/// What `immune servers` says of a trace that could not be read: the reason cut on its own.
fn trace_failed(kind: &str, reason: &str) -> String {
    format!("{kind}: could not be read, {}", secrets::said(reason))
}

/// What the run's line says of a source that could not be read: the reason cut on its own.
fn not_read_note(what: &str, reason: &str) -> String {
    format!("{what} could not be read: {}.", secrets::said(reason))
}

/// A row of the watched places read for a place not read: why is what the reader's source said,
/// cut here, where it is put beside the core's words (`prefix`).
fn not_read_row(watched_as: &str, path: &str, prefix: &str, why: &str) -> Vec<String> {
    vec![
        "not read".to_string(),
        watched_as.to_string(),
        path.to_string(),
        format!("{prefix}{}", secrets::said(why)),
    ]
}

/// What the run's line says of folders that could not be listed: their names, never cut, each
/// written as the contract writes a name (`known::whole`).
fn unlisted_note(folders: &[String]) -> String {
    let shown: Vec<String> = folders.iter().map(|f| known::whole(f)).collect();
    format!("Folders that could not be listed: {}.", shown.join(", "))
}

type CheckoutWalk = (Option<Vec<checkouts::Checkout>>, Option<&'static str>);

/// Which checkouts are on this machine, with a reason if the walk failed. When its root is
/// not a folder its reading failed. A walk closes a checkout the store holds only where it
/// looked: one it went past (`Walk::went_past`), or one looked at where it was and not there.
/// A walk of a given folder leaves the checkouts outside it as they were. The folder given is
/// made real first (`checkouts::given`).
fn read_checkouts(run: &mut Run, args: &Args) -> Result<CheckoutWalk, Box<dyn Error>> {
    let home = &args.home;
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.clone());
    let given = (args.checkouts_root.as_ref()).map(|r| checkouts::given(r, home, &real_home));
    let root = given.as_ref().unwrap_or(home);
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader: checkouts::READER,
        scope: &machine,
        kind: checkouts::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    if !root.is_dir() {
        run.notes.push(format!(
            "Could not look for checkouts in {}: not a folder.",
            known::whole(&root.display().to_string())
        ));
        let reason = format!(
            "could not look for checkouts in {}: not a folder",
            root.display()
        );
        let gap = Gap::of(Cause::Failed);
        run.apply(&reading, checkouts::BASIS, "none", Some(&reason), &gap, &[])?;
        return Ok((
            None,
            Some("the checkout walk could not open its root folder"),
        ));
    }
    run.readers += 1;
    let mut walk = checkouts::walk(root, home);
    let homes = [home.as_path(), real_home.as_path()];
    // A checkout the store holds that the walk did not meet is kept as it was, nothing inside
    // it read, outside the folder the walk was given, and otherwise as looking again says.
    let prefix = format!("checkout:{machine}/");
    let met: BTreeSet<String> = walk.checkouts.iter().map(|c| c.rel.clone()).collect();
    let (mut kept, mut unknown) = (Vec::new(), Vec::new());
    for rel in store::live_subjects(run.tx, checkouts::READER)?
        .into_iter()
        .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
        .filter(|rel| !met.contains(rel))
    {
        if args.checkouts_root.is_some() && !home.join(&rel).starts_with(root) {
            kept.push(rel);
            continue;
        }
        match walk.look_again(&rel, home, root, &homes) {
            checkouts::Again::Found(path) => walk.checkouts.push(checkouts::Checkout { rel, path }),
            checkouts::Again::Gone => {}
            checkouts::Again::Moved => kept.push(rel),
            checkouts::Again::NotTold => {
                unknown.push(rel.clone());
                kept.push(rel);
            }
            checkouts::Again::Guarded(g) => {
                if !walk.guarded.contains(&g) {
                    walk.guarded.push(g);
                }
                kept.push(rel);
            }
        }
    }
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
    let failure = unlisted
        .as_ref()
        .map(|_| "the checkout walk could not list some folders");
    if unlisted.is_some() {
        run.notes.push(unlisted_note(&walk.unlisted));
    }
    // A folder that could not be listed or a known checkout that could not be looked at
    // failed; a walk limited to the folder given read what it was given, which does not hold
    // the rest of the home folder. The worse is the reading's cause.
    let reasons: Vec<(String, Cause)> = args
        .checkouts_root
        .iter()
        .map(|_| (checkouts::ONLY_GIVEN.to_string(), Cause::NotGiven))
        .chain(unlisted.map(|u| (u, Cause::Failed)))
        .chain((!unknown.is_empty()).then(|| {
            let rels = unknown.join(", ");
            let why =
                format!("known checkouts that could not be looked at, kept as they were: {rels}");
            (why, Cause::Failed)
        }))
        .collect();
    let gap = Gap::when(Cause::worst(reasons.iter().map(|(_, c)| *c)));
    let reason = (!reasons.is_empty()).then(|| {
        let said: Vec<&str> = reasons.iter().map(|(r, _)| r.as_str()).collect();
        said.join("; ")
    });
    let completeness = if reason.is_some() { "partial" } else { "full" };
    // Every checkout the store holds is in the statements or was looked for and is gone, so
    // the reading is compared whole, whatever its coverage says.
    let applied = Applied {
        completeness,
        reason: reason.as_deref(),
        gap: &gap,
        compared: "full",
    };
    run.apply_found(&reading, checkouts::BASIS, &applied, &statements)?;
    // The folders the walk listed in full and those it found in them: a checkout found later
    // in a folder listed before is new (`baseline.rs`).
    baseline::record(
        run.tx,
        checkouts::READER,
        checkouts::KIND,
        &run_id,
        run.at,
        &walk.listed.iter().map(Unit::whole).collect::<Vec<_>>(),
        &walk.seen.iter().map(Unit::whole).collect::<Vec<_>>(),
    )?;
    Ok((Some(walk.checkouts), failure))
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
            run.notes.push(not_read_note("Agent sessions", &reason));
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
    let applied = Applied {
        completeness,
        reason: reason.as_deref(),
        gap: &gap,
        compared: completeness,
    };
    run.apply_found(&reading, agent_folders::BASIS, &applied, &statements)?;
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
            // The command is not at the places this version looks: lost sight of when an
            // earlier check read it, else not installed.
            traces::Found::Absent(note) if reader == tailnet::READER => {
                let places = match args.tailscale.as_deref() {
                    Some(at) => vec![at.display().to_string()],
                    None => tailnet::places(&args.home),
                };
                tool_not_found(run, &reading, basis, note, tailnet::NAME, &places)?;
            }
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
                    .push(not_read_note(&format!("The {kind}"), &reason));
            }
            // Switched off by the owner: nothing was asked of it, what was known from it stays
            // as it was, and the source does not give it now. Said once, in what is not
            // covered, never as a reading that failed.
            traces::Found::Off(why) => {
                let gap = Gap::of(Cause::NotGiven);
                run.apply(&reading, basis, "none", Some(&why), &gap, &[])?;
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
        let reading = Reading {
            reader: lockfiles::READER,
            scope: &id,
            kind: lockfiles::KIND,
            run_id: &run_id,
            at: run.at,
            observed_at: run.at,
        };
        // A checkout opened with no lockfile in it is read in full with a note, so that it is
        // told from one never opened, and what an earlier reading found in it goes.
        let Some(o) = lockfiles::read(checkout, &id) else {
            run.apply(
                &reading,
                lockfiles::BASIS,
                "full",
                Some(lockfiles::NONE_FOUND_NOTE),
                &Gap::default(),
                &[],
            )?;
            continue;
        };
        let commit = lockfiles::commit(&checkout.path, &homes).unwrap_or_else(|g| {
            guarded.insert(g);
            "unknown".to_string()
        });
        for (path, size) in &o.lockfiles {
            manifest.push_str(&format!("{path}\t{size}\t{commit}\n"));
        }
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
    look: look::Look,
    /// Why the checkout's hooks were not looked at where they were: its `.git` is a file, or
    /// the checkout itself is no longer a folder there.
    elsewhere: Option<String>,
    /// The completeness, reason and cause the reading says, where its reader gives them.
    coverage: Option<(&'static str, Option<String>, Option<Cause>)>,
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

    /// Why a reading over this machine's checkouts is not whole, with its cause: the walk that
    /// finds them failed, or checkouts the store holds were not looked into.
    fn missed<'a>(&self, walk_failure: Option<&'a str>) -> Option<(&'a str, Cause)> {
        let omitted = !self.held.is_subset(&self.looked);
        walk_failure
            .map(|why| (why, Cause::Failed))
            .or(omitted.then_some(("known checkouts were not looked into", Cause::NotGiven)))
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

/// The entries a reading holds live about what `keep`, given the subject and the file's path
/// as ids name it, says was not read now: the statements to make again, with what they rested on.
fn kept(
    tx: &rusqlite::Transaction,
    r: &Reading,
    keep: impl Fn(&str, Option<&Unit>) -> bool,
) -> rusqlite::Result<Vec<Statement>> {
    let mut kept = Vec::new();
    let mut stmt = tx.prepare(
        "SELECT a.subject, a.predicate, a.object, a.source_ref, u.path, u.part FROM assertion a
         LEFT JOIN watched_unit u ON (u.kind, u.scope, u.subject) = (a.kind, a.scope, a.subject)
         WHERE a.layer = 'live' AND a.reader = ?1 AND a.scope = ?2 AND a.kind = ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![r.reader, r.scope, r.kind], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    for row in rows {
        let (subject, predicate, object, source_ref, path, part) = row?;
        let predicate = match predicate.as_str() {
            "watched_as" => "watched_as",
            "located_on" => "located_on",
            autorun::HOLDS => autorun::HOLDS,
            _ => continue,
        };
        // Every entry a reading of this format holds was recorded with its unit, in the
        // transaction that made it, and a unit's row is never taken out.
        let unit = path.map(|path| Unit {
            path,
            part: part.unwrap_or_default(),
        });
        if keep(&subject, unit.as_ref()) {
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
/// small run of the watched places alone calls it with nothing else, and with `only` the
/// readings, by scope and kind, that a change touched. Returns the rows printed under the
/// report line and how many findings it opened.
fn watch_places(
    run: &mut Run,
    args: &Args,
    checkouts: &[checkouts::Checkout],
    only: Option<&BTreeSet<watch::Reading>>,
    walk_failure: Option<&str>,
) -> Result<(Rows, usize), Box<dyn Error>> {
    let (rows, seen) = read_watched(run, args, checkouts, only, walk_failure)?;
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
///
/// With `only`, it makes only those readings, each whole, and writes coverage for them alone:
/// what it did not read keeps the coverage, and the time, of the reading that last read it.
fn read_watched(
    run: &mut Run,
    args: &Args,
    checkouts: &[checkouts::Checkout],
    only: Option<&BTreeSet<watch::Reading>>,
    walk_failure: Option<&str>,
) -> Result<(Rows, Vec<findings::Observed>), Box<dyn Error>> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let wanted = |scope: &str, kind: &str| {
        only.is_none_or(|o| o.contains(&(scope.to_string(), kind.to_string())))
    };
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
    // What an earlier run read and this build has no row for is closed as retired before any
    // reading compares with it: not shown as watched, never told as removed, and said once in
    // the run's line (`run`), the watcher's included. Only a reading of every place does it: a
    // build's rows change between runs, never between two looks of a watcher, which would pay
    // for it at every change.
    if only.is_none() {
        look::retire_unread(
            run.tx,
            &Reading {
                reader: watched::READER,
                scope: &machine,
                kind: "",
                run_id: &run_id,
                at: run.at,
                observed_at: run.at,
            },
        )?;
    }
    let mut placed = Vec::new();
    for (watched_as, kind) in watched::kinds() {
        if kind == watched::HOOK_KIND || !wanted(&machine, kind) {
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
        if !wanted(&scope, watched::HOOK_KIND) {
            continue;
        }
        let (look, elsewhere) = match watched::look_checkout(&c.path, &c.rel, &args.home) {
            watched::Hooks::GitFile => (look::Look::default(), Some(watched::GIT_FILE.to_string())),
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
        let scope = format!("checkout:{machine}/{rel}");
        if !wanted(&scope, watched::HOOK_KIND) {
            continue;
        }
        let why = format!("{rel} {}", checkouts::MOVED);
        placed.push(Placed {
            scope,
            watched_as: watched::HOOK,
            kind: watched::HOOK_KIND.to_string(),
            look: look::Look::default(),
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
    let omitted = !visited.held.is_subset(&visited.looked);
    for point in autorun::POINTS.iter().filter(|p| p.read_here()) {
        if !wanted(&machine, &point.kind()) {
            continue;
        }
        let (looked, kept, over) = match point.scope {
            autorun::Scope::Home => (
                autorun::look_all(point, [(args.home.as_path(), "")].into_iter(), &args.home),
                Vec::new(),
                Vec::new(),
            ),
            _ if !visited.looked_for && walk_failure.is_none() => continue,
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
                    kept(run.tx, &reading, |_, unit| match unit {
                        Some(unit) => visited.unvisited(&unit.path),
                        None => omitted,
                    })?,
                    rels.clone(),
                )
            }
        };
        let missed = visited
            .missed(walk_failure)
            .filter(|_| point.scope == autorun::Scope::Checkout);
        let (completeness, reason) = looked.coverage(point, missed.map(|(why, _)| why));
        let cause = (completeness != "full").then(|| match missed {
            _ if !looked.look.failed().is_empty() => Cause::Failed,
            Some((_, cause)) => cause,
            None => looked.look.cause(),
        });
        placed.push(Placed {
            scope: machine.clone(),
            watched_as: point.watched_as().unwrap_or_default(),
            kind: point.kind(),
            coverage: Some((completeness, reason, cause)),
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
                watched::field(&e.unit.to_string()),
                watched::field(&content),
                watched::field(link)
            ));
            n += 1;
            mine.push(n);
        }
        lines.push(mine);
    }
    // A reading of some places is kept apart from one of every place, so that neither is saved
    // again only because the other came between.
    let raw_name = if only.is_some() {
        watched::RAW_SOME
    } else {
        watched::RAW
    };
    let raw_file = run.keep_raw(watched::READER, raw_name, raw.as_bytes())?;
    // A place new in a new worktree, the same as in another checkout of its repository as this
    // reading read it, raises no finding (`worktrees.rs`).
    let siblings = worktrees::Siblings::of(run.tx, &machine, &run_id, checkouts, &args.home)?;
    let read: BTreeMap<&Unit, &watched::Entry> = placed
        .iter()
        .flat_map(|p| &p.look.entries)
        .map(|e| (&e.unit, e))
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
        let file_id = |unit: &Unit| format!("file:{machine}/{unit}");
        let prefix = format!("file:{machine}/");
        let path_of = |id: &str| id.strip_prefix(&prefix).unwrap_or(id).to_string();
        // The place a thing read for the first time is told by: its checkout, the folder that
        // was listed, or its file.
        let group = |unit: &Unit| {
            if let Some(c) = judge.checkout_of(&unit.path) {
                return c.to_string();
            }
            let folder = baseline::parent(&unit.path);
            if p.look
                .read_units()
                .iter()
                .any(|r| r.part.is_empty() && r.path == folder)
            {
                folder.to_string()
            } else {
                unit.path.clone()
            }
        };
        let mut statements = Vec::new();
        let mut units = HashMap::new();
        for (e, line) in p.look.entries.iter().zip(mine) {
            let subject = file_id(&e.unit);
            units.insert(subject.clone(), &e.unit);
            let source_ref = format!("{raw_file}:{line}");
            statements.push(Statement {
                subject: subject.clone(),
                predicate: "watched_as",
                object: e.watched_as.to_string(),
                source_ref: source_ref.clone(),
            });
            statements.push(Statement {
                subject,
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
        // What the reading may not retract keeps what was known of it (`look::Look::retracts`),
        // so that the rest of the reading is compared whole: what is gone from a unit read in
        // full is gone, whatever failed elsewhere. A part of a file that could not be read,
        // its neighbours read, keeps only its own. Hooks kept elsewhere keep all of theirs.
        statements.extend(kept(tx, &reading, |_, unit| {
            p.elsewhere.is_some() || !p.look.retracts(unit)
        })?);
        baseline::remember_units(tx, &reading, &units)?;
        let (completeness, reason) = if let Some(why) = &p.elsewhere {
            ("partial", Some(why.clone()))
        } else if p.kind == watched::HOOK_KIND && p.look.entries.is_empty() {
            match p.look.completeness() {
                ("full", _) => ("full", Some(watched::NO_HOOKS.to_string())),
                other => other,
            }
        } else if let Some((completeness, reason, _)) = &p.coverage {
            (*completeness, reason.clone())
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
        } else if let Some((_, _, cause)) = &p.coverage {
            Gap::when(*cause)
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
            let Some(unit) = units.get(&e.subject) else {
                return Ok(Verdict::FirstRead);
            };
            let v = judge.verdict(unit)?;
            judged.insert(e.subject.clone(), v);
            Ok(v)
        })?;
        let mut new = BTreeSet::new();
        for (e, verdict) in events {
            match (verdict, e.kind, e.predicate.as_str()) {
                (Verdict::Change, "added", "watched_as") => {
                    let path = path_of(&e.subject);
                    let Some(unit) = units.get(&e.subject).copied() else {
                        continue;
                    };
                    let same = siblings.same_as(unit, &read);
                    let why = match &same {
                        Some((checkout, there)) => {
                            let content = read.get(unit).and_then(|e| e.content.literal());
                            let ids = (format!("checkout:{machine}/{checkout}"), file_id(there));
                            worktrees::journal(
                                run.tx, &reading, &e.subject, content, &ids.0, &ids.1,
                            )?;
                            format!("the same as in {}", known::whole(checkout))
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
                    let Some(unit) = units.get(&e.subject).copied() else {
                        continue;
                    };
                    if let Some((checkout, there)) = siblings.same_as(unit, &read) {
                        let content = read.get(unit).and_then(|e| e.content.literal());
                        let ids = (format!("checkout:{machine}/{checkout}"), file_id(&there));
                        worktrees::journal(run.tx, &reading, &e.subject, content, &ids.0, &ids.1)?;
                        continue;
                    }
                    *first_reads.entry((group(unit), p.watched_as)).or_default() += 1;
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
        let hooks = p
            .checkouts
            .first()
            .map(|c| Unit::whole(format!("{c}/.git/hooks")));
        let unread_now: Vec<(Unit, String)> = match (&p.elsewhere, &hooks) {
            (Some(why), Some(unit)) if judge.read_before(&unit.path)? => {
                vec![(unit.clone(), why.clone())]
            }
            (Some(_), _) => Vec::new(),
            (None, _) => p.look.not_read().cloned().collect(),
        };
        // A part of a file that could not be read is judged as itself, so that losing sight
        // of the whole file later is a change of its own.
        for (unit, why) in &unread_now {
            if baseline::judged_unread(tx, watched::READER, &p.kind, unit, &run_id)? {
                continue;
            }
            let id = file_id(unit);
            match judge.verdict(unit)? {
                Verdict::Change => {
                    lost_sight(run.tx, &reading, &id, why)?;
                    observe(findings::NOT_READ, p.watched_as, &id);
                }
                Verdict::FirstRead => {
                    *first_reads.entry((group(unit), p.watched_as)).or_default() += 1;
                }
                Verdict::Baseline => {}
            }
        }
        for (path, why) in p.look.failed() {
            rows.push(not_read_row(p.watched_as, &path.to_string(), "", why));
        }
        for (path, why) in p.look.unreached() {
            rows.push(not_read_row(
                p.watched_as,
                &path.to_string(),
                guarded::NOT_LOOKED_INTO,
                why,
            ));
        }

        for (e, line) in p.look.entries.iter().zip(mine) {
            let id = file_id(&e.unit);
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
                    .entry((group(&e.unit), e.watched_as))
                    .or_default() += 1;
            }
            if events.iter().any(|(_, v)| *v == Verdict::Change) && !new.contains(&id) {
                observe("changed", e.watched_as, &id);
                rows.push(vec![
                    "changed".to_string(),
                    e.watched_as.to_string(),
                    e.unit.to_string(),
                    String::new(),
                ]);
            }
            let content_unit = Unit::whole(&id);
            if completeness == "full" {
                baseline::read_again(tx, watched::READER, watched::CONTENT, &id)?;
            } else if lost
                && !baseline::judged_unread(
                    tx,
                    watched::READER,
                    watched::CONTENT,
                    &content_unit,
                    &run_id,
                )?
            {
                lost_sight(run.tx, &reading, &id, reason.unwrap_or_default())?;
                observe(findings::NOT_READ, e.watched_as, &id);
            }
            if let Some(why) = reason {
                rows.push(not_read_row(e.watched_as, &e.unit.to_string(), "", why));
            }
        }
        baseline::record(
            run.tx,
            watched::READER,
            &p.kind,
            &run_id,
            run.at,
            p.look.read_units(),
            p.look.seen_units(),
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
    // Which folders macOS asks permission for the reader met is said by a reading of every
    // place: one of some places did not meet those the others lead into.
    if only.is_none() {
        not_looked_into_when_met(run, watched::READER, &guarded, &args.home)?;
    }
    if placed.iter().any(|p| {
        !p.look.entries.is_empty()
            || !p.look.failed().is_empty()
            || !p.look.unreached().is_empty()
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
    let presence = (w.presence_only > 0).then(|| {
        format!(
            "; {} watched only for presence: {}",
            things(w.presence_only, "entry", "entries"),
            watched::PRESENCE_ONLY
        )
    });
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
    if let Some(presence) = presence {
        s.push_str(&presence);
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
    guarded.extend(read_managers(run, args)?);
    guarded.sort();
    guarded.dedup();
    not_looked_into_when_met(run, integrity::READER, &guarded, &args.home)?;
    Ok(integrity::observed(run.tx, &run_id)?)
}

/// The package managers on this Mac that no reader reads, named by kind: none read, with
/// what this build has no reader for; none, not given, when nothing was found but a place
/// leads into a folder macOS asks permission for; or full (`managers.rs`). Returns those
/// folders.
fn read_managers(run: &mut Run, args: &Args) -> rusqlite::Result<Vec<PathBuf>> {
    let (run_id, machine) = (run.run_id.to_string(), run.machine.to_string());
    let reading = Reading {
        reader: integrity::READER,
        scope: &machine,
        kind: managers::KIND,
        run_id: &run_id,
        at: run.at,
        observed_at: run.at,
    };
    let homes = watched::homes(&args.home);
    let homes = [homes[0].as_path(), homes[1].as_path()];
    let found = managers::found(&args.system_root, &homes);
    if !found.names.is_empty() {
        let reason = format!("{}{}", managers::NOT_READ, found.names.join(", "));
        let gap = Gap {
            cause: Some(Cause::NoReader),
            lacks: found
                .names
                .iter()
                .map(|name| Lack::new(managers::NO_READER, Some(name)))
                .collect(),
        };
        run.apply(&reading, integrity::BASIS, "none", Some(&reason), &gap, &[])?;
    } else if !found.guarded.is_empty() {
        let shown: Vec<String> = found
            .guarded
            .iter()
            .map(|g| guarded::shown(g, &args.home))
            .collect();
        let reason = format!("{}{}", guarded::NOT_LOOKED_INTO, shown.join(", "));
        let gap = Gap::of(Cause::NotGiven);
        run.apply(&reading, integrity::BASIS, "none", Some(&reason), &gap, &[])?;
    } else {
        run.apply(
            &reading,
            integrity::BASIS,
            "full",
            None,
            &Gap::default(),
            &[],
        )?;
    }
    Ok(found.guarded)
}

// ---- End of integrity of what is installed. ----

// ---- What runs by itself and indicators: see src/autorun.rs and src/indicators.rs. ----

/// Which known ways a project runs code by itself each checkout holds, and which places of
/// the home folder this machine holds, read here or not, as one reading of this machine; and
/// apart, as before, the ways present that this build does not read, each with how many
/// checkouts hold it, and the places of the home folder. What is held about a checkout the run
/// did not look into is kept, and a reading over checkouts is full only when every checkout
/// the store holds was looked into and the walk did not fail.
fn read_other_autoruns(
    run: &mut Run,
    home: &Path,
    found: &[checkouts::Checkout],
    walk_failure: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let (run_id, machine, at) = (run.run_id.to_string(), run.machine.to_string(), run.at);
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
    // What is held about a checkout this run did not look into is made again as it was, so
    // the rest is compared whole, and the reading says why it is not.
    let visited = Visited::of(run.tx, &machine, found)?;
    let prefix = format!("checkout:{machine}/");
    statements.extend(kept(run.tx, &present_kind, |subject, _| {
        subject
            .strip_prefix(&prefix)
            .is_some_and(|rel| visited.held.contains(rel) && !visited.looked.contains(rel))
    })?);
    let missed = visited.missed(walk_failure);
    let gap = Gap::when(missed.map(|(_, cause)| cause));
    let with_basis: Vec<(&str, &Statement)> =
        statements.iter().map(|s| (watched::BASIS, s)).collect();
    // The home folder is read whatever was missed, so the reading is never none.
    let applied = Applied {
        completeness: if missed.is_some() { "partial" } else { "full" },
        reason: missed.map(|(why, _)| why),
        gap: &gap,
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
    // The ways not read that checkouts hold, those kept as they were among them.
    let mut present: BTreeMap<String, usize> = BTreeMap::new();
    for s in statements.iter().filter(|s| s.subject.starts_with(&prefix)) {
        let way = autorun::ways().find(|(p, _)| p.name() == s.object);
        if way.is_some_and(|(p, _)| !p.read()) {
            *present.entry(s.object.clone()).or_default() += 1;
        }
    }
    let (completeness, reason, gap) = if present.is_empty() {
        match missed {
            Some((why, cause)) if found.is_empty() => {
                ("none", Some(why.to_string()), Gap::of(cause))
            }
            Some((why, cause)) => ("partial", Some(why.to_string()), Gap::of(cause)),
            None => ("full", None, Gap::default()),
        }
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

/// One sentence about the vulnerability data for the report line, with what matching found. It
/// speaks for the projects found: whether those are all of them is the status's to say.
fn feeds_sentence(states: &[osv::State], run_id: &str, t: &vulnerabilities::Totals) -> String {
    let clauses: Vec<String> = states.iter().map(|s| feed_clause(s, run_id)).collect();
    let mut matched = format!(
        "matched against the package-lock.json, pnpm-lock.yaml and Cargo.lock of the projects found: {} in packages they use",
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
    let (without_lockfile, not_read) = vulnerabilities::project_counts(&t.unread_places);
    matched.push_str(&text::not_wholly_read(
        not_read as u64,
        without_lockfile as u64,
    ));
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
            // What the download said: cut on its own, as every source's text in the run's line.
            let reason = secrets::said(reason.as_deref().unwrap_or_default());
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
        // What the download said: cut on its own, as every source's text in the run's line.
        Catalogue::Failed {
            reason,
            last: Some((at, total)),
            ..
        } => format!(
            "CISA catalogue not read: {}; what is new is unknown, and the {} it held at its last reading, {}, are {judged}.",
            secrets::said(reason),
            held(*total),
            view::utc(*at)
        ),
        Catalogue::Failed {
            reason, last: None, ..
        } => format!(
            "CISA catalogue not read: {}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown.",
            secrets::said(reason)
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

/// The run's line: the core's words and the notes, each put together from the core's words and
/// pieces of what sources said cut on their own (`secrets::said`). It is kept and printed as it
/// is and never cut whole, which could take the core's words with it.
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
            known::whole(&servers.seen.join(", "))
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
    fn a_check_waits_out_whoever_holds_the_store_past_two_seconds_and_else_fails_as_a_run() {
        // A reading or a verdict holds the run lock, no watcher among them. The check waits for
        // it longer than a command waits; when it still cannot take the store, it is a failed
        // run, never `run_in_progress`, which says another check is running when none is.
        let dir = std::env::temp_dir().join(format!(
            "immune-take-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let held = std::fs::File::open(&dir).unwrap();
        held.lock().unwrap();
        let failed = take_store(&dir, std::time::Duration::ZERO).unwrap_err();
        assert!(failed.downcast_ref::<Stop>().is_none(), "{failed}");
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(3));
                drop(held);
            });
            assert!(take_store(&dir, std::time::Duration::from_secs(10)).is_ok());
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
        let _removed = crate::common::Scratch::at(dir.clone());
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
            form: answer::Form::Text,
        };
        let count = |conn: &rusqlite::Connection| -> i64 {
            conn.query_row("SELECT COUNT(*) FROM session_file", [], |r| r.get(0))
                .unwrap()
        };
        let mut conn = store::open_or_make(&store_path).unwrap();
        {
            let tx = conn.transaction().unwrap();
            store::put_entity(&tx, "machine:mac").unwrap();
            let mut run = Run {
                tx: &tx,
                home: &dir,
                run_id: "run-1",
                at: 1,
                machine: "machine:mac",
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

    #[test]
    fn no_reason_a_source_gave_takes_a_word_of_the_core_s_from_the_run_s_line() {
        // A reason that leaves a quote open after `password:`, one over the cap the patterns read
        // and one cut while the patterns did not load each become a mark in their own place:
        // the counts, what needs a look, the name of every other server that failed, the advice
        // about a host key and the folders that could not be listed all stay, and the run prints
        // its line as it keeps it.
        let scratch = common::Scratch::new("run-line-pieces");
        let conn = store::open_or_make(&scratch.0.join("store.db")).unwrap();
        let mark = status::RunMark {
            id: "1767412800-000000000".to_string(),
            started_at: 1_767_412_800,
            finished_at: None,
        };
        let summary = status::summary(&conn, mark, &scratch.0).unwrap();
        let failed = |reason: String| servers::Failure {
            at: 1_767_412_800, // 2026-01-03 04:00:00 UTC
            reason,
        };
        let long = format!("refused {}", "x".repeat(secrets::LINE_CAP));
        let host_key = "Host key verification failed.".to_string();
        let notes = [
            visit_note("db-1", None, &failed("it's down, password: x".to_string())),
            visit_note("db-2", None, &failed(long.clone())),
            secrets::without_patterns(|| visit_note("db-3", None, &failed(host_key.clone()))),
            visit_note("db-4", Some(1_767_323_045), &failed(host_key.clone())),
            not_read_note("Homebrew", "it's down, password: x"),
            unlisted_note(&[
                "/Users/example/a".to_string(),
                "/Users/example/b\\c".to_string(),
            ]),
        ];
        let needs = needs_sentence(2, 1);
        let line = report(1, &notes, &summary, &needs);
        let advice = "Connect to this server once by hand and check its host key: the sweep never accepts a key for you.";
        let failed_at = "the latest visit failed 2026-01-03 04:00 UTC:";
        for words in [
            "1 reader, 0 checkouts, 0 components. No servers known. ".to_string(),
            format!(" {needs} db-1 "),
            format!("db-1 was never read; {failed_at} it's down, password:"),
            format!(
                "db-2 was never read; {failed_at} {}. db-3 ",
                secrets::mark(secrets::TOO_LONG, long.chars().count())
            ),
            format!(
                "db-3 was never read; {failed_at} {}. {advice} db-4 ",
                secrets::mark(secrets::NO_PATTERNS, 28)
            ),
            format!(
                "db-4 was last read 2026-01-02 03:04 UTC; {failed_at} Host key verification failed. {advice} Homebrew"
            ),
            format!(
                "Homebrew could not be read: it's down, password:{}. Folders",
                secrets::mark(secrets::FLAG_VALUE, 2)
            ),
            // Names are never cut, and a backslash in one is written as a source's.
            "Folders that could not be listed: /Users/example/a, /Users/example/b\\u{5c}c."
                .to_string(),
        ] {
            assert!(line.contains(&words), "{words}\n{line}");
        }
        assert!(needs.contains("2 things need a look"), "{needs}");
        assert_eq!(
            trace_failed("ssh known hosts", "it's down, password: x"),
            format!(
                "ssh known hosts: could not be read, it's down, password:{}",
                secrets::mark(secrets::FLAG_VALUE, 2)
            )
        );
        let named = visit_note("db\\5", None, &failed(host_key.clone()));
        assert!(named.starts_with("db\\u{5c}5 was never read; "), "{named}");
    }

    #[test]
    fn a_row_s_why_is_cut_where_it_is_put_beside_the_core_s_words() {
        // A row's why is cut where it is put beside the core's words (`read_watched`), so a mark
        // the core made stays its own and a source's backslash stays written as a source's.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let row = not_read_row(
            "shell profile",
            "/Users/example/.zshrc",
            guarded::NOT_LOOKED_INTO,
            &format!("?t={token} a\\cut{{x 1}}"),
        );
        let why = format!(
            "{}?t={} a\\u{{5c}}cut{{x 1}}",
            guarded::NOT_LOOKED_INTO,
            secrets::mark("gitleaks:github-pat", 40)
        );
        assert_eq!(row[3], why);
    }

    #[test]
    fn what_a_download_said_is_cut_in_the_run_s_line_and_the_core_s_words_around_it_stay() {
        // The catalogue's and a feed's reason is what curl or a parser said: a token in a URL is
        // cut, a mark it wrote stays its text, a password's value is cut, and the sentence
        // around each is the core's, whole.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let reason =
            format!("curl: (22) https://example.invalid/?t={token} \\cut{{x 1}} password: x");
        let cut = format!(
            "curl: (22) https://example.invalid/?t={} \\u{{5c}}cut{{x 1}} password:{}",
            secrets::mark("gitleaks:github-pat", 40),
            secrets::mark(secrets::FLAG_VALUE, 2)
        );
        let catalogue = status::Catalogue::Failed {
            reason: reason.clone(),
            last: None,
            at: 1_767_412_800,
        };
        assert_eq!(
            catalogue_sentence(Some(&catalogue), &[]),
            format!(
                "CISA catalogue not read: {cut}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown."
            )
        );
        let feed = osv::State {
            feed: &osv::FEEDS[0],
            latest: Some((
                "run".to_string(),
                1_767_412_800,
                "failed".to_string(),
                Some(reason),
            )),
            good_at: None,
            changed_at: None,
            records: 0,
            malicious: 0,
            withdrawn: 0,
            counts: None,
        };
        assert_eq!(
            feed_clause(&feed, "run"),
            format!(
                "{} not read: {cut}; nothing of it is known yet",
                osv::FEEDS[0].ecosystem
            )
        );
    }

    #[test]
    fn a_name_never_reads_as_a_mark_in_what_the_server_list_prints() {
        // A name is never cut, and its backslash is written as a source's: a server's names in
        // `immune servers`.
        let forged = "/Users/example/\\cut{gitleaks:github-pat 40}";
        let shown = "/Users/example/\\u{5c}cut{gitleaks:github-pat 40}";
        assert_eq!(
            names(&[vec![forged.to_string(), "linux".to_string()]]),
            [[shown.to_string(), "linux".to_string()]]
        );
    }
}
