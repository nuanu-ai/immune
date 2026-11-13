//! The `brew` reader: what Homebrew has installed, formulae and casks. Input is Homebrew's
//! machine form, `brew info --json=v2 --installed`, read with `serde_json`.
//!
//! A formula and a cask are different software even under one token, and a formula of a tap
//! is not the core formula of the same name. So the ecosystem says which of the two it is,
//! `brew` or `brew-cask`, and the name is Homebrew's full name: the bare name for the core
//! taps, `<user>/<tap>/<name>` for any other. A package Homebrew names no tap for would take
//! a core name without being from core: it is not recorded, and the reading is partial.
//!
//! Every installed version is kept: each keg of a formula, the one installed version of a
//! cask, as `brew list --versions` gives them.
//!
//! Homebrew's answer is most of a megabyte of metadata that changes with every update of
//! Homebrew. The raw copy keeps only what facts are made of: one line per package, a JSON
//! array of its kind, its full name, its tap and its versions. Facts are made from that copy.

use crate::store::Statement;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const READER: &str = "brew";
pub const KIND: &str = "brew packages";
pub const BASIS: &str = "observed";
/// The note on a full reading that had nothing to read.
pub const NOT_INSTALLED: &str = "Homebrew is not installed on this machine";
/// The name of the raw copy.
pub const RAW: &str = "brew.jsonl";

/// Where Homebrew puts `brew`: Apple Silicon, then Intel.
const STANDARD: [&str; 2] = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];
/// What a person calls it.
pub const NAME: &str = "Homebrew";

/// The places `brew` is looked for, as a reason names them.
pub fn places() -> Vec<String> {
    STANDARD.iter().map(|p| p.to_string()).collect()
}
/// The arguments that ask for every installed package in the machine form.
const ARGS: [&str; 3] = ["info", "--json=v2", "--installed"];
/// Homebrew's documented switches: do not update Homebrew itself, send no analytics.
const QUIET: [(&str, &str); 2] = [
    ("HOMEBREW_NO_AUTO_UPDATE", "1"),
    ("HOMEBREW_NO_ANALYTICS", "1"),
];

/// What reading Homebrew found.
pub enum Found {
    /// The raw copy: one line per installed package.
    Output(String),
    /// No `brew` here: nothing to read, which is not a failure.
    NotInstalled,
    /// `brew` is here and could not be read, with the reason.
    Failed(String),
}

/// `input` is a saved answer of brew to read instead of running it. `brew` is the one place
/// to look for brew instead of the standard places. `home` is the home folder.
pub fn read(input: Option<&Path>, brew: Option<&Path>, home: &Path) -> Found {
    let json = match input {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => return Found::Failed(format!("cannot read {}: {e}", path.display())),
        },
        None => {
            let Some(brew) = find(brew, home) else {
                return Found::NotInstalled;
            };
            match run(&brew) {
                Ok(text) => text,
                Err(e) => return Found::Failed(e),
            }
        }
    };
    match extract(&json) {
        Ok(raw) => Found::Output(raw),
        Err(e) => Found::Failed(e),
    }
}

fn run(brew: &Path) -> Result<String, String> {
    let out = Command::new(brew)
        .args(ARGS)
        .envs(QUIET)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", brew.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Err(format!(
            "brew {} failed, {}: {first}",
            ARGS.join(" "),
            out.status
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "brew output is not UTF-8".to_string())
}

/// Where brew is, if at either standard place. A `brew` anywhere else is another Homebrew, at a
/// prefix of its own choosing, and is neither looked for nor run: what is found must not
/// depend on the PATH of whoever started the check (`managers.rs`).
fn find(at: Option<&Path>, home: &Path) -> Option<PathBuf> {
    if let Some(path) = at {
        return path.is_file().then(|| path.to_path_buf());
    }
    let standard: Vec<PathBuf> = STANDARD.iter().map(PathBuf::from).collect();
    let homes = crate::watched::homes(home);
    let homes = [homes[0].as_path(), homes[1].as_path()];
    crate::tools::find(&standard, &homes).at
}

/// The raw copy made from brew's answer, in its order. Anything out of the shape
/// fails the whole reading: a reading that dropped a package would mark it gone.
fn extract(json: &str) -> Result<String, String> {
    let bad = |what: &str| format!("brew gave an answer this reader cannot read: {what}");
    let v: Value = serde_json::from_str(json).map_err(|e| bad(&e.to_string()))?;
    let list = |key: &str| {
        v.get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| bad(&format!("no list of {key}")))
    };
    let mut lines = Vec::new();
    for f in list("formulae")? {
        let name = f.get("full_name").and_then(Value::as_str);
        // One version per installed keg, or none at all if any keg lacks one.
        let versions: Option<Vec<&str>> =
            f.get("installed")
                .and_then(Value::as_array)
                .and_then(|kegs| {
                    kegs.iter()
                        .map(|k| k.get("version").and_then(Value::as_str))
                        .collect()
                });
        match (name, versions) {
            (Some(name), Some(versions)) if !versions.is_empty() => {
                lines.push(line("formula", name, f.get("tap"), &versions)?);
            }
            _ => return Err(bad("a formula without its full name or installed versions")),
        }
    }
    for c in list("casks")? {
        let name = c.get("full_token").and_then(Value::as_str);
        let version = c.get("installed").and_then(Value::as_str);
        match (name, version) {
            (Some(name), Some(version)) => {
                lines.push(line("cask", name, c.get("tap"), &[version])?);
            }
            _ => return Err(bad("a cask without its full token or installed version")),
        }
    }
    Ok(lines.into_iter().map(|l| l + "\n").collect())
}

/// One package as a line of the raw copy. The tap is a name or `null`.
fn line(kind: &str, name: &str, tap: Option<&Value>, versions: &[&str]) -> Result<String, String> {
    let tap = match tap {
        Some(Value::String(tap)) => Value::String(tap.clone()),
        None | Some(Value::Null) => Value::Null,
        Some(_) => return Err(format!("brew gave {name} a tap that is not a name")),
    };
    let mut row = vec![kind.into(), name.into(), tap];
    row.extend(versions.iter().map(|v| Value::from(*v)));
    Ok(Value::Array(row).to_string())
}

/// The statements made from the raw copy, and why the reading is partial if it is.
/// `raw_file` is the saved copy, relative to the store's folder.
pub fn statements(raw: &str, machine: &str, raw_file: &str) -> (Vec<Statement>, Option<String>) {
    let mut out = Vec::new();
    let mut untapped = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let Ok(Value::Array(row)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let (Some(kind), Some(name)) = (
            row.first().and_then(Value::as_str),
            row.get(1).and_then(Value::as_str),
        ) else {
            continue;
        };
        if row.get(2).is_none_or(Value::is_null) {
            untapped.push(name.to_string());
            continue;
        }
        let ecosystem = if kind == "cask" { "brew-cask" } else { "brew" };
        let component = format!("component:{machine}/{ecosystem}/{name}");
        let source_ref = format!("{raw_file}:{}", i + 1);
        out.push(Statement {
            subject: component.clone(),
            predicate: "part_of",
            object: machine.to_string(),
            source_ref: source_ref.clone(),
        });
        for version in row.iter().skip(3).filter_map(Value::as_str) {
            out.push(Statement {
                subject: component.clone(),
                predicate: "has_version",
                object: version.to_string(),
                source_ref: source_ref.clone(),
            });
        }
    }
    let partial = (!untapped.is_empty()).then(|| {
        format!(
            "Homebrew names no tap for {}, so it cannot be told from a core package and is not recorded",
            untapped.join(", ")
        )
    });
    (out, partial)
}
