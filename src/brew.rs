//! The `brew` reader: what Homebrew has installed, formulae and casks.
//! Input is the output of `brew list --versions`: one package per line,
//! the name followed by every installed version.

use crate::store::Statement;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const READER: &str = "brew";
pub const KIND: &str = "brew packages";
pub const BASIS: &str = "observed";
/// The note on a full reading that had nothing to read.
pub const NOT_INSTALLED: &str = "Homebrew is not installed on this machine";

/// Where Homebrew puts `brew` when it is not on PATH: Apple Silicon, then Intel.
const STANDARD: [&str; 2] = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];

/// What reading Homebrew found.
pub enum Found {
    /// The output of `brew list --versions`.
    Output(String),
    /// No `brew` here: nothing to read, which is not a failure.
    NotInstalled,
    /// `brew` is here and could not be read, with the reason.
    Failed(String),
}

/// `input` is a saved output to read instead of running brew. `brew` is the one place to
/// look for brew instead of PATH and the standard places.
pub fn read(input: Option<&Path>, brew: Option<&Path>) -> Found {
    if let Some(path) = input {
        return match std::fs::read_to_string(path) {
            Ok(text) => Found::Output(text),
            Err(e) => Found::Failed(format!("cannot read {}: {e}", path.display())),
        };
    }
    let Some(brew) = find(brew) else {
        return Found::NotInstalled;
    };
    let out = match Command::new(&brew).args(["list", "--versions"]).output() {
        Ok(out) => out,
        Err(e) => return Found::Failed(format!("cannot run {}: {e}", brew.display())),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Found::Failed(format!(
            "brew list --versions failed, {}: {first}",
            out.status
        ));
    }
    match String::from_utf8(out.stdout) {
        Ok(text) => Found::Output(text),
        Err(_) => Found::Failed("brew output is not UTF-8".to_string()),
    }
}

fn find(at: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = at {
        return path.is_file().then(|| path.to_path_buf());
    }
    let on_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|dir| dir.join("brew"))
                .collect()
        })
        .unwrap_or_default();
    on_path
        .into_iter()
        .chain(STANDARD.iter().map(PathBuf::from))
        .find(|path| path.is_file())
}

/// `raw_file` is the saved copy of the input, relative to the store's folder.
pub fn statements(raw: &str, machine: &str, raw_file: &str) -> Vec<Statement> {
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { continue };
        let component = format!("component:{machine}/brew/{name}");
        let source_ref = format!("{raw_file}:{}", i + 1);
        out.push(Statement {
            subject: component.clone(),
            predicate: "part_of",
            object: machine.to_string(),
            source_ref: source_ref.clone(),
        });
        for version in words {
            out.push(Statement {
                subject: component.clone(),
                predicate: "has_version",
                object: version.to_string(),
                source_ref: source_ref.clone(),
            });
        }
    }
    out
}
