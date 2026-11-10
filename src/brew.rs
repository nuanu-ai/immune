//! The `brew` reader: what Homebrew has installed, formulae and casks.
//! Input is the output of `brew list --versions`: one package per line,
//! the name followed by every installed version.

use crate::store::Statement;
use std::path::Path;
use std::process::Command;

pub const READER: &str = "brew";
pub const KIND: &str = "brew packages";
pub const BASIS: &str = "observed";

/// The raw output, or the reason it could not be read.
pub fn read(input: Option<&Path>) -> Result<String, String> {
    if let Some(path) = input {
        return std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()));
    }
    let out = Command::new("brew")
        .args(["list", "--versions"])
        .output()
        .map_err(|e| format!("cannot run brew: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().next().unwrap_or("").trim();
        return Err(format!(
            "brew list --versions failed, {}: {first}",
            out.status
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "brew output is not UTF-8".to_string())
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
