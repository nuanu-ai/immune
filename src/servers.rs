//! The `servers` reader: what is installed on servers, read from the files the owner's
//! read-only sweep leaves behind. It never connects anywhere; it only reads files.
//!
//! One file per server, `<name>.txt`, made of sections that start with a `##<section>`
//! line. A file is a complete read only if it reaches `##end`.

use crate::store::Statement;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const READER: &str = "servers";
pub const BASIS: &str = "observed";
pub const PACKAGES: &str = "system packages";
pub const CONTAINERS: &str = "containers";
pub const CONTENTS: &str = "container contents";

const NOT_COMPLETE: &str = "the sweep of this server did not complete";
const NO_RIGHTS: &str = "no rights to list containers";
const CONTENTS_PARTIAL: &str = "only version variables and the WordPress core version are read";
/// What the probe prints when docker refused, in the language it is written in.
const REFUSED: [&str; 2] = ["нет прав", "no access"];
const NOT_INSTALLED: [&str; 2] = ["docker не установлен", "docker not installed"];

/// One server file as it was found.
pub struct Input {
    pub name: String,
    /// `None` when the file could not be read.
    pub raw: Option<Vec<u8>>,
    /// When the sweep wrote the file, UTC seconds.
    pub modified: i64,
}

/// What one reading of one server found.
pub struct Outcome {
    pub kind: &'static str,
    pub completeness: &'static str,
    pub reason: Option<String>,
    pub statements: Vec<Statement>,
}

/// Every `<name>.txt` in the folder, by name. An error if the folder cannot be listed;
/// a file that cannot be read is still a server we know about.
pub fn inputs(dir: &Path) -> Result<Vec<Input>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".txt"))
        else {
            continue;
        };
        if name.is_empty() || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64);
        out.push(Input {
            name: name.to_string(),
            raw: std::fs::read(&path).ok(),
            modified,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Lines of each section, with their line numbers, counted from 1.
type Sections<'a> = BTreeMap<&'a str, Vec<(usize, &'a str)>>;

fn sections(text: &str) -> Sections<'_> {
    let mut out = Sections::new();
    let mut current = None;
    for (i, line) in text.lines().enumerate() {
        if let Some(name) = line.strip_prefix("##") {
            let name = name.trim();
            out.entry(name).or_default();
            current = Some(name);
        } else if let Some(name) = current {
            out.entry(name).or_default().push((i + 1, line));
        }
    }
    out
}

/// The non-empty rows of a section, split at the first tab.
fn pairs<'a>(sections: &Sections<'a>, name: &str) -> Vec<(usize, &'a str, &'a str)> {
    let rows = sections.get(name).map(Vec::as_slice).unwrap_or_default();
    rows.iter()
        .filter_map(|(n, line)| {
            let (a, b) = line.split_once('\t')?;
            let (a, b) = (a.trim(), b.trim());
            (!a.is_empty() && !b.is_empty()).then_some((*n, a, b))
        })
        .collect()
}

fn first_line<'a>(sections: &Sections<'a>, name: &str) -> Option<(usize, &'a str)> {
    let (n, line) = sections.get(name)?.first()?;
    let line = line.trim();
    (!line.is_empty()).then_some((*n, line))
}

/// The readings of one server file. `raw_file` is the saved copy, relative to the store's
/// folder. A file that does not reach `##end` is a read that did not happen.
pub fn readings(machine: &str, text: &str, raw_file: &str) -> Vec<Outcome> {
    let s = sections(text);
    if !s.contains_key("end") {
        return vec![
            not_read(PACKAGES, NOT_COMPLETE),
            not_read(CONTAINERS, NOT_COMPLETE),
        ];
    }
    let at = |n: usize| format!("{raw_file}:{n}");
    let say = |out: &mut Vec<Statement>, subject: &str, predicate, object: &str, n| {
        out.push(Statement {
            subject: subject.to_string(),
            predicate,
            object: object.to_string(),
            source_ref: at(n),
        });
    };
    let mut out = Vec::new();

    // System packages, with the system itself.
    let dpkg = pairs(&s, "dpkg");
    if !s.contains_key("dpkg") {
        out.push(not_read(PACKAGES, "the sweep has no package list"));
    } else if dpkg.is_empty() {
        // An empty list is a missing dpkg, not a server with nothing installed.
        out.push(not_read(PACKAGES, "the package list is empty"));
    } else {
        let mut st = Vec::new();
        if let Some((n, os)) = first_line(&s, "os") {
            say(&mut st, machine, "runs_os", os, n);
        }
        if let Some((n, kernel)) = first_line(&s, "kernel") {
            say(&mut st, machine, "runs_kernel", kernel, n);
        }
        let snap = pairs(&s, "snap");
        let rows = dpkg
            .iter()
            .map(|r| ("deb", r))
            .chain(snap.iter().map(|r| ("snap", r)));
        for (ecosystem, (n, name, version)) in rows {
            let component = format!("component:{machine}/{ecosystem}/{name}");
            say(&mut st, &component, "part_of", machine, *n);
            say(&mut st, &component, "has_version", version, *n);
        }
        out.push(Outcome {
            kind: PACKAGES,
            completeness: "full",
            reason: None,
            statements: st,
        });
    }

    // Containers. Docker that is not installed has nothing to list: that is a full read.
    let access = first_line(&s, "docker_access").map(|(_, a)| a);
    let mut containers = Vec::new();
    match access {
        None => out.push(not_read(CONTAINERS, "the sweep has no docker section")),
        Some(a) if REFUSED.contains(&a) => out.push(not_read(CONTAINERS, NO_RIGHTS)),
        Some(a) if NOT_INSTALLED.contains(&a) => out.push(full(CONTAINERS, Vec::new())),
        Some(_) if !s.contains_key("docker_ps") => {
            out.push(not_read(CONTAINERS, "the sweep has no container list"))
        }
        Some(_) => {
            let mut st = Vec::new();
            for (n, line) in s.get("docker_ps").map(Vec::as_slice).unwrap_or_default() {
                let mut cols = line.split('\t').map(str::trim);
                let (Some(image), Some(name)) = (cols.next(), cols.next()) else {
                    continue;
                };
                if image.is_empty() || name.is_empty() {
                    continue;
                }
                let container = format!("container:{machine}/{name}");
                say(&mut st, &container, "located_on", machine, *n);
                say(&mut st, &container, "runs_image", image, *n);
                containers.push(container);
            }
            out.push(full(CONTAINERS, st));
        }
    }

    // What is inside the containers: only a few things are read, so never full.
    if !containers.is_empty() {
        let mut st = Vec::new();
        for (n, name, var) in pairs(&s, "container_versions") {
            let container = format!("container:{machine}/{}", name.trim_start_matches('/'));
            let Some((key, value)) = var.split_once('=') else {
                continue;
            };
            let component = key.strip_suffix("_VERSION").unwrap_or("").to_lowercase();
            if component.is_empty() || value.trim().is_empty() {
                continue;
            }
            let component = format!("component:{container}/container-env/{component}");
            say(&mut st, &component, "part_of", &container, n);
            say(&mut st, &component, "has_version", value.trim(), n);
        }
        for (n, name, value) in pairs(&s, "wp") {
            // The probe prints `wp_version=<version>`; a bare version is accepted too.
            let version = value.split_once('=').map_or(value, |(_, v)| v).trim();
            if version.is_empty() {
                continue;
            }
            let container = format!("container:{machine}/{name}");
            let component = format!("component:{container}/wordpress-core/wordpress");
            say(&mut st, &component, "part_of", &container, n);
            say(&mut st, &component, "has_version", version, n);
        }
        out.push(Outcome {
            kind: CONTENTS,
            completeness: "partial",
            reason: Some(CONTENTS_PARTIAL.to_string()),
            statements: st,
        });
    }
    out
}

/// The readings of a file that could not be read at all.
pub fn unreadable() -> Vec<Outcome> {
    let reason = "the file of this server could not be read";
    vec![not_read(PACKAGES, reason), not_read(CONTAINERS, reason)]
}

fn not_read(kind: &'static str, reason: &str) -> Outcome {
    Outcome {
        kind,
        completeness: "none",
        reason: Some(reason.to_string()),
        statements: Vec::new(),
    }
}

fn full(kind: &'static str, statements: Vec<Statement>) -> Outcome {
    Outcome {
        kind,
        completeness: "full",
        reason: None,
        statements,
    }
}
