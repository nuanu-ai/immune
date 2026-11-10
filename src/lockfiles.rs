//! The `lockfiles` reader: dependencies that lockfiles declare in local checkouts.
//! It only reads: it never runs git or a package manager and writes nothing where it reads.
//!
//! The checkouts come from the `checkouts` reader. Lockfiles are kept under version
//! control, so the raw input is a manifest of their paths, sizes and the checkout's commit
//! instead of a copy.

use crate::checkouts::Checkout;
use crate::store::Statement;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const READER: &str = "lockfiles";
pub const KIND: &str = "lockfile dependencies";
pub const BASIS: &str = "declared";

const MAX_DEPTH: usize = 4;
const PRUNED: [&str; 4] = ["node_modules", "target", "vendor", ".git"];
const SUPPORTED: [&str; 2] = ["package-lock.json", "Cargo.lock"];
const NOT_SUPPORTED: [&str; 9] = [
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "composer.lock",
    "go.sum",
    "requirements.txt",
    "Package.resolved",
    "bun.lock",
];

/// What reading one checkout found.
pub struct Outcome {
    pub completeness: &'static str,
    pub reason: Option<String>,
    pub statements: Vec<Statement>,
    /// Every lockfile found: path relative to the home folder, and size in bytes.
    pub lockfiles: Vec<(String, u64)>,
}

fn pruned(name: &str) -> bool {
    name.starts_with('.') || PRUNED.contains(&name)
}

/// Lockfiles of known kinds inside a checkout, relative to it, and whether every
/// folder could be listed.
fn lockfiles(checkout: &Path) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut listed = true;
    let mut stack = vec![(String::new(), checkout.to_path_buf(), 0)];
    while let Some((rel, dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            listed = false;
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                listed = false;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(file_type) = entry.file_type() else {
                listed = false;
                continue;
            };
            let path = format!("{rel}{name}");
            if file_type.is_file()
                && (SUPPORTED.contains(&name.as_str()) || NOT_SUPPORTED.contains(&name.as_str()))
            {
                out.push(path);
            } else if file_type.is_dir() && depth < MAX_DEPTH && !pruned(&name) {
                stack.push((format!("{path}/"), entry.path(), depth + 1));
            }
        }
    }
    out.sort();
    (out, listed)
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Reads one checkout. `None` when it holds no lockfile at all: then there is nothing
/// to cover. Where the checkout is, is said by the `checkouts` reader.
pub fn read(checkout: &Checkout, id: &str) -> Option<Outcome> {
    let (found, listed) = lockfiles(&checkout.path);
    if found.is_empty() && listed {
        return None;
    }
    let prefix = if checkout.rel == "." {
        String::new()
    } else {
        format!("{}/", checkout.rel)
    };
    let mut not_supported = BTreeSet::new();
    let mut not_parsed = BTreeSet::new();
    let mut lockfiles = Vec::new();
    // (ecosystem, name) -> version -> where it was first read
    let mut deps: BTreeMap<(&str, String), BTreeMap<String, String>> = BTreeMap::new();

    for rel in &found {
        let source = format!("{prefix}{rel}");
        let name = file_name(rel);
        let path = checkout.path.join(rel);
        let text = std::fs::read(&path).ok();
        lockfiles.push((source.clone(), text.as_ref().map_or(0, |t| t.len() as u64)));
        if !SUPPORTED.contains(&name) {
            not_supported.insert(name);
            continue;
        }
        let parsed = text
            .and_then(|t| String::from_utf8(t).ok())
            .and_then(|t| match name {
                "package-lock.json" => npm(&t).map(|d| ("npm", d)),
                _ => cargo(&t).map(|d| ("crates.io", d)),
            });
        let Some((ecosystem, found)) = parsed else {
            not_parsed.insert(name);
            continue;
        };
        for (line, dep, version) in found {
            let at = line.map_or(source.clone(), |n| format!("{source}:{n}"));
            deps.entry((ecosystem, dep))
                .or_default()
                .entry(version)
                .or_insert(at);
        }
    }

    let mut statements = Vec::new();
    for ((ecosystem, name), versions) in deps {
        let component = format!("component:{id}/{ecosystem}/{name}");
        for (i, (version, at)) in versions.into_iter().enumerate() {
            if i == 0 {
                statements.push(Statement {
                    subject: component.clone(),
                    predicate: "part_of",
                    object: id.to_string(),
                    source_ref: at.clone(),
                });
            }
            statements.push(Statement {
                subject: component.clone(),
                predicate: "has_version",
                object: version,
                source_ref: at,
            });
        }
    }

    let list = |set: &BTreeSet<&str>| set.iter().copied().collect::<Vec<_>>().join(", ");
    let mut reasons = Vec::new();
    if !not_supported.is_empty() {
        reasons.push(format!("not supported yet: {}", list(&not_supported)));
    }
    if !not_parsed.is_empty() {
        reasons.push(format!("could not be read: {}", list(&not_parsed)));
    }
    if !listed {
        reasons.push("a folder could not be listed".to_string());
    }
    Some(Outcome {
        completeness: if reasons.is_empty() {
            "full"
        } else {
            "partial"
        },
        reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        statements,
        lockfiles,
    })
}

type Deps = Vec<(Option<usize>, String, String)>;

/// `package-lock.json`, lockfile versions 2 and 3: the `packages` map. The root entry,
/// workspace folders and linked entries carry no installed version and are skipped.
fn npm(text: &str) -> Option<Deps> {
    let lock: serde_json::Value = serde_json::from_str(text).ok()?;
    let packages = lock.get("packages")?.as_object()?;
    let mut out = Vec::new();
    for (key, entry) in packages {
        let Some(i) = key.rfind("node_modules/") else {
            continue;
        };
        let name = &key[i + "node_modules/".len()..];
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if !name.is_empty() && !version.is_empty() {
            out.push((None, name.to_string(), version.to_string()));
        }
    }
    Some(out)
}

/// `Cargo.lock`: every `[[package]]` block, its name and version, at the line of its name.
fn cargo(text: &str) -> Option<Deps> {
    let lines: Vec<&str> = text.lines().collect();
    // A block runs from its header to the next header.
    let headers: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].trim_start().starts_with('['))
        .collect();
    let mut out = Vec::new();
    for (k, &start) in headers.iter().enumerate() {
        if lines[start].trim() != "[[package]]" {
            continue;
        }
        let end = headers.get(k + 1).copied().unwrap_or(lines.len());
        let (mut name, mut version) = (None, None);
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "name" => name = Some((i + 1, value)),
                "version" => version = Some(value),
                _ => {}
            }
        }
        let ((line, name), version) = (name?, version?);
        out.push((Some(line), name.to_string(), version.to_string()));
    }
    Some(out)
}

/// The commit the checkout is at, read from `.git` by hand, or `unknown`.
pub fn commit(checkout: &Path) -> String {
    read_commit(checkout).unwrap_or_else(|| "unknown".to_string())
}

fn read_commit(checkout: &Path) -> Option<String> {
    let dotgit = checkout.join(".git");
    // A worktree or a submodule has a `.git` file that points at the real folder.
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        let text = std::fs::read_to_string(&dotgit).ok()?;
        checkout.join(text.trim().strip_prefix("gitdir:")?.trim())
    };
    let common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(text) => gitdir.join(text.trim()),
        Err(_) => gitdir.clone(),
    };
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(name) = head.strip_prefix("ref:").map(str::trim) else {
        return is_hash(head).then(|| head.to_string());
    };
    for dir in [&gitdir, &common] {
        if let Ok(hash) = std::fs::read_to_string(dir.join(name)) {
            let hash = hash.trim();
            return is_hash(hash).then(|| hash.to_string());
        }
    }
    let packed = std::fs::read_to_string(common.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let (hash, refname) = line.split_once(' ')?;
        (refname.trim() == name && is_hash(hash)).then(|| hash.to_string())
    })
}

fn is_hash(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
