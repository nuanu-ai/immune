//! The `lockfiles` reader: dependencies that lockfiles declare in local checkouts.
//! It only reads: it never runs git or a package manager and writes nothing where it reads.
//!
//! The checkouts come from the `checkouts` and `agent-folders` readers. Lockfiles are kept under version
//! control, so the raw input is a manifest of their paths, sizes and the checkout's commit
//! instead of a copy.
//!
//! A component is named by the package an entry really is, not by the name it was installed
//! under, and carries where the entry comes from (`Source`). Only an entry from its ecosystem's
//! public registry is named bare, `component:<checkout>/npm/<name>`; any other source is part of
//! the name, `component:<checkout>/npm/<name> (git)`, so a package from git and the registry's
//! package of the same name are two components and never one. No registry name holds a space,
//! so such a name can never equal one an advisory gives.

use crate::checkouts::Checkout;
use crate::store::Statement;
use crate::store::{Cause, Gap, Lack};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const READER: &str = "lockfiles";
pub const KIND: &str = "lockfile dependencies";
pub const BASIS: &str = "declared";
/// What this build has no reader for among lockfiles, in its own words: a kind, by name.
pub const LOCKFILE_KIND: &str = "lockfile kind";

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

/// Where a lockfile entry comes from. A closed set: only `Registry`, the ecosystem's public
/// registry, is what the ecosystem's open vulnerability data speaks of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// npm's public registry; for Cargo, crates.io.
    Registry,
    Git,
    /// A file, a link or a folder on disk: npm's `file:` and linked entries, Cargo's path and
    /// workspace crates.
    Path,
    /// Any other registry, or an address that is not the public registry's.
    OtherRegistry,
}

/// The name part of a component's id: the real name, and for any source but the public registry
/// the source in brackets.
fn component_name(name: &str, source: Source) -> String {
    let source = match source {
        Source::Registry => return name.to_string(),
        Source::Git => "git",
        Source::Path => "path",
        Source::OtherRegistry => "other registry",
    };
    format!("{name} ({source})")
}

/// What reading one checkout found.
pub struct Outcome {
    pub completeness: &'static str,
    pub reason: Option<String>,
    /// Why the reading is incomplete, and the lockfile kinds this build has no reader for.
    pub gap: Gap,
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

/// The lockfiles inside a checkout that this reader opens as text, relative to it, for the
/// indicators reader to look for strings in.
pub fn read_as_text(checkout: &Path) -> Vec<String> {
    lockfiles(checkout)
        .0
        .into_iter()
        .filter(|p| SUPPORTED.contains(&file_name(p)))
        .collect()
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
    let mut not_supported: BTreeSet<String> = BTreeSet::new();
    let mut not_parsed: BTreeSet<&str> = BTreeSet::new();
    // Entries whose package cannot be told, as `<lockfile>#<key>`.
    let mut not_told: Vec<String> = Vec::new();
    let mut lockfiles = Vec::new();
    // (ecosystem, name with its source) -> where it was first read, and version -> where
    // that version was first read.
    let mut deps: BTreeMap<(&str, String), Found> = BTreeMap::new();

    for rel in &found {
        let source = format!("{prefix}{rel}");
        let name = file_name(rel);
        let path = checkout.path.join(rel);
        let text = std::fs::read(&path).ok();
        lockfiles.push((source.clone(), text.as_ref().map_or(0, |t| t.len() as u64)));
        if !SUPPORTED.contains(&name) {
            not_supported.insert(name.to_string());
            continue;
        }
        let parsed = match text.and_then(|t| String::from_utf8(t).ok()) {
            None => Parsed::Failed,
            Some(t) if name == "package-lock.json" => npm(&t),
            Some(t) => cargo(&t),
        };
        let (ecosystem, found) = match parsed {
            Parsed::Deps(ecosystem, found, unknown) => {
                not_told.extend(unknown.iter().map(|key| format!("{source}#{key}")));
                (ecosystem, found)
            }
            Parsed::NoReader(kind) => {
                not_supported.insert(kind);
                continue;
            }
            Parsed::Failed => {
                not_parsed.insert(name);
                continue;
            }
        };
        for dep in found {
            let at = match &dep.at {
                At::Line(n) => format!("{source}:{n}"),
                At::Key(key) => format!("{source}#{key}"),
            };
            let (_, versions) = deps
                .entry((ecosystem, component_name(&dep.name, dep.source)))
                .or_insert_with(|| (at.clone(), BTreeMap::new()));
            if let Some(version) = dep.version {
                versions.entry(version).or_insert(at);
            }
        }
    }

    let mut statements = Vec::new();
    for ((ecosystem, name), (first, versions)) in deps {
        let component = format!("component:{id}/{ecosystem}/{name}");
        statements.push(Statement {
            subject: component.clone(),
            predicate: "part_of",
            object: id.to_string(),
            source_ref: first,
        });
        for (version, at) in versions {
            statements.push(Statement {
                subject: component.clone(),
                predicate: "has_version",
                object: version,
                source_ref: at,
            });
        }
    }

    let mut reasons = Vec::new();
    if !not_supported.is_empty() {
        let names: Vec<&str> = not_supported.iter().map(String::as_str).collect();
        reasons.push(format!("not supported yet: {}", names.join(", ")));
    }
    if !not_parsed.is_empty() {
        let names: Vec<&str> = not_parsed.iter().copied().collect();
        reasons.push(format!("could not be read: {}", names.join(", ")));
    }
    if !not_told.is_empty() {
        // Never a guess: an entry that is not known to be the package it names is left out,
        // and the reading is partial, so it never says that a package is not there.
        let shown: Vec<&str> = not_told.iter().take(3).map(String::as_str).collect();
        let more = if not_told.len() > shown.len() {
            ", …"
        } else {
            ""
        };
        reasons.push(format!(
            "the package of {} cannot be told: {}{more}",
            if not_told.len() == 1 {
                "1 entry".to_string()
            } else {
                format!("{} entries", not_told.len())
            },
            shown.join(", ")
        ));
    }
    if !listed {
        reasons.push("a folder could not be listed".to_string());
    }
    // A lockfile that could not be read or a folder that could not be listed failed; a kind
    // of lockfile without a reader is no reader; an entry the lockfile does not say enough
    // about is not given. The reading takes the worst.
    let mut causes = Vec::new();
    if !not_parsed.is_empty() || !listed {
        causes.push(Cause::Failed);
    }
    if !not_supported.is_empty() {
        causes.push(Cause::NoReader);
    }
    if !not_told.is_empty() {
        causes.push(Cause::NotGiven);
    }
    let gap = Gap {
        cause: Cause::worst(causes),
        lacks: not_supported
            .iter()
            .map(|name| Lack::new(LOCKFILE_KIND, Some(name)))
            .collect(),
    };
    Some(Outcome {
        gap,
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

/// Where a component was first read, and each of its versions with where it was first read.
type Found = (String, BTreeMap<String, String>);

/// Where in its lockfile an entry was read.
enum At {
    Line(usize),
    /// The key of `package-lock.json`'s `packages` map. It names an alias as it was
    /// installed, so a person finds the entry.
    Key(String),
}

/// One entry of a lockfile: the package it really is, its version, and where it comes from.
struct Dep {
    at: At,
    name: String,
    /// `None` only for a linked entry whose target gives no version.
    version: Option<String>,
    source: Source,
}

enum Parsed {
    /// The ecosystem, the entries, and the keys of entries whose package cannot be told.
    Deps(&'static str, Vec<Dep>, Vec<String>),
    /// A lockfile of a kind this build has no reader for, by name.
    NoReader(String),
    Failed,
}

/// npm's public registry. An entry is from it when it names no `resolved` address, as a
/// bundled entry does, or names one here; anything else is not its package. A mirror counts
/// as another registry.
const NPM_REGISTRY: &str = "https://registry.npmjs.org/";

/// `package-lock.json`, lockfile versions 2 and 3: the `packages` map. The root entry and
/// workspace folders are the project itself and are skipped. Version 1 has no such map and no
/// reader here; it is named as a kind of lockfile without one.
fn npm(text: &str) -> Parsed {
    let Ok(lock) = serde_json::from_str::<serde_json::Value>(text) else {
        return Parsed::Failed;
    };
    match lock.get("lockfileVersion").and_then(|v| v.as_u64()) {
        Some(2 | 3) => {}
        Some(n) => return Parsed::NoReader(format!("package-lock.json version {n}")),
        None => return Parsed::Failed,
    }
    let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) else {
        return Parsed::Failed;
    };
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    for (key, entry) in packages {
        let Some(i) = key.rfind("node_modules/") else {
            continue;
        };
        match npm_entry(key, &key[i + "node_modules/".len()..], entry, packages) {
            Some(dep) => out.push(dep),
            None => unknown.push(key.clone()),
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One entry under `node_modules`, or `None` when the lockfile does not tell what it is: a
/// name that is not a package's, no version, or a registry address of another package.
fn npm_entry(
    key: &str,
    installed_as: &str,
    entry: &serde_json::Value,
    packages: &serde_json::Map<String, serde_json::Value>,
) -> Option<Dep> {
    let text = |field: &str| match entry.get(field) {
        None => Some(None),
        Some(v) => v.as_str().map(Some),
    };
    // An alias is installed under its own name and records the package in `name`.
    let name = text("name")?.unwrap_or(installed_as);
    let resolved = text("resolved")?;
    if !npm_name(name) {
        return None;
    }
    let link = entry.get("link").and_then(|l| l.as_bool()) == Some(true);
    let source = match resolved {
        _ if link => Source::Path,
        None => Source::Registry,
        Some(r) if r.starts_with(NPM_REGISTRY) => Source::Registry,
        Some(r)
            if ["git+", "git://", "github:", "gitlab:", "bitbucket:"]
                .iter()
                .any(|p| r.starts_with(p)) =>
        {
            Source::Git
        }
        Some(r) if r.starts_with("file:") => Source::Path,
        // Another registry, a tarball's address, or an address of a kind not known here:
        // whatever it is, it is not the public registry.
        Some(_) => Source::OtherRegistry,
    };
    // The registry's address names the package, `<registry><name>/-/<file>`. One that names
    // another package means the entry is not what its name says.
    if let Some(path) = resolved
        .filter(|_| source == Source::Registry)
        .and_then(|r| r.strip_prefix(NPM_REGISTRY))
        && path.split("/-/").next() != Some(name)
    {
        return None;
    }
    let version = match text("version")? {
        Some("") => return None,
        Some(v) => Some(v.to_string()),
        // A link points at a folder of the project, whose entry carries the version if any.
        None if link => resolved
            .and_then(|target| packages.get(target))
            .and_then(|t| t.get("version"))
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        None => return None,
    };
    Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version,
        source,
    })
}

/// A package name as npm allows it, in the part that matters here: not empty, no blank or
/// control character, and a slash only in `@scope/name`.
fn npm_name(name: &str) -> bool {
    let plain = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control());
    match name.split_once('/') {
        None => plain(name),
        Some((scope, rest)) => {
            scope.len() > 1
                && scope.starts_with('@')
                && plain(scope)
                && plain(rest)
                && !rest.contains('/')
        }
    }
}

/// crates.io's index, in both forms Cargo writes it.
const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// `Cargo.lock`: every `[[package]]` block, its name, version and source, at the line of its
/// name. A crate with no source is a path or workspace crate, including one patched to a path.
/// `[[patch.unused]]` blocks are patches the build does not use, not dependencies.
fn cargo(text: &str) -> Parsed {
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
        let (mut name, mut version, mut source) = (None, None, None);
        for (i, line) in lines.iter().enumerate().take(end).skip(start + 1) {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "name" => name = Some((i + 1, value)),
                "version" => version = Some(value),
                "source" => source = Some(value),
                _ => {}
            }
        }
        let (Some((line, name)), Some(version)) = (name, version) else {
            return Parsed::Failed;
        };
        let source = match source {
            None => Source::Path,
            Some(s) if CRATES_IO.contains(&s) => Source::Registry,
            Some(s) if s.starts_with("git+") => Source::Git,
            Some(_) => Source::OtherRegistry,
        };
        out.push(Dep {
            at: At::Line(line),
            name: name.to_string(),
            version: Some(version.to_string()),
            source,
        });
    }
    Parsed::Deps("crates.io", out, Vec::new())
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

#[cfg(test)]
mod tests {
    use super::{Checkout, read};
    use crate::store::Cause;
    use std::path::PathBuf;

    /// A `package-lock.json` of version 3 as npm 10 writes it, with every source an entry can
    /// come from. Names and addresses other than the public registry's are invented.
    const NPM: &str = r#"{
  "name": "shop",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "shop",
      "version": "1.0.0",
      "workspaces": ["packages/ui"],
      "dependencies": {
        "ink": "npm:@jrichman/ink@6.4.6",
        "left-pad": "github:example/left-pad",
        "local-tool": "file:vendor/local-tool-1.0.0.tgz",
        "private-lib": "^2.0.0",
        "string-width": "^5.1.2",
        "string-width-cjs": "npm:string-width@^4.2.0"
      }
    },
    "node_modules/@shop/ui": {
      "resolved": "packages/ui",
      "link": true
    },
    "node_modules/ink": {
      "name": "@jrichman/ink",
      "version": "6.4.6",
      "resolved": "https://registry.npmjs.org/@jrichman/ink/-/ink-6.4.6.tgz",
      "integrity": "sha512-AAAA",
      "license": "MIT"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "git+ssh://git@github.com/example/left-pad.git#0123456789abcdef0123456789abcdef01234567",
      "license": "WTFPL"
    },
    "node_modules/local-tool": {
      "version": "1.0.0",
      "resolved": "file:vendor/local-tool-1.0.0.tgz",
      "integrity": "sha512-BBBB"
    },
    "node_modules/npm-bundler": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/npm-bundler/-/npm-bundler-2.0.0.tgz",
      "integrity": "sha512-CCCC",
      "bundleDependencies": ["abbrev"]
    },
    "node_modules/npm-bundler/node_modules/abbrev": {
      "version": "1.1.1",
      "inBundle": true,
      "license": "ISC"
    },
    "node_modules/private-lib": {
      "version": "2.0.0",
      "resolved": "https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz",
      "integrity": "sha512-DDDD"
    },
    "node_modules/string-width": {
      "version": "5.1.2",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-5.1.2.tgz",
      "integrity": "sha512-EEEE",
      "dev": true
    },
    "node_modules/string-width-cjs": {
      "name": "string-width",
      "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
      "integrity": "sha512-FFFF",
      "dev": true
    },
    "packages/ui": {
      "name": "@shop/ui",
      "version": "0.1.0"
    }
  }
}
"#;

    /// A `Cargo.lock` of version 4 with every source a crate can come from: the workspace,
    /// both forms of crates.io's index, git, another registry, and a crate patched to a path.
    const CARGO: &str = r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "libc",
 "rand 0.8.5",
 "rand 0.9.0-dev",
 "serde",
 "internal-crate",
]

[[package]]
name = "internal-crate"
version = "1.2.0"
source = "sparse+https://cargo.example.com/index/"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "libc"
version = "0.2.191"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"

[[package]]
name = "rand"
version = "0.9.0-dev"
source = "git+https://github.com/rust-random/rand?branch=master#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "serde"
version = "1.0.210"
source = "sparse+https://index.crates.io/"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"

[[patch.unused]]
name = "log"
version = "0.4.22"
source = "git+https://github.com/rust-lang/log#89abcdef0123456789abcdef0123456789abcdef"
"#;

    /// A checkout of its own for one test, removed after it.
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str, files: &[(&str, &str)]) -> Dir {
            let dir = std::env::temp_dir().join(format!("soc-lock-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            for (name, text) in files {
                let path = dir.join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            }
            Dir(dir)
        }

        /// What the reader says of it: each statement as `subject|predicate|object|where`,
        /// with the checkout's id left out.
        fn read(&self) -> (super::Outcome, Vec<String>) {
            let checkout = Checkout {
                rel: "dev/shop".to_string(),
                path: self.0.clone(),
            };
            let o = read(&checkout, "checkout:machine:mac/dev/shop").unwrap();
            let said = o
                .statements
                .iter()
                .map(|s| {
                    let subject = s
                        .subject
                        .replace("component:checkout:machine:mac/dev/shop/", "");
                    let object = s
                        .object
                        .replace("checkout:machine:mac/dev/shop", "checkout");
                    format!("{subject}|{}|{object}|{}", s.predicate, s.source_ref)
                })
                .collect();
            (o, said)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_npm_entry_is_named_by_the_package_it_is_and_says_where_it_comes_from() {
        // An alias installed as `string-width-cjs` is string-width, and only an entry from the
        // public registry carries the bare name an advisory gives: a package from git, a file,
        // a link or another registry is a component of its own, never the registry's one.
        let dir = Dir::new("npm", &[("package-lock.json", NPM)]);
        let (o, said) = dir.read();
        let at = "dev/shop/package-lock.json#node_modules";
        let expected = [
            format!("npm/@jrichman/ink|part_of|checkout|{at}/ink"),
            format!("npm/@jrichman/ink|has_version|6.4.6|{at}/ink"),
            format!("npm/@shop/ui (path)|part_of|checkout|{at}/@shop/ui"),
            format!("npm/@shop/ui (path)|has_version|0.1.0|{at}/@shop/ui"),
            format!("npm/abbrev|part_of|checkout|{at}/npm-bundler/node_modules/abbrev"),
            format!("npm/abbrev|has_version|1.1.1|{at}/npm-bundler/node_modules/abbrev"),
            format!("npm/left-pad (git)|part_of|checkout|{at}/left-pad"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}/left-pad"),
            format!("npm/local-tool (path)|part_of|checkout|{at}/local-tool"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}/local-tool"),
            format!("npm/npm-bundler|part_of|checkout|{at}/npm-bundler"),
            format!("npm/npm-bundler|has_version|2.0.0|{at}/npm-bundler"),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}/private-lib"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}/private-lib"),
            format!("npm/string-width|part_of|checkout|{at}/string-width"),
            format!("npm/string-width|has_version|4.2.3|{at}/string-width-cjs"),
            format!("npm/string-width|has_version|5.1.2|{at}/string-width"),
        ];
        assert_eq!(said, expected);
        assert_eq!((o.completeness, o.reason), ("full", None));
    }

    #[test]
    fn an_npm_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // An alias written without the package's name would be taken for a package of the
        // alias's name, which anyone may register. Left out, it must not let the reading
        // say the package is absent.
        let unknown = NPM
            .replace(
                "\"node_modules/string-width-cjs\": {\n      \"name\": \"string-width\",",
                "\"node_modules/string-width-cjs\": {",
            )
            .replace(
                "\"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",",
                "\"node_modules/left-pad\": {",
            )
            .replace(
                "\"name\": \"@jrichman/ink\"",
                "\"name\": \"@jrichman/ink 2\"",
            );
        let dir = Dir::new("npm-unknown", &[("package-lock.json", &unknown)]);
        let (o, said) = dir.read();
        for gone in ["string-width-cjs", "left-pad", "ink"] {
            assert!(!said.iter().any(|s| s.contains(gone)), "{gone}: {said:?}");
        }
        assert!(said.contains(
            &"npm/string-width|has_version|5.1.2|dev/shop/package-lock.json#node_modules/string-width"
                .to_string()
        ));
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        assert_eq!(
            o.reason.as_deref(),
            Some(
                "the package of 3 entries cannot be told: \
                 dev/shop/package-lock.json#node_modules/ink, \
                 dev/shop/package-lock.json#node_modules/left-pad, \
                 dev/shop/package-lock.json#node_modules/string-width-cjs"
            )
        );
    }

    #[test]
    fn a_crate_from_a_path_git_or_another_registry_is_never_named_as_the_crates_io_one() {
        // The workspace's own crate, a crate patched to a path, one from git and one from
        // another registry share names with crates.io's at will; only an entry from
        // crates.io's index, in either form, is named bare. An unused patch is not there.
        let dir = Dir::new("cargo", &[("Cargo.lock", CARGO)]);
        let (o, said) = dir.read();
        let at = "dev/shop/Cargo.lock";
        assert_eq!(
            said,
            [
                format!("crates.io/app (path)|part_of|checkout|{at}:6"),
                format!("crates.io/app (path)|has_version|0.1.0|{at}:6"),
                format!("crates.io/internal-crate (other registry)|part_of|checkout|{at}:17"),
                format!("crates.io/internal-crate (other registry)|has_version|1.2.0|{at}:17"),
                format!("crates.io/libc (path)|part_of|checkout|{at}:23"),
                format!("crates.io/libc (path)|has_version|0.2.191|{at}:23"),
                format!("crates.io/rand|part_of|checkout|{at}:27"),
                format!("crates.io/rand|has_version|0.8.5|{at}:27"),
                format!("crates.io/rand (git)|part_of|checkout|{at}:33"),
                format!("crates.io/rand (git)|has_version|0.9.0-dev|{at}:33"),
                format!("crates.io/serde|part_of|checkout|{at}:38"),
                format!("crates.io/serde|has_version|1.0.210|{at}:38"),
            ]
        );
        assert_eq!(o.completeness, "full");
    }

    #[test]
    fn an_npm_lockfile_of_version_1_is_named_as_a_kind_without_a_reader() {
        // Version 1 records aliases and git sources as versions; it is not read, and says so
        // by name, like any lockfile kind without a reader, so nothing is taken as absent.
        let v1 = r#"{"name": "old", "lockfileVersion": 1, "requires": true,
                     "dependencies": {"left-pad": {"version": "1.3.0"}}}"#;
        let dir = Dir::new("npm-v1", &[("package-lock.json", v1)]);
        let (o, said) = dir.read();
        assert!(said.is_empty());
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NoReader));
        assert_eq!(
            o.gap.lacks[0].name.as_deref(),
            Some("package-lock.json version 1")
        );
        assert_eq!(
            o.reason.as_deref(),
            Some("not supported yet: package-lock.json version 1")
        );
    }
}
