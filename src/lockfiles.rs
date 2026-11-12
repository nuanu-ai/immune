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
const SUPPORTED: [&str; 3] = ["package-lock.json", "pnpm-lock.yaml", "Cargo.lock"];
const NOT_SUPPORTED: [&str; 8] = [
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

/// The name part of a component's id told apart: the package's name, and where it comes from
/// when that is not the public registry. The inverse of `component_name`.
pub fn split_name(name: &str) -> (&str, Option<&'static str>) {
    for (suffix, from) in [
        (" (git)", "git"),
        (" (path)", "a path"),
        (" (other registry)", "another registry"),
    ] {
        if let Some(package) = name.strip_suffix(suffix) {
            return (package, Some(from));
        }
    }
    (name, None)
}

/// The ecosystem whose dependencies a kind of lockfile declares, by its name as `read` names
/// it; `None` for one not known here.
fn ecosystem_of(kind: &str) -> Option<&'static str> {
    match kind {
        "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock" => Some("npm"),
        k if k.starts_with("package-lock.json version") => Some("npm"),
        k if k.starts_with("pnpm-lock.yaml version") => Some("npm"),
        "Cargo.lock" => Some("crates.io"),
        "uv.lock" | "poetry.lock" | "requirements.txt" => Some("PyPI"),
        "composer.lock" => Some("Packagist"),
        "go.sum" => Some("Go"),
        "Package.resolved" => Some("SwiftURL"),
        _ => None,
    }
}

/// Whether a partial reading, by the reason `read` gives it, leaves the dependencies of one
/// ecosystem in part unknown: a lockfile of that ecosystem not read or not parsed, an entry not
/// told, a folder not listed. A clause this does not recognise counts for every ecosystem, so
/// that nothing reads as fully known that is not.
pub fn partial_for(reason: &str, ecosystem: &str) -> bool {
    let names_it = |names: &str| {
        names
            .split(", ")
            .any(|n| ecosystem_of(n).is_none_or(|e| e == ecosystem))
    };
    reason.split("; ").any(|clause| {
        if let Some(names) = clause.strip_prefix("not supported yet: ") {
            names_it(names)
        } else if let Some(names) = clause.strip_prefix("could not be read: ") {
            names_it(names)
        } else if clause.starts_with("the package of ") {
            ecosystem == "npm"
        } else {
            true
        }
    })
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
            Some(t) if name == "pnpm-lock.yaml" => pnpm(&t),
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
    /// installed, so a person finds the entry. For `pnpm-lock.yaml`, the key of its `packages`
    /// map, or the path to a dependency as `<where>/<field>/<name>`.
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

/// The shapes of `pnpm-lock.yaml` read here, as pnpm's own specification describes them: the
/// documents `lockfile/5.md`, `5.2.md`, `6.0.md`, `9.0.md` and `dependency-path.md` of
/// github.com/pnpm/spec at commit 834f2815, with what the specification leaves out taken from
/// pnpm's code: `@pnpm/dependency-path` and `nameVerFromPkgSnapshot` of pnpm 8.15.9 for 5.x and
/// 6.0, and of pnpm 11 (`deps/path`, `lockfile/utils`, `lockfile/types`) for 9.0.
#[derive(Clone, Copy, PartialEq)]
enum PnpmFormat {
    /// 5.0 to 5.4 (pnpm 3 to 7). A key is `/<name>/<version>`, a peer suffix after `_`; a key
    /// without the leading slash names a host or a source other than the registry.
    V5,
    /// 6.0 (pnpm 8). A key is `/<name>@<version>`, a peer suffix in parentheses.
    V6,
    /// 9.0 (pnpm 9 to 11). A key of `packages` is `<name>@<version or source>`; `snapshots`
    /// holds each package as installed, its key with a peer suffix in parentheses.
    V9,
}

/// The lockfile versions pnpm has written, in the shape of the version field: digits, letters,
/// dots and dashes, as `5.4` or `5.4-inlineSpecifiers`. Anything else is not a version.
fn pnpm_version_shape(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// `pnpm-lock.yaml`: every entry of `packages`, by the package it is, and every `link:` among
/// the dependencies of the projects. Every document of the file is read, since pnpm 11 may put
/// the packages of its own configuration in a first one. A version of the format not listed in
/// `PnpmFormat` has no reader here and is named as a kind of lockfile without one. A `link:`
/// among a package's own dependencies (5.2 and later) is not recorded: it names a folder on
/// disk, never a package from a registry.
///
/// pnpm does not write which registry a package came from: an entry the registry served carries
/// only its `integrity`, and pnpm fetches it from the registry the project is set up with. Such
/// an entry is taken as the public registry's, as npm's own lockfile is read for an entry with no
/// address; one whose key names a host, in 5.x and 6.0, is another registry's.
fn pnpm(text: &str) -> Parsed {
    let (mut out, mut unknown) = (Vec::new(), Vec::new());
    // An empty file is one empty document, which has no version.
    for document in serde_norway::Deserializer::from_str(text) {
        // serde_norway's own pass-through helper turns a document into a value, so that serde
        // itself need not be named here.
        let Ok(lock) =
            serde_norway::with::singleton_map::deserialize::<serde_norway::Value, _>(document)
        else {
            return Parsed::Failed;
        };
        let version = match lock.get("lockfileVersion") {
            Some(serde_norway::Value::String(v)) => v.clone(),
            Some(serde_norway::Value::Number(n)) => n.to_string(),
            _ => return Parsed::Failed,
        };
        let format = match version.as_str() {
            "5" | "5.1" | "5.2" | "5.3" | "5.4" => PnpmFormat::V5,
            "6.0" => PnpmFormat::V6,
            "9.0" => PnpmFormat::V9,
            v if pnpm_version_shape(v) => {
                return Parsed::NoReader(format!("pnpm-lock.yaml version {v}"));
            }
            _ => return Parsed::Failed,
        };
        if pnpm_document(&lock, format, &mut out, &mut unknown).is_none() {
            return Parsed::Failed;
        }
    }
    Parsed::Deps("npm", out, unknown)
}

/// One document of `pnpm-lock.yaml`; `None` when it is not in the shape of its version.
fn pnpm_document(
    lock: &serde_norway::Value,
    format: PnpmFormat,
    out: &mut Vec<Dep>,
    unknown: &mut Vec<String>,
) -> Option<()> {
    // A map that may be left out, and when there must be a map.
    let map = |field: &str| match lock.get(field) {
        None => Some(None),
        Some(v) => v.as_mapping().map(Some),
    };
    let packages = map("packages")?;
    let snapshots = map("snapshots")?;
    let importers = map("importers")?;
    // pnpm 9 and later write `importers` even for a project with no dependencies.
    if format == PnpmFormat::V9 && importers.is_none() {
        return None;
    }
    for (key, entry) in packages.into_iter().flatten() {
        let key = key.as_str().unwrap_or_default();
        match pnpm_package(format, key, entry) {
            Some(dep) => out.push(dep),
            None => unknown.push(key.to_string()),
        }
        // pnpm writes the names of the packages bundled inside one, never their versions.
        match entry.get("bundledDependencies") {
            None => {}
            Some(serde_norway::Value::Sequence(names)) => unknown.extend(names.iter().map(|n| {
                format!(
                    "{key}/bundledDependencies/{}",
                    n.as_str().unwrap_or_default()
                )
            })),
            Some(_) => unknown.push(format!("{key}/bundledDependencies")),
        }
    }
    // In 9.0 a package as installed is an entry of `snapshots`, its key the key of its entry
    // in `packages` and its peers in parentheses. One with no entry there is not described.
    for key in snapshots.into_iter().flat_map(|s| s.keys()) {
        let key = key.as_str().unwrap_or_default();
        let described = |id: &str| packages.is_some_and(|p| p.contains_key(id));
        if !described(key) && !key.match_indices('(').any(|(i, _)| described(&key[..i])) {
            unknown.push(key.to_string());
        }
    }
    match importers {
        Some(importers) => {
            for (id, importer) in importers {
                let id = id.as_str().unwrap_or_default();
                pnpm_links(&format!("importers/{id}/"), importer, out, unknown);
            }
        }
        // A lockfile of 5.x or 6.0 for a single project lists its dependencies at the top.
        None => pnpm_links("", lock, out, unknown),
    }
    Some(())
}

/// One entry of `packages`, or `None` when the lockfile does not tell what it is: a name that is
/// not a package's, no version, a name its key and its `name` field disagree on, no resolution,
/// or a registry address of another package.
fn pnpm_package(format: PnpmFormat, key: &str, entry: &serde_norway::Value) -> Option<Dep> {
    fn text<'a>(v: &'a serde_norway::Value, field: &str) -> Option<Option<&'a str>> {
        match v.get(field) {
            None => Some(None),
            Some(v) => v.as_str().map(Some),
        }
    }
    let (key_name, key_version) = pnpm_key(format, key);
    let name = match (text(entry, "name")?, key_name) {
        (Some(field), Some(key)) if field != key => return None,
        (Some(name), _) | (None, Some(name)) => name,
        (None, None) => return None,
    };
    if !npm_name(name) {
        return None;
    }
    let version = match text(entry, "version")? {
        Some("") => return None,
        Some(v) => v,
        None => key_version?,
    };
    let resolution = entry.get("resolution")?;
    // A key that does not start with a slash, in 5.x and 6.0, names a host or a source.
    let configured = if format != PnpmFormat::V9 && !key.starts_with('/') {
        Source::OtherRegistry
    } else {
        Source::Registry
    };
    let source = match (text(resolution, "type")?, text(resolution, "tarball")?) {
        (Some("git"), _) => Source::Git,
        (Some("directory"), _) => Source::Path,
        // A binary, a runtime or a custom resolver's: not the public registry.
        (Some(_), _) => Source::OtherRegistry,
        (None, Some(t)) if t.starts_with("file:") => Source::Path,
        // An archive of a commit from the git hosts pnpm knows.
        (None, Some(t))
            if [
                "https://codeload.github.com/",
                "https://gitlab.com/",
                "https://bitbucket.org/",
            ]
            .iter()
            .any(|p| t.starts_with(p)) =>
        {
            Source::Git
        }
        (None, Some(t)) if t.starts_with(NPM_REGISTRY) => {
            // The registry's address names the package, `<registry><name>/-/<file>`.
            if t[NPM_REGISTRY.len()..].split("/-/").next() != Some(name) {
                return None;
            }
            Source::Registry
        }
        (None, Some(t)) if t.contains("://") => Source::OtherRegistry,
        // `integrity` alone: the registry the project is set up with.
        (None, None) if resolution.get("integrity").is_some() => configured,
        // An address of a kind not known here, or nothing to fetch the package by.
        _ => return None,
    };
    Some(Dep {
        at: At::Key(key.to_string()),
        name: name.to_string(),
        version: Some(version.to_string()),
        source,
    })
}

/// The name and version a key of `packages` carries, as pnpm's `dependency-path` parses it for
/// the format: the version without its peer suffix, and only when it is SemVer. A key of 9.0
/// always names the package; one of 5.x or 6.0 only with a SemVer version, after the host or
/// source it starts with when it does not start with a slash, as `github.com/<owner>/<repo>/<commit>`
/// names none.
fn pnpm_key(format: PnpmFormat, key: &str) -> (Option<&str>, Option<&str>) {
    let path = match (format, key.strip_prefix('/')) {
        (PnpmFormat::V9, _) => key,
        (_, Some(path)) => path,
        (_, None) => key.split_once('/').map_or("", |(_, path)| path),
    };
    let at = match format {
        PnpmFormat::V5 => {
            // `<name>/<version>`, a scoped name holding one slash itself.
            let skip = if path.starts_with('@') {
                path.find('/').map_or(0, |i| i + 1)
            } else {
                0
            };
            path[skip..].find('/').map(|i| i + skip)
        }
        _ => path.get(1..).and_then(|p| p.find('@')).map(|i| i + 1),
    };
    let Some(at) = at else {
        return (None, None);
    };
    // A peer suffix is in parentheses, or after `_` in 5.x; neither can be part of SemVer.
    let version = path[at + 1..].split(['(', '_']).next().unwrap_or_default();
    match semver::Version::parse(version) {
        Ok(_) => (Some(&path[..at]), Some(version)),
        Err(_) if format == PnpmFormat::V9 => (Some(&path[..at]), None),
        Err(_) => (None, None),
    }
}

/// The `link:` dependencies of a project: a folder on disk, which no entry of `packages`
/// describes. Every other reference is to an entry of `packages`. A workspace package taken
/// under another name, `workspace:<name>@<range>`, is that package. A reference that is not
/// text cannot be told.
fn pnpm_links(
    at: &str,
    holder: &serde_norway::Value,
    out: &mut Vec<Dep>,
    unknown: &mut Vec<String>,
) {
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(deps) = holder.get(field).and_then(|d| d.as_mapping()) else {
            continue;
        };
        for (installed_as, reference) in deps {
            let installed_as = installed_as.as_str().unwrap_or_default();
            let at = format!("{at}{field}/{installed_as}");
            // 5.x and a package's own: the reference as text, with the project's specifiers
            // beside; 6.0 and 9.0 projects: `{specifier, version}`.
            let (version, specifier) = match reference.as_mapping() {
                Some(r) => (r.get("version"), r.get("specifier")),
                None => (
                    Some(reference),
                    holder.get("specifiers").and_then(|s| s.get(installed_as)),
                ),
            };
            let Some(version) = version.and_then(|v| v.as_str()) else {
                unknown.push(at);
                continue;
            };
            if !version.starts_with("link:") {
                continue;
            }
            let name = specifier
                .and_then(|s| s.as_str())
                .and_then(|s| s.strip_prefix("workspace:"))
                .and_then(|s| s.get(1..)?.find('@').map(|i| &s[..=i]))
                .unwrap_or(installed_as);
            if !npm_name(name) {
                unknown.push(at);
                continue;
            }
            out.push(Dep {
                at: At::Key(at),
                name: name.to_string(),
                version: None,
                source: Source::Path,
            });
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

    /// A `pnpm-lock.yaml` of version 5.4 as pnpm 7 writes it for a workspace: keys
    /// `/<name>/<version>`, a peer suffix after `_`, specifiers apart from the references, a
    /// workspace package taken under another name, and every source an entry can come from.
    /// Names and addresses other than the public registry's are invented.
    const PNPM_5: &str = r#"lockfileVersion: 5.4

importers:

  .:
    specifiers:
      '@types/node': ^20.14.10
      fsevents: ^2.3.3
      left-pad: github:example/left-pad
      local-dir: file:vendor/local-dir
      local-tool: file:vendor/local-tool-1.0.0.tgz
      ms: ^2.1.3
      ms-legacy: npm:ms@2.0.0
      private-lib: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
      react: ^18.3.1
      react-dom: ^18.3.1
    dependencies:
      left-pad: github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567
      local-dir: file:vendor/local-dir
      local-tool: file:vendor/local-tool-1.0.0.tgz
      ms: 2.1.3
      ms-legacy: /ms/2.0.0
      private-lib: '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz'
      react: 18.3.1
      react-dom: 18.3.1_react@18.3.1
    devDependencies:
      '@types/node': 20.14.10
    optionalDependencies:
      fsevents: 2.3.3

  packages/ui:
    specifiers:
      react: ^18.3.1
    dependencies:
      react: 18.3.1

  packages/web:
    specifiers:
      ui-kit: workspace:@shop/ui@*
    devDependencies:
      ui-kit: link:../ui

packages:

  /@types/node/20.14.10:
    resolution: {integrity: sha512-AAAA}
    dependencies:
      undici-types: 5.26.5
    dev: true

  /fsevents/2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]
    requiresBuild: true
    dev: false
    optional: true

  /js-tokens/4.0.0:
    resolution: {integrity: sha512-CCCC}
    dev: false

  /loose-envify/1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true
    dependencies:
      js-tokens: 4.0.0
    dev: false

  /ms/2.0.0:
    resolution: {integrity: sha512-EEEE}
    dev: false

  /ms/2.1.3:
    resolution: {integrity: sha512-FFFF}
    dev: false

  /react-dom/18.3.1_react@18.3.1:
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2
    dev: false

  /react/18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /scheduler/0.23.2:
    resolution: {integrity: sha512-IIII}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /undici-types/5.26.5:
    resolution: {integrity: sha512-JJJJ}
    dev: true

  '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz':
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    name: private-lib
    version: 2.0.0
    dev: false

  file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    name: local-dir
    version: 0.1.0
    dev: false

  file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    name: local-tool
    version: 1.0.0
    dev: false

  github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    name: left-pad
    version: 1.3.0
    dev: false
"#;

    /// A `pnpm-lock.yaml` of version 6.0 as pnpm 8 writes it for a single project: keys
    /// `/<name>@<version>`, a peer suffix in parentheses, and the dependencies at the top with
    /// their specifiers inline. Names and addresses other than the public registry's are
    /// invented.
    const PNPM_6: &str = r#"lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  left-pad:
    specifier: github:example/left-pad
    version: github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567
  local-dir:
    specifier: file:vendor/local-dir
    version: file:vendor/local-dir
  local-tool:
    specifier: file:vendor/local-tool-1.0.0.tgz
    version: file:vendor/local-tool-1.0.0.tgz
  ms:
    specifier: ^2.1.3
    version: 2.1.3
  ms-legacy:
    specifier: npm:ms@2.0.0
    version: /ms@2.0.0
  private-lib:
    specifier: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
    version: '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz'
  react:
    specifier: ^18.3.1
    version: 18.3.1
  react-dom:
    specifier: ^18.3.1
    version: 18.3.1(react@18.3.1)

optionalDependencies:
  '@shop/ui':
    specifier: link:../ui
    version: link:../ui
  fsevents:
    specifier: ^2.3.3
    version: 2.3.3

devDependencies:
  '@types/node':
    specifier: ^20.14.10
    version: 20.14.10

packages:

  /@types/node@20.14.10:
    resolution: {integrity: sha512-AAAA}
    dependencies:
      undici-types: 5.26.5
    dev: true

  /fsevents@2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]
    requiresBuild: true
    dev: false
    optional: true

  /js-tokens@4.0.0:
    resolution: {integrity: sha512-CCCC}
    dev: false

  /loose-envify@1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true
    dependencies:
      js-tokens: 4.0.0
    dev: false

  /ms@2.0.0:
    resolution: {integrity: sha512-EEEE}
    dev: false

  /ms@2.1.3:
    resolution: {integrity: sha512-FFFF}
    dev: false

  /react-dom@18.3.1(react@18.3.1):
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2
    dev: false

  /react@18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /scheduler@0.23.2:
    resolution: {integrity: sha512-IIII}
    dependencies:
      loose-envify: 1.4.0
    dev: false

  /undici-types@5.26.5:
    resolution: {integrity: sha512-JJJJ}
    dev: true

  '@npm.example.com/private-lib/-/private-lib-2.0.0.tgz':
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    name: private-lib
    version: 2.0.0
    dev: false

  file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    name: local-dir
    version: 0.1.0
    dev: false

  file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    name: local-tool
    version: 1.0.0
    dev: false

  github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    name: left-pad
    version: 1.3.0
    dev: false
"#;

    /// A `pnpm-lock.yaml` of version 9.0 as pnpm 9 writes it for a workspace: `packages` keyed
    /// `<name>@<version or source>`, `snapshots` with peer suffixes in parentheses, and a
    /// dependency from a git server that is not a known host. Names and addresses other than
    /// the public registry's are invented.
    const PNPM_9: &str = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@shop/ui':
        specifier: workspace:*
        version: link:packages/ui
      is-even:
        specifier: git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567
        version: git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567
      left-pad:
        specifier: github:example/left-pad
        version: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567
      local-dir:
        specifier: file:vendor/local-dir
        version: file:vendor/local-dir
      local-tool:
        specifier: file:vendor/local-tool-1.0.0.tgz
        version: file:vendor/local-tool-1.0.0.tgz
      ms:
        specifier: ^2.1.3
        version: 2.1.3
      ms-legacy:
        specifier: npm:ms@2.0.0
        version: ms@2.0.0
      private-lib:
        specifier: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
        version: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz
      react:
        specifier: ^18.3.1
        version: 18.3.1
      react-dom:
        specifier: ^18.3.1
        version: 18.3.1(react@18.3.1)
    devDependencies:
      '@types/node':
        specifier: ^20.14.10
        version: 20.14.10
    optionalDependencies:
      fsevents:
        specifier: ^2.3.3
        version: 2.3.3

  packages/ui:
    dependencies:
      react:
        specifier: ^18.3.1
        version: 18.3.1

  packages/web:
    dependencies:
      ui-kit:
        specifier: workspace:@shop/ui@*
        version: link:../ui

packages:

  '@types/node@20.14.10':
    resolution: {integrity: sha512-AAAA}

  fsevents@2.3.3:
    resolution: {integrity: sha512-BBBB}
    engines: {node: ^8.16.0 || ^10.6.0 || >=11.0.0}
    os: [darwin]

  is-even@git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567:
    resolution: {commit: 0123456789abcdef0123456789abcdef01234567, repo: https://git.example.com/tools/is-even.git, type: git}
    version: 1.0.0

  js-tokens@4.0.0:
    resolution: {integrity: sha512-CCCC}

  left-pad@https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567}
    version: 1.3.0

  local-dir@file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}
    version: 0.1.0

  local-tool@file:vendor/local-tool-1.0.0.tgz:
    resolution: {integrity: sha512-KKKK, tarball: file:vendor/local-tool-1.0.0.tgz}
    version: 1.0.0

  loose-envify@1.4.0:
    resolution: {integrity: sha512-DDDD}
    hasBin: true

  ms@2.0.0:
    resolution: {integrity: sha512-EEEE}

  ms@2.1.3:
    resolution: {integrity: sha512-FFFF}

  private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz:
    resolution: {tarball: https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz}
    version: 2.0.0

  react-dom@18.3.1:
    resolution: {integrity: sha512-GGGG}
    peerDependencies:
      react: ^18.3.1

  react@18.3.1:
    resolution: {integrity: sha512-HHHH}
    engines: {node: '>=0.10.0'}

  scheduler@0.23.2:
    resolution: {integrity: sha512-IIII}

  undici-types@5.26.5:
    resolution: {integrity: sha512-JJJJ}

snapshots:

  '@types/node@20.14.10':
    dependencies:
      undici-types: 5.26.5

  fsevents@2.3.3:
    optional: true

  is-even@git+https://git.example.com/tools/is-even.git#0123456789abcdef0123456789abcdef01234567: {}

  js-tokens@4.0.0: {}

  left-pad@https://codeload.github.com/example/left-pad/tar.gz/0123456789abcdef0123456789abcdef01234567: {}

  local-dir@file:vendor/local-dir: {}

  local-tool@file:vendor/local-tool-1.0.0.tgz: {}

  loose-envify@1.4.0:
    dependencies:
      js-tokens: 4.0.0

  ms@2.0.0: {}

  ms@2.1.3: {}

  private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz: {}

  react-dom@18.3.1(react@18.3.1):
    dependencies:
      loose-envify: 1.4.0
      react: 18.3.1
      scheduler: 0.23.2

  react@18.3.1:
    dependencies:
      loose-envify: 1.4.0

  scheduler@0.23.2:
    dependencies:
      loose-envify: 1.4.0

  undici-types@5.26.5: {}
"#;

    /// What each pnpm sample says, given the keys its version writes for the scoped package,
    /// the git one, the local file, the other registry's, `ms` at both versions, `react-dom`
    /// and where the workspace package is first linked: the same packages from every version.
    fn pnpm_expected(key: impl Fn(&str, &str) -> String, git: &str, link: &str) -> Vec<String> {
        let at = "dev/shop/pnpm-lock.yaml#";
        let mut said = vec![
            format!("npm/@shop/ui (path)|part_of|checkout|{at}{link}"),
            format!(
                "npm/@types/node|part_of|checkout|{at}{}",
                key("@types/node", "20.14.10")
            ),
            format!(
                "npm/@types/node|has_version|20.14.10|{at}{}",
                key("@types/node", "20.14.10")
            ),
            format!(
                "npm/fsevents|part_of|checkout|{at}{}",
                key("fsevents", "2.3.3")
            ),
            format!(
                "npm/fsevents|has_version|2.3.3|{at}{}",
                key("fsevents", "2.3.3")
            ),
        ];
        if !git.is_empty() {
            said.push(format!("npm/is-even (git)|part_of|checkout|{at}{git}"));
            said.push(format!("npm/is-even (git)|has_version|1.0.0|{at}{git}"));
        }
        let left_pad = key("left-pad", "");
        let dir = key("local-dir", "");
        let local = key("local-tool", "");
        let private = key("private-lib", "");
        said.extend([
            format!(
                "npm/js-tokens|part_of|checkout|{at}{}",
                key("js-tokens", "4.0.0")
            ),
            format!(
                "npm/js-tokens|has_version|4.0.0|{at}{}",
                key("js-tokens", "4.0.0")
            ),
            format!("npm/left-pad (git)|part_of|checkout|{at}{left_pad}"),
            format!("npm/left-pad (git)|has_version|1.3.0|{at}{left_pad}"),
            format!("npm/local-dir (path)|part_of|checkout|{at}{dir}"),
            format!("npm/local-dir (path)|has_version|0.1.0|{at}{dir}"),
            format!("npm/local-tool (path)|part_of|checkout|{at}{local}"),
            format!("npm/local-tool (path)|has_version|1.0.0|{at}{local}"),
            format!(
                "npm/loose-envify|part_of|checkout|{at}{}",
                key("loose-envify", "1.4.0")
            ),
            format!(
                "npm/loose-envify|has_version|1.4.0|{at}{}",
                key("loose-envify", "1.4.0")
            ),
            format!("npm/ms|part_of|checkout|{at}{}", key("ms", "2.0.0")),
            format!("npm/ms|has_version|2.0.0|{at}{}", key("ms", "2.0.0")),
            format!("npm/ms|has_version|2.1.3|{at}{}", key("ms", "2.1.3")),
            format!("npm/private-lib (other registry)|part_of|checkout|{at}{private}"),
            format!("npm/private-lib (other registry)|has_version|2.0.0|{at}{private}"),
            format!("npm/react|part_of|checkout|{at}{}", key("react", "18.3.1")),
            format!(
                "npm/react|has_version|18.3.1|{at}{}",
                key("react", "18.3.1")
            ),
            format!(
                "npm/react-dom|part_of|checkout|{at}{}",
                key("react-dom", "18.3.1")
            ),
            format!(
                "npm/react-dom|has_version|18.3.1|{at}{}",
                key("react-dom", "18.3.1")
            ),
            format!(
                "npm/scheduler|part_of|checkout|{at}{}",
                key("scheduler", "0.23.2")
            ),
            format!(
                "npm/scheduler|has_version|0.23.2|{at}{}",
                key("scheduler", "0.23.2")
            ),
            format!(
                "npm/undici-types|part_of|checkout|{at}{}",
                key("undici-types", "5.26.5")
            ),
            format!(
                "npm/undici-types|has_version|5.26.5|{at}{}",
                key("undici-types", "5.26.5")
            ),
        ]);
        said
    }

    /// The keys pnpm 5.x and 6.0 write for the entries that come from elsewhere than the
    /// registry; `None` for one from the registry.
    fn pnpm_elsewhere(name: &str) -> Option<String> {
        match name {
            "left-pad" => Some(
                "github.com/example/left-pad/0123456789abcdef0123456789abcdef01234567".to_string(),
            ),
            "local-dir" => Some("file:vendor/local-dir".to_string()),
            "local-tool" => Some("file:vendor/local-tool-1.0.0.tgz".to_string()),
            "private-lib" => {
                Some("@npm.example.com/private-lib/-/private-lib-2.0.0.tgz".to_string())
            }
            _ => None,
        }
    }

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

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn every_pnpm_lockfile_version_names_each_package_by_what_it_is_and_says_where_it_comes_from() {
        // pnpm 7, 8 and 9 write the same project in three shapes; each is read to the same
        // packages. An alias is the package it stands for, a peer suffix is not part of the
        // version, a dev and an optional dependency are there, and only an entry from the
        // registry carries the bare name an advisory gives.
        let v5 = |name: &str, version: &str| match (pnpm_elsewhere(name), name) {
            (Some(key), _) => key,
            (None, "react-dom") => "/react-dom/18.3.1_react@18.3.1".to_string(),
            (None, _) => format!("/{name}/{version}"),
        };
        let v6 = |name: &str, version: &str| match (pnpm_elsewhere(name), name) {
            (Some(key), _) => key,
            (None, "react-dom") => "/react-dom@18.3.1(react@18.3.1)".to_string(),
            (None, _) => format!("/{name}@{version}"),
        };
        let v9 = |name: &str, version: &str| match name {
            "left-pad" => {
                format!("left-pad@https://codeload.github.com/example/left-pad/tar.gz/{SHA}")
            }
            "local-dir" => "local-dir@file:vendor/local-dir".to_string(),
            "local-tool" => "local-tool@file:vendor/local-tool-1.0.0.tgz".to_string(),
            "private-lib" => {
                "private-lib@https://npm.example.com/private-lib/-/private-lib-2.0.0.tgz"
                    .to_string()
            }
            _ => format!("{name}@{version}"),
        };
        let git = format!("is-even@git+https://git.example.com/tools/is-even.git#{SHA}");
        let link5 = "importers/packages/web/devDependencies/ui-kit";
        // pnpm 3 to 6 wrote 5.0 to 5.3 in the same shape as pnpm 7's 5.4.
        let older: Vec<(String, Vec<String>)> = ["5", "5.1", "5.2", "5.3"]
            .iter()
            .map(|v| {
                let text = PNPM_5.replace("lockfileVersion: 5.4", &format!("lockfileVersion: {v}"));
                (text, pnpm_expected(v5, "", link5))
            })
            .collect();
        for (sample, expected) in [
            (PNPM_5.to_string(), pnpm_expected(v5, "", link5)),
            (
                PNPM_6.to_string(),
                pnpm_expected(v6, "", "optionalDependencies/@shop/ui"),
            ),
            (
                PNPM_9.to_string(),
                pnpm_expected(v9, &git, "importers/./dependencies/@shop/ui"),
            ),
        ]
        .into_iter()
        .chain(older)
        {
            let dir = Dir::new("pnpm", &[("pnpm-lock.yaml", &sample)]);
            let (o, said) = dir.read();
            assert_eq!(said, expected, "{}", &sample[..20]);
            assert_eq!((o.completeness, o.reason), ("full", None));
        }
    }

    #[test]
    fn a_pnpm_entry_from_another_registry_or_a_runtime_is_never_named_as_the_registrys() {
        // A key of 5.x that names a host is another registry's package even with `integrity`
        // alone; the public registry's own address is the registry's package; an archive from
        // each git host pnpm knows is from git; a runtime pnpm installs, such as Node.js
        // itself, is not an npm package from the registry.
        let gitlab =
            format!("is-odd@https://gitlab.com/example/is-odd/-/archive/{SHA}/is-odd-{SHA}.tar.gz");
        let bitbucket =
            format!("is-number@https://bitbucket.org/example/is-number/get/{SHA}.tar.gz");
        let v5 = "lockfileVersion: 5.4\n\nspecifiers:\n  is-positive: ^3.1.0\n\n\
                  dependencies:\n  is-positive: registry.example.com/is-positive/3.1.0\n\n\
                  packages:\n\n  registry.example.com/is-positive/3.1.0:\n    \
                  resolution: {integrity: sha512-AAAA}\n    engines: {node: '>=0.10.0'}\n    dev: false\n";
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      ms:\n        \
                  specifier: ^2.1.3\n        version: 2.1.3\n    devDependencies:\n      node:\n        \
                  specifier: runtime:22.11.0\n        version: runtime:22.11.0\n\npackages:\n\n  \
                  ms@2.1.3:\n    resolution: {integrity: sha512-BBBB, tarball: https://registry.npmjs.org/ms/-/ms-2.1.3.tgz}\n\n  \
                  node@runtime:22.11.0:\n    hasBin: true\n    resolution:\n      type: variations\n      \
                  variants:\n        - resolution: {archive: tarball, bin: bin/node, integrity: sha256-CCCC, type: binary, \
                  url: https://nodejs.org/download/release/v22.11.0/node-v22.11.0-darwin-arm64.tar.gz}\n          \
                  targets:\n            - cpu: arm64\n              os: darwin\n    version: 22.11.0\n\n\
                  snapshots:\n\n  ms@2.1.3: {}\n\n  node@runtime:22.11.0: {}\n";
        let git_hosts = |text: &str| {
            let packages = [&gitlab, &bitbucket]
                .iter()
                .map(|k| {
                    let url = k.split_once('@').unwrap().1;
                    format!("  {k}:\n    resolution: {{tarball: {url}}}\n    version: 1.0.0\n\n")
                })
                .collect::<String>();
            let snapshots: String = [&gitlab, &bitbucket]
                .iter()
                .map(|k| format!("  {k}: {{}}\n\n"))
                .collect();
            text.replace("packages:\n\n", &format!("packages:\n\n{packages}"))
                .replace("snapshots:\n\n", &format!("snapshots:\n\n{snapshots}"))
        };
        let v9 = git_hosts(v9);
        let at = "dev/shop/pnpm-lock.yaml#";
        for (text, expected) in [
            (
                v5,
                vec![
                    format!(
                        "npm/is-positive (other registry)|part_of|checkout|{at}registry.example.com/is-positive/3.1.0"
                    ),
                    format!(
                        "npm/is-positive (other registry)|has_version|3.1.0|{at}registry.example.com/is-positive/3.1.0"
                    ),
                ],
            ),
            (
                &v9,
                vec![
                    format!("npm/is-number (git)|part_of|checkout|{at}{bitbucket}"),
                    format!("npm/is-number (git)|has_version|1.0.0|{at}{bitbucket}"),
                    format!("npm/is-odd (git)|part_of|checkout|{at}{gitlab}"),
                    format!("npm/is-odd (git)|has_version|1.0.0|{at}{gitlab}"),
                    format!("npm/ms|part_of|checkout|{at}ms@2.1.3"),
                    format!("npm/ms|has_version|2.1.3|{at}ms@2.1.3"),
                    format!("npm/node (other registry)|part_of|checkout|{at}node@runtime:22.11.0"),
                    format!(
                        "npm/node (other registry)|has_version|22.11.0|{at}node@runtime:22.11.0"
                    ),
                ],
            ),
        ] {
            let dir = Dir::new("pnpm-registries", &[("pnpm-lock.yaml", text)]);
            let (o, said) = dir.read();
            assert_eq!(said, expected);
            assert_eq!(o.completeness, "full");
        }
    }

    #[test]
    fn a_pnpm_entry_whose_package_cannot_be_told_is_never_guessed_and_makes_the_reading_partial() {
        // No false calm: an entry whose version is not written or empty, whose name its key and
        // its field disagree on, whose registry address names another package, or whose
        // resolution says nothing to fetch it by is left out; so are the packages bundled inside
        // another, whose versions pnpm never writes, an installed package with no entry, a
        // dependency whose reference is not text and a link whose name is not a package's. Each
        // makes the reading partial, so it never says that a package is not there.
        let unknown = PNPM_9
            .replace(
                "  '@types/node@20.14.10':\n    resolution: {integrity: sha512-AAAA}\n",
                "  '@types/node@20.14.10':\n    resolution: {tarball: vendor/node-types.tgz}\n",
            )
            .replace(
                "    os: [darwin]\n",
                "    os: [darwin]\n    bundledDependencies: true\n",
            )
            .replace(
                "type: git}\n    version: 1.0.0\n",
                "type: git}\n    version: ''\n",
            )
            .replace(
                "      ms-legacy:\n        specifier: npm:ms@2.0.0\n",
                "      broken:\n        specifier: ^1.0.0\n      ms-legacy:\n        specifier: npm:ms@2.0.0\n",
            )
            .replace(
                "      ui-kit:\n        specifier: workspace:@shop/ui@*\n",
                "      bad name:\n        specifier: link:../x\n        version: link:../x\n      \
                 ui-kit:\n        specifier: workspace:@shop/ui@*\n",
            )
            .replace(
                &format!("tar.gz/{SHA}}}\n    version: 1.3.0\n"),
                &format!("tar.gz/{SHA}}}\n"),
            )
            .replace(
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n",
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n    name: lodash\n",
            )
            .replace(
                "resolution: {integrity: sha512-HHHH}",
                "resolution: {integrity: sha512-HHHH, tarball: https://registry.npmjs.org/preact/-/preact-10.0.0.tgz}",
            )
            .replace(
                "  loose-envify@1.4.0:\n    resolution: {integrity: sha512-DDDD}\n",
                "  loose-envify@1.4.0:\n    resolution: {integrity: sha512-DDDD}\n    bundledDependencies: [js-tokens]\n",
            )
            .replace(
                "  scheduler@0.23.2:\n    resolution: {integrity: sha512-IIII}\n\n",
                "",
            )
            .replace(
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n",
                "  undici-types@5.26.5: {}\n",
            );
        let dir = Dir::new("pnpm-unknown", &[("pnpm-lock.yaml", &unknown)]);
        let (o, said) = dir.read();
        for gone in [
            "npm/@types/node",
            "npm/is-even",
            "npm/left-pad",
            "lodash",
            "ms|has_version|2.0.0",
            "npm/react|",
            "npm/scheduler",
            "npm/undici-types",
            "bad name",
        ] {
            assert!(!said.iter().any(|s| s.contains(gone)), "{gone}: {said:?}");
        }
        assert!(
            said.contains(&"npm/ms|has_version|2.1.3|dev/shop/pnpm-lock.yaml#ms@2.1.3".to_string())
        );
        assert_eq!(o.completeness, "partial");
        assert_eq!(o.gap.cause, Some(Cause::NotGiven));
        // In the order of the file: packages, then snapshots, then projects.
        assert_eq!(
            o.reason.as_deref(),
            Some(
                format!(
                    "the package of 11 entries cannot be told: \
                     dev/shop/pnpm-lock.yaml#@types/node@20.14.10, \
                     dev/shop/pnpm-lock.yaml#fsevents@2.3.3/bundledDependencies, \
                     dev/shop/pnpm-lock.yaml#is-even@git+https://git.example.com/tools/is-even.git#{SHA}, …"
                )
                .as_str()
            )
        );
        // The ones after the first three, each left out by its own rule.
        let only = |from: &str, to: &str| {
            let text = PNPM_9.replace(from, to);
            let dir = Dir::new("pnpm-unknown-one", &[("pnpm-lock.yaml", &text)]);
            dir.read().0.reason.unwrap_or_default()
        };
        let one = |key: &str| {
            format!("the package of 1 entry cannot be told: dev/shop/pnpm-lock.yaml#{key}")
        };
        for (from, to, key) in [
            (
                format!("tar.gz/{SHA}}}\n    version: 1.3.0\n"),
                format!("tar.gz/{SHA}}}\n"),
                format!("left-pad@https://codeload.github.com/example/left-pad/tar.gz/{SHA}"),
            ),
            (
                "    hasBin: true\n".to_string(),
                "    hasBin: true\n    bundledDependencies: [js-tokens]\n".to_string(),
                "loose-envify@1.4.0/bundledDependencies/js-tokens".to_string(),
            ),
            (
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n".to_string(),
                "  ms@2.0.0:\n    resolution: {integrity: sha512-EEEE}\n    name: lodash\n".to_string(),
                "ms@2.0.0".to_string(),
            ),
            (
                "resolution: {integrity: sha512-HHHH}".to_string(),
                "resolution: {integrity: sha512-HHHH, tarball: https://registry.npmjs.org/preact/-/preact-10.0.0.tgz}".to_string(),
                "react@18.3.1".to_string(),
            ),
            (
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n".to_string(),
                "  undici-types@5.26.5: {}\n".to_string(),
                "undici-types@5.26.5".to_string(),
            ),
            (
                "  undici-types@5.26.5:\n    resolution: {integrity: sha512-JJJJ}\n".to_string(),
                "  undici-types@5.26.5:\n    resolution: {}\n".to_string(),
                "undici-types@5.26.5".to_string(),
            ),
            (
                "  scheduler@0.23.2:\n    resolution: {integrity: sha512-IIII}\n\n".to_string(),
                String::new(),
                "scheduler@0.23.2".to_string(),
            ),
            (
                "      ms-legacy:\n        specifier: npm:ms@2.0.0\n".to_string(),
                "      broken:\n        specifier: ^1.0.0\n      ms-legacy:\n        specifier: npm:ms@2.0.0\n".to_string(),
                "importers/./dependencies/broken".to_string(),
            ),
            (
                "      ui-kit:\n        specifier: workspace:@shop/ui@*\n".to_string(),
                "      bad name:\n        specifier: link:../x\n        version: link:../x\n      \
                 ui-kit:\n        specifier: workspace:@shop/ui@*\n"
                    .to_string(),
                "importers/packages/web/dependencies/bad name".to_string(),
            ),
        ] {
            assert_eq!(only(&from, &to), one(&key), "{to}");
        }
        // A name that is not a package's, where only the entry's field gives one.
        let text = PNPM_5.replace("    name: left-pad\n", "    name: left pad\n");
        let dir = Dir::new("pnpm-unknown-name", &[("pnpm-lock.yaml", &text)]);
        assert_eq!(
            dir.read().0.reason.unwrap_or_default(),
            one(&format!("github.com/example/left-pad/{SHA}"))
        );
    }

    #[test]
    fn a_pnpm_lockfile_of_a_version_not_read_here_is_named_as_a_kind_without_a_reader() {
        // A version of the format this build was not written for is never guessed at: it is
        // named, and it leaves npm's packages of the project unknown and no other ecosystem's.
        // pnpm 7's experiment with inline specifiers is such a version.
        for version in ["6.1", "5.4-inlineSpecifiers"] {
            let dir = Dir::new(
                "pnpm-other",
                &[(
                    "pnpm-lock.yaml",
                    &PNPM_9.replace(
                        "lockfileVersion: '9.0'",
                        &format!("lockfileVersion: '{version}'"),
                    ),
                )],
            );
            let (o, said) = dir.read();
            assert!(said.is_empty());
            assert_eq!(o.completeness, "partial");
            assert_eq!(o.gap.cause, Some(Cause::NoReader));
            let name = format!("pnpm-lock.yaml version {version}");
            assert_eq!(o.gap.lacks[0].name.as_deref(), Some(name.as_str()));
            let reason = o.reason.unwrap();
            assert_eq!(reason, format!("not supported yet: {name}"));
            assert!(super::partial_for(&reason, "npm"));
            assert!(!super::partial_for(&reason, "crates.io"));
        }
    }

    #[test]
    fn a_pnpm_lockfile_out_of_its_shape_is_not_read_and_never_taken_for_one_with_no_packages() {
        // A file pnpm would not write is a reading that failed, never a project with nothing
        // in it: no version, a version that is not one (and so is never repeated as a name),
        // YAML that does not parse, an empty file, a map that is not one, and a 9.0 lockfile
        // without its projects.
        let long = format!("lockfileVersion: '{}'\nimporters: {{}}\n", "9".repeat(33));
        for text in [
            "packages: {}\n",
            "lockfileVersion: 'nine point oh'\nimporters: {}\n",
            "lockfileVersion: ''\nimporters: {}\n",
            &long,
            "lockfileVersion: '9.0'\nimporters: {.: {}\n",
            "",
            "lockfileVersion: '9.0'\nimporters: {}\npackages: [ms@2.1.3]\n",
            "lockfileVersion: '9.0'\n",
        ] {
            let dir = Dir::new("pnpm-broken", &[("pnpm-lock.yaml", text)]);
            let (o, said) = dir.read();
            assert!(said.is_empty(), "{text}");
            assert_eq!(o.gap.cause, Some(Cause::Failed), "{text}");
            assert_eq!(
                o.reason.as_deref(),
                Some("could not be read: pnpm-lock.yaml"),
                "{text}"
            );
        }
    }

    #[test]
    fn every_document_of_a_pnpm_lockfile_is_read() {
        // pnpm 11 may put the packages of its own configuration in a first document; they are
        // installed packages like the project's.
        let env = "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      \
                   is-positive:\n        specifier: 3.1.0\n        version: 3.1.0\n\npackages:\n\n  \
                   is-positive@3.1.0:\n    resolution: {integrity: sha512-LLLL}\n\nsnapshots:\n\n  \
                   is-positive@3.1.0: {}\n\n---\n";
        let dir = Dir::new("pnpm-env", &[("pnpm-lock.yaml", &format!("{env}{PNPM_9}"))]);
        let (o, said) = dir.read();
        assert!(
            said.contains(
                &"npm/is-positive|has_version|3.1.0|dev/shop/pnpm-lock.yaml#is-positive@3.1.0"
                    .to_string()
            )
        );
        assert!(
            said.contains(&"npm/ms|has_version|2.1.3|dev/shop/pnpm-lock.yaml#ms@2.1.3".to_string())
        );
        assert_eq!(o.completeness, "full");
    }

    #[test]
    fn a_project_with_both_an_npm_and_a_pnpm_lockfile_is_read_from_both() {
        // Two lockfiles are two declarations of what the project uses; neither hides the other.
        let dir = Dir::new(
            "npm-and-pnpm",
            &[("package-lock.json", NPM), ("web/pnpm-lock.yaml", PNPM_9)],
        );
        let (o, said) = dir.read();
        assert!(said.contains(
            &"npm/string-width|has_version|5.1.2|dev/shop/package-lock.json#node_modules/string-width"
                .to_string()
        ));
        assert!(said.contains(
            &"npm/ms|has_version|2.1.3|dev/shop/web/pnpm-lock.yaml#ms@2.1.3".to_string()
        ));
        assert_eq!(
            o.lockfiles
                .iter()
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>(),
            ["dev/shop/package-lock.json", "dev/shop/web/pnpm-lock.yaml"]
        );
        assert_eq!(o.completeness, "full");
    }
}
