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
use std::path::{Path, PathBuf};

pub const READER: &str = "lockfiles";
pub const KIND: &str = "lockfile dependencies";
pub const BASIS: &str = "declared";
/// The note of a full reading of a checkout in which no lockfile this version knows was found:
/// it was opened, and there was nothing to read. A checkout with no reading was never opened.
pub const NONE_FOUND_NOTE: &str = "no lockfile this version knows of was found in it";
/// What this build has no reader for among lockfiles, in its own words: a kind, by name.
pub const LOCKFILE_KIND: &str = "lockfile kind";

/// What this build reads of a lockfile below the folders it opens: its kind, by name. The
/// lockfile is there and was not opened.
pub const DEEPER: &str = "lockfile below the folders read";
/// What this build reads of a lockfile in a folder it sets aside, `vendor` or a hidden one: its
/// kind, by name. The lockfile is there and was not opened.
pub const SET_ASIDE: &str = "lockfile in a folder set aside";
/// Folders past `LOOK_LIMIT` that the walk did not look through: what they hold is not known.
pub const NOT_LOOKED: &str = "folders not looked through for lockfiles";
/// What this build reads of a lockfile that is a symbolic link: its kind, by name. Links are not
/// followed, so it was not opened.
pub const LINKED: &str = "lockfile that is a link";
/// How a partial reading's reason begins a clause for what its lacks name (`Gap::lacks`): the
/// kinds with no reader and the lockfiles not opened. The lacks decide what such a clause
/// leaves unknown; the words are for a person.
const NOT_SUPPORTED_SAID: &str = "not supported yet: ";
const NOT_OPENED_SAID: &str = "not opened: ";

/// Lockfiles are opened in the project's folder and in folders at most this deep below it.
/// Below, the walk only looks for them by name, so that one it does not open is said and never
/// taken as absent.
const MAX_DEPTH: usize = 4;
/// How many folders the walk lists, besides those whose lockfiles it opens, only to look for
/// lockfiles it does not open: below `MAX_DEPTH` and in folders set aside. Listing a folder is
/// one call to the system, about 0.1 s for 9,000 folders on a debug build, and ordinary build
/// trees (`android/app/build/intermediates`, a large Java package tree) hold several thousand.
/// Past this the reading is partial for every ecosystem, since what lies there is not known.
const LOOK_LIMIT: usize = 50_000;
/// Folders never entered, at any depth, since none holds what the project itself declares:
/// `.git` is git's own database, never a working file; `node_modules` holds installed copies of
/// packages, which the project's lockfile beside it declares, and a lockfile inside one is a
/// published package's own, about how that package was built; `target` is build output, made
/// from the project's own files. Every other hidden folder, and `vendor`, can hold code of the
/// project's own with its own lockfile, a CI action or a vendored app: they are set aside,
/// looked through for lockfiles that are then not opened (`SET_ASIDE`).
const NEVER_ENTERED: [&str; 3] = [".git", "node_modules", "target"];
const SET_ASIDE_FOLDER: &str = "vendor";
/// What marks a folder, or part of one, as holding nothing of the project's own. Marks only
/// bound the look for names below `MAX_DEPTH` and in folders set aside: where lockfiles are
/// opened, every one is opened whatever marks are there. What a marked folder holds is not the
/// project's and is not looked at.
/// - `pyvenv.cfg` marks a Python virtual environment (PEP 405). People make one in place in a
///   project's folder, so only the subfolders of an environment's own layout, as `venv` makes
///   them on POSIX and on Windows, are not looked into; the folder's own files and its other
///   subfolders are looked at as any other.
/// - `conda-meta` marks a conda environment, a folder of its own by construction.
/// - `CACHEDIR.TAG` beginning with its signature marks a cache (the Cache Directory Tagging
///   Specification, bford.info/cachedir).
/// - `.git`, a folder or a file (a worktree, a submodule, a nested repository), below the
///   project's own folder marks another project.
const ENVIRONMENT_MARK: &str = "pyvenv.cfg";
const ENVIRONMENT_LAYOUT: [&str; 8] = [
    "lib", "lib64", "bin", "include", "share", "Scripts", "Lib", "Include",
];
const CONDA_MARK: &str = "conda-meta";
const CACHE_MARK: &str = "CACHEDIR.TAG";
const CACHE_SIGNATURE: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55";
const CHECKOUT_MARK: &str = ".git";

const SUPPORTED: [&str; 3] = ["package-lock.json", "pnpm-lock.yaml", "Cargo.lock"];
/// Lockfiles this build has no reader for, by name, with the ecosystem whose packages each
/// declares, as OSV names it. Data, from OSV-Scanner's list of supported lockfiles
/// (google.github.io/osv-scanner, "Supported languages and lockfiles", read on 16 November
/// 2026), with `go.sum` for Go, npm's own `npm-shrinkwrap.json`, Swift's `Package.resolved`, and
/// CocoaPods' `Podfile.lock` and Nix's `flake.lock`, whose ecosystems OSV does not name. The
/// manifests that page lists beside the lockfiles (`go.mod`, `pom.xml`, `deps.json` and the
/// like) are not lockfiles and are not here. A lockfile of a name on no list is not known to be
/// one and cannot be said (docs/reference.md).
const NOT_SUPPORTED: [(&str, Option<&str>); 25] = [
    ("yarn.lock", Some("npm")),
    ("bun.lock", Some("npm")),
    ("npm-shrinkwrap.json", Some("npm")),
    ("uv.lock", Some("PyPI")),
    ("poetry.lock", Some("PyPI")),
    ("Pipfile.lock", Some("PyPI")),
    ("pdm.lock", Some("PyPI")),
    ("pylock.toml", Some("PyPI")),
    ("requirements.txt", Some("PyPI")),
    ("composer.lock", Some("Packagist")),
    ("go.sum", Some("Go")),
    ("Package.resolved", Some("SwiftURL")),
    ("Gemfile.lock", Some("RubyGems")),
    ("gems.locked", Some("RubyGems")),
    ("mix.lock", Some("Hex")),
    ("pubspec.lock", Some("Pub")),
    ("renv.lock", Some("CRAN")),
    ("gradle.lockfile", Some("Maven")),
    ("buildscript-gradle.lockfile", Some("Maven")),
    ("packages.lock.json", Some("NuGet")),
    ("conan.lock", Some("ConanCenter")),
    ("cabal.project.freeze", Some("Hackage")),
    ("stack.yaml.lock", Some("Hackage")),
    ("Podfile.lock", None),
    ("flake.lock", None),
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
pub fn ecosystem_of(kind: &str) -> Option<&'static str> {
    match kind {
        "package-lock.json" | "pnpm-lock.yaml" => Some("npm"),
        k if k.starts_with("package-lock.json version") => Some("npm"),
        k if k.starts_with("pnpm-lock.yaml version") => Some("npm"),
        "Cargo.lock" => Some("crates.io"),
        _ => NOT_SUPPORTED
            .iter()
            .find(|(name, _)| *name == kind)
            .and_then(|(_, ecosystem)| *ecosystem),
    }
}

/// Whether a partial reading leaves the dependencies of one ecosystem in part unknown. What the
/// reading names it did not read, `lacks` by their names (a kind with no reader, a lockfile not
/// opened), leaves the ecosystem of each name unknown and no other: a name of no ecosystem a
/// record can be about, such as `flake.lock`, leaves none. A lack with no name, folders not
/// looked through, counts for every ecosystem. The reason's clauses for the lacks are only words
/// for a person. The reason decides the rest: a lockfile of that ecosystem not parsed, an entry
/// not told, a folder not listed. A clause this does not recognise counts for every ecosystem,
/// so that nothing reads as fully known that is not.
pub fn partial_for(reason: &str, lacks: &[Option<String>], ecosystem: &str) -> bool {
    let of_it = |name: &str| ecosystem_of(name) == Some(ecosystem);
    lacks.iter().any(|name| name.as_deref().is_none_or(of_it))
        || reason.split("; ").any(|clause| {
            if clause.starts_with(NOT_SUPPORTED_SAID) || clause.starts_with(NOT_OPENED_SAID) {
                false
            } else if let Some(names) = clause.strip_prefix("could not be read: ") {
                names.split(", ").any(of_it)
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

/// The kind of lockfile a file's name says, as this build names the kind; `None` for a name of
/// no lockfile. Names are matched ignoring case: macOS volumes ignore case by default, so
/// `Package-Lock.json` is the same file to its tool.
fn lockfile_kind(name: &str) -> Option<&'static str> {
    SUPPORTED
        .iter()
        .copied()
        .chain(NOT_SUPPORTED.iter().map(|(n, _)| *n))
        .find(|kind| kind.eq_ignore_ascii_case(name))
}

/// Where the walk found a lockfile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Where {
    /// Where lockfiles are opened.
    Opened,
    /// Below `MAX_DEPTH`.
    Deeper,
    /// In a folder set aside, at any depth.
    SetAside,
    /// A symbolic link, anywhere: not followed, so not opened.
    Linked,
}

/// What the walk of a checkout found: lockfiles relative to it, each with its kind and where.
struct Walk {
    lockfiles: Vec<(String, &'static str, Where)>,
    /// Whether every folder could be listed.
    listed: bool,
    /// Whether folders were left that the look limit kept it from looking through.
    stopped: bool,
}

/// Whether a file is a cache's tag: `CACHE_MARK` beginning with its signature.
fn cache_tag(name: &str, path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; CACHE_SIGNATURE.len()];
    name == CACHE_MARK
        && std::fs::File::open(path)
            .and_then(|mut f| f.read_exact(&mut head))
            .is_ok()
        && head == CACHE_SIGNATURE
}

/// Walks a checkout for lockfiles: opened down to `MAX_DEPTH`, as they always were, and below
/// it and in folders set aside looked for by name only, at most `limit` folders. Links are not
/// followed. A folder a mark says is not the project's is not looked at by that look; where
/// lockfiles are opened, marks change nothing.
fn walk(checkout: &Path, limit: usize) -> Walk {
    let mut out = Walk {
        lockfiles: Vec::new(),
        listed: true,
        stopped: false,
    };
    let mut looked = 0;
    // Each folder with where it is and whether a mark above it says it is not the project's.
    let mut stack = vec![(
        String::new(),
        checkout.to_path_buf(),
        0,
        Where::Opened,
        false,
    )];
    while let Some((rel, dir, depth, at, not_own)) = stack.pop() {
        if at != Where::Opened {
            if looked == limit {
                out.stopped = true;
                continue;
            }
            looked += 1;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            out.listed = false;
            continue;
        };
        let (mut files, mut folders) = (Vec::new(), Vec::new());
        let (mut environment, mut whole) = (false, not_own);
        for entry in entries {
            let Ok(entry) = entry else {
                out.listed = false;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(file_type) = entry.file_type() else {
                out.listed = false;
                continue;
            };
            environment |= file_type.is_file() && name == ENVIRONMENT_MARK;
            whole |= depth > 0
                && (name == CHECKOUT_MARK
                    || (file_type.is_dir() && name == CONDA_MARK)
                    || (file_type.is_file() && cache_tag(&name, &entry.path())));
            if file_type.is_dir() {
                if !NEVER_ENTERED.contains(&name.as_str()) {
                    folders.push((name, entry.path()));
                }
            } else if let Some(kind) = lockfile_kind(&name) {
                if file_type.is_symlink() {
                    files.push((name, kind, Where::Linked));
                } else if file_type.is_file() {
                    files.push((name, kind, at));
                }
            }
        }
        // The look for names does not look at what a mark says is not the project's.
        if at != Where::Opened && whole {
            continue;
        }
        out.lockfiles.extend(
            files
                .into_iter()
                .map(|(name, kind, at)| (format!("{rel}{name}"), kind, at)),
        );
        for (name, path) in folders {
            let next = match at {
                Where::Opened if name.starts_with('.') || name == SET_ASIDE_FOLDER => {
                    Where::SetAside
                }
                Where::Opened if depth == MAX_DEPTH => Where::Deeper,
                other => other,
            };
            let not_own = whole || (environment && ENVIRONMENT_LAYOUT.contains(&name.as_str()));
            stack.push((format!("{rel}{name}/"), path, depth + 1, next, not_own));
        }
    }
    out.lockfiles.sort();
    out
}

/// What one walk of a checkout gives the indicators reader to look for strings in, relative
/// to the checkout: the lockfiles of the kinds read here that are opened as text, those found
/// and not opened, and whether every folder could be listed and the walk went to its end.
pub struct Texts {
    pub opened: Vec<String>,
    pub not_opened: Vec<String>,
    pub listed: bool,
    pub stopped: bool,
}

pub fn read_as_text(checkout: &Path) -> Texts {
    let walked = walk(checkout, LOOK_LIMIT);
    let (opened, not_opened) = (walked.lockfiles.into_iter())
        .filter(|(_, kind, _)| SUPPORTED.contains(kind))
        .partition::<Vec<_>, _>(|(_, _, at)| *at == Where::Opened);
    let paths = |found: Vec<(String, &str, Where)>| found.into_iter().map(|(p, ..)| p).collect();
    Texts {
        opened: paths(opened),
        not_opened: paths(not_opened),
        listed: walked.listed,
        stopped: walked.stopped,
    }
}

/// Reads one checkout. `None` when it holds no lockfile at all: then there is nothing
/// to cover. Where the checkout is, is said by the `checkouts` reader.
pub fn read(checkout: &Checkout, id: &str) -> Option<Outcome> {
    read_within(checkout, id, LOOK_LIMIT)
}

/// `read`, with the look for names below the folders opened stopping after `limit` folders.
fn read_within(checkout: &Checkout, id: &str, limit: usize) -> Option<Outcome> {
    let walked = walk(&checkout.path, limit);
    if walked.lockfiles.is_empty() && walked.listed && !walked.stopped {
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
    // Lockfiles of a kind read here that were not opened, by where, and their kinds.
    let mut not_opened: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut lacks: BTreeSet<(&'static str, &str)> = BTreeSet::new();
    let mut lockfiles = Vec::new();
    // (ecosystem, name with its source) -> where it was first read, and version -> where
    // that version was first read.
    let mut deps: BTreeMap<(&str, String), Found> = BTreeMap::new();

    for (rel, kind, at) in &walked.lockfiles {
        let source = format!("{prefix}{rel}");
        let name: &str = kind;
        // A kind with no reader is that wherever it is; one read here is not opened where the
        // walk does not open lockfiles, or when it is a link, and is named as such.
        let unopened = match at {
            Where::Opened => None,
            Where::Deeper => Some(DEEPER),
            Where::SetAside => Some(SET_ASIDE),
            Where::Linked => Some(LINKED),
        };
        if let Some(what) = unopened {
            if SUPPORTED.contains(&name) {
                not_opened.entry(what).or_default().push(source);
                lacks.insert((what, name));
            } else {
                not_supported.insert(name.to_string());
            }
            continue;
        }
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
        reasons.push(format!("{NOT_SUPPORTED_SAID}{}", names.join(", ")));
    }
    for (what, paths) in &not_opened {
        let shown: Vec<&str> = paths.iter().take(3).map(String::as_str).collect();
        let more = if paths.len() > shown.len() {
            ", …"
        } else {
            ""
        };
        let place = match *what {
            DEEPER => format!("deeper than {MAX_DEPTH} folders"),
            LINKED if paths.len() == 1 => "that is a link".to_string(),
            LINKED => "that are links".to_string(),
            _ => "in vendor or hidden folders".to_string(),
        };
        reasons.push(format!(
            "{NOT_OPENED_SAID}{} {place}: {}{more}",
            if paths.len() == 1 {
                "1 lockfile".to_string()
            } else {
                format!("{} lockfiles", paths.len())
            },
            shown.join(", ")
        ));
    }
    if walked.stopped {
        reasons.push(format!(
            "{NOT_OPENED_SAID}what lies past the first {limit} folders looked through \
             for lockfiles below {MAX_DEPTH} folders or in vendor and hidden folders"
        ));
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
    if !walked.listed {
        reasons.push("a folder could not be listed".to_string());
    }
    // A lockfile that could not be read or a folder that could not be listed failed; a kind
    // of lockfile without a reader, a lockfile not opened where it is and folders not looked
    // through are no reader; an entry the lockfile does not say enough about is not given.
    // The reading takes the worst.
    let mut causes = Vec::new();
    if !not_parsed.is_empty() || !walked.listed {
        causes.push(Cause::Failed);
    }
    if !not_supported.is_empty() || !lacks.is_empty() || walked.stopped {
        causes.push(Cause::NoReader);
    }
    if !not_told.is_empty() {
        causes.push(Cause::NotGiven);
    }
    // What was not read, each by name where it has one, so that what it leaves unknown is
    // decided from these and never from the reason's words (`partial_for`).
    let gap = Gap {
        cause: Cause::worst(causes),
        lacks: not_supported
            .iter()
            .map(|name| Lack::new(LOCKFILE_KIND, Some(name)))
            .chain(lacks.iter().map(|(what, name)| Lack::new(what, Some(name))))
            .chain(walked.stopped.then(|| Lack::new(NOT_LOOKED, None)))
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

/// The commit the checkout is at, read from `.git` by hand, or `unknown`. `Err` names the
/// folder macOS asks permission for that the git folder is in, which is not entered; `homes`
/// are the home folder's names.
pub fn commit(checkout: &Path, homes: &[&Path]) -> Result<String, PathBuf> {
    Ok(read_commit(checkout, homes)?.unwrap_or_else(|| "unknown".to_string()))
}

fn read_commit(checkout: &Path, homes: &[&Path]) -> Result<Option<String>, PathBuf> {
    // `.git` itself may be a link, which is not followed into a guarded folder.
    let dotgit = crate::guarded::followed(&checkout.join(".git"), homes)?;
    // A worktree or a submodule has a `.git` file that points at the real folder. Where it
    // points is data, so it is made real without entering a guarded folder.
    let real = |p: PathBuf| match crate::guarded::real(&p, homes) {
        crate::guarded::Real::At(p) => Ok(Some(p)),
        crate::guarded::Real::Guarded(g) => Err(g),
        crate::guarded::Real::Failed(_) => Ok(None),
    };
    let gitdir = if dotgit.is_dir() {
        dotgit
    } else {
        let Some(to) = std::fs::read_to_string(&dotgit)
            .ok()
            .and_then(|text| Some(text.trim().strip_prefix("gitdir:")?.trim().to_string()))
        else {
            return Ok(None);
        };
        match real(checkout.join(to))? {
            Some(p) => p,
            None => return Ok(None),
        }
    };
    let common = match std::fs::read_to_string(gitdir.join("commondir")) {
        Ok(text) => match real(gitdir.join(text.trim()))? {
            Some(p) => p,
            None => return Ok(None),
        },
        Err(_) => gitdir.clone(),
    };
    head_commit(&gitdir, &common, homes)
}

fn head_commit(gitdir: &Path, common: &Path, homes: &[&Path]) -> Result<Option<String>, PathBuf> {
    let Ok(head) = std::fs::read_to_string(gitdir.join("HEAD")) else {
        return Ok(None);
    };
    let head = head.trim();
    let Some(name) = head.strip_prefix("ref:").map(str::trim) else {
        return Ok(is_hash(head).then(|| head.to_string()));
    };
    for dir in [gitdir, common] {
        // The name of the ref is data: the file it names is not looked for in a guarded
        // folder.
        let path = match crate::guarded::real(&dir.join(name), homes) {
            crate::guarded::Real::Guarded(g) => return Err(g),
            crate::guarded::Real::At(path) => path,
            crate::guarded::Real::Failed(_) => continue,
        };
        if let Ok(hash) = std::fs::read_to_string(path) {
            let hash = hash.trim();
            return Ok(is_hash(hash).then(|| hash.to_string()));
        }
    }
    let Ok(packed) = std::fs::read_to_string(common.join("packed-refs")) else {
        return Ok(None);
    };
    Ok(packed.lines().find_map(|line| {
        let (hash, refname) = line.split_once(' ')?;
        (refname.trim() == name && is_hash(hash)).then(|| hash.to_string())
    }))
}

fn is_hash(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_SIGNATURE, Checkout, DEEPER, LINKED, LOCKFILE_KIND, NOT_LOOKED, SET_ASIDE,
        ecosystem_of, partial_for, read, read_as_text, read_within,
    };

    fn file_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }
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
            let dir =
                std::env::temp_dir().join(format!("immunity-lock-{tag}-{}", std::process::id()));
            crate::common::remove(&dir);
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
            crate::common::remove(&self.0);
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
            let lacks: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
            assert!(super::partial_for(&reason, &lacks, "npm"));
            assert!(!super::partial_for(&reason, &lacks, "crates.io"));
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

    /// The lacks of a reading by what and name, as `what name`.
    fn lacks(o: &super::Outcome) -> Vec<String> {
        o.gap
            .lacks
            .iter()
            .map(|l| format!("{} {}", l.what, l.name.as_deref().unwrap_or("-")))
            .collect()
    }

    /// Whether the reading leaves each of npm and crates.io in part unknown.
    fn unknown_for(o: &super::Outcome) -> [bool; 2] {
        let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
        let reason = o.reason.as_deref().unwrap_or_default();
        ["npm", "crates.io"].map(|e| o.completeness == "partial" && partial_for(reason, &names, e))
    }

    #[test]
    fn a_lockfile_the_walk_does_not_open_makes_the_reading_partial_for_its_ecosystem_by_its_kind() {
        // No false calm. A lockfile below the folders the reader opens, or in `vendor` or a
        // hidden folder, is named by its kind in a lack of its own, and leaves its ecosystem
        // unknown: never a reading in full beside a `Cargo.lock` at the root.
        for (tag, path, what, eco) in [
            (
                "deep",
                "apps/web/client/ui/desk/package-lock.json",
                DEEPER,
                [true, false],
            ),
            (
                "vendor",
                "vendor/app/package-lock.json",
                SET_ASIDE,
                [true, false],
            ),
            (
                "hidden",
                ".github/actions/deploy/package-lock.json",
                SET_ASIDE,
                [true, false],
            ),
            (
                "deep-cargo",
                "a/b/c/d/tool/Cargo.lock",
                DEEPER,
                [false, true],
            ),
            (
                "vendor-deep",
                "vendor/a/b/c/d/e/pnpm-lock.yaml",
                SET_ASIDE,
                [true, false],
            ),
        ] {
            let dir = Dir::new(tag, &[("Cargo.lock", CARGO), (path, NPM)]);
            let (o, said) = dir.read();
            assert!(!said.iter().any(|s| s.contains("npm/")), "{tag}: {said:?}");
            assert_eq!(o.completeness, "partial", "{tag}");
            assert_eq!(o.gap.cause, Some(Cause::NoReader), "{tag}");
            let kind = file_name(path);
            assert_eq!(lacks(&o), [format!("{what} {kind}")], "{tag}");
            assert!(
                o.reason
                    .as_deref()
                    .unwrap()
                    .contains(&format!("dev/shop/{path}")),
                "{tag}"
            );
            assert_eq!(unknown_for(&o), eco, "{tag}");
            // Not opened, so neither in the copy of what was read nor read as text.
            assert_eq!(o.lockfiles.len(), 1, "{tag}");
            assert_eq!(read_as_text(&dir.0).opened, ["Cargo.lock"], "{tag}");
        }
    }

    #[test]
    fn a_lockfile_of_an_ecosystem_with_no_reader_is_named_as_a_kind_wherever_it_is() {
        // `Pipfile.lock`, `Gemfile.lock` and the rest of the published list are lockfiles: one
        // beside a `Cargo.lock` is a kind with no reader, by name, whether at the root, deep or
        // set aside. It leaves its own ecosystem unknown and no other: a deep `uv.lock` makes
        // PyPI partial and not npm, and a name of no ecosystem a record can be about leaves none.
        for (tag, path, eco) in [
            ("uv-deep", "a/b/c/d/e/uv.lock", Some("PyPI")),
            ("pipfile", "Pipfile.lock", Some("PyPI")),
            ("gemfile", "api/Gemfile.lock", Some("RubyGems")),
            (
                "composer-deep",
                "a/b/c/d/e/composer.lock",
                Some("Packagist"),
            ),
            ("mix-vendor", "vendor/x/mix.lock", Some("Hex")),
            ("pubspec", "app/pubspec.lock", Some("Pub")),
            ("swift", "Package.resolved", Some("SwiftURL")),
            ("flake", "flake.lock", None),
        ] {
            let dir = Dir::new(tag, &[("Cargo.lock", CARGO), (path, "{}\n")]);
            let (o, _) = dir.read();
            let kind = file_name(path);
            assert_eq!(lacks(&o), [format!("{LOCKFILE_KIND} {kind}")], "{tag}");
            assert_eq!(ecosystem_of(kind), eco, "{tag}");
            assert_eq!(o.completeness, "partial", "{tag}");
            assert_eq!(unknown_for(&o), [false, false], "{tag}");
            let names: Vec<Option<String>> = o.gap.lacks.iter().map(|l| l.name.clone()).collect();
            if let Some(eco) = eco {
                assert!(
                    partial_for(o.reason.as_deref().unwrap(), &names, eco),
                    "{tag}"
                );
            }
        }
    }

    #[test]
    fn a_folder_of_installed_copies_build_output_an_environment_or_a_cache_holds_no_lockfile_of_the_project()
     {
        // A project read in full stays full. What `node_modules`, `target`, `.git`, a Python
        // environment's own folders, a conda environment, a tagged cache and another checkout
        // hold is not what the project declares, so a lockfile the look for names finds inside
        // one leaves nothing unknown. A `CACHEDIR.TAG` without its signature marks nothing.
        let tag = std::str::from_utf8(CACHE_SIGNATURE).unwrap();
        let dir = Dir::new(
            "set-aside-not",
            &[
                ("Cargo.lock", CARGO),
                ("node_modules/left-pad/package-lock.json", NPM),
                ("web/node_modules/x/yarn.lock", ""),
                ("target/package/app-0.1.0/Cargo.lock", CARGO),
                (".git/modules/x/package-lock.json", NPM),
                (".venv/pyvenv.cfg", "home = /usr/bin\n"),
                (
                    ".venv/lib/python3.12/site-packages/lab/staging/yarn.lock",
                    "",
                ),
                ("env/pyvenv.cfg", "home = /usr/bin\n"),
                ("env/lib/python3.12/site-packages/lab/staging/yarn.lock", ""),
                (".conda/conda-meta/history", ""),
                (".conda/pkgs/x/package-lock.json", NPM),
                ("envs/py/conda-meta/history", ""),
                ("envs/py/share/a/b/package-lock.json", NPM),
                (".cache/CACHEDIR.TAG", &format!("{tag}\n# a cache\n")),
                (".cache/x/package-lock.json", NPM),
                ("src/a/b/c/d/e/f/main.rs", ""),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!((o.completeness, o.reason.as_deref()), ("full", None));
        assert!(o.gap.lacks.is_empty());
        let read: Vec<&str> = o.lockfiles.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(read, ["dev/shop/Cargo.lock"]);
        let dir = Dir::new(
            "unsigned-tag",
            &[
                ("Cargo.lock", CARGO),
                (
                    ".cache/CACHEDIR.TAG",
                    "Signature: 0000000000000000000000000000000\n",
                ),
                (".cache/x/package-lock.json", NPM),
            ],
        );
        assert_eq!(
            lacks(&dir.read().0),
            [format!("{SET_ASIDE} package-lock.json")]
        );
        // A project's own folder holding such a file is still the project's.
        let dir = Dir::new(
            "marked-root",
            &[("Cargo.lock", CARGO), ("pyvenv.cfg", "home = /usr/bin\n")],
        );
        assert!(!dir.read().1.is_empty());
    }

    #[test]
    fn a_mark_never_changes_which_lockfiles_are_opened() {
        // No false calm. A folder within the four the reader opens is opened as it always was,
        // whatever marks it holds: a `package-lock.json` beside a `pyvenv.cfg`, a signed
        // `CACHEDIR.TAG`, a `conda-meta` or a `.git` is read, and read as text.
        let tag = format!("{}\n", std::str::from_utf8(CACHE_SIGNATURE).unwrap());
        for (mark, text) in [
            ("pyvenv.cfg", "home = /usr/bin\n"),
            ("CACHEDIR.TAG", tag.as_str()),
            ("conda-meta/history", ""),
            (".git", "gitdir: ../.git/worktrees/web\n"),
            (".git/HEAD", "ref: refs/heads/main\n"),
        ] {
            let dir = Dir::new(
                "marked-opened",
                &[
                    (&format!("web/{mark}") as &str, text),
                    ("web/package-lock.json", NPM),
                    ("web/a/b/package-lock.json", NPM),
                ],
            );
            let (o, said) = dir.read();
            assert!(
                said.iter().any(|s| s.contains("npm/string-width")),
                "{mark}"
            );
            assert_eq!(
                (o.completeness, o.reason.as_deref()),
                ("full", None),
                "{mark}"
            );
            assert_eq!(
                read_as_text(&dir.0).opened,
                ["web/a/b/package-lock.json", "web/package-lock.json"],
                "{mark}"
            );
        }
    }

    #[test]
    fn a_lockfile_beside_an_environment_made_in_place_is_still_looked_for() {
        // People make a Python environment in a project's own folder: only the environment's
        // own folders are not looked into, so a lockfile deep beside them is told.
        let dir = Dir::new(
            "venv-in-place",
            &[
                ("Cargo.lock", CARGO),
                ("svc/pyvenv.cfg", "home = /usr/bin\n"),
                (
                    "svc/lib/python3.12/site-packages/x/a/package-lock.json",
                    NPM,
                ),
                ("svc/bin/a/b/c/package-lock.json", NPM),
                ("svc/web/client/ui/desk/package-lock.json", NPM),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!(lacks(&o), [format!("{DEEPER} package-lock.json")]);
        assert!(
            o.reason
                .as_deref()
                .unwrap()
                .ends_with(": dev/shop/svc/web/client/ui/desk/package-lock.json")
        );
    }

    #[test]
    fn another_checkout_inside_a_project_is_not_looked_into() {
        // A worktree an agent made, a submodule or a nested repository is a project of its own:
        // the look for names stops at its `.git`, a file or a folder, and the project stays full.
        let dir = Dir::new(
            "nested-checkout",
            &[
                ("Cargo.lock", CARGO),
                (
                    ".claude/worktrees/x/.git",
                    "gitdir: ../../../.git/worktrees/x\n",
                ),
                (".claude/worktrees/x/package-lock.json", NPM),
                ("vendor/dep/.git/HEAD", "ref: refs/heads/main\n"),
                ("vendor/dep/yarn.lock", ""),
                ("libs/sub/.git", "gitdir: ../../.git/modules/sub\n"),
                ("libs/sub/a/b/c/package-lock.json", NPM),
            ],
        );
        let (o, _) = dir.read();
        assert_eq!((o.completeness, o.reason.as_deref()), ("full", None));
    }

    #[test]
    fn a_lockfile_that_is_a_link_leaves_its_ecosystem_unknown() {
        // A link is not followed, so the lockfile it names is not opened: it is named by its
        // kind and leaves npm unknown, and not crates.io.
        let dir = Dir::new("linked", &[("Cargo.lock", CARGO), ("web/real.json", NPM)]);
        std::os::unix::fs::symlink("real.json", dir.0.join("web/package-lock.json")).unwrap();
        let (o, said) = dir.read();
        assert!(!said.iter().any(|s| s.contains("npm/")));
        assert_eq!(lacks(&o), [format!("{LINKED} package-lock.json")]);
        assert_eq!(unknown_for(&o), [true, false]);
    }

    #[test]
    fn a_lockfile_named_in_another_case_is_read_as_its_kind() {
        // macOS volumes ignore case by default, so npm reads `Package-Lock.json` as its lockfile.
        let dir = Dir::new(
            "case",
            &[("Package-Lock.json", NPM), ("api/CARGO.LOCK", CARGO)],
        );
        let (o, said) = dir.read();
        assert!(said.iter().any(|s| s.contains("npm/string-width")));
        assert!(said.iter().any(|s| s.contains("crates.io/serde")));
        assert_eq!(o.completeness, "full");
    }

    #[test]
    fn ordinary_projects_whose_lockfiles_are_all_opened_stay_read_in_full() {
        // No new partial reading for an ordinary project: lockfiles within four folders,
        // deep source trees, CI configuration and a vendored folder without a lockfile.
        let shapes: [&[(&str, &str)]; 5] = [
            &[("Cargo.lock", CARGO), ("src/a/b/c/d/e/f/g/lib.rs", "")],
            &[("package-lock.json", NPM), (".github/workflows/ci.yml", "")],
            &[
                ("pnpm-lock.yaml", PNPM_9),
                ("apps/web/client/ui/package-lock.json", NPM),
                ("packages/ui/src/a/b/c/d/index.ts", ""),
            ],
            &[("Cargo.lock", CARGO), ("vendor/lib/src/a.c", "")],
            &[
                ("app/package-lock.json", NPM),
                (".vscode/settings.json", "{}"),
            ],
        ];
        for (i, files) in shapes.iter().enumerate() {
            let dir = Dir::new(&format!("ordinary-{i}"), files);
            let (o, said) = dir.read();
            assert_eq!((o.completeness, o.reason.as_deref()), ("full", None), "{i}");
            assert!(!said.is_empty(), "{i}");
        }
    }

    #[test]
    fn folders_past_the_look_through_limit_leave_every_ecosystem_unknown() {
        // The walk below the folders it opens is bounded; what it did not look through is not
        // known to hold no lockfile, so it is a lack with no name, for every ecosystem.
        // `vendor` and the folders in it, as many as the walk looks through.
        let dir = Dir::new(
            "look-limit",
            &[
                ("Cargo.lock", CARGO),
                ("vendor/1/a", ""),
                ("vendor/2/a", ""),
            ],
        );
        let checkout = Checkout {
            rel: "dev/shop".to_string(),
            path: dir.0.clone(),
        };
        let within = |limit| read_within(&checkout, "checkout:machine:mac/dev/shop", limit);
        let o = within(3).unwrap();
        assert_eq!((o.completeness, o.reason), ("full", None));
        let o = within(2).unwrap();
        assert_eq!(lacks(&o), [format!("{NOT_LOOKED} -")]);
        assert_eq!(o.gap.cause, Some(Cause::NoReader));
        assert_eq!(unknown_for(&o), [true, true]);
        // Without a lockfile where it opens them, such a project is still not one with none.
        std::fs::remove_file(dir.0.join("Cargo.lock")).unwrap();
        assert_eq!(within(2).unwrap().completeness, "partial");
    }

    #[test]
    fn what_a_reading_did_not_open_is_decided_from_its_lacks_and_never_from_its_words() {
        // The words of a reason are for a person: a clause about a lockfile not opened or a
        // kind with no reader decides nothing, its lack does.
        let said = "not opened: 1 lockfile deeper than 4 folders: a/b/c/d/e/Cargo.lock; \
                    not supported yet: yarn.lock";
        for eco in ["npm", "crates.io"] {
            assert!(!partial_for(said, &[], eco), "{eco}");
        }
        let npm = [Some("package-lock.json".to_string())];
        assert!(partial_for(said, &npm, "npm"));
        assert!(!partial_for(said, &npm, "crates.io"));
        for eco in ["npm", "crates.io"] {
            assert!(partial_for(said, &[None], eco), "{eco}");
            assert!(
                !partial_for(said, &[Some("flake.lock".to_string())], eco),
                "{eco}"
            );
        }
    }
}
