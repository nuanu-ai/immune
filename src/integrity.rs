//! The `integrity` reader: whether what is installed changed while its version did not.
//! Persistence needs no autostart item: code appended to a program the owner starts every
//! day runs just as well. For every installed thing that has a version, content that
//! changed while the version stayed is the signal. This reader makes it visible as an
//! ordinary lifecycle event; turning that into a finding is a rule's work, see
//! `changed_in_place`.
//!
//! Three kinds of thing, each one reading scoped to the machine:
//!
//! - **Application bundles** in `/Applications` and `~/Applications`, direct children named
//!   `*.app`, and those one folder down (`/Applications/<folder>/<name>.app`), since
//!   installers put suites there. A symbolic link is not followed. Each is a component of
//!   the ecosystem `macos-app`, named by its bundle identifier, else by its folder name: its
//!   version, who signed it, whether its seal verifies, where it is, and a digest.
//! - **Homebrew kegs**, `<prefix>/Cellar/<name>/<version>` under the two prefixes Homebrew
//!   installs to. Each keg is a `file` entity named by its path, so a new version is a new
//!   entity and a file changed inside a keg is a `changed` digest of the same one.
//! - **Global npm packages**, `<prefix>/lib/node_modules/<name>` under the same prefixes, where
//!   Homebrew's node puts them. Each is a component of the ecosystem `npm`: version and digest.
//!
//! The digest is over every file's path and change time, never over content: content is never
//! read or kept. The kernel sets the change time on every write, rename, link and change of
//! mode, and a process cannot set it (setattrlist(2)), so a file written and given back its
//! old modification time still moves the digest; size, inode and modification time add
//! nothing to it. Folders themselves are left out, so that macOS adding an attribute to a
//! bundle's folder is not a change; so are Python's `__pycache__` folders, which Python writes
//! into kegs on its own.
//!
//! The seal of a bundle is verified by the Security framework (`codesign.rs`), with nested
//! code, every architecture and strict validation, which takes most of a minute for a
//! Mac's applications. So it is verified only for a bundle whose digest changed
//! since the last reading, or that has no verdict yet; otherwise the last verdict is carried
//! forward, and the reading's note says from when. Who signed it is asked on every reading:
//! that takes the signature alone.

use crate::codesign;
use crate::store::{Cause, Gap, Statement};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const READER: &str = "integrity";
pub const BASIS: &str = "observed";
pub const BUNDLES: &str = "application bundles in /Applications and ~/Applications";
pub const KEGS: &str = "Homebrew kegs";
pub const NPM: &str = "global npm packages";
pub const APP_SUPPORT: &str =
    "code kept by applications not signed by Apple under ~/Library/Application Support";
/// The raw copy: one line per thing with its path and facts, never content.
pub const RAW: &str = "integrity.txt";
/// The system's own tool for property lists, run by its absolute path.
pub const PLUTIL: &str = "/usr/bin/plutil";
/// Where Homebrew installs, Apple Silicon first, as paths from `/`.
const PREFIXES: [&str; 2] = ["opt/homebrew", "usr/local"];
/// Where Homebrew keeps kegs under a prefix.
const CELLAR: &str = "Cellar";
/// Where npm keeps global packages under a prefix.
const NODE_MODULES: &str = "lib/node_modules";
/// Folders a digest leaves out: Python writes them into a keg when it imports a module.
const SKIPPED: [&str; 1] = ["__pycache__"];

/// Kinds of file that are code, by extension: scripts, native modules and libraries, and
/// archives of code. A file anyone may run is code too, whatever its name. Python's compiled
/// files are left out: Python writes them by itself.
const CODE: [&str; 13] = [
    "js", "mjs", "cjs", "node", "dylib", "so", "py", "asar", "jar", "wasm", "sh", "rb", "lua",
];
/// Folders applications fill by themselves as they run: caches, web storage, crash reports and
/// logs. Code there is not compared. A name containing `cache` is one too.
const NOT_CODE: [&str; 7] = [
    "service worker",
    "indexeddb",
    "local storage",
    "session storage",
    "blob_storage",
    "crashpad",
    "logs",
];
/// How deep under a matched folder, and how many code files in it, are compared. A folder over
/// either is not recorded, and the reading says so.
const MAX_DEPTH: usize = 16;
const MAX_FILES: usize = 20_000;

/// What a reading's note says the reader cannot judge, kind by kind.
const BUNDLES_CANNOT: &str = "not covered: extended attributes, which no seal covers; a bundle changed and signed again shows only as another signer at the same version; an application that updates itself in place shows as a change of its digest";
const KEGS_CANNOT: &str = "compared by files' metadata between readings, since Homebrew keeps no record of a keg's files to verify against; __pycache__ folders are not compared";
const APP_SUPPORT_CANNOT: &str = "compared by the metadata of code files between readings; only a folder named like an application read here that Apple did not sign is looked into, so code kept under another name is not compared; caches, web storage, crash reports and logs are not compared";
const NPM_CANNOT: &str = "compared by files' metadata between readings, since npm keeps no record of a global package's files to verify against; a global folder set in npm's configuration or by a version manager is not looked for, and a linked package is not read";

/// Where places are resolved: the home folder, and the root of the system, `/` unless a test
/// gives another. `store` is the store this run writes, whose folder is the program's own.
pub struct Roots<'a> {
    pub home: &'a Path,
    pub system: &'a Path,
    pub store: &'a Path,
}

/// One thing read: its entity, its path as ids name it, its facts, and how its verdict was
/// reached, for the raw copy.
pub struct Thing {
    pub subject: String,
    pub shown: String,
    pub facts: Vec<(&'static str, String)>,
    pub how: String,
}

/// One reading: a kind of thing on this machine.
pub struct Kind {
    pub kind: &'static str,
    pub things: Vec<Thing>,
    /// Places or things that are there and could not be read, with why.
    pub failed: Vec<(String, String)>,
    /// Things not recorded because another one took their name first, by path.
    pub shared: Vec<String>,
    /// Things not recorded because they are over a cap, by path, with the cap.
    pub capped: Vec<(String, String)>,
    /// Places of this kind that are there.
    pub present: usize,
    /// What the full reading's note says besides what it cannot judge.
    pub notes: Vec<String>,
    /// Places not looked into because they lead into a folder macOS asks permission for,
    /// with why.
    pub unreached: Vec<(String, String)>,
    /// Those folders, for the reader's coverage.
    pub guarded: Vec<PathBuf>,
    cannot: &'static str,
}

impl Kind {
    fn new(kind: &'static str, cannot: &'static str) -> Kind {
        Kind {
            kind,
            things: Vec::new(),
            failed: Vec::new(),
            shared: Vec::new(),
            capped: Vec::new(),
            present: 0,
            notes: Vec::new(),
            unreached: Vec::new(),
            guarded: Vec::new(),
            cannot,
        }
    }

    /// Completeness, the reason or note, and why it is incomplete. A place that is not there
    /// is not a failure; a place or thing that could not be read makes the reading partial,
    /// so nothing of this kind is retracted, or none when nothing could be read.
    pub fn coverage(&self) -> (&'static str, String, Gap) {
        let mut said = Vec::new();
        if !self.failed.is_empty() {
            let failed: Vec<String> = self
                .failed
                .iter()
                .map(|(path, why)| format!("{path} ({why})"))
                .collect();
            said.push(format!("could not be read: {}", failed.join("; ")));
        }
        if !self.shared.is_empty() {
            said.push(format!(
                "not recorded, since another one has the same name: {}",
                self.shared.join("; ")
            ));
        }
        if !self.capped.is_empty() {
            let capped: Vec<String> = self
                .capped
                .iter()
                .map(|(path, cap)| format!("{path} ({cap})"))
                .collect();
            said.push(format!("not recorded, over a cap: {}", capped.join("; ")));
        }
        if !self.unreached.is_empty() {
            let unreached: Vec<String> = self
                .unreached
                .iter()
                .map(|(path, why)| format!("{path}: {why}"))
                .collect();
            said.push(format!(
                "{}{}",
                crate::guarded::NOT_LOOKED_INTO,
                unreached.join("; ")
            ));
        }
        let unrecorded =
            !self.shared.is_empty() || !self.capped.is_empty() || !self.unreached.is_empty();
        let cause = Cause::worst(
            (!self.failed.is_empty())
                .then_some(Cause::Failed)
                .into_iter()
                .chain(unrecorded.then_some(Cause::NotGiven)),
        );
        let completeness = match cause {
            None => "full",
            Some(_) if self.present == 0 => "none",
            Some(_) => "partial",
        };
        if self.present == 0 && cause.is_none() {
            said.push("none of these places is on this machine".to_string());
        }
        said.extend(self.notes.iter().cloned());
        said.push(self.cannot.to_string());
        (completeness, said.join("; "), Gap::when(cause))
    }

    /// The statements of this reading, each pointing at its line of the raw copy.
    pub fn statements(&self, raw_file: &str, lines: &[usize]) -> Vec<Statement> {
        let mut out = Vec::new();
        for (t, line) in self.things.iter().zip(lines) {
            for (predicate, object) in &t.facts {
                out.push(Statement {
                    subject: t.subject.clone(),
                    predicate,
                    object: object.clone(),
                    source_ref: format!("{raw_file}:{line}"),
                });
            }
        }
        out
    }
}

/// Reads every kind of thing. `conn` holds the last verdicts, carried forward for bundles that
/// did not move; `machine` is this machine's id.
pub fn read(conn: &Connection, roots: &Roots, machine: &str) -> rusqlite::Result<Vec<Kind>> {
    let bundles = bundles(conn, roots, machine)?;
    let app_support = app_support(roots, machine, &bundles);
    Ok(vec![
        bundles,
        kegs(roots, machine),
        npm(roots, machine),
        app_support,
    ])
}

/// What a code walk ran into.
enum Walked {
    Done,
    /// Over a cap: which one.
    Capped(String),
}

/// The records of every code file under `dir`, by path and change time, as `walk` makes them,
/// within the caps.
fn walk_code(
    dir: &Path,
    rel: &[u8],
    depth: usize,
    out: &mut Vec<u8>,
    files: &mut usize,
) -> std::io::Result<Walked> {
    let mut names = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<OsString>>>()?;
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let m = std::fs::symlink_metadata(&path)?;
        let text = name.to_string_lossy().to_lowercase();
        let mut here = rel.to_vec();
        here.push(b'/');
        here.extend_from_slice(name.as_bytes());
        if m.is_dir() {
            if text.contains("cache") || NOT_CODE.contains(&text.as_str()) {
                continue;
            }
            if depth == MAX_DEPTH {
                return Ok(Walked::Capped(format!("deeper than {MAX_DEPTH} folders")));
            }
            if let Walked::Capped(cap) = walk_code(&path, &here, depth + 1, out, files)? {
                return Ok(Walked::Capped(cap));
            }
            continue;
        }
        let extension = text.rsplit_once('.').map_or("", |(_, e)| e);
        if !CODE.contains(&extension) && m.mode() & 0o111 == 0 {
            continue;
        }
        *files += 1;
        if *files > MAX_FILES {
            return Ok(Walked::Capped(format!("more than {MAX_FILES} code files")));
        }
        out.extend_from_slice(&here);
        out.extend_from_slice(format!("\0{}.{}\n", m.ctime(), m.ctime_nsec()).as_bytes());
    }
    Ok(Walked::Done)
}

/// Code that applications keep outside their bundle, in `~/Library/Application Support`.
///
/// Only folders there whose name is, ignoring case, the bundle identifier or the name of an
/// application just read that Apple did not sign are looked into; the folder itself is listed
/// for names alone, and no other folder in it is ever opened. macOS guards some folders there
/// with a dialog or with Full Disk Access (contacts, call history, its own services), all
/// Apple's, so a folder named after an application from another developer is not one of them.
/// Each matched folder is one `file` entity with the version of its application, so a change
/// of its code while that version stayed is a `changed` digest with no `has_version` event.
///
/// The folder that holds the store in use is left out, whatever application it is named after.
/// It holds the program's own output: pages rewritten every few seconds and the scripts it
/// writes for the owner, so a change there says nothing about an application. And whoever can
/// write there can rewrite the store itself, which is not guarded against yet (`AGENTS.md`).
fn app_support(roots: &Roots, machine: &str, bundles: &Kind) -> Kind {
    let mut kind = Kind::new(APP_SUPPORT, APP_SUPPORT_CANNOT);
    // Each name of an application not signed by Apple, lowercased, with its version.
    let mut names: BTreeMap<String, Option<String>> = BTreeMap::new();
    for t in &bundles.things {
        let fact = |p: &str| t.facts.iter().find(|(q, _)| *q == p).map(|(_, o)| o);
        if fact("signed_by").is_some_and(|s| s == "apple") {
            continue;
        }
        let version = fact("has_version").cloned();
        let identifier = t.subject.rsplit_once("/macos-app/").map_or("", |(_, n)| n);
        let folder = t.shown.rsplit('/').next().unwrap_or_default();
        let stem = folder.strip_suffix(".app").unwrap_or(folder);
        for name in [identifier, stem] {
            names
                .entry(name.to_lowercase())
                .or_insert_with(|| version.clone());
        }
    }
    // An application that could not be read is not matched: its folder must not look gone.
    for (path, _) in &bundles.failed {
        kind.failed.push((
            path.clone(),
            "applications there could not be read, so their folders were not looked for"
                .to_string(),
        ));
    }
    let base = roots.home.join("Library/Application Support");
    if !reachable(&base, "Library/Application Support", roots, &mut kind) {
        return kind;
    }
    let entries = match list(&base) {
        None => return kind,
        Some(Err(e)) => {
            kind.failed
                .push(("Library/Application Support".to_string(), e.to_string()));
            return kind;
        }
        Some(Ok(entries)) => entries,
    };
    let own = roots.store.parent().map(same_place);
    kind.present += 1;
    let (mut matched, mut files) = (0, 0);
    for entry in entries {
        let text = entry.to_string_lossy().into_owned();
        let Some(version) = names.get(&text.to_lowercase()) else {
            continue;
        };
        let path = base.join(&entry);
        if !real_folder(&path) || own.as_ref() == Some(&same_place(&path)) {
            continue;
        }
        let shown = format!("Library/Application Support/{text}");
        matched += 1;
        let (mut records, mut count) = (Vec::new(), 0);
        match walk_code(&path, b"", 0, &mut records, &mut count) {
            Err(e) => kind.failed.push((shown, e.to_string())),
            Ok(Walked::Capped(cap)) => kind.capped.push((shown, cap)),
            Ok(Walked::Done) => {
                files += count;
                let mut facts = vec![("located_on", machine.to_string())];
                facts.extend(version.clone().map(|v| ("has_version", v)));
                facts.push((
                    "has_digest",
                    format!("stat:{}", crate::sha256::hex(&records)),
                ));
                kind.things.push(Thing {
                    subject: format!("file:{machine}/{shown}"),
                    shown,
                    facts,
                    how: format!("{count} code files"),
                });
            }
        }
    }
    kind.notes.push(format!(
        "{matched} folders matched an application, {files} code files compared"
    ));
    kind
}

/// The raw copy: kind, path, entity and facts, one line per thing; and each kind's line
/// numbers.
pub fn raw(kinds: &[Kind]) -> (String, Vec<Vec<usize>>) {
    let field = crate::watched::field;
    let (mut raw, mut lines, mut n) = (String::new(), Vec::new(), 0);
    for k in kinds {
        let mut mine = Vec::new();
        for t in &k.things {
            let facts: Vec<String> = t
                .facts
                .iter()
                .map(|(p, o)| format!("{p}={}", field(o)))
                .collect();
            raw.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                k.kind,
                field(&t.shown),
                field(&t.subject),
                facts.join("\t"),
                field(&t.how)
            ));
            n += 1;
            mine.push(n);
        }
        lines.push(mine);
    }
    (raw, lines)
}

/// The digest of a tree: every entry but folders, in order of path, by metadata alone.
pub fn digest(root: &Path) -> Result<String, String> {
    let mut records = Vec::new();
    walk(root, b"", &mut records).map_err(|e| e.to_string())?;
    Ok(format!("stat:{}", crate::sha256::hex(&records)))
}

fn walk(dir: &Path, rel: &[u8], out: &mut Vec<u8>) -> std::io::Result<()> {
    let mut names = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<OsString>>>()?;
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let m = std::fs::symlink_metadata(&path)?;
        let mut here = rel.to_vec();
        here.push(b'/');
        here.extend_from_slice(name.as_bytes());
        if m.is_dir() {
            if !SKIPPED.iter().any(|s| name == *s) {
                walk(&path, &here, out)?;
            }
            continue;
        }
        out.extend_from_slice(&here);
        out.extend_from_slice(format!("\0{}.{}\n", m.ctime(), m.ctime_nsec()).as_bytes());
    }
    Ok(())
}

/// Whether a place this reader starts at may be looked into: not when it leads into a folder
/// macOS asks permission for, through a link or as it is, which `kind` then says. Inside a
/// place no link is followed.
fn reachable(dir: &Path, shown: &str, roots: &Roots, kind: &mut Kind) -> bool {
    let homes = crate::watched::homes(roots.home);
    match crate::guarded::real(dir, &[&homes[0], &homes[1]]) {
        crate::guarded::Real::Guarded(g) => {
            let why = crate::guarded::leads_into(&g, roots.home);
            kind.unreached.push((shown.to_string(), why));
            if !kind.guarded.contains(&g) {
                kind.guarded.push(g);
            }
            false
        }
        _ => true,
    }
}

/// The names in a folder, sorted, or `None` when it is not there.
fn list(dir: &Path) -> Option<std::io::Result<Vec<OsString>>> {
    let listing = std::fs::read_dir(dir).and_then(|entries| {
        entries
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
    });
    match listing {
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Ok(mut names) => {
            names.sort();
            Some(Ok(names))
        }
        Err(e) => Some(Err(e)),
    }
}

/// Whether a path is a folder itself, not a link to one.
fn real_folder(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A path by what it resolves to, so that one folder reached through a link or a relative
/// path is still one folder; as it is given when it cannot be resolved.
fn same_place(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// One value of a property list, asked of the system's tool, or `None` when it has none.
fn plist_value(plist: &Path, key: &str) -> Option<String> {
    let out = Command::new(PLUTIL)
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    out.status.success().then(|| text.to_string())
}

/// The version as a bundle gives it: the short version, and the build in brackets when it
/// gives another one.
fn bundle_version(short: Option<String>, build: Option<String>) -> Option<String> {
    match (short, build) {
        (Some(s), Some(b)) if s != b => Some(format!("{s} ({b})")),
        (Some(s), _) => Some(s),
        (None, b) => b,
    }
}

/// A bundle found on disk.
struct Found {
    path: PathBuf,
    shown: String,
}

/// Where bundles are looked for, as ids name paths: the system's folder, and the home folder's.
const BUNDLE_PLACES: [&str; 2] = ["/Applications", "Applications"];

/// Whether the readings of this file that find programs look at the path `rel`, as ids name
/// paths: inside a bundle they find (a folder named `*.app` directly in a place of bundles or one
/// folder down), or under a Cellar or a global `node_modules` of one of Homebrew's prefixes.
pub fn reads(rel: &str) -> bool {
    let bundle = BUNDLE_PLACES.iter().any(|place| {
        rel.strip_prefix(place)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|rest| {
                let mut names = rest.split('/');
                let app = |n: Option<&str>| n.is_some_and(|n| n.ends_with(".app"));
                app(names.next()) || app(names.next())
            })
    });
    bundle
        || PREFIXES.iter().any(|p| {
            [CELLAR, NODE_MODULES]
                .iter()
                .any(|under| crate::known::within(rel, &format!("/{p}/{under}")))
        })
}

/// The bundles of both places, with the places that could not be listed.
fn find_bundles(roots: &Roots, kind: &mut Kind) -> Vec<Found> {
    let [system, home] = BUNDLE_PLACES;
    let places = [
        (roots.system.join(&system[1..]), system.to_string()),
        (roots.home.join(home), home.to_string()),
    ];
    let mut found = Vec::new();
    for (dir, shown) in places {
        if !reachable(&dir, &shown, roots, kind) {
            continue;
        }
        let names = match list(&dir) {
            None => continue,
            Some(Err(e)) => {
                kind.failed.push((shown, e.to_string()));
                continue;
            }
            Some(Ok(names)) => names,
        };
        kind.present += 1;
        for name in names {
            let path = dir.join(&name);
            let text = name.to_string_lossy();
            if !real_folder(&path) {
                continue;
            }
            let here = format!("{shown}/{text}");
            if text.ends_with(".app") {
                found.push(Found { path, shown: here });
                continue;
            }
            // One folder down, where installers put suites.
            match list(&path) {
                None => {}
                Some(Err(e)) => kind.failed.push((here, e.to_string())),
                Some(Ok(inner)) => {
                    for name in inner {
                        let text = name.to_string_lossy();
                        let inside = path.join(&name);
                        if text.ends_with(".app") && real_folder(&inside) {
                            found.push(Found {
                                path: inside,
                                shown: format!("{here}/{text}"),
                            });
                        }
                    }
                }
            }
        }
    }
    found
}

/// What the store holds of a bundle from the last reading: digest and seal, and when
/// the digest was first seen, which is when its seal was last verified.
struct Previous {
    digest: Option<String>,
    seal: Option<String>,
    verified_at: i64,
}

fn previous(conn: &Connection, subject: &str) -> rusqlite::Result<Previous> {
    let mut stmt = conn.prepare(
        "SELECT predicate, object, observed_at FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND subject = ?2
           AND predicate IN ('has_digest', 'has_seal')",
    )?;
    let mut values: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
    for row in stmt.query_map(params![READER, subject], |r| {
        Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
    })? {
        let (predicate, object, at) = row?;
        values.entry(predicate).or_default().push((object, at));
    }
    // Only one value is a value; two, left by a partial reading, are not to be trusted.
    let one = |p: &str| match values.get(p).map(Vec::as_slice) {
        Some([(object, at)]) => Some((object.clone(), *at)),
        _ => None,
    };
    let digest = one("has_digest");
    Ok(Previous {
        verified_at: digest.as_ref().map_or(0, |(_, at)| *at),
        digest: digest.map(|(d, _)| d),
        seal: one("has_seal").map(|(s, _)| s),
    })
}

/// A bundle read up to the point where the framework is asked about it.
struct Prepared {
    found: Found,
    subject: String,
    digest: String,
    version: Option<String>,
    /// The last verdict and when it was reached, when it is carried forward.
    carry: Option<(String, i64)>,
}

/// Who signed each bundle, and its seal unless its verdict is carried forward, asked of the
/// framework on several threads: verifying seals is most of this reader's time, and one call
/// takes one bundle. Each thread makes and drops its own code objects.
fn examine_all(prepared: &[Prepared]) -> Vec<(Option<String>, Option<String>)> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(vec![(None, None); prepared.len()]);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = prepared.get(i) else { break };
                    let verify = p.carry.is_none();
                    let result = match codesign::Code::at(&p.found.path) {
                        Ok(code) => (code.signer(), verify.then(|| code.seal())),
                        Err(status) => (None, verify.then(|| codesign::does_not_verify(status))),
                    };
                    if let Ok(mut all) = results.lock() {
                        all[i] = result;
                    }
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(|e| e.into_inner())
}

fn bundles(conn: &Connection, roots: &Roots, machine: &str) -> rusqlite::Result<Kind> {
    let mut kind = Kind::new(BUNDLES, BUNDLES_CANNOT);
    let found = find_bundles(roots, &mut kind);
    let mut names = BTreeSet::new();
    let mut prepared = Vec::new();
    for f in found {
        let digest = match digest(&f.path) {
            Ok(d) => d,
            Err(why) => {
                kind.failed.push((f.shown, why));
                continue;
            }
        };
        let plist = f.path.join("Contents/Info.plist");
        let folder = f.path.file_name().unwrap_or_default().to_string_lossy();
        let name = plist_value(&plist, "CFBundleIdentifier").unwrap_or_else(|| folder.to_string());
        if !names.insert(name.clone()) {
            kind.shared.push(f.shown);
            continue;
        }
        let version = bundle_version(
            plist_value(&plist, "CFBundleShortVersionString"),
            plist_value(&plist, "CFBundleVersion"),
        );
        let subject = format!("component:{machine}/macos-app/{name}");
        let before = previous(conn, &subject)?;
        // The Info.plist is in the digest: a new version is a new digest.
        let unmoved = before.digest.as_ref() == Some(&digest);
        let carry = before
            .seal
            .filter(|_| unmoved)
            .map(|s| (s, before.verified_at));
        prepared.push(Prepared {
            found: f,
            subject,
            digest,
            version,
            carry,
        });
    }
    let examined = examine_all(&prepared);
    let (mut verified, mut carried, mut oldest) = (0, 0, i64::MAX);
    for (p, (signer, seal)) in prepared.into_iter().zip(examined) {
        let (seal, how) = match (seal, p.carry) {
            (Some(seal), _) => {
                verified += 1;
                (seal, "verified".to_string())
            }
            (None, Some((seal, at))) => {
                carried += 1;
                oldest = oldest.min(at);
                (
                    seal,
                    format!("carried forward from {}", crate::view::iso(at)),
                )
            }
            // A thread that could not record its answer: never taken for a bundle gone.
            (None, None) => {
                kind.failed
                    .push((p.found.shown, "not examined".to_string()));
                continue;
            }
        };
        let mut facts = vec![
            ("part_of", machine.to_string()),
            ("installed_at", p.found.shown.clone()),
        ];
        facts.extend(p.version.map(|v| ("has_version", v)));
        facts.extend(signer.map(|s| ("signed_by", s)));
        facts.push(("has_seal", seal));
        facts.push(("has_digest", p.digest));
        kind.things.push(Thing {
            subject: p.subject,
            shown: p.found.shown,
            facts,
            how,
        });
    }
    let mut note = format!("seal verified for {verified}");
    if carried > 0 {
        note.push_str(&format!(
            ", carried forward for {carried} whose digest and version did not change, from their last verification, the oldest {}",
            crate::view::utc(oldest)
        ));
    }
    if kind.present > 0 {
        kind.notes.push(note);
    }
    Ok(kind)
}

/// Each prefix of Homebrew under the system root, and its path from `/`.
fn prefixes(roots: &Roots, under: &str) -> Vec<(PathBuf, String)> {
    PREFIXES
        .iter()
        .map(|p| (roots.system.join(p).join(under), format!("/{p}/{under}")))
        .collect()
}

fn kegs(roots: &Roots, machine: &str) -> Kind {
    let mut kind = Kind::new(KEGS, KEGS_CANNOT);
    for (cellar, shown) in prefixes(roots, CELLAR) {
        if !reachable(&cellar, &shown, roots, &mut kind) {
            continue;
        }
        let names = match list(&cellar) {
            None => continue,
            Some(Err(e)) => {
                kind.failed.push((shown, e.to_string()));
                continue;
            }
            Some(Ok(names)) => names,
        };
        kind.present += 1;
        for name in names {
            let formula = cellar.join(&name);
            let here = format!("{shown}/{}", name.to_string_lossy());
            if !real_folder(&formula) {
                continue;
            }
            let versions = match list(&formula) {
                None => continue,
                Some(Err(e)) => {
                    kind.failed.push((here, e.to_string()));
                    continue;
                }
                Some(Ok(versions)) => versions,
            };
            for version in versions {
                let keg = formula.join(&version);
                let shown = format!("{here}/{}", version.to_string_lossy());
                if !real_folder(&keg) {
                    continue;
                }
                match digest(&keg) {
                    Err(why) => kind.failed.push((shown, why)),
                    Ok(d) => kind.things.push(Thing {
                        subject: format!("file:{machine}/{shown}"),
                        facts: vec![("located_on", machine.to_string()), ("has_digest", d)],
                        shown,
                        how: String::new(),
                    }),
                }
            }
        }
    }
    kind
}

/// The version a package's `package.json`, `file`, gives, if it gives one.
fn package_version(file: &Path) -> Option<String> {
    let text = std::fs::read(file).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

fn npm(roots: &Roots, machine: &str) -> Kind {
    let mut kind = Kind::new(NPM, NPM_CANNOT);
    let homes = crate::watched::homes(roots.home);
    let mut names = BTreeSet::new();
    for (root, shown) in prefixes(roots, NODE_MODULES) {
        if !reachable(&root, &shown, roots, &mut kind) {
            continue;
        }
        let entries = match list(&root) {
            None => continue,
            Some(Err(e)) => {
                kind.failed.push((shown, e.to_string()));
                continue;
            }
            Some(Ok(entries)) => entries,
        };
        kind.present += 1;
        let mut packages = Vec::new();
        for entry in entries {
            let text = entry.to_string_lossy().into_owned();
            let path = root.join(&entry);
            if text.starts_with('.') || !real_folder(&path) {
                continue;
            }
            if !text.starts_with('@') {
                packages.push((text, path));
                continue;
            }
            match list(&path) {
                None => {}
                Some(Err(e)) => kind.failed.push((format!("{shown}/{text}"), e.to_string())),
                Some(Ok(scoped)) => {
                    for name in scoped {
                        let inside = path.join(&name);
                        if !name.as_bytes().starts_with(b".") && real_folder(&inside) {
                            packages.push((format!("{text}/{}", name.to_string_lossy()), inside));
                        }
                    }
                }
            }
        }
        for (name, path) in packages {
            let here = format!("{shown}/{name}");
            let d = match digest(&path) {
                Ok(d) => d,
                Err(why) => {
                    kind.failed.push((here, why));
                    continue;
                }
            };
            if !names.insert(name.clone()) {
                kind.shared.push(here);
                continue;
            }
            let mut facts = vec![
                ("part_of", machine.to_string()),
                ("installed_at", here.clone()),
            ];
            // Its `package.json` may be a link: not followed into a guarded folder.
            match crate::guarded::followed(&path.join("package.json"), &[&homes[0], &homes[1]]) {
                Ok(file) => facts.extend(package_version(&file).map(|v| ("has_version", v))),
                Err(g) => {
                    let why = crate::guarded::leads_into(&g, roots.home);
                    kind.unreached.push((format!("{here}/package.json"), why));
                    if !kind.guarded.contains(&g) {
                        kind.guarded.push(g);
                    }
                }
            }
            facts.push(("has_digest", d));
            kind.things.push(Thing {
                subject: format!("component:{machine}/npm/{name}"),
                shown: here,
                facts,
                how: String::new(),
            });
        }
    }
    kind
}

/// One change in place: kind, subject, predicate and the new value.
pub type InPlace = (String, String, String, Option<String>);

/// The changes of one run that a finding rule looks for: content that changed while the
/// version stayed. Each is a `changed` event of this reader on `has_seal` or `signed_by` of a
/// bundle, or on `has_digest` of a keg or a global package, whose subject has no `has_version`
/// event in the same run. A first reading has no `changed` events, so it adds nothing here.
/// Returns kind, subject, predicate and new value, in the order of the journal.
pub fn changed_in_place(conn: &Connection, run_id: &str) -> rusqlite::Result<Vec<InPlace>> {
    conn.prepare(
        "SELECT j.kind, j.subject, j.predicate, j.new_value FROM journal j
         WHERE j.run_id = ?1 AND j.reader = ?2 AND j.entry = 'changed'
           AND ((j.kind = ?3 AND j.predicate IN ('has_seal', 'signed_by'))
                OR (j.kind IN (?4, ?5, ?6) AND j.predicate = 'has_digest'))
           AND NOT EXISTS (SELECT 1 FROM journal v
                           WHERE v.run_id = j.run_id AND v.reader = j.reader
                             AND v.subject = j.subject AND v.predicate = 'has_version')
         ORDER BY j.seq",
    )?
    .query_map(
        params![run_id, READER, BUNDLES, KEGS, NPM, APP_SUPPORT],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?
    .collect()
}

/// What the rules read of a run, from `changed_in_place`. A seal that verifies again is not
/// one: only a seal that does not verify now is.
pub fn observed(
    conn: &Connection,
    run_id: &str,
) -> rusqlite::Result<Vec<crate::findings::Observed>> {
    let mut out = Vec::new();
    for (kind, subject, predicate, new) in changed_in_place(conn, run_id)? {
        if kind == BUNDLES && predicate == "has_seal" && new.as_deref() == Some(codesign::VERIFIES)
        {
            continue;
        }
        out.push(crate::findings::Observed {
            change: "changed",
            place: place(&kind, &predicate).to_string(),
            file: subject,
        });
    }
    Ok(out)
}

/// What the rules are told changed when a fact of an installed thing changed in place.
fn place(kind: &str, predicate: &str) -> &'static str {
    match (kind, predicate) {
        (BUNDLES, "has_seal") => SEAL_BROKEN,
        (BUNDLES, _) => SIGNER_CHANGED,
        (APP_SUPPORT, _) => CODE_OUTSIDE_CHANGED,
        _ => FILES_CHANGED,
    }
}

/// Everything the rules can be told about installed things of one kind: what `observed`
/// gives for each fact `changed_in_place` looks at.
pub fn places(kind: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = ["has_seal", "signed_by", "has_digest"]
        .iter()
        .map(|p| place(kind, p))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// What the rules are told changed, each the kind of its findings.
pub const SEAL_BROKEN: &str = "application changed inside its signature";
pub const SIGNER_CHANGED: &str = "application signed by someone else";
pub const FILES_CHANGED: &str = "installed package changed in place";
pub const CODE_OUTSIDE_CHANGED: &str = "application code changed outside its bundle";

/// What the last run learned of what is installed, for the report line and `immune status`.
pub struct Summary {
    /// No reading of this reader was made before this run: this one is the baseline.
    pub first: bool,
    pub bundles: i64,
    /// Live bundles by the class of who signed them: the literal before its first comma.
    pub signers: BTreeMap<String, i64>,
    pub not_verifying: i64,
    /// Of those, the ones that did not verify already at the reader's first reading.
    pub not_verifying_since_first: i64,
    /// Bundles whose seal this run verified, and those whose verdict it carried forward.
    pub verified: i64,
    pub carried: i64,
    pub kegs: i64,
    pub packages: i64,
    /// Folders of applications' code under Application Support.
    pub app_folders: i64,
    /// Things whose content changed while their version stayed, in this run.
    pub changed_in_place: usize,
    /// This run's readings, kind, completeness and reason, in the order of reading.
    pub readings: Vec<(String, String, Option<String>)>,
}

/// What `run_id` left, or `None` when this reader never read.
pub fn summary(conn: &Connection, run_id: &str) -> rusqlite::Result<Option<Summary>> {
    if !crate::store::read_any(conn, READER)? {
        return Ok(None);
    }
    let count = |sql: &str, kind: &str| -> rusqlite::Result<i64> {
        conn.query_row(sql, params![READER, kind], |r| r.get(0))
    };
    let live = "SELECT COUNT(DISTINCT subject) FROM assertion
                WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND predicate = 'has_digest'";
    let mut signers = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT object FROM assertion WHERE layer = 'live' AND reader = ?1 AND kind = ?2
           AND predicate = 'signed_by'",
    )?;
    for row in stmt.query_map(params![READER, BUNDLES], |r| r.get::<_, String>(0))? {
        let signer = row?;
        let class = signer.split(',').next().unwrap_or_default().to_string();
        *signers.entry(class).or_default() += 1;
    }
    let first_run: Option<String> = conn
        .query_row(
            "SELECT run_id FROM coverage WHERE reader = ?1 AND kind = ?2
               AND completeness != 'none' ORDER BY id LIMIT 1",
            params![READER, BUNDLES],
            |r| r.get(0),
        )
        .optional()?;
    let not_verifying = |since: Option<&str>| -> rusqlite::Result<i64> {
        conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND predicate = 'has_seal'
               AND object != ?3 AND (?4 IS NULL OR run_id = ?4)",
            params![READER, BUNDLES, codesign::VERIFIES, since],
            |r| r.get(0),
        )
    };
    let verified: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND kind = ?2 AND run_id = ?3
           AND predicate IN ('has_digest', 'has_version', 'has_seal')",
        params![READER, BUNDLES, run_id],
        |r| r.get(0),
    )?;
    let bundles = count(live, BUNDLES)?;
    let mut readings = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT kind, completeness, reason FROM coverage WHERE reader = ?1 AND run_id = ?2
         ORDER BY id",
    )?;
    for row in stmt.query_map(params![READER, run_id], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    })? {
        readings.push(row?);
    }
    Ok(Some(Summary {
        first: !conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM coverage WHERE reader = ?1 AND run_id != ?2)",
            params![READER, run_id],
            |r| r.get(0),
        )?,
        bundles,
        signers,
        not_verifying: not_verifying(None)?,
        not_verifying_since_first: match &first_run {
            Some(first) => not_verifying(Some(first))?,
            None => 0,
        },
        verified,
        carried: bundles - verified,
        kegs: count(live, KEGS)?,
        packages: count(live, NPM)?,
        app_folders: count(live, APP_SUPPORT)?,
        changed_in_place: changed_in_place(conn, run_id)?
            .iter()
            .map(|(_, subject, _, _)| subject)
            .collect::<BTreeSet<_>>()
            .len(),
        readings,
    }))
}

fn things(n: i64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One sentence for the report line. Paths and names are never in it.
pub fn sentence(s: Option<&Summary>) -> String {
    let Some(s) = s else {
        return "Installed software: never read.".to_string();
    };
    let counted = format!(
        "Installed software: {}, {}, {}",
        things(s.bundles, "application bundle", "application bundles"),
        things(s.kegs, "Homebrew keg", "Homebrew kegs"),
        things(s.packages, "global npm package", "global npm packages")
    );
    let mut line = if s.first {
        format!("{counted}, first reading, kept as the baseline")
    } else {
        format!(
            "{counted}, {} changed while the version stayed, since the last reading",
            s.changed_in_place
        )
    };
    if s.not_verifying > 0 {
        line.push_str(&format!(
            "; {} not verify, {} of them since the first reading",
            things(s.not_verifying, "bundle does", "bundles do"),
            s.not_verifying_since_first
        ));
    }
    let not_full: Vec<String> = s
        .readings
        .iter()
        .filter(|(_, completeness, _)| completeness != "full")
        .map(|(kind, completeness, _)| {
            let words = if completeness == "partial" {
                "partial"
            } else {
                "nothing read"
            };
            format!("{kind} ({words})")
        })
        .collect();
    if !not_full.is_empty() {
        line.push_str(&format!("; not read in full: {}", not_full.join(", ")));
    }
    line.push('.');
    line
}

/// `integrity` of the contract's `Status`: counts only, and each reading's own words, whole.
pub fn message(s: &Summary) -> crate::contract::v1::Integrity {
    use crate::contract::{v1, value_of};
    let n = |x: i64| u64::try_from(x).unwrap_or(0);
    v1::Integrity {
        first_reading: s.first,
        bundles: n(s.bundles),
        bundles_by_signer: s
            .signers
            .iter()
            .map(|(name, count)| v1::Count {
                name: name.clone(),
                count: n(*count),
            })
            .collect(),
        bundles_not_verifying: n(s.not_verifying),
        not_verifying_since_first_reading: n(s.not_verifying_since_first),
        seals_verified_this_run: n(s.verified),
        seals_carried_forward: n(s.carried),
        homebrew_kegs: n(s.kegs),
        global_npm_packages: n(s.packages),
        application_code_folders: n(s.app_folders),
        changed_while_version_stayed: s.changed_in_place as u64,
        readings: s
            .readings
            .iter()
            .map(|(kind, completeness, reason)| v1::IntegrityReading {
                kind: kind.clone(),
                completeness: value_of::<v1::Completeness>(completeness),
                reason_text: reason.as_deref().map(crate::known::whole),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::bundle_version;

    #[test]
    fn a_bundles_version_is_its_short_version_with_the_build_only_where_it_differs() {
        let v = |s: Option<&str>, b: Option<&str>| {
            bundle_version(s.map(str::to_string), b.map(str::to_string))
        };
        assert_eq!(v(Some("2.1"), Some("2104")).as_deref(), Some("2.1 (2104)"));
        assert_eq!(v(Some("2.1"), Some("2.1")).as_deref(), Some("2.1"));
        assert_eq!(v(Some("2.1"), None).as_deref(), Some("2.1"));
        assert_eq!(v(None, Some("2104")).as_deref(), Some("2104"));
        assert_eq!(v(None, None), None);
    }
}
