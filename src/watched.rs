//! The `watched-places` reader: the few places on a Mac where persistence lives and that
//! rarely change for a good reason. It keeps a checksum of each file there, so the lifecycle
//! turns a difference between two runs into an event. Content is never kept or printed. Of a
//! preferences file only a few keys count, and each is an entry of its own with the checksum
//! of its value (`Part::Keys`). The places are rows of the table of autorun points
//! (`autorun::POINTS`), and what is read is recorded through `look.rs`.
//!
//! Two kinds of reading. One per kind of place and scope says which entries are there: a
//! file `watched_as` its kind and `located_on` the machine, or on the checkout for git hooks.
//! One per file says what is in it: `has_content`, and `links_to` for a symbolic link. A file
//! that cannot be read is then a reading of its own that read nothing, so nothing about it is
//! retracted or reported as changed, and every other file is still compared in full. A file
//! that is gone takes its content reading with it, as a checkout takes what is inside it.
//!
//! Nothing that is not a regular file is ever read, and nothing is opened in a way that can
//! block: a named pipe, a socket or a device is recorded as present with what it is.

use crate::autorun::{Kind, Part, Point, Scope, places};
use crate::baseline::Unit;
use crate::git_hooks::{Folder, Unread};
use crate::guarded::{self, Real};
use crate::look::{Absent, Look};
use std::fs::{File, FileType, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::store::Cause;

pub const READER: &str = "watched-places";
pub const BASIS: &str = "observed";
/// The kind of the reading of one file's content, scoped to the file.
pub const CONTENT: &str = "content of a watched file";
/// The raw copy: one line per entry with its kind, path and checksum, never content.
pub const RAW: &str = "watched-places.txt";
/// The same, of a watcher's reading of the places a change touched.
pub const RAW_SOME: &str = "watched-places-touched.txt";
/// A file larger than this is not read.
pub const CAP: u64 = 8 * 1024 * 1024;
/// The note of a full reading of a checkout's hooks when it has none.
pub const NO_HOOKS: &str = "the checkout has no hooks";
/// Journal note for a scoped removal while another checkout still uses the same hook.
pub const HOOK_STILL_ACTIVE: &str = "this hook is still watched in another checkout";
/// Journal note for a hook a checkout's reading places that another checkout's already did.
pub const HOOK_ALREADY_WATCHED: &str = "this hook is already watched in another checkout";
/// Why the hooks of a checkout whose `.git` is a file were not read.
pub const GIT_FILE: &str = ".git is a file, as in a worktree or a submodule: the hooks are kept elsewhere and were not read";
/// What this build has no reader for among watched places, in its own words.
pub const HOOKS_ELSEWHERE: &str = "git hooks of a checkout whose .git is a file";
pub const OVER_CAP: &str = "watched file over the size cap";

pub const AUTOSTART: &str = "autostart item";
pub const LOGIN_HOOK: &str = "login or logout hook";
pub const PROFILE: &str = "shell profile";
pub const SSH: &str = "ssh access file";
pub const AUTH: &str = "authentication module";
pub const HOOK: &str = "git hook";
pub const AUTOSTART_KIND: &str = "launch agents and daemons";
pub const LOGIN_HOOK_KIND: &str = "login and logout hooks in the login window's preferences";
pub const PROFILE_KIND: &str = "shell profiles of zsh and bash";
pub const SSH_KIND: &str = "ssh access files";
pub const AUTH_KIND: &str = "PAM policies and modules, and authorization plugins";
pub const HOOK_KIND: &str = "hooks in the checkout's .git folder";
/// A file directly in a folder `core.hooksPath` names, under none of Git's hook names: a
/// dispatcher every hook there runs, for one.
pub const HOOK_FOLDER_FILE: &str = "other file in a git hooks folder";
pub const HOOK_FOLDER_KIND: &str = "other files in the folder core.hooksPath names";
/// The most of those files read in one folder, in the order of their names. A hooks manager
/// keeps a dispatcher and a few files of its own there; a folder that holds more is not only a
/// folder of hooks, and its other files are not hashed at every change.
pub const HOOK_FOLDER_CAP: usize = 32;
/// What has no reader where that folder is too wide to read whole (`wide`).
pub const HOOK_FOLDER_WIDE: &str =
    "other files of a hooks folder that is the checkout, its .git folder, the home folder or /";
/// What has no reader past `HOOK_FOLDER_CAP`.
pub const HOOK_FOLDER_PAST_CAP: &str = "files of a hooks folder past the number read";
/// The most entries listed in such a folder. Git's names and a hooks manager's files are a few
/// dozen; a folder of thousands is a folder of other things, and listing it whole at every
/// check would cost more than what it could hold of a hooks folder.
pub const HOOK_FOLDER_LISTED: usize = 4096;
/// What every reading of those files says: no watcher subscribes to them.
pub const HOOK_FOLDER_AT_CHECKS: &str =
    "the other files of the folder are read at each check and are not watched between checks";
/// The note of a full reading of those files where no folder is configured.
pub const NO_HOOK_FOLDER: &str = "Git's configuration names no folder for hooks";
/// Entries of a hooks folder that git itself never runs.
const SAMPLE: &str = ".sample";

/// The kinds of place, each the literal of `watched_as` and the coverage kind of its reading.
/// The places themselves are rows of the table of autorun points (`autorun::POINTS`).
pub const AUTOSTARTS: Kind = (AUTOSTART, AUTOSTART_KIND);
pub const LOGIN_HOOKS: Kind = (LOGIN_HOOK, LOGIN_HOOK_KIND);
pub const PROFILES: Kind = (PROFILE, PROFILE_KIND);
pub const SSH_FILES: Kind = (SSH, SSH_KIND);
pub const AUTHS: Kind = (AUTH, AUTH_KIND);
pub const HOOKS: Kind = (HOOK, HOOK_KIND);
pub const HOOK_FOLDER_FILES: Kind = (HOOK_FOLDER_FILE, HOOK_FOLDER_KIND);

/// Whether a kind is read once per checkout and may place one file from several checkouts,
/// as a folder one setting gives to many does: its hooks and the other files of that folder.
pub fn of_checkout(kind: &str) -> bool {
    kind == HOOK_KIND || kind == HOOK_FOLDER_KIND
}

pub fn hook_departure(kind: &str, event: &crate::store::Event) -> bool {
    of_checkout(kind) && event.kind == "removed" && event.predicate == "watched_as"
}

/// A hook added to a checkout's reading: journaled once it is known whether another
/// checkout's reading already placed it.
pub fn hook_arrival(kind: &str, event: &crate::store::Event) -> bool {
    of_checkout(kind) && event.kind == "added" && event.predicate == "watched_as"
}

/// The unit a reading of a checkout's hooks reads when it tells the folder Git runs hooks
/// from: recorded, so that a later run knows an earlier one told it (`baseline.rs`).
pub fn hooks_told(checkout: &str) -> Unit {
    Unit::part(format!("{checkout}/.git/config"), "core.hooksPath")
}

/// Registers the coverage kinds of the places, on every open: a store of the current format
/// takes a kind added since without a rebuild.
pub fn add_kinds(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    for (_, kind) in kinds() {
        conn.execute(
            "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
            [kind],
        )?;
    }
    Ok(())
}

/// The kinds of place in the order of the table, each once.
pub fn kinds() -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for (_, kind) in places() {
        if !out.iter().any(|(w, _)| *w == kind.0) {
            out.push(kind);
        }
    }
    out
}

/// The start of the `has_content` literal of something that is not a regular file.
pub const NOT_A_FILE: &str = "not a regular file: ";
/// What a person or an agent reads of the content of an entry watched only for presence: a
/// folder such as a plugin's bundle, or a pipe, socket or device. Its arrival and departure
/// are seen, a change inside it is not, so it is never said to be unchanged.
pub const PRESENCE_ONLY: &str = "a change inside it is not seen, only whether it is there";
/// What is read of the content of an entry no reading has read yet.
pub const NEVER_READ: &str = "not known: its content has not been read";
/// What is read of an entry whose content the latest check did not read in full, before why.
pub const NOT_READ_NOW: &str = "not read at the last check";
/// Why, when the entry's kind was read in full and its content was not read with it.
const CONTENT_NOT_READ: &str = "its content was not read";

/// What the latest check knows of one live entry's content: the latest reading that speaks of
/// it, as completeness and reason.
pub struct ContentNow {
    pub completeness: String,
    pub reason: Option<String>,
}

impl ContentNow {
    /// Whether its content was read in full by the latest reading of its kind: only then may a
    /// person or an agent be told that it has not changed.
    pub fn read(&self) -> bool {
        self.completeness == "full"
    }

    /// What a row says in place of when it last changed, when its content was not read. The
    /// reason is what the reader's source said: cut, as every such text where it is printed.
    pub fn not_read(&self) -> String {
        format!(
            "{NOT_READ_NOW}: {}",
            self.reason
                .as_deref()
                .map_or(CONTENT_NOT_READ.to_string(), crate::view::said)
        )
    }
}

/// For every live watched entry, by id, what the latest check knows of its content. The
/// reading of its content counts only when it is as recent as the latest reading of the
/// entry's kind, which writes it in the same run; otherwise the kind's latest reading speaks:
/// what was known of the entry is kept from an earlier one, and its content was not read now.
pub fn content_now(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<std::collections::BTreeMap<String, ContentNow>> {
    use std::collections::{BTreeMap, HashMap};
    type Row = (i64, String, Option<String>);
    let mut latest: HashMap<(String, String), Row> = HashMap::new();
    // From the latest reading of each scope and kind, never through every reading: the cost
    // follows what is watched, not how long the store has been kept (`store::LATEST`).
    let mut stmt = conn.prepare(&format!(
        "{latest}
         SELECT c.scope, c.kind, c.id, c.completeness, c.reason FROM latest c
         WHERE c.reader = ?1",
        latest = crate::store::LATEST
    ))?;
    for row in stmt.query_map([READER], |r| {
        Ok((
            (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
            (r.get(2)?, r.get(3)?, r.get(4)?),
        ))
    })? {
        let (key, value) = row?;
        latest.insert(key, value);
    }
    let mut out = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject, scope, kind FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'",
    )?;
    for row in stmt.query_map([READER], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (subject, scope, kind) = row?;
        let of_kind = latest.get(&(scope, kind));
        let content = latest.get(&(subject.clone(), CONTENT.to_string()));
        let (completeness, reason) = match (of_kind, content) {
            (Some(k), Some(c)) if c.0 > k.0 => (c.1.clone(), c.2.clone()),
            (None, Some(c)) => (c.1.clone(), c.2.clone()),
            (Some(k), _) if k.1 != "full" => ("none".to_string(), k.2.clone()),
            _ => ("none".to_string(), None),
        };
        out.insert(
            subject,
            ContentNow {
                completeness,
                reason,
            },
        );
    }
    Ok(out)
}

/// The watched entries, by id, whose content is not hashed: only whether they are there is
/// watched.
pub fn presence_only(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<std::collections::BTreeSet<String>> {
    conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'has_content'
           AND substr(object, 1, ?2) = ?3",
    )?
    .query_map(
        rusqlite::params![READER, NOT_A_FILE.len() as i64, NOT_A_FILE],
        |r| r.get(0),
    )?
    .collect()
}

/// How many live watched entries of each kind, by `watched_as`, are watched only for presence.
pub fn presence_only_by_kind(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<std::collections::BTreeMap<String, i64>> {
    conn.prepare(
        "SELECT w.object, COUNT(DISTINCT w.subject) FROM assertion w
         WHERE w.layer = 'live' AND w.reader = ?1 AND w.predicate = 'watched_as'
           AND EXISTS (SELECT 1 FROM assertion c
                       WHERE c.layer = 'live' AND c.reader = ?1 AND c.subject = w.subject
                         AND c.predicate = 'has_content' AND substr(c.object, 1, ?2) = ?3)
         GROUP BY w.object",
    )?
    .query_map(
        rusqlite::params![READER, NOT_A_FILE.len() as i64, NOT_A_FILE],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?
    .collect()
}

/// Whether the last retained observation was only of an entry's presence. An entry that went
/// can still have an observation; a missing or unrecognised content value says nothing.
pub fn last_presence_only(
    conn: &rusqlite::Connection,
    subject: &str,
) -> rusqlite::Result<Option<bool>> {
    use rusqlite::OptionalExtension;
    let latest: Option<String> = conn
        .query_row(
            "SELECT object FROM assertion
             WHERE reader = ?1 AND subject = ?2 AND predicate = 'has_content'
               AND layer IN ('live', 'retracted')
             ORDER BY id DESC LIMIT 1",
            rusqlite::params![READER, subject],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match latest.as_deref() {
        Some(content) if content.starts_with(NOT_A_FILE) => Some(true),
        Some(content) if content.starts_with("sha256:") || content.starts_with("value sha256:") => {
            Some(false)
        }
        _ => None,
    })
}

/// What is in one watched file, as `has_content` says it, or why it could not be read.
#[derive(Debug, PartialEq)]
pub enum Content {
    /// `sha256:<64 hex>` of a regular file.
    Hash(String),
    /// `sha256:<64 hex>` of a part taken from a file, not of the file: said as
    /// `value sha256:<64 hex>`, so that nothing takes it for a file's checksum.
    Value(String),
    /// Present and not a regular file: what it is.
    Special(&'static str),
    /// A symbolic link whose target is not there.
    Dangling,
    /// Present and not read, with why as data and the reason in words.
    Unread(Cause, String),
}

impl Content {
    /// The `has_content` literal, or `None` when nothing was read.
    pub fn literal(&self) -> Option<String> {
        match self {
            Content::Hash(h) => Some(h.clone()),
            Content::Value(h) => Some(format!("value {h}")),
            Content::Special(what) => Some(format!("{NOT_A_FILE}{what}")),
            Content::Dangling => Some("dangling link".to_string()),
            Content::Unread(..) => None,
        }
    }
}

/// One entry found in a watched place.
pub struct Entry {
    pub unit: Unit,
    pub watched_as: &'static str,
    pub content: Content,
    /// The target text of a symbolic link, when the path is one.
    pub link: Option<String>,
}

/// Where a place is on disk, and its path as ids name it.
pub struct Roots<'a> {
    pub home: &'a Path,
    pub system: &'a Path,
}

/// The home folder by its names, as `guarded::real` takes them: as given and made real.
pub fn homes(home: &Path) -> [PathBuf; 2] {
    let real = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    [home.to_path_buf(), real]
}

/// Looks at every place of one kind on this machine. A system place is named by its path
/// from `/` whatever root it was read under.
pub fn look_machine(roots: &Roots, kind: &str) -> Look {
    let mut look = Look::default();
    let homes = homes(roots.home);
    let at = Where {
        homes: [homes[0].as_path(), homes[1].as_path()],
        home: roots.home,
        given: &[],
    };
    for (p, k) in places().filter(|(_, k)| k.1 == kind) {
        for path in p.paths {
            let (base, shown) = match p.scope {
                Scope::Home => (roots.home, path.to_string()),
                Scope::System => (roots.system, format!("/{path}")),
                _ => continue,
            };
            look_place(&mut look, p, k, path, base, &shown, &at);
        }
    }
    look
}

/// How the hooks of one checkout could be looked at.
pub enum Hooks {
    /// What was read, and why the folder Git's configuration names could not be told; and
    /// what was read of the other files of that folder.
    Looked(Look, Option<(Cause, String)>, Box<Others>),
    /// `.git` is a file: the hooks are elsewhere.
    GitFile,
}

/// What was read of the files beside Git's hook names in a configured folder, and what of
/// them this build does not read: a folder too wide, with why, or files past the cap, each
/// such folder one unit not read (`cut`).
#[derive(Default)]
pub struct Others {
    pub look: Look,
    pub lacks: Vec<&'static str>,
    pub cut: usize,
    pub why: Vec<String>,
    /// A folder could not be resolved, or leads into a guarded one.
    pub unplaced: bool,
}

impl Others {
    fn lack(&mut self, what: &'static str) {
        if !self.lacks.contains(&what) {
            self.lacks.push(what);
        }
    }
}

/// What a configured folder is when it is too wide for its other files to be read: the
/// checkout, its `.git` folder, the home folder or `/`. Compared by what each folder is, not
/// by how it is spelt: a volume may ignore case, and a link gives one folder two names.
pub fn wide(folder: &Path, checkout: &Path, homes: &[&Path]) -> Option<&'static str> {
    let is = |other: &Path| same(folder, other);
    if is(Path::new("/")) {
        Some("/")
    } else if homes.iter().any(|home| is(home)) {
        Some("the home folder")
    } else if is(checkout) {
        Some("the checkout itself")
    } else if is(&checkout.join(".git")) {
        Some("the checkout's .git folder")
    } else {
        None
    }
}

/// Whether two paths lead to one folder or file: the same device and inode.
fn same(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let id = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    id(a).is_some_and(|a| id(b) == Some(a))
}

/// The entries of a folder, `None` past `HOOK_FOLDER_LISTED` of them. Any error once the folder
/// is open fails the whole listing: an entry missed is never a file gone.
fn listed<T>(entries: impl Iterator<Item = std::io::Result<T>>) -> Result<Option<Vec<T>>, String> {
    let mut found = Vec::new();
    for entry in entries {
        if found.len() == HOOK_FOLDER_LISTED {
            return Ok(None);
        }
        found.push(entry.map_err(|e| reason(&e))?);
    }
    Ok(Some(found))
}

/// How the reason of a checkout's hooks reading says the configured folder was not told.
const UNTOLD: &str = "the folder Git's configuration names for hooks could not be told: ";

/// The places of each checkout: its hooks.
fn in_checkout() -> impl Iterator<Item = (&'static Point, Kind, &'static str)> {
    places()
        .filter(|(p, _)| p.scope == Scope::Checkout)
        .flat_map(|(p, k)| p.paths.iter().map(move |path| (p, k, *path)))
}

/// Looks at the hooks of one checkout: `.git/hooks` as it always was, whatever Git's
/// configuration says, and besides it the folder the configuration names (`git_hooks`) when
/// that can be told. When it cannot, `.git/hooks` is still read and the reason says why.
pub fn look_checkout(
    checkout: &crate::checkouts::Checkout,
    home: &Path,
    homes: [&Path; 2],
    folder: Folder,
    given: &[&Path],
) -> Hooks {
    let at = Where { homes, home, given };
    let mut look = Look::default();
    let untold = match &folder {
        Folder::Unknown(Unread::GitFile) => return Hooks::GitFile,
        Folder::Unknown(Unread::Guarded(g)) => {
            look.met(g.clone());
            let into = guarded::shown(g, home);
            let why =
                format!("Git's configuration leads into {into}, which macOS asks permission for");
            Some((Cause::NotGiven, format!("{UNTOLD}{why}")))
        }
        Folder::Unknown(Unread::Failed(why)) => Some((Cause::Failed, format!("{UNTOLD}{why}"))),
        _ => None,
    };
    for (p, k, path) in in_checkout() {
        let shown = format!("{}/{path}", checkout.rel);
        look_place(&mut look, p, k, path, &checkout.path, &shown, &at);
    }
    let mut told = untold.is_none();
    let configured = folder.configured();
    for (path, names) in &configured {
        let unit = Unit::whole(crate::checkouts::rel(at.homes[0], path));
        configured_hooks(&mut look, path, unit.clone(), names, &at);
        // A folder that could not be looked at is not told yet.
        told &= !look.not_read().any(|(u, _)| *u == unit);
    }
    if told {
        look.read(hooks_told(&checkout.rel));
    }
    // The working tree's folder and the push's are one when the setting is absolute.
    let mut others = Others::default();
    for (i, (path, _)) in configured.iter().enumerate() {
        if configured[..i].iter().any(|(p, _)| p == path) {
            continue;
        }
        let names: Vec<&str> = (configured.iter().filter(|(p, _)| p == path))
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        other_files(&mut others, path, &names, &checkout.path, &at);
    }
    Hooks::Looked(look, untold, Box::new(others))
}

/// Reads by content the regular files directly in a configured folder beside the hooks Git
/// runs by `names`, at most `HOOK_FOLDER_CAP` of them, and a link among them as `examine`
/// does. A folder below is not entered. Not done where the folder is too wide (`wide`).
fn other_files(others: &mut Others, path: &Path, names: &[&str], checkout: &Path, at: &Where) {
    let unit = Unit::whole(crate::checkouts::rel(at.homes[0], path));
    // Which of the files read before a folder not resolved holds is not known: all are kept.
    // A folder not there, or what is not a folder, holds nothing.
    let folder = match guarded::real_in(path, &at.homes, at.given) {
        Real::At(folder) => folder,
        Real::Guarded(g) => {
            others.unplaced = true;
            return others.look.not_into(unit, g, at.home);
        }
        Real::Failed(e) => match Absent::on_the_way(&e) {
            Some(absent) => return others.look.absent(unit, absent),
            None => {
                others.unplaced = true;
                return others.look.not_looked_at(unit, reason(&e));
            }
        },
    };
    if let Some(what) = wide(&folder, checkout, &at.homes) {
        others.lack(HOOK_FOLDER_WIDE);
        return others.why.push(format!(
            "the folder core.hooksPath names is {what}: only the files with Git's hook names are read there"
        ));
    }
    // Every file of `.git/hooks` is read as a hook already.
    if same(&folder, &checkout.join(".git/hooks")) {
        others.look.present += 1;
        return;
    }
    // From here the folder is named as its files are, so a failure covers exactly them. Only
    // one that cannot be opened may be absent: listing a named pipe fails without waiting.
    let shown = crate::checkouts::rel(at.homes[1], &folder);
    let entries = match std::fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(e) => match Absent::on_the_way(&e) {
            Some(absent) => return others.look.absent(Unit::whole(shown), absent),
            None => return others.look.not_looked_at(Unit::whole(shown), reason(&e)),
        },
    };
    let entries = entries.map(|entry| entry.and_then(|e| Ok((e.file_name(), e.file_type()?))));
    let mut found = match listed(entries) {
        Ok(Some(found)) => found,
        Ok(None) => {
            let why = format!(
                "the folder holds more than {HOOK_FOLDER_LISTED} entries: its other files were not read"
            );
            others.cut += 1;
            others.lack(HOOK_FOLDER_PAST_CAP);
            return others.look.unread(Unit::whole(&shown), why);
        }
        Err(why) => return others.look.not_looked_at(Unit::whole(&shown), why),
    };
    // A link is examined as a file; only a folder itself is below.
    found.retain(|(name, kind)| !kind.is_dir() && !names.iter().any(|n| name == *n));
    found.sort_by(|a, b| a.0.cmp(&b.0));
    let past = found.len().saturating_sub(HOOK_FOLDER_CAP);
    if past == 0 {
        others.look.read(Unit::whole(&shown));
    } else {
        let why = format!("{past} files past the first {HOOK_FOLDER_CAP} were not read");
        others.look.unread(Unit::whole(&shown), why);
        others.cut += 1;
        others.lack(HOOK_FOLDER_PAST_CAP);
    }
    let look = &mut others.look;
    look.present += 1;
    for (name, _) in found.iter().take(HOOK_FOLDER_CAP) {
        let entry = format!("{shown}/{}", name.to_string_lossy());
        let examined = examine(&folder.join(name), look, at, None);
        take(look, HOOK_FOLDER_FILES, None, entry, examined, at);
    }
}

/// Reads the hooks Git runs by `names` from a configured folder, `path` as written and
/// `unit` as ids name it.
fn configured_hooks(look: &mut Look, path: &Path, unit: Unit, names: &[&str], at: &Where) {
    // The checkout's hooks were looked at, whatever this folder turns out to be.
    look.present += 1;
    if look.not_read().any(|(u, _)| *u == unit) {
        return;
    }
    let folder = match guarded::real_in(path, &at.homes, at.given) {
        Real::At(folder) => folder,
        Real::Guarded(g) => return look.not_into(unit, g, at.home),
        Real::Failed(e) if Absent::on_the_way(&e).is_some() => return,
        Real::Failed(e) => return look.not_looked_at(unit, reason(&e)),
    };
    match std::fs::metadata(&folder) {
        Ok(meta) if meta.is_dir() => {}
        // A non-directory cannot contain a Git hook. This does not open a FIFO,
        // socket or device configured as the hooks path.
        Ok(_) => return,
        Err(e) => return look.not_looked_at(unit, reason(&e)),
    }
    let shown = crate::checkouts::rel(at.homes[1], &folder);
    for name in names {
        let entry = if shown == "/" {
            format!("/{name}")
        } else {
            format!("{shown}/{name}")
        };
        let examined = examine(&folder.join(name), look, at, None);
        take(look, HOOKS, None, entry, examined, at);
    }
}

/// What a look needs to tell a guarded folder: the home folder by its names, and as ids
/// name it.
struct Where<'a> {
    homes: [&'a Path; 2],
    home: &'a Path,
    given: &'a [&'a Path],
}

/// The keys of a row whose parts count, `None` for a row read whole.
fn keys_of(p: &Point) -> Option<&'static [&'static str]> {
    match p.part {
        Part::Keys(keys) => Some(keys),
        _ => None,
    }
}

/// Looks at one place, `path` of row `p`, under `base`. Its folder is reached one part at a
/// time and a link on the way is made real, so that nothing in a folder macOS asks permission
/// for is looked at.
fn look_place(
    look: &mut Look,
    p: &Point,
    kind: Kind,
    path: &str,
    base: &Path,
    shown: &str,
    at: &Where,
) {
    let rel = Path::new(path);
    let (Some(folder), Some(name)) = (rel.parent(), rel.file_name()) else {
        return;
    };
    let path = match crate::guarded::under(base, folder, &at.homes) {
        Ok(folder) => folder.join(name),
        Err(guarded) => return look.not_into(Unit::whole(shown), guarded, at.home),
    };
    let keys = keys_of(p);
    if p.part != Part::Entries {
        let examined = examine(&path, look, at, keys);
        match examined {
            // A single file not there was read in full: it holds nothing.
            Examined::Absent(absent) => look.absent(Unit::whole(shown), absent),
            Examined::Present(..) | Examined::Parts(..) => look.present += 1,
            _ => {}
        }
        return take(look, kind, keys, shown.to_string(), examined, at);
    }
    let path = match crate::guarded::followed(&path, &at.homes) {
        Ok(path) => path,
        Err(guarded) => return look.not_into(Unit::whole(shown), guarded, at.home),
    };
    // Listing what is not a folder, a named pipe included, fails at once without waiting.
    let listing = std::fs::read_dir(&path).and_then(|entries| {
        entries
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
    });
    let names = match listing {
        Ok(names) => names,
        Err(e) => {
            // A folder that is not there was listed in full: it holds nothing.
            return match Absent::of(&e) {
                Some(absent) => look.absent(Unit::whole(shown), absent),
                None => look.not_looked_at(Unit::whole(shown), e.to_string()),
            };
        }
    };
    look.present += 1;
    look.read(Unit::whole(shown));
    for name in names {
        let text = name.to_string_lossy();
        if p.scope == Scope::Checkout && text.ends_with(SAMPLE) {
            continue;
        }
        let entry = format!("{shown}/{text}");
        let examined = examine(&path.join(&name), look, at, keys);
        take(look, kind, keys, entry, examined, at);
    }
}

/// Keeps what was found at one path, named `shown`, as the place's entries, or says why
/// nothing was, and records the unit it is (`baseline.rs`). A file whose parts count is one
/// unit, as a file read whole is: its parts, `<file>#/<key>`, are entries of it, and the file
/// is read in full only when every part there was read. A part that could not be read is
/// named as it is, so that what was known of it is kept and only of it; the file is then seen
/// and not read, and losing sight of it is judged as for any unit.
fn take(
    look: &mut Look,
    kind: Kind,
    keys: Option<&'static [&'static str]>,
    shown: String,
    examined: Examined,
    at: &Where,
) {
    let shown = Unit::whole(shown);
    let entry = |unit: Unit, content: Content, link: Option<String>| Entry {
        unit,
        watched_as: kind.0,
        content,
        link,
    };
    match examined {
        // Listed and gone before it was looked at: the listing read in full holds it.
        Examined::Absent(_) => {}
        Examined::Unknown(why) | Examined::Unread(why) => look.unread(shown, why),
        Examined::Unreached(guarded) => look.there_not_into(shown, guarded, at.home),
        Examined::Present(content, link) => {
            look.read(shown.clone());
            look.entries.push(entry(shown, content, link));
        }
        Examined::Parts(parts, failed, link) => {
            if failed.is_empty() {
                look.read(shown.clone());
            } else {
                // A key read or known absent can lose coverage again, even if another key failed.
                for key in keys.unwrap_or_default() {
                    if !failed.iter().any(|(unread, _)| unread == key) {
                        look.read_part(&shown, format!("/{key}"));
                    }
                }
                look.there(shown.clone());
            }
            for (key, content) in parts {
                let unit = Unit::part(&shown.path, format!("/{key}"));
                look.entries.push(entry(unit, content, link.clone()));
            }
            for (key, why) in failed {
                look.not_looked_at(Unit::part(&shown.path, format!("/{key}")), why.to_string());
            }
        }
    }
}

enum Examined {
    Absent(Absent),
    /// Whether it is there is not known, with the reason.
    Unknown(String),
    /// A file whose parts count, there and not read, with the reason.
    Unread(String),
    /// A link into this folder macOS asks permission for, of a file whose parts count: what
    /// it holds is not known.
    Unreached(PathBuf),
    Present(Content, Option<String>),
    /// A file whose parts count: each part there and read, by its key; each part there and
    /// not read, with why; and the link it was reached by.
    Parts(
        Vec<(&'static str, Content)>,
        Vec<(&'static str, &'static str)>,
        Option<String>,
    ),
}

/// What is at a path, whose folder was reached. A symbolic link is followed to its final
/// target for the content, unless that target is in a folder macOS asks permission for:
/// then the link is there and what it leads to was not looked into.
fn examine(
    path: &Path,
    look: &mut Look,
    at: &Where,
    keys: Option<&'static [&'static str]>,
) -> Examined {
    let own = std::fs::symlink_metadata(path).and_then(|m| {
        if !m.file_type().is_symlink() {
            return Ok((m, None));
        }
        let target = std::fs::read_link(path)?;
        Ok((m, Some(target.to_string_lossy().into_owned())))
    });
    let link = match own {
        Ok((m, None)) => return counted(path, &m, keys, None),
        Ok((_, Some(link))) => link,
        Err(e) => {
            return match Absent::of(&e) {
                Some(absent) => Examined::Absent(absent),
                None => Examined::Unknown(e.to_string()),
            };
        }
    };
    let target = match crate::guarded::followed(path, &at.homes) {
        Ok(target) => target,
        Err(guarded) if keys.is_some() => return Examined::Unreached(guarded),
        Err(guarded) => {
            let why = format!(
                "{}{}",
                crate::guarded::NOT_LOOKED_INTO,
                crate::guarded::leads_into(&guarded, at.home)
            );
            look.met(guarded);
            return Examined::Present(Content::Unread(Cause::NotGiven, why), Some(link));
        }
    };
    match std::fs::metadata(&target) {
        Ok(meta) => counted(&target, &meta, keys, Some(link)),
        // A link to nothing holds no part: what reads the file reads nothing there.
        Err(e) if Absent::of(&e).is_some() && keys.is_some() => {
            Examined::Parts(Vec::new(), Vec::new(), Some(link))
        }
        Err(e) if Absent::of(&e).is_some() => Examined::Present(Content::Dangling, Some(link)),
        Err(e) if keys.is_some() => Examined::Unread(reason(&e)),
        Err(e) => Examined::Present(Content::Unread(Cause::Failed, reason(&e)), Some(link)),
    }
}

/// What a file reached holds, as `counts` takes it. Of a file whose parts count, anything but
/// a property list that was read is a place that failed: an entry of the whole file beside
/// its parts would make a reading that cannot see them say they are gone.
fn counted(
    path: &Path,
    meta: &Metadata,
    keys: Option<&'static [&'static str]>,
    link: Option<String>,
) -> Examined {
    let Some(keys) = keys else {
        return Examined::Present(content(path, meta), link);
    };
    let bytes = match bytes(path, meta) {
        Ok(bytes) => bytes,
        Err(Content::Unread(_, why)) => return Examined::Unread(why),
        Err(other) => return Examined::Unread(other.literal().unwrap_or_default()),
    };
    match crate::plist::values(&bytes, keys) {
        Err(why) => Examined::Unread(why.to_string()),
        Ok(values) => {
            let (mut parts, mut failed) = (Vec::new(), Vec::new());
            for (key, value) in values {
                match value {
                    Ok(value) => {
                        let hash = format!("sha256:{}", crate::sha256::hex(&value));
                        parts.push((key, Content::Value(hash)));
                    }
                    Err(why) => failed.push((key, why)),
                }
            }
            Examined::Parts(parts, failed, link)
        }
    }
}

fn reason(e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::ELOOP) {
        "link loop".to_string()
    } else {
        e.to_string()
    }
}

/// The content of what `meta` describes, by the checksum of its bytes.
fn content(path: &Path, meta: &Metadata) -> Content {
    match bytes(path, meta) {
        Ok(bytes) => Content::Hash(format!("sha256:{}", crate::sha256::hex(&bytes))),
        Err(not) => not,
    }
}

/// The bytes of what `meta` describes, or what it is instead. Only a regular file is opened,
/// and without waiting: a file swapped for a named pipe after it was looked at cannot hold the
/// run, and is told by what was opened.
fn bytes(path: &Path, meta: &Metadata) -> Result<Vec<u8>, Content> {
    if !meta.is_file() {
        return Err(Content::Special(kind_of(meta.file_type())));
    }
    let read = || -> std::io::Result<Result<Vec<u8>, &'static str>> {
        let file = match open_regular(path)? {
            Ok((file, _)) => file,
            Err(what) => return Ok(Err(what)),
        };
        let mut bytes = Vec::new();
        file.take(CAP + 1).read_to_end(&mut bytes)?;
        Ok(Ok(bytes))
    };
    match read() {
        Err(e) => Err(Content::Unread(Cause::Failed, reason(&e))),
        Ok(Err(what)) => Err(Content::Special(what)),
        // The file is there and this build does not read a file that large.
        Ok(Ok(bytes)) if bytes.len() as u64 > CAP => Err(Content::Unread(
            Cause::NoReader,
            format!("over the size cap of {} MiB", CAP >> 20),
        )),
        Ok(Ok(bytes)) => Ok(bytes),
    }
}

/// Opens `path` to read only when it is a regular file: without following a link in its last
/// part and without waiting, so that a file swapped for a link or a named pipe after it was
/// looked at is neither followed nor able to hold the reader. A link fails to open; anything
/// else that is not a regular file is told by what it is. The file is returned with its
/// metadata as opened.
pub fn open_regular(path: &Path) -> std::io::Result<Result<(File, Metadata), &'static str>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Ok(Err(kind_of(opened.file_type())));
    }
    Ok(Ok((file, opened)))
}

/// What a thing that is not a regular file is, after links are followed: then nothing else
/// is left once the first four are ruled out.
fn kind_of(t: FileType) -> &'static str {
    if t.is_dir() {
        "folder"
    } else if t.is_fifo() {
        "fifo"
    } else if t.is_socket() {
        "socket"
    } else if t.is_block_device() {
        "block device"
    } else {
        "character device"
    }
}

/// A field of the raw copy: one line per entry, fields apart by tabs.
pub fn field(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hooks_folder_that_is_the_root_the_home_folder_the_checkout_or_its_git_folder_is_too_wide_to_read()
     {
        // Each is known by what it is: a link names the checkout and its `.git` a second time,
        // as another case does on a volume that ignores case.
        let home = crate::common::Scratch::new("hooks-folder-wide");
        let checkout = home.join("dev/app");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::create_dir_all(checkout.join(".husky/_")).unwrap();
        std::os::unix::fs::symlink(&checkout, home.join("alias")).unwrap();
        let wide = |folder: &Path| wide(folder, &checkout, &[&*home]);
        assert_eq!(wide(Path::new("/")), Some("/"));
        assert_eq!(wide(&home.join("dev/..")), Some("the home folder"));
        assert_eq!(wide(&home.join("alias")), Some("the checkout itself"));
        assert_eq!(
            wide(&home.join("alias/.git")),
            Some("the checkout's .git folder")
        );
        assert_eq!(wide(&checkout.join(".husky/_")), None);
        assert_eq!(wide(&home.join("absent")), None);
    }

    #[test]
    fn a_listing_that_fails_after_its_first_entries_is_a_failure_and_never_those_entries() {
        let gone = || std::io::Error::from(std::io::ErrorKind::NotFound);
        let entries = [Ok(1), Err(gone()), Ok(2)].into_iter();
        assert_eq!(listed(entries), Err(reason(&gone())));
        assert_eq!(listed([Ok(1), Ok(2)].into_iter()), Ok(Some(vec![1, 2])));
        let many = (0..=HOOK_FOLDER_LISTED).map(Ok::<_, std::io::Error>);
        assert_eq!(listed(many), Ok(None));
        let all = (0..HOOK_FOLDER_LISTED).map(Ok::<_, std::io::Error>);
        assert_eq!(
            listed(all).map(|l| l.map(|l| l.len())),
            Ok(Some(HOOK_FOLDER_LISTED))
        );
    }

    #[test]
    fn a_file_swapped_for_a_named_pipe_after_it_was_looked_at_never_holds_the_run() {
        // Between looking at a regular file and opening it, it may become a named pipe, which
        // a plain open waits on for a writer forever.
        let dir =
            std::env::temp_dir().join(format!("immunity-watched-swap-{}", std::process::id()));
        let _removed = crate::common::Scratch::at(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile");
        std::fs::write(&path, "regular\n").unwrap();
        let looked = std::fs::metadata(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let swapped = path.clone();
        std::thread::spawn(move || tx.send(content(&swapped, &looked)).unwrap());
        let got = rx.recv_timeout(std::time::Duration::from_secs(10));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, Ok(Content::Special("fifo")));
    }
}
