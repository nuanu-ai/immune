//! The `watched-places` reader: the few places on a Mac where persistence lives and that
//! rarely change for a good reason. It keeps a checksum of each file there, so the lifecycle
//! turns a difference between two runs into an event. Content is never kept or printed. Of a
//! preferences file only a few keys count, and each is an entry of its own with the checksum
//! of its value (`Counts::Keys`).
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

use std::fs::{FileType, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::store::Cause;

pub const READER: &str = "watched-places";
pub const BASIS: &str = "observed";
/// The kind of the reading of one file's content, scoped to the file.
pub const CONTENT: &str = "content of a watched file";
/// The raw copy: one line per entry with its kind, path and checksum, never content.
pub const RAW: &str = "watched-places.txt";
/// A file larger than this is not read.
pub const CAP: u64 = 8 * 1024 * 1024;
/// The note of a full reading when none of its places is on this machine.
pub const NOT_HERE: &str = "none of these places is on this machine";
/// The note of a full reading of a checkout's hooks when it has none.
pub const NO_HOOKS: &str = "the checkout has no hooks";
/// Why the hooks of a checkout whose `.git` is a file were not read.
pub const GIT_FILE: &str = ".git is a file, as in a worktree or a submodule: the hooks are kept elsewhere and were not read";
/// What this build has no reader for among watched places, in its own words.
pub const HOOKS_ELSEWHERE: &str = "git hooks of a checkout whose .git is a file";
pub const OVER_CAP: &str = "watched file over the size cap";

/// What a place is resolved against.
#[derive(Clone, Copy, PartialEq)]
pub enum Base {
    /// The home folder.
    Home,
    /// The root of the system, `/` unless a test gives another.
    System,
    /// Each checkout this run holds.
    Checkout,
}

/// One place: a file, or a folder whose every entry is watched.
pub struct Place {
    /// The kind of place, the literal of `watched_as`.
    pub watched_as: &'static str,
    /// The coverage kind of the reading of this kind of place.
    pub kind: &'static str,
    pub base: Base,
    pub path: &'static str,
    pub folder: bool,
    /// What of a file counts.
    pub counts: Counts,
}

/// What of a watched file counts.
#[derive(Clone, Copy, PartialEq)]
pub enum Counts {
    /// The whole file, by its checksum.
    Whole,
    /// The values at these top-level keys of a property list, each an entry of its own named
    /// `<file>#<key>`, by the checksum of the value's exact encoding (`plist.rs`): for a
    /// preferences file whose other settings change for their own reasons. A key that is not
    /// there is no entry; a file that is not a property list is a place that failed, and a key
    /// whose value cannot be read is a part that failed, named `<file>#<key>`.
    Keys(&'static [&'static str]),
}

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
/// The keys of the login window's preferences that name a script it runs as root at every
/// login and logout (Apple, "Customizing Login and Logout"; KnockKnock's `LogInOutHooks`).
const HOOK_KEYS: &[&str] = &["LoginHook", "LogoutHook"];
/// Entries of a hooks folder that git itself never runs.
const SAMPLE: &str = ".sample";

/// A kind of place: the literal of `watched_as` and the coverage kind of its reading.
type Kind = (&'static str, &'static str);
const AUTOSTARTS: Kind = (AUTOSTART, AUTOSTART_KIND);
const LOGIN_HOOKS: Kind = (LOGIN_HOOK, LOGIN_HOOK_KIND);
const PROFILES: Kind = (PROFILE, PROFILE_KIND);
const SSH_FILES: Kind = (SSH, SSH_KIND);
const AUTHS: Kind = (AUTH, AUTH_KIND);
const HOOKS: Kind = (HOOK, HOOK_KIND);

const fn place(kind: Kind, base: Base, path: &'static str, folder: bool) -> Place {
    Place {
        watched_as: kind.0,
        kind: kind.1,
        base,
        path,
        folder,
        counts: Counts::Whole,
    }
}

/// A property list of which only the values at `keys` count.
const fn keys(kind: Kind, base: Base, path: &'static str, keys: &'static [&'static str]) -> Place {
    Place {
        counts: Counts::Keys(keys),
        ..place(kind, base, path, false)
    }
}

/// Every watched place. Adding a place is one row. Each holds on every Mac; none is a
/// private key or known hosts. The order is the order of the view and the report.
///
/// The list is laid next to the categories Objective-See's KnockKnock enumerates and MITRE
/// ATT&CK's persistence techniques for macOS. It keeps what a program running as the user can
/// read without a permission dialog, what current macOS still acts on, and what has a normal
/// state. A place added later is read for the first time on a store that already exists:
/// what it holds is told once, never raised by its kind's rule (`baseline.rs`).
pub const PLACES: [Place; 36] = [
    place(AUTOSTARTS, Base::Home, "Library/LaunchAgents", true),
    place(AUTOSTARTS, Base::System, "Library/LaunchAgents", true),
    place(AUTOSTARTS, Base::System, "Library/LaunchDaemons", true),
    // Root's own preferences, where `sudo defaults write` puts a hook, only root can read.
    keys(
        LOGIN_HOOKS,
        Base::System,
        "Library/Preferences/com.apple.loginwindow.plist",
        HOOK_KEYS,
    ),
    keys(
        LOGIN_HOOKS,
        Base::Home,
        "Library/Preferences/com.apple.loginwindow.plist",
        HOOK_KEYS,
    ),
    place(PROFILES, Base::System, "etc/zshenv", false),
    place(PROFILES, Base::System, "etc/zprofile", false),
    place(PROFILES, Base::System, "etc/zshrc", false),
    place(PROFILES, Base::System, "etc/zlogin", false),
    place(PROFILES, Base::System, "etc/zlogout", false),
    place(PROFILES, Base::System, "etc/profile", false),
    place(PROFILES, Base::System, "etc/bashrc", false),
    place(PROFILES, Base::Home, ".zshenv", false),
    place(PROFILES, Base::Home, ".zprofile", false),
    place(PROFILES, Base::Home, ".zshrc", false),
    place(PROFILES, Base::Home, ".zlogin", false),
    place(PROFILES, Base::Home, ".zlogout", false),
    place(PROFILES, Base::Home, ".bash_profile", false),
    place(PROFILES, Base::Home, ".bash_login", false),
    place(PROFILES, Base::Home, ".profile", false),
    place(PROFILES, Base::Home, ".bashrc", false),
    place(PROFILES, Base::Home, ".bash_logout", false),
    place(SSH_FILES, Base::Home, ".ssh/config", false),
    place(SSH_FILES, Base::Home, ".ssh/authorized_keys", false),
    place(SSH_FILES, Base::Home, ".ssh/rc", false),
    place(SSH_FILES, Base::System, "etc/ssh/ssh_config", false),
    place(SSH_FILES, Base::System, "etc/ssh/sshd_config", false),
    place(SSH_FILES, Base::System, "etc/ssh/ssh_config.d", true),
    place(SSH_FILES, Base::System, "etc/ssh/sshd_config.d", true),
    // OpenPAM as Apple builds it looks for a service's policy in these, in this order, after
    // one a device management profile installs and before `/usr/share/pam.d` (pam.conf(5);
    // `openpam_configure.c`). A module named without a path is looked for in `/usr/lib/pam`,
    // then in `/usr/local/lib/pam`. Only an update of macOS changes what is in `/usr/share`
    // and `/usr/lib`.
    place(AUTHS, Base::System, "etc/pam.d", true),
    place(AUTHS, Base::System, "etc/pam.conf", false),
    place(AUTHS, Base::System, "usr/local/etc/pam.d", true),
    place(AUTHS, Base::System, "usr/local/etc/pam.conf", false),
    place(AUTHS, Base::System, "usr/local/lib/pam", true),
    // Each plugin is a bundle: its arrival and departure are seen, a change inside it is not.
    // Which plugins run is said by the authorization database, which is not read.
    place(
        AUTHS,
        Base::System,
        "Library/Security/SecurityAgentPlugins",
        true,
    ),
    place(HOOKS, Base::Checkout, ".git/hooks", true),
];

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
    for p in &PLACES {
        if !out.iter().any(|(w, _)| *w == p.watched_as) {
            out.push((p.watched_as, p.kind));
        }
    }
    out
}

/// The start of the `has_content` literal of something that is not a regular file.
pub const NOT_A_FILE: &str = "not a regular file: ";
/// What a person or an agent reads of the content of an entry watched only for presence: a
/// folder such as a plugin's bundle, or a pipe, socket or device. Its arrival and departure
/// are seen, a change inside it is not, so it is never said to be unchanged.
pub const PRESENCE_ONLY: &str =
    "a change inside it is not seen: only whether it is there is watched";
/// What is read of the content of an entry no reading has read yet.
pub const NEVER_READ: &str = "not known: its content has not been read";

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
    /// The path as ids name it: from the home folder when inside it, else the full path.
    pub path: String,
    pub watched_as: &'static str,
    pub content: Content,
    /// The target text of a symbolic link, when the path is one.
    pub link: Option<String>,
}

/// What looking at the places of one kind in one scope found.
#[derive(Default)]
pub struct Look {
    pub entries: Vec<Entry>,
    /// Places that are there and could not be looked at, with the reason.
    pub failed: Vec<(String, String)>,
    /// Places that are there and were looked at.
    pub present: usize,
    /// Places not looked into because they lead into a folder macOS asks permission for,
    /// each with why: whether they hold anything is not known.
    pub unreached: Vec<(String, String)>,
    /// Every such folder met, a link's target among them, for the reader's coverage.
    pub guarded: Vec<PathBuf>,
    /// The units read in full, by their paths as ids name them: a file looked at, found or
    /// absent, and a folder listed or found absent (`baseline.rs`).
    pub read: Vec<String>,
    /// The units found present, read or not.
    pub seen: Vec<String>,
}

impl Look {
    /// The completeness of the reading of which entries are there, and its reason or note.
    pub fn completeness(&self) -> (&'static str, Option<String>) {
        if self.failed.is_empty() && self.unreached.is_empty() {
            let note = (self.present == 0).then(|| NOT_HERE.to_string());
            return ("full", note);
        }
        let mut reasons = Vec::new();
        if !self.failed.is_empty() {
            let failed: Vec<String> = self
                .failed
                .iter()
                .map(|(path, why)| format!("{path} ({why})"))
                .collect();
            reasons.push(format!("could not be read: {}", failed.join("; ")));
        }
        if !self.unreached.is_empty() {
            let unreached: Vec<String> = self
                .unreached
                .iter()
                .map(|(path, why)| format!("{path}: {why}"))
                .collect();
            reasons.push(format!(
                "{}{}",
                crate::guarded::NOT_LOOKED_INTO,
                unreached.join("; ")
            ));
        }
        let reason = Some(reasons.join("; "));
        if self.present == 0 {
            ("none", reason)
        } else {
            ("partial", reason)
        }
    }

    /// Why a reading that is not full is not: it failed, or what it did not look into is
    /// only what macOS asks permission for, which the owner did not give.
    pub fn cause(&self) -> Cause {
        if self.failed.is_empty() && !self.unreached.is_empty() {
            Cause::NotGiven
        } else {
            Cause::Failed
        }
    }

    /// A place that leads into a guarded folder: not looked into, and said.
    pub fn not_into(&mut self, shown: String, folder: PathBuf, home: &Path) {
        self.unreached
            .push((shown, crate::guarded::leads_into(&folder, home)));
        self.met(folder);
    }

    /// A guarded folder met, for the reader's coverage.
    pub fn met(&mut self, folder: PathBuf) {
        if !self.guarded.contains(&folder) {
            self.guarded.push(folder);
        }
    }
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
    };
    for p in PLACES.iter().filter(|p| p.kind == kind) {
        let (base, shown) = match p.base {
            Base::Home => (roots.home, p.path.to_string()),
            Base::System => (roots.system, format!("/{}", p.path)),
            Base::Checkout => continue,
        };
        look_place(&mut look, p, base, &shown, &at);
    }
    look
}

/// How the hooks of one checkout could be looked at.
pub enum Hooks {
    Looked(Look),
    /// `.git` is a file: the hooks are elsewhere.
    GitFile,
}

/// Looks at the hooks folder of one checkout. `rel` is the checkout's path as ids name it.
pub fn look_checkout(checkout: &Path, rel: &str, home: &Path) -> Hooks {
    let homes = homes(home);
    let at = Where {
        homes: [homes[0].as_path(), homes[1].as_path()],
        home,
    };
    let mut look = Look::default();
    // `.git` is not looked at where it leads into a folder macOS asks permission for.
    let dotgit = match crate::guarded::followed(&checkout.join(".git"), &at.homes) {
        Ok(dotgit) => dotgit,
        Err(folder) => {
            for p in PLACES.iter().filter(|p| p.base == Base::Checkout) {
                look.not_into(format!("{rel}/{}", p.path), folder.clone(), home);
            }
            return Hooks::Looked(look);
        }
    };
    // When `.git` cannot be looked at, its hooks folder cannot be either, and says so.
    match std::fs::metadata(dotgit) {
        Ok(m) if !m.is_dir() => Hooks::GitFile,
        _ => {
            for p in PLACES.iter().filter(|p| p.base == Base::Checkout) {
                look_place(&mut look, p, checkout, &format!("{rel}/{}", p.path), &at);
            }
            Hooks::Looked(look)
        }
    }
}

/// What a look needs to tell a guarded folder: the home folder by its names, and as ids
/// name it.
struct Where<'a> {
    homes: [&'a Path; 2],
    home: &'a Path,
}

/// Looks at one place under `base`. Its folder is reached one part at a time and a link on
/// the way is made real, so that nothing in a folder macOS asks permission for is looked at.
fn look_place(look: &mut Look, p: &Place, base: &Path, shown: &str, at: &Where) {
    let rel = Path::new(p.path);
    let (Some(folder), Some(name)) = (rel.parent(), rel.file_name()) else {
        return;
    };
    let path = match crate::guarded::under(base, folder, &at.homes) {
        Ok(folder) => folder.join(name),
        Err(guarded) => return look.not_into(shown.to_string(), guarded, at.home),
    };
    if !p.folder {
        let examined = examine(&path, look, at, p.counts);
        match examined {
            // A single file not there was read in full: it holds nothing.
            Examined::Absent => look.read.push(shown.to_string()),
            Examined::Present(..) | Examined::Parts(..) => look.present += 1,
            _ => {}
        }
        return take(look, p, shown.to_string(), examined, at);
    }
    let path = match crate::guarded::followed(&path, &at.homes) {
        Ok(path) => path,
        Err(guarded) => return look.not_into(shown.to_string(), guarded, at.home),
    };
    // Listing what is not a folder, a named pipe included, fails at once without waiting.
    let listing = std::fs::read_dir(&path).and_then(|entries| {
        entries
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
    });
    let names = match listing {
        Ok(names) => names,
        // A folder that is not there was listed in full: it holds nothing.
        Err(e) if absent(&e) => return look.read.push(shown.to_string()),
        Err(e) => return look.failed.push((shown.to_string(), e.to_string())),
    };
    look.present += 1;
    look.read.push(shown.to_string());
    look.seen.push(shown.to_string());
    for name in names {
        let text = name.to_string_lossy();
        if p.base == Base::Checkout && text.ends_with(SAMPLE) {
            continue;
        }
        let entry = format!("{shown}/{text}");
        let examined = examine(&path.join(&name), look, at, p.counts);
        take(look, p, entry, examined, at);
    }
}

/// Keeps what was found at one path, named `shown`, as the place's entries, or says why
/// nothing was, and records the unit it is (`baseline.rs`). A file whose parts count is one
/// unit, as a file read whole is: its parts, `<file>#<key>`, are entries of it, and the file
/// is read in full only when every part there was read. A part that could not be read is
/// named as it is, so that what was known of it is kept and only of it; the file is then seen
/// and not read, and losing sight of it is judged as for any unit.
fn take(look: &mut Look, p: &Place, shown: String, examined: Examined, at: &Where) {
    let entry = |path: String, content: Content, link: Option<String>| Entry {
        path,
        watched_as: p.watched_as,
        content,
        link,
    };
    match examined {
        Examined::Absent => {}
        Examined::Unknown(why) | Examined::Unread(why) => {
            look.seen.push(shown.clone());
            look.failed.push((shown, why));
        }
        Examined::Unreached(guarded) => {
            look.seen.push(shown.clone());
            look.not_into(shown, guarded, at.home);
        }
        Examined::Present(content, link) => {
            look.read.push(shown.clone());
            look.seen.push(shown.clone());
            look.entries.push(entry(shown, content, link));
        }
        Examined::Parts(parts, failed, link) => {
            if failed.is_empty() {
                look.read.push(shown.clone());
            }
            look.seen.push(shown.clone());
            for (key, content) in parts {
                let path = format!("{shown}#{key}");
                look.entries.push(entry(path, content, link.clone()));
            }
            for (key, why) in failed {
                look.failed
                    .push((format!("{shown}#{key}"), why.to_string()));
            }
        }
    }
}

fn absent(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::NotFound
}

enum Examined {
    Absent,
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
fn examine(path: &Path, look: &mut Look, at: &Where, counts: Counts) -> Examined {
    let own = std::fs::symlink_metadata(path).and_then(|m| {
        if !m.file_type().is_symlink() {
            return Ok((m, None));
        }
        let target = std::fs::read_link(path)?;
        Ok((m, Some(target.to_string_lossy().into_owned())))
    });
    let link = match own {
        Ok((m, None)) => return counted(path, &m, counts, None),
        Ok((_, Some(link))) => link,
        Err(e) if absent(&e) => return Examined::Absent,
        Err(e) => return Examined::Unknown(e.to_string()),
    };
    let target = match crate::guarded::followed(path, &at.homes) {
        Ok(target) => target,
        Err(guarded) if counts != Counts::Whole => return Examined::Unreached(guarded),
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
        Ok(meta) => counted(&target, &meta, counts, Some(link)),
        // A link to nothing holds no part: what reads the file reads nothing there.
        Err(e) if absent(&e) && counts != Counts::Whole => {
            Examined::Parts(Vec::new(), Vec::new(), Some(link))
        }
        Err(e) if absent(&e) => Examined::Present(Content::Dangling, Some(link)),
        Err(e) if counts != Counts::Whole => Examined::Unread(reason(&e)),
        Err(e) => Examined::Present(Content::Unread(Cause::Failed, reason(&e)), Some(link)),
    }
}

/// What a file reached holds, as `counts` takes it. Of a file whose parts count, anything but
/// a property list that was read is a place that failed: an entry of the whole file beside
/// its parts would make a reading that cannot see them say they are gone.
fn counted(path: &Path, meta: &Metadata, counts: Counts, link: Option<String>) -> Examined {
    let Counts::Keys(keys) = counts else {
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
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() {
            return Ok(Err(kind_of(opened.file_type())));
        }
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
    fn a_file_swapped_for_a_named_pipe_after_it_was_looked_at_never_holds_the_run() {
        // Between looking at a regular file and opening it, it may become a named pipe, which
        // a plain open waits on for a writer forever.
        let dir = std::env::temp_dir().join(format!("immune-watched-swap-{}", std::process::id()));
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
