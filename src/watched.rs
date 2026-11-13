//! The `watched-places` reader: the few places on a Mac where persistence lives and that
//! rarely change for a good reason. It keeps a checksum of each file there, so the lifecycle
//! turns a difference between two runs into an event. Content is never kept or printed.
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
}

pub const AUTOSTART: &str = "autostart item";
pub const PROFILE: &str = "shell profile";
pub const SSH: &str = "ssh access file";
pub const HOOK: &str = "git hook";
pub const AUTOSTART_KIND: &str = "launch agents and daemons";
pub const PROFILE_KIND: &str = "shell profiles of zsh and bash";
pub const SSH_KIND: &str = "ssh access files";
pub const HOOK_KIND: &str = "hooks in the checkout's .git folder";
/// Entries of a hooks folder that git itself never runs.
const SAMPLE: &str = ".sample";

/// A kind of place: the literal of `watched_as` and the coverage kind of its reading.
type Kind = (&'static str, &'static str);
const AUTOSTARTS: Kind = (AUTOSTART, AUTOSTART_KIND);
const PROFILES: Kind = (PROFILE, PROFILE_KIND);
const SSH_FILES: Kind = (SSH, SSH_KIND);
const HOOKS: Kind = (HOOK, HOOK_KIND);

const fn place(kind: Kind, base: Base, path: &'static str, folder: bool) -> Place {
    Place {
        watched_as: kind.0,
        kind: kind.1,
        base,
        path,
        folder,
    }
}

/// Every watched place. Adding a place is one row. Each holds on every Mac; none is a
/// private key or known hosts. The order is the order of the view and the report.
pub const PLACES: [Place; 28] = [
    place(AUTOSTARTS, Base::Home, "Library/LaunchAgents", true),
    place(AUTOSTARTS, Base::System, "Library/LaunchAgents", true),
    place(AUTOSTARTS, Base::System, "Library/LaunchDaemons", true),
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
    place(HOOKS, Base::Checkout, ".git/hooks", true),
];

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
            Content::Special(what) => Some(format!("not a regular file: {what}")),
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
        match examine(&path, look, at) {
            Examined::Absent => look.read.push(shown.to_string()),
            Examined::Unknown(why) => {
                look.seen.push(shown.to_string());
                look.failed.push((shown.to_string(), why));
            }
            Examined::Present(content, link) => {
                look.present += 1;
                look.read.push(shown.to_string());
                look.seen.push(shown.to_string());
                look.entries.push(Entry {
                    path: shown.to_string(),
                    watched_as: p.watched_as,
                    content,
                    link,
                });
            }
        }
        return;
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
        match examine(&path.join(&name), look, at) {
            Examined::Absent => {}
            Examined::Unknown(why) => {
                look.seen.push(entry.clone());
                look.failed.push((entry, why));
            }
            Examined::Present(content, link) => {
                look.read.push(entry.clone());
                look.seen.push(entry.clone());
                look.entries.push(Entry {
                    path: entry,
                    watched_as: p.watched_as,
                    content,
                    link,
                });
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
    Present(Content, Option<String>),
}

/// What is at a path, whose folder was reached. A symbolic link is followed to its final
/// target for the content, unless that target is in a folder macOS asks permission for:
/// then the link is there and what it leads to was not looked into.
fn examine(path: &Path, look: &mut Look, at: &Where) -> Examined {
    let own = std::fs::symlink_metadata(path).and_then(|m| {
        if !m.file_type().is_symlink() {
            return Ok((m, None));
        }
        let target = std::fs::read_link(path)?;
        Ok((m, Some(target.to_string_lossy().into_owned())))
    });
    let link = match own {
        Ok((m, None)) => return Examined::Present(content(path, &m), None),
        Ok((_, Some(link))) => link,
        Err(e) if absent(&e) => return Examined::Absent,
        Err(e) => return Examined::Unknown(e.to_string()),
    };
    let target = match crate::guarded::followed(path, &at.homes) {
        Ok(target) => target,
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
    let content = match std::fs::metadata(&target) {
        Ok(meta) => content(&target, &meta),
        Err(e) if absent(&e) => Content::Dangling,
        Err(e) => Content::Unread(Cause::Failed, reason(&e)),
    };
    Examined::Present(content, Some(link))
}

fn reason(e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::ELOOP) {
        "link loop".to_string()
    } else {
        e.to_string()
    }
}

/// The content of what `meta` describes. Only a regular file is opened, and without
/// waiting: a file swapped for a named pipe after it was looked at cannot hold the run, and
/// is told by what was opened.
fn content(path: &Path, meta: &Metadata) -> Content {
    if !meta.is_file() {
        return Content::Special(kind_of(meta.file_type()));
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
        Err(e) => Content::Unread(Cause::Failed, reason(&e)),
        Ok(Err(what)) => Content::Special(what),
        // The file is there and this build does not read a file that large.
        Ok(Ok(bytes)) if bytes.len() as u64 > CAP => Content::Unread(
            Cause::NoReader,
            format!("over the size cap of {} MiB", CAP >> 20),
        ),
        Ok(Ok(bytes)) => Content::Hash(format!("sha256:{}", crate::sha256::hex(&bytes))),
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
