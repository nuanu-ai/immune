//! The `agent-folders` reader: checkouts in the folders agents worked in. Agents also work
//! in temporary folders, hidden worktrees and on other volumes, which the walk of the home
//! folder never sees.
//!
//! The source is Claude Code's session files, `<sessions>/<folder>/*.jsonl`. Of a session
//! only the `cwd` field of a line is read; nothing else from it reaches the store, the raw
//! input or the output. A working folder that still exists leads to the nearest folder
//! above it that holds `.git`: that folder is the checkout. git is never run.
//!
//! Sessions are deleted after a while and the checkout stays. So the candidates of a run
//! are the working folders in the sessions plus the checkouts this reader already holds,
//! and each is checked on disk: only a checkout whose folder is really gone is dropped.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::{Path, PathBuf};

pub const READER: &str = "agent-folders";
pub const KIND: &str = "checkouts in agent working folders";
pub const BASIS: &str = "observed";
/// Where Claude Code keeps its sessions, inside the home folder.
pub const SESSIONS: &str = ".claude/projects";
/// The note of a full reading when there are no sessions to read.
pub const NOT_HERE: &str = "no Claude Code sessions on this machine";

/// What the session files hold that this reader uses.
pub enum Found {
    /// The session folder is not here: nothing to read, which is not a failure.
    Absent,
    Read(Sessions),
    /// The session folder is here and could not be listed, with the reason.
    Failed(String),
    /// The session folder leads into this folder macOS asks permission for, which was not
    /// entered.
    Guarded(PathBuf),
}

#[derive(Default)]
pub struct Sessions {
    pub files: usize,
    /// Session files that could not be read to the end.
    pub unreadable: usize,
    /// Folders of sessions that could not be listed.
    pub unlisted: usize,
    /// Lines that mention `"cwd"` and are not JSON.
    pub unparsed: usize,
    /// Every distinct working folder, as recorded.
    pub folders: BTreeSet<String>,
    /// Folders macOS asks permission for that a session file, a link, leads into: not read.
    pub guarded: BTreeSet<PathBuf>,
}

/// Reads the working folders from every session file under `dir`. The folder, and a session
/// file, may be a link: it is not followed into a folder macOS asks permission for. `homes`
/// are the home folder's names.
pub fn sessions(dir: &Path, homes: &[&Path]) -> Found {
    let listed = match crate::guarded::real(dir, homes) {
        crate::guarded::Real::At(real) => real,
        crate::guarded::Real::Guarded(g) => return Found::Guarded(g),
        // Looking at it fails where making it real failed, before any guarded folder.
        crate::guarded::Real::Failed(_) => dir.to_path_buf(),
    };
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Found::Absent,
        Err(e) => return Found::Failed(format!("{}: {e}", dir.display())),
        Ok(_) => {}
    }
    let projects = match std::fs::read_dir(listed) {
        Ok(entries) => entries,
        Err(e) => return Found::Failed(format!("{}: {e}", dir.display())),
    };
    let mut out = Sessions::default();
    for project in projects {
        let Ok(project) = project else {
            out.unlisted += 1;
            continue;
        };
        if !project.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(project.path()) else {
            out.unlisted += 1;
            continue;
        };
        for file in files {
            let Ok(file) = file else {
                out.unlisted += 1;
                continue;
            };
            let path = file.path();
            if path.extension().is_none_or(|e| e != "jsonl") {
                continue;
            }
            let path = match crate::guarded::followed(&path, homes) {
                Ok(path) => path,
                Err(g) => {
                    out.guarded.insert(g);
                    continue;
                }
            };
            out.files += 1;
            if read_file(&path, &mut out).is_err() {
                out.unreadable += 1;
            }
        }
    }
    Found::Read(out)
}

fn read_file(path: &Path, out: &mut Sessions) -> std::io::Result<()> {
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        // Most of the volume is text that never names a folder: skip it unparsed.
        if !contains(&line, b"\"cwd\"") {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&line) else {
            out.unparsed += 1;
            continue;
        };
        if let Some(cwd) = value.get("cwd").and_then(|v| v.as_str()) {
            out.folders.insert(cwd.to_string());
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    let first = needle[0];
    let mut rest = haystack;
    while let Some(i) = rest.iter().position(|&b| b == first) {
        if rest[i..].starts_with(needle) {
            return true;
        }
        rest = &rest[i + 1..];
    }
    false
}

/// What looking at one folder on disk found.
#[derive(Debug, PartialEq)]
pub enum OnDisk {
    /// The checkout, as a path without symbolic links.
    Checkout(PathBuf),
    /// The folder is gone, or no folder above it holds `.git`.
    Nothing,
    /// The disk could not say, for want of permission.
    Unknown,
    /// It leads into this folder macOS asks permission for, which was not entered.
    Guarded(PathBuf),
}

/// The checkout a working folder is in. `home` is the home folder without symbolic links,
/// and `homes` are its names, for the guarded folders. The home folder itself is never
/// taken for a checkout, as in the walk of the home folder, and nothing above it is looked
/// at.
pub fn checkout_of(folder: &str, home: &Path, homes: &[&Path]) -> OnDisk {
    let folder = Path::new(folder);
    if !folder.is_absolute() {
        return OnDisk::Nothing;
    }
    // Paths are taken without symbolic links, so one folder has one id whichever way an
    // agent reached it; they are made real without entering a guarded folder.
    let real = match crate::guarded::real(folder, homes) {
        crate::guarded::Real::At(real) => real,
        crate::guarded::Real::Guarded(g) => return OnDisk::Guarded(g),
        crate::guarded::Real::Failed(e) if gone(&e) => return OnDisk::Nothing,
        crate::guarded::Real::Failed(_) => return OnDisk::Unknown,
    };
    real.ancestors()
        .take_while(|dir| *dir != home)
        .find(|dir| std::fs::symlink_metadata(dir.join(".git")).is_ok())
        .map_or(OnDisk::Nothing, |dir| OnDisk::Checkout(dir.to_path_buf()))
}

/// Whether a checkout this reader holds is still there. `None` when the disk cannot say.
pub fn still_there(path: &Path) -> Option<bool> {
    match std::fs::symlink_metadata(path.join(".git")) {
        Ok(_) => Some(true),
        Err(e) if gone(&e) => Some(false),
        Err(_) => None,
    }
}

fn gone(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::NotFound
}
