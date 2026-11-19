//! The `agent-folders` reader: checkouts in the folders agents worked in. Agents also work
//! in temporary folders, hidden worktrees and on other volumes, which the walk of the home
//! folder never sees.
//!
//! The sources are the session files of the coding agents in `SOURCES`, line-delimited JSON
//! whose lines state the session's working folder: Claude Code's and Codex CLI's. Of a session
//! only the working folder of a line is read; nothing else from it reaches the store, the raw
//! input or the output. A working folder that still exists leads to the nearest folder
//! above it that holds `.git`: that folder is the checkout. git is never run. The agents in
//! `UNREAD` keep sessions whose working folder this version cannot read: their folder is only
//! looked for, never listed, and when it is there the agent is named as not read.
//!
//! Sessions are deleted after a while and the checkout stays. So the candidates of a run
//! are the working folders in the sessions plus the checkouts this reader already holds,
//! and each is checked on disk: only a checkout whose folder is really gone is dropped.
//!
//! A session file only grows while its agent works, so a reading goes on from where the last
//! one stopped. For each file the store keeps, in `session_file`, the end of the last whole
//! line read (the position), the SHA-256 of every byte before it, the working folders and the
//! count of unparsed lines those bytes hold, and the file's inode and change time at that
//! reading. The folders kept stand for the bytes before the position, so a reading of the
//! rest gives what a reading from the first byte gives. A position is trusted only when the
//! bytes before it are shown to be the bytes read: the file has the same inode, and either
//! its change time is unchanged or the bytes before the position hash to the digest kept.
//!
//! An unchanged change time stands for unchanged content only on APFS and HFS+, where the
//! kernel moves it on a write, a change of size and a change of the modification time, and
//! no program can set it (setattrlist(2)). On any other volume (FAT, exFAT, SMB, NFS, FUSE),
//! where a program may set it or it moves in steps of seconds, the bytes before the position
//! are hashed every time. Even on APFS and HFS+ there are two cases in which changed bytes
//! are not seen until the change time moves: a write through a shared mapping of the file,
//! until the mapping is synced or unmapped, and a change to the volume while it was not
//! mounted. A program that can do either can as well rewrite the session file outright, and
//! a reading from the first byte would see no more than this one. A change time taken less
//! than a second after the file last changed never stands for its content, as git does not
//! trust an index entry that is "racily clean". Anything else is read from the first byte.
//! A last line without its line break is read, as a reading from the first byte reads it,
//! but the position stays before it.
//!
//! Claude Code keeps the sessions of its subagents in folders below a project's folder, so for
//! it every `.jsonl` file at any depth below one is a session file. That walk lists at most
//! `LOOK_LIMIT` folders; past it the reading is partial and names `NOT_LOOKED`.
//!
//! A session file is a regular file in its folder of sessions. It is opened without following
//! a link and without waiting, so an entry that is a link, a named pipe or anything else is a
//! session file that could not be read, and the kept row of a file is keyed by its own path.
//! A line is held up to `LINE_BYTES`; the rest of a longer one is passed over without being
//! held, and the line is counted as unparsed.
//!
//! Codex CLI compresses a session it has not changed for seven days with zstd. Only `decode`
//! reads such a file's bytes: as a stream, its lines read as a plain file's are, never all in
//! memory. It does not grow, so it gives all or nothing: its position is its length, its
//! digest is that of its compressed bytes, and it is trusted by the same rule. A trusted file
//! gives the folders kept without its content being read; anything else is decoded from the
//! first byte. One that is not a single zstd frame, is cut short, asks for a window over
//! `WINDOW_BYTES` or decodes to more than `DECODED_BYTES` could not be read, and gives no
//! folder.

use crate::sha256::Hasher;
use rusqlite::{Connection, Transaction, params};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const READER: &str = "agent-folders";
pub const KIND: &str = "checkouts in agent working folders";
pub const BASIS: &str = "observed";
/// Where Claude Code keeps its sessions, inside the home folder: the folder
/// `--sessions-root` stands in for.
pub const SESSIONS: &str = ".claude/projects";
/// The note of a full reading when there are no sessions to read.
pub const NOT_HERE: &str = "no sessions of Claude Code or Codex CLI on this machine";
/// How the reason's last clause begins when session files lead into folders macOS asks
/// permission for; the folders follow.
pub const FILES_NOT_LOOKED_INTO: &str = "session files not looked into: ";
/// What a reading names, by the agent's name, as sessions this version does not read.
pub const OTHER_AGENT: &str = "sessions of a coding agent";
/// What a reading names when the walk below the level of a source's sessions (`Source::deeper`)
/// reached `LOOK_LIMIT`: what the folders past it hold is not known.
pub const NOT_LOOKED: &str = "folders not looked through for agent sessions";
/// How many folders the walk lists below the level of one source's sessions. The lockfile
/// reader's walk stops at the same number (`lockfiles::LOOK_LIMIT`). A session with subagents
/// takes two folders below its project's folder and a workflow of them two more, so this holds
/// more than ten thousand sessions.
pub const LOOK_LIMIT: usize = 50_000;

/// One agent's session files this reader reads.
pub struct Source {
    /// The folder of the sessions, inside the home folder.
    pub dir: &'static str,
    /// How many folders lie between it and a session file.
    pub depth: usize,
    /// Whether session files also lie in folders below that level, at any depth.
    pub deeper: bool,
    /// Where a line states the working folder, as a JSON pointer.
    pub cwd: &'static str,
    /// The quoted values of `type` whose lines always state it: such a line that does not is
    /// of a shape this version does not know, and is counted as unparsed.
    pub stated_by: &'static [&'static str],
    /// The end of the name of a session file the agent compressed with zstd.
    pub compressed: Option<&'static str>,
}

/// Claude Code: `<dir>/<folder>/<session>.jsonl`, the working folder in `cwd`. It keeps them
/// elsewhere when started with `CLAUDE_CONFIG_DIR`, which this reader cannot know.
/// https://code.claude.com/docs/en/claude-directory
/// The sessions of its subagents lie deeper, as observed:
/// `<folder>/<session>/subagents/agent-<id>.jsonl` and below that, in
/// `subagents/workflows/<id>/`. Their lines state the working folder in the same field, and a
/// subagent that works in a worktree of its own may state it only there. So every `.jsonl`
/// file below a project's folder is read as a session.
pub const CLAUDE_CODE: Source = Source {
    dir: SESSIONS,
    depth: 1,
    deeper: true,
    cwd: "/cwd",
    stated_by: &[],
    compressed: None,
};

/// Codex CLI keeps a session as `sessions/<year>/<month>/<day>/rollout-*.jsonl`, and one
/// archived flat in `archived_sessions`, inside `~/.codex`. Each line is
/// `{"timestamp", "type", "payload"}`; the first, `session_meta`, and every `turn_context`
/// state the working folder in `payload.cwd`. A file not changed for seven days is compressed
/// with zstd to `.jsonl.zst`.
/// https://github.com/openai/codex/blob/main/codex-rs/rollout/src/lib.rs (the folders),
/// https://github.com/openai/codex/blob/main/codex-rs/history/src/rollout_payload.rs (a line),
/// https://github.com/openai/codex/blob/main/codex-rs/rollout/src/compression.rs
const CODEX: Source = Source {
    dir: ".codex/sessions",
    depth: 3,
    // Its layout is fixed by its own code, cited above: nothing below it is a session.
    deeper: false,
    cwd: "/payload/cwd",
    stated_by: &["\"session_meta\"", "\"turn_context\""],
    compressed: Some(".jsonl.zst"),
};

/// Every agent whose sessions are read.
pub static SOURCES: [Source; 3] = [
    CLAUDE_CODE,
    CODEX,
    Source {
        dir: ".codex/archived_sessions",
        depth: 0,
        ..CODEX
    },
];

/// Agents that keep sessions in the home folder in a form whose working folder this version
/// cannot read, with where.
pub const UNREAD: [(&str, &str); 3] = [
    // JSON lines whose working folder is given only as a hash of it.
    // https://geminicli.com/docs/cli/session-management/
    // https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts
    ("Gemini CLI", ".gemini/tmp"),
    // One JSON file for each session.
    // https://github.com/continuedev/continue/blob/main/core/util/paths.ts
    ("Continue", ".continue/sessions"),
    // A format its documentation does not give.
    // https://docs.github.com/en/copilot/concepts/agents/copilot-cli/chronicle
    ("GitHub Copilot CLI", ".copilot/session-state"),
];

/// The agents of `UNREAD` whose folder is in `home`, whose names are `homes`. A folder is
/// looked for and never listed or read, and the last name of its path is not followed. One
/// whose path leads into a folder macOS asks permission for is not looked for.
pub fn unread_here(home: &Path, homes: &[&Path]) -> Vec<&'static str> {
    UNREAD
        .iter()
        .filter(|(_, dir)| {
            let path = home.join(dir);
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return false;
            };
            match crate::guarded::real(parent, homes) {
                crate::guarded::Real::At(real) => std::fs::symlink_metadata(real.join(name))
                    .is_ok_and(|m| m.is_dir() || m.is_symlink()),
                _ => false,
            }
        })
        .map(|(agent, _)| *agent)
        .collect()
}

/// Part of the store's schema (`store::schema`). A new store has no positions, so its first
/// reading is from the first byte of every file.
pub const SCHEMA: &str = "
-- Where each agent session file was read up to, see agent_folders.rs. Every byte before
-- `position` is whole lines already read; `digest` is the SHA-256 of those bytes; `folders`
-- are the working folders they name, as a JSON array, and `unparsed` their lines with a
-- working folder that are not JSON. The inode and change time are the file's at that
-- reading; `settled` is 0 when the file had changed too shortly before for an unchanged
-- change time to stand for it.
CREATE TABLE session_file (
    path     BLOB PRIMARY KEY,
    inode    INTEGER NOT NULL,
    ctime_ns INTEGER NOT NULL,
    settled  INTEGER NOT NULL,
    position INTEGER NOT NULL,
    digest   TEXT NOT NULL,
    folders  TEXT NOT NULL,
    unparsed INTEGER NOT NULL
);
";

/// How long after a file's last change its stat starts to stand for its content.
const SETTLE_NS: i64 = 1_000_000_000;
/// What the store keeps of the folders of one file and of all files. A file whose folders
/// would go past either is not kept, and is read from its first byte the next time.
/// 1024 bytes is `PATH_MAX` on macOS.
const HELD_FOLDERS: usize = 64;
const HELD_FOLDER_BYTES: usize = 1024;
const HELD_BYTES: usize = 4 << 20;
/// What the working folders one file names, as it is read, may come to. A row keeps at most
/// `HELD_FOLDERS` of `HELD_FOLDER_BYTES`, 64 KiB; four times that leaves room for a session of
/// more folders than a row keeps, which is read every time as before. A file past it could not
/// be read, so that a file written to be hostile cannot make the reader hold a gigabyte of
/// folder names.
const FILE_FOLDER_BYTES: usize = 4 * HELD_FOLDERS * HELD_FOLDER_BYTES;
/// What one compressed session file may decode to. A plain file is read to its size on disk;
/// a compressed one can stand for far more than it holds, since a block of three bytes may
/// repeat one byte 128 KiB times. 1 GiB leaves room for the text of turns and tool output of
/// a long session, and keeps what one file can cost to seconds of decoding.
const DECODED_BYTES: u64 = 1 << 30;
/// The largest window a zstd frame may ask the decoder to keep in memory: 128 MiB, libzstd's
/// own default limit for decoding (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`, a window log of 27), which
/// every frame its levels up to 22 write stays within. A frame that asks for more is refused
/// before anything is kept for it.
const WINDOW_BYTES: u64 = 128 << 20;
/// How much of one line of a session, plain or compressed, is held to be parsed. A line is one
/// item of a session; the longest are images given as base64, and 64 MiB holds one of 48 MiB.
/// The rest of a longer line is passed over without being held, and the line is counted as
/// unparsed.
const LINE_BYTES: u64 = 64 << 20;

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
    /// Whether the walk below the level of the sessions reached its budget and left folders
    /// not listed.
    pub stopped: bool,
    /// Lines that mention `"cwd"` and are not JSON, lines of a kind that always states the
    /// working folder and do not, and lines longer than `LINE_BYTES`.
    pub unparsed: usize,
    /// Every distinct working folder, as recorded.
    pub folders: BTreeSet<String>,
    /// Folders macOS asks permission for that a folder of sessions leads into: not read.
    pub guarded: BTreeSet<PathBuf>,
    /// What the store is to keep for the next reading: an entry for each file read, and the
    /// entry it had for a file that could not be read.
    pub held: BTreeMap<PathBuf, Held>,
    pub cost: Cost,
}

/// What a reading of the session files read.
#[derive(Default, Debug, PartialEq)]
pub struct Cost {
    /// Files whose stat was unchanged: nothing before the position was read.
    pub unchanged: usize,
    /// Files read on from the position, after the bytes before it hashed to the digest kept.
    pub from_position: usize,
    /// Files read from their first byte.
    pub from_start: usize,
    /// Bytes read from session files, to hash and to parse, and those a compressed one
    /// decoded to.
    pub bytes: u64,
}

/// What the store keeps of one session file between readings.
#[derive(Clone, Debug, PartialEq)]
pub struct Held {
    pub stat: Stat,
    /// Whether the file had not changed for a while when `stat` was taken, so that an
    /// unchanged stat stands for unchanged content.
    pub settled: bool,
    /// The end of the last whole line read.
    pub position: u64,
    /// SHA-256 of the bytes before `position`, as hexadecimal.
    pub digest: String,
    /// The working folders and the unparsed lines in the bytes before `position`.
    pub folders: BTreeSet<String>,
    pub unparsed: usize,
}

/// A file's identity and the time the kernel last changed it, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub inode: u64,
    pub ctime_ns: i64,
}

impl Stat {
    fn of(m: &std::fs::Metadata) -> Stat {
        Stat {
            inode: m.ino(),
            ctime_ns: m
                .ctime()
                .saturating_mul(1_000_000_000)
                .saturating_add(m.ctime_nsec()),
        }
    }
}

impl Sessions {
    /// Takes in what another source's reading read, within what the store keeps of all files.
    /// What a reading cost stays each source's own.
    pub fn add(&mut self, mut other: Sessions) {
        self.files += other.files;
        self.unreadable += other.unreadable;
        self.unlisted += other.unlisted;
        self.stopped |= other.stopped;
        self.unparsed += other.unparsed;
        self.folders.append(&mut other.folders);
        self.guarded.append(&mut other.guarded);
        self.held.append(&mut other.held);
        within_bounds(&mut self.held);
    }
}

/// Reads the working folders from every session file of `source` under `dir`, each from where
/// `held` says the last reading stopped when that can be trusted, at `now`. The folder may be
/// a link: it is not followed into a folder macOS asks permission for. `homes` are the home
/// folder's names. Below the level of its sessions, at most `budget` folders are listed.
pub fn sessions(
    source: &'static Source,
    dir: &Path,
    homes: &[&Path],
    held: &BTreeMap<PathBuf, Held>,
    now: SystemTime,
    budget: usize,
) -> Found {
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
    let entries = match std::fs::read_dir(listed) {
        Ok(entries) => entries,
        Err(e) => return Found::Failed(format!("{}: {e}", dir.display())),
    };
    let mut walk = Walk {
        source,
        held,
        // A file whose change time is before this had not changed for a while.
        settled_before: now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
            .saturating_sub(SETTLE_NS),
        budget,
        out: Sessions::default(),
    };
    walk.entries(entries, source.depth);
    within_bounds(&mut walk.out.held);
    Found::Read(walk.out)
}

/// One reading of a source's folder.
struct Walk<'a> {
    source: &'static Source,
    held: &'a BTreeMap<PathBuf, Held>,
    settled_before: i64,
    /// The folders below the level of the sessions still to be listed.
    budget: usize,
    out: Sessions,
}

impl Walk<'_> {
    /// Reads the session files `depth` folders below the entries of a folder, and in every
    /// folder below that level when the source keeps sessions there, within the budget. A
    /// folder is entered only when it is one, not a link to one, and only once the folder
    /// above it is closed, so a walk holds one folder open however deep it goes. How deep it
    /// goes is bounded by the length of a path, 1024 bytes on macOS.
    fn entries(&mut self, entries: std::fs::ReadDir, depth: usize) {
        let mut below = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                self.out.unlisted += 1;
                continue;
            };
            let path = entry.path();
            let compressed = self
                .source
                .compressed
                .is_some_and(|end| path.as_os_str().as_bytes().ends_with(end.as_bytes()));
            if depth > 0 || (!compressed && path.extension().is_none_or(|e| e != "jsonl")) {
                if (depth > 0 || self.source.deeper) && entry.file_type().is_ok_and(|t| t.is_dir())
                {
                    below.push(path);
                }
                continue;
            }
            self.out.files += 1;
            let before = self.held.get(&path);
            read_session(
                self.source,
                &path,
                before,
                self.settled_before,
                compressed.then_some(DECODED_BYTES),
                &mut self.out,
            );
        }
        for path in below {
            if depth == 0 {
                if self.budget == 0 {
                    self.out.stopped = true;
                    break;
                }
                self.budget -= 1;
            }
            match std::fs::read_dir(&path) {
                Ok(inner) => self.entries(inner, depth.saturating_sub(1)),
                Err(_) => self.out.unlisted += 1,
            }
        }
    }
}

/// The working folders and unparsed lines of some lines of a session of `source`.
struct Parsed {
    source: &'static Source,
    folders: BTreeSet<String>,
    unparsed: usize,
    /// The bytes of the distinct folders named, held or not.
    text: usize,
}

impl Parsed {
    fn of(source: &'static Source) -> Parsed {
        Parsed {
            source,
            folders: BTreeSet::new(),
            unparsed: 0,
            text: 0,
        }
    }

    /// Starts from what the entry before holds of the bytes not read again.
    fn kept(&mut self, b: &Held) {
        self.folders.clone_from(&b.folders);
        self.unparsed = b.unparsed;
        self.text = b.folders.iter().map(String::len).sum();
    }

    fn take(&mut self, line: &[u8]) {
        // Most of the volume is text that never names a folder: skip it unparsed.
        let stated_by = self.source.stated_by;
        if !contains(line, b"\"cwd\"") && !stated_by.iter().any(|t| contains(line, t.as_bytes())) {
            return;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            self.unparsed += 1;
            return;
        };
        match value.pointer(self.source.cwd).and_then(|v| v.as_str()) {
            // Past what one file may name, a folder is not held.
            Some(cwd) if !self.folders.contains(cwd) => {
                self.text += cwd.len();
                if self.text <= FILE_FOLDER_BYTES {
                    self.folders.insert(cwd.to_string());
                }
            }
            Some(_) => {}
            // A line of a kind that always states it, and does not: a shape not known.
            None if value
                .get("type")
                .and_then(|v| v.as_str())
                .is_some_and(|t| stated_by.iter().any(|s| s.trim_matches('"') == t)) =>
            {
                self.unparsed += 1;
            }
            None => {}
        }
    }

    /// Takes a line `read_line` read: one longer than what is held of it is counted. Fails
    /// once the folders named come to more than one file may name.
    fn line(&mut self, line: &[u8], read: Line) -> std::io::Result<()> {
        if read.long {
            self.unparsed += 1;
        } else {
            self.take(line);
        }
        if self.text > FILE_FOLDER_BYTES {
            return Err(std::io::Error::other(format!(
                "working folders of more than {FILE_FOLDER_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

/// Reads one session file into `out`. A file that cannot be read keeps its entry, and what
/// that entry holds still counts: what was established is not dropped because a reading
/// failed, and the reading is partial. `compressed` is what a compressed file may decode to.
fn read_session(
    source: &'static Source,
    path: &Path,
    before: Option<&Held>,
    settled_before: i64,
    compressed: Option<u64>,
    out: &mut Sessions,
) {
    let (mut whole, mut last) = (Parsed::of(source), Parsed::of(source));
    let read = crate::watched::open_regular(path).and_then(|opened| {
        let (mut file, meta) = opened.map_err(|what| std::io::Error::other(format!("a {what}")))?;
        let then = Then {
            stat: Stat::of(&meta),
            before,
            settled_before,
            change_time_kept: change_time_kept(&file),
        };
        match compressed {
            Some(most) => {
                let len = meta.len();
                read_compressed(&mut file, &then, len, most, &mut whole, &mut out.cost)
            }
            None => read_from(&mut file, &then, &mut whole, &mut last, &mut out.cost),
        }
    });
    match read {
        Ok(Some(held)) => {
            out.held.insert(path.to_path_buf(), held);
        }
        Ok(None) => {}
        Err(_) => {
            out.unreadable += 1;
            if let Some(before) = before {
                whole.folders.extend(before.folders.iter().cloned());
                out.held.insert(path.to_path_buf(), before.clone());
            }
        }
    }
    out.folders.append(&mut whole.folders);
    out.folders.append(&mut last.folders);
    out.unparsed += whole.unparsed + last.unparsed;
}

/// What is known of a file as its reading starts.
struct Then<'a> {
    stat: Stat,
    before: Option<&'a Held>,
    settled_before: i64,
    /// Whether the file's volume keeps a change time no program can set.
    change_time_kept: bool,
}

impl<'a> Then<'a> {
    /// The entry before, when it is of this file.
    fn same_file(&self) -> Option<&'a Held> {
        // Another file at the path is read from its first byte, even one that begins with
        // the same bytes.
        self.before.filter(|b| b.stat.inode == self.stat.inode)
    }

    /// The entry before, when the file has not been written to since it was taken.
    fn unchanged(&self) -> Option<&'a Held> {
        self.same_file()
            .filter(|b| self.change_time_kept && b.settled && b.stat == self.stat)
    }

    /// The entry to keep of the bytes before `position`, or `None` when it would hold more
    /// than the store keeps.
    fn held(&self, position: u64, digest: String, whole: &Parsed) -> Option<Held> {
        let fits = whole.folders.len() <= HELD_FOLDERS
            && whole.folders.iter().all(|f| f.len() <= HELD_FOLDER_BYTES);
        fits.then(|| Held {
            stat: self.stat,
            settled: self.stat.ctime_ns < self.settled_before,
            position,
            digest,
            folders: whole.folders.clone(),
            unparsed: whole.unparsed,
        })
    }
}

/// The file systems whose change time no program can set, by the type name `statfs` gives:
/// APFS and HFS+.
const CHANGE_TIME_KEPT: [&[u8]; 2] = [b"apfs", b"hfs"];

/// Whether the volume of `file` is one of those. `false` when `fstatfs` fails.
fn change_time_kept(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: `statfs` is plain data, so all zeros is a valid value, and fstatfs writes only
    // into the one structure it is given, for a descriptor that stays open during the call.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 {
        return false;
    }
    let name: Vec<u8> = fs
        .f_fstypename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    kept_by(&name)
}

fn kept_by(fs_type: &[u8]) -> bool {
    CHANGE_TIME_KEPT.contains(&fs_type)
}

/// Reads a plain session from where it can be trusted that the last reading stopped. The
/// whole lines before the new position go to `whole`, together with what the entry before
/// holds of the bytes not read again; a last line without its line break goes to `last`.
/// Returns the entry to keep, or `None` when it would hold more than the store keeps.
fn read_from<R: Read + Seek>(
    file: &mut R,
    then: &Then,
    whole: &mut Parsed,
    last: &mut Parsed,
    cost: &mut Cost,
) -> std::io::Result<Option<Held>> {
    if let Some(b) = then.unchanged() {
        // Not written to since: only what follows the position, a line still being written.
        cost.unchanged += 1;
        whole.kept(b);
        file.seek(SeekFrom::Start(b.position))?;
        let mut reader = BufReader::with_capacity(1 << 20, file);
        let mut line = Vec::new();
        while let Some(read) = read_line(&mut reader, &mut line, cost, |_| {})? {
            last.line(&line, read)?;
        }
        return Ok(Some(b.clone()));
    }
    let mut hasher = Hasher::new();
    let mut position = 0;
    match then.same_file() {
        Some(b) if head_is(file, b, &mut hasher, cost)? => {
            cost.from_position += 1;
            whole.kept(b);
            position = b.position;
        }
        _ => {
            cost.from_start += 1;
            hasher = Hasher::new();
            file.seek(SeekFrom::Start(0))?;
        }
    }
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut line = Vec::new();
    loop {
        // A line is hashed as it is read, and taken back if it turns out to be the last one,
        // still being written.
        let before = hasher.clone();
        let Some(read) = read_line(&mut reader, &mut line, cost, |b| hasher.update(b))? else {
            break;
        };
        if read.ends {
            position += read.len;
            whole.line(&line, read)?;
        } else {
            // The last line, still being written: read now, and again next time.
            hasher = before;
            last.line(&line, read)?;
        }
    }
    Ok(then.held(position, hasher.hex(), whole))
}

/// Reads a compressed session, which gives all or nothing. Its content is read only by
/// `decode`, from the first byte and no further than `len`, its length when it was opened; a
/// file trusted as read before gives the folders kept.
fn read_compressed<R: Read + Seek>(
    file: &mut R,
    then: &Then,
    len: u64,
    most: u64,
    whole: &mut Parsed,
    cost: &mut Cost,
) -> std::io::Result<Option<Held>> {
    if let Some(b) = then.unchanged() {
        cost.unchanged += 1;
        whole.kept(b);
        return Ok(Some(b.clone()));
    }
    let mut hasher = Hasher::new();
    if let Some(b) = then.same_file()
        // Its bytes are the bytes read: the same digest, and no byte after them.
        && head_is(file, b, &mut hasher, cost)?
        && len == b.position
    {
        cost.from_position += 1;
        whole.kept(b);
        return Ok(then.held(b.position, hasher.hex(), whole));
    }
    cost.from_start += 1;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Hasher::new();
    // A file that grows while it is decoded is cut where it ended when it was opened.
    let mut reader = BufReader::with_capacity(1 << 20, file.take(len));
    let position = decode(&mut reader, most, &mut hasher, whole, cost)?;
    Ok(then.held(position, hasher.hex(), whole))
}

/// What `read_line` read of one line.
#[derive(Clone, Copy)]
struct Line {
    /// Its length, its line break included.
    len: u64,
    /// Whether it ends with its line break.
    ends: bool,
    /// Whether it is longer than what was held of it, `LINE_BYTES`.
    long: bool,
}

/// Reads the next line, holding its first `LINE_BYTES` bytes in `line` and passing over the
/// rest without holding it, a mebibyte at a time. Every byte of it is given to `seen`. `None`
/// at the end.
///
/// Each turn of the loop takes up to a line break, and no more than a bound: what is left of
/// `LINE_BYTES` while the line is held, a mebibyte after that. A turn that takes its line
/// break ends the line, which `ends`. A turn that takes less than its bound without one met
/// the end of what there is to read: the line does not end, and is read again the next time.
/// Only a turn that took all of its bound looks on. The line is `long` when more than
/// `LINE_BYTES` of its bytes, its line break included, were taken. Nothing is looked at once
/// the line has ended, so a line break that arrives after the end was met belongs to the next
/// reading.
fn read_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    cost: &mut Cost,
    mut seen: impl FnMut(&[u8]),
) -> std::io::Result<Option<Line>> {
    line.clear();
    let mut rest = Vec::new();
    let mut read = Line {
        len: 0,
        ends: false,
        long: false,
    };
    loop {
        let (into, bound) = match LINE_BYTES.checked_sub(read.len).filter(|&b| b > 0) {
            Some(left) => (&mut *line, left),
            None => {
                rest.clear();
                (&mut rest, 1 << 20)
            }
        };
        let start = into.len();
        let n = Read::take(&mut *reader, bound).read_until(b'\n', into)? as u64;
        seen(&into[start..]);
        read.len += n;
        read.ends = into.last() == Some(&b'\n');
        if read.ends || n < bound {
            break;
        }
    }
    read.long = read.len > LINE_BYTES;
    cost.bytes += read.len;
    Ok((read.len > 0).then_some(read))
}

/// Reads the lines of the one zstd frame `file` holds into `whole`, hashing its bytes into
/// `hasher`, and returns how many bytes it has. Fails on anything that is not one whole
/// frame and nothing after it, on a frame that asks for a window over `WINDOW_BYTES`, and on
/// one that decodes to more than `most`, and then gives no folder. The frame's checksum is
/// read and not checked, since the decoder checks it only with a hash this program does not
/// take in. A damaged frame often fails to decode; one that does not gives other text, as a
/// damaged plain file does.
fn decode(
    file: &mut impl Read,
    most: u64,
    hasher: &mut Hasher,
    whole: &mut Parsed,
    cost: &mut Cost,
) -> std::io::Result<u64> {
    let mut source = Hashing {
        inner: file,
        hasher,
        bytes: 0,
    };
    let mut frame =
        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(&mut source, WINDOW_BYTES)
            .map_err(std::io::Error::other)?;
    let mut reader = BufReader::new((&mut frame).take(most.saturating_add(1)));
    let (mut got, mut line, mut decoded) = (Parsed::of(whole.source), Vec::new(), 0);
    while let Some(read) = read_line(&mut reader, &mut line, cost, |_| {})? {
        decoded += read.len;
        got.line(&line, read)?;
    }
    if decoded > most {
        return Err(std::io::Error::other(format!(
            "decodes to more than {most} bytes"
        )));
    }
    drop(reader);
    if frame.get_mut().read(&mut [0])? > 0 {
        return Err(std::io::Error::other("bytes after the frame"));
    }
    // Accepted whole: only now does what it holds count.
    whole.folders.append(&mut got.folders);
    whole.unparsed += got.unparsed;
    cost.bytes += source.bytes;
    Ok(source.bytes)
}

/// Whether the file's first `b.position` bytes hash to `b.digest`, hashing them into
/// `hasher`. On `true` the file is at the position. A file now shorter hashes fewer bytes,
/// which do not hash to the digest.
fn head_is<R: Read>(
    file: &mut R,
    b: &Held,
    hasher: &mut Hasher,
    cost: &mut Cost,
) -> std::io::Result<bool> {
    let mut head = Hashing {
        inner: file.take(b.position),
        hasher,
        bytes: 0,
    };
    std::io::copy(&mut head, &mut std::io::sink())?;
    cost.bytes += head.bytes;
    Ok(head.hasher.clone().hex() == b.digest)
}

/// Hashes and counts what is read through it.
struct Hashing<'a, R> {
    inner: R,
    hasher: &'a mut Hasher,
    bytes: u64,
}

impl<R: Read> Read for Hashing<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Drops entries, in the order of their paths, past what the store keeps of all files.
fn within_bounds(held: &mut BTreeMap<PathBuf, Held>) {
    let mut total = 0;
    held.retain(|_, h| {
        total += h.folders.iter().map(String::len).sum::<usize>();
        total <= HELD_BYTES
    });
}

/// The entries the store keeps, by the path of the file. One that does not read back as
/// written is left out, and that file is read from its first byte.
pub fn held(conn: &Connection) -> rusqlite::Result<BTreeMap<PathBuf, Held>> {
    let mut stmt = conn.prepare(
        "SELECT path, inode, ctime_ns, settled, position, digest, folders, unparsed
         FROM session_file",
    )?;
    let rows = stmt.query_map([], |r| {
        let Ok(path) = r.get::<_, Vec<u8>>(0) else {
            return Ok(None);
        };
        let n = |i: usize| r.get::<_, i64>(i).ok().and_then(|v| u64::try_from(v).ok());
        let entry = || -> Option<Held> {
            let folders: String = r.get(6).ok()?;
            Some(Held {
                stat: Stat {
                    // Kept as the same 64 bits, which an integer of SQLite holds.
                    inode: r.get::<_, i64>(1).ok()? as u64,
                    ctime_ns: r.get(2).ok()?,
                },
                settled: r.get::<_, i64>(3).ok()? == 1,
                position: n(4)?,
                digest: r.get(5).ok()?,
                folders: serde_json::from_str::<Vec<String>>(&folders)
                    .ok()?
                    .into_iter()
                    .collect(),
                unparsed: usize::try_from(n(7)?).ok()?,
            })
        };
        Ok(entry().map(|e| (PathBuf::from(std::ffi::OsString::from_vec(path)), e)))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        if let Some((path, entry)) = row? {
            out.insert(path, entry);
        }
    }
    Ok(out)
}

/// Replaces the entries the store keeps with `held`, in the run's transaction, so that a
/// position is committed together with what was derived from the bytes before it.
pub fn keep(tx: &Transaction, held: &BTreeMap<PathBuf, Held>) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM session_file", [])?;
    let mut stmt = tx.prepare(
        "INSERT INTO session_file (path, inode, ctime_ns, settled, position, digest, folders,
                                   unparsed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for (path, h) in held {
        stmt.execute(params![
            path.as_os_str().as_bytes(),
            h.stat.inode as i64,
            h.stat.ctime_ns,
            i64::from(h.settled),
            h.position as i64,
            h.digest,
            // A list of strings always serializes; were it not to, the entry would not read
            // back and the file would be read from its first byte.
            serde_json::to_string(&h.folders).unwrap_or_default(),
            h.unparsed as i64,
        ])?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::time::Duration;

    /// A folder of sessions in a temporary folder, with two project folders. Every line in it
    /// is invented.
    struct Trial {
        root: PathBuf,
    }

    impl Trial {
        fn new(tag: &str) -> Trial {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "immunity-sessions-{tag}-{}-{nanos}",
                std::process::id()
            ));
            for p in ["-invented-a", "-invented-b"] {
                std::fs::create_dir_all(root.join(p)).unwrap();
            }
            // Made real, as the reader lists the folder.
            let root = std::fs::canonicalize(root).unwrap();
            Trial { root }
        }

        fn file(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        /// Reads the folder at `now` as Claude Code's, going on from `held`.
        fn read(&self, held: &BTreeMap<PathBuf, Held>, now: SystemTime) -> Sessions {
            self.read_as(&SOURCES[0], held, now)
        }

        fn read_as(
            &self,
            source: &'static Source,
            held: &BTreeMap<PathBuf, Held>,
            now: SystemTime,
        ) -> Sessions {
            let homes = [Path::new("/nonexistent-home")];
            match sessions(source, &self.root, &homes, held, now, LOOK_LIMIT) {
                Found::Read(s) => s,
                _ => panic!("the folder of sessions was not read"),
            }
        }
    }

    impl Drop for Trial {
        fn drop(&mut self) {
            crate::common::remove(&self.root);
        }
    }

    /// A line of a turn that names a working folder, as Claude Code writes one.
    fn turn(cwd: &str, n: usize) -> String {
        format!(
            "{{\"type\":\"user\",\"cwd\":\"{cwd}\",\"sessionId\":\"00000000-0000-4000-8000-000000000001\",\
             \"message\":{{\"role\":\"user\",\"content\":\"invented request {n}\"}}}}\n"
        )
    }

    /// A line that names no folder.
    fn reply(n: usize) -> String {
        format!("{{\"type\":\"assistant\",\"message\":{{\"content\":\"invented reply {n}\"}}}}\n")
    }

    fn append(path: &Path, text: &str) {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    /// What a reading says, without what it cost or what it keeps.
    fn said(s: &Sessions) -> (usize, usize, usize, usize, BTreeSet<String>) {
        (
            s.files,
            s.unreadable,
            s.unlisted,
            s.unparsed,
            s.folders.clone(),
        )
    }

    fn folders(s: &Sessions) -> Vec<&str> {
        s.folders.iter().map(String::as_str).collect()
    }

    fn later(by: u64) -> SystemTime {
        SystemTime::now() + Duration::from_secs(by)
    }

    /// A small generator of invented sequences, the same on every run.
    struct Dice(u64);

    impl Dice {
        fn roll(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    /// Working folders all of one length, so that one can stand in for another without
    /// changing a file's size.
    const FOLDERS: [&str; 6] = [
        "/invented/w0",
        "/invented/w1",
        "/invented/w2",
        "/invented/w3",
        "/invented/w4",
        "/invented/w5",
    ];

    fn some_lines(dice: &mut Dice, n: &mut usize) -> String {
        let mut text = String::new();
        for _ in 0..=dice.roll(3) {
            *n += 1;
            text.push_str(&match dice.roll(5) {
                0 | 1 => turn(FOLDERS[dice.roll(FOLDERS.len())], *n),
                2 | 3 => reply(*n),
                // Names a working folder and is not JSON.
                _ => format!("{{\"cwd\": not json {n}\n"),
            });
        }
        text
    }

    /// The text with every working folder moved on to the next: as long, and different
    /// wherever it names one.
    fn moved_on(text: &str) -> String {
        let mut out = text.to_string();
        for (i, f) in FOLDERS.iter().enumerate() {
            out = out.replace(f, &format!("/invented/x{i}"));
        }
        for i in 0..FOLDERS.len() {
            out = out.replace(&format!("/invented/x{i}"), FOLDERS[(i + 1) % FOLDERS.len()]);
        }
        out
    }

    /// One change to one session file, of the kinds files go through: grows, gets a line
    /// still being written, is replaced by another of the same size, is rewritten in place
    /// with its modification time put back, is cut short, is deleted, comes back.
    fn change(path: &Path, dice: &mut Dice, n: &mut usize) {
        let text = std::fs::read(path).ok();
        match (dice.roll(11), text) {
            (0..=2, _) => append(path, &some_lines(dice, n)),
            (3, _) => append(
                path,
                [
                    "{\"type\":\"user\",\"cwd\":\"/invented/w4\"",
                    "{\"cwd\":\"/invented/w5\"}",
                    "{\"type\":\"assistant\",\"message\":{\"content\":\"cut off",
                ][dice.roll(3)],
            ),
            (4, _) => append(path, "\n"),
            (5, Some(text)) => {
                let other = path.with_extension("tmp");
                std::fs::write(&other, moved_on(&String::from_utf8_lossy(&text))).unwrap();
                std::fs::rename(&other, path).unwrap();
            }
            (6, Some(text)) => {
                let mtime = std::fs::metadata(path).unwrap().modified().unwrap();
                let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                (&file)
                    .write_all(moved_on(&String::from_utf8_lossy(&text)).as_bytes())
                    .unwrap();
                file.set_modified(mtime).unwrap();
            }
            (7, Some(text)) => {
                let mut longer = moved_on(&String::from_utf8_lossy(&text));
                longer.push_str(&some_lines(dice, n));
                let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                (&file).write_all(longer.as_bytes()).unwrap();
            }
            (8, Some(text)) if !text.is_empty() => {
                let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                file.set_len(dice.roll(text.len()) as u64).unwrap();
            }
            (9, Some(_)) => std::fs::remove_file(path).unwrap(),
            (9, None) => std::fs::write(path, some_lines(dice, n)).unwrap(),
            (10, Some(_)) => {
                let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
                file.set_modified(SystemTime::now()).unwrap();
            }
            _ => {}
        }
    }

    #[test]
    fn reading_on_from_a_position_gives_what_reading_from_the_first_byte_gives() {
        // Whatever a session file goes through, a reading that goes on from where the last
        // one stopped finds the same working folders, unparsed lines and unreadable files as
        // a reading of every byte, and keeps the same entry for the next reading. Both ways
        // of trusting a position are taken: soon after a change, when only the digest can,
        // and later, when an unchanged stat can.
        let t = Trial::new("same");
        let files = [
            "-invented-a/s1.jsonl",
            "-invented-a/s2.jsonl",
            "-invented-b/s3.jsonl",
        ];
        let mut dice = Dice(0x9e37_79b9_7f4a_7c15);
        let mut n = 0;
        let (mut soon, mut settled) = (BTreeMap::new(), BTreeMap::new());
        let mut ways = Cost::default();
        for step in 0..1500 {
            let path = t.file(files[dice.roll(files.len())]);
            change(&path, &mut dice, &mut n);

            let now = SystemTime::now();
            let whole = t.read(&BTreeMap::new(), now);
            let on = t.read(&soon, now);
            assert_eq!(said(&on), said(&whole), "soon after a change, step {step}");
            assert_eq!(on.held, whole.held, "soon after a change, step {step}");
            soon = on.held;

            let now = later(10);
            let whole = t.read(&BTreeMap::new(), now);
            let on = t.read(&settled, now);
            assert_eq!(said(&on), said(&whole), "once settled, step {step}");
            assert_eq!(on.held, whole.held, "once settled, step {step}");
            settled = on.held;
            ways.unchanged += on.cost.unchanged;
            ways.from_position += on.cost.from_position;
            ways.from_start += on.cost.from_start;
        }
        // Each way of reading was taken many times, so the sequence tried each of them.
        assert!(ways.unchanged > 100, "{ways:?}");
        assert!(ways.from_position > 100, "{ways:?}");
        assert!(ways.from_start > 100, "{ways:?}");
    }

    #[test]
    fn a_file_that_only_grew_is_read_from_where_the_last_reading_stopped() {
        // The cost of living: a session that grew is not parsed again from its first byte,
        // and one that did not change is not read before its position at all.
        let t = Trial::new("grew");
        let grows = t.file("-invented-a/s1.jsonl");
        let still = t.file("-invented-b/s2.jsonl");
        std::fs::write(&grows, turn("/invented/w0", 1) + &reply(2)).unwrap();
        std::fs::write(&still, turn("/invented/w1", 1)).unwrap();
        let first = t.read(&BTreeMap::new(), later(10));
        append(&grows, &turn("/invented/w2", 3));

        let next = t.read(&first.held, later(10));

        assert_eq!(
            next.cost,
            Cost {
                unchanged: 1,
                from_position: 1,
                from_start: 0,
                // The grown file's head is hashed again and its new line parsed; nothing of
                // the other file is read.
                bytes: std::fs::metadata(&grows).unwrap().len(),
            }
        );
        assert_eq!(
            folders(&next),
            ["/invented/w0", "/invented/w1", "/invented/w2"]
        );
    }

    /// Reads the sessions once, settled, and returns what the store keeps.
    fn held_once(t: &Trial, path: &Path) -> BTreeMap<PathBuf, Held> {
        let first = t.read(&BTreeMap::new(), later(10));
        assert!(first.held.contains_key(path));
        first.held
    }

    #[test]
    fn a_file_replaced_by_another_of_the_same_size_is_read_from_the_first_byte() {
        let t = Trial::new("replaced");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, turn("/invented/w0", 1)).unwrap();
        let held = held_once(&t, &path);
        let other = t.file("-invented-a/next.tmp");
        std::fs::write(&other, turn("/invented/w1", 1)).unwrap();
        std::fs::rename(&other, &path).unwrap();

        let next = t.read(&held, later(10));

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/w1"]);
    }

    #[test]
    fn a_file_rewritten_in_place_with_its_time_put_back_is_read_from_the_first_byte() {
        // The same file, the same size and the same modification time: only the change time
        // and the content differ, and the content is what is checked.
        let t = Trial::new("rewritten");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, turn("/invented/w0", 1) + &reply(2)).unwrap();
        let held = held_once(&t, &path);
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        (&file)
            .write_all(turn("/invented/w1", 1).as_bytes())
            .unwrap();
        file.set_modified(mtime).unwrap();

        let next = t.read(&held, later(10));

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/w1"]);
    }

    #[test]
    fn a_file_cut_short_is_read_from_the_first_byte() {
        let t = Trial::new("cut");
        let path = t.file("-invented-a/s1.jsonl");
        let first = turn("/invented/w0", 1);
        std::fs::write(&path, first.clone() + &turn("/invented/w1", 2)).unwrap();
        let held = held_once(&t, &path);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(first.len() as u64).unwrap();

        let next = t.read(&held, later(10));

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/w0"]);
    }

    #[test]
    fn an_unchanged_stat_stands_for_the_content_only_once_the_file_had_settled() {
        // A stat taken in the moment of a change may miss a write in that same moment, as
        // git's index can: such an entry is checked by its digest, which here does not match.
        let t = Trial::new("racy");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, turn("/invented/w0", 1)).unwrap();
        let mut held = t.read(&BTreeMap::new(), SystemTime::now()).held;
        let entry = held.get_mut(&path).unwrap();
        assert!(!entry.settled);
        entry.digest = "0".repeat(64);
        entry.folders = BTreeSet::from(["/invented/w5".to_string()]);

        let next = t.read(&held, SystemTime::now());

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/w0"]);

        // A change at the very moment the settling ends has not settled.
        let settled_at = |ctime_ns: i64, settled_before: i64| {
            let then = Then {
                stat: Stat { inode: 1, ctime_ns },
                before: None,
                settled_before,
                change_time_kept: true,
            };
            let (mut whole, mut last) = (Parsed::of(&CLAUDE_CODE), Parsed::of(&CLAUDE_CODE));
            read_from(
                &mut Cursor::new(Vec::new()),
                &then,
                &mut whole,
                &mut last,
                &mut Cost::default(),
            )
            .unwrap()
            .unwrap()
            .settled
        };
        assert!(!settled_at(7, 7));
        assert!(settled_at(6, 7));
    }

    #[test]
    fn on_a_volume_whose_change_time_a_program_can_set_a_rewrite_with_its_times_put_back_is_read_from_the_first_byte()
     {
        // On FAT, exFAT, SMB, NFS or FUSE a program can put the change time back, or it moves
        // in steps of seconds. A test cannot mount such a volume, so its type is given: the
        // same file with the same change time, rewritten in place, is hashed and read whole.
        let stat = Stat {
            inode: 3,
            ctime_ns: 10,
        };
        let read = |text: &str, before: Option<&Held>, change_time_kept: bool| {
            let then = Then {
                stat,
                before,
                settled_before: 1_000,
                change_time_kept,
            };
            let (mut whole, mut last) = (Parsed::of(&CLAUDE_CODE), Parsed::of(&CLAUDE_CODE));
            let mut cost = Cost::default();
            let held = read_from(
                &mut Cursor::new(text.as_bytes().to_vec()),
                &then,
                &mut whole,
                &mut last,
                &mut cost,
            )
            .unwrap()
            .unwrap();
            (held, whole.folders, cost)
        };
        let (before, _, _) = read(&turn("/invented/w0", 1), None, true);
        assert!(before.settled);
        let rewritten = turn("/invented/w1", 1);

        let (_, folders, cost) = read(&rewritten, Some(&before), false);
        assert_eq!(cost.from_start, 1);
        assert_eq!(folders, BTreeSet::from(["/invented/w1".to_string()]));
        // On APFS or HFS+ the same stat is taken as unchanged content.
        let (_, _, cost) = read(&rewritten, Some(&before), true);
        assert_eq!(cost.unchanged, 1);

        for fs_type in ["msdos", "exfat", "smbfs", "nfs", "macfuse", "webdav", ""] {
            assert!(!kept_by(fs_type.as_bytes()), "{fs_type}");
        }
        assert!(kept_by(b"apfs") && kept_by(b"hfs"));
        // The folder of the tests is on the Mac's own APFS volume.
        let t = Trial::new("fs-type");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, "").unwrap();
        assert!(change_time_kept(&File::open(&path).unwrap()));
    }

    #[test]
    fn a_kept_row_that_does_not_read_back_is_dropped_and_its_file_read_from_the_first_byte() {
        // A row written by hand or by another build must not stop every reading: it is left
        // out, and the file it was about has no position.
        let t = Trial::new("bad-row");
        let mut store = crate::store::open_or_make(&t.root.join("store.db")).unwrap();
        let tx = store.transaction().unwrap();
        let entry = Held {
            stat: Stat {
                inode: 1,
                ctime_ns: 2,
            },
            settled: true,
            position: 0,
            digest: crate::sha256::hex(b""),
            folders: BTreeSet::new(),
            unparsed: 0,
        };
        let good = BTreeMap::from([(PathBuf::from("/invented/good.jsonl"), entry)]);
        keep(&tx, &good).unwrap();
        for path in ["'/invented/text.jsonl'", "NULL"] {
            tx.execute(
                &format!(
                    "INSERT INTO session_file VALUES ({path}, 1, 1, 1, 0, '{}', '[]', 0)",
                    crate::sha256::hex(b"")
                ),
                [],
            )
            .unwrap();
        }

        assert_eq!(held(&tx).unwrap(), good);
    }

    #[test]
    fn a_file_replaced_by_another_that_begins_with_the_same_bytes_is_read_from_the_first_byte() {
        // A position belongs to one file. Another file at the path, written whole, is read
        // whole, even when what was read of the first is where it begins.
        let t = Trial::new("same-head");
        let path = t.file("-invented-a/s1.jsonl");
        let head = turn("/invented/w0", 1);
        std::fs::write(&path, &head).unwrap();
        let held = held_once(&t, &path);
        let other = t.file("-invented-a/next.tmp");
        std::fs::write(&other, head + &turn("/invented/w1", 2)).unwrap();
        std::fs::rename(&other, &path).unwrap();

        let next = t.read(&held, later(10));

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/w0", "/invented/w1"]);
    }

    #[test]
    fn a_last_line_still_being_written_is_read_but_the_position_stays_before_it() {
        let t = Trial::new("last-line");
        let path = t.file("-invented-a/s1.jsonl");
        let whole = turn("/invented/w0", 1);
        // Complete as JSON, but its line break is not written yet.
        std::fs::write(&path, whole.clone() + "{\"cwd\":\"/invented/w1\"}").unwrap();

        let first = t.read(&BTreeMap::new(), later(10));

        assert_eq!(folders(&first), ["/invented/w0", "/invented/w1"]);
        let entry = &first.held[&path];
        assert_eq!(entry.position, whole.len() as u64);
        assert_eq!(entry.folders, BTreeSet::from(["/invented/w0".to_string()]));

        // The line is finished as something else: the next reading sees what it became.
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        (&file)
            .write_all(
                (whole.clone() + "{\"cwd\":\"/invented/w2\",\"type\":\"user\"}\n").as_bytes(),
            )
            .unwrap();
        let next = t.read(&first.held, later(10));
        assert_eq!(next.cost.from_position, 1);
        assert_eq!(folders(&next), ["/invented/w0", "/invented/w2"]);

        // Cut off in the middle, it names a working folder and is not JSON yet: counted as
        // unparsed, as a reading from the first byte counts it.
        append(&path, "{\"type\":\"user\",\"cwd\":\"/invented/w3");
        let cut = t.read(&next.held, later(10));
        assert_eq!(cut.unparsed, 1);
        assert_eq!(cut.held[&path].unparsed, 0);
    }

    #[test]
    fn what_the_head_of_a_file_named_still_counts_when_only_its_tail_is_read() {
        // A working folder named once, early in a long session, is not lost because later
        // readings read only what was added.
        let t = Trial::new("head");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, turn("/invented/w0", 1)).unwrap();
        let mut held = t.read(&BTreeMap::new(), later(10)).held;
        for n in 2..6 {
            append(&path, &reply(n));
            let next = t.read(&held, later(10));
            assert_eq!(next.cost.from_position, 1);
            assert_eq!(folders(&next), ["/invented/w0"]);
            held = next.held;
        }
        // The file goes, and so does what it named.
        std::fs::remove_file(&path).unwrap();
        let gone = t.read(&held, later(10));
        assert!(gone.folders.is_empty());
        assert!(gone.held.is_empty());
    }

    /// Bytes that fail to read once `fail_at` is reached.
    struct Failing {
        bytes: Cursor<Vec<u8>>,
        fail_at: u64,
    }

    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let left = self.fail_at.saturating_sub(self.bytes.position());
            if left == 0 {
                return Err(std::io::Error::other("invented failure"));
            }
            let n = buf.len().min(left as usize);
            self.bytes.read(&mut buf[..n])
        }
    }

    impl Seek for Failing {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(to)
        }
    }

    #[test]
    fn a_reading_that_fails_part_way_keeps_no_new_position() {
        // What was read before a failure is not taken as read: the entry before stays, and
        // what it holds still counts.
        let head = turn("/invented/w0", 1);
        let stat = |ctime_ns: i64| Stat { inode: 2, ctime_ns };
        let then = Then {
            stat: stat(4),
            before: None,
            settled_before: 0,
            change_time_kept: true,
        };
        let (mut whole, mut last) = (Parsed::of(&CLAUDE_CODE), Parsed::of(&CLAUDE_CODE));
        let mut cost = Cost::default();
        let before = read_from(
            &mut Cursor::new(head.clone().into_bytes()),
            &then,
            &mut whole,
            &mut last,
            &mut cost,
        )
        .unwrap()
        .unwrap();
        let grown = head.clone() + &turn("/invented/w1", 2) + &turn("/invented/w2", 3);
        let mut failing = Failing {
            // After the head and the first new line.
            fail_at: (head.len() + turn("/invented/w1", 2).len() + 10) as u64,
            bytes: Cursor::new(grown.clone().into_bytes()),
        };
        let then = Then {
            stat: stat(5),
            before: Some(&before),
            settled_before: 0,
            change_time_kept: true,
        };
        let (mut whole, mut last) = (Parsed::of(&CLAUDE_CODE), Parsed::of(&CLAUDE_CODE));
        assert!(read_from(&mut failing, &then, &mut whole, &mut last, &mut cost).is_err());

        // A real file that cannot be opened: its entry and what that holds stay.
        let t = Trial::new("fails");
        let path = t.file("-invented-a/s1.jsonl");
        std::fs::write(&path, &head).unwrap();
        let held = held_once(&t, &path);
        append(&path, &turn("/invented/w1", 2));
        let mode = |m: u32| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m)).unwrap();
        };
        mode(0o000);
        let failed = t.read(&held, later(10));
        mode(0o644);
        assert_eq!(failed.unreadable, 1);
        assert_eq!(failed.held, held);
        assert_eq!(folders(&failed), ["/invented/w0"]);
        // Readable again, it goes on from the position kept.
        let next = t.read(&failed.held, later(10));
        assert_eq!(next.cost.from_position, 1);
        assert_eq!(folders(&next), ["/invented/w0", "/invented/w1"]);
    }

    #[test]
    fn what_the_store_keeps_of_a_session_reads_back_as_it_was_kept() {
        // Otherwise every reading would go back to the first byte, or trust what it should not.
        let t = Trial::new("kept");
        let store = crate::store::open_or_make(&t.root.join("store.db")).unwrap();
        let entry = Held {
            stat: Stat {
                // Past what a signed 64-bit integer holds.
                inode: u64::MAX - 1,
                ctime_ns: 1_794_000_001_123_456_789,
            },
            settled: true,
            position: 250,
            digest: "ab".repeat(32),
            folders: BTreeSet::from(["/invented/w0".to_string(), "/invented/w\"1".to_string()]),
            unparsed: 2,
        };
        let other = Held {
            settled: false,
            ..entry.clone()
        };
        // A path is kept as its bytes, whatever they are.
        let odd = PathBuf::from(std::ffi::OsString::from_vec(
            b"/invented/\xff.jsonl".to_vec(),
        ));
        let kept = BTreeMap::from([(odd, entry), (PathBuf::from("/invented/s.jsonl"), other)]);
        let mut store = store;
        let tx = store.transaction().unwrap();
        keep(&tx, &kept).unwrap();
        // Kept again, it replaces what was kept.
        keep(&tx, &kept).unwrap();
        assert_eq!(held(&tx).unwrap(), kept);
    }

    #[test]
    fn what_the_store_keeps_of_a_session_is_bounded() {
        // Session files may be written by an attacker. Of their text the store keeps the
        // working folders and nothing else, and no more of them than the bounds: a file past
        // them is not kept, and is read from its first byte each time, as before.
        let t = Trial::new("bounds");
        let many = t.file("-invented-a/many.jsonl");
        let long = t.file("-invented-a/long.jsonl");
        let fine = t.file("-invented-b/fine.jsonl");
        let text: String = (0..=HELD_FOLDERS)
            .map(|i| turn(&format!("/invented/m{i}"), i))
            .collect();
        std::fs::write(&many, text).unwrap();
        let too_long = format!("/{}", "l".repeat(HELD_FOLDER_BYTES));
        std::fs::write(&long, turn(&too_long, 1)).unwrap();
        std::fs::write(&fine, turn("/invented/w0", 1)).unwrap();

        let first = t.read(&BTreeMap::new(), later(10));

        assert_eq!(first.held.keys().collect::<Vec<_>>(), [&fine]);
        assert_eq!(first.folders.len(), HELD_FOLDERS + 3);
        let next = t.read(&first.held, later(10));
        assert_eq!(next.cost.from_start, 2);
        assert_eq!(next.folders, first.folders);
    }

    #[test]
    fn a_session_at_the_bounds_is_kept_and_the_bound_over_all_files_holds() {
        // Each of these files names as many folders as are kept, each as long as is kept, so
        // 64 of them come to exactly what the store keeps of all files and the 65th is past it.
        let t = Trial::new("at-bounds");
        for file in 0..65 {
            let text: String = (0..HELD_FOLDERS)
                .map(|i| {
                    let mut folder = format!("/invented/{file:02}-{i:02}-");
                    folder.push_str(&"p".repeat(HELD_FOLDER_BYTES - folder.len()));
                    turn(&folder, i)
                })
                .collect();
            std::fs::write(t.file(&format!("-invented-a/s{file:02}.jsonl")), text).unwrap();
        }

        let read = t.read(&BTreeMap::new(), later(10));

        assert_eq!(read.held.len(), 64);
        assert!(!read.held.contains_key(&t.file("-invented-a/s64.jsonl")));
        assert_eq!(read.folders.len(), 65 * HELD_FOLDERS);
    }

    /// A line of a Codex CLI rollout, as it writes one: `type` and `payload`.
    fn codex(kind: &str, payload: &str) -> String {
        format!(
            "{{\"timestamp\":\"2026-11-19T09:00:00.000Z\",\"type\":\"{kind}\",\"payload\":{payload}}}\n"
        )
    }

    fn codex_meta(cwd: &str) -> String {
        codex(
            "session_meta",
            &format!(
                "{{\"session_id\":\"00000000-0000-4000-8000-000000000002\",\"id\":\"00000000-0000-4000-8000-000000000002\",\
                 \"timestamp\":\"2026-11-19T09:00:00.000Z\",\"cwd\":\"{cwd}\",\"originator\":\"codex_cli_rs\",\
                 \"cli_version\":\"0.200.0\"}}"
            ),
        )
    }

    fn codex_message(n: usize) -> String {
        codex(
            "response_item",
            &format!(
                "{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"invented request {n}\"}}]}}"
            ),
        )
    }

    /// A session of Codex CLI compressed by the reference implementation of zstd, and the
    /// lines it holds (`tests/codex/README.md`).
    const ZST: &[u8] = include_bytes!("../tests/codex/session.jsonl.zst");
    const ZST_LINES: &str = include_str!("../tests/codex/session.jsonl");
    /// Another, with another working folder.
    const LATER_ZST: &[u8] = include_bytes!("../tests/codex/later.jsonl.zst");

    fn zst_folders() -> BTreeSet<String> {
        BTreeSet::from([
            "/Users/example/dev/api".into(),
            "/Users/example/dev/worker".into(),
        ])
    }

    #[test]
    fn a_working_folder_named_only_in_a_codex_session_is_read_compressed_or_not() {
        // Codex CLI keeps its sessions by date, three folders deep, and states the working
        // folder in the payload of its first line and of each turn's context. A session it
        // compressed after a week is read as well.
        let t = Trial::new("codex");
        let day = t.file("2026/11/19");
        std::fs::create_dir_all(&day).unwrap();
        let text = codex_meta("/invented/c0")
            + &codex_message(1)
            + &codex(
                "turn_context",
                "{\"cwd\":\"/invented/c1\",\"approval_policy\":\"on-request\",\"model\":\"invented\"}",
            )
            + &codex(
                "event_msg",
                "{\"type\":\"user_message\",\"message\":\"the cwd is /invented/not-a-folder\"}",
            );
        std::fs::write(day.join("rollout-2026-11-19T09-00-00-a.jsonl"), text).unwrap();
        std::fs::write(day.join("rollout-2026-11-05T09-00-00-b.jsonl.zst"), ZST).unwrap();
        // A folder of a session's name is not a file: a session that could not be read.
        std::fs::create_dir(day.join("rollout-2026-11-07T09-00-00-d.jsonl.zst")).unwrap();
        // Not at the depth sessions are kept at, above it or below it.
        std::fs::write(t.file("2026/stray.jsonl"), codex_meta("/invented/c9")).unwrap();
        std::fs::create_dir(day.join("deeper")).unwrap();
        std::fs::write(day.join("deeper/stray.jsonl"), codex_meta("/invented/c8")).unwrap();

        let read = t.read_as(&SOURCES[1], &BTreeMap::new(), later(10));

        let mut expected = zst_folders();
        expected.extend(["/invented/c0", "/invented/c1"].map(String::from));
        assert_eq!(read.folders, expected);
        assert_eq!((read.files, read.unreadable, read.unparsed), (3, 1, 0));
        // Claude Code's sessions are not Codex's: the same folder read as Claude Code's finds
        // no working folder where Claude Code states one.
        assert!(t.read(&BTreeMap::new(), later(10)).folders.is_empty());
    }

    #[test]
    fn a_codex_session_that_states_no_working_folder_names_none_and_its_line_is_counted() {
        // A first line or a turn's context without the working folder is a shape this
        // version does not know: never dropped in silence.
        let t = Trial::new("codex-none");
        // Archived sessions are kept flat.
        let path = t.file("rollout-2026-11-19T09-00-00-c.jsonl");
        let text = codex("session_meta", "{\"id\":\"00000000-0000-4000-8000-000000000003\"}")
            + &codex("turn_context", "{\"workdir\":\"/invented/c2\"}")
            + &codex_message(1)
            // Claude Code's shape, not Codex's.
            + &turn("/invented/c3", 2);
        std::fs::write(&path, text).unwrap();

        let read = t.read_as(&SOURCES[2], &BTreeMap::new(), later(10));

        assert!(read.folders.is_empty());
        assert_eq!((read.files, read.unparsed), (1, 2));
        assert_eq!(read.held[&path].unparsed, 2);
    }

    /// Reads archived Codex sessions at `now`, going on from `held`.
    fn read_archived(t: &Trial, held: &BTreeMap<PathBuf, Held>, now: SystemTime) -> Sessions {
        t.read_as(&SOURCES[2], held, now)
    }

    /// A zstd frame written by hand to RFC 8878: the magic number, a frame header with no
    /// content size and the window descriptor `window`, and one raw block, marked last.
    fn raw_frame(window: u8, bytes: &[u8]) -> Vec<u8> {
        let header = (bytes.len() as u32) << 3 | 1;
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, window];
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(bytes);
        frame
    }

    #[test]
    fn a_compressed_session_read_once_is_not_decoded_again_while_unchanged_and_is_read_again_when_its_bytes_change()
     {
        let t = Trial::new("zst-once");
        let path = t.file("rollout-2026-11-05T09-00-00-a.jsonl.zst");
        std::fs::write(&path, ZST).unwrap();
        let first = read_archived(&t, &BTreeMap::new(), SystemTime::now());
        assert_eq!(first.cost.from_start, 1);
        assert_eq!(first.folders, zst_folders());
        // It is kept whole: its length, and the digest of its compressed bytes.
        let entry = &first.held[&path];
        assert_eq!(entry.position, ZST.len() as u64);
        assert_eq!(entry.digest, crate::sha256::hex(ZST));
        assert_eq!(entry.folders, zst_folders());

        // Soon after, its digest stands for it: hashed, not decoded.
        let soon = read_archived(&t, &first.held, SystemTime::now());
        let hashed = Cost {
            unchanged: 0,
            from_position: 1,
            from_start: 0,
            bytes: ZST.len() as u64,
        };
        assert_eq!(soon.cost, hashed);
        assert_eq!(soon.folders, zst_folders());
        // Once it has settled, its stat does: nothing of it is read.
        let settled = read_archived(&t, &soon.held, later(10));
        let settled = read_archived(&t, &settled.held, later(10));
        assert_eq!(
            settled.cost,
            Cost {
                unchanged: 1,
                ..Cost::default()
            }
        );
        assert_eq!(settled.folders, zst_folders());

        // Bytes after the frame: decoded again, and not one frame.
        append(&path, "{\"cwd\":\"/invented/z9\"}\n");
        let grown = read_archived(&t, &settled.held, later(10));
        assert_eq!((grown.cost.from_start, grown.unreadable), (1, 1));
        // Rewritten with another session: decoded again.
        std::fs::write(&path, LATER_ZST).unwrap();
        let other = read_archived(&t, &grown.held, later(10));
        assert_eq!((other.cost.from_start, other.unreadable), (1, 0));
        assert_eq!(folders(&other), ["/Users/example/dev/web"]);
    }

    #[test]
    fn a_compressed_session_rewritten_in_place_to_the_same_length_is_decoded_again() {
        // The same file and the same length: only its bytes say it changed.
        let t = Trial::new("zst-same-length");
        let path = t.file("rollout-2026-11-05T09-00-00-a.jsonl.zst");
        std::fs::write(&path, ZST).unwrap();
        let first = read_archived(&t, &BTreeMap::new(), later(10));
        let meta = codex_meta("/invented/z1");
        let pad = ZST.len() - 9 - meta.len() - 1;
        let other = raw_frame(0x38, format!("{meta}{}\n", " ".repeat(pad)).as_bytes());
        assert_eq!(other.len(), ZST.len());
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        (&file).write_all(&other).unwrap();

        let next = read_archived(&t, &first.held, later(10));

        assert_eq!(next.cost.from_start, 1);
        assert_eq!(folders(&next), ["/invented/z1"]);
    }

    #[test]
    fn a_plain_codex_session_replaced_by_its_compressed_copy_keeps_its_folders() {
        let t = Trial::new("zst-replaced");
        let plain = t.file("rollout-2026-11-05T09-00-00-a.jsonl");
        std::fs::write(&plain, ZST_LINES).unwrap();
        let first = read_archived(&t, &BTreeMap::new(), later(10));
        assert_eq!(first.folders, zst_folders());
        let copy = t.file("rollout-2026-11-05T09-00-00-a.jsonl.zst");
        std::fs::write(&copy, ZST).unwrap();
        std::fs::remove_file(&plain).unwrap();

        let next = read_archived(&t, &first.held, later(10));

        assert_eq!(next.folders, first.folders);
        assert_eq!((next.files, next.unreadable, next.unparsed), (1, 0, 0));
        assert_eq!(next.held.keys().collect::<Vec<_>>(), [&copy]);
    }

    #[test]
    fn a_compressed_session_that_is_not_one_whole_zstd_frame_is_told_as_not_read_and_gives_no_folder()
     {
        // Never dropped in silence and never taken as read: each is a session file that could
        // not be read, and nothing of it counts. A whole first frame followed by another gives
        // none of its folders either.
        let t = Trial::new("zst-damaged");
        let cut = |n: usize| ZST[..ZST.len() - n].to_vec();
        let meta = codex_meta("/invented/z2");
        let damaged = [
            ("not-zstd", ZST_LINES.as_bytes().to_vec()),
            ("empty", Vec::new()),
            ("cut-in-half", ZST[..ZST.len() / 2].to_vec()),
            ("cut-in-its-checksum", cut(2)),
            ("two-frames", [ZST, LATER_ZST].concat()),
            // A window of 144 MiB, past what the decoder may keep.
            ("window-too-large", raw_frame(0x89, meta.as_bytes())),
        ];
        for (name, bytes) in &damaged {
            std::fs::write(t.file(&format!("{name}.jsonl.zst")), bytes).unwrap();
        }

        let read = read_archived(&t, &BTreeMap::new(), later(10));

        assert_eq!((read.files, read.unreadable), (6, 6));
        assert!(read.folders.is_empty(), "{:?}", read.folders);
        assert!(read.held.is_empty());
        // A window of 128 MiB is within it.
        let path = t.file("window-at-the-bound.jsonl.zst");
        std::fs::write(&path, raw_frame(0x88, meta.as_bytes())).unwrap();
        let read = read_archived(&t, &BTreeMap::new(), later(10));
        assert_eq!(read.unreadable, 6);
        assert_eq!(folders(&read), ["/invented/z2"]);
    }

    /// Reads `bytes` as a compressed session that may decode to `most`: what it gave, and what
    /// it cost.
    fn decoded(bytes: &[u8], most: u64) -> (std::io::Result<Option<Held>>, Parsed, Cost) {
        decoded_within(bytes, bytes.len() as u64, most)
    }

    /// The same, of a file that was `len` bytes long when it was opened.
    fn decoded_within(
        bytes: &[u8],
        len: u64,
        most: u64,
    ) -> (std::io::Result<Option<Held>>, Parsed, Cost) {
        let then = Then {
            stat: Stat {
                inode: 1,
                ctime_ns: 1,
            },
            before: None,
            settled_before: 0,
            change_time_kept: true,
        };
        let mut whole = Parsed::of(&CODEX);
        let mut cost = Cost::default();
        let read = read_compressed(
            &mut Cursor::new(bytes.to_vec()),
            &then,
            len,
            most,
            &mut whole,
            &mut cost,
        );
        (read, whole, cost)
    }

    #[test]
    fn a_compressed_session_is_read_no_further_than_its_length_when_it_was_opened() {
        // What it grew by while it was decoded is not taken in: it is read up to where it
        // ended, and told as not read when its frame does not end there.
        let grown = [ZST, LATER_ZST].concat();
        let (read, whole, _) = decoded_within(&grown, ZST.len() as u64, DECODED_BYTES);
        assert_eq!(read.unwrap().unwrap().position, ZST.len() as u64);
        assert_eq!(whole.folders, zst_folders());
        let (read, whole, _) = decoded_within(ZST, ZST.len() as u64 - 1, DECODED_BYTES);
        assert!(read.is_err());
        assert!(whole.folders.is_empty());
    }

    #[test]
    fn a_compressed_session_that_decodes_to_more_than_the_bound_is_not_read_nor_decoded_past_it() {
        // A small file may decode to far more than it holds. The bound is given small here, so
        // that the file of the tests goes past it.
        let size = ZST_LINES.len() as u64;
        let (read, whole, cost) = decoded(ZST, size);
        assert!(read.unwrap().is_some());
        assert_eq!(whole.folders, zst_folders());
        assert_eq!(cost.bytes, ZST.len() as u64 + size);

        let (read, whole, _) = decoded(ZST, size - 1);
        assert!(read.is_err());
        assert!(whole.folders.is_empty());
        let (read, _, cost) = decoded(ZST, 100);
        assert!(read.is_err());
        assert_eq!(cost.bytes, 101);
    }

    /// A line longer than `LINE_BYTES` that names a working folder past what is held of it.
    fn long_line() -> String {
        format!(
            "{{\"text\":\"{}\",\"type\":\"user\",\"cwd\":\"/invented/w9\"}}\n",
            "a".repeat(LINE_BYTES as usize)
        )
    }

    #[test]
    fn a_line_longer_than_the_bound_is_counted_and_the_lines_after_it_are_read_plain_or_compressed()
    {
        // What is held of one line is bounded, for both kinds of file; the rest of it is
        // passed over, the line is counted as unparsed, and the session goes on.
        let t = Trial::new("long-line");
        let path = t.file("-invented-a/s1.jsonl");
        let text = turn("/invented/w0", 1) + &long_line() + &turn("/invented/w1", 2);
        std::fs::write(&path, &text).unwrap();
        let read = t.read(&BTreeMap::new(), later(10));
        assert_eq!(folders(&read), ["/invented/w0", "/invented/w1"]);
        assert_eq!((read.unreadable, read.unparsed), (0, 1));
        // Every byte of it is read past and hashed: the position is after it.
        let entry = &read.held[&path];
        assert_eq!(entry.position, text.len() as u64);
        assert_eq!(entry.digest, crate::sha256::hex(text.as_bytes()));
        // Cut off in the middle, it is the last line and the position stays before it.
        let head = turn("/invented/w0", 1);
        std::fs::write(
            &path,
            head.clone() + &long_line()[..LINE_BYTES as usize + 10],
        )
        .unwrap();
        let read = t.read(&BTreeMap::new(), later(10));
        assert_eq!(read.held[&path].position, head.len() as u64);
        assert_eq!(read.unparsed, 1);

        let t = Trial::new("long-line-zst");
        std::fs::write(
            t.file("rollout-a.jsonl.zst"),
            include_bytes!("../tests/codex/long-line.jsonl.zst"),
        )
        .unwrap();
        let read = read_archived(&t, &BTreeMap::new(), later(10));
        assert_eq!(
            folders(&read),
            ["/Users/example/dev/api", "/Users/example/dev/web"]
        );
        assert_eq!((read.unreadable, read.unparsed), (0, 1));
    }

    /// Bytes that arrive in parts: an empty part is an end of what there is to read for now.
    struct Arriving(std::collections::VecDeque<Cursor<Vec<u8>>>);

    impl Read for Arriving {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(part) = self.0.front_mut() else {
                return Ok(0);
            };
            let n = part.read(buf)?;
            // An empty part is given once, as an end.
            if part.position() == part.get_ref().len() as u64 {
                self.0.pop_front();
            }
            Ok(n)
        }
    }

    /// What `read_line` makes of the first line of `parts`: whether it ended with its line
    /// break, whether it was long, and what was held of it.
    fn first_line(parts: Vec<Vec<u8>>) -> (bool, bool, usize) {
        let mut reader = BufReader::new(Arriving(parts.into_iter().map(Cursor::new).collect()));
        let mut line = Vec::new();
        let read = read_line(&mut reader, &mut line, &mut Cost::default(), |_| {})
            .unwrap()
            .unwrap();
        (read.ends, read.long, line.len())
    }

    #[test]
    fn whether_a_line_is_over_the_bound_is_told_by_the_bytes_of_the_line_taken_and_nothing_after_it()
     {
        let n = LINE_BYTES as usize;
        // Its line break included, a line of the bound is within it, and one byte more is not.
        let at = [vec![b'a'; n - 1], b"\n".to_vec()].concat();
        assert_eq!(first_line(vec![at]), (true, false, n));
        let over = [vec![b'a'; n], b"\n".to_vec()].concat();
        assert_eq!(first_line(vec![over]), (true, true, n));
        // Ended by the end of what there is, at the bound and past it.
        assert_eq!(first_line(vec![vec![b'a'; n]]), (false, false, n));
        assert_eq!(first_line(vec![vec![b'a'; n + 1]]), (false, true, n));
        // A short line whose line break arrives after the end was met: a last line, read
        // again next time, never a long one.
        let short = b"{\"cwd\":\"/invented/w0\"}".to_vec();
        let parts = vec![short.clone(), Vec::new(), b"\n".to_vec()];
        assert_eq!(first_line(parts), (false, false, short.len()));
    }

    #[test]
    fn a_session_that_names_more_folder_text_than_one_file_may_is_not_read() {
        // Each folder as long as a row keeps one: as many as the bound holds are read, and one
        // more is past it.
        let folder = |i: usize| {
            let mut f = format!("/invented/{i:03}-");
            f.push_str(&"p".repeat(HELD_FOLDER_BYTES - f.len()));
            f
        };
        let count = FILE_FOLDER_BYTES / HELD_FOLDER_BYTES;
        let t = Trial::new("folder-text");
        let path = t.file("-invented-a/s1.jsonl");
        let text: String = (0..count).map(|i| turn(&folder(i), i)).collect();
        std::fs::write(&path, &text).unwrap();
        let read = t.read(&BTreeMap::new(), later(10));
        assert_eq!((read.unreadable, read.folders.len()), (0, count));

        append(&path, &turn(&folder(count), count));
        let read = t.read(&BTreeMap::new(), later(10));
        assert_eq!(read.unreadable, 1);
        assert_eq!(read.folders.len(), count);

        // Read on from a kept row, what the row holds counts toward it as well.
        let text: String = (0..HELD_FOLDERS).map(|i| turn(&folder(i), i)).collect();
        std::fs::write(&path, &text).unwrap();
        let first = t.read(&BTreeMap::new(), later(10));
        assert!(first.held.contains_key(&path));
        let more: String = (HELD_FOLDERS..=count)
            .map(|i| turn(&folder(i), i))
            .collect();
        append(&path, &more);
        let next = t.read(&first.held, later(10));
        assert_eq!((next.cost.from_position, next.unreadable), (1, 1));
    }

    #[test]
    fn a_session_file_that_is_a_link_plain_or_compressed_is_told_as_not_read_and_not_followed() {
        let t = Trial::new("link");
        let target = t.file("elsewhere.jsonl");
        std::fs::write(&target, turn("/invented/w0", 1)).unwrap();
        std::os::unix::fs::symlink(&target, t.file("-invented-a/s1.jsonl")).unwrap();
        let read = t.read(&BTreeMap::new(), later(10));
        assert_eq!((read.files, read.unreadable), (1, 1));
        assert!(read.folders.is_empty());
        assert!(read.held.is_empty());

        let t = Trial::new("link-zst");
        std::fs::write(t.file("-invented-a/elsewhere"), ZST).unwrap();
        std::os::unix::fs::symlink(t.file("-invented-a/elsewhere"), t.file("rollout.jsonl.zst"))
            .unwrap();
        let read = read_archived(&t, &BTreeMap::new(), later(10));
        assert_eq!((read.files, read.unreadable), (1, 1));
        assert!(read.folders.is_empty());
    }

    #[test]
    fn a_named_pipe_in_place_of_a_session_does_not_hold_the_reading() {
        let t = Trial::new("pipe");
        let pipe = t.file("-invented-a/s1.jsonl");
        let name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).unwrap();
        // SAFETY: the name is a valid C string that lives for the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        std::fs::write(t.file("-invented-b/s2.jsonl"), turn("/invented/w0", 1)).unwrap();
        let root = t.root.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let homes = [Path::new("/nonexistent-home")];
            let read = match sessions(
                &SOURCES[0],
                &root,
                &homes,
                &BTreeMap::new(),
                later(10),
                LOOK_LIMIT,
            ) {
                Found::Read(s) => (s.files, s.unreadable, s.folders),
                _ => panic!("the folder of sessions was not read"),
            };
            tx.send(read).unwrap();
        });

        let read = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the reading waited on the pipe");

        assert_eq!(read, (2, 1, BTreeSet::from(["/invented/w0".to_string()])));
    }

    /// Writes `text` at `rel` under the trial's folder, making the folders on the way.
    fn deep(t: &Trial, rel: &str, text: &str) -> PathBuf {
        let path = t.file(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn a_subagents_session_below_a_projects_folder_gives_its_working_folder_at_any_depth() {
        // Claude Code keeps a subagent's session in the folder of the session that started it,
        // and a workflow's two folders deeper. Their working folder may be stated nowhere else.
        let t = Trial::new("subagents");
        deep(&t, "-invented-a/s1.jsonl", &turn("/invented/w0", 1));
        deep(
            &t,
            "-invented-a/s1/subagents/agent-x.jsonl",
            &turn("/invented/w1", 1),
        );
        let workflow = "-invented-a/s1/subagents/workflows/wf1";
        deep(
            &t,
            &format!("{workflow}/agent-y.jsonl"),
            &turn("/invented/w2", 1),
        );
        // A file of the same ending that states no working folder adds nothing.
        deep(
            &t,
            &format!("{workflow}/journal.jsonl"),
            "{\"type\":\"step\",\"step\":\"invented step\"}\n",
        );
        // Files of other endings beside them are not sessions.
        deep(
            &t,
            "-invented-a/s1/tool-results/r1.txt",
            &turn("/invented/w8", 1),
        );
        deep(
            &t,
            "-invented-a/s1/tool-results/r2.json",
            &turn("/invented/w9", 1),
        );
        // A folder down there that cannot be listed is counted.
        let locked = t.file("-invented-b/s2");
        std::fs::create_dir(&locked).unwrap();
        let mode = |m: u32| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(m)).unwrap();
        };

        mode(0o000);
        let read = t.read(&BTreeMap::new(), later(10));
        mode(0o755);

        assert_eq!(
            folders(&read),
            ["/invented/w0", "/invented/w1", "/invented/w2"]
        );
        assert_eq!(
            (read.files, read.unreadable, read.unparsed, read.unlisted),
            (4, 0, 0, 1)
        );
        assert!(!read.stopped);
    }

    #[test]
    fn a_second_reading_opens_no_deeper_file_that_did_not_change_and_reads_one_that_grew_from_where_it_stopped()
     {
        let t = Trial::new("subagents-grew");
        let grows = deep(
            &t,
            "-invented-a/s1/subagents/agent-x.jsonl",
            &(turn("/invented/w0", 1) + &reply(2)),
        );
        deep(
            &t,
            "-invented-b/s2/subagents/workflows/wf1/agent-y.jsonl",
            &turn("/invented/w1", 1),
        );
        let first = t.read(&BTreeMap::new(), later(10));
        append(&grows, &turn("/invented/w2", 3));

        let next = t.read(&first.held, later(10));

        assert_eq!(
            next.cost,
            Cost {
                unchanged: 1,
                from_position: 1,
                from_start: 0,
                bytes: std::fs::metadata(&grows).unwrap().len(),
            }
        );
        assert_eq!(
            folders(&next),
            ["/invented/w0", "/invented/w1", "/invented/w2"]
        );
    }

    #[test]
    fn a_link_below_a_projects_folder_is_not_followed_whether_to_a_folder_or_to_a_session() {
        let t = Trial::new("subagents-link");
        let real = deep(
            &t,
            "-invented-b/s2/subagents/agent-x.jsonl",
            &turn("/invented/w0", 1),
        );
        std::fs::create_dir(t.file("-invented-a/s1")).unwrap();
        // A link to a folder of sessions is not entered: its session is read once, by its own
        // path.
        let folder = real.parent().unwrap();
        std::os::unix::fs::symlink(folder, t.file("-invented-a/s1/subagents")).unwrap();
        // A link in place of a session is a session file that could not be read.
        std::os::unix::fs::symlink(&real, t.file("-invented-b/s2/agent-l.jsonl")).unwrap();

        let read = t.read(&BTreeMap::new(), later(10));

        assert_eq!((read.files, read.unreadable), (2, 1));
        assert_eq!(read.held.keys().collect::<Vec<_>>(), [&real]);
        assert_eq!(folders(&read), ["/invented/w0"]);
    }

    #[test]
    fn the_walk_below_the_level_of_the_sessions_stops_at_its_budget_and_says_so() {
        // Three folders below the projects' folders: `s1`, `s1/subagents` and `s2`.
        let t = Trial::new("subagents-budget");
        deep(
            &t,
            "-invented-a/s1/subagents/agent-x.jsonl",
            &turn("/invented/w0", 1),
        );
        deep(&t, "-invented-b/s2/agent-y.jsonl", &turn("/invented/w1", 1));
        let homes = [Path::new("/nonexistent-home")];
        let read = |budget: usize| match sessions(
            &SOURCES[0],
            &t.root,
            &homes,
            &BTreeMap::new(),
            later(10),
            budget,
        ) {
            Found::Read(s) => s,
            _ => panic!("the folder of sessions was not read"),
        };

        let within = read(3);
        assert!(!within.stopped);
        assert_eq!(folders(&within), ["/invented/w0", "/invented/w1"]);

        let past = read(2);
        assert!(past.stopped);
        assert!(past.files < 2, "{}", past.files);
    }

    #[test]
    fn what_each_agents_sessions_gave_is_told_together_within_the_bound_over_all_files() {
        // A file or a line one agent's sessions could not give is not lost because another's
        // were read too, and the store keeps no more of all of them than of one.
        let entry = |file: usize| Held {
            stat: Stat {
                inode: file as u64,
                ctime_ns: 1,
            },
            settled: true,
            position: 0,
            digest: String::new(),
            folders: (0..HELD_FOLDERS)
                .map(|i| format!("/{file:03}-{i:02}-{}", "p".repeat(HELD_FOLDER_BYTES - 8)))
                .collect(),
            unparsed: 0,
        };
        let one = |n: usize, files: std::ops::Range<usize>| Sessions {
            files: n,
            unreadable: n,
            unlisted: n,
            // Only the second walk stopped.
            stopped: n == 2,
            unparsed: n,
            folders: BTreeSet::from([format!("/invented/{n}")]),
            guarded: BTreeSet::from([PathBuf::from(format!("/invented/g{n}"))]),
            held: files
                .map(|f| (PathBuf::from(format!("/invented/{f:03}.jsonl")), entry(f)))
                .collect(),
            ..Sessions::default()
        };
        let mut all = one(1, 0..40);
        all.add(one(2, 40..80));
        // A walk that did not stop, added after one that did, leaves it said.
        all.add(Sessions::default());

        assert_eq!(
            said(&all),
            (
                3,
                3,
                3,
                3,
                BTreeSet::from(["/invented/1".into(), "/invented/2".into()])
            )
        );
        assert_eq!(all.guarded.len(), 2);
        assert!(all.stopped);
        assert_eq!(all.held.len(), 64);
    }

    #[test]
    fn another_agents_session_store_is_named_without_reading_inside_it() {
        // Present is all that is learned of it: a store that cannot be listed is named all
        // the same, and one reached through a folder macOS asks permission for is not looked
        // for.
        let t = Trial::new("unread");
        let home = t.file("home");
        let homes = [home.as_path()];
        std::fs::create_dir_all(&home).unwrap();
        assert!(unread_here(&home, &homes).is_empty());

        let store = home.join(".gemini/tmp");
        std::fs::create_dir_all(store.join("invented-hash/chats")).unwrap();
        let mode = |m: u32| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(m)).unwrap();
        };
        mode(0o000);
        let named = unread_here(&home, &homes);
        mode(0o755);
        assert_eq!(named, ["Gemini CLI"]);

        std::fs::create_dir_all(home.join("Documents/kept/sessions")).unwrap();
        std::os::unix::fs::symlink(home.join("Documents/kept"), home.join(".continue")).unwrap();
        assert_eq!(unread_here(&home, &homes), ["Gemini CLI"]);
    }
}
