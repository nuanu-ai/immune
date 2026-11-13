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
//!
//! A session file only grows while its agent works, so a reading goes on from where the last
//! one stopped. For each file the store keeps, in `session_file`, the end of the last whole
//! line read (the position), the SHA-256 of every byte before it, the working folders and the
//! count of unparsed lines those bytes hold, and the file's inode and change time at that
//! reading. The folders kept stand for the bytes before the position, so a reading of the
//! rest gives what a reading from the first byte gives. A position is trusted only when the
//! bytes before it are shown to be the bytes read: the file has the same inode, and either
//! its change time is unchanged or the bytes before the position hash to the digest kept.
//! The kernel sets the change time on every write, every change of size and every change of
//! the modification time, and no program can set it (setattrlist(2)). A change time taken
//! less than a second after the file last changed never stands for its content, as git does
//! not trust an index entry that is "racily clean". Anything else is read from the first
//! byte. A last line without its line break is read, as a reading from the first byte reads
//! it, but the position stays before it.

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
/// Where Claude Code keeps its sessions, inside the home folder.
pub const SESSIONS: &str = ".claude/projects";
/// The note of a full reading when there are no sessions to read.
pub const NOT_HERE: &str = "no Claude Code sessions on this machine";

/// Created on every open of the store: a store made before it starts with no positions, so
/// its first reading is from the first byte of every file.
pub const SCHEMA: &str = "
-- Where each agent session file was read up to, see agent_folders.rs. Every byte before
-- `position` is whole lines already read; `digest` is the SHA-256 of those bytes; `folders`
-- are the working folders they name, as a JSON array, and `unparsed` their lines with a
-- working folder that are not JSON. The inode and change time are the file's at that
-- reading; `settled` is 0 when the file had changed too shortly before for an unchanged
-- change time to stand for it.
CREATE TABLE IF NOT EXISTS session_file (
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
    /// Bytes read from session files, to hash and to parse.
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

/// Reads the working folders from every session file under `dir`, each from where `held`
/// says the last reading stopped when that can be trusted, at `now`. The folder, and a
/// session file, may be a link: it is not followed into a folder macOS asks permission for.
/// `homes` are the home folder's names.
pub fn sessions(
    dir: &Path,
    homes: &[&Path],
    held: &BTreeMap<PathBuf, Held>,
    now: SystemTime,
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
    let projects = match std::fs::read_dir(listed) {
        Ok(entries) => entries,
        Err(e) => return Found::Failed(format!("{}: {e}", dir.display())),
    };
    // A file whose change time is before this had not changed for a while.
    let settled_before = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .saturating_sub(SETTLE_NS);
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
            read_session(&path, held.get(&path), settled_before, &mut out);
        }
    }
    within_bounds(&mut out.held);
    Found::Read(out)
}

/// The working folders and unparsed lines of some lines of a session.
#[derive(Default)]
struct Parsed {
    folders: BTreeSet<String>,
    unparsed: usize,
}

impl Parsed {
    fn take(&mut self, line: &[u8]) {
        // Most of the volume is text that never names a folder: skip it unparsed.
        if !contains(line, b"\"cwd\"") {
            return;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            self.unparsed += 1;
            return;
        };
        if let Some(cwd) = value.get("cwd").and_then(|v| v.as_str()) {
            self.folders.insert(cwd.to_string());
        }
    }
}

/// Reads one session file into `out`. A file that cannot be read keeps its entry, and what
/// that entry holds still counts: what was established is not dropped because a reading
/// failed, and the reading is partial.
fn read_session(path: &Path, before: Option<&Held>, settled_before: i64, out: &mut Sessions) {
    let (mut whole, mut last) = (Parsed::default(), Parsed::default());
    let read = File::open(path).and_then(|mut file| {
        let then = Then {
            stat: Stat::of(&file.metadata()?),
            before,
            settled_before,
        };
        read_from(&mut file, &then, &mut whole, &mut last, &mut out.cost)
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
}

/// Reads a session from where it can be trusted that the last reading stopped. The whole
/// lines before the new position go to `whole`, together with what the entry before holds
/// of the bytes not read again; a last line without its line break goes to `last`. Returns
/// the entry to keep, or `None` when it would hold more than the store keeps.
fn read_from<R: Read + Seek>(
    file: &mut R,
    then: &Then,
    whole: &mut Parsed,
    last: &mut Parsed,
    cost: &mut Cost,
) -> std::io::Result<Option<Held>> {
    let stat = then.stat;
    // Another file at the path is read from its first byte, even one that begins with the
    // same bytes.
    let same_file = then.before.filter(|b| b.stat.inode == stat.inode);
    if let Some(b) = same_file.filter(|b| b.settled && b.stat == stat) {
        // Not written to since: only what follows the position, a line still being written.
        cost.unchanged += 1;
        whole.folders.clone_from(&b.folders);
        whole.unparsed = b.unparsed;
        file.seek(SeekFrom::Start(b.position))?;
        let mut reader = BufReader::with_capacity(1 << 20, file);
        let mut line = Vec::new();
        while read_line(&mut reader, &mut line, cost)? {
            last.take(&line);
        }
        return Ok(Some(b.clone()));
    }
    let mut hasher = Hasher::new();
    let mut position = 0;
    match same_file {
        Some(b) if head_is(file, b, &mut hasher, cost)? => {
            cost.from_position += 1;
            whole.folders.clone_from(&b.folders);
            whole.unparsed = b.unparsed;
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
    while read_line(&mut reader, &mut line, cost)? {
        if line.last() == Some(&b'\n') {
            hasher.update(&line);
            position += line.len() as u64;
            whole.take(&line);
        } else {
            // The last line, still being written: read now, and again next time.
            last.take(&line);
        }
    }
    let held = Held {
        stat,
        settled: stat.ctime_ns < then.settled_before,
        position,
        digest: hasher.hex(),
        folders: whole.folders.clone(),
        unparsed: whole.unparsed,
    };
    let fits = held.folders.len() <= HELD_FOLDERS
        && held.folders.iter().all(|f| f.len() <= HELD_FOLDER_BYTES);
    Ok(fits.then_some(held))
}

/// Reads the next line into `line`, its line break included; `false` at the end.
fn read_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    cost: &mut Cost,
) -> std::io::Result<bool> {
    line.clear();
    let n = reader.read_until(b'\n', line)?;
    cost.bytes += n as u64;
    Ok(n > 0)
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
    cost.bytes += std::io::copy(&mut file.take(b.position), &mut Hashing(hasher))?;
    Ok(hasher.clone().hex() == b.digest)
}

/// Hashes what is written to it.
struct Hashing<'a>(&'a mut Hasher);

impl std::io::Write for Hashing<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
        let path: Vec<u8> = r.get(0)?;
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
                "immune-sessions-{tag}-{}-{nanos}",
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

        /// Reads the folder at `now`, going on from `held`.
        fn read(&self, held: &BTreeMap<PathBuf, Held>, now: SystemTime) -> Sessions {
            match sessions(&self.root, &[Path::new("/nonexistent-home")], held, now) {
                Found::Read(s) => s,
                _ => panic!("the folder of sessions was not read"),
            }
        }
    }

    impl Drop for Trial {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
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
            };
            let (mut whole, mut last) = (Parsed::default(), Parsed::default());
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
        };
        let (mut whole, mut last) = (Parsed::default(), Parsed::default());
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
        };
        let (mut whole, mut last) = (Parsed::default(), Parsed::default());
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
        let store = crate::store::open(&t.root.join("store.db")).unwrap();
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
}
