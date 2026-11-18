//! The `checkouts` reader: which local checkouts exist on this machine. It walks the home
//! folder, or the one folder it is given, and only lists folders: it opens no file. A walk
//! of a given folder is partial, since it did not look at the rest of the home folder.
//!
//! A checkout is a folder that holds `.git`. A checkout is not searched for further
//! checkouts. Paths are relative to the home folder, so the same checkout has the same id
//! whoever runs it and wherever the walk starts.

use crate::agent_folders::still_there;
use crate::guarded;
use std::path::{Path, PathBuf};

pub const READER: &str = "checkouts";
pub const KIND: &str = "checkouts under the home folder";
pub const BASIS: &str = "observed";
/// The entity type of a checkout, which the questions call a project.
pub const TYPE: &str = "checkout";
/// Why a walk of a folder given instead of the home folder is partial.
pub const ONLY_GIVEN: &str = "only the given folder was walked";
/// What is said of a checkout the store holds that is still there in another form.
pub const MOVED: &str = "is no longer a folder there, as when a link to a folder elsewhere took its place: it was not looked into, and what was known of it is kept";

/// The checkouts the store holds on `machine`, by their paths as ids name them, that are still
/// there in another form, as looking again from where the walk started finds (`look`). One
/// outside the walk's root is not looked at. A checkout a reader found is a folder, so it is
/// never among them.
pub fn moved(
    conn: &rusqlite::Connection,
    machine: &str,
    start: &Start,
) -> rusqlite::Result<Vec<String>> {
    let prefix = format!("checkout:{machine}/");
    Ok(crate::store::live_subjects(conn, READER)?
        .into_iter()
        .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
        .filter(|rel| {
            let path = start.home.join(rel);
            path.strip_prefix(&start.root).is_ok_and(|under| {
                matches!(look(&start.root, under, &start.home), Some(Again::Kept))
            })
        })
        .collect())
}

/// Where a walk starts, and the home folder as it meets it there.
pub struct Start {
    pub root: PathBuf,
    /// The home folder as written when the walk starts in it, and made real otherwise: ids
    /// are named relative to it.
    pub home: PathBuf,
    /// The home folder made real, as the disk spells it.
    pub real_home: PathBuf,
}

/// Where a walk of the folder `given`, or of the home folder, starts. A folder given is made
/// real, so that no id names a checkout through a link, `..` or the working folder: the
/// person gave it, so following it is asked for. One that cannot be made real stays as given,
/// and the walk says it is not a folder.
pub fn start(given: Option<&Path>, home: &Path) -> Start {
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let root = given.map_or_else(
        || home.to_path_buf(),
        |g| std::fs::canonicalize(g).unwrap_or_else(|_| g.to_path_buf()),
    );
    let home = match root.starts_with(home) {
        true => home.to_path_buf(),
        false => real_home.clone(),
    };
    Start {
        root,
        home,
        real_home,
    }
}

/// How a checkout the store holds, at `under` below the walk's `root`, is looked at again:
/// as the walk goes, down real folders from `root`, taken as given, following no link and
/// looking up nothing past one. First, as written, it may be in a folder macOS asks
/// permission for under `home` that the walk was not given. Then, one part at a time, it is
/// gone where a part is missing or a part above it is no longer a folder, a link included,
/// since that path is no longer there; something other than a folder at its own place is it
/// in another form, kept. `None` when every part is a folder.
fn look(root: &Path, under: &Path, home: &Path) -> Option<Again> {
    if let Some(g) = guarded::folder_of(&root.join(under), home)
        && !root.starts_with(&g)
    {
        return Some(Again::Guarded(g));
    }
    let mut at = root.to_path_buf();
    let mut parts = under.components().peekable();
    while let Some(part) = parts.next() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(_) if parts.peek().is_none() => return Some(Again::Kept),
            Ok(_) => return Some(Again::Gone),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Again::Gone),
            Err(_) => return Some(Again::NotTold),
        }
    }
    None
}

const MAX_DEPTH: usize = 5;

/// Where projects are looked for, in a person's words made from the walk's own depth, so the
/// words cannot drift from the code.
pub fn walked() -> String {
    format!(
        "They are looked for in your home folder, up to {MAX_DEPTH} folders down, and in the folders your coding agents worked in."
    )
}
/// Folders that are never descended into, wherever they are: tools keep copies of other
/// people's code there, not checkouts.
const PRUNED: [&str; 3] = ["node_modules", "target", "vendor"];
/// Folders macOS makes in the home folder that hold media, applications or settings.
/// Pruned only directly under the home folder: elsewhere they are ordinary names.
const PRUNED_IN_HOME: [&str; 6] = [
    LIBRARY,
    "Applications",
    "Movies",
    "Music",
    "Pictures",
    "Public",
];
/// The home folder's Library, where iCloud Drive and other cloud storage keep their files.
const LIBRARY: &str = "Library";

pub struct Checkout {
    /// Path relative to the home folder, with `/` between parts; the full path when the
    /// checkout is outside the home folder.
    pub rel: String,
    pub path: PathBuf,
}

/// What a walk found.
pub struct Walk {
    pub checkouts: Vec<Checkout>,
    /// Folders that could not be listed, named as checkouts are.
    pub unlisted: Vec<String>,
    /// Folders macOS asks permission for that the walk did not enter (`guarded.rs`).
    pub guarded: Vec<PathBuf>,
    /// Folders listed in full, named as checkouts are: a checkout that appears in one later
    /// is new (`baseline.rs`).
    pub listed: Vec<String>,
    /// Every folder found in a folder that was listed, entered or not.
    pub seen: Vec<String>,
}

impl Walk {
    /// Whether a checkout the store holds, at `under` below the walk's root, that the walk did
    /// not meet is still there: as looking again finds (`look`), then as it is where it was,
    /// as an agent's working folder is (`still_there`). It is never read from here: one the
    /// walk does not reach is kept as it was. A folder there that the disk spells otherwise,
    /// as a volume that ignores case lets it, and that the walk met under the disk's name is
    /// gone: it is held under that name.
    pub fn look_again(&self, under: &Path, start: &Start) -> Again {
        if let Some(again) = look(&start.root, under, &start.home) {
            return again;
        }
        let path = start.root.join(under);
        match still_there(&path) {
            Some(true) => {}
            Some(false) => return Again::Gone,
            None => return Again::NotTold,
        }
        match std::fs::canonicalize(&path).map(|real| rel(&start.real_home, &real)) {
            Ok(named) if self.checkouts.iter().any(|c| c.rel == named) => Again::Gone,
            _ => Again::Kept,
        }
    }
}

/// What looking again at a known checkout found.
pub enum Again {
    Gone,
    /// It is there, as it was or in another form: kept as it was, nothing in it read.
    Kept,
    /// The disk could not say.
    NotTold,
    /// It is in this folder macOS asks permission for, which was not entered.
    Guarded(PathBuf),
}

/// The path as ids name it: relative to the home folder when it is inside it.
pub fn rel(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(p) if p.as_os_str().is_empty() => ".".to_string(),
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// What one folder holds: the folders to descend into, every folder in it, and whether every
/// entry could be read.
struct Listed {
    descend: Vec<PathBuf>,
    folders: Vec<PathBuf>,
    complete: bool,
}

/// The folders inside `dir`. `None` when the folder could not be listed at all.
fn subfolders(dir: &Path, in_home: bool) -> Option<Listed> {
    let mut out = Vec::new();
    let mut folders = Vec::new();
    let mut complete = true;
    for entry in std::fs::read_dir(dir).ok()? {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        // Symbolic links are not followed: they lead out of the tree or into a loop.
        let Ok(file_type) = entry.file_type() else {
            complete = false;
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        folders.push(entry.path());
        let name = entry.file_name().to_string_lossy().into_owned();
        let pruned = name.starts_with('.')
            || PRUNED.contains(&name.as_str())
            || (in_home && PRUNED_IN_HOME.contains(&name.as_str()));
        if !pruned {
            out.push(entry.path());
        }
    }
    out.sort();
    Some(Listed {
        descend: out,
        folders,
        complete,
    })
}

/// Walks `root` to a fixed depth. The home folder, met from whatever root, is never taken for
/// a checkout: a home folder under git is a store of settings, and taking it would hide every
/// checkout inside it. Its own folders that hold media, applications or settings are pruned.
pub fn walk(root: &Path, home: &Path) -> Walk {
    let mut checkouts = Vec::new();
    let mut unlisted = Vec::new();
    let mut guarded = Vec::new();
    let mut listed = Vec::new();
    let mut seen = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let top = dir == home;
        if !top && std::fs::symlink_metadata(dir.join(".git")).is_ok() {
            checkouts.push(Checkout {
                rel: rel(home, &dir),
                path: dir,
            });
            continue;
        }
        if depth == MAX_DEPTH {
            continue;
        }
        let Some(found) = subfolders(&dir, top) else {
            unlisted.push(rel(home, &dir));
            continue;
        };
        if found.complete {
            listed.push(rel(home, &dir));
        } else {
            unlisted.push(rel(home, &dir));
        }
        seen.extend(found.folders.iter().map(|f| rel(home, f)));
        for path in found.descend.into_iter().rev() {
            // Entering it would ask the owner's permission, from a run he did not start.
            match crate::guarded::may_enter(&path, root, home) {
                Ok(()) => stack.push((path, depth + 1)),
                Err(folder) => guarded.push(folder),
            }
        }
    }
    checkouts.sort_by(|a, b| a.rel.cmp(&b.rel));
    unlisted.sort();
    guarded.sort();
    guarded.dedup();
    Walk {
        checkouts,
        unlisted,
        guarded,
        listed,
        seen,
    }
}
