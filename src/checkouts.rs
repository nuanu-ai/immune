//! The `checkouts` reader: which local checkouts exist on this machine. It walks the home
//! folder, or the one folder it is given, and only lists folders: it opens no file. A walk
//! of a given folder is partial, since it did not look at the rest of the home folder.
//!
//! A checkout is a folder that holds `.git`. A checkout is not searched for further
//! checkouts. Paths are relative to the home folder, so the same checkout has the same id
//! whoever runs it and wherever the walk starts.

use std::path::{Path, PathBuf};

pub const READER: &str = "checkouts";
pub const KIND: &str = "checkouts under the home folder";
pub const BASIS: &str = "observed";
/// Why a walk of a folder given instead of the home folder is partial.
pub const ONLY_GIVEN: &str = "only the given folder was walked";

const MAX_DEPTH: usize = 5;
/// Folders that are never descended into, wherever they are: tools keep copies of other
/// people's code there, not checkouts.
const PRUNED: [&str; 3] = ["node_modules", "target", "vendor"];
/// Folders macOS makes in the home folder that hold media, applications or settings.
/// Pruned only directly under the home folder: elsewhere they are ordinary names.
const PRUNED_IN_HOME: [&str; 6] = [
    "Library",
    "Applications",
    "Movies",
    "Music",
    "Pictures",
    "Public",
];

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
}

/// The path as ids name it: relative to the home folder when it is inside it.
pub fn rel(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(p) if p.as_os_str().is_empty() => ".".to_string(),
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// The folders inside `dir` to descend into, and whether every entry could be read.
/// `None` when the folder could not be listed at all.
fn subfolders(dir: &Path, in_home: bool) -> Option<(Vec<PathBuf>, bool)> {
    let mut out = Vec::new();
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
        let name = entry.file_name().to_string_lossy().into_owned();
        let pruned = name.starts_with('.')
            || PRUNED.contains(&name.as_str())
            || (in_home && PRUNED_IN_HOME.contains(&name.as_str()));
        if !pruned {
            out.push(entry.path());
        }
    }
    out.sort();
    Some((out, complete))
}

/// Walks `root` to a fixed depth. When the root is the home folder, the home folder itself
/// is not taken for a checkout: a home folder under git is a store of settings, and taking
/// it would hide every checkout inside it.
pub fn walk(root: &Path, home: &Path) -> Walk {
    let is_home = root == home;
    let mut checkouts = Vec::new();
    let mut unlisted = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let top = depth == 0 && is_home;
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
        let Some((subs, complete)) = subfolders(&dir, top) else {
            unlisted.push(rel(home, &dir));
            continue;
        };
        if !complete {
            unlisted.push(rel(home, &dir));
        }
        for path in subs.into_iter().rev() {
            stack.push((path, depth + 1));
        }
    }
    checkouts.sort_by(|a, b| a.rel.cmp(&b.rel));
    unlisted.sort();
    Walk {
        checkouts,
        unlisted,
    }
}
