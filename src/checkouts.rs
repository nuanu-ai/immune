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
/// The entity type of a checkout, which the questions call a project.
pub const TYPE: &str = "checkout";
/// Why a walk of a folder given instead of the home folder is partial.
pub const ONLY_GIVEN: &str = "only the given folder was walked";
/// What is said of a checkout the store holds that is still there in another form.
pub const MOVED: &str = "is no longer a folder there, as when a link to a folder elsewhere took its place: it was not looked into, and what was known of it is kept";

/// Whether something other than a folder is where a checkout was, a link to one included:
/// the checkout is not gone, and is not looked into there.
pub fn is_moved(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir())
}

/// The checkouts the store holds on `machine`, by their paths as ids name them, that are not
/// among `found` and are still there in another form (`is_moved`).
pub fn moved(
    conn: &rusqlite::Connection,
    machine: &str,
    home: &Path,
    found: &[String],
) -> rusqlite::Result<Vec<String>> {
    let prefix = format!("checkout:{machine}/");
    Ok(crate::store::live_subjects(conn, READER)?
        .into_iter()
        .filter_map(|id| id.strip_prefix(&prefix).map(str::to_string))
        .filter(|rel| !found.contains(rel) && is_moved(&home.join(rel)))
        .collect())
}

const MAX_DEPTH: usize = 5;
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

/// What the walk does not look in by design, in a person's words made from the walk's own
/// limits, so the words cannot drift from the code.
pub fn not_walked() -> String {
    let in_home: Vec<String> = PRUNED_IN_HOME
        .iter()
        .map(|n| {
            if *n == LIBRARY {
                format!("{n} (which holds iCloud Drive and other cloud storage)")
            } else {
                n.to_string()
            }
        })
        .collect();
    let in_home: Vec<&str> = in_home.iter().map(String::as_str).collect();
    format!(
        "Projects are looked for in your home folder, but not in {} directly in it, not in hidden folders or folders named {}, not through a link to a folder, and not deeper than {MAX_DEPTH} folders down.",
        crate::covered::listed(&in_home),
        match PRUNED.split_last() {
            Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
            None => String::new(),
        }
    )
}

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

/// The path as ids name it: relative to the home folder when it is inside it.
pub fn rel(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(p) if p.as_os_str().is_empty() => ".".to_string(),
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

/// Whether a walk of the home folder looks at the folder `rel`, a path as ids name it, for a
/// checkout: it is inside the home folder, no deeper than the walk goes, and not pruned. Two
/// things the walk does not enter are left to the caller: a folder macOS asks permission for,
/// and a folder inside a checkout.
pub fn reaches(rel: &str) -> bool {
    let names: Vec<&str> = rel.split('/').collect();
    !rel.starts_with('/')
        && names.len() <= MAX_DEPTH
        && !PRUNED_IN_HOME.contains(&names[0])
        && names
            .iter()
            .all(|n| !n.starts_with('.') && !PRUNED.contains(n))
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

/// Walks `root` to a fixed depth. When the root is the home folder, the home folder itself
/// is not taken for a checkout: a home folder under git is a store of settings, and taking
/// it would hide every checkout inside it.
pub fn walk(root: &Path, home: &Path) -> Walk {
    let is_home = root == home;
    let mut checkouts = Vec::new();
    let mut unlisted = Vec::new();
    let mut guarded = Vec::new();
    let mut listed = Vec::new();
    let mut seen = Vec::new();
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
