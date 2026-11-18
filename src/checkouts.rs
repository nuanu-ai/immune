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
pub const MOVED: &str = "is no longer a folder reached through folders alone, as when a link to a folder elsewhere took its place or that of a folder above it: it was not looked into, and what was known of it is kept";

/// The checkouts the store holds on `machine`, by their paths as ids name them, that are not
/// among `found` and are still there in another form, as looking along real folders from the
/// home folder finds (`look`).
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
        .filter(|rel| {
            !found.contains(rel) && matches!(look(rel, home, home, &[home]), Some(Again::Moved))
        })
        .collect())
}

/// The folder a walk was given, made real, so that no id names a checkout through a link,
/// `..` or the working folder. The person gave this folder, so following it is asked for.
/// Inside the home folder made real (`real_home`) it is named under `home` as written, as ids
/// are. A folder that cannot be made real stays as given, and the walk says it is not a folder.
pub fn given(root: &Path, home: &Path, real_home: &Path) -> PathBuf {
    let Ok(real) = std::fs::canonicalize(root) else {
        return root.to_path_buf();
    };
    // The home folder itself comes back with a trailing separator, which a `Path` ignores.
    match real.strip_prefix(real_home) {
        Ok(rest) => home.join(rest),
        Err(_) => real,
    }
}

/// How the checkout the store holds at `rel` is looked at again, as the walk started at `root`
/// goes: along real folders down from `root`, which is taken as given, or from `/` when it is
/// not under `root`. No link is followed and nothing past one is looked up, so a second look
/// reaches nothing the walk could not. First, as written, it may be in a folder macOS asks
/// permission for that the walk was not given. Then, one part at a time, it is still there in
/// another form where a link is in its way or something other than a folder is where it was,
/// and gone where a part is missing or a folder above it is no longer one. `None` when every
/// part of its path is a folder.
fn look(rel: &str, home: &Path, root: &Path, homes: &[&Path]) -> Option<Again> {
    let path = home.join(rel);
    // Named under the first of `homes`, however it was written, as `guarded::real` names it.
    let folder = homes.iter().find_map(|h| {
        guarded::folder_of(&path, h).map(|g| match g.strip_prefix(h) {
            Ok(rest) => homes[0].join(rest),
            Err(_) => g,
        })
    });
    if let Some(g) = folder
        && !root.starts_with(&g)
    {
        return Some(Again::Guarded(g));
    }
    // Outside `root`, down from `/`. `home` is absolute, so `path` always is: the guard holds.
    let (from, under) = match path.strip_prefix(root) {
        Ok(under) => (root, under),
        Err(_) => match path.strip_prefix("/") {
            Ok(under) => (Path::new("/"), under),
            Err(_) => return Some(Again::NotTold),
        },
    };
    let mut at = from.to_path_buf();
    let mut parts = under.components().peekable();
    while let Some(part) = parts.next() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(m) if m.is_symlink() || parts.peek().is_none() => return Some(Again::Moved),
            Ok(_) => return Some(Again::Gone),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Again::Gone),
            Err(_) => return Some(Again::NotTold),
        }
    }
    None
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

impl Walk {
    /// Whether the walk looked where the checkout `rel` was and it was not there: at some
    /// level of its path the walk listed a folder in full, and no folder of the next name was
    /// in it. Names are compared as written. A checkout no folder on whose way the walk listed
    /// (deeper than it goes, inside a hidden, pruned or guarded folder, in one that could not
    /// be listed, inside another checkout) was not walked past, nor was one whose folders are
    /// all still there.
    pub fn went_past(&self, rel: &str) -> bool {
        let named = |p: &Path| match p.as_os_str().is_empty() {
            true => ".".to_string(),
            false => p.to_string_lossy().into_owned(),
        };
        let path = Path::new(rel);
        path.ancestors()
            .zip(path.ancestors().skip(1))
            .any(|(at, held)| self.listed.contains(&named(held)) && !self.seen.contains(&named(at)))
    }

    /// A checkout the store holds at `rel` that this walk, started at `root`, did not meet:
    /// as looking along real folders from `root` finds (`look`), then gone when the walk went
    /// past it, and otherwise looked at where it was, as an agent's working folder is
    /// (`still_there`).
    pub fn look_again(&self, rel: &str, home: &Path, root: &Path, homes: &[&Path]) -> Again {
        if let Some(again) = look(rel, home, root, homes) {
            return again;
        }
        if self.went_past(rel) {
            return Again::Gone;
        }
        let path = home.join(rel);
        match still_there(&path) {
            Some(true) => Again::Found(path),
            Some(false) => Again::Gone,
            None => Again::NotTold,
        }
    }
}

/// What looking again at a known checkout found.
pub enum Again {
    /// It is there, at this path, as the walk names the paths it meets.
    Found(PathBuf),
    Gone,
    /// Something other than a folder is where it was, or a link took the place of a folder
    /// above it.
    Moved,
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
