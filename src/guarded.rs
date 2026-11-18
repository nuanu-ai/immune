//! Folders macOS asks the owner's permission for before a program may look inside them. A run
//! started by the app must never raise that dialog, so no reader of ours enters one unless the
//! owner points it there with `--checkouts-root`. What was not looked into is named in
//! coverage, under `KIND` with the cause `not_given`, and in the status's `not_covered`.
//!
//! The list is data true on every Mac. Sources:
//! - Apple Platform Security, "Controlling app access to files in macOS": consent is asked
//!   before access to Desktop, Documents, Downloads, iCloud Drive, network volumes and
//!   removable volumes.
//! - Apple's Mac User Guide, "Control access to files and folders on Mac": Desktop,
//!   Documents and Downloads.
//! - Not on those pages, and asked for all the same: storage of other cloud providers
//!   (`~/Library/CloudStorage`, where File Provider keeps it) and other applications' data
//!   (`~/Library/Containers`, `~/Library/Group Containers`, asked for since macOS 14).
//!
//! A volume is anything under `/Volumes`: removable and network volumes are mounted there.
//! Nothing there is looked at to tell them apart, since looking could itself ask.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Components, Path, PathBuf};

/// The coverage kind of what the readers did not look into.
pub const KIND: &str = "folders macOS asks permission for";

/// How the reason of that reading begins; the folders follow, as `shown` gives them.
pub const NOT_LOOKED_INTO: &str = "not looked into: ";

/// The guarded folders in the home folder, relative to it.
pub const IN_HOME: [&str; 7] = [
    "Desktop",
    "Documents",
    "Downloads",
    // iCloud Drive.
    "Library/Mobile Documents",
    "Library/CloudStorage",
    "Library/Containers",
    "Library/Group Containers",
];

/// Where removable and network volumes are mounted.
pub const VOLUMES: &str = "/Volumes";

// The writable side of the macOS startup volume is also reachable by this name.
const DATA: &str = "/System/Volumes/Data";

fn after_prefix<'a>(
    mut path: Components<'a>,
    mut prefix: Components<'_>,
) -> Option<Components<'a>> {
    prefix
        .all(|p| {
            path.next().is_some_and(|c| {
                c.as_os_str()
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(p.as_os_str().as_encoded_bytes())
            })
        })
        .then_some(path)
}

fn data_path(path: &Path) -> Components<'_> {
    after_prefix(path.components(), Path::new(DATA).components())
        .or_else(|| after_prefix(path.components(), Path::new("/").components()))
        .unwrap_or_else(|| path.components())
}

/// The guarded folder `path` is in, or `None`. `path` is taken as written: making it real
/// would look inside the folder, and `real` is how a path from data is made real. The names
/// are compared without regard to case, as the Mac's volumes compare them by default.
pub fn folder_of(path: &Path, home: &Path) -> Option<PathBuf> {
    let same = |a: &std::ffi::OsStr, b: &str| a.to_string_lossy().eq_ignore_ascii_case(b);
    let mut parts = data_path(path);
    if let (Some(Component::Normal(v)), Some(Component::Normal(volume))) =
        (parts.next(), parts.next())
        && path.is_absolute()
        && same(v, "Volumes")
    {
        return Some(Path::new(VOLUMES).join(volume));
    }
    let rest = after_prefix(data_path(path), data_path(home))?;
    IN_HOME
        .iter()
        .find(|g| {
            let mut names = rest.clone();
            g.split('/').all(
                |want| matches!(names.next(), Some(Component::Normal(name)) if same(name, want)),
            )
        })
        .map(|g| home.join(g))
}

/// Where a path from data leads.
#[derive(Debug)]
pub enum Real {
    /// The path without symbolic links, `.` or `..`.
    At(PathBuf),
    /// It leads into this guarded folder, which was not entered.
    Guarded(PathBuf),
    /// It could not be followed: a part of it is missing or cannot be looked at.
    Failed(std::io::Error),
}

/// How many links one path may pass through, as macOS allows (`MAXSYMLINKS`).
const MAX_LINKS: usize = 32;

/// The real path `path` leads to, made one part at a time so that no part inside a guarded
/// folder is ever looked at: each part is checked against the guarded folders of each of
/// `homes` before it is looked up, and a link is read where it is and its target checked
/// the same way. Reading where a link points is not entering where it points;
/// `canonicalize` on a path inside a guarded folder would be. A relative path fails.
pub fn real(path: &Path, homes: &[&Path]) -> Real {
    real_in(path, homes, &[])
}

/// A folder's device and inode: what every spelling of it shares.
type Id = (u64, u64);

fn id(meta: &std::fs::Metadata) -> Id {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

/// The guarded folders by identity, each with its name under the first of `homes` and its path
/// under the home it was found in, the last of `homes` first; and `/Volumes`. The volume folds
/// names that a comparison of ASCII case does not (`Deſktop` is `~/Desktop`), so another
/// spelling is told by identity. Looking at a folder is not entering it.
fn identities(homes: &[&Path]) -> (Option<Id>, Vec<(Id, PathBuf, PathBuf)>) {
    let meta = |p: &Path| std::fs::symlink_metadata(p).ok().filter(|m| m.is_dir());
    let mut in_home = Vec::new();
    for h in homes.iter().rev() {
        for g in IN_HOME {
            if let Some(m) = meta(&h.join(g)) {
                in_home.push((id(&m), homes[0].join(g), h.join(g)));
            }
        }
    }
    (meta(Path::new(VOLUMES)).map(|m| id(&m)), in_home)
}

/// Like `real`, with the given checkout allowed under both its supplied and resolved names.
/// Its guarded ancestors may be traversed to reach it.
pub fn real_in(path: &Path, homes: &[&Path], given: &[&Path]) -> Real {
    let exempt = |p: &Path, on_the_way: bool| {
        given
            .iter()
            .any(|root| p.starts_with(root) || on_the_way && root.starts_with(p))
    };
    // A guarded folder is named under the first of `homes`, however it was reached.
    let guarded = |p: &Path, on_the_way: bool| {
        if exempt(p, on_the_way) {
            return None;
        }
        homes.iter().find_map(|h| {
            folder_of(p, h).map(|g| match g.strip_prefix(h) {
                Ok(rest) => homes[0].join(rest),
                Err(_) => g,
            })
        })
    };
    if !path.is_absolute() {
        return Real::Failed(std::io::Error::other("the path is not absolute"));
    }
    // As written first: a home folder reached through a link is in `homes` by both names.
    if let Some(g) = guarded(path, false) {
        return Real::Guarded(g);
    }
    let mut todo: VecDeque<OsString> = path
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut done = PathBuf::from("/");
    // The identity of `done`, while it is known; and the guarded folders', asked once.
    let mut done_id: Option<Id> = None;
    let mut ids = None;
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            done.pop();
            done_id = None;
            continue;
        }
        let next = done.join(&part);
        let more = !todo.is_empty();
        if let Some(g) = guarded(&next, more) {
            return Real::Guarded(g);
        }
        // A folder directly under /Volumes is told by its parent before it is looked at:
        // looking at a mount point can wait on a server.
        let (volumes, in_home) = ids.get_or_insert_with(|| identities(homes));
        let parent = done_id.or_else(|| std::fs::symlink_metadata(&done).ok().map(|m| id(&m)));
        let volume =
            (parent.is_some() && parent == *volumes).then(|| Path::new(VOLUMES).join(&part));
        if let Some(name) = &volume
            && !exempt(name, more)
            && !exempt(&next, more)
        {
            return Real::Guarded(name.clone());
        }
        match std::fs::symlink_metadata(&next) {
            Err(e) => return Real::Failed(e),
            Ok(m) if m.file_type().is_symlink() => {
                links += 1;
                if links > MAX_LINKS {
                    return Real::Failed(std::io::Error::other(
                        "too many levels of symbolic links",
                    ));
                }
                let target = match std::fs::read_link(&next) {
                    Ok(t) => t,
                    Err(e) => return Real::Failed(e),
                };
                if target.is_absolute() {
                    done = PathBuf::from("/");
                    done_id = None;
                }
                for c in target.components().rev() {
                    if c != Component::RootDir {
                        todo.push_front(c.as_os_str().to_os_string());
                    }
                }
            }
            Ok(m) if !m.is_dir() && more => {
                return Real::Failed(std::io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            Ok(m) if m.is_dir() => {
                done = match in_home.iter().find(|(i, ..)| *i == id(&m)) {
                    Some((_, name, at)) if !exempt(name, more) && !exempt(at, more) => {
                        return Real::Guarded(name.clone());
                    }
                    // Exempt: on under the folder's own name, so what follows is told by it.
                    Some((_, _, at)) => at.clone(),
                    None => next,
                };
                done_id = Some(id(&m));
            }
            Ok(_) => done = next,
        }
    }
    guarded(&done, false).map_or(Real::At(done), Real::Guarded)
}

/// `path` with its last part made real by `real` when that part is a symbolic link, and as
/// written otherwise. A reader that goes down from a folder it has reached adds one part at
/// a time, and only the part it adds can lead elsewhere. `Err` is the guarded folder the
/// link leads into. A link that cannot be followed is left as written: looking at it fails
/// where `real` failed, before any guarded folder.
pub fn followed(path: &Path, homes: &[&Path]) -> Result<PathBuf, PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => match real(path, homes) {
            Real::At(p) => Ok(p),
            Real::Guarded(g) => Err(g),
            Real::Failed(_) => Ok(path.to_path_buf()),
        },
        _ => Ok(path.to_path_buf()),
    }
}

/// `rel` under `base`, each of its parts `followed` in turn. `base` is a folder the reader
/// was given, taken as it is.
pub fn under(base: &Path, rel: &Path, homes: &[&Path]) -> Result<PathBuf, PathBuf> {
    rel.components().try_fold(base.to_path_buf(), |at, part| {
        followed(&at.join(part), homes)
    })
}

/// Why something was not looked into, as a reason says it.
pub fn leads_into(folder: &Path, home: &Path) -> String {
    format!(
        "it leads into {}, which macOS asks permission for",
        shown(folder, home)
    )
}

/// A guarded folder as a person reads it: `~/Documents`, `/Volumes/Backup`.
pub fn shown(folder: &Path, home: &Path) -> String {
    match folder.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => folder.display().to_string(),
    }
}

/// Whether a reader that started at `root` may enter `path`: not when `path` is in a guarded
/// folder that `root` is not itself inside, which is the owner pointing there.
pub fn may_enter(path: &Path, root: &Path, home: &Path) -> Result<(), PathBuf> {
    match folder_of(path, home) {
        Some(g) if !root.starts_with(&g) => Err(g),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_never_enters_a_folder_macos_asks_permission_for_unless_pointed_there() {
        // A run started by the app must not raise a permission dialog on the owner's Mac.
        let home = Path::new("/Users/someone");
        for inside in [
            "/Users/someone/Desktop/x",
            "/Users/someone/Documents/dev/shop",
            "/Users/someone/Downloads",
            "/Users/someone/Library/Mobile Documents/com~apple~CloudDocs/a",
            "/Users/someone/Library/CloudStorage/Drive/b",
            "/Users/someone/Library/Containers/com.example/Data",
            "/Users/someone/Library/Group Containers/group.example",
            "/Volumes/Backup/dev",
        ] {
            assert!(
                may_enter(Path::new(inside), home, home).is_err(),
                "{inside}"
            );
        }
        for outside in [
            "/Users/someone/dev/shop",
            "/Users/someone/Desktopper",
            "/Users/someone/Library/Application Support/x",
            "/Volumes",
        ] {
            assert!(
                may_enter(Path::new(outside), home, home).is_ok(),
                "{outside}"
            );
        }
        // On a volume that ignores case, every spelling is the same folder.
        for spelled in [
            "/Users/someone/documents/x",
            "/users/SOMEONE/Documents/x",
            "/Users/someone/DESKTOP",
            "/Users/someone/library/mobile documents/a",
            "/System/Volumes/Data/Users/someone/Documents/x",
            "/System/Volumes/Data/Volumes/Backup/dev",
            "/volumes/Backup/dev",
        ] {
            assert!(folder_of(Path::new(spelled), home).is_some(), "{spelled}");
        }
        // Pointed there by the owner, the reader enters what it was pointed at.
        let root = Path::new("/Users/someone/Documents/dev");
        assert!(may_enter(Path::new("/Users/someone/Documents/dev/shop"), root, home).is_ok());
        assert_eq!(
            folder_of(Path::new("/Volumes/Backup/dev"), home).map(|g| shown(&g, home)),
            Some("/Volumes/Backup".to_string())
        );
        assert_eq!(
            shown(&home.join("Documents"), home),
            "~/Documents".to_string()
        );
    }

    #[test]
    fn a_path_from_data_is_made_real_without_entering_a_guarded_folder_whatever_name_led_there() {
        // A link outside a guarded folder that points inside it must not make the program
        // enter it: macOS would ask the owner's permission. The folder here cannot be
        // searched, so entering it would fail where not entering it succeeds.
        use std::os::unix::fs::{PermissionsExt, symlink};
        let base = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-guarded-{}", std::process::id())),
        );
        std::fs::create_dir_all(base.join("Documents/proj")).unwrap();
        std::fs::create_dir_all(base.join("dev/shop")).unwrap();
        let home = std::fs::canonicalize(&base).unwrap();
        let docs = home.join("Documents");
        symlink(home.join("Documents/proj"), home.join("absolute")).unwrap();
        symlink("Documents/proj", home.join("relative")).unwrap();
        symlink(home.join("relative"), home.join("chain")).unwrap();
        symlink(home.join("documents"), home.join("spelled")).unwrap();
        symlink("/Volumes/Backup", home.join("volume")).unwrap();
        symlink(home.join("dev"), home.join("work")).unwrap();
        symlink(home.join("loop2"), home.join("loop1")).unwrap();
        symlink(home.join("loop1"), home.join("loop2")).unwrap();
        std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o000)).unwrap();

        let real_of = |p: PathBuf| real(&p, &[&base, &home]);
        assert!(std::fs::canonicalize(home.join("absolute")).is_err());
        for (written, folder) in [
            (home.join("absolute"), base.join("Documents")),
            (home.join("relative/x"), base.join("Documents")),
            (home.join("chain"), base.join("Documents")),
            (home.join("spelled/proj"), base.join("Documents")),
            (home.join("dev/../Documents/proj"), base.join("Documents")),
            (base.join("Documents/proj"), base.join("Documents")),
            (home.join("volume/dev"), PathBuf::from("/Volumes/Backup")),
            // The volume folds `ſ` to `s`: the same folder by another spelling, told by identity.
            (home.join("Documentſ/proj"), base.join("Documents")),
            (
                Path::new("/System/Volumes/Data")
                    .join(home.strip_prefix("/").unwrap())
                    .join("documentſ/proj"),
                base.join("Documents"),
            ),
        ] {
            match real_of(written.clone()) {
                Real::Guarded(g) => assert_eq!(g, folder, "{}", written.display()),
                other => panic!("{}: {other:?}", written.display()),
            }
        }
        // A folder given inside a guarded one lets the walk pass the guarded one on its way
        // there, under the folder's own name, so nothing beside the given folder is entered.
        let given = home.join("Documents/given");
        let beside = real_in(&home.join("Documentſ/other/x"), &[&base, &home], &[&given]);
        assert!(matches!(beside, Real::Guarded(g) if g == base.join("Documents")));
        assert!(
            matches!(real_of(home.join("work/shop")), Real::At(p) if p == home.join("dev/shop"))
        );
        assert!(
            matches!(real_of(home.join("work/../dev/./shop")), Real::At(p) if p == home.join("dev/shop"))
        );
        assert!(matches!(real_of(home.join("loop1")), Real::Failed(_)));
        assert!(
            matches!(real_of(home.join("missing/x")), Real::Failed(e) if e.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(matches!(real_of(PathBuf::from("dev")), Real::Failed(_)));

        std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }
}
