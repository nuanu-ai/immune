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

use std::path::{Path, PathBuf};

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

/// The guarded folder `path` is in, or `None`. `path` is taken as written: making it real
/// would look inside the folder.
pub fn folder_of(path: &Path, home: &Path) -> Option<PathBuf> {
    if let Ok(rest) = path.strip_prefix(VOLUMES)
        && let Some(volume) = rest.components().next()
    {
        return Some(Path::new(VOLUMES).join(volume));
    }
    IN_HOME
        .iter()
        .map(|g| home.join(g))
        .find(|g| path.starts_with(g))
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
}
