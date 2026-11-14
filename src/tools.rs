//! Which programs the program runs, and how it finds them. What a tool prints becomes facts
//! about this Mac, so a program planted where a lookup would find it could write any facts.
//!
//! Tools that come with macOS are run by their absolute path and never looked up. Homebrew
//! and Tailscale are looked for only in the places their installers put them, and only a
//! regular file that may be executed is run. Nothing of the caller's environment, PATH
//! included, decides which program runs or what is found: the same Mac gives the same reading
//! whoever starts the check, and a program in the current folder or anywhere on PATH is
//! never run.
//!
//! This does not protect against a process running as the owner, which can replace a tool in
//! any folder the owner can write, the Homebrew prefix included.

use std::path::{Path, PathBuf};

/// How the reason of a reading goes on after a tool's name when the tool is not at the places
/// this version looks and the store holds what an earlier check read from it: lost sight of,
/// never "not installed". The places follow.
pub const READ_BEFORE: &str =
    " was read before and is not found now at the places this version looks for it: ";

/// The system's own tools, where every Mac has them.
pub const SCUTIL: &str = "/usr/sbin/scutil";
pub const HOSTNAME: &str = "/bin/hostname";
pub const OPEN: &str = "/usr/bin/open";
pub const PS: &str = "/bin/ps";
#[allow(dead_code)]
pub const SW_VERS: &str = "/usr/bin/sw_vers";

/// Whether `path` may be run: a regular file, after following links, with an execute bit.
pub fn runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// What looking for a program found.
#[derive(Debug, PartialEq)]
pub struct Found {
    /// The program to run, by the path it was found at.
    pub at: Option<PathBuf>,
    /// Folders macOS asks permission for that a place to look led into, not looked into.
    pub guarded: Vec<PathBuf>,
}

/// The first runnable program among `known`. A place that leads into a folder macOS asks
/// permission for, whatever name leads there, is not looked into: it is named in `guarded`.
/// `homes` are the home folder's names.
pub fn find(known: &[PathBuf], homes: &[&Path]) -> Found {
    let mut guarded = Vec::new();
    for candidate in known.iter().cloned() {
        match crate::guarded::real(&candidate, homes) {
            crate::guarded::Real::At(real) if runnable(&real) => {
                return Found {
                    at: Some(candidate),
                    guarded,
                };
            }
            crate::guarded::Real::Guarded(g) if !guarded.contains(&g) => guarded.push(g),
            _ => {}
        }
    }
    Found { at: None, guarded }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A file at `path` with these permissions.
    fn file(path: &Path, mode: u32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn only_a_runnable_file_at_a_known_place_is_taken() {
        // What a found tool prints is stored as facts about this Mac: a folder or a file that
        // may not be run is passed over for the next place.
        let base = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-tools-{}", std::process::id())),
        );
        file(&base.join("not-executable/tool"), 0o644);
        std::fs::create_dir_all(base.join("folder/tool")).unwrap();
        file(&base.join("known/tool"), 0o755);
        let known = [
            base.join("not-executable/tool"),
            base.join("folder/tool"),
            base.join("known/tool"),
        ];
        let found = find(&known, &[&base]);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(found.at, Some(base.join("known/tool")));
    }

    #[test]
    fn a_known_place_in_a_folder_macos_asks_permission_for_is_not_looked_into_whatever_name_leads_there()
     {
        // A run the app starts must not make macOS ask the owner for his Documents because a
        // place to look leads there, directly or through a link.
        let base = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-tools-guarded-{}", std::process::id())),
        );
        file(&base.join("Documents/bin/tool"), 0o755);
        std::os::unix::fs::symlink(base.join("Documents/bin"), base.join("bin")).unwrap();
        let known = [base.join("bin/tool"), base.join("Documents/bin/tool")];
        let real = std::fs::canonicalize(&base).unwrap();
        let found = find(&known, &[&base, &real]);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(
            found,
            Found {
                at: None,
                guarded: vec![base.join("Documents")]
            }
        );
    }

    #[test]
    fn the_systems_own_tools_are_named_by_paths_every_mac_has() {
        // A system tool found through PATH could be any program named like it.
        for tool in [SCUTIL, HOSTNAME, OPEN, PS, crate::threats::CURL] {
            assert!(
                Path::new(tool).is_absolute() && runnable(Path::new(tool)),
                "{tool}"
            );
        }
    }
}
