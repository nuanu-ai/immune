//! Which programs the program runs, and how it finds them. What a tool prints becomes facts
//! about this Mac, so a program planted where a lookup would find it could write any facts.
//!
//! Tools that come with macOS are run by their absolute path and never looked up. Homebrew
//! and Tailscale live in different places on different Macs: they are looked for in the
//! places their installers put them, and only then on PATH, where only absolute folders are
//! taken and only regular files that may be executed. A program in the current folder, or
//! one reached through a relative entry of PATH, is never run.
//!
//! This does not protect against a process running as the owner, which can replace a tool in
//! any folder the owner can write, the Homebrew prefix included.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The system's own tools, where every Mac has them.
pub const SCUTIL: &str = "/usr/sbin/scutil";
pub const HOSTNAME: &str = "/bin/hostname";
pub const OPEN: &str = "/usr/bin/open";
pub const PS: &str = "/bin/ps";

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

/// The first runnable program among `known`, else the first `name` in an absolute folder of
/// `path`, a value in the form of PATH. Relative and empty entries are skipped, and so is a
/// place that leads into a folder macOS asks permission for, whatever name leads there: it
/// is named in `guarded`. `homes` are the home folder's names.
pub fn find(name: &str, known: &[PathBuf], path: &OsStr, homes: &[&Path]) -> Found {
    let on_path = std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name));
    let mut guarded = Vec::new();
    for candidate in known.iter().cloned().chain(on_path) {
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

/// PATH of this process.
pub fn path() -> std::ffi::OsString {
    std::env::var_os("PATH").unwrap_or_default()
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
    fn a_program_in_the_current_folder_or_reached_through_a_relative_path_entry_is_never_run() {
        // What a found tool prints is stored as facts about this Mac. A relative entry of
        // PATH is resolved against whatever folder the program was started in.
        let cwd = std::env::current_dir().unwrap();
        let rel = PathBuf::from("target").join(format!("immune-tools-{}", std::process::id()));
        let abs = cwd.join(&rel);
        let _ = std::fs::remove_dir_all(&abs);
        file(&abs.join("relative/tool"), 0o755);
        file(&abs.join("not-executable/tool"), 0o644);
        std::fs::create_dir_all(abs.join("folder/tool")).unwrap();
        file(&abs.join("real/tool"), 0o755);
        file(&abs.join("known/tool"), 0o755);

        let entries = [
            rel.join("relative"),
            PathBuf::new(),
            PathBuf::from("."),
            abs.join("not-executable"),
            abs.join("folder"),
            abs.join("real"),
        ];
        let path = std::env::join_paths(&entries).unwrap();
        let at = |known: &[PathBuf], path: &OsStr| find("tool", known, path, &[&abs]).at;
        assert_eq!(at(&[], &path), Some(abs.join("real/tool")));
        let only_relative = std::env::join_paths(&entries[..5]).unwrap();
        assert_eq!(at(&[], &only_relative), None);
        // The places an installer puts the tool come before PATH, and are checked the same way.
        let known = [abs.join("folder/tool"), abs.join("known/tool")];
        assert_eq!(at(&known, &path), Some(abs.join("known/tool")));
        let _ = std::fs::remove_dir_all(&abs);
    }

    #[test]
    fn a_folder_of_path_in_a_folder_macos_asks_permission_for_is_not_looked_into_whatever_name_leads_there()
     {
        // A run the app starts must not make macOS ask the owner for his Documents because
        // PATH names a folder there, directly or through a link.
        let base =
            std::env::temp_dir().join(format!("immune-tools-guarded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        file(&base.join("Documents/bin/tool"), 0o755);
        std::os::unix::fs::symlink(base.join("Documents/bin"), base.join("bin")).unwrap();
        let path = std::env::join_paths([base.join("bin"), base.join("Documents/bin")]).unwrap();
        let real = std::fs::canonicalize(&base).unwrap();
        let found = find("tool", &[], &path, &[&base, &real]);
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
