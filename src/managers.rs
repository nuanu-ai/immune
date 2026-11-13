//! Package managers this version has no reader for: found, never read. A Mac may hold software
//! installed with MacPorts, Nix, pkgsrc, Fink or conda, or npm packages installed globally under
//! nvm, and no reader reads any of it: the readers of installed software look at applications,
//! at Homebrew's two places and at the global npm packages there (`integrity.rs`, `brew.rs`).
//! Unnamed, the report would read as if all installed software were covered.
//!
//! A manager is looked for only at the places its installer uses by default, which are the same
//! on every Mac: the table below, one row per manager with the source of each place. Nothing of
//! the caller's environment, PATH included, decides what is found, so a check the app starts
//! and one an agent starts find the same. Each place is looked at through `guarded::real`: a
//! link is read where it is and its target checked against the folders macOS asks permission
//! for before anything inside is touched. Nothing found is run or opened.
//!
//! The table names a few managers and is not complete: what it cannot see, any other manager
//! and one installed at a place of its own choosing, is a standing limit of this version
//! (`covered::MANAGERS_ELSEWHERE`), and `immune program` carries it whenever it does not know
//! a program.

use std::path::{Path, PathBuf};

/// The coverage kind, a reading of the `integrity` reader.
pub const KIND: &str = "software of package managers this version does not read";
/// What coverage says this version has no reader for, with the manager's name.
pub const NO_READER: &str = "package manager on this Mac";
/// How the reason of a reading that found some begins; their names follow.
pub const NOT_READ: &str = "not read: ";

/// What a place is under.
#[derive(Clone, Copy)]
enum Base {
    /// The root of the system, `/` unless a test gives another.
    Root,
    /// The home folder.
    Home,
}

/// A package manager no reader reads: its name, and the places its installer uses by default.
struct Manager {
    name: &'static str,
    places: &'static [(Base, &'static str)],
}

const MANAGERS: [Manager; 6] = [
    // guide.macports.org, "Installing MacPorts": the prefix is /opt/local.
    Manager {
        name: "MacPorts",
        places: &[(Base::Root, "opt/local/bin/port")],
    },
    // nix.dev, "Install Nix": every installer keeps the store at /nix/store.
    Manager {
        name: "Nix",
        places: &[(Base::Root, "nix/store")],
    },
    // pkgsrc.org, "The pkgsrc guide", bootstrap: /opt/pkg for the binary bootstrap on macOS,
    // /usr/pkg for a bootstrap from source. pkg_info is in every pkgsrc installation.
    Manager {
        name: "pkgsrc",
        places: &[
            (Base::Root, "opt/pkg/sbin/pkg_info"),
            (Base::Root, "usr/pkg/sbin/pkg_info"),
        ],
    },
    // finkproject.org, "Installing Fink": the prefix is /sw.
    Manager {
        name: "Fink",
        places: &[(Base::Root, "sw/bin/fink")],
    },
    // docs.anaconda.com, "Installing on macOS": the graphical installer puts it in /opt, the
    // shell installer in the home folder; Miniforge's installer uses ~/miniforge3.
    Manager {
        name: "conda",
        places: &[
            (Base::Root, "opt/miniconda3/bin/conda"),
            (Base::Root, "opt/anaconda3/bin/conda"),
            (Base::Home, "miniconda3/bin/conda"),
            (Base::Home, "anaconda3/bin/conda"),
            (Base::Home, "miniforge3/bin/conda"),
        ],
    },
    // github.com/nvm-sh/nvm, README: NVM_DIR is ~/.nvm by default, and each Node version keeps
    // its global packages under versions/node/<version>/lib/node_modules.
    Manager {
        name: "npm packages installed globally under nvm",
        places: &[(Base::Home, ".nvm/versions/node")],
    },
];

/// What looking for the managers found.
#[derive(Debug, Default, PartialEq)]
pub struct Found {
    /// The managers here, in the order of the table.
    pub names: Vec<&'static str>,
    /// Folders macOS asks permission for that a place led into, not looked into.
    pub guarded: Vec<PathBuf>,
}

/// The package managers here that no reader reads. `root` is where `/` is; `homes` are the
/// home folder's names, the first the one the places under the home folder are taken from.
pub fn found(root: &Path, homes: &[&Path]) -> Found {
    let mut out = Found::default();
    for m in &MANAGERS {
        let mut here = false;
        for (base, place) in m.places {
            let path = match base {
                Base::Root => root.join(place),
                Base::Home => homes[0].join(place),
            };
            match crate::guarded::real(&path, homes) {
                crate::guarded::Real::At(_) => here = true,
                crate::guarded::Real::Guarded(g) if !out.guarded.contains(&g) => {
                    out.guarded.push(g)
                }
                _ => {}
            }
        }
        if here {
            out.names.push(m.name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_managers_place_that_is_a_link_into_a_folder_macos_asks_permission_for_is_not_entered() {
        // A run the app starts must not make macOS ask the owner for his Documents because a
        // manager's place is a link there. The folder is named as not looked into.
        let root =
            std::env::temp_dir().join(format!("immune-managers-guarded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("Users/invented");
        std::fs::create_dir_all(home.join("Documents/macports/bin")).unwrap();
        std::fs::write(home.join("Documents/macports/bin/port"), "").unwrap();
        std::fs::create_dir_all(root.join("opt")).unwrap();
        std::os::unix::fs::symlink(home.join("Documents/macports"), root.join("opt/local"))
            .unwrap();
        // The home folder by both its names, as `watched::homes` gives them.
        let real = std::fs::canonicalize(&home).unwrap();
        let found = found(&root, &[home.as_path(), real.as_path()]);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            found,
            Found {
                names: Vec::new(),
                guarded: vec![home.join("Documents")]
            }
        );
    }
}
