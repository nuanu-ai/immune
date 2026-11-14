//! A test's own folder under the temporary folder, removed with all it holds when the test
//! ends, whether it passed or failed. Shared by the unit tests (`src/main.rs` takes it by path)
//! and by every integration test; each uses only part of it.
//!
//! A folder a test shut (mode 000, or a store folder made read-only) is opened again before it
//! is removed: `remove_dir_all` cannot list or empty a folder its owner may not read or write,
//! and would leave it, and the folders above it, behind.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A new folder `immune-<tag>-<pid>-<nanos>` under the temporary folder, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let path = std::env::temp_dir().join(unique(tag));
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    /// A path the caller named, removed when dropped. What a run before left there is
    /// removed first; the folder itself is not made.
    pub fn at(path: PathBuf) -> Scratch {
        remove(&path);
        Scratch(path)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

/// `immune-<tag>-<pid>-<nanos>`: no two tests, runs or test binaries share it.
pub fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("immune-{tag}-{}-{nanos}", std::process::id())
}

/// Removes `path` and everything under it, opening again first any folder under it that its
/// owner may not list, enter or write. A path that is not there is left as it is.
pub fn remove(path: &Path) {
    open(path);
    let _ = std::fs::remove_dir_all(path);
}

fn open(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mode = meta.permissions().mode();
    if mode & 0o700 != 0o700 {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o700));
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            open(&entry.path());
        }
    }
}

/// Waits until the clock is in a later second than when this was called. The store keeps
/// times in whole seconds, so what a test does after it falls in a later second than all it
/// did before: the guarantee a fixed sleep of 1.1 s gives, at half its cost on average.
pub fn next_second() {
    let second = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let at = second();
    while second() == at {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
