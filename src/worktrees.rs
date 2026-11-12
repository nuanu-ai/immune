//! A checkout new to the store that is a linked worktree of a repository the store already
//! holds a checkout of. Agents make such worktrees all day, and each holds the project's own
//! settings, scripts and tasks byte for byte. Judged by its path alone, every one of them would
//! be a new way code runs by itself, and the owner would learn to ignore the alarm.
//!
//! So a place that appears in such a worktree is compared, by its path in the checkout, with
//! the same place in the other checkouts of the same repository, as this same reading read
//! them. Where the part that counts is the same, the place adds nothing that can run: it is
//! recorded as any place is, so that a later change in it is a finding, and its appearance is
//! journaled as `same_as_sibling` instead of raising a finding. Anything else is raised as
//! before. False calm is the guard here: the other place counts only as this reading read it,
//! so what the store used to hold, what was retracted, a place this reading could not read and
//! a checkout it did not look into give nothing to compare with.
//!
//! What industry practice gives and what is ours. File integrity monitors (Tripwire, OSSEC,
//! Wazuh) keep a baseline of hashes and alert on what differs from it; allow-listing by hash
//! (Santa, AppLocker) lets known content run wherever it sits; detection rules keep "first
//! seen" state per key. Taken: content is judged by its hash, and what is new is judged against
//! what is already in force. Ours: the hash is not trusted wherever it sits. It counts only
//! between checkouts git itself made of one repository, proven both ways, because a fresh clone
//! with something that runs by itself is the attack this program exists for.
//!
//! "The same repository" is git's own relation, never a name. The new checkout's `.git` is a
//! file that points into `<common git folder>/worktrees/<name>`; that folder's `gitdir` points
//! back at the checkout's `.git`, and its `commondir` names the common git folder; and the
//! common git folder is the `.git` of a checkout the store held before this reading, or the
//! common folder of another such worktree, proven the same way. The pointer in the new
//! checkout is text anyone who writes in it can write, so it is believed only when the
//! repository's own folder points back. A submodule's `.git` file points at a folder with no
//! `commondir`, so a submodule is never taken for a worktree.
//!
//! Every pointer is followed with `guarded::real` and `guarded::followed`, as the reading of a
//! commit is: nothing in a folder macOS asks permission for is looked at, and a pointer that
//! leads there proves nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rusqlite::{Transaction, params};
use serde_json::json;

use crate::checkouts::Checkout;
use crate::guarded::{self, Real};
use crate::store::Reading;
use crate::watched::Entry;

/// The journal's entry for a place that appeared the same as in another checkout.
pub const SAME: &str = "same_as_sibling";

/// The largest pointer file read: git writes one path and a newline.
const POINTER_CAP: u64 = 4096;

/// The real common git folder of a checkout, and whether the checkout is a linked worktree of
/// it. `None` when it is neither a checkout with a `.git` folder nor a worktree git's own folder
/// points back at, or when it cannot be told without looking into a guarded folder.
fn repository(checkout: &Path, homes: &[&Path]) -> Option<(PathBuf, bool)> {
    let checkout = at(checkout, homes)?;
    let written = checkout.join(".git");
    let dotgit = guarded::followed(&written, homes).ok()?;
    let meta = std::fs::symlink_metadata(&dotgit).ok()?;
    if meta.is_dir() {
        return Some((at(&dotgit, homes)?, false));
    }
    let to = pointer(&written, homes)?;
    let to = to.strip_prefix("gitdir:")?.trim();
    // A relative pointer is from the folder that holds it, as git reads it.
    let own = at(&checkout.join(to), homes)?;
    let common = at(&own.join(pointer(&own.join("commondir"), homes)?), homes)?;
    // The worktree's own folder is in the repository's folder of worktrees, and points back.
    if own.parent()? != common.join("worktrees") {
        return None;
    }
    let back = at(&own.join(pointer(&own.join("gitdir"), homes)?), homes)?;
    (back == at(&written, homes)?).then_some((common, true))
}

/// A path from data made real, unless it leads into a guarded folder or cannot be followed.
fn at(path: &Path, homes: &[&Path]) -> Option<PathBuf> {
    match guarded::real(path, homes) {
        Real::At(p) => Some(p),
        Real::Guarded(_) | Real::Failed(_) => None,
    }
}

/// The one line a pointer file of git holds, trimmed. The file is reached without following a
/// link into a guarded folder and is opened without waiting.
fn pointer(path: &Path, homes: &[&Path]) -> Option<String> {
    let path = guarded::followed(path, homes).ok()?;
    let bytes = crate::autorun::read_capped(&path, POINTER_CAP).ok()?;
    Some(String::from_utf8(bytes).ok()?.trim().to_string())
}

/// The new worktrees of a reading, each with the checkouts of its repository that the store
/// held before this reading.
pub struct Siblings {
    /// Every checkout the reading looked into, by its path as ids name it.
    looked: BTreeSet<String>,
    /// A new linked worktree, by its path, and the other checkouts of its repository.
    of: BTreeMap<String, Vec<String>>,
}

impl Siblings {
    /// Finds the checkouts of `looked` that are new to the store in this reading and are
    /// linked worktrees of a repository with another checkout the store held before it. A
    /// checkout is new when nothing the store holds live says where it is from an earlier run;
    /// the watcher reads only checkouts a full run found, so for it none is.
    pub fn of(
        tx: &Transaction,
        machine: &str,
        run_id: &str,
        looked: &[Checkout],
        home: &Path,
    ) -> rusqlite::Result<Siblings> {
        let prefix = format!("checkout:{machine}/");
        let before: BTreeSet<String> = tx
            .prepare(
                "SELECT DISTINCT subject FROM assertion
                 WHERE layer = 'live' AND predicate = 'located_on' AND run_id != ?2
                   AND substr(subject, 1, length(?1)) = ?1",
            )?
            .query_map(params![prefix, run_id], |r| r.get::<_, String>(0))?
            .map(|id| id.map(|id| id[prefix.len()..].to_string()))
            .collect::<rusqlite::Result<_>>()?;
        let homes = crate::watched::homes(home);
        let homes = [homes[0].as_path(), homes[1].as_path()];
        let mut of = BTreeMap::new();
        // The common git folder of every checkout held before, looked at only once a new
        // worktree asks for it.
        let mut held: Option<Vec<(&String, PathBuf)>> = None;
        for c in looked.iter().filter(|c| !before.contains(&c.rel)) {
            let Some((common, true)) = repository(&c.path, &homes) else {
                continue;
            };
            let held = held.get_or_insert_with(|| {
                before
                    .iter()
                    .filter_map(|rel| {
                        let path = match rel.starts_with('/') {
                            true => PathBuf::from(rel),
                            false => home.join(rel),
                        };
                        Some((rel, repository(&path, &homes)?.0))
                    })
                    .collect()
            });
            let others: Vec<String> = held
                .iter()
                .filter(|(_, other)| *other == common)
                .map(|(rel, _)| rel.to_string())
                .collect();
            if !others.is_empty() {
                of.insert(c.rel.clone(), others);
            }
        }
        Ok(Siblings {
            looked: looked.iter().map(|c| c.rel.clone()).collect(),
            of,
        })
    }

    /// For a place new in this reading, by its path as ids name it: the checkout of its
    /// repository whose same place, by its path in the checkout, holds the same part that
    /// counts as this reading read it, and that place's path. Only a place in a new worktree
    /// has one. The checkout of a path is the deepest one looked into whose folder holds it.
    /// A path names one row of the tables, so the same path is the same kind of place, and a
    /// part is never equal to a whole file: their literals differ. `read` is every entry of
    /// this reading by its path.
    pub fn same_as(&self, path: &str, read: &BTreeMap<&str, &Entry>) -> Option<(String, String)> {
        let (worktree, within) = self
            .looked
            .iter()
            .filter_map(|rel| Some((rel, path.strip_prefix(rel.as_str())?.strip_prefix('/')?)))
            .max_by_key(|(rel, _)| rel.len())?;
        let part = read.get(path)?.content.literal()?;
        self.of.get(worktree)?.iter().find_map(|other| {
            let there = format!("{other}/{within}");
            let same = read.get(there.as_str())?.content.literal()? == part;
            same.then(|| (other.clone(), there))
        })
    }
}

/// Journals that a place appeared the same as in another checkout of its repository: its
/// subject, the part that counts, and in `text` which checkout and which place it was compared
/// with.
pub fn journal(
    tx: &Transaction,
    r: &Reading,
    subject: &str,
    content: Option<String>,
    checkout: &str,
    file: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                              new_value, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'has_content', ?8, ?9)",
        params![
            r.at,
            r.run_id,
            SAME,
            r.reader,
            r.scope,
            r.kind,
            subject,
            content,
            json!({ "checkout": checkout, "file": file }).to_string()
        ],
    )?;
    Ok(())
}
