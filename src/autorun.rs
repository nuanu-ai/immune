//! What a checkout runs by itself when it is opened: an editor task set to run when its
//! folder is opened. In the incident the loader was planted in projects this way.
//!
//! The editor's task file, `.vscode/tasks.json`, is a watched file of its own kind only while
//! it holds such a task, so it goes through the watched places reader like any other: the
//! first reading on this Mac is the baseline, and a task of this kind that appears later, in
//! a checkout the store held or in one that is new, or whose file changes, is a finding. This
//! is smaller than a reader of its own: the watched reader already keeps a file's checksum,
//! its lifecycle and what a rule is told. This file only decides which task files belong.
//!
//! The format is JSON with comments and trailing commas. It is read by Foundation's JSON5
//! reader, see `json5.rs`; nothing is stripped here. A file it cannot read is a failed reading
//! with Foundation's reason, never "no such task".
//!
//! Whether a file that reads holds such a task is told by its text, not by the parsed value.
//! The editor runs a task whose `runOptions.runOn` is `folderOpen` in any case. Of two equal
//! keys Foundation keeps the first and the editor the last, so a parsed value that says
//! `default` cannot rule a task out; and the editor decodes no escape but `\u` inside a word.
//! So a file holds such a task when its text says `folderOpen` in any case, or holds a `\u`
//! escape that could spell it. That errs only toward watching: a file that names it in a
//! comment is watched too.
//!
//! Other ways a project runs code by itself are not read: each that is present in a
//! checkout is named in a reading of its own, with no reader for it.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::watched::{Content, Entry, Look};

/// The editor's task file, from the checkout.
pub const TASKS: &str = ".vscode/tasks.json";
/// The kind of watched file, the literal of `watched_as`.
pub const RUNS_ON_OPEN: &str = "task run when the project folder is opened";
/// The coverage kind of the reading of the task files of every checkout.
pub const KIND: &str = "editor tasks set to run when a checkout's folder is opened";
/// The coverage kind of the reading that names what is not read.
pub const OTHERS_KIND: &str = "other ways a checkout runs code by itself";
/// What this build has no reader for, in its own words; the name says which.
pub const OTHER_WAY: &str = "way a project runs code by itself";
/// The note of a full reading that found no such task.
pub const NO_TASK: &str = "no checkout has an editor task set to run when its folder is opened";
/// A task file larger than this is not read.
pub const CAP: u64 = 1024 * 1024;

/// Files in a checkout through which something runs code without being asked, other than
/// the editor task read here, each with what runs it. None is read; one that is present is
/// named. The list is data: a row is added when another way is known.
pub const OTHERS: [(&str, &str); 10] = [
    (
        "package.json",
        "package.json (scripts a package manager runs on install)",
    ),
    (".envrc", ".envrc (direnv, on entering the folder)"),
    (
        ".mise.toml",
        ".mise.toml (mise hooks, on entering the folder)",
    ),
    (
        ".devcontainer/devcontainer.json",
        ".devcontainer/devcontainer.json (dev container commands)",
    ),
    (
        ".devcontainer.json",
        ".devcontainer.json (dev container commands)",
    ),
    (".idea", ".idea (JetBrains startup tasks)"),
    (".nvim.lua", ".nvim.lua (Neovim, on opening with exrc)"),
    (".exrc", ".exrc (Vim and Neovim, on opening with exrc)"),
    (
        ".claude/settings.json",
        ".claude/settings.json (a coding agent's hooks)",
    ),
    (".mcp.json", ".mcp.json (servers a coding agent starts)"),
];

/// Looks at the task file of every checkout, each given as its folder and its path as ids
/// name it.
pub fn look_all<'a>(checkouts: impl Iterator<Item = (&'a Path, &'a str)>) -> Look {
    let mut all = Look::default();
    for (path, rel) in checkouts {
        let one = look(path, rel);
        all.entries.extend(one.entries);
        all.failed.extend(one.failed);
        all.present += one.present;
    }
    all
}

/// Looks at one checkout's task file. `rel` is the checkout's path as ids name it. Only a
/// file that holds a task set to run on opening is an entry; one that cannot be read or
/// parsed is a failure with its reason, and is not counted as looked at.
pub fn look(checkout: &Path, rel: &str) -> Look {
    let mut look = Look::default();
    let shown = format!("{rel}/{TASKS}");
    let path = checkout.join(TASKS);
    let link = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return look,
        Err(e) => {
            look.failed.push((shown, e.to_string()));
            return look;
        }
        Ok(m) if m.file_type().is_symlink() => std::fs::read_link(&path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned()),
        Ok(_) => None,
    };
    let decided = read(&path).and_then(|bytes| Ok((runs_on_open(&bytes)?, bytes)));
    match decided {
        Err(why) => look.failed.push((shown, why)),
        Ok((runs, bytes)) => {
            look.present += 1;
            if runs {
                look.entries.push(Entry {
                    path: shown,
                    watched_as: RUNS_ON_OPEN,
                    content: Content::Hash(format!("sha256:{}", crate::sha256::hex(&bytes))),
                    link,
                });
            }
        }
    }
    look
}

/// A regular file's bytes, opened without waiting, up to the cap; else why not.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    read_capped(path, CAP)
}

/// The same with a cap of the caller's.
pub fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("not a regular file".to_string());
    }
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > cap {
        return Err(format!("over the size cap of {} KiB", cap >> 10));
    }
    Ok(bytes)
}

/// Whether a task file holds a task set to run when the folder is opened; an error when it
/// cannot be read as JSON with comments.
pub fn runs_on_open(bytes: &[u8]) -> Result<bool, String> {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    // Inside a list, so that a file of comments only is an empty list and not an error. The
    // line break keeps a comment on the last line from swallowing the bracket; none is added
    // before, so that the lines Foundation names are the file's own.
    let mut wrapped = b"[".to_vec();
    wrapped.extend_from_slice(text);
    wrapped.extend_from_slice(b"\n]");
    crate::json5::reads(&wrapped)?;
    let lower = text.to_ascii_lowercase();
    let says = |word: &[u8]| lower.windows(word.len()).any(|w| w == word);
    Ok(says(b"folderopen") || says(b"\\u"))
}

/// The other ways of `OTHERS` that are present in a checkout, by name. One that cannot be
/// looked at is named too: it may be there.
pub fn others(checkout: &Path) -> Vec<&'static str> {
    OTHERS
        .iter()
        .filter(|(path, _)| {
            !matches!(std::fs::symlink_metadata(checkout.join(path)),
                      Err(e) if e.kind() == ErrorKind::NotFound)
        })
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_set_to_run_on_opening_is_found_however_the_file_is_written() {
        // As editors write it: comments, a trailing comma, the value in another case, and the
        // task under a platform's own settings.
        let file = br#"{
            // See https://go.microsoft.com/fwlink/?LinkId=733558
            "version": "2.0.0",
            "tasks": [
                { "label": "build", "type": "shell", "command": "make" },
                {
                    "label": "setup",
                    "osx": { "runOptions": { "runOn": "FOLDEROPEN" } }, /* here */
                },
            ]
        }"#;
        assert_eq!(runs_on_open(file), Ok(true));
        let plain = br#"{"version": "2.0.0", "tasks": [{"label": "build", "command": "make"}]}"#;
        assert_eq!(runs_on_open(plain), Ok(false));
        let default = br#"{"tasks": [{"label": "a", "runOptions": {"runOn": "default"}}]}"#;
        assert_eq!(runs_on_open(default), Ok(false));
    }

    #[test]
    fn where_foundation_and_the_editor_could_differ_the_file_is_taken_as_holding_a_task() {
        // Foundation keeps the first of two equal keys, the editor the last.
        let twice = br#"{"tasks": [{"runOptions": {"runOn": "default", "runOn": "folderOpen"}}]}"#;
        assert_eq!(runs_on_open(twice), Ok(true));
        // An escape spells the word unlike its letters.
        let escaped = b"{\"tasks\": [{\"runOptions\": {\"runOn\": \"default\", \"runOn\": \"folder\\u004Fpen\"}}]}";
        assert!(
            !escaped
                .windows(10)
                .any(|w| w.eq_ignore_ascii_case(b"folderopen"))
        );
        assert_eq!(runs_on_open(escaped), Ok(true));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_and_one_of_comments_only_holds_no_task() {
        assert!(runs_on_open(b"{\"tasks\": [ {\"label\": } ]}").is_err());
        assert!(runs_on_open(b"{} {}").is_err());
        assert_eq!(runs_on_open(b"// nothing yet"), Ok(false));
        assert_eq!(runs_on_open(b"\xEF\xBB\xBF{}"), Ok(false));
    }
}
