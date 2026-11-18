//! Tells the hook folder Git's configuration names for an ordinary working tree. Git parses
//! bounded copies of the configuration files and is never given a checkout to open; an include
//! is followed here, one bounded copy at a time. `.git/hooks` is read whatever this tells
//! (`watched::look_checkout`): the folder it names is only read besides.

use crate::guarded::{self, Real};
use crate::look::Absent;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

const CAP: u64 = 1024 * 1024;
const KEY: &[u8] = b"core.hookspath";
const SYSTEM_CONFIG: &str = "etc/gitconfig";
/// Apple Git's own file, in the developer folder, read before the system file.
const APPLE_CONFIG: &str = "usr/share/git-core/gitconfig";
/// Git refuses an included file deeper than this (`MAX_INCLUDE_DEPTH` in Git's `config.c`).
const INCLUDE_DEPTH: usize = 10;
/// The configuration files one resolution reads at most, includes counted: an honest
/// configuration reads a handful, and includes that fan out would cost a Git run each.
const BUDGET: usize = 64;
const UNPARSED: &str = "Git could not parse a configuration file";
const ODD_WORD: &str = "core.bare, extensions.worktreeConfig or core.repositoryformatversion has a value this reader does not read";

/// The names Git documents for hooks it runs itself, from githooks(5). A configured
/// folder might be the worktree, the home folder or `/`. Only these names are examined
/// there, so its other contents have no effect on the reading or the subscriptions.
pub const WORKTREE_HOOKS: &[&str] = &[
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "p4-prepare-changelist",
    "post-applypatch",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-rewrite",
    "pre-applypatch",
    "pre-auto-gc",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "prepare-commit-msg",
    "reference-transaction",
    "sendemail-validate",
];

/// The hooks Git runs in the Git directory during a push, `reference-transaction` and
/// `pre-auto-gc` among them.
pub const RECEIVE_HOOKS: &[&str] = &[
    "post-receive",
    "post-update",
    "pre-receive",
    // `git receive-pack` runs `git gc --auto` after a push.
    "pre-auto-gc",
    "proc-receive",
    "push-to-checkout",
    "reference-transaction",
    "update",
];

#[derive(Clone)]
pub enum Unread {
    Failed(String),
    Guarded(PathBuf),
    GitFile,
}

#[derive(Clone, Default)]
enum Setting {
    #[default]
    Unset,
    Path(PathBuf),
    Unknown(Unread),
    Unavailable(Unread),
}

/// The folder Git's configuration names for a checkout's hooks.
pub enum Folder {
    /// None, or `/dev/null`: only `.git/hooks`, which is read in every case.
    Default,
    Configured {
        worktree: PathBuf,
        receive: PathBuf,
    },
    Unknown(Unread),
}

impl Folder {
    /// Each folder a configured `core.hooksPath` leads to, with the names of the hooks Git
    /// runs from it: from the working tree, and from the Git directory during a push.
    pub fn configured(&self) -> Vec<(&Path, &'static [&'static str])> {
        match self {
            Folder::Configured { worktree, receive } => {
                vec![(worktree, WORKTREE_HOOKS), (receive, RECEIVE_HOOKS)]
            }
            _ => Vec::new(),
        }
    }
}

/// Shared Git configuration, read once per pass, in Git's order of precedence.
pub struct Config {
    sources: Vec<PathBuf>,
    inherited: Setting,
}

impl Config {
    /// The files Git reads for every repository, found as Git finds them with only `HOME` set:
    /// Apple Git's own file in the developer folder, the system file and the user's two.
    /// This process's own environment is not taken: the login job's has no `XDG_CONFIG_HOME`.
    pub fn new(home: &Path, system: &Path, homes: &[&Path]) -> Self {
        let developer = developer_dir();
        let apple = developer.as_deref().map(|dir| {
            let dir = dir.strip_prefix("/").unwrap_or(dir);
            system.join(dir).join(APPLE_CONFIG)
        });
        *DEVELOPER.lock().unwrap_or_else(|e| e.into_inner()) = developer;
        let sources: Vec<PathBuf> = apple
            .into_iter()
            .chain([
                system.join(SYSTEM_CONFIG),
                home.join(".config/git/config"),
                home.join(".gitconfig"),
            ])
            .collect();
        let mut inherited = Setting::Unset;
        let mut budget = BUDGET;
        for source in &sources {
            apply(source, home, homes, &[], &mut inherited, 0, &mut budget);
        }
        Self { sources, inherited }
    }

    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }

    pub fn folder(&self, checkout: &Path, home: &Path, homes: &[&Path], given: &[&Path]) -> Folder {
        let failed = |why: &str| Folder::Unknown(Unread::Failed(why.to_string()));
        let dotgit = checkout.join(".git");
        let git_dir = match guarded::real_in(&dotgit, homes, given) {
            Real::At(at) => match std::fs::symlink_metadata(&at) {
                Ok(meta) if meta.is_dir() => at,
                Ok(_) => return Folder::Unknown(Unread::GitFile),
                Err(_) => return failed("could not read .git"),
            },
            Real::Guarded(g) => return Folder::Unknown(Unread::Guarded(g)),
            Real::Failed(e) if Absent::of(&e).is_some() => return Folder::Default,
            Real::Failed(_) => return failed("could not reach .git"),
        };
        // A separate common directory holds the configuration and the default hooks Git uses.
        match std::fs::symlink_metadata(git_dir.join("commondir")) {
            Ok(_) => return failed("Git uses a separate common directory"),
            Err(e) if Absent::of(&e).is_none() => return failed("could not read .git"),
            Err(_) => {}
        }
        let mut setting = self.inherited.clone();
        let mut budget = BUDGET;
        let mut apply = |path: &Path, setting: &mut Setting| {
            apply(path, home, homes, given, setting, 0, &mut budget)
        };
        let local = apply(&git_dir.join("config"), &mut setting);
        // Git takes `extensions.worktreeConfig`, as `git sparse-checkout` sets it, only beside
        // a format version of 0 or 1, and then reads `config.worktree` after `config`.
        let worktree_config = match (
            last(&local, b"core.repositoryformatversion"),
            last(&local, b"extensions.worktreeconfig"),
        ) {
            (None, _) | (_, None) => Some(false),
            (Some(Some(b"0" | b"1")), Some(value)) => boolean(value),
            _ => None,
        };
        let worktree = match worktree_config {
            None => return failed(ODD_WORD),
            Some(true) => apply(&git_dir.join("config.worktree"), &mut setting),
            Some(false) => Vec::new(),
        };
        // `core.worktree`, or a true `core.bare`, moves the working tree; the later file wins.
        let (mut worktree_set, mut bare) = (false, false);
        for keys in [&local, &worktree] {
            worktree_set |= last(keys, b"core.worktree").is_some();
            if let Some(value) = last(keys, b"core.bare") {
                let Some(value) = boolean(value) else {
                    return failed(ODD_WORD);
                };
                bare = value;
            }
        }
        match setting {
            Setting::Unset => Folder::Default,
            Setting::Unknown(why) | Setting::Unavailable(why) => Folder::Unknown(why),
            Setting::Path(path) if path == Path::new("/dev/null") => Folder::Default,
            // Git appends `/hook-name` to an empty value, so it looks in `/`.
            Setting::Path(path) if path.as_os_str().is_empty() => Folder::Configured {
                worktree: "/".into(),
                receive: "/".into(),
            },
            Setting::Path(path) if (worktree_set || bare) && path.is_relative() => failed(
                "core.worktree or core.bare moves the folder a relative core.hooksPath starts from",
            ),
            Setting::Path(path) => Folder::Configured {
                worktree: checkout.join(&path),
                receive: git_dir.join(path),
            },
        }
    }
}

/// Applies one configuration file to `setting` in Git's order: an include's values land where
/// the include stands, to the depth Git allows. An `includeIf` is followed without evaluating
/// its condition, so it changes the answer only when what it includes names a hook folder.
/// A file that cannot be read or parsed blocks the whole reading, even when another file
/// names a hook folder, and so does reading more than `BUDGET` files for one resolution.
/// Returns the file's own records.
fn apply(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
    setting: &mut Setting,
    depth: usize,
    budget: &mut usize,
) -> Vec<u8> {
    let refused = |why: String| Setting::Unavailable(Unread::Failed(why));
    let Some(left) = budget.checked_sub(1) else {
        *setting = refused(format!(
            "more than {BUDGET} Git configuration files are included"
        ));
        return Vec::new();
    };
    *budget = left;
    let keys = match config(path, home, homes, given) {
        Ok(Some(keys)) => keys,
        Ok(None) => return Vec::new(),
        Err(why) => {
            *setting = Setting::Unavailable(why);
            return Vec::new();
        }
    };
    // Git skips a missing file at any depth and refuses one that is there.
    if depth > INCLUDE_DEPTH {
        *setting = refused(format!(
            "Git configuration includes go more than {INCLUDE_DEPTH} levels deep"
        ));
        return Vec::new();
    }
    let unknown = |why: String| Setting::Unknown(Unread::Failed(why));
    for (key, value) in records(&keys) {
        if matches!(setting, Setting::Unavailable(_)) {
            break;
        }
        let include = key == b"include.path";
        if key == KEY {
            *setting = match value.map(|value| expand(value, home)) {
                Some(Ok(path)) => Setting::Path(path),
                Some(Err(why)) => unknown(format!("core.hooksPath {why}")),
                None => refused("core.hooksPath has no value".into()),
            };
        } else if include || key.starts_with(b"includeif.") && key.ends_with(b".path") {
            let included = match value.map(|value| expand(value, home)) {
                Some(Ok(to)) => path.parent().unwrap_or(path).join(to),
                Some(Err(why)) => {
                    *setting = unknown(format!("an include path {why}"));
                    continue;
                }
                None => {
                    *setting = refused("an include path has no value".into());
                    continue;
                }
            };
            if include {
                apply(&included, home, homes, given, setting, depth + 1, budget);
                continue;
            }
            let mut probe = Setting::Unset;
            apply(&included, home, homes, given, &mut probe, depth + 1, budget);
            match probe {
                Setting::Unset => {}
                Setting::Path(_) => {
                    *setting = unknown(
                        "an includeIf sets core.hooksPath, and its condition is not evaluated here"
                            .into(),
                    )
                }
                Setting::Unknown(why) | Setting::Unavailable(why) => {
                    *setting = Setting::Unknown(why)
                }
            }
        }
    }
    keys
}

/// The last value of `key` among one file's records, `Some(None)` for a key with no value.
fn last<'a>(keys: &'a [u8], key: &[u8]) -> Option<Option<&'a [u8]>> {
    records(keys)
        .filter(|(k, _)| *k == key)
        .last()
        .map(|(_, v)| v)
}

/// A Git boolean by the words Git documents, a key with no value being true. `None` for any
/// other value: Git reads numbers there by rules this reader does not follow.
fn boolean(value: Option<&[u8]>) -> Option<bool> {
    let Some(value) = value else {
        return Some(true);
    };
    let is = |words: &[&[u8]]| words.iter().any(|w| value.eq_ignore_ascii_case(w));
    if is(&[b"true", b"yes", b"on", b"1"]) {
        Some(true)
    } else if is(&[b"false", b"no", b"off", b"0", b""]) {
        Some(false)
    } else {
        None
    }
}

fn config(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
) -> Result<Option<Vec<u8>>, Unread> {
    let failed = |why: String| Unread::Failed(why);
    let at = match guarded::real_in(path, homes, given) {
        Real::At(at) => at,
        Real::Guarded(g) => return Err(Unread::Guarded(g)),
        Real::Failed(e) if Absent::on_the_way(&e).is_some() => return Ok(None),
        Real::Failed(e) => {
            return Err(failed(format!(
                "a Git configuration file could not be reached: {e}"
            )));
        }
    };
    // Do not open a special file. The capped reader also checks what it opened and
    // uses O_NONBLOCK in case the file is replaced between the check and the open.
    if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_file() && m.len() <= CAP) {
        return Err(failed(
            "a Git configuration file is not a regular file within the size cap of 1 MiB".into(),
        ));
    }
    let bytes = crate::autorun::read_capped_resolved(&at, CAP)
        .map_err(|e| failed(format!("a Git configuration file could not be read: {e}")))?;
    // A NUL in a value would read as a record of its own in Git's `--null` listing.
    if bytes.contains(&0) {
        return Err(failed(UNPARSED.into()));
    }
    git_config(home, homes, &bytes).map(Some).map_err(failed)
}

/// `git config --null --list` separates records with NUL and a key from its
/// value with the first newline. A key with an implicit boolean value has no newline.
fn records(bytes: &[u8]) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> {
    bytes.split(|&b| b == 0).map(|entry| {
        let mut record = entry.splitn(2, |&b| b == b'\n');
        (record.next().unwrap_or_default(), record.next())
    })
}

/// A path from Git's configuration as Git expands it, or what keeps it from being told here:
/// only `~/` is expanded.
fn expand(value: &[u8], home: &Path) -> Result<PathBuf, &'static str> {
    if value.len() >= libc::PATH_MAX as usize {
        return Err("exceeds the macOS path limit");
    }
    let value = std::str::from_utf8(value).map_err(|_| "is not UTF-8")?;
    if value.starts_with(":(") {
        return Err("uses unsupported path magic");
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(home.join(rest.trim_start_matches('/')));
    }
    if value.starts_with('~') || value.starts_with("%(prefix)/") {
        return Err("requests an unsupported Git path expansion");
    }
    Ok(value.into())
}

/// The developer folder `xcode-select` named when the shared configuration was last read.
static DEVELOPER: Mutex<Option<PathBuf>> = Mutex::new(None);

/// The developer folder `xcode-select` names. /usr/bin/git is a developer-tools shim on Macs
/// without those tools; this finds the installation without invoking the shim or prompting
/// to install it. Asked for every pass: a watcher outlives a switch of developer tools.
fn developer_dir() -> Option<PathBuf> {
    let selected = Command::new("/usr/bin/xcode-select")
        .env_clear()
        .current_dir("/")
        .arg("--print-path")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let dir = std::str::from_utf8(&selected.stdout)
        .ok()?
        .trim_end_matches('\n');
    let dir = PathBuf::from(dir);
    (selected.status.success() && dir.is_absolute()).then_some(dir)
}

/// Git in the developer folder, or why it is not run: running it from a folder macOS asks
/// permission for would enter that folder.
fn git_in(dir: Option<&Path>, home: &Path, homes: &[&Path]) -> Result<PathBuf, String> {
    let not_installed = "Git is not installed: macOS names no developer tools that hold it";
    let git = dir.ok_or(not_installed)?.join("usr/bin/git");
    match guarded::real_in(&git, homes, &[]) {
        Real::At(git) if git.is_file() => Ok(git),
        Real::Guarded(g) => {
            let shown = guarded::shown(&g, home);
            Err(format!(
                "Git is in {shown}, which macOS asks permission for"
            ))
        }
        _ => Err(not_installed.into()),
    }
}

/// The records Git parses from `bytes`, or why there are none.
fn git_config(home: &Path, homes: &[&Path], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let developer = DEVELOPER.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let git = git_in(developer.as_deref(), home, homes)?;
    let mut child = Command::new(git)
        .current_dir("/")
        .env_clear()
        .env("HOME", home)
        // Git's Trace2 startup looks at protected config, even with `--file -`.
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_DIR", "/dev/null")
        .args([
            "--no-pager",
            "config",
            "--file",
            "-",
            "--no-includes",
            "--null",
        ])
        // Listing streams records. A matching query first accumulates them in Git.
        .arg("--list")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Git could not be run")?;
    let (Some(mut input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("Git could not be run".into());
    };
    let mut output = output.take(CAP + 1);
    // Drain output while writing input, even if Git prints before it consumes the file.
    std::thread::scope(|s| {
        let write = s.spawn(move || input.write_all(bytes));
        let mut parsed = Vec::new();
        let complete = output.read_to_end(&mut parsed).is_ok() && parsed.len() as u64 <= CAP;
        if !complete {
            let _ = child.kill();
        }
        let status = child.wait();
        let written = write.join().is_ok_and(|w| w.is_ok());
        let parsed_whole = complete && written && status.is_ok_and(|s| s.success());
        parsed_whole.then_some(parsed).ok_or(UNPARSED.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_in_a_folder_macos_asks_permission_for_is_not_run() {
        let home = Path::new("/Users/someone");
        let dir = home.join("Documents/Xcode.app/Contents/Developer");
        let why = git_in(Some(&dir), home, &[home]).unwrap_err();
        assert_eq!(
            why,
            "Git is in ~/Documents, which macOS asks permission for"
        );
    }
}
