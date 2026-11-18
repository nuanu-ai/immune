//! Tells the hook folder Git's configuration names for an ordinary working tree. Git parses
//! bounded copies of the configuration files and is never given a checkout to open; an include
//! is followed here, one bounded copy at a time. `.git/hooks` is read whatever this tells
//! (`watched::look_checkout`): the folder it names is only read besides.

use crate::guarded::{self, Real};
use crate::look::Absent;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const CAP: u64 = 1024 * 1024;
const KEY: &[u8] = b"core.hookspath";
const SYSTEM_CONFIG: &str = "etc/gitconfig";
/// Git stops at a deeper include (`MAX_INCLUDE_DEPTH` in Git's `config.c`).
const INCLUDE_DEPTH: usize = 10;
const UNPARSED: &str = "Git could not parse a configuration file";

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

/// The hooks Git runs in the Git directory during a push, `reference-transaction` among them.
pub const RECEIVE_HOOKS: &[&str] = &[
    "post-receive",
    "post-update",
    "pre-receive",
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
    sources: [PathBuf; 3],
    inherited: Setting,
}

impl Config {
    /// The files Git reads for every repository, found as Git finds them with only `HOME` set.
    /// This process's own environment is not taken: the login job's has no `XDG_CONFIG_HOME`.
    pub fn new(home: &Path, system: &Path, homes: &[&Path]) -> Self {
        let sources = [
            system.join(SYSTEM_CONFIG),
            home.join(".config/git/config"),
            home.join(".gitconfig"),
        ];
        let mut inherited = Setting::Unset;
        for source in &sources {
            apply(source, home, homes, &[], &mut inherited, 0);
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
        if !std::fs::symlink_metadata(git_dir.join("commondir"))
            .is_err_and(|e| Absent::of(&e).is_some())
        {
            return failed("Git uses a separate common directory");
        }
        let mut setting = self.inherited.clone();
        let (mut moved, worktree_config) =
            apply(&git_dir.join("config"), home, homes, given, &mut setting, 0);
        // As `git sparse-checkout` sets it: Git then reads `config.worktree` after `config`.
        if worktree_config {
            let worktree = git_dir.join("config.worktree");
            moved |= apply(&worktree, home, homes, given, &mut setting, 0).0;
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
            Setting::Path(path) if moved && path.is_relative() => failed(
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
/// names a hook folder. Returns whether the file itself moves the working tree
/// (`core.worktree`, a true `core.bare`) and turns on `config.worktree`
/// (`extensions.worktreeConfig`), which Git takes from a repository's own files only.
fn apply(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
    setting: &mut Setting,
    depth: usize,
) -> (bool, bool) {
    let mut layout = (false, false);
    let keys = match config(path, home, homes, given) {
        Ok(Some(keys)) => keys,
        Ok(None) => return layout,
        Err(why) => {
            *setting = Setting::Unavailable(why);
            return layout;
        }
    };
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
                None => Setting::Unavailable(Unread::Failed("core.hooksPath has no value".into())),
            };
        } else if include || key.starts_with(b"includeif.") && key.ends_with(b".path") {
            let refused = |why: String| Setting::Unavailable(Unread::Failed(why));
            let included = match value.map(|value| expand(value, home)) {
                // Git refuses the whole configuration then.
                _ if depth >= INCLUDE_DEPTH => Err(refused(format!(
                    "Git configuration includes are nested deeper than the {INCLUDE_DEPTH} levels Git allows"
                ))),
                None => Err(refused("an include path has no value".into())),
                Some(Err(why)) => Err(unknown(format!("an include path {why}"))),
                Some(Ok(to)) => Ok(path.parent().unwrap_or(path).join(to)),
            };
            let included = match included {
                Ok(included) => included,
                Err(untold) => {
                    *setting = untold;
                    continue;
                }
            };
            if include {
                apply(&included, home, homes, given, setting, depth + 1);
                continue;
            }
            let mut probe = Setting::Unset;
            apply(&included, home, homes, given, &mut probe, depth + 1);
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
        } else if key == b"core.worktree" || key == b"core.bare" && is_true(value) {
            layout.0 = true;
        } else if key == b"extensions.worktreeconfig" {
            layout.1 = is_true(value);
        }
    }
    layout
}

/// A Git boolean as Git reads it: a key with no value is true.
fn is_true(value: Option<&[u8]>) -> bool {
    !value.is_some_and(|v| {
        [b"false".as_slice(), b"no", b"off", b"0", b""]
            .iter()
            .any(|x| v.eq_ignore_ascii_case(x))
    })
}

fn config(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
) -> Result<Option<Vec<u8>>, Unread> {
    let failed = |why: &str| Unread::Failed(why.to_string());
    let at = match guarded::real_in(path, homes, given) {
        Real::At(at) => at,
        Real::Guarded(g) => return Err(Unread::Guarded(g)),
        Real::Failed(e) if Absent::on_the_way(&e).is_some() => return Ok(None),
        Real::Failed(_) => return Err(failed("a Git configuration file could not be reached")),
    };
    // Do not open a special file. The capped reader also checks what it opened and
    // uses O_NONBLOCK in case the file is replaced between the check and the open.
    if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_file() && m.len() <= CAP) {
        return Err(failed(
            "a Git configuration file is not a regular file within the size cap of 1 MiB",
        ));
    }
    let bytes = crate::autorun::read_capped_resolved(&at, CAP).map_err(|_| {
        failed("a Git configuration file could not be read within the size cap of 1 MiB")
    })?;
    if bytes.contains(&0) {
        return Err(failed(UNPARSED));
    }
    git_config(home, &bytes).map(Some).map_err(failed)
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

/// The records Git parses from `bytes`, or why there are none.
fn git_config(home: &Path, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    // /usr/bin/git is a developer-tools shim on Macs without those tools. Ask for the
    // selected installation without invoking the shim or prompting to install it.
    static GIT: OnceLock<Option<PathBuf>> = OnceLock::new();
    let git = GIT
        .get_or_init(|| {
            let selected = Command::new("/usr/bin/xcode-select")
                .env_clear()
                .current_dir("/")
                .arg("--print-path")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            let root = std::str::from_utf8(&selected.stdout)
                .ok()?
                .trim_end_matches('\n');
            let git = Path::new(root).join("usr/bin/git");
            (selected.status.success() && git.is_absolute() && git.is_file()).then_some(git)
        })
        .as_ref()
        .ok_or("Git is not installed: macOS names no developer tools that hold it")?;
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
        return Err("Git could not be run");
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
        parsed_whole.then_some(parsed).ok_or(UNPARSED)
    })
}
