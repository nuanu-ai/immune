//! Resolves the hook folder used by Git commands in an ordinary working tree. Git parses
//! bounded copies of the configuration files. It is never given a checkout to open or
//! asked to follow an include.

use crate::guarded::{self, Real};
use crate::look::Absent;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const CAP: u64 = 1024 * 1024;
const KEY: &[u8] = b"core.hookspath";
const SYSTEM_CONFIG: &str = "etc/gitconfig";
pub const DEFAULT: &str = ".git/hooks";

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

pub const RECEIVE_HOOKS: &[&str] = &[
    "post-receive",
    "post-update",
    "pre-receive",
    "proc-receive",
    "push-to-checkout",
    "update",
];

#[derive(Clone)]
pub enum Unread {
    Failed(&'static str),
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

/// How a checkout's active hook folder is reached.
pub enum Folder {
    Default,
    Configured { worktree: PathBuf, receive: PathBuf },
    Disabled,
    Unknown(Unread),
}

/// Shared Git configuration, read once per pass, in Git's order of precedence.
pub struct Config {
    sources: [PathBuf; 3],
    inherited: Setting,
}

impl Config {
    pub fn new(home: &Path, system: &Path, homes: &[&Path]) -> Self {
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let sources = [
            system.join(SYSTEM_CONFIG),
            xdg.join("git/config"),
            home.join(".gitconfig"),
        ];
        let mut inherited = Setting::Unset;
        for source in &sources {
            if source.is_absolute() {
                apply(source, home, homes, &[], &mut inherited, false);
            } else if !matches!(inherited, Setting::Unavailable(_)) {
                inherited = Setting::Unknown(Unread::Failed("Git uses a relative XDG_CONFIG_HOME"));
            }
        }
        Self { sources, inherited }
    }

    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }

    pub fn folder(&self, checkout: &Path, home: &Path, homes: &[&Path], given: &[&Path]) -> Folder {
        let dotgit = checkout.join(".git");
        let git_dir = match guarded::real_in(&dotgit, homes, given) {
            Real::At(at) => match std::fs::symlink_metadata(&at) {
                Ok(meta) if meta.is_dir() => at,
                Ok(_) => return Folder::Unknown(Unread::GitFile),
                Err(_) => return Folder::Unknown(Unread::Failed("could not read .git")),
            },
            Real::Guarded(g) => return Folder::Unknown(Unread::Guarded(g)),
            Real::Failed(e) if Absent::of(&e).is_some() => return Folder::Default,
            Real::Failed(_) => return Folder::Unknown(Unread::Failed("could not reach .git")),
        };
        // A separate common directory changes both the default path and where Git reads
        // repository configuration. Leave that checkout's earlier reading in place.
        if !std::fs::symlink_metadata(git_dir.join("commondir"))
            .is_err_and(|e| Absent::of(&e).is_some())
        {
            return Folder::Unknown(Unread::Failed("Git uses a separate common directory"));
        }
        let mut setting = self.inherited.clone();
        apply(
            &git_dir.join("config"),
            home,
            homes,
            given,
            &mut setting,
            true,
        );
        match setting {
            Setting::Unset => Folder::Default,
            Setting::Unknown(why) | Setting::Unavailable(why) => Folder::Unknown(why),
            Setting::Path(path) if path == Path::new("/dev/null") => Folder::Disabled,
            // Git appends `/hook-name` to an empty value, so it looks in `/`.
            Setting::Path(path) if path.as_os_str().is_empty() => Folder::Configured {
                worktree: "/".into(),
                receive: "/".into(),
            },
            Setting::Path(path) => Folder::Configured {
                worktree: checkout.join(&path),
                receive: git_dir.join(path),
            },
        }
    }
}

/// An include can shadow earlier values. A configuration file that cannot be read or
/// parsed blocks the whole reading, even when another file specifies a hook folder.
fn apply(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
    setting: &mut Setting,
    local: bool,
) {
    if matches!(setting, Setting::Unavailable(_)) {
        return;
    }
    let keys = match config(path, home, homes, given) {
        Ok(Some(keys)) => keys,
        Ok(None) => return,
        Err(why) => {
            *setting = Setting::Unavailable(why);
            return;
        }
    };
    for (key, value) in records(&keys) {
        if key == KEY {
            *setting = match value {
                Some(value) => hooks_path(value, home),
                None => {
                    *setting = Setting::Unavailable(Unread::Failed("core.hooksPath has no value"));
                    return;
                }
            };
        } else if key == b"include.path"
            || key.starts_with(b"includeif.") && key.ends_with(b".path")
        {
            *setting = Setting::Unknown(Unread::Failed(
                "a Git config include may set core.hooksPath",
            ));
        }
        if local
            && (key == b"core.worktree"
                || matches!(key, b"core.bare" | b"extensions.worktreeconfig")
                    && !value.is_some_and(|v| {
                        [b"false".as_slice(), b"no", b"off", b"0", b""]
                            .iter()
                            .any(|x| v.eq_ignore_ascii_case(x))
                    }))
        {
            *setting = Setting::Unknown(Unread::Failed(
                "Git uses separate working tree configuration",
            ));
            return;
        }
    }
}

fn config(
    path: &Path,
    home: &Path,
    homes: &[&Path],
    given: &[&Path],
) -> Result<Option<Vec<u8>>, Unread> {
    let at = match guarded::real_in(path, homes, given) {
        Real::At(at) => at,
        Real::Guarded(g) => return Err(Unread::Guarded(g)),
        Real::Failed(e) if Absent::on_the_way(&e).is_some() => return Ok(None),
        Real::Failed(_) => return Err(Unread::Failed("could not reach a Git configuration file")),
    };
    // Do not open a special file. The capped reader also checks what it opened and
    // uses O_NONBLOCK in case the file is replaced between the check and the open.
    if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_file() && m.len() <= CAP) {
        return Err(Unread::Failed(
            "Git configuration is not a regular file within the size cap of 1 MiB",
        ));
    }
    let bytes = crate::autorun::read_capped_resolved(&at, CAP).map_err(|_| {
        Unread::Failed("could not read a Git configuration file within the size cap of 1 MiB")
    })?;
    let output = (!bytes.contains(&0))
        .then(|| git_config(home, &bytes))
        .flatten()
        .ok_or(Unread::Failed(
            "Apple Git could not parse a configuration file",
        ))?;
    Ok(Some(output))
}

/// `git config --null --list` separates records with NUL and a key from its
/// value with the first newline. A key with an implicit boolean value has no newline.
fn records(bytes: &[u8]) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> {
    bytes.split(|&b| b == 0).map(|entry| {
        let mut record = entry.splitn(2, |&b| b == b'\n');
        (record.next().unwrap_or_default(), record.next())
    })
}

fn hooks_path(value: &[u8], home: &Path) -> Setting {
    if value.len() >= libc::PATH_MAX as usize {
        return Setting::Unknown(Unread::Failed(
            "core.hooksPath exceeds the macOS path limit",
        ));
    }
    let Ok(value) = std::str::from_utf8(value) else {
        return Setting::Unknown(Unread::Failed("core.hooksPath is not UTF-8"));
    };
    if let Some(rest) = value.strip_prefix("~/") {
        return Setting::Path(home.join(rest.trim_start_matches('/')));
    }
    if value.starts_with('~') || value.starts_with("%(prefix)/") {
        return Setting::Unknown(Unread::Failed(
            "core.hooksPath requests an unsupported Git path expansion",
        ));
    }
    Setting::Path(value.into())
}

fn git_config(home: &Path, bytes: &[u8]) -> Option<Vec<u8>> {
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
        .as_ref()?;
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
        .ok()?;
    let mut input = child.stdin.take()?;
    let mut output = child.stdout.take()?.take(CAP + 1);
    // Drain output while writing input, even if Git prints before it consumes the file.
    std::thread::scope(|s| {
        let write = s.spawn(move || input.write_all(bytes));
        let mut parsed = Vec::new();
        let complete = output.read_to_end(&mut parsed).is_ok() && parsed.len() as u64 <= CAP;
        if !complete {
            let _ = child.kill();
        }
        let status = child.wait().ok()?;
        write.join().ok()?.ok()?;
        (complete && status.success()).then_some(parsed)
    })
}
