//! `immune install` and `immune uninstall`: the core as a login job of this user.
//!
//! Install registers the core with launchd as the job `ai.nuanu.immune.watch`, which runs
//! `watch --background`. Which file the job runs depends on who can replace the core install was
//! run from (`root_only`):
//! - only root, as for a core a signed package put in a folder owned by root: the job runs it
//!   where it is and nothing is copied. A copy in the home folder would undo that protection, since
//!   any program of the account could replace it, and an update of the package would never reach
//!   the job. A copy an earlier install left is removed once the old job is stopped;
//! - anyone else as well, as for a build in a checkout: install copies the core to `bin/immune` in
//!   the store's folder and the job runs the copy, so a rebuild, another branch or a removed
//!   checkout does not touch the running core, and no other account chooses what the job runs.
//!
//! The watcher the job runs leaves by itself when the file it was started from is replaced, and
//! launchd starts it again from the new one (`watch.rs`). Uninstall stops the job and removes its
//! property list and the copy, never a core the job ran where it is, and keeps the store and the
//! event collector. After the job is loaded, install waits a few seconds for a watcher to watch
//! the store live, and says whether one did.
//!
//! The home folder is the account's own, from the user database, and never `$HOME`: the job
//! belongs to `gui/<uid>`, and launchd loads that user's `LaunchAgents` at login, so files found
//! through another home would not be the job's.
//!
//! These commands act, so their order is the point. Install:
//! - every refusal comes first, with nothing changed; one of the two commands runs at a time;
//! - then the property list and the copy are staged under temporary names beside their places;
//! - then the copy and then the property list are renamed into place, under the running job: the
//!   process keeps the old binary's inode and launchd the configuration it loaded, so the job is
//!   not stopped, and a file that cannot be replaced fails the install before anything is. The
//!   full checks the watcher starts, and a restart of the job, run the new copy from then on.
//!   The copy goes first, so a property list never names a core that is not there;
//! - then a loaded job is stopped and waited for until launchd no longer has it;
//! - then the job is registered again and confirmed.
//!
//! The installed file is never written in place, since a running job has it open: a new copy
//! replaces it by rename. What was staged under a temporary name is removed on every way out
//! but a kill, which leaves it.
//! A failure says what the command did and did not touch and what launchd answered, never what
//! the job does next: the command does not know what launchd will do. The answer says the job
//! is loaded only when `launchctl print` said so after it was registered.
//!
//! The property list is written by the system's `plutil`, never by hand, since a path can hold
//! `&` or `<`. `launchctl` and `plutil` are run by absolute path. For tests, `--launchctl` gives
//! a stand-in and `--home` another home folder; they go only together, so that a test that forgets
//! one of the two is refused before anything runs. No switch changes whether the core is run where
//! it is: the unit tests give `install` that judgement directly.

use crate::answer::{self, Form, Options};
use crate::contract::v1;
use crate::known::whole;
use std::ffi::{CStr, OsStr};
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The job's label in launchd.
pub const LABEL: &str = "ai.nuanu.immune.watch";
/// launchd's tool, where every Mac has it.
const LAUNCHCTL: &str = "/bin/launchctl";
/// The folder of the installed core inside the store's folder.
const BIN: &str = "bin";
/// The installed core's name in `BIN`.
const PROGRAM: &str = "immune";
/// Every failure of these commands exits with this code; the failure's `code` says which.
const EXIT_FAILED: u8 = 1;
/// What a failure after the stop adds, so a person and an agent know how to recover.
const RECOVER: &str = "; the core job may be stopped. The store was kept. The core and its property list are in place. Run immune install again to recover";
/// At most this many characters of another job's label are quoted in a failure.
const LABEL_QUOTED: usize = 200;
/// The menu-bar app's bundle identifier, the `CFBundleIdentifier` of its `Info.plist`, which is
/// kept with the app and not read from here: a change there must be made here too. The job names
/// it in `AssociatedBundleIdentifiers`, so that Login Items shows the job under the app when the
/// app is installed.
pub const APP_BUNDLE_ID: &str = "ai.nuanu.immune";
/// How long install waits after launchd loaded the job for a watcher to watch the store live, and
/// how often it looks meanwhile. launchd starts a loaded job at once, and a watcher's first reading
/// of the watched places takes a second or two on a Mac of ordinary size; past that the answer
/// says what the status says of the watcher, rather than keep the person waiting.
const WATCHER_WITHIN: Duration = Duration::from_secs(5);
const WATCHER_ASKED_EVERY: Duration = Duration::from_millis(200);

/// How long a job that was told to stop is given to leave launchd, and how long one whose stop
/// launchd refused; how often launchd is asked meanwhile. launchd gives a job 20 seconds after
/// it is told to stop before it kills it, so 30 is past that.
const LEAVES_WITHIN: Duration = Duration::from_secs(30);
const REFUSED_LEAVES_WITHIN: Duration = Duration::from_secs(2);
const ASKED_EVERY: Duration = Duration::from_millis(100);

/// Which of the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Install,
    Uninstall,
}

impl Verb {
    fn op(self) -> &'static str {
        match self {
            Verb::Install => "install",
            Verb::Uninstall => "uninstall",
        }
    }
}

/// `immune install` or `immune uninstall`.
pub struct ServiceArgs {
    pub verb: Verb,
    /// The launchctl to run instead of the system's.
    pub launchctl: PathBuf,
    /// The home folder to act in instead of the account's; only with a stand-in launchctl.
    pub home: Option<PathBuf>,
    pub form: Form,
}

pub fn parse(
    verb: Verb,
    it: impl Iterator<Item = String>,
    options: &mut Options,
) -> Result<ServiceArgs, String> {
    let (mut launchctl, mut home) = (None, None);
    options.read(it, |arg, it| {
        match arg.as_str() {
            "--launchctl" => launchctl = Some(PathBuf::from(crate::value(it, &arg)?)),
            "--home" => home = Some(PathBuf::from(crate::value(it, &arg)?)),
            _ => return Err(format!("unexpected argument: {arg}")),
        }
        Ok(())
    })?;
    if options.store_named() {
        return Err(format!(
            "immune {} takes no --store: the job runs with the store in its usual place",
            verb.op()
        ));
    }
    // A home of one's choosing with the real launchd, or a stand-in with the real home, would act
    // on the real Mac: the two are for tests and go only together.
    let launchctl = match (launchctl, &home) {
        (None, None) => PathBuf::from(LAUNCHCTL),
        (Some(launchctl), Some(_)) => launchctl,
        _ => return Err("--home and --launchctl are for tests and go only together".to_string()),
    };
    Ok(ServiceArgs {
        verb,
        launchctl,
        home,
        form: options.form(),
    })
}

/// Why a command stopped: the contract's `Error` parts.
struct Failed {
    code: &'static str,
    message: String,
    detail: String,
}

fn failed(code: &'static str, message: impl Into<String>, detail: impl Into<String>) -> Failed {
    Failed {
        code,
        message: message.into(),
        detail: detail.into(),
    }
}

/// The places these commands act on, for one home folder and one user.
struct Places {
    /// The lock on the home folder that lets one of the two commands run at a time, held while
    /// this lives.
    _lock: File,
    /// `gui/<uid>`, and the job in it.
    domain: String,
    job: String,
    home: PathBuf,
    agents: PathBuf,
    plist: PathBuf,
    bin: PathBuf,
    program: PathBuf,
    /// The store the job's watcher keeps, the default one under `home`.
    store: PathBuf,
}

/// Answers `immune install` or `immune uninstall` with `Service`, or fails with `Failure`.
pub fn service_cmd(args: &ServiceArgs) -> ExitCode {
    let op = args.verb.op();
    let home = args.home.as_deref();
    let done = match args.verb {
        Verb::Install => install(&args.launchctl, home, root_only),
        Verb::Uninstall => uninstall(&args.launchctl, home),
    };
    match done {
        Ok(m) => answer::print(op, args.form, &m, |m| {
            crate::after_run::service(m, &crate::screen::Screen::of_stdout())
        }),
        Err(f) => {
            let example = format!("immune {op} --json");
            answer::fail(
                op,
                args.form,
                answer::error(f.code, &f.message, &example, &f.detail),
                EXIT_FAILED,
            )
        }
    }
}

/// The home folder of the account `uid` from the user database, `pw_dir` of getpwuid_r(3). The
/// job belongs to `gui/<uid>` and launchd loads the `LaunchAgents` of that account's home at
/// login, so `$HOME`, which any caller sets, is not where its files are. None when the account
/// has no entry or no home.
fn account_home(uid: libc::uid_t) -> Option<PathBuf> {
    let mut buffer = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill in.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to memory that lives across the call, and the buffer's length
        // is the one given.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && buffer.len() < 1 << 20 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded, so pw_dir points to a string ending in NUL in `buffer`.
        let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
        return Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
}

/// The refusals both commands share, in order, before anything is changed: root, the home
/// folder, another of the two commands running, the login session, and what stands at the
/// property list's place and at `bin` and `bin/immune`. Returns the places, with the lock that
/// lets one command run at a time, and whether the property list is there.
fn refusals(launchctl: &Path, home: Option<&Path>) -> Result<(Places, bool), Failed> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err(failed(
            "run_as_root",
            "run this as the user being watched, without sudo; nothing was changed",
            "",
        ));
    }
    let home = home.map(Path::to_path_buf).or_else(|| account_home(uid));
    let Some(home) = home.filter(|h| h.is_absolute()) else {
        return Err(failed(
            "home_not_absolute",
            "this account has no home folder with an absolute path; nothing was changed",
            "",
        ));
    };
    // One of the two at a time: flock(2) on the home folder, which needs no file of its own and
    // goes when the process ends, however it ends.
    let lock = File::open(&home).map_err(|e| unreadable(&home, &e.to_string()))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(failed(
                "busy",
                "another immune install or uninstall is running; nothing was changed",
                "",
            ));
        }
        Err(TryLockError::Error(e)) => return Err(unreadable(&home, &e.to_string())),
    }
    let domain = format!("gui/{uid}");
    let store_folder = home.join(crate::STORE_FOLDER);
    let places = Places {
        _lock: lock,
        job: format!("{domain}/{LABEL}"),
        domain,
        agents: home.join("Library/LaunchAgents"),
        plist: home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")),
        bin: store_folder.join(BIN),
        program: store_folder.join(BIN).join(PROGRAM),
        store: store_folder.join(crate::STORE_FILE),
        home,
    };
    if let Err(said) = launchctl_run(launchctl, &["print", &places.domain]) {
        return Err(failed(
            "no_login_session",
            "this user's login session is not available to launchd; nothing was changed",
            said,
        ));
    }
    let plist_there = match fs::symlink_metadata(&places.plist) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(unreadable(&places.plist, &e.to_string())),
        Ok(m) if m.file_type().is_symlink() => return Err(link(&places.plist)),
        Ok(m) if !m.is_file() => return Err(not_a_file(&places.plist)),
        Ok(_) => {
            let label = plist_string(&places.plist, "Label")?;
            if label != LABEL {
                // The label is another program's text: it goes in the detail, never in the
                // core's words.
                let quoted: String = label.chars().take(LABEL_QUOTED).collect();
                return Err(failed(
                    "another_job",
                    "another job's property list stands where the core job's goes; nothing was changed",
                    format!("{}: Label {quoted}", places.plist.display()),
                ));
            }
            true
        }
    };
    match fs::symlink_metadata(&places.bin) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(unreadable(&places.bin, &e.to_string())),
        Ok(m) if m.file_type().is_symlink() => return Err(link(&places.bin)),
        Ok(m) if !m.is_dir() => {
            return Err(failed(
                "not_a_folder",
                "something other than a folder stands where the installed core's folder goes; nothing was changed",
                places.bin.display().to_string(),
            ));
        }
        Ok(_) => match fs::symlink_metadata(&places.program) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(unreadable(&places.program, &e.to_string())),
            Ok(m) if m.file_type().is_symlink() => return Err(link(&places.program)),
            Ok(m) if !m.is_file() => return Err(not_a_file(&places.program)),
            Ok(_) => {}
        },
    }
    Ok((places, plist_there))
}

fn link(path: &Path) -> Failed {
    failed(
        "symbolic_link",
        "refusing a symbolic link where the core job's files go; nothing was changed",
        path.display().to_string(),
    )
}

fn not_a_file(path: &Path) -> Failed {
    failed(
        "not_a_file",
        "something other than a file stands where the core job's files go; nothing was changed",
        path.display().to_string(),
    )
}

fn unreadable(path: &Path, said: &str) -> Failed {
    failed(
        "unreadable",
        "a place the core job's files go cannot be read; nothing was changed",
        format!("{}: {said}", path.display()),
    )
}

/// The string at `key` of the property list at `path`, read by the system's plutil.
fn plist_string(path: &Path, key: &str) -> Result<String, Failed> {
    let out = Command::new(crate::integrity::PLUTIL)
        .args(["-extract", key, "raw", "-expect", "string", "-n", "-o", "-"])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| unreadable(path, &e.to_string()))?;
    if !out.status.success() {
        return Err(unreadable(path, &said(&out)));
    }
    // With `-n` plutil adds no line feed, so every byte is the value's own. `-expect string`
    // refuses a value that is not a string: of a dictionary plutil would print the keys.
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What a tool said when it failed, stderr first.
fn said(out: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !err.is_empty() {
        return err;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        format!("exited with {}", out.status)
    } else {
        text
    }
}

/// Runs launchctl with `args`; what it said when it did not succeed.
fn launchctl_run(launchctl: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new(launchctl)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", launchctl.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(said(&out))
    }
}

/// Stops the loaded job and waits until launchd no longer has it.
///
/// launchd can answer a stop before the job is gone, and can refuse a stop that is already under
/// way; a job registered while the old one is still there is refused. So a stop is judged by
/// whether the job left and not by what `bootout` returned. One that launchd refused is given a
/// short time, one it took a longer one. What is returned when the job stayed is what launchd
/// said, or that it still has the job.
fn stop(launchctl: &Path, job: &str) -> Result<(), String> {
    let asked = launchctl_run(launchctl, &["bootout", job]);
    let within = if asked.is_ok() {
        LEAVES_WITHIN
    } else {
        REFUSED_LEAVES_WITHIN
    };
    let until = Instant::now() + within;
    loop {
        if launchctl_run(launchctl, &["print", job]).is_err() {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(asked.err().unwrap_or_else(|| {
                format!(
                    "launchd still had the job {} seconds after it took the stop; it may leave later",
                    within.as_secs()
                )
            }));
        }
        std::thread::sleep(ASKED_EVERY);
    }
}

/// Runs the system's plutil with `args` and then `path`.
fn plutil(args: &[&str], path: &Path) -> Result<(), String> {
    let out = Command::new(crate::integrity::PLUTIL)
        .args(args)
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(said(&out))
    }
}

/// What is staged under temporary names, removed when it goes out of scope unless it was moved
/// into place.
#[derive(Default)]
struct Staged {
    /// A folder inside `LaunchAgents` that holds the new property list.
    folder: Option<PathBuf>,
    /// A new copy of the core inside `bin`.
    copy: Option<PathBuf>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        if let Some(copy) = self.copy.take() {
            let _ = fs::remove_file(copy);
        }
        if let Some(folder) = self.folder.take() {
            let _ = fs::remove_dir_all(folder);
        }
    }
}

/// A name in `dir` that no file has, made from `stem`, this process and the time: the caller
/// creates it exclusively and tries again if another took it meanwhile.
fn temporary(dir: &Path, stem: &str, attempt: u32) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dir.join(format!(".{stem}.{}.{nanos}.{attempt}", std::process::id()))
}

/// Makes a new folder of mode 0700 under a temporary name in `dir`.
fn stage_folder(dir: &Path) -> io::Result<PathBuf> {
    let mut attempt = 0;
    loop {
        let path = temporary(dir, LABEL, attempt);
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => attempt += 1,
            Err(e) => return Err(e),
        }
    }
}

/// Writes the job's property list at `path` with plutil, key by key, and lints it.
fn write_plist(path: &Path, program: &Path, home: &Path) -> Result<(), String> {
    let text = |p: &Path| {
        p.to_str()
            .map(str::to_string)
            .ok_or_else(|| format!("{} is not UTF-8", p.display()))
    };
    let (program, home) = (text(program)?, text(home)?);
    let steps: [&[&str]; 15] = [
        &["-create", "xml1"],
        &["-insert", "Label", "-string", LABEL],
        &["-insert", "ProgramArguments", "-array"],
        &["-insert", "ProgramArguments.0", "-string", &program],
        &["-insert", "ProgramArguments.1", "-string", "watch"],
        &["-insert", "ProgramArguments.2", "-string", "--background"],
        &["-insert", "EnvironmentVariables", "-dictionary"],
        &["-insert", "EnvironmentVariables.HOME", "-string", &home],
        &["-insert", "StandardOutPath", "-string", "/dev/null"],
        &["-insert", "StandardErrorPath", "-string", "/dev/null"],
        &["-insert", "KeepAlive", "-bool", "YES"],
        &["-insert", "ThrottleInterval", "-integer", "30"],
        &["-insert", "AssociatedBundleIdentifiers", "-array"],
        &[
            "-insert",
            "AssociatedBundleIdentifiers.0",
            "-string",
            APP_BUNDLE_ID,
        ],
        &["-lint", "-s"],
    ];
    for step in steps {
        plutil(step, path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
}

/// Copies `source` to a new file of mode 0755 under a temporary name in `dir`, created
/// exclusively and synced.
fn stage_copy(source: &Path, dir: &Path) -> io::Result<PathBuf> {
    let mut from = File::open(source)?;
    let mut attempt = 0;
    let (path, mut to) = loop {
        let path = temporary(dir, PROGRAM, attempt);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
        {
            Ok(f) => break (path, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => attempt += 1,
            Err(e) => return Err(e),
        }
    };
    let written = io::copy(&mut from, &mut to)
        .and_then(|_| to.set_permissions(fs::Permissions::from_mode(0o755)))
        .and_then(|()| to.sync_all());
    match written {
        Ok(()) => Ok(path),
        Err(e) => {
            let _ = fs::remove_file(&path);
            Err(e)
        }
    }
}

/// The device and inode of a file, to tell whether two paths are one file.
fn identity(m: &fs::Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}

/// The running executable, which must be a regular file, and whether it is the installed copy
/// itself.
fn source(program: &Path) -> Result<(PathBuf, bool), Failed> {
    let not_file = |detail: String| {
        failed(
            "source_not_a_file",
            "the binary install was run from is not a regular file; nothing was changed",
            detail,
        )
    };
    let exe = std::env::current_exe().map_err(|e| not_file(e.to_string()))?;
    let exe = fs::canonicalize(&exe).map_err(|e| not_file(format!("{}: {e}", exe.display())))?;
    let m = fs::metadata(&exe).map_err(|e| not_file(format!("{}: {e}", exe.display())))?;
    if !m.is_file() {
        return Err(not_file(exe.display().to_string()));
    }
    // `refusals` has made sure that `bin/immune`, when it is there, is a regular file and no link.
    let same = fs::symlink_metadata(program).is_ok_and(|p| identity(&p) == identity(&m));
    Ok((exe, same))
}

/// What `lstat` gave of one part of a path: its owner and its mode, with the bits of its kind.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Part {
    uid: u32,
    mode: u32,
}

/// Whether only root can replace the file whose path's parts, from `/` to the file itself, are
/// `parts`, as `lstat` gave them for a path whose links were resolved: every part is owned by root
/// and writable by neither its group nor anyone else. A sticky folder anyone may write is passed,
/// since in it only root can replace a part root owns, which the part directly inside it must be
/// like every part. Which account runs the command plays no part: a core another account or a
/// group could replace would let them choose what the job runs as this user. A part that is a
/// symbolic link means the path was not resolved. With no parts there is nothing to judge, and
/// the core is copied, as it always was.
fn root_only_parts(parts: &[Part]) -> bool {
    let last = parts.len().saturating_sub(1);
    !parts.is_empty()
        && parts.iter().enumerate().all(|(i, part)| {
            let kind = part.mode & libc::S_IFMT as u32;
            let sticky = part.mode & libc::S_ISVTX as u32 != 0;
            part.uid == 0
                && kind != libc::S_IFLNK as u32
                && (part.mode & 0o022 == 0 || (sticky && i < last))
        })
}

/// Whether the core at `path` is one only root can replace (`root_only_parts`). `path` is resolved
/// first, so a link anywhere on the way is followed and each part it leads through is judged. A
/// path whose parts cannot all be looked at is not.
fn root_only(path: &Path) -> bool {
    let Ok(resolved) = fs::canonicalize(path) else {
        return false;
    };
    let mut parts = Vec::new();
    for part in resolved.ancestors() {
        let Ok(m) = fs::symlink_metadata(part) else {
            return false;
        };
        parts.push(Part {
            uid: m.uid(),
            mode: m.mode(),
        });
    }
    parts.reverse();
    root_only_parts(&parts)
}

fn answered_at() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// What the command left, for the answer.
struct Left {
    installed: bool,
    loaded: bool,
    replaced: bool,
    /// The core the job runs or ran, and whether it is run where it is.
    program: PathBuf,
    in_place: Option<bool>,
    /// What the status said of the store's watcher after the job was loaded; `None` when it could
    /// not be told, and after uninstall.
    seen: Option<crate::watch::Seen>,
}

fn answer(places: &Places, left: Left) -> v1::Service {
    use crate::watch::Seen;
    v1::Service {
        format: 1,
        answered_at: answered_at(),
        label: LABEL.to_string(),
        program_path_text: whole(&left.program.to_string_lossy()),
        plist_path_text: whole(&places.plist.to_string_lossy()),
        installed: left.installed,
        loaded: left.loaded,
        replaced: left.replaced,
        in_place: left.in_place,
        watching: left.seen.as_ref().map(|seen| *seen == Seen::Live),
        started: left.seen.as_ref().map(Seen::started),
        watcher_note: left
            .seen
            .as_ref()
            .filter(|seen| **seen != Seen::Live)
            .map(Seen::words),
    }
}

/// What the status says of the watcher on `store`, asked until a watcher watches it live or
/// `WATCHER_WITHIN` has passed: the last answer, `None` when it could not be told.
fn watcher_after_load(store: &Path) -> Option<crate::watch::Seen> {
    let until = Instant::now() + WATCHER_WITHIN;
    loop {
        let seen = crate::watch::seen(store);
        if seen == Some(crate::watch::Seen::Live) || Instant::now() >= until {
            return seen;
        }
        std::thread::sleep(WATCHER_ASKED_EVERY);
    }
}

/// Removes the copy of the core in `bin`, if there is one, and `bin` when nothing else is in it.
/// `refusals` has made sure that `bin` is a folder and the copy a regular file, neither a link.
fn remove_copy(places: &Places) -> Result<(), (&Path, io::Error)> {
    match fs::remove_file(&places.program) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err((&places.program, e)),
        _ => {}
    }
    match fs::remove_dir(&places.bin) {
        Err(e)
            if !matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Err((&places.bin, e))
        }
        _ => Ok(()),
    }
}

/// `immune install`. `root_only` judges the core it was run from (`root_only` above, for the
/// command), so that a test can give the judgement.
fn install(
    launchctl: &Path,
    home: Option<&Path>,
    root_only: impl Fn(&Path) -> bool,
) -> Result<v1::Service, Failed> {
    let (places, plist_there) = refusals(launchctl, home)?;
    let (exe, same) = source(&places.program)?;
    let program_there = places.program.is_file();
    // A core only root can replace is run where it is: a copy under the home folder would be one
    // any program of the account could replace. The installed copy itself is the account's, so
    // it is never judged one and never removed as a copy an earlier install left.
    let in_place = root_only(&exe);
    let runs = if in_place {
        exe.clone()
    } else {
        places.program.clone()
    };

    // Stage the property list and the copy under temporary names. The job's files in place are
    // not touched.
    let not_staged = |what: &Path, e: String| {
        failed(
            "not_staged",
            "could not prepare the core job's files; the core job, its property list and the installed core were not touched",
            format!("{}: {e}", what.display()),
        )
    };
    let mut staged = Staged::default();
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&places.agents)
        .map_err(|e| not_staged(&places.agents, e.to_string()))?;
    let folder =
        stage_folder(&places.agents).map_err(|e| not_staged(&places.agents, e.to_string()))?;
    staged.folder = Some(folder.clone());
    let new_plist = folder.join(format!("{LABEL}.plist"));
    write_plist(&new_plist, &runs, &places.home).map_err(|e| not_staged(&new_plist, e))?;
    if !same && !in_place {
        if let Some(store) = places.bin.parent() {
            fs::create_dir_all(store).map_err(|e| not_staged(store, e.to_string()))?;
        }
        match DirBuilder::new().mode(0o700).create(&places.bin) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && places.bin.is_dir() => {}
            Err(e) => return Err(not_staged(&places.bin, e.to_string())),
        }
        let copy = stage_copy(&exe, &places.bin).map_err(|e| not_staged(&exe, e.to_string()))?;
        staged.copy = Some(copy);
    }

    // Put the copy and then the property list in place under the running job, which keeps the
    // binary it opened and the configuration launchd loaded. A file that cannot be replaced
    // fails here, before anything is stopped. The copy goes first, so a property list never
    // names a core that is not there. What was staged goes with `staged`.
    if let Some(copy) = &staged.copy {
        fs::rename(copy, &places.program).map_err(|e| {
            failed(
                "not_installed",
                "could not put the new core in place; the installed core, the property list and the job launchd has were not touched",
                format!("{}: {e}", places.program.display()),
            )
        })?;
    }
    fs::rename(&new_plist, &places.plist).map_err(|e| {
        let core = if staged.copy.is_some() {
            "the new core is in place, and"
        } else {
            "the installed core,"
        };
        failed(
            "not_installed",
            format!(
                "could not put the core job's property list in place; {core} the property list and the job launchd has were not touched. Run immune install again"
            ),
            format!("{}: {e}", places.plist.display()),
        )
    })?;

    // Stop the job that runs and wait until launchd no longer has it.
    let loaded_before = launchctl_run(launchctl, &["print", &places.job]).is_ok();
    if loaded_before && let Err(said) = stop(launchctl, &places.job) {
        return Err(failed(
            "stop_failed",
            "could not see the core job stop in time: the core and its property list are in place, and launchd still has the previous job, which it was told to stop. Run immune install again",
            said,
        ));
    }
    let replaced = loaded_before || plist_there || program_there;

    // From here the job may be stopped: every failure says how to recover.
    let after = |code: &'static str, what: &str, detail: String| {
        failed(code, format!("could not {what}{RECOVER}"), detail)
    };
    // A copy an earlier install left goes once no job runs it: the property list in place names
    // the core where it is.
    if in_place {
        remove_copy(&places).map_err(|(path, e)| {
            after(
                "not_removed",
                "remove the copy of the core an earlier install left",
                format!("{}: {e}", path.display()),
            )
        })?;
    }
    launchctl_run(launchctl, &["enable", &places.job])
        .map_err(|said| after("not_loaded", "enable the core job", said))?;
    let plist = places.plist.to_string_lossy().into_owned();
    launchctl_run(launchctl, &["bootstrap", &places.domain, &plist])
        .map_err(|said| after("not_loaded", "load the core job", said))?;
    launchctl_run(launchctl, &["print", &places.job])
        .map_err(|said| after("not_loaded", "find the core job loaded", said))?;
    let seen = watcher_after_load(&places.store);
    Ok(answer(
        &places,
        Left {
            installed: true,
            loaded: true,
            replaced,
            program: runs,
            in_place: Some(in_place),
            seen,
        },
    ))
}

fn uninstall(launchctl: &Path, home: Option<&Path>) -> Result<v1::Service, Failed> {
    let (places, plist_there) = refusals(launchctl, home)?;
    let program_there = places.program.is_file();
    // What the job runs, as its property list names it: the copy, which goes, or a core run where
    // it is, which this command never removes.
    let runs = plist_there
        .then(|| plist_string(&places.plist, "ProgramArguments.0").ok())
        .flatten()
        .map(PathBuf::from);
    let in_place = match &runs {
        Some(runs) => Some(*runs != places.program),
        None => program_there.then_some(false),
    };
    let loaded_before = launchctl_run(launchctl, &["print", &places.job]).is_ok();
    if loaded_before && let Err(said) = stop(launchctl, &places.job) {
        return Err(failed(
            "stop_failed",
            "could not stop the core job; its property list and the installed core were kept",
            said,
        ));
    }
    let removed = |what: &Path, e: io::Error| {
        failed(
            "not_removed",
            "the core job is stopped, and its property list or the installed core could not be removed and is still there; the store was kept. Run immune uninstall again",
            format!("{}: {e}", what.display()),
        )
    };
    match fs::remove_file(&places.plist) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(removed(&places.plist, e)),
        _ => {}
    }
    // The copy in `bin` is always install's own, whatever the job ran; `bin` goes only when
    // nothing else is in it.
    remove_copy(&places).map_err(|(path, e)| removed(path, e))?;
    let program = match (in_place, runs) {
        (Some(true), Some(runs)) => runs,
        _ => places.program.clone(),
    };
    Ok(answer(
        &places,
        Left {
            installed: false,
            loaded: false,
            replaced: loaded_before || plist_there || program_there,
            program,
            in_place,
            seen: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<ServiceArgs, String> {
        let mut options = Options::default();
        parse(
            Verb::Install,
            args.iter().map(|a| a.to_string()),
            &mut options,
        )
    }

    /// The stand-in and the home named are the ones used, and only without both is it the
    /// system's launchctl and the account's home: the promise every test of these commands rests
    /// on, so that none reaches the real launchd or the real home folder.
    #[test]
    fn the_launchctl_and_home_named_are_the_ones_used_and_the_system_s_only_without_both() {
        let named = parsed(&[
            "--launchctl",
            "/invented/launchctl",
            "--home",
            "/Users/example",
            "--json",
        ])
        .unwrap();
        assert_eq!(named.launchctl, Path::new("/invented/launchctl"));
        assert_eq!(named.home.as_deref(), Some(Path::new("/Users/example")));
        assert_eq!(named.form, Form::Json);
        let neither = parsed(&[]).unwrap();
        assert_eq!(neither.launchctl, Path::new(LAUNCHCTL));
        assert_eq!(neither.home, None);
        assert!(parsed(&["--store", "/invented/store.db"]).is_err());
    }

    /// The account's home is the one in the user database, as `id -P` prints its entry; an
    /// account with no entry has none.
    #[test]
    fn the_account_s_home_is_the_one_in_the_user_database() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let out = Command::new("/usr/bin/id").arg("-P").output().unwrap();
        let entry = String::from_utf8(out.stdout).unwrap();
        // name:password:uid:gid:class:change:expire:gecos:home:shell
        let home = entry.trim_end().split(':').nth(8).unwrap();
        assert_eq!(account_home(uid), Some(PathBuf::from(home)));
        assert_eq!(account_home(4_000_000_000), None);
    }

    /// A stand-in launchctl with the account's real home would act on the real job's files.
    #[test]
    fn a_stand_in_launchctl_without_a_home_is_a_misuse() {
        assert!(parsed(&["--launchctl", "/invented/launchctl"]).is_err());
    }

    /// A home of one's choosing with the real launchd would stop the real job and report on
    /// files that are not its own.
    #[test]
    fn a_home_without_a_stand_in_launchctl_is_a_misuse() {
        assert!(parsed(&["--home", "/Users/example"]).is_err());
    }

    /// A stand-in launchctl and a temporary home folder: the stand-in keeps whether the job is
    /// loaded in a file beside itself, and runs nothing.
    fn stand_in(dir: &Path) -> (PathBuf, PathBuf) {
        let launchctl = dir.join("launchctl");
        fs::write(
            &launchctl,
            r#"#!/bin/sh
dir=$(dirname "$0")
case "$1" in
    print) case "$2" in */*/*) [ -f "$dir/loaded" ] ;; *) true ;; esac ;;
    bootout) rm -f "$dir/loaded" ;;
    enable) true ;;
    bootstrap) cp "$3" "$dir/loaded" ;;
    *) exit 2 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&launchctl, fs::Permissions::from_mode(0o755)).unwrap();
        let home = dir.join("home");
        fs::create_dir(&home).unwrap();
        (launchctl, home)
    }

    fn done(result: Result<v1::Service, Failed>) -> v1::Service {
        match result {
            Ok(m) => m,
            Err(f) => panic!("{}: {} {}", f.code, f.message, f.detail),
        }
    }

    /// Below the command line, with the judgement given: a core only root can replace is run
    /// where it is, the copy an earlier install left goes, and uninstall leaves the core and says
    /// where it is.
    #[test]
    fn a_core_only_root_can_replace_is_run_where_it_is_and_uninstall_leaves_it() {
        use std::io::Write;
        let dir = crate::common::Scratch::new("service-in-place");
        let (launchctl, home) = stand_in(&dir);
        // A watcher that watches the store, so that install answers at once.
        let folder = home.join(crate::STORE_FOLDER);
        fs::create_dir_all(&folder).unwrap();
        crate::store::open_or_make(&folder.join(crate::STORE_FILE)).unwrap();
        let mut lock = crate::store::lock_watch(&folder).unwrap().unwrap();
        let since = crate::now_secs() - 1;
        write!(lock, "{since}\nheartbeat\nready").unwrap();
        let copy = folder.join(BIN).join(PROGRAM);
        let plist = home.join(format!("Library/LaunchAgents/{LABEL}.plist"));

        let m = done(install(&launchctl, Some(&home), |_| false));
        assert_eq!((m.in_place, m.watching), (Some(false), Some(true)));
        assert!(copy.is_file());
        let core = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let m = done(install(&launchctl, Some(&home), |_| true));
        assert_eq!((m.in_place, m.loaded), (Some(true), true));
        assert_eq!(Path::new(&m.program_path_text), core);
        let named = plist_string(&plist, "ProgramArguments.0").ok().unwrap();
        assert_eq!(Path::new(&named), core);
        assert!(!copy.exists() && !folder.join(BIN).exists());

        let m = done(uninstall(&launchctl, Some(&home)));
        assert_eq!((m.installed, m.in_place), (false, Some(true)));
        assert_eq!(Path::new(&m.program_path_text), core);
        assert!(core.is_file() && !plist.exists() && !dir.join("loaded").exists());
    }

    const DIR: u32 = libc::S_IFDIR as u32;
    const FILE: u32 = libc::S_IFREG as u32;
    const STICKY: u32 = libc::S_ISVTX as u32;

    fn part(uid: u32, mode: u32) -> Part {
        Part { uid, mode }
    }

    /// `/usr/local/bin/immune` as a package would leave it, owned by root all the way, with the
    /// folder that holds the file and the file given.
    fn package(bin: Part, file: Part) -> Vec<Part> {
        vec![
            part(0, DIR | 0o755),
            part(0, DIR | 0o755),
            part(0, DIR | 0o755),
            bin,
            file,
        ]
    }

    /// The job runs a core where it is only when nobody but root can replace it; any other owner,
    /// and any folder or file a group or anyone may write, make it one to copy, whoever runs the
    /// command.
    #[test]
    fn a_core_is_run_where_it_is_only_when_nobody_but_root_can_replace_it() {
        let root_dir = part(0, DIR | 0o755);
        let root_file = part(0, FILE | 0o755);
        assert!(root_only_parts(&package(root_dir, root_file)));
        // A folder its group may write, as `/Applications` is, root:admin 0775.
        assert!(!root_only_parts(&package(part(0, DIR | 0o775), root_file)));
        // Folders owned by another account than root, whatever their mode.
        assert!(!root_only_parts(&package(
            part(502, DIR | 0o755),
            root_file
        )));
        let build = vec![
            root_dir,
            root_dir,
            part(502, DIR | 0o700),
            root_dir,
            root_file,
        ];
        assert!(!root_only_parts(&build));
        // A file of another owner, and one its group or anyone may write.
        assert!(!root_only_parts(&package(
            root_dir,
            part(501, FILE | 0o555)
        )));
        assert!(!root_only_parts(&package(root_dir, part(0, FILE | 0o775))));
        assert!(!root_only_parts(&package(root_dir, part(0, FILE | 0o757))));
        // A sticky folder anyone may write passes for a part of root's inside it; not sticky, it
        // does not, and a sticky file is still a file anyone may write.
        let tmp = part(0, DIR | STICKY | 0o777);
        assert!(root_only_parts(&package(tmp, root_file)));
        assert!(!root_only_parts(&package(tmp, part(501, FILE | 0o755))));
        assert!(!root_only_parts(&package(
            part(502, DIR | STICKY | 0o777),
            root_file
        )));
        assert!(!root_only_parts(&package(part(0, DIR | 0o777), root_file)));
        assert!(!root_only_parts(&package(
            root_dir,
            part(0, FILE | STICKY | 0o777)
        )));
        // A link left on the way: the path was not resolved. Nothing to judge: copied.
        let mut linked = package(root_dir, root_file);
        linked[3] = part(0, libc::S_IFLNK as u32 | 0o755);
        assert!(!root_only_parts(&linked));
        assert!(!root_only_parts(&[]));
    }

    /// A link on the way to the core is followed, and the parts it leads to are judged: a link in
    /// a folder of the account's to a program of the system's is a core only root can replace,
    /// and a file in that folder is not.
    #[test]
    fn a_link_on_the_way_is_followed_and_what_it_leads_to_is_judged() {
        let dir = crate::common::Scratch::new("service-link-to-core");
        let link = dir.join("core");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(root_only(&link));
        let own = dir.join("own");
        fs::write(&own, "invented core").unwrap();
        assert!(!root_only(&own));
        assert!(!root_only(&dir.join("absent")));
    }
}
