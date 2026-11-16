//! `immune install` and `immune uninstall`: the core as a login job of this user.
//!
//! Install copies the binary it is run from to `bin/immune` in the store's folder and registers
//! that copy with launchd as the job `ai.nuanu.immune.watch`, which runs `watch --background`.
//! The job never runs the binary a build left in a checkout, so a rebuild, another branch or a
//! removed checkout does not touch the running core. Uninstall stops the job and removes its
//! property list and the copy, and keeps the store and the event collector.
//!
//! The home folder is the account's own, from the user database, and never `$HOME`: the job
//! belongs to `gui/<uid>`, and launchd loads that user's `LaunchAgents` at login, so files found
//! through another home would not be the job's.
//!
//! These commands act, so their order is the point. Install:
//! - every refusal comes first, with nothing changed; one of the two commands runs at a time;
//! - then the property list and the copy are staged under temporary names beside their places;
//! - then the copy and then the property list are renamed into place, under the running job: it
//!   keeps the old binary's inode and the configuration launchd loaded, so it is not disturbed,
//!   and a file that cannot be replaced fails the install before anything is stopped. The copy
//!   goes first, so a property list never names a core that is not there;
//! - then a loaded job is stopped and waited for until launchd no longer has it;
//! - then the job is registered again and confirmed.
//!
//! The installed file is never written in place, since a running job has it open: a new copy
//! replaces it by rename. What was staged under a temporary name is removed on every way out.
//! A failure says what the command did and did not touch and what launchd answered, never what
//! the job does next: the command does not know what launchd will do. The answer says the job
//! is loaded only when `launchctl print` said so after it was registered.
//!
//! The property list is written by the system's `plutil`, never by hand, since a path can hold
//! `&` or `<`. `launchctl` and `plutil` are run by absolute path. For tests, `--launchctl` gives
//! a stand-in and `--home` another home folder; they go only together, so that a test that forgets
//! one of the two is refused before anything runs.

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
const RECOVER: &str = "; the core job may be stopped. The store was kept. The new core and its property list are in place. Run immune install again to recover";
/// At most this many characters of another job's label are quoted in a failure.
const LABEL_QUOTED: usize = 200;

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
}

/// Answers `immune install` or `immune uninstall` with `Service`, or fails with `Failure`.
pub fn service_cmd(args: &ServiceArgs) -> ExitCode {
    let op = args.verb.op();
    let home = args.home.as_deref();
    let done = match args.verb {
        Verb::Install => install(&args.launchctl, home),
        Verb::Uninstall => uninstall(&args.launchctl, home),
    };
    match done {
        Ok(m) => answer::print(op, args.form, &m, crate::text::service),
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
    let places = Places {
        _lock: lock,
        job: format!("{domain}/{LABEL}"),
        domain,
        agents: home.join("Library/LaunchAgents"),
        plist: home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")),
        bin: home.join(crate::STORE_FOLDER).join(BIN),
        program: home.join(crate::STORE_FOLDER).join(BIN).join(PROGRAM),
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
            let label = plist_label(&places.plist)?;
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

/// The `Label` of the property list at `path`, read by the system's plutil.
fn plist_label(path: &Path) -> Result<String, Failed> {
    let out = Command::new(crate::integrity::PLUTIL)
        .args([
            "-extract", "Label", "raw", "-expect", "string", "-n", "-o", "-",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| unreadable(path, &e.to_string()))?;
    if !out.status.success() {
        return Err(unreadable(path, &said(&out)));
    }
    // With `-n` plutil adds no line feed, so every byte is the label's own. `-expect string`
    // refuses a label that is not a string: of a dictionary plutil would print the keys.
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
    let steps: [&[&str]; 13] = [
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

fn answered_at() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn answer(places: &Places, installed: bool, loaded: bool, replaced: bool) -> v1::Service {
    v1::Service {
        format: 1,
        answered_at: answered_at(),
        label: LABEL.to_string(),
        program_path_text: whole(&places.program.to_string_lossy()),
        plist_path_text: whole(&places.plist.to_string_lossy()),
        installed,
        loaded,
        replaced,
    }
}

fn install(launchctl: &Path, home: Option<&Path>) -> Result<v1::Service, Failed> {
    let (places, plist_there) = refusals(launchctl, home)?;
    let (exe, same) = source(&places.program)?;
    let program_there = places.program.is_file();

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
    write_plist(&new_plist, &places.program, &places.home)
        .map_err(|e| not_staged(&new_plist, e))?;
    if !same {
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
        let core = if same {
            "the installed core,"
        } else {
            "the new core is in place, and"
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
            "could not see the core job stop in time: the new core and its property list are in place, and launchd still has the previous job, which it was told to stop. Run immune install again",
            said,
        ));
    }
    let replaced = loaded_before || plist_there || program_there;

    // From here the job may be stopped: every failure says how to recover.
    let after = |code: &'static str, what: &str, detail: String| {
        failed(code, format!("could not {what}{RECOVER}"), detail)
    };
    launchctl_run(launchctl, &["enable", &places.job])
        .map_err(|said| after("not_loaded", "enable the core job", said))?;
    let plist = places.plist.to_string_lossy().into_owned();
    launchctl_run(launchctl, &["bootstrap", &places.domain, &plist])
        .map_err(|said| after("not_loaded", "load the core job", said))?;
    launchctl_run(launchctl, &["print", &places.job])
        .map_err(|said| after("not_loaded", "find the core job loaded", said))?;
    Ok(answer(&places, true, true, replaced))
}

fn uninstall(launchctl: &Path, home: Option<&Path>) -> Result<v1::Service, Failed> {
    let (places, plist_there) = refusals(launchctl, home)?;
    let program_there = places.program.is_file();
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
            "the core job is stopped, and one of its files could not be removed; the store was kept. Run immune uninstall again",
            format!("{}: {e}", what.display()),
        )
    };
    for path in [&places.plist, &places.program] {
        match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(removed(path, e)),
            _ => {}
        }
    }
    // `bin` goes only when nothing else is in it.
    match fs::remove_dir(&places.bin) {
        Err(e)
            if !matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            return Err(removed(&places.bin, e));
        }
        _ => {}
    }
    Ok(answer(
        &places,
        false,
        false,
        loaded_before || plist_there || program_there,
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
}
