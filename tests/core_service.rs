//! `immune install` and `immune uninstall` against a stand-in for launchctl and a temporary home.
//!
//! Every run of the two commands goes through `Login::immune`, which always names the stand-in
//! with `--launchctl` and always sets `HOME` to the test's own folder, so no test reaches the real
//! launchd or the real home folder.

mod common;

use common::Scratch;
use immune_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LABEL: &str = "ai.nuanu.immune.watch";
/// The binary this repository builds, which install copies.
const CORE: &str = env!("CARGO_BIN_EXE_immune");

/// A login of one user: a home folder with awkward characters in its name, and a stand-in for
/// launchctl that keeps whether the job is loaded in a file.
struct Login {
    scratch: Scratch,
    home: PathBuf,
    agents: PathBuf,
    plist: PathBuf,
    store: PathBuf,
    bin: PathBuf,
    program: PathBuf,
    domain: String,
    job: String,
}

impl Login {
    fn new(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        let home = scratch.join("home 'quoted' & \"double\"");
        fs::create_dir(&home).unwrap();
        let agents = home.join("Library/LaunchAgents");
        let store = home.join("Library/Application Support/ai.nuanu.immune");
        let bin = store.join("bin");
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let domain = format!("gui/{uid}");
        let job = format!("{domain}/{LABEL}");
        fs::create_dir(scratch.join("tools")).unwrap();
        tool(
            &scratch.join("tools/launchctl"),
            &format!(
                r#"
printf '%s\0' "$@" >>"$TEST_LOGIN/calls"
printf '\n' >>"$TEST_LOGIN/calls"
[ "$1" != "${{FAIL_LAUNCHCTL-}}" ] || exit 1
case "$1:${{2-}}" in
    print:{domain}) ;;
    print:{job})
        if [ -f "$TEST_LOGIN/leaving" ]; then
            left=$(cat "$TEST_LOGIN/leaving")
            if [ "$left" -gt 0 ]; then
                echo $((left - 1)) >"$TEST_LOGIN/leaving"
            else
                rm "$TEST_LOGIN/leaving" "$TEST_LOGIN/loaded"
            fi
        fi
        [ -f "$TEST_LOGIN/loaded" ] ;;
    bootout:{job})
        [ -f "$TEST_LOGIN/loaded" ] || exit 1
        if [ -n "${{JOB_LEAVES_AFTER-}}" ]; then
            echo "$JOB_LEAVES_AFTER" >"$TEST_LOGIN/leaving"
            [ -z "${{STOP_UNDER_WAY-}}" ] || exit 36
        else
            rm "$TEST_LOGIN/loaded"
        fi ;;
    enable:{job}) ;;
    bootstrap:{domain})
        [ "$#" -eq 3 ] && [ ! -f "$TEST_LOGIN/loaded" ] && /usr/bin/plutil -lint -s "$3" &&
            {{ [ -n "${{BOOTSTRAP_LOADS_NOTHING-}}" ] || cp "$3" "$TEST_LOGIN/loaded"; }} ;;
    *) exit 2 ;;
esac"#
            ),
        );
        Self {
            plist: agents.join(format!("{LABEL}.plist")),
            program: bin.join("immune"),
            scratch,
            home,
            agents,
            store,
            bin,
            domain,
            job,
        }
    }

    /// `exe <args> --launchctl <the stand-in>` with `HOME` the test's home folder and nothing else
    /// of the caller's environment. `env` adds to it; a `HOME` there must be relative, so that it
    /// can only point inside the test's folder.
    fn immune(&self, exe: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        for (key, value) in env {
            assert!(*key != "HOME" || Path::new(value).is_relative());
        }
        Command::new(exe)
            .args(args)
            .arg("--launchctl")
            .arg(self.scratch.join("tools/launchctl"))
            .current_dir(&*self.scratch)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("TEST_LOGIN", &*self.scratch)
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    /// `immune <verb> --json` from the binary this repository builds.
    fn run(&self, verb: &str, env: &[(&str, &str)]) -> Output {
        self.immune(Path::new(CORE), &[verb, "--json"], env)
    }

    fn calls(&self) -> Vec<Vec<String>> {
        String::from_utf8(fs::read(self.scratch.join("calls")).unwrap_or_default())
            .unwrap()
            .lines()
            .map(|line| {
                line.trim_end_matches('\0')
                    .split('\0')
                    .map(str::to_string)
                    .collect()
            })
            .collect()
    }

    fn loaded(&self) -> bool {
        self.scratch.join("loaded").is_file()
    }

    /// What install and uninstall may change, as it stands: the property list, the installed
    /// core with its inode, whether the job is loaded, and what is in the two folders.
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            plist: fs::read(&self.plist).ok(),
            program: fs::read(&self.program).ok(),
            inode: fs::symlink_metadata(&self.program).ok().map(|m| m.ino()),
            loaded: fs::read(self.scratch.join("loaded")).ok(),
            agents: names(&self.agents),
            bin: names(&self.bin),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    plist: Option<Vec<u8>>,
    program: Option<Vec<u8>>,
    inode: Option<u64>,
    loaded: Option<Vec<u8>>,
    agents: Vec<String>,
    bin: Vec<String>,
}

/// The names in a folder, sorted; none when it is not there.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn tool(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The `Service` a command answered with in JSON, which must be all it printed.
fn service(out: &Output) -> v1::Service {
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    let raw: Value = serde_json::from_str(&text).unwrap();
    let m: v1::Service = serde_json::from_value(raw.clone()).unwrap();
    // Read back and printed again it is the same object: no key the message does not have.
    assert_eq!(serde_json::to_value(&m).unwrap(), raw);
    assert_eq!(m.format, 1);
    m
}

/// The `Failure` a command printed in JSON in place of an answer: its error's code and message.
fn failure(out: &Output, op: &str) -> (String, String) {
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let raw: Value = serde_json::from_slice(&out.stdout).unwrap();
    let f: v1::Failure = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(&f).unwrap(), raw);
    assert_eq!((f.operation.as_str(), f.ok), (op, false));
    let e = &f.errors[0];
    (e.code.clone(), e.message.clone())
}

fn plist(path: &Path) -> Value {
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn one_login_job_runs_the_installed_copy_and_removal_keeps_the_store_and_collector() {
    let login = Login::new("core-service-lifecycle");
    fs::create_dir_all(&login.store).unwrap();
    let store = login.store.join("store.db");
    fs::write(&store, "invented store").unwrap();
    let collector = login
        .scratch
        .join("system/Library/LaunchDaemons/ai.nuanu.immune.event-filter.plist");
    fs::create_dir_all(collector.parent().unwrap()).unwrap();
    fs::write(&collector, "invented collector").unwrap();

    let m = service(&login.run("install", &[]));
    assert_eq!(
        (m.installed, m.loaded, m.replaced, m.label.as_str()),
        (true, true, false, LABEL)
    );
    assert_eq!(m.program_path_text, login.program.to_str().unwrap());
    assert_eq!(m.plist_path_text, login.plist.to_str().unwrap());
    let installed = plist(&login.plist);
    assert_eq!(installed["Label"], LABEL);
    assert_eq!(
        installed["ProgramArguments"],
        json!([login.program, "watch", "--background"])
    );
    assert_eq!(installed["EnvironmentVariables"]["HOME"], json!(login.home));
    assert_eq!(installed["KeepAlive"], true);
    assert_eq!(installed["ThrottleInterval"], 30);
    assert_eq!(installed["StandardOutPath"], "/dev/null");
    assert_eq!(installed["StandardErrorPath"], "/dev/null");
    assert_eq!(installed.as_object().unwrap().len(), 7);
    assert_eq!(plist(&login.scratch.join("loaded")), installed);
    assert_eq!(fs::read(&login.program).unwrap(), fs::read(CORE).unwrap());
    assert_eq!((mode(&login.program), mode(&login.bin)), (0o755, 0o700));
    assert_eq!(names(&login.agents), [format!("{LABEL}.plist")]);
    assert_eq!(names(&login.bin), ["immune"]);

    let again = service(&login.run("install", &[]));
    assert!(again.installed && again.loaded && again.replaced);
    let removed = service(&login.run("uninstall", &[]));
    assert_eq!(
        (removed.installed, removed.loaded, removed.replaced),
        (false, false, true)
    );
    assert!(!login.loaded() && !login.plist.exists() && !login.program.exists());
    assert!(!login.bin.exists());
    let nothing = service(&login.run("uninstall", &[]));
    assert_eq!(
        (nothing.installed, nothing.loaded, nothing.replaced),
        (false, false, false)
    );
    assert_eq!(fs::read_to_string(&store).unwrap(), "invented store");
    assert_eq!(
        fs::read_to_string(&collector).unwrap(),
        "invented collector"
    );
    assert_eq!(names(&login.agents), Vec::<String>::new());
    let (d, j) = (login.domain.as_str(), login.job.as_str());
    let path = login.plist.to_str().unwrap();
    assert_eq!(
        login.calls(),
        [
            vec!["print", d],
            vec!["print", j],
            vec!["enable", j],
            vec!["bootstrap", d, path],
            vec!["print", j],
            vec!["print", d],
            vec!["print", j],
            vec!["bootout", j],
            vec!["print", j],
            vec!["enable", j],
            vec!["bootstrap", d, path],
            vec!["print", j],
            vec!["print", d],
            vec!["print", j],
            vec!["bootout", j],
            vec!["print", j],
            vec!["print", d],
            vec!["print", j],
        ]
    );
}

#[test]
fn the_core_s_help_is_the_usage_on_stdout_with_exit_0() {
    for arg in ["--help", "-h", "help"] {
        let out = Command::new(CORE).arg(arg).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{arg}");
        assert!(said.contains("immune install"), "{arg}: {said}");
        assert!(out.stderr.is_empty(), "{arg}");
    }
}

#[test]
fn a_refusal_leaves_the_job_its_plist_and_the_installed_copy_as_they_were() {
    let login = Login::new("core-service-refusals");
    service(&login.run("install", &[]));
    let before = login.snapshot();
    for verb in ["install", "uninstall"] {
        let calls = login.calls();
        let (code, _) = failure(&login.run(verb, &[("HOME", "relative home")]), verb);
        assert_eq!(code, "home_not_absolute");
        assert_eq!(login.calls(), calls, "{verb}: launchctl was asked");
        let (code, _) = failure(&login.run(verb, &[("FAIL_LAUNCHCTL", "print")]), verb);
        assert_eq!(code, "no_login_session");
        assert_eq!(
            login.calls().last().unwrap(),
            &["print", login.domain.as_str()]
        );
        assert_eq!(login.snapshot(), before, "{verb}");
    }
    assert!(!login.scratch.join("relative home").exists());
}

#[test]
fn neither_command_follows_a_symbolic_link_or_touches_another_job_s_plist() {
    let login = Login::new("core-service-foreign");
    fs::create_dir_all(&login.agents).unwrap();
    let foreign = login.scratch.join("foreign.plist");
    fs::write(
        &foreign,
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>org.example.other</string></dict></plist>"#,
    )
    .unwrap();
    let before = fs::read(&foreign).unwrap();
    symlink(&foreign, &login.plist).unwrap();
    for verb in ["install", "uninstall"] {
        assert_eq!(failure(&login.run(verb, &[]), verb).0, "symbolic_link");
    }
    assert_eq!(fs::read_link(&login.plist).unwrap(), foreign);
    assert_eq!(fs::read(&foreign).unwrap(), before);

    fs::remove_file(&login.plist).unwrap();
    fs::copy(&foreign, &login.plist).unwrap();
    for verb in ["install", "uninstall"] {
        assert_eq!(failure(&login.run(verb, &[]), verb).0, "another_job");
    }
    assert_eq!(fs::read(&login.plist).unwrap(), before);
    fs::remove_file(&login.plist).unwrap();

    // A link at `bin`, to a folder of somebody else's.
    let elsewhere = login.scratch.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("immune"), "invented other program").unwrap();
    fs::create_dir_all(&login.store).unwrap();
    symlink(&elsewhere, &login.bin).unwrap();
    for verb in ["install", "uninstall"] {
        assert_eq!(failure(&login.run(verb, &[]), verb).0, "symbolic_link");
    }
    assert_eq!(names(&elsewhere), ["immune"]);
    assert_eq!(
        fs::read_to_string(elsewhere.join("immune")).unwrap(),
        "invented other program"
    );
    fs::remove_file(&login.bin).unwrap();

    // A link at `bin/immune`, to a file of somebody else's.
    fs::create_dir(&login.bin).unwrap();
    symlink(elsewhere.join("immune"), &login.program).unwrap();
    for verb in ["install", "uninstall"] {
        assert_eq!(failure(&login.run(verb, &[]), verb).0, "symbolic_link");
    }
    assert_eq!(
        fs::read_link(&login.program).unwrap(),
        elsewhere.join("immune")
    );
    assert_eq!(
        fs::read_to_string(elsewhere.join("immune")).unwrap(),
        "invented other program"
    );
    assert_eq!(names(&login.agents), Vec::<String>::new());
    assert_eq!(login.calls(), vec![vec!["print", login.domain.as_str()]; 8]);
}

#[test]
fn a_failed_stop_keeps_everything_and_a_failure_after_the_stop_says_how_to_recover() {
    let login = Login::new("core-service-recovery");
    service(&login.run("install", &[]));
    let before = login.snapshot();
    let (code, message) = failure(
        &login.run("uninstall", &[("FAIL_LAUNCHCTL", "bootout")]),
        "uninstall",
    );
    assert_eq!(code, "stop_failed");
    assert!(message.contains("were kept"), "{message}");
    assert_eq!(login.snapshot(), before);
    let (code, _) = failure(
        &login.run("install", &[("FAIL_LAUNCHCTL", "bootout")]),
        "install",
    );
    assert_eq!(code, "stop_failed");
    assert_eq!(login.snapshot(), before);

    const RECOVER: &str =
        "the core job may be stopped. The store was kept. Run immune install again to recover";
    let (code, message) = failure(
        &login.run("install", &[("FAIL_LAUNCHCTL", "bootstrap")]),
        "install",
    );
    assert_eq!(code, "not_loaded");
    assert!(message.contains(RECOVER), "{message}");
    assert!(!login.loaded() && login.plist.is_file());
    assert_eq!(names(&login.agents), [format!("{LABEL}.plist")]);
    assert_eq!(names(&login.bin), ["immune"]);

    // launchd took the job and then does not have it: install does not say it is loaded.
    let (code, message) = failure(
        &login.run("install", &[("BOOTSTRAP_LOADS_NOTHING", "1")]),
        "install",
    );
    assert_eq!(code, "not_loaded");
    assert!(message.contains(RECOVER), "{message}");
    let for_a_person = login.immune(
        Path::new(CORE),
        &["install"],
        &[("BOOTSTRAP_LOADS_NOTHING", "1")],
    );
    assert_eq!(for_a_person.status.code(), Some(1));
    assert!(for_a_person.stdout.is_empty());
    assert!(String::from_utf8_lossy(&for_a_person.stderr).contains(RECOVER));
    assert!(!login.loaded());

    let m = service(&login.run("install", &[]));
    assert!(m.loaded && login.loaded());
}

#[test]
fn a_stopped_job_is_waited_for_until_launchd_no_longer_has_it() {
    let login = Login::new("core-service-leaving");
    service(&login.run("install", &[]));
    // launchd took the stop and still has the job for three more questions: the stand-in
    // refuses to load a job while the old one is there, as launchd does.
    let m = service(&login.run("install", &[("JOB_LEAVES_AFTER", "3")]));
    assert!(m.loaded && m.replaced && login.loaded());
    // launchd refused the stop because one is under way, and the job leaves all the same.
    let under_way = [("JOB_LEAVES_AFTER", "3"), ("STOP_UNDER_WAY", "1")];
    let m = service(&login.run("install", &under_way));
    assert!(m.loaded && login.loaded());
    let m = service(&login.run("uninstall", &under_way));
    assert!(!m.loaded && !login.loaded());
    assert!(!login.plist.exists() && !login.program.exists());
}

#[test]
fn an_update_replaces_the_copy_by_rename_and_leaves_no_temporary_file() {
    let login = Login::new("core-service-update");
    service(&login.run("install", &[]));
    // An earlier core, as a running job would hold it open.
    fs::write(&login.program, "invented earlier core").unwrap();
    let old = fs::metadata(&login.program).unwrap().ino();
    let mut held = fs::File::open(&login.program).unwrap();

    let m = service(&login.run("install", &[]));
    assert!(m.replaced && m.loaded);
    assert_ne!(fs::metadata(&login.program).unwrap().ino(), old);
    let mut read = String::new();
    held.read_to_string(&mut read).unwrap();
    assert_eq!(read, "invented earlier core");
    assert_eq!(fs::read(&login.program).unwrap(), fs::read(CORE).unwrap());
    assert_eq!(mode(&login.program), 0o755);
    assert_eq!(names(&login.agents), [format!("{LABEL}.plist")]);
    assert_eq!(names(&login.bin), ["immune"]);
}

#[test]
fn install_and_uninstall_run_from_the_installed_copy_itself() {
    let login = Login::new("core-service-from-copy");
    service(&login.run("install", &[]));
    let before = fs::metadata(&login.program).unwrap();
    let calls = login.calls().len();

    let m = service(&login.immune(&login.program, &["install", "--json"], &[]));
    assert!(m.installed && m.loaded && m.replaced && login.loaded());
    let after = fs::metadata(&login.program).unwrap();
    assert_eq!(
        (after.ino(), after.mtime(), after.mtime_nsec()),
        (before.ino(), before.mtime(), before.mtime_nsec())
    );
    assert_eq!(fs::read(&login.program).unwrap(), fs::read(CORE).unwrap());
    assert_eq!(names(&login.bin), ["immune"]);
    let (d, j) = (login.domain.as_str(), login.job.as_str());
    let path = login.plist.to_str().unwrap();
    assert_eq!(
        login.calls()[calls..],
        [
            vec!["print", d],
            vec!["print", j],
            vec!["bootout", j],
            vec!["print", j],
            vec!["enable", j],
            vec!["bootstrap", d, path],
            vec!["print", j],
        ]
    );

    let m = service(&login.immune(&login.program, &["uninstall", "--json"], &[]));
    assert!(!m.installed && !m.loaded && m.replaced);
    assert!(!login.loaded() && !login.plist.exists() && !login.bin.exists());
}

#[test]
fn uninstall_removes_only_the_job_its_plist_and_the_copy() {
    let login = Login::new("core-service-only-its-own");
    fs::create_dir_all(login.store.join("pages")).unwrap();
    fs::write(login.store.join("store.db"), "invented store").unwrap();
    fs::write(login.store.join("pages/index.html"), "invented page").unwrap();
    service(&login.run("install", &[]));
    fs::write(login.bin.join("notes.txt"), "invented note").unwrap();
    let other = login.agents.join("com.example.other.plist");
    fs::write(&other, "invented other job").unwrap();

    service(&login.run("uninstall", &[]));
    assert_eq!(names(&login.bin), ["notes.txt"]);
    assert_eq!(names(&login.agents), ["com.example.other.plist"]);
    assert_eq!(names(&login.store), ["bin", "pages", "store.db"]);
    assert_eq!(
        fs::read_to_string(login.store.join("store.db")).unwrap(),
        "invented store"
    );
    assert_eq!(
        fs::read_to_string(login.store.join("pages/index.html")).unwrap(),
        "invented page"
    );
}

#[test]
fn the_answer_is_the_message_service_in_three_forms_and_a_failure_is_failure() {
    let login = Login::new("core-service-forms");
    let json = service(&login.run("install", &[]));
    let binary = login.immune(Path::new(CORE), &["install", "--proto"], &[]);
    assert!(binary.status.success());
    let mut binary = v1::Service::decode(binary.stdout.as_slice()).unwrap();
    binary.answered_at = json.answered_at;
    assert_eq!(
        binary,
        v1::Service {
            replaced: true,
            ..json.clone()
        }
    );

    let quoted = format!("\"{}\"", json.program_path_text.replace('"', "\\\""));
    let text = login.immune(Path::new(CORE), &["install"], &[]);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains(&quoted), "{text}");
    assert!(text.contains("every hour"), "{text}");
    assert!(text.contains("immune status"), "{text}");
    let text = login.immune(Path::new(CORE), &["uninstall"], &[]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("were kept"), "{text}");

    let (code, _) = failure(
        &login.run("install", &[("FAIL_LAUNCHCTL", "print")]),
        "install",
    );
    assert_eq!(code, "no_login_session");
    let out = login.immune(
        Path::new(CORE),
        &["install", "--proto"],
        &[("FAIL_LAUNCHCTL", "print")],
    );
    let f = v1::Failure::decode(out.stdout.as_slice()).unwrap();
    assert_eq!(
        (f.operation.as_str(), f.errors[0].code.as_str()),
        ("install", "no_login_session")
    );
    let out = login.immune(
        Path::new(CORE),
        &["uninstall", "--json", "--store", "x"],
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let f: v1::Failure = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (f.operation.as_str(), f.errors[0].code.as_str()),
        ("uninstall", "usage")
    );
}
