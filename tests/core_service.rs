//! The service scripts against a stand-in for launchctl and a temporary home.

mod common;

use common::Scratch;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LABEL: &str = "ai.nuanu.immune.watch";
const DOMAIN: &str = "gui/501";
const JOB: &str = "gui/501/ai.nuanu.immune.watch";

struct Login {
    scratch: Scratch,
    home: PathBuf,
    core: PathBuf,
    plist: PathBuf,
}

impl Login {
    fn new(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        let home = scratch.join("home 'quoted' & \"double\"");
        let core = scratch.join("core 'quoted' & \"double\"");
        let plist = home
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"));
        fs::create_dir_all(plist.parent().unwrap()).unwrap();
        fs::create_dir(scratch.join("bin")).unwrap();
        tool(
            &scratch.join("bin/id"),
            "printf '%s\\n' \"${TEST_UID:-501}\"",
        );
        tool(
            &scratch.join("bin/launchctl"),
            r#"
printf '%s\0' "$@" >>"$TEST_LOGIN/calls"
printf '\n' >>"$TEST_LOGIN/calls"
[ "$1" != "${FAIL_LAUNCHCTL-}" ] || exit 1
case "$1:$2" in
    print:gui/501) ;;
    print:gui/501/ai.nuanu.immune.watch) [ -f "$TEST_LOGIN/loaded" ] ;;
    bootout:gui/501/ai.nuanu.immune.watch)
        [ -f "$TEST_LOGIN/loaded" ] && rm "$TEST_LOGIN/loaded" ;;
    enable:gui/501/ai.nuanu.immune.watch) ;;
    bootstrap:gui/501)
        [ "$#" -eq 3 ] && [ ! -f "$TEST_LOGIN/loaded" ] &&
            /usr/bin/plutil -lint -s "$3" && cp "$3" "$TEST_LOGIN/loaded" ;;
    *) exit 2 ;;
esac"#,
        );
        tool(
            &core,
            "[ \"$#\" -eq 1 ] && [ \"$1\" = --help ] && echo --background",
        );
        Self {
            scratch,
            home,
            core,
            plist,
        }
    }

    fn command(&self, script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts/core")
                    .join(script),
            )
            .current_dir(&*self.scratch)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.scratch.join("bin").display()),
            )
            .env("HOME", &self.home)
            .env("TEST_LOGIN", &*self.scratch);
        command
    }

    fn install(&self, core: &Path) -> Output {
        self.command("install").arg(core).output().unwrap()
    }

    fn uninstall(&self) -> Output {
        self.command("uninstall").output().unwrap()
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
}

fn tool(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn succeeds(out: Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn fails(out: Output, reason: &str) {
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && said.contains(reason), "{said}");
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

#[test]
fn one_login_job_runs_the_external_core_and_removal_keeps_the_store_and_collector() {
    let login = Login::new("core-service-lifecycle");
    let store = login
        .home
        .join("Library/Application Support/ai.nuanu.immune/store.db");
    fs::create_dir_all(store.parent().unwrap()).unwrap();
    fs::write(&store, "invented store").unwrap();
    let collector = login
        .scratch
        .join("system/Library/LaunchDaemons/ai.nuanu.immune.event-filter.plist");
    fs::create_dir_all(collector.parent().unwrap()).unwrap();
    fs::write(&collector, "invented collector").unwrap();
    let core_before = fs::read(&login.core).unwrap();
    let new_core = login.scratch.join("updated core");
    fs::copy(&login.core, &new_core).unwrap();

    succeeds(login.install(&login.core));
    let installed = plist(&login.plist);
    assert_eq!(installed["Label"], LABEL);
    assert_eq!(
        installed["ProgramArguments"],
        json!([login.core, "watch", "--background"])
    );
    assert_eq!(installed["EnvironmentVariables"]["HOME"], json!(login.home));
    assert_eq!(installed["KeepAlive"], true);
    assert_eq!(installed["ThrottleInterval"], 30);
    assert_eq!(installed["StandardOutPath"], "/dev/null");
    assert_eq!(installed["StandardErrorPath"], "/dev/null");
    assert_eq!(plist(&login.scratch.join("loaded")), installed);
    assert_eq!(
        fs::read_dir(login.plist.parent().unwrap()).unwrap().count(),
        1
    );

    succeeds(login.install(&new_core));
    assert_eq!(
        plist(&login.scratch.join("loaded"))["ProgramArguments"][0],
        json!(new_core)
    );
    succeeds(login.uninstall());
    assert!(!login.loaded() && !login.plist.exists());
    succeeds(login.uninstall());
    assert_eq!(fs::read(&login.core).unwrap(), core_before);
    assert_eq!(fs::read(&new_core).unwrap(), core_before);
    assert_eq!(fs::read_to_string(&store).unwrap(), "invented store");
    assert_eq!(
        fs::read_to_string(&collector).unwrap(),
        "invented collector"
    );
    assert_eq!(
        fs::read_dir(login.plist.parent().unwrap()).unwrap().count(),
        0
    );
    let path = login.plist.to_str().unwrap();
    assert_eq!(
        login.calls(),
        [
            vec!["print", DOMAIN],
            vec!["print", JOB],
            vec!["enable", JOB],
            vec!["bootstrap", DOMAIN, path],
            vec!["print", JOB],
            vec!["print", DOMAIN],
            vec!["print", JOB],
            vec!["bootout", JOB],
            vec!["enable", JOB],
            vec!["bootstrap", DOMAIN, path],
            vec!["print", JOB],
            vec!["print", DOMAIN],
            vec!["print", JOB],
            vec!["bootout", JOB],
            vec!["print", DOMAIN],
            vec!["print", JOB],
        ]
    );
}

#[test]
fn the_installer_accepts_the_core_this_repository_builds() {
    let login = Login::new("core-service-real-core");
    let core = Path::new(env!("CARGO_BIN_EXE_immune"));
    succeeds(login.install(core));
    assert_eq!(
        plist(&login.scratch.join("loaded"))["ProgramArguments"][0],
        json!(core)
    );
}

#[test]
fn the_core_s_help_is_the_usage_on_stdout_with_exit_0() {
    for arg in ["--help", "-h", "help"] {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .arg(arg)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{arg}");
        assert!(said.contains("--background"), "{arg}: {said}");
        assert!(out.stderr.is_empty(), "{arg}");
    }
}

#[test]
fn install_refusals_leave_the_current_job_and_its_plist_in_place() {
    let login = Login::new("core-service-refusals");
    succeeds(login.install(&login.core));
    let before = fs::read(&login.plist).unwrap();
    let calls = login.calls();
    fails(
        login.install(Path::new(login.core.file_name().unwrap())),
        "the core binary path must be absolute",
    );
    let old_core = login.scratch.join("old core");
    tool(&old_core, "echo 'old core'");
    fails(
        login.install(&old_core),
        "this core does not support watch --background",
    );
    let root_core = login.scratch.join("core offered under sudo");
    tool(
        &root_core,
        "touch \"$TEST_LOGIN/ran-as-root\"; echo --background",
    );
    fails(
        login
            .command("install")
            .arg(&root_core)
            .env("TEST_UID", "0")
            .output()
            .unwrap(),
        "without sudo",
    );
    assert!(!login.scratch.join("ran-as-root").exists());
    assert_eq!(login.calls(), calls);
    fails(
        login
            .command("install")
            .arg(&login.core)
            .env("FAIL_LAUNCHCTL", "print")
            .output()
            .unwrap(),
        "the user login session is unavailable",
    );
    assert!(login.loaded());
    assert_eq!(fs::read(&login.plist).unwrap(), before);
    assert_eq!(login.calls().last().unwrap(), &["print", DOMAIN]);
}

#[test]
fn neither_script_follows_a_plist_symlink_or_touches_a_different_job() {
    let login = Login::new("core-service-foreign");
    let foreign = login.scratch.join("foreign.plist");
    fs::write(
        &foreign,
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>org.example.other</string></dict></plist>"#,
    )
    .unwrap();
    let before = fs::read(&foreign).unwrap();
    symlink(&foreign, &login.plist).unwrap();
    fails(login.install(&login.core), "refusing a symbolic link");
    fails(login.uninstall(), "refusing a symbolic link");
    assert_eq!(fs::read_link(&login.plist).unwrap(), foreign);
    assert_eq!(fs::read(&foreign).unwrap(), before);

    fs::remove_file(&login.plist).unwrap();
    fs::copy(&foreign, &login.plist).unwrap();
    fails(login.install(&login.core), "another job occupies");
    fails(login.uninstall(), "another job occupies");
    assert_eq!(fs::read(&login.plist).unwrap(), before);
    assert_eq!(login.calls(), vec![vec!["print", DOMAIN]; 4]);
}

#[test]
fn failed_stop_preserves_the_job_and_failed_reinstall_explains_how_to_retry() {
    let login = Login::new("core-service-recovery");
    succeeds(login.install(&login.core));
    let before = fs::read(&login.plist).unwrap();
    fails(
        login
            .command("uninstall")
            .env("FAIL_LAUNCHCTL", "bootout")
            .output()
            .unwrap(),
        "its plist was kept",
    );
    fails(
        login
            .command("install")
            .arg(&login.core)
            .env("FAIL_LAUNCHCTL", "bootout")
            .output()
            .unwrap(),
        "could not stop",
    );
    assert_eq!(fs::read(&login.plist).unwrap(), before);
    assert!(login.loaded());
    assert_eq!(
        fs::read_dir(login.plist.parent().unwrap()).unwrap().count(),
        1
    );

    fails(
        login
            .command("install")
            .arg(&login.core)
            .env("FAIL_LAUNCHCTL", "bootstrap")
            .output()
            .unwrap(),
        "the core job may be stopped; rerun install to recover",
    );
    assert!(!login.loaded() && login.plist.is_file());
    assert_eq!(
        fs::read_dir(login.plist.parent().unwrap()).unwrap().count(),
        1
    );
    succeeds(login.install(&login.core));
    assert!(login.loaded());
}
