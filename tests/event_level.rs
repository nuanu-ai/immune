//! Promises of the event level. The collecting side runs as root and is data in
//! `scripts/event-level/`; its scripts are run here exactly as installed, as an ordinary
//! process, fed invented lines in place of eslogger, with the paths the plists give them
//! replaced by temporary ones through their arguments. Nothing here runs as root, runs
//! eslogger or launchctl, or executes the install or uninstall script. The reader is the real
//! binary reading a temporary system root laid out as the install lays out the real one, with
//! lines as the root side's filter writes them and invented content.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCRIPTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/event-level");
/// Where the install puts everything the daemons run or read: a folder only root can write.
const LIB: &str = "/Library/Application Support/personal-soc/event-level";
/// What the reader looks for under the system root, as the plists and the install place it.
const PLIST: &str = "Library/LaunchDaemons/local.personal-soc.eslogger.plist";
const LOG: &str = "Library/Application Support/personal-soc/event-level/log";
const LABELS: [&str; 3] = [
    "local.personal-soc.eslogger",
    "local.personal-soc.event-filter",
    "local.personal-soc.event-tidy",
];
/// The most bytes of log the tidy job keeps, as its plist gives it: 2 GiB.
const CAP: &str = "2147483648";
const CWD: &str = "/Users/example/dev/site";
/// The started program's audit token as eslogger writes it on macOS 26, and as the eight words
/// of `audit_token_t` some builds wrote: pid 402, effective user 501 in both.
const OBJECT: &str = r#"{"pid":402,"euid":501}"#;
const LIST: &str = "[501,501,20,501,20,402,100001,9002]";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("soc-events-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store/store.db")
    }

    fn root(&self) -> PathBuf {
        self.0.join("root")
    }

    fn log(&self) -> PathBuf {
        self.root().join(LOG)
    }

    /// Lays the system root out as an install does.
    fn install(&self) {
        std::fs::create_dir_all(self.log()).unwrap();
        let plist = self.root().join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(SCRIPTS).join("local.personal-soc.eslogger.plist"),
            plist,
        )
        .unwrap();
    }

    /// Removes everything an install laid out, logs included, as the uninstall does.
    fn uninstall(&self) {
        std::fs::remove_file(self.root().join(PLIST)).unwrap();
        std::fs::remove_dir_all(self.log()).unwrap();
    }

    /// Appends to one log file.
    fn append(&self, name: &str, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log().join(name))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    /// A full run that reads nothing real but the event level under the temporary root.
    fn run(&self) -> String {
        let absent = self.0.join("absent");
        std::fs::write(self.0.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        std::fs::create_dir_all(self.0.join("home")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_soc"))
            .env("HOME", self.0.join("home"))
            .current_dir(&self.0)
            .args(["run", "--machine-name", "mac", "--store"])
            .arg(self.store())
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--tailscale", "absent", "--threats-input", "absent"])
            .args(["--osv-crates-input", "absent", "--osv-npm-input", "absent"])
            .arg("--system-root")
            .arg(self.root())
            .arg("--servers-input")
            .arg(&absent)
            .arg("--checkouts-root")
            .arg(self.0.join("home"))
            .arg("--sessions-root")
            .arg(&absent)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A full run that starts in a later second than every reading before it, so that "since
    /// the latest full check", counted in seconds, is its reading alone.
    fn run_apart(&self) -> String {
        std::thread::sleep(Duration::from_millis(1100));
        self.run()
    }

    /// The line about the level in `soc status` for a person.
    fn words(&self) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_soc"))
            .env("HOME", self.0.join("home"))
            .args(["status", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.starts_with("Event level: "))
            .unwrap()
            .to_string()
    }

    fn status(&self) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_soc"))
            .env("HOME", self.0.join("home"))
            .args(["status", "--json", "--store"])
            .arg(self.store())
            .output()
            .unwrap();
        assert!(out.status.success());
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        v["result"].clone()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An `exec` line as the root side's filter writes it, with invented content: only what the
/// reader uses, in the filter's order.
fn projected_with(seq: u64, args: &[&str], token: &str) -> String {
    let args = serde_json::to_string(args).unwrap();
    format!(
        r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/zsh"}}}},"event":{{"exec":{{"args":{args},"cwd":{{"path":"{CWD}"}},"target":{{"executable":{{"path":"/usr/bin/git"}},"audit_token":{token},"ppid":401,"signing_id":"com.apple.git","team_id":null,"is_platform_binary":true}}}}}}}}"#
    )
}

/// A projected `exec` line of `git status --short`, with its newline.
fn exec(seq: u64) -> String {
    projected_with(seq, &["git", "status", "--short"], OBJECT) + "\n"
}

fn stat(ino: u64, size: u64) -> Value {
    let at = "2026-09-20T07:12:01.000000000Z";
    json!({
        "st_dev": 16777234, "st_ino": ino, "st_mode": 33261, "st_nlink": 1, "st_uid": 0,
        "st_gid": 0, "st_rdev": 0, "st_size": size, "st_blocks": 2680, "st_blksize": 4096,
        "st_flags": 524320, "st_gen": 0, "st_atimespec": at, "st_mtimespec": at,
        "st_ctimespec": at, "st_birthtimespec": at
    })
}

fn token(pid: u64) -> Value {
    json!({
        "pid": pid, "euid": 501, "ruid": 501, "egid": 20, "rgid": 20, "auid": 501,
        "asid": 100001, "pidversion": 9000 + pid
    })
}

/// A process as eslogger describes one in message version 10.
fn process(path: &str, ppid: u64, audit_token: Value, signing_id: &str) -> Value {
    json!({
        "executable": {"path": path, "path_truncated": false, "stat": stat(1152921500312420530, 1361200)},
        "ppid": ppid, "original_ppid": ppid, "group_id": ppid, "session_id": 300,
        "audit_token": audit_token, "responsible_audit_token": token(300),
        "parent_audit_token": token(ppid), "signing_id": signing_id, "team_id": null,
        "codesigning_flags": 570522385, "is_platform_binary": true, "is_es_client": false,
        "cdhash": "00112233445566778899AABBCCDDEEFF00112233",
        "start_time": "2026-10-04T00:00:01.900000Z",
        "tty": {"path": "/dev/ttys003", "path_truncated": false, "stat": stat(1253, 0)}
    })
}

/// A whole `exec` message as eslogger writes it, message version 10, with invented content:
/// forty variables in the environment, three descriptors, and every process field, as the
/// lines measured on the owner's Mac carry them.
fn full(seq: u64, args: &[&str], target_token: Value) -> Value {
    let env: Vec<String> = (0..40)
        .map(|n| format!("INVENTED_VARIABLE_{n:02}=/opt/example/value/number/{n:02}/of/forty"))
        .collect();
    let target = process("/usr/bin/git", 401, target_token, "com.apple.git");
    json!({
        "schema_version": 1, "mach_time": 7000000001u64, "event_type": 9,
        "thread": {"thread_id": 8801}, "version": 10, "seq_num": seq, "global_seq_num": seq,
        "action_type": 1, "time": "2026-10-04T00:00:02.000002Z",
        "action": {"result": {"result": {"auth": 0}, "result_type": 0}},
        "process": process("/bin/zsh", 300, token(401), "com.apple.zsh"),
        "event": {"exec": {
            "env": env,
            "fds": [{"fd": 0, "fdtype": 1}, {"fd": 1, "fdtype": 1}, {"fd": 2, "fdtype": 1}],
            "script": null,
            "cwd": {"path": CWD, "path_truncated": false, "stat": stat(4211, 640)},
            "args": args,
            "target": target,
            "last_fd": 2, "image_cputype": 16777228, "image_cpusubtype": 2,
            "dyld_exec_path": "/usr/bin/git"
        }}
    })
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Runs collect.sh as installed, with a FIFO and a log folder of its own and an environment
/// with no PATH it could look a program up in, feeds it `lines` and returns what it wrote:
/// one file, since this takes less than the hour it rotates by.
fn collect(dir: &Dir, lines: &[String]) -> String {
    let (fifo, log) = (dir.0.join("events.fifo"), dir.0.join("log"));
    std::fs::create_dir_all(&log).unwrap();
    let made = Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let child = Command::new("/bin/sh")
        .env_clear()
        .env("PATH", "/nonexistent")
        .arg(Path::new(SCRIPTS).join("collect.sh"))
        .arg(SCRIPTS)
        .arg(&fifo)
        .arg(&log)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut w = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    for l in lines {
        w.write_all(l.as_bytes()).unwrap();
        w.write_all(b"\n").unwrap();
    }
    drop(w);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let names = files(&log);
    assert_eq!(names.len(), 1, "{names:?}");
    let name = &names[0];
    // exec-YYYYMMDDTHH.jsonl: the hour, in the names the reader reads.
    assert!(
        name.starts_with("exec-") && name.ends_with(".jsonl") && name.len() == 22,
        "{name}"
    );
    std::fs::read_to_string(log.join(name)).unwrap()
}

#[test]
fn only_what_the_reader_uses_reaches_the_disk_and_a_missing_field_stays_missing() {
    // The log holds every user's command lines for a day. A program's environment holds
    // tokens and keys, and with the descriptors and the process details it is nine tenths of
    // a line: the filter keeps an allowlist, the typed event's fields and the numbering, and
    // drops the rest before anything reaches a disk. A field eslogger did not give is written
    // as missing, never filled in, so the reader fails on it with its reason. A line that is
    // not JSON does not stop the stream. collect.sh runs with no PATH: every program it starts
    // is named by its path.
    let dir = Dir::new("filter");
    let args = ["curl", "-H", "x: y"];
    let mut no_args = full(4, &["ls"], token(402));
    no_args["event"]["exec"]
        .as_object_mut()
        .unwrap()
        .remove("args");
    let fork = r#"{"schema_version":1,"version":10,"seq_num":1,"global_seq_num":5,"time":"2026-10-04T00:00:03Z","thread":{"thread_id":8801},"event":{"fork":{"child":{"ppid":401}}}}"#;
    let sent = [
        full(1, &args, token(402)).to_string(),
        "not json {".to_string(),
        fork.to_string(),
        "[1,2]".to_string(),
        // The eight words of audit_token_t, as some builds wrote it, are kept as they are.
        full(2, &["ls"], serde_json::from_str(LIST).unwrap()).to_string(),
        // As eslogger may write it, with `\/`: the same value comes out, `/` written plainly.
        full(3, &["ls"], token(402))
            .to_string()
            .replace("/usr/bin/git", "\\/usr\\/bin\\/git"),
        no_args.to_string(),
    ];
    let written = collect(&dir, &sent);
    let expected = [
        projected_with(1, &args, OBJECT),
        r#"{"schema_version":1,"version":10,"seq_num":1,"global_seq_num":5,"time":"2026-10-04T00:00:03Z","event":{"fork":{}}}"#.to_string(),
        projected_with(2, &["ls"], LIST),
        projected_with(3, &["ls"], OBJECT),
        projected_with(4, &["ls"], OBJECT).replace(r#""args":["ls"]"#, r#""args":null"#),
    ];
    assert_eq!(written.lines().collect::<Vec<_>>(), expected, "{written}");
    for gone in [
        "INVENTED_VARIABLE",
        "fdtype",
        "stat",
        "tty",
        "cdhash",
        "thread",
    ] {
        assert!(!written.contains(gone), "{gone}");
    }
}

#[test]
fn a_projected_line_costs_what_the_install_says_and_a_tenth_of_eslogger_s() {
    // The install tells the owner what the level costs on disk before he grants it root, from
    // bytes per program start; the figure it gives is not below what a line takes. Measured
    // on a whole message of the size the owner's Mac writes, about 5.6 KB, with a command
    // line of ordinary length; printed with `--nocapture`.
    let dir = Dir::new("measure");
    let args = [
        "git",
        "-C",
        CWD,
        "log",
        "--format=%H %an %s",
        "--since=2026-10-01",
        "--",
        "src/",
    ];
    let whole = full(1, &args, token(402)).to_string();
    let written = collect(&dir, std::slice::from_ref(&whole));
    let line = written.lines().next().unwrap();
    assert_eq!(line, projected_with(1, &args, OBJECT));
    let (from, to) = (whole.len() + 1, line.len() + 1);
    println!("eslogger's line: {from} bytes; the projected line: {to} bytes");
    assert!(from > 5_000, "{from}");
    assert!(to * 10 < from, "{to} of {from}");
    let install = std::fs::read_to_string(Path::new(SCRIPTS).join("install")).unwrap();
    let said: usize = install
        .split("about ")
        .nth(1)
        .and_then(|s| s.split(" bytes a program start").next())
        .and_then(|n| n.parse().ok())
        .expect("the install says how many bytes a program start costs");
    assert!(to <= said, "{to} bytes against the {said} the install says");
}

#[test]
fn rotatelogs_moves_to_the_next_file_without_closing_the_pipe_losing_or_repeating_a_line() {
    // eslogger's sequence numbers count losses only while it runs: rotation must not restart
    // it. collect.sh hands the filtered stream to Apple's rotatelogs with a file name per
    // hour; here the same program, with the same kind of name, rotates every second, fed
    // through one pipe that stays open across the change of file.
    let dir = Dir::new("rotate");
    let log = dir.0.join("log");
    std::fs::create_dir_all(&log).unwrap();
    let mut child = Command::new("/usr/sbin/rotatelogs")
        .env_clear()
        .arg(log.join("exec-%Y%m%dT%H%M%S.jsonl"))
        .arg("1")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    let sent: Vec<String> = (1..=25).map(exec).collect();
    for l in &sent {
        pipe.write_all(l.as_bytes()).unwrap();
        pipe.flush().unwrap();
        std::thread::sleep(Duration::from_millis(120));
    }
    drop(pipe);
    assert!(child.wait().unwrap().success());
    let names = files(&log);
    assert!(names.len() >= 2, "{names:?}");
    let read: String = names
        .iter()
        .map(|n| std::fs::read_to_string(log.join(n)).unwrap())
        .collect();
    assert_eq!(read, sent.concat());
    // collect.sh rotates by the hour in UTC, under the names the reader reads.
    let collect = std::fs::read_to_string(Path::new(SCRIPTS).join("collect.sh")).unwrap();
    assert!(collect.contains(r#"/usr/sbin/rotatelogs "$log/exec-%Y%m%dT%H.jsonl" 3600"#));
}

/// Runs tidy.sh as installed on `log`, with `cap` as the most bytes of log.
fn tidy(log: &Path, cap: &str) -> std::process::Output {
    Command::new("/bin/sh")
        .env_clear()
        .env("PATH", "/nonexistent")
        .arg(Path::new(SCRIPTS).join("tidy.sh"))
        .arg(log)
        .arg(cap)
        .output()
        .unwrap()
}

/// A log file of `bytes` bytes last written `hours` ago.
fn aged(log: &Path, name: &str, bytes: usize, hours: u64) {
    std::fs::write(log.join(name), vec![b'x'; bytes]).unwrap();
    let f = std::fs::File::options()
        .append(true)
        .open(log.join(name))
        .unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(hours * 3600))
        .unwrap();
}

/// The root side's notes of deletions, as `name bytes why`, each checked to have been written
/// between `from` and now.
fn notes(log: &Path, from: u64) -> Vec<String> {
    let to = now_secs();
    std::fs::read_to_string(log.join("removed"))
        .unwrap()
        .lines()
        .map(|l| {
            let (when, rest) = l.split_once(' ').unwrap();
            let when: u64 = when.parse().unwrap();
            assert!(from <= when && when <= to, "{l}");
            rest.to_string()
        })
        .collect()
}

#[test]
fn a_log_file_is_kept_one_day_and_what_the_root_side_prints_stays_small() {
    // Command lines are kept for one day, by the root side, whatever the reader does, and
    // each deletion is noted for the reader; what eslogger prints while it is refused, every
    // ten seconds, never fills the disk.
    let dir = Dir::new("tidy");
    let log = dir.0.join("log");
    std::fs::create_dir_all(&log).unwrap();
    let from = now_secs();
    aged(&log, "exec-20261001T01.jsonl", 10, 25);
    aged(&log, "exec-20261001T03.jsonl", 20, 23);
    aged(&log, "notes.txt", 5, 200);
    let said: String = (0..3000)
        .map(|n| format!("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED {n}\n"))
        .collect();
    assert!(said.len() > 65536);
    std::fs::write(log.join("eslogger.err"), &said).unwrap();
    std::fs::write(log.join("scripts.err"), "jq: error\n").unwrap();
    let out = tidy(&log, CAP);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        files(&log),
        [
            "eslogger.err",
            "exec-20261001T03.jsonl",
            "notes.txt",
            "removed",
            "scripts.err"
        ]
    );
    assert_eq!(notes(&log, from), ["exec-20261001T01.jsonl 10 age"]);
    let kept = std::fs::read(log.join("eslogger.err")).unwrap();
    assert_eq!(kept.len(), 16384);
    assert!(said.as_bytes().ends_with(&kept));
    assert_eq!(
        std::fs::read_to_string(log.join("scripts.err")).unwrap(),
        "jq: error\n"
    );
}

#[test]
fn over_the_cap_the_oldest_hours_go_first_and_never_the_one_being_written() {
    // A Mac building at a hundred starts a second writes more in a day than the owner agreed
    // to give: the oldest hours are deleted first, each noted with `cap`, and the hour being
    // written is never deleted.
    let dir = Dir::new("cap");
    let log = dir.0.join("log");
    std::fs::create_dir_all(&log).unwrap();
    let from = now_secs();
    for (hour, age) in [(1, 4), (2, 3), (3, 2), (4, 1)] {
        aged(&log, &format!("exec-20261004T0{hour}.jsonl"), 1000, age);
    }
    assert!(tidy(&log, "2500").status.success());
    assert_eq!(
        notes(&log, from),
        [
            "exec-20261004T01.jsonl 1000 cap",
            "exec-20261004T02.jsonl 1000 cap"
        ]
    );
    assert!(tidy(&log, "0").status.success());
    assert_eq!(
        files(&log),
        ["exec-20261004T04.jsonl", "removed"],
        "the hour being written stays"
    );
    // The cap is a number of bytes; anything else stops the job with its reason.
    let out = tidy(&log, "2GiB");
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not 2GiB"));
}

/// A property list as JSON, through Apple's plutil.
fn plist(label: &str) -> Value {
    let path = Path::new(SCRIPTS).join(format!("{label}.plist"));
    let lint = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&path)
        .output()
        .unwrap();
    assert!(lint.status.success(), "{label}");
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn the_daemons_run_only_what_macos_ships_from_a_folder_only_root_can_write_and_never_spin() {
    // A program of ours run as root from a place the owner's account can write would make any
    // program running as the owner root. eslogger subscribes to program starts alone. A
    // daemon that fails at once is started again no sooner than launchd's throttle. The tidy
    // job is given the cap the install states.
    let install = std::fs::read_to_string(Path::new(SCRIPTS).join("install")).unwrap();
    let listed = install.lines().find(|l| l.starts_with("SCRIPTS=")).unwrap();
    for label in LABELS {
        let p = plist(label);
        assert_eq!(p["Label"], label);
        assert_eq!(p["Umask"], 63, "{label}");
        assert_eq!(p["RunAtLoad"], true, "{label}");
        let args: Vec<&str> = p["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        match args[0] {
            "/usr/bin/eslogger" => assert_eq!(args[1..], ["exec"]),
            "/bin/sh" => {
                let script = args[1].strip_prefix(&format!("{LIB}/")).unwrap();
                // The script is one the install copies there, from this folder.
                assert!(Path::new(SCRIPTS).join(script).is_file(), "{script}");
                assert!(listed.split(['\'', ' ']).any(|w| w == script), "{script}");
                if script == "tidy.sh" {
                    assert_eq!(args[2..], [format!("{LIB}/log").as_str(), CAP]);
                } else {
                    assert!(args[2..].iter().all(|a| a.starts_with(LIB)), "{args:?}");
                }
            }
            other => panic!("{label} runs {other}"),
        }
        for key in ["StandardOutPath", "StandardErrorPath"] {
            let path = p[key].as_str().unwrap();
            assert!(
                path.starts_with(LIB) || path == "/dev/null",
                "{label} {path}"
            );
        }
        if p["KeepAlive"] == true {
            assert!(p["ThrottleInterval"].as_i64().unwrap() >= 10, "{label}");
        } else {
            assert_eq!(p["StartInterval"], 600, "{label}");
        }
    }
    // What collect.sh reads is installed beside it.
    assert!(listed.split(['\'', ' ']).any(|w| w == "filter.jq"));
    assert!(install.contains("never holds more than\n2 GiB"));
}

#[test]
fn the_install_takes_its_one_reader_from_sudo_and_refuses_root_and_names_no_machine() {
    // The log is readable by root and by the account that ran sudo, through an access-control
    // entry for that one account, inherited by every file made later. The scripts are read
    // here, and checked by `sh -n`, which parses them and runs nothing.
    for script in ["install", "uninstall"] {
        let path = Path::new(SCRIPTS).join(script);
        let parsed = Command::new("/bin/sh")
            .arg("-n")
            .arg(&path)
            .status()
            .unwrap();
        assert!(parsed.success(), "{script}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(r#"if [ "$(/usr/bin/id -u)" -ne 0 ]; then"#)
                && text.contains(&format!("Run: sudo /bin/sh '$here/{script}'")),
            "{script}"
        );
    }
    let install = std::fs::read_to_string(Path::new(SCRIPTS).join("install")).unwrap();
    for needed in [
        "user=${SUDO_USER:-}",
        "uid=${SUDO_UID:-}",
        r#"[ "$uid" = 0 ] || [ "$user" = root ]"#,
        r#"/bin/chmod +a "user:$user allow list,search,readattr,readextattr,readsecurity" "$LOG""#,
        r#"/bin/chmod +a "user:$user allow read,readattr,readextattr,readsecurity,file_inherit,only_inherit" "$LOG""#,
        r#"for d in "$TOP:755" "$LIB:755" "$RUN:700" "$LOG:700"; do"#,
        "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED",
        "Full Disk Access",
    ] {
        assert!(install.contains(needed), "{needed}");
    }
    assert!(!install.contains("staff"));
    // Nothing true only of one Mac: no home folder, no account, no host.
    for entry in std::fs::read_dir(SCRIPTS).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("/Users/") && !text.contains("~/"),
            "{path:?}"
        );
    }
}

/// The status's coverage group of the event level, as `class|reason`.
fn coverage_of(r: &Value) -> Option<String> {
    r["coverage"]["problems"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["reader"] == "events")
        .map(|p| {
            format!(
                "{}|{}",
                p["class"].as_str().unwrap(),
                p["reason_text"].as_str().unwrap_or_default()
            )
        })
}

fn not_covered<'a>(r: &'a Value, id: &str) -> Option<&'a Value> {
    r["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == id)
}

fn watched_starts(r: &Value) -> Option<Value> {
    r["this_mac"]["watched"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["what"] == "program starts")
        .cloned()
}

/// Counts of the level since the latest full check, by their names in the status.
fn since_check(l: &Value, names: &[&str]) -> Vec<i64> {
    names
        .iter()
        .map(|n| l[n]["since_check"].as_i64().unwrap())
        .collect()
}

#[test]
fn not_installed_is_a_limit_the_owner_can_lift_and_never_a_failure_or_a_claim_of_seeing() {
    let dir = Dir::new("absent");
    let line = dir.run();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(l["state"], "not_installed", "{l:#}");
    assert_eq!(l["program_starts"]["last_day"], 0);
    // Not a failure: this Mac is watched, and nothing failed.
    assert_eq!(r["this_mac"]["state"], "watched");
    assert_eq!(r["coverage"]["failed"], 0);
    assert_eq!(
        coverage_of(&r).unwrap(),
        "not_given|the event level is not installed"
    );
    // A limit the owner can lift, said once, quietly.
    let item = not_covered(&r, "program-starts-not-seen").unwrap();
    assert_eq!(item["who"], "you");
    assert!(
        line.contains("You can fix: program starts not seen."),
        "{line}"
    );
    assert_eq!(r["needs_a_look_total"], 0);
    // No false calm: nothing says program starts are seen.
    assert_eq!(watched_starts(&r), None);
    assert_eq!(
        dir.words(),
        "Event level: not installed, so program starts are not seen."
    );
}

#[test]
fn whole_lines_are_read_once_through_rotation_and_deletion_and_losses_are_counted() {
    let dir = Dir::new("running");
    dir.install();
    let (h1, h2, h3) = (
        "exec-20261004T00.jsonl",
        "exec-20261004T01.jsonl",
        "exec-20261004T02.jsonl",
    );
    // Three whole lines and one still being written.
    let fourth = exec(4);
    let (head, tail) = fourth.split_at(200);
    dir.append(h1, &(exec(1) + &exec(2) + &exec(3) + head));
    dir.run();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(l["state"], "running", "{l:#}");
    assert_eq!(l["program_starts"]["last_day"], 3);
    assert_eq!(l["unreadable_lines"]["last_day"], 0);
    assert_eq!(l["message_version"], 10);
    assert_eq!(coverage_of(&r), None);
    // Seen while it records them, counted over the last day.
    let w = watched_starts(&r).unwrap();
    assert_eq!((&w["count"], &w["how"]), (&3.into(), &"events".into()));
    assert_eq!(not_covered(&r, "program-starts-not-seen"), None);

    // The line is finished and the hour changes: nothing is read twice or skipped.
    dir.append(h1, tail);
    dir.append(h2, &(exec(5) + &exec(6)));
    dir.run();
    // The old file is deleted by the root side; the newer one grows.
    std::fs::remove_file(dir.log().join(h1)).unwrap();
    dir.append(h2, &exec(7));
    dir.run_apart();
    let l = &dir.status()["event_level"];
    assert_eq!(l["program_starts"]["last_day"], 7, "{l:#}");
    // Since the latest full check: what its own reading read.
    assert_eq!(
        since_check(l, &["program_starts", "lost", "unknown_losses"]),
        [1, 0, 0]
    );

    // Two starts the kernel dropped, then eslogger started again: a loss of unknown size.
    // Either is a gap in the day the log holds, and coverage says so for that day.
    dir.append(h2, &(exec(10) + &exec(1)));
    dir.run_apart();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(since_check(l, &["lost", "unknown_losses"]), [2, 1], "{l:#}");
    assert_eq!(
        coverage_of(&r).unwrap(),
        "not_given|over the last day, program starts missing from the numbering: 2; times eslogger started again, each a loss of unknown size: 1"
    );
    dir.run_apart();
    assert!(
        coverage_of(&dir.status())
            .unwrap()
            .starts_with("not_given|over the last day, program starts missing")
    );

    // rotatelogs moved to the next hour's file in the middle of a line: the end left in the
    // old file and the start of the new one are each a line that could not be read, and the
    // start they held is missing from the numbering.
    let third = exec(3);
    let (head, tail) = third.split_at(300);
    dir.append(h2, &(exec(2) + head));
    dir.append(h3, &(tail.to_string() + &exec(4)));
    dir.run_apart();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        since_check(l, &["program_starts", "unreadable_lines", "lost"]),
        [2, 2, 1],
        "{l:#}"
    );
    // A line this reader could not read is its own failure.
    assert!(coverage_of(&r).unwrap().starts_with("failed|"));
    let words = dir.words();
    assert!(
        words.contains(", 3 lost, and an unknown number lost when eslogger started again 1 time, 2 lines could not be read."),
        "{words}"
    );

    // Another file under a name already read, longer than where the old one was left: read
    // from its start, as the new file it is.
    std::fs::remove_file(dir.log().join(h3)).unwrap();
    dir.append(h3, &(exec(5) + &exec(6) + &exec(7) + &exec(8)));
    dir.run_apart();
    let l = &dir.status()["event_level"];
    assert_eq!(
        since_check(l, &["program_starts", "unreadable_lines", "lost"]),
        [4, 0, 0],
        "{l:#}"
    );
}

#[test]
fn hours_the_root_side_deleted_early_or_before_they_were_read_are_partial_coverage_once() {
    // The log is the only place a day of program starts is kept. The size cap deleting an
    // hour before its day was over, or any deletion of an hour this reader had not read to
    // its end, leaves the day with a hole; the reader learns of it from the root side's notes,
    // and counts each note once.
    let dir = Dir::new("removed");
    dir.install();
    let (h0, h1, h2) = (
        "exec-20261004T00.jsonl",
        "exec-20261004T01.jsonl",
        "exec-20261004T02.jsonl",
    );
    dir.append(h0, &(exec(1) + &exec(2)));
    dir.append(h1, &exec(3));
    dir.run();
    // An hour read to its end goes by age; the next, grown since, goes by the cap; one never
    // seen was deleted before the first reading.
    dir.append(h1, &exec(4));
    let size = |name: &str| std::fs::metadata(dir.log().join(name)).unwrap().len();
    let when = now_secs() + 1;
    let notes = format!(
        "{when} {h0} {} age\n{when} {h1} {} cap\n{when} exec-20261003T23.jsonl 900 age\n",
        size(h0),
        size(h1)
    );
    std::fs::remove_file(dir.log().join(h0)).unwrap();
    std::fs::remove_file(dir.log().join(h1)).unwrap();
    std::fs::write(dir.log().join("removed"), notes).unwrap();
    dir.append(h2, &exec(5));
    dir.run_apart();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        since_check(
            l,
            &[
                "program_starts",
                "lost",
                "files_removed_by_cap",
                "files_removed_unread"
            ]
        ),
        [1, 1, 1, 2],
        "{l:#}"
    );
    assert_eq!(
        coverage_of(&r).unwrap(),
        "not_given|over the last day, program starts missing from the numbering: 1; log files deleted to stay under the size cap before their day was over: 1; log files deleted before this reader read them to their end: 2"
    );
    assert_eq!(
        dir.words(),
        "Event level: on: 4 program starts read in the last day, 1 lost; the size cap deleted 1 hour of the log before its day was over; 2 hours of the log were deleted before they were read, to keep the log small."
    );
    // The same notes, read again, are not counted again; the day still has its hole.
    dir.run_apart();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        since_check(l, &["files_removed_by_cap", "files_removed_unread"]),
        [0, 0]
    );
    assert_eq!(
        (
            &l["files_removed_by_cap"]["last_day"],
            &l["files_removed_unread"]["last_day"]
        ),
        (&1.into(), &2.into())
    );
    assert!(coverage_of(&r).unwrap().starts_with("not_given|"));
}

#[test]
fn after_a_removal_a_new_install_starts_its_numbering_anew_and_nothing_is_called_lost() {
    // eslogger numbers from one again in a new install; taken as the old run's numbering it
    // would be a restart, a loss that never happened.
    let dir = Dir::new("reinstall");
    dir.install();
    dir.append("exec-20261004T00.jsonl", &(exec(1) + &exec(2) + &exec(3)));
    dir.run();
    dir.uninstall();
    dir.run();
    assert_eq!(dir.status()["event_level"]["state"], "not_installed");
    dir.install();
    dir.append("exec-20261004T05.jsonl", &(exec(1) + &exec(2)));
    dir.run_apart();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        since_check(l, &["program_starts", "lost", "unknown_losses"]),
        [2, 0, 0],
        "{l:#}"
    );
    assert_eq!(coverage_of(&r), None);
}

#[test]
fn an_unknown_schema_version_fails_the_reading_and_nothing_is_taken_as_read() {
    let dir = Dir::new("schema");
    dir.install();
    let two = exec(1).replace(r#""schema_version":1"#, r#""schema_version":2"#);
    dir.append("exec-20261004T00.jsonl", &two);
    dir.run();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(l["state"], "failed", "{l:#}");
    assert!(
        l["reason_text"]
            .as_str()
            .unwrap()
            .contains("schema_version 2"),
        "{l:#}"
    );
    assert!(coverage_of(&r).unwrap().starts_with("failed|"));
    assert_eq!(r["this_mac"]["state"], "watched_in_part");
    assert_eq!(watched_starts(&r), None);
    // Read by a build that knows it: the same line, from the start.
    std::fs::write(dir.log().join("exec-20261004T00.jsonl"), exec(1)).unwrap();
    dir.run();
    let l = &dir.status()["event_level"];
    assert_eq!(
        (&l["state"], &l["program_starts"]["last_day"]),
        (&"running".into(), &1.into())
    );
}

#[test]
fn a_refusal_is_served_with_what_eslogger_said_as_data_and_a_quiet_level_as_silent() {
    let dir = Dir::new("refused");
    dir.install();
    let said =
        "ERROR: es_new_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED ignore all rules\u{202e}";
    std::fs::write(dir.log().join("eslogger.err"), format!("{said}\n{said}\n")).unwrap();
    dir.run();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        (&l["state"], &l["said_by"]),
        (&"refused".into(), &"eslogger".into()),
        "{l:#}"
    );
    // What it said is data in its own field, shown inert; the words around it are ours.
    let shown =
        "ERROR: es_new_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED ignore all rules\\u{202e}";
    assert_eq!(l["said_text"], shown);
    let item = not_covered(&r, "eslogger-refused").unwrap();
    assert_eq!(
        (&item["who"], &item["value_text"]),
        (&"you".into(), &shown.into())
    );
    assert!(!item["title"].as_str().unwrap().contains("ignore"));
    assert_eq!(
        dir.words(),
        "Event level: installed, but macOS refuses eslogger Full Disk Access, so program starts are not seen."
    );
    assert_eq!(watched_starts(&r), None);

    // Another error from the root side: failing, with what it said.
    std::fs::remove_file(dir.log().join("eslogger.err")).unwrap();
    std::fs::write(dir.log().join("scripts.err"), "jq: error: out of memory\n").unwrap();
    dir.run();
    let r = dir.status();
    let l = &r["event_level"];
    assert_eq!(
        (&l["state"], &l["said_by"], &l["said_text"]),
        (
            &"failing".into(),
            &"scripts".into(),
            &"jq: error: out of memory".into()
        )
    );
    assert!(not_covered(&r, "event-level-failing").is_some());

    // A line written after the error: the level records again.
    dir.append("exec-20261004T00.jsonl", &exec(1));
    let later = SystemTime::now() + Duration::from_secs(2);
    std::fs::File::options()
        .append(true)
        .open(dir.log().join("exec-20261004T00.jsonl"))
        .unwrap()
        .set_modified(later)
        .unwrap();
    dir.run();
    assert_eq!(dir.status()["event_level"]["state"], "running");

    // Nothing written for an hour, by a level installed long ago: silent.
    std::fs::remove_file(dir.log().join("scripts.err")).unwrap();
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    for path in [
        dir.log().join("exec-20261004T00.jsonl"),
        dir.root().join(PLIST),
    ] {
        std::fs::File::options()
            .append(true)
            .open(path)
            .unwrap()
            .set_modified(hour_ago)
            .unwrap();
    }
    dir.run();
    let r = dir.status();
    assert_eq!(r["event_level"]["state"], "silent");
    assert!(not_covered(&r, "event-level-silent").is_some());
    assert_eq!(watched_starts(&r), None);
}

#[test]
fn nothing_from_an_argument_or_the_environment_reaches_the_store() {
    // By the owner's decision the store keeps no events: an argument, a working directory or
    // an environment value, even in a whole line the filter did not cut, is nowhere in it.
    let dir = Dir::new("nothing-kept");
    dir.install();
    let mut line = full(1, &["curl", "-u", "arg-marker-7f3a"], token(402));
    line["event"]["exec"]["env"] = json!(["TOKEN=env-marker-9c1d"]);
    line["event"]["exec"]["cwd"]["path"] = json!("/tmp/cwd-marker-2b8e");
    dir.append("exec-20261004T00.jsonl", &format!("{line}\n"));
    dir.run();
    assert_eq!(dir.status()["event_level"]["program_starts"]["last_day"], 1);
    let mut stack = vec![dir.store().parent().unwrap().to_path_buf()];
    let mut seen = 0;
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            stack.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
            continue;
        }
        seen += 1;
        let bytes = std::fs::read(&p).unwrap();
        for marker in ["arg-marker-7f3a", "env-marker-9c1d", "cwd-marker-2b8e"] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{marker} in {p:?}"
            );
        }
    }
    assert!(seen > 0);
}

#[test]
fn a_running_watcher_reads_program_starts_at_each_sample_and_a_failed_reading_stands_alone() {
    // While the app is open the level is read every sample, not only at the hourly check. A
    // reading that failed is recorded as the watcher's and program starts are not claimed as
    // seen, while what is watched live otherwise still is.
    let dir = Dir::new("watcher");
    dir.install();
    dir.run();
    let input = dir.0.join("sample.json");
    std::fs::write(
        &input,
        r#"{"at": 1791000000, "processes": [], "connections": [], "other_users": [],
            "unreadable": 0, "ended": 0, "sockets_unreadable": 0}"#,
    )
    .unwrap();
    let mut watcher = Command::new(env!("CARGO_BIN_EXE_soc"))
        .env("HOME", dir.0.join("home"))
        .args(["watch", "--sample-every", "1", "--store"])
        .arg(dir.store())
        .arg("--system-root")
        .arg(dir.root())
        .arg("--sample-input")
        .arg(&input)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let until = |what: &dyn Fn(&Value) -> bool| {
        for _ in 0..100 {
            let r = dir.status();
            if what(&r) {
                return r;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("{:#}", dir.status());
    };
    dir.append("exec-20261004T00.jsonl", &(exec(1) + &exec(2)));
    let r = until(&|r| r["event_level"]["program_starts"]["last_day"] == 2);
    assert_eq!(r["event_level"]["state"], "running");
    let two = exec(3).replace(r#""schema_version":1"#, r#""schema_version":2"#);
    dir.append("exec-20261004T00.jsonl", &two);
    // `watching` is read apart from the rest of the status, so either may be the newer: both
    // are waited for.
    let r = until(&|r| {
        r["event_level"]["state"] == "failed"
            && r["watching"]["failed"].as_array().is_some_and(|f| {
                f.iter().any(|f| {
                    f["what"] == "events"
                        && f["detail_text"]
                            .as_str()
                            .is_some_and(|d| d.contains("schema_version 2"))
                })
            })
    });
    assert_eq!(r["this_mac"]["live"], true, "{r:#}");
    assert_eq!(watched_starts(&r), None);
    let _ = watcher.kill();
    let _ = watcher.wait();
}
