//! Promises of `immune matches`, the queue of rule matches the response layer reads. The real
//! binary reads a temporary system root laid out as the event level's install lays out the real
//! one, with log lines as the collector's filter writes them and invented content. Nothing here
//! reads the real log or the real store.

use immune_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SCRIPTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/event-level");
const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
const CWD: &str = "/Users/example/dev/site";
const T0: &str = "2026-10-04T00:00:02.000002Z";
const H00: &str = "exec-20261004T00.jsonl";
const H01: &str = "exec-20261004T01.jsonl";

/// "Binary Padding - MacOS", high, and the arguments of the start Atomic Red Team's test makes.
const PADDING: &str = "95361ce5-c891-4b0a-87ca-e24607884a96";
const DD: [&str; 4] = ["dd", "if=/dev/zero", "bs=1", "count=1"];
/// "System Information Discovery Using sw_vers", medium.
const SW_VERS: &str = "5de06a6f-673a-4fc0-8d48-bcfe3837b033";
/// "Axios NPM Compromise File Creation Indicators - MacOS", high.
const AXIOS: &str = "2db0458c-05c9-4069-a26f-77becd9c8c13";
/// "Python Path Configuration File Creation - MacOS", medium.
const PTH: &str = "4f394635-13ef-4599-b677-3353e0f84f55";
/// The rule evaluated in part: one branch reads `OriginalFileName`, which macOS does not give.
const IN_PART: &str = "rules/macos/process_creation/proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "immune-matches-{tag}-{}-{nanos}",
            std::process::id()
        ));
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

    /// Lays the system root out as an install does: the launch daemon, the log folder, and the
    /// record of what it collects, extracted by Apple's plutil as the install extracts it.
    fn install(&self) {
        self.install_before_file_events();
        let out = Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments", "json", "-o"])
            .arg(self.root().join(COLLECTS))
            .arg(self.root().join(PLIST))
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    /// As an install from before file events: no record of what the collector records.
    fn install_before_file_events(&self) {
        std::fs::create_dir_all(self.log()).unwrap();
        let plist = self.root().join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(SCRIPTS).join("ai.nuanu.immune.eslogger.plist"),
            plist,
        )
        .unwrap();
    }

    /// As the uninstall leaves it: the launch daemon and the whole log deleted.
    fn uninstall(&self) {
        std::fs::remove_file(self.root().join(PLIST)).unwrap();
        std::fs::remove_dir_all(self.log().parent().unwrap()).unwrap();
    }

    fn append(&self, name: &str, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log().join(name))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    /// Sets when a log file was last written to.
    fn touch(&self, name: &str, when: SystemTime) {
        std::fs::File::options()
            .append(true)
            .open(self.log().join(name))
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    /// Deletes a log file as the root side's tidy job does, with its note.
    fn tidy_away(&self, name: &str) {
        let bytes = std::fs::metadata(self.log().join(name)).unwrap().len();
        std::fs::remove_file(self.log().join(name)).unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        self.append(
            "removed",
            &format!("{} {name} {bytes} age\n", now.as_secs()),
        );
    }

    fn inode(&self, name: &str) -> u64 {
        std::fs::metadata(self.log().join(name)).unwrap().ino()
    }

    /// A match's position in a log file, as the answer gives it.
    fn position(&self, name: &str, offset: usize) -> String {
        let hour = &name["exec-".len()..name.len() - ".jsonl".len()];
        format!("{hour}-{}-{offset}", self.inode(name))
    }

    /// `immune <args> <more> --store <this store>`, to be run.
    fn command(&self, args: &[&str], more: &[&std::ffi::OsStr]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_immune"));
        c.env("HOME", self.0.join("home"))
            .current_dir(&self.0)
            .args(args)
            .args(more)
            .arg("--store")
            .arg(self.store());
        c
    }

    /// A full run that reads nothing real but the event level under the temporary root. The
    /// core's own reading reads the log, and the store is made.
    fn run(&self) {
        let absent = self.0.join("absent");
        std::fs::write(self.0.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        std::fs::create_dir_all(self.0.join("home")).unwrap();
        std::fs::create_dir_all(self.store().parent().unwrap()).unwrap();
        let (brew, root, home) = (self.0.join("brew.json"), self.root(), self.0.join("home"));
        let out = self
            .command(
                &[
                    "run",
                    "--machine-name",
                    "mac",
                    "--tailscale",
                    "absent",
                    "--threats-input",
                    "absent",
                    "--osv-crates-input",
                    "absent",
                    "--osv-npm-input",
                    "absent",
                ],
                &[
                    "--brew-input".as_ref(),
                    brew.as_os_str(),
                    "--system-root".as_ref(),
                    root.as_os_str(),
                    "--servers-input".as_ref(),
                    absent.as_os_str(),
                    "--checkouts-root".as_ref(),
                    home.as_os_str(),
                    "--sessions-root".as_ref(),
                    absent.as_os_str(),
                ],
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The result of a report command's `--json` envelope.
    fn report(&self, args: &[&str]) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let out = self.command(&args, &[]).output().unwrap();
        assert!(out.status.success());
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["result"].clone()
    }

    /// `immune matches <args>` over this root and store, as it ran.
    fn matches_output(&self, args: &[&str]) -> Output {
        let root = self.root();
        let mut more: Vec<&std::ffi::OsStr> = vec![root.as_os_str()];
        more.extend(args.iter().map(std::ffi::OsStr::new));
        self.command(&["matches", "--system-root"], &more)
            .output()
            .unwrap()
    }

    /// `immune matches <args> --json` over this root and store: its message.
    fn matches(&self, args: &[&str]) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let out = self.matches_output(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// `immune matches <args>` in binary: its stdout.
    fn matches_binary(&self, args: &[&str]) -> Vec<u8> {
        let mut args = args.to_vec();
        args.push("--proto");
        let out = self.matches_output(&args);
        assert!(out.status.success());
        out.stdout
    }

    /// The findings of SigmaHQ's rule `id`, in every state.
    fn findings_of(&self, id: &str) -> Vec<String> {
        self.findings_named(&format!("sigma:{id}"))
    }

    /// The findings of the rule named `rule`, as findings name it, in every state.
    fn findings_named(&self, rule: &str) -> Vec<String> {
        let out = self.command(&["findings", "--json"], &[]).output().unwrap();
        assert!(out.status.success());
        let all: Value = serde_json::from_slice(&out.stdout).unwrap();
        all["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["finding"]["rule"] == rule)
            .map(|f| f["finding"]["id"].as_str().unwrap().to_string())
            .collect()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An `exec` line as the collector's filter writes it, with invented content and its newline.
fn start(seq: u64, time: &str, parent: &str, image: &str, args: &[&str]) -> String {
    let args = serde_json::to_string(args).unwrap();
    format!(
        r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"{time}","process":{{"executable":{{"path":"{parent}"}}}},"event":{{"exec":{{"args":{args},"cwd":{{"path":"{CWD}"}},"target":{{"executable":{{"path":"{image}"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.example.tool","team_id":null,"is_platform_binary":false}}}}}}}}"#
    ) + "\n"
}

/// A program start that Binary Padding matches.
fn dd(seq: u64) -> String {
    start(seq, T0, "/bin/sh", "/bin/dd", &DD)
}

/// A program start no rule matches.
fn git(seq: u64) -> String {
    start(seq, T0, "/bin/zsh", "/usr/bin/git", &["git", "status"])
}

/// A program start sw_vers matches, medium.
fn sw_vers(seq: u64) -> String {
    start(
        seq,
        T0,
        "/bin/zsh",
        "/usr/bin/sw_vers",
        &["sw_vers", "-productVersion"],
    )
}

/// A file event as the filter writes it, with its newline; a rename comes from an invented
/// source.
fn file_event(seq: u64, kind: &str, program: &str, path: &str) -> String {
    let source = match kind {
        "rename" => r#","source":"/Users/example/dev/site/.tmp-1""#,
        _ => "",
    };
    format!(
        r#"{{"schema_version":1,"seq_num":{seq},"time":"{T0}","process":{{"executable":{{"path":"{program}"}}}},"event":{{"{kind}":{{"destination":"{path}"{source}}}}}}}"#
    ) + "\n"
}

/// Lines as the root side's filter writes them from whole eslogger messages: Apple's jq run
/// with `filter.jq` as collect.sh runs it.
fn filtered(messages: &[Value]) -> String {
    let mut jq = Command::new("/usr/bin/jq")
        .args(["--raw-input", "--compact-output", "-f"])
        .arg(Path::new(SCRIPTS).join("filter.jq"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = jq.stdin.take().unwrap();
    for m in messages {
        writeln!(input, "{m}").unwrap();
    }
    drop(input);
    let out = jq.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn a_match_hands_over_who_the_process_was_as_the_collector_keeps_it() {
    // The response layer looks into a match by the process behind it, and a pid alone is
    // reused. Each match carries what the collector keeps of who the process was: the program
    // started, with its pid version, start time and code-signing flags; the process before the
    // `exec`; the parent's pid and pid version; the script; and for a file event the program
    // that did it, with its signing id. Here from whole messages through the filter itself.
    let dir = Dir::new("identity");
    dir.install();
    dir.run();
    let token = |pid: u64, version: u64| json!({"pid": pid, "euid": 501, "pidversion": version, "asid": 100001});
    let process = |path: &str, audit_token: Value| {
        json!({
            "executable": {"path": path, "path_truncated": false},
            "audit_token": audit_token, "parent_audit_token": [501, 501, 20, 501, 20, 401, 100001, 9300],
            "ppid": 401, "signing_id": "com.example.tool", "team_id": null,
            "is_platform_binary": false, "codesigning_flags": 570522385,
            "start_time": "2026-10-04T00:00:01.900000Z",
        })
    };
    let exec = json!({
        "schema_version": 1, "version": 10, "seq_num": 1, "global_seq_num": 1, "time": T0,
        "process": process("/bin/sh", token(402, 9401)),
        "event": {"exec": {
            "env": ["INVENTED=1"], "args": DD, "cwd": {"path": CWD},
            "script": {"path": "/Users/example/pad.sh", "path_truncated": false},
            "target": process("/bin/dd", token(402, 9402)),
        }},
    });
    let create = json!({
        "schema_version": 1, "version": 10, "seq_num": 1, "global_seq_num": 2, "time": T0,
        "process": process("/usr/local/bin/node", json!([501, 501, 20, 501, 20, 500, 100001, 9500])),
        "event": {"create": {"destination_type": 0, "destination": {"existing_file": {"path": "/private/tmp/6202033", "path_truncated": false}}}},
    });
    dir.append(H00, &filtered(&[exec, create]));
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING, AXIOS]);
    // 2026-10-04T00:00:01.900000Z
    let started = (1_791_072_001i64, 900_000_000i64);
    let start = &m["matches"][0]["event"]["program_start"];
    let p = &start["process"];
    assert_eq!(
        (
            &p["pid"],
            &p["pid_version"],
            &p["started_at"],
            &p["started_nanos"],
            &p["codesigning_flags"]
        ),
        (
            &json!(402),
            &json!(9402),
            &json!(started.0),
            &json!(started.1),
            &json!(570522385)
        )
    );
    let i = &start["instigator"];
    assert_eq!(
        (
            &i["executable_text"],
            &i["pid"],
            &i["pid_version"],
            &i["started_at"],
            &i["codesigning_flags"]
        ),
        (
            &json!("/bin/sh"),
            &json!(402),
            &json!(9401),
            &json!(started.0),
            &json!(570522385)
        )
    );
    assert_eq!(start["parent"], json!({"pid": 401, "pid_version": 9300}));
    assert_eq!(start["script_text"], "/Users/example/pad.sh");
    let f = &m["matches"][1]["event"]["file_event"]["instigator"];
    assert_eq!(
        (
            &f["pid"],
            &f["pid_version"],
            &f["started_at"],
            &f["signing_id_text"]
        ),
        (
            &json!(500),
            &json!(9500),
            &json!(started.0),
            &json!("com.example.tool")
        )
    );
    assert_eq!(m["collector"]["not_kept"], json!([]));
}

/// The time now as eslogger writes it, a microsecond past the second.
fn now_time() -> String {
    let out = Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S.000001Z"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// The rule ids of an answer's matches, in order.
fn rules_of(m: &Value) -> Vec<String> {
    m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["rule"]["id_text"].as_str().unwrap().to_string())
        .collect()
}

/// What each match of an answer raised, and the finding it went to with its state.
fn raised_of(m: &Value) -> Vec<(String, Option<(String, String)>)> {
    m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let f = x["findings"].as_array().unwrap();
            assert!(f.len() <= 1, "{x:#}");
            (
                x["raised"].as_str().unwrap().to_string(),
                f.first().map(|f| {
                    (
                        f["id"].as_str().unwrap().to_string(),
                        f["state"].as_str().unwrap().to_string(),
                    )
                }),
            )
        })
        .collect()
}

fn r(raised: &str) -> (String, Option<(String, String)>) {
    (raised.to_string(), None)
}

fn to(id: &str, state: &str) -> (String, Option<(String, String)>) {
    (
        "finding".to_string(),
        Some((id.to_string(), state.to_string())),
    )
}

/// Every string in `v` that holds `marker`, with the name of the field it is under.
fn holders<'a>(v: &'a Value, key: &'a str, marker: &str, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) if s.contains(marker) => out.push(key),
        Value::Array(items) => items.iter().for_each(|i| holders(i, key, marker, out)),
        Value::Object(m) => m.iter().for_each(|(k, i)| holders(i, k, marker, out)),
        _ => {}
    }
}

/// Reads an answer through every page of `limit` matches, from `after`: the matches, the
/// stretches' tallies of program starts, unreadable lines, lost starts and file events, and the
/// place to read on from.
fn pages(dir: &Dir, after: Option<String>, limit: &str) -> (Vec<Value>, [i64; 4], String) {
    let mut after = after;
    let mut all = Vec::new();
    let mut sums = [0i64; 4];
    for turn in 0.. {
        assert!(turn < 20);
        let mut args = vec!["--limit", limit];
        if let Some(a) = &after {
            args.extend(["--after", a]);
        }
        let m = dir.matches(&args);
        assert_eq!(m["after"], json!(after));
        all.extend(m["matches"].as_array().unwrap().iter().cloned());
        for (i, k) in [
            "program_starts",
            "unreadable_lines",
            "program_starts_lost",
            "file_events",
        ]
        .iter()
        .enumerate()
        {
            sums[i] += m["stretch"][k].as_i64().unwrap();
        }
        after = m["continue_after"].as_str().map(str::to_string);
        if m["more"] == false {
            break;
        }
    }
    (all, sums, after.unwrap())
}

#[test]
fn a_match_says_which_finding_it_went_to_as_the_core_recorded_it_with_the_person_s_answer() {
    // The response layer looks into what the core is not sure of, so it gets every match of
    // every level with the event whole. A high one names the finding the core's own reading
    // put it in, with that finding's state now, so a match the person already answered is not
    // taken for a new one; or it says the core has not read it yet.
    let dir = Dir::new("levels");
    dir.install();
    dir.run();
    let t1 = now_time();
    dir.append(
        H00,
        &(start(1, &t1, "/bin/sh", "/bin/dd", &DD)
            + &start(
                2,
                &t1,
                "/bin/zsh",
                "/usr/bin/sw_vers",
                &["sw_vers", "-productVersion"],
            )),
    );
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING, SW_VERS]);
    let (high, medium) = (&m["matches"][0], &m["matches"][1]);
    assert_eq!(high["position"], dir.position(H00, 0));
    assert_eq!(raised_of(&m), [r("not_read_yet"), r("below_high")]);
    assert_eq!(
        medium["rule"],
        json!({
            "name": format!("sigma:{SW_VERS}"),
            "file": "rules/macos/process_creation/proc_creation_macos_swvers_discovery.yml",
            "id_text": SW_VERS,
            "title_text": "System Information Discovery Using sw_vers",
            "level": "medium",
            "techniques_text": ["T1082"],
            "author_text": "Joseliyo Sanchez, @Joseliyo_Jstnk",
            "source": "sigma",
            "set": "SigmaHQ's rule set",
        })
    );
    let secs: i64 = {
        let out = Command::new("/bin/date")
            .args(["-u", "-j", "-f", "%Y-%m-%dT%H:%M:%S", &t1[..19], "+%s"])
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };
    assert_eq!(
        medium["event"],
        json!({
            "program_start": {
                "happened_at": secs,
                "happened_nanos": 1000,
                "process": {
                    "executable_text": "/usr/bin/sw_vers",
                    "pid": 402,
                    "user_id": 501,
                    "signing_id_text": "com.example.tool",
                    "team_id_text": null,
                    "platform_binary": false,
                    "pid_version": null,
                    "started_at": null,
                    "started_nanos": null,
                    "codesigning_flags": null,
                },
                "instigator": {
                    "executable_text": "/bin/zsh",
                    "pid": null,
                    "user_id": null,
                    "signing_id_text": null,
                    "team_id_text": null,
                    "platform_binary": null,
                    "pid_version": null,
                    "started_at": null,
                    "started_nanos": null,
                    "codesigning_flags": null,
                },
                "parent_pid": 401,
                "args_text": ["sw_vers", "-productVersion"],
                "working_directory_text": CWD,
                "parent": null,
                "script_text": null,
            },
        })
    );

    // Once the core's own reading has read it, the high match names its finding.
    dir.run();
    let [first] = <[String; 1]>::try_from(dir.findings_of(PADDING)).unwrap();
    let m = dir.matches(&[]);
    assert_eq!(raised_of(&m), [to(&first, "open"), r("below_high")]);
    assert_eq!(
        m["matches"][0]["findings"][0]["rule"],
        format!("sigma:{PADDING}")
    );

    // The person marks it expected; a repeat goes to the same finding, and both matches say
    // it was answered.
    dir.report(&["finding", &first, "expected", "--reason", "invented"]);
    dir.append(H00, &start(3, &now_time(), "/bin/sh", "/bin/dd", &DD));
    dir.run();
    let m = dir.matches(&[]);
    assert_eq!(
        raised_of(&m),
        [
            to(&first, "expected"),
            r("below_high"),
            to(&first, "expected")
        ]
    );

    // The person closes it; a later start raises a new finding. Each match names the finding
    // it went to, the closed one too, whatever the times the findings were last seen.
    dir.report(&["finding", &first, "seen"]);
    dir.append(H00, &start(4, &now_time(), "/bin/sh", "/bin/dd", &DD));
    assert_eq!(raised_of(&dir.matches(&[]))[3], r("not_read_yet"));
    dir.run();
    let second = dir
        .findings_of(PADDING)
        .into_iter()
        .find(|f| *f != first)
        .unwrap();
    let store = rusqlite::Connection::open(dir.store()).unwrap();
    store
        .execute(
            "UPDATE finding SET last_seen_at = last_seen_at + 86400 WHERE id = ?1",
            [&first],
        )
        .unwrap();
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING, SW_VERS, PADDING, PADDING]);
    assert_eq!(
        raised_of(&m),
        [
            to(&first, "seen"),
            r("below_high"),
            to(&first, "seen"),
            to(&second, "open")
        ]
    );
}

#[test]
fn a_line_read_with_no_finding_and_one_read_before_the_record_are_told_apart_and_never_guessed() {
    // A match the core's own reading read, and that no finding holds, says so; one it read
    // before the store kept which finding each match went to says it cannot tell. Neither is
    // tied to a finding by a guess.
    let dir = Dir::new("unrecorded");
    dir.install();
    dir.run();
    dir.append(H00, &(dd(1) + &git(2)));
    dir.run();
    let [first] = <[String; 1]>::try_from(dir.findings_of(PADDING)).unwrap();
    assert_eq!(raised_of(&dir.matches(&[])), [to(&first, "open")]);
    let store = rusqlite::Connection::open(dir.store()).unwrap();
    // As a build that lacked the rule leaves it: read, and nothing recorded of it.
    store.execute("DELETE FROM rule_line", []).unwrap();
    assert_eq!(raised_of(&dir.matches(&[])), [r("no_finding")]);
    // As a store from before the record: the line read, and no record kept at all.
    store
        .execute_batch("DROP TABLE rule_line; DROP TABLE rule_line_from;")
        .unwrap();
    assert_eq!(raised_of(&dir.matches(&[])), [r("unrecorded")]);
    // A reading of this build begins the record: what it reads now is told, what was read
    // before is not.
    dir.append(H00, &dd(3));
    dir.run();
    assert_eq!(
        raised_of(&dir.matches(&[])),
        [r("unrecorded"), to(&first, "open")]
    );
    // The first line read with the record kept is told apart from those before it.
    store.execute("DELETE FROM rule_line", []).unwrap();
    assert_eq!(
        raised_of(&dir.matches(&[])),
        [r("unrecorded"), r("no_finding")]
    );
    // A file the reading no longer finds takes its record with it.
    dir.append(H00, &dd(5));
    dir.run();
    let count = |table: &str| -> i64 {
        store
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!((count("rule_line"), count("rule_line_from")), (1, 1));
    dir.append(H01, &git(4));
    dir.tidy_away(H00);
    dir.run();
    let rows: i64 = store
        .query_row(
            "SELECT (SELECT COUNT(*) FROM rule_line) + (SELECT COUNT(*) FROM rule_line_from)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn not_read_yet_is_no_promise_a_line_deleted_before_the_core_read_it_raises_nothing() {
    // `not_read_yet` says the core's reading has not reached the line, not that it will: a
    // line deleted first is never read and no finding holds it. A reader that kept the place
    // is told the lines are gone.
    let dir = Dir::new("deleted-unread");
    dir.install();
    dir.run();
    dir.append(H00, &(git(1) + &dd(2)));
    let m = dir.matches(&[]);
    assert_eq!(raised_of(&m), [r("not_read_yet")]);
    let place = m["continue_after"].as_str().unwrap().to_string();
    dir.append(H00, &dd(3));
    dir.append(H01, &git(4));
    dir.tidy_away(H00);
    dir.run();
    assert!(dir.findings_of(PADDING).is_empty());
    let m = dir.matches(&["--after", &place]);
    assert_eq!(
        (&m["stretch"]["gone"], &m["stretch"]["kept_from"]),
        (&json!(true), &json!(dir.position(H01, 0)))
    );
    assert_eq!(m["matches"], json!([]));
}

#[test]
fn what_immune_matches_gives_and_what_the_core_s_reading_counts_agree_for_the_same_log() {
    // One way of evaluating: the queue and the core's own reading cannot disagree about what
    // matched, program starts and file events alike.
    let dir = Dir::new("agree");
    dir.install();
    dir.run();
    dir.append(
        H00,
        &(dd(1)
            + &sw_vers(2)
            + &git(3)
            + &start(
                4,
                T0,
                "/bin/zsh",
                "/usr/bin/base64",
                &["base64", "-d", "in.txt"],
            )
            + &start(5, T0, "/bin/zsh", "/usr/bin/split", &["split", "big.bin"])
            + &file_event(1, "create", "/usr/local/bin/node", "/private/tmp/6202033")
            + &file_event(
                2,
                "create",
                "/usr/bin/python3",
                "/Users/example/lib/python3.12/site-packages/x.pth",
            )
            + &start(6, T0, "/bin/zsh", "/usr/bin/split", &["split", "big.bin"])),
    );
    let m = dir.matches(&[]);
    let mut given: std::collections::BTreeMap<String, i64> = Default::default();
    for id in rules_of(&m) {
        *given.entry(id).or_default() += 1;
    }
    assert!(
        given.contains_key(AXIOS) && given.contains_key(PTH),
        "{given:?}"
    );
    // The core's reading of the log on disk without the store.
    let out = Command::new(env!("CARGO_BIN_EXE_immune"))
        .args(["rules", "--over-log", "--json", "--system-root"])
        .arg(dir.root())
        .output()
        .unwrap();
    let replay: Value = serde_json::from_slice(&out.stdout).unwrap();
    let replayed: std::collections::BTreeMap<String, i64> = replay["result"]["matched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["id_text"].as_str().unwrap().to_string(),
                r["matches"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(given, replayed);
    let s = &m["stretch"];
    let r = &replay["result"];
    assert_eq!(
        (&s["program_starts"], &s["file_events"]),
        (&r["program_starts"], &r["file_events"])
    );
    // And the reading that makes findings, through the store.
    dir.run();
    let rules = dir.report(&["rules"]);
    let counted: std::collections::BTreeMap<String, i64> = ["evaluated", "in_part"]
        .iter()
        .flat_map(|k| rules[*k].as_array().unwrap().iter())
        .filter(|r| r["matches_last_day"].as_i64().unwrap() > 0)
        .map(|r| {
            (
                r["id_text"].as_str().unwrap().to_string(),
                r["matches_last_day"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(given, counted);
    let m = dir.matches(&[]);
    let high: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["rule"]["level"] == "high")
        .collect();
    assert_eq!(high.len(), 2);
    assert!(high.iter().all(|x| x["raised"] == "finding"), "{high:#?}");
}

#[test]
fn reading_on_from_the_place_given_gives_the_rest_and_nothing_twice_across_the_turn_of_an_hour() {
    // The caller keeps its place. Read on one match at a time from the place each answer
    // gives, the answers add up to one reading of the whole log: the same matches, none twice,
    // and the same counts, a gap in eslogger's numbering at the seam between two answers and a
    // line split at the turn of the hour included.
    let dir = Dir::new("pages");
    dir.install();
    dir.run();
    let split = dd(4);
    let (head, tail) = split.split_at(60);
    dir.append(H00, &(dd(1) + &git(2) + &dd(3) + head));
    dir.append(
        H01,
        &(tail.to_string()
            + &dd(5)
            + &file_event(1, "create", "/usr/bin/touch", "/Users/example/a")
            + &git(7)
            + &dd(8)),
    );
    // The two files carry the same time, as on a clock too coarse to tell them apart: the
    // later hour's file was written to at or after the earlier, whose hour is over.
    let same = SystemTime::now() - Duration::from_secs(60);
    dir.touch(H00, same);
    dir.touch(H01, same);
    let whole = dir.matches(&[]);
    assert_eq!(whole["more"], false);
    let all: Vec<&Value> = whole["matches"].as_array().unwrap().iter().collect();
    let positions: Vec<&str> = all
        .iter()
        .map(|x| x["position"].as_str().unwrap())
        .collect();
    assert_eq!(
        positions,
        [
            dir.position(H00, 0),
            dir.position(H00, dd(1).len() + git(2).len()),
            dir.position(H01, tail.len()),
            dir.position(
                H01,
                tail.len()
                    + dd(5).len()
                    + file_event(1, "create", "/usr/bin/touch", "/Users/example/a").len()
                    + git(7).len()
            ),
        ]
    );
    let s = &whole["stretch"];
    assert_eq!(
        (
            &s["program_starts"],
            &s["unreadable_lines"],
            &s["program_starts_lost"]
        ),
        (&json!(6), &json!(2), &json!(2)),
        "{s:#}"
    );
    let (paged, sums, after) = pages(&dir, None, "1");
    assert_eq!(paged.iter().collect::<Vec<_>>(), all);
    // The file event's number has nothing before it in the log: no loss, as in one reading.
    assert_eq!(sums, [6, 2, 2, 1]);
    // Read on from the end, nothing new is given; a line added later is.
    let end = dir.matches(&["--after", &after]);
    assert_eq!(
        (&end["matches"], &end["continue_after"], &end["more"]),
        (&json!([]), &json!(after), &json!(false))
    );
    dir.append(H01, &dd(9));
    let next = dir.matches(&["--after", &after]);
    assert_eq!(next["matches"].as_array().unwrap().len(), 1);
    assert_eq!(next["stretch"]["program_starts_lost"], 0);
    // A gap at the seam is counted exactly, however far back the number before it is.
    let at = next["continue_after"].as_str().unwrap().to_string();
    dir.append(H01, &dd(12));
    let gap = dir.matches(&["--after", &at]);
    assert_eq!(
        (
            &gap["stretch"]["program_starts_lost"],
            &gap["stretch"]["program_starts_unknown_losses"]
        ),
        (&json!(2), &json!(0))
    );
    // Numbers that fall back across the seam are a restart: a loss of unknown size.
    let at = gap["continue_after"].as_str().unwrap().to_string();
    dir.append(H01, &dd(1));
    let restarted = dir.matches(&["--after", &at]);
    assert_eq!(
        restarted["stretch"]["program_starts_unknown_losses"], 1,
        "{restarted:#}"
    );
}

#[test]
fn a_clock_set_ahead_and_back_skips_no_line_and_hides_no_match() {
    // While the clock was ahead the collector wrote a file of a later hour; set right, it
    // writes to the file of the real hour, earlier by name. A place taken while the later file
    // was the newest still gives every line written after it, wherever it went.
    let dir = Dir::new("clock");
    dir.install();
    dir.run();
    let ahead = "exec-20261004T09.jsonl";
    dir.append(ahead, &dd(1));
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING]);
    let place = m["continue_after"].as_str().unwrap().to_string();
    // The clock is set back: lines go on into the real hour's file. Read on a match at a time,
    // each is given once, and the later file read before is not read again.
    dir.append(H00, &(dd(2) + &dd(3)));
    let (all, sums, place) = pages(&dir, Some(place), "1");
    assert_eq!(rules_of(&json!({ "matches": all })), [PADDING, PADDING]);
    assert_eq!(sums, [2, 0, 0, 0]);
    let m = dir.matches(&["--after", &place]);
    assert_eq!(
        (&m["matches"], &m["stretch"]["gone"]),
        (&json!([]), &json!(false))
    );
    // The file of the later hour is deleted by the tidy job a day on, read to its end; the
    // real hour's file goes on.
    dir.tidy_away(ahead);
    dir.append(H00, &dd(4));
    let m = dir.matches(&["--after", &place]);
    assert_eq!(rules_of(&m), [PADDING]);
    assert_eq!(m["stretch"]["gone"], false);
    // The real hour's file is not over while it is still written to after the later one, so a
    // line still being written at its end is left for the next answer, not counted lost.
    let place = m["continue_after"].as_str().unwrap().to_string();
    dir.append(ahead, &git(5));
    std::thread::sleep(Duration::from_millis(20));
    let line = dd(6);
    let (head, rest) = line.split_at(40);
    dir.append(H00, head);
    let m = dir.matches(&["--after", &place]);
    assert_eq!(
        (&m["matches"], &m["stretch"]["unreadable_lines"]),
        (&json!([]), &json!(0))
    );
    dir.append(H00, rest);
    let m = dir.matches(&["--after", m["continue_after"].as_str().unwrap()]);
    assert_eq!(rules_of(&m), [PADDING]);
}

#[test]
fn a_file_made_again_under_the_same_name_is_read_from_its_start_shorter_or_longer() {
    // Uninstalled and installed again within one hour, the collector writes a new file of the
    // same name. A place in the old one is not a place in it: the new file is read from its
    // start, whether it is shorter or longer than the place, and the lines the old one held
    // unread are gone.
    for (tag, lines) in [("shorter", 1), ("longer", 12)] {
        let dir = Dir::new(tag);
        dir.install();
        dir.run();
        dir.append(H00, &(1..=6).map(git).collect::<String>());
        let place = dir.matches(&[])["continue_after"]
            .as_str()
            .unwrap()
            .to_string();
        dir.uninstall();
        let m = dir.matches(&["--after", &place]);
        assert_eq!(
            (
                &m["collector"]["state"],
                &m["stretch"]["gone"],
                &m["continue_after"]
            ),
            (&json!("not_installed"), &json!(true), &Value::Null)
        );
        dir.install();
        dir.append(H00, &(dd(1) + &(2..=lines).map(git).collect::<String>()));
        let m = dir.matches(&["--after", &place]);
        assert_eq!(rules_of(&m), [PADDING], "{tag}");
        assert_eq!(
            (&m["stretch"]["gone"], &m["stretch"]["kept_from"]),
            (&json!(true), &json!(dir.position(H00, 0))),
            "{tag}"
        );
        // A position names the new file, never a line of the old one.
        assert_eq!(m["matches"][0]["position"], dir.position(H00, 0));
    }
    // A file emptied in place keeps its inode and is shorter than the place: it too is read
    // from its start, and what it held is gone.
    let dir = Dir::new("emptied");
    dir.install();
    dir.run();
    dir.append(H00, &(1..=6).map(git).collect::<String>());
    let place = dir.matches(&[])["continue_after"]
        .as_str()
        .unwrap()
        .to_string();
    let file = std::fs::File::options()
        .write(true)
        .open(dir.log().join(H00))
        .unwrap();
    file.set_len(0).unwrap();
    dir.append(H00, &dd(1));
    let m = dir.matches(&["--after", &place]);
    assert_eq!(rules_of(&m), [PADDING]);
    assert_eq!(m["stretch"]["gone"], true);
}

#[test]
fn a_file_the_place_held_is_gone_only_when_lines_in_it_were_not_read() {
    // A file deleted after the place read it to its end, with its hour over, lost nothing;
    // one deleted with lines after the place, or with its end not yet reached, did.
    let dir = Dir::new("gone");
    dir.install();
    dir.run();
    let place = |args: &[&str]| -> String {
        dir.matches(args)["continue_after"]
            .as_str()
            .unwrap()
            .to_string()
    };
    dir.append(H00, &(git(1) + &git(2)));
    // Taken while H00 was the newest file: its end not seen.
    let early = place(&[]);
    std::thread::sleep(Duration::from_millis(20));
    dir.append(H01, &git(3));
    // Taken once H00's hour was over and it was read to its end.
    let over = place(&[]);
    // A clock set back writes to H00 again, and then forward to H01.
    dir.append(H00, &dd(4));
    std::thread::sleep(Duration::from_millis(20));
    dir.append(H01, &git(5));
    let finished = place(&[]);
    dir.tidy_away(H00);
    let m = dir.matches(&["--after", &finished]);
    assert_eq!(
        (
            &m["stretch"]["gone"],
            &m["stretch"]["kept_from"],
            &m["matches"]
        ),
        (&json!(false), &Value::Null, &json!([]))
    );
    // The root side's note says H00 held more than the earlier places read: those lines are
    // gone, and the log kept goes on in H01. A later note of a smaller file of the same name
    // does not take that back.
    dir.append("removed", &format!("0 {H00} 1 age\n"));
    for p in [&early, &over] {
        let m = dir.matches(&["--after", p]);
        assert_eq!(
            (&m["stretch"]["gone"], &m["stretch"]["kept_from"]),
            (&json!(true), &json!(dir.position(H01, 0)))
        );
        assert_eq!(m["matches"], json!([]));
    }
    // Deleted without a note, a file whose end the place had not seen is gone, and with
    // nothing kept there is nowhere to go on from.
    std::fs::remove_file(dir.log().join(H01)).unwrap();
    let m = dir.matches(&["--after", &finished]);
    assert_eq!(
        (&m["stretch"]["gone"], &m["stretch"]["kept_from"]),
        (&json!(true), &Value::Null)
    );
    // An answer that stopped at its limit in a file whose hour is over had not read it to its
    // end either.
    let (h02, h03) = ("exec-20261004T02.jsonl", "exec-20261004T03.jsonl");
    dir.append(h02, &(dd(6) + &dd(7)));
    std::thread::sleep(Duration::from_millis(20));
    dir.append(h03, &git(8));
    let stopped = place(&["--limit", "1"]);
    std::fs::remove_file(dir.log().join(h02)).unwrap();
    let m = dir.matches(&["--after", &stopped]);
    assert_eq!(
        (&m["stretch"]["gone"], &m["stretch"]["kept_from"]),
        (&json!(true), &json!(dir.position(h03, 0)))
    );
}

/// A place as a build before this one printed it, version 1: the last numbers, then for each
/// file its hour's difference from the one before, doubled, plus one when finished, its inode
/// and its offset, each a varint, in lower-case hexadecimal.
fn place_v1(seq: [u64; 3], files: &[(u64, bool, u64, u64)]) -> String {
    let mut bytes = Vec::new();
    let mut put = |mut n: u64| {
        while n >= 0x80 {
            bytes.push((n as u8) | 0x80);
            n >>= 7;
        }
        bytes.push(n as u8);
    };
    put(1);
    for s in seq {
        put(s + 1);
    }
    put(files.len() as u64);
    let mut before = 0;
    for (hour, finished, inode, offset) in files {
        put(((hour - before) << 1) | u64::from(*finished));
        put(*inode);
        put(*offset);
        before = *hour;
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_log_an_earlier_collector_began_and_a_later_one_went_on_is_read_in_the_order_it_was_written() {
    // Installed over an earlier collector, the log holds files named by the hour and files
    // named by run and start. They are read in the order they were written, the earlier
    // collector's first, by one answer or by many; a place an earlier build printed reads on
    // from where it was; and the root side's notes of deletions count what was read and what
    // was not, under both kinds of name.
    let dir = Dir::new("mixed");
    dir.install();
    dir.run();
    let (n1, n2, n3) = (
        "exec-20261004T013012-20261004T010000.jsonl",
        "exec-20261004T013012-20261004T014511.jsonl",
        "exec-20261004T020004-20261004T020000.jsonl",
    );
    dir.append(H00, &(dd(1) + &git(2)));
    dir.append(H01, &dd(3));
    dir.append(n1, &(dd(4) + &dd(5)));
    dir.append(n2, &dd(6));
    let now = SystemTime::now();
    for (i, name) in [H00, H01, n1, n2].iter().enumerate() {
        dir.touch(name, now - Duration::from_secs(400 - 100 * i as u64));
    }
    let whole = dir.matches(&[]);
    let positions: Vec<&str> = whole["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["position"].as_str().unwrap())
        .collect();
    assert_eq!(
        positions,
        [
            dir.position(H00, 0),
            dir.position(H01, 0),
            dir.position(n1, 0),
            dir.position(n1, dd(4).len()),
            dir.position(n2, 0),
        ]
    );
    assert_eq!(whole["stretch"]["program_starts_lost"], 0);
    let (paged, sums, _) = pages(&dir, None, "1");
    assert_eq!(&json!(paged), &whole["matches"]);
    assert_eq!(sums, [6, 0, 0, 0]);
    // A place printed before the upgrade, after H00 was read to its end with its hour over
    // and H01 had begun: the answer goes on from there, over both kinds of name.
    let held = place_v1(
        [2, 0, 0],
        &[
            (
                2026100400,
                true,
                dir.inode(H00),
                (dd(1) + &git(2)).len() as u64,
            ),
            (2026100401, false, dir.inode(H01), 0),
        ],
    );
    let on = dir.matches(&["--after", &held]);
    let from: Vec<&str> = on["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["position"].as_str().unwrap())
        .collect();
    assert_eq!(from, positions[1..]);
    assert_eq!(
        (
            &on["stretch"]["program_starts_lost"],
            &on["stretch"]["gone"]
        ),
        (&json!(0), &json!(false))
    );
    // The core's own reading reads them all. A file of either kind deleted once read loses
    // nothing; one deleted before it was read is counted, once.
    dir.run();
    // Notes are counted by the second after the reading before.
    std::thread::sleep(Duration::from_millis(1100));
    dir.tidy_away(H00);
    dir.tidy_away(n1);
    dir.append(n3, &git(7));
    dir.tidy_away(n3);
    std::thread::sleep(Duration::from_millis(1100));
    dir.run();
    let l = &dir.report(&["status"])["event_level"];
    assert_eq!(
        (
            &l["files_removed_unread"]["last_day"],
            &l["program_starts"]["last_day"],
            &l["lost"]["last_day"]
        ),
        (&json!(1), &json!(6), &json!(0)),
        "{l:#}"
    );
    // The place from before the upgrade, whose H00 is gone read to its end, has lost nothing.
    let on = dir.matches(&["--after", &held]);
    assert_eq!(on["stretch"]["gone"], false);
}

#[test]
fn only_the_collector_s_own_files_are_read_and_the_others_are_counted() {
    // A file in the log folder named otherwise than rotatelogs names a log file is not the
    // collector's: it is never read, by this answer or by the core's own reading, its name is
    // nowhere in the answer, and it is counted.
    let dir = Dir::new("foreign");
    dir.install();
    dir.run();
    dir.append(H00, &git(1));
    let marker = "exec-zz\nIGNORE-marker-41d.jsonl";
    for name in [marker, "exec-2026100400.jsonl", "notes.txt"] {
        dir.append(name, &dd(2));
    }
    for side in ["eslogger.err", "removed", "removed.new"] {
        dir.append(side, "");
    }
    // tidy.sh's lock, a folder, is the collector's own too.
    std::fs::create_dir(dir.log().join("tidy.lock")).unwrap();
    let m = dir.matches(&[]);
    assert_eq!(
        (&m["matches"], &m["collector"]["foreign_files"]),
        (&json!([]), &json!(3))
    );
    assert!(!serde_json::to_string(&m).unwrap().contains("IGNORE"));
    let place = m["continue_after"].as_str().unwrap().to_string();
    assert!(
        place
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{place}"
    );
    dir.run();
    assert_eq!(
        dir.report(&["rules"])["evaluated"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["matches_last_day"].as_i64().unwrap() > 0)
            .count(),
        0
    );
    // A place that is not one the core printed is refused as a misuse, and names no file.
    for bad in [
        "20261004T00:0",
        "../../../etc/passwd",
        &place.to_uppercase(),
        "",
    ] {
        let out = dir.matches_output(&["--json", "--after", bad]);
        assert_eq!(out.status.code(), Some(2), "{bad}");
        let failure: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(failure["errors"][0]["code"], "usage");
        assert_eq!(failure.get("format"), None);
    }
}

#[test]
fn no_collector_and_no_log_is_an_answer_that_says_so_and_names_the_rules_that_judge_nothing() {
    // Without the event level there is nothing to match, and the answer says why, so that a
    // caller does not read an empty list as a quiet Mac: the state, and the rules for file
    // events among those that judge nothing.
    let dir = Dir::new("absent");
    dir.run();
    let m = dir.matches(&[]);
    assert_eq!(m["format"], 1);
    assert_eq!(m["matches"], json!([]));
    assert_eq!(
        (
            &m["collector"]["state"],
            &m["collector"]["status_state"],
            &m["continue_after"],
            &m["more"],
            &m["stretch"]["gone"]
        ),
        (
            &json!("not_installed"),
            &json!("not_installed"),
            &Value::Null,
            &json!(false),
            &json!(false)
        )
    );
    let read_at = m["collector"]["status_read_at"].as_i64().unwrap();
    assert!((0..=60).contains(&(m["answered_at"].as_i64().unwrap() - read_at)));
    let not_collected: Vec<&Value> = m["unevaluated"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["reason"] == "not_collected")
        .collect();
    assert_eq!(not_collected.len(), 14, "{m:#}");
    assert!(
        not_collected
            .iter()
            .all(|u| u["detail_text"] == "the event level is not installed")
    );
    // Uninstalling deletes the log. A place in an empty log lost nothing with it; a place in a
    // file still being written did.
    dir.install();
    let empty = dir.matches(&[])["continue_after"]
        .as_str()
        .unwrap()
        .to_string();
    dir.uninstall();
    assert_eq!(dir.matches(&["--after", &empty])["stretch"]["gone"], false);
    dir.install();
    dir.append(H00, &git(1));
    std::thread::sleep(Duration::from_millis(20));
    dir.append(H01, &git(2));
    let place = dir.matches(&[])["continue_after"]
        .as_str()
        .unwrap()
        .to_string();
    dir.uninstall();
    assert_eq!(dir.matches(&["--after", &place])["stretch"]["gone"], true);
}

#[test]
fn without_a_store_the_answer_is_a_failure_that_never_parses_as_a_calm_message() {
    // Without the store the answer could not say what became of a match, so it is a failure,
    // as for the other commands of the contract. Every failure printed with `--json` lacks the
    // contract's format, so a reader that takes it for a `Matches` reads format 0 and stops.
    let dir = Dir::new("no-store");
    dir.install();
    dir.append(H00, &dd(1));
    let out = dir.matches_output(&["--json"]);
    assert_eq!(out.status.code(), Some(3));
    let failure: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (
            &failure["ok"],
            &failure["errors"][0]["code"],
            failure.get("format")
        ),
        (&json!(false), &json!("store_unreadable"), None)
    );
    let said = failure["errors"][0]["detail_text"].as_str().unwrap();
    assert!(said.ends_with("`immune run` makes it"), "{said}");
    let parsed: v1::Matches = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed.format, 0);
    let out = dir.matches_output(&[]);
    assert_eq!((out.status.code(), out.stdout.len()), (Some(3), 0));
    // A log that cannot be read is a failure of the same shape.
    dir.run();
    dir.append(
        H00,
        "{\"schema_version\":2,\"seq_num\":2,\"time\":\"2026-10-04T00:00:02Z\",\"event\":{\"exec\":{}}}\n",
    );
    let out = dir.matches_output(&["--json"]);
    assert_eq!(out.status.code(), Some(1));
    let failure: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        (&failure["errors"][0]["code"], failure.get("format")),
        (&json!("log_unreadable"), None)
    );
    // A log of more files than a place holds fails rather than leave files out of the place.
    std::fs::write(dir.log().join(H00), "").unwrap();
    for i in 0..=4096 {
        let (h, m, s) = (i / 3600, i / 60 % 60, i % 60);
        dir.append(
            &format!("exec-20261001T000000-20261001T{h:02}{m:02}{s:02}.jsonl"),
            "",
        );
    }
    let out = dir.matches_output(&["--json"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_collector_that_records_nothing_is_said_so_with_what_it_printed() {
    // An empty stretch from a collector macOS refuses is not a quiet Mac: the state says so,
    // with what eslogger printed as data and when the log was last written.
    let dir = Dir::new("refused");
    dir.install();
    dir.run();
    dir.append(H00, &git(1));
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    dir.touch(H00, hour_ago);
    std::fs::write(
        dir.log().join("eslogger.err"),
        "ERROR: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED\n",
    )
    .unwrap();
    let m = dir.matches(&[]);
    let c = &m["collector"];
    assert_eq!(
        (&c["state"], &c["said_by"], &c["said_text"]),
        (
            &json!("refused"),
            &json!("eslogger"),
            &json!("ERROR: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
        )
    );
    let hour_ago = hour_ago.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    assert_eq!(c["written_at"], hour_ago);
    // Nothing written for an hour, and a file dated ahead of now: silent, not running.
    std::fs::remove_file(dir.log().join("eslogger.err")).unwrap();
    dir.append(H01, "");
    dir.touch(H01, SystemTime::now() + Duration::from_secs(3 * 3600));
    assert_eq!(dir.matches(&[])["collector"]["state"], "silent");
}

#[test]
fn unreadable_lines_are_counted_and_the_rules_that_judge_nothing_are_named_with_why() {
    // Lines that could not be read were not evaluated, and are counted. Rules that cannot
    // judge what this collector records are named, each with why.
    let dir = Dir::new("unread");
    dir.install_before_file_events();
    dir.run();
    dir.append(
        H00,
        &(dd(1)
            + "not a message\n"
            + r#"{"schema_version":1,"seq_num":3,"time":"2026-10-04T00:00:03Z","event":{"create":{}}}"#
            + "\n"
            + &git(2)),
    );
    let m = dir.matches(&[]);
    let s = &m["stretch"];
    assert_eq!(
        (
            &s["program_starts"],
            &s["unreadable_lines"],
            &s["unreadable_file_events"]
        ),
        (&json!(2), &json!(1), &json!(1))
    );
    assert_eq!(m["collector"]["file_events_collected"], false);
    // An earlier collector keeps none of what a later one keeps, and the answer names it.
    assert_eq!(
        m["collector"]["not_kept"],
        json!(["identity", "script", "signature"])
    );
    let unevaluated = m["unevaluated"].as_array().unwrap();
    let in_part = unevaluated.iter().find(|u| u["file"] == IN_PART).unwrap();
    assert_eq!(
        (
            &in_part["reason"],
            &in_part["fields_text"],
            &in_part["name"]
        ),
        (
            &json!("in_part"),
            &json!(["OriginalFileName"]),
            &json!("sigma:bd3b5eaa-439d-4a42-8f35-a49f5c8a2582")
        )
    );
    let not_collected: Vec<&Value> = unevaluated
        .iter()
        .filter(|u| u["reason"] == "not_collected")
        .collect();
    assert_eq!(not_collected.len(), 14, "{unevaluated:#?}");
    assert!(
        not_collected.iter().all(|u| u["detail_text"]
            == "the collector installed here records program starts only; installing the event level again adds files created and renamed"),
        "{not_collected:#?}"
    );
    // Installed as today, the rules for file events judge, and only the rules in part and the
    // upstream rules a translated set did not take are named, each with its reason.
    dir.install();
    let m = dir.matches(&[]);
    assert_eq!(m["collector"]["file_events_collected"], true);
    let mut reasons: std::collections::BTreeMap<&str, usize> = Default::default();
    for u in m["unevaluated"].as_array().unwrap() {
        *reasons.entry(u["reason"].as_str().unwrap()).or_default() += 1;
    }
    assert_eq!(
        reasons,
        [
            ("backslash_in_wildcard", 2),
            ("function", 1),
            ("in_part", 23),
            ("needs_events", 23 + 42),
            ("needs_fields", 23 + 61),
            ("never_true", 4),
            ("not_eql", 40),
            ("regex", 1),
            ("sequence", 30 + 109),
            ("spans_kinds", 1 + 1),
            ("unsupported", 2),
        ]
        .into(),
    );
    let files: Vec<&Value> = m["unevaluated"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["reason"] == "in_part" && u["name"].as_str().unwrap().starts_with("sigma:"))
        .collect();
    assert_eq!(files.len(), 1, "{files:#?}");
    assert_eq!(files[0]["file"], IN_PART);
}

/// "Pbpaste Execution via Unusual Parent Process", Elastic's, high.
const PBPASTE: &str = "d7182e12-df8f-4ecf-b8f8-7cc0adcec425";

#[test]
fn a_high_translated_rule_raises_a_finding_named_elastic_and_its_match_is_handed_over_with_its_rule()
 {
    // A translated rule is a published rule like SigmaHQ's: its high match raises one finding,
    // named by its set and Elastic's rule id, and `immune matches` gives the match with the
    // rule as Elastic names it and the finding it went to. The same start under another parent
    // matches nothing of Elastic's.
    let dir = Dir::new("elastic");
    dir.install();
    dir.append(
        H00,
        &(start(
            1,
            T0,
            "/usr/local/bin/node",
            "/usr/bin/pbpaste",
            &["pbpaste"],
        ) + &start(2, T0, "/bin/zsh", "/usr/bin/pbpaste", &["pbpaste"])),
    );
    dir.run();
    let raised = dir.findings_named(&format!("elastic:{PBPASTE}"));
    assert_eq!(raised.len(), 1);
    let finding = raised[0].as_str();
    let m = dir.matches(&[]);
    let elastic: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["rule"]["name"].as_str().unwrap().starts_with("elastic:"))
        .collect();
    assert_eq!(elastic.len(), 1, "{m:#}");
    assert_eq!(
        elastic[0]["rule"],
        json!({
            "name": format!("elastic:{PBPASTE}"),
            "file": "macos/collection_pbpaste_execution_via_unusual_parent.yml",
            "id_text": PBPASTE,
            "title_text": "Pbpaste Execution via Unusual Parent Process",
            "level": "high",
            "techniques_text": ["T1115"],
            "author_text": "Elastic",
            "source": "elastic",
            "set": "Elastic's detection rules",
        })
    );
    assert_eq!(elastic[0]["position"], dir.position(H00, 0));
    assert_eq!(
        (
            &elastic[0]["raised"],
            &elastic[0]["findings"][0]["id"],
            &elastic[0]["findings"][0]["state"]
        ),
        (&json!("finding"), &json!(finding), &json!("open"))
    );
    // A person is told whose rule it is and under which licence, in words: in the finding's
    // meaning, which the app's card shows, and in the line about the rule.
    let out = dir.command(&["finding", finding, "--json"], &[]).output();
    let whole: Value = serde_json::from_slice(&out.unwrap().stdout).unwrap();
    let meaning = whole["meaning"].as_str().unwrap();
    assert!(
        meaning.contains("comes from Elastic's detection rules and"),
        "{meaning}"
    );
    let out = dir.command(&["finding", finding], &[]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let said = r#"; from Elastic's detection rules under the Elastic License 2.0, "macos/collection_pbpaste_execution_via_unusual_parent.yml"."#;
    assert!(text.contains(said), "{text}");
}

#[test]
fn a_behaviour_rule_states_no_level_so_its_match_is_counted_and_handed_over_and_raises_nothing() {
    // Elastic's behaviour rules state no level, and the core gives them none of its own. A
    // match of one is handed over like one below high, with the level `not_stated`, and counted
    // in the hour like any match; it raises no finding, so the owner is told of nothing.
    let dir = Dir::new("behaviour");
    dir.install();
    dir.append(
        H00,
        &start(
            1,
            &now_time(),
            "/bin/zsh",
            "/usr/bin/SetFile",
            &["SetFile", "-a", "V", "/Users/example/x"],
        ),
    );
    dir.run();
    let rule = format!("elastic-behaviour:{SETFILE}");
    assert!(dir.findings_named(&rule).is_empty());
    let m = dir.matches(&[]);
    let behaviour: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["rule"]["name"] == rule.as_str())
        .collect();
    assert_eq!(behaviour.len(), 1, "{m:#}");
    assert_eq!(
        (
            &behaviour[0]["rule"]["level"],
            &behaviour[0]["rule"]["file"],
            &behaviour[0]["raised"],
            &behaviour[0]["findings"]
        ),
        (
            &json!("not_stated"),
            &json!("macos/defense_evasion_file_hidden_via_setfile.yml"),
            &json!("level_not_stated"),
            &json!([])
        )
    );
    let r = dir.report(&["status"]);
    let counted: Vec<&Value> = r["rules"]["matched_last_day"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["id_text"] == SETFILE)
        .collect();
    assert_eq!(
        counted,
        [&json!({
            "id_text": SETFILE,
            "title_text": "File Hidden via SetFile",
            "level": null,
            "source": "elastic-behaviour",
            "set": "Elastic's behaviour rules",
            "matches": 1,
        })]
    );
    // No other rule matches this start, so nothing at all asks for a look.
    assert_eq!(r["needs_a_look_total"], 0, "{r:#}");
}

/// Elastic's behaviour rule "File Hidden via SetFile".
const SETFILE: &str = "2ed9c6bf-025e-4edf-a9ec-1493d0bb4f81";

/// "Potential XCSSET Malware Infection": SigmaHQ's rule, medium, and Elastic's behaviour rule of
/// the same title, under different ids.
const XCSSET: &str = "Potential XCSSET Malware Infection";
const XCSSET_SETS: [(&str, &str); 2] = [
    ("sigma", "SigmaHQ's rule set"),
    ("elastic-behaviour", "Elastic's behaviour rules"),
];

#[test]
fn every_listing_of_rules_tells_two_rules_of_the_same_title_apart_by_their_set() {
    // Two sets ship a rule of the same title. Wherever rules are listed, a person reads each
    // with its set beside its title, so the two rows differ, and a machine reads `source` and
    // `set`: in `rules` and `rules --over-log`, text and JSON, in `matches`, in the status, on
    // the summary page and on the rules page. One invented start matches both.
    let dir = Dir::new("same-title");
    dir.install();
    dir.append(
        H00,
        &start(
            1,
            &now_time(),
            "/bin/zsh",
            "/usr/bin/zip",
            &[
                "zip",
                "-r",
                "/tmp/x.zip",
                "/Users/example/Library/Group Containers/invented",
            ],
        ),
    );
    dir.run();
    let labels: Vec<String> = XCSSET_SETS
        .iter()
        .map(|(_, set)| format!("{XCSSET} ({set})"))
        .collect();
    // A machine form: the entries of this title carry each set once, by name and in words.
    let sets_of = |entries: Vec<&Value>, title: &str| -> Vec<(String, String)> {
        let mut sets: Vec<(String, String)> = entries
            .into_iter()
            .filter(|e| e[title] == XCSSET)
            .map(|e| {
                (
                    e["source"].as_str().unwrap().to_string(),
                    e["set"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        sets.sort();
        sets
    };
    let mut both: Vec<(String, String)> = XCSSET_SETS
        .iter()
        .map(|(n, s)| (n.to_string(), s.to_string()))
        .collect();
    both.sort();
    fn array(v: &Value) -> Vec<&Value> {
        v.as_array().unwrap().iter().collect()
    }
    // A person's form: one line or row for each, each with its set.
    let rows_of = |text: &str| -> Vec<String> {
        let rows: Vec<String> = text
            .lines()
            .filter(|l| l.contains(XCSSET))
            .map(str::to_string)
            .collect();
        assert_eq!(rows.len(), 2, "{text}");
        assert_ne!(rows[0], rows[1]);
        for label in &labels {
            assert!(
                rows.iter().any(|r| r.contains(label.as_str())),
                "{label}: {rows:?}"
            );
        }
        rows
    };

    let rules = dir.report(&["rules"]);
    assert_eq!(sets_of(array(&rules["evaluated"]), "title_text"), both);
    let out = dir.command(&["rules"], &[]).output().unwrap();
    rows_of(&String::from_utf8(out.stdout).unwrap());

    let replay = |json: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_immune"));
        c.args(["rules", "--over-log", "--system-root"])
            .arg(dir.root());
        if json {
            c.arg("--json");
        }
        String::from_utf8(c.output().unwrap().stdout).unwrap()
    };
    let over: Value = serde_json::from_str(&replay(true)).unwrap();
    assert_eq!(
        sets_of(array(&over["result"]["matched"]), "title_text"),
        both
    );
    let text = replay(false);
    rows_of(&text);
    // The rule of a set that states no level is not ranked among the levels: it comes after
    // them under its own heading.
    let heading = text
        .find("\n  Of a set that states no level: 1\n")
        .expect("the heading");
    assert!(text.find(&labels[1]).unwrap() > heading, "{text}");
    assert!(text.find(&labels[0]).unwrap() < heading, "{text}");

    let m = dir.matches(&[]);
    let rules_matched: Vec<&Value> = array(&m["matches"])
        .into_iter()
        .map(|x| &x["rule"])
        .collect();
    assert_eq!(sets_of(rules_matched, "title_text"), both);

    let status = dir.report(&["status"]);
    assert_eq!(
        sets_of(array(&status["rules"]["matched_last_day"]), "title_text"),
        both
    );

    let out = dir.command(&["view", "--no-open"], &[]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pages: Vec<(String, String)> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|p| (p.to_string(), std::fs::read_to_string(p).unwrap()))
        .collect();
    let rules_page = &pages
        .iter()
        .find(|(p, _)| p.ends_with("view/rules.html"))
        .unwrap()
        .1;
    let summary = &pages[0].1;
    for page in [summary, rules_page] {
        for label in &labels {
            let label = label.replace('\'', "&#39;");
            assert_eq!(page.matches(&label).count(), 1, "{label}");
        }
    }

    // Every entry of every machine listing carries its set, whatever its title.
    let mut entries: Vec<&Value> = Vec::new();
    for key in ["evaluated", "in_part", "not_evaluated"] {
        entries.extend(array(&rules[key]));
    }
    entries.extend(array(&m["unevaluated"]));
    entries.extend(array(&status["rules"]["matched_last_day"]));
    entries.extend(array(&status["rules"]["not_watching"]));
    entries.extend(array(&over["result"]["matched"]));
    for d in array(&rules["drill"]) {
        entries.extend(array(&d["matches"]));
    }
    let words = |source: &str| match source {
        "sigma" => "SigmaHQ's rule set",
        "elastic" => "Elastic's detection rules",
        "elastic-behaviour" => "Elastic's behaviour rules",
        other => panic!("no set {other}"),
    };
    for e in entries {
        assert_eq!(e["set"], words(e["source"].as_str().unwrap()), "{e}");
    }
}

#[test]
fn immune_rules_lists_both_sets_and_names_every_rule_not_taken_with_its_reason() {
    // `immune rules` says where each set comes from, and names every upstream rule a translated
    // set did not take with the translation's reason and detail, and every translated rule in
    // part with what its left-out alternatives need.
    let dir = Dir::new("rules-sets");
    dir.install();
    dir.run();
    let rules = dir.report(&["rules"]);
    // The words of a published rule's finding are given for each set, since they name it,
    // and apart for a rule about file events.
    let said = &rules["catalogue"]["published_rules"];
    for (words, set, about) in [
        (
            &said["meaning_by_set"]["sigma"],
            "SigmaHQ's rule set",
            "run the same commands",
        ),
        (
            &said["meaning_by_set"]["elastic"],
            "Elastic's detection rules",
            "run the same commands",
        ),
        (
            &said["for_file_events"]["meaning_by_set"]["sigma"],
            "SigmaHQ's rule set",
            "put files in the same places",
        ),
        (
            &said["for_file_events"]["meaning_by_set"]["elastic"],
            "Elastic's detection rules",
            "put files in the same places",
        ),
    ] {
        let words = words.as_str().unwrap();
        assert!(words.contains(set) && words.contains(about), "{words}");
    }
    // Only the sets whose rules state levels raise findings; the catalogue names no finding a
    // behaviour rule could raise by itself, and says why it raises none.
    assert_eq!(
        said["rule"],
        "sigma:<the rule's id> or elastic:<the rule's id>"
    );
    assert_eq!(said["raised_by_sets"], json!(["sigma", "elastic"]));
    assert_eq!(
        said["sets_that_raise_nothing"],
        json!([{
            "name": "elastic-behaviour",
            "set": "Elastic's behaviour rules",
            "why": "its rules state no level, so a match is counted and handed over and raises no finding by itself",
        }])
    );
    for meanings in [
        &said["meaning_by_set"],
        &said["for_file_events"]["meaning_by_set"],
    ] {
        assert!(meanings.get("elastic-behaviour").is_none(), "{meanings}");
    }
    let sources: Vec<&Value> = rules["sources"].as_array().unwrap().iter().collect();
    assert_eq!(
        sources
            .iter()
            .map(|s| (
                s["name"].clone(),
                s["totals"]["shipped"].clone(),
                s["totals"]["not_taken"].clone()
            ))
            .collect::<Vec<_>>(),
        [
            (json!("sigma"), json!(75), json!(0)),
            (json!("elastic"), json!(66), json!(119)),
            (json!("elastic-behaviour"), json!(57), json!(221)),
        ]
    );
    let not_evaluated = rules["not_evaluated"].as_array().unwrap();
    assert_eq!(not_evaluated.len(), 119 + 221);
    assert!(
        not_evaluated
            .iter()
            .all(|r| r["source"] == "elastic" || r["source"] == "elastic-behaviour")
    );
    // Every reason the behaviour rules' translation gave has its code.
    let mut codes: std::collections::BTreeMap<&str, usize> = Default::default();
    for r in not_evaluated
        .iter()
        .filter(|r| r["source"] == "elastic-behaviour")
    {
        *codes.entry(r["reason"].as_str().unwrap()).or_default() += 1;
    }
    assert_eq!(
        codes,
        [
            ("function", 1),
            ("needs_events", 42),
            ("needs_fields", 61),
            ("never_true", 4),
            ("regex", 1),
            ("sequence", 109),
            ("spans_kinds", 1),
            ("unsupported", 2),
        ]
        .into()
    );
    // A behaviour rule not taken is named with the translation's reason, and with no level,
    // since its set states none.
    let never = not_evaluated
        .iter()
        .find(|r| r["id_text"] == "76259650-ed25-4d48-9cb2-e4a32073f945")
        .unwrap();
    assert_eq!(
        (
            &never["reason"],
            &never["level"],
            &never["name"],
            &never["detail_text"]
        ),
        (
            &json!("never_true"),
            &Value::Null,
            &json!("elastic-behaviour:76259650-ed25-4d48-9cb2-e4a32073f945"),
            &json!(
                "asks for a field every event of its kinds has to be absent: process.command_line"
            )
        )
    );
    let sequence = not_evaluated
        .iter()
        .find(|r| r["id_text"] == "a0fbd7a9-1923-4e05-92df-b484168f17bc")
        .unwrap();
    assert_eq!(
        (
            &sequence["reason"],
            &sequence["detail_text"],
            &sequence["name"]
        ),
        (
            &json!("sequence"),
            &json!("Sequence"),
            &json!("elastic:a0fbd7a9-1923-4e05-92df-b484168f17bc")
        )
    );
    let fields = not_evaluated
        .iter()
        .find(|r| r["reason"] == "needs_fields" && r["detail_text"] == "needs_fields user.name")
        .unwrap();
    assert_eq!(fields["fields_text"], json!(["user.name"]));
    let in_part = rules["in_part"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id_text"] == "10a500bb-a28f-418e-ba29-ca4c8d1a9f2f")
        .unwrap();
    assert_eq!(
        in_part["never_matches"],
        json!([
            {
                "selection_text": null,
                "fields_text": ["process.parent.code_signature.exists"],
                "left_out_text": "needs_fields process.parent.code_signature.exists",
            },
            {
                "selection_text": null,
                "fields_text": ["process.parent.code_signature.trusted"],
                "left_out_text": "needs_fields process.parent.code_signature.trusted",
            },
        ])
    );
    let plain = String::from_utf8(dir.command(&["rules"], &[]).output().unwrap().stdout).unwrap();
    assert!(
        plain.contains("      correlates a sequence of events, which is not translated (Sequence)"),
        "{plain}"
    );
    // The reasons the behaviour rules' translation added, each in its own words.
    for said in [
        "      could never be true over the events here (asks for a field",
        "      needs a regular expression in EQL's syntax, which is not translated (regex match~(",
        "      uses a function of EQL's that is not translated (expected a field, got length(",
        "      compares one field with another, which a Sigma rule cannot (function startswith: ",
    ] {
        assert!(plain.contains(said), "{said}");
    }
    assert!(
        plain.contains("  no level stated File Hidden via SetFile (Elastic's behaviour rules)"),
        "{plain}"
    );
    assert!(
        plain.contains("      an alternative of the upstream rule needs process.parent.code_signature.trusted, which a program start does not give"),
        "{plain}"
    );
}

#[test]
fn a_rule_a_translated_set_did_not_take_is_named_with_its_reason_and_what_the_translation_said() {
    // No rule of a set is skipped silently: an upstream rule the translation did not take is in
    // the answer with its name, its upstream file, its level and the translation's reason and
    // detail, and a translated rule in part says what it needs or what was left out.
    let dir = Dir::new("not-taken");
    dir.install();
    dir.run();
    let m = dir.matches(&[]);
    let unevaluated = m["unevaluated"].as_array().unwrap();
    let by_name = |name: &str| unevaluated.iter().find(|u| u["name"] == name).unwrap();
    assert_eq!(
        by_name("elastic:a0fbd7a9-1923-4e05-92df-b484168f17bc"),
        &json!({
            "file": "macos/collection_sensitive_file_access_followed_by_compression.toml",
            "name": "elastic:a0fbd7a9-1923-4e05-92df-b484168f17bc",
            "id_text": "a0fbd7a9-1923-4e05-92df-b484168f17bc",
            "title_text": "Sensitive File Access followed by Compression",
            "level": "high",
            "reason": "sequence",
            "fields_text": [],
            "detail_text": "Sequence",
            "source": "elastic",
            "set": "Elastic's detection rules",
        })
    );
    let fields = by_name("elastic:f85ce03f-d8a8-4c83-acdc-5c8cd0592be7");
    assert_eq!(
        (
            &fields["reason"],
            &fields["fields_text"],
            &fields["detail_text"]
        ),
        (
            &json!("needs_fields"),
            &json!(["user.name"]),
            &json!("needs_fields user.name")
        )
    );
    let in_part = by_name("elastic:10a500bb-a28f-418e-ba29-ca4c8d1a9f2f");
    assert_eq!(
        (
            &in_part["reason"],
            &in_part["fields_text"],
            &in_part["detail_text"]
        ),
        (
            &json!("in_part"),
            &json!([
                "process.parent.code_signature.exists",
                "process.parent.code_signature.trusted"
            ]),
            &Value::Null
        )
    );
    // A rule of a set that states no level is given as such, never as `unspecified`, which a
    // reader takes for the highest severity.
    let never = by_name("elastic-behaviour:76259650-ed25-4d48-9cb2-e4a32073f945");
    assert_eq!(
        (&never["level"], &never["reason"]),
        (&json!("not_stated"), &json!("never_true"))
    );
    let papercut = by_name("elastic:a2d4508e-e9c2-41f6-9466-0c3aed8cc2c9");
    assert_eq!(
        (
            &papercut["reason"],
            &papercut["fields_text"],
            &papercut["level"]
        ),
        (&json!("in_part"), &json!([]), &json!("critical"))
    );
    assert!(
        papercut["detail_text"]
            .as_str()
            .unwrap()
            .starts_with("backslash_in_wildcard file.path: ")
    );
    // The same in the binary form: the reasons are the schema's values, not numbers made up.
    let binary = v1::Matches::decode(dir.matches_binary(&[]).as_slice()).unwrap();
    let reasons: std::collections::BTreeSet<i32> =
        binary.unevaluated.iter().map(|u| u.reason).collect();
    for why in [
        v1::UnevaluatedReason::Sequence,
        v1::UnevaluatedReason::NotEql,
        v1::UnevaluatedReason::NeedsEvents,
        v1::UnevaluatedReason::NeedsFields,
        v1::UnevaluatedReason::BackslashInWildcard,
        v1::UnevaluatedReason::SpansKinds,
        v1::UnevaluatedReason::NeverTrue,
        v1::UnevaluatedReason::Regex,
        v1::UnevaluatedReason::Unsupported,
        v1::UnevaluatedReason::Function,
        v1::UnevaluatedReason::InPart,
    ] {
        assert!(reasons.contains(&(why as i32)), "{why:?}");
    }
}

#[test]
fn arguments_are_given_whole_each_in_its_own_string_and_only_in_text_fields() {
    // The response layer judges a command line as it was run: no argument is cut, each stays
    // apart, a hidden character is shown escaped, and none of it is anywhere but a `_text`
    // field, where an agent reads it as data.
    let dir = Dir::new("args");
    dir.install();
    dir.run();
    let marker = "arg-marker-7c2e";
    let long = format!("{marker}-{}", "x".repeat(5000));
    let spaced = format!("{marker} with spaces");
    dir.append(
        H00,
        &start(
            1,
            T0,
            "/bin/sh",
            "/bin/dd",
            &[
                "dd",
                "if=/dev/zero",
                &long,
                &spaced,
                "esc\u{1b}[31m",
                "count=1",
            ],
        ),
    );
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING]);
    let args = &m["matches"][0]["event"]["program_start"]["args_text"];
    assert_eq!(
        args,
        &json!([
            "dd",
            "if=/dev/zero",
            long,
            spaced,
            "esc\\u{1b}[31m",
            "count=1"
        ])
    );
    let mut keys = Vec::new();
    holders(&m, "", marker, &mut keys);
    assert_eq!(keys, ["args_text", "args_text"]);
}

#[test]
fn the_binary_and_the_json_forms_are_one_message_and_an_event_names_its_kind_by_its_one_case() {
    // A caller may read either form: the binary message, decoded by types generated from the
    // schema, prints as the JSON the command prints. An event is an object with one key, its
    // kind; a kind the reader does not know reads as no event, never as another.
    let dir = Dir::new("forms");
    dir.install();
    dir.run();
    dir.append(
        H00,
        &(dd(1)
            + &file_event(1, "rename", "/usr/local/bin/node", "/private/tmp/6202033")
            + &git(2)),
    );
    let json = dir.matches(&[]);
    let binary = v1::Matches::decode(dir.matches_binary(&[]).as_slice()).unwrap();
    assert_eq!(binary.matches.len(), 2);
    let mut decoded = serde_json::to_value(&binary).unwrap();
    decoded["answered_at"] = json["answered_at"].clone();
    assert_eq!(decoded, json);
    let file = &json["matches"][1]["event"];
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["file_event"]
    );
    assert_eq!(
        (
            &file["file_event"]["action"],
            &file["file_event"]["source_text"],
            &file["file_event"]["instigator"]["executable_text"]
        ),
        (
            &json!("rename"),
            &json!("/Users/example/dev/site/.tmp-1"),
            &json!("/usr/local/bin/node")
        )
    );
    let unknown: v1::Event = serde_json::from_str(r#"{"network_flow":{"bytes":1}}"#).unwrap();
    assert_eq!(unknown.body, None);
}

#[test]
fn the_limit_holds_and_more_says_when_it_cut() {
    // The limit keeps an answer small, and `more` with the place given says there is more
    // to read rather than leaving the caller to take the rest for silence.
    let dir = Dir::new("limit");
    dir.install();
    dir.run();
    let mut text = String::new();
    for seq in 1..=5 {
        text.push_str(&dd(seq));
    }
    dir.append(H00, &text);
    let m = dir.matches(&["--limit", "2"]);
    assert_eq!(
        (m["matches"].as_array().unwrap().len(), &m["more"]),
        (2, &json!(true))
    );
    assert_eq!(m["stretch"]["program_starts"], 2);
    let rest = dir.matches(&["--after", m["continue_after"].as_str().unwrap()]);
    assert_eq!(
        (rest["matches"].as_array().unwrap().len(), &rest["more"]),
        (3, &json!(false))
    );
    // A limit that falls on the last line leaves nothing more; one that falls on the last line
    // of an hour leaves the next hour's; a line still being written is not more.
    assert_eq!(dir.matches(&["--limit", "5"])["more"], false);
    std::thread::sleep(Duration::from_millis(20));
    dir.append(H01, &dd(6));
    assert_eq!(dir.matches(&["--limit", "5"])["more"], true);
    dir.append(H01, r#"{"schema_version":1,"seq_num":7"#);
    let m = dir.matches(&["--limit", "6"]);
    assert_eq!(
        (m["matches"].as_array().unwrap().len(), &m["more"]),
        (6, &json!(false))
    );
    // A place taken where the limit stopped, in an earlier file, keeps what an earlier place
    // held of the files after it: they are read on, not again from their start.
    let (all, _, _) = pages(&dir, None, "1");
    assert_eq!(all.len(), 6);
}

#[test]
fn a_busy_hour_is_given_in_answers_of_about_a_megabyte_and_long_command_lines_do_not_swell_one() {
    // Sizes on invented logs. A busy hour: a program start every few milliseconds, one in five
    // matched by a rule. The default limit keeps an answer near a megabyte. A command line can
    // be a megabyte and is never cut, so the bytes of matched lines stop an answer too.
    let dir = Dir::new("busy");
    dir.install();
    dir.run();
    let mut text = String::new();
    for seq in 1..=10_000u64 {
        let line = match seq % 10 {
            0 => dd(seq),
            5 => sw_vers(seq),
            _ => start(
                seq,
                T0,
                "/opt/example/bin/node",
                "/usr/bin/git",
                &[
                    "git",
                    "-C",
                    "/Users/example/dev/site",
                    "log",
                    "--oneline",
                    "-n",
                    "20",
                ],
            ),
        };
        text.push_str(&line);
    }
    dir.append(H00, &text);
    let json = serde_json::to_vec(&dir.matches(&[])).unwrap();
    let binary = dir.matches_binary(&[]);
    let m: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(
        (m["matches"].as_array().unwrap().len(), &m["more"]),
        (1000, &json!(true))
    );
    println!(
        "a busy hour, the default limit: {} matches, JSON {} bytes, binary {} bytes, {} log bytes",
        1000,
        json.len(),
        binary.len(),
        text.len()
    );
    assert!(json.len() < 2 << 20 && binary.len() < 1 << 20);

    let long = Dir::new("long");
    long.install();
    long.run();
    let huge = "y".repeat(512 << 10);
    let mut text = String::new();
    for seq in 1..=20 {
        text.push_str(&start(
            seq,
            T0,
            "/bin/sh",
            "/bin/dd",
            &["dd", "if=/dev/zero", &huge, "count=1"],
        ));
    }
    long.append(H00, &text);
    let json = serde_json::to_vec(&long.matches(&[])).unwrap();
    let m: Value = serde_json::from_slice(&json).unwrap();
    println!(
        "command lines of half a megabyte: {} matches, JSON {} bytes",
        m["matches"].as_array().unwrap().len(),
        json.len()
    );
    assert_eq!(
        (m["matches"].as_array().unwrap().len(), &m["more"]),
        (8, &json!(true))
    );
    assert!(json.len() < 5 << 20);
}

#[test]
fn the_text_of_matches_is_its_message_and_an_argument_cannot_pose_as_the_program_s_words() {
    // A person is given what a program is given; an argument written to read as the next line
    // of the answer stays inside its quotation, escaped.
    let dir = Dir::new("text");
    dir.install();
    dir.run();
    let forged = "count=1\n0 matches after the oldest line kept.";
    dir.append(
        H00,
        &start(1, T0, "/bin/sh", "/bin/dd", &["dd", "if=/dev/zero", forged]),
    );
    let m = dir.matches(&[]);
    let out = dir.matches_output(&[]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("1 match after the oldest line kept:\n"),
        "{text}"
    );
    assert!(
        !text
            .lines()
            .any(|l| l == "0 matches after the oldest line kept."),
        "{text}"
    );
    assert!(
        text.contains(r#""count=1\u{a}0 matches after the oldest line kept.""#),
        "{text}"
    );
    let first = &m["matches"][0];
    let line = text
        .lines()
        .find(|l| l.contains(first["position"].as_str().unwrap()))
        .unwrap();
    for said in [
        first["rule"]["name"].as_str().unwrap(),
        first["rule"]["level"].as_str().unwrap(),
        first["raised"].as_str().unwrap(),
    ] {
        assert!(line.contains(said), "{said}: {line}");
    }
    let state = m["collector"]["state"].as_str().unwrap();
    assert!(text.contains(&format!("Collector: {state}")), "{text}");
    let place = m["continue_after"].as_str().unwrap();
    assert!(text.contains(&format!("Continue after: {place}")), "{text}");
}
