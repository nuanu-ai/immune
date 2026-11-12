//! Promises of `immune matches`, the queue of rule matches the response layer reads. The real
//! binary reads a temporary system root laid out as the event level's install lays out the real
//! one, with log lines as the collector's filter writes them and invented content. Nothing here
//! reads the real log or the real store.

#[path = "../src/contract.rs"]
#[allow(dead_code)]
mod contract;

use contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
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

    fn append(&self, name: &str, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log().join(name))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
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

    /// A full run that reads nothing real but the event level under the temporary root.
    fn run(&self) {
        let absent = self.0.join("absent");
        std::fs::write(self.0.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
        std::fs::create_dir_all(self.0.join("home")).unwrap();
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

    /// `immune matches <args> --json` over this root and store: its message.
    fn matches(&self, args: &[&str]) -> Value {
        let root = self.root();
        let mut more: Vec<&std::ffi::OsStr> = vec![root.as_os_str()];
        more.extend(args.iter().map(std::ffi::OsStr::new));
        let out = self
            .command(&["matches", "--json", "--system-root"], &more)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// `immune matches <args>` in binary: its stdout.
    fn matches_binary(&self, args: &[&str]) -> Vec<u8> {
        let root = self.root();
        let mut more: Vec<&std::ffi::OsStr> = vec![root.as_os_str()];
        more.extend(args.iter().map(std::ffi::OsStr::new));
        let out = self
            .command(&["matches", "--system-root"], &more)
            .output()
            .unwrap();
        assert!(out.status.success());
        out.stdout
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

/// Every string in `v` that holds `marker`, with the name of the field it is under.
fn holders<'a>(v: &'a Value, key: &'a str, marker: &str, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) if s.contains(marker) => out.push(key),
        Value::Array(items) => items.iter().for_each(|i| holders(i, key, marker, out)),
        Value::Object(m) => m.iter().for_each(|(k, i)| holders(i, k, marker, out)),
        _ => {}
    }
}

#[test]
fn a_match_below_high_is_given_with_its_event_and_a_high_one_with_the_finding_it_raised() {
    // The response layer looks into what the core is not sure of, so it gets every match of
    // every level with the event whole; a high one says which finding it raised, or that the
    // core's own reading has not reached it yet, or that the store cannot tell.
    let dir = Dir::new("levels");
    dir.install();
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
    assert_eq!(high["position"], "20261004T00:0");
    assert_eq!(
        (&high["raised"], &high["finding_id"]),
        (&json!("not_read_yet"), &Value::Null)
    );
    assert_eq!(
        (&medium["raised"], &medium["finding_id"]),
        (&json!("below_high"), &Value::Null)
    );
    assert_eq!(
        medium["rule"],
        json!({
            "file": "rules/macos/process_creation/proc_creation_macos_swvers_discovery.yml",
            "id_text": SW_VERS,
            "title_text": "System Information Discovery Using sw_vers",
            "level": "medium",
            "techniques_text": ["T1082"],
            "author_text": "Joseliyo Sanchez, @Joseliyo_Jstnk",
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
            "kind": "program_start",
            "program_start": {
                "happened_at": secs,
                "happened_nanos": 1000,
                "executable_text": "/usr/bin/sw_vers",
                "args_text": ["sw_vers", "-productVersion"],
                "working_directory_text": CWD,
                "pid": 402,
                "user_id": 501,
                "parent_pid": 401,
                "parent_executable_text": "/bin/zsh",
                "signing_id_text": "com.example.tool",
                "team_id_text": null,
                "platform_binary": false,
            },
            "file_event": null,
        })
    );

    // Once the core's own reading has read it, the high match names its finding.
    dir.run();
    let findings = dir.report(&["findings"]);
    let first = findings["findings"][0]["id"].as_str().unwrap().to_string();
    let m = dir.matches(&[]);
    assert_eq!(
        (&m["matches"][0]["raised"], &m["matches"][0]["finding_id"]),
        (&json!("finding"), &json!(first))
    );
    assert_eq!(m["matches"][1]["raised"], "below_high");

    // The owner closes it; a later start raises a new finding. The new match is tied to the
    // new finding. The first could have gone to either as far as the store can say, and the
    // answer says so rather than guessing.
    dir.report(&["finding", &first, "seen"]);
    std::thread::sleep(Duration::from_millis(1100));
    dir.append(H00, &start(3, &now_time(), "/bin/sh", "/bin/dd", &DD));
    // A line that begins where the core's reading stopped is not read yet.
    assert_eq!(dir.matches(&[])["matches"][2]["raised"], "not_read_yet");
    dir.run();
    let all = dir.report(&["findings"]);
    let second = all["findings"][0]["id"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    let m = dir.matches(&[]);
    assert_eq!(rules_of(&m), [PADDING, SW_VERS, PADDING]);
    assert_eq!(
        (&m["matches"][2]["raised"], &m["matches"][2]["finding_id"]),
        (&json!("finding"), &json!(second))
    );
    assert_eq!(
        (&m["matches"][0]["raised"], &m["matches"][0]["finding_id"]),
        (&json!("untold"), &Value::Null)
    );
}

#[test]
fn what_immune_matches_gives_and_what_the_core_s_reading_counts_agree_for_the_same_log() {
    // One way of evaluating: the queue and the core's own reading cannot disagree about what
    // matched, program starts and file events alike.
    let dir = Dir::new("agree");
    dir.install();
    dir.append(
        H00,
        &(dd(1)
            + &start(
                2,
                T0,
                "/bin/zsh",
                "/usr/bin/sw_vers",
                &["sw_vers", "-productVersion"],
            )
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
    let raised: Vec<&Value> = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["rule"]["level"] == "high")
        .collect();
    assert_eq!(raised.len(), 2);
}

#[test]
fn reading_on_from_the_position_given_gives_the_rest_and_nothing_twice_across_the_turn_of_an_hour()
{
    // The caller keeps its place. Read on one match at a time from the position each answer
    // gives, the answers add up to one reading of the whole log: the same matches, none twice,
    // and the same counts, a gap in eslogger's numbering at the seam between two answers and a
    // line split at the turn of the hour included.
    let dir = Dir::new("pages");
    dir.install();
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
            "20261004T00:0",
            &format!("20261004T00:{}", dd(1).len() + git(2).len()),
            &format!("20261004T01:{}", tail.len()),
            &format!(
                "20261004T01:{}",
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
    let mut after: Option<String> = None;
    let mut paged: Vec<Value> = Vec::new();
    let mut sums = [0i64; 5];
    for turn in 0.. {
        assert!(turn < 10);
        let mut args = vec!["--limit", "1"];
        if let Some(a) = &after {
            args.extend(["--after", a]);
        }
        let m = dir.matches(&args);
        assert_eq!(m["after"], json!(after));
        paged.extend(m["matches"].as_array().unwrap().iter().cloned());
        for (i, k) in [
            "program_starts",
            "unreadable_lines",
            "program_starts_lost",
            "file_events",
            "file_events_unknown_losses",
        ]
        .iter()
        .enumerate()
        {
            sums[i] += m["stretch"][k].as_i64().unwrap();
        }
        assert!(m["matches"].as_array().unwrap().len() <= 1);
        after = m["continue_after"].as_str().map(str::to_string);
        if m["more"] == false {
            break;
        }
    }
    assert_eq!(paged.iter().collect::<Vec<_>>(), all);
    // The file event's number has nothing before it in the log: no loss, as in one reading.
    assert_eq!(sums, [6, 2, 2, 1, 0]);
    // Read on from the end, nothing new is given; a line added later is.
    let end = dir.matches(&["--after", after.as_deref().unwrap()]);
    assert_eq!(
        (&end["matches"], &end["continue_after"], &end["more"]),
        (&json!([]), &json!(after), &json!(false))
    );
    dir.append(H01, &dd(9));
    let next = dir.matches(&["--after", after.as_deref().unwrap()]);
    assert_eq!(next["matches"].as_array().unwrap().len(), 1);
    assert_eq!(next["stretch"]["program_starts_lost"], 0);
    // Numbers that fall back across the seam are a restart: a loss of unknown size.
    let restarted = dir.matches(&["--after", next["continue_after"].as_str().unwrap()]);
    assert_eq!(restarted["matches"], json!([]));
    dir.append(H01, &dd(1));
    let restarted = dir.matches(&["--after", next["continue_after"].as_str().unwrap()]);
    assert_eq!(
        restarted["stretch"]["program_starts_unknown_losses"], 1,
        "{restarted:#}"
    );
}

#[test]
fn a_position_older_than_the_oldest_log_kept_says_the_events_after_it_are_gone() {
    // A caller that comes back after the log it was reading was deleted is told that what
    // came after its position is gone and was not evaluated, never answered as if nothing
    // happened in between.
    let dir = Dir::new("gone");
    dir.install();
    dir.append("exec-20261004T05.jsonl", &(git(40) + &dd(41)));
    let m = dir.matches(&["--after", "20261004T03:2048"]);
    assert_eq!(
        (
            &m["stretch"]["gone"],
            &m["stretch"]["kept_from"],
            &m["after"]
        ),
        (
            &json!(true),
            &json!("20261004T05:0"),
            &json!("20261004T03:2048")
        )
    );
    assert_eq!(rules_of(&m), [PADDING]);
    // A position in a file that is still there is not gone, nor one in an hour after it.
    let kept = dir.matches(&["--after", "20261004T05:0"]);
    assert_eq!(
        (&kept["stretch"]["gone"], &kept["stretch"]["kept_from"]),
        (&json!(false), &Value::Null)
    );
    assert_eq!(rules_of(&kept), [PADDING]);
    let later = dir.matches(&["--after", "20261004T07:0"]);
    assert_eq!(
        (&later["stretch"]["gone"], &later["matches"]),
        (&json!(false), &json!([]))
    );
    // A file of that hour shorter than the position is another file: the one the position
    // was in is gone, and the one there now is read from its start.
    let replaced = dir.matches(&["--after", "20261004T05:99999"]);
    assert_eq!(
        (
            &replaced["stretch"]["gone"],
            &replaced["stretch"]["kept_from"]
        ),
        (&json!(true), &json!("20261004T05:0"))
    );
    assert_eq!(rules_of(&replaced), [PADDING]);
    // Everything deleted: gone, and nothing kept to go on from.
    std::fs::remove_file(dir.log().join("exec-20261004T05.jsonl")).unwrap();
    let empty = dir.matches(&["--after", "20261004T05:0"]);
    assert_eq!(
        (
            &empty["stretch"]["gone"],
            &empty["stretch"]["kept_from"],
            &empty["continue_after"]
        ),
        (&json!(true), &Value::Null, &json!("20261004T05:0"))
    );
}

#[test]
fn no_collector_and_no_log_is_an_answer_that_says_so_and_not_a_failure() {
    // Without the event level there is nothing to match, and the answer says why, so that a
    // caller does not read an empty list as a quiet Mac.
    let dir = Dir::new("absent");
    let m = dir.matches(&[]);
    assert_eq!(m["format"], 1);
    assert_eq!(m["matches"], json!([]));
    assert_eq!(
        (
            &m["collector"]["state"],
            &m["collector"]["status_state"],
            &m["continue_after"],
            &m["more"]
        ),
        (
            &json!("not_installed"),
            &Value::Null,
            &Value::Null,
            &json!(false)
        )
    );
    assert_eq!(m["stretch"]["gone"], false);
    assert!(!dir.store().exists());
    // Uninstalling deletes the log, so a caller's place is gone with it.
    let m = dir.matches(&["--after", "20261004T00:0"]);
    assert_eq!(m["stretch"]["gone"], true);
    // The state as `immune status` serves it comes with it once the store has a reading.
    dir.run();
    let m = dir.matches(&[]);
    assert_eq!(
        (&m["collector"]["state"], &m["collector"]["status_state"]),
        (&json!("not_installed"), &json!("not_installed"))
    );
    let read_at = m["collector"]["status_read_at"].as_i64().unwrap();
    assert!((0..=60).contains(&(m["answered_at"].as_i64().unwrap() - read_at)));
}

#[test]
fn a_collector_that_records_nothing_is_said_so_with_what_it_printed() {
    // An empty stretch from a collector macOS refuses is not a quiet Mac: the state says so,
    // with what eslogger printed as data and when the log was last written.
    let dir = Dir::new("refused");
    dir.install();
    dir.append(H00, &git(1));
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    std::fs::File::options()
        .append(true)
        .open(dir.log().join(H00))
        .unwrap()
        .set_modified(hour_ago)
        .unwrap();
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
}

#[test]
fn a_gap_at_the_seam_whose_number_lies_beyond_reach_is_a_loss_of_unknown_size_never_none() {
    // Before where it starts the core looks back a bounded way for the numbers to count a
    // gap at the seam on from. A kind whose last number lies further back is not taken as
    // having lost nothing.
    let dir = Dir::new("reach");
    dir.install();
    let mut text = file_event(1, "rename", "/bin/mv", "/Users/example/b");
    let mut seq = 1;
    while text.len() < 17 << 20 {
        text.push_str(&git(seq));
        seq += 1;
    }
    let at = text.len();
    text.push_str(&dd(seq));
    text.push_str(&file_event(2, "rename", "/bin/mv", "/Users/example/c"));
    dir.append(H00, &text);
    let m = dir.matches(&["--after", &format!("20261004T00:{at}")]);
    let s = &m["stretch"];
    assert_eq!(
        (
            &s["file_events"],
            &s["file_events_unknown_losses"],
            &s["program_starts"],
            &s["program_starts_unknown_losses"]
        ),
        (&json!(1), &json!(1), &json!(0), &json!(0)),
        "{s:#}"
    );
    // Read from the start, the same rename follows the first with nothing lost.
    let whole = dir.matches(&["--limit", "1000000"]);
    assert_eq!(whole["stretch"]["file_events_unknown_losses"], 0);
}

#[test]
fn unreadable_lines_are_counted_and_the_rules_that_judge_nothing_are_named_with_why() {
    // Lines that could not be read were not evaluated, and are counted. Rules that cannot
    // judge what this collector records are named, each with why.
    let dir = Dir::new("unread");
    dir.install_before_file_events();
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
    let unevaluated = m["unevaluated"].as_array().unwrap();
    let in_part = unevaluated.iter().find(|u| u["file"] == IN_PART).unwrap();
    assert_eq!(
        (&in_part["reason"], &in_part["fields_text"]),
        (&json!("in_part"), &json!(["OriginalFileName"]))
    );
    let not_collected: Vec<&Value> = unevaluated
        .iter()
        .filter(|u| u["reason"] == "not_collected")
        .collect();
    assert_eq!(not_collected.len(), 5, "{unevaluated:#?}");
    assert!(
        not_collected.iter().all(|u| u["detail_text"]
            == "the collector installed here records program starts only; installing the event level again adds files created and renamed"),
        "{not_collected:#?}"
    );
    // Installed as today, the rules for file events judge, and only the one in part is named.
    dir.install();
    let m = dir.matches(&[]);
    assert_eq!(m["collector"]["file_events_collected"], true);
    let files: Vec<&Value> = m["unevaluated"].as_array().unwrap().iter().collect();
    assert_eq!(files.len(), 1, "{files:#?}");
    assert_eq!(files[0]["file"], IN_PART);
}

#[test]
fn arguments_are_given_whole_each_in_its_own_string_and_only_in_text_fields() {
    // The response layer judges a command line as it was run: no argument is cut, each stays
    // apart, a hidden character is shown escaped, and none of it is anywhere but a `_text`
    // field, where an agent reads it as data.
    let dir = Dir::new("args");
    dir.install();
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
fn the_binary_and_the_json_forms_are_one_message() {
    // A caller may read either form: the binary message, decoded by types generated from the
    // schema, prints as the JSON the command prints.
    let dir = Dir::new("forms");
    dir.install();
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
        (
            &file["kind"],
            &file["file_event"]["action"],
            &file["program_start"]
        ),
        (&json!("file_event"), &json!("rename"), &Value::Null)
    );
    assert_eq!(
        file["file_event"]["source_text"],
        "/Users/example/dev/site/.tmp-1"
    );
}

#[test]
fn the_limit_holds_and_more_says_when_it_cut() {
    // The limit keeps an answer small, and `more` with the position given says there is more
    // to read rather than leaving the caller to take the rest for silence.
    let dir = Dir::new("limit");
    dir.install();
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
    dir.append(H01, &dd(6));
    assert_eq!(dir.matches(&["--limit", "5"])["more"], true);
    dir.append(H01, r#"{"schema_version":1,"seq_num":7"#);
    let m = dir.matches(&["--limit", "6"]);
    assert_eq!(
        (m["matches"].as_array().unwrap().len(), &m["more"]),
        (6, &json!(false))
    );
}

#[test]
fn a_busy_hour_is_given_in_answers_of_about_a_megabyte_and_long_command_lines_do_not_swell_one() {
    // Sizes on invented logs. A busy hour: a program start every few milliseconds, one in five
    // matched by a rule. The default limit keeps an answer near a megabyte. A command line can
    // be a megabyte and is never cut, so the bytes of matched lines stop an answer too.
    let dir = Dir::new("busy");
    dir.install();
    let mut text = String::new();
    for seq in 1..=10_000u64 {
        let line = match seq % 10 {
            0 => dd(seq),
            5 => start(
                seq,
                T0,
                "/bin/zsh",
                "/usr/bin/sw_vers",
                &["sw_vers", "-productVersion"],
            ),
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
