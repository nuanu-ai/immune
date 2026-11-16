//! Promises of the example client of the crate `immune-contract`, `contract/examples/client.rs`,
//! to the engineer of a program that runs the core and starts from it: it runs against the core
//! as built, reads the matches, and sends a verdict whose repeat is the first one. The real
//! binary and the example run over an invented home folder, system root, event log and store.

mod common;

use serde_json::Value;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
const H00: &str = "exec-20261004T00.jsonl";
/// "Binary Padding - MacOS", high: the core raises a finding of it.
const PADDING: &str = "sigma:95361ce5-c891-4b0a-87ca-e24607884a96";
/// "System Information Discovery Using sw_vers", medium: the core raises nothing of it.
const SW_VERS: &str = "sigma:5de06a6f-673a-4fc0-8d48-bcfe3837b033";
/// Two `exec` lines as the collector's filter writes them, with invented content: the first a
/// start `PADDING` matches, the second one `SW_VERS` matches.
const DD: &str = concat!(
    r#"{"schema_version":1,"version":10,"seq_num":1,"global_seq_num":1,"time":"2026-10-04T00:00:02.000002Z","process":{"executable":{"path":"/bin/sh"}},"#,
    r#""event":{"exec":{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{"path":"/Users/example/dev/site"},"#,
    r#""target":{"executable":{"path":"/bin/dd"},"audit_token":{"pid":402,"euid":501},"ppid":401,"signing_id":"com.example.tool","team_id":null,"is_platform_binary":false}}}}"#,
    "\n"
);
const SW_VERS_START: &str = concat!(
    r#"{"schema_version":1,"version":10,"seq_num":2,"global_seq_num":2,"time":"2026-10-04T00:00:03.000003Z","process":{"executable":{"path":"/bin/sh"}},"#,
    r#""event":{"exec":{"args":["sw_vers","-productVersion"],"cwd":{"path":"/Users/example/dev/site"},"#,
    r#""target":{"executable":{"path":"/usr/bin/sw_vers"},"audit_token":{"pid":403,"euid":501},"ppid":401,"signing_id":"com.example.tool","team_id":null,"is_platform_binary":false}}}}"#,
    "\n"
);

/// The example's binary, built once per run of this test binary.
///
/// Cargo builds a member's examples only when that member is tested, and gives an integration
/// test the paths of its own package's binaries alone (`CARGO_BIN_EXE_<name>`), never an
/// example's. So the test asks the cargo that runs it (`CARGO`) to build the example in the same
/// target folder, from the lockfile and without the network, and takes the path cargo reports.
/// With the test profile and both packages named, cargo resolves the features and builds the
/// crate as the tests' own build did, so it compiles the example alone, in under a second;
/// naming `immune-contract` alone would compile prost, serde and the crate a second time.
fn client() -> &'static Path {
    static CLIENT: OnceLock<PathBuf> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let out = Command::new(env!("CARGO"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["build", "--frozen", "--quiet", "--message-format=json"])
            .args(["--profile", "test", "-p", "immune", "-p", "immune-contract"])
            .args(["--example", "client"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "client")
            .and_then(|m| m["executable"].as_str().map(PathBuf::from))
            .expect("cargo names the example's executable")
    })
}

/// An invented Mac: a home folder, a system root with the collector and a log of one line that a
/// high rule matches, and a store beside them that one full run has made.
struct Mac(common::Scratch);

impl Mac {
    fn new(tag: &str) -> Mac {
        let mut scratch = common::Scratch::new(&format!("contract-client-{tag}"));
        scratch.0 = std::fs::canonicalize(&scratch.0).unwrap();
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(scratch.join(dir)).unwrap();
        }
        std::fs::write(
            scratch.join("brew.json"),
            r#"{"formulae": [], "casks": []}"#,
        )
        .unwrap();
        let mac = Mac(scratch);
        mac.collector();
        mac.run();
        mac
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The event level laid out as its install does, with a program start `PADDING` matches.
    fn collector(&self) {
        let system = self.path("system");
        let plist = system.join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scripts/event-level/ai.nuanu.immune.eslogger.plist"),
            &plist,
        )
        .unwrap();
        std::fs::create_dir_all(system.join(LOG)).unwrap();
        let out = Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments", "json", "-o"])
            .arg(system.join(COLLECTS))
            .arg(&plist)
            .output()
            .unwrap();
        assert!(out.status.success());
        std::fs::write(system.join(LOG).join(H00), format!("{DD}{SW_VERS_START}")).unwrap();
    }

    /// The position of the log's line at `offset`, as `immune matches` prints it.
    fn position(&self, offset: usize) -> String {
        let log = self.path("system").join(LOG).join(H00);
        let inode = std::fs::metadata(log).unwrap().ino();
        format!("20261004T00-{inode}-{offset}")
    }

    fn immune(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_immune"))
            .env_clear()
            .env("HOME", self.path("home"))
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&*self.0)
            .args(args)
            .arg("--store")
            .arg(self.path("store.db"))
            .output()
            .unwrap()
    }

    /// A full run, with every outside source pointed at nothing.
    fn run(&self) {
        let (empty, none, home) = (self.path("empty"), self.path("none"), self.path("home"));
        let (system, brew) = (self.path("system"), self.path("brew.json"));
        let mut args = vec!["run", "--machine-name", "mac"];
        for (flag, value) in [
            ("--system-root", &system),
            ("--brew-input", &brew),
            ("--osv-crates-input", &none),
            ("--osv-npm-input", &none),
            ("--tailscale", &none),
            ("--threats-input", &none),
            ("--checkouts-root", &home),
            ("--sessions-root", &empty),
            ("--servers-input", &empty),
        ] {
            args.extend([flag, value.to_str().unwrap()]);
        }
        let out = self.immune(&args);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The example, run as `client <args>` with an invented home and nothing else in its
    /// environment.
    fn client(&self, args: &[&str]) -> Output {
        Command::new(client())
            .env_clear()
            .env("HOME", self.path("home"))
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&*self.0)
            .args(args)
            .output()
            .unwrap()
    }

    /// The example on this store with `--judge-first`, which must succeed: what it printed.
    fn judge_first(&self) -> String {
        let system = self.path("system");
        let store = self.path("store.db");
        let out = self.client(&[
            "--immune",
            env!("CARGO_BIN_EXE_immune"),
            "--store",
            store.to_str().unwrap(),
            "--judge-first",
            "--",
            "--system-root",
            system.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn finding(&self, id: &str) -> Value {
        let out = self.immune(&["finding", id, "--json"]);
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

/// What the example printed of each verdict it sent: when it was recorded, its finding, and
/// whether it was already recorded.
fn verdicts(printed: &str) -> Vec<(String, String, bool)> {
    printed
        .lines()
        .filter_map(|l| l.strip_prefix("verdict recorded at "))
        .map(|l| {
            let words: Vec<&str> = l.split(' ').collect();
            (
                words[0].to_string(),
                words[3].to_string(),
                words[words.len() - 1] == "true",
            )
        })
        .collect()
}

#[test]
fn the_client_prints_each_match_with_its_rule_level_whether_it_raised_and_program() {
    let mac = Mac::new("match");
    let printed = mac.judge_first();
    let high = format!(
        "match {} rule {PADDING} level LEVEL_HIGH title \"Binary Padding - MacOS\": finding; program \"/bin/dd\"",
        mac.position(0)
    );
    assert!(printed.lines().any(|l| l == high), "{printed}");
    let medium = format!(
        "match {} rule {SW_VERS} level LEVEL_MEDIUM title \"System Information Discovery Using sw_vers\": no finding (RAISED_BELOW_HIGH); program \"/usr/bin/sw_vers\"",
        mac.position(DD.len())
    );
    assert!(printed.lines().any(|l| l == medium), "{printed}");
}

#[test]
fn the_client_s_verdict_is_recorded_in_an_open_finding_and_its_repeat_is_the_first_one() {
    let mac = Mac::new("repeat");
    let printed = mac.judge_first();
    let sent = verdicts(&printed);
    assert_eq!(sent.len(), 2, "{printed}");
    let (at, finding, already) = &sent[0];
    assert!(!already, "{printed}");
    // The repeat is answered with the verdict recorded the first time, and records nothing.
    assert_eq!(sent[1], (at.clone(), finding.clone(), true), "{printed}");
    let whole = mac.finding(finding);
    assert_eq!(whole["finding"]["state"], "open", "{whole:#}");
    assert_eq!(whole["finding"]["rule"], "verdict.suspicious", "{whole:#}");
    assert_eq!(whole["verdicts"]["total"], 1, "{whole:#}");
    // The same id on a changed message is refused, and the client says what to do.
    assert!(
        printed
            .lines()
            .any(|l| l.starts_with("failure \"verdict_id_reused\"")
                && l.ends_with("send a real decision again under a new id")),
        "{printed}"
    );
}

#[test]
fn a_second_run_of_the_client_makes_a_fresh_id_and_so_a_new_decision() {
    let mac = Mac::new("again");
    let first = verdicts(&mac.judge_first());
    let second = verdicts(&mac.judge_first());
    assert!(!second[0].2, "a fresh id is not a repeat: {second:?}");
    assert_eq!(
        second[0].1, first[0].1,
        "the same rule and thing, the same finding"
    );
    assert_eq!(mac.finding(&first[0].1)["verdicts"]["total"], 2);
}

#[test]
fn without_a_store_the_client_refuses_and_runs_nothing() {
    let dir = common::Scratch::new("contract-client-no-store");
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    // A stand-in for the core that leaves a mark if it is ever run.
    let fake = dir.join("immune");
    std::fs::write(&fake, "#!/bin/sh\n/usr/bin/touch \"$0.ran\"\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new(client())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(&dir)
        .args(["--immune", fake.to_str().unwrap(), "--judge-first"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--store <path> is required"), "{said}");
    assert!(said.contains("never uses the default store"), "{said}");
    assert!(!dir.join("immune.ran").exists(), "the core was run");
    assert_eq!(
        std::fs::read_dir(&home).unwrap().count(),
        0,
        "the home is left empty"
    );
    assert_eq!(
        std::fs::read_dir(&*dir).unwrap().count(),
        2,
        "nothing is made beside"
    );
}
