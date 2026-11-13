//! Promises of `immune verdict`. The first is the foundation: the core's findings are the same
//! whether or not verdicts are sent. The rest are the promises of the finding a suspicious
//! verdict raises, of what is refused, and of the sender's text staying data. Each test runs the
//! real binary over an invented home folder and system root, with log lines as the collector's
//! filter writes them, an invented project and invented content.

use immune_contract::v1;
use prost::Message;
use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRIPTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/event-level");
const PLIST: &str = "Library/LaunchDaemons/ai.nuanu.immune.eslogger.plist";
const LOG: &str = "Library/Application Support/ai.nuanu.immune/event-level/log";
const COLLECTS: &str = "Library/Application Support/ai.nuanu.immune/event-level/collects";
const H00: &str = "exec-20261004T00.jsonl";

/// "Binary Padding - MacOS", high: the core raises a finding of it.
const PADDING: &str = "sigma:95361ce5-c891-4b0a-87ca-e24607884a96";
/// "System Information Discovery Using sw_vers", medium: the core raises nothing of it.
const SW_VERS: &str = "sigma:5de06a6f-673a-4fc0-8d48-bcfe3837b033";
/// The lockfile rule that finds a malicious package, a state the core raises and clears.
const MALICIOUS: &str = "lockfiles.malicious-package";
const VERDICT_RULE: &str = "verdict.suspicious";
/// One of Elastic's behaviour rules, whose set states no level, about a file hidden with SetFile.
const NO_LEVEL: &str = "elastic-behaviour:2ed9c6bf-025e-4edf-a9ec-1493d0bb4f81";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// An invented Mac: a home folder with one project, a system root with the collector, the
/// malicious-package records, and a store beside them.
struct Mac(PathBuf);

impl Mac {
    fn new(tag: &str) -> Mac {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "immune-verdict-{tag}-{}-{nanos}",
            std::process::id()
        ));
        for dir in ["home/dev/shop/.git", "root", "store", "empty"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        let mac = Mac(std::fs::canonicalize(root).unwrap());
        mac.put(&mac.0.join("brew.json"), r#"{"formulae": [], "casks": []}"#);
        mac.put(&mac.0.join("indicators.json"), "[]");
        mac.package(false);
        mac.records();
        mac.install();
        mac
    }

    fn home(&self) -> PathBuf {
        self.0.join("home")
    }

    fn root(&self) -> PathBuf {
        self.0.join("root")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store/store.db")
    }

    fn log(&self) -> PathBuf {
        self.root().join(LOG)
    }

    fn put(&self, path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The project's lockfile, with the malicious release of `ansi-regex` or a clean one.
    fn package(&self, malicious: bool) {
        let version = if malicious { "6.2.1" } else { "6.2.2" };
        let lock = json!({ "lockfileVersion": 3, "packages": {
            "": { "name": "shop" },
            "node_modules/ansi-regex": { "version": version } } });
        self.put(
            &self.home().join("dev/shop/package-lock.json"),
            &lock.to_string(),
        );
    }

    /// The npm records the run reads, as OSV's archive gives them: the one malicious record,
    /// modified an hour ago.
    fn records(&self) {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/osv/npm/MAL-2025-46966.json");
        let mut v: Value = serde_json::from_slice(&std::fs::read(src).unwrap()).unwrap();
        let out = Command::new("/bin/date")
            .args([
                "-u",
                "-r",
                &(now() - 3600).to_string(),
                "+%Y-%m-%dT%H:%M:%SZ",
            ])
            .output()
            .unwrap();
        v["modified"] = json!(String::from_utf8(out.stdout).unwrap().trim());
        let dir = self.0.join("npm-src");
        self.put(&dir.join("MAL-2025-46966.json"), &v.to_string());
        let ok = Command::new("/usr/bin/bsdtar")
            .args(["-c", "--format", "zip", "-f"])
            .arg(self.0.join("npm.zip"))
            .arg("-C")
            .arg(&dir)
            .arg("MAL-2025-46966.json")
            .status()
            .unwrap();
        assert!(ok.success());
    }

    /// Lays the system root out as the event level's install does.
    fn install(&self) {
        std::fs::create_dir_all(self.log()).unwrap();
        let plist = self.root().join(PLIST);
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::copy(
            Path::new(SCRIPTS).join("ai.nuanu.immune.eslogger.plist"),
            &plist,
        )
        .unwrap();
        let out = Command::new("/usr/bin/plutil")
            .args(["-extract", "ProgramArguments", "json", "-o"])
            .arg(self.root().join(COLLECTS))
            .arg(&plist)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    /// Appends a line to the log; its offset.
    fn append(&self, text: &str) -> usize {
        let path = self.log().join(H00);
        let offset = std::fs::metadata(&path).map_or(0, |m| m.len() as usize);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
        offset
    }

    /// A line's position as `immune matches` prints it.
    fn position(&self, offset: usize) -> String {
        let inode = std::fs::metadata(self.log().join(H00)).unwrap().ino();
        format!("20261004T00-{inode}-{offset}")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_immune"));
        c.env("HOME", self.home())
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.0)
            .arg(args[0])
            .arg("--store")
            .arg(self.store())
            .args(&args[1..]);
        c
    }

    /// A full run that reads nothing real: the project, the records and the log under the root.
    fn run(&self) {
        let empty = self.0.join("empty");
        let out = self
            .command(&["run", "--machine-name", "mac", "--system-root"])
            .arg(self.root())
            .arg("--brew-input")
            .arg(self.0.join("brew.json"))
            .args(["--osv-crates-input", "none", "--osv-npm-input"])
            .arg(self.0.join("npm.zip"))
            .args(["--tailscale", "none", "--threats-input", "none"])
            .arg("--checkouts-root")
            .arg(self.home())
            .arg("--sessions-root")
            .arg(&empty)
            .arg("--servers-input")
            .arg(&empty)
            .arg("--indicators")
            .arg(self.0.join("indicators.json"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.command(args).arg("--json").output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn status(&self) -> Value {
        self.json(&["status"])["result"].clone()
    }

    fn findings(&self) -> Value {
        self.json(&["findings"])
    }

    fn finding(&self, id: &str) -> Value {
        self.json(&["finding", id])
    }

    fn store_id(&self) -> String {
        self.findings()["store_id"].as_str().unwrap().to_string()
    }

    /// The latest occurrence of a rule's finding, in any state, as the store holds it.
    fn latest(&self, rule: &str) -> Option<String> {
        use rusqlite::OptionalExtension;
        rusqlite::Connection::open(self.store())
            .unwrap()
            .query_row(
                "SELECT id FROM finding WHERE rule = ?1 ORDER BY occurrence DESC LIMIT 1",
                [rule],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
    }

    /// The ids of the response layer's findings, oldest first.
    fn verdict_findings(&self) -> Vec<String> {
        let db = rusqlite::Connection::open(self.store()).unwrap();
        let mut stmt = db
            .prepare("SELECT id FROM finding WHERE rule LIKE 'verdict.suspicious:%' ORDER BY rowid")
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// What `immune status --json` shows of a finding in what needs a look.
    fn shown(&self, id: &str) -> Option<Value> {
        self.status()["needs_a_look"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == id)
            .cloned()
    }

    fn send_bytes(&self, bytes: &[u8], args: &[&str]) -> Output {
        let mut child = self
            .command(&["verdict", "--system-root"])
            .arg(self.root())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let bytes = bytes.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out
    }

    fn send_output(&self, verdict: &Value) -> Output {
        self.send_bytes(verdict.to_string().as_bytes(), &["--json"])
    }

    /// A verdict in JSON that must be recorded: the answer.
    fn send(&self, verdict: &Value) -> Value {
        let out = self.send_output(verdict);
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// A verdict that must be refused with this code and exit, with nothing recorded.
    fn refused(&self, verdict: &[u8], code: &str, exit: i32) {
        let before = self.recorded();
        let out = self.send_bytes(verdict, &["--json"]);
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["errors"][0]["code"], code, "{v:#}");
        assert!(v.get("format").is_none(), "{v:#}");
        assert_eq!(self.recorded(), before, "{code}: nothing is recorded");
    }

    /// How many verdicts the store holds, and how many journal entries of verdicts.
    fn recorded(&self) -> (i64, i64) {
        let Ok(db) = rusqlite::Connection::open(self.store()) else {
            return (0, 0);
        };
        let count = |sql: &str| db.query_row(sql, [], |r| r.get(0)).unwrap_or(0);
        (
            count("SELECT COUNT(*) FROM verdict"),
            count("SELECT COUNT(*) FROM journal WHERE entry = 'verdict'"),
        )
    }

    /// The person's answer to a finding, as it ran.
    fn answer(&self, id: &str, answer: &[&str]) -> Output {
        self.command(&["finding", id])
            .args(answer)
            .arg("--json")
            .output()
            .unwrap()
    }

    /// Ends every mark of expected now, as time would.
    fn end_marks(&self) {
        rusqlite::Connection::open(self.store())
            .unwrap()
            .execute(
                "UPDATE finding SET until_at = ?1 WHERE until_at IS NOT NULL",
                [now() - 1],
            )
            .unwrap();
    }

    fn matches(&self) -> Value {
        let out = self
            .command(&["matches", "--json", "--system-root"])
            .arg(self.root())
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// The page, as `immune view` writes it.
    fn page(&self) -> String {
        let out = self.command(&["view", "--no-open"]).output().unwrap();
        assert!(out.status.success());
        std::fs::read_to_string(self.0.join("store/view.html")).unwrap()
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A verdict about a finding, in JSON; a suspicious one at the levels given.
fn about_finding(store: &str, id: &str, kind: &str, case: &str) -> Value {
    levels(
        json!({
            "format": 1,
            "store_id": store,
            "finding": { "id": id },
            "kind": kind,
            "reason_text": "invented: the person added the line themselves",
            "case_text": case,
        }),
        ("low", "low"),
    )
}

/// A verdict about a match, in JSON.
fn about_match(store: &str, position: &str, rule: &str, kind: &str) -> Value {
    levels(
        json!({
            "format": 1,
            "store_id": store,
            "match": { "position": position, "rule": rule },
            "kind": kind,
            "reason_text": "invented: an inventory script asks the version",
            "case_text": "case-7",
        }),
        ("low", "low"),
    )
}

/// A verdict with these levels when it is suspicious.
fn levels(mut v: Value, (s, c): (&str, &str)) -> Value {
    if v["kind"] == "suspicious" {
        v["severity"] = json!(s);
        v["confidence"] = json!(c);
    }
    v
}

/// An `exec` line as the collector's filter writes it, with invented content.
fn start(seq: u64, image: &str, args: &[&str]) -> String {
    let out = Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S.000001Z"])
        .output()
        .unwrap();
    let time = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let args = serde_json::to_string(args).unwrap();
    format!(
        r#"{{"schema_version":1,"version":10,"seq_num":{seq},"global_seq_num":{seq},"time":"{time}","process":{{"executable":{{"path":"/bin/sh"}}}},"event":{{"exec":{{"args":{args},"cwd":{{"path":"/Users/example/dev/site"}},"target":{{"executable":{{"path":"{image}"}},"audit_token":{{"pid":402,"euid":501}},"ppid":401,"signing_id":"com.example.tool","team_id":null,"is_platform_binary":false}}}}}}}}"#
    ) + "\n"
}

/// A start the high rule `PADDING` matches.
fn dd(seq: u64) -> String {
    start(seq, "/bin/dd", &["dd", "if=/dev/zero", "bs=1", "count=1"])
}

/// A start the medium rule `SW_VERS` matches.
fn sw_vers(seq: u64) -> String {
    start(seq, "/usr/bin/sw_vers", &["sw_vers", "-productVersion"])
}

// ---- The foundation: a verdict never writes into a finding the core raised. ----

/// One step of a history: what the core does, the person does, or time does, on both twins; or
/// a verdict, or the person's answer to the response layer's finding, on one twin only.
#[derive(Clone, Copy, Debug)]
enum Step {
    Run,
    Package(bool),
    /// A line the high rule matches, or one the medium rule does.
    Event(bool),
    /// The person answers the latest finding of the lockfile rule (`true`) or of `PADDING`.
    Seen(bool),
    Expected(bool),
    Reopen(bool),
    EndMarks,
    /// A verdict about the latest finding of the lockfile rule (`true`) or of `PADDING`: kind
    /// suspicious or harmless, and levels urgent or not.
    AboutFinding(bool, bool, bool),
    /// A verdict about the latest line of the log.
    AboutLine(bool, bool),
    /// The person answers the latest finding of the response layer.
    VerdictSeen,
    VerdictExpected,
}

impl Step {
    fn verdicts_only(self) -> bool {
        matches!(
            self,
            Step::AboutFinding(..)
                | Step::AboutLine(..)
                | Step::VerdictSeen
                | Step::VerdictExpected
        )
    }
}

/// What the core holds of its own findings, as every output a person or the response layer
/// reads gives it: ids, states, occurrences, answers, evidence, counts, which run last saw each,
/// urgency, order, what needs a look. The response layer's findings are left out, and the run
/// that last saw a finding is named by its place among the twin's runs.
fn core(mac: &Mac) -> String {
    if !mac.store().exists() {
        return "no store yet".to_string();
    }
    let db = rusqlite::Connection::open(mac.store()).unwrap();
    let rows = |sql: &str| -> Vec<String> {
        let mut stmt = db.prepare(sql).unwrap();
        let n = stmt.column_count();
        stmt.query_map([now()], |r| {
            Ok((0..n)
                .map(|i| match r.get_ref(i).unwrap() {
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join("|"))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    };
    const CORE: &str = "SELECT id FROM finding WHERE rule NOT LIKE 'verdict.suspicious:%'";
    let runs = rows("SELECT run_id FROM journal WHERE entry = 'run_started' AND ?1 ORDER BY seq");
    let mut out = rows(
        "SELECT id, rule, about, occurrence, state, change, answered_at IS NOT NULL, reason, via,
                until_at IS NOT NULL, until_at <= ?1, first_seen_run, last_seen_run
         FROM finding WHERE rule NOT LIKE 'verdict.suspicious:%' ORDER BY id",
    );
    for sql in [
        "SELECT b.finding, j.entry, j.reader, j.kind FROM finding_basis b JOIN journal j
         ON j.seq = b.journal WHERE b.finding IN (CORE) AND ?1 ORDER BY b.finding, j.seq",
        "SELECT finding, matches FROM rule_finding WHERE finding IN (CORE) AND ?1 ORDER BY finding",
        "SELECT finding, executable, args, timestamp FROM rule_evidence
         WHERE finding IN (CORE) AND ?1 ORDER BY rowid",
        "SELECT file, offset, rule, finding FROM rule_line WHERE ?1 ORDER BY file, offset, rule",
    ] {
        // A table the first reading of the event level makes may not be there yet.
        let sql = sql.replace("CORE", CORE);
        if db.prepare(&sql).is_ok() {
            out.extend(rows(&sql));
        }
    }
    let listed = mac.findings();
    for f in listed["findings"].as_array().unwrap() {
        if f["finding"]["rule"] != VERDICT_RULE {
            out.push(format!(
                "listed {} {} {} {} {}",
                f["finding"],
                f["answer"]["given"],
                f["answer"]["in_force"],
                f["first_seen_at"] == f["last_seen_at"],
                f["kind"]
            ));
        }
    }
    let status = mac.status();
    for i in status["needs_a_look"].as_array().unwrap() {
        if i["rule"] != VERDICT_RULE {
            out.push(format!(
                "needs {} {} {}",
                i["id"], i["urgent"], i["severity"]
            ));
        }
    }
    let mut text = out.join("\n");
    for (n, run) in runs.iter().enumerate() {
        text = text.replace(run, &format!("run#{n}"));
    }
    text.replace(&mac.0.display().to_string(), "<mac>")
}

/// Plays `steps` on two Macs alike, sending verdicts and answering the response layer's
/// findings on the second only, and compares what the core holds after every step.
fn twins(name: &str, steps: &[Step]) {
    let (plain, judged) = (
        Mac::new(&format!("{name}-plain")),
        Mac::new(&format!("{name}-judged")),
    );
    let mut seq = 0;
    let mut line: Option<usize> = None;
    for (n, step) in steps.iter().enumerate() {
        let event = match step {
            Step::Event(high) => {
                seq += 1;
                Some(if *high { dd(seq) } else { sw_vers(seq) })
            }
            _ => None,
        };
        let rule = |lockfile: bool| if lockfile { MALICIOUS } else { PADDING };
        for mac in [&plain, &judged] {
            if step.verdicts_only() && std::ptr::eq(mac, &plain) {
                continue;
            }
            match *step {
                Step::Run => mac.run(),
                Step::Package(malicious) => mac.package(malicious),
                Step::Event(_) => line = Some(mac.append(event.as_deref().unwrap())),
                Step::Seen(r) | Step::Expected(r) | Step::Reopen(r) => {
                    if let Some(id) = mac.latest(rule(r)) {
                        let act: &[&str] = match step {
                            Step::Seen(_) => &["seen"],
                            Step::Expected(_) => {
                                &["expected", "--days", "1", "--reason", "invented"]
                            }
                            _ => &["reopen"],
                        };
                        mac.answer(&id, act);
                    }
                }
                Step::EndMarks => mac.end_marks(),
                Step::AboutFinding(r, suspicious, urgent) => {
                    if let Some(id) = mac.latest(rule(r)) {
                        let kind = if suspicious { "suspicious" } else { "harmless" };
                        let v = about_finding(&mac.store_id(), &id, kind, &format!("case-{n}"));
                        let v = levels(
                            v,
                            if urgent {
                                ("critical", "high")
                            } else {
                                ("low", "low")
                            },
                        );
                        mac.send(&v);
                    }
                }
                Step::AboutLine(suspicious, urgent) => {
                    if let Some(at) = line {
                        let kind = if suspicious { "suspicious" } else { "harmless" };
                        for rule in [PADDING, SW_VERS] {
                            let mut v = about_match(&mac.store_id(), &mac.position(at), rule, kind);
                            v["case_text"] = json!(format!("case-{n}"));
                            let v = levels(
                                v,
                                if urgent {
                                    ("high", "medium")
                                } else {
                                    ("low", "low")
                                },
                            );
                            // The line matches one of the two rules; the other is refused.
                            mac.send_output(&v);
                        }
                    }
                }
                Step::VerdictSeen | Step::VerdictExpected => {
                    if let Some(id) = mac.verdict_findings().last() {
                        let act: &[&str] = if matches!(step, Step::VerdictSeen) {
                            &["seen"]
                        } else {
                            &["expected", "--days", "1", "--reason", "invented"]
                        };
                        mac.answer(id, act);
                    }
                }
            }
        }
        // An answer and the run after it never share a second, on either Mac.
        if matches!(step, Step::Seen(_) | Step::Expected(_) | Step::Reopen(_)) {
            let at = now();
            while now() == at {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        let (a, b) = (core(&plain), core(&judged));
        let differ: Vec<_> = a.lines().zip(b.lines()).filter(|(x, y)| x != y).collect();
        assert!(
            a == b,
            "{name}, after step {n} {step:?} of {steps:?}: {differ:#?}\nwithout verdicts:\n{a}\nwith them:\n{b}"
        );
    }
}

/// A history drawn from `seed`, the same every time.
fn drawn(seed: u64, len: usize) -> Vec<Step> {
    let mut x = seed;
    let mut next = |n: u64| {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (x >> 33) % n
    };
    let mut steps = vec![Step::Package(true), Step::Event(true), Step::Run];
    while steps.len() < len {
        let b = |v: u64| v == 1;
        steps.push(match next(13) {
            0 | 1 => Step::Run,
            2 => Step::Package(b(next(2))),
            3 => Step::Event(b(next(2))),
            4 => Step::Seen(b(next(2))),
            5 => Step::Expected(b(next(2))),
            6 => Step::Reopen(b(next(2))),
            7 => Step::EndMarks,
            8 | 9 => Step::AboutFinding(b(next(2)), next(3) > 0, b(next(2))),
            10 => Step::AboutLine(next(3) > 0, b(next(2))),
            11 => Step::VerdictSeen,
            _ => Step::VerdictExpected,
        });
    }
    steps
}

#[test]
fn the_core_s_findings_are_the_same_whether_or_not_verdicts_are_sent() {
    use Step::*;
    let named: Vec<(&str, Vec<Step>)> = vec![
        // A malicious package found, gone and cleared; a suspicious verdict about it, seen;
        // the package comes back: the core raises it again.
        (
            "comes-back",
            vec![
                Package(true),
                Run,
                Package(false),
                Run,
                AboutFinding(true, true, true),
                VerdictSeen,
                Run,
                Package(true),
                Run,
            ],
        ),
        // An urgent suspicious verdict about an open finding, then the package goes, and the
        // same in the other order: the run clears the core's finding either way.
        (
            "verdict-then-gone",
            vec![
                Package(true),
                Run,
                AboutFinding(true, true, true),
                Package(false),
                Run,
            ],
        ),
        (
            "gone-then-verdict",
            vec![
                Package(true),
                Run,
                Package(false),
                Run,
                AboutFinding(true, true, true),
                Run,
            ],
        ),
        // A harmless verdict after an urgent one; a mark of expected then a suspicious verdict
        // and the mark's end; a cleared finding then a suspicious verdict.
        (
            "harmless-after-urgent",
            vec![
                Event(true),
                Run,
                AboutFinding(false, true, true),
                AboutFinding(false, false, false),
                AboutLine(false, false),
                Run,
            ],
        ),
        (
            "expected-then-suspicious",
            vec![
                Event(true),
                Run,
                Expected(false),
                AboutFinding(false, true, true),
                AboutLine(true, true),
                EndMarks,
                Run,
                Event(true),
                Run,
            ],
        ),
        (
            "cleared-then-suspicious",
            vec![
                Package(true),
                Run,
                Package(false),
                Run,
                AboutFinding(true, true, false),
                Run,
                Run,
            ],
        ),
        // A line below high, judged suspicious before and after the reading reaches it.
        (
            "below-high",
            vec![
                Run,
                Event(false),
                AboutLine(true, true),
                Run,
                AboutLine(true, false),
                Run,
            ],
        ),
    ];
    let mut histories = named;
    for seed in 1..=3 {
        histories.push(("drawn", drawn(seed, 18)));
    }
    let threads: Vec<_> = histories
        .into_iter()
        .enumerate()
        .map(|(i, (name, steps))| std::thread::spawn(move || twins(&format!("{name}-{i}"), &steps)))
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

// ---- The finding a suspicious verdict raises. ----

#[test]
fn a_suspicious_verdict_raises_one_finding_of_its_rule_and_thing_that_only_the_person_closes() {
    let mac = Mac::new("one-finding");
    mac.package(true);
    let at = mac.append(&dd(1));
    mac.run();
    let store = mac.store_id();
    let padding = mac.latest(PADDING).unwrap();
    let malicious = mac.latest(MALICIOUS).unwrap();
    // A verdict about the core's finding and one about a match of the same rule on this Mac go
    // to one finding; another rule's thing goes to another.
    let first = mac.send(&about_finding(&store, &padding, "suspicious", "case-1"));
    assert_eq!(first["recorded"]["raised"], true);
    let own = first["recorded"]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(own, padding);
    assert_eq!(first["recorded"]["finding"]["rule"], VERDICT_RULE);
    let second = mac.send(&about_match(
        &store,
        &mac.position(at),
        PADDING,
        "suspicious",
    ));
    assert_eq!(second["recorded"]["finding"]["id"], own.as_str());
    assert_eq!(second["recorded"]["raised"], false);
    let other = mac.send(&about_finding(&store, &malicious, "suspicious", "case-2"));
    assert_ne!(other["recorded"]["finding"]["id"], own.as_str());
    assert_eq!(mac.verdict_findings().len(), 2);
    // A run that no longer finds the package clears the core's finding and not the response
    // layer's: only the person closes it.
    mac.package(false);
    mac.run();
    let lockfile_own = other["recorded"]["finding"]["id"].as_str().unwrap();
    assert!(mac.shown(lockfile_own).is_some());
    assert!(mac.shown(&malicious).is_none());
    // The core's finding names it, and says how many verdicts there are and nothing they said.
    let item = mac.shown(&padding).unwrap();
    assert_eq!(item["verdict"]["finding"], own.as_str());
    assert_eq!(item["verdict"]["total"], 1);
    assert_eq!(
        item["verdict"]["said"],
        "1 verdict from the response layer, 1 suspicious."
    );
    assert!(item["verdict"].get("reason_text").is_none());
    // It rests on the verdict that raised it, as a finding rests on what raised it.
    let text = mac.command(&["finding", &own]).output().unwrap();
    let text = String::from_utf8_lossy(&text.stdout);
    let raising: i64 = rusqlite::Connection::open(mac.store())
        .unwrap()
        .query_row(
            "SELECT MIN(seq) FROM journal WHERE entry = 'verdict'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        text.contains(&format!("Rests on 1 journal entry: {raising}.")),
        "{text}"
    );
    // Once the person saw it, the core's finding no longer names it, and the next suspicious
    // verdict raises its next occurrence, which the core's finding names.
    assert!(mac.answer(&own, &["seen"]).status.success());
    assert!(mac.shown(&padding).unwrap()["verdict"]["finding"].is_null());
    let mut again = about_finding(&store, &padding, "suspicious", "case-3");
    again["reason_text"] = json!("invented: it ran again");
    let next = mac.send(&again);
    assert_eq!(next["recorded"]["raised"], true);
    assert_ne!(next["recorded"]["finding"]["id"], own.as_str());
    let next_id = next["recorded"]["finding"]["id"].as_str().unwrap();
    assert_eq!(mac.shown(&padding).unwrap()["verdict"]["finding"], next_id);
    // A verdict about the response layer's finding is about the same rule and thing: it goes to
    // that finding.
    let on_own = mac.send(&about_finding(&store, next_id, "suspicious", "case-4"));
    assert_eq!(on_own["recorded"]["finding"]["id"], next_id);
    // Its one-line form quotes the verdict that raised this occurrence, and counts the rest.
    let item = mac.shown(next_id).unwrap();
    assert_eq!(item["verdict"]["reason_text"], "invented: it ran again");
    assert_eq!(item["verdict"]["more"], 1);
    let about = item["value_text"].as_str().unwrap();
    assert!(about.starts_with("Binary Padding - MacOS, by "), "{about}");
}

#[test]
fn a_verdict_finding_s_levels_are_the_highest_its_verdicts_gave_and_only_go_up() {
    let mac = Mac::new("levels");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let send = |case: &str, l: (&str, &str)| {
        mac.send(&levels(about_finding(&store, &id, "suspicious", case), l))["recorded"]["finding"]
            ["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let core = mac.shown(&id).unwrap();
    let own_levels = (core["severity"].clone(), core["confidence"].clone());
    let own = send("case-1", ("medium", "low"));
    let item = |mac: &Mac| mac.shown(&own).unwrap();
    assert_eq!(
        (item(&mac)["severity"].clone(), item(&mac)["urgent"].clone()),
        (json!("medium"), json!(false))
    );
    send("case-2", ("critical", "low"));
    send("case-3", ("low", "high"));
    let i = item(&mac);
    assert_eq!(
        (
            i["severity"].clone(),
            i["confidence"].clone(),
            i["urgent"].clone()
        ),
        (json!("critical"), json!("high"), json!(true))
    );
    send("case-4", ("informational", "low"));
    assert_eq!(item(&mac)["urgent"], true);
    // The core's finding keeps its own levels, whatever the verdicts said.
    let core = mac.shown(&id).unwrap();
    assert_eq!(
        (core["severity"].clone(), core["confidence"].clone()),
        own_levels
    );
}

#[test]
fn a_verdict_finding_keeps_the_event_it_is_about_and_a_match_s_raised_stays_what_the_core_did() {
    let mac = Mac::new("evidence");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    let position = mac.position(at);
    let answer = mac.send(&about_match(&store, &position, SW_VERS, "suspicious"));
    let own = answer["recorded"]["finding"]["id"].as_str().unwrap();
    let whole = mac.finding(own);
    let evidence = &whole["evidence"]["verdict_given"];
    assert_eq!(evidence["rule"], SW_VERS);
    assert_eq!(evidence["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        evidence["events"][0]["program_start"]["process"]["executable_text"],
        "/usr/bin/sw_vers"
    );
    // The match stays below high, as the core left it; the response layer's finding is named.
    let m = mac.matches();
    let x = &m["matches"][0];
    assert_eq!(x["raised"], "below_high");
    assert_eq!(x["findings"][0]["id"], own);
    assert_eq!(x["verdicts"]["total"], 1);
}

#[test]
fn a_suspicious_verdict_about_a_match_of_a_rule_with_no_level_is_a_finding_the_person_is_shown() {
    // Elastic's behaviour rules state no level, so the core raises nothing on a match of one and
    // hands it over. The response layer's judgement of it is then the only finding there is, and
    // it is listed and needs a look like any other.
    let mac = Mac::new("no-level");
    let at = mac.append(&start(
        1,
        "/usr/bin/SetFile",
        &["SetFile", "-a", "V", "/Users/example/x"],
    ));
    mac.run();
    let store = mac.store_id();
    let m = mac.matches();
    let hit = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["rule"]["name"] == NO_LEVEL)
        .unwrap_or_else(|| panic!("{m:#}"));
    assert_eq!(hit["raised"], "level_not_stated");
    let answer = mac.send(&levels(
        about_match(&store, &mac.position(at), NO_LEVEL, "suspicious"),
        ("high", "medium"),
    ));
    let own = answer["recorded"]["finding"]["id"].as_str().unwrap();
    let whole = mac.finding(own);
    assert_eq!(whole["evidence"]["verdict_given"]["rule"], NO_LEVEL);
    let listed = mac.findings();
    let listed = listed.to_string();
    assert!(listed.contains(own), "{listed}");
    let status = mac.status().to_string();
    assert!(status.contains(own), "{status}");
    // The match stays what the core made of it.
    let m = mac.matches();
    let hit = m["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["rule"]["name"] == NO_LEVEL)
        .unwrap();
    assert_eq!(hit["raised"], "level_not_stated");
    assert_eq!(hit["findings"][0]["id"], own);
}

#[test]
fn a_verdict_finding_about_a_rule_a_later_build_drops_stays_listed_and_can_be_opened() {
    // The response layer's finding is the person's to close. A build that no longer ships the
    // rule it is about still lists it, counts it and opens it, named as the verdict named it.
    let mac = Mac::new("dropped-rule");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    let answer = mac.send(&levels(
        about_match(&store, &mac.position(at), SW_VERS, "suspicious"),
        ("critical", "high"),
    ));
    let own = answer["recorded"]["finding"]["id"].as_str().unwrap();
    // What a store is left with when a later build drops the rule: the finding names a rule
    // the build does not have.
    let gone = "sigma:00000000-0000-4000-8000-000000000000";
    rusqlite::Connection::open(mac.store())
        .unwrap()
        .execute(
            "UPDATE finding SET rule = ?1 WHERE id = ?2",
            [&format!("{VERDICT_RULE}:{gone}"), own],
        )
        .unwrap();
    assert!(mac.findings().to_string().contains(own));
    let status = mac.status();
    assert!(
        status["needs_a_look"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == own),
        "{status:#}"
    );
    let whole = mac.finding(own);
    assert_eq!(whole["finding"]["id"], own, "{whole:#}");
}

#[test]
fn a_position_in_a_log_file_named_by_run_and_second_is_taken_as_immune_matches_printed_it() {
    // The collector names a file by its run and the second it began, so the name holds a dash.
    // A verdict names a match by the position `immune matches` printed, whole.
    let mac = Mac::new("named-by-second");
    std::fs::write(
        mac.log().join("exec-20261004T000013-20261004T000000.jsonl"),
        sw_vers(1),
    )
    .unwrap();
    mac.run();
    let m = mac.matches();
    let position = m["matches"][0]["position"].as_str().unwrap().to_string();
    assert!(
        position.starts_with("20261004T000013-20261004T000000-"),
        "{position}"
    );
    let answer = mac.send(&about_match(
        &mac.store_id(),
        &position,
        SW_VERS,
        "suspicious",
    ));
    assert_eq!(answer["recorded"]["raised"], true, "{answer:#}");
    assert_eq!(
        answer["recorded"]["verdict"]["match"]["position"],
        position.as_str()
    );
}

#[test]
fn the_same_message_is_recorded_once_while_its_finding_is_open_and_raises_the_next_after_an_answer()
{
    let mac = Mac::new("same");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let v = about_finding(&store, &id, "suspicious", "case-1");
    let first = mac.send(&v);
    let again = mac.send(&v);
    assert_eq!(again["already_recorded"], true);
    assert_eq!(again["recorded"], first["recorded"]);
    // Anything else in the message is another verdict: its levels, its reason.
    let mut graver = levels(v.clone(), ("high", "low"));
    assert_eq!(mac.send(&graver)["already_recorded"], false);
    graver["confidence"] = json!("medium");
    assert_eq!(mac.send(&graver)["already_recorded"], false);
    let mut reason = v.clone();
    reason["reason_text"] = json!("invented: another reason");
    assert_eq!(mac.send(&reason)["already_recorded"], false);
    assert_eq!(mac.recorded(), (4, 4));
    // After the person saw it, the same message is the response layer saying it again.
    let own = first["recorded"]["finding"]["id"].as_str().unwrap();
    assert!(mac.answer(own, &["seen"]).status.success());
    let next = mac.send(&v);
    assert_eq!(next["already_recorded"], false);
    assert_eq!(next["recorded"]["raised"], true);
    // A harmless message is recorded once.
    let harmless = about_finding(&store, &id, "harmless", "case-9");
    mac.send(&harmless);
    assert_eq!(mac.send(&harmless)["already_recorded"], true);
}

#[test]
fn an_answer_lists_the_first_verdict_and_the_latest_twenty_with_the_total() {
    let mac = Mac::new("bound");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    for n in 0..25 {
        mac.send(&about_finding(
            &store,
            &id,
            "harmless",
            &format!("case-{n}"),
        ));
    }
    let whole = mac.finding(&id);
    let listed = whole["verdicts"]["listed"].as_array().unwrap();
    assert_eq!(whole["verdicts"]["total"], 25);
    assert_eq!(listed.len(), 21);
    assert_eq!(listed[0]["verdict"]["case_text"], "case-0");
    assert_eq!(listed[1]["verdict"]["case_text"], "case-5");
    assert_eq!(listed[20]["verdict"]["case_text"], "case-24");
}

// ---- What is refused, and that a refusal writes nothing. ----

#[test]
fn what_this_build_does_not_read_is_refused_in_either_form_and_records_nothing() {
    let mac = Mac::new("refused");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let good = about_finding(&store, &id, "suspicious", "case-1");
    let with = |key: &str, value: Value| {
        let mut v = good.clone();
        v[key] = value;
        v.to_string().into_bytes()
    };
    let without = |key: &str| {
        let mut v = good.clone();
        v.as_object_mut().unwrap().remove(key);
        v.to_string().into_bytes()
    };
    let harmless = about_finding(&store, &id, "harmless", "case-1");
    let mut harmless_with_levels = harmless.clone();
    harmless_with_levels["severity"] = json!("high");
    for bad in [
        b"".to_vec(),
        b"not json".to_vec(),
        format!("{good} {good}").into_bytes(),
        with("format", json!(2)),
        with("kind", json!("benign")),
        with("severity", json!("unspecified")),
        with("confidence", json!("critical")),
        without("finding"),
        without("severity"),
        without("confidence"),
        harmless_with_levels.to_string().into_bytes(),
        with("urgency", json!("critical")),
        with("finding", json!({ "id": id, "extra": 1 })),
        with("match", json!({ "position": "x", "rule": PADDING })),
        format!(
            r#"{{"format":1,"store_id":"{store}","finding":{{"id":"{id}","id":"{id}"}},"kind":"harmless","reason_text":"r","case_text":"c"}}"#
        )
        .into_bytes(),
    ] {
        mac.refused(&bad, "not_a_verdict", 2);
    }
    for (field, code) in [("reason_text", "empty_reason"), ("case_text", "empty_case")] {
        for empty in ["", "  \n", "\u{200b}\u{2060}"] {
            mac.refused(&with(field, json!(empty)), code, 2);
        }
    }
    mac.refused(
        &with("reason_text", json!("x".repeat(1001))),
        "reason_too_long",
        2,
    );
    mac.refused(
        &with("case_text", json!("é".repeat(201))),
        "case_too_long",
        2,
    );
    mac.refused(&with("store_id", json!("0".repeat(32))), "another_store", 2);
    mac.refused(
        &with("finding", json!({ "id": "f0000000000" })),
        "unknown_finding",
        2,
    );
    let mut no_match = about_match(&store, "20261004T00-1-0", PADDING, "harmless");
    mac.refused(no_match.to_string().as_bytes(), "match_gone", 2);
    no_match["match"]["rule"] = json!("sigma:nope");
    mac.refused(no_match.to_string().as_bytes(), "no_such_match", 2);
    // In binary: a field this build does not know, a field given twice, both subjects.
    let message = v1::Verdict {
        format: 1,
        store_id: store.clone(),
        about: Some(v1::verdict::About::Finding(v1::AboutFinding {
            id: id.clone(),
        })),
        kind: v1::VerdictKind::Harmless as i32,
        reason_text: "invented".to_string(),
        case_text: "case-binary".to_string(),
        severity: None,
        confidence: None,
    }
    .encode_to_vec();
    let both = {
        let mut b = message.clone();
        b.extend(
            v1::Verdict {
                about: Some(v1::verdict::About::Match(v1::AboutMatch::default())),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        b
    };
    for bad in [
        [message.clone(), vec![0x78, 0x01]].concat(),
        [message.clone(), vec![0x08, 0x01]].concat(),
        both,
        vec![0xff, 0xff],
    ] {
        let before = mac.recorded();
        let out = mac.send_bytes(&bad, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert_eq!(mac.recorded(), before);
    }
    // The message itself, in binary, is taken and answered in binary.
    let out = mac.send_bytes(&message, &[]);
    assert!(out.status.success());
    let answer = v1::VerdictRecorded::decode(out.stdout.as_slice()).unwrap();
    assert_eq!(
        answer.recorded.unwrap().verdict.unwrap().case_text,
        "case-binary"
    );
}

#[test]
fn a_refused_verdict_gives_no_store_an_id_and_makes_no_store_of_a_file() {
    let mac = Mac::new("refusal-writes-nothing");
    mac.run();
    let db = rusqlite::Connection::open(mac.store()).unwrap();
    db.execute("DELETE FROM meta WHERE key = 'store_id'", [])
        .unwrap();
    drop(db);
    let bytes = std::fs::read(mac.store()).unwrap();
    let v = about_finding("", "f0", "harmless", "case-1");
    mac.refused(v.to_string().as_bytes(), "another_store", 2);
    assert_eq!(std::fs::read(mac.store()).unwrap(), bytes);
    std::fs::write(mac.store(), b"").unwrap();
    assert_eq!(mac.send_output(&v).status.code(), Some(3));
    assert_eq!(std::fs::metadata(mac.store()).unwrap().len(), 0);
}

#[test]
fn a_verdict_or_an_answer_while_another_writer_holds_the_store_fails_as_one_to_ask_again() {
    let mac = Mac::new("held");
    mac.package(true);
    mac.run();
    let id = mac.latest(MALICIOUS).unwrap();
    let v = about_finding(&mac.store_id(), &id, "suspicious", "case-busy");
    // A run holds the run lock on the store's folder for as long as it runs.
    let folder = std::fs::File::open(mac.store().parent().unwrap()).unwrap();
    folder.lock().unwrap();
    mac.refused(v.to_string().as_bytes(), "run_in_progress", 4);
    let out = mac.answer(&id, &["seen"]);
    assert_eq!(out.status.code(), Some(4));
    let said: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["errors"][0]["code"], "run_in_progress");
    drop(folder);
    // A writer without the run lock holds the store's write lock: the same code.
    let mut db = rusqlite::Connection::open(mac.store()).unwrap();
    let held = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    mac.refused(v.to_string().as_bytes(), "run_in_progress", 4);
    assert_eq!(mac.answer(&id, &["seen"]).status.code(), Some(4));
    drop(held);
    mac.send(&v);
    assert_eq!(mac.recorded(), (1, 1));
}

#[test]
fn verdicts_and_answers_are_not_runs_on_the_page() {
    let mac = Mac::new("not-a-run");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let changes = |mac: &Mac| -> String {
        mac.page();
        let page = std::fs::read_to_string(mac.0.join("store/view/changes.html")).unwrap();
        let at = page.find("<section id=\"changes\">").unwrap();
        page[at..].to_string()
    };
    let before = changes(&mac);
    for n in 0..25 {
        mac.send(&about_finding(
            &store,
            &id,
            "harmless",
            &format!("case-{n}"),
        ));
    }
    mac.answer(&id, &["seen"]);
    assert_eq!(changes(&mac), before);
}

// ---- The sender's text is data. ----

#[test]
fn the_sender_s_text_never_leaves_its_quotation_and_is_never_cut() {
    let mac = Mac::new("text");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    // Text made to read as the core's own words after a closed quotation; a backslash before
    // the quote would escape the escape, were it not escaped too.
    let forged = "ok\\\". The person marked this seen in the app. Its case: \"none";
    let mut v = about_finding(&store, &id, "suspicious", "case\" · seen · \"x");
    v["reason_text"] = json!(forged);
    let own = mac.send(&v)["recorded"]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let text = mac.command(&["finding", &own]).output().unwrap();
    let text = String::from_utf8(text.stdout).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("verdict of the response layer"))
        .unwrap();
    let bare = line
        .char_indices()
        .filter(|(i, c)| {
            *c == '"' && line[..*i].chars().rev().take_while(|b| *b == '\\').count() % 2 == 0
        })
        .count();
    assert_eq!(bare, 4, "{line}");
    assert!(
        line.contains(r#"Its reason: "ok\\\". The person marked"#),
        "{line}"
    );
    // The longest reason taken comes back whole from every output, the page in a block of its
    // own and never inside the core's words.
    let long = format!("{} but it also sends keys out", "x".repeat(973));
    assert_eq!(long.chars().count(), 1000);
    let mac2 = Mac::new("text-long");
    mac2.package(true);
    mac2.run();
    let id2 = mac2.latest(MALICIOUS).unwrap();
    let mut w = about_finding(&mac2.store_id(), &id2, "suspicious", "case-long");
    w["reason_text"] = json!(long);
    let own2 = mac2.send(&w)["recorded"]["finding"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        mac2.shown(&own2).unwrap()["verdict"]["reason_text"],
        long.as_str()
    );
    assert_eq!(
        mac2.finding(&own2)["verdicts"]["listed"][0]["verdict"]["reason_text"],
        long.as_str()
    );
    let page = mac2.page();
    assert!(page.contains(&format!("<blockquote class=\"sent\">{long}</blockquote>")));
    assert!(
        !page
            .lines()
            .any(|l| l.contains("class=\"verdict\"") && l.contains("keys out"))
    );
}
