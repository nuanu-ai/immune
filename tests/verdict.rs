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
        // A statement rewrites the sweep, which reads the tailnet: from a path that is not
        // there, never this Mac's own `tailscale`.
        if args[0] == "owner" {
            c.arg("--tailscale").arg(self.0.join("no-tailscale"));
        }
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
        self.json(&["status"]).clone()
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
        looks(&self.status())
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
    for i in looks(&status).as_array().unwrap() {
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
    assert_eq!(item["verdicts"]["verdict_finding"]["id"], own.as_str());
    assert_eq!(
        (&item["verdicts"]["total"], &item["verdicts"]["suspicious"]),
        (&json!(1), &json!(1))
    );
    assert_eq!(item["verdicts"]["listed"], json!([]));
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
    assert!(mac.shown(&padding).unwrap()["verdicts"]["verdict_finding"].is_null());
    let mut again = about_finding(&store, &padding, "suspicious", "case-3");
    again["reason_text"] = json!("invented: it ran again");
    let next = mac.send(&again);
    assert_eq!(next["recorded"]["raised"], true);
    assert_ne!(next["recorded"]["finding"]["id"], own.as_str());
    let next_id = next["recorded"]["finding"]["id"].as_str().unwrap();
    assert_eq!(
        mac.shown(&padding).unwrap()["verdicts"]["verdict_finding"]["id"],
        next_id
    );
    // A verdict about the response layer's finding is about the same rule and thing: it goes to
    // that finding.
    let on_own = mac.send(&about_finding(&store, next_id, "suspicious", "case-4"));
    assert_eq!(on_own["recorded"]["finding"]["id"], next_id);
    // Its one-line form quotes the verdict that raised this occurrence, and counts the rest.
    let item = mac.shown(next_id).unwrap();
    let verdicts = &item["verdicts"];
    assert_eq!(
        verdicts["listed"][0]["verdict"]["reason_text"],
        "invented: it ran again"
    );
    assert_eq!(
        (
            &verdicts["total"],
            verdicts["listed"].as_array().unwrap().len()
        ),
        (&json!(2), 1)
    );
    let about = item["value_text"].as_str().unwrap();
    assert!(about.starts_with("Binary Padding - MacOS, by "), "{about}");
}

/// Findings of the core inserted as a check would leave them: `n` of `rule`, each about an
/// invented application, open.
fn insert_findings(mac: &Mac, rule: &str, tag: &str, n: usize) -> Vec<String> {
    let conn = rusqlite::Connection::open(mac.store()).unwrap();
    (0..n)
        .map(|k| {
            let about = format!("file:machine:mac//Applications/Invented {tag} {k}.app");
            conn.execute(
                "INSERT OR IGNORE INTO entity (id, type) VALUES (?1, 'file')",
                [&about],
            )
            .unwrap();
            let id = format!("f{tag}{k:08x}");
            conn.execute(
                "INSERT INTO finding (id, rule, about, occurrence, state, first_seen_at,
                                      first_seen_run, last_seen_at, last_seen_run)
                 VALUES (?1, ?2, ?3, 1, 'open', 1, 'r', 1, 'r')",
                rusqlite::params![id, rule, about],
            )
            .unwrap();
            id
        })
        .collect()
}

/// What needs a look as the status lists it, by source: the core's and the response layer's.
fn by_source(r: &Value) -> (Vec<Value>, Vec<Value>) {
    looks(r)
        .as_array()
        .unwrap()
        .iter()
        .cloned()
        .partition(|i| i["rule"] != "verdict.suspicious")
}

#[test]
fn each_source_keeps_its_own_fifty_so_urgent_findings_of_one_never_push_out_the_other() {
    // The core has more urgent findings than its fifty: the response layer's finding that is
    // not urgent is listed all the same, beside the core's fifty urgent ones.
    let mac = Mac::new("cut-core");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let own = mac.send(&about_finding(&store, &id, "suspicious", "case-1"))["recorded"]["finding"]
        ["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(mac.shown(&own).unwrap()["urgent"], false);
    // integrity.app-seal is high and medium: urgent.
    insert_findings(&mac, "integrity.app-seal", "a", 51);
    let r = mac.status();
    let (core, layer) = by_source(&r);
    assert_eq!((core.len(), layer.len()), (50, 1), "{:#}", looks(&r));
    assert!(core.iter().all(|i| i["urgent"] == true));
    assert!(mac.shown(&own).is_some());
    assert_eq!(
        r["needs_a_look"]["total"], 53,
        "{:#}",
        r["needs_a_look"]["total"]
    );
    assert_eq!(r["needs_a_look"]["urgent_total"], 52);

    // The response layer has more urgent findings than its fifty: the core's findings that are
    // not urgent are listed all the same, fifty of them, beside the layer's fifty urgent ones.
    let mac = Mac::new("cut-layer");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    // watched.shell-profile is medium and low: not urgent.
    let quiet = insert_findings(&mac, "watched.shell-profile", "b", 51);
    for (k, id) in quiet.iter().enumerate() {
        let v = levels(
            about_finding(&store, id, "suspicious", &format!("case-{k}")),
            ("critical", "high"),
        );
        assert!(mac.send_output(&v).status.success(), "{k}");
    }
    let r = mac.status();
    let (core, layer) = by_source(&r);
    assert_eq!((core.len(), layer.len()), (50, 50), "{:#}", looks(&r));
    assert!(layer.iter().all(|i| i["urgent"] == true));
    assert!(core.iter().any(|i| i["urgent"] == false), "{core:#?}");
    // Urgent first within the core's own fifty.
    let first_quiet = core.iter().position(|i| i["urgent"] == false).unwrap();
    assert!(core[first_quiet..].iter().all(|i| i["urgent"] == false));
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
    let out = mac.command(&["finding", own]).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains(&format!("Rule the verdict is about: {SW_VERS}.")),
        "{text}"
    );
    assert!(
        text.contains(r#""/usr/bin/sw_vers": "sw_vers" "-productVersion""#),
        "{text}"
    );
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
        looks(&status)
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
        let out = mac.send_bytes(&bad, &["--proto"]);
        assert_eq!(out.status.code(), Some(2));
        let failure = v1::Failure::decode(out.stdout.as_slice()).unwrap();
        assert_eq!(failure.errors[0].code, "not_a_verdict");
        assert_eq!(mac.recorded(), before);
    }
    // The message itself, in binary, is taken and answered in binary.
    let out = mac.send_bytes(&message, &["--proto"]);
    assert!(out.status.success());
    let answer = v1::VerdictRecorded::decode(out.stdout.as_slice()).unwrap();
    assert_eq!(
        answer.recorded.unwrap().verdict.unwrap().case_text,
        "case-binary"
    );
}

/// `n` invented letters and digits, the same for the same seed: a token's body made when the test
/// runs, so no literal in the source looks like one.
fn invented(seed: u64, n: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            chars[((x >> 33) as usize) % chars.len()]
        })
        .collect()
}

#[test]
fn a_secret_in_a_key_of_a_verdict_is_refused_without_echo_and_the_finding_is_as_it_was() {
    // A key of a verdict (its case, the store and what it names) is never rewritten: cut, it
    // would mean something else. One that holds a secret is refused before anything is written,
    // the refusal names the field alone, in either form, and what it is about is as it was.
    let mac = Mac::new("secret");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(4, 36));
    let password = format!("Fk{}", invented(5, 14));
    let before = mac.finding(&id)["finding"].clone();
    let good = about_finding(&store, &id, "harmless", "case-1");
    let mut sent = Vec::new();
    for case in [
        format!("case {token}"),
        format!("case --password {password}"),
    ] {
        let mut v = good.clone();
        v["case_text"] = json!(case);
        sent.push(("case_text".to_string(), v));
    }
    let mut rule = about_match(&store, "20261004T00-1-0", PADDING, "harmless");
    rule["match"]["rule"] = json!(token);
    sent.push(("match.rule".to_string(), rule));
    let mut position = about_match(&store, "20261004T00-1-0", PADDING, "harmless");
    position["match"]["position"] = json!(token);
    sent.push(("match.position".to_string(), position));
    let mut named = good.clone();
    named["finding"]["id"] = json!(token);
    sent.push(("finding.id".to_string(), named));
    let mut other = good.clone();
    other["store_id"] = json!(token);
    sent.push(("store_id".to_string(), other));
    let mut bodies: Vec<(String, Vec<u8>, Value)> = sent
        .into_iter()
        .map(|(field, v)| (field, v.to_string().into_bytes(), v))
        .collect();
    // A JSON escape hides nothing: the key is checked as read.
    let escaped = good
        .to_string()
        .replacen("case-1", &format!("case \\u0067{}", &token[1..]), 1);
    bodies.push((
        "case_text".to_string(),
        escaped.clone().into_bytes(),
        serde_json::from_str(&escaped).unwrap(),
    ));
    for (field, json, v) in bodies {
        mac.refused(&json, "holds_secret", 2);
        let out = mac.send_bytes(&json, &["--json"]);
        let failure: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(failure["errors"][0]["detail_text"], field, "{failure:#}");
        let mut said = out.stdout;
        // The same in binary.
        let binary = binary_verdict(&v);
        let out = mac.send_bytes(&binary, &["--proto"]);
        assert_eq!(out.status.code(), Some(2));
        let failure = v1::Failure::decode(out.stdout.as_slice()).unwrap();
        assert_eq!(failure.errors[0].code, "holds_secret");
        assert_eq!(
            failure.errors[0].detail_text.as_deref(),
            Some(field.as_str())
        );
        said.extend(out.stdout);
        for secret in [&token, &password] {
            assert!(!holds(&said, secret), "{field}");
        }
    }
    assert_eq!(mac.recorded(), (0, 0));
    assert_eq!(mac.finding(&id)["finding"], before);
    // The same verdict without the secret is taken.
    mac.send(&good);
}

/// A verdict given in JSON, as the binary message the core reads with `--proto`.
fn binary_verdict(v: &Value) -> Vec<u8> {
    let m: v1::Verdict = serde_json::from_value(v.clone()).unwrap();
    m.encode_to_vec()
}

/// Whether `bytes` hold `secret` as it is.
fn holds(bytes: &[u8], secret: &str) -> bool {
    bytes.windows(secret.len()).any(|w| w == secret.as_bytes())
}

#[test]
fn a_verdict_that_cannot_be_read_prints_no_secret_it_was_sent_written_plain_or_escaped() {
    // A refusal names what it could not read, a key or a value, and that may be a secret,
    // written plain or behind a JSON escape. What it repeats is cut where it is printed, so the
    // refusal says what it could not read and prints none of the secret.
    let mac = Mac::new("echo");
    mac.package(true);
    mac.run();
    let store = mac.store_id();
    let id = mac.latest(MALICIOUS).unwrap();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(10, 36));
    let good = about_finding(&store, &id, "harmless", "case-1");
    for written in [token.clone(), format!("\\u0067{}", &token[1..])] {
        let base = good.to_string();
        let mut cases = vec![
            // A key it does not know, at the top and inside what the verdict names.
            base.replacen('{', &format!("{{\"{written}\":1,"), 1),
            base.replacen(
                "\"finding\":{",
                &format!("\"finding\":{{\"{written}\":1,"),
                1,
            ),
            // A key given twice.
            base.replacen('{', &format!("{{\"{written}\":1,\"{written}\":2,"), 1),
        ];
        // A value of the wrong kind.
        for field in ["kind", "format", "severity"] {
            let mut v = good.clone();
            v[field] = json!("PLACEHOLDER");
            cases.push(v.to_string().replacen("PLACEHOLDER", &written, 1));
        }
        // A reason too long to take, holding it.
        let mut v = good.clone();
        v["reason_text"] = json!(format!("PLACEHOLDER {}", "x".repeat(1100)));
        cases.push(v.to_string().replacen("PLACEHOLDER", &written, 1));
        for body in cases {
            let out = mac.send_bytes(body.as_bytes(), &["--json"]);
            assert_eq!(out.status.code(), Some(2), "{body}");
            let failure: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_ne!(failure["errors"][0]["code"], "holds_secret", "{failure:#}");
            assert!(!holds(&out.stdout, &token), "{failure:#}");
            assert!(!holds(&out.stderr, &token));
        }
    }
    // A key it does not know that glues a token to a mark it quotes.
    let aws = ["AK", "IA", "QZ7WK4RM2TX3PD5N"].concat();
    let glued = format!("\\\\cut{{gitleaks:github-pat 40}}{aws}");
    let body = good
        .to_string()
        .replacen('{', &format!("{{\"{glued}\":1,"), 1);
    let out = mac.send_bytes(body.as_bytes(), &["--json"]);
    assert_eq!(out.status.code(), Some(2), "{body}");
    assert!(!holds(&out.stdout, &aws) && !holds(&out.stderr, &aws));
    assert_eq!(mac.recorded().0, 0);
}

#[test]
fn a_failure_of_any_command_prints_no_secret_it_was_given_in_any_form() {
    // A failure that repeats what it was given (an argument, a path) cuts it where it is
    // printed: for the contract's commands in binary, JSON and text, and for a report's.
    let mac = Mac::new("failures");
    mac.run();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(12, 36));
    let password = format!("Fk{}", invented(13, 14));
    let flag = format!("--password={password}");
    for command in ["findings", "matches", "status", "rules"] {
        let contract = ["findings", "matches"].contains(&command);
        for form in [&["--json"][..], &["--proto"][..], &[][..]] {
            if form == ["--proto"] && !contract {
                continue;
            }
            for given in [&token, &flag] {
                let mut run = mac.command(&[command]);
                // A command that reads the collector's log reads the invented one.
                if ["matches", "rules"].contains(&command) {
                    run.arg("--system-root").arg(mac.root());
                }
                let out = run.arg(given).args(form).output().unwrap();
                assert_eq!(out.status.code(), Some(2), "{command} {form:?}");
                let printed = [out.stdout.as_slice(), out.stderr.as_slice()].concat();
                for secret in [&token, &password] {
                    assert!(!holds(&printed, secret), "{command} {form:?}");
                }
                // It was repeated, and cut.
                let said = String::from_utf8_lossy(&printed).to_string();
                if form != ["--proto"] {
                    assert!(said.contains("cut{"), "{command} {form:?}: {said}");
                }
            }
        }
    }
}

#[test]
fn a_refusal_or_an_answer_about_what_was_asked_prints_no_secret_it_was_asked_in_any_form() {
    // A refusal's message is the core's own words; what was asked goes into a field of its
    // own, cut, and an answer that repeats the question cuts it too.
    let mac = Mac::new("asked");
    mac.run();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(14, 36));
    let password = format!("Fk{}", invented(15, 14));
    let root = mac.root();
    let root = root.to_str().unwrap();
    let mut asked: Vec<Vec<String>> = Vec::new();
    for form in [&["--json"][..], &[][..]] {
        for args in [
            vec!["owner", &token, "retired", "--reason", "x"],
            vec!["owner", &token, "withdraw"],
            vec!["vulnerability", &token],
            vec!["program", &token],
            vec!["project", &token],
            vec!["machine", &token],
            vec!["finding", &token],
            vec!["finding", &token, "expected", "--reason", "x"],
            vec!["findings", "--state", &token],
            vec!["matches", "--after", &token, "--system-root", root],
            vec!["rules", &token, "--system-root", root],
        ] {
            let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            a.extend(form.iter().map(|s| s.to_string()));
            asked.push(a);
        }
    }
    for args in [
        vec!["program", &token, "--proto"],
        vec!["finding", &token, "--proto"],
        vec!["status", &format!("--password={password}"), "--json"],
        vec!["view", &format!("--x={token}")],
    ] {
        asked.push(args.iter().map(|s| s.to_string()).collect());
    }
    for args in &asked {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = mac.command(&a).output().unwrap();
        for secret in [&token, &password] {
            assert!(!holds(&out.stdout, secret), "{}", args[0]);
            assert!(!holds(&out.stderr, secret), "{}", args[0]);
        }
    }
    // A store asked for at a path that holds a secret, and is not there.
    let missing = mac.0.join(&token);
    for form in [&["--json"][..], &[][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_immune"))
            .env("HOME", mac.home())
            .args(["owner", "a", "retired", "--reason", "x", "--store"])
            .arg(&missing)
            .arg("--tailscale")
            .arg(mac.0.join("no-tailscale"))
            .args(form)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{form:?}");
        let printed = [out.stdout.as_slice(), out.stderr.as_slice()].concat();
        assert!(!holds(&printed, &token), "{form:?}");
        assert!(holds(&printed, "cut{gitleaks:github-pat 40}"), "{form:?}");
    }
    // The refusal says what it is in its own words, and repeats what was asked cut.
    let out = mac
        .command(&["owner", &token, "retired", "--reason", "x", "--json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "unknown_machine");
    assert_eq!(
        v["errors"][0]["message"],
        "the store knows no machine by the name asked; nothing was said"
    );
    assert_eq!(
        v["errors"][0]["detail_text"],
        "\\cut{gitleaks:github-pat 40}"
    );
}

// The shapes in which the response layer may quote the core's cut output.
const JOINED: &str = "the arguments joined by spaces";
const ARRAY: &str = "the arguments as a compact JSON array";
const VALUE: &str = "args_text as the JSON value";
const BARE: &str = "one argument bare";
const DOUBLE: &str = "one argument in double quotes";
const SINGLE: &str = "one argument in single quotes";
const EVENT: &str = "the whole event as compact JSON";
const LINE: &str = "a line of the text a command prints";
const FINDING: &str = "a finding as compact JSON";

/// Whether a quote of this shape may lose words: the whole event as compact JSON, where a cut
/// value after a space, as in `--token <value>` or `Authorization: Bearer <value>`, ends its
/// argument, so its mark is glued to `"],"cuts":…` in one word, and the rest of that word is cut
/// as it would be after a real value. Every other shape keeps its words.
fn loses(shape: &str) -> bool {
    shape == EVENT
}

/// The marks Immune made in a text as the contract shows it, where a source's backslash is
/// `\u{5c}`: each kind and length, in order.
fn made(kept: &str) -> Vec<(String, u64)> {
    kept.split("\\cut{")
        .skip(1)
        .map(|rest| {
            let (inside, _) = rest.split_once('}').unwrap();
            let (kind, length) = inside.rsplit_once(' ').unwrap();
            (kind.to_string(), length.parse().unwrap())
        })
        .collect()
}

/// The marks a text quotes, each written out.
fn quoted_marks(q: &str) -> Vec<String> {
    q.match_indices("\\cut{")
        .map(|(at, _)| {
            let end = at + q[at..].find('}').unwrap() + 1;
            q[at..end].to_string()
        })
        .collect()
}

/// A Mac whose log holds command lines with a secret in each form the core cuts, run, with a
/// finding of the response layer's own; and everything the response layer could honestly
/// quote of the core's cut output about them: each match's arguments joined, as a JSON array
/// and as the JSON value, each argument bare and in either quotes, the whole event, the same
/// from the binary answer, the lines of `immune matches`, of a finding and of the findings for
/// a person that hold a mark, and the finding as JSON. A quote longer than a reason may be is
/// taken in pieces, each ending at a comma. Also the store's id and the first match's position.
fn quoting(name: &str) -> (Mac, String, String, Vec<(&'static str, String)>) {
    let mac = Mac::new(name);
    let pw = ["Pq8", "Zr5", "Lm3", "Xv"].concat();
    let pw2 = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(31, 36));
    let sets: Vec<Vec<String>> = vec![
        vec!["--password".into(), pw.clone()],
        vec![format!("--password={pw}")],
        vec!["-H".into(), format!("Authorization: Bearer {pw}.tok")],
        vec![format!("tool --password '{pw} {pw2}' next")],
        vec![format!("mysql -u root -p{pw} db")],
        vec![format!("https://u:{pw}@h.invalid/r")],
        vec![token.clone()],
        vec![format!("C:\\dir --token {pw} x")],
        vec![format!("--token {pw}\nnext")],
        vec!["--api-key".into(), pw.clone(), format!("x=1&password={pw}")],
        vec![format!("tool --password $(cat f) {pw} y")],
        vec![format!("\"--password\" {pw} z")],
        vec![format!(
            "tool --password=\"{pw} x\" && echo `id` --token {pw2}"
        )],
        vec![format!("DB_PASSWORD={pw} run; X-Api-Key: {pw2}")],
    ];
    let mut at = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        let mut args: Vec<&str> = vec!["sw_vers", "-productVersion"];
        args.extend(set.iter().map(String::as_str));
        at.push(mac.append(&start(i as u64 + 1, "/usr/bin/sw_vers", &args)));
    }
    mac.run();
    let store = mac.store_id();
    let mut quotes: Vec<(&'static str, String)> = Vec::new();
    for x in mac.matches()["matches"].as_array().unwrap() {
        if x["rule"]["name"] != SW_VERS {
            continue;
        }
        let value = &x["event"]["program_start"]["args_text"];
        let args: Vec<String> = serde_json::from_value(value.clone()).unwrap();
        quotes.push((JOINED, format!("it ran {}", args.join(" "))));
        quotes.push((
            ARRAY,
            format!("args: {}", serde_json::to_string(&args).unwrap()),
        ));
        quotes.push((VALUE, format!("args_text: {value}")));
        for (i, a) in args.iter().enumerate().skip(2) {
            quotes.push((BARE, format!("argument {i} was {a}")));
            quotes.push((DOUBLE, format!("argument {i} was \"{a}\"")));
            quotes.push((SINGLE, format!("argument {i} was '{a}'")));
        }
        quotes.push((EVENT, format!("event: {}", x["event"])));
    }
    let proto = mac
        .command(&["matches", "--proto", "--system-root"])
        .arg(mac.root())
        .output()
        .unwrap();
    for x in v1::Matches::decode(proto.stdout.as_slice())
        .unwrap()
        .matches
    {
        if let Some(v1::event::Body::ProgramStart(ps)) = x.event.and_then(|e| e.body) {
            quotes.push((JOINED, format!("it ran {}", ps.args_text.join(" "))));
        }
    }
    mac.send(&about_match(
        &store,
        &mac.position(at[3]),
        SW_VERS,
        "suspicious",
    ));
    let own = mac.verdict_findings().pop().unwrap();
    let text = |args: &[&str]| {
        let out = mac.command(args).output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let root = mac.root();
    for printed in [
        text(&["matches", "--system-root", root.to_str().unwrap()]),
        text(&["finding", &own]),
        text(&["findings"]),
    ] {
        quotes.extend(
            printed
                .lines()
                .filter(|l| l.contains("cut{"))
                .map(|l| (LINE, l.trim().to_string())),
        );
    }
    quotes.push((
        FINDING,
        format!("finding: {}", text(&["finding", &own, "--json"])),
    ));
    let mut pieces = Vec::new();
    for (shape, q) in quotes {
        let mut rest: Vec<char> = q.trim().chars().collect();
        while rest.len() > 1000 {
            let cut = rest[..1000]
                .iter()
                .rposition(|c| *c == ',')
                .map_or(1000, |p| p + 1);
            pieces.push((shape, rest.drain(..cut).collect::<String>()));
        }
        pieces.push((shape, rest.into_iter().collect()));
    }
    let first = mac.position(at[0]);
    (mac, store, first, pieces)
}

/// Text from a source as the contract shows it: the backslash and control characters escaped.
fn escaped(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\\' || c.is_control() {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Sends a verdict about the match at `position` with this reason and case, in JSON or in
/// binary: what was recorded, or the failure.
fn send_reason(
    mac: &Mac,
    (store, position): (&str, &str),
    kind: &str,
    reason: &str,
    proto: bool,
) -> Result<v1::RecordedVerdict, v1::Failure> {
    let mut v = about_match(store, position, SW_VERS, kind);
    v["reason_text"] = json!(reason);
    let out = if proto {
        mac.send_bytes(&binary_verdict(&v), &["--proto"])
    } else {
        mac.send_output(&v)
    };
    match (out.status.success(), proto) {
        (true, true) => Ok(v1::VerdictRecorded::decode(out.stdout.as_slice())
            .unwrap()
            .recorded
            .unwrap()),
        (true, false) => Ok(serde_json::from_slice::<v1::VerdictRecorded>(&out.stdout)
            .unwrap()
            .recorded
            .unwrap()),
        (false, true) => Err(v1::Failure::decode(out.stdout.as_slice()).unwrap()),
        (false, false) => Err(serde_json::from_slice(&out.stdout).unwrap()),
    }
}

#[test]
fn every_quote_of_the_core_s_cut_output_in_a_verdict_s_reason_lands_and_keeps_the_marks_it_quotes()
{
    // A reason is prose: it is cut where it is kept and never refused. A mark it quotes from
    // the core's output is a value already cut, kept as text. Quoted as a person reads the core's
    // output, a word apart, the quote keeps all its words. Quoted as compact JSON, a mark is glued
    // to what follows it in its word, and that is cut as it would be after a real value; the
    // marks it quoted stay as they were, and `reason_cuts` says what was cut.
    let (mac, store, first, quotes) = quoting("quotes");
    assert!(quotes.len() >= 140, "{}", quotes.len());
    let mut tally: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for (shape, q) in &quotes {
        let mut lost = false;
        for proto in [false, true] {
            let recorded = send_reason(&mac, (&store, &first), "harmless", q, proto)
                .unwrap_or_else(|f| panic!("{q}: {f:?}"));
            let kept = recorded.verdict.unwrap().reason_text;
            let cuts: Vec<(String, u64)> = recorded
                .reason_cuts
                .iter()
                .map(|c| (c.kind.clone(), c.length))
                .collect();
            assert_eq!(cuts, made(&kept), "{q}");
            for m in quoted_marks(q) {
                assert!(kept.contains(&escaped(&m)), "{m} in {q}: {kept}");
            }
            if kept != escaped(q) {
                assert!(!cuts.is_empty(), "{q}");
                assert!(loses(shape), "{shape}: {q}: {kept}");
                lost = true;
            }
        }
        if lost {
            println!("loses words: {}", q.split("],\"cuts\"").next().unwrap());
        }
        let t = tally.entry(shape).or_default();
        t.0 += usize::from(lost);
        t.1 += 1;
    }
    println!("quotes that lose words, by shape: {tally:?}");
    // Three do: an Authorization header, `x=1&password=` and `--token` after a backtick,
    // each a cut value that ends the last argument.
    assert_eq!(tally[EVENT].0, 3);
}

#[test]
fn a_secret_in_a_reason_alone_or_beside_a_mark_is_cut_where_kept_and_wherever_printed() {
    // A secret the response layer quotes, alone or before, after or glued to a mark it quotes,
    // is cut in the store and everywhere the reason is printed, the verdict lands, and the
    // answer names each cut. A mark hides nothing beside it in its word.
    let mac = Mac::new("beside");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    let first = mac.position(at);
    let pw = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(32, 36));
    let aws = ["AK", "IA", "QZ7WK4RM2TX3PD5N"].concat();
    let gcp = ["AI", "za", "SyQz7Wk4Rm2Tx9Pd3Vn6Bc1Hd5Js0Ga7KLm"].concat();
    let m = "\\cut{immune:flag-value 11}";
    let cut = |kind: &str, length: u64| v1::Cut {
        argument: 0,
        kind: kind.to_string(),
        length,
    };
    let (fv, pat) = ("immune:flag-value", "gitleaks:github-pat");
    let named: Vec<(String, Vec<v1::Cut>)> = vec![
        (format!("ran tool --password {pw} next"), vec![cut(fv, 11)]),
        (format!("{token}{m} was printed"), vec![cut(pat, 40)]),
        (
            format!("ran tool --password {m}{pw} next"),
            vec![cut(fv, 11)],
        ),
        (
            format!("\\cut{{gitleaks:github-pat 40}} {token}"),
            vec![cut(pat, 40)],
        ),
        // With the backslash doubled, as JSON writes it.
        (format!("ran tool --password=\\{m}{pw}"), vec![cut(fv, 11)]),
        // In the same quotes as the mark: the word is the value, cut where it is not the mark.
        (
            format!("ran tool --password \"{m} {pw}\" next"),
            vec![cut(fv, 1), cut(fv, 13)],
        ),
    ];
    for (reason, cuts) in &named {
        for proto in [false, true] {
            let r = send_reason(&mac, (&store, &first), "suspicious", reason, proto)
                .unwrap_or_else(|f| panic!("{reason}: {f:?}"));
            assert_eq!(&r.reason_cuts, cuts, "{reason}");
        }
    }
    // The reviewer's forms of a secret beside a mark: each is cut, whatever else is.
    let beside = [
        format!("ran tool --password={m}{pw}"),
        format!("ran tool --password=\\cut{{gitleaks:github-pat 3}}{pw}"),
        format!("ran tool --password=\\cut{{a 99999999999999999999}}{pw}"),
        format!("ran tool --pass{m}word={pw}"),
        format!("ran tool {m}--password={pw}"),
        format!("ran tool {m}password={pw}"),
        format!("ran tool --password '{m}'{pw}"),
        format!("ran tool --password \\{m}{m}{pw}"),
        format!("ran tool --password \\\\{m}{pw}"),
        format!("sent Authorization: Bearer \\cut{{immune:authorization 12}}{pw}"),
        format!("ran mysql -p\\cut{{immune:mysql-password 8}}{pw} db"),
        format!("ran {m}{token}"),
        format!("ran https://u:{m}{pw}@h.invalid/r"),
        format!("ran {m}\n--password {pw}"),
        format!("ran \\cut{{a 1 --password {pw}"),
        format!("ran --password=\\cut{{A 1}}{pw}"),
        // A token glued to a mark is found as beside a boundary, and a value that begins with
        // a mark ends where a real one would.
        format!("it ran \\cut{{gitleaks:github-pat 40}}{aws} then"),
        format!("it ran {aws}\\cut{{gitleaks:github-pat 40}} then"),
        format!("it ran {m}{gcp} then"),
        format!("it ran --password={m},{pw} then"),
        format!("it ran --password={m}]{pw} then"),
        format!("Authorization: Bearer {m} {pw}"),
        format!("ran immune:mysql-password={pw}"),
    ];
    for reason in &beside {
        for proto in [false, true] {
            let r = send_reason(&mac, (&store, &first), "suspicious", reason, proto)
                .unwrap_or_else(|f| panic!("{reason}: {f:?}"));
            assert!(!r.reason_cuts.is_empty(), "{reason}");
            let shown = r.verdict.unwrap().reason_text;
            for secret in [&pw, &token, &aws, &gcp] {
                assert!(!shown.contains(secret.as_str()), "{shown}");
            }
        }
    }
    // Behind a JSON escape.
    let mut v = about_match(&store, &first, SW_VERS, "suspicious");
    v["reason_text"] = json!(format!("the token {token} was used"));
    let body = v
        .to_string()
        .replacen(&token, &format!("\\u0067{}", &token[1..]), 1);
    let out = mac.send_bytes(body.as_bytes(), &["--json"]);
    let answer: v1::VerdictRecorded = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(answer.recorded.unwrap().reason_cuts, vec![cut(pat, 40)]);
    let own = mac.verdict_findings().pop().unwrap();
    let mut printed = Vec::new();
    let root = mac.root();
    for args in [
        vec!["status", "--json"],
        vec!["status"],
        vec!["findings", "--all", "--json"],
        vec!["findings", "--all", "--proto"],
        vec!["findings", "--all"],
        vec!["finding", own.as_str(), "--json"],
        vec!["finding", own.as_str(), "--proto"],
        vec!["finding", own.as_str()],
        vec!["matches", "--json", "--system-root", root.to_str().unwrap()],
        vec!["view", "--no-open"],
    ] {
        let out = mac.command(&args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        printed.push((format!("{args:?}"), out.stdout));
    }
    files_under(&mac.0.join("store"), &mut printed);
    for (what, bytes) in printed {
        for secret in [&token, &pw, &aws, &gcp] {
            assert!(!holds(&bytes, secret), "{what}");
        }
    }
}

#[test]
fn the_core_s_cut_output_quoted_as_a_person_s_reason_or_by_the_collector_keeps_its_words() {
    // One reading of a mark for every kind of kept text: the same quotes, given as the reason
    // of a person's statement or printed by the collector, are taken; those a word apart from
    // the marks they quote keep their words and cut nothing.
    let (mac, _, _, quotes) = quoting("general");
    for (shape, q) in &quotes {
        let out = mac
            .command(&["owner", "mac", "retired", "--reason", q, "--json"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{q}");
        let said: Value = serde_json::from_slice(&out.stdout).unwrap();
        if !loses(shape) {
            assert_eq!(said["said"]["reason_text"], escaped(q), "{q}");
            assert_eq!(said["said"]["reason_cuts"], json!([]), "{q}");
        } else if said["said"]["reason_text"] != escaped(q) {
            assert_ne!(said["said"]["reason_cuts"], json!([]), "{q}");
        }
    }
    // What the collector printed is read on a run, one line at a time.
    for (_, q) in quotes
        .iter()
        .filter(|(shape, q)| !loses(shape) && !q.contains('\n'))
        .step_by(20)
    {
        std::fs::write(mac.log().join("scripts.err"), format!("{q}\n")).unwrap();
        mac.run();
        let level = &mac.status()["event_level"];
        assert_eq!(level["said_text"], escaped(q), "{q}");
    }
}

#[test]
fn a_verdict_s_text_that_spells_a_mark_out_is_kept_and_shown_as_text() {
    // Only the core makes a mark. A reason or a case that spells one out, or a backslash, is
    // the response layer's text, and stays that wherever it is shown.
    let mac = Mac::new("spelled");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    let mut v = about_match(&store, &mac.position(at), SW_VERS, "suspicious");
    v["reason_text"] = json!("invented: \\cut{forged 3}");
    v["case_text"] = json!("case \\cut{forged 4}");
    mac.send(&v);
    let own = mac.verdict_findings().pop().unwrap();
    let whole = mac.finding(&own).to_string();
    for shown in [
        "\"reason_text\":\"invented: \\\\u{5c}cut{forged 3}\"",
        "\"case_text\":\"case \\\\u{5c}cut{forged 4}\"",
    ] {
        assert!(whole.contains(shown), "{whole}");
    }
    // The same message again is the same verdict.
    mac.send(&v);
    assert_eq!(mac.recorded().0, 1);
}

#[test]
fn a_store_not_yet_cleaned_prints_no_secret_from_any_kind_of_kept_text() {
    // A store an earlier build kept holds text as it was read. Until a run cleans it, every
    // command that only reads it cuts each kind of kept text as it reads it: the arguments of
    // evidence, what the collector printed, a verdict's reason and case, and the reasons of an
    // answer and of a statement about a machine.
    let mac = Mac::new("uncleaned");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    mac.send(&about_match(
        &store,
        &mac.position(at),
        SW_VERS,
        "suspicious",
    ));
    let own = mac.verdict_findings().pop().unwrap();
    let placeholder = ["--reason", "invented: placeholder", "--via", "agent"];
    let out = mac.answer(&own, &[&["seen"][..], &placeholder].concat());
    assert_eq!(out.status.code(), Some(0));
    let out = mac
        .command(&[&["owner", "mac", "retired"][..], &placeholder].concat())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(9, 36));
    {
        let db = rusqlite::Connection::open(mac.store()).unwrap();
        // As an earlier build kept it: what the store's form would write `\u{5c}` is a source's
        // own text here, never an escape.
        let said = format!("invented: the token {token} was used \\u{{5c}}");
        db.execute(
            "UPDATE verdict SET reason = ?1, case_ref = ?1",
            [said.as_str()],
        )
        .unwrap();
        db.execute(
            "UPDATE rule_evidence SET args = ?1",
            [json!(["sw_vers", "-productVersion", token]).to_string()],
        )
        .unwrap();
        db.execute(
            "UPDATE event_level SET state = 'refused', said_by = 'eslogger', said = ?1",
            [said.as_str()],
        )
        .unwrap();
        db.execute(
            "UPDATE finding SET reason = ?1 WHERE reason IS NOT NULL",
            [said.as_str()],
        )
        .unwrap();
        db.execute("UPDATE owner_statement SET reason = ?1", [said.as_str()])
            .unwrap();
        db.execute(
            "UPDATE meta SET value = '4' WHERE key = 'format_version'",
            [],
        )
        .unwrap();
    }
    let root = mac.root();
    let root = root.to_str().unwrap();
    let mut printed = Vec::new();
    for args in [
        vec!["status", "--json"],
        vec!["status"],
        vec!["findings", "--all", "--json"],
        vec!["findings", "--all", "--proto"],
        vec!["findings", "--all"],
        vec!["owner", "--json"],
        vec!["owner"],
        vec!["finding", own.as_str(), "--json"],
        vec!["finding", own.as_str(), "--proto"],
        vec!["finding", own.as_str()],
        vec!["matches", "--json", "--system-root", root],
        vec!["view", "--no-open"],
    ] {
        let out = mac.command(&args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        printed.push((format!("{args:?}"), out.stdout));
    }
    let db = rusqlite::Connection::open(mac.store()).unwrap();
    let kept: String = db
        .query_row("SELECT reason FROM verdict", [], |r| r.get(0))
        .unwrap();
    assert!(kept.contains(&token), "only a run cleans the store");
    let whole = mac.finding(&own).to_string();
    for field in ["reason_text", "case_text"] {
        let shown = format!(
            "\"{field}\":\"invented: the token \\\\cut{{gitleaks:github-pat 40}} was used \\\\u{{5c}}u{{5c}}\""
        );
        assert!(whole.contains(&shown), "{whole}");
    }
    let status = String::from_utf8_lossy(&printed[0].1).to_string();
    assert!(
        status.contains(
            "\"said_text\":\"invented: the token \\\\cut{gitleaks:github-pat 40} was used \\\\u{5c}u{5c}\""
        ),
        "{status}"
    );
    assert_eq!(
        mac.finding(&own)["answer"]["reason_text"],
        "invented: the token \\cut{gitleaks:github-pat 40} was used \\u{5c}u{5c}"
    );
    let owner = mac.command(&["owner", "--json"]).output().unwrap().stdout;
    let owner = String::from_utf8_lossy(&owner);
    assert!(
        owner.contains(
            "\"reason_text\":\"invented: the token \\\\cut{gitleaks:github-pat 40} was used \\\\u{5c}u{5c}\""
        ),
        "{owner}"
    );
    files_under(&mac.0.join("store"), &mut printed);
    for (what, bytes) in printed {
        // The store itself still holds the text until a run cleans it.
        if what.contains("store.db") {
            continue;
        }
        assert!(
            !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
            "{what}"
        );
    }
}

#[test]
fn an_answer_or_a_statement_whose_reason_holds_a_secret_is_taken_with_its_reason_cut() {
    // A reason is the person's decision, given by them or by their agent: it is taken whatever
    // it holds, never refused, and kept and shown with its secrets cut. The command's answer
    // lists what was cut by kind, so the agent knows what was kept.
    let mac = Mac::new("answer-reason");
    mac.package(true);
    mac.run();
    let id = mac.latest(MALICIOUS).unwrap();
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(21, 36));
    let pw = ["Hunter", "2xQ9z"].concat();
    let out = mac.answer(
        &id,
        &[
            "expected",
            "--reason",
            &format!("invented: the run used {token} and --password {pw}"),
            "--via",
            "agent",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let answered: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        answered["answer"]["reason_cuts"],
        json!([
            { "argument": 0, "kind": "gitleaks:github-pat", "length": 40 },
            { "argument": 0, "kind": "immune:flag-value", "length": 11 }
        ]),
        "{answered:#}"
    );
    let out = mac
        .command(&[
            "owner",
            "mac",
            "retired",
            "--reason",
            &format!("invented: {token}"),
            "--via",
            "agent",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let said: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        said["said"]["reason_cuts"],
        json!([{ "argument": 0, "kind": "gitleaks:github-pat", "length": 40 }]),
        "{said:#}"
    );
    // For a person, the same in words.
    let again = mac
        .command(&[
            "owner",
            "mac",
            "retired",
            "--reason",
            &format!("invented: again {token}"),
        ])
        .output()
        .unwrap();
    let words = String::from_utf8_lossy(&again.stdout);
    assert!(
        words.contains(
            "Its reason held what Immune recognises as a secret, and is kept with it cut."
        ),
        "{words}"
    );
    let mut printed = vec![
        ("answer".to_string(), out.stdout),
        ("again".to_string(), again.stdout),
    ];
    for args in [
        vec!["status", "--json"],
        vec!["status"],
        vec!["findings", "--all", "--json"],
        vec!["findings", "--all", "--proto"],
        vec!["findings", "--all"],
        vec!["finding", id.as_str(), "--json"],
        vec!["finding", id.as_str(), "--proto"],
        vec!["finding", id.as_str()],
        vec!["owner", "--json"],
        vec!["owner"],
        vec!["view", "--no-open"],
    ] {
        let out = mac.command(&args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        printed.push((format!("{args:?}"), out.stdout));
    }
    files_under(&mac.0.join("store"), &mut printed);
    for (what, bytes) in printed {
        for secret in [&token, &pw] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{what}"
            );
        }
    }
}

#[test]
fn a_store_of_format_4_is_cleaned_into_format_5_which_a_build_of_4_refuses_as_newer() {
    // The cleaned state is the store's format, so a build from before cutting, which knows
    // format 4, refuses a cleaned store as newer and never writes raw text into it. This build
    // takes format 4 only to clean it, and refuses anything else it does not know.
    let mac = Mac::new("format");
    let at = mac.append(&sw_vers(1));
    mac.run();
    let store = mac.store_id();
    mac.send(&about_match(
        &store,
        &mac.position(at),
        SW_VERS,
        "suspicious",
    ));
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(41, 36));
    let format = || -> String {
        rusqlite::Connection::open(mac.store())
            .unwrap()
            .query_row(
                "SELECT value FROM meta WHERE key = 'format_version'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(format(), "5");
    {
        let db = rusqlite::Connection::open(mac.store()).unwrap();
        db.execute(
            "UPDATE verdict SET reason = ?1",
            [format!("invented: {token}")],
        )
        .unwrap();
        db.execute(
            "UPDATE meta SET value = '4' WHERE key = 'format_version'",
            [],
        )
        .unwrap();
    }
    mac.run();
    assert_eq!(format(), "5");
    let file = std::fs::read(mac.store()).unwrap();
    assert!(!file.windows(token.len()).any(|w| w == token.as_bytes()));
    for (version, said) in [("6", "newer format"), ("3", "older format")] {
        rusqlite::Connection::open(mac.store())
            .unwrap()
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'format_version'",
                [version],
            )
            .unwrap();
        let out = mac.command(&["status", "--json"]).output().unwrap();
        assert_ne!(out.status.code(), Some(0), "{version}");
        let all = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(all.contains(said), "{version}: {all}");
    }
}

/// Every file under `folder` and what it holds, each named.
fn files_under(folder: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push((path.display().to_string(), std::fs::read(&path).unwrap()));
        }
    }
}

#[test]
fn a_verdict_about_a_match_keeps_the_event_it_read_again_cut() {
    // A verdict about a match reads the line again from the log and keeps its event with the
    // finding it raises: that copy is cut as the core's own reading's is.
    let mac = Mac::new("secret-event");
    let token = format!("{}{}", ["gh", "p_"].concat(), invented(6, 36));
    let at = mac.append(&start(
        1,
        "/usr/bin/sw_vers",
        &["sw_vers", "-productVersion", &token],
    ));
    mac.run();
    let store = mac.store_id();
    let answer = mac.send(&about_match(
        &store,
        &mac.position(at),
        SW_VERS,
        "suspicious",
    ));
    let own = answer["recorded"]["finding"]["id"].as_str().unwrap();
    let whole = mac.finding(own);
    let event = &whole["evidence"]["verdict_given"]["events"][0]["program_start"];
    assert_eq!(
        event["cuts"],
        json!([{ "argument": 2, "kind": "gitleaks:github-pat", "length": 40 }])
    );
    assert_eq!(event["args_text"][2], "\\cut{gitleaks:github-pat 40}");
    let db = std::fs::read(mac.store()).unwrap();
    assert!(!db.windows(token.len()).any(|w| w == token.as_bytes()));
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
    // The backslash is written as the contract writes it, so the quote after it stays escaped.
    assert!(
        line.contains(r#"Its reason: "ok\u{5c}\". The person marked"#),
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
        mac2.shown(&own2).unwrap()["verdicts"]["listed"][0]["verdict"]["reason_text"],
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

/// What `needs_a_look` lists, each `LookFinding` read as one object: the finding's reference,
/// the finding as listed and its words side by side, so a test names a field once.
fn looks(status: &serde_json::Value) -> serde_json::Value {
    let items = status["needs_a_look"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    items
        .iter()
        .map(|look| {
            let mut flat = serde_json::Map::new();
            for part in [&look["finding"]["finding"], &look["finding"], look] {
                for (k, v) in part.as_object().into_iter().flatten() {
                    if k != "finding" {
                        flat.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            serde_json::Value::Object(flat)
        })
        .collect()
}
