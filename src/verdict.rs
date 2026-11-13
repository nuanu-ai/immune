//! `immune verdict`: the response layer's verdict about a rule match or a finding, read as the
//! contract's `Verdict` message on standard input, recorded, and answered with `VerdictRecorded`
//! (`contract/immune/v1/verdict.proto`).
//!
//! A verdict never writes into a finding the core raised. A `suspicious` verdict is an event of
//! one rule of Immune's own, `verdict.suspicious` (`RULE`), and goes through the path every rule
//! that finds an event goes through (`findings::occur`, `events::keep`), with no case of its own:
//! its finding is about the rule the verdict names and the thing that rule's findings are about
//! on this Mac, so its rule as the store keeps it is `verdict.suspicious:<that rule>` (`PREFIX`).
//! Its levels are the highest its verdicts gave (`attach`). A `harmless` verdict is a record and
//! nothing else.
//!
//! What is shown beside a finding is read when asked, by what the verdicts are about: counted in
//! SQL, and listed at most the first and the latest `LISTED`.
//!
//! A match is named by the position `immune matches` printed and its rule's name. The core reads
//! the one line at that position from the collector's log again and evaluates it at the one place
//! an event is evaluated (`events::at_line`), so a verdict is about what the core matched.
//!
//! Text from the response layer is data: it read files an attacker may have written. Its reason
//! and its case are kept as sent and shown only in `_text` fields, escaped as all such text is,
//! and after the core's own words, never inside them.

use crate::contract::{v1, value_of};
use crate::events::{self, AtLine, LineAt};
use crate::findings::{self, CONFIDENCES, Found, SEVERITIES, Words};
use crate::known::{self, whole};
use crate::sigma::Rules;
use crate::{Stop, answer, store, view};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

/// The version of the contract this build reads and prints.
const FORMAT: u32 = 1;
/// The most bytes a verdict may be. More is refused, never cut.
pub const CAP: usize = 64 << 10;
/// The most Unicode scalar values `reason_text` and `case_text` may hold. Longer is refused,
/// never cut: a reason cut short can say the opposite.
pub const REASON_CHARS: usize = 1000;
pub const CASE_CHARS: usize = 200;
/// The most verdicts an answer lists after the first: the latest ones.
pub const LISTED: i64 = 20;
/// How the run id of a verdict begins, in the journal.
const RUN_PREFIX: &str = "verdict-";
const EXAMPLE: &str = "immune verdict --json < verdict.json";

/// The rule of Immune's own that a `suspicious` verdict is an event of, and how its findings'
/// rule begins in the store: `verdict.suspicious:<the rule the verdict is about>`.
pub const RULE: &str = "verdict.suspicious";
pub const PREFIX: &str = "verdict.suspicious:";
pub const KIND: &str = "verdict of the response layer";
/// The core's words for a finding of `RULE`. What it is about is beside them: the rule's title
/// and the thing.
pub const WORDS: Words = Words {
    title: "The response layer judged something on this Mac suspicious.",
    meaning: "Another program that runs Immune, the response layer, looked into what a rule found here and judged it suspicious. The rule and the thing are named with this finding; the reason is the response layer's own, quoted.",
    advice: "Read its reason and look at what it is about. Mark this finding seen once you have; Immune's own finding about the same thing, if there is one, is answered apart.",
};

/// Created on every open, so a store of the current format takes it without a rebuild.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS verdict (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    journal    INTEGER NOT NULL,  -- its entry in the journal, `verdict`
    kind       TEXT NOT NULL CHECK (kind IN ('suspicious', 'harmless')),
    named      TEXT,              -- the finding it named, as sent
    position   TEXT,              -- or the match it named: its position and its rule, as sent
    rule       TEXT,
    finding    TEXT REFERENCES finding (id),  -- the `verdict.suspicious` finding; NULL when harmless
    raised     INTEGER NOT NULL,  -- it raised that occurrence
    severity   TEXT,
    confidence TEXT,
    reason     TEXT NOT NULL,     -- text from the response layer
    case_ref   TEXT NOT NULL,     -- text from the response layer
    CHECK ((named IS NULL) = (position IS NOT NULL AND rule IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS verdict_named ON verdict (named);
CREATE INDEX IF NOT EXISTS verdict_finding ON verdict (finding);
CREATE INDEX IF NOT EXISTS verdict_match ON verdict (position, rule);
";

/// What the response layer concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Suspicious,
    Harmless,
}

impl Kind {
    /// The store's word, the contract's value without its prefix.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Suspicious => "suspicious",
            Kind::Harmless => "harmless",
        }
    }
}

/// A verdict as the store keeps it.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub at: i64,
    pub kind: Kind,
    /// The finding it named, as sent.
    pub named: Option<String>,
    /// Or the match it named: its position and its rule's name, as sent.
    pub position: Option<String>,
    pub rule: Option<String>,
    /// The `verdict.suspicious` finding it went to; `None` when harmless.
    pub finding: Option<String>,
    pub raised: bool,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub reason: String,
    pub case: String,
}

const COLUMNS: &str =
    "at, kind, named, position, rule, finding, raised, severity, confidence, reason, case_ref";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Recorded> {
    let kind: String = r.get(1)?;
    Ok(Recorded {
        at: r.get(0)?,
        kind: if kind == "suspicious" {
            Kind::Suspicious
        } else {
            Kind::Harmless
        },
        named: r.get(2)?,
        position: r.get(3)?,
        rule: r.get(4)?,
        finding: r.get(5)?,
        raised: r.get(6)?,
        severity: r.get(7)?,
        confidence: r.get(8)?,
        reason: r.get(9)?,
        case: r.get(10)?,
    })
}

fn has_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'verdict')",
        [],
        |r| r.get(0),
    )
}

/// The verdicts that meet `cond`, counted, and listed oldest first: the first and the latest
/// `LISTED`. A store without the table has none.
pub fn listed(
    conn: &Connection,
    cond: &str,
    args: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<(u32, u32, Vec<Recorded>)> {
    if !has_table(conn)? {
        return Ok((0, 0, Vec::new()));
    }
    let (total, suspicious): (u32, u32) = conn.query_row(
        &format!(
            "SELECT COUNT(*), COALESCE(SUM(kind = 'suspicious'), 0) FROM verdict WHERE {cond}"
        ),
        args,
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let list = conn
        .prepare(&format!(
            "SELECT {COLUMNS} FROM verdict WHERE {cond}
               AND (id = (SELECT MIN(id) FROM verdict WHERE {cond})
                    OR id IN (SELECT id FROM verdict WHERE {cond} ORDER BY id DESC LIMIT {LISTED}))
             ORDER BY id"
        ))?
        .query_map(args, row)?
        .collect::<rusqlite::Result<_>>()?;
    Ok((total, suspicious, list))
}

/// The verdicts a whole view of a finding lists: those of this occurrence for a
/// `verdict.suspicious` finding, those that name it for a finding of the core.
pub fn of_finding(
    conn: &Connection,
    id: &str,
    rule: &str,
) -> rusqlite::Result<(u32, u32, Vec<Recorded>)> {
    let cond = if rule.starts_with(PREFIX) {
        "finding = ?1"
    } else {
        "named = ?1"
    };
    listed(conn, cond, &[&id])
}

/// What a finding carries of the verdicts, read with the findings (`findings::all`), counted in
/// SQL: for a finding of the core, the verdicts that name it and its `verdict.suspicious`
/// finding that stands; for a `verdict.suspicious` finding, the verdicts of this occurrence,
/// their highest levels and the one that raised it.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub total: u32,
    pub suspicious: u32,
    /// The highest severity and confidence given, as places in `SEVERITIES` and `CONFIDENCES`.
    pub levels: Option<(usize, usize)>,
    pub opening: Option<Recorded>,
    pub standing: Option<String>,
}

/// Gives each finding what it carries of the verdicts (`Summary`).
pub fn attach(conn: &Connection, found: &mut [Found]) -> rusqlite::Result<()> {
    if !has_table(conn)? {
        return Ok(());
    }
    let rank = |column: &str, scale: &[&str]| {
        let whens: String = scale
            .iter()
            .enumerate()
            .map(|(i, s)| format!(" WHEN '{s}' THEN {i}"))
            .collect();
        format!("MAX(CASE {column}{whens} END)")
    };
    let mut named: BTreeMap<String, Summary> = BTreeMap::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT named, NULL, COUNT(*), SUM(kind = 'suspicious'), NULL, NULL
           FROM verdict WHERE named IS NOT NULL GROUP BY named
         UNION ALL
         SELECT NULL, finding, COUNT(*), COUNT(*), {}, {}
           FROM verdict WHERE finding IS NOT NULL GROUP BY finding",
        rank("severity", &SEVERITIES),
        rank("confidence", &CONFIDENCES)
    ))?;
    let mut of_finding: BTreeMap<String, Summary> = BTreeMap::new();
    for r in stmt.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, u32>(2)?,
            r.get::<_, u32>(3)?,
            r.get::<_, Option<u32>>(4)?.map(|x| x as usize),
            r.get::<_, Option<u32>>(5)?.map(|x| x as usize),
        ))
    })? {
        let (by_name, finding, total, suspicious, s, c) = r?;
        let summary = Summary {
            total,
            suspicious,
            levels: s.zip(c),
            ..Summary::default()
        };
        match (by_name, finding) {
            (Some(id), _) => named.insert(id, summary),
            (_, Some(id)) => of_finding.insert(id, summary),
            _ => None,
        };
    }
    for v in conn
        .prepare(&format!("SELECT {COLUMNS} FROM verdict WHERE raised"))?
        .query_map([], row)?
    {
        let v = v?;
        if let Some(s) = v.finding.as_ref().and_then(|f| of_finding.get_mut(f)) {
            s.opening = Some(v);
        }
    }
    // The `verdict.suspicious` finding that stands for a rule and a thing: its latest occurrence,
    // open or marked expected.
    let standing: BTreeMap<(String, String), String> = conn
        .prepare(
            "SELECT substr(f.rule, length(?1) + 1), f.about, f.id FROM finding f
             WHERE f.rule LIKE ?1 || '%' AND f.state IN ('open', 'expected')
               AND NOT EXISTS (SELECT 1 FROM finding g WHERE g.rule = f.rule
                               AND g.about = f.about AND g.occurrence > f.occurrence)",
        )?
        .query_map([PREFIX], |r| Ok(((r.get(0)?, r.get(1)?), r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for f in found.iter_mut() {
        f.verdicts = if f.rule.starts_with(PREFIX) {
            of_finding.remove(&f.id)
        } else {
            let stands = standing.get(&(f.rule.clone(), f.about.clone())).cloned();
            match (named.remove(&f.id), stands) {
                (None, None) => None,
                (s, standing) => Some(Summary {
                    standing,
                    ..s.unwrap_or_default()
                }),
            }
        };
    }
    Ok(())
}

/// The core's words for what a one-line form of a finding carries of the verdicts.
pub fn said(s: &Summary) -> String {
    let plural = |n: u32, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    match &s.opening {
        Some(_) if s.total > 1 => format!(
            "The response layer judged this suspicious, and sent {} since.",
            plural(s.total - 1, "more verdict")
        ),
        Some(_) => "The response layer judged this suspicious.".to_string(),
        None => format!(
            "{} from the response layer, {} suspicious.",
            plural(s.total, "verdict"),
            s.suspicious
        ),
    }
}

/// What `immune status --json` gives of the verdicts with a finding: for a `verdict.suspicious`
/// finding the verdict that raised this occurrence, its text whole in `_text` fields; for a
/// finding of the core only counts and the `verdict.suspicious` finding that stands.
pub fn item_json(s: &Summary) -> Value {
    match &s.opening {
        Some(o) => json!({
            "said": said(s),
            "reason_text": view::shown(&o.reason),
            "case_text": view::shown(&o.case),
            "at": view::iso(o.at),
            "severity": o.severity,
            "confidence": o.confidence,
            "more": s.total - 1,
        }),
        None => json!({
            "said": said(s),
            "total": s.total,
            "suspicious": s.suspicious,
            "finding": s.standing,
        }),
    }
}

/// A verdict as the contract gives it, with its finding by reference.
pub fn recorded(
    r: &Recorded,
    store_id: Option<&str>,
    finding: Option<v1::FindingRef>,
) -> v1::RecordedVerdict {
    use v1::verdict::About;
    let about = match (&r.named, &r.position, &r.rule) {
        (Some(id), ..) => About::Finding(v1::AboutFinding { id: whole(id) }),
        (None, position, rule) => About::Match(v1::AboutMatch {
            position: whole(position.as_deref().unwrap_or_default()),
            rule: whole(rule.as_deref().unwrap_or_default()),
        }),
    };
    v1::RecordedVerdict {
        verdict: Some(v1::Verdict {
            format: FORMAT,
            store_id: store_id.unwrap_or_default().to_string(),
            about: Some(about),
            kind: value_of::<v1::VerdictKind>(r.kind.word()),
            reason_text: whole(&r.reason),
            case_text: whole(&r.case),
            severity: r.severity.as_deref().map(value_of::<v1::Level>),
            confidence: r.confidence.as_deref().map(value_of::<v1::Level>),
        }),
        recorded_at: r.at,
        finding,
        raised: r.raised,
    }
}

/// The contract's `Verdicts`: counted, listed, and the finding that stands.
pub fn verdicts(
    (total, suspicious, list): (u32, u32, Vec<Recorded>),
    store_id: Option<&str>,
    refs: &BTreeMap<String, v1::FindingRef>,
    standing: Option<&String>,
) -> Option<v1::Verdicts> {
    let of = |id: &String| refs.get(id).cloned();
    (total > 0 || standing.is_some()).then(|| v1::Verdicts {
        total,
        suspicious,
        listed: list
            .iter()
            .map(|v| recorded(v, store_id, v.finding.as_ref().and_then(of)))
            .collect(),
        verdict_finding: standing.and_then(of),
    })
}

/// `immune verdict`.
pub struct VerdictArgs {
    pub store: PathBuf,
    /// The form it reads and answers in, `--proto` or `--json`: never text, since a message is
    /// not typed as text.
    pub form: answer::Form,
    /// The folder the collector's log is read under: `/` unless given another, as for `immune run`.
    pub system_root: PathBuf,
}

/// Reads the arguments after `verdict`.
pub fn parse(
    it: impl Iterator<Item = String>,
    options: &mut answer::Options,
) -> Result<VerdictArgs, String> {
    let mut root = None;
    options.read(it, |arg, it| {
        match arg.as_str() {
            "--system-root" => root = Some(crate::value(it, &arg)?.into()),
            _ => return Err(format!("unexpected argument: {arg}")),
        }
        Ok(())
    })?;
    // Nothing is read or recorded without a form: standard input would be taken for one.
    let form = options.form();
    if form == answer::Form::Text {
        return Err(
            "immune verdict reads one message and answers in the same form, which is never text: name it, --proto or --json"
                .to_string(),
        );
    }
    Ok(VerdictArgs {
        store: options.store()?,
        form,
        system_root: root.unwrap_or_else(|| PathBuf::from("/")),
    })
}

/// Why nothing was recorded: a stable code, the core's words, what was found, and the exit code.
pub struct Refusal {
    pub code: &'static str,
    pub message: &'static str,
    /// Raw detail. The failure message escapes it when it is built.
    pub detail: String,
    pub exit: u8,
}

fn refused(code: &'static str, message: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message,
        detail: detail.into(),
        exit: crate::EXIT_USAGE,
    }
}

fn not_a_verdict(detail: impl Into<String>) -> Refusal {
    refused(
        "not_a_verdict",
        "standard input is not one Verdict of format 1; nothing was recorded",
        detail,
    )
}

fn store_unreadable(detail: impl Into<String>) -> Refusal {
    Refusal {
        code: "store_unreadable",
        message: "the store cannot be read or written; nothing was recorded",
        detail: Stop::Store(detail.into()).to_string(),
        exit: crate::EXIT_STORE,
    }
}

/// Another writer holds the store: the code and exit the other writing commands give, which a
/// caller asks again on.
pub fn busy() -> Refusal {
    Refusal {
        code: "run_in_progress",
        message: "another run or answer is writing to this store; nothing was recorded, ask again",
        detail: String::new(),
        exit: crate::EXIT_RUN_IN_PROGRESS,
    }
}

impl From<rusqlite::Error> for Refusal {
    fn from(e: rusqlite::Error) -> Refusal {
        match e.sqlite_error_code() {
            // Another writer held the store past the busy timeout: not a broken store.
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => busy(),
            _ => store_unreadable(e.to_string()),
        }
    }
}

/// The store could not be opened: busy with another writer, which is asked again, or unreadable.
fn failed(e: Box<dyn std::error::Error>) -> Refusal {
    match e.downcast::<rusqlite::Error>() {
        Ok(e) => Refusal::from(*e),
        Err(e) => store_unreadable(e.to_string()),
    }
}

/// What a verdict names, checked.
enum About {
    Finding(String),
    Match { position: String, rule: String },
}

/// A verdict as read and checked before the store is opened.
struct Sent {
    store_id: String,
    about: About,
    kind: Kind,
    reason: String,
    case: String,
    severity: Option<&'static str>,
    confidence: Option<&'static str>,
}

/// A level as the store words it: `None` for one that is not on the core's scale.
fn level(value: i32) -> Option<&'static str> {
    match v1::Level::try_from(value).ok()? {
        v1::Level::Informational => Some("informational"),
        v1::Level::Low => Some("low"),
        v1::Level::Medium => Some("medium"),
        v1::Level::High => Some("high"),
        v1::Level::Critical => Some("critical"),
        v1::Level::Unspecified | v1::Level::NotStated => None,
    }
}

/// Text with no visible character: only spaces and characters a person cannot see.
fn blank(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_whitespace() || crate::icu::hidden(c))
}

/// Reads one `Verdict`, in the form asked, and checks what can be checked without the store.
/// What this build does not read is refused in either form. Text is taken as sent, never cut.
fn read(bytes: &[u8], json: bool) -> Result<Sent, Refusal> {
    if bytes.len() > CAP {
        return Err(refused(
            "too_large",
            "the verdict is larger than immune verdict reads, and it is never cut; nothing was recorded",
            format!("more than {CAP} bytes"),
        ));
    }
    let v: v1::Verdict = if json {
        from_json(bytes)?
    } else {
        let v = v1::Verdict::decode(bytes).map_err(|e| not_a_verdict(e.to_string()))?;
        // A field this build does not know, one given twice, or both subjects decode to a
        // message that encodes otherwise.
        if v.encode_to_vec() != bytes {
            return Err(not_a_verdict(
                "it is not the encoding of one Verdict this build reads: a field it does not know, a field given twice, or both a match and a finding",
            ));
        }
        v
    };
    if v.format != FORMAT {
        return Err(not_a_verdict(format!(
            "its format is {}, and this build reads {FORMAT}",
            v.format
        )));
    }
    let about = match v.about {
        Some(v1::verdict::About::Finding(f)) => About::Finding(f.id),
        Some(v1::verdict::About::Match(m)) => About::Match {
            position: m.position,
            rule: m.rule,
        },
        None => return Err(not_a_verdict("it names neither a match nor a finding")),
    };
    let kind = match v1::VerdictKind::try_from(v.kind) {
        Ok(v1::VerdictKind::Suspicious) => Kind::Suspicious,
        Ok(v1::VerdictKind::Harmless) => Kind::Harmless,
        _ => return Err(not_a_verdict("its kind is neither suspicious nor harmless")),
    };
    let severity = v.severity.map(|s| {
        level(s).ok_or_else(|| not_a_verdict("its severity is not a level of the core's"))
    });
    let confidence = v.confidence.map(|c| {
        level(c)
            .filter(|c| CONFIDENCES.contains(c))
            .ok_or_else(|| not_a_verdict("its confidence is not low, medium or high"))
    });
    let (severity, confidence) = match (kind, severity, confidence) {
        (Kind::Suspicious, Some(s), Some(c)) => (Some(s?), Some(c?)),
        (Kind::Suspicious, ..) => {
            return Err(not_a_verdict(
                "a suspicious verdict needs both a severity and a confidence",
            ));
        }
        (Kind::Harmless, None, None) => (None, None),
        (Kind::Harmless, ..) => {
            return Err(not_a_verdict(
                "a harmless verdict carries no severity and no confidence",
            ));
        }
    };
    for (text, limit, empty, long) in [
        (
            &v.reason_text,
            REASON_CHARS,
            "empty_reason",
            "reason_too_long",
        ),
        (&v.case_text, CASE_CHARS, "empty_case", "case_too_long"),
    ] {
        if blank(text) {
            return Err(refused(
                empty,
                "a verdict needs reason_text and case_text, each with a visible character; nothing was recorded",
                "",
            ));
        }
        let n = text.chars().count();
        if n > limit {
            return Err(refused(
                long,
                "reason_text or case_text is longer than a verdict may carry, and it is never cut; nothing was recorded",
                format!("{n} characters, and at most {limit} are taken"),
            ));
        }
    }
    Ok(Sent {
        store_id: v.store_id,
        about,
        kind,
        reason: v.reason_text,
        case: v.case_text,
        severity,
        confidence,
    })
}

/// A `Verdict` from JSON, refused whole when it is not exactly one: a key given twice anywhere,
/// or a key the message does not have, at any depth. What the message has is what the generated
/// type prints back, so no list of names is kept by hand.
fn from_json(bytes: &[u8]) -> Result<v1::Verdict, Refusal> {
    let sent: Value = serde_json::from_slice(bytes).map_err(|e| not_a_verdict(e.to_string()))?;
    if let Some(at) = crate::jsonc::twice(bytes).map_err(not_a_verdict)? {
        return Err(not_a_verdict(format!("the key {at} is given twice")));
    }
    let v: v1::Verdict =
        serde_json::from_value(sent.clone()).map_err(|e| not_a_verdict(e.to_string()))?;
    let back = serde_json::to_value(&v).map_err(|e| not_a_verdict(e.to_string()))?;
    if let Some(at) = unknown_key(&sent, &back, "") {
        return Err(not_a_verdict(format!(
            "{at} is not a field of the message, or names a second thing it is about"
        )));
    }
    Ok(v)
}

/// The first key of `sent`, as a JSON pointer, that `back` does not have at the same place.
fn unknown_key(sent: &Value, back: &Value, at: &str) -> Option<String> {
    let (Value::Object(sent), Value::Object(back)) = (sent, back) else {
        return None;
    };
    sent.iter().find_map(|(key, value)| {
        let here = format!("{at}/{key}");
        match back.get(key) {
            None => Some(here),
            Some(b) => unknown_key(value, b, &here),
        }
    })
}

/// Answers `immune verdict` with a `VerdictRecorded` or a `Failure` in the form named.
pub fn verdict_cmd(args: &VerdictArgs) -> ExitCode {
    match take(args) {
        // The form is binary or JSON (`parse`), so there is no text to give.
        Ok(m) => answer::print("verdict", args.form, &m, |_| String::new()),
        Err(r) => {
            let error = answer::error(r.code, r.message, EXAMPLE, &r.detail);
            answer::fail("verdict", args.form, error, r.exit)
        }
    }
}

/// Opens the store to write as every writing command does: under the run lock, waited for as
/// they wait, with the write lock taken at the start of the transaction. A store another writer
/// holds is `run_in_progress`, never a broken store.
pub fn writing(store: &std::path::Path) -> Result<(std::fs::File, Connection), Refusal> {
    let lock = store::lock_run(&crate::home(store))
        .map_err(|e| store_unreadable(e.to_string()))?
        .ok_or_else(busy)?;
    Ok((lock, store::open(store).map_err(failed)?))
}

/// Reads the verdict, records it in one transaction, and gives what was recorded.
fn take(args: &VerdictArgs) -> Result<v1::VerdictRecorded, Refusal> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(refused(
            "usage",
            "standard input is a terminal; immune verdict reads one message from a program and asks nothing",
            "",
        ));
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(CAP as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| not_a_verdict(format!("standard input could not be read: {e}")))?;
    let sent = read(&bytes, args.form == answer::Form::Json)?;
    if !args.store.is_file() {
        return Err(store_unreadable(format!(
            "there is no store at {}; `immune run` makes it",
            args.store.display()
        )));
    }
    let now = crate::now_secs();
    // Everything that can refuse is checked first against the store opened for reading only, so
    // a refused verdict writes nothing: it makes no store of a file, migrates none and gives none
    // an id.
    let event = check(
        &store::open_read_only(&args.store).map_err(failed)?,
        args,
        &sent,
        now,
    )?;
    let (_lock, mut conn) = writing(&args.store)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(earlier) = same(&tx, &sent)? {
        return answer(&tx, earlier, true, now);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let run_id = format!("{RUN_PREFIX}{now}-{nanos:09}");
    let (named, position, rule) = match &sent.about {
        About::Finding(id) => (Some(id.as_str()), None, None),
        About::Match { position, rule } => (None, Some(position.as_str()), Some(rule.as_str())),
    };
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, kind, subject, new_value, text)
         VALUES (?1, ?2, 'verdict', ?3, ?4, ?5, ?6)",
        params![
            now,
            run_id,
            rule,
            named.or(position),
            sent.kind.word(),
            json!({
                "named": named, "position": position, "rule": rule,
                "severity": sent.severity, "confidence": sent.confidence,
                "reason": sent.reason, "case": sent.case,
            })
            .to_string()
        ],
    )?;
    let journal = tx.last_insert_rowid();
    let (finding, raised) = match sent.kind {
        Kind::Harmless => (None, false),
        Kind::Suspicious => {
            // The rule and the thing the verdict is about, in the core's terms.
            let (subject, about) = match &sent.about {
                About::Finding(id) => {
                    let (rule, about): (String, String) =
                        tx.query_row("SELECT rule, about FROM finding WHERE id = ?1", [id], |r| {
                            Ok((r.get(0)?, r.get(1)?))
                        })?;
                    let rule = rule
                        .strip_prefix(PREFIX)
                        .map_or(rule.clone(), str::to_string);
                    (rule, about)
                }
                About::Match { rule, .. } => {
                    let machine = crate::this_machine_or_named(&tx)?;
                    store::put_entity(&tx, &machine)?;
                    (rule.clone(), machine)
                }
            };
            let (finding, raised) = findings::occur(
                &tx,
                &format!("{PREFIX}{subject}"),
                &about,
                "new",
                &run_id,
                now,
            )?;
            if raised {
                tx.execute(
                    "INSERT INTO finding_basis (finding, journal) VALUES (?1, ?2)",
                    params![finding, journal],
                )?;
            }
            if let Some(e) = event {
                events::schema(&tx)?;
                events::keep(&tx, &finding, now, 1, &VecDeque::from([e]))?;
            }
            (Some(finding), raised)
        }
    };
    tx.execute(
        &format!(
            "INSERT INTO verdict (at, journal, {}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            "kind, named, position, rule, finding, raised, severity, confidence, reason, case_ref"
        ),
        params![
            now,
            journal,
            sent.kind.word(),
            named,
            position,
            rule,
            finding,
            raised,
            sent.severity,
            sent.confidence,
            sent.reason,
            sent.case
        ],
    )?;
    let out = answer(&tx, tx.last_insert_rowid(), false, now)?;
    tx.commit()?;
    Ok(out)
}

/// What can refuse a verdict once the store is open: another store's, a finding the store does
/// not hold, a match the log does not hold. It writes nothing. A match gives back its event.
fn check(
    conn: &Connection,
    args: &VerdictArgs,
    sent: &Sent,
    now: i64,
) -> Result<Option<events::Evidence>, Refusal> {
    let id = store::id(conn)?;
    if id.as_deref() != Some(sent.store_id.as_str()) {
        return Err(refused(
            "another_store",
            "the verdict names another store than the one it was given to; nothing was recorded",
            format!(
                "the verdict names {}, and this store is {}",
                sent.store_id,
                id.as_deref().unwrap_or("without an id")
            ),
        ));
    }
    match &sent.about {
        About::Finding(id) => {
            let known = findings::all(conn, now)?
                .unwrap_or_default()
                .iter()
                .any(|f| f.id == *id && findings::item(f).is_some());
            if !known {
                return Err(refused(
                    "unknown_finding",
                    "the store has no finding with this id; nothing was recorded",
                    id,
                ));
            }
            Ok(None)
        }
        About::Match { position, rule } => checked_match(args, position, rule).map(Some),
    }
}

/// A match a verdict names, checked against the log: the rule is one this build ships, the
/// position is one `immune matches` prints, and the event on the line there, read again and
/// evaluated at the one place the core evaluates an event, matched the rule.
fn checked_match(
    args: &VerdictArgs,
    position: &str,
    rule: &str,
) -> Result<events::Evidence, Refusal> {
    let no_match = |detail: String| {
        refused(
            "no_such_match",
            "the log holds no match of that rule at that position; nothing was recorded",
            detail,
        )
    };
    if Rules::shipped().by_name(rule).is_none() {
        return Err(no_match(format!("this build ships no rule named {rule}")));
    }
    let Some(at) = LineAt::parse(position) else {
        return Err(no_match(format!(
            "{position} is not a position immune matches printed"
        )));
    };
    let hit = match events::at_line(&args.system_root, &at, crate::now_secs()) {
        Ok(AtLine::Event(hit)) => hit,
        Ok(AtLine::NoLine) => {
            return Err(no_match(format!("no event's line begins at {position}")));
        }
        Ok(AtLine::Gone) => {
            return Err(refused(
                "match_gone",
                "the log holds no line at that position: the file it names is not in the log, or another file has its name now; nothing was recorded",
                position,
            ));
        }
        Err(why) => {
            return Err(Refusal {
                code: "log_unreadable",
                message: "the event log could not be read, so the match cannot be read again; nothing was recorded",
                detail: why,
                exit: 1,
            });
        }
    };
    if !hit.matched.iter().any(|(_, m)| m.name == rule) {
        return Err(no_match(format!(
            "the event at {position} did not match {rule}"
        )));
    }
    Ok(hit.event)
}

/// The verdict recorded before that is the same message, while it means the same: a `harmless`
/// one, or a `suspicious` one whose finding is still open. After the person answered that
/// finding, the same message is the response layer saying it again.
fn same(tx: &Transaction, s: &Sent) -> rusqlite::Result<Option<i64>> {
    let (named, position, rule) = match &s.about {
        About::Finding(id) => (Some(id.as_str()), None, None),
        About::Match { position, rule } => (None, Some(position.as_str()), Some(rule.as_str())),
    };
    tx.query_row(
        "SELECT v.id FROM verdict v LEFT JOIN finding f ON f.id = v.finding
         WHERE v.named IS ?1 AND v.position IS ?2 AND v.rule IS ?3 AND v.kind = ?4
           AND v.case_ref = ?5 AND v.reason = ?6 AND v.severity IS ?7 AND v.confidence IS ?8
           AND (v.finding IS NULL OR f.state = 'open')
         ORDER BY v.id LIMIT 1",
        params![
            named,
            position,
            rule,
            s.kind.word(),
            s.case,
            s.reason,
            s.severity,
            s.confidence
        ],
        |r| r.get(0),
    )
    .optional()
}

/// What was recorded, as the contract's answer: the verdict, and its finding by reference.
fn answer(
    tx: &Transaction,
    id: i64,
    already: bool,
    now: i64,
) -> Result<v1::VerdictRecorded, Refusal> {
    let store_id = store::id(tx)?;
    let r = tx.query_row(
        &format!("SELECT {COLUMNS} FROM verdict WHERE id = ?1"),
        [id],
        row,
    )?;
    let finding = match &r.finding {
        Some(f) => findings::all(tx, now)?
            .unwrap_or_default()
            .iter()
            .find(|x| &x.id == f)
            .and_then(findings::item)
            .map(|i| known::finding_ref(&i)),
        None => None,
    };
    Ok(v1::VerdictRecorded {
        format: FORMAT,
        answered_at: now,
        store_id: store_id.clone(),
        recorded: Some(recorded(&r, store_id.as_deref(), finding)),
        already_recorded: already,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_error_preserves_a_newline_and_its_literal_escape_as_different_data() {
        for (key, escaped) in [
            ("extra\n\"", r#"extra\u{a}""#),
            (r#"extra\u{a}""#, r#"extra\u{5c}u{a}""#),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({ key: 1 })).unwrap();
            let Err(refusal) = from_json(&bytes) else {
                panic!("accepted an unknown field");
            };
            let failure = v1::Failure {
                operation: "verdict".to_string(),
                ok: false,
                errors: vec![answer::error(
                    refusal.code,
                    refusal.message,
                    EXAMPLE,
                    &refusal.detail,
                )],
            };
            let detail = format!(
                "/{escaped} is not a field of the message, or names a second thing it is about"
            );
            let binary = failure.encode_to_vec();
            let json = serde_json::to_vec(&failure).unwrap();
            for decoded in [
                v1::Failure::decode(binary.as_slice()).unwrap(),
                serde_json::from_slice::<v1::Failure>(&json).unwrap(),
            ] {
                let error = &decoded.errors[0];
                assert_eq!(error.code, "not_a_verdict");
                assert_eq!(error.detail_text.as_deref(), Some(detail.as_str()));
                assert!(!error.message.contains("extra"));
            }
            let text = crate::text::failure(&failure);
            let quoted = detail.replace('"', "\\\"");
            assert!(
                text.lines()
                    .next()
                    .unwrap()
                    .ends_with(&format!(": \"{quoted}\"")),
                "{text}"
            );
        }
    }
}
