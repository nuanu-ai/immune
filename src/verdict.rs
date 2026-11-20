//! `immunity verdict`: the response layer's verdict about a rule match or a finding, read as the
//! contract's `Verdict` message on standard input, recorded, and answered with `VerdictRecorded`
//! (`contract/immunity/v1/verdict.proto`).
//!
//! A verdict never writes into a finding the core raised. A `suspicious` verdict is an event of
//! one rule of Immunity Core's own, `verdict.suspicious` (`RULE`), and goes through the path every rule
//! that finds an event goes through (`findings::occur`, `events::keep`), with no case of its own:
//! its finding is about the rule the verdict names and the thing that rule's findings are about
//! on this Mac, so its rule as the store keeps it is `verdict.suspicious:<that rule>` (`PREFIX`).
//! Its levels are the highest its verdicts gave (`attach`). A `harmless` verdict is a record and
//! nothing else.
//!
//! What is shown beside a finding is read when asked, by what the verdicts are about: counted in
//! SQL, and listed at most the first and the latest `LISTED`.
//!
//! A match is named by the position `immunity matches` printed and its rule's name. The core reads
//! the one line at that position from the collector's log again and evaluates it at the one place
//! an event is evaluated (`events::at_line`), so a verdict is about what the core matched. The log
//! keeps about a day: a `suspicious` verdict about a line no longer in it is recorded all the same,
//! marked `event_gone`, so a late decision is not lost (`checked_match`).
//!
//! A verdict may carry `verdict_id`, the response layer's id for it, a token (`token`), as an
//! idempotency key: a repeat with the same id gets the first answer and writes nothing, and the
//! same id on another message is refused (`by_id`). Without an id, sameness is by content
//! (`same`).
//!
//! Text from the response layer is data: it read files an attacker may have written. Its reason
//! and its case are shown only in `_text` fields, escaped as all such text is, and after the
//! core's own words, never inside them. Its reason is prose: a secret in it is cut where it is
//! kept, as in every text the core keeps (`secrets::Text`), and the verdict lands. Its keys (the
//! case, the store, what it names) are never rewritten: one that holds a secret is refused.

use crate::contract::{v1, value_of};
use crate::events::{self, AtLine, LineAt};
use crate::findings::{self, CONFIDENCES, Found, SEVERITIES, Words};
use crate::known::{self, whole};
use crate::secrets::{Kept, Text, holds};
use crate::sigma::Rules;
use crate::{Stop, answer, store};
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
/// The most characters `verdict_id` may hold.
pub const ID_CHARS: usize = 200;

/// Whether an id is a token, as the IETF draft of the `Idempotency-Key` header takes one: 1 to
/// `ID_CHARS` characters of printable ASCII, `!` to `~`, with no backslash. Such an id needs no
/// escaping, so it is kept, shown and asked back exactly as it was sent.
fn token(id: &str) -> bool {
    (1..=ID_CHARS).contains(&id.len())
        && id.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'\\')
}
/// The most verdicts an answer lists after the first: the latest ones.
pub const LISTED: i64 = 20;
/// How the run id of a verdict begins, in the journal.
const RUN_PREFIX: &str = "verdict-";
const EXAMPLE: &str = "immunity verdict --json < verdict.json";

/// The rule of Immunity Core's own that a `suspicious` verdict is an event of, and how its findings'
/// rule begins in the store: `verdict.suspicious:<the rule the verdict is about>`.
pub const RULE: &str = "verdict.suspicious";
pub const PREFIX: &str = "verdict.suspicious:";
pub const KIND: &str = "verdict of the response layer";
/// The core's words for a finding of `RULE`. What it is about is beside them: the rule's title
/// and the thing.
pub const WORDS: Words = Words {
    title: "The response layer judged something on this Mac suspicious.",
    short: "Judged suspicious by the response layer",
    meaning: "Another program that runs Immunity Core, the response layer, looked into what a rule found here and judged it suspicious. The rule and the thing are named with this finding; the reason is the response layer's own, quoted.",
    advice: "Read its reason and look at what it is about. Mark this finding seen once you have. Immunity Core's own finding about the same thing, if there is one, keeps an answer of its own; one answer that names both answers both.",
};
/// The core's words for an occurrence raised by a verdict whose line had left the log
/// (`event_gone`): the response layer names a match Immunity Core could no longer check.
pub const WORDS_EVENT_GONE: Words = Words {
    short: "Judged suspicious, event not checked",
    meaning: "Another program that runs Immunity Core, the response layer, judged suspicious a match of this rule whose event is no longer in the event log, so Immunity Core could not read that event again or check that the rule matched it. The rule and the thing are named with this finding; the reason is the response layer's own, quoted.",
    ..WORDS
};

/// The core's words for a finding of `RULE`, by the verdict that raised its occurrence.
pub fn words(verdicts: Option<&Summary>) -> Words {
    match verdicts.and_then(|v| v.opening.as_ref()) {
        Some(opening) if opening.event_gone => WORDS_EVENT_GONE,
        _ => WORDS,
    }
}

/// Part of the store's schema (`store::schema`).
pub const SCHEMA: &str = "
CREATE TABLE verdict (
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
    verdict_id TEXT,              -- the response layer's id for it, a token kept as sent; NULL when not given
    event_gone INTEGER NOT NULL,  -- about a match whose line was no longer in the log: no event read
    CHECK ((named IS NULL) = (position IS NOT NULL AND rule IS NOT NULL))
);
CREATE INDEX verdict_named ON verdict (named);
CREATE INDEX verdict_finding ON verdict (finding);
CREATE INDEX verdict_match ON verdict (position, rule);
CREATE UNIQUE INDEX verdict_by_id ON verdict (verdict_id) WHERE verdict_id IS NOT NULL;
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
    /// The response layer's text, read cut (`secrets::Kept`), as every reader shows it.
    pub reason: Text,
    pub case: Text,
    /// The response layer's id for it, a token kept and shown as sent (`token`); `None` when it
    /// gave none.
    pub verdict_id: Option<String>,
    /// About a match whose line was no longer in the log: the event was not read again.
    pub event_gone: bool,
}

const COLUMNS: &str = "at, kind, named, position, rule, finding, raised, severity, confidence, reason, case_ref, verdict_id, event_gone";

/// A verdict's row.
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
        reason: Kept::Reason.read(&r.get::<_, String>(9)?),
        case: Kept::Case.read(&r.get::<_, String>(10)?),
        verdict_id: r.get(11)?,
        event_gone: r.get(12)?,
    })
}

/// The verdicts that meet `cond`, counted, and listed oldest first: the first and the latest
/// `LISTED`.
pub fn listed(
    conn: &Connection,
    cond: &str,
    args: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<(u32, u32, Vec<Recorded>)> {
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
            reason_text: r.reason.said(),
            case_text: r.case.said(),
            severity: r.severity.as_deref().map(value_of::<v1::Level>),
            confidence: r.confidence.as_deref().map(value_of::<v1::Level>),
            verdict_id: r.verdict_id.clone(),
        }),
        recorded_at: r.at,
        finding,
        raised: r.raised,
        reason_cuts: crate::answer::reason_cuts(&r.reason),
        event_gone: r.event_gone,
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

/// `immunity verdict`.
pub struct VerdictArgs {
    pub store: PathBuf,
    /// The form it reads and answers in, `--proto` or `--json`: never text, since a message is
    /// not typed as text.
    pub form: answer::Form,
    /// The folder the collector's log is read under: `/` unless given another, as for `immunity run`.
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
            "immunity verdict reads one message and answers in the same form, which is never text: name it, --proto or --json"
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

/// A failure met on the store, by the rule every command tells it by (`Stop::of`): busy with
/// another writer, which is asked again, or unreadable.
fn failed(e: &(dyn std::error::Error + 'static)) -> Refusal {
    match Stop::of(e) {
        Stop::RunInProgress => busy(),
        Stop::Store(detail) => store_unreadable(detail),
    }
}

impl From<rusqlite::Error> for Refusal {
    fn from(e: rusqlite::Error) -> Refusal {
        failed(&e)
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
    /// The response layer's id for this verdict, a token (`token`), kept as sent.
    verdict_id: Option<String>,
}

impl Sent {
    /// The reason and the case as the store keeps them (`secrets::Kept`), and as a retry is
    /// compared on: two reasons that differ only in a secret are the same once cut.
    fn kept(&self) -> (String, String) {
        (
            Text::source(&self.reason).store(),
            Text::source(&self.case).store(),
        )
    }

    /// What it names: a finding, or a match by its position and rule.
    fn named(&self) -> (Option<&str>, Option<&str>, Option<&str>) {
        match &self.about {
            About::Finding(id) => (Some(id.as_str()), None, None),
            About::Match { position, rule } => (None, Some(position.as_str()), Some(rule.as_str())),
        }
    }
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
/// What this build does not read is refused in either form. Text is never shortened; a secret in
/// the reason is cut where it is kept, and a key that holds one is refused.
fn read(bytes: &[u8], json: bool) -> Result<Sent, Refusal> {
    if bytes.len() > CAP {
        return Err(refused(
            "too_large",
            "the verdict is larger than immunity verdict reads, and it is never cut; nothing was recorded",
            format!("more than {CAP} bytes"),
        ));
    }
    // The reason is prose, cut where it is kept (`Sent::kept`); the keys are checked here. What
    // a refusal repeats of what was sent is cut where the refusal is printed (`answer::fail`).
    let sent = parsed(bytes, json)?;
    match secret_field(&sent)? {
        Some(field) => Err(holds_secret(field)),
        None => Ok(sent),
    }
}

/// One `Verdict` read in the form asked and checked, as far as it can be without the store.
fn parsed(bytes: &[u8], json: bool) -> Result<Sent, Refusal> {
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
    if v.verdict_id.as_deref().is_some_and(|id| !token(id)) {
        return Err(refused(
            "verdict_id_not_a_token",
            "verdict_id, when given, is 1 to 200 characters of printable ASCII, from ! to ~, with no backslash; nothing was recorded",
            "verdict_id",
        ));
    }
    Ok(Sent {
        store_id: v.store_id,
        about,
        kind,
        reason: v.reason_text,
        case: v.case_text,
        severity,
        confidence,
        verdict_id: v.verdict_id,
    })
}

/// A verdict whose key holds a secret the core recognises is refused before anything is read or
/// written, and the refusal names the field, never what it holds. A key is never cut instead:
/// the case is the response layer's reference and what a retry is compared on, and the others
/// name what the verdict is about, so a rewritten one would mean something else. With patterns
/// that did not load, nothing can be checked and nothing is taken.
fn holds_secret(field: &str) -> Refusal {
    refused(
        "holds_secret",
        "a key of the verdict holds what Immunity Core recognises as a secret, and a key is never rewritten; nothing was recorded",
        field,
    )
}

fn unchecked(holds: Result<bool, &'static str>) -> Result<bool, Refusal> {
    holds.map_err(|_| Refusal {
        code: "secrets_unchecked",
        message: "the patterns Immunity Core recognises secrets by did not load, so the verdict cannot be checked; nothing was recorded",
        detail: String::new(),
        exit: 1,
    })
}

/// The first key of a verdict that holds a secret, as read, so a JSON escape hides nothing. Of
/// the message's fields, `reason_text` is prose and is cut where it is kept; `format`, `kind`,
/// `severity` and `confidence` are numbers of a closed list; every other text is a key: the
/// case, the verdict's id, the store and what the verdict names.
fn secret_field(s: &Sent) -> Result<Option<&'static str>, Refusal> {
    let (named, position, rule) = s.named();
    for (field, text) in [
        ("case_text", Some(s.case.as_str())),
        ("verdict_id", s.verdict_id.as_deref()),
        ("store_id", Some(s.store_id.as_str())),
        ("finding.id", named),
        ("match.position", position),
        ("match.rule", rule),
    ] {
        if let Some(text) = text
            && unchecked(holds(text))?
        {
            return Ok(Some(field));
        }
    }
    Ok(None)
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

/// Answers `immunity verdict` with a `VerdictRecorded` or a `Failure` in the form named.
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
    Ok((lock, store::open(store).map_err(|e| failed(&*e))?))
}

/// Reads the verdict, records it in one transaction, and gives what was recorded.
fn take(args: &VerdictArgs) -> Result<v1::VerdictRecorded, Refusal> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(refused(
            "usage",
            "standard input is a terminal; immunity verdict reads one message from a program and asks nothing",
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
        return Err(store_unreadable(crate::store::absent(&args.store)));
    }
    let now = crate::now_secs();
    // Everything that can refuse is checked first against the store opened for reading only, so
    // a refused verdict writes nothing: it makes no store of a file, migrates none and gives none
    // an id.
    let line = {
        let read = store::open_read_only(&args.store).map_err(|e| failed(&*e))?;
        this_store(&read, &sent)?;
        // A verdict sent again under its id gets its first answer before anything else can
        // refuse it: its line may have left the log since, or its finding been answered. Nothing
        // is written.
        if let Some(earlier) = by_id(&read, &sent)? {
            return answer(&read, earlier, true, now);
        }
        check(&read, args, &sent, now)?
    };
    let (_lock, mut conn) = writing(&args.store)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Decided again under the write lock: another process may have recorded the same verdict
    // since it was read. The unique index on the id backs this.
    let earlier = match sent.verdict_id {
        Some(_) => by_id(&tx, &sent)?,
        None => same(&tx, &sent)?,
    };
    if let Some(earlier) = earlier {
        return answer(&tx, earlier, true, now);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let run_id = format!("{RUN_PREFIX}{now}-{nanos:09}");
    let (named, position, rule) = sent.named();
    let (reason, case) = sent.kept();
    let verdict_id = sent.verdict_id.as_deref();
    let event_gone = matches!(line, Some(Line::Gone));
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
                "verdict_id": verdict_id, "event_gone": event_gone,
                crate::secrets::VERDICT_ENTRY_TEXT[0]: reason,
                crate::secrets::VERDICT_ENTRY_TEXT[1]: case,
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
            // A line no longer in the log gives no event to keep.
            if let Some(Line::Read(e)) = line {
                events::keep(&tx, &finding, now, 1, &VecDeque::from([*e]))?;
            }
            (Some(finding), raised)
        }
    };
    tx.execute(
        &format!(
            "INSERT INTO verdict (at, journal, {}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            "kind, named, position, rule, finding, raised, severity, confidence, reason, case_ref, verdict_id, event_gone"
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
            reason,
            case,
            verdict_id,
            event_gone
        ],
    )?;
    let out = answer(&tx, tx.last_insert_rowid(), false, now)?;
    tx.commit()?;
    Ok(out)
}

/// A verdict names the store it was judged from: another store's is refused, since a finding's
/// id is unique only within one store. It writes nothing.
fn this_store(conn: &Connection, sent: &Sent) -> Result<(), Refusal> {
    let id = store::id(conn)?;
    if id != sent.store_id {
        return Err(refused(
            "another_store",
            "the verdict names another store than the one it was given to; nothing was recorded",
            format!(
                "the verdict names {}, and this store is {}",
                sent.store_id, id
            ),
        ));
    }
    Ok(())
}

/// What the log gave of the match a verdict names.
enum Line {
    /// The event on the line, read again: it matched the rule.
    Read(Box<events::Evidence>),
    /// The line is no longer in the log and the verdict is `suspicious`: it is recorded with no
    /// event, and the rule was not checked against one.
    Gone,
}

/// What can refuse a verdict once the store is open and the verdict is not one recorded under
/// its id: a finding the store does not hold, a match the log does not hold. It writes nothing.
/// A match gives back what the log holds of it; a finding, nothing.
fn check(
    conn: &Connection,
    args: &VerdictArgs,
    sent: &Sent,
    now: i64,
) -> Result<Option<Line>, Refusal> {
    match &sent.about {
        About::Finding(id) => {
            let known = findings::all(conn, now)?.iter().any(|f| f.id == *id);
            if !known {
                return Err(refused(
                    "unknown_finding",
                    "the store has no finding with this id; nothing was recorded",
                    id,
                ));
            }
            Ok(None)
        }
        About::Match { position, rule } => {
            checked_match(args, position, rule, sent.kind, now).map(Some)
        }
    }
}

/// A match a verdict names, checked against the log: the rule is one this build ships, the
/// position is one `immunity matches` prints, and the event on the line there, read again and
/// evaluated at the one place the core evaluates an event, matched the rule.
///
/// The log keeps about a day, and a decision can take longer. When the line is no longer in it,
/// a `suspicious` verdict is not lost: it is taken with no event (`Line::Gone`), as long as the
/// time its position's file was started is a real one and not later than now, since
/// `immunity matches` never printed any other (`LineAt::start`). A `harmless` one is refused: it
/// is a record beside a match, and there is no match to keep it beside.
fn checked_match(
    args: &VerdictArgs,
    position: &str,
    rule: &str,
    kind: Kind,
    now: i64,
) -> Result<Line, Refusal> {
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
            "{position} is not a position immunity matches printed"
        )));
    };
    let hit = match events::at_line(&args.system_root, &at, now) {
        Ok(AtLine::Event(hit)) => hit,
        Ok(AtLine::NoLine) => {
            return Err(no_match(format!("no event's line begins at {position}")));
        }
        Ok(AtLine::Gone) if kind == Kind::Harmless => {
            return Err(refused(
                "match_gone",
                "the log holds no line at that position: the file it names is not in the log, or another file has its name now; nothing was recorded",
                position,
            ));
        }
        Ok(AtLine::Gone) => {
            return match at.start() {
                Some(start) if start <= now => Ok(Line::Gone),
                _ => Err(no_match(format!(
                    "{position} names a log file started later than now, or at no real time"
                ))),
            };
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
    Ok(Line::Read(Box::new(hit.event)))
}

/// The verdict recorded before under the same id, when this one carries an id: the same verdict
/// sent again, whose first answer is given whatever the state of its finding. An id names one
/// verdict, so the same id on a message that differs in what it names, its kind, its reason as
/// kept, its case or a level is refused, saying which of them differ, and the earlier verdict's
/// kind and when it was recorded, in the core's own values: never what either message holds.
fn by_id(conn: &Connection, s: &Sent) -> Result<Option<i64>, Refusal> {
    let Some(id) = s.verdict_id.as_deref() else {
        return Ok(None);
    };
    let (named, position, rule) = s.named();
    let (reason, case) = s.kept();
    let row = conn
        .query_row(
            "SELECT id, named IS ?2 AND position IS ?3 AND rule IS ?4, kind = ?5, reason = ?6,
                    case_ref = ?7, severity IS ?8, confidence IS ?9, kind, at
             FROM verdict WHERE verdict_id = ?1",
            params![
                id,
                named,
                position,
                rule,
                s.kind.word(),
                reason,
                case,
                s.severity,
                s.confidence
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    [
                        r.get::<_, bool>(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ],
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((earlier, equal, kind, at)) = row else {
        return Ok(None);
    };
    let differs: Vec<&str> = [
        "what it is about",
        "kind",
        "reason_text",
        "case_text",
        "severity",
        "confidence",
    ]
    .into_iter()
    .zip(equal)
    .filter(|(_, equal)| !equal)
    .map(|(field, _)| field)
    .collect();
    if differs.is_empty() {
        return Ok(Some(earlier));
    }
    // `kind` is the store's word, one of two, and `at` a number: no text of either message.
    Err(refused(
        "verdict_id_reused",
        "a verdict with this verdict_id was recorded before and this one differs from it; an id names one verdict, so nothing was recorded. A verdict that is a new decision is sent under a new id",
        format!(
            "it differs in {}; the verdict recorded under this id is {kind}, with recorded_at {at}",
            differs.join(", ")
        ),
    ))
}

/// The verdict recorded before that is the same message, while it means the same: a `harmless`
/// one, or a `suspicious` one whose finding is still open. After the person answered that
/// finding, the same message is the response layer saying it again. Only between verdicts that
/// carry no id: one with an id is told apart by it (`by_id`).
fn same(tx: &Transaction, s: &Sent) -> rusqlite::Result<Option<i64>> {
    let (named, position, rule) = s.named();
    let (reason, case) = s.kept();
    tx.query_row(
        "SELECT v.id FROM verdict v LEFT JOIN finding f ON f.id = v.finding
         WHERE v.named IS ?1 AND v.position IS ?2 AND v.rule IS ?3 AND v.kind = ?4
           AND v.case_ref = ?5 AND v.reason = ?6 AND v.severity IS ?7 AND v.confidence IS ?8
           AND v.verdict_id IS NULL AND (v.finding IS NULL OR f.state = 'open')
         ORDER BY v.id LIMIT 1",
        params![
            named,
            position,
            rule,
            s.kind.word(),
            case,
            reason,
            s.severity,
            s.confidence
        ],
        |r| r.get(0),
    )
    .optional()
}

/// What was recorded, as the contract's answer: the verdict, and its finding by reference.
fn answer(
    conn: &Connection,
    id: i64,
    already: bool,
    now: i64,
) -> Result<v1::VerdictRecorded, Refusal> {
    let store_id = Some(store::id(conn)?);
    let r = conn.query_row(
        &format!("SELECT {COLUMNS} FROM verdict WHERE id = ?1"),
        [id],
        row,
    )?;
    let finding = match &r.finding {
        Some(f) => findings::all(conn, now)?
            .iter()
            .find(|x| &x.id == f)
            .map(|f| known::finding_ref(&findings::item(f))),
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
            // For a person, the detail whole on a line of its own under its label.
            let text = crate::text::failure(&failure, &crate::screen::Screen::pipe());
            assert!(
                text.lines().any(
                    |l| l.trim_start().strip_prefix("Given").map(str::trim_start)
                        == Some(detail.as_str())
                ),
                "{text}"
            );
        }
    }
}
