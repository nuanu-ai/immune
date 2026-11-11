//! Findings: one thing a rule found, kept until the owner answers it, with the program's own
//! words for it. A change in a watched place is no longer only "since the last reading": the
//! finding stays open through quiet runs until the owner says it is expected or that he has
//! seen it. Everything that needs a look, findings and the program's own health, is served
//! from here with the same three sentences, so the app, the page and an agent say the same.
//!
//! A rule is plain code: an id, the ATT&CK technique where one fits, how bad and how sure as
//! two values named after OCSF's levels, whether it finds an event or a state, its fixed
//! wording, and a function that says whether it fires on what a run saw. Its samples are in
//! the promise tests. The wording never holds text from a source: what the source says is
//! returned beside it, in fields of its own.
//!
//! What a finding rests on is kept by reference, as journal entries, never as content.

use crate::status::{Problems, Unreached};
use crate::{sha256, status, watched};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

/// Created on every open, so a store of the current format takes it without a rebuild.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS finding (
    id             TEXT PRIMARY KEY,
    rule           TEXT NOT NULL,
    about          TEXT NOT NULL REFERENCES entity (id),
    -- 1 for the first finding of a rule about a thing; one more each time it is found again
    -- after the owner has seen the one before.
    occurrence     INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('open', 'expected', 'seen', 'cleared')),
    change         TEXT,  -- what the latest occurrence was: new, changed, gone or first read
    first_seen_at  INTEGER NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    last_seen_run  TEXT NOT NULL,
    answered_at    INTEGER,  -- the owner's latest answer
    reason         TEXT,     -- given with `expected`
    until_at       INTEGER,  -- when an `expected` mark ends
    UNIQUE (rule, about, occurrence)
);
-- What a finding rests on: journal entries by their sequence number.
CREATE TABLE IF NOT EXISTS finding_basis (
    finding TEXT NOT NULL REFERENCES finding (id),
    journal INTEGER NOT NULL
);
";

/// The levels of how bad, OCSF's `severity_id` names.
pub const SEVERITIES: [&str; 5] = ["informational", "low", "medium", "high", "critical"];
/// The levels of how sure that it is something bad, OCSF's `confidence_id` names.
pub const CONFIDENCES: [&str; 3] = ["low", "medium", "high"];

/// What every listing of findings says to an agent that reads it.
pub const ANSWERS_NOTE: &str = "Marking a finding expected or seen is the owner's answer: it hides the finding from him. An agent must not give it on the owner's behalf; it may show the owner the command to give it.";

/// The three sentences for a person: what happened, when it is normal, what to do.
#[derive(Clone, Copy)]
pub struct Words {
    pub title: &'static str,
    pub meaning: &'static str,
    pub advice: &'static str,
}

/// What a run saw in a watched place, as the rules read it.
pub struct Observed {
    /// `new`, `changed`, `gone` or `first read`.
    pub change: &'static str,
    /// The kind of place, the literal of `watched_as`.
    pub place: String,
    /// The file's id.
    pub file: String,
}

pub struct Rule {
    pub id: &'static str,
    /// What the rule is about, as the item's `kind`.
    pub kind: &'static str,
    /// The ATT&CK technique, v20.1, where one fits honestly.
    pub technique: Option<&'static str>,
    pub severity: &'static str,
    pub confidence: &'static str,
    /// `event`: it stays open until the owner answers. `state`: it clears itself when the
    /// condition is gone. Every rule of this pass finds an event.
    pub finds: &'static str,
    pub words: Words,
    pub fires: fn(&Observed) -> bool,
}

/// A file that appeared, changed or disappeared in a kind of place.
fn changed_in(o: &Observed, place: &str) -> bool {
    o.place == place && o.change != FIRST_READ
}

pub const FIRST_READ: &str = "first read";

fn autostart() -> Rule {
    Rule {
        id: "watched.autostart",
        kind: watched::AUTOSTART,
        // Create or Modify System Process: its Launch Agent and Launch Daemon sub-techniques
        // are the two folders watched here.
        technique: Some("T1543"),
        severity: "medium",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "A program set to start by itself on this Mac was added, changed or removed.",
            meaning: "This is normal right after you install, update or remove an app that works in the background.",
            advice: "If you did not just do that, look at the file named here and find out which app it belongs to.",
        },
        fires: |o| changed_in(o, watched::AUTOSTART),
    }
}

fn shell_profile() -> Rule {
    Rule {
        id: "watched.shell-profile",
        kind: watched::PROFILE,
        // Event Triggered Execution: Unix Shell Configuration Modification.
        technique: Some("T1546.004"),
        severity: "medium",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "A file your terminal runs every time it starts was added, changed or removed.",
            meaning: "This is normal when you or an installer just edited it; many tools add a line there.",
            advice: "If you did not, open the file and look at its last lines.",
        },
        fires: |o| changed_in(o, watched::PROFILE),
    }
}

fn ssh_access() -> Rule {
    Rule {
        id: "watched.ssh-access",
        kind: watched::SSH,
        // SSH Authorized Keys fits one of these files, not the client configuration: none is
        // given rather than one stretched over all of them.
        technique: None,
        severity: "high",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "An SSH file that decides who can log in to this Mac, or how it connects to other machines, was added, changed or removed.",
            meaning: "This is normal when you just added a key, a server or a setting.",
            advice: "If you did not, look at the file now, before you next connect anywhere.",
        },
        fires: |o| changed_in(o, watched::SSH),
    }
}

fn git_hook() -> Rule {
    Rule {
        id: "watched.git-hook",
        kind: watched::HOOK,
        // No technique names a script a project's version control runs by itself.
        technique: None,
        severity: "medium",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "A script that git runs by itself in one of your projects was added, changed or removed.",
            meaning: "This is normal when you just set up a tool for that project, such as a formatter or a linter.",
            advice: "If you did not, read the script before your next commit in that project.",
        },
        fires: |o| changed_in(o, watched::HOOK),
    }
}

fn first_read() -> Rule {
    Rule {
        id: "watched.first-read",
        kind: "file read for the first time",
        technique: None,
        severity: "informational",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "A file that is checked for changes could be opened for the first time.",
            meaning: "Until now it could not be opened, so a change to it before today would have gone unseen; this is normal after a permission was fixed.",
            advice: "Look at the file once, so that from now on only changes to it are shown.",
        },
        fires: |o| o.change == FIRST_READ,
    }
}

/// Every rule, in the order they are listed.
pub fn rules() -> [Rule; 5] {
    [
        autostart(),
        shell_profile(),
        ssh_access(),
        git_hook(),
        first_read(),
    ]
}

fn rule(id: &str) -> Option<Rule> {
    rules().into_iter().find(|r| r.id == id)
}

/// What is not a finding but still needs the owner: the program's own health, computed from
/// what the latest readings left.
pub struct Health {
    pub kind: &'static str,
    pub severity: &'static str,
    pub words: Words,
}

pub const UNREACHED: Health = Health {
    kind: "machine not reached",
    severity: "low",
    words: Words {
        title: "A machine could not be reached.",
        meaning: "This is normal if it is switched off or offline; while it cannot be reached, changes on it go unseen.",
        advice: "If it should be on, check that you can connect to it.",
    },
};

pub const CHECK_FAILED: Health = Health {
    kind: "check failed",
    severity: "low",
    words: Words {
        title: "Something could not be checked.",
        meaning: "Until this is fixed, changes there go unseen; the cause is often a permission or a file in an unexpected state.",
        advice: "Look at the reason given here, or ask your agent to find out why.",
    },
};

pub const THREATS_UNREAD: Health = Health {
    kind: "threat list not downloaded",
    severity: "low",
    words: Words {
        title: "The list of vulnerabilities that attackers are using could not be downloaded.",
        meaning: "This is normal if this Mac was offline; until it is downloaded, new ones go unannounced.",
        advice: "Check again when you are online.",
    },
};

pub const HEALTH: [Health; 3] = [UNREACHED, CHECK_FAILED, THREATS_UNREAD];

/// A short id, the same for the same rule, thing and occurrence.
fn short_id(prefix: char, parts: &[&str]) -> String {
    let hex = sha256::hex(parts.join("\n").as_bytes());
    format!("{prefix}{}", &hex[..10])
}

/// Looks at what a run saw and raises what the rules find. Marks of `expected` that ended
/// while the thing happened again during them open their findings again first. Returns how
/// many findings were opened by this run.
pub fn detect(
    tx: &Transaction,
    run_id: &str,
    at: i64,
    seen: &[Observed],
) -> rusqlite::Result<usize> {
    let lapsed: Vec<(String, String, String)> = tx
        .prepare(
            "SELECT id, rule, about FROM finding
             WHERE state = 'expected' AND until_at <= ?1 AND last_seen_at > answered_at",
        )?
        .query_map([at], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, rule, about) in lapsed {
        tx.execute("UPDATE finding SET state = 'open' WHERE id = ?1", [&id])?;
        journal(
            tx,
            at,
            run_id,
            "finding_reopened",
            &id,
            &rule,
            &about,
            json!({}),
        )?;
    }
    let mut opened = 0;
    for o in seen {
        for rule in rules().iter().filter(|r| (r.fires)(o)) {
            opened += usize::from(raise(tx, rule, o, run_id, at)?);
        }
    }
    Ok(opened)
}

/// Raises one finding, or adds this occurrence to the one that stands. Returns whether it
/// opened a finding.
fn raise(
    tx: &Transaction,
    rule: &Rule,
    o: &Observed,
    run_id: &str,
    at: i64,
) -> rusqlite::Result<bool> {
    let latest: Option<(String, i64, String, Option<i64>)> = tx
        .query_row(
            "SELECT id, occurrence, state, until_at FROM finding
             WHERE rule = ?1 AND about = ?2 ORDER BY occurrence DESC LIMIT 1",
            params![rule.id, o.file],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (id, opened) = match latest {
        // Still open, or marked expected: the same finding, seen again. A mark that has ended
        // opens it again.
        Some((id, _, state, until)) if state == "open" || state == "expected" => {
            let ended = state == "expected" && until.is_some_and(|u| u <= at);
            tx.execute(
                "UPDATE finding SET last_seen_at = ?2, last_seen_run = ?3, change = ?4,
                        state = CASE WHEN ?5 THEN 'open' ELSE state END
                 WHERE id = ?1",
                params![id, at, run_id, o.change, ended],
            )?;
            if ended {
                journal(
                    tx,
                    at,
                    run_id,
                    "finding_reopened",
                    &id,
                    rule.id,
                    &o.file,
                    json!({}),
                )?;
            }
            (id, ended)
        }
        // Never found, or the owner has seen the one before: a new finding.
        latest => {
            let n = latest.map_or(1, |(_, n, _, _)| n + 1);
            let id = short_id('f', &[rule.id, &o.file, &n.to_string()]);
            tx.execute(
                "INSERT INTO finding (id, rule, about, occurrence, state, change, first_seen_at,
                                      first_seen_run, last_seen_at, last_seen_run)
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?6, ?7)",
                params![id, rule.id, o.file, n, o.change, at, run_id],
            )?;
            journal(
                tx,
                at,
                run_id,
                "finding_raised",
                &id,
                rule.id,
                &o.file,
                json!({}),
            )?;
            (id, true)
        }
    };
    tx.execute(
        "INSERT INTO finding_basis (finding, journal)
         SELECT ?1, seq FROM journal
         WHERE run_id = ?2 AND reader = ?3 AND entry IN ('added', 'changed', 'removed')
           AND subject = ?4",
        params![id, run_id, watched::READER, o.file],
    )?;
    Ok(opened)
}

/// One journal entry about a finding: its id is the subject, its rule the kind, the thing it
/// is about the scope, and what else there is to say a JSON object in `text`.
#[allow(clippy::too_many_arguments)]
fn journal(
    tx: &Transaction,
    at: i64,
    run_id: &str,
    entry: &str,
    id: &str,
    rule: &str,
    about: &str,
    text: Value,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO journal (at, run_id, entry, kind, scope, subject, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![at, run_id, entry, rule, about, id, text.to_string()],
    )?;
    Ok(())
}

/// A finding as the store holds it, with its state as it stands now.
pub struct Found {
    pub id: String,
    pub rule: String,
    pub about: String,
    /// The state now: an `expected` mark that has ended while the thing happened again
    /// during it is `open`.
    pub state: String,
    pub change: Option<String>,
    pub first_seen: (i64, String),
    pub last_seen: (i64, String),
    pub answered_at: Option<i64>,
    pub reason: Option<String>,
    pub until: Option<i64>,
    /// Where the thing is, as a person recognises it.
    pub place: String,
}

/// The state of a finding at `now`. An `expected` mark hides the finding until it ends; at
/// its end the finding is open again if it was found again after the mark was given, and
/// otherwise it stays closed under the ended mark until it is found again.
fn state_at(
    state: String,
    answered: Option<i64>,
    until: Option<i64>,
    last: i64,
    now: i64,
) -> String {
    let ended = until.is_some_and(|u| u <= now);
    let again = answered.is_some_and(|a| last > a);
    if state == "expected" && ended && again {
        "open".to_string()
    } else {
        state
    }
}

fn has_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'finding')",
        [],
        |r| r.get(0),
    )
}

/// Every finding, newest first; `None` on a store no run of this build has opened.
pub fn all(conn: &Connection, now: i64) -> rusqlite::Result<Option<Vec<Found>>> {
    if !has_table(conn)? {
        return Ok(None);
    }
    let this = this_machine(conn)?;
    conn.prepare(
        "SELECT id, rule, about, state, change, first_seen_at, first_seen_run, last_seen_at,
                last_seen_run, answered_at, reason, until_at
         FROM finding ORDER BY last_seen_at DESC, id",
    )?
    .query_map([], |r| {
        let (state, answered_at, until, last): (String, Option<i64>, Option<i64>, i64) =
            (r.get(3)?, r.get(9)?, r.get(11)?, r.get(7)?);
        let about: String = r.get(2)?;
        Ok(Found {
            id: r.get(0)?,
            rule: r.get(1)?,
            place: place(&about, this.as_deref()),
            about,
            state: state_at(state, answered_at, until, last, now),
            change: r.get(4)?,
            first_seen: (r.get(5)?, r.get(6)?),
            last_seen: (last, r.get(8)?),
            answered_at,
            reason: r.get(10)?,
            until,
        })
    })?
    .collect::<rusqlite::Result<_>>()
    .map(Some)
}

/// One journal entry a finding rests on.
pub struct Basis {
    pub seq: i64,
    pub at: i64,
    pub run_id: String,
    pub entry: String,
    pub predicate: Option<String>,
    pub subject: Option<String>,
}

pub fn basis(conn: &Connection, id: &str) -> rusqlite::Result<Vec<Basis>> {
    conn.prepare(
        "SELECT j.seq, j.at, j.run_id, j.entry, j.predicate, j.subject
         FROM finding_basis b JOIN journal j ON j.seq = b.journal
         WHERE b.finding = ?1 ORDER BY j.seq",
    )?
    .query_map([id], |r| {
        Ok(Basis {
            seq: r.get(0)?,
            at: r.get(1)?,
            run_id: r.get(2)?,
            entry: r.get(3)?,
            predicate: r.get(4)?,
            subject: r.get(5)?,
        })
    })?
    .collect()
}

/// The owner's answer to a finding.
pub enum Answer {
    Expected { reason: String, days: i64 },
    Seen,
}

/// Why an answer was not taken.
#[derive(Debug)]
pub enum Refused {
    Unknown,
    /// The finding is not open or expected now.
    Closed(String),
}

/// Takes the owner's answer, journaled with how it was given.
pub fn answer(
    tx: &Transaction,
    id: &str,
    a: &Answer,
    at: i64,
    run_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let found = all(tx, at)?
        .unwrap_or_default()
        .into_iter()
        .find(|f| f.id == id);
    let Some(f) = found else {
        return Err(Box::new(RefusedError(Refused::Unknown)));
    };
    if f.state != "open" && f.state != "expected" {
        return Err(Box::new(RefusedError(Refused::Closed(f.state))));
    }
    let (entry, state, reason, until, text) = match a {
        Answer::Expected { reason, days } => {
            let until = at + days * 86_400;
            (
                "finding_expected",
                "expected",
                Some(reason.as_str()),
                Some(until),
                json!({ "via": "command", "reason": reason, "until": until }),
            )
        }
        Answer::Seen => (
            "finding_seen",
            "seen",
            None,
            None,
            json!({ "via": "command" }),
        ),
    };
    tx.execute(
        "UPDATE finding SET state = ?2, answered_at = ?3, reason = ?4, until_at = ?5
         WHERE id = ?1",
        params![id, state, at, reason, until],
    )?;
    journal(tx, at, run_id, entry, id, &f.rule, &f.about, text)?;
    Ok(())
}

#[derive(Debug)]
pub struct RefusedError(pub Refused);

impl std::fmt::Display for RefusedError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.0 {
            Refused::Unknown => write!(f, "the store has no finding with this id"),
            Refused::Closed(state) => write!(
                f,
                "the finding is {state}, so there is nothing to answer; a new occurrence opens a new one"
            ),
        }
    }
}

impl std::error::Error for RefusedError {}

/// One thing that needs a look: a finding or an item of the program's health.
pub struct Item {
    pub id: String,
    /// `finding` or `health`.
    pub kind_of: &'static str,
    pub kind: &'static str,
    pub rule: Option<&'static str>,
    pub technique: Option<&'static str>,
    pub severity: &'static str,
    pub confidence: Option<&'static str>,
    pub state: String,
    pub change: Option<String>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub words: Words,
    /// What the source says, such as why a machine could not be reached.
    pub value: Option<String>,
    /// Where: a path, a machine.
    pub place: Option<String>,
    pub answer: Option<(i64, Option<String>, Option<i64>)>,
}

/// The machine the latest run ran on: the scope of its resolver reading.
fn this_machine(conn: &Connection) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT scope FROM coverage WHERE reader = ?1 ORDER BY id DESC LIMIT 1",
        [crate::resolver::READER],
        |r| r.get(0),
    )
    .optional()
}

/// Where a thing is, from its entity id, as a person recognises it: a path under the home
/// folder as `~/…`, a path outside it as it is, a machine by its name, a container with its
/// machine, and the machine first for a file or checkout on a machine other than `this`.
/// Anything else is shown as its id.
pub fn place(id: &str, this: Option<&str>) -> String {
    if let Some(name) = id.strip_prefix("machine:") {
        return name.to_string();
    }
    if let Some(rest) = id.strip_prefix("container:")
        && let Some((machine, name)) = rest.rsplit_once('/')
    {
        return format!("{name} on {}", place(machine, this));
    }
    let Some((machine, path)) = ["file:", "checkout:"]
        .iter()
        .find_map(|p| id.strip_prefix(p))
        .and_then(|rest| rest.split_once('/'))
    else {
        return id.to_string();
    };
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("~/{path}")
    };
    if this.is_some_and(|t| t != machine) {
        format!("{}: {path}", place(machine, this))
    } else {
        path
    }
}

/// A finding as an item; `None` for a rule this build does not have.
pub fn item(f: &Found) -> Option<Item> {
    let r = rule(&f.rule)?;
    Some(Item {
        id: f.id.clone(),
        kind_of: "finding",
        kind: r.kind,
        rule: Some(r.id),
        technique: r.technique,
        severity: r.severity,
        confidence: Some(r.confidence),
        state: f.state.clone(),
        change: f.change.clone(),
        first_seen: Some(f.first_seen.0),
        last_seen: Some(f.last_seen.0),
        words: r.words,
        value: None,
        place: Some(f.place.clone()),
        answer: f.answered_at.map(|at| (at, f.reason.clone(), f.until)),
    })
}

fn health(h: &Health, about: &[&str], first: Option<i64>, last: Option<i64>) -> Item {
    let mut parts = vec![h.kind];
    parts.extend(about);
    Item {
        id: short_id('h', &parts),
        kind_of: "health",
        kind: h.kind,
        rule: None,
        technique: None,
        severity: h.severity,
        confidence: None,
        state: "current".to_string(),
        change: None,
        first_seen: first,
        last_seen: last,
        words: h.words,
        value: None,
        place: None,
        answer: None,
    }
}

/// Everything that needs a look now, newest first.
pub struct Needs {
    pub items: Vec<Item>,
    /// No run of this build has looked for findings in this store yet.
    pub findings_unknown: bool,
}

/// Open findings and the program's health: machines not reached, checks that failed, and
/// the threat list when its latest download failed. Only a machine not reached says since
/// when; the others say when they were last so.
pub fn needs(
    conn: &Connection,
    p: &Problems,
    catalogue: Option<&status::Catalogue>,
    now: i64,
) -> rusqlite::Result<Needs> {
    let found = all(conn, now)?;
    let this = this_machine(conn)?;
    let this = this.as_deref();
    let findings_unknown = found.is_none();
    let mut items: Vec<Item> = found
        .unwrap_or_default()
        .iter()
        .filter(|f| f.state == "open")
        .filter_map(item)
        .collect();
    for u in &p.unreached {
        items.push(unreached(u, this));
    }
    for g in p.groups.iter().filter(|g| g.class == "failed") {
        let reason = g.reason.as_deref().unwrap_or_default();
        let mut i = health(
            &CHECK_FAILED,
            &[&g.reader, &g.kind, reason],
            None,
            Some(g.latest),
        );
        i.value = g.reason.clone();
        i.place = g.scopes.first().map(|s| place(s, this));
        items.push(i);
    }
    if let Some(status::Catalogue::Failed { reason, at, .. }) = catalogue {
        let mut i = health(&THREATS_UNREAD, &[], None, Some(*at));
        i.value = Some(reason.clone());
        items.push(i);
    }
    order(&mut items);
    Ok(Needs {
        items,
        findings_unknown,
    })
}

fn unreached(u: &Unreached, this: Option<&str>) -> Item {
    let mut i = health(&UNREACHED, &[&u.scope], Some(u.since), Some(u.last));
    i.value = u.reason.clone();
    i.place = Some(place(&u.scope, this));
    i
}

/// The order of everything that needs a look, and of findings: the most severe first, then
/// the newest, then by id. The app shows the first few, so a severe finding is never under
/// a mild item.
pub fn order(items: &mut [Item]) {
    let rank = |i: &Item| SEVERITIES.iter().position(|s| *s == i.severity);
    items.sort_by(|a, b| {
        rank(b)
            .cmp(&rank(a))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// An item in the machine-readable form. Text from a source is only in `_text` fields.
pub fn item_json(i: &Item) -> Value {
    let iso = |t: Option<i64>| t.map(crate::view::iso);
    let mut v = json!({
        "id": i.id,
        "type": i.kind_of,
        "kind": i.kind,
        "severity": i.severity,
        "state": i.state,
        "first_seen": iso(i.first_seen),
        "last_seen": iso(i.last_seen),
        "title": i.words.title,
        "meaning": i.words.meaning,
        "advice": i.words.advice,
        "value_text": i.value.as_deref().map(status::text),
        "where_text": i.place.as_deref().map(status::text),
    });
    if let Some(rule) = i.rule {
        v["rule"] = json!(rule);
        v["confidence"] = json!(i.confidence);
        v["change"] = json!(i.change);
    }
    if let Some(t) = i.technique {
        v["technique"] = json!(t);
    }
    if let Some((at, reason, until)) = &i.answer {
        v["answer"] = json!({
            "at": crate::view::iso(*at),
            "reason_text": reason.as_deref().map(status::text),
            "until": until.map(crate::view::iso),
        });
    }
    v
}

/// Every rule and every kind of health item with its wording, for an agent to learn what each
/// can say.
pub fn catalogue_json() -> Value {
    let rules: Vec<Value> = rules()
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "kind": r.kind,
                "technique": r.technique,
                "severity": r.severity,
                "confidence": r.confidence,
                "finds": r.finds,
                "title": r.words.title,
                "meaning": r.words.meaning,
                "advice": r.words.advice,
            })
        })
        .collect();
    let health: Vec<Value> = HEALTH
        .iter()
        .map(|h| {
            json!({
                "kind": h.kind,
                "severity": h.severity,
                "title": h.words.title,
                "meaning": h.words.meaning,
                "advice": h.words.advice,
            })
        })
        .collect();
    json!({
        "rules": rules,
        "health": health,
        "levels": { "severity": SEVERITIES, "confidence": CONFIDENCES },
    })
}

#[cfg(test)]
mod tests {
    use super::place;

    #[test]
    fn where_a_thing_is_reads_as_a_person_knows_it() {
        // The owner recognises `~/.zshrc` and a project's folder, not an entity id.
        let this = Some("machine:mac");
        for (id, said) in [
            ("file:machine:mac/.zshrc", "~/.zshrc"),
            ("file:machine:mac//etc/zshrc", "/etc/zshrc"),
            (
                "file:machine:mac/dev/shop/.git/hooks/pre-commit",
                "~/dev/shop/.git/hooks/pre-commit",
            ),
            (
                "file:machine:mac//Volumes/work/shop/.git/hooks/pre-commit",
                "/Volumes/work/shop/.git/hooks/pre-commit",
            ),
            (
                "file:machine:web-1//etc/ssh/sshd_config",
                "web-1: /etc/ssh/sshd_config",
            ),
            ("checkout:machine:mac/dev/shop", "~/dev/shop"),
            ("machine:db-1", "db-1"),
            ("container:machine:web-1/blog", "blog on web-1"),
            (
                "component:machine:mac/brew/jq",
                "component:machine:mac/brew/jq",
            ),
        ] {
            assert_eq!(place(id, this), said, "{id}");
        }
        // Not knowing which machine this is, a file is shown without one.
        assert_eq!(place("file:machine:web-1/.zshrc", None), "~/.zshrc");
    }
}
