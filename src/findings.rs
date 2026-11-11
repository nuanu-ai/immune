//! Findings: one thing a rule found, kept until the owner answers it, with the program's own
//! words for it. A change in a watched place is no longer only "since the last reading": the
//! finding stays open through quiet runs until the owner says it is expected or that he has
//! seen it. Everything that needs a look is a finding, served
//! from here with the same three sentences, so the app, the page and an agent say the same.
//!
//! A rule is plain code: an id, the ATT&CK technique where one fits, how bad and how sure as
//! two values named after OCSF's levels, whether it finds an event or a state, its fixed
//! wording, and a function that says whether it fires on what a run saw. Its samples are in
//! the promise tests. The wording never holds text from a source: what the source says is
//! returned beside it, in fields of its own.
//!
//! What a finding rests on is kept by reference, as journal entries, never as content.

use crate::{autorun, indicators, integrity, sha256, status, watched};
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

// ---- Integrity of what is installed: what the integrity reader saw change while the
// version stayed, see `integrity::observed`. ----

fn app_seal() -> Rule {
    Rule {
        id: "integrity.app-seal",
        kind: integrity::SEAL_BROKEN,
        // Compromise Host Software Binary: code added to software the owner runs.
        technique: Some("T1554"),
        severity: "high",
        confidence: "medium",
        finds: "event",
        words: Words {
            title: "An app's files were changed after its developer signed it, while its version stayed the same.",
            meaning: "This happens when something writes code into an app so that it runs whenever you open the app; some apps that update themselves in place cause it too.",
            advice: "If the app did not just update itself, do not open it; reinstall it from its developer and look for what else changed.",
        },
        fires: |o| o.place == integrity::SEAL_BROKEN,
    }
}

fn app_signer() -> Rule {
    Rule {
        id: "integrity.app-signer",
        kind: integrity::SIGNER_CHANGED,
        // The same act as above, covered by signing the app again.
        technique: Some("T1554"),
        severity: "high",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "An app is now signed by someone other than before, while its version stayed the same.",
            meaning: "This is normal for an app you build yourself; otherwise it can mean that someone changed the app and signed it again to hide it.",
            advice: "If you did not just build or reinstall this app, reinstall it from its developer and look for what else changed.",
        },
        fires: |o| o.place == integrity::SIGNER_CHANGED,
    }
}

fn package_files() -> Rule {
    Rule {
        id: "integrity.package-files",
        kind: integrity::FILES_CHANGED,
        technique: Some("T1554"),
        severity: "high",
        confidence: "medium",
        finds: "event",
        words: Words {
            title: "Files of an installed command-line tool or package were changed in place, while its version stayed the same.",
            meaning: "Package managers put in a new version rather than change an installed one, so this is rare; it happens when something adds code to a tool you run.",
            advice: "If you did not edit it yourself, reinstall that package and look for what else changed.",
        },
        fires: |o| o.place == integrity::FILES_CHANGED,
    }
}

fn app_code_outside() -> Rule {
    Rule {
        id: "integrity.app-code-outside",
        kind: integrity::CODE_OUTSIDE_CHANGED,
        technique: Some("T1554"),
        severity: "medium",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "Code an app keeps in your Library folder, outside the app itself, changed while the app's version stayed the same.",
            meaning: "Many apps download parts of themselves there and update them on their own, so this is often normal; it is also where code can be added so that it runs inside the app.",
            advice: "If this happens again without an update, reinstall the app and remove its folder named here.",
        },
        fires: |o| o.place == integrity::CODE_OUTSIDE_CHANGED,
    }
}

// ---- End of integrity of what is installed. ----

// ---- What runs by itself and indicators: see `autorun` and `indicators`. ----

fn folder_open_task() -> Rule {
    Rule {
        id: "autorun.folder-open",
        kind: autorun::RUNS_ON_OPEN,
        // Event Triggered Execution: code set to run on an event, here the folder being
        // opened. No sub-technique names an editor's tasks; its procedure examples include
        // `runOn` conditions written into coding tools' settings.
        technique: Some("T1546"),
        severity: "high",
        confidence: "medium",
        finds: "event",
        words: Words {
            title: "A project on this Mac now has a task that runs by itself when its folder is opened in the editor.",
            meaning: "Some projects use this to start a build or a server when you open them; it is also how code was planted in projects, so that it runs as soon as anyone opens the folder.",
            advice: "Do not open that folder in the editor until you have read the task file named here and know who added the task.",
        },
        fires: |o| o.place == autorun::RUNS_ON_OPEN && (o.change == "new" || o.change == "changed"),
    }
}

fn indicator_match() -> Rule {
    Rule {
        id: "indicator.match",
        kind: indicators::MATCHED,
        // What technique a match is evidence of is the list's to say, not the program's.
        technique: None,
        severity: "high",
        confidence: "high",
        finds: "event",
        words: Words {
            title: "Something on this Mac matches a sign of a known attack from the list you gave.",
            meaning: "The list names files, sites and addresses that the attack is known to use, so a match is rarely chance; it is wrong only when the list itself is wrong.",
            advice: "Do not open or run what is named here; find out how it got there, and treat this Mac as affected until you know.",
        },
        fires: |o| o.place == indicators::MATCHED,
    }
}

// ---- End of what runs by itself and indicators. ----

/// Every rule, in the order they are listed.
pub fn rules() -> [Rule; 11] {
    [
        autostart(),
        shell_profile(),
        ssh_access(),
        git_hook(),
        first_read(),
        app_seal(),
        app_signer(),
        package_files(),
        app_code_outside(),
        folder_open_task(),
        indicator_match(),
    ]
}

fn rule(id: &str) -> Option<Rule> {
    rules().into_iter().find(|r| r.id == id)
}

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
         WHERE run_id = ?2 AND reader IN (?3, ?5, ?6)
           AND entry IN ('added', 'changed', 'removed') AND subject = ?4",
        params![
            id,
            run_id,
            watched::READER,
            o.file,
            integrity::READER,
            indicators::READER
        ],
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
    /// Where the thing is, as a person recognises it: from its id, or from `installed_at`
    /// for an installed thing whose id does not say.
    pub place: String,
    /// What an application's seal or signer became, in the program's words with the team or
    /// code directory the signature gives: told as text from a source.
    /// For a match of indicators, the indicators the file matches, as the list gives them.
    pub became: Option<String>,
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
                last_seen_run, answered_at, reason, until_at,
                (SELECT object FROM assertion a WHERE a.subject = f.about
                   AND a.predicate = 'installed_at' ORDER BY a.id DESC LIMIT 1),
                (SELECT j.new_value FROM finding_basis b JOIN journal j ON j.seq = b.journal
                 WHERE b.finding = f.id AND j.entry IN ('added', 'changed')
                   AND j.predicate = CASE f.rule WHEN 'integrity.app-seal' THEN 'has_seal'
                                                 WHEN 'integrity.app-signer' THEN 'signed_by'
                                                 WHEN 'indicator.match' THEN 'matches_indicator'
                                                 END
                 ORDER BY j.seq DESC LIMIT 1)
         FROM finding f ORDER BY last_seen_at DESC, id",
    )?
    .query_map([], |r| {
        let (state, answered_at, until, last): (String, Option<i64>, Option<i64>, i64) =
            (r.get(3)?, r.get(9)?, r.get(11)?, r.get(7)?);
        let about: String = r.get(2)?;
        // Where it is installed, as the reader wrote it: under the home folder when it does
        // not start at the root.
        let installed: Option<String> = r.get(12)?;
        Ok(Found {
            id: r.get(0)?,
            rule: r.get(1)?,
            place: match installed {
                Some(path) if path.starts_with('/') => path,
                Some(path) => format!("~/{path}"),
                None => place(&about, this.as_deref()),
            },
            about,
            state: state_at(state, answered_at, until, last, now),
            change: r.get(4)?,
            first_seen: (r.get(5)?, r.get(6)?),
            last_seen: (last, r.get(8)?),
            answered_at,
            reason: r.get(10)?,
            until,
            became: r.get(13)?,
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

/// One thing that needs a look: a finding.
pub struct Item {
    pub id: String,
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
        value: f.became.clone(),
        place: Some(f.place.clone()),
        answer: f.answered_at.map(|at| (at, f.reason.clone(), f.until)),
    })
}

/// Everything that needs a look now, newest first.
pub struct Needs {
    pub items: Vec<Item>,
    /// No run of this build has looked for findings in this store yet.
    pub findings_unknown: bool,
}

/// The open findings. What the program does not cover is not among them: it is apart, in
/// `covered.rs`, and never something to look at.
pub fn needs(conn: &Connection, now: i64) -> rusqlite::Result<Needs> {
    let found = all(conn, now)?;
    let findings_unknown = found.is_none();
    let mut items: Vec<Item> = found
        .unwrap_or_default()
        .iter()
        .filter(|f| f.state == "open")
        .filter_map(item)
        .collect();
    order(&mut items);
    Ok(Needs {
        items,
        findings_unknown,
    })
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

/// Whether an item is urgent, what the app tells the owner about at once: a finding both bad
/// and sure, its severity high or critical and its confidence medium or high. The program's
/// health has no confidence and is never urgent. The app shows this and decides nothing itself.
pub fn urgent(severity: &str, confidence: Option<&str>) -> bool {
    matches!(severity, "high" | "critical") && matches!(confidence, Some("medium" | "high"))
}

/// An item in the machine-readable form. Text from a source is only in `_text` fields.
pub fn item_json(i: &Item) -> Value {
    let iso = |t: Option<i64>| t.map(crate::view::iso);
    let mut v = json!({
        "id": i.id,
        // Every item is a finding; the field stays for those that read it.
        "type": "finding",
        "kind": i.kind,
        "severity": i.severity,
        "urgent": urgent(i.severity, i.confidence),
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

/// Every rule, and every cause of what is not covered, with its wording, for an agent to
/// learn what each can say.
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
                "urgent": urgent(r.severity, Some(r.confidence)),
                "finds": r.finds,
                "title": r.words.title,
                "meaning": r.words.meaning,
                "advice": r.words.advice,
            })
        })
        .collect();
    json!({
        "rules": rules,
        "not_covered": crate::covered::causes_json(),
        "levels": { "severity": SEVERITIES, "confidence": CONFIDENCES },
    })
}

#[cfg(test)]
mod tests {
    use super::{CONFIDENCES, SEVERITIES, place, urgent};

    #[test]
    fn only_a_finding_both_bad_and_sure_is_urgent_and_the_programs_health_never_is() {
        // The app tells the owner at once about what is urgent: a mild or unsure finding must
        // not, a bad and sure one must, and the program's own health never does.
        for severity in SEVERITIES {
            for confidence in CONFIDENCES {
                let bad = severity == "high" || severity == "critical";
                let sure = confidence == "medium" || confidence == "high";
                assert_eq!(
                    urgent(severity, Some(confidence)),
                    bad && sure,
                    "{severity} {confidence}"
                );
            }
            assert!(!urgent(severity, None), "{severity}");
        }
    }

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
