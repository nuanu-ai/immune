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
    reason         TEXT,     -- given with `expected`, and with `seen` when one was given
    until_at       INTEGER,  -- when an `expected` mark ends
    via            TEXT,     -- how the answer was given: app, agent or command
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

/// How an answer was given, kept with it. A table made before this was kept takes the column
/// on open; an answer given before has none and is read as `unknown`.
pub fn add_via(conn: &Connection) -> rusqlite::Result<()> {
    if !has_via(conn)? {
        conn.execute_batch("ALTER TABLE finding ADD COLUMN via TEXT")?;
    }
    Ok(())
}

fn has_via(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('finding') WHERE name = 'via')",
        [],
        |r| r.get(0),
    )
}

/// What every listing of findings says to an agent that reads it.
pub const ANSWERS_NOTE: &str = "Answer a finding only after the owner has agreed in this conversation, having been told what it is and what the options are. Pass --via agent and the reason the owner agreed to. The app shows every answer given this way.";

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
    // Event Triggered Execution: code set to run on an event, here the folder being opened. No
    // sub-technique names an editor's tasks; its procedure examples include `runOn` conditions
    // written into coding tools' settings. The levels are the table's.
    let (technique, severity, confidence) = autorun::levels(autorun::Trigger::OpenInEditor);
    Rule {
        id: "autorun.folder-open",
        kind: autorun::RUNS_ON_OPEN,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now has a task that runs by itself when its folder is opened in the editor.",
            meaning: "Some projects use this to start a build or a server when you open them; it is also how code was planted in projects, so that it runs as soon as anyone opens the folder.",
            advice: "Do not open that folder in the editor until you have read the task file named here and know who added the task.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::Trigger::OpenInEditor),
    }
}

fn package_install() -> Rule {
    // Installer Packages: its procedure examples are npm's pre- and post-install scripts.
    let (technique, severity, confidence) = autorun::levels(autorun::Trigger::InstallPackages);
    Rule {
        id: "autorun.package-install",
        kind: autorun::Trigger::InstallPackages
            .watched()
            .map_or("", |w| w.0),
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now has a script that runs by itself when its packages are installed.",
            meaning: "Some projects need this to build themselves or to set up their tools; it is also how code was planted in projects, so that it runs as soon as anyone installs their packages.",
            advice: "Do not install that project's packages again until you have read the script named here. If you did not add it and no tool you use did, do not install them, and ask your agent to look into it.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::Trigger::InstallPackages),
    }
}

fn agent_start() -> Rule {
    // Event Triggered Execution: the event is an agent started in the folder.
    let (technique, severity, confidence) = autorun::levels(autorun::Trigger::StartAgent);
    Rule {
        id: "autorun.agent-start",
        kind: autorun::Trigger::StartAgent.watched().map_or("", |w| w.0),
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now tells your coding agent to run a program or a tool by itself.",
            meaning: "Projects use this to give the agent tools and to run checks; it is also how a project was made to run code as soon as an agent was started in its folder.",
            advice: "Do not start your agent in that folder again until you have read what the file named here starts. If you did not add it and no tool you use did, do not start the agent there.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::Trigger::StartAgent),
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

// ---- Processes: what samples of this user's processes saw, see `processes::take`. ----

fn detached_inline_code() -> Rule {
    Rule {
        id: "processes.detached-inline-code",
        kind: crate::processes::DETACHED_INLINE,
        // Command and Scripting Interpreter. The sub-technique depends on the interpreter
        // and is named for each in `processes::INTERPRETERS`; a rule carries one technique.
        technique: Some("T1059"),
        // Not one such process was found on the first Mac in the research's samples: high
        // because it is how hidden code is kept running, medium because twelve minutes of
        // samples are not a week.
        severity: "high",
        confidence: "medium",
        finds: "event",
        words: Words {
            title: "A program that runs scripts has been running code it was handed when it started, on its own in the background, for at least a minute.",
            meaning: "Tools and agents do this for a moment while they work; staying alive on its own, with no terminal or app it belongs to, is how some malware keeps hidden code running.",
            advice: "If you did not start something like this, ask your agent to find the process of the program named here and what started it, and stop it if nobody knows it.",
        },
        fires: |o| o.place == crate::processes::DETACHED_INLINE,
    }
}

// ---- End of processes. ----

// ---- Packages the projects depend on: what matching the lockfiles against the vulnerability
// data found, see `vulnerabilities`. These rules find a state: a finding stays while the
// dependency matches and is cleared when it goes. They are raised by `hold`, never by what a
// run saw change, so `fires` is false for every observation. ----

/// What these rules are about, as the item's `kind`.
pub const DEPENDENCY: &str = "lockfile dependency";

/// The ids of the rules about packages the projects depend on.
pub const MALICIOUS_PACKAGE: &str = "lockfiles.malicious-package";
pub const MALICIOUS_NAME_REMOVED: &str = "lockfiles.malicious-name-removed";
pub const EXPLOITED_VULNERABILITY: &str = "lockfiles.exploited-vulnerability";

fn malicious_package() -> Rule {
    Rule {
        id: MALICIOUS_PACKAGE,
        kind: DEPENDENCY,
        // Supply Chain Compromise: Compromise Software Dependencies and Development Tools.
        technique: Some("T1195.001"),
        severity: "critical",
        confidence: "high",
        finds: "state",
        words: Words {
            title: "A project on this Mac depends on a package that is known to be malicious.",
            meaning: "The package, or this release of it, was reported as carrying harmful code. If the project's packages were installed on this Mac, that code may have run here.",
            advice: "Do not install or run that project again. Ask your agent to look into it; if its packages were installed here, treat the tokens and keys this Mac could reach as exposed.",
        },
        fires: |_| false,
    }
}

fn malicious_name_removed() -> Rule {
    Rule {
        id: MALICIOUS_NAME_REMOVED,
        kind: DEPENDENCY,
        technique: Some("T1195.001"),
        severity: "high",
        confidence: "low",
        finds: "state",
        words: Words {
            title: "A project on this Mac depends on a package name that was removed from the registry as malicious.",
            meaning: "The registry now serves a harmless placeholder under that name, so installing it does nothing harmful today. But the project asks for a name that carried harmful code, often through a misspelt dependency.",
            advice: "Find how that name got into the project and remove it.",
        },
        fires: |_| false,
    }
}

fn exploited_vulnerability() -> Rule {
    Rule {
        id: EXPLOITED_VULNERABILITY,
        kind: DEPENDENCY,
        // Exploitation is the attacker's act elsewhere; no technique describes this Mac.
        technique: None,
        severity: "critical",
        confidence: "medium",
        finds: "state",
        words: Words {
            title: "A project on this Mac depends on a package with a vulnerability that attackers are using.",
            meaning: "The vulnerability is on the list of those known to be used in real attacks. Whether this project can be reached that way is not known.",
            advice: "Update the package to a release that fixes it; the finding names one where the record gives it.",
        },
        fires: |_| false,
    }
}

/// Holds a rule that finds a state for what a run found now: each thing in `now` has a finding
/// that stands, raised when none does, with the journal entries it rests on; each finding of
/// the rule about a thing no longer in `now` is cleared. A finding the owner answered stays
/// answered while the thing stays. Returns how many findings were opened.
pub fn hold(
    tx: &Transaction,
    rule: &str,
    now: &[(String, Vec<i64>)],
    run_id: &str,
    at: i64,
) -> rusqlite::Result<usize> {
    let mut opened = 0;
    for (about, basis) in now {
        let latest: Option<(String, i64, String, Option<i64>)> = tx
            .query_row(
                "SELECT id, occurrence, state, until_at FROM finding
                 WHERE rule = ?1 AND about = ?2 ORDER BY occurrence DESC LIMIT 1",
                params![rule, about],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        match latest {
            Some((id, _, state, until)) if state != "cleared" => {
                let ended = state == "expected" && until.is_some_and(|u| u <= at);
                tx.execute(
                    "UPDATE finding SET last_seen_at = ?2, last_seen_run = ?3,
                            state = CASE WHEN ?4 THEN 'open' ELSE state END
                     WHERE id = ?1",
                    params![id, at, run_id, ended],
                )?;
                if ended {
                    journal(
                        tx,
                        at,
                        run_id,
                        "finding_reopened",
                        &id,
                        rule,
                        about,
                        json!({}),
                    )?;
                }
            }
            latest => {
                let n = latest.map_or(1, |(_, n, _, _)| n + 1);
                let id = short_id('f', &[rule, about, &n.to_string()]);
                tx.execute(
                    "INSERT INTO finding (id, rule, about, occurrence, state, change, first_seen_at,
                                          first_seen_run, last_seen_at, last_seen_run)
                     VALUES (?1, ?2, ?3, ?4, 'open', 'new', ?5, ?6, ?5, ?6)",
                    params![id, rule, about, n, at, run_id],
                )?;
                journal(
                    tx,
                    at,
                    run_id,
                    "finding_raised",
                    &id,
                    rule,
                    about,
                    json!({}),
                )?;
                for seq in basis {
                    tx.execute(
                        "INSERT INTO finding_basis (finding, journal) VALUES (?1, ?2)",
                        params![id, seq],
                    )?;
                }
                opened += 1;
            }
        }
    }
    let standing: Vec<(String, String)> = tx
        .prepare("SELECT id, about FROM finding WHERE rule = ?1 AND state != 'cleared'")?
        .query_map([rule], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, about) in standing {
        if now.iter().any(|(a, _)| *a == about) {
            continue;
        }
        tx.execute("UPDATE finding SET state = 'cleared' WHERE id = ?1", [&id])?;
        journal(
            tx,
            at,
            run_id,
            "finding_cleared",
            &id,
            rule,
            &about,
            json!({}),
        )?;
    }
    Ok(opened)
}

// ---- End of packages the projects depend on. ----

/// Every rule, in the order they are listed.
pub fn rules() -> [Rule; 17] {
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
        package_install(),
        agent_start(),
        indicator_match(),
        detached_inline_code(),
        malicious_package(),
        malicious_name_removed(),
        exploited_vulnerability(),
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
         WHERE run_id = ?2 AND reader IN (?3, ?5, ?6, ?7)
           AND entry IN ('added', 'changed', 'removed', 'sampled') AND subject = ?4",
        params![
            id,
            run_id,
            watched::READER,
            o.file,
            integrity::READER,
            indicators::READER,
            crate::processes::READER
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
    /// How the answer was given; `None` before this was kept.
    pub via: Option<String>,
    /// A later occurrence of the same rule about the same thing was raised.
    pub superseded: bool,
    /// Its answer hides it now, see `in_force`.
    pub in_force: bool,
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
    // A store opened only for reading since this build keeps no `via` yet.
    let via = if has_via(conn)? { "via" } else { "NULL" };
    conn.prepare(&format!(
        "SELECT id, rule, about, state, change, first_seen_at, first_seen_run, last_seen_at,
                last_seen_run, answered_at, reason, until_at,
                (SELECT object FROM assertion a WHERE a.subject = f.about
                   AND a.predicate = 'installed_at' ORDER BY a.id DESC LIMIT 1),
                (SELECT j.new_value FROM finding_basis b JOIN journal j ON j.seq = b.journal
                 WHERE b.finding = f.id AND j.entry IN ('added', 'changed', 'sampled')
                   AND j.predicate = CASE f.rule WHEN 'integrity.app-seal' THEN 'has_seal'
                                                 WHEN 'integrity.app-signer' THEN 'signed_by'
                                                 WHEN 'indicator.match' THEN 'matches_indicator'
                                                 END
                 ORDER BY j.seq DESC LIMIT 1),
                {via},
                EXISTS (SELECT 1 FROM finding g WHERE g.rule = f.rule AND g.about = f.about
                          AND g.occurrence > f.occurrence)
         FROM finding f ORDER BY last_seen_at DESC, id"
    ))?
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
            via: r.get(14)?,
            superseded: r.get(15)?,
            in_force: false,
        })
    })?
    .map(|f| {
        f.map(|mut f| {
            f.in_force = in_force(&f, now);
            // A finding about a dependency says where its lockfile lines are and what records
            // it rests on, from the answers that stand now.
            if f.rule.starts_with("lockfiles.")
                && let Some((place, value)) = crate::vulnerabilities::finding_detail(conn, &f.about)
            {
                f.place = place;
                f.became = Some(value);
            }
            f
        })
    })
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
    Seen { reason: Option<String> },
}

/// What is done to a finding: an answer, or taking an answer back.
pub enum Act {
    Answer(Answer),
    Reopen,
}

/// How an answer was given: in the app, by the owner's agent with their agreement, or from
/// the command line, which is what an answer that names neither is. `Unknown` is an answer
/// given before this was kept: most were given in the app, so it is never taken for one given
/// outside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    App,
    Agent,
    Command,
    Unknown,
}

impl Via {
    pub fn literal(self) -> &'static str {
        match self {
            Via::App => "app",
            Via::Agent => "agent",
            Via::Command => "command",
            Via::Unknown => "unknown",
        }
    }

    /// How a stored answer or statement was given: one kept before this was recorded, or
    /// with a value this build does not know, is `Unknown`.
    pub fn stored(v: Option<&str>) -> Via {
        match v {
            Some("app") => Via::App,
            Some("agent") => Via::Agent,
            Some("command") => Via::Command,
            _ => Via::Unknown,
        }
    }

    /// Given outside the app, as far as is known: by an agent or from the command line.
    pub fn outside_app(self) -> bool {
        matches!(self, Via::Agent | Via::Command)
    }
}

/// Why an answer was not taken.
#[derive(Debug)]
pub enum Refused {
    Unknown,
    /// The finding is not open or expected now.
    Closed(String),
    /// There is no answer to take back: the finding is in this state.
    NotAnswered(String),
}

fn found(tx: &Transaction, id: &str, at: i64) -> Result<Found, Box<dyn std::error::Error>> {
    all(tx, at)?
        .unwrap_or_default()
        .into_iter()
        .find(|f| f.id == id)
        .ok_or_else(|| Box::new(RefusedError(Refused::Unknown)) as Box<dyn std::error::Error>)
}

/// Takes the owner's answer, kept and journaled with how it was given.
pub fn answer(
    tx: &Transaction,
    id: &str,
    a: &Answer,
    via: Via,
    at: i64,
    run_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let f = found(tx, id, at)?;
    if f.state != "open" && f.state != "expected" {
        return Err(Box::new(RefusedError(Refused::Closed(f.state))));
    }
    let via = via.literal();
    let (entry, state, reason, until, text) = match a {
        Answer::Expected { reason, days } => {
            let until = at + days * 86_400;
            (
                "finding_expected",
                "expected",
                Some(reason.as_str()),
                Some(until),
                json!({ "via": via, "reason": reason, "until": until }),
            )
        }
        Answer::Seen { reason } => {
            let mut text = json!({ "via": via });
            if let Some(reason) = reason {
                text["reason"] = json!(reason);
            }
            ("finding_seen", "seen", reason.as_deref(), None, text)
        }
    };
    tx.execute(
        "UPDATE finding SET state = ?2, answered_at = ?3, reason = ?4, until_at = ?5, via = ?6
         WHERE id = ?1",
        params![id, state, at, reason, until, via],
    )?;
    journal(tx, at, run_id, entry, id, &f.rule, &f.about, text)?;
    Ok(())
}

/// Takes an answer back: the finding is open again as if it had never been answered, with
/// its first and last seen as they were. The journal says who took it back and what the
/// answer was. An `expected` mark that ended is still an answer that can be taken back.
pub fn reopen(
    tx: &Transaction,
    id: &str,
    via: Via,
    at: i64,
    run_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let f = found(tx, id, at)?;
    let Some(given) = f.answered_at.map(|_| given(&f)) else {
        return Err(Box::new(RefusedError(Refused::NotAnswered(f.state))));
    };
    if f.state != "expected" && f.state != "seen" {
        return Err(Box::new(RefusedError(Refused::NotAnswered(f.state))));
    }
    tx.execute(
        "UPDATE finding SET state = 'open', answered_at = NULL, reason = NULL, until_at = NULL,
                            via = NULL
         WHERE id = ?1",
        [id],
    )?;
    journal(
        tx,
        at,
        run_id,
        "finding_reopened",
        id,
        &f.rule,
        &f.about,
        json!({ "via": via.literal(), "taken_back": given }),
    )?;
    Ok(())
}

/// What the answer to a finding was: `expected` when it carries an end, `seen` otherwise.
fn given(f: &Found) -> &'static str {
    if f.until.is_some() {
        "expected"
    } else {
        "seen"
    }
}

/// Whether a finding's answer hides it now: seen, or expected until a time still ahead, and
/// not followed by a later occurrence of the same thing, which is open and shown by itself.
fn in_force(f: &Found, now: i64) -> bool {
    f.answered_at.is_some()
        && !f.superseded
        && (f.state == "seen" || (f.state == "expected" && f.until.is_some_and(|u| u > now)))
}

/// Every finding whose answer is in force now, whoever gave it, the latest answer first.
pub fn answered(conn: &Connection, now: i64) -> rusqlite::Result<Option<Vec<Item>>> {
    let Some(found) = all(conn, now)? else {
        return Ok(None);
    };
    let mut items: Vec<Item> = found
        .iter()
        .filter(|f| f.in_force)
        .filter_map(item)
        .collect();
    items.sort_by(|a, b| {
        let at = |i: &Item| i.answer.as_ref().map(|a| a.at);
        at(b).cmp(&at(a)).then_with(|| a.id.cmp(&b.id))
    });
    Ok(Some(items))
}

/// The answers in force known to have been given outside the app, by an agent or from the
/// command line, listed apart so that nothing is quieted silently. An answer from before
/// `via` was kept is not among them. Never counted as something to look at.
pub fn outside_app_json(answered: &[Item], shown: usize) -> Value {
    let outside: Vec<&Item> = answered
        .iter()
        .filter(|i| i.answer.as_ref().is_some_and(|a| a.via.outside_app()))
        .collect();
    let items: Vec<Value> = outside
        .iter()
        .take(shown)
        .map(|i| {
            let a = i.answer.as_ref().expect("filtered on an answer");
            json!({
                "id": i.id,
                "title": i.words.title,
                "answer": a.given,
                "until": a.until.map(crate::view::iso),
                "via": a.via.literal(),
                "at": crate::view::iso(a.at),
                "reason_text": a.reason.as_deref().map(status::text),
                "where_text": i.place.as_deref().map(status::text),
            })
        })
        .collect();
    json!({ "total": outside.len(), "items": items })
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
            Refused::NotAnswered(state) => {
                write!(
                    f,
                    "the finding is {state}, so there is no answer to take back"
                )
            }
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
    pub answer: Option<Answered>,
}

/// The answer a finding has.
pub struct Answered {
    pub at: i64,
    /// `expected` or `seen`.
    pub given: &'static str,
    pub via: Via,
    pub reason: Option<String>,
    pub until: Option<i64>,
    /// It hides the finding now.
    pub in_force: bool,
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
        answer: f.answered_at.map(|at| Answered {
            at,
            given: given(f),
            via: Via::stored(f.via.as_deref()),
            reason: f.reason.clone(),
            until: f.until,
            in_force: f.in_force,
        }),
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
    if let Some(a) = &i.answer {
        v["answer"] = json!({
            "given": a.given,
            "via": a.via.literal(),
            "at": crate::view::iso(a.at),
            "until": a.until.map(crate::view::iso),
            "in_force": a.in_force,
            "reason_text": a.reason.as_deref().map(status::text),
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
