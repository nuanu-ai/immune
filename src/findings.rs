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
    change         TEXT,  -- what the latest occurrence was: new, changed, gone, not read or
                          -- first read
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
    /// `new`, `changed`, `gone` or `not read`.
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
/// What a run saw of something an earlier run read in full that is there and could not be
/// read: losing sight of it is a change (`baseline.rs`).
pub const NOT_READ: &str = "not read";

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

/// The rule of the item that tells the places read for the first time in a check. It is
/// raised once for a check by `first_read`, never by one thing seen.
pub const FIRST_READ_RULE: &str = "watched.first-read";
/// The prefix of the id of one check, `check:<machine>/<run id>`, which the item of places
/// read for the first time is about.
pub const CHECK: &str = "check:";

fn first_read_rule() -> Rule {
    Rule {
        id: FIRST_READ_RULE,
        kind: "places read for the first time",
        technique: None,
        severity: "informational",
        confidence: "low",
        finds: "event",
        words: Words {
            title: "Some places on this Mac were read for the first time, and what runs by itself in them was taken as their starting point.",
            meaning: "They could not be read before, or were not known, so a change in them before today would have gone unseen; this is normal after a permission was fixed, a folder was checked for the first time or a project was found later.",
            advice: "Look once at the places named here and what runs by itself in them; from now on only changes there are shown.",
        },
        fires: |_| false,
    }
}

/// Raises the item that tells the places this run read for the first time, by the journal
/// entries that name them, or adds them to the one that stands. Returns whether it opened one.
pub fn first_read(
    tx: &Transaction,
    run_id: &str,
    at: i64,
    machine: &str,
) -> rusqlite::Result<bool> {
    let any: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM journal WHERE run_id = ?1 AND entry = 'place_first_read')",
        [run_id],
        |r| r.get(0),
    )?;
    if !any {
        return Ok(false);
    }
    // The item is about the check that read them: each check raises its own, whatever was
    // answered about an earlier one.
    let check = format!("{CHECK}{machine}/{run_id}");
    crate::store::put_entity(tx, &check)?;
    let (id, opened) = occur(tx, FIRST_READ_RULE, &check, FIRST_READ, run_id, at)?;
    tx.execute(
        "INSERT INTO finding_basis (finding, journal)
         SELECT ?1, seq FROM journal WHERE run_id = ?2 AND entry = 'place_first_read'",
        params![id, run_id],
    )?;
    Ok(opened)
}

/// What the item of places read for the first time names: each place with how many things it
/// held, from its latest occurrence's entries.
fn first_read_places(conn: &Connection, id: &str, this: Option<&This>) -> rusqlite::Result<String> {
    let rows: Vec<(String, String)> = conn
        .prepare(
            "SELECT j.subject, j.new_value FROM finding_basis b JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 AND j.entry = 'place_first_read' ORDER BY j.seq",
        )?
        .query_map([id], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows
        .iter()
        .map(|(subject, n)| format!("{} ({n})", place(subject, this)))
        .collect::<Vec<_>>()
        .join("; "))
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
    let (technique, severity, confidence) = autorun::levels(autorun::RUNS_ON_OPEN);
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
        fires: |o| autorun::fires(&o.place, o.change, autorun::RUNS_ON_OPEN),
    }
}

fn editor_open() -> Rule {
    // Event Triggered Execution: the event is the folder opened in the editor, which then
    // runs what the project's settings name: an executable, a tool approved in advance, a dev
    // container's command.
    let (technique, severity, confidence) = autorun::levels(autorun::EDITOR_OPEN.0);
    Rule {
        id: "autorun.editor-open",
        kind: autorun::EDITOR_OPEN.0,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now tells your editor to run a program or a command by itself.",
            meaning: "Projects set this to use their own tools, such as a linter or a container; it is also how a project was made to run code as soon as it was opened in an editor.",
            advice: "Do not open that folder in the editor until you have read what the file named here sets and know who added it. If you did not add it and no tool you use did, ask your agent to look into it.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::EDITOR_OPEN.0),
    }
}

fn package_install() -> Rule {
    // Installer Packages: its procedure examples are npm's pre- and post-install scripts.
    let (technique, severity, confidence) = autorun::levels(autorun::PACKAGE_INSTALL.0);
    Rule {
        id: "autorun.package-install",
        kind: autorun::PACKAGE_INSTALL.0,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now has a script that runs by itself when its packages are installed.",
            meaning: "Some projects need this to build themselves or to set up their tools; it is also how code was planted in projects, so that it runs as soon as anyone installs their packages.",
            advice: "Do not install that project's packages again until you have read the script named here. If you did not add it and no tool you use did, do not install them, and ask your agent to look into it.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::PACKAGE_INSTALL.0),
    }
}

fn agent_start() -> Rule {
    // Event Triggered Execution: the event is an agent started in the folder.
    let (technique, severity, confidence) = autorun::levels(autorun::AGENT_START.0);
    Rule {
        id: "autorun.agent-start",
        kind: autorun::AGENT_START.0,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "A project on this Mac now tells your coding agent to run a program or a tool by itself.",
            meaning: "Projects use this to give the agent tools and to run checks; it is also how a project was made to run code as soon as an agent was started in its folder.",
            advice: "Do not start your agent in that folder again until you have read what the file named here starts. If you did not add it and no tool you use did, do not start the agent there.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::AGENT_START.0),
    }
}

fn agent_settings() -> Rule {
    // Event Triggered Execution: the event is the agent started, anywhere, which then runs
    // what its own settings in the home folder name.
    let (technique, severity, confidence) = autorun::levels(autorun::AGENT_SETTINGS.0);
    Rule {
        id: "autorun.agent-settings",
        kind: autorun::AGENT_SETTINGS.0,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "The settings of a coding agent on this Mac now tell it to run a program or a tool by itself.",
            meaning: "You or a tool you installed may have added it; it is also how malware made agents run its code in every project, by adding its own tool to the agent's settings.",
            advice: "Read what was added in the file named here. If you did not add it, do not start that agent until the entry is removed, and ask an agent started in a clean folder to look into where it came from.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::AGENT_SETTINGS.0),
    }
}

fn editor_extension() -> Rule {
    // IDE Extensions. An entry is an extension by its publisher and name, with no version in
    // it: a new version is the same entry, unchanged; a new one, or one whose publisher
    // changed, is new.
    let (technique, severity, confidence) = autorun::levels(autorun::EDITOR_EXTENSION.0);
    Rule {
        id: "autorun.editor-extension",
        kind: autorun::EDITOR_EXTENSION.0,
        technique,
        severity,
        confidence,
        finds: "event",
        words: Words {
            title: "An extension was added to an editor on this Mac.",
            meaning: "Extensions run with your access as soon as the editor starts; this is normal when you just installed one, and it is also how code was planted through extension stores.",
            advice: "If you did not install it, remove it in the editor and ask your agent to look into it.",
        },
        fires: |o| autorun::fires(&o.place, o.change, autorun::EDITOR_EXTENSION.0),
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
        // Not one such process was seen in twelve minutes of samples on a developer's Mac:
        // high because it is how hidden code is kept running, medium because twelve minutes
        // of samples are not a week.
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
pub fn rules() -> [Rule; 20] {
    [
        autostart(),
        shell_profile(),
        ssh_access(),
        git_hook(),
        first_read_rule(),
        app_seal(),
        app_signer(),
        package_files(),
        app_code_outside(),
        folder_open_task(),
        editor_open(),
        package_install(),
        agent_start(),
        agent_settings(),
        editor_extension(),
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
    let (id, opened) = occur(tx, rule.id, &o.file, o.change, run_id, at)?;
    tx.execute(
        "INSERT INTO finding_basis (finding, journal)
         SELECT ?1, seq FROM journal
         WHERE run_id = ?2 AND reader IN (?3, ?5, ?6, ?7)
           AND entry IN ('added', 'changed', 'removed', 'sampled', 'not_read') AND subject = ?4",
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

/// One occurrence of what `rule` finds about `about`: the finding that stands seen again, or a
/// new one. Returns the finding's id and whether it opened. Every rule that finds an event
/// raises here, the published rules over program starts included, so they share one
/// lifecycle.
pub fn occur(
    tx: &Transaction,
    rule: &str,
    about: &str,
    change: &str,
    run_id: &str,
    at: i64,
) -> rusqlite::Result<(String, bool)> {
    let latest: Option<(String, i64, String, Option<i64>)> = tx
        .query_row(
            "SELECT id, occurrence, state, until_at FROM finding
             WHERE rule = ?1 AND about = ?2 ORDER BY occurrence DESC LIMIT 1",
            params![rule, about],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    Ok(match latest {
        // Still open, or marked expected: the same finding, seen again. A mark that has ended
        // opens it again.
        Some((id, _, state, until)) if state == "open" || state == "expected" => {
            let ended = state == "expected" && until.is_some_and(|u| u <= at);
            tx.execute(
                "UPDATE finding SET last_seen_at = ?2, last_seen_run = ?3, change = ?4,
                        state = CASE WHEN ?5 THEN 'open' ELSE state END
                 WHERE id = ?1",
                params![id, at, run_id, change, ended],
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
            (id, ended)
        }
        // Never found, or the owner has seen the one before: a new finding.
        latest => {
            let n = latest.map_or(1, |(_, n, _, _)| n + 1);
            let id = short_id('f', &[rule, about, &n.to_string()]);
            tx.execute(
                "INSERT INTO finding (id, rule, about, occurrence, state, change, first_seen_at,
                                      first_seen_run, last_seen_at, last_seen_run)
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?6, ?7)",
                params![id, rule, about, n, change, at, run_id],
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
            (id, true)
        }
    })
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
    /// For a published rule's finding, the rule, its count and its evidence, as
    /// `events::finding_detail` gives them.
    pub detail: Option<Value>,
    /// What it carries of the response layer's verdicts (`verdict::attach`).
    pub verdicts: Option<crate::verdict::Summary>,
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
    let this = This::of(conn, this_machine(conn)?)?;
    // A store opened only for reading since this build keeps no `via` yet.
    let via = if has_via(conn)? { "via" } else { "NULL" };
    let mut affecting: Option<Vec<crate::vulnerabilities::Affecting>> = None;
    conn.prepare(&format!(
        "SELECT id, rule, about, state, change, first_seen_at, first_seen_run, last_seen_at,
                last_seen_run, answered_at, reason, until_at,
                (SELECT object FROM assertion a WHERE a.subject = f.about
                   AND a.predicate = 'installed_at' ORDER BY a.id DESC LIMIT 1),
                (SELECT j.new_value FROM finding_basis b JOIN journal j ON j.seq = b.journal
                 WHERE b.finding = f.id
                   AND ((j.entry IN ('added', 'changed', 'sampled')
                         AND j.predicate = CASE f.rule WHEN 'integrity.app-seal' THEN 'has_seal'
                                                       WHEN 'integrity.app-signer' THEN 'signed_by'
                                                       WHEN 'indicator.match' THEN 'matches_indicator'
                                                       END)
                        OR (f.change = 'not read' AND j.entry = 'not_read'))
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
                None => place(&about, this.as_ref()),
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
            detail: None,
            verdicts: None,
        })
    })?
    .map(|f| {
        f.and_then(|mut f| {
            f.in_force = in_force(&f, now);
            // The item of places read for the first time names them, from what it rests on.
            if f.rule == FIRST_READ_RULE {
                f.became = Some(first_read_places(conn, &f.id, this.as_ref())?);
            }
            // A finding about a dependency says where its lockfile lines are and what records
            // it rests on, from the answers that stand now. They are read once for all such
            // findings, not once for each.
            if f.rule.starts_with("lockfiles.") {
                let list = affecting.get_or_insert_with(|| {
                    crate::vulnerabilities::affecting(conn).unwrap_or_default()
                });
                if let Some((place, value)) = crate::vulnerabilities::finding_detail(list, &f.about)
                {
                    f.place = place;
                    f.became = Some(value);
                }
            }
            // A published rule's finding carries the rule and the events it matched.
            if let Some(l) = published(&f.rule)
                && let Some(meta) = &l.meta
                && let Some(kind) = l.kind
            {
                f.detail = Some(crate::events::finding_detail(
                    conn, &f.id, l.file, meta, kind,
                )?);
            }
            Ok(f)
        })
    })
    .collect::<rusqlite::Result<Vec<Found>>>()
    .and_then(|mut found| {
        crate::verdict::attach(conn, &mut found)?;
        Ok(Some(found))
    })
}

/// One journal entry a finding rests on.
pub struct Basis {
    pub seq: i64,
    pub at: i64,
    pub run_id: String,
    pub entry: String,
    pub reader: Option<String>,
    pub kind: Option<String>,
    pub predicate: Option<String>,
    pub subject: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

pub fn basis(conn: &Connection, id: &str) -> rusqlite::Result<Vec<Basis>> {
    conn.prepare(
        "SELECT j.seq, j.at, j.run_id, j.entry, j.reader, j.kind, j.predicate, j.subject,
                j.old_value, j.new_value
         FROM finding_basis b JOIN journal j ON j.seq = b.journal
         WHERE b.finding = ?1 ORDER BY j.seq",
    )?
    .query_map([id], |r| {
        Ok(Basis {
            seq: r.get(0)?,
            at: r.get(1)?,
            run_id: r.get(2)?,
            entry: r.get(3)?,
            reader: r.get(4)?,
            kind: r.get(5)?,
            predicate: r.get(6)?,
            subject: r.get(7)?,
            old_value: r.get(8)?,
            new_value: r.get(9)?,
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
    /// The entity it is about, by its id: what the map of the summary marks.
    pub about: String,
    pub answer: Option<Answered>,
    /// For a published rule's finding, the rule and the starts it matched, served as they are.
    pub detail: Option<Value>,
    /// What it carries of the response layer's verdicts.
    pub verdicts: Option<crate::verdict::Summary>,
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

/// This Mac as a place names it: its id in the store, and its name now where the store
/// keeps one, which differs from the name in its id once the Mac was renamed.
pub struct This {
    pub id: String,
    pub name: Option<String>,
}

impl This {
    /// The Mac whose id is `id`, with its name now as the store keeps it.
    pub fn of(conn: &Connection, id: Option<String>) -> rusqlite::Result<Option<This>> {
        let Some(id) = id else {
            return Ok(None);
        };
        let name = crate::store::held_mac(conn)?
            .filter(|(held, _)| *held == id)
            .map(|(_, name)| name);
        Ok(Some(This { id, name }))
    }
}

/// Where a thing is, from its entity id, as a person recognises it: a path under the home
/// folder as `~/…`, a path outside it as it is, a machine by its name, this Mac by its name
/// now, a container with its machine, and the machine first for a file or checkout on a
/// machine other than `this`. Anything else is shown as its id.
pub fn place(id: &str, this: Option<&This>) -> String {
    // A check is shown by the machine it read.
    if let Some((machine, _run)) = id
        .strip_prefix(CHECK)
        .and_then(|rest| rest.rsplit_once('/'))
    {
        return place(machine, this);
    }
    if let Some(name) = id.strip_prefix("machine:") {
        return match this {
            Some(This {
                id: mine,
                name: Some(now),
            }) if mine == id => now.clone(),
            _ => name.to_string(),
        };
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
    if this.is_some_and(|t| t.id != machine) {
        format!("{}: {path}", place(machine, this))
    } else {
        path
    }
}

/// The shipped published rule a finding's rule names, `sigma:<id>` or `elastic:<id>`; `None`
/// for any other rule and for a rule this build no longer ships.
pub fn published(rule: &str) -> Option<&'static crate::sigma::Loaded> {
    crate::sigma::Rules::shipped().by_name(rule)
}

/// What a finding from a published rule is about, as the item's `kind`: a program start for a
/// rule about program starts, a file for a rule about file events.
pub const PUBLISHED_KIND: &str = "program start matched by a published rule";
pub const PUBLISHED_FILE_KIND: &str = "file event matched by a published rule";

/// The program's own words for a finding of a published rule, with the name of the set the rule
/// came from: for a rule about program starts, then for one about file events, a file created or
/// renamed into a place the rule names. The rule's title, its authors and the event it matched
/// are text from a source and stand beside these, in fields of their own.
const START_TITLE: &str =
    "A program started on this Mac in a way that a published detection rule marks as high risk.";
const START_ORDINARY: &str = "Coding agents, build tools and people run the same commands for ordinary work, so a match is often harmless.";
const START_ADVICE: &str = "Look at the program, its arguments and what started it, shown here. If you or a tool you use ran it, mark it expected; if nobody knows it, ask your agent to look into it.";
const FILE_TITLE: &str = "A file was created or renamed on this Mac where a published detection rule marks it as high risk.";
const FILE_ORDINARY: &str = "Installers, updaters and people put files in the same places for ordinary work, so a match is often harmless.";
const FILE_ADVICE: &str = "Look at the file and the program that wrote it, shown here. If you or a tool you use put it there, mark it expected; if nobody knows it, ask your agent to look into it.";

/// The words for a finding of a rule of this set: for a rule about program starts, then for
/// one about file events. They differ between sets only in the set's name, `Source::set`, which
/// a person reads in the meaning, so no set can be given another's name. Each set's meanings are
/// made once and kept for as long as the program runs.
pub fn published_words(source: &crate::sigma::Source) -> (Words, Words) {
    type Made = std::collections::BTreeMap<&'static str, [&'static str; 2]>;
    static MADE: std::sync::Mutex<Made> = std::sync::Mutex::new(Made::new());
    let mut made = MADE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let [starts, files] = *made.entry(source.set).or_insert_with(|| {
        [START_ORDINARY, FILE_ORDINARY].map(|ordinary| {
            let meaning = format!(
                "The rule, named with this finding, comes from {} and was written from attacks seen elsewhere. {ordinary}",
                source.set
            );
            &*Box::leak(meaning.into_boxed_str())
        })
    });
    (
        Words {
            title: START_TITLE,
            meaning: starts,
            advice: START_ADVICE,
        },
        Words {
            title: FILE_TITLE,
            meaning: files,
            advice: FILE_ADVICE,
        },
    )
}

/// A finding of a published rule as an item: how bad is the rule's level, how sure follows its
/// status (`sigma::Status::confidence`), and its first ATT&CK technique stands as the item's;
/// every technique, the authors and the evidence are in `detail`. `None` for a rule whose set
/// states no level: this build raises no finding of one, and an item is never given an empty
/// severity.
fn published_item(f: &Found, l: &'static crate::sigma::Loaded) -> Option<Item> {
    let m = l.meta.as_ref()?;
    let severity = m.level_name()?;
    let (starts, files) = published_words(m.source);
    let (kind, words) = match l.kind {
        Some(crate::sigma::Kind::File) => (PUBLISHED_FILE_KIND, files),
        _ => (PUBLISHED_KIND, starts),
    };
    Some(Item {
        id: f.id.clone(),
        kind,
        rule: Some(m.name.as_str()),
        technique: m.techniques.first().map(String::as_str),
        severity,
        confidence: Some(m.status.confidence()),
        state: f.state.clone(),
        change: f.change.clone(),
        first_seen: Some(f.first_seen.0),
        last_seen: Some(f.last_seen.0),
        words,
        // The rule's title with its authors: wherever the finding is shown, the page and the
        // app's card included, the authors travel with it, as the Detection Rule License asks.
        value: Some(published_value(m)),
        place: Some(f.place.clone()),
        about: f.about.clone(),
        answer: answered_of(f),
        detail: f.detail.clone(),
        verdicts: f.verdicts.clone(),
    })
}

/// A published rule's title with its authors, as a finding's `value`.
fn published_value(m: &crate::sigma::Meta) -> String {
    match &m.author {
        Some(a) => format!("{}, by {a}", m.title),
        None => m.title.clone(),
    }
}

/// The answer a finding has, as an item carries it.
fn answered_of(f: &Found) -> Option<Answered> {
    f.answered_at.map(|at| Answered {
        at,
        given: given(f),
        via: Via::stored(f.via.as_deref()),
        reason: f.reason.clone(),
        until: f.until,
        in_force: f.in_force,
    })
}

/// A finding of the response layer's `verdict.suspicious` about the rule `subject`: its levels
/// are the highest its verdicts gave, and what it is about, the subject rule's title, stands
/// beside its words.
fn verdict_item(f: &Found, subject: &str) -> Option<Item> {
    // The subject rule's title whether or not the rule has a level: a verdict about a match of
    // a rule whose set states none is the response layer's judgement of it, and is shown. A
    // rule this build no longer has is named as the verdict named it: the response layer's
    // finding is the person's to close, and never goes when a build drops the rule.
    let value = match published(subject) {
        Some(l) => l.meta.as_ref().map(published_value),
        None => rule(subject).map(|r| r.words.title.to_string()),
    }
    .unwrap_or_else(|| subject.to_string());
    let (s, c) = f.verdicts.as_ref()?.levels?;
    Some(Item {
        id: f.id.clone(),
        kind: crate::verdict::KIND,
        rule: Some(crate::verdict::RULE),
        technique: None,
        severity: SEVERITIES[s],
        confidence: Some(CONFIDENCES[c]),
        state: f.state.clone(),
        change: f.change.clone(),
        first_seen: Some(f.first_seen.0),
        last_seen: Some(f.last_seen.0),
        words: crate::verdict::WORDS,
        value: Some(value),
        place: Some(f.place.clone()),
        about: f.about.clone(),
        answer: answered_of(f),
        detail: None,
        verdicts: f.verdicts.clone(),
    })
}

/// A finding as an item; `None` for a rule this build does not have or does not raise.
pub fn item(f: &Found) -> Option<Item> {
    if let Some(l) = published(&f.rule) {
        return published_item(f, l);
    }
    if let Some(subject) = f.rule.strip_prefix(crate::verdict::PREFIX) {
        return verdict_item(f, subject);
    }
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
        about: f.about.clone(),
        answer: answered_of(f),
        detail: None,
        verdicts: f.verdicts.clone(),
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
    if let Some(d) = &i.detail {
        v["published_rule"] = d.clone();
    }
    if let Some(s) = &i.verdicts {
        v["verdict"] = crate::verdict::item_json(s);
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
    // Only a set whose rules state levels raises findings; a rule of a set that states none is
    // counted and handed over, and raises nothing by itself.
    let (sets, silent): (Vec<&crate::sigma::Source>, Vec<&crate::sigma::Source>) =
        crate::sigma::SOURCES.iter().partition(|s| s.states_levels);
    let (starts, files) = published_words(sets[0]);
    let meanings = |of_files: bool| -> Value {
        sets.iter()
            .map(|s| {
                let (starts, files) = published_words(s);
                let words = if of_files { files } else { starts };
                (s.name.to_string(), json!(words.meaning))
            })
            .collect::<serde_json::Map<String, Value>>()
            .into()
    };
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
        // Every finding of a published rule says the same words; the rule is in its own field.
        "published_rules": {
            "rule": sets
                .iter()
                .map(|s| format!("{}:<the rule's id>", s.name))
                .collect::<Vec<_>>()
                .join(" or "),
            "kind": PUBLISHED_KIND,
            "raised_by_sets": sets.iter().map(|s| s.name).collect::<Vec<_>>(),
            "raised_by_levels": ["high", "critical"],
            "sets_that_raise_nothing": silent
                .iter()
                .map(|s| json!({
                    "name": s.name,
                    "set": s.set,
                    "why": "its rules state no level, so a match is counted and handed over and raises no finding by itself",
                }))
                .collect::<Vec<_>>(),
            "severity": "the rule's level",
            "confidence_by_status": {
                "stable": crate::sigma::Status::Stable.confidence(),
                "test": crate::sigma::Status::Test.confidence(),
                "experimental": crate::sigma::Status::Experimental.confidence(),
            },
            "finds": "event",
            // The title and the advice are the same for every set; the meaning names the
            // set, so it is given for each by the name its rules carry.
            "title": starts.title,
            "meaning_by_set": meanings(false),
            "advice": starts.advice,
            // A rule about file events raises a finding of its own kind and words; the rest
            // is the same.
            "for_file_events": {
                "kind": PUBLISHED_FILE_KIND,
                "title": files.title,
                "meaning_by_set": meanings(true),
                "advice": files.advice,
            },
        },
        // A suspicious verdict of the response layer raises a finding of Immune's own rule; its
        // levels are the verdict's, and what it is about stands beside these words.
        "verdict_rule": {
            "id": crate::verdict::RULE,
            "kind": crate::verdict::KIND,
            "severity": "the highest a verdict of the occurrence gave",
            "confidence": "the highest a verdict of the occurrence gave",
            "finds": "event",
            "title": crate::verdict::WORDS.title,
            "meaning": crate::verdict::WORDS.meaning,
            "advice": crate::verdict::WORDS.advice,
        },
        "not_covered": crate::covered::causes_json(),
        "levels": { "severity": SEVERITIES, "confidence": CONFIDENCES },
    })
}

#[cfg(test)]
mod tests {
    use super::{CONFIDENCES, Connection, SEVERITIES, This, place, urgent};

    #[test]
    fn a_finding_of_a_published_rule_names_the_set_its_rule_came_from() {
        // A person reading such a finding is told whose rule it is: the meaning names the
        // set in words, for every set shipped and for both kinds of event. A set added
        // without words of its own fails here.
        for source in crate::sigma::SOURCES {
            let (starts, files) = super::published_words(source);
            for words in [starts, files] {
                assert!(
                    words
                        .meaning
                        .contains(&format!("comes from {} and", source.set)),
                    "{}: {}",
                    source.name,
                    words.meaning
                );
            }
        }
    }

    #[test]
    fn a_finding_of_a_rule_that_states_no_level_is_no_item_and_no_item_has_an_empty_severity() {
        // This build raises no finding of a rule whose set states no level; one in the store is
        // not shown as an item with a blank severity, which a reader could not weigh.
        let found = |rule: &str| super::Found {
            id: "f-1".into(),
            rule: rule.into(),
            about: "process:invented".into(),
            state: "open".into(),
            change: None,
            first_seen: (1, "1".into()),
            last_seen: (1, "1".into()),
            answered_at: None,
            reason: None,
            until: None,
            via: None,
            superseded: false,
            in_force: false,
            place: "invented".into(),
            became: None,
            detail: None,
            verdicts: None,
        };
        assert!(
            super::item(&found(
                "elastic-behaviour:2ed9c6bf-025e-4edf-a9ec-1493d0bb4f81"
            ))
            .is_none()
        );
        let padding = super::item(&found("sigma:95361ce5-c891-4b0a-87ca-e24607884a96")).unwrap();
        assert_eq!(padding.severity, "high");
    }

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
        let this = Some(This {
            id: "machine:mac".to_string(),
            name: None,
        });
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
            assert_eq!(place(id, this.as_ref()), said, "{id}");
        }
        // Not knowing which machine this is, a file is shown without one.
        assert_eq!(place("file:machine:web-1/.zshrc", None), "~/.zshrc");
    }

    #[test]
    fn this_mac_is_shown_by_its_name_now_after_it_was_renamed() {
        // The store keeps the id of its first run; the owner knows the Mac by its new name.
        let this = Some(This {
            id: "machine:mac".to_string(),
            name: Some("mac-2".to_string()),
        });
        assert_eq!(place("machine:mac", this.as_ref()), "mac-2");
        assert_eq!(
            place("container:machine:mac/blog", this.as_ref()),
            "blog on mac-2"
        );
        assert_eq!(place("machine:db-1", this.as_ref()), "db-1");
        assert_eq!(
            place("file:machine:web-1/.zshrc", this.as_ref()),
            "web-1: ~/.zshrc"
        );
        // The name now is the one the store keeps beside this Mac's id, and no other's.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta VALUES ('machine', 'machine:mac'), ('machine_name', 'mac-2');",
        )
        .unwrap();
        let named = |id: &str| {
            This::of(&conn, Some(id.to_string()))
                .unwrap()
                .and_then(|t| t.name)
        };
        assert_eq!(named("machine:mac"), Some("mac-2".to_string()));
        assert_eq!(named("machine:other"), None);
        assert!(This::of(&conn, None).unwrap().is_none());
    }
}
