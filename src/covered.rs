//! What the status answers first, for a person: is this Mac watched, and is it quiet. What
//! needs a look is findings only. What the program does not cover is apart from it, quiet and
//! aggregated: one item per cause, never one per machine or per file, in fixed words like
//! the rules' words. Both are derived from the latest readings in the store and nothing else.
//!
//! `cannot_judge`, `coverage` and `no_reader_for` stay as they were, for agents: this is the
//! same data told for a person.

use crate::status::{self, Catalogue, Problems};
use crate::view::Latest;
use crate::{autorun, findings, guarded, integrity, resolver, servers, watched};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// What is watched on this Mac, in words a person knows: the kind of thing as the store
/// counts it, the words, and whether the watcher sees it within seconds. What runs by itself
/// in projects is one kind per trigger whose ways are read, from the table in `autorun`.
pub fn watched() -> Vec<(Count, &'static str, bool)> {
    let mut out = vec![
        (Count::Files(watched::AUTOSTART), "startup items", true),
        (Count::Files(watched::LOGIN_HOOK), LOGIN_HOOKS, true),
        (Count::Files(watched::PROFILE), "shell startup files", true),
        (Count::Files(watched::SSH), "SSH files", true),
        (Count::Files(watched::AUTH), LOGIN_MODULES, true),
        (Count::Files(watched::HOOK), "git hooks in projects", true),
    ];
    out.extend(
        autorun::watched()
            .into_iter()
            .map(|(as_, what, _)| (Count::Files(as_), what, autorun::live(as_))),
    );
    out.extend(INSTALLED);
    out.push((Count::Dependencies, DEPENDENCIES, false));
    out
}

/// Scripts the login window runs at every login and logout, in the words for a person.
pub const LOGIN_HOOKS: &str = "login and logout hooks";
/// What decides how the owner logs in and how a password is checked, in the same words.
pub const LOGIN_MODULES: &str = "login and password modules";

/// What the projects' lockfiles declare, matched against the known vulnerabilities at every
/// check.
pub const DEPENDENCIES: &str = "packages your projects depend on";

/// Installed software, as the integrity reader counts it.
const INSTALLED: [(Count, &str, bool); 4] = [
    (Count::Installed(integrity::BUNDLES), "applications", false),
    (
        Count::Installed(integrity::KEGS),
        "Homebrew packages",
        false,
    ),
    (Count::Installed(integrity::NPM), "npm packages", false),
    (
        Count::Installed(integrity::APP_SUPPORT),
        "app code kept outside the app",
        false,
    ),
];

/// What a watcher samples, in the same words as the other kinds.
pub const SAMPLED: &str = "running programs and their connections";

/// What the event level records, in the same words: listed with how `events` while it
/// records them, counted over the last day, and not listed otherwise.
pub const EVENTS: &str = "program starts";

/// The rules that tell the owner about a change in a kind of watched thing, by its words as
/// `watched` and `SAMPLED` give them. Derived from the rules themselves: a rule speaks about a
/// kind when it fires on what a run reports for a change of that kind. None for words that
/// name no kind.
pub fn rules_about(what: &str) -> Vec<findings::Rule> {
    // What the matching of dependencies finds is a state, not a change: its rules say so by
    // their kind.
    if what == DEPENDENCIES {
        return findings::rules()
            .into_iter()
            .filter(|r| r.kind == findings::DEPENDENCY)
            .collect();
    }
    let places: Vec<&str> = if what == SAMPLED {
        // What a sample of running programs reports for a rule about the programs themselves;
        // a match of an indicator is not about one kind and is told apart.
        vec![crate::processes::DETACHED_INLINE]
    } else {
        match watched().into_iter().find(|(_, w, _)| *w == what) {
            Some((Count::Files(as_), _, _)) => vec![as_],
            Some((Count::Installed(kind), _, _)) => integrity::places(kind),
            Some((Count::Dependencies, _, _)) | None => Vec::new(),
        }
    };
    findings::rules()
        .into_iter()
        .filter(|r| {
            places.iter().any(|p| {
                ["new", "changed", "gone"].into_iter().any(|change| {
                    (r.fires)(&findings::Observed {
                        change,
                        place: p.to_string(),
                        file: String::new(),
                    })
                })
            })
        })
        .collect()
}

/// The kinds of watched thing, by their words, that the latest readings of this Mac looked
/// for and found none of, so the page can still say what a change there would tell. A kind
/// that was not read, or whose reading failed, is not one: what is not covered says why.
pub fn none_here(
    conn: &Connection,
    latest: &[Latest],
    m: &ThisMac,
) -> rusqlite::Result<Vec<&'static str>> {
    let Some(this) = this_machine(conn)? else {
        return Ok(Vec::new());
    };
    let in_checkout = format!("checkout:{this}/");
    let mut out = Vec::new();
    for (count, what, _) in watched() {
        if m.watched.iter().any(|w| w.0 == what) {
            continue;
        }
        let (reader, kinds) = match count {
            // Projects were looked for on this Mac and no lockfile of them failed.
            Count::Dependencies => {
                let looked = latest
                    .iter()
                    .any(|r| r.reader == crate::checkouts::READER && r.scope == this);
                let failed_here = latest
                    .iter()
                    .any(|r| r.reader == crate::lockfiles::READER && failed(r));
                if looked && !failed_here {
                    out.push(what);
                }
                continue;
            }
            Count::Files(as_) => {
                let mut kinds = autorun::kinds_of(as_);
                kinds.extend(
                    watched::kinds()
                        .into_iter()
                        .filter(|(w, _)| *w == as_)
                        .map(|(_, kind)| kind.to_string()),
                );
                if kinds.is_empty() {
                    continue;
                }
                (watched::READER, kinds)
            }
            Count::Installed(kind) => (integrity::READER, vec![kind.to_string()]),
        };
        // The reader looked at this Mac at its last reading: for files, any place of its; for
        // installed things, this very kind.
        let ran = latest.iter().any(|r| {
            r.reader == reader
                && r.scope == this
                && (matches!(count, Count::Files(_)) || kinds.contains(&r.kind))
        });
        let failed_here = latest.iter().any(|r| {
            r.reader == reader
                && kinds.contains(&r.kind)
                && (r.scope == this || r.scope.starts_with(&in_checkout))
                && failed(r)
        });
        if ran && !failed_here {
            out.push(what);
        }
    }
    Ok(out)
}

/// How a kind of watched thing is counted: live files of a kind of watched place, or live
/// installed things of a kind of the integrity reader.
#[derive(Clone, Copy)]
pub enum Count {
    Files(&'static str),
    Installed(&'static str),
    /// Packages the projects' lockfiles declare, from the lockfiles reader.
    Dependencies,
}

/// The state of this Mac, as `this_mac` gives it.
pub struct ThisMac {
    /// `watched`, `watched_in_part` or `not_checked`.
    pub state: &'static str,
    /// Whether a watcher runs on the store now and nothing in it has failed since it last
    /// succeeded: `failed` is empty.
    pub live: bool,
    /// When the latest full run finished.
    pub checked_at: Option<i64>,
    /// When a watcher last read every watched place: a reading of the places one change touched does not move it.
    pub live_read_at: Option<i64>,
    /// What is watched, its count, and `live`, `hourly` or `sampled`.
    pub watched: Vec<(&'static str, i64, &'static str)>,
    /// What has failed in the watcher running now and not succeeded since.
    pub failed: Vec<crate::watch::Failure>,
}

impl ThisMac {
    /// Before any reading of this Mac.
    pub fn unchecked(live: bool) -> ThisMac {
        ThisMac {
            state: "not_checked",
            live,
            checked_at: None,
            live_read_at: None,
            watched: Vec::new(),
            failed: Vec::new(),
        }
    }
}

/// The machine the store's readings of this Mac are scoped to: the resolver's, which every
/// full run makes, else the watched places', which a watcher makes.
pub fn this_machine(conn: &Connection) -> rusqlite::Result<Option<String>> {
    // The id the store keeps for this Mac, whatever its name is now.
    if let Some((id, _)) = crate::store::held_mac(conn)? {
        return Ok(Some(id));
    }
    // The latest row of a reader is the latest reading of one of its scopes and kinds.
    conn.query_row(
        &format!(
            "{}
             SELECT scope FROM latest
             WHERE reader IN (?1, ?2) AND scope LIKE 'machine:%'
             ORDER BY reader = ?1 DESC, id DESC LIMIT 1",
            crate::store::LATEST
        ),
        params![resolver::READER, watched::READER],
        |r| r.get(0),
    )
    .optional()
}

/// Whether a reading is of this Mac's own places: the machine itself or a file on it.
fn on_this_mac(scope: &str, this: &str) -> bool {
    scope == this
        || scope
            .strip_prefix("file:")
            .and_then(|rest| rest.strip_prefix(this))
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether a reading is a failure the owner can act on. A reading written before causes
/// were kept has none, and is not taken for a failure here: the next run reads it again and
/// says why (`coverage` still counts it as failed, for agents).
fn failed(r: &Latest) -> bool {
    r.cause.is_some()
        && status::class(&r.completeness, r.reason.as_deref(), r.cause.as_deref()) == Some("failed")
}

/// Is this Mac watched, and how: from the latest readings, `live` and when a watcher last
/// read. `not_checked` before any reading of this Mac; `watched_in_part` when a reading of its
/// own places failed, that is, they are there and could not be read; else `watched`.
pub fn this_mac(conn: &Connection, latest: &[Latest], live: bool) -> rusqlite::Result<ThisMac> {
    let this = this_machine(conn)?;
    let checked_at = status::latest_finished(conn)?.and_then(|r| r.finished_at);
    let live_read_at = crate::watch::last_read(conn)?;
    let Some(this) = this else {
        return Ok(ThisMac {
            checked_at,
            live_read_at,
            ..ThisMac::unchecked(live)
        });
    };
    let mine: Vec<&Latest> = latest
        .iter()
        .filter(|r| on_this_mac(&r.scope, &this))
        .collect();
    let state = if mine.iter().any(|r| failed(r)) {
        "watched_in_part"
    } else {
        "watched"
    };
    let counts = |sql: &str, reader: &str| -> rusqlite::Result<BTreeMap<String, i64>> {
        conn.prepare(sql)?
            .query_map([reader], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect()
    };
    let files = counts(
        "SELECT object, COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as' GROUP BY object",
        watched::READER,
    )?;
    let installed = counts(
        "SELECT kind, COUNT(DISTINCT subject) FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND predicate = 'has_digest' GROUP BY kind",
        integrity::READER,
    )?;
    // Installed software is listed once it has been read here: a watcher alone, before any
    // full run, reads only the watched places, which every reading of this Mac reads.
    let installed_read = mine.iter().any(|r| r.reader == integrity::READER);
    // Packages of the projects on this Mac, once their lockfiles have been read.
    let in_checkout = format!("checkout:{this}/%");
    let dependencies: Option<i64> = if latest
        .iter()
        .any(|r| r.reader == crate::lockfiles::READER && r.scope.starts_with("checkout:"))
    {
        Some(conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'part_of' AND scope LIKE ?2",
            params![crate::lockfiles::READER, in_checkout],
            |r| r.get(0),
        )?)
    } else {
        None
    };
    // A kind with nothing to watch on this Mac has no count and is left out.
    let mut watched: Vec<(&'static str, i64, &'static str)> = watched()
        .into_iter()
        .filter_map(|(count, what, fast)| {
            let n = match count {
                Count::Files(as_) => files.get(as_),
                Count::Installed(kind) if installed_read => installed.get(kind),
                Count::Installed(_) => return None,
                Count::Dependencies => dependencies.as_ref().filter(|n| **n > 0),
            };
            let how = if live && fast { "live" } else { "hourly" };
            Some((what, *n?, how))
        })
        .collect();
    // Running programs are sampled only while a watcher runs.
    if live && let Some(n) = crate::processes::last_sampled(conn)? {
        watched.push((SAMPLED, n, "sampled"));
    }
    Ok(ThisMac {
        state,
        live,
        checked_at,
        live_read_at,
        watched,
        failed: Vec::new(),
    })
}

/// What has failed in the watcher, in words: "reading of the watched places and sample of
/// running programs". The reasons are text from the failures and are not in it.
pub fn watcher_failed(m: &ThisMac) -> String {
    let words: Vec<&str> = m
        .failed
        .iter()
        .map(|f| crate::watch::failed_words(&f.what))
        .collect();
    words.join(" and ")
}

pub fn this_mac_json(m: &ThisMac) -> Value {
    let iso = |t: Option<i64>| t.map(crate::view::iso);
    let watched: Vec<Value> = m
        .watched
        .iter()
        .map(|(what, count, how)| json!({ "what": what, "count": count, "how": how }))
        .collect();
    json!({
        "state": m.state,
        "live": m.live,
        "checked_at": iso(m.checked_at),
        "live_read_at": iso(m.live_read_at),
        "watched": watched,
    })
}

/// Who can do something about a thing that is not covered: the owner, or nobody, because it
/// is a limit of this version or passes by itself. Its words say which.
pub const YOU: &str = "you";
pub const NOTHING: &str = "nothing";

/// The fixed words of one cause of what is not covered, for a person: plain words, what it
/// means for him, and whether he can do something about it. A title is given for one and
/// for many. In the words `{n}` is the count, `{examples}` the first examples and `{all}` every
/// one, as a list.
pub struct Cause {
    pub id: &'static str,
    pub who: &'static str,
    /// Where it is, unless the item says otherwise.
    pub scope: &'static str,
    /// What it is in a few words, for the report line.
    pub kind: &'static str,
    pub title: [&'static str; 2],
    pub meaning: &'static str,
    /// What it means when the count is none, where that is said otherwise.
    pub meaning_none: Option<&'static str>,
    pub advice: &'static str,
}

pub const SERVERS_NOT_CHECKED: Cause = Cause {
    id: "servers-not-checked",
    who: YOU,
    scope: "servers",
    kind: "servers not checked last time",
    title: [
        "{n} of your servers was not checked last time.",
        "{n} of your servers were not checked last time.",
    ],
    meaning: "Servers are checked only when you run the server check yourself. The last one did not finish on these, so changes on them go unseen for now.",
    meaning_none: None,
    advice: "Run the server check again when it suits you.",
};

pub const SERVERS_NOT_OPENED: Cause = Cause {
    id: "servers-not-opened",
    who: YOU,
    scope: "servers",
    kind: "servers that could not be opened",
    title: [
        "{n} server could not be opened at the last server check.",
        "{n} servers could not be opened at the last server check.",
    ],
    meaning: "A server that refuses or does not answer cannot be checked; the reason is listed with each one.",
    meaning_none: None,
    advice: "If you still use them, check that you can log in to them yourself and run the server check again. If one is no longer yours, mark it as retired.",
};

pub const NOT_PERMITTED: Cause = Cause {
    id: "not-permitted",
    who: YOU,
    scope: "this_mac",
    kind: "files their permissions keep closed",
    title: [
        "{n} file could not be opened because of its permissions.",
        "{n} files could not be opened because of their permissions.",
    ],
    meaning: "Their permissions do not let this program open them, so a change in them goes unseen. Where they are and the reason are listed with them.",
    meaning_none: None,
    advice: "If they are yours, make them readable for your user account again; your agent can tell you how.",
};

pub const READING_FAILED: Cause = Cause {
    id: "could-not-read",
    who: NOTHING,
    scope: "this_mac",
    kind: "things that could not be read",
    title: [
        "{n} thing could not be read at the last check.",
        "{n} things could not be read at the last check.",
    ],
    meaning: "Changes in them go unseen until they can be read again. Where they are and the reason are listed with them.",
    meaning_none: None,
    advice: "Nothing to do for now: they are tried again at every check. If one stays, your agent can find out why.",
};

pub const TAILNET_OFF: Cause = Cause {
    id: "tailnet-switched-off",
    who: NOTHING,
    scope: "servers",
    kind: "tailnet not looked at while Tailscale is switched off",
    title: [
        "Tailscale is switched off on this Mac, so your tailnet was not looked at since {date}.",
        "Tailscale is switched off on this Mac, so your tailnet was not looked at since {date}.",
    ],
    meaning: "Devices known from your tailnet on that date are kept as they were, but a new one, or one that is gone, is not seen until Tailscale is on again.",
    meaning_none: None,
    advice: "Nothing to do if you switched it off yourself. Your tailnet is looked at again at the first check after Tailscale connects.",
};

pub const TAILNET_NEEDS_YOU: Cause = Cause {
    id: "tailnet-not-connected",
    who: YOU,
    scope: "servers",
    kind: "tailnet not looked at while Tailscale waits for the owner",
    title: [
        "Tailscale on this Mac is not connected, so your tailnet was not looked at since {date}.",
        "Tailscale on this Mac is not connected, so your tailnet was not looked at since {date}.",
    ],
    meaning: "Why: {reasons}. Devices known from your tailnet on that date are kept as they were, but a new one, or one that is gone, is not seen until Tailscale connects.",
    meaning_none: None,
    advice: "Open Tailscale and do what it asks: log in, ask an admin of your tailnet to approve this Mac, or switch it to your own account.",
};

pub const GUARDED: Cause = Cause {
    id: "protected-folders",
    who: NOTHING,
    scope: "projects",
    kind: "what is in folders macOS protects",
    title: [
        "{what} inside {examples} are not checked.",
        "{what} inside {examples} are not checked.",
    ],
    meaning: "This version does not look inside them: macOS asks for your permission before a program may, and this version does not ask. If nothing of these is kept there, nothing is missed.",
    meaning_none: None,
    advice: "Nothing to do for now. Including them from the app comes in a later version.",
};

pub const NOT_UNDERSTOOD: Cause = Cause {
    id: "not-understood",
    who: NOTHING,
    scope: "projects",
    kind: "files this version does not understand yet",
    title: [
        "Some files and packages are not understood by this version yet.",
        "Some files and packages are not understood by this version yet.",
    ],
    meaning: "They tell what your projects or servers depend on, for example {examples}. A change in them is not noticed yet.",
    meaning_none: None,
    advice: "Nothing to do. Support for them comes in later versions.",
};

pub const OTHER_MANAGERS: Cause = Cause {
    id: "package-managers-not-read",
    who: NOTHING,
    scope: "this_mac",
    kind: "software installed by package managers this version does not read",
    title: [
        "Software installed with {all} is not checked by this version.",
        "Software installed with {all} is not checked by this version.",
    ],
    meaning: "This version checks applications, what Homebrew installed in /opt/homebrew or /usr/local, and the npm packages installed globally in /opt/homebrew/lib/node_modules or /usr/local/lib/node_modules. It does not read what these installed, so a change in it goes unseen.",
    meaning_none: None,
    advice: "Nothing to do. This is a limit of this version.",
};

pub const TOOL_LOST: Cause = Cause {
    id: "read-before-not-found",
    who: NOTHING,
    scope: "this_mac",
    kind: "tools read before and not found now",
    title: [
        "{what} was read before and is not found now, so it was not looked at since {date}.",
        "{what} were read before and are not found now, so they were not looked at since {date}.",
    ],
    meaning: "An earlier check read it, and this version looks for it only where its installer puts it by default: {reasons}. What was known from it is kept as it was and nothing of it is said to be gone, but a change in it is not seen.",
    meaning_none: None,
    advice: "Nothing to do if it is installed somewhere else on purpose: this version does not look there. It is read again at the first check that finds it at one of these places.",
};

pub const MANAGERS_ELSEWHERE: Cause = Cause {
    id: "package-managers-elsewhere-not-found",
    who: NOTHING,
    scope: "this_mac",
    kind: "software of other package managers, and tools installed at other places",
    title: [
        "Software installed by a package manager other than Homebrew and npm is not checked.",
        "Software installed by a package manager other than Homebrew and npm is not checked.",
    ],
    meaning: "This version reads what Homebrew installed and the npm packages installed globally in /opt/homebrew/lib/node_modules or /usr/local/lib/node_modules. Software from any other package manager is not checked, and only the few managers this version looks for are named when found, so a manager not named may still be here. Homebrew, Tailscale and those few are looked for only where their installers put them by default, the same on every Mac, and one installed elsewhere is not found.",
    meaning_none: None,
    advice: "Nothing to do. This is a limit of this version.",
};

pub const PROJECT_AUTORUN: Cause = Cause {
    id: "project-autorun",
    who: NOTHING,
    scope: "projects",
    kind: "ways a project runs code by itself that are not read",
    title: [
        "This version reads {read} of the {known} known ways a project can make code run by itself.",
        "This version reads {read} of the {known} known ways a project can make code run by itself.",
    ],
    meaning: "{n} of the others are present in your projects and are not read, so a change in them would go unseen.",
    meaning_none: Some("None of the others is present in your projects now."),
    advice: "Nothing to do. This is a limit of this version; the page lists every way and whether it is read.",
};

pub const HOME_AUTORUN: Cause = Cause {
    id: "home-autorun",
    who: NOTHING,
    scope: "this_mac",
    kind: "places in the home folder where a tool's settings run code by itself that are not read",
    title: [
        "This version reads {read} of the {known} known places where a developer tool's own settings can make code run by itself.",
        "This version reads {read} of the {known} known places where a developer tool's own settings can make code run by itself.",
    ],
    meaning: "{n} of the others are present on this Mac and are not read, so a change in them would go unseen.",
    meaning_none: Some("None of the others is present on this Mac now."),
    advice: "Nothing to do. This is a limit of this version; the page lists every place and whether it is read.",
};

pub const THREATS_UNREAD: Cause = Cause {
    id: "vulnerability-list-not-downloaded",
    who: NOTHING,
    scope: "threats",
    kind: "vulnerability list not downloaded",
    title: [
        "The list of vulnerabilities attackers are using could not be downloaded since {date}.",
        "The list of vulnerabilities attackers are using could not be downloaded since {date}.",
    ],
    meaning: "Why: {reasons}. Until it is downloaded, a vulnerability attackers start using after that date is not announced. The download uses a proxy only when the environment names one; it does not read the macOS proxy settings.",
    meaning_none: None,
    advice: "Nothing to do if this Mac was offline: it is tried again at every check. If it stays while the Mac is online, ask your agent to look at why.",
};

pub const THREATS_FIXABLE: Cause = Cause {
    id: "vulnerability-list-not-downloaded-fixable",
    who: YOU,
    scope: "threats",
    kind: "vulnerability list not downloaded for a cause on this Mac or its network",
    title: [
        "The list of vulnerabilities attackers are using could not be downloaded since {date}, for a cause on this Mac or its network.",
        "The list of vulnerabilities attackers are using could not be downloaded since {date}, for a cause on this Mac or its network.",
    ],
    meaning: "Why: {reasons}. Until it is downloaded, a vulnerability attackers start using after that date is not announced.",
    meaning_none: None,
    advice: "Fix what the reason names: free space on this Mac's disk, set its clock right, or give the proxy the password it asks for. If the clock is right and the network inspects encrypted traffic, ask whoever runs it to let this Mac reach www.cisa.gov over HTTPS.",
};

pub const VULNERABILITIES_UNKNOWN: Cause = Cause {
    id: "vulnerabilities-unknown",
    who: NOTHING,
    scope: "projects",
    kind: "packages whose known vulnerabilities cannot be told",
    title: [
        "For {n} of the packages your projects use, this version cannot tell whether a known vulnerability affects them.",
        "For {n} of the packages your projects use, this version cannot tell whether a known vulnerability affects them.",
    ],
    meaning: "Why, with how many packages each: {reasons}.",
    meaning_none: None,
    advice: "Nothing to do. This is a limit of this version.",
};

pub const VULNERABILITY_DATA_OLD: Cause = Cause {
    id: "vulnerability-data-old",
    who: NOTHING,
    scope: "threats",
    kind: "list of known vulnerabilities not current",
    title: [
        "The list of known vulnerabilities could not be updated since {date}.",
        "The list of known vulnerabilities could not be updated since {date}.",
    ],
    meaning: "Why: {reasons}. It is downloaded again at every check. Until it is, a vulnerability published after that date is not known here. The download uses a proxy only when the environment names one; it does not read the macOS proxy settings.",
    meaning_none: None,
    advice: "Nothing to do if this Mac was offline. If it stays while the Mac is online, ask your agent to look at why.",
};

pub const VULNERABILITY_DATA_FIXABLE: Cause = Cause {
    id: "vulnerability-data-not-updated-fixable",
    who: YOU,
    scope: "threats",
    kind: "list of known vulnerabilities not updated for a cause on this Mac or its network",
    title: [
        "The list of known vulnerabilities could not be updated since {date}, for a cause on this Mac or its network.",
        "The list of known vulnerabilities could not be updated since {date}, for a cause on this Mac or its network.",
    ],
    meaning: "Why: {reasons}. It is downloaded again at every check. Until it is, a vulnerability published after that date is not known here.",
    meaning_none: None,
    advice: "Fix what the reason names: free space on this Mac's disk, set its clock right, or give the proxy the password it asks for. If the clock is right and the network inspects encrypted traffic, ask whoever runs it to let this Mac reach osv-vulnerabilities.storage.googleapis.com over HTTPS.",
};

pub const NOT_COMPARED: Cause = Cause {
    id: "vulnerabilities-not-compared",
    who: NOTHING,
    scope: "threats",
    kind: "vulnerabilities not yet compared with installed software and servers",
    title: [
        "Known vulnerabilities are not yet compared with your installed software, your servers or projects of other kinds.",
        "Known vulnerabilities are not yet compared with your installed software, your servers or projects of other kinds.",
    ],
    meaning: "The packages your projects list in package-lock.json, pnpm-lock.yaml and Cargo.lock are compared. Applications, Homebrew packages, what your servers run, and projects in other languages are not yet, so this version does not tell you which vulnerabilities affect them.",
    meaning_none: None,
    advice: "Nothing to do. This comes in a later version.",
};

pub const EVENTS_OFF: Cause = Cause {
    id: "program-starts-not-seen",
    who: YOU,
    scope: "this_mac",
    kind: "program starts not seen",
    title: [
        "Program starts on this Mac are not seen.",
        "Program starts on this Mac are not seen.",
    ],
    meaning: "Seeing every program start as it happens, with its command line, needs the event level: Apple's eslogger, run as administrator. Without it, running programs are looked at only in samples while the app is open, and a program that starts and ends between two samples goes unseen.",
    meaning_none: None,
    advice: "If you want it, give /usr/bin/eslogger Full Disk Access in System Settings, Privacy & Security, and run the event level's install command once with your administrator password; your agent can prepare it.",
};

pub const EVENTS_REFUSED: Cause = Cause {
    id: "eslogger-refused",
    who: YOU,
    scope: "this_mac",
    kind: "eslogger refused Full Disk Access",
    title: [
        "Program starts are not seen: macOS refuses eslogger Full Disk Access.",
        "Program starts are not seen: macOS refuses eslogger Full Disk Access.",
    ],
    meaning: "The event level is installed, but macOS does not let Apple's eslogger run, so no program start is recorded. What eslogger said is listed with it.",
    meaning_none: None,
    advice: "Open System Settings, Privacy & Security, Full Disk Access, and turn on eslogger. If it is not in the list, add /usr/bin/eslogger with the plus button and Command-Shift-G.",
};

pub const EVENTS_FAILING: Cause = Cause {
    id: "event-level-failing",
    who: YOU,
    scope: "this_mac",
    kind: "event level stopped with an error",
    title: [
        "Program starts are not seen: the event level stopped with an error.",
        "Program starts are not seen: the event level stopped with an error.",
    ],
    meaning: "The event level is installed, but it printed an error after the last program start it wrote, so program starts are not being recorded. What it said is listed with it.",
    meaning_none: None,
    advice: "Ask your agent to look at what it said. Running the event level's install command again may help.",
};

pub const EVENTS_SILENT: Cause = Cause {
    id: "event-level-silent",
    who: YOU,
    scope: "this_mac",
    kind: "event level silent",
    title: [
        "Program starts are not seen: the event level has written nothing since {date}.",
        "Program starts are not seen: the event level has written nothing since {date}.",
    ],
    meaning: "It is installed, but its log has not been written to for longer than a Mac that is awake allows, so program starts are not being recorded.",
    meaning_none: None,
    advice: "If it stays, ask your agent to look at why. Running the event level's install command again may help.",
};

pub const FILES_NOT_COLLECTED: Cause = Cause {
    id: "file-events-not-seen",
    who: YOU,
    scope: "this_mac",
    kind: "files created and renamed not seen",
    title: [
        "Files created and renamed on this Mac are not seen.",
        "Files created and renamed on this Mac are not seen.",
    ],
    meaning: "The event level records program starts, but the collector installed here was set up by an earlier version or replaced since, so it does not record files created or renamed. The published rules that look for files appearing in places attackers use do not watch until it does.",
    meaning_none: None,
    advice: "Run the event level's install command again with your administrator password; it keeps the log and adds file events. Your agent can prepare it.",
};

pub const PERSISTENCE_NOT_READ: Cause = Cause {
    id: "persistence-not-read",
    who: NOTHING,
    scope: "this_mac",
    kind: "places where something can be set to start by itself that are not read",
    title: [
        "Some places where something can be set to start by itself on this Mac are not checked.",
        "Some places where something can be set to start by itself on this Mac are not checked.",
    ],
    meaning: "Login items and background items, scheduled commands, the list of who may act as the administrator, and login scripts kept in the administrator's own settings open only with permissions this app does not ask for. Login scripts set in ByHost preferences, kept for one Mac, or in Managed Preferences, which a device management profile writes, are not read in this version. Jobs started with no file on disk, and the apps reopened at login, which change at every logout, have nothing to compare against. A change in any of them goes unseen.",
    meaning_none: None,
    advice: "Nothing to do. This is a limit of this version.",
};

/// Every cause, in the order items are listed: what the owner can fix first.
pub const CAUSES: [&Cause; 25] = [
    &SERVERS_NOT_CHECKED,
    &SERVERS_NOT_OPENED,
    &NOT_PERMITTED,
    &READING_FAILED,
    &EVENTS_OFF,
    &EVENTS_REFUSED,
    &EVENTS_FAILING,
    &EVENTS_SILENT,
    &FILES_NOT_COLLECTED,
    &TAILNET_OFF,
    &TAILNET_NEEDS_YOU,
    &TOOL_LOST,
    &GUARDED,
    &NOT_UNDERSTOOD,
    &OTHER_MANAGERS,
    &MANAGERS_ELSEWHERE,
    &PROJECT_AUTORUN,
    &HOME_AUTORUN,
    &THREATS_UNREAD,
    &THREATS_FIXABLE,
    &VULNERABILITY_DATA_OLD,
    &VULNERABILITY_DATA_FIXABLE,
    &VULNERABILITIES_UNKNOWN,
    // The limits of this version, `LIMITS`, last.
    &PERSISTENCE_NOT_READ,
    &NOT_COMPARED,
];

/// Each sentence of `status::CANNOT_JUDGE`, told for a person, one for one: the builder who
/// closes a gap deletes the sentence and its line here, and the item goes with them.
pub const LIMITS: [(&str, &Cause); 3] = [
    (crate::status::PERSISTENCE_UNREAD, &PERSISTENCE_NOT_READ),
    (
        "no vulnerability is matched against installed software, servers' packages or ecosystems other than npm and crates.io yet",
        &NOT_COMPARED,
    ),
    (status::OTHER_MANAGERS, &MANAGERS_ELSEWHERE),
];

/// The scopes of what is not covered.
pub const SCOPES: [&str; 4] = ["this_mac", "projects", "servers", "threats"];

/// One thing not covered: one per cause, never one per machine or per file.
pub struct Uncovered {
    pub scope: &'static str,
    pub cause: &'static Cause,
    pub count: usize,
    /// When it is counted from: the last server check for servers not checked, the first
    /// failed visit for servers that could not be opened, the last download of the list of
    /// vulnerabilities, else the latest reading that found it.
    pub since: Option<i64>,
    pub value: Option<String>,
    pub examples: Vec<String>,
    /// Why, clause by clause in the program's words, where the words say `{reasons}`.
    pub reasons: Vec<String>,
    /// What it is, each in a few words, where the words say `{what}`: a list that begins
    /// the sentence.
    pub what: Vec<&'static str>,
}

impl Uncovered {
    fn new(cause: &'static Cause, count: usize) -> Uncovered {
        Uncovered {
            scope: cause.scope,
            cause,
            count,
            since: None,
            value: None,
            examples: Vec::new(),
            reasons: Vec::new(),
            what: Vec::new(),
        }
    }

    fn fill(&self, words: &str) -> String {
        let shown: Vec<&str> = self
            .examples
            .iter()
            .take(EXAMPLES)
            .map(String::as_str)
            .collect();
        let date = self
            .since
            .map_or("the first check".to_string(), crate::view::utc);
        let reasons = self.reasons.join("; ");
        let what = listed(&self.what);
        let mut chars = what.chars();
        let what: String = chars
            .next()
            .map(|c| c.to_uppercase().chain(chars).collect())
            .unwrap_or_default();
        let all: Vec<&str> = self.examples.iter().map(String::as_str).collect();
        numbers(words, self.cause)
            .replace("{n}", &self.count.to_string())
            .replace("{examples}", &listed(&shown))
            .replace("{all}", &listed(&all))
            .replace("{date}", &date)
            .replace("{reasons}", &reasons)
            .replace("{what}", &what)
    }

    pub fn title(&self) -> String {
        self.fill(self.cause.title[usize::from(self.count != 1)])
    }

    pub fn meaning(&self) -> String {
        match self.cause.meaning_none {
            Some(none) if self.count == 0 => self.fill(none),
            _ => self.fill(self.cause.meaning),
        }
    }

    /// What is told apart from the words: the examples, unless the words name them, and the
    /// value.
    pub fn apart(&self) -> Vec<&str> {
        let named = ["{examples}", "{all}"]
            .iter()
            .any(|p| self.cause.title[1].contains(p) || self.cause.meaning.contains(p));
        let mut out: Vec<&str> = Vec::new();
        if !named {
            out.extend(self.examples.iter().map(String::as_str));
        }
        out.extend(self.value.as_deref());
        out
    }
}

/// Words with the numbers of this build filled in: how many known ways a project runs code by
/// itself are read, and how many are known; for the home folder's item, its places.
fn numbers(words: &str, cause: &Cause) -> String {
    let (read, known) = autorun::counts(cause.id == HOME_AUTORUN.id);
    words
        .replace("{read}", &read.to_string())
        .replace("{known}", &known.to_string())
}

/// `a`, `a and b`, `a, b and c`.
pub fn listed(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Where a reading's scope belongs, for a person.
fn scope_of(scope: &str, this: Option<&str>) -> &'static str {
    if this.is_some_and(|t| on_this_mac(scope, t)) {
        "this_mac"
    } else if scope.starts_with("checkout:") {
        "projects"
    } else {
        "servers"
    }
}

/// Whether a reading failed because of permissions, which the owner can change. Readers keep
/// the system's error as the reason, and Rust writes an error from the system with its
/// number: EPERM is 1 and EACCES is 13 on macOS and on Linux (errno.h).
fn not_permitted(reason: Option<&str>) -> bool {
    reason.is_some_and(|r| r.contains("(os error 13)") || r.contains("(os error 1)"))
}

/// The first of `SCOPES` among some readings' scopes.
fn first_scope<'a>(scopes: impl Iterator<Item = &'a str>, this: Option<&str>) -> &'static str {
    let found: BTreeSet<&str> = scopes.map(|s| scope_of(s, this)).collect();
    SCOPES
        .into_iter()
        .find(|s| found.contains(s))
        .unwrap_or("this_mac")
}

/// `place: reason`, or the place alone.
fn with_reason(place: String, reason: Option<&str>) -> String {
    match reason {
        Some(r) => format!("{place}: {r}"),
        None => place,
    }
}

/// What the program does not cover, one item per cause, in the order of `CAUSES`: what the
/// owner can fix first.
pub fn not_covered(
    conn: &Connection,
    latest: &[Latest],
    p: &Problems,
    catalogue: Option<&Catalogue>,
) -> rusqlite::Result<Vec<Uncovered>> {
    let mac = findings::This::of(conn, this_machine(conn)?)?;
    let this = mac.as_ref().map(|m| m.id.as_str());
    let place = |s: &str| findings::place(s, mac.as_ref());
    let mut out = Vec::new();

    // Servers: those the last server check did not finish on, and apart, those it could not
    // open, each with its reason.
    let last_sweep = latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .map(|r| r.at)
        .max();
    let (unfinished, unopened): (Vec<_>, Vec<_>) = p
        .unreached
        .iter()
        .partition(|u| u.reason.as_deref() == Some(servers::NOT_COMPLETE));
    if !unfinished.is_empty() {
        out.push(Uncovered {
            since: last_sweep,
            examples: unfinished.iter().map(|u| place(&u.scope)).collect(),
            ..Uncovered::new(&SERVERS_NOT_CHECKED, unfinished.len())
        });
    }
    if !unopened.is_empty() {
        out.push(Uncovered {
            since: unopened.iter().map(|u| u.since).min(),
            examples: unopened
                .iter()
                .map(|u| with_reason(place(&u.scope), u.reason.as_deref()))
                .collect(),
            ..Uncovered::new(&SERVERS_NOT_OPENED, unopened.len())
        });
    }

    // Readings that failed: those kept closed by permissions, which the owner can open, and
    // the rest. On a server that could not be opened they are implied by it and told there.
    let away: BTreeSet<&str> = p.unreached.iter().map(|u| u.scope.as_str()).collect();
    let (closed, other): (Vec<&Latest>, Vec<&Latest>) = latest
        .iter()
        .filter(|r| failed(r))
        .filter(|r| !(r.reader == servers::READER && away.contains(r.scope.as_str())))
        .partition(|r| not_permitted(r.reason.as_deref()));
    for (cause, list) in [(&NOT_PERMITTED, closed), (&READING_FAILED, other)] {
        if list.is_empty() {
            continue;
        }
        let mut examples: Vec<String> = Vec::new();
        for r in &list {
            let e = with_reason(place(&r.scope), r.reason.as_deref());
            if !examples.contains(&e) {
                examples.push(e);
            }
        }
        out.push(Uncovered {
            scope: first_scope(list.iter().map(|r| r.scope.as_str()), this),
            since: list.iter().map(|r| r.at).max(),
            examples,
            ..Uncovered::new(cause, list.len())
        });
    }

    // The event level, as its latest reading left it: not installed, or installed and not
    // recording, each with its own words. A reading of it that failed is among the readings
    // that failed above.
    if let Some(l) = crate::events::level(conn, crate::now_secs())? {
        let cause = match l.state.as_str() {
            crate::events::NOT_INSTALLED => Some(&EVENTS_OFF),
            crate::events::REFUSED => Some(&EVENTS_REFUSED),
            crate::events::FAILING => Some(&EVENTS_FAILING),
            crate::events::SILENT => Some(&EVENTS_SILENT),
            _ => None,
        };
        if let Some(cause) = cause {
            out.push(Uncovered {
                // Silent since the last write; else since the reading that found it so.
                since: if l.state == crate::events::SILENT {
                    l.written
                } else {
                    Some(l.read_at)
                },
                // Read cut (`events::level`), as every reader of it reads it.
                value: l
                    .said
                    .as_ref()
                    .map(|s| s.shown(str::to_string))
                    .filter(|s| !s.is_empty()),
                ..Uncovered::new(cause, 1)
            });
        }
        // Recording program starts, not files: the rules for files do not watch.
        if l.state == crate::events::RUNNING && !l.files.collected {
            out.push(Uncovered {
                since: Some(l.read_at),
                ..Uncovered::new(&FILES_NOT_COLLECTED, 1)
            });
        }
    }

    // Tailscale that is not connected, as its latest reading left it, since the tailnet was
    // last read in full. A state not readable this time is a reading that failed, above.
    if let Some((r, t)) = latest
        .iter()
        .filter(|r| r.reader == crate::tailnet::READER)
        .find_map(|r| Some((r, crate::tailnet::told(r.reason.as_deref()?)?)))
        .filter(|(_, t)| !t.retry)
    {
        out.push(Uncovered {
            since: r.last_full,
            reasons: vec![t.reason.to_string()],
            ..Uncovered::new(
                if t.yours {
                    &TAILNET_NEEDS_YOU
                } else {
                    &TAILNET_OFF
                },
                1,
            )
        });
    }

    // Tools an earlier check read and this one did not find at the places it looks: one item,
    // since the oldest last full reading of them.
    let lost: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.completeness == "none")
        .filter(|r| {
            r.reason
                .as_deref()
                .is_some_and(|s| s.contains(crate::tools::READ_BEFORE))
        })
        .collect();
    if !lost.is_empty() {
        let mut what: Vec<&'static str> = Vec::new();
        for r in &lost {
            let name = match r.reader.as_str() {
                crate::brew::READER => crate::brew::NAME,
                crate::tailnet::READER => crate::tailnet::NAME,
                _ => continue,
            };
            if !what.contains(&name) {
                what.push(name);
            }
        }
        // The places each was looked for, after its name.
        let reasons: Vec<String> = lost
            .iter()
            .filter_map(|r| r.reason.as_deref()?.split_once(crate::tools::READ_BEFORE))
            .map(|(name, places)| format!("{name} at {places}"))
            .collect();
        let n = what.len();
        if n > 0 {
            out.push(Uncovered {
                since: lost.iter().filter_map(|r| r.last_full).min(),
                reasons,
                what,
                ..Uncovered::new(&TOOL_LOST, n)
            });
        }
    }

    // Folders macOS protects, whichever reader did not look into them, and what each reader
    // looks at, in the order of `GUARDED_WHAT`.
    let mut folders = BTreeSet::new();
    let mut what = BTreeSet::new();
    let mut at = None;
    for r in latest.iter().filter(|r| r.kind == guarded::KIND) {
        let named = not_looked_into(r);
        if !named.is_empty() {
            what.insert(guarded_what(&r.reader));
        }
        folders.extend(named);
        at = at.max(Some(r.at));
    }
    if !folders.is_empty() {
        let what: Vec<&'static str> = what.into_iter().map(|i| GUARDED_WHAT[i].1).collect();
        out.push(Uncovered {
            since: at,
            examples: folders.iter().cloned().collect(),
            scope: if what == ["projects"] {
                GUARDED.scope
            } else {
                "this_mac"
            },
            what,
            ..Uncovered::new(&GUARDED, folders.len())
        });
    }

    // What runs by itself in projects, against the table of every known way: how many this
    // version reads, and how many of the others the latest look at projects found here. Told
    // once projects were looked at.
    let (ways, lacks): (Vec<_>, Vec<_>) = lacks(conn)?
        .into_iter()
        .partition(|(_, what, _)| what == autorun::OTHER_WAY);
    let (in_home, lacks): (Vec<_>, Vec<_>) = lacks
        .into_iter()
        .partition(|(_, what, _)| what == autorun::OTHER_HOME);
    // Package managers on this Mac are told in their own item, below.
    let lacks: Vec<_> = lacks
        .into_iter()
        .filter(|(_, what, _)| what != crate::managers::NO_READER)
        .collect();
    let looked = latest.iter().any(|r| {
        r.reader == watched::READER
            && r.kind == autorun::OTHERS_KIND
            && this.is_some_and(|t| r.scope == t)
    });
    let mut project_autorun = None;
    if looked {
        let names: BTreeSet<&str> = ways.iter().filter_map(|(_, _, n)| n.as_deref()).collect();
        project_autorun = Some(Uncovered {
            since: latest
                .iter()
                .filter(|r| r.kind == autorun::OTHERS_KIND)
                .map(|r| r.at)
                .max(),
            examples: names.iter().map(|n| n.to_string()).collect(),
            ..Uncovered::new(&PROJECT_AUTORUN, names.len())
        });
    }

    // What this version does not understand otherwise, wherever it was found: one item, the
    // kinds counted once each.
    let kinds: BTreeSet<String> = lacks
        .iter()
        .map(|(_, what, name)| plain_lack(what, name.as_deref()))
        .collect();
    if !kinds.is_empty() {
        out.push(Uncovered {
            scope: first_scope(lacks.iter().map(|(s, _, _)| s.as_str()), this),
            examples: names_first(&kinds),
            ..Uncovered::new(&NOT_UNDERSTOOD, kinds.len())
        });
    }
    // Package managers on this Mac that no reader reads, each named, in the order the latest
    // reading found them.
    if let Some(names) = latest
        .iter()
        .filter(|r| r.reader == integrity::READER && r.kind == crate::managers::KIND)
        .find_map(|r| r.reason.as_deref()?.strip_prefix(crate::managers::NOT_READ))
    {
        let names: Vec<String> = names.split(", ").map(str::to_string).collect();
        out.push(Uncovered {
            count: names.len(),
            examples: names,
            ..Uncovered::new(&OTHER_MANAGERS, 0)
        });
    }
    out.extend(project_autorun);
    // The same for the places of the home folder, told once the home folder was looked at.
    let home_read = latest
        .iter()
        .filter(|r| {
            r.reader == watched::READER
                && r.kind == autorun::HOME_OTHERS_KIND
                && this.is_some_and(|t| r.scope == t)
        })
        .map(|r| r.at)
        .max();
    if home_read.is_some() {
        let names: BTreeSet<&str> = in_home
            .iter()
            .filter_map(|(_, _, n)| n.as_deref())
            .collect();
        out.push(Uncovered {
            since: home_read,
            examples: names.iter().map(|n| n.to_string()).collect(),
            ..Uncovered::new(&HOME_AUTORUN, names.len())
        });
    }

    // A download that failed, told with why in a person's words: the network's doing, which
    // the owner can take up, or what passes by itself.
    if let Some(Catalogue::Failed { reason, last, .. }) = catalogue {
        let why = crate::threats::why(reason);
        out.push(Uncovered {
            since: last.map(|(at, _)| at),
            value: Some(reason.clone()),
            reasons: vec![why.said.to_string()],
            ..Uncovered::new(
                if why.yours {
                    &THREATS_FIXABLE
                } else {
                    &THREATS_UNREAD
                },
                1,
            )
        });
    }
    // The vulnerability data, judged as the latest run judged it: current or not, and why not,
    // feed by feed: why its latest download failed, else why what it holds is not current.
    if let Some(run) = status::latest_finished(conn)?
        && let Some(since) = crate::vulnerabilities::stale(conn, run.started_at)?
    {
        let (mut reasons, mut failures, mut yours) = (Vec::new(), Vec::new(), false);
        for f in crate::vulnerabilities::freshness(conn, run.started_at)? {
            let Some(not_current) = f.not_current else {
                continue;
            };
            let failed = crate::osv::last_failure(conn, f.feed.source)?;
            let ecosystem = f.feed.ecosystem;
            match failed {
                Some(reason) => {
                    let why = crate::threats::why(&reason);
                    yours |= why.yours;
                    reasons.push(format!("{ecosystem}: {}", why.said));
                    failures.push(format!("{ecosystem}: {reason}"));
                }
                None => reasons.push(format!("{ecosystem}: {not_current}")),
            }
        }
        out.push(Uncovered {
            since,
            reasons,
            value: (!failures.is_empty()).then(|| failures.join("; ")),
            ..Uncovered::new(
                if yours {
                    &VULNERABILITY_DATA_FIXABLE
                } else {
                    &VULNERABILITY_DATA_OLD
                },
                1,
            )
        });
    }
    // Packages whose answer is "don't know", one count, with each reason and its count. The
    // data not being current is the item above, and here it is the reason for the packages
    // it leaves untold.
    let t = crate::vulnerabilities::totals(conn, crate::now_secs())?;
    if t.packages_unknown > 0 {
        out.push(Uncovered {
            reasons: t
                .packages_by_reason
                .iter()
                .map(|(code, n)| crate::vulnerabilities::reason_said(code, *n))
                .collect(),
            ..Uncovered::new(&VULNERABILITIES_UNKNOWN, t.packages_unknown)
        });
    }
    // One for each sentence of `CANNOT_JUDGE`: a test pins the pairing.
    out.extend(LIMITS.iter().map(|(_, cause)| Uncovered::new(cause, 1)));
    Ok(out)
}

/// Names of files first, `yarn.lock`, then what is said in words, so that a sentence that
/// gives them as examples reads as one.
fn names_first(kinds: &BTreeSet<String>) -> Vec<String> {
    let (named, said): (Vec<String>, Vec<String>) =
        kinds.iter().cloned().partition(|k| !k.contains(' '));
    named.into_iter().chain(said).collect()
}

/// What each reader that can meet a folder macOS protects looks at, as a person names it, in
/// the order the words list them. A reader not named here looks at files.
const GUARDED_WHAT: [(&[&str], &str); 7] = [
    (
        &[
            crate::checkouts::READER,
            crate::agent_folders::READER,
            crate::lockfiles::READER,
        ],
        "projects",
    ),
    (
        &[crate::ssh_config::READER, crate::known_hosts::READER],
        "ssh settings",
    ),
    (&[watched::READER], "watched files"),
    (&[crate::integrity::READER], "installed apps and packages"),
    (&[crate::processes::READER], "programs"),
    (&[crate::brew::READER, crate::tailnet::READER], "tools"),
    (&[], "files"),
];

/// The folders macOS protects that a reading of what a reader did not look into names, as a
/// person names them.
fn not_looked_into(r: &Latest) -> Vec<String> {
    let named = r
        .reason
        .as_deref()
        .and_then(|s| s.strip_prefix(guarded::NOT_LOOKED_INTO))
        .unwrap_or_default();
    named
        .split(", ")
        .filter(|f| !f.is_empty())
        .map(plain_folder)
        .collect()
}

/// The folders macOS protects that the latest readings that find projects did not look into,
/// as a person names them, each once: a project kept there is not found.
pub fn projects_not_looked_into(latest: &[Latest]) -> Vec<String> {
    let folders: BTreeSet<String> = latest
        .iter()
        .filter(|r| r.kind == guarded::KIND && guarded_what(&r.reader) == 0)
        .flat_map(not_looked_into)
        .collect();
    folders.into_iter().collect()
}

/// Where a reader is in `GUARDED_WHAT`.
fn guarded_what(reader: &str) -> usize {
    GUARDED_WHAT
        .iter()
        .position(|(readers, _)| readers.contains(&reader))
        .unwrap_or(GUARDED_WHAT.len() - 1)
}

/// A folder macOS protects, as a person names it.
fn plain_folder(shown: &str) -> String {
    match shown {
        "~/Library/Mobile Documents" => "iCloud Drive".to_string(),
        "~/Library/CloudStorage" => "cloud storage folders".to_string(),
        "~/Library/Containers" | "~/Library/Group Containers" => "other apps' folders".to_string(),
        _ => match shown.strip_prefix("/Volumes/") {
            Some(disk) => format!("the disk {disk}"),
            None => shown.strip_prefix("~/").unwrap_or(shown).to_string(),
        },
    }
}

/// Something this version has no reader for, as a person names it: by its own name where
/// the source gives one, such as `yarn.lock`, else in plain words.
fn plain_lack(what: &str, name: Option<&str>) -> String {
    use crate::{indicators, ssh_config};
    let plain = match what {
        indicators::NO_MATCHER | indicators::NOT_AGAINST => "some kinds of indicator in your list",
        servers::PACKAGE_MANAGER => return format!("{} packages", name.unwrap_or("other")),
        _ if name.is_some() => return name.unwrap_or_default().to_string(),
        watched::HOOKS_ELSEWHERE => "git hooks of projects kept as separate working folders",
        watched::OVER_CAP => "files too large to read",
        ssh_config::MATCH => "Match blocks in your SSH settings",
        ssh_config::INCLUDE_TOKENS | ssh_config::INCLUDE_USER => {
            "Include lines in your SSH settings"
        }
        servers::OTHER_MANAGER => "packages of other package managers on servers",
        servers::CONTAINER_CONTENTS => "software inside containers on servers",
        other => other,
    };
    plain.to_string()
}

/// What the latest readings found this version has no reader for: the scope it was found in,
/// what it is and its name.
fn lacks(conn: &Connection) -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'coverage_lack')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(Vec::new());
    }
    conn.prepare(&format!(
        "{}
         SELECT DISTINCT c.scope, l.what, l.name
         FROM latest c CROSS JOIN coverage_lack l ON l.coverage = c.id
         WHERE c.scope NOT IN (SELECT id FROM gone_entity)",
        crate::store::LATEST
    ))?
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
    .collect()
}

/// The most examples given with one item.
pub const EXAMPLES: usize = 3;

pub fn uncovered_json(u: &Uncovered) -> Value {
    let examples: Vec<Value> = u
        .examples
        .iter()
        .take(EXAMPLES)
        .map(|e| status::text(e))
        .collect();
    json!({
        "id": u.cause.id,
        "who": u.cause.who,
        "scope": u.scope,
        "kind": u.cause.kind,
        "title": u.title(),
        "meaning": u.meaning(),
        "advice": u.cause.advice,
        "count": u.count,
        "since": u.since.map(crate::view::iso),
        "value_text": u.value.as_deref().map(status::text),
        "examples_text": examples,
    })
}

/// Every cause with its words, for an agent to learn what each can say. `{n}`, `{all}` and
/// `{examples}` stand for the count, every example and the first examples of an item, and
/// `{what}` for what it is, as a list.
pub fn causes_json() -> Value {
    Value::Array(
        CAUSES
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "who": c.who,
                    "kind": c.kind,
                    "title": numbers(c.title[1], c),
                    "meaning": c.meaning,
                    "advice": c.advice,
                })
            })
            .collect(),
    )
}

/// What is not covered, for the report line, each by name: what the owner can fix, then
/// the limits of this version. What the program cannot judge here is part of every report.
pub fn clause(list: &[Uncovered]) -> Option<String> {
    let said: Vec<String> = [(YOU, "You can fix"), (NOTHING, "Limits of this version")]
        .into_iter()
        .filter_map(|(who, head)| {
            let kinds: Vec<&str> = list
                .iter()
                .filter(|u| u.cause.who == who)
                .map(|u| u.cause.kind)
                .collect();
            (!kinds.is_empty()).then(|| format!("{head}: {}.", kinds.join(", ")))
        })
        .collect();
    (!said.is_empty()).then(|| said.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reading_kept_closed_by_permissions_is_told_from_one_that_failed_otherwise() {
        // The owner can open a file whose permissions keep it closed; he can do nothing about
        // a source that is not there. The samples are the system's own messages.
        // EPERM is 1, ENOENT 2, EAGAIN 35, EACCES 13 and EIO 5 (sys/errno.h).
        let said = |errno: i32| std::io::Error::from_raw_os_error(errno).to_string();
        for (errno, closed) in [(1, true), (13, true), (2, false), (35, false), (5, false)] {
            assert_eq!(not_permitted(Some(&said(errno))), closed, "{}", said(errno));
        }
        assert!(!not_permitted(None));
    }

    #[test]
    fn what_this_version_does_not_understand_is_named_as_the_owner_knows_it() {
        // "for example software inside containers on servers and yarn.lock" reads as one
        // thing; the names of files come first.
        let kinds: BTreeSet<String> = [
            plain_lack(servers::CONTAINER_CONTENTS, None),
            plain_lack(crate::lockfiles::LOCKFILE_KIND, Some("yarn.lock")),
            plain_lack(servers::PACKAGE_MANAGER, Some("apk")),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            names_first(&kinds),
            [
                "yarn.lock",
                "apk packages",
                "software inside containers on servers"
            ]
        );
    }

    #[test]
    fn every_sentence_this_version_cannot_judge_and_only_those_is_told_to_a_person_as_a_limit() {
        // A gap an agent reads in `cannot_judge` and the owner never sees would be calm the
        // program has not earned; a limit told after its gap was closed would be a false one.
        let told: Vec<&str> = LIMITS.iter().map(|(s, _)| *s).collect();
        assert_eq!(told, status::CANNOT_JUDGE);
        assert!(LIMITS.iter().all(|(_, c)| c.who == NOTHING));
        // An agent learns from the catalogue every item it can meet, a limit's among them.
        assert!(
            LIMITS
                .iter()
                .all(|(_, c)| CAUSES.iter().any(|known| known.id == c.id))
        );
    }
}
