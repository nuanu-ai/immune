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
/// counts it, the words, and whether the watcher sees it within seconds.
const WATCHED: [(Count, &str, bool); 9] = [
    (
        Count::Files(watched::AUTOSTART),
        "programs set to start by themselves",
        true,
    ),
    (Count::Files(watched::PROFILE), "shell profiles", true),
    (Count::Files(watched::SSH), "SSH access files", true),
    (Count::Files(watched::HOOK), "git hooks in projects", true),
    (
        Count::Files(autorun::RUNS_ON_OPEN),
        "editor tasks that run when a project is opened",
        false,
    ),
    (Count::Installed(integrity::BUNDLES), "applications", false),
    (
        Count::Installed(integrity::KEGS),
        "Homebrew packages",
        false,
    ),
    (
        Count::Installed(integrity::NPM),
        "global npm packages",
        false,
    ),
    (
        Count::Installed(integrity::APP_SUPPORT),
        "folders of code applications keep outside their bundle",
        false,
    ),
];

/// What a watcher samples, in the same words as the other kinds.
pub const SAMPLED: &str = "running programs and their connections";

/// How a kind of watched thing is counted: live files of a kind of watched place, or live
/// installed things of a kind of the integrity reader.
#[derive(Clone, Copy)]
enum Count {
    Files(&'static str),
    Installed(&'static str),
}

/// The state of this Mac, as `this_mac` gives it.
pub struct ThisMac {
    /// `watched`, `watched_in_part` or `not_checked`.
    pub state: &'static str,
    /// Whether a watcher runs on the store now.
    pub live: bool,
    /// When the latest full run finished.
    pub checked_at: Option<i64>,
    /// When a watcher last read the watched places.
    pub live_read_at: Option<i64>,
    /// What is watched, its count, and `live`, `hourly` or `sampled`.
    pub watched: Vec<(&'static str, i64, &'static str)>,
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
        }
    }
}

/// The machine the store's readings of this Mac are scoped to: the resolver's, which every
/// full run makes, else the watched places', which a watcher makes.
pub fn this_machine(conn: &Connection) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT scope FROM coverage WHERE reader IN (?1, ?2) AND scope LIKE 'machine:%'
         ORDER BY reader = ?1 DESC, id DESC LIMIT 1",
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
    // A kind with nothing to watch on this Mac has no count and is left out.
    let mut watched: Vec<(&'static str, i64, &'static str)> = WATCHED
        .iter()
        .filter_map(|(count, what, fast)| {
            let n = match count {
                Count::Files(as_) => files.get(*as_),
                Count::Installed(kind) if installed_read => installed.get(*kind),
                Count::Installed(_) => return None,
            };
            let how = if live && *fast { "live" } else { "hourly" };
            Some((*what, *n?, how))
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
    })
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

/// The fixed words of one cause of what is not covered.
pub struct Cause {
    pub id: &'static str,
    pub kind: &'static str,
    pub words: findings::Words,
}

pub const SERVERS_NOT_READ: Cause = Cause {
    id: "servers-not-read",
    kind: "servers not read at the last sweep",
    words: findings::Words {
        title: "Some servers were not read at the last sweep.",
        meaning: "The program reads servers only when you run the sweep by hand, and never connects to them itself; a server whose part of the sweep did not finish was not read, and changes on it go unseen until a sweep reads it.",
        advice: "Run the sweep again when it suits you; nothing here says the servers are switched off.",
    },
};

pub const VISIT_FAILED: Cause = Cause {
    id: "server-visit-failed",
    kind: "server visits that failed",
    words: findings::Words {
        title: "The sweep could not read some servers.",
        meaning: "At the last sweep the visit to them failed for the reason given here; changes on them go unseen until a visit succeeds.",
        advice: "If a server should be reachable, check that you can connect to it, then run the sweep again.",
    },
};

pub const NO_READER: Cause = Cause {
    id: "no-reader",
    kind: "kinds of file this build has no reader for",
    words: findings::Words {
        title: "Some kinds of file found here are not read by this build.",
        meaning: "They are there and this build cannot read them, so a change in them goes unseen; this is a limit of the program, not a fault of yours.",
        advice: "Nothing to do; `soc status --json` names each kind under no_reader_for.",
    },
};

pub const READING_FAILED: Cause = Cause {
    id: "reading-failed",
    kind: "readings that failed",
    words: findings::Words {
        title: "Something could not be read.",
        meaning: "Until it can be read again, changes there go unseen; the cause is often a permission or a file in an unexpected state.",
        advice: "Look at the reason given here, or ask your agent to find out why.",
    },
};

pub const THREATS_UNREAD: Cause = Cause {
    id: "threats-not-downloaded",
    kind: "threat list not downloaded",
    words: findings::Words {
        title: "The list of vulnerabilities that attackers are using could not be downloaded.",
        meaning: "This is normal if this Mac was offline; until it is downloaded, new ones go unannounced.",
        advice: "Nothing to do if you were offline; it is tried again at every run.",
    },
};

pub const GUARDED: Cause = Cause {
    id: "guarded-folders",
    kind: "folders macOS asks permission for",
    words: findings::Words {
        title: "Folders macOS asks permission for were not searched for projects.",
        meaning: "Looking into them would make macOS ask you for permission on behalf of a program running in the background, so it does not; projects already known there stay as they were, and nothing inside them is read.",
        advice: "To read a project kept there, run `soc run --checkouts-root <that folder>` yourself in Terminal; granting the app more access changes nothing in this build.",
    },
};

/// Every cause, for the catalogue.
pub const CAUSES: [Cause; 6] = [
    SERVERS_NOT_READ,
    VISIT_FAILED,
    NO_READER,
    READING_FAILED,
    THREATS_UNREAD,
    GUARDED,
];

/// The scopes of what is not covered, in the order they are listed.
pub const SCOPES: [&str; 4] = ["this_mac", "projects", "servers", "threats"];

/// One thing not covered.
pub struct Uncovered {
    pub id: String,
    pub scope: &'static str,
    pub cause: &'static Cause,
    pub count: usize,
    /// When it is counted from: the last sweep for servers not read, the first failed visit
    /// for visits that failed, the last download of the threat list, else the latest reading
    /// that found it.
    pub since: Option<i64>,
    pub value: Option<String>,
    pub examples: Vec<String>,
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

/// A short id, the same for the same cause and group.
fn id(cause: &Cause, parts: &[&str]) -> String {
    if parts.is_empty() {
        return cause.id.to_string();
    }
    let hex = crate::sha256::hex(parts.join("\n").as_bytes());
    format!("{}-{}", cause.id, &hex[..8])
}

/// What the program does not cover, one item per cause and group, in the order of `SCOPES`.
pub fn not_covered(
    conn: &Connection,
    latest: &[Latest],
    p: &Problems,
    catalogue: Option<&Catalogue>,
) -> rusqlite::Result<Vec<Uncovered>> {
    let this = this_machine(conn)?;
    let this = this.as_deref();
    let place = |s: &str| findings::place(s, this);
    let mut out = Vec::new();

    // Servers: those whose part of the last sweep did not finish, and apart, by reason,
    // those whose visit failed.
    let visits: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .collect();
    let last_sweep = visits.iter().map(|r| r.at).max();
    let (unfinished, failed_visits): (Vec<_>, Vec<_>) = p
        .unreached
        .iter()
        .partition(|u| u.reason.as_deref() == Some(servers::NOT_COMPLETE));
    if !unfinished.is_empty() {
        out.push(Uncovered {
            id: id(&SERVERS_NOT_READ, &[]),
            scope: "servers",
            cause: &SERVERS_NOT_READ,
            count: unfinished.len(),
            since: last_sweep,
            value: Some(format!(
                "{} of {} servers in the last sweep",
                unfinished.len(),
                visits.len()
            )),
            examples: unfinished.iter().map(|u| place(&u.scope)).collect(),
        });
    }
    let mut by_reason: BTreeMap<String, Vec<&status::Unreached>> = BTreeMap::new();
    for u in failed_visits {
        by_reason
            .entry(u.reason.clone().unwrap_or_default())
            .or_default()
            .push(u);
    }
    for (reason, list) in by_reason {
        out.push(Uncovered {
            id: id(&VISIT_FAILED, &[&reason]),
            scope: "servers",
            cause: &VISIT_FAILED,
            count: list.len(),
            since: list.iter().map(|u| u.since).min(),
            value: Some(reason),
            examples: list.iter().map(|u| place(&u.scope)).collect(),
        });
    }

    // Readings that failed, by where and why. On a server that was not reached they are
    // implied by it and told there.
    let away: BTreeSet<&str> = p.unreached.iter().map(|u| u.scope.as_str()).collect();
    let mut groups: BTreeMap<(&str, Option<&str>), Vec<&Latest>> = BTreeMap::new();
    for r in latest.iter().filter(|r| failed(r)) {
        if r.reader == servers::READER && away.contains(r.scope.as_str()) {
            continue;
        }
        groups
            .entry((scope_of(&r.scope, this), r.reason.as_deref()))
            .or_default()
            .push(r);
    }
    for ((scope, reason), list) in groups {
        let mut places: Vec<String> = list.iter().map(|r| place(&r.scope)).collect();
        places.dedup();
        out.push(Uncovered {
            id: id(&READING_FAILED, &[scope, reason.unwrap_or_default()]),
            scope,
            cause: &READING_FAILED,
            count: list.len(),
            since: list.iter().map(|r| r.at).max(),
            value: reason.map(str::to_string),
            examples: places,
        });
    }

    // Kinds of file with no reader, one item per scope with the count of kinds.
    let mut kinds: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (scope, what) in lacks(conn)? {
        kinds
            .entry(scope_of(&scope, this))
            .or_default()
            .insert(what);
    }
    for (scope, list) in kinds {
        out.push(Uncovered {
            id: id(&NO_READER, &[scope]),
            scope,
            cause: &NO_READER,
            count: list.len(),
            since: None,
            value: None,
            examples: list.into_iter().collect(),
        });
    }

    // Folders not looked into, whichever reader did not look.
    let mut folders = BTreeSet::new();
    let mut at = None;
    for r in latest.iter().filter(|r| r.kind == guarded::KIND) {
        let named = r
            .reason
            .as_deref()
            .and_then(|s| s.strip_prefix(guarded::NOT_LOOKED_INTO))
            .unwrap_or_default();
        folders.extend(
            named
                .split(", ")
                .filter(|f| !f.is_empty())
                .map(str::to_string),
        );
        at = at.max(Some(r.at));
    }
    if !folders.is_empty() {
        out.push(Uncovered {
            id: id(&GUARDED, &[]),
            scope: "projects",
            cause: &GUARDED,
            count: folders.len(),
            since: at,
            value: None,
            examples: folders.into_iter().collect(),
        });
    }

    if let Some(Catalogue::Failed { reason, last, .. }) = catalogue {
        out.push(Uncovered {
            id: id(&THREATS_UNREAD, &[]),
            scope: "threats",
            cause: &THREATS_UNREAD,
            count: 1,
            since: last.map(|(at, _)| at),
            value: Some(reason.clone()),
            examples: Vec::new(),
        });
    }
    let rank = |u: &Uncovered| SCOPES.iter().position(|s| *s == u.scope);
    out.sort_by_key(rank);
    Ok(out)
}

/// What the latest readings found this build has no reader for, by the scope it was found in.
fn lacks(conn: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
    let has_table: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'coverage_lack')",
        [],
        |r| r.get(0),
    )?;
    if !has_table {
        return Ok(Vec::new());
    }
    // A kind is what it is with its name, where it has one: `lockfile kind yarn.lock`.
    conn.prepare(
        "SELECT DISTINCT c.scope, l.what || COALESCE(' ' || l.name, '')
         FROM coverage_lack l JOIN coverage c ON c.id = l.coverage
         WHERE c.id IN (SELECT MAX(id) FROM coverage GROUP BY reader, scope, kind)
           AND c.scope NOT IN (SELECT id FROM gone_entity)",
    )?
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
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
        "id": u.id,
        "scope": u.scope,
        "kind": u.cause.kind,
        "title": u.cause.words.title,
        "meaning": u.cause.words.meaning,
        "advice": u.cause.words.advice,
        "count": u.count,
        "since": u.since.map(crate::view::iso),
        "value_text": u.value.as_deref().map(status::text),
        "examples_text": examples,
    })
}

/// Every cause with its words, for an agent to learn what each can say.
pub fn causes_json() -> Value {
    Value::Array(
        CAUSES
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "kind": c.kind,
                    "title": c.words.title,
                    "meaning": c.words.meaning,
                    "advice": c.words.advice,
                })
            })
            .collect(),
    )
}

/// What is not covered, in one clause for the report line: the kinds, each once.
pub fn clause(list: &[Uncovered]) -> Option<String> {
    let mut kinds: Vec<&str> = Vec::new();
    for u in list {
        if !kinds.contains(&u.cause.kind) {
            kinds.push(u.cause.kind);
        }
    }
    (!kinds.is_empty()).then(|| format!("Not covered: {}.", kinds.join(", ")))
}
