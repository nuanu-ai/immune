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
pub const WATCHED: [(Count, &str, bool); 9] = [
    (Count::Files(watched::AUTOSTART), "startup items", true),
    (Count::Files(watched::PROFILE), "shell startup files", true),
    (Count::Files(watched::SSH), "SSH files", true),
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
    (Count::Installed(integrity::NPM), "npm packages", false),
    (
        Count::Installed(integrity::APP_SUPPORT),
        "app code kept outside the app",
        false,
    ),
];

/// What a watcher samples, in the same words as the other kinds.
pub const SAMPLED: &str = "running programs and their connections";

/// The rules that tell the owner about a change in a kind of watched thing, by its words as
/// `WATCHED` and `SAMPLED` give them. Derived from the rules themselves: a rule speaks about a
/// kind when it fires on what a run reports for a change of that kind. None for words that
/// name no kind.
pub fn rules_about(what: &str) -> Vec<findings::Rule> {
    let places: Vec<&str> = if what == SAMPLED {
        // What a sample of running programs reports for a rule about the programs themselves;
        // a match of an indicator is not about one kind and is told apart.
        vec![crate::processes::DETACHED_INLINE]
    } else {
        match WATCHED.iter().find(|(_, w, _)| *w == what) {
            Some((Count::Files(as_), _, _)) => vec![*as_],
            Some((Count::Installed(kind), _, _)) => integrity::places(kind),
            None => Vec::new(),
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
    for (count, what, _) in WATCHED {
        if m.watched.iter().any(|w| w.0 == what) {
            continue;
        }
        let (reader, kind) = match count {
            Count::Files(as_) if as_ == autorun::RUNS_ON_OPEN => (watched::READER, autorun::KIND),
            Count::Files(as_) => match watched::kinds().into_iter().find(|(w, _)| *w == as_) {
                Some((_, kind)) => (watched::READER, kind),
                None => continue,
            },
            Count::Installed(kind) => (integrity::READER, kind),
        };
        // The reader looked at this Mac at its last reading: for files, any place of its; for
        // installed things, this very kind.
        let ran = latest.iter().any(|r| {
            r.reader == reader
                && r.scope == this
                && (matches!(count, Count::Files(_)) || r.kind == kind)
        });
        let failed_here = latest.iter().any(|r| {
            r.reader == reader
                && r.kind == kind
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

/// Who can do something about a thing that is not covered: the owner, or nobody, because it
/// is a limit of this version or passes by itself. Its words say which.
pub const YOU: &str = "you";
pub const NOTHING: &str = "nothing";

/// The fixed words of one cause of what is not covered, for a person: plain words, what it
/// means for him, and whether he can do something about it. A title is given for one and
/// for many. In the words `{n}` is the count and `{examples}` the examples, as a list.
pub struct Cause {
    pub id: &'static str,
    pub who: &'static str,
    /// Where it is, unless the item says otherwise.
    pub scope: &'static str,
    /// What it is in a few words, for the report line.
    pub kind: &'static str,
    pub title: [&'static str; 2],
    pub meaning: &'static str,
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
    advice: "Nothing to do for now: they are tried again at every check. If one stays, your agent can find out why.",
};

pub const GUARDED: Cause = Cause {
    id: "protected-folders",
    who: NOTHING,
    scope: "projects",
    kind: "projects in folders macOS protects",
    title: [
        "Projects inside {examples} are not checked.",
        "Projects inside {examples} are not checked.",
    ],
    meaning: "macOS asks for permission before a program may look there, and this program does not ask on its own. If you keep no code there, nothing is missed.",
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
    meaning: "They tell what your projects or servers depend on or what runs by itself, for example {examples}. A change in them is not noticed yet.",
    advice: "Nothing to do. Support for them comes in later versions.",
};

pub const THREATS_UNREAD: Cause = Cause {
    id: "vulnerability-list-not-downloaded",
    who: NOTHING,
    scope: "threats",
    kind: "vulnerability list not downloaded",
    title: [
        "The list of vulnerabilities attackers are using could not be downloaded.",
        "The list of vulnerabilities attackers are using could not be downloaded.",
    ],
    meaning: "This is normal when the Mac is offline. Until it is downloaded, new ones go unannounced.",
    advice: "Nothing to do. It is tried again at every check.",
};

pub const NOT_COMPARED: Cause = Cause {
    id: "vulnerabilities-not-compared",
    who: NOTHING,
    scope: "threats",
    kind: "vulnerabilities not yet compared with what you have",
    title: [
        "Known vulnerabilities are not yet compared with what you have installed.",
        "Known vulnerabilities are not yet compared with what you have installed.",
    ],
    meaning: "The list of vulnerabilities attackers are using is downloaded at every check, but this version does not yet tell you which of them affect you.",
    advice: "Nothing to do. This comes in a later version.",
};

/// Every cause, in the order items are listed: what the owner can fix first.
pub const CAUSES: [&Cause; 8] = [
    &SERVERS_NOT_CHECKED,
    &SERVERS_NOT_OPENED,
    &NOT_PERMITTED,
    &READING_FAILED,
    &GUARDED,
    &NOT_UNDERSTOOD,
    &THREATS_UNREAD,
    &NOT_COMPARED,
];

/// Each sentence of `status::CANNOT_JUDGE`, told for a person, one for one: the builder who
/// closes a gap deletes the sentence and its line here, and the item goes with them.
pub const LIMITS: [(&str, &Cause); 1] = [(
    "no vulnerability from the catalogue is matched against the estate yet",
    &NOT_COMPARED,
)];

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
        }
    }

    fn fill(&self, words: &str) -> String {
        let shown: Vec<&str> = self
            .examples
            .iter()
            .take(EXAMPLES)
            .map(String::as_str)
            .collect();
        words
            .replace("{n}", &self.count.to_string())
            .replace("{examples}", &listed(&shown))
    }

    pub fn title(&self) -> String {
        self.fill(self.cause.title[usize::from(self.count != 1)])
    }

    pub fn meaning(&self) -> String {
        self.fill(self.cause.meaning)
    }

    /// What is told apart from the words: the examples, unless the words name them, and the
    /// value.
    pub fn apart(&self) -> Vec<&str> {
        let named =
            self.cause.title[1].contains("{examples}") || self.cause.meaning.contains("{examples}");
        let mut out: Vec<&str> = Vec::new();
        if !named {
            out.extend(self.examples.iter().map(String::as_str));
        }
        out.extend(self.value.as_deref());
        out
    }
}

/// `a`, `a and b`, `a, b and c`.
fn listed(items: &[&str]) -> String {
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
    let this = this_machine(conn)?;
    let this = this.as_deref();
    let place = |s: &str| findings::place(s, this);
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

    // Folders macOS protects, whichever reader did not look into them.
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
                .map(plain_folder),
        );
        at = at.max(Some(r.at));
    }
    if !folders.is_empty() {
        out.push(Uncovered {
            since: at,
            examples: folders.iter().cloned().collect(),
            ..Uncovered::new(&GUARDED, folders.len())
        });
    }

    // What this version does not understand, wherever it was found: one item, the kinds
    // counted once each.
    let lacks = lacks(conn)?;
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

    if let Some(Catalogue::Failed { reason, last, .. }) = catalogue {
        out.push(Uncovered {
            since: last.map(|(at, _)| at),
            value: Some(reason.clone()),
            ..Uncovered::new(&THREATS_UNREAD, 1)
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
    conn.prepare(
        "SELECT DISTINCT c.scope, l.what, l.name
         FROM coverage_lack l JOIN coverage c ON c.id = l.coverage
         WHERE c.id IN (SELECT MAX(id) FROM coverage GROUP BY reader, scope, kind)
           AND c.scope NOT IN (SELECT id FROM gone_entity)",
    )?
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

/// Every cause with its words, for an agent to learn what each can say. `{n}` and
/// `{examples}` stand for the count and the examples of an item.
pub fn causes_json() -> Value {
    Value::Array(
        CAUSES
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "who": c.who,
                    "kind": c.kind,
                    "title": c.title[1],
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
    }
}
