//! The programs that startup items run, read at checks only, from the slot the platform defines
//! as the executable (`autorun::Runs`) in the bytes the watched reader hashed in the same run.
//! A target is a watched file of its own kind, `TARGET`, and goes through the lifecycle of
//! watched files (`read_watched` in `main.rs`), with `started_by` naming each item that runs it.
//! What is read, what is counted as not read and what is adopted from the industry is in
//! `docs/reference.md` and `docs/how-it-works.md`.

use crate::autorun::{self, Runs};
use crate::baseline::Unit;
use crate::codesign;
use crate::guarded::{self, Real};
use crate::look::{Absent, Look};
use crate::plist::{self, Text};
use crate::store::{Cause, Gap, Lack, Statement};
use crate::watched::{self, Content, Entry, Roots};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The literal of `watched_as` of a target, and the coverage kind of its reading.
pub const TARGET: &str = "program a startup item runs";
pub const KIND: &str = "programs that launch agents, daemons and login hooks run";
/// Which item runs a target: the target is the subject, the item the object.
pub const BY: &str = "started_by";
/// The rule of a target's content changed while an item names it.
pub const RULE: &str = "watched.startup-target";
/// A target larger than this is not read.
pub const CAP: u64 = 256 << 20;

/// Why a target was not read, or a file not judged, in the reading's words (`coverage`).
const NOT_FULL: &str = "startup programs not named by a full path";
const IN_BUNDLE: &str = "startup programs inside an app bundle (BundleProgram)";
const NOT_FILE: &str = "startup programs that are not a regular file, such as an app named whole";
const GUARDED: &str = "startup programs in a folder macOS asks permission for";
const FAILED: &str = "startup programs that could not be opened";
const ITEMS: &str = "startup items that could not be read, whose programs are kept as last read";
const ARGUMENTS: &str = "files named in startup items' arguments, which are not judged";
/// What the reading names and is no gap in it.
const ELSEWHERE: &str = "startup programs watched as another kind, judged there";
const ABSENT: &str = "startup programs named and not there";
const NOTES: [&str; 2] = [ELSEWHERE, ABSENT];
/// What the reading always says of when it reads.
pub const AT_CHECKS: &str = "programs are read at each check and not between checks";
/// Why a target was read once more and then not read.
pub const MOVED: &str = "it changed while it was read, twice";
/// What a change by the same publisher is told as.
pub const PUBLISHER: &str =
    "an update by its publisher: the same identifier and team, verified at both readings";

/// What a target's content reading says of it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signature {
    pub content: Option<String>,
    pub link: Option<String>,
    pub signed_by: Option<String>,
    pub seal: Option<String>,
}

/// The beginnings of a `codesign::signer` literal that name a publisher Apple vouches for: its
/// own code, or a team it certified. An `other certificate` can say any team.
const VOUCHED: [&str; 3] = ["apple, ", "app store, team ", "developer id, team "];
/// How the identifier follows the signer in `signed_by`.
const IDENTIFIER: &str = ", identifier ";

/// Whether a change of a target is an update by its publisher: the same identifier of the same
/// publisher Apple vouches for, verified at both readings, reached the same way. A name alone
/// never is.
pub fn by_publisher(before: &Signature, after: &Signature) -> bool {
    let vouched = |s: &str| VOUCHED.iter().any(|c| s.starts_with(c)) && s.contains(IDENTIFIER);
    let verified = |s: &Signature| s.seal.as_deref() == Some(codesign::VERIFIES);
    before.signed_by == after.signed_by
        && after.signed_by.as_deref().is_some_and(vouched)
        && before.link == after.link
        && verified(before)
        && verified(after)
}

/// What a check read of the targets, beside the look it hands to the store.
#[derive(Default)]
pub struct Targets {
    /// By its unit, the items that run each target, and what the store held of each target
    /// read and what was read now; a target another kind watches has neither of the last two.
    by: BTreeMap<Unit, BTreeSet<String>>,
    before: BTreeMap<Unit, Signature>,
    after: BTreeMap<Unit, Signature>,
    /// What was not read or not judged, by why.
    counts: BTreeMap<&'static str, usize>,
    /// Rows for the run: the item, and why its target was not read.
    pub rows: Vec<(String, &'static str)>,
}

impl Targets {
    /// The `started_by` statements of a target.
    pub fn by(&self, unit: &Unit, subject: &str, source_ref: &str) -> Vec<Statement> {
        let items = self.by.get(unit).into_iter().flatten();
        items
            .map(|item| Statement {
                subject: subject.to_string(),
                predicate: BY,
                object: item.clone(),
                source_ref: source_ref.to_string(),
            })
            .collect()
    }

    /// The signer and the verdict of a target's code, for its content reading.
    pub fn signature(&self, unit: &Unit, subject: &str, source_ref: &str) -> Vec<Statement> {
        let Some(s) = self.after.get(unit) else {
            return Vec::new();
        };
        [("signed_by", &s.signed_by), ("has_seal", &s.seal)]
            .into_iter()
            .filter_map(|(predicate, v)| {
                Some(Statement {
                    subject: subject.to_string(),
                    predicate,
                    object: v.clone()?,
                    source_ref: source_ref.to_string(),
                })
            })
            .collect()
    }

    /// Whether a target's content is another kind's to read and judge.
    pub fn judged_elsewhere(&self, unit: &Unit) -> bool {
        !self.after.contains_key(unit)
    }

    /// Whether a change seen in a target raises nothing: an update by its publisher.
    pub fn quiet(&self, unit: &Unit) -> bool {
        match (self.before.get(unit), self.after.get(unit)) {
            (Some(b), Some(a)) => by_publisher(b, a),
            _ => false,
        }
    }

    /// The reading's completeness, its reason or note, and its gap: never full while anything
    /// named was not read or not judged. What is in a guarded folder was not given, what could
    /// not be opened or told failed, and the rest has no reader in this build.
    pub fn coverage(&self) -> (&'static str, Option<String>, Gap) {
        let said = (self.counts.iter())
            .map(|(why, n)| format!("{why}: {n}; "))
            .collect::<String>()
            + AT_CHECKS;
        let short: Vec<&str> = (self.counts.keys().copied())
            .filter(|why| !NOTES.contains(why))
            .collect();
        if short.is_empty() {
            return ("full", Some(said), Gap::default());
        }
        let cause = |why: &str| match why {
            GUARDED => Cause::NotGiven,
            FAILED | ITEMS => Cause::Failed,
            _ => Cause::NoReader,
        };
        let lacks = (short.iter().filter(|why| cause(why) == Cause::NoReader))
            .map(|why| Lack::new(why, None))
            .collect();
        let cause = Cause::worst(short.iter().map(|w| cause(w)));
        let reason = format!("not read in full: {said}");
        ("partial", Some(reason), Gap { cause, lacks })
    }

    fn count(&mut self, why: &'static str) {
        *self.counts.entry(why).or_default() += 1;
    }
}

/// How the files of a kind of watched place name a program, where they do.
pub fn runs_of(watched_as: &str) -> Option<Runs> {
    autorun::places()
        .find(|(_, k)| k.0 == watched_as)
        .and_then(|(p, _)| p.runs)
}

/// Whether a program is named by a plain full path, which stays under the root it is read
/// from, `on_disk`: from `/`, with no empty, `.` or `..` part, so no trailing slash either.
fn plain(path: &str) -> bool {
    (path.strip_prefix('/'))
        .is_some_and(|rest| rest.split('/').all(|part| !matches!(part, "" | "." | "..")))
}

fn on_disk(roots: &Roots, path: &str) -> PathBuf {
    roots.system.join(path.trim_start_matches('/'))
}

/// What a file of an item names: the target, or why none is read, and the arguments beside it.
enum Named {
    Path(String),
    NotFull,
    Bundle,
    Nothing,
}

/// What the file of an item names, `part` the key of a login hook. launchd's slot is `Program`,
/// else the first string of `ProgramArguments`. `None` when it cannot be told: not a property
/// list, its top not a dictionary, or text past what this build reads.
fn named_by(runs: Runs, bytes: &[u8], part: &str) -> Option<(Named, Vec<String>)> {
    let keys = match runs {
        Runs::Launchd => vec!["Program", "ProgramArguments", "BundleProgram"],
        Runs::Values(keys) => vec![*keys.iter().find(|k| Some(**k) == part.strip_prefix('/'))?],
    };
    let texts = plist::texts(bytes, &keys).ok()?;
    if texts.iter().any(|(_, t)| *t == Text::Untold) {
        return None;
    }
    let get = |key: &str| texts.iter().find(|(k, _)| *k == key).map(|(_, t)| t);
    if let Runs::Values(_) = runs {
        let named = match texts.first() {
            Some((_, Text::One(p))) => Named::Path(p.clone()),
            _ => Named::NotFull,
        };
        return Some((named, Vec::new()));
    }
    let list = match get("ProgramArguments") {
        Some(Text::List(list)) => list.as_slice(),
        _ => &[],
    };
    let rest = list.iter().skip(1).flatten().cloned().collect();
    let named = match (get("Program"), list.first()) {
        (Some(Text::One(p)), _) | (None, Some(Some(p))) => Named::Path(p.clone()),
        (Some(_), _) | (None, Some(None)) => Named::NotFull,
        (None, None) if get("BundleProgram").is_some() => Named::Bundle,
        (None, None) => Named::Nothing,
    };
    Some((named, rest))
}

/// Reads what the items in `items` name and each target they name; `others` are this run's
/// looks of every kind. An item, or a folder of items, whose program could not be told keeps
/// the targets the store says it named, and is counted.
pub fn read(
    tx: &Transaction,
    machine: &str,
    roots: &Roots,
    items: &[&Look],
    others: &[&Look],
) -> rusqlite::Result<(Look, Targets)> {
    let homes = watched::homes(roots.home);
    let homes = [homes[0].as_path(), homes[1].as_path()];
    let mut t = Targets::default();
    let mut named: BTreeMap<Unit, BTreeSet<String>> = BTreeMap::new();
    let prefix = format!("file:{machine}/");
    let mut unread: BTreeSet<String> = (items.iter().flat_map(|l| l.not_read()))
        .map(|(unit, _)| format!("{prefix}{unit}"))
        .collect();
    for e in items.iter().flat_map(|l| &l.entries) {
        let Some(runs) = runs_of(e.watched_as) else {
            continue;
        };
        let id = format!("{prefix}{}", e.unit);
        let told = match (&e.content, &e.bytes) {
            (_, Some(bytes)) => named_by(runs, bytes, &e.unit.part),
            // Not a file, or a link that leads nowhere: it names nothing.
            (Content::Special(_) | Content::Dangling, None) => Some((Named::Nothing, Vec::new())),
            _ => None,
        };
        let Some((target, arguments)) = told else {
            unread.insert(id);
            continue;
        };
        let not_read = match target {
            Named::Path(p) if plain(&p) => {
                named.entry(Unit::whole(p)).or_default().insert(id);
                None
            }
            Named::Path(_) | Named::NotFull => Some(NOT_FULL),
            Named::Bundle => Some(IN_BUNDLE),
            Named::Nothing => None,
        };
        if let Some(why) = not_read {
            t.count(why);
            t.rows.push((e.unit.to_string(), why));
        }
        // A file an argument names is counted, never read, as is one in a guarded folder.
        for a in arguments.iter().filter(|a| plain(a)) {
            let file = match guarded::real(&on_disk(roots, a), &homes) {
                Real::At(p) => std::fs::metadata(p).is_ok_and(|m| m.is_file()),
                Real::Guarded(_) => true,
                Real::Failed(_) => false,
            };
            if file {
                t.count(ARGUMENTS);
            }
        }
    }
    // What the store says each item not told now ran, or each item a folder not listed hides.
    let mut stmt = tx.prepare(
        "SELECT a.subject, a.object, u.path, u.part FROM assertion a
         JOIN watched_unit u ON u.subject = a.object AND u.scope = a.scope AND u.kind != a.kind
         WHERE a.layer = 'live' AND a.reader = ?1 AND a.scope = ?2 AND a.kind = ?3
           AND a.predicate = ?4",
    )?;
    let held = stmt
        .query_map(params![watched::READER, machine, KIND, BY], |r| {
            let unit = Unit::part(r.get::<_, String>(2)?, r.get::<_, String>(3)?);
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, unit))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (target, item, unit) in held {
        let hidden = items.iter().any(|l| !l.retracts(Some(&unit)));
        if let Some(path) = target.strip_prefix(&prefix)
            && (hidden || unread.contains(&item))
        {
            named.entry(Unit::whole(path)).or_default().insert(item);
        }
    }
    for _ in &unread {
        t.count(ITEMS);
    }
    let mut look = Look::default();
    for (unit, by) in named {
        let id = format!("{prefix}{unit}");
        look.read(unit.clone());
        // A file another kind of this Mac watches keeps its content there (`judged_elsewhere`):
        // every check reads them all, so this run's looks say it.
        let watched = others
            .iter()
            .any(|l| l.entries.iter().any(|e| e.unit == unit));
        let (content, link) = if watched {
            t.count(ELSEWHERE);
            (Content::Unread(Cause::NoReader, ELSEWHERE.into()), None)
        } else {
            let before = previous(tx, &id)?;
            let mut resolve = || guarded::real(&on_disk(roots, &unit.path), &homes);
            let (content, after, why) =
                read_target(&mut resolve, roots, &unit.path, &before, &mut look);
            why.into_iter().for_each(|why| t.count(why));
            let link = after.link.clone();
            t.before.insert(unit.clone(), before);
            t.after.insert(unit.clone(), after);
            (content, link)
        };
        let bytes = None;
        let watched_as = TARGET;
        t.by.insert(unit.clone(), by);
        look.entries.push(Entry {
            unit,
            watched_as,
            content,
            link,
            bytes,
        });
    }
    Ok((look, t))
}

/// What the store holds live of a target's content reading, its verdict only when the latest
/// reading was full: without it nothing is carried and nothing passes for its publisher's.
fn previous(tx: &Transaction, id: &str) -> rusqlite::Result<Signature> {
    let mut s = Signature::default();
    let mut stmt = tx.prepare(
        "SELECT predicate, object FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3",
    )?;
    let reading = params![watched::READER, id, watched::CONTENT];
    for row in stmt.query_map(reading, |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })? {
        let (predicate, object) = row?;
        let slot = match predicate.as_str() {
            "has_content" => &mut s.content,
            "links_to" => &mut s.link,
            "signed_by" => &mut s.signed_by,
            "has_seal" => &mut s.seal,
            _ => continue,
        };
        *slot = Some(object);
    }
    let latest: Option<String> = tx
        .query_row(
            "SELECT completeness FROM coverage WHERE reader = ?1 AND scope = ?2 AND kind = ?3
             ORDER BY id DESC LIMIT 1",
            reading,
            |r| r.get(0),
        )
        .optional()?;
    if latest.as_deref() != Some("full") {
        s.seal = None;
    }
    Ok(s)
}

/// A path the guard made real, as from the Mac's root whatever root it was read under.
fn from_root(system: &Path, real: &Path) -> String {
    let root = std::fs::canonicalize(system).unwrap_or_else(|_| system.to_path_buf());
    match real.strip_prefix(&root) {
        Ok(rest) if root != Path::new("/") => format!("/{}", rest.display()),
        _ => real.display().to_string(),
    }
}

/// Reads one target, which `resolve` makes real with the guard watched files keep, and says the
/// bucket it counts in. The name is made real again and the identity taken again after the
/// read: if either moved it is read once more, then not read. Out of reach: a file swapped
/// during the read with its identity put back, since the signature is asked of a name.
fn read_target(
    resolve: &mut dyn FnMut() -> Real,
    roots: &Roots,
    path: &str,
    before: &Signature,
    look: &mut Look,
) -> (Content, Signature, Option<&'static str>) {
    let not = |content, why| (content, Signature::default(), why);
    for _ in 0..2 {
        let real = match resolve() {
            Real::At(real) => real,
            Real::Guarded(g) => {
                let into = guarded::leads_into(&g, roots.home);
                look.met(g);
                let why = format!("{}{into}", guarded::NOT_LOOKED_INTO);
                return not(Content::Unread(Cause::NotGiven, why), Some(GUARDED));
            }
            // A link that leads nowhere is that; a name with nothing at it is named so.
            Real::Failed(e) if Absent::on_the_way(&e).is_some() => {
                return match std::fs::symlink_metadata(on_disk(roots, path)) {
                    Ok(_) => not(Content::Dangling, None),
                    _ => not(Content::Missing, Some(ABSENT)),
                };
            }
            Real::Failed(e) => {
                return not(Content::Unread(Cause::Failed, e.to_string()), Some(FAILED));
            }
        };
        let shown = from_root(roots.system, &real);
        let link = (shown != path).then_some(shown);
        let read = std::fs::metadata(&real)
            .map_err(|e| Content::Unread(Cause::Failed, e.to_string()))
            .and_then(|meta| Ok((watched::bytes(&real, &meta, CAP)?, meta)));
        let (bytes, meta) = match read {
            Ok(read) => read,
            Err(content @ Content::Special(_)) => return not(content, Some(NOT_FILE)),
            Err(content @ Content::Unread(Cause::NoReader, _)) => {
                return not(content, Some(watched::OVER_CAP));
            }
            Err(content) => return not(content, Some(FAILED)),
        };
        let content = format!("sha256:{}", crate::sha256::hex(&bytes));
        drop(bytes);
        // Carried only for the same content reached the same way; else asked of the code.
        let same = before.content.as_ref() == Some(&content) && before.link == link;
        let (signed_by, seal) = if same && before.seal.is_some() {
            (before.signed_by.clone(), before.seal.clone())
        } else {
            signed(&real)
        };
        if matches!(resolve(), Real::At(again) if again == real) && !moved(&meta, &real) {
            let s = Signature {
                content: Some(content.clone()),
                link,
                signed_by,
                seal,
            };
            return (Content::Hash(content), s, None);
        }
    }
    not(
        Content::Unread(Cause::Failed, MOVED.to_string()),
        Some(FAILED),
    )
}

/// Whether the file at `real` is gone or no longer the one `meta` was taken of: written,
/// replaced, renamed or given another mode since.
fn moved(meta: &std::fs::Metadata, real: &Path) -> bool {
    let id = |m: &std::fs::Metadata| (m.dev(), m.ino(), m.size(), m.ctime(), m.ctime_nsec());
    std::fs::symlink_metadata(real).map_or(true, |m| id(&m) != id(meta))
}

/// Who signed the code at `real`, with its identifier, and whether its own code verifies.
fn signed(real: &Path) -> (Option<String>, Option<String>) {
    match codesign::Code::at(real) {
        Ok(code) => {
            let signer = code.signed().map(|(signer, id)| match id {
                Some(id) => format!("{signer}{IDENTIFIER}{id}"),
                None => signer,
            });
            (signer, Some(code.code()))
        }
        Err(status) => (None, Some(codesign::does_not_verify(status))),
    }
}

/// Adds to each finding of the rule this run raised or saw again the entry that says which
/// items run its program now: the latest of `started_by`, which holds, since a program seen
/// this run is named by a live item. Who signed it and whether its code verified are this
/// run's entries where they changed, which `raise` adds.
pub fn evidence(tx: &Transaction, run_id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO finding_basis (finding, journal)
         SELECT f.id, j.seq FROM finding f
         JOIN journal j ON j.seq = (SELECT MAX(k.seq) FROM journal k
                                    WHERE k.subject = f.about AND k.reader = ?3 AND k.predicate = ?4)
         WHERE f.rule = ?1 AND f.last_seen_run = ?2
           AND NOT EXISTS (SELECT 1 FROM finding_basis b WHERE b.finding = f.id AND b.journal = j.seq)",
        params![RULE, run_id, watched::READER, BY],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(signed_by: &str, seal: &str) -> Signature {
        Signature {
            content: Some("sha256:00".to_string()),
            link: None,
            signed_by: Some(signed_by.to_string()),
            seal: Some(seal.to_string()),
        }
    }

    #[test]
    fn the_same_identifier_and_team_verified_at_both_readings_is_an_update_by_its_publisher() {
        let ok = codesign::VERIFIES;
        let id = "developer id, team ABCDE12345, identifier org.example.agent";
        assert!(by_publisher(&signature(id, ok), &signature(id, ok)));
        let apple = "apple, identifier org.example.tool";
        assert!(by_publisher(&signature(apple, ok), &signature(apple, ok)));
    }

    #[test]
    fn a_signers_name_alone_never_quiets_a_change_of_a_startup_program() {
        let ok = codesign::VERIFIES;
        let broken = "does not verify: main executable failed strict validation";
        let id = "developer id, team ABCDE12345, identifier org.example.agent";
        let same = |s: &str| (signature(s, ok), signature(s, ok));
        let mut no = vec![
            // The same name with a signature that does not verify, before or after.
            (signature(id, ok), signature(id, broken)),
            (signature(id, broken), signature(id, ok)),
            // Another identifier, another team, a team that went.
            (
                signature(id, ok),
                signature(
                    "developer id, team ABCDE12345, identifier org.example.other",
                    ok,
                ),
            ),
            (
                signature(id, ok),
                signature(
                    "developer id, team ZZZZZ99999, identifier org.example.agent",
                    ok,
                ),
            ),
            (
                signature(id, ok),
                signature("developer id, identifier org.example.agent", ok),
            ),
            // No team for a class that names a publisher only by it.
            same("developer id, identifier org.example.agent"),
            same("app store, identifier org.example.agent"),
            // A certificate Apple does not vouch for, whatever team it says.
            same("other certificate, team ABCDE12345, identifier x"),
            // Ad hoc, unsigned, or a signer without an identifier.
            same("ad hoc, cdhash 00, identifier x"),
            same("unsigned"),
            same("apple"),
        ];
        // The same signature where the path now leads elsewhere.
        let moved = Signature {
            link: Some("/usr/local/other".to_string()),
            ..signature(id, ok)
        };
        no.push((signature(id, ok), moved));
        for (before, after) in no {
            assert!(!by_publisher(&before, &after), "{before:?} {after:?}");
        }
        // Nothing known before: not a signature that verified then.
        assert!(!by_publisher(&Signature::default(), &signature(id, ok)));
    }

    /// An invented launch agent, as XML.
    const AGENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>org.example.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Users/example/bin/agent</string>
		<string>--config</string>
		<string>/Users/example/agent.conf</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
"#;

    /// The same agent in the binary form launchd's tools write: the file above converted by
    /// `plutil -convert binary1`.
    const AGENT_BINARY: &str = "62706c6973743030d3010203040509554c6162656c5f101050726f677261\
        6d417267756d656e74735952756e41744c6f61645f10116f72672e657861\
        6d706c652e6167656e74a30607085f10182f55736572732f6578616d706c\
        652f62696e2f6167656e74582d2d636f6e6669675f10192f55736572732f\
        6578616d706c652f6167656e742e636f6e6609080f152832464a656e8a00\
        00000000000101000000000000000a000000000000000000000000000000\
        8b";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn slot(bytes: &[u8]) -> (String, Vec<String>) {
        let (named, rest) = named_by(Runs::Launchd, bytes, "").unwrap();
        let named = match named {
            Named::Path(p) => p,
            Named::NotFull => "not full".to_string(),
            Named::Bundle => "bundle".to_string(),
            Named::Nothing => "nothing".to_string(),
        };
        (named, rest)
    }

    #[test]
    fn the_program_of_a_launch_item_is_its_first_argument_or_program_in_both_real_formats() {
        let both = [AGENT.as_bytes().to_vec(), unhex(AGENT_BINARY)];
        for bytes in &both {
            assert_eq!(
                slot(bytes),
                (
                    "/Users/example/bin/agent".to_string(),
                    vec![
                        "--config".to_string(),
                        "/Users/example/agent.conf".to_string()
                    ]
                )
            );
        }
        // `Program` is the executable whatever the first argument says.
        let program = AGENT.replace(
            "<key>RunAtLoad</key>",
            "<key>Program</key><string>/Users/example/bin/other</string><key>RunAtLoad</key>",
        );
        assert_eq!(slot(program.as_bytes()).0, "/Users/example/bin/other");
        // A program inside a bundle, a program that is not a string, and none at all.
        let only = |key: &str, value: &str| {
            AGENT.replace(
                "<key>ProgramArguments</key>",
                &format!("<key>{key}</key>{value}<key>Ignored</key>"),
            )
        };
        let bundle = only("BundleProgram", "<string>Contents/MacOS/agent</string>");
        assert_eq!(slot(bundle.as_bytes()).0, "bundle");
        let number = only("Program", "<integer>1</integer>");
        assert_eq!(slot(number.as_bytes()).0, "not full");
        let none = only("Other", "<string>x</string>");
        assert_eq!(slot(none.as_bytes()).0, "nothing");
    }

    #[test]
    fn an_item_whose_program_cannot_be_told_is_never_taken_as_one_that_names_none() {
        // Not a property list, a top that is not a dictionary, more arguments than are read,
        // and text past what is read.
        let many = format!(
            "<key>ProgramArguments</key><array>{}</array>",
            "<string>/x</string>".repeat(10_001)
        );
        let long = format!(
            "<key>Program</key><string>/{}</string>",
            "x".repeat(600_000)
        );
        let cases = [
            b"not a plist".to_vec(),
            b"<plist version=\"1.0\"><array/></plist>".to_vec(),
            format!("<plist version=\"1.0\"><dict>{many}</dict></plist>").into_bytes(),
            format!("<plist version=\"1.0\"><dict>{long}</dict></plist>").into_bytes(),
        ];
        for bytes in &cases {
            assert!(named_by(Runs::Launchd, bytes, "").is_none());
        }
    }

    #[test]
    fn a_program_named_where_nothing_is_or_judged_by_another_kind_is_named_and_leaves_it_full() {
        let mut t = Targets::default();
        t.count(ABSENT);
        t.count(ELSEWHERE);
        let (completeness, reason, gap) = t.coverage();
        assert_eq!(completeness, "full");
        assert_eq!(
            reason.as_deref(),
            Some(format!("{ABSENT}: 1; {ELSEWHERE}: 1; {AT_CHECKS}").as_str())
        );
        assert_eq!(gap.cause, None);
        t.count(NOT_FULL);
        assert_eq!(t.coverage().0, "partial");
    }

    #[test]
    fn only_a_plain_full_path_is_a_program_read() {
        for path in ["/usr/local/bin/runner", "/opt/example/hook.sh"] {
            assert!(plain(path), "{path}");
        }
        for path in [
            "runner",
            "bin/runner",
            "//usr/local/bin/runner",
            "/usr/local/../bin/runner",
            "/usr/./bin/runner",
            "/usr/local/bin/",
            "/",
        ] {
            assert!(!plain(path), "{path}");
        }
    }

    /// A folder of its own in the temporary folder, removed with it.
    fn scratch(name: &str) -> (crate::common::Scratch, PathBuf) {
        let dir = crate::common::Scratch::new(name);
        let path = dir.to_path_buf();
        (dir, path)
    }

    fn read_at(
        dir: &Path,
        resolve: &mut dyn FnMut() -> Real,
        before: &Signature,
    ) -> (Content, Signature) {
        let roots = Roots {
            home: dir,
            system: dir,
        };
        let (content, s, _) = read_target(resolve, &roots, "/runner", before, &mut Look::default());
        (content, s)
    }

    #[test]
    fn a_programs_signature_is_asked_only_of_content_judged_in_full_at_the_same_place() {
        let (_removed, dir) = scratch("carried");
        let program = dir.join("runner");
        std::fs::write(&program, "#!/bin/sh\n").unwrap();
        let mut at = || Real::At(program.clone());
        let (Content::Hash(content), fresh) = read_at(&dir, &mut at, &Signature::default()) else {
            panic!("not read");
        };
        assert_eq!(fresh.signed_by.as_deref(), Some("unsigned"));
        // The same content at the same place keeps what was judged of it, even what this file
        // could never show.
        let judged = Signature {
            content: Some(content),
            signed_by: Some("developer id, team ABCDE12345, identifier org.example.x".into()),
            seal: Some(codesign::VERIFIES.into()),
            link: fresh.link.clone(),
        };
        assert_eq!(
            read_at(&dir, &mut at, &judged).1.signed_by,
            judged.signed_by
        );
        // Without a verdict kept with it, or reached by another way, it is asked again.
        let unjudged = Signature {
            seal: None,
            ..judged.clone()
        };
        let elsewhere = Signature {
            link: Some("/elsewhere".into()),
            ..judged.clone()
        };
        for before in [unjudged, elsewhere] {
            assert_eq!(
                read_at(&dir, &mut at, &before).1.signed_by.as_deref(),
                Some("unsigned")
            );
        }
    }

    #[test]
    fn a_program_past_a_watched_files_cap_is_hashed_whole_up_to_its_own() {
        let (_removed, dir) = scratch("large");
        let bytes = vec![b'x'; (watched::CAP + 1) as usize];
        std::fs::write(dir.join("runner"), &bytes).unwrap();
        let mut at = || Real::At(dir.join("runner"));
        let (content, _) = read_at(&dir, &mut at, &Signature::default());
        let whole = format!("sha256:{}", crate::sha256::hex(&bytes));
        assert_eq!(content, Content::Hash(whole));
    }

    #[test]
    fn a_program_replaced_while_it_was_read_is_read_once_more_and_the_stable_file_is_judged() {
        let (_removed, dir) = scratch("moved");
        let program = dir.join("runner");
        std::fs::write(&program, "#!/bin/sh\necho old\n").unwrap();
        // The second look at the name, after the first read, finds another file there.
        let mut looks = 0;
        let mut resolve = || {
            looks += 1;
            if looks == 2 {
                std::fs::write(dir.join("new"), "#!/bin/sh\necho new\n").unwrap();
                std::fs::rename(dir.join("new"), &program).unwrap();
            }
            Real::At(program.clone())
        };
        let (content, _) = read_at(&dir, &mut resolve, &Signature::default());
        let new = format!("sha256:{}", crate::sha256::hex(b"#!/bin/sh\necho new\n"));
        assert_eq!(content, Content::Hash(new));
        // The name leads to another file at the second look: what it leads to now is read.
        let other = dir.join("other");
        std::fs::write(&other, "#!/bin/sh\necho other\n").unwrap();
        let mut looks = 0;
        let mut retargeted = || {
            looks += 1;
            Real::At(if looks == 1 { &program } else { &other }.clone())
        };
        let (content, _) = read_at(&dir, &mut retargeted, &Signature::default());
        let now = format!("sha256:{}", crate::sha256::hex(b"#!/bin/sh\necho other\n"));
        assert_eq!(content, Content::Hash(now));
        // Moved at every look: not read this time.
        let mut always = || {
            std::fs::write(dir.join("new"), "#!/bin/sh\n").unwrap();
            std::fs::rename(dir.join("new"), &program).unwrap();
            Real::At(program.clone())
        };
        let (content, _) = read_at(&dir, &mut always, &Signature::default());
        assert_eq!(content, Content::Unread(Cause::Failed, MOVED.to_string()));
    }

    #[test]
    fn a_program_macos_ships_is_signed_by_apple_under_its_identifier_and_its_code_verifies() {
        let (signer, seal) = signed(Path::new("/usr/bin/true"));
        assert_eq!(signer.as_deref(), Some("apple, identifier com.apple.true"));
        assert_eq!(seal.as_deref(), Some(codesign::VERIFIES));
        let before = signature("apple, identifier com.apple.true", codesign::VERIFIES);
        let after = Signature {
            signed_by: signer,
            seal,
            ..before.clone()
        };
        assert!(by_publisher(&before, &after));
        // The main executable of an app macOS ships is judged as the code of its bundle.
        let app = Path::new("/System/Applications/Calculator.app/Contents/MacOS/Calculator");
        let (signer, seal) = signed(app);
        let signer = signer.unwrap_or_default();
        assert!(signer.starts_with("apple, identifier "), "{signer}");
        assert_eq!(seal.as_deref(), Some(codesign::VERIFIES));
    }
}
