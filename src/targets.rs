//! The programs that startup items run. A launch agent or daemon is watched by the checksum of
//! its property list and a login hook by its value; what they start is read here, so that a
//! program replaced behind an untouched item is seen. A target is only the slot the platform
//! defines as the executable (`autorun::Runs`): for launchd `Program`, else the first string of
//! `ProgramArguments`; for a login hook its value. No other argument is a target: a file an
//! argument names is counted as not judged, never read.
//!
//! A target is a watched file of its own kind, `TARGET`, in one reading of this machine that
//! only a check makes: a watcher neither subscribes to targets nor reads them. It goes through
//! the lifecycle of watched files (`read_watched` in `main.rs`): which item runs it is the fact
//! `started_by`, the target its subject and the item its object, and its content reading holds
//! `has_content`, `links_to` where the path leads elsewhere, `signed_by` with the code's
//! identifier, and `has_seal`, whether its own code verifies. A target is kept while a live item
//! names it; one that no item names any more is gone with the item's change, which the item's
//! own rule tells. An item that could not be read this time keeps the targets it named.
//!
//! What is adopted: an item has a target with content and a signer, as Autoruns, KnockKnock,
//! Background Task Management and osquery's `launchd` table show; and the same program is told
//! by its identifier and team, as macOS's own designated requirement tells it. Immunity Core's
//! own: the rule `watched.startup-target`, a change of a target's content while an item still
//! names it, which is quiet only for an update by its publisher (`by_publisher`).

use crate::autorun::{self, Runs};
use crate::baseline::Unit;
use crate::codesign;
use crate::guarded::{self, Real};
use crate::look::{Absent, Look};
use crate::plist::{self, Text};
use crate::store::{Cause, Gap, Lack, Statement};
use crate::watched::{self, Content, Entry, Roots};
use rusqlite::{Transaction, params};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
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

/// Why a target was not read, or a file not judged, in the reading's words. The first two and
/// the last are what this build has no reader for, as is a target over the size cap.
const NOT_FULL: &str = "startup programs not named by a full path";
const IN_BUNDLE: &str = "startup programs inside an app bundle (BundleProgram)";
const GUARDED: &str = "startup programs in a folder macOS asks permission for";
const FAILED: &str = "startup programs that could not be opened";
const ITEMS: &str = "startup items that could not be read, whose programs are kept as last read";
const ARGUMENTS: &str = "files named in startup items' arguments, which are not judged";
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

/// The classes of `codesign::signer` whose team, where they name one, Apple's anchor vouches
/// for. An `other certificate` can be made by anyone and say any team.
const VOUCHED: [&str; 3] = ["apple", "app store", "developer id"];

/// Whether a change of a target is an update by its publisher: at both readings the signature
/// verified, and both name the same identifier and the same team of a class Apple vouches for.
/// Unsigned or ad hoc code, a script, a signature that does not verify, another identifier,
/// another team, or a team that appeared or went is not; neither is a name alone.
pub fn by_publisher(before: &Signature, after: &Signature) -> bool {
    let vouched = |s: &str| VOUCHED.iter().any(|c| s.starts_with(c));
    let verified = |s: &Signature| s.seal.as_deref() == Some(codesign::VERIFIES);
    matches!((&before.signed_by, &after.signed_by),
        (Some(b), Some(a)) if a == b && vouched(a) && a.contains(IDENTIFIER))
        && verified(before)
        && verified(after)
}

/// How the identifier follows the signer in `signed_by`.
const IDENTIFIER: &str = ", identifier ";

/// What a check read of the targets, beside the look it hands to the store.
#[derive(Default)]
pub struct Targets {
    /// The items that run each target, by its unit.
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

    /// Whether a change seen in a target raises nothing: an update by its publisher.
    pub fn quiet(&self, unit: &Unit) -> bool {
        match (self.before.get(unit), self.after.get(unit)) {
            (Some(b), Some(a)) => by_publisher(b, a),
            _ => false,
        }
    }

    /// The reading's completeness, its reason or note, and its gap. Never full while anything
    /// named was not read or not judged.
    pub fn coverage(&self) -> (&'static str, Option<String>, Gap) {
        let said: Vec<String> = self
            .counts
            .iter()
            .map(|(why, n)| format!("{why}: {n}"))
            .collect();
        if said.is_empty() {
            return ("full", Some(AT_CHECKS.to_string()), Gap::default());
        }
        let cause = |why: &str| match why {
            GUARDED => Cause::NotGiven,
            FAILED | ITEMS => Cause::Failed,
            _ => Cause::NoReader,
        };
        let lacks = self
            .counts
            .keys()
            .filter(|why| cause(why) == Cause::NoReader)
            .map(|why| Lack::new(why, None))
            .collect();
        let gap = Gap {
            cause: Cause::worst(self.counts.keys().map(|w| cause(w))),
            lacks,
        };
        let reason = format!("not read in full: {}; {AT_CHECKS}", said.join("; "));
        ("partial", Some(reason), gap)
    }

    fn count(&mut self, why: &'static str) {
        *self.counts.entry(why).or_default() += 1;
    }
}

/// Whether a kind of watched place has files that name a program.
pub fn reads(watched_as: &str) -> bool {
    runs_of(watched_as).is_some()
}

fn runs_of(watched_as: &str) -> Option<Runs> {
    autorun::places()
        .find(|(_, k)| k.0 == watched_as)
        .and_then(|(p, _)| p.runs)
}

/// A path as ids name it, on disk: from the system's root when it starts with `/`, else from
/// the home folder.
fn on_disk(roots: &Roots, path: &str) -> PathBuf {
    match path.strip_prefix('/') {
        Some(rest) => roots.system.join(rest),
        None => roots.home.join(path),
    }
}

/// What a file of an item names: the target, or why none is read, and the arguments beside it.
enum Named {
    Path(String),
    NotFull,
    Bundle,
    Nothing,
}

/// launchd's slot: `Program`, else the first string of `ProgramArguments`; `BundleProgram`
/// alone is named and not read. `None`: not a property list launchd can read, which runs
/// nothing.
fn launchd(bytes: &[u8]) -> Option<(Named, Vec<String>)> {
    let texts = plist::texts(bytes, &["Program", "ProgramArguments", "BundleProgram"]).ok()?;
    let get = |key: &str| texts.iter().find(|(k, _)| *k == key).map(|(_, t)| t);
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

/// Reads what the items in `items` name and each target they name. An item whose file could not
/// be read keeps the targets the store says it named. The look holds one entry per target.
pub fn read(
    tx: &Transaction,
    machine: &str,
    roots: &Roots,
    items: &[&Look],
) -> rusqlite::Result<(Look, Targets)> {
    let homes = watched::homes(roots.home);
    let homes = [homes[0].as_path(), homes[1].as_path()];
    let mut t = Targets::default();
    let mut named: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unread = BTreeSet::new();
    for e in items.iter().flat_map(|l| &l.entries) {
        let Some(runs) = runs_of(e.watched_as) else {
            continue;
        };
        let id = format!("file:{machine}/{}", e.unit);
        let bytes = match &e.content {
            Content::Hash(_) | Content::Value(_) => {
                match guarded::real(&on_disk(roots, &e.unit.path), &homes) {
                    Real::At(p) => autorun::read_capped_resolved(&p, watched::CAP).ok(),
                    _ => None,
                }
            }
            Content::Unread(..) => None,
            // Not a file: it names nothing.
            _ => continue,
        };
        let Some(bytes) = bytes else {
            unread.insert(id);
            continue;
        };
        let (target, arguments) = match runs {
            Runs::Launchd => launchd(&bytes).unwrap_or((Named::Nothing, Vec::new())),
            Runs::Values(keys) => {
                let key = keys.iter().find(|k| e.unit.part == format!("/{k}"));
                let text = key.and_then(|k| plist::texts(&bytes, &[k]).ok()?.pop());
                match text {
                    Some((_, Text::One(p))) => (Named::Path(p), Vec::new()),
                    _ => (Named::NotFull, Vec::new()),
                }
            }
        };
        let not_read = match target {
            Named::Path(p) if p.starts_with('/') => {
                named.entry(p).or_default().insert(id.clone());
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
        // A file an argument names is counted, never read; one whose presence cannot be told
        // without entering a guarded folder is counted too.
        for a in arguments.iter().filter(|a| a.starts_with('/')) {
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
    // What the store says each item ran, for the items not read now: hidden by a folder that
    // could not be listed, or there and not readable. An item read now is neither.
    let prefix = format!("file:{machine}/");
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
        if !(hidden || unread.contains(&item)) {
            continue;
        }
        if let Some(path) = target.strip_prefix(&prefix) {
            named
                .entry(path.to_string())
                .or_default()
                .insert(item.clone());
        }
        unread.insert(item);
    }
    for _ in &unread {
        t.count(ITEMS);
    }
    let mut look = Look::default();
    for (path, by) in named {
        let unit = Unit::whole(&path);
        let id = format!("{prefix}{unit}");
        let before = previous(tx, &id)?;
        let (content, after) = read_target(roots, &homes, &path, &before, &mut look);
        if let Content::Unread(cause, _) = &content {
            t.count(match cause {
                Cause::NotGiven => GUARDED,
                Cause::NoReader => watched::OVER_CAP,
                Cause::Failed => FAILED,
            });
        }
        look.read(unit.clone());
        look.entries.push(Entry {
            unit: unit.clone(),
            watched_as: TARGET,
            content,
            link: after.link.clone(),
        });
        t.by.insert(unit.clone(), by);
        t.before.insert(unit.clone(), before);
        t.after.insert(unit, after);
    }
    Ok((look, t))
}

/// What the store holds live of a target's content reading.
fn previous(tx: &Transaction, id: &str) -> rusqlite::Result<Signature> {
    let mut s = Signature::default();
    let mut stmt = tx.prepare(
        "SELECT predicate, object FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3",
    )?;
    for row in stmt.query_map(params![watched::READER, id, watched::CONTENT], |r| {
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

/// Reads one target named by its full path. Links are followed with the guard watched files
/// keep, and what the path leads to is what is read. Its identity is taken before and after the
/// hash and the signature; if it moved it is read once more, and if it moved again it is not
/// read this time.
fn read_target(
    roots: &Roots,
    homes: &[&Path],
    path: &str,
    before: &Signature,
    look: &mut Look,
) -> (Content, Signature) {
    let real = match guarded::real(&on_disk(roots, path), homes) {
        Real::At(real) => real,
        Real::Guarded(g) => {
            let why = format!(
                "{}{}",
                guarded::NOT_LOOKED_INTO,
                guarded::leads_into(&g, roots.home)
            );
            look.met(g);
            return (Content::Unread(Cause::NotGiven, why), Signature::default());
        }
        // Named and not there: the item leads nowhere, which is its content.
        Real::Failed(e) if Absent::on_the_way(&e).is_some() => {
            return (Content::Dangling, Signature::default());
        }
        Real::Failed(e) => {
            return (
                Content::Unread(Cause::Failed, e.to_string()),
                Signature::default(),
            );
        }
    };
    let shown = from_root(roots.system, &real);
    let link = (shown != path).then_some(shown);
    for _ in 0..2 {
        match once(&real, before) {
            Ok(Some((content, mut s))) => {
                s.link = link;
                return (content, s);
            }
            Ok(None) => continue,
            Err(content) => {
                let s = Signature {
                    link,
                    ..Signature::default()
                };
                return (content, s);
            }
        }
    }
    let s = Signature {
        link,
        ..Signature::default()
    };
    (Content::Unread(Cause::Failed, MOVED.to_string()), s)
}

/// What changes whenever the file is written, replaced, renamed or given another mode.
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (m.dev(), m.ino(), m.size(), m.ctime(), m.ctime_nsec())
}

/// One reading of a target made real: `Ok(None)` when it moved while it was read. The signature
/// is asked only of content read anew; otherwise what the store holds with that content is it.
#[allow(clippy::type_complexity)]
fn once(real: &Path, before: &Signature) -> Result<Option<(Content, Signature)>, Content> {
    let (mut file, meta) = match watched::open_regular(real) {
        Ok(Ok(opened)) => opened,
        Ok(Err(what)) => return Err(Content::Special(what)),
        Err(e) => return Err(Content::Unread(Cause::Failed, e.to_string())),
    };
    if meta.len() > CAP {
        let why = format!("over the size cap of {} MiB", CAP >> 20);
        return Err(Content::Unread(Cause::NoReader, why));
    }
    let mut hasher = crate::sha256::Hasher::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => return Err(Content::Unread(Cause::Failed, e.to_string())),
        }
    }
    let content = format!("sha256:{}", hasher.hex());
    let mut s = Signature {
        content: Some(content.clone()),
        ..Signature::default()
    };
    if before.content.as_ref() == Some(&content) && before.seal.is_some() {
        s.signed_by = before.signed_by.clone();
        s.seal = before.seal.clone();
    } else {
        (s.signed_by, s.seal) = signed(real);
    }
    Ok((!moved(&meta, real)).then_some((Content::Hash(content), s)))
}

/// Whether the file at `real` is no longer the one `meta` was taken of, or is gone.
fn moved(meta: &std::fs::Metadata, real: &Path) -> bool {
    std::fs::symlink_metadata(real).map_or(true, |m| identity(&m) != identity(meta))
}

/// Who signed the code at `real`, with its identifier, and whether its own code verifies.
fn signed(real: &Path) -> (Option<String>, Option<String>) {
    match codesign::Code::at(real) {
        Ok(code) => {
            let signer = code.signer().map(|s| match code.identifier() {
                Some(id) => format!("{s}{IDENTIFIER}{id}"),
                None => s,
            });
            (signer, Some(code.code()))
        }
        Err(status) => (None, Some(codesign::does_not_verify(status))),
    }
}

/// Adds to each finding of the rule this run raised or saw again the journal entries that say
/// who signed the target and whether its code verified, before and after, and which items run
/// it: the latest entry of each, which is this run's when it changed now and holds every item
/// as the journal joins a set. A finding then names every item, and the signer even when it did
/// not change.
pub fn evidence(tx: &Transaction, run_id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO finding_basis (finding, journal)
         SELECT f.id, j.seq FROM finding f JOIN journal j ON j.subject = f.about
         WHERE f.rule = ?1 AND f.last_seen_run = ?2 AND j.reader = ?3
           AND j.predicate IN ('signed_by', 'has_seal', ?4) AND j.entry IN ('added', 'changed')
           AND j.seq = (SELECT MAX(k.seq) FROM journal k
                        WHERE k.subject = j.subject AND k.predicate = j.predicate
                          AND k.reader = ?3 AND k.entry IN ('added', 'changed'))
           AND NOT EXISTS (SELECT 1 FROM finding_basis b WHERE b.finding = f.id
                             AND b.journal = j.seq)",
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
        let no = [
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
            // A certificate Apple does not vouch for, whatever team it says.
            (
                signature("other certificate, team ABCDE12345, identifier x", ok),
                signature("other certificate, team ABCDE12345, identifier x", ok),
            ),
            // Ad hoc, unsigned, or a signer without an identifier.
            (
                signature("ad hoc, cdhash 00, identifier x", ok),
                signature("ad hoc, cdhash 00, identifier x", ok),
            ),
            (signature("unsigned", ok), signature("unsigned", ok)),
            (signature("apple", ok), signature("apple", ok)),
        ];
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
        let (named, rest) = launchd(bytes).unwrap();
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
        // A file that is not a property list names nothing launchd runs.
        assert!(launchd(b"not a plist").is_none());
    }

    #[test]
    fn a_programs_signature_is_asked_only_of_content_not_judged_before_and_a_replaced_file_is_seen()
    {
        let dir = std::env::temp_dir().join(format!("immunity-targets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("runner");
        std::fs::write(&program, "#!/bin/sh\n").unwrap();
        let (Content::Hash(content), fresh) =
            once(&program, &Signature::default()).unwrap().unwrap()
        else {
            panic!("not read");
        };
        assert_eq!(fresh.signed_by.as_deref(), Some("unsigned"));
        // The same content keeps what was judged of it, even what this file could never show.
        let judged = Signature {
            content: Some(content),
            signed_by: Some("developer id, team ABCDE12345, identifier org.example.x".into()),
            seal: Some(codesign::VERIFIES.into()),
            link: None,
        };
        let (_, kept) = once(&program, &judged).unwrap().unwrap();
        assert_eq!(kept.signed_by, judged.signed_by);
        // Without a verdict kept with it, the signature is asked again.
        let unjudged = Signature {
            seal: None,
            ..judged.clone()
        };
        let (_, asked) = once(&program, &unjudged).unwrap().unwrap();
        assert_eq!(asked.signed_by.as_deref(), Some("unsigned"));
        // Replaced while it was read: another file stands at the path.
        let (_, meta) = watched::open_regular(&program).unwrap().unwrap();
        assert!(!moved(&meta, &program));
        let other = dir.join("other");
        std::fs::write(&other, "#!/bin/sh\n").unwrap();
        std::fs::rename(&other, &program).unwrap();
        assert!(moved(&meta, &program));
        std::fs::remove_file(&program).unwrap();
        std::fs::remove_dir(&dir).unwrap();
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
    }
}
