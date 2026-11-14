//! One reading of autorun points as its reader hands it to the store, and the rules about
//! readings of them, kept here once. Both readers of the table (`autorun::POINTS`), the watched
//! places reader (`watched.rs`) and the reader of parts (`autorun.rs`), record what they found
//! through `Look`, and the store compares and retracts through it (`read_watched` in
//! `main.rs`):
//!
//! - Not read is not absent. A unit is read in full only by `absent`, which takes proof that
//!   its path is not there, or by `read`, `read_part`; a unit that could not be read is
//!   recorded with why (`unread`, `not_looked_at`, `not_into`). What was known of a unit is
//!   retracted only where `retracts` allows it: a unit read in full covers it, and no unit not
//!   read hides it.
//! - Losing sight is a change. Every unit that is there and was not read carries its reason,
//!   and `not_read` hands each one to the store, which judges it as `baseline.rs` says and
//!   never carries it as unchanged.
//! - No longer read is not a reading. What an earlier run read and this build has no row for
//!   is closed as retired by `retire_unread`: not shown as watched, never told as removed,
//!   and said once by the next run's line, also when a watcher closed it (`lifecycle::set_aside`).
//! - A time from the future proves nothing: `fresh`.
//! - Not present on this Mac is not applicable: a full reading with a note. Present and
//!   unreadable is a failed reading with its reason (`completeness`, `cause`).

use crate::autorun::{self, POINTS, Point};
use crate::baseline::{self, Unit};
use crate::store::{Cause, Reading};
use crate::watched::{self, Entry};
use rusqlite::{Transaction, params};
use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

/// Proof that a path is not there, taken only from the error of looking at it. A unit found
/// absent was read in full: it holds nothing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Absent(());

impl Absent {
    /// The path is not there.
    pub fn of(e: &Error) -> Option<Absent> {
        (e.kind() == ErrorKind::NotFound).then_some(Absent(()))
    }

    /// The path is not there, or a part on the way to it is not a folder, as under a file such
    /// as a worktree's `.git`.
    pub fn on_the_way(e: &Error) -> Option<Absent> {
        matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory).then_some(Absent(()))
    }
}

/// The note of a full reading when none of its places is on this machine.
pub const NOT_HERE: &str = "none of these places is on this machine";

/// What looking at the places of one reading found.
#[derive(Default)]
pub struct Look {
    pub entries: Vec<Entry>,
    /// Places that are there and were looked at.
    pub present: usize,
    /// Every folder macOS asks permission for that was met, a link's target among them, for
    /// the reader's coverage.
    pub guarded: Vec<PathBuf>,
    /// Units there, or whose presence is not known, that could not be read, with the reason.
    failed: Vec<(Unit, String)>,
    /// Units not looked into because they lead into a folder macOS asks permission for, each
    /// with why: whether they hold anything is not known.
    unreached: Vec<(Unit, String)>,
    /// The units read in full, by their paths as ids name them: a file looked at, found or
    /// absent, and a folder listed or found absent (`baseline.rs`).
    read: Vec<Unit>,
    /// The units found present and not read in full. One read in full is known to be there by
    /// its reading, which is all the store asks of it (`baseline::Judge::facts`).
    seen: Vec<Unit>,
}

impl Look {
    /// A unit looked at and not there: read in full, it holds nothing.
    pub fn absent(&mut self, unit: Unit, _: Absent) {
        self.read.push(unit);
    }

    /// A unit there and read in full: a file read, a folder listed.
    pub fn read(&mut self, unit: Unit) {
        self.read.push(unit);
    }

    /// A part of a file that was parsed whole, there or known absent from it: read in full.
    pub fn read_part(&mut self, file: &Unit, pointer: impl Into<String>) {
        self.read.push(Unit::part(&file.path, pointer));
    }

    /// A unit there whose parts are judged one by one, one of them not read: seen and not read
    /// in full.
    pub fn there(&mut self, unit: Unit) {
        self.seen.push(unit);
    }

    /// A unit there that could not be read, with why.
    pub fn unread(&mut self, unit: Unit, why: String) {
        self.seen.push(unit.clone());
        self.failed.push((unit, why));
    }

    /// A unit that could not be looked at, with why: whether it is there is not known. A part
    /// of a file that could not be read is one too: only it is not known.
    pub fn not_looked_at(&mut self, unit: Unit, why: String) {
        self.failed.push((unit, why));
    }

    /// A unit that leads into a guarded folder: not looked into, and said.
    pub fn not_into(&mut self, unit: Unit, folder: PathBuf, home: &Path) {
        self.unreached
            .push((unit, crate::guarded::leads_into(&folder, home)));
        self.met(folder);
    }

    /// A unit there that leads into a guarded folder.
    pub fn there_not_into(&mut self, unit: Unit, folder: PathBuf, home: &Path) {
        self.seen.push(unit.clone());
        self.not_into(unit, folder, home);
    }

    /// A guarded folder met, for the reader's coverage.
    pub fn met(&mut self, folder: PathBuf) {
        if !self.guarded.contains(&folder) {
            self.guarded.push(folder);
        }
    }

    /// The units read in full.
    pub fn read_units(&self) -> &[Unit] {
        &self.read
    }

    /// The units found present and not read in full.
    pub fn seen_units(&self) -> &[Unit] {
        &self.seen
    }

    pub fn failed(&self) -> &[(Unit, String)] {
        &self.failed
    }

    pub fn unreached(&self) -> &[(Unit, String)] {
        &self.unreached
    }

    /// Every unit not read, with why: those that failed, then those not looked into. The store
    /// judges each (`baseline.rs`): losing sight of a unit read before is a change.
    pub fn not_read(&self) -> impl Iterator<Item = &(Unit, String)> {
        self.failed.iter().chain(&self.unreached)
    }

    /// Whether this reading may retract what was known of a unit: whenever no unit it did not
    /// read hides it. What it did not find is gone, at whatever level: a file, its folder, a
    /// checkout no longer found or one whose `.git` is gone takes along what was read inside
    /// it. What it cannot place, `None`, only when it read everything it looked at.
    pub fn retracts(&self, unit: Option<&Unit>) -> bool {
        let Some(unit) = unit else {
            return self.failed.is_empty() && self.unreached.is_empty();
        };
        !self.not_read().any(|(u, _)| u.hides(unit))
    }

    /// The completeness of the reading of which entries are there, and its reason or note. A
    /// reading of places none of which is here is full, with the note that says so.
    pub fn completeness(&self) -> (&'static str, Option<String>) {
        if self.failed.is_empty() && self.unreached.is_empty() {
            let note = (self.present == 0).then(|| NOT_HERE.to_string());
            return ("full", note);
        }
        let mut reasons = Vec::new();
        if !self.failed.is_empty() {
            let failed: Vec<String> = self
                .failed
                .iter()
                .map(|(path, why)| format!("{path} ({why})"))
                .collect();
            reasons.push(format!("could not be read: {}", failed.join("; ")));
        }
        if !self.unreached.is_empty() {
            let unreached: Vec<String> = self
                .unreached
                .iter()
                .map(|(path, why)| format!("{path}: {why}"))
                .collect();
            reasons.push(format!(
                "{}{}",
                crate::guarded::NOT_LOOKED_INTO,
                unreached.join("; ")
            ));
        }
        let reason = Some(reasons.join("; "));
        if self.present == 0 {
            ("none", reason)
        } else {
            ("partial", reason)
        }
    }

    /// Why a reading that is not full is not: it failed, or what it did not look into is
    /// only what macOS asks permission for, which the owner did not give.
    pub fn cause(&self) -> Cause {
        if self.failed.is_empty() && !self.unreached.is_empty() {
            Cause::NotGiven
        } else {
            Cause::Failed
        }
    }
}

/// Whether a reading taken at `at` speaks for now: taken by the latest check, `latest_run`, and
/// not dated ahead of this Mac's clock (`store::age`). A time from the future proves nothing.
pub fn fresh(at: i64, latest_run: Option<i64>, now: i64) -> bool {
    crate::store::age(at, now).is_some() && latest_run.is_some_and(|run| at >= run)
}

/// Why what an earlier run read is closed as retired: this build has no row that reads it.
pub const NO_ROW: &str = "this version has no row for it in its table of autorun points";

/// The coverage kinds the watched places reader writes in this build: one per kind of place
/// and per row read by parts, and the readings beside them.
pub fn kinds_written() -> BTreeSet<String> {
    let mut kinds: BTreeSet<String> = POINTS
        .iter()
        .filter(|p| p.watched_place() || p.read_here())
        .map(Point::kind)
        .collect();
    for kind in [
        watched::CONTENT,
        autorun::PRESENT_KIND,
        autorun::OTHERS_KIND,
        autorun::HOME_OTHERS_KIND,
        crate::guarded::KIND,
    ] {
        kinds.insert(kind.to_string());
    }
    kinds
}

/// Closes what an earlier run read and this build has no row for: a kind no row reads any
/// more, by `lifecycle::retire`, and a thing of a kind still read that no row of the kind
/// names, such as a file a row no longer lists. Each is retracted with a journal entry
/// `retired` that says why, never told as removed, and the content read of it goes with it.
/// `r` gives the run; its scope and kind are ignored. Returns how many things were closed.
pub fn retire_unread(tx: &Transaction, r: &Reading) -> rusqlite::Result<usize> {
    let written = kinds_written();
    let reader = watched::READER;
    // Kind by kind through the index of readings by reader and kind, never through every
    // reading: the cost follows how many kinds there are, not how long the store was kept.
    let kinds: Vec<String> = tx
        .prepare(
            "WITH RECURSIVE k (kind) AS (
                 SELECT MIN(kind) FROM coverage WHERE reader = ?1
                 UNION ALL
                 SELECT (SELECT MIN(kind) FROM coverage WHERE reader = ?1 AND kind > k.kind)
                 FROM k WHERE k.kind IS NOT NULL
             )
             SELECT kind FROM k WHERE kind IS NOT NULL
             UNION SELECT DISTINCT kind FROM assertion WHERE layer = 'live' AND reader = ?1",
        )?
        .query_map([reader], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let checkouts = baseline::past_checkouts(tx)?;
    let rows: Vec<(String, String, String)> = tx
        .prepare(
            "SELECT scope, kind, subject FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'",
        )?
        .query_map([reader], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    // An id is never cut into parts: the machine is the run's own, `r.scope`, and a thing is
    // named by what follows the prefix of its ids, as `kept` in `main.rs` takes it. A thing of
    // another machine is left as it is.
    let prefix = format!("file:{}/", r.scope);
    let checkout = |rel: &str| checkouts.contains(&format!("{}/{rel}", r.scope));
    let mut watched: BTreeSet<&str> = BTreeSet::new();
    let mut unclaimed = Vec::new();
    for (scope, kind, subject) in &rows {
        // A kind no row reads has no candidates, so what is of it is never claimed.
        let claimed = subject
            .strip_prefix(&prefix)
            .is_none_or(|name| !baseline::candidates(kind, name, checkout).is_empty());
        if claimed {
            watched.insert(subject);
        } else {
            unclaimed.push((scope, kind, subject));
        }
    }
    let mut closed = 0;
    for (scope, kind, subject) in &unclaimed {
        closed += retire_facts(tx, r, scope, kind, subject)?;
    }
    // The content read of a thing goes with the last kind that watched it.
    let gone: BTreeSet<&str> = unclaimed
        .iter()
        .map(|(_, _, subject)| subject.as_str())
        .filter(|subject| !watched.contains(subject))
        .collect();
    for subject in gone {
        closed += retire_facts(tx, r, subject, watched::CONTENT, subject)?;
    }
    for kind in kinds.iter().filter(|k| !written.contains(*k)) {
        let of_kind = Reading { kind, ..*r };
        closed += crate::lifecycle::retire(tx, &of_kind, NO_ROW)?.0;
    }
    Ok(closed)
}

/// Retracts the live facts of one thing in one reading, each with a journal entry `retired`.
/// Returns how many were closed.
fn retire_facts(
    tx: &Transaction,
    r: &Reading,
    scope: &str,
    kind: &str,
    subject: &str,
) -> rusqlite::Result<usize> {
    let why = format!("{}{NO_ROW}", crate::lifecycle::NO_LONGER_READ);
    let facts: Vec<(i64, String, String)> = tx
        .prepare(
            "SELECT id, predicate, object FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND scope = ?2 AND kind = ?3 AND subject = ?4",
        )?
        .query_map(params![watched::READER, scope, kind, subject], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    for (id, predicate, object) in &facts {
        tx.execute(
            "UPDATE assertion SET layer = 'retracted', retracted_at = ?1, retracted_by = ?2
             WHERE id = ?3",
            params![r.at, r.run_id, id],
        )?;
        tx.execute(
            "INSERT INTO journal (at, run_id, entry, reader, scope, kind, subject, predicate,
                                  old_value, text)
             VALUES (?1, ?2, 'retired', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                r.at,
                r.run_id,
                watched::READER,
                scope,
                kind,
                subject,
                predicate,
                object,
                why
            ],
        )?;
    }
    Ok(facts.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autorun::Scope;
    use crate::watched::Roots;
    use std::os::unix::fs::PermissionsExt;

    /// An invented Mac: a home folder and a system root, empty.
    struct Mac {
        dir: PathBuf,
    }

    impl Mac {
        fn new(name: &str) -> Mac {
            let dir =
                std::env::temp_dir().join(format!("immune-look-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("home")).unwrap();
            std::fs::create_dir_all(dir.join("sys")).unwrap();
            Mac { dir }
        }

        fn home(&self) -> PathBuf {
            self.dir.join("home")
        }

        fn put(&self, rel: &str, text: &str) -> PathBuf {
            let path = self.home().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            path
        }

        /// Shut, as a folder or file this user may not read.
        fn shut(&self, rel: &str) {
            let mode = std::fs::Permissions::from_mode(0o000);
            std::fs::set_permissions(self.home().join(rel), mode).unwrap();
        }

        /// A reading of a kind of watched place: a row of the watched places reader.
        fn place(&self, kind: &str) -> Look {
            let (home, system) = (self.home(), self.dir.join("sys"));
            watched::look_machine(
                &Roots {
                    home: &home,
                    system: &system,
                },
                kind,
            )
        }

        /// A reading of a known way, of the checkout `dev/a` or of the home folder.
        fn way(&self, path: &str, scope: Scope) -> autorun::Looked {
            let p = row(path, scope);
            let home = self.home();
            let (base, rel) = match scope {
                Scope::Home => (home.clone(), ""),
                _ => (home.join("dev/a"), "dev/a"),
            };
            autorun::look_all(p, [(base.as_path(), rel)].into_iter(), &home)
        }
    }

    impl Drop for Mac {
        fn drop(&mut self) {
            // Opened again, so that what a test shut can be removed.
            for entry in walk(&self.dir) {
                let _ = std::fs::set_permissions(entry, std::fs::Permissions::from_mode(0o755));
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = vec![dir.to_path_buf()];
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() && !path.is_symlink() {
                    out.extend(walk(&path));
                } else {
                    out.push(path);
                }
            }
        }
        out
    }

    /// The row of the table at `path` in `scope`.
    fn row(path: &str, scope: Scope) -> &'static Point {
        POINTS
            .iter()
            .find(|p| p.scope == scope && p.paths.contains(&path))
            .unwrap()
    }

    #[test]
    fn only_the_error_that_says_a_path_is_not_there_proves_it_absent() {
        // A file that is there and shut, or a folder of the home folder the owner did not open,
        // is not a file that is not there: neither may be recorded as read and empty.
        let said = |errno| Error::from_raw_os_error(errno);
        // ENOENT 2, ENOTDIR 20, EACCES 13, EPERM 1, EIO 5, ELOOP 62 (sys/errno.h).
        assert!(Absent::of(&said(2)).is_some());
        assert!(Absent::of(&said(20)).is_none());
        assert!(Absent::on_the_way(&said(20)).is_some());
        for errno in [13, 1, 5, 62] {
            assert!(Absent::of(&said(errno)).is_none(), "{errno}");
            assert!(Absent::on_the_way(&said(errno)).is_none(), "{errno}");
        }
    }

    #[test]
    fn what_could_not_be_read_is_never_absent_and_what_was_known_of_it_is_never_retracted() {
        let mac = Mac::new("unread");
        // A place: the user's launch agents, a folder that cannot be listed.
        mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
        mac.shut("Library/LaunchAgents");
        // A way: a project's MCP servers, in a file that cannot be opened.
        mac.put(
            "dev/a/.mcp.json",
            r#"{"mcpServers": {"x": {"command": "npx"}}}"#,
        );
        mac.shut("dev/a/.mcp.json");
        let place = mac.place(watched::AUTOSTART_KIND);
        let way = mac.way(".mcp.json", Scope::Checkout).look;

        let agents = Unit::whole("Library/LaunchAgents");
        let agent = Unit::whole("Library/LaunchAgents/org.example.sync.plist");
        assert!(!place.read_units().contains(&agents));
        assert!(!place.retracts(Some(&agent)));
        // The system's folder is not there: read in full, and what was known in it may go.
        assert!(
            place
                .read_units()
                .contains(&Unit::whole("/Library/LaunchAgents"))
        );
        assert!(place.retracts(Some(&Unit::whole(
            "/Library/LaunchAgents/org.example.gone.plist"
        ))));

        let file = Unit::whole("dev/a/.mcp.json");
        assert!(!way.read_units().contains(&file));
        assert!(!way.retracts(Some(&Unit::part(&file.path, "/mcpServers/x"))));
        // What cannot be placed is kept while anything was not read. What no unit left unread
        // hides was looked for and not found: a checkout no longer found takes its ways along.
        assert!(!place.retracts(None) && !way.retracts(None));
        let elsewhere = Unit::whole("dev/b/.mcp.json");
        assert!(place.retracts(Some(&elsewhere)) && way.retracts(Some(&elsewhere)));
        // A reading whose only gap is a folder macOS guards has not read everything either.
        let mut guarded = Look::default();
        guarded.not_into(
            Unit::whole("Library/Mail/x"),
            PathBuf::from("/Users/example/Library/Mail"),
            Path::new("/Users/example"),
        );
        assert!(!guarded.retracts(None));
    }

    #[test]
    fn an_entry_that_could_not_be_read_keeps_what_was_known_of_it_inside_a_folder_read_in_full() {
        // The editor's extensions are listed; one entry leads nowhere and cannot be looked at.
        // Its neighbour that is gone is gone; it is not.
        let mac = Mac::new("entry");
        mac.put(".vscode/extensions/example.kept-1.0.0/package.json", "{}");
        std::os::unix::fs::symlink(
            mac.home().join("nowhere"),
            mac.home().join(".vscode/extensions/example.lost-1.0.0"),
        )
        .unwrap();
        let way = mac.way(".vscode/extensions", Scope::Home).look;
        let folder = Unit::whole(".vscode/extensions");
        assert!(way.read_units().contains(&folder));
        assert!(!way.retracts(Some(&Unit::whole(".vscode/extensions/example.lost"))));
        assert!(way.retracts(Some(&Unit::whole(".vscode/extensions/example.gone"))));
        assert!(way.retracts(None) == way.not_read().next().is_none());
    }

    #[test]
    fn every_unit_there_and_not_read_is_handed_to_the_store_with_its_reason() {
        // Losing sight of a unit read before is a change only if the store hears of it: each
        // one not read comes with why, whether it failed or leads where macOS asks first.
        let mac = Mac::new("lost");
        mac.put("Library/LaunchAgents/org.example.sync.plist", "<plist/>\n");
        mac.shut("Library/LaunchAgents");
        mac.put(".cursor/mcp.json", "{}");
        let link = mac.home().join(".cursor/hooks.json");
        mac.put("Documents/hooks.json", "{}");
        std::os::unix::fs::symlink(mac.home().join("Documents/hooks.json"), &link).unwrap();
        mac.put("dev/a/.mcp.json", "{}");
        mac.shut("dev/a/.mcp.json");
        let place = mac.place(watched::AUTOSTART_KIND);
        let guarded = mac.way(".cursor/hooks.json", Scope::Home).look;
        let failed = mac.way(".mcp.json", Scope::Checkout).look;
        let said = |look: &Look| -> Vec<(String, bool)> {
            look.not_read()
                .map(|(u, why)| (u.to_string(), !why.is_empty()))
                .collect()
        };
        assert_eq!(said(&place), [("Library/LaunchAgents".to_string(), true)]);
        assert_eq!(said(&guarded), [(".cursor/hooks.json".to_string(), true)]);
        assert_eq!(said(&failed), [("dev/a/.mcp.json".to_string(), true)]);
        assert_eq!(place.cause(), Cause::Failed);
        assert_eq!(guarded.cause(), Cause::NotGiven);
        for look in [&place, &guarded, &failed] {
            assert_ne!(look.completeness().0, "full");
        }
    }

    #[test]
    fn a_place_not_on_this_mac_is_not_applicable_and_one_there_and_unreadable_failed() {
        let mac = Mac::new("here");
        // Nothing of either kind here: full, with the note that says so, and each place read.
        let place = mac.place(watched::PROFILE_KIND);
        assert_eq!(place.completeness(), ("full", Some(NOT_HERE.to_string())));
        assert!(place.read_units().contains(&Unit::whole(".zshrc")));
        let mcp = row(".mcp.json", Scope::Checkout);
        let way = mac.way(".mcp.json", Scope::Checkout);
        assert_eq!(way.coverage(mcp).0, "full");
        assert!(
            way.look
                .read_units()
                .contains(&Unit::whole("dev/a/.mcp.json"))
        );
        // There and shut: a failed reading, with its reason.
        mac.put(".ssh/config", "Host *\n");
        mac.shut(".ssh");
        mac.put("dev/a/.mcp.json", "{}");
        mac.shut("dev/a/.mcp.json");
        let place = mac.place(watched::SSH_KIND);
        let way = mac.way(".mcp.json", Scope::Checkout);
        for (completeness, reason, cause) in [
            (
                place.completeness().0,
                place.completeness().1,
                place.cause(),
            ),
            (way.coverage(mcp).0, way.coverage(mcp).1, way.look.cause()),
        ] {
            assert_eq!(completeness, "none");
            assert!(reason.is_some_and(|r| r.starts_with("could not be read: ")));
            assert_eq!(cause, Cause::Failed);
        }
    }

    #[test]
    fn a_reading_dated_ahead_of_the_clock_never_speaks_for_now() {
        let (run, now) = (Some(1_000_000), 1_000_100);
        let allowed = crate::store::AHEAD_ALLOWED;
        assert!(fresh(1_000_000, run, now));
        assert!(fresh(now + allowed, run, now));
        assert!(!fresh(now + allowed + 1, run, now));
        assert!(!fresh(now + 365 * 86_400, run, now));
        // Taken before the latest check, or with no check at all.
        assert!(!fresh(999_999, run, now));
        assert!(!fresh(now, None, now));
    }

    /// A store with the facts of an earlier build, of the machine `machine:mac` and the
    /// checkout `dev/a`.
    fn earlier(dir: &Path) -> rusqlite::Connection {
        let mut conn = crate::store::open(&dir.join("store.db")).unwrap();
        let tx = conn.transaction().unwrap();
        crate::store::put_entity(&tx, "machine:mac").unwrap();
        crate::store::put_entity(&tx, "checkout:machine:mac/dev/a").unwrap();
        tx.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id)
             VALUES ('live', 'checkout:machine:mac/dev/a', 'located_on', 'machine:mac', ?1,
                     'machine:mac', ?2, 'x:1', 'observed', 1, 'run-1')",
            params![crate::checkouts::READER, crate::checkouts::KIND],
        )
        .unwrap();
        tx.commit().unwrap();
        conn
    }

    /// A live fact of the watched places reader.
    fn fact(
        tx: &Transaction,
        scope: &str,
        kind: &str,
        subject: &str,
        predicate: &str,
        object: &str,
    ) {
        crate::store::put_entity(tx, subject).unwrap();
        tx.execute(
            "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
            [kind],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                    source_ref, basis, observed_at, run_id)
             VALUES ('live', ?1, ?2, ?3, ?4, ?5, ?6, 'x:1', 'observed', 1, 'run-1')",
            params![subject, predicate, object, watched::READER, scope, kind],
        )
        .unwrap();
    }

    #[test]
    fn what_no_row_reads_any_more_is_retired_and_never_counted_or_told_as_removed() {
        let dir = std::env::temp_dir().join(format!("immune-look-retire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = earlier(&dir);
        let tx = conn.transaction().unwrap();
        let mac = "machine:mac";
        let mcp = row(".mcp.json", Scope::Checkout).kind();
        let gone_kind = "old.json of each checkout, the part that runs by itself";
        let kept = [
            // A place a row still names, and a server a row still selects.
            (watched::PROFILE_KIND, "file:machine:mac/.zshrc"),
            (
                mcp.as_str(),
                "file:machine:mac/dev/a/.mcp.json#/mcpServers/x",
            ),
            // A thing of another machine is left as it is: this run does not speak for it.
            (watched::PROFILE_KIND, "file:machine:other/.zfoo"),
        ];
        let retired = [
            // A place no row names, and a key no row selects, of kinds still read.
            (watched::PROFILE_KIND, "file:machine:mac/.zfoo"),
            (mcp.as_str(), "file:machine:mac/dev/a/.mcp.json#/other/x"),
            // A server of a folder that was never a checkout.
            (
                mcp.as_str(),
                "file:machine:mac/dev/b/.mcp.json#/mcpServers/x",
            ),
            // A way no row reads at all.
            (gone_kind, "file:machine:mac/dev/a/old.json#/x"),
        ];
        for (kind, subject) in kept.iter().chain(&retired) {
            fact(&tx, mac, kind, subject, "watched_as", "a watched thing");
            fact(
                &tx,
                subject,
                watched::CONTENT,
                subject,
                "has_content",
                "sha256:00",
            );
        }
        // The readings this build writes beside the rows' own kinds stay as they are.
        let beside = [
            autorun::PRESENT_KIND,
            autorun::OTHERS_KIND,
            autorun::HOME_OTHERS_KIND,
            crate::guarded::KIND,
        ];
        let noted = |i: usize| format!("file:machine:mac/noted/{i}");
        for (i, kind) in beside.iter().enumerate() {
            fact(&tx, mac, kind, &noted(i), "has_content", "sha256:00");
        }
        // The profile a row still names, watched also under a kind no row reads, as an earlier
        // build named its row: that kind's fact goes, the content stays with the kind left.
        let old_kind = "shell profiles of an earlier build";
        fact(
            &tx,
            mac,
            old_kind,
            "file:machine:mac/.zshrc",
            "watched_as",
            "a watched thing",
        );
        // A launch agent recorded by a part of its file, as a build whose row read it by parts
        // would: the row of this build reads the folder's files whole, so none names it.
        let agent = "file:machine:mac/Library/LaunchAgents/a.plist#/x";
        fact(
            &tx,
            mac,
            watched::AUTOSTART_KIND,
            agent,
            "watched_as",
            "a watched thing",
        );
        let at = 2_000;
        let r = |kind| Reading {
            reader: watched::READER,
            scope: mac,
            kind,
            run_id: "run-2",
            at,
            observed_at: at,
        };
        crate::store::put_coverage(&tx, &r(gone_kind), "full", None, &Default::default()).unwrap();
        let closed = retire_unread(&tx, &r("")).unwrap();
        // Done once: the next reading closes nothing.
        let again = retire_unread(&tx, &r("")).unwrap();
        let live = |subject: &str| -> i64 {
            tx.query_row(
                "SELECT COUNT(*) FROM assertion WHERE layer = 'live' AND subject = ?1",
                [subject],
                |row| row.get(0),
            )
            .unwrap()
        };
        let journaled = |entry: &str| -> i64 {
            tx.query_row(
                "SELECT COUNT(*) FROM journal WHERE entry = ?1",
                [entry],
                |row| row.get(0),
            )
            .unwrap()
        };
        let latest: (String, Option<String>) = tx
            .query_row(
                "SELECT completeness, reason FROM coverage WHERE kind = ?1 ORDER BY id DESC LIMIT 1",
                [gone_kind],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let (kept_live, retired_live): (Vec<i64>, Vec<i64>) = (
            kept.iter().map(|(_, s)| live(s)).collect(),
            retired.iter().map(|(_, s)| live(s)).collect(),
        );
        let beside_live: Vec<i64> = (0..beside.len()).map(|i| live(&noted(i))).collect();
        let agent_live = live(agent);
        let (retired_entries, removed) = (journaled("retired"), journaled("removed"));
        drop(tx);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!((closed, again), (10, 0));
        // The profile keeps its own kind's fact and its content; the older kind's fact is gone.
        assert_eq!(kept_live, [2, 2, 2]);
        assert_eq!((retired_live, agent_live), (vec![0, 0, 0, 0], 0));
        assert_eq!(beside_live, [1, 1, 1, 1]);
        assert_eq!((retired_entries, removed), (10, 0));
        assert_eq!(latest.0, "none");
        assert!(
            latest
                .1
                .is_some_and(|r| r.starts_with(crate::lifecycle::NO_LONGER_READ))
        );
    }
}
