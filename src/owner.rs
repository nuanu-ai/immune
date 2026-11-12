//! The owner's word: the owner says that a machine is retired or not theirs. A statement is
//! kept next to the facts and never edits them: readers go on writing what they see.
//!
//! A statement names one entity, and covers the machine as the resolver groups it. While it
//! stands, the machine is not offered for the sweep and is not counted among the servers.
//! It never hides a machine seen alive after it: anything a reader other than the resolver
//! learned about the machine later than the statement contradicts it, and the machine is
//! counted and shown again. Only a withdrawal or a later statement clears that.

use crate::findings::Via;
use crate::{resolver, status, store};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

pub const RETIRED: &str = "retired";
pub const NOT_MINE: &str = "not mine";

/// One statement as it was made.
pub struct Word {
    pub entity: String,
    pub said: String,
    pub reason: String,
    pub made_at: i64,
    /// How it was given; `Unknown` for one made before this was kept.
    pub via: Via,
}

/// Something read about the machine after the statement.
pub struct Evidence {
    pub at: i64,
    pub what: String,
}

/// A statement that stands, with the machine it covers.
pub struct Standing {
    pub word: Word,
    /// The entities the resolver found to be the machine the statement names.
    pub machine: Vec<String>,
    /// Every name and address the store knows the machine by, the statement's own first.
    pub names: Vec<String>,
    /// Something seen alive after the statement, if anything was.
    pub seen: Option<Evidence>,
}

impl Standing {
    pub fn covers(&self, id: &str) -> bool {
        self.machine.iter().any(|m| m == id)
    }

    /// The name the statement was made under.
    pub fn name(&self) -> &str {
        bare(&self.word.entity)
    }

    /// `retired by the owner on <date>: <reason>`.
    pub fn summary(&self) -> String {
        format!(
            "{} by the owner on {}: {}",
            self.word.said,
            crate::view::utc(self.word.made_at),
            self.word.reason
        )
    }

    /// `<date>, <what was seen>`, when the statement is contradicted.
    pub fn contradiction(&self) -> Option<String> {
        self.seen
            .as_ref()
            .map(|e| format!("{}, {}", crate::view::utc(e.at), e.what))
    }
}

pub fn bare(id: &str) -> &str {
    id.strip_prefix("machine:").unwrap_or(id)
}

/// How a statement was given, kept with it. A table made before this was kept takes the
/// column on open; a statement made before has none and is read as `unknown`.
pub fn add_via(conn: &Connection) -> rusqlite::Result<()> {
    if !has_via(conn)? {
        conn.execute_batch("ALTER TABLE owner_statement ADD COLUMN via TEXT")?;
    }
    Ok(())
}

fn has_via(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pragma_table_info('owner_statement') WHERE name = 'via')",
        [],
        |r| r.get(0),
    )
}

fn has_table(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'owner_statement')",
        [],
        |r| r.get(0),
    )
}

/// The statements that stand. A store made before the owner's word has none.
pub fn standing(conn: &Connection) -> rusqlite::Result<Vec<Standing>> {
    if !has_table(conn)? {
        return Ok(Vec::new());
    }
    // A store opened only for reading since this build keeps no `via` yet.
    let via = if has_via(conn)? { "via" } else { "NULL" };
    let words: Vec<Word> = conn
        .prepare(&format!(
            "SELECT entity, said, reason, made_at, {via} FROM owner_statement
             WHERE withdrawn_at IS NULL"
        ))?
        .query_map([], |r| {
            Ok(Word {
                entity: r.get(0)?,
                said: r.get(1)?,
                reason: r.get(2)?,
                made_at: r.get(3)?,
                via: Via::stored(r.get::<_, Option<String>>(4)?.as_deref()),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    // Without a word in force there is nothing to place on a machine, and finding the
    // machines reads every live assertion.
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let groups = store::machine_groups(conn)?;
    let known_as = store::live_known_as(conn)?;
    let mut out: Vec<Standing> = Vec::new();
    for word in words {
        let machine = groups
            .iter()
            .find(|g| g.contains(&word.entity))
            .cloned()
            .unwrap_or_else(|| vec![word.entity.clone()]);
        let mut names = vec![bare(&word.entity).to_string()];
        let others = machine.iter().map(|m| bare(m).to_string()).chain(
            known_as
                .iter()
                .filter(|k| machine.contains(&k.entity))
                .map(|k| k.value.clone()),
        );
        for name in others {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        names[1..].sort();
        let seen = evidence(conn, &machine, word.made_at)?;
        out.push(Standing {
            word,
            machine,
            names,
            seen,
        });
    }
    out.sort_by(|a, b| a.name().cmp(b.name()));
    Ok(out)
}

/// Something a reader other than the resolver learned about the machine after the time: a
/// reading of it that read something, or an assertion first made then, whether it is still
/// made or was retracted since. A link the resolver makes later is not a sign of life, and
/// its readings are never of a server.
fn evidence(
    conn: &Connection,
    machine: &[String],
    after: i64,
) -> rusqlite::Result<Option<Evidence>> {
    for m in machine {
        let reading = conn
            .query_row(
                "SELECT observed_at, reader, kind FROM coverage
                 WHERE scope = ?1 AND completeness != 'none' AND observed_at > ?2
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![m, after],
                |r| {
                    Ok(Evidence {
                        at: r.get(0)?,
                        what: format!(
                            "{} read {} on {}",
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            bare(m)
                        ),
                    })
                },
            )
            .optional()?;
        if reading.is_some() {
            return Ok(reading);
        }
        let assertion = conn
            .query_row(
                "SELECT observed_at, reader, subject, predicate, object FROM assertion
                 WHERE reader != ?2 AND (subject = ?1 OR scope = ?1)
                   AND observed_at > ?3
                 ORDER BY observed_at DESC, id DESC LIMIT 1",
                params![m, resolver::READER, after],
                |r| {
                    Ok(Evidence {
                        at: r.get(0)?,
                        what: format!(
                            "{} saw {} {} {}",
                            r.get::<_, String>(1)?,
                            bare(&r.get::<_, String>(2)?),
                            r.get::<_, String>(3)?,
                            bare(&r.get::<_, String>(4)?)
                        ),
                    })
                },
            )
            .optional()?;
        if assertion.is_some() {
            return Ok(assertion);
        }
    }
    Ok(None)
}

/// What a name given by the owner fits.
pub enum Found {
    /// One machine: the entity the statement names, and the machine as grouped.
    One(String, Vec<String>),
    Unknown,
    /// Several machines that are not known to be one.
    Several(Vec<Vec<String>>),
}

/// The machine a name or address fits, or a full entity id. Names compare the way the
/// resolver compares them. Nothing is guessed: a name that fits several machines is not one.
pub fn find(conn: &Connection, name: &str) -> rusqlite::Result<Found> {
    let mut groups = store::machine_groups(conn)?;
    // A machine no trace names any more can still have a statement to withdraw.
    for s in standing(conn)? {
        if !groups.iter().any(|g| g.contains(&s.word.entity)) {
            groups.push(s.machine);
        }
    }
    if let Some(g) = groups.iter().find(|g| g.iter().any(|m| m == name)) {
        return Ok(Found::One(name.to_string(), g.clone()));
    }
    let norm = |v: &str| resolver::key(v).unwrap_or_else(|| v.trim().to_string());
    let wanted = norm(name);
    let mut hits: Vec<String> = Vec::new();
    for m in groups.iter().flatten() {
        if norm(bare(m)) == wanted {
            hits.push(m.clone());
        }
    }
    for k in store::live_known_as(conn)? {
        if norm(&k.value) == wanted && !hits.contains(&k.entity) {
            hits.push(k.entity);
        }
    }
    let fits: Vec<&Vec<String>> = groups
        .iter()
        .filter(|g| g.iter().any(|m| hits.contains(m)))
        .collect();
    Ok(match fits.as_slice() {
        [] => Found::Unknown,
        [machine] => {
            let named = hits.iter().find(|h| machine.contains(h)).unwrap();
            Found::One(named.clone(), machine.to_vec())
        }
        several => Found::Several(several.iter().map(|g| g.to_vec()).collect()),
    })
}

/// Withdraws every statement that stands about the machine, journals each with how it was
/// withdrawn, and returns what each said and about which entity. They are kept, with the
/// time of withdrawal.
fn withdraw_in(
    tx: &Transaction,
    machine: &[String],
    at: i64,
    run_id: &str,
    how: &str,
    via: Via,
) -> rusqlite::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for m in machine {
        let said: Vec<(i64, String)> = tx
            .prepare(
                "SELECT id, said FROM owner_statement WHERE entity = ?1 AND withdrawn_at IS NULL",
            )?
            .query_map([m], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, said) in said {
            tx.execute(
                "UPDATE owner_statement SET withdrawn_at = ?1 WHERE id = ?2",
                params![at, id],
            )?;
            store::journal_owner(
                tx,
                at,
                run_id,
                "owner_withdrew",
                m,
                &said,
                how,
                via.literal(),
            )?;
            out.push((m.clone(), said));
        }
    }
    Ok(out)
}

/// Makes a statement about the entity. One that stood about the same machine is withdrawn
/// in the same transaction: a machine has one standing statement.
#[allow(clippy::too_many_arguments)]
pub fn say(
    conn: &mut Connection,
    entity: &str,
    machine: &[String],
    said: &str,
    reason: &str,
    via: Via,
    at: i64,
    run_id: &str,
) -> rusqlite::Result<usize> {
    let tx = conn.transaction()?;
    let replaced = withdraw_in(
        &tx,
        machine,
        at,
        run_id,
        "replaced by a later statement",
        via,
    )?
    .len();
    tx.execute(
        "INSERT INTO owner_statement (entity, said, reason, made_at, via)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![entity, said, reason, at, via.literal()],
    )?;
    store::journal_owner(
        &tx,
        at,
        run_id,
        "owner_said",
        entity,
        said,
        reason,
        via.literal(),
    )?;
    tx.commit()?;
    Ok(replaced)
}

/// Withdraws what stands about the machine. Returns what was withdrawn: entity and what was
/// said about it.
pub fn withdraw(
    conn: &mut Connection,
    machine: &[String],
    via: Via,
    at: i64,
    run_id: &str,
) -> rusqlite::Result<Vec<(String, String)>> {
    let tx = conn.transaction()?;
    let n = withdraw_in(&tx, machine, at, run_id, "withdrawn by the owner", via)?;
    tx.commit()?;
    Ok(n)
}

/// How many statements were withdrawn and are kept.
pub fn withdrawn(conn: &Connection) -> rusqlite::Result<i64> {
    if !has_table(conn)? {
        return Ok(0);
    }
    conn.query_row(
        "SELECT COUNT(*) FROM owner_statement WHERE withdrawn_at IS NOT NULL",
        [],
        |r| r.get(0),
    )
}

/// The statements that stand and are known to have been made outside the app, by the owner's
/// agent or from the command line, the latest first: each sets a machine aside, so none is
/// made silently. One made before `via` was kept is not among them. Never counted as
/// something to look at.
pub fn outside_app_json(standing: &[Standing], shown: usize) -> Value {
    let mut outside: Vec<&Standing> = standing
        .iter()
        .filter(|s| s.word.via.outside_app())
        .collect();
    outside.sort_by(|a, b| {
        b.word
            .made_at
            .cmp(&a.word.made_at)
            .then_with(|| a.name().cmp(b.name()))
    });
    let items: Vec<Value> = outside
        .iter()
        .take(shown)
        .map(|s| {
            json!({
                "machine_text": status::text(s.name()),
                "entity_text": status::text(&s.word.entity),
                "said": s.word.said,
                "via": s.word.via.literal(),
                "at": crate::view::iso(s.word.made_at),
                "reason_text": status::text(&s.word.reason),
            })
        })
        .collect();
    json!({ "total": outside.len(), "items": items })
}
