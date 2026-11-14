//! `immune findings` and `immune finding <id>` as commands of the contract: the core's own
//! findings as the messages `Findings` and `Finding` (`contract/immune/v1/findings.proto`). The
//! response layer reads a finding whole to give a verdict about it.
//!
//! It reads the store and nothing else, through the same `findings::all` and `findings::item`
//! that the status, the pages and the person's form of these commands read, so the words, the
//! state and the order are theirs. What a finding rests on is given as the store holds it: the
//! journal entries it rests on, and by its kind the evidence the core keeps beside them. Text
//! from the Mac or a source goes through `known::whole`, whole and escaped one to one.

use crate::contract::{v1, value_of};
use crate::events::{self, Evidence, FileEvent, ProcessStart};
use crate::findings::{self, Found, Item};
use crate::known::{self, Refused, whole};
use crate::secrets::Args;
use crate::{matches, sigma, status, store, verdict, vulnerabilities};
use rusqlite::{Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};

/// The version of the contract this build prints.
const FORMAT: u32 = 1;

/// Every finding the store holds, in every state, the most severe first.
pub fn list(conn: &Connection, now: i64) -> rusqlite::Result<v1::Findings> {
    let found = all(conn, now)?;
    let mut items: Vec<Item> = found.iter().filter_map(findings::item).collect();
    findings::order(&mut items);
    let store_id = store::id(conn)?;
    let refs = refs(&items);
    Ok(v1::Findings {
        format: FORMAT,
        answered_at: now,
        latest_run_at: status::latest_finished(conn)?.and_then(|r| r.finished_at),
        findings: items
            .iter()
            .map(|i| listed(i, store_id.as_deref(), &refs))
            .collect(),
        store_id,
        answers_note: findings::ANSWERS_NOTE.to_string(),
    })
}

/// One finding whole; a refusal when the store has no finding with this id that this build
/// knows the rule of.
pub fn one(
    conn: &Connection,
    id: &str,
    now: i64,
) -> rusqlite::Result<Result<v1::Finding, Refused>> {
    let found = all(conn, now)?;
    let Some((f, i)) = found
        .iter()
        .find(|f| f.id == id)
        .and_then(|f| findings::item(f).map(|i| (f, i)))
    else {
        return Ok(Err(Refused {
            code: "unknown_finding",
            message: "the store has no finding with this id",
            example: "immune findings --all lists every finding with its id; with --json, every one in every state",
            ids: Vec::new(),
        }));
    };
    let rests_on = findings::basis(conn, id)?
        .into_iter()
        .map(|b| v1::JournalEntry {
            seq: b.seq,
            recorded_at: b.at,
            run_id: b.run_id,
            entry: b.entry,
            reader: b.reader,
            kind: b.kind,
            predicate: b.predicate,
            subject_text: b.subject.as_deref().map(whole),
            old_value_text: b.old_value.as_deref().map(whole),
            new_value_text: b.new_value.as_deref().map(whole),
        })
        .collect();
    let store_id = store::id(conn)?;
    let items: Vec<Item> = found.iter().filter_map(findings::item).collect();
    let verdicts = verdict::verdicts(
        verdict::of_finding(conn, id, &f.rule)?,
        store_id.as_deref(),
        &refs(&items),
        i.verdicts.as_ref().and_then(|s| s.standing.as_ref()),
    );
    Ok(Ok(v1::Finding {
        format: FORMAT,
        answered_at: now,
        store_id,
        verdicts,
        finding: Some(known::finding_ref(&i)),
        kind: i.kind.to_string(),
        title: i.words.title.to_string(),
        meaning: i.words.meaning.to_string(),
        advice: i.words.advice.to_string(),
        technique_text: i.technique.map(whole),
        where_text: whole(&f.place),
        first_seen_at: f.first_seen.0,
        last_seen_at: f.last_seen.0,
        answer: i.answer.as_ref().map(answer),
        evidence: evidence(conn, f)?.map(|body| v1::Evidence { body: Some(body) }),
        rests_on,
        answers_note: findings::ANSWERS_NOTE.to_string(),
    }))
}

/// Every finding. The table of findings is read first, so that a store an older build left
/// without it fails as written by an older build (`known::read` says so) rather than reading
/// as a store with no findings.
fn all(conn: &Connection, now: i64) -> rusqlite::Result<Vec<Found>> {
    conn.query_row("SELECT COUNT(*) FROM finding", [], |_| Ok(()))?;
    Ok(findings::all(conn, now)?.unwrap_or_default())
}

/// Every finding by id, as an answer names one.
pub fn refs(items: &[Item]) -> BTreeMap<String, v1::FindingRef> {
    items
        .iter()
        .map(|i| (i.id.clone(), known::finding_ref(i)))
        .collect()
}

pub fn listed(
    i: &Item,
    store_id: Option<&str>,
    refs: &BTreeMap<String, v1::FindingRef>,
) -> v1::ListedFinding {
    v1::ListedFinding {
        // Counted, with only the verdict that raised a `verdict.suspicious` finding listed.
        verdicts: i.verdicts.as_ref().and_then(|s| {
            let opening = s.opening.iter().cloned().collect();
            verdict::verdicts(
                (s.total, s.suspicious, opening),
                store_id,
                refs,
                s.standing.as_ref(),
            )
        }),
        finding: Some(known::finding_ref(i)),
        kind: i.kind.to_string(),
        title: i.words.title.to_string(),
        where_text: whole(i.place.as_deref().unwrap_or_default()),
        // A finding's item always has both.
        first_seen_at: i.first_seen.unwrap_or_default(),
        last_seen_at: i.last_seen.unwrap_or_default(),
        answer: i.answer.as_ref().map(answer),
    }
}

fn answer(a: &findings::Answered) -> v1::Answer {
    v1::Answer {
        given: value_of::<v1::AnswerKind>(a.given),
        via: value_of::<v1::Via>(a.via.literal()),
        given_at: a.at,
        reason_text: a.reason.as_ref().map(|r| r.shown(whole)),
        reason_cuts: a
            .reason
            .as_ref()
            .map(crate::answer::reason_cuts)
            .unwrap_or_default(),
        until_at: a.until,
        in_force: a.in_force,
    }
}

/// What a finding rests on, by the kind of its rule; `None` for a kind this build does not
/// shape.
pub fn evidence(conn: &Connection, f: &Found) -> rusqlite::Result<Option<v1::evidence::Body>> {
    use v1::evidence::Body;
    if let Some(l) = findings::published(&f.rule) {
        let (Some(meta), Some(kind)) = (&l.meta, l.kind) else {
            return Ok(None);
        };
        return Ok(Some(Body::PublishedRuleMatched(v1::PublishedRuleMatched {
            rule: Some(matches::rule(l.file, meta)),
            matches: rule_count(conn, &f.id)?,
            events: rule_events(conn, &f.id, kind)?,
            source: meta.source.url.to_string(),
            licence: meta.source.licence.to_string(),
        })));
    }
    if let Some(subject) = f.rule.strip_prefix(verdict::PREFIX) {
        let events = match findings::published(subject).and_then(|l| l.kind) {
            Some(kind) => rule_events(conn, &f.id, kind)?,
            None => Vec::new(),
        };
        return Ok(Some(Body::VerdictGiven(v1::VerdictGiven {
            rule: subject.to_string(),
            events,
        })));
    }
    let became = || f.became.as_deref().map(whole);
    Ok(Some(
        match f.rule.split_once('.').map(|(family, _)| family) {
            Some("watched" | "autorun") => Body::PlaceChanged(v1::PlaceChanged {
                change: change(f.change.as_deref()),
                presence_only: crate::watched::last_presence_only(conn, &f.about)?,
            }),
            Some("integrity") => Body::ChangedInPlace(v1::ChangedInPlace {
                became_text: became(),
            }),
            Some("indicator") => Body::IndicatorMatched(v1::IndicatorMatched {
                indicators_text: became(),
            }),
            Some("processes") => Body::DetachedProcess(detached(conn, &f.id)?),
            Some("lockfiles") => Body::VulnerablePackage(package(conn, &f.about)?),
            _ => return Ok(None),
        },
    ))
}

/// A change as the store words it, with spaces written as underscores in the contract.
fn change(word: Option<&str>) -> i32 {
    change_of(word.unwrap_or_default())
}

/// The same for a word that is there.
pub fn change_of(word: &str) -> i32 {
    value_of::<v1::Change>(&word.replace(' ', "_"))
}

/// Whether the store has a table: one a reading of this build creates may be missing from a
/// store no such reading has written.
fn has(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |r| r.get(0),
    )
}

/// How many events a published rule's finding counts since it was raised; `None` when the
/// store holds no count for it.
fn rule_count(conn: &Connection, finding: &str) -> rusqlite::Result<Option<u64>> {
    if !has(conn, "rule_finding")? {
        return Ok(None);
    }
    let n: Option<i64> = conn
        .query_row(
            "SELECT matches FROM rule_finding WHERE finding = ?1",
            [finding],
            |r| r.get(0),
        )
        .optional()?;
    Ok(n.map(|n| n as u64))
}

/// The events a published rule's finding keeps, newest first, as `immune matches` gives an
/// event: the rows are made back into what the collector's reading made them from.
fn rule_events(
    conn: &Connection,
    finding: &str,
    kind: sigma::Kind,
) -> rusqlite::Result<Vec<v1::Event>> {
    let table = match kind {
        sigma::Kind::Process => "rule_evidence",
        sigma::Kind::File => "rule_file_evidence",
    };
    if !has(conn, table)? {
        return Ok(Vec::new());
    }
    // A row's arguments are read back cut, and cut again, so a set newer than the one that kept
    // them applies; the start made from the row holds none.
    let form = crate::secrets::form(conn)?;
    let read: Vec<(Evidence, Args)> = match kind {
        sigma::Kind::Process => conn
            .prepare(
                "SELECT timestamp, executable, args, parent_executable, working_directory, pid,
                        parent_pid, user_id, signing_id, team_id, platform_binary
                 FROM rule_evidence WHERE finding = ?1 ORDER BY rowid DESC",
            )?
            .query_map([finding], |r| {
                let args: String = r.get(2)?;
                let args: Vec<String> = serde_json::from_str(&args).unwrap_or_default();
                let start = Evidence::Start(ProcessStart {
                    timestamp: r.get(0)?,
                    executable: r.get(1)?,
                    parent_executable: r.get(3)?,
                    working_directory: r.get(4)?,
                    pid: r.get(5)?,
                    parent_pid: r.get(6)?,
                    user_id: r.get(7)?,
                    signing_id: r.get(8)?,
                    team_id: r.get(9)?,
                    platform_binary: r.get(10)?,
                    ..ProcessStart::default()
                });
                Ok((start, Args::stored(&args, form)))
            })?
            .collect::<rusqlite::Result<_>>()?,
        sigma::Kind::File => conn
            .prepare(
                "SELECT timestamp, action, path, source, executable
                 FROM rule_file_evidence WHERE finding = ?1 ORDER BY rowid DESC",
            )?
            .query_map([finding], |r| {
                let action: String = r.get(1)?;
                let event = Evidence::File(FileEvent {
                    timestamp: r.get(0)?,
                    // A word the collector's reading does not write is no action: it prints
                    // as unspecified, which a reader cannot judge.
                    action: events::FILE_KINDS
                        .iter()
                        .find(|k| **k == action)
                        .copied()
                        .unwrap_or_default(),
                    path: r.get(2)?,
                    source: r.get(3)?,
                    executable: r.get(4)?,
                    ..FileEvent::default()
                });
                Ok((event, Args(Vec::new())))
            })?
            .collect::<rusqlite::Result<_>>()?,
    };
    Ok(read
        .iter()
        .map(|(e, args)| matches::event_cut(e, args))
        .collect())
}

/// The process the latest sample that raised or found again a finding saw, by its pid and
/// start, as the journal entry `sampled` keeps them.
fn detached(conn: &Connection, finding: &str) -> rusqlite::Result<v1::DetachedProcess> {
    let note: Option<String> = conn
        .query_row(
            "SELECT j.text FROM finding_basis b JOIN journal j ON j.seq = b.journal
             WHERE b.finding = ?1 AND j.entry = 'sampled' ORDER BY j.seq DESC LIMIT 1",
            [finding],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let note: serde_json::Value = note
        .and_then(|n| serde_json::from_str(&n).ok())
        .unwrap_or_default();
    Ok(v1::DetachedProcess {
        pid: note["pid"].as_i64(),
        start_micros: note["start"].as_i64(),
    })
}

/// A package a project depends on, from the answers that stand now, as the report reads them
/// (`vulnerabilities::finding_detail`): every record that affects it, and every release it
/// affects with where it is declared.
fn package(conn: &Connection, about: &str) -> rusqlite::Result<v1::VulnerablePackage> {
    let mine: Vec<vulnerabilities::Affecting> = vulnerabilities::affecting(conn)?
        .into_iter()
        .filter(|a| format!("component:{}/{}/{}", a.checkout, a.ecosystem, a.package) == about)
        .collect();
    let mut out = v1::VulnerablePackage::default();
    let Some(first) = mine.first() else {
        return Ok(out);
    };
    out.project_text = Some(whole(&first.checkout));
    out.ecosystem = Some(first.ecosystem.clone());
    out.package_text = Some(whole(&first.package));
    // A release two records affect is given once.
    let releases: BTreeSet<(String, String)> = mine.iter().flat_map(|a| a.affected()).collect();
    out.releases = releases
        .iter()
        .map(|(version, line)| v1::PackageRelease {
            version_text: whole(version),
            at_text: whole(&vulnerabilities::at_shown(line)),
        })
        .collect();
    let listed = crate::threats::last_good(conn).unwrap_or(None).is_some();
    for a in &mine {
        out.records.push(v1::PackageRecord {
            id_text: whole(&a.advisory),
            aliases_text: a.aliases.iter().map(|s| whole(s)).collect(),
            source: vulnerabilities::source_name(&a.advisory).to_string(),
            label: a.label.to_string(),
            exploited: vulnerabilities::exploited(a.exploited, listed),
            summary_text: a.summary.as_deref().map(whole),
            fixed_text: a.fixed.iter().map(|s| whole(s)).collect(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{change, v1};

    #[test]
    fn every_change_the_store_words_is_a_value_of_the_contract_and_never_unspecified() {
        // A reader takes an unspecified change for one it cannot judge.
        for (word, value) in [
            ("new", v1::Change::New),
            ("changed", v1::Change::Changed),
            ("gone", v1::Change::Gone),
            ("first read", v1::Change::FirstRead),
            (crate::findings::NOT_READ, v1::Change::NotRead),
        ] {
            assert_eq!(change(Some(word)), value as i32, "{word}");
        }
        assert_eq!(change(None), v1::Change::Unspecified as i32);
        assert_eq!(
            change(Some("unknown change")),
            v1::Change::Unspecified as i32
        );
    }
}
