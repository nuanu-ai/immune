//! The view: one self-contained HTML page that shows what is in the store.
//! It only reads. No scripts, no outside files: plain HTML, `<details>` and inline CSS.
//!
//! Invariant: every piece of text that comes from the store goes through `esc`
//! before it enters the page. Names, versions, reasons and source references are
//! partly written by an attacker and must never become markup.

use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

const RUNS_SHOWN: i64 = 20;

type Out = Result<(), Box<dyn Error>>;

pub fn page(conn: &Connection, store: &str, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = String::new();
    out.push_str(HEAD);
    header(conn, &mut out, store, now)?;
    coverage(conn, &mut out)?;
    machines(conn, &mut out)?;
    changes(conn, &mut out)?;
    retracted(conn, &mut out)?;
    vocabulary(conn, &mut out)?;
    out.push_str("</main>\n</body>\n</html>\n");
    Ok(out)
}

/// Makes text safe to put anywhere in the page, inside elements and inside quoted attributes.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// UTC seconds as `YYYY-MM-DD HH:MM UTC`, from the civil-from-days algorithm.
pub fn utc(secs: i64) -> String {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn utc_or(secs: Option<i64>, missing: &str) -> String {
    secs.map(utc).unwrap_or_else(|| missing.to_string())
}

/// Ecosystem and name from `component:<where>/<ecosystem>/<name>`, or no ecosystem and
/// the whole id for anything else.
fn component_name(id: &str) -> (&str, &str) {
    let Some(rest) = id.strip_prefix("component:") else {
        return ("", id);
    };
    let mut parts = rest.rsplitn(3, '/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(name), Some(ecosystem), Some(_)) => (ecosystem, name),
        _ => ("", id),
    }
}

/// The predicate in plain words where there is one.
fn what(predicate: &str) -> &str {
    match predicate {
        "part_of" => "present on",
        "has_version" => "version",
        "located_on" => "located on",
        "runs_os" => "operating system",
        other => other,
    }
}

/// A table cell with escaped text and an optional class.
fn td(out: &mut String, class: &str, text: &str) -> Out {
    if class.is_empty() {
        write!(out, "<td>{}</td>", esc(text))?;
    } else {
        write!(out, "<td class=\"{class}\">{}</td>", esc(text))?;
    }
    Ok(())
}

/// A cell that shows a component's name and keeps its full id as a tooltip.
fn td_component(out: &mut String, id: &str) -> Out {
    write!(
        out,
        "<td title=\"{}\">{}</td>",
        esc(id),
        esc(component_name(id).1)
    )?;
    Ok(())
}

fn thead(out: &mut String, columns: &[&str]) {
    out.push_str("<thead><tr>");
    for c in columns {
        out.push_str("<th>");
        out.push_str(c);
        out.push_str("</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");
}

fn header(conn: &Connection, out: &mut String, store: &str, now: i64) -> Out {
    let version: String = conn.query_row(
        "SELECT value FROM meta WHERE key = 'format_version'",
        [],
        |r| r.get(0),
    )?;
    let finished: Option<i64> = conn.query_row(
        "SELECT MAX(at) FROM journal WHERE entry = 'run_finished'",
        [],
        |r| r.get(0),
    )?;
    write!(
        out,
        "<header>\n<h1>What the store holds</h1>\n<p class=\"meta\">Generated {} · store <span class=\"mono\">{}</span> · format version {} · last run finished {}</p>\n</header>\n",
        utc(now),
        esc(store),
        esc(&version),
        utc_or(finished, "never")
    )?;
    Ok(())
}

/// The latest run, by the order of the journal, if it never wrote `run_finished`.
fn unfinished_latest_run(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let latest: Option<(i64, bool)> = conn
        .query_row(
            "SELECT at, EXISTS (SELECT 1 FROM journal f
                                WHERE f.run_id = j.run_id AND f.entry = 'run_finished')
             FROM journal j WHERE entry = 'run_started' ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(latest.and_then(|(at, finished)| (!finished).then_some(at)))
}

fn coverage(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"coverage\">\n<h2>What was read and how completely</h2>\n");
    out.push_str("<p class=\"muted\">Everything below is only as good as this.</p>\n");
    if let Some(at) = unfinished_latest_run(conn)? {
        writeln!(
            out,
            "<p class=\"alert\">The latest run started at {} and never finished. Nothing it read is in the store.</p>",
            utc(at)
        )?;
    }

    // The latest record for each reader, scope and kind, and its latest full one.
    let mut stmt = conn.prepare(
        "SELECT c.reader, c.scope, c.kind, c.completeness, c.reason, c.observed_at,
                (SELECT MAX(f.observed_at) FROM coverage f
                 WHERE f.reader = c.reader AND f.scope = c.scope AND f.kind = c.kind
                   AND f.completeness = 'full')
         FROM coverage c
         WHERE c.id = (SELECT MAX(d.id) FROM coverage d
                       WHERE d.reader = c.reader AND d.scope = c.scope AND d.kind = c.kind)
         ORDER BY c.reader, c.scope, c.kind",
    )?;
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        Option<i64>,
    );
    let rows: Vec<Row> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;

    if rows.is_empty() {
        out.push_str("<p class=\"alert\">Nothing has been read yet.</p>\n</section>\n");
        return Ok(());
    }
    let not_full = rows.iter().filter(|r| r.3 != "full").count();
    if not_full == 0 {
        out.push_str("<p class=\"ok\">Every reading was full at its latest run.</p>\n");
    } else {
        writeln!(
            out,
            "<p class=\"alert\">{not_full} of {} readings were not full at their latest run. \
             What they cover below may be out of date or missing.</p>",
            rows.len()
        )?;
    }

    out.push_str("<div class=\"scroll\"><table>\n");
    thead(
        out,
        &[
            "Reader",
            "Where",
            "What",
            "Completeness",
            "Why not full",
            "Last read",
            "Last full read",
        ],
    );
    for (reader, scope, kind, completeness, reason, at, last_full) in &rows {
        let full = completeness == "full";
        out.push_str(if full { "<tr>" } else { "<tr class=\"bad\">" });
        td(out, "", reader)?;
        td(out, "mono", scope)?;
        td(out, "", kind)?;
        let label = match completeness.as_str() {
            "none" => "nothing read",
            other => other,
        };
        write!(
            out,
            "<td><span class=\"badge {}\">{}</span></td>",
            if full { "good" } else { "bad" },
            esc(label)
        )?;
        td(
            out,
            "",
            reason
                .as_deref()
                .unwrap_or(if full { "" } else { "no reason given" }),
        )?;
        td(out, "nowrap", &utc(*at))?;
        let last = if full {
            "this one".to_string()
        } else {
            utc_or(*last_full, "never")
        };
        td(out, "nowrap", &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</section>\n");
    Ok(())
}

#[derive(Default)]
struct Component {
    versions: BTreeSet<String>,
    bases: BTreeSet<String>,
    readers: BTreeSet<String>,
    sources: BTreeSet<String>,
    first_seen: Option<i64>,
}

fn machines(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"machines\">\n<h2>Machines</h2>\n");
    let ids: Vec<String> = conn
        .prepare("SELECT id FROM entity WHERE type = 'machine' ORDER BY id")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if ids.is_empty() {
        out.push_str("<p>No machines known.</p>\n");
    }

    // Only live rows: a component whose assertions were all retracted is not on the machine.
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object, reader, basis, observed_at, source_ref
         FROM assertion
         WHERE layer = 'live'
           AND subject IN (SELECT subject FROM assertion
                           WHERE predicate = 'part_of' AND object = ?1)",
    )?;
    for machine in &ids {
        let mut components: BTreeMap<String, Component> = BTreeMap::new();
        let rows = stmt.query_map([machine], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        for row in rows {
            let (subject, predicate, object, reader, basis, at, source) = row?;
            let c = components.entry(subject).or_default();
            if predicate == "has_version" {
                c.versions.insert(object);
            }
            c.bases.insert(basis);
            c.readers.insert(reader);
            c.sources.insert(source);
            c.first_seen = Some(c.first_seen.map_or(at, |t| t.min(at)));
        }
        let mut sorted: Vec<_> = components.iter().collect();
        sorted.sort_by_key(|(id, _)| {
            let (ecosystem, name) = component_name(id);
            (name.to_lowercase(), ecosystem.to_string())
        });

        let label = machine.strip_prefix("machine:").unwrap_or(machine);
        write!(
            out,
            "<details open>\n<summary><strong>{}</strong> <span class=\"muted\">{} · {} components</span></summary>\n",
            esc(label),
            esc(machine),
            sorted.len()
        )?;
        if sorted.is_empty() {
            out.push_str("<p>No components known.</p>\n</details>\n");
            continue;
        }
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        thead(
            out,
            &[
                "Name",
                "Ecosystem",
                "Version",
                "Basis",
                "Reader",
                "First seen",
                "Source",
            ],
        );
        let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
        for (id, c) in sorted {
            out.push_str("<tr>");
            td_component(out, id)?;
            td(out, "", component_name(id).0)?;
            td(out, "mono", &join(&c.versions))?;
            td(out, "", &join(&c.bases))?;
            td(out, "", &join(&c.readers))?;
            td(out, "nowrap", &utc_or(c.first_seen, ""))?;
            td(out, "mono", &join(&c.sources))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

fn changes(conn: &Connection, out: &mut String) -> Out {
    write!(
        out,
        "<section id=\"changes\">\n<h2>Changes</h2>\n<p class=\"muted\">The last {RUNS_SHOWN} runs, newest first.</p>\n"
    )?;
    let mut runs_stmt = conn.prepare(
        "SELECT run_id, MIN(at),
                MAX(entry = 'run_finished'),
                MAX(CASE WHEN entry = 'report' THEN text END)
         FROM journal GROUP BY run_id ORDER BY MAX(seq) DESC LIMIT ?1",
    )?;
    let runs: Vec<(String, i64, bool, Option<String>)> = runs_stmt
        .query_map([RUNS_SHOWN], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if runs.is_empty() {
        out.push_str("<p>No runs yet.</p>\n");
    }

    let mut events_stmt = conn.prepare(
        "SELECT entry, subject, predicate, old_value, new_value FROM journal
         WHERE run_id = ?1 AND entry IN ('added', 'changed', 'removed') ORDER BY seq",
    )?;
    let mut not_full_stmt = conn.prepare(
        "SELECT kind, completeness, reason FROM coverage
         WHERE run_id = ?1 AND completeness != 'full' ORDER BY id",
    )?;
    for (i, (run_id, at, finished, report)) in runs.iter().enumerate() {
        type Event = (String, String, String, Option<String>, Option<String>);
        let events: Vec<Event> = events_stmt
            .query_map([run_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let not_full: Vec<(String, String, Option<String>)> = not_full_stmt
            .query_map([run_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;

        // Counts things, not assertions, as the report does.
        let count = |kind: &str| {
            events
                .iter()
                .filter(|e| e.0 == kind)
                .map(|e| e.1.as_str())
                .collect::<BTreeSet<_>>()
                .len()
        };
        // No events is "no changes" only when the run finished and read everything in full.
        let summary = if !finished {
            "did not finish, changes unknown".to_string()
        } else if !events.is_empty() {
            format!(
                "+{} added, {} changed, {} removed",
                count("added"),
                count("changed"),
                count("removed")
            )
        } else if !not_full.is_empty() {
            "changes unknown, a reading was not full".to_string()
        } else {
            "no changes".to_string()
        };

        write!(
            out,
            "<details{}>\n<summary><span class=\"nowrap\">{}</span> · {}</summary>\n",
            if i == 0 { " open" } else { "" },
            utc(*at),
            esc(&summary)
        )?;
        if let Some(report) = report {
            writeln!(out, "<p class=\"muted mono\">{}</p>", esc(report))?;
        }
        for (kind, completeness, reason) in &not_full {
            writeln!(
                out,
                "<p class=\"alert\">{}: {}. {}</p>",
                esc(kind),
                esc(completeness),
                esc(reason.as_deref().unwrap_or("no reason given"))
            )?;
        }
        if !events.is_empty() {
            out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
            thead(out, &["Change", "Component", "What", "Value"]);
            for (entry, subject, predicate, old, new) in &events {
                write!(out, "<tr class=\"{}\">", esc(entry))?;
                td(out, "", entry)?;
                td_component(out, subject)?;
                td(out, "", what(predicate))?;
                let value = match (old, new) {
                    (Some(o), Some(n)) => format!("{o} → {n}"),
                    (Some(v), None) | (None, Some(v)) => v.clone(),
                    (None, None) => String::new(),
                };
                td(out, "mono", &value)?;
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table></div>\n");
        }
        out.push_str("</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

fn retracted(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"gone\">\n<h2>No longer there</h2>\n");
    type Row = (String, String, String, String, i64, Option<i64>, String);
    let rows: Vec<Row> = conn
        .prepare(
            "SELECT subject, predicate, object, reader, observed_at, retracted_at, source_ref
             FROM assertion WHERE layer = 'retracted'
             ORDER BY retracted_at DESC, subject, predicate, object",
        )?
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        out.push_str("<p>Nothing has disappeared yet.</p>\n</section>\n");
        return Ok(());
    }
    write!(
        out,
        "<details>\n<summary>{} statements no longer made, newest first</summary>\n",
        rows.len()
    )?;
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    thead(
        out,
        &[
            "Component",
            "What",
            "Value",
            "Reader",
            "First seen",
            "Gone since",
            "Source",
        ],
    );
    for (subject, predicate, object, reader, seen, gone, source) in &rows {
        out.push_str("<tr>");
        td_component(out, subject)?;
        td(out, "", what(predicate))?;
        td(out, "mono", object)?;
        td(out, "", reader)?;
        td(out, "nowrap", &utc(*seen))?;
        td(out, "nowrap", &utc_or(*gone, ""))?;
        td(out, "mono", source)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</details>\n</section>\n");
    Ok(())
}

fn vocabulary(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"vocabulary\">\n<h2>Vocabulary</h2>\n<details>\n");
    out.push_str("<summary>The words the store uses: kinds of things, links between them and how a source knows</summary>\n");
    let tables: [(&str, &[&str], &str); 3] = [
        (
            "Kinds of things",
            &["Name", "Status"],
            "SELECT name, status FROM entity_type ORDER BY status = 'reserved', name",
        ),
        (
            "Links",
            &["Name", "Points to", "Status"],
            "SELECT name, COALESCE(object_kind, ''), status FROM predicate
             ORDER BY status = 'reserved', name",
        ),
        (
            "Basis, strongest first",
            &["Name", "Strength"],
            "SELECT name, CAST(strength AS TEXT) FROM basis_kind ORDER BY strength",
        ),
    ];
    for (title, columns, sql) in tables {
        write!(
            out,
            "<h3>{title}</h3>\n<div class=\"scroll\"><table class=\"dense\">\n"
        )?;
        thead(out, columns);
        let mut stmt = conn.prepare(sql)?;
        let n = stmt.column_count();
        let rows = stmt.query_map([], |r| {
            (0..n)
                .map(|i| r.get::<_, String>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for row in rows {
            out.push_str("<tr>");
            for cell in row? {
                td(out, "", &cell)?;
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</details>\n</section>\n");
    Ok(())
}

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>What the store holds</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --fg: #1d1d1f; --muted: #5c5f66; --line: #e2e2df; --head: #f2f2ef;
  --bad-bg: #fdeceb; --bad-fg: #a3120a; --ok-bg: #e7f3ea; --ok-fg: #1b6331;
  --added: #1b6331; --removed: #a3120a; --changed: #8a4b00;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #151517; --fg: #e9e9e7; --muted: #a2a3a8; --line: #2f2f34; --head: #1f1f23;
    --bad-bg: #3b1714; --bad-fg: #ffb3a8; --ok-bg: #15301d; --ok-fg: #94d6a5;
    --added: #94d6a5; --removed: #ffb3a8; --changed: #f2c27b;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 76rem; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 1.4rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 40px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: .95rem; margin: 16px 0 6px; }
p { margin: 8px 0; }
.meta { color: var(--muted); font-size: .875rem; margin: 0; overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; margin: 6px 0; }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--head); font-weight: 600; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
table.dense th, table.dense td { padding: 3px 10px; }
td.mono { overflow-wrap: normal; white-space: nowrap; }
tr.bad td { background: var(--bad-bg); }
tr.added td:first-child { color: var(--added); }
tr.removed td:first-child { color: var(--removed); }
tr.changed td:first-child { color: var(--changed); }
.badge { display: inline-block; padding: 0 8px; border-radius: 999px; font-weight: 600; font-size: .8rem; white-space: nowrap; }
.badge.good { background: var(--ok-bg); color: var(--ok-fg); }
.badge.bad { background: var(--bad-fg); color: var(--bg); }
.alert { background: var(--bad-bg); color: var(--bad-fg); border-left: 4px solid var(--bad-fg);
  padding: 8px 12px; border-radius: 4px; font-weight: 600; overflow-wrap: anywhere; }
.ok { background: var(--ok-bg); color: var(--ok-fg); border-left: 4px solid var(--ok-fg);
  padding: 8px 12px; border-radius: 4px; }
details { margin: 8px 0; }
summary { cursor: pointer; padding: 4px 0; }
</style>
</head>
<body>
<main>
"#;

#[cfg(test)]
mod tests {
    use super::utc;

    #[test]
    fn times_are_shown_as_utc_calendar_dates() {
        // The owner reads every time on the page; a wrong date misleads silently.
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc(1_731_196_800), "2024-11-10 00:00 UTC");
        assert_eq!(utc(4_107_542_340), "2100-02-28 23:59 UTC");
    }
}
