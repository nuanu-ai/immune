//! The summary's section "As it happens": every program start on this Mac, checked against the
//! published rules. Three numbers first, each drawn: program starts in the last day with a bar
//! for each hour, what was lost, and how many rules watch. Then the rules that matched this week,
//! the most severe first, and a grid of ATT&CK techniques for macOS, one square each, grouped by
//! tactic in the matrix's order, saying which the rules cover and what they found. Drawn in Rust
//! as inline SVG and plain elements, as `src/map.rs` draws the map.
//!
//! Alive while open. A running watcher writes `view/live.js` after every reading of program
//! starts (`live`): numbers, rule ids of shipped rules and fixed words, nothing from an event,
//! a rule's text or the store's free text. One fixed script, `src/happens.js`, written beside
//! the pages, loads it every ten seconds and redraws the numbers in place; the header says how
//! fresh they are, or "not updating: no watcher is running" once the file is a minute old. It is
//! the page's only script, and it adds no text but its own words and numbers. Without it the
//! section is complete as made, and says when it was made.
//!
//! No false calm, the project's first invariant. Nothing is drawn as watching unless the event
//! level's latest state is `running`: while it is not, the section says so first, and the rules
//! and the grid show what would be watched, a technique with a rule drawn hollow, never calm. A
//! technique is covered only by a rule evaluated in full; one named only by rules evaluated in
//! part or not at all is "no rule yet". "None lost" is said only when coverage over the day is
//! full. Red is for an open finding alone.
//!
//! The list of techniques is MITRE's, `rules/attack/macos.json` with its NOTICE, compiled in.
//! Which techniques a rule covers is the rule's own `attack.t…` tags (`src/sigma.rs`), a
//! sub-technique counted as its parent. Every string taken from a rule is data: escaped, in an
//! element of its own.

use crate::events::{self, Level};
use crate::findings::Item;
use crate::sigma::{self, Placement, Reason, Rules};
use crate::view::{DETAILS, Out, esc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::sync::OnceLock;

/// The section's anchor, which the app opens, and its heading.
pub const ANCHOR: &str = "as-it-happens";
pub const TITLE: &str = "As it happens";
/// How many rules that matched this week the section lists; the rest are counted.
const ROWS_SHOWN: usize = 10;
/// The section's script, and where it is written, relative to the store's folder, beside the
/// pages; the summary names it in its one script tag.
pub const SCRIPT: &str = include_str!("happens.js");
pub const SCRIPT_FILE: &str = "view/happens.js";
pub const SCRIPT_TAG: &str = "<script src=\"view/happens.js\"></script>";
/// What a running watcher writes after each reading of program starts, for the script.
pub const LIVE_FILE: &str = "view/live.js";
/// MITRE's techniques for macOS, as `rules/attack/NOTICE` says they were made.
const ATTACK: &str = include_str!("../rules/attack/macos.json");
/// MITRE's copyright designation, which its licence asks every copy to carry.
const MITRE: &str = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.";

/// The ATT&CK techniques for macOS, by tactic in the matrix's order.
pub struct Attack {
    pub release: String,
    pub tactics: Vec<Tactic>,
    /// Every technique's name, by its id.
    pub names: BTreeMap<String, String>,
}

pub struct Tactic {
    pub name: String,
    pub techniques: Vec<String>,
}

/// The data file, read once. It is compiled in, and a test reads it whole, so a malformed file
/// fails the build's tests, never a page.
pub fn attack() -> &'static Attack {
    static READ: OnceLock<Attack> = OnceLock::new();
    READ.get_or_init(|| {
        let v: Value = serde_json::from_str(ATTACK).expect("rules/attack/macos.json is JSON");
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        Attack {
            release: text(&v["release"]),
            tactics: v["tactics"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| Tactic {
                    name: text(&t["name"]),
                    techniques: t["techniques"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(text)
                        .collect(),
                })
                .collect(),
            names: v["techniques"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| (text(&t["id"]), text(&t["name"])))
                .collect(),
        }
    })
}

/// A technique as the grid draws it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Square {
    /// A rule for it raised a finding that is open.
    Finding,
    /// A rule for it matched this week.
    Matched,
    /// A rule evaluated in full covers it, the level runs, and nothing matched: calm.
    Quiet,
    /// A rule evaluated in full covers it, but the level does not run: nothing watches it now.
    Would,
    /// No rule evaluated in full covers it.
    NoRule,
}

impl Square {
    fn class(self) -> &'static str {
        match self {
            Square::Finding => "look",
            Square::Matched => "hit",
            Square::Quiet => "calm",
            Square::Would => "would",
            Square::NoRule => "open",
        }
    }

    fn said(self) -> &'static str {
        match self {
            Square::Finding => "a rule for it raised a finding",
            Square::Matched => "a rule for it matched this week",
            Square::Quiet => "watched, quiet",
            Square::Would => "has a rule, not watching now",
            Square::NoRule => "no rule yet",
        }
    }
}

/// A technique id as the grid counts it: a sub-technique as its parent.
fn parent(t: &str) -> &str {
    t.split('.').next().unwrap_or(t)
}

/// The techniques the rules name, as parents, for the rules `which` picks.
fn named(rules: &Rules, which: impl Fn(&sigma::Loaded) -> bool) -> BTreeSet<&str> {
    rules
        .rules
        .iter()
        .filter(|l| which(l))
        .filter_map(|l| l.meta.as_ref())
        .flat_map(|m| m.techniques.iter().map(|t| parent(t)))
        .collect()
}

/// Which events the level records now, and so which rules evaluated in full watch: those for
/// program starts while it runs, those for file events while it runs and its collector
/// records them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Watching {
    pub starts: bool,
    pub files: bool,
}

impl Watching {
    #[cfg(test)]
    pub const NONE: Watching = Watching {
        starts: false,
        files: false,
    };
    #[cfg(test)]
    pub const ALL: Watching = Watching {
        starts: true,
        files: true,
    };

    /// As the level's latest reading left it.
    pub fn of(level: Option<&Level>) -> Watching {
        let starts = level.is_some_and(|l| l.state == events::RUNNING);
        Watching {
            starts,
            files: level.is_some_and(Level::files_watched),
        }
    }

    /// Whether this rule watches now: evaluated in full, about events the level records.
    pub fn watches(self, l: &sigma::Loaded) -> bool {
        l.placement == Placement::Evaluated
            && match l.kind {
                Some(sigma::Kind::Process) => self.starts,
                Some(sigma::Kind::File) => self.files,
                None => false,
            }
    }
}

/// Every tactic with its techniques, each in its state, the most telling first and then by id.
/// `watching`: which events the level records now. `week`: matches by rule id this week.
/// `raised`: the ids of rules with an open finding. `rules`: the rules shipped.
pub fn grid<'a>(
    attack: &'a Attack,
    rules: &Rules,
    watching: Watching,
    week: &BTreeMap<String, i64>,
    raised: &BTreeSet<&str>,
) -> Vec<(&'a Tactic, Vec<(&'a str, Square)>)> {
    let watched = named(rules, |l| l.placement == Placement::Evaluated);
    let now = named(rules, |l| watching.watches(l));
    fn id(l: &sigma::Loaded) -> Option<&str> {
        l.meta.as_ref().map(|m| m.id.as_str())
    }
    let matched = named(rules, |l| {
        id(l).is_some_and(|id| week.get(id).is_some_and(|n| *n > 0))
    });
    let found = named(rules, |l| id(l).is_some_and(|id| raised.contains(id)));
    attack
        .tactics
        .iter()
        .map(|t| {
            let mut squares: Vec<(&str, Square)> = t
                .techniques
                .iter()
                .map(|tech| {
                    let tech = tech.as_str();
                    let square = if found.contains(tech) {
                        Square::Finding
                    } else if matched.contains(tech) {
                        Square::Matched
                    } else if !watched.contains(tech) {
                        Square::NoRule
                    } else if now.contains(tech) {
                        Square::Quiet
                    } else {
                        Square::Would
                    };
                    (tech, square)
                })
                .collect();
            squares.sort_by_key(|(tech, square)| (*square, *tech));
            (t, squares)
        })
        .collect()
}

/// One rule that matched this week, as a row.
struct Row<'a> {
    meta: &'a sigma::Meta,
    count: i64,
    /// Its finding: the id, and whether it is open, else answered and in force.
    finding: Option<(&'a str, bool)>,
}

/// A number as a person reads it, thousands separated.
fn num(n: i64) -> String {
    crate::view::counted(n, "", "").trim_end().to_string()
}

/// The level's state as one of the fixed words `events` names: the store is not trusted to
/// hold only those.
pub fn known(l: Option<&Level>) -> &'static str {
    let states = [
        events::NOT_INSTALLED,
        events::RUNNING,
        events::REFUSED,
        events::FAILING,
        events::SILENT,
        events::FAILED,
    ];
    match l {
        None => "none",
        Some(l) => states
            .into_iter()
            .find(|s| *s == l.state)
            .unwrap_or(events::FAILED),
    }
}

/// The ids of shipped rules that matched this week: what the page was made with, for the
/// script to tell a rule that matched since.
fn matched_ids(level: Option<&Level>) -> Vec<&'static str> {
    let rules = Rules::shipped();
    level
        .map(|l| {
            l.matches_last_week
                .iter()
                .filter(|(_, n)| **n > 0)
                .filter_map(|(id, _)| Some(rules.by_id(id)?.meta.as_ref()?.id.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

/// The section, from the state and the status's part `rules`, made at `now`.
pub fn draw(
    out: &mut String,
    st: &crate::status::State,
    r: &crate::contract::v1::RulesNow,
    now: i64,
) -> Out {
    let level = st.event_level.as_ref();
    let running = level.is_some_and(|l| l.state == events::RUNNING);
    writeln!(
        out,
        "<section id=\"{ANCHOR}\" data-state=\"{}\" data-matched=\"{}\">\n<div class=\"head\"><h2>{TITLE}</h2><span class=\"n\">every program start, checked against published rules</span><span class=\"n live\" data-live=\"said\">as made, {}</span></div>\n<p class=\"first\" data-live=\"moved\" hidden></p>",
        known(level),
        esc(&matched_ids(level).join(" ")),
        crate::view::utc(now)
    )?;
    // Not running: said first, before anything is drawn.
    if !running {
        let (state, notes) = match level {
            Some(l) => {
                let said = events::words(l);
                (said.state, said.notes.join(" "))
            }
            None => (
                "not looked for yet",
                "The next check looks for them.".to_string(),
            ),
        };
        writeln!(
            out,
            "<p class=\"first\"><strong>Program starts: {}.</strong> {} No rule is watching now; below is what the rules would watch once program starts are seen.</p>",
            esc(state),
            esc(&notes)
        )?;
    }
    out.push_str("<div class=\"stats\">\n");
    // While the level does not run, its state is the line above; nothing is counted here.
    if let Some(l) = level.filter(|_| running) {
        stat(
            out,
            ("Program starts in the last day", "last_day"),
            &num(l.last_day.starts),
            &bars(&l.starts_by_hour),
            &["by hour, last 24 hours".to_string()],
        )?;
        lost(out, l)?;
    }
    watching(out, r, level)?;
    out.push_str("</div>\n");
    matched(out, st, level)?;
    cover(out, st, level, running)?;
    out.push_str(SCRIPT_TAG);
    out.push_str("\n</section>\n");
    Ok(())
}

/// One of the three numbers: what it counts, the number, a drawing under it, and quieter lines.
/// `live` names the number for the script, and its lines as `<live>-note`.
fn stat(
    out: &mut String,
    (title, live): (&str, &str),
    big: &str,
    drawing: &str,
    notes: &[String],
) -> Out {
    write!(
        out,
        "<div class=\"stat\"><span class=\"st\">{}</span><span class=\"sv\" data-live=\"{live}\">{}</span>{drawing}",
        esc(title),
        esc(big)
    )?;
    for n in notes {
        write!(
            out,
            "<span class=\"ss\" data-live=\"{live}-note\">{}</span>",
            esc(n)
        )?;
    }
    out.push_str("</div>\n");
    Ok(())
}

/// What was lost over the last day as the big number says it. "0" only when nothing was lost,
/// unreadable or deleted before it was read; a restart of the collector is a loss of unknown
/// size, said as "some" or as "at least".
fn lost_shown(d: &events::Tally) -> String {
    if d.whole() {
        return "0".to_string();
    }
    let unknown = d.unknown_gaps + d.unreadable + d.removed_cap + d.removed_unread > 0;
    match (d.lost, unknown) {
        (0, _) => "some".to_string(),
        (n, true) => format!("{}+", num(n)),
        (n, false) => num(n),
    }
}

/// What was lost over the last day, with the reader's own caveats under it.
fn lost(out: &mut String, l: &Level) -> Out {
    let notes = if l.last_day.whole() {
        vec!["program starts the system could not hand over".to_string()]
    } else {
        events::words(l).notes
    };
    stat(out, ("Lost", "lost"), &lost_shown(&l.last_day), "", &notes)
}

/// What a running watcher writes to `LIVE_FILE` after a reading of program starts, at `now`:
/// the level's numbers, its state as a fixed word, the caveats in their few words, and how
/// many program starts matched each shipped rule this week, by id. Nothing else: a title or
/// anything read from an event stays in the page as it was made.
pub fn live(l: Option<&Level>, now: i64) -> Value {
    let series = |s: &events::Series| serde_json::json!({ "ends_at_seconds": s.ends_at, "step": s.step, "counts": s.counts });
    let Some(level) = l else {
        return serde_json::json!({ "written_at_seconds": now, "state": known(None) });
    };
    let said = events::words(level);
    let rules = Rules::shipped();
    let week: BTreeMap<&str, i64> = level
        .matches_last_week
        .iter()
        .filter_map(|(id, n)| Some((rules.by_id(id)?.meta.as_ref()?.id.as_str(), *n)))
        .collect();
    serde_json::json!({
        "written_at_seconds": now,
        "state": known(l),
        "state_words": said.state,
        "last_day": level.last_day.starts,
        "last_hour": level.starts_by_minute.counts.iter().sum::<i64>(),
        "by_hour": series(&level.starts_by_hour),
        "by_minute": series(&level.starts_by_minute),
        "lost": lost_shown(&level.last_day),
        "caveats": said.caveats.iter().map(|c| serde_json::json!({ "kind": c.kind, "short": c.short })).collect::<Vec<_>>(),
        "matches_last_week": week,
        // File events of the last day while the rules for them watch, else null.
        "file_events_last_day": level.files_watched().then_some(level.files.last_day.files),
    })
}

/// `live` as the script file the page loads: one assignment. Written whole and then moved into
/// place, so that the page never loads half of one.
pub fn write_live(folder: &std::path::Path, l: Option<&Level>, now: i64) -> std::io::Result<()> {
    let path = folder.join(LIVE_FILE);
    std::fs::create_dir_all(path.parent().unwrap_or(folder))?;
    let part = path.with_extension("js.part");
    std::fs::write(&part, format!("window.immuneLive = {};\n", live(l, now)))?;
    std::fs::rename(&part, &path)
}

/// How many rules watch, of how many shipped, with what the rest need.
fn watching(out: &mut String, r: &crate::contract::v1::RulesNow, level: Option<&Level>) -> Out {
    let running = level.is_some_and(|l| l.state == events::RUNNING);
    let rules = Rules::shipped();
    let (evaluated, in_part, not_evaluated) = rules.groups();
    let shipped = rules.rules.len();
    let now = Watching::of(level);
    let watching = evaluated.iter().filter(|l| now.watches(l)).count();
    let mut rest: Vec<String> = Vec::new();
    if !running {
        rest.push(format!(
            "{} would watch once program starts are seen",
            evaluated.len()
        ));
    } else if !now.files {
        // Named on the rules page and in the status; here, how many and why, quietly.
        let files = rules.evaluated(sigma::Kind::File);
        rest.push(format!(
            "{files} for files created or renamed do not watch: the collector here records program starts only"
        ));
    }
    if !in_part.is_empty() {
        rest.push(format!(
            "{} {} checked in part and not counted",
            in_part.len(),
            if in_part.len() == 1 { "is" } else { "are" }
        ));
    }
    // What the rest need, by kind: what a rule needs, said for one and for several.
    let mut needs: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for l in not_evaluated {
        if let Placement::NotEvaluated(reason) = &l.placement {
            *needs.entry(not_evaluated_said(reason)).or_default() += 1;
        }
    }
    for ((one, many), n) in needs {
        rest.push(format!("{n} {}", if n == 1 { one } else { many }));
    }
    let mut notes = vec![rest.join("; ")];
    if let Some(note) = r.judged_note.as_deref().filter(|_| running) {
        notes.push(note.to_string());
    }
    let mut meter = format!(
        "<span class=\"meter\" aria-hidden=\"true\"><span style=\"width:{}%\"></span></span>",
        watching * 100 / shipped.max(1)
    );
    // File events, many a second, are said once, quietly, here, where the rules that read
    // them are counted; never as a number beside program starts.
    if let Some(l) = level.filter(|_| now.files) {
        write!(
            meter,
            "<span class=\"ss\" data-live=\"files\">{}</span>",
            esc(&files_said(l.files.last_day.files))
        )?;
    }
    stat(
        out,
        ("Rules watching", "watching"),
        &format!("{watching} of {shipped}"),
        &meter,
        &notes,
    )
}

/// Why a rule is not evaluated, as the summary says it, for one rule and for several. Every
/// reason has its own words, so a rule that could not be read is never counted with rules that
/// were read and not taken, and a reason added later must be given words here.
fn not_evaluated_said(reason: &Reason) -> (&'static str, &'static str) {
    match reason {
        // Which kinds is said on the rules page; here, only that they are not collected.
        Reason::NeedsEvents(_) => (
            "needs a kind of event not collected",
            "need kinds of event not collected",
        ),
        Reason::NeedsFields(_) => (
            "needs details a program start does not give",
            "need details a program start does not give",
        ),
        Reason::KeywordSearch => ("searches whole messages", "search whole messages"),
        Reason::NotParsed(_) => ("could not be read", "could not be read"),
        Reason::Sequence => (
            "is a sequence of events, not translated",
            "are sequences of events, not translated",
        ),
        Reason::NotEql => (
            "is not in EQL, not translated",
            "are not in EQL, not translated",
        ),
        Reason::BackslashInWildcard | Reason::SpansKinds => (
            "could not be translated exactly",
            "could not be translated exactly",
        ),
        Reason::NeverTrue => (
            "could never be true over the events here",
            "could never be true over the events here",
        ),
        Reason::Regex => (
            "needs a regular expression in EQL's syntax, not translated",
            "need regular expressions in EQL's syntax, not translated",
        ),
        Reason::Unsupported => (
            "uses a function of EQL's that is not translated",
            "use functions of EQL's that are not translated",
        ),
        Reason::Function => (
            "compares one field with another",
            "compare one field with another",
        ),
    }
}

/// The file events of the last day, as the section says them.
fn files_said(n: i64) -> String {
    format!(
        "{} checked in the last day",
        crate::view::counted(n, "file event", "file events")
    )
}

/// Program starts by hour as bars, the last hour on the right, each with its hours and count in
/// its title. An hour with none is drawn as a faint line, never as a bar of the colour.
fn bars(h: &events::Series) -> String {
    const W: f64 = 220.0;
    const H: f64 = 40.0;
    const GAP: f64 = 2.0;
    let n = h.counts.len().max(1);
    let bw = (W - GAP * (n as f64 - 1.0)) / n as f64;
    let top = h.counts.iter().copied().max().unwrap_or(0).max(1) as f64;
    let mut svg = format!(
        "<svg class=\"hours\" data-live=\"hours\" viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"Program starts by hour over the last 24 hours; the most in one hour: {}\">",
        num(top as i64)
    );
    let hhmm = |t: i64| crate::view::utc(t)[11..16].to_string();
    for (i, c) in h.counts.iter().enumerate() {
        let end = h.ends_at - (n - 1 - i) as i64 * 3600;
        let (bh, fill) = if *c > 0 {
            ((*c as f64 / top * H).max(1.5), "var(--blue)")
        } else {
            (1.5, "var(--faint)")
        };
        let _ = write!(
            svg,
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{bw:.1}\" height=\"{bh:.1}\" rx=\"1\" style=\"fill:{fill}\"><title>{}–{} UTC: {}</title></rect>",
            i as f64 * (bw + GAP),
            H - bh,
            hhmm(end - 3600),
            hhmm(end),
            crate::view::counted(*c, "program start", "program starts")
        );
    }
    svg.push_str("</svg>");
    svg
}

/// One rule's row: its title as data in an element of its own, its level, a bar for its count
/// against the `most` any rule counted, the count, and its finding, linked, or "Counted".
fn rule_row(out: &mut String, row: &Row, most: i64) -> Out {
    // A rule with no level stated is drawn as one below high, and says it states none.
    let level = row.meta.level_name().unwrap_or("none");
    let state = match row.finding {
        Some((id, true)) => format!("<a class=\"look\" href=\"#{}\">Finding</a>", esc(id)),
        Some((id, false)) => format!("<a href=\"#answered-{}\">Finding, answered</a>", esc(id)),
        None if row.meta.raises() => "Finding".to_string(),
        None => "Counted".to_string(),
    };
    writeln!(
        out,
        "<div class=\"rr\" data-rule=\"{}\"><span class=\"rt\"><span class=\"src\">{}</span></span><span class=\"rl\"><span class=\"lv lv-{level}\">{}</span></span><span class=\"rb\" aria-hidden=\"true\"><span style=\"width:{}%\"></span></span><span class=\"rc\">{}</span><span class=\"rs\">{state}</span></div>",
        esc(&row.meta.id),
        esc(&row.meta.label()),
        esc(&crate::pages::capital(sigma::level_said(row.meta.level))),
        (row.count * 100 / most.max(1)).max(1),
        num(row.count),
    )?;
    Ok(())
}

/// The rules that matched this week, most severe first, then by count: each with its title as
/// data, its level, a bar for its count, the count, and its finding or "Counted".
fn matched(out: &mut String, st: &crate::status::State, level: Option<&Level>) -> Out {
    let rules = Rules::shipped();
    let empty = BTreeMap::new();
    let week = level.map_or(&empty, |l| &l.matches_last_week);
    let finding_of = |m: &sigma::Meta| -> Option<(&str, bool)> {
        let of = |i: &&Item| i.rule == Some(m.name.as_str());
        if let Some(i) = st.needs.items.iter().find(of) {
            return Some((i.id.as_str(), true));
        }
        st.answered
            .as_ref()
            .and_then(|a| a.iter().find(of))
            .map(|i| (i.id.as_str(), false))
    };
    let mut rows: Vec<Row> = week
        .iter()
        .filter(|(_, n)| **n > 0)
        .filter_map(|(id, n)| {
            let meta = rules.by_id(id)?.meta.as_ref()?;
            Some(Row {
                meta,
                count: *n,
                finding: finding_of(meta),
            })
        })
        .collect();
    out.push_str("<div class=\"matched\">\n<div class=\"sh\"><h3>Rules that matched this week</h3><span class=\"n\">only a rule marked high raises a finding; the rest are counted</span></div>\n");
    matched_rows(out, &mut rows)?;
    writeln!(
        out,
        "<p class=\"all\">{}<a href=\"{DETAILS}/{}.html\">Published rules, each with what it looks for</a> · all {}</p>\n</div>",
        shown_said(&rows),
        crate::pages::RULES,
        rules.rules.len()
    )?;
    Ok(())
}

/// The rows of the rules that matched, sorted and cut. Most severe first, then by count. The
/// rules of a set that states no level are not ranked among them: they are a group of their
/// own after them, by count, with its own heading, count and cut.
fn matched_rows(out: &mut String, rows: &mut [Row]) -> Out {
    rows.sort_by(|a, b| {
        b.meta
            .level
            .cmp(&a.meta.level)
            .then(b.count.cmp(&a.count))
            .then_with(|| a.meta.label().cmp(&b.meta.label()))
    });
    let (ranked, unranked): (Vec<&Row>, Vec<&Row>) =
        rows.iter().partition(|r| r.meta.level.is_some());
    if rows.is_empty() {
        out.push_str("<p class=\"none\" data-live=\"none\">No rule matched this week.</p>\n");
    }
    let most = rows.iter().map(|r| r.count).max().unwrap_or(1).max(1);
    for row in ranked.iter().take(ROWS_SHOWN) {
        rule_row(out, row, most)?;
    }
    if !unranked.is_empty() {
        writeln!(
            out,
            "<div class=\"sh grp\"><h4>{}</h4><span class=\"n\">{}, counted and not ranked by severity</span></div>",
            esc(&crate::pages::capital(sigma::NO_LEVEL_GROUP)),
            crate::view::counted(unranked.len() as i64, "rule", "rules")
        )?;
        for row in unranked.iter().take(ROWS_SHOWN) {
            rule_row(out, row, most)?;
        }
    }
    out.push_str("<p class=\"all\" data-live=\"more\" hidden></p>\n");
    Ok(())
}

/// What the cut left out, said for each group apart: the rules with a level by severity, the
/// rules of a set that states no level by count.
fn shown_said(rows: &[Row]) -> String {
    let ranked = rows.iter().filter(|r| r.meta.level.is_some()).count();
    let unranked = rows.len() - ranked;
    let mut shown = String::new();
    if ranked > ROWS_SHOWN {
        shown.push_str(&format!(
            "{ranked} rules with a level matched this week; the {ROWS_SHOWN} most severe are shown · "
        ));
    }
    if unranked > ROWS_SHOWN {
        shown.push_str(&format!(
            "{unranked} rules {} matched this week; the {ROWS_SHOWN} counted most are shown · ",
            sigma::NO_LEVEL_GROUP
        ));
    }
    shown
}

/// The grid of techniques: a legend, each tactic with its squares and "N of M", and what the
/// squares are, with MITRE's notice.
fn cover(out: &mut String, st: &crate::status::State, level: Option<&Level>, running: bool) -> Out {
    let attack = attack();
    let empty = BTreeMap::new();
    let week = level.map_or(&empty, |l| &l.matches_last_week);
    let raised: BTreeSet<&str> = st
        .needs
        .items
        .iter()
        .filter_map(|i| {
            let rule = Rules::shipped().by_name(i.rule?)?;
            Some(rule.meta.as_ref()?.id.as_str())
        })
        .collect();
    let grid = grid(attack, Rules::shipped(), Watching::of(level), week, &raised);
    out.push_str("<div class=\"covers\">\n<div class=\"sh\"><h3>What the rules cover</h3><ul class=\"legend\">");
    let legend = [
        Square::Finding,
        Square::Matched,
        if running {
            Square::Quiet
        } else {
            Square::Would
        },
        Square::NoRule,
    ];
    for s in legend {
        write!(
            out,
            "<li><span class=\"m {}\" aria-hidden=\"true\"></span>{}</li>",
            s.class(),
            esc(&crate::pages::capital(s.said()))
        )?;
    }
    out.push_str("</ul></div>\n<div class=\"tactics\">\n");
    for (tactic, squares) in &grid {
        let covered = squares.iter().filter(|(_, s)| *s != Square::NoRule).count();
        write!(
            out,
            "<div class=\"tactic\"><h4>{}</h4><div class=\"sq\">",
            esc(&tactic.name)
        )?;
        for (tech, s) in squares {
            let name = attack.names.get(*tech).map_or("", String::as_str);
            write!(
                out,
                "<span class=\"m {}\" title=\"{} {}: {}\"></span>",
                s.class(),
                esc(tech),
                esc(name),
                s.said()
            )?;
        }
        writeln!(
            out,
            "</div><span class=\"nm\">{covered} of {}</span></div>",
            squares.len()
        )?;
    }
    out.push_str("</div>\n");
    let listed: BTreeSet<&str> = attack.names.keys().map(String::as_str).collect();
    let all = named(Rules::shipped(), |_| true);
    let outside: Vec<&str> = all.difference(&listed).copied().collect();
    let mut said = "Each square is one ATT&CK technique for macOS, grouped by what an attacker is trying to do. A technique only rules checked in part or not at all name counts as no rule yet.".to_string();
    if !outside.is_empty() {
        said.push_str(&format!(
            " Named by the rules but not listed by ATT&CK for macOS: {}.",
            outside.join(", ")
        ));
    }
    writeln!(
        out,
        "<p class=\"meta\">{}</p>\n<p class=\"meta\">Techniques from MITRE ATT&amp;CK {}. {}</p>\n</div>",
        esc(&said),
        esc(&attack.release),
        esc(MITRE)
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Series, Tally};

    const PADDING: &str = "95361ce5-c891-4b0a-87ca-e24607884a96";
    const SW_VERS: &str = "5de06a6f-673a-4fc0-8d48-bcfe3837b033";

    fn counts(grid: &[(&Tactic, Vec<(&str, Square)>)], s: Square) -> usize {
        grid.iter()
            .flat_map(|(_, squares)| squares.iter())
            .filter(|(_, x)| *x == s)
            .count()
    }

    #[test]
    fn each_tactic_says_how_many_of_its_techniques_a_rule_checked_in_full_covers_as_the_rules_and_mitre_say()
     {
        // "N of M" is a claim of coverage. It is counted here again from the raw sources: the
        // `attack.t…` tags in the text of each rule evaluated in full, and MITRE's file as it
        // is, so a technique counted for a rule that is not checked, or one missing from its
        // tactic, shows.
        let data: Value = serde_json::from_str(ATTACK).unwrap();
        let rules = Rules::shipped();
        let mut tagged: BTreeSet<String> = BTreeSet::new();
        for l in rules
            .rules
            .iter()
            .filter(|l| l.placement == Placement::Evaluated)
        {
            let text = l.source.files.iter().find(|(f, _)| *f == l.file).unwrap().1;
            for word in text.split_whitespace() {
                // A tag in a YAML list or in a JSON one, as the translated rules write theirs.
                let word = word.trim_matches(['[', ']', '"', ',']);
                if let Some(t) = word.strip_prefix("attack.t") {
                    tagged.insert(format!("T{}", t.split('.').next().unwrap()));
                }
            }
        }
        let a = attack();
        let grid = grid(a, rules, Watching::ALL, &BTreeMap::new(), &BTreeSet::new());
        let tactics = data["tactics"].as_array().unwrap();
        assert_eq!(grid.len(), tactics.len());
        for ((tactic, squares), raw) in grid.iter().zip(tactics) {
            let all: Vec<&str> = raw["techniques"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap())
                .collect();
            assert_eq!(tactic.name, raw["name"].as_str().unwrap());
            assert_eq!(squares.len(), all.len(), "{}", tactic.name);
            let covered = all.iter().filter(|t| tagged.contains(**t)).count();
            let drawn = squares.iter().filter(|(_, s)| *s == Square::Quiet).count();
            assert_eq!(drawn, covered, "{}", tactic.name);
        }
        // MITRE's file as made: the matrix's order, and a name for every technique drawn.
        assert_eq!(a.release, "v20.1");
        assert_eq!(a.names.len(), 154);
        assert_eq!(a.tactics.first().unwrap().name, "Initial Access");
        assert_eq!(a.tactics.last().unwrap().name, "Impact");
        assert!(
            a.tactics
                .iter()
                .flat_map(|t| &t.techniques)
                .all(|t| a.names.contains_key(t))
        );
    }

    #[test]
    fn a_level_that_is_not_running_draws_nothing_as_watching() {
        // No false calm: while program starts are not seen, a technique with a rule is drawn
        // as what would be watched, never as watched and quiet.
        let a = attack();
        let none = BTreeMap::new();
        let off = grid(a, Rules::shipped(), Watching::NONE, &none, &BTreeSet::new());
        let on = grid(a, Rules::shipped(), Watching::ALL, &none, &BTreeSet::new());
        assert_eq!(counts(&off, Square::Quiet), 0);
        assert_eq!(counts(&on, Square::Would), 0);
        assert!(counts(&on, Square::Quiet) > 0);
        assert_eq!(counts(&off, Square::Would), counts(&on, Square::Quiet));
        assert_eq!(counts(&off, Square::NoRule), counts(&on, Square::NoRule));
    }

    #[test]
    fn a_finding_outranks_a_match_and_a_match_outranks_calm_on_every_tactic_of_its_technique() {
        // The red square is the technique of the open finding's rule, wherever ATT&CK lists
        // it; a rule that only matched is drawn as such, never as calm.
        let a = attack();
        let week = BTreeMap::from([(SW_VERS.to_string(), 3), (PADDING.to_string(), 1)]);
        let raised = BTreeSet::from([PADDING]);
        let g = grid(a, Rules::shipped(), Watching::ALL, &week, &raised);
        let state = |tech: &str| -> Vec<Square> {
            g.iter()
                .flat_map(|(_, s)| s.iter())
                .filter(|(t, _)| *t == tech)
                .map(|(_, s)| *s)
                .collect()
        };
        let in_tactics = |tech: &str| {
            a.tactics
                .iter()
                .filter(|t| t.techniques.iter().any(|x| x == tech))
                .count()
        };
        assert_eq!(state("T1027"), vec![Square::Finding; in_tactics("T1027")]);
        assert_eq!(state("T1082"), vec![Square::Matched; in_tactics("T1082")]);
        assert_eq!(counts(&g, Square::Finding), in_tactics("T1027"));
        // The most telling first within a tactic.
        for (_, squares) in &g {
            assert!(squares.windows(2).all(|w| w[0].1 <= w[1].1));
        }
    }

    /// A rule for macOS program starts tagged with a technique; `also` is a second alternative
    /// of its selection.
    const IN_PART: &str = "title: Checked in part
id: 11111111-1111-4111-8111-111111111111
status: test
level: medium
tags:
    - attack.t1021.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        - Image|endswith: '/ssh'
        - User: 'root'
    condition: selection
";
    const IN_FULL: &str = "title: Checked in full
id: 22222222-2222-4222-8222-222222222222
status: test
level: medium
tags:
    - attack.t1021.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/ssh'
    condition: selection
";

    #[test]
    fn a_technique_only_a_rule_checked_in_part_names_is_no_rule_yet() {
        // A rule evaluated in part never matches some of what it looks for here; drawing its
        // technique as watched would claim coverage the program does not have.
        let a = attack();
        let state = |files: &[(&'static str, &'static str)]| -> Vec<Square> {
            let rules = Rules::load(files);
            grid(a, &rules, Watching::ALL, &BTreeMap::new(), &BTreeSet::new())
                .into_iter()
                .flat_map(|(_, s)| s)
                .filter(|(t, _)| *t == "T1021")
                .map(|(_, s)| s)
                .collect()
        };
        let part = state(&[("in-part.yml", IN_PART)]);
        assert!(
            !part.is_empty() && part.iter().all(|s| *s == Square::NoRule),
            "{part:?}"
        );
        let full = state(&[("in-part.yml", IN_PART), ("in-full.yml", IN_FULL)]);
        assert!(full.iter().all(|s| *s == Square::Quiet), "{full:?}");
    }

    #[test]
    fn a_rule_title_is_data_escaped_in_an_element_of_its_own() {
        // A rule's title is its author's text. In the page it is escaped and set apart, never
        // markup and never mixed into the program's words.
        let meta = sigma::Meta {
            id: "x".to_string(),
            name: "sigma:x".to_string(),
            title: "<b>Padding</b> & \"co\"".to_string(),
            level: Some(sigma::Level::Medium),
            status: sigma::Status::Test,
            author: None,
            techniques: Vec::new(),
            description: None,
            source: &sigma::SIGMAHQ,
        };
        let mut out = String::new();
        let row = Row {
            meta: &meta,
            count: 1_234,
            finding: None,
        };
        rule_row(&mut out, &row, 2_468).unwrap();
        assert!(
            out.contains(
                "<span class=\"rt\"><span class=\"src\">&lt;b&gt;Padding&lt;/b&gt; &amp; &quot;co&quot; (SigmaHQ&#39;s rule set)</span></span>"
            ),
            "{out}"
        );
        assert!(!out.contains("<b>"), "{out}");
        assert!(
            out.contains("width:50%")
                && out.contains("<span class=\"rc\">1,234</span><span class=\"rs\">Counted</span>"),
            "{out}"
        );
    }

    #[test]
    fn the_rules_not_evaluated_are_counted_by_their_own_reason_and_none_as_unreadable() {
        // A rule that was read and not taken is never counted as one that could not be read:
        // each reason has its own words, so a real failure to read stands apart.
        let mut out = String::new();
        watching(&mut out, &Default::default(), None).unwrap();
        let note = "175 would watch once program starts are seen; 23 are checked in part and not counted; \
                    1 compares one field with another; 4 could never be true over the events here; \
                    4 could not be translated exactly; 139 are sequences of events, not translated; \
                    40 are not in EQL, not translated; 65 need kinds of event not collected; \
                    1 needs a regular expression in EQL's syntax, not translated; \
                    84 need details a program start does not give; \
                    2 use functions of EQL's that are not translated";
        assert!(out.contains(&esc(note)), "{out}");
        assert!(!out.contains("could not be read"), "{out}");
    }

    #[test]
    fn only_a_rule_that_could_not_be_read_is_said_to_be_unreadable_for_any_count() {
        // The note above shows one form of each reason, for today's counts; the other form is
        // shown when a count changes, so every reason is held here in both.
        let unreadable = not_evaluated_said(&Reason::NotParsed(String::new()));
        assert_eq!(unreadable, ("could not be read", "could not be read"));
        for reason in [
            Reason::NeedsEvents(String::new()),
            Reason::NeedsFields(Vec::new()),
            Reason::KeywordSearch,
            Reason::Sequence,
            Reason::NotEql,
            Reason::BackslashInWildcard,
            Reason::SpansKinds,
            Reason::NeverTrue,
            Reason::Regex,
            Reason::Unsupported,
            Reason::Function,
        ] {
            let (one, many) = not_evaluated_said(&reason);
            for said in [one, many] {
                assert!(
                    !said.is_empty() && !said.contains(unreadable.0),
                    "{reason:?}: {said}"
                );
            }
        }
    }

    #[test]
    fn a_rule_of_a_set_that_states_no_level_is_never_ranked_or_cut_by_severity() {
        // Twelve rules with a level and twelve of a set that states none matched. The cut by
        // severity is over the rules with a level only; the others are a group of their own
        // under its heading, with its own count and its own cut, by count, never hidden as the
        // least severe.
        let metas: Vec<sigma::Meta> = (0..24)
            .map(|i| sigma::Meta {
                id: format!("r{i:02}"),
                name: format!("x:r{i:02}"),
                title: format!("Invented {i:02}"),
                level: (i < 12).then(|| [sigma::Level::Medium, sigma::Level::Low][i % 2]),
                status: sigma::Status::Test,
                author: None,
                techniques: Vec::new(),
                description: None,
                source: if i < 12 {
                    &sigma::SIGMAHQ
                } else {
                    &sigma::ELASTIC_BEHAVIOUR
                },
            })
            .collect();
        // The rules with no level matched most, so a cut by count over all would show them.
        let mut rows: Vec<Row> = metas
            .iter()
            .enumerate()
            .map(|(i, meta)| Row {
                meta,
                count: if i < 12 { 1 } else { 100 + i as i64 },
                finding: None,
            })
            .collect();
        let mut out = String::new();
        matched_rows(&mut out, &mut rows).unwrap();
        let heading = out
            .find("<h4>Of a set that states no level</h4><span class=\"n\">12 rules, counted and not ranked by severity</span>")
            .expect("the group's heading");
        let shown = |range: std::ops::Range<usize>| {
            range
                .map(|i| out.find(&format!("Invented {i:02} (")))
                .collect::<Vec<_>>()
        };
        let levelled = shown(0..12);
        let unlevelled = shown(12..24);
        // Ten with a level shown, the mediums first, all before the heading.
        assert_eq!(levelled.iter().flatten().count(), 10, "{out}");
        assert!(levelled.iter().flatten().all(|at| *at < heading), "{out}");
        assert!(levelled[0].is_some() && levelled[11].is_none(), "{out}");
        // Ten of the group shown after its heading, the most counted first.
        assert_eq!(unlevelled.iter().flatten().count(), 10, "{out}");
        assert!(unlevelled.iter().flatten().all(|at| *at > heading), "{out}");
        assert!(unlevelled[11].unwrap() < unlevelled[10].unwrap(), "{out}");
        assert!(unlevelled[0].is_none() && unlevelled[1].is_none(), "{out}");
        assert_eq!(
            shown_said(&rows),
            "12 rules with a level matched this week; the 10 most severe are shown · \
             12 rules of a set that states no level matched this week; the 10 counted most are shown · "
        );
    }

    #[test]
    fn a_rule_that_states_no_level_is_drawn_as_counted_and_says_so() {
        // A rule of a set that states no level shows that in the row, in the style of a rule
        // below high, and its matches are counted, never drawn as a finding.
        let meta = sigma::Meta {
            id: "y".to_string(),
            name: "elastic-behaviour:y".to_string(),
            title: "Invented".to_string(),
            level: None,
            status: sigma::Status::Test,
            author: None,
            techniques: Vec::new(),
            description: None,
            source: &sigma::ELASTIC_BEHAVIOUR,
        };
        let mut out = String::new();
        let row = Row {
            meta: &meta,
            count: 3,
            finding: None,
        };
        rule_row(&mut out, &row, 3).unwrap();
        assert!(
            out.contains("<span class=\"src\">Invented (Elastic&#39;s behaviour rules)</span>")
                && out.contains("<span class=\"lv lv-none\">No level stated</span>")
                && out.contains("<span class=\"rs\">Counted</span>"),
            "{out}"
        );
    }

    fn level(last_day: Tally) -> Level {
        Level {
            state: events::RUNNING.to_string(),
            read_at: 0,
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day,
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: crate::events::Files::default(),
            arrivals: Default::default(),
            cap: None,
        }
    }

    #[test]
    fn lost_reads_zero_only_when_every_start_of_the_day_was_read() {
        // "0 lost" is calm. A restart of the collector, a line that could not be read or an
        // hour deleted before it was read lose starts nobody counted: never zero.
        let big = |t: Tally| {
            let mut out = String::new();
            lost(&mut out, &level(t)).unwrap();
            let tag = "<span class=\"sv\" data-live=\"lost\">";
            let at = out.find(tag).unwrap() + tag.len();
            out[at..at + out[at..].find('<').unwrap()].to_string()
        };
        assert_eq!(big(Tally::default()), "0");
        let restart = Tally {
            unknown_gaps: 1,
            ..Tally::default()
        };
        assert_eq!(big(restart), "some");
        let deleted = Tally {
            removed_unread: 1,
            ..Tally::default()
        };
        assert_eq!(big(deleted), "some");
        let both = Tally {
            lost: 1_204,
            unknown_gaps: 1,
            ..Tally::default()
        };
        assert_eq!(big(both), "1,204+");
        let counted = Tally {
            lost: 12,
            ..Tally::default()
        };
        assert_eq!(big(counted), "12");
    }

    #[test]
    fn the_bars_add_up_to_the_day_and_an_empty_hour_is_never_drawn_in_the_colour() {
        // The bars stand beside the count of the day: each says its hours and its count, and
        // an hour with no start is a faint line, not a short bar that reads as some.
        let mut counts = vec![0; events::HOURS];
        counts[0] = 1_500;
        counts[23] = 3;
        let svg = bars(&Series {
            ends_at: 1_791_000_000,
            step: 3600,
            counts,
        });
        assert_eq!(svg.matches("<rect").count(), events::HOURS);
        assert_eq!(svg.matches("var(--blue)").count(), 2);
        assert_eq!(svg.matches("var(--faint)").count(), events::HOURS - 2);
        assert!(svg.contains("UTC: 1,500 program starts</title>"), "{svg}");
        assert!(svg.contains("UTC: 3 program starts</title>"), "{svg}");
        assert!(svg.contains("most in one hour: 1,500"), "{svg}");
    }

    /// JavaScriptCore's shell, which macOS ships.
    const JSC: &str =
        "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc";

    /// Runs the section's script over a stand-in for the page made while the level was
    /// `state`, with `live` as the file holds it, written `age` seconds ago, or no file. Returns
    /// the text the script left in each element it names, by name, and whether it is hidden.
    fn page_after(state: &str, live: Option<Value>, age: i64) -> Value {
        let stand_in = format!(
            r#"var window = globalThis;
var LIVE = {};
var made = {{}};
function el() {{
  return {{ textContent: "", hidden: false, style: {{}}, a: {{}},
    getAttribute: function (n) {{ return n in this.a ? this.a[n] : null; }},
    setAttribute: function (n, v) {{ this.a[n] = String(v); }},
    querySelector: function () {{ return null; }},
    querySelectorAll: function () {{ return []; }} }};
}}
var sec = el();
sec.a["data-state"] = "{state}";
sec.a["data-matched"] = "";
sec.querySelector = function (sel) {{
  var m = /data-live="([^"]+)"/.exec(sel);
  return m ? (made[m[1]] = made[m[1]] || el()) : null;
}};
sec.querySelectorAll = function (sel) {{
  var e = sec.querySelector(sel);
  return e ? [e] : [];
}};
var document = {{
  getElementById: function (id) {{ return id === "as-it-happens" ? sec : null; }},
  createElement: function () {{ return {{ remove: function () {{}} }}; }},
  head: {{ appendChild: function (s) {{
    if (LIVE) {{ LIVE.written_at_seconds = Date.now() / 1000 - {age}; window.immuneLive = LIVE; }}
    LIVE ? s.onload() : s.onerror();
  }} }},
}};
function setInterval() {{}}
{SCRIPT}
var out = {{}};
for (var k in made) out[k] = {{ text: made[k].textContent, hidden: made[k].hidden }};
print(JSON.stringify(out));
"#,
            live.map_or("null".to_string(), |v| v.to_string()),
        );
        static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "immune-happens-{}-{}.js",
            std::process::id(),
            RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::write(&path, stand_in).unwrap();
        let out = std::process::Command::new(JSC).arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn running_live() -> Value {
        let mut l = level(Tally {
            starts: 154_358,
            unknown_gaps: 2,
            ..Tally::default()
        });
        l.starts_by_hour = Series {
            ends_at: 1_791_000_000,
            step: 3600,
            counts: vec![0; events::HOURS],
        };
        live(Some(&l), 0)
    }

    #[test]
    fn the_page_says_how_fresh_its_numbers_are_and_that_it_is_not_updating_once_the_file_is_a_minute_old()
     {
        // A page that keeps showing numbers nobody updates would read as watched: once the
        // watcher's file is a minute old, or there is none, the page says so in its header.
        let fresh = page_after(events::RUNNING, Some(running_live()), 5);
        assert_eq!(fresh["said"]["text"], "updated 5 seconds ago", "{fresh}");
        assert_eq!(fresh["last_day"]["text"], "154,358", "{fresh}");
        assert_eq!(fresh["lost"]["text"], "some", "{fresh}");
        assert_eq!(fresh["lost-note"]["text"], "2 restarts", "{fresh}");
        assert_eq!(fresh["moved"]["hidden"], true, "{fresh}");
        let old = page_after(events::RUNNING, Some(running_live()), 61);
        assert_eq!(old["said"]["text"], "not updating: no watcher is running");
        let within = page_after(events::RUNNING, Some(running_live()), 50);
        assert_eq!(within["said"]["text"], "updated 50 seconds ago");
        let none = page_after(events::RUNNING, None, 0);
        assert_eq!(none["said"]["text"], "not updating: no watcher is running");
        assert!(none.get("last_day").is_none(), "{none}");
    }

    #[test]
    fn a_page_made_while_the_level_ran_never_shows_its_numbers_as_current_once_it_stopped() {
        // No false calm: the numbers of a running level stay on the page only beside the line
        // that says it no longer runs, and are not redrawn as if it did.
        let mut l = level(Tally::default());
        l.state = events::REFUSED.to_string();
        // Nor a count of file events checked, though the collector here records them.
        l.files.collected = true;
        l.files.last_day.files = 9;
        assert_eq!(
            live(Some(&l), 0)["file_events_last_day"],
            serde_json::Value::Null
        );
        let page = page_after(events::RUNNING, Some(live(Some(&l), 0)), 5);
        assert_eq!(
            page["moved"],
            serde_json::json!({ "text": "Program starts are refused by macOS now. The rest of this section is as the page was made; open it again from the app.", "hidden": false }),
            "{page}"
        );
        assert!(page.get("last_day").is_none(), "{page}");
    }

    #[test]
    fn the_file_for_an_open_page_holds_numbers_ids_of_shipped_rules_and_fixed_words_only() {
        // A browser runs what the file holds: a rule id the store holds that no shipped rule
        // has, or a state the program never writes, does not reach it.
        let mut l = level(Tally {
            starts: 7,
            lost: 3,
            ..Tally::default()
        });
        l.state = "<img src=x onerror=alert(1)>".to_string();
        l.matches_last_week = BTreeMap::from([
            (PADDING.to_string(), 2),
            ("</script><script>alert(1)//".to_string(), 1),
        ]);
        let v = live(Some(&l), 1_791_000_000);
        assert_eq!(v["state"], events::FAILED);
        assert_eq!(v["matches_last_week"], serde_json::json!({ PADDING: 2 }));
        assert_eq!(v["written_at_seconds"], 1_791_000_000);
        l.state = events::RUNNING.to_string();
        let v = live(Some(&l), 0);
        assert_eq!(
            (&v["state"], &v["state_words"]),
            (&serde_json::json!("running"), &serde_json::json!("on"))
        );
        assert_eq!(
            (&v["last_day"], &v["lost"]),
            (&serde_json::json!(7), &serde_json::json!("3"))
        );
        assert_eq!(
            live(None, 5),
            serde_json::json!({ "written_at_seconds": 5, "state": "none" })
        );
    }
}
