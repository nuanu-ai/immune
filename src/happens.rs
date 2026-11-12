//! The summary's section "As it happens": every program start on this Mac, checked against the
//! published rules. Three numbers first, each drawn: program starts in the last day with a bar
//! for each hour, what was lost, and how many rules watch. Then the rules that matched this week,
//! the most severe first, and a grid of ATT&CK techniques for macOS, one square each, grouped by
//! tactic in the matrix's order, saying which the rules cover and what they found. Drawn in Rust
//! as inline SVG and plain elements, as `src/map.rs` draws the map; no script.
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

/// Every tactic with its techniques, each in its state, the most telling first and then by id.
/// `running`: the level's latest state is running. `week`: matches by rule id this week.
/// `raised`: the ids of rules with an open finding. `rules`: the rules shipped.
pub fn grid<'a>(
    attack: &'a Attack,
    rules: &Rules,
    running: bool,
    week: &BTreeMap<String, i64>,
    raised: &BTreeSet<&str>,
) -> Vec<(&'a Tactic, Vec<(&'a str, Square)>)> {
    let watched = named(rules, |l| l.placement == Placement::Evaluated);
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
                    } else if running {
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

/// The section, from the state and the status's part `rules`.
pub fn draw(out: &mut String, st: &crate::status::State, r: &Value) -> Out {
    let level = st.event_level.as_ref();
    let running = level.is_some_and(|l| l.state == events::RUNNING);
    writeln!(
        out,
        "<section id=\"{ANCHOR}\">\n<div class=\"head\"><h2>{TITLE}</h2><span class=\"n\">every program start, checked against published rules</span></div>"
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
            "Program starts in the last day",
            &num(l.last_day.starts),
            &bars(&l.starts_by_hour),
            &["by hour, last 24 hours".to_string()],
        )?;
        lost(out, l)?;
    }
    watching(out, r, running)?;
    out.push_str("</div>\n");
    matched(out, st, level)?;
    cover(out, st, level, running)?;
    out.push_str("</section>\n");
    Ok(())
}

/// One of the three numbers: what it counts, the number, a drawing under it, and quieter lines.
fn stat(out: &mut String, title: &str, big: &str, drawing: &str, notes: &[String]) -> Out {
    write!(
        out,
        "<div class=\"stat\"><span class=\"st\">{}</span><span class=\"sv\">{}</span>{drawing}",
        esc(title),
        esc(big)
    )?;
    for n in notes {
        write!(out, "<span class=\"ss\">{}</span>", esc(n))?;
    }
    out.push_str("</div>\n");
    Ok(())
}

/// What was lost over the last day. "0" only when nothing was lost, unreadable or deleted before
/// it was read; a restart of the collector is a loss of unknown size, said as "some" or as "at
/// least", with the reader's own caveats under it.
fn lost(out: &mut String, l: &Level) -> Out {
    let d = &l.last_day;
    if d.whole() {
        return stat(
            out,
            "Lost",
            "0",
            "",
            &["program starts the system could not hand over".to_string()],
        );
    }
    let unknown = d.unknown_gaps + d.unreadable + d.removed_cap + d.removed_unread > 0;
    let big = match (d.lost, unknown) {
        (0, _) => "some".to_string(),
        (n, true) => format!("{}+", num(n)),
        (n, false) => num(n),
    };
    stat(out, "Lost", &big, "", &events::words(l).notes)
}

/// How many rules watch, of how many shipped, with what the rest need.
fn watching(out: &mut String, r: &Value, running: bool) -> Out {
    let rules = Rules::shipped();
    let (evaluated, in_part, not_evaluated) = rules.groups();
    let shipped = rules.rules.len();
    let watching = if running { evaluated.len() } else { 0 };
    let mut rest: Vec<String> = Vec::new();
    if !running {
        rest.push(format!(
            "{} would watch once program starts are seen",
            evaluated.len()
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
    let mut needs: BTreeMap<(String, String), usize> = BTreeMap::new();
    for l in not_evaluated {
        let (one, many) = match &l.placement {
            Placement::NotEvaluated(Reason::NeedsEvents(c)) => {
                let what = format!(
                    "{} events, not collected",
                    c.trim_end_matches("_event").replace('_', " ")
                );
                (format!("needs {what}"), format!("need {what}"))
            }
            Placement::NotEvaluated(Reason::NeedsFields(_)) => (
                "needs details a program start does not give".to_string(),
                "need details a program start does not give".to_string(),
            ),
            Placement::NotEvaluated(Reason::KeywordSearch) => (
                "searches whole messages".to_string(),
                "search whole messages".to_string(),
            ),
            _ => (
                "could not be read".to_string(),
                "could not be read".to_string(),
            ),
        };
        *needs.entry((one, many)).or_default() += 1;
    }
    for ((one, many), n) in needs {
        rest.push(format!("{n} {}", if n == 1 { one } else { many }));
    }
    let mut notes = vec![rest.join("; ")];
    if let Some(note) = r["judged_note"].as_str().filter(|_| running) {
        notes.push(note.to_string());
    }
    let meter = format!(
        "<span class=\"meter\" aria-hidden=\"true\"><span style=\"width:{}%\"></span></span>",
        watching * 100 / shipped.max(1)
    );
    stat(
        out,
        "Rules watching",
        &format!("{watching} of {shipped}"),
        &meter,
        &notes,
    )
}

/// Program starts by hour as bars, the last hour on the right, each with its hours and count in
/// its title. An hour with none is drawn as a faint line, never as a bar of the colour.
fn bars(h: &events::ByHour) -> String {
    const W: f64 = 220.0;
    const H: f64 = 40.0;
    const GAP: f64 = 2.0;
    let n = h.counts.len().max(1);
    let bw = (W - GAP * (n as f64 - 1.0)) / n as f64;
    let top = h.counts.iter().copied().max().unwrap_or(0).max(1) as f64;
    let mut svg = format!(
        "<svg class=\"hours\" viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"Program starts by hour over the last 24 hours; the most in one hour: {}\">",
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
    let level = row.meta.level.as_str();
    let state = match row.finding {
        Some((id, true)) => format!("<a class=\"look\" href=\"#{}\">Finding</a>", esc(id)),
        Some((id, false)) => format!("<a href=\"#answered-{}\">Finding, answered</a>", esc(id)),
        None if row.meta.level.raises() => "Finding".to_string(),
        None => "Counted".to_string(),
    };
    writeln!(
        out,
        "<div class=\"rr\"><span class=\"rt src\">{}</span><span><span class=\"lv lv-{level}\">{}</span></span><span class=\"rb\" aria-hidden=\"true\"><span style=\"width:{}%\"></span></span><span class=\"rc\">{}</span><span class=\"rs\">{state}</span></div>",
        esc(&row.meta.title),
        esc(&crate::pages::capital(level)),
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
        let of = |i: &&Item| i.rule == Some(m.finding_rule.as_str());
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
    rows.sort_by(|a, b| {
        b.meta
            .level
            .cmp(&a.meta.level)
            .then(b.count.cmp(&a.count))
            .then_with(|| a.meta.title.cmp(&b.meta.title))
    });
    out.push_str("<div class=\"matched\">\n<div class=\"sh\"><h3>Rules that matched this week</h3><span class=\"n\">only a rule marked high raises a finding; the rest are counted</span></div>\n");
    if rows.is_empty() {
        out.push_str("<p class=\"none\">No rule matched this week.</p>\n");
    }
    let most = rows.iter().map(|r| r.count).max().unwrap_or(1).max(1);
    for row in rows.iter().take(ROWS_SHOWN) {
        rule_row(out, row, most)?;
    }
    let shown = if rows.len() > ROWS_SHOWN {
        format!(
            "{} rules matched this week; the {ROWS_SHOWN} most severe are shown · ",
            rows.len()
        )
    } else {
        String::new()
    };
    writeln!(
        out,
        "<p class=\"all\">{shown}<a href=\"{DETAILS}/{}.html\">Published rules, each with what it looks for</a> · all {}</p>\n</div>",
        crate::pages::RULES,
        rules.rules.len()
    )?;
    Ok(())
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
        .filter_map(|i| i.rule?.strip_prefix(sigma::FINDING_PREFIX))
        .collect();
    let grid = grid(attack, Rules::shipped(), running, week, &raised);
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
    use crate::events::{ByHour, Tally};

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
            let text = sigma::SHIPPED.iter().find(|(f, _)| *f == l.file).unwrap().1;
            for word in text.split_whitespace() {
                if let Some(t) = word.strip_prefix("attack.t") {
                    tagged.insert(format!("T{}", t.split('.').next().unwrap()));
                }
            }
        }
        let a = attack();
        let grid = grid(a, rules, true, &BTreeMap::new(), &BTreeSet::new());
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
        let off = grid(a, Rules::shipped(), false, &none, &BTreeSet::new());
        let on = grid(a, Rules::shipped(), true, &none, &BTreeSet::new());
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
        let g = grid(a, Rules::shipped(), true, &week, &raised);
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
            grid(a, &rules, true, &BTreeMap::new(), &BTreeSet::new())
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
            finding_rule: "sigma:x".to_string(),
            title: "<b>Padding</b> & \"co\"".to_string(),
            level: sigma::Level::Medium,
            status: sigma::Status::Test,
            author: None,
            techniques: Vec::new(),
            description: None,
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
                "<span class=\"rt src\">&lt;b&gt;Padding&lt;/b&gt; &amp; &quot;co&quot;</span>"
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
            starts_by_hour: ByHour::default(),
        }
    }

    #[test]
    fn lost_reads_zero_only_when_every_start_of_the_day_was_read() {
        // "0 lost" is calm. A restart of the collector, a line that could not be read or an
        // hour deleted before it was read lose starts nobody counted: never zero.
        let big = |t: Tally| {
            let mut out = String::new();
            lost(&mut out, &level(t)).unwrap();
            let at = out.find("<span class=\"sv\">").unwrap() + 17;
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
        let svg = bars(&ByHour {
            ends_at: 1_791_000_000,
            counts,
        });
        assert_eq!(svg.matches("<rect").count(), events::HOURS);
        assert_eq!(svg.matches("var(--blue)").count(), 2);
        assert_eq!(svg.matches("var(--faint)").count(), events::HOURS - 2);
        assert!(svg.contains("UTC: 1,500 program starts</title>"), "{svg}");
        assert!(svg.contains("UTC: 3 program starts</title>"), "{svg}");
        assert!(svg.contains("most in one hour: 1,500"), "{svg}");
    }
}
