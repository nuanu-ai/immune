//! The text for a person of each message of the contract, rendered from the message alone: no
//! store is asked and nothing else is read, so a person, an agent and a program are told the
//! same thing (`answer.rs`).
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`): a line break or a hidden character is written `\u{...}`, and so is the
//! backslash. In the text it is set in double quotes with a double quote inside written `\"`, or
//! in a column of its own, so nothing in it can end a line or a quotation and go on in the
//! program's own words. Words without the suffix are the core's own vocabulary.

use crate::contract::v1;
use crate::screen::{Screen, Step};
use crate::{store, view};

/// Text from a source as data: in double quotes, a quote inside escaped, and anything hidden
/// written out.
pub fn quoted(s: &str) -> String {
    format!("\"{}\"", view::shown(&s.replace('"', "\\\"")))
}

/// One word of a command Immunity Core prints for pasting, written for a POSIX shell so that the shell
/// reads back exactly `word`: as it is when it is made only of `A-Z a-z 0-9 _ @ % + = : , . / -`
/// (not `~`, which the shell would expand), else in single quotes, with a quote in it written
/// `'\''`. `None` when the word cannot be shown exactly, so that a command holding it would name
/// another value: a control character, a line break, anything the screen writes as an escape
/// (`view::shown`), a backslash among them, or what reads as a secret (`secrets::said`). The
/// caller puts the word's placeholder in its place. Every command printed with a word that is
/// not Immunity Core's own goes through this.
pub fn shell_word(word: &str) -> Option<String> {
    if view::shown(word) != word || crate::secrets::said(word) != word {
        return None;
    }
    // `=` is not of the set: zsh, the default shell of macOS, reads a word that starts with it as
    // the path of that command.
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+:,./-".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        Some(word.to_string())
    } else {
        Some(format!("'{}'", word.replace('\'', "'\\''")))
    }
}

/// `shell_word`, or `placeholder` where the word cannot be shown exactly.
pub fn shell_word_or(word: &str, placeholder: &str) -> String {
    shell_word(word).unwrap_or_else(|| placeholder.to_string())
}

/// An enum's value as the JSON names it, the store's own word: `unspecified` for a value this
/// build does not know.
pub fn word<E: TryFrom<i32> + serde::Serialize>(value: i32) -> String {
    E::try_from(value)
        .ok()
        .and_then(|e| serde_json::to_value(e).ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unspecified".to_string())
}

/// `n one` or `n many`, with thousands grouped.
fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// `n` with thousands grouped.
fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
}

/// What the rules do here now, after where they come from: the sentence the status's page and
/// `immunity rules` share.
pub fn rules_said(head: &str, r: &v1::RulesNow) -> String {
    let (Some(true), Some(watching_rules)) = (r.watching, r.watching_rules) else {
        // Before any reading of the event level, whether it is on is not known.
        let state = if r.watching.is_none() {
            "Whether it is on is not known yet: it has not been read, so none of them is known to be watching."
        } else {
            "It is not on, so none of them is watching."
        };
        return format!(
            "{head} Once the event level is on, every program start on this Mac is checked against them. {state}"
        );
    };
    let watching_file_rules = r.watching_file_rules.unwrap_or(0);
    let matched = count(r.matches_last_day.unwrap_or(0), "time", "times");
    let mut said = if r.file_events_collected == Some(true) {
        format!(
            "{head} The event level is on, so {} of them are watching this Mac: {} every program start and {} every file created or renamed; {} more are checked in part. In the last day they matched {matched}.",
            watching_rules,
            watching_rules - watching_file_rules,
            watching_file_rules,
            r.in_part
        )
    } else {
        format!(
            "{head} The event level is on, so {} of them are watching every program start on this Mac, and {} more are checked in part. The {} rules for files created or renamed are not watching: the collector installed here records program starts only, and installing the event level again adds file events. In the last day they matched {matched}.",
            watching_rules, r.in_part, r.file_rules
        )
    };
    if let Some(note) = &r.judged_note {
        said.push(' ');
        said.push_str(note);
    }
    said
}

/// How many projects have no lockfile this version reads, as one counted item.
fn without_lockfile(n: u64) -> String {
    format!(
        "{} no lockfile this version reads",
        if n == 1 {
            "1 project has".to_string()
        } else {
            format!("{} projects have", grouped(n))
        }
    )
}

/// For how many packages whether `what` affects them cannot be told, "it" for one.
fn untold(n: u64, what: &str) -> String {
    format!(
        "for {} whether {what} affects {} cannot be told",
        count(n, "package", "packages"),
        if n == 1 { "it" } else { "them" }
    )
}

/// What matching found in the packages the projects' lockfiles declare, by count: the known
/// vulnerabilities, the packages for which whether one affects them cannot be told, and the
/// projects compared in full, not wholly read and with no lockfile this version reads.
pub struct Matched {
    pub known: u64,
    pub unknown_packages: u64,
    pub compared: u64,
    pub not_read: u64,
    pub no_lockfile: u64,
}

impl Matched {
    pub fn of(t: &v1::VulnerabilityTotals) -> Self {
        Matched {
            known: t.affected_records,
            unknown_packages: t.unknown_packages,
            compared: t.projects_compared,
            not_read: t.projects_not_read,
            no_lockfile: t.projects_without_lockfile,
        }
    }

    /// The same counts from the store's totals, for the report line of a check and the pages.
    pub fn of_totals(t: &crate::vulnerabilities::Totals) -> Self {
        let (no_lockfile, not_read) = crate::vulnerabilities::project_counts(&t.unread_places);
        Matched {
            known: t.records as u64,
            unknown_packages: t.packages_unknown as u64,
            compared: t.projects_compared as u64,
            not_read: not_read as u64,
            no_lockfile: no_lockfile as u64,
        }
    }

    /// A project was compared in full, none was left out by a lockfile not wholly read or
    /// missing, and no package cannot be told: only then is a count said of the packages the
    /// projects use.
    pub fn all_compared(&self) -> bool {
        self.compared > 0
            && self.not_read == 0
            && self.no_lockfile == 0
            && self.unknown_packages == 0
    }

    /// The one sentence about known vulnerabilities in the projects' packages, which the status,
    /// the report line of a check and the pages say. The count goes with the number of projects
    /// compared in full, and what was not compared is said beside it by count. With none
    /// compared it says so and why, and gives no count of zero, which a reader would take for a
    /// clean result. `projects` is how many projects the store holds, `None` when not known:
    /// the three counts of projects do not cover one whose lockfiles were read in full against
    /// data not current, so their zeros never stand for "no project".
    pub fn said(&self, found: crate::covered::Found, projects: Option<u64>) -> String {
        // "No project" only while nothing is held of any: a count that is not zero is said.
        let counts = [
            self.known,
            self.unknown_packages,
            self.compared,
            self.not_read,
            self.no_lockfile,
        ];
        if projects == Some(0) && counts.iter().all(|n| *n == 0) {
            return "no projects were found to compare".to_string();
        }
        let mut not = Vec::new();
        if self.not_read > 0 {
            not.push(format!(
                "the lockfiles of {} were not all read, so whether a known vulnerability affects what was not read cannot be told",
                count(self.not_read, "project", "projects")
            ));
        }
        if self.no_lockfile > 0 {
            not.push(without_lockfile(self.no_lockfile));
        }
        let not = not.join(", and ");
        let known = count(self.known, "known vulnerability", "known vulnerabilities");
        if self.compared == 0 {
            let mut said = "no project's packages could be compared in full".to_string();
            if !not.is_empty() {
                said.push_str(&format!(": {not}"));
            }
            if self.known > 0 {
                said.push_str(&format!("; {known} in the packages read"));
            }
            if self.unknown_packages > 0 {
                said.push_str(&format!(
                    "; {}",
                    untold(self.unknown_packages, "a known vulnerability")
                ));
            }
            return said;
        }
        let all = self.all_compared();
        let mut said = format!(
            "matched against the package-lock.json, pnpm-lock.yaml and Cargo.lock of {}, {} compared in full: {known} in {}",
            found.projects(),
            grouped(self.compared),
            if all {
                "packages they use"
            } else {
                "the packages read"
            }
        );
        if self.unknown_packages > 0 {
            said.push_str(&format!(", and {}", untold(self.unknown_packages, "one")));
        }
        // Packages that cannot be told are their own reason, said above; this names the rest.
        if !not.is_empty() {
            said.push_str(&format!("; not compared: {not}"));
        }
        said
    }
}

/// What an answer tells a person when there is no store at the path, in the words a failure
/// gives (`store::NO_STORE`): the sentence, then what makes one. Every command says it so.
pub fn no_store(screen: &Screen) -> Vec<String> {
    let mut first = store::NO_STORE.to_string();
    first[..1].make_ascii_uppercase();
    let mut out = vec![screen.paint(crate::screen::BOLD, &format!("{first}."))];
    out.extend(screen.marked(store::NO_STORE_FIX, screen.fits()));
    out
}

/// A failure, as a person reads it on stderr: each of its errors in the one form of an error.
pub fn failure(f: &v1::Failure, screen: &Screen) -> String {
    f.errors.iter().map(|e| error(e, screen)).collect()
}

/// A refusal of a command the person typed, told as `error` tells it but with `next`, the
/// command to run next made from what was typed (`usage::finding_next`), in place of the
/// example the message carries for an agent.
pub fn refusal(f: &v1::Failure, next: &crate::usage::Pasted, screen: &Screen) -> String {
    f.errors
        .iter()
        .map(|e| told(e, Some(next), screen))
        .collect()
}

/// One error of a failure in the one form of an error (`Screen::error`), rendered from the
/// error alone: its cause in Immunity Core's words, what to do, and what it quotes under a label. The
/// two conditions of a store that every command meets, none at the path and one of another
/// format, are worded once (`store::NO_STORE`, `store::OTHER_FORMAT`), whichever command met
/// them; their exit codes and the message itself are as each command gives them.
pub fn error(e: &v1::Error, screen: &Screen) -> String {
    told(e, None, screen)
}

/// One error, with the command to run next when the caller made one from what was typed.
fn told(e: &v1::Error, next: Option<&crate::usage::Pasted>, screen: &Screen) -> String {
    let detail = e.detail_text.as_deref().unwrap_or_default();
    let condition = match e.code.as_str() {
        // `immunity owner` names the path alone, under a code of its own.
        "no_store" => store::Condition::Absent(detail),
        "store_unreadable" | "command_failed" => store::condition(detail),
        _ => store::Condition::Other,
    };
    match condition {
        store::Condition::Absent(path) => {
            return screen.error(
                store::NO_STORE,
                &[Step::Words(store::NO_STORE_FIX.to_string())],
                &[("Store", path)],
            );
        }
        store::Condition::OtherFormat(path) => {
            return screen.error(
                store::OTHER_FORMAT,
                &[Step::Words(store::OTHER_FORMAT_FIX.to_string())],
                &[("Store", path)],
            );
        }
        store::Condition::Other => {}
    }
    if e.code == "run_in_progress" {
        return screen.error(
            "another check is running on this store",
            &[Step::Words(
                "Nothing was done. Try again when it ends, or see it with: `immunity status`"
                    .to_string(),
            )],
            &[],
        );
    }
    // The message is the cause, and what was done about it, after "; nothing was", a step.
    let (cause, done) = match e.message.split_once("; nothing was ") {
        Some((cause, done)) => (cause, Some(format!("Nothing was {done}."))),
        None => (e.message.as_str(), None),
    };
    let mut steps: Vec<Step> = done.into_iter().map(Step::Words).collect();
    let label = match e.code.as_str() {
        "changed_since_read" => "Finding",
        code if code.ends_with("_unreadable")
            || code.ends_with("_failed")
            || code.ends_with("_unchecked") =>
        {
            "Reason"
        }
        _ => "Given",
    };
    // What failed to be read or done is not helped by running a command again.
    if let Some(next) = next {
        steps.extend(next.steps());
    } else if label != "Reason"
        && let Some(example) = e.example.as_deref().and_then(example_for_a_person)
    {
        steps.push(Step::Words(example));
    }
    let mut quoted: Vec<(&str, &str)> = Vec::new();
    if !detail.is_empty() {
        quoted.push((label, detail));
    }
    for (i, id) in e.ids_text.iter().enumerate() {
        quoted.push((if i == 0 { "Fits" } else { "" }, id));
    }
    screen.error(cause, &steps, &quoted)
}

/// An error's example as a person is shown it: without `--json` and `--proto`, a form the
/// person did not ask for, and only where it says more than a command again, as "ask for one
/// of them by its id, as in: …" does. A bare command line is the command that failed, or
/// another, and is left out.
fn example_for_a_person(example: &str) -> Option<String> {
    let plain = example.replace(" --json", "").replace(" --proto", "");
    let says_more = plain.split(' ').any(|w| {
        w.len() >= 3
            && w.bytes().all(|b| b.is_ascii_lowercase())
            && w != "immunity"
            && !crate::usage::is_command(w)
    });
    says_more.then_some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_says_under_its_command_what_was_typed_and_left_out() {
        let f = v1::Failure {
            operation: "finding".to_string(),
            ok: false,
            errors: vec![v1::Error {
                code: "finding_closed".to_string(),
                message: "the finding is already answered".to_string(),
                ..Default::default()
            }],
        };
        let next = crate::usage::Pasted {
            command: "immunity finding f0 reopen --store <path>".to_string(),
            left_out: Some("What was typed for the value of --store cannot be shown".to_string()),
        };
        let said = refusal(&f, &next, &Screen::pipe());
        assert!(
            said.contains("\n  immunity finding f0 reopen --store <path>\n  What was typed for the value of --store"),
            "{said}"
        );
    }

    /// Every code a failure of the binary can carry, from the reference's tables and the source.
    const CODES: &[&str] = &[
        "another_job",
        "another_store",
        "busy",
        "case_too_long",
        "changed_since_read",
        "command_failed",
        "empty_case",
        "empty_reason",
        "finding_closed",
        "finding_not_answered",
        "holds_secret",
        "home_not_absolute",
        "journal_seq_ahead",
        "log_unreadable",
        "match_gone",
        "named_twice",
        "no_login_session",
        "no_statement",
        "no_store",
        "no_such_match",
        "not_a_file",
        "not_a_folder",
        "not_a_machine",
        "not_a_program",
        "not_a_project",
        "not_a_verdict",
        "not_installed",
        "not_removed",
        "not_one_group",
        "not_staged",
        "not_the_pair",
        "reason_too_long",
        "run_as_root",
        "run_failed",
        "run_in_progress",
        "sample_failed",
        "secrets_unchecked",
        "several_machines",
        "several_programs",
        "source_not_a_file",
        "spelled_otherwise",
        "stop_failed",
        "store_unreadable",
        "symbolic_link",
        "too_large",
        "unknown_finding",
        "unknown_machine",
        "unreadable",
        "usage",
        "watch_failed",
        "watch_in_progress",
    ];

    #[test]
    fn every_refusal_is_told_as_one_error_with_one_cause_and_never_the_usage() {
        for code in CODES {
            let e = crate::answer::error(
                code,
                "a cause in the core's words; nothing was changed",
                "ask for one of them by its id, as in: immunity project <id> --json",
                "a detail",
            );
            for screen in [Screen::pipe(), Screen::terminal(80, false)] {
                let said = error(&e, &screen);
                let lines: Vec<&str> = said.lines().collect();
                assert!(lines[0].starts_with("error: "), "{code}: {said}");
                assert!(
                    lines[1..].iter().all(|l| l.starts_with("  ")),
                    "{code}: {said}"
                );
                assert!(
                    !said.contains("usage:") && !said.contains("--json"),
                    "{code}: {said}"
                );
                assert!(lines.len() <= 5, "{code}: {said}");
            }
        }
    }

    #[test]
    fn a_failure_says_what_was_done_and_its_example_only_where_it_says_more_than_a_command() {
        let said = |code: &str, example: &str| {
            error(
                &crate::answer::error(code, "a cause; nothing was recorded", example, "what"),
                &Screen::pipe(),
            )
        };
        assert_eq!(
            said(
                "not_a_project",
                "immunity program asks about a program --json"
            ),
            "error: a cause\n  Nothing was recorded.\n  immunity program asks about a program\n  \
             Given   what\n"
        );
        // A command again, or another command, is no help.
        assert_eq!(
            said("not_a_project", "immunity status --json --store <file>"),
            "error: a cause\n  Nothing was recorded.\n  Given   what\n"
        );
        // Nor anything for what could not be read or done, whatever its example says.
        assert_eq!(
            said("run_failed", "immunity finding <id> seen"),
            "error: a cause\n  Nothing was recorded.\n  Reason   what\n"
        );
    }

    #[test]
    fn hostile_text_in_a_failure_s_detail_cannot_forge_a_line_or_a_style() {
        let hostile = format!(
            "x\u{1b}[31mred\u{9b}31m\u{202e}evil\u{200b}\nerror: forged\n→ immunity on{}error: forged too",
            " ".repeat(90)
        );
        for code in ["store_unreadable", "run_failed", "unknown_finding", "usage"] {
            let e = crate::answer::error(code, "a cause", "", &hostile);
            for screen in [
                Screen::pipe(),
                Screen::terminal(80, true),
                Screen::terminal(30, true),
            ] {
                let said = error(&e, &screen);
                let visible = crate::screen::visible(&said);
                let starts = |w: &str| visible.lines().filter(|l| l.starts_with(w)).count();
                assert_eq!(starts("error:"), 1, "{said}");
                assert_eq!(starts("→"), 0, "{said}");
                assert!(
                    !visible.chars().any(|c| c != '\n' && crate::icu::hidden(c)),
                    "{said:?}"
                );
                // Every escape is one this module wrote: a style, opened and closed.
                assert_eq!(
                    said.matches('\u{1b}').count(),
                    said.matches("\u{1b}[0m").count() * 2,
                    "{said:?}"
                );
            }
            assert!(!error(&e, &Screen::pipe()).contains('\u{1b}'));
        }
    }

    #[test]
    fn no_store_and_another_format_are_worded_once_whatever_command_met_them() {
        let none = crate::store::absent(std::path::Path::new("/x/store.db"));
        let older = "the store at /x/store.db is from an older format (5); this version uses \
                     format 6 and does not convert old stores. Nothing was changed.";
        let cases = [
            (
                "store_unreadable",
                "the store cannot be read; nothing was changed",
                none.clone(),
            ),
            (
                "store_unreadable",
                "the store cannot be read, so what became of a match cannot be told; nothing was evaluated",
                none.clone(),
            ),
            (
                "no_store",
                "there is no store at the path given; `immunity run` makes it",
                "/x/store.db".to_string(),
            ),
            (
                "command_failed",
                "immunity view could not finish",
                format!("the store cannot be read: {none}"),
            ),
        ];
        for (code, message, detail) in &cases {
            let said = error(
                &crate::answer::error(code, message, "", detail),
                &Screen::pipe(),
            );
            assert_eq!(
                said,
                "error: there is no store here yet\n  immunity run makes one, or immunity on, \
                 which also keeps it checked.\n  Store   /x/store.db\n",
                "{code}"
            );
        }
        let newer = "the store at /x/store.db is from a newer format (7) than this version \
                     knows (6). Nothing was changed.";
        for (code, detail) in [
            ("store_unreadable", older),
            ("command_failed", older),
            ("store_unreadable", newer),
        ] {
            let said = error(
                &crate::answer::error(code, "m", "", detail),
                &Screen::pipe(),
            );
            assert!(
                said.starts_with("error: this store was made by another build of Immunity Core\n  It was left unchanged."),
                "{said}"
            );
            assert!(said.ends_with("  Store   /x/store.db\n"), "{said}");
        }
    }

    #[test]
    fn text_from_a_source_never_ends_its_quotation_or_its_line() {
        // A value made to read as the program's own words after a closed quotation, on a line
        // of its own: escaped one to one as the contract escapes it, then quoted.
        let made = crate::known::whole("x\"\nThe store knows nothing more.");
        let shown = quoted(&made);
        assert_eq!(shown, r#""x\"\u{a}The store knows nothing more.""#);
        assert!(!shown.contains('\n'));
    }
}
