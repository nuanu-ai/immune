//! What in a project makes code run by itself: one table of data, `POINTS`, one row per known
//! way. A row says where the file is, which part of it counts, what routine action runs it,
//! which tool, whether that tool asks first, the ATT&CK technique, how bad and how sure a
//! change is, and the source the row rests on. Everything else is derived from the table: the
//! kinds of reading, the watcher's subscriptions, the watched kinds for a person, the rules'
//! levels, the inventory on the page and the count of ways read. Adding a product is adding a
//! row; a row of a trigger that has no rule yet needs that trigger's words and rule.
//!
//! The rows are `docs/research/what-is-missed.md`, section 3, with `.gemini/settings.json` and
//! the `.env` files Gemini CLI loads as two rows, since one part is read and one is not.
//!
//! A row that is read goes through the watched places reader like any other watched file,
//! one reading per row scoped to the machine and covering every checkout: its first reading on
//! this Mac is the baseline, and an entry that appears later, in a checkout the store held or
//! in one that is new, or whose part changes, is a finding of its trigger's rule. A row read
//! for the first time after an upgrade is a kind read for the first time: a baseline too.
//!
//! How the part that counts is taken, a closed set:
//!
//! - `Entries`: every entry of a folder, read by the watched places reader as its own place
//!   (`.git/hooks`); listed here so that the inventory is whole.
//! - `FolderOpenTask`: the editor's task file, whose part is decided by its own reading, see
//!   `runs_on_open`. It is named apart because no other extraction says the same honestly.
//! - `Bytes`: the whole file's checksum.
//! - `Select`: the file parsed as strict JSON, and per key path the SHA-256 of the canonical
//!   value there; `*` stands for every key of an object. The text of a script or command is
//!   never kept: an entry names the file and the key, and holds the checksum.
//! - `Lines`: the lines that start with a prefix.
//! - `Present`: not read; whether it is there is named and counted.
//!
//! What `Select` reads is what the tool reads, or it does not guess. The tools of the rows read
//! here read strict JSON with a reader that keeps the last of two equal keys (`JSON.parse`;
//! npm, Yarn, pnpm, Claude Code, Gemini CLI after stripping comments, Cursor's JSON with
//! comments reader), or one that may keep the first (Bun's own parser). serde_json keeps the
//! last; Foundation's strict reader keeps the first (`json5::first_of_equal_keys`). A file is
//! read by key only when both agree at every selected key, it has no byte order mark, which
//! the tools treat differently, and it is strict JSON. Otherwise it falls back to the whole
//! file's checksum, `Bytes`, and the reading says why: a change in it is never "unchanged".

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde_json::Value;

use crate::watched::{self, Content, Entry, Look};

/// Where a row's paths are looked for.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Scope {
    /// In each checkout's folder.
    Checkout,
    /// Where another file names it: the setting given. Not looked for in this version.
    NamedBy(&'static str),
}

/// How the part that counts is taken.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Part {
    /// Every entry of a folder, read by the watched places reader as the place of this kind.
    Entries(&'static str),
    /// The editor's task file: watched while it holds a task set to run on opening.
    FolderOpenTask,
    /// No row of this version is read whole yet; a test reads a row of it.
    #[allow(dead_code)]
    Bytes,
    /// JSON pointers into a strict JSON file; a `*` segment is every key of an object.
    Select(&'static [&'static str]),
    /// The lines that start with this prefix. No row of this version uses it yet; a test
    /// reads a row of it.
    #[allow(dead_code)]
    Lines(&'static str),
    Present,
}

/// The routine action that runs it, a closed vocabulary.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Trigger {
    OpenInEditor,
    EnterInShell,
    StartAgent,
    AgentEvent,
    InstallPackages,
    BuildOrTest,
    GitCommand,
    InterpreterStart,
    EveryCommand,
}

/// Whether the tool asks the owner before it runs what the file says.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Asks {
    Never,
    OncePerFolder,
    /// Again whenever what it would run changes.
    OncePerContent,
    /// Depends on a setting of the tool, or on how it is started.
    DependsOnSetting,
    /// No source says.
    NotKnown,
}

/// One known way a project makes code run by itself.
pub struct Point {
    pub scope: Scope,
    /// Paths from the scope; a segment may hold one `*`.
    pub paths: &'static [&'static str],
    pub part: Part,
    pub trigger: Trigger,
    pub tool: &'static str,
    pub asks: Asks,
    pub technique: Option<&'static str>,
    pub severity: &'static str,
    pub confidence: &'static str,
    /// The page the row rests on; empty where the note found none that could be read. Data
    /// for whoever reads or extends the table: no page of this program links out.
    #[allow(dead_code)]
    pub source: &'static str,
}

/// The keys of Claude Code's project settings that run something or let it run unasked
/// (`.claude/settings.json` and `.claude/settings.local.json` take the same keys).
const CLAUDE: &[&str] = &[
    "/hooks",
    "/env",
    "/enableAllProjectMcpServers",
    "/enabledMcpjsonServers",
    "/permissions/allow",
    "/enabledPlugins",
    "/extraKnownMarketplaces",
];
/// The scripts of a project's own `package.json` that npm, pnpm, Yarn or Bun runs by itself
/// when its packages are installed: npm's `install` and `ci` lifecycle and `dependencies`;
/// pnpm's, with `pnpm:devPreinstall`; Yarn 1 and 2+; Bun's `{pre|post}install` and
/// `{pre|post}prepare`.
const PACKAGE_SCRIPTS: &[&str] = &[
    "/scripts/preinstall",
    "/scripts/install",
    "/scripts/postinstall",
    "/scripts/prepublish",
    "/scripts/preprepare",
    "/scripts/prepare",
    "/scripts/postprepare",
    "/scripts/dependencies",
    "/scripts/pnpm:devPreinstall",
];
/// Every MCP server a file declares, each whole: command, arguments, environment, address.
const MCP_SERVERS: &[&str] = &["/mcpServers/*"];
/// Gemini CLI: servers it starts, hooks, and what runs or is allowed without asking.
const GEMINI: &[&str] = &[
    "/mcpServers/*",
    "/hooks",
    "/tools/allowed",
    "/tools/discoveryCommand",
    "/tools/callCommand",
    "/general/defaultApprovalMode",
];

const fn row(
    paths: &'static [&'static str],
    part: Part,
    trigger: Trigger,
    tool: &'static str,
    asks: Asks,
    levels: (Option<&'static str>, &'static str, &'static str),
    source: &'static str,
) -> Point {
    Point {
        scope: Scope::Checkout,
        paths,
        part,
        trigger,
        tool,
        asks,
        technique: levels.0,
        severity: levels.1,
        confidence: levels.2,
        source,
    }
}

/// Event Triggered Execution: code set to run on a routine event.
const EVENT: Option<&str> = Some("T1546");
/// Installer Packages: its procedure examples are npm's pre- and post-install scripts.
const INSTALLER: Option<&str> = Some("T1546.016");

use Asks::*;
use Part::*;
use Trigger::*;

/// Every known way, in the order of the note's inventory. The order is the page's.
#[rustfmt::skip]
pub const POINTS: [Point; 41] = [
    row(&[".vscode/tasks.json"], FolderOpenTask, OpenInEditor, "VS Code, Cursor", DependsOnSetting, (EVENT, "high", "medium"), "https://code.visualstudio.com/docs/editor/tasks"),
    row(&[".vscode/settings.json"], Present, OpenInEditor, "VS Code", DependsOnSetting, (EVENT, "high", "low"), "https://code.visualstudio.com/docs/editor/workspace-trust"),
    row(&["*.code-workspace"], Present, OpenInEditor, "VS Code", DependsOnSetting, (EVENT, "high", "low"), "https://maccarita.com/posts/idesaster"),
    row(&[".vscode/mcp.json"], Present, StartAgent, "VS Code", OncePerContent, (EVENT, "high", "medium"), "https://code.visualstudio.com/docs/copilot/customization/mcp-servers"),
    row(&[".idea"], Present, OpenInEditor, "JetBrains IDEs", OncePerFolder, (EVENT, "high", "low"), "https://www.jetbrains.com/help/idea/project-security.html"),
    row(&[".zed/settings.json"], Present, OpenInEditor, "Zed", NotKnown, (EVENT, "high", "low"), "https://maccarita.com/posts/idesaster"),
    row(&[".nvim.lua", ".nvimrc", ".exrc"], Present, OpenInEditor, "Vim, Neovim", OncePerContent, (EVENT, "high", "medium"), ""),
    row(&[".dir-locals.el"], Present, OpenInEditor, "Emacs", OncePerContent, (EVENT, "high", "low"), "https://www.gnu.org/software/emacs/manual/html_node/emacs/Safe-File-Variables.html"),
    row(&["build.rs"], Present, BuildOrTest, "Cargo, rust-analyzer", Never, (EVENT, "high", "low"), "https://doc.rust-lang.org/cargo/reference/build-scripts.html"),
    row(&[".claude/settings.json"], Select(CLAUDE), StartAgent, "Claude Code", OncePerFolder, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/settings"),
    row(&[".claude/settings.local.json"], Select(CLAUDE), StartAgent, "Claude Code", Never, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/settings"),
    row(&[".mcp.json"], Select(MCP_SERVERS), StartAgent, "Claude Code", DependsOnSetting, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/mcp"),
    row(&[".claude/skills", ".claude/commands", ".claude/agents"], Present, AgentEvent, "Claude Code", Never, (EVENT, "high", "low"), "https://github.com/osquery/osquery/blob/master/specs/ai_agent_skills.table"),
    row(&["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursor/rules", ".github/copilot-instructions.md"], Present, AgentEvent, "coding agents", Never, (None, "medium", "low"), "https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"),
    row(&[".cursor/mcp.json"], Select(MCP_SERVERS), StartAgent, "Cursor", OncePerContent, (EVENT, "high", "medium"), "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison"),
    row(&[".cursor/hooks.json"], Select(&["/hooks"]), StartAgent, "Cursor", DependsOnSetting, (EVENT, "high", "medium"), "https://cursor.com/docs/agent/hooks"),
    row(&[".codex/config.toml"], Present, StartAgent, "Codex", OncePerFolder, (EVENT, "high", "medium"), "https://learn.chatgpt.com/docs/config-file/config-reference"),
    row(&[".gemini/settings.json"], Select(GEMINI), StartAgent, "Gemini CLI", DependsOnSetting, (EVENT, "high", "medium"), "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md"),
    row(&[".env", ".gemini/.env"], Present, StartAgent, "Gemini CLI", DependsOnSetting, (EVENT, "medium", "low"), "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md"),
    row(&[".kiro/hooks"], Present, AgentEvent, "Kiro", Never, (EVENT, "high", "medium"), "https://kiro.dev/docs/hooks/"),
    row(&["package.json"], Select(PACKAGE_SCRIPTS), InstallPackages, "npm, pnpm, Yarn, Bun", Never, (INSTALLER, "high", "low"), "https://docs.npmjs.com/cli/v11/using-npm/scripts"),
    row(&[".npmrc"], Present, EveryCommand, "npm", Never, (EVENT, "high", "low"), "https://docs.npmjs.com/cli/v11/using-npm/config"),
    row(&[".yarnrc.yml"], Present, EveryCommand, "Yarn", Never, (EVENT, "high", "low"), "https://yarnpkg.com/configuration/yarnrc"),
    row(&[".pnpmfile.cjs", ".pnpmfile.mjs"], Present, InstallPackages, "pnpm", Never, (INSTALLER, "high", "low"), "https://pnpm.io/pnpmfile"),
    row(&["bunfig.toml"], Present, BuildOrTest, "Bun", Never, (EVENT, "high", "low"), "https://bun.sh/docs/runtime/bunfig"),
    row(&[".venv/lib/*/site-packages/*.pth"], Present, InterpreterStart, "Python", Never, (EVENT, "high", "medium"), "https://docs.python.org/3/library/site.html"),
    row(&["conftest.py"], Present, BuildOrTest, "pytest", Never, (EVENT, "high", "low"), "https://docs.pytest.org/en/stable/how-to/writing_plugins.html"),
    row(&[".cargo/config.toml", ".cargo/config"], Present, BuildOrTest, "Cargo", Never, (EVENT, "high", "low"), "https://doc.rust-lang.org/cargo/reference/config.html"),
    row(&["rust-toolchain.toml"], Present, EveryCommand, "rustup", Never, (EVENT, "high", "low"), "https://rust-lang.github.io/rustup/overrides.html"),
    row(&["gradlew", "gradle/wrapper", "*.gradle", "*.gradle.kts"], Present, BuildOrTest, "Gradle, IntelliJ", DependsOnSetting, (EVENT, "high", "low"), "https://docs.gradle.org/current/userguide/gradle_wrapper.html"),
    row(&["composer.json"], Present, InstallPackages, "Composer", Never, (INSTALLER, "high", "low"), "https://getcomposer.org/doc/articles/scripts.md"),
    row(&["*.xcodeproj"], Present, BuildOrTest, "Xcode", NotKnown, (EVENT, "high", "low"), "https://attack.mitre.org/techniques/T1546/"),
    row(&[".git/hooks"], Entries(watched::HOOK), GitCommand, "git", Never, (None, "medium", "low"), "https://git-scm.com/docs/githooks"),
    row(&[".git/config"], Present, GitCommand, "git", Never, (EVENT, "high", "medium"), "https://git-scm.com/docs/git-config"),
    Point {
        scope: Scope::NamedBy("core.hooksPath"),
        ..row(&[], Present, GitCommand, "git", Never, (EVENT, "medium", "low"), "https://git-scm.com/docs/githooks")
    },
    row(&[".gitmodules", ".git/modules"], Present, GitCommand, "git", Never, (EVENT, "high", "low"), "https://securitylabs.datadoghq.com/articles/git-arbitrary-file-write/"),
    row(&[".pre-commit-config.yaml"], Present, GitCommand, "pre-commit", Never, (EVENT, "medium", "low"), "https://pre-commit.com/"),
    row(&[".envrc"], Present, EnterInShell, "direnv", OncePerContent, (EVENT, "high", "medium"), "https://direnv.net/"),
    row(&["mise.toml", ".mise.toml"], Present, EnterInShell, "mise", OncePerFolder, (EVENT, "high", "medium"), "https://mise.jdx.dev/cli/trust.html"),
    row(&[".devcontainer/devcontainer.json", ".devcontainer.json"], Present, OpenInEditor, "Dev Containers", DependsOnSetting, (EVENT, "high", "medium"), "https://containers.dev/implementors/json_reference/"),
    row(&[".github/workflows"], Present, GitCommand, "a self-hosted runner", Never, (EVENT, "high", "low"), "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"),
];

/// The editor's task file, from the checkout.
pub const TASKS: &str = ".vscode/tasks.json";
/// The literal of `watched_as` of the editor's task file, kept from before the table.
pub const RUNS_ON_OPEN: &str = "task run when the project folder is opened";
/// The coverage kind of the reading of the task files, kept from before the table.
pub const KIND: &str = "editor tasks set to run when a checkout's folder is opened";
/// The coverage kind of the reading that names what is present and not read.
pub const OTHERS_KIND: &str = "other ways a checkout runs code by itself";
/// The coverage kind of the reading of which ways each checkout holds, read or not.
pub const PRESENT_KIND: &str = "ways a checkout runs code by itself, as present in each";
/// The predicate of that reading: a checkout holds the file of a way, by its name.
pub const HOLDS: &str = "holds_autorun_point";
/// What this build has no reader for, in its own words; the name says which.
pub const OTHER_WAY: &str = "way a project runs code by itself";
/// The note of a full reading of the task files that found no such task.
pub const NO_TASK: &str = "no checkout has an editor task set to run when its folder is opened";
/// A file of a row read here larger than this is not read.
pub const CAP: u64 = 1024 * 1024;

impl Trigger {
    /// What runs it, in plain words.
    pub fn words(self) -> &'static str {
        match self {
            OpenInEditor => "opening the folder in an editor",
            EnterInShell => "entering the folder in a shell",
            StartAgent => "starting a coding agent in the folder",
            AgentEvent => "a coding agent's actions",
            InstallPackages => "installing the project's packages",
            BuildOrTest => "building or testing the project",
            GitCommand => "a git command",
            InterpreterStart => "starting an interpreter there",
            EveryCommand => "every command of the tool",
        }
    }

    /// For a trigger whose rows are read here: the literal of `watched_as`, what is watched in
    /// a person's words, and what it is in a line. `None` for a trigger with no such row; a
    /// row of it that is read needs these words and a rule.
    pub fn watched(self) -> Option<(&'static str, &'static str, &'static str)> {
        match self {
            OpenInEditor => Some((
                RUNS_ON_OPEN,
                "editor tasks that run when a project is opened",
                "Tasks an editor runs by itself as soon as a project folder is opened.",
            )),
            InstallPackages => Some((
                "script run when a project's packages are installed",
                "scripts that run when a project's packages are installed",
                "Scripts a package manager runs by itself when a project's packages are installed.",
            )),
            StartAgent => Some((
                "program or tool a project tells a coding agent to run",
                "programs and tools a project tells your coding agent to run",
                "Programs and tools a coding agent starts or runs by itself because a project's settings tell it to.",
            )),
            _ => None,
        }
    }
}

impl Asks {
    pub fn words(self) -> &'static str {
        match self {
            Never => "No",
            OncePerFolder => "Once per folder",
            OncePerContent => "Each time it changes",
            DependsOnSetting => "Depends on a setting",
            NotKnown => "Not known",
        }
    }
}

impl Point {
    /// The row's name: its paths, or where another file names it.
    pub fn name(&self) -> String {
        match self.scope {
            Scope::NamedBy(setting) => format!("the folder {setting} names"),
            Scope::Checkout => self.paths.join(", "),
        }
    }

    /// Whether this version reads the part that counts.
    pub fn read(&self) -> bool {
        self.part != Present
    }

    /// Whether it is read by this file, in a reading of its own, rather than as a place of
    /// the watched places reader.
    pub fn read_here(&self) -> bool {
        !matches!(self.part, Present | Entries(_))
    }

    /// The coverage kind of the reading of this row in every checkout.
    pub fn kind(&self) -> String {
        match self.part {
            FolderOpenTask => KIND.to_string(),
            Entries(_) => watched::HOOK_KIND.to_string(),
            _ => format!(
                "{} of each checkout, the part that runs by itself",
                self.name()
            ),
        }
    }

    /// The literal of `watched_as` of what this row finds.
    pub fn watched_as(&self) -> Option<&'static str> {
        match self.part {
            Entries(as_) => Some(as_),
            _ => self.trigger.watched().map(|w| w.0),
        }
    }

    /// The note of a full reading that found nothing to watch.
    fn nothing(&self) -> String {
        match self.part {
            FolderOpenTask => NO_TASK.to_string(),
            Select(_) => format!("no checkout's {} holds any of the keys read", self.name()),
            _ => format!("no checkout has {}", self.name()),
        }
    }
}

/// How many known ways this version reads, and how many are known.
pub fn counts() -> (usize, usize) {
    (POINTS.iter().filter(|p| p.read()).count(), POINTS.len())
}

/// The files of a checkout read here, each from the checkout's folder. The watcher subscribes
/// to each of them in every checkout it holds, as it does to the hooks folder, so a row read
/// here is watched within seconds with no change to the watcher.
pub fn files() -> Vec<&'static str> {
    POINTS
        .iter()
        .filter(|p| p.read_here())
        .flat_map(|p| p.paths.iter().copied())
        .collect()
}

/// The triggers whose rows are read here, each once, in the order of the table, with their
/// `watched_as`, words and line.
pub fn watched() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut out: Vec<(&str, &str, &str)> = Vec::new();
    for p in POINTS.iter().filter(|p| p.read_here()) {
        if let Some(w) = p.trigger.watched()
            && !out.contains(&w)
        {
            out.push(w);
        }
    }
    out
}

/// The coverage kinds of the readings of the rows read here whose findings are `watched_as`.
pub fn kinds_of(watched_as: &str) -> Vec<String> {
    POINTS
        .iter()
        .filter(|p| p.read_here() && p.watched_as() == Some(watched_as))
        .map(Point::kind)
        .collect()
}

/// What a line about a kind of watched thing says, by its words; empty for words not here.
pub fn about(what: &str) -> &'static str {
    watched()
        .into_iter()
        .find(|w| w.1 == what)
        .map(|w| w.2)
        .unwrap_or_default()
}

/// A rule's technique, severity and confidence, taken from the rows read of its trigger.
pub fn levels(trigger: Trigger) -> (Option<&'static str>, &'static str, &'static str) {
    POINTS
        .iter()
        .find(|p| p.read_here() && p.trigger == trigger)
        .map(|p| (p.technique, p.severity, p.confidence))
        .unwrap_or((None, "medium", "low"))
}

/// Whether what a run saw is a new or changed entry of a trigger's rows.
pub fn fires(place: &str, change: &str, trigger: Trigger) -> bool {
    trigger.watched().is_some_and(|w| w.0 == place) && (change == "new" || change == "changed")
}

/// Registers the kinds of reading and the predicate this table needs, on every open.
pub fn add_kinds(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut kinds: Vec<String> = POINTS
        .iter()
        .filter(|p| p.read_here())
        .map(Point::kind)
        .collect();
    kinds.push(PRESENT_KIND.to_string());
    for kind in kinds {
        conn.execute(
            "INSERT OR IGNORE INTO coverage_kind (name) VALUES (?1)",
            [kind],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO predicate (name, object_kind, status) VALUES (?1, 'literal', 'used')",
        [HOLDS],
    )?;
    Ok(())
}

/// What looking at one row in every checkout found.
#[derive(Default)]
pub struct Looked {
    pub look: Look,
    /// Files read whole rather than by key, each with why.
    pub whole: Vec<(String, String)>,
}

impl Looked {
    /// The completeness of the reading and its reason or note.
    pub fn coverage(&self, p: &Point) -> (&'static str, Option<String>) {
        let whole = (!self.whole.is_empty()).then(|| {
            let files: Vec<String> = self
                .whole
                .iter()
                .map(|(path, why)| format!("{path} ({why})"))
                .collect();
            format!("read whole, not by key: {}", files.join("; "))
        });
        match (self.look.completeness(), whole) {
            (("full", _), Some(whole)) => ("full", Some(whole)),
            (("full", _), None) if self.look.entries.is_empty() => ("full", Some(p.nothing())),
            ((c, Some(reason)), Some(whole)) => (c, Some(format!("{reason}; {whole}"))),
            (other, _) => other,
        }
    }
}

/// Looks at one row read here in every checkout, each given as its folder and its path as
/// ids name it.
pub fn look_all<'a>(p: &Point, checkouts: impl Iterator<Item = (&'a Path, &'a str)>) -> Looked {
    let mut all = Looked::default();
    for (path, rel) in checkouts {
        for file in p.paths {
            look(p, path, rel, file, &mut all);
        }
    }
    all
}

/// Looks at one file of a row in one checkout. Only a file whose part is there is an entry; one
/// that cannot be read, or whose task file cannot be parsed, is a failure with its reason, and
/// is not counted as looked at.
fn look(p: &Point, checkout: &Path, rel: &str, file: &str, out: &mut Looked) {
    let shown = format!("{rel}/{file}");
    let path = checkout.join(file);
    let link = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return,
        Err(e) => return out.look.failed.push((shown, e.to_string())),
        Ok(m) if m.file_type().is_symlink() => std::fs::read_link(&path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned()),
        Ok(_) => None,
    };
    let bytes = match read(&path) {
        Ok(bytes) => bytes,
        Err(why) => return out.look.failed.push((shown, why)),
    };
    let whole = |bytes: &[u8]| Content::Hash(format!("sha256:{}", crate::sha256::hex(bytes)));
    let mut found: Vec<(String, Content)> = Vec::new();
    match p.part {
        FolderOpenTask => match runs_on_open(&bytes) {
            Err(why) => return out.look.failed.push((shown, why)),
            Ok(true) => found.push((shown, whole(&bytes))),
            Ok(false) => {}
        },
        Bytes => found.push((shown, whole(&bytes))),
        Lines(prefix) => {
            let lines: Vec<&[u8]> = bytes
                .split(|b| *b == b'\n')
                .filter(|l| l.starts_with(prefix.as_bytes()))
                .collect();
            if !lines.is_empty() {
                found.push((shown, value(&lines.join(&b'\n'))));
            }
        }
        Select(keys) => match select(&bytes, keys) {
            Selected::Values(values) => {
                for (pointer, hash) in values {
                    found.push((format!("{shown}#{pointer}"), Content::Value(hash)));
                }
            }
            Selected::Whole(why) => {
                found.push((shown.clone(), whole(&bytes)));
                out.whole.push((shown, why));
            }
        },
        Present | Entries(_) => return,
    }
    out.look.present += 1;
    for (path, content) in found {
        out.look.entries.push(Entry {
            path,
            watched_as: p.watched_as().unwrap_or_default(),
            content,
            link: link.clone(),
        });
    }
}

/// The checksum of a part, said apart from a file's: `sha256:<hex>` of what is selected.
fn value(bytes: &[u8]) -> Content {
    Content::Value(format!("sha256:{}", crate::sha256::hex(bytes)))
}

/// What `Select` took from a file.
#[derive(Debug, PartialEq)]
pub enum Selected {
    /// Per selected JSON pointer that is there, the checksum of its canonical value.
    Values(Vec<(String, String)>),
    /// Read whole instead, and why.
    Whole(String),
}

/// Why a file is read whole: two readers that keep a different one of two equal keys see a
/// different value at a selected key.
pub const EQUAL_KEYS: &str = "two equal keys that tools read differently";
/// Why a file is read whole: it starts with a byte order mark.
pub const BOM: &str = "starts with a byte order mark, which the tools read differently";

/// Takes the parts at `keys` from a strict JSON file, or says why it must be read whole. A
/// value that is `null` is no part: no tool runs it.
pub fn select(bytes: &[u8], keys: &[&str]) -> Selected {
    if bytes.starts_with(b"\xEF\xBB\xBF") {
        return Selected::Whole(BOM.to_string());
    }
    let last: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => return Selected::Whole(format!("not strict JSON: {e}")),
    };
    let mut pointers = Vec::new();
    for key in keys {
        expand(&last, key, String::new(), &mut pointers);
    }
    if pointers.is_empty() {
        return Selected::Values(Vec::new());
    }
    let first: Value = match crate::json5::first_of_equal_keys(bytes)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(why) => return Selected::Whole(format!("not read alike by a second reader: {why}")),
    };
    let mut out = Vec::new();
    for pointer in pointers {
        let (Some(at), other) = (last.pointer(&pointer), first.pointer(&pointer)) else {
            continue;
        };
        if Some(at) != other {
            return Selected::Whole(EQUAL_KEYS.to_string());
        }
        if at.is_null() {
            continue;
        }
        let canonical = serde_json::to_vec(at).unwrap_or_default();
        out.push((
            pointer,
            format!("sha256:{}", crate::sha256::hex(&canonical)),
        ));
    }
    Selected::Values(out)
}

/// The JSON pointers a key path names in a value: itself, or with each `*` one per key of the
/// object there, escaped as RFC 6901 says.
fn expand(v: &Value, rest: &str, done: String, out: &mut Vec<String>) {
    let Some(rest) = rest.strip_prefix('/') else {
        if !out.contains(&done) {
            out.push(done);
        }
        return;
    };
    let (segment, tail) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if segment == "*" {
        if let Value::Object(map) = v {
            for (key, inner) in map {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                expand(inner, tail, format!("{done}/{escaped}"), out);
            }
        }
    } else if let Some(inner) = v.pointer(&format!("/{segment}")) {
        expand(inner, tail, format!("{done}/{segment}"), out);
    }
}

/// A regular file's bytes, opened without waiting, up to the cap; else why not.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    read_capped(path, CAP)
}

/// The same with a cap of the caller's.
pub fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("not a regular file".to_string());
    }
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > cap {
        return Err(format!("over the size cap of {} KiB", cap >> 10));
    }
    Ok(bytes)
}

/// Whether a task file holds a task set to run when the folder is opened; an error when it
/// cannot be read as JSON with comments.
///
/// The format is JSON with comments and trailing commas, read by Foundation's JSON5 reader,
/// see `json5.rs`; nothing is stripped here. Whether a file that reads holds such a task is
/// told by its text, not by the parsed value. The editor runs a task whose `runOptions.runOn`
/// is `folderOpen` in any case. Of two equal keys Foundation keeps the first and the editor the
/// last, so a parsed value that says `default` cannot rule a task out; and the editor decodes
/// no escape but `\u` inside a word. So a file holds such a task when its text says
/// `folderOpen` in any case, or holds a `\u` escape that could spell it. That errs only toward
/// watching: a file that names it in a comment is watched too.
pub fn runs_on_open(bytes: &[u8]) -> Result<bool, String> {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    // Inside a list, so that a file of comments only is an empty list and not an error. The
    // line break keeps a comment on the last line from swallowing the bracket; none is added
    // before, so that the lines Foundation names are the file's own.
    let mut wrapped = b"[".to_vec();
    wrapped.extend_from_slice(text);
    wrapped.extend_from_slice(b"\n]");
    crate::json5::reads(&wrapped)?;
    let lower = text.to_ascii_lowercase();
    let says = |word: &[u8]| lower.windows(word.len()).any(|w| w == word);
    Ok(says(b"folderopen") || says(b"\\u"))
}

/// The rows a checkout holds a file of, read or not. One that cannot be looked at is counted
/// too: it may be there. A row named by another file is not looked for.
pub fn present(checkout: &Path) -> Vec<&'static Point> {
    POINTS
        .iter()
        .filter(|p| p.scope == Scope::Checkout)
        .filter(|p| {
            p.paths.iter().any(|path| {
                let segments: Vec<&str> = path.split('/').collect();
                exists(checkout, &segments)
            })
        })
        .collect()
}

/// Whether a path of segments is there under `base`; a segment with a `*` matches every
/// entry that begins and ends as it does.
fn exists(base: &Path, segments: &[&str]) -> bool {
    let Some((first, rest)) = segments.split_first() else {
        return true;
    };
    let Some((before, after)) = first.split_once('*') else {
        let path = base.join(first);
        if rest.is_empty() {
            // Not there, or under a file such as a worktree's `.git`: absent.
            return !matches!(std::fs::symlink_metadata(&path),
                             Err(e) if absent(&e));
        }
        return exists(&path, rest);
    };
    let names = match std::fs::read_dir(base) {
        Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.file_name()),
        Err(e) => return !absent(&e),
    };
    for name in names {
        let text = name.to_string_lossy();
        if text.len() >= before.len() + after.len()
            && text.starts_with(before)
            && text.ends_with(after)
            && exists(&base.join(&name), rest)
        {
            return true;
        }
    }
    false
}

/// Whether an error says the path is not there: missing, or a part of it is not a folder.
fn absent(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_set_to_run_on_opening_is_found_however_the_file_is_written() {
        // As editors write it: comments, a trailing comma, the value in another case, and the
        // task under a platform's own settings.
        let file = br#"{
            // See https://go.microsoft.com/fwlink/?LinkId=733558
            "version": "2.0.0",
            "tasks": [
                { "label": "build", "type": "shell", "command": "make" },
                {
                    "label": "setup",
                    "osx": { "runOptions": { "runOn": "FOLDEROPEN" } }, /* here */
                },
            ]
        }"#;
        assert_eq!(runs_on_open(file), Ok(true));
        let plain = br#"{"version": "2.0.0", "tasks": [{"label": "build", "command": "make"}]}"#;
        assert_eq!(runs_on_open(plain), Ok(false));
        let default = br#"{"tasks": [{"label": "a", "runOptions": {"runOn": "default"}}]}"#;
        assert_eq!(runs_on_open(default), Ok(false));
    }

    #[test]
    fn where_foundation_and_the_editor_could_differ_the_file_is_taken_as_holding_a_task() {
        // Foundation keeps the first of two equal keys, the editor the last.
        let twice = br#"{"tasks": [{"runOptions": {"runOn": "default", "runOn": "folderOpen"}}]}"#;
        assert_eq!(runs_on_open(twice), Ok(true));
        // An escape spells the word unlike its letters.
        let escaped = b"{\"tasks\": [{\"runOptions\": {\"runOn\": \"default\", \"runOn\": \"folder\\u004Fpen\"}}]}";
        assert!(
            !escaped
                .windows(10)
                .any(|w| w.eq_ignore_ascii_case(b"folderopen"))
        );
        assert_eq!(runs_on_open(escaped), Ok(true));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_and_one_of_comments_only_holds_no_task() {
        assert!(runs_on_open(b"{\"tasks\": [ {\"label\": } ]}").is_err());
        assert!(runs_on_open(b"{} {}").is_err());
        assert_eq!(runs_on_open(b"// nothing yet"), Ok(false));
        assert_eq!(runs_on_open(b"\xEF\xBB\xBF{}"), Ok(false));
    }

    fn hash(v: &str) -> String {
        format!("sha256:{}", crate::sha256::hex(v.as_bytes()))
    }

    #[test]
    fn a_selected_part_is_the_checksum_of_its_canonical_value_whatever_the_file_around_it() {
        // The rest of the file changes often and is not read; the order of keys and the
        // spacing of the value are not the part.
        let one = br#"{"name": "a", "scripts": {"test": "x", "prepare": {"b": 1, "a": "s"}}}"#;
        let two = br#"{"scripts": {"prepare": {"a":"s","b":1}, "test": "y"}, "name": "b"}"#;
        let keys = &["/scripts/prepare", "/scripts/install"];
        let expected = Selected::Values(vec![(
            "/scripts/prepare".to_string(),
            hash(r#"{"a":"s","b":1}"#),
        )]);
        assert_eq!(select(one, keys), expected);
        assert_eq!(select(two, keys), expected);
        // Absent, null, a parent that is not an object, a top that is not one, an empty file
        // and one that is not JSON at all.
        assert_eq!(
            select(br#"{"scripts": {"prepare": null}}"#, keys),
            Selected::Values(vec![])
        );
        assert_eq!(
            select(br#"{"scripts": "prepare"}"#, keys),
            Selected::Values(vec![])
        );
        assert_eq!(select(b"[1, 2]", keys), Selected::Values(vec![]));
        assert_eq!(
            select(br#"{"scripts": {"install": 3}}"#, keys),
            Selected::Values(vec![("/scripts/install".to_string(), hash("3"))])
        );
        for not_json in [&b""[..], b"{\"scripts\": {,}}", b"\x00\xff"] {
            assert!(
                matches!(select(not_json, keys), Selected::Whole(w) if w.starts_with("not strict JSON")),
            );
        }
    }

    #[test]
    fn every_key_of_an_object_is_its_own_part_and_a_key_is_escaped_as_a_json_pointer() {
        let file = br#"{"mcpServers": {"a/b": {"command": "x"}, "c~d": {"command": "y"}}}"#;
        assert_eq!(
            select(file, &["/mcpServers/*"]),
            Selected::Values(vec![
                ("/mcpServers/a~1b".to_string(), hash(r#"{"command":"x"}"#)),
                ("/mcpServers/c~0d".to_string(), hash(r#"{"command":"y"}"#)),
            ])
        );
    }

    #[test]
    fn a_duplicate_key_that_readers_resolve_differently_is_read_whole_never_unchanged() {
        // The false calm: a benign value where one reader looks and a planted one where the
        // other does. Either order is read whole, so it cannot read as the benign value.
        let keys = &["/scripts/prepare"];
        for file in [
            &br#"{"scripts": {"prepare": "husky", "prepare": "node x.js"}}"#[..],
            br#"{"scripts": {"prepare": "node x.js", "prepare": "husky"}}"#,
            br#"{"scripts": {"prepare": "husky"}, "scripts": {"prepare": "node x.js"}}"#,
        ] {
            assert_eq!(select(file, keys), Selected::Whole(EQUAL_KEYS.to_string()));
        }
        // Equal keys elsewhere, or with the same value, change nothing.
        let elsewhere =
            br#"{"name": "a", "name": "b", "scripts": {"prepare": "p", "prepare": "p"}}"#;
        assert_eq!(
            select(elsewhere, keys),
            Selected::Values(vec![("/scripts/prepare".to_string(), hash("\"p\""))])
        );
        assert_eq!(
            select(b"\xEF\xBB\xBF{\"scripts\": {}}", keys),
            Selected::Whole(BOM.to_string())
        );
    }

    #[test]
    fn every_key_of_every_row_read_by_key_is_an_entry_of_its_triggers_kind() {
        // A row is data: what it lists is what is read, with nothing else to write.
        let dir = std::env::temp_dir().join(format!("soc-autorun-keys-{}", std::process::id()));
        for p in POINTS.iter() {
            let Select(keys) = p.part else { continue };
            let _ = std::fs::remove_dir_all(&dir);
            let mut file = Value::Object(Default::default());
            for key in keys {
                let mut at = &mut file;
                for segment in key.trim_start_matches('/').split('/') {
                    let segment = if segment == "*" { "x" } else { segment };
                    at = at
                        .as_object_mut()
                        .unwrap()
                        .entry(segment)
                        .or_insert(Value::Object(Default::default()));
                }
                *at = Value::String(format!("set {key}"));
            }
            let path = dir.join(p.paths[0]);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            let looked = look_all(p, [(dir.as_path(), "dev/a")].into_iter());
            assert_eq!(looked.look.entries.len(), keys.len(), "{}", p.name());
            assert!(
                looked
                    .look
                    .entries
                    .iter()
                    .all(|e| Some(e.watched_as) == p.watched_as())
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_with_a_star_matches_entries_that_begin_and_end_as_it_does() {
        let dir = std::env::temp_dir().join(format!("soc-autorun-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".venv/lib/python3.12/site-packages")).unwrap();
        std::fs::write(dir.join(".venv/lib/python3.12/site-packages/a.pth"), "").unwrap();
        std::fs::write(dir.join("w.code-workspace"), "{}").unwrap();
        let names: Vec<String> = present(&dir).iter().map(|p| p.name()).collect();
        std::fs::remove_file(dir.join("w.code-workspace")).unwrap();
        std::fs::rename(
            dir.join(".venv/lib/python3.12/site-packages/a.pth"),
            dir.join(".venv/lib/python3.12/site-packages/a.txt"),
        )
        .unwrap();
        let after = present(&dir).len();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            names,
            ["*.code-workspace", ".venv/lib/*/site-packages/*.pth"]
        );
        assert_eq!(after, 0);
    }

    #[test]
    fn a_row_of_each_extraction_reads_its_part_and_derives_its_kind_from_the_table() {
        // A hypothetical row of each extraction this version does not use in the table yet.
        let dir = std::env::temp_dir().join(format!("soc-autorun-row-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hook.pth"), "# x\nimport a\nimport b\n").unwrap();
        let bytes = Point {
            part: Bytes,
            ..row(
                &["hook.pth"],
                Present,
                InterpreterStart,
                "Python",
                Never,
                (EVENT, "high", "low"),
                "",
            )
        };
        let lines = Point {
            part: Lines("import"),
            ..row(
                &["hook.pth"],
                Present,
                InterpreterStart,
                "Python",
                Never,
                (EVENT, "high", "low"),
                "",
            )
        };
        let at = [(dir.as_path(), "dev/a")];
        let b = look_all(&bytes, at.iter().copied());
        let l = look_all(&lines, at.iter().copied());
        let _ = std::fs::remove_dir_all(&dir);
        let content = |x: &Looked| {
            x.look
                .entries
                .iter()
                .map(|e| (e.path.clone(), e.content.literal()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            content(&b),
            [(
                "dev/a/hook.pth".to_string(),
                Some(hash("# x\nimport a\nimport b\n"))
            )]
        );
        assert_eq!(
            content(&l),
            [(
                "dev/a/hook.pth".to_string(),
                Some(format!("value {}", hash("import a\nimport b")))
            )]
        );
        assert_eq!(
            bytes.kind(),
            "hook.pth of each checkout, the part that runs by itself"
        );
    }
}
