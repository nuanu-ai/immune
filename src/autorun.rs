//! What makes code run by itself, in a project or in a developer tool's own settings in the
//! home folder: one table of data, `POINTS`, one row per known way. A row says where the file
//! is, which part of it counts, what routine action runs it, which tool, whether that tool asks
//! first, the ATT&CK technique, how bad and how sure a change is, and the source the row rests
//! on. Everything else is derived from the table: the kinds of reading, the watcher's
//! subscriptions, the watched kinds for a person, the rules' levels, the inventory on the page
//! and the count of ways read. Adding a product is adding a row; a row of a trigger and scope
//! that has no rule yet needs their words and a rule.
//!
//! The project rows are `docs/research/what-is-missed.md`, section 3, with
//! `.gemini/settings.json` and the `.env` files Gemini CLI loads as two rows, since one part is
//! read and one is not. The home rows are the tools' own configuration its section 1 names, each
//! at the path its tool documents; one not documented for macOS is not a row.
//!
//! A row that is read goes through the watched places reader like any other watched file,
//! one reading per row scoped to the machine and, for a project row, covering every checkout:
//! its first reading on this Mac is the baseline, and an entry that appears later, in a
//! checkout the store held or in one that is new, or whose part changes, is a finding of the
//! rule of its trigger and scope. A row read for the first time after an upgrade is a kind
//! read for the first time: a baseline too.
//!
//! How the part that counts is taken, a closed set:
//!
//! - `Entries`: every entry of a folder, read by the watched places reader as its own place
//!   (`.git/hooks`); listed here so that the inventory is whole.
//! - `Folders`: the folders in a folder, each by what identifies it apart from its version, as
//!   the row's `Ident` says: an editor's extensions, which the editor updates by itself.
//! - `WholeWhen`: the whole file's checksum, kept while a property of a name holds a value
//!   anywhere in its tree: the editor's task file, while a task runs on opening.
//! - `Bytes`: the whole file's checksum.
//! - `Select`: the file parsed in its tool's format, and per key path the SHA-256 of the
//!   canonical value there; a `*` in a segment stands for any run of characters in a key. The
//!   text of a script or command is never kept: an entry names the file and the key, and holds
//!   the checksum.
//! - `Lines`: the lines that start with a prefix.
//! - `Present`: not read; whether it is there is named and counted.
//!
//! What `Select` reads is what the tool reads, or it does not guess. Strict JSON: npm, Yarn,
//! pnpm and Claude Code read it with `JSON.parse`, which keeps the last of two equal keys; Bun's
//! own parser may keep the first. serde_json keeps the last; Foundation's strict reader keeps
//! the first (`json5::first_of_equal_keys`). JSON with comments (VS Code, its dev containers
//! and its forks; Gemini CLI, comments only): `jsonc.rs` sees every equal key. A file is read by
//! key only when no equal key leaves a doubt at a selected key, it has no byte order mark,
//! which the tools treat differently, and it is in the row's format. Otherwise it falls back to
//! the whole file's checksum, `Bytes`, and the reading says why: a change in it is never
//! "unchanged".

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
    /// In the home folder.
    Home,
    /// Where another file names it: the setting given. Not looked for in this version.
    NamedBy(&'static str),
}

/// The format a tool reads a file in.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Format {
    Strict,
    /// Comments, and no trailing comma: `JSON.parse` after comments are stripped.
    Comments,
    /// Comments and trailing commas: VS Code's reader.
    CommentsAndCommas,
}

/// What identifies a folder apart from its version: the name before the last `separator` that
/// is followed by a version of `numbers` numbers joined by dots, at the end of the name or
/// before another `separator` and what follows it (a target platform). A name with no version
/// is itself, whole.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Ident {
    pub separator: char,
    pub numbers: usize,
}

impl Ident {
    pub fn of<'a>(&self, name: &'a str) -> &'a str {
        let versioned = |rest: &str| {
            let (version, platform) = rest.split_once(self.separator).unwrap_or((rest, "x"));
            let numbers: Vec<&str> = version.split('.').collect();
            !platform.is_empty()
                && numbers.len() == self.numbers
                && numbers
                    .iter()
                    .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        };
        name.char_indices()
            .filter(|(i, c)| *c == self.separator && versioned(&name[i + c.len_utf8()..]))
            .map(|(i, _)| &name[..i])
            .next_back()
            .unwrap_or(name)
    }
}

/// How the part that counts is taken.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Part {
    /// Every entry of a folder, read by the watched places reader as the place of this kind.
    Entries(&'static str),
    /// The folders in a folder, by what identifies each apart from its version.
    Folders(Ident),
    /// The whole file while a property of this name holds this value, in any case, anywhere.
    WholeWhen(Format, &'static str, &'static str),
    /// No row of this version is read whole yet; a test reads a row of it.
    #[allow(dead_code)]
    Bytes,
    /// JSON pointers into a file of this format; a `*` in a segment is any run of characters.
    Select(Format, &'static [&'static str]),
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

/// Names a row keeps from before the table, so that a store keeps its history: the coverage
/// kind, the literal of `watched_as`, the words for a person, its line and the note of a
/// reading that found nothing.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Kept {
    pub kind: &'static str,
    pub watched: Watched,
    pub nothing: &'static str,
}

/// What a finding of a row is watched as: the literal of `watched_as`, the words for a person,
/// and what it is in a line.
pub type Watched = (&'static str, &'static str, &'static str);

/// One known way code runs by itself.
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
    pub kept: Option<Kept>,
    /// Why a row read here is read only at each full run and when a watcher starts, not at
    /// every write to its file; `None` for a row the watcher subscribes to.
    pub hourly: Option<&'static str>,
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
/// The same in the user's settings, with the keys whose value is a command Claude Code runs,
/// as its settings reference lists them: in any file, and the last three in the user's or
/// managed settings only.
const CLAUDE_USER: &[&str] = &[
    "/hooks",
    "/env",
    "/enableAllProjectMcpServers",
    "/enabledMcpjsonServers",
    "/permissions/allow",
    "/enabledPlugins",
    "/extraKnownMarketplaces",
    "/apiKeyHelper",
    "/awsAuthRefresh",
    "/awsCredentialExport",
    "/gcpAuthRefresh",
    "/otelHeadersHelper",
    "/fileSuggestion",
    "/statusLine",
    "/subagentStatusLine",
    "/processWrapper",
    "/sshHostCommands",
    "/sandbox/ripgrep",
];
/// The MCP servers Claude Code keeps in its own state file, which it rewrites all the time:
/// user scope at the top, local scope under each project's path.
const CLAUDE_STATE: &[&str] = &["/mcpServers/*", "/projects/*/mcpServers/*"];
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
/// VS Code's settings that let its agent run tools unasked (CVE-2025-53773 and its successors),
/// Kiro's trusted commands, and settings that name an executable. Those are open-ended, every
/// extension adds its own: they are bounded here by name, a key ending in `Path` or `.path`
/// (`php.validate.executablePath`, `git.path`), at the top or in a language's block. An
/// executable named by a key of another shape is not seen.
const VSCODE_SETTINGS: &[&str] = &[
    "/chat.tools.autoApprove",
    "/chat.tools.global.autoApprove",
    "/chat.tools.terminal.autoApprove",
    "/kiro.trustedCommands",
    "/*Path",
    "/*.path",
    "/[*]/*Path",
    "/[*]/*.path",
];
/// The same inside a workspace file, with its folders and its tasks, which can run on opening.
const WORKSPACE: &[&str] = &[
    "/folders",
    "/tasks",
    "/settings/chat.tools.autoApprove",
    "/settings/chat.tools.global.autoApprove",
    "/settings/chat.tools.terminal.autoApprove",
    "/settings/kiro.trustedCommands",
    "/settings/*Path",
    "/settings/*.path",
    "/settings/[*]/*Path",
    "/settings/[*]/*.path",
];
/// A dev container's commands, `initializeCommand` on the host and the others inside, and
/// what it mounts from the host.
const DEVCONTAINER: &[&str] = &[
    "/initializeCommand",
    "/onCreateCommand",
    "/updateContentCommand",
    "/postCreateCommand",
    "/postStartCommand",
    "/postAttachCommand",
    "/mounts",
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
        kept: None,
        hourly: None,
    }
}

/// A row of the home folder.
const fn home(
    paths: &'static [&'static str],
    part: Part,
    trigger: Trigger,
    tool: &'static str,
    asks: Asks,
    levels: (Option<&'static str>, &'static str, &'static str),
    source: &'static str,
) -> Point {
    Point {
        scope: Scope::Home,
        ..row(paths, part, trigger, tool, asks, levels, source)
    }
}

/// Event Triggered Execution: code set to run on a routine event.
const EVENT: Option<&str> = Some("T1546");
/// Installer Packages: its procedure examples are npm's pre- and post-install scripts.
const INSTALLER: Option<&str> = Some("T1546.016");
/// IDE Extensions.
const IDE_EXTENSION: Option<&str> = Some("T1176.002");
/// An editor's extension folder, as VS Code names it (`ExtensionKey.toString` in
/// `extensionManagementUtil.ts`): `publisher.name-1.2.3`, with `-darwin-arm64` for an
/// extension built for one platform. VS Code parses it back with
/// `^([^.]+\..+)-(\d+\.\d+\.\d+)(-(.+))?$`: the identity is its first group.
const EXTENSION: Part = Folders(Ident {
    separator: '-',
    numbers: 3,
});

use Asks::*;
use Format::*;
use Part::*;
use Trigger::*;

/// Why a row is not watched live: its tool writes its own state into the file as it works,
/// so the file changes every few seconds while what is read in it almost never does, and a
/// reading at every write would be a reading every few seconds.
pub const REWRITTEN: &str = "its tool rewrites it constantly with its own state";
/// Why a row is not watched live: a path with a `*` names no one file to subscribe to.
pub const NO_FIXED_NAME: &str = "its name is not fixed, so there is no one file to subscribe to";

/// The editor's task file, from the checkout.
pub const TASKS: &str = ".vscode/tasks.json";
/// The literal of `watched_as` of the editor's task file, kept from before the table.
pub const RUNS_ON_OPEN: &str = "task run when the project folder is opened";
/// The coverage kind of the reading of the task files, kept from before the table.
pub const KIND: &str = "editor tasks set to run when a checkout's folder is opened";
/// The note of a full reading of the task files that found no such task.
pub const NO_TASK: &str = "no checkout has an editor task set to run when its folder is opened";
const TASK: Kept = Kept {
    kind: KIND,
    watched: (
        RUNS_ON_OPEN,
        "editor tasks that run when a project is opened",
        "Tasks an editor runs by itself as soon as a project folder is opened.",
    ),
    nothing: NO_TASK,
};

/// What each trigger and scope is watched as, for the rows read here.
pub const EDITOR_OPEN: Watched = (
    "setting or command an editor runs in a project",
    "programs and commands a project sets an editor to run",
    "Settings and commands in a project that make an editor, or its dev container, run a program by itself.",
);
pub const PACKAGE_INSTALL: Watched = (
    "script run when a project's packages are installed",
    "scripts that run when a project's packages are installed",
    "Scripts a package manager runs by itself when a project's packages are installed.",
);
pub const AGENT_START: Watched = (
    "program or tool a project tells a coding agent to run",
    "programs and tools a project tells your coding agent to run",
    "Programs and tools a coding agent starts or runs by itself because a project's settings tell it to.",
);
pub const AGENT_SETTINGS: Watched = (
    "program or tool a coding agent is set to run",
    "programs and tools your coding agents are set to run",
    "Programs and tools your coding agents start or run by themselves because their own settings in your home folder say so.",
);
pub const EDITOR_EXTENSION: Watched = (
    "editor extension",
    "editor extensions",
    "Extensions installed in an editor, each by its publisher and name; a new version of one is not news.",
);

/// Every known way, in the order of the note's inventory, then the home folder. The order is
/// the page's.
#[rustfmt::skip]
pub const POINTS: [Point; 52] = [
    Point { kept: Some(TASK), ..row(&[".vscode/tasks.json"], WholeWhen(CommentsAndCommas, "runOn", "folderOpen"), OpenInEditor, "VS Code, Cursor", DependsOnSetting, (EVENT, "high", "medium"), "https://code.visualstudio.com/docs/editor/tasks") },
    row(&[".vscode/settings.json"], Select(CommentsAndCommas, VSCODE_SETTINGS), OpenInEditor, "VS Code and its forks", DependsOnSetting, (EVENT, "high", "low"), "https://code.visualstudio.com/docs/editor/workspace-trust"),
    Point { hourly: Some(NO_FIXED_NAME), ..row(&["*.code-workspace"], Select(CommentsAndCommas, WORKSPACE), OpenInEditor, "VS Code and its forks", DependsOnSetting, (EVENT, "high", "low"), "https://maccarita.com/posts/idesaster") },
    row(&[".vscode/mcp.json"], Select(CommentsAndCommas, &["/servers/*"]), StartAgent, "VS Code", OncePerContent, (EVENT, "high", "medium"), "https://code.visualstudio.com/docs/agents/reference/mcp-configuration"),
    row(&[".idea"], Present, OpenInEditor, "JetBrains IDEs", OncePerFolder, (EVENT, "high", "low"), "https://www.jetbrains.com/help/idea/project-security.html"),
    row(&[".zed/settings.json"], Present, OpenInEditor, "Zed", NotKnown, (EVENT, "high", "low"), "https://maccarita.com/posts/idesaster"),
    row(&[".nvim.lua", ".nvimrc", ".exrc"], Present, OpenInEditor, "Vim, Neovim", OncePerContent, (EVENT, "high", "medium"), ""),
    row(&[".dir-locals.el"], Present, OpenInEditor, "Emacs", OncePerContent, (EVENT, "high", "low"), "https://www.gnu.org/software/emacs/manual/html_node/emacs/Safe-File-Variables.html"),
    row(&["build.rs"], Present, BuildOrTest, "Cargo, rust-analyzer", Never, (EVENT, "high", "low"), "https://doc.rust-lang.org/cargo/reference/build-scripts.html"),
    row(&[".claude/settings.json"], Select(Strict, CLAUDE), StartAgent, "Claude Code", OncePerFolder, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/settings"),
    row(&[".claude/settings.local.json"], Select(Strict, CLAUDE), StartAgent, "Claude Code", Never, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/settings"),
    row(&[".mcp.json"], Select(Strict, MCP_SERVERS), StartAgent, "Claude Code", DependsOnSetting, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/mcp"),
    row(&[".claude/skills", ".claude/commands", ".claude/agents"], Present, AgentEvent, "Claude Code", Never, (EVENT, "high", "low"), "https://github.com/osquery/osquery/blob/master/specs/ai_agent_skills.table"),
    row(&["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursor/rules", ".github/copilot-instructions.md"], Present, AgentEvent, "coding agents", Never, (None, "medium", "low"), "https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents"),
    row(&[".cursor/mcp.json"], Select(CommentsAndCommas, MCP_SERVERS), StartAgent, "Cursor", OncePerContent, (EVENT, "high", "medium"), "https://cursor.com/docs/context/mcp"),
    row(&[".cursor/hooks.json"], Select(CommentsAndCommas, &["/hooks"]), StartAgent, "Cursor", DependsOnSetting, (EVENT, "high", "medium"), "https://cursor.com/docs/agent/hooks"),
    row(&[".codex/config.toml"], Present, StartAgent, "Codex", OncePerFolder, (EVENT, "high", "medium"), "https://learn.chatgpt.com/docs/config-file/config-reference"),
    row(&[".gemini/settings.json"], Select(Comments, GEMINI), StartAgent, "Gemini CLI", DependsOnSetting, (EVENT, "high", "medium"), "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md"),
    row(&[".env", ".gemini/.env"], Present, StartAgent, "Gemini CLI", DependsOnSetting, (EVENT, "medium", "low"), "https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md"),
    row(&[".kiro/hooks"], Present, AgentEvent, "Kiro", Never, (EVENT, "high", "medium"), "https://kiro.dev/docs/hooks/"),
    row(&["package.json"], Select(Strict, PACKAGE_SCRIPTS), InstallPackages, "npm, pnpm, Yarn, Bun", Never, (INSTALLER, "high", "low"), "https://docs.npmjs.com/cli/v11/using-npm/scripts"),
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
    Point { scope: Scope::NamedBy("core.hooksPath"), ..row(&[], Present, GitCommand, "git", Never, (EVENT, "medium", "low"), "https://git-scm.com/docs/githooks") },
    row(&[".gitmodules", ".git/modules"], Present, GitCommand, "git", Never, (EVENT, "high", "low"), "https://securitylabs.datadoghq.com/articles/git-arbitrary-file-write/"),
    row(&[".pre-commit-config.yaml"], Present, GitCommand, "pre-commit", Never, (EVENT, "medium", "low"), "https://pre-commit.com/"),
    row(&[".envrc"], Present, EnterInShell, "direnv", OncePerContent, (EVENT, "high", "medium"), "https://direnv.net/"),
    row(&["mise.toml", ".mise.toml"], Present, EnterInShell, "mise", OncePerFolder, (EVENT, "high", "medium"), "https://mise.jdx.dev/cli/trust.html"),
    row(&[".devcontainer/devcontainer.json", ".devcontainer.json"], Select(CommentsAndCommas, DEVCONTAINER), OpenInEditor, "Dev Containers", DependsOnSetting, (EVENT, "high", "low"), "https://containers.dev/implementors/json_reference/"),
    row(&[".github/workflows"], Present, GitCommand, "a self-hosted runner", Never, (EVENT, "high", "low"), "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"),
    home(&[".claude/settings.json"], Select(Strict, CLAUDE_USER), StartAgent, "Claude Code", Never, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/settings-reference"),
    Point { hourly: Some(REWRITTEN), ..home(&[".claude.json"], Select(Strict, CLAUDE_STATE), StartAgent, "Claude Code", Never, (EVENT, "high", "medium"), "https://code.claude.com/docs/en/mcp") },
    home(&["Library/Application Support/Claude/claude_desktop_config.json"], Select(Strict, MCP_SERVERS), StartAgent, "Claude Desktop", Never, (EVENT, "high", "medium"), "https://modelcontextprotocol.io/docs/develop/connect-local-servers"),
    home(&[".cursor/mcp.json"], Select(CommentsAndCommas, MCP_SERVERS), StartAgent, "Cursor", OncePerContent, (EVENT, "high", "medium"), "https://cursor.com/docs/context/mcp"),
    home(&[".cursor/hooks.json"], Select(CommentsAndCommas, &["/hooks"]), StartAgent, "Cursor", Never, (EVENT, "high", "medium"), "https://cursor.com/docs/agent/hooks"),
    home(&[".gemini/settings.json"], Select(Comments, GEMINI), StartAgent, "Gemini CLI", Never, (EVENT, "high", "medium"), "https://geminicli.com/docs/reference/configuration/"),
    home(&[".claude/skills", ".claude/commands", ".claude/agents"], Present, AgentEvent, "Claude Code", Never, (EVENT, "high", "low"), "https://code.claude.com/docs/en/settings"),
    home(&[".continue/config.yaml"], Present, StartAgent, "Continue", Never, (EVENT, "high", "medium"), "https://docs.continue.dev/customize/deep-dives/configuration"),
    home(&[".codex/config.toml"], Present, StartAgent, "Codex", Never, (EVENT, "high", "medium"), "https://learn.chatgpt.com/docs/config-file/config-reference"),
    home(&[".vscode/extensions"], EXTENSION, OpenInEditor, "VS Code", Never, (IDE_EXTENSION, "medium", "low"), "https://code.visualstudio.com/docs/configure/extensions/extension-marketplace"),
    home(&["Library/Application Support/JetBrains/*/plugins"], Present, OpenInEditor, "JetBrains IDEs", Never, (IDE_EXTENSION, "medium", "low"), "https://attack.mitre.org/techniques/T1176/002/"),
];

/// The coverage kind of the reading that names what is present in checkouts and not read.
pub const OTHERS_KIND: &str = "other ways a checkout runs code by itself";
/// The same for the home folder.
pub const HOME_OTHERS_KIND: &str =
    "other places in the home folder where a tool's settings run code by itself";
/// The coverage kind of the reading of which ways each checkout, and the home folder, holds,
/// read or not.
pub const PRESENT_KIND: &str = "ways a checkout runs code by itself, as present in each";
/// The predicate of that reading: a checkout, or this machine for the home folder, holds the
/// file of a way, by its name.
pub const HOLDS: &str = "holds_autorun_point";
/// What this build has no reader for, in its own words; the name says which.
pub const OTHER_WAY: &str = "way a project runs code by itself";
pub const OTHER_HOME: &str = "place where a developer tool's settings run code by itself";
/// A file of a project row read here larger than this is not read.
pub const CAP: u64 = 1024 * 1024;
/// The same for a home row: Claude Code's state file grows with every project it was used in.
pub const HOME_CAP: u64 = 32 * 1024 * 1024;

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

    /// The same for a place in the home folder.
    pub fn words_home(self) -> &'static str {
        match self {
            OpenInEditor => "starting the editor",
            StartAgent => "starting the coding agent",
            AgentEvent => "a coding agent's actions",
            _ => self.words(),
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
    /// The row's name: its paths, from the home folder with `~/`, or where another file names
    /// it.
    pub fn name(&self) -> String {
        match self.scope {
            Scope::NamedBy(setting) => format!("the folder {setting} names"),
            Scope::Checkout => self.paths.join(", "),
            Scope::Home => self
                .paths
                .iter()
                .map(|p| format!("~/{p}"))
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    /// Whether this version reads the part that counts.
    pub fn read(&self) -> bool {
        self.part != Present
    }

    /// Whether a watcher subscribes to its files, so that a write to one is read within
    /// seconds.
    pub fn live(&self) -> bool {
        self.read_here() && self.hourly.is_none()
    }

    /// Whether it is read by this file, in a reading of its own, rather than as a place of
    /// the watched places reader.
    pub fn read_here(&self) -> bool {
        !matches!(self.part, Present | Entries(_))
    }

    /// The coverage kind of the reading of this row in every checkout, or in the home folder.
    pub fn kind(&self) -> String {
        match (self.kept, self.part, self.scope) {
            (Some(k), _, _) => k.kind.to_string(),
            (_, Entries(_), _) => watched::HOOK_KIND.to_string(),
            (_, Folders(_), _) => format!("{}, every folder by name", self.name()),
            (_, _, Scope::Home) => format!("{}, the part that runs by itself", self.name()),
            _ => format!(
                "{} of each checkout, the part that runs by itself",
                self.name()
            ),
        }
    }

    /// What a finding of this row is watched as, for a row read here.
    pub fn watched(&self) -> Option<Watched> {
        if let Some(k) = self.kept {
            return Some(k.watched);
        }
        match (self.scope, self.trigger) {
            (Scope::Checkout, OpenInEditor) => Some(EDITOR_OPEN),
            (Scope::Checkout, InstallPackages) => Some(PACKAGE_INSTALL),
            (Scope::Checkout, StartAgent) => Some(AGENT_START),
            (Scope::Home, StartAgent) => Some(AGENT_SETTINGS),
            (Scope::Home, OpenInEditor) => Some(EDITOR_EXTENSION),
            _ => None,
        }
    }

    /// The literal of `watched_as` of what this row finds.
    pub fn watched_as(&self) -> Option<&'static str> {
        match self.part {
            Entries(as_) => Some(as_),
            _ => self.watched().map(|w| w.0),
        }
    }

    /// The note of a full reading that found nothing to watch.
    fn nothing(&self) -> String {
        match (self.kept, self.part, self.scope) {
            (Some(k), _, _) => k.nothing.to_string(),
            (_, Select(..), Scope::Home) => format!("none of the keys read is in {}", self.name()),
            (_, Select(..), _) => {
                format!("no checkout's {} holds any of the keys read", self.name())
            }
            (_, Folders(_), _) => format!("no folder in {}", self.name()),
            _ => format!("no checkout has {}", self.name()),
        }
    }

    /// The largest file of this row read.
    fn cap(&self) -> u64 {
        match self.scope {
            Scope::Home => HOME_CAP,
            _ => CAP,
        }
    }
}

/// How many known ways of a scope this version reads, and how many are known. `NamedBy` rows
/// count with the checkout's.
pub fn counts(home: bool) -> (usize, usize) {
    let of: Vec<&Point> = POINTS
        .iter()
        .filter(|p| (p.scope == Scope::Home) == home)
        .collect();
    (of.iter().filter(|p| p.read()).count(), of.len())
}

/// The files of a checkout read here, each from the checkout's folder. The watcher subscribes
/// to each of them in every checkout it holds, as it does to the hooks folder, so a row read
/// here is watched within seconds with no change to the watcher. A row that says why it is not
/// (`hourly`) is read at every full run and by the watcher's readings, not subscribed to.
pub fn files() -> Vec<&'static str> {
    POINTS
        .iter()
        .filter(|p| p.live() && p.scope == Scope::Checkout)
        .flat_map(|p| p.paths.iter().copied())
        .collect()
}

/// The places in the home folder read here, and whether each is a folder.
pub fn home_places() -> Vec<(&'static str, bool)> {
    POINTS
        .iter()
        .filter(|p| p.live() && p.scope == Scope::Home)
        .flat_map(|p| {
            p.paths
                .iter()
                .map(|path| (*path, matches!(p.part, Folders(_))))
        })
        .collect()
}

/// Whether a change to things watched as `watched_as` shows within seconds while a watcher
/// runs: whether any row read here whose findings are such is watched live.
pub fn live(watched_as: &str) -> bool {
    live_in(&POINTS, watched_as)
}

fn live_in(points: &[Point], watched_as: &str) -> bool {
    points
        .iter()
        .any(|p| p.live() && p.watched_as() == Some(watched_as))
}

/// What the rows read here are watched as, each once, in the order of the table.
pub fn watched() -> Vec<Watched> {
    let mut out: Vec<Watched> = Vec::new();
    for p in POINTS.iter().filter(|p| p.read_here()) {
        if let Some(w) = p.watched()
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

/// A rule's technique, severity and confidence, taken from the rows read whose findings are
/// `watched_as`.
pub fn levels(watched_as: &str) -> (Option<&'static str>, &'static str, &'static str) {
    POINTS
        .iter()
        .find(|p| p.read_here() && p.watched_as() == Some(watched_as))
        .map(|p| (p.technique, p.severity, p.confidence))
        .unwrap_or((None, "medium", "low"))
}

/// Whether what a run saw is a new or changed entry watched as `watched_as`.
pub fn fires(place: &str, change: &str, watched_as: &str) -> bool {
    place == watched_as && (change == "new" || change == "changed")
}

/// Registers the kinds of reading and the predicate this table needs, on every open.
pub fn add_kinds(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mut kinds: Vec<String> = POINTS
        .iter()
        .filter(|p| p.read_here())
        .map(Point::kind)
        .collect();
    kinds.push(PRESENT_KIND.to_string());
    kinds.push(HOME_OTHERS_KIND.to_string());
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

/// Looks at one row read here in every place given, each as its folder and its path as ids
/// name it: a checkout, or the home folder with an empty path. A place in the home folder that
/// macOS asks permission for is never looked into.
pub fn look_all<'a>(p: &Point, places: impl Iterator<Item = (&'a Path, &'a str)>) -> Looked {
    let mut all = Looked::default();
    for (base, rel) in places {
        for pattern in p.paths {
            if p.scope == Scope::Home
                && crate::guarded::folder_of(&base.join(pattern), base).is_some()
            {
                continue;
            }
            for file in matching(base, rel, pattern, &mut all) {
                look(p, base, rel, &file, &mut all);
            }
        }
    }
    all
}

/// The files a path names under `base`: itself, or for a `*` in its last segment, every entry
/// of its folder that begins and ends as it does. A folder that cannot be listed is a failure.
fn matching(base: &Path, rel: &str, pattern: &str, out: &mut Looked) -> Vec<String> {
    let (folder, name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let Some((before, after)) = name.split_once('*') else {
        return vec![pattern.to_string()];
    };
    let names = match std::fs::read_dir(base.join(folder)) {
        Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.file_name()),
        Err(e) if absent(&e) => return Vec::new(),
        Err(e) => {
            out.look.failed.push((shown(rel, folder), e.to_string()));
            return Vec::new();
        }
    };
    let mut found: Vec<String> = names
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| {
            n.len() >= before.len() + after.len() && n.starts_with(before) && n.ends_with(after)
        })
        .map(|n| {
            if folder.is_empty() {
                n
            } else {
                format!("{folder}/{n}")
            }
        })
        .collect();
    found.sort();
    found
}

/// A path as ids name it: from the checkout's path, or from the home folder's when `rel` is
/// empty.
fn shown(rel: &str, file: &str) -> String {
    if rel.is_empty() {
        file.to_string()
    } else {
        format!("{rel}/{file}")
    }
}

/// Looks at one file of a row in one place. Only a file whose part is there is an entry; one
/// that cannot be read, or whose task file cannot be parsed, is a failure with its reason, and
/// is not counted as looked at.
fn look(p: &Point, base: &Path, rel: &str, file: &str, out: &mut Looked) {
    let shown = shown(rel, file);
    let path = base.join(file);
    let link = match std::fs::symlink_metadata(&path) {
        Err(e) if absent(&e) => return,
        Err(e) => return out.look.failed.push((shown, e.to_string())),
        Ok(m) if m.file_type().is_symlink() => std::fs::read_link(&path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned()),
        Ok(_) => None,
    };
    let mut found: Vec<(String, Content)> = Vec::new();
    if let Folders(ident) = p.part {
        match folders(&path, ident) {
            Err(why) => return out.look.failed.push((shown, why)),
            Ok(names) => {
                for name in names {
                    found.push((format!("{shown}/{name}"), value(name.as_bytes())));
                }
            }
        }
        return push(p, out, found, link);
    }
    let bytes = match read_capped(&path, p.cap()) {
        Ok(bytes) => bytes,
        Err(why) => return out.look.failed.push((shown, why)),
    };
    let whole = |bytes: &[u8]| Content::Hash(format!("sha256:{}", crate::sha256::hex(bytes)));
    match p.part {
        WholeWhen(format, key, holds) => match whole_when(&bytes, format, key, holds) {
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
        Select(format, keys) => match select(&bytes, format, keys) {
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
        Present | Entries(_) | Folders(_) => return,
    }
    push(p, out, found, link);
}

/// Counts a place looked at and keeps what it holds as entries of the row.
fn push(p: &Point, out: &mut Looked, found: Vec<(String, Content)>, link: Option<String>) {
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

/// The folders in a folder, each by what identifies it apart from its version, sorted and once
/// each. Files, and entries whose name begins with a dot, are the editor's own bookkeeping.
fn folders(path: &Path, ident: Ident) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !std::fs::metadata(entry.path()).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let id = ident.of(&name).to_string();
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out.sort();
    Ok(out)
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

/// Takes the parts at `keys` from a file in its tool's format, or says why it must be read
/// whole. A value that is `null` is no part: no tool runs it.
pub fn select(bytes: &[u8], format: Format, keys: &[&str]) -> Selected {
    if bytes.starts_with(b"\xEF\xBB\xBF") {
        return Selected::Whole(BOM.to_string());
    }
    if format != Strict {
        return match crate::jsonc::read(bytes, format == CommentsAndCommas) {
            Err(e) => Selected::Whole(format!("not JSON with comments as its tool reads it: {e}")),
            Ok(r) => pick(r.value.as_ref(), keys, |pointer| {
                r.doubts.iter().any(|d| related(d, pointer))
            }),
        };
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
    pick(Some(&last), keys, |pointer| {
        last.pointer(pointer) != first.pointer(pointer)
    })
}

/// The parts at `keys` of a value, unless `doubt` says of one that a tool could read it
/// otherwise.
fn pick(v: Option<&Value>, keys: &[&str], doubt: impl Fn(&str) -> bool) -> Selected {
    let Some(v) = v else {
        return Selected::Values(Vec::new());
    };
    let mut pointers = Vec::new();
    for key in keys {
        expand(v, key, String::new(), &mut pointers);
    }
    let mut out = Vec::new();
    for pointer in pointers {
        if doubt(&pointer) {
            return Selected::Whole(EQUAL_KEYS.to_string());
        }
        let Some(at) = v.pointer(&pointer) else {
            continue;
        };
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

/// Whether one JSON pointer is the other or inside it, segment by segment.
fn related(a: &str, b: &str) -> bool {
    let inside = |outer: &str, inner: &str| {
        inner == outer
            || inner
                .strip_prefix(outer)
                .is_some_and(|r| r.starts_with('/'))
    };
    inside(a, b) || inside(b, a)
}

/// The JSON pointers a key path names in a value: itself, or with each segment that holds a
/// `*` one per key of the object there that begins and ends as it does, escaped as RFC 6901
/// says.
fn expand(v: &Value, rest: &str, done: String, out: &mut Vec<String>) {
    let Some(rest) = rest.strip_prefix('/') else {
        if !out.contains(&done) {
            out.push(done);
        }
        return;
    };
    let (segment, tail) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if let Some((before, after)) = segment.split_once('*') {
        if let Value::Object(map) = v {
            for (key, inner) in map {
                if key.len() >= before.len() + after.len()
                    && key.starts_with(before)
                    && key.ends_with(after)
                {
                    let escaped = key.replace('~', "~0").replace('/', "~1");
                    expand(inner, tail, format!("{done}/{escaped}"), out);
                }
            }
        }
    } else if let Some(inner) = v.pointer(&format!("/{segment}")) {
        expand(inner, tail, format!("{done}/{segment}"), out);
    }
}

/// A regular file's bytes, opened without waiting, up to the cap; else why not.
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

/// Whether a file holds, anywhere in its tree, a property named `key` whose value is `holds` in
/// any case; an error when it cannot be read in its format. A byte order mark is skipped, as
/// VS Code skips it.
///
/// For the task file: the editor runs a task whose `runOptions.runOn` is `folderOpen`, at the
/// task or under a platform's own settings. Of two equal keys the editor keeps the last; where
/// an earlier equal `runOn` said something else, the file is taken as holding such a task, so
/// that it errs only toward watching.
pub fn whole_when(bytes: &[u8], format: Format, key: &str, holds: &str) -> Result<bool, String> {
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let r = crate::jsonc::read(text, format == CommentsAndCommas)?;
    let doubt = r.doubts.iter().any(|d| d.rsplit('/').next() == Some(key));
    Ok(doubt || r.value.as_ref().is_some_and(|v| anywhere(v, key, holds)))
}

fn anywhere(v: &Value, key: &str, holds: &str) -> bool {
    match v {
        Value::Object(map) => map.iter().any(|(k, inner)| {
            (k == key
                && inner
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case(holds)))
                || anywhere(inner, key, holds)
        }),
        Value::Array(items) => items.iter().any(|i| anywhere(i, key, holds)),
        _ => false,
    }
}

/// Whether a task file holds a task set to run when the folder is opened.
#[cfg(test)]
pub fn runs_on_open(bytes: &[u8]) -> Result<bool, String> {
    whole_when(bytes, CommentsAndCommas, "runOn", "folderOpen")
}

/// The rows of a scope a place holds a file of, read or not: a checkout's, or the home
/// folder's. One that cannot be looked at is counted too: it may be there. A row named by
/// another file is not looked for, nor a place in the home folder macOS asks permission for.
pub fn present(base: &Path, scope: Scope) -> Vec<&'static Point> {
    POINTS
        .iter()
        .filter(|p| p.scope == scope && holds(base, p))
        .collect()
}

/// Whether a place holds a file of a row.
fn holds(base: &Path, p: &Point) -> bool {
    p.paths.iter().any(|path| {
        if p.scope == Scope::Home && crate::guarded::folder_of(&base.join(path), base).is_some() {
            return false;
        }
        let segments: Vec<&str> = path.split('/').collect();
        exists(base, &segments)
    })
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
        // The editor keeps the last, a reader that keeps the first would run it: watched.
        let first = br#"{"tasks": [{"runOptions": {"runOn": "folderOpen", "runOn": "default"}}]}"#;
        assert_eq!(runs_on_open(first), Ok(true));
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
        assert_eq!(select(one, Strict, keys), expected);
        assert_eq!(select(two, Strict, keys), expected);
        // Absent, null, a parent that is not an object, a top that is not one, an empty file
        // and one that is not JSON at all.
        assert_eq!(
            select(br#"{"scripts": {"prepare": null}}"#, Strict, keys),
            Selected::Values(vec![])
        );
        assert_eq!(
            select(br#"{"scripts": "prepare"}"#, Strict, keys),
            Selected::Values(vec![])
        );
        assert_eq!(select(b"[1, 2]", Strict, keys), Selected::Values(vec![]));
        assert_eq!(
            select(br#"{"scripts": {"install": 3}}"#, Strict, keys),
            Selected::Values(vec![("/scripts/install".to_string(), hash("3"))])
        );
        for not_json in [&b""[..], b"{\"scripts\": {,}}", b"\x00\xff"] {
            assert!(
                matches!(select(not_json, Strict, keys), Selected::Whole(w) if w.starts_with("not strict JSON")),
            );
        }
    }

    #[test]
    fn every_key_of_an_object_is_its_own_part_and_a_key_is_escaped_as_a_json_pointer() {
        let file = br#"{"mcpServers": {"a/b": {"command": "x"}, "c~d": {"command": "y"}}}"#;
        assert_eq!(
            select(file, Strict, &["/mcpServers/*"]),
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
            assert_eq!(
                select(file, Strict, keys),
                Selected::Whole(EQUAL_KEYS.to_string())
            );
        }
        // Equal keys elsewhere, or with the same value, change nothing.
        let elsewhere =
            br#"{"name": "a", "name": "b", "scripts": {"prepare": "p", "prepare": "p"}}"#;
        assert_eq!(
            select(elsewhere, Strict, keys),
            Selected::Values(vec![("/scripts/prepare".to_string(), hash("\"p\""))])
        );
        assert_eq!(
            select(b"\xEF\xBB\xBF{\"scripts\": {}}", Strict, keys),
            Selected::Whole(BOM.to_string())
        );
    }

    #[test]
    fn equal_keys_in_a_file_with_comments_are_never_read_as_unchanged() {
        // The false calm: a benign server where one reader looks and a planted one where
        // another does. Whether the equal keys hold what is read, a part of it, or the object
        // around it, the file is read whole.
        let keys = &["/servers/*"];
        for file in [
            &b"{\"servers\": {\"a\": {\"command\": \"x\", \"command\": \"npx\"}}}"[..],
            b"{\"servers\": {\"a\": {\"command\": \"x\"}, \"a\": {\"command\": \"npx\"}}}",
            b"{\"servers\": {\"b\": {}}, // first\n \"servers\": {\"a\": {\"command\": \"npx\"},},}",
        ] {
            assert_eq!(
                select(file, CommentsAndCommas, keys),
                Selected::Whole(EQUAL_KEYS.to_string()),
                "{}",
                String::from_utf8_lossy(file)
            );
        }
        // A key matched by a pattern is a selected key too.
        let settings =
            b"{\"php.validate.executablePath\": \"./x\", \"php.validate.executablePath\": \"\"}";
        assert_eq!(
            select(settings, CommentsAndCommas, VSCODE_SETTINGS),
            Selected::Whole(EQUAL_KEYS.to_string())
        );
        // Equal keys elsewhere change nothing.
        let elsewhere = b"{\"theme\": 1, \"theme\": 2, \"servers\": {\"a\": {}}}";
        assert_eq!(
            select(elsewhere, CommentsAndCommas, keys),
            Selected::Values(vec![("/servers/a".to_string(), hash("{}"))])
        );
    }

    #[test]
    fn a_file_with_comments_is_read_by_key_in_its_tools_format_and_an_edit_elsewhere_is_no_change()
    {
        // Gemini CLI strips comments and parses strictly; Cursor reads as VS Code does.
        let one = b"{\n  // mine\n  \"theme\": \"dark\",\n  \"mcpServers\": {\"a\": {\"command\": \"npx\"}}\n}";
        let two = b"{\"mcpServers\": {\"a\": {\"command\": \"npx\"}}, /* light now */ \"theme\": \"light\"}";
        let expected = Selected::Values(vec![(
            "/mcpServers/a".to_string(),
            hash(r#"{"command":"npx"}"#),
        )]);
        for format in [Comments, CommentsAndCommas] {
            assert_eq!(select(one, format, GEMINI), expected);
            assert_eq!(select(two, format, GEMINI), expected);
        }
        // A trailing comma Gemini CLI would refuse: not read by key, and why.
        let comma = b"{\"mcpServers\": {\"a\": {\"command\": \"npx\"}},}";
        assert!(matches!(
            select(comma, Comments, GEMINI),
            Selected::Whole(w) if w.starts_with("not JSON with comments as its tool reads it: ")
        ));
        assert_eq!(select(comma, CommentsAndCommas, GEMINI), expected);
        assert_eq!(
            select(b"\xEF\xBB\xBF{}", CommentsAndCommas, GEMINI),
            Selected::Whole(BOM.to_string())
        );
        assert_eq!(
            select(b"// nothing yet", Comments, GEMINI),
            Selected::Values(vec![])
        );
    }

    #[test]
    fn settings_that_name_an_executable_are_read_and_other_settings_are_not() {
        // The bound, as data: a key ending in `Path` or `.path`, at the top or in a
        // language's block, and the agent's approvals.
        let file = br#"{
            "editor.fontSize": 14,
            "php.validate.executablePath": "./bin/php",
            "git.path": "/usr/bin/git",
            "[python]": {"python.defaultInterpreterPath": "./py", "editor.tabSize": 4},
            "chat.tools.autoApprove": true,
            "files.exclude": {"x": true},
        }"#;
        let Selected::Values(values) = select(file, CommentsAndCommas, VSCODE_SETTINGS) else {
            panic!("not read by key")
        };
        let pointers: Vec<&str> = values.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            pointers,
            [
                "/chat.tools.autoApprove",
                "/php.validate.executablePath",
                "/git.path",
                "/[python]/python.defaultInterpreterPath",
            ]
        );
    }

    #[test]
    fn an_extension_is_identified_apart_from_its_version_as_vs_code_names_its_folder() {
        // Folder names as VS Code writes them: `publisher.name-version`, with the target
        // platform after it for an extension built for one; names and publishers may hold
        // a `-` and digits, never a dot.
        for (folder, id) in [
            ("ms-python.python-2024.2.1-darwin-arm64", "ms-python.python"),
            (
                "rust-lang.rust-analyzer-0.3.1850-darwin-arm64",
                "rust-lang.rust-analyzer",
            ),
            ("esbenp.prettier-vscode-10.1.0", "esbenp.prettier-vscode"),
            (
                "ms-vscode-remote.remote-containers-0.348.0",
                "ms-vscode-remote.remote-containers",
            ),
            ("github.copilot-chat-0.12.2023120701", "github.copilot-chat"),
            ("vue.volar-2.0.6", "vue.volar"),
            ("someone.vue-3-snippets-1.0.4", "someone.vue-3-snippets"),
            ("someone.tool-1.0.0-beta-darwin-x64", "someone.tool"),
            // Not as the editor names an installed extension: itself, whole.
            ("someone.tool-1.0", "someone.tool-1.0"),
            ("someone.tool-1.0.0-", "someone.tool-1.0.0-"),
            ("someone.tool", "someone.tool"),
        ] {
            let Folders(ident) = EXTENSION else { panic!() };
            assert_eq!(ident.of(folder), id, "{folder}");
        }
    }

    #[test]
    fn a_kind_shows_within_seconds_only_while_one_of_its_rows_is_watched_live() {
        // What the page says of how fast a change shows: a kind whose every row is read only
        // at the hourly check is hourly; one live row makes it live.
        let of = |hourly| Point {
            hourly,
            ..row(
                &["a.json"],
                Select(Strict, MCP_SERVERS),
                StartAgent,
                "a tool",
                Never,
                (EVENT, "high", "medium"),
                "",
            )
        };
        let w = AGENT_START.0;
        assert!(!live_in(&[of(Some(REWRITTEN))], w));
        assert!(live_in(&[of(Some(REWRITTEN)), of(None)], w));
        assert!(!live_in(&[of(None)], AGENT_SETTINGS.0));
    }

    #[test]
    fn nothing_in_a_folder_macos_asks_permission_for_is_opened() {
        // Opening a file there raises a permission dialog. A row of the home folder that
        // named such a place is neither read nor looked for.
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::temp_dir().join(format!("soc-autorun-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("Documents/tool")).unwrap();
        std::fs::write(home.join("Documents/tool/settings.json"), "{}").unwrap();
        // Shut, as macOS keeps it: had it been opened, the look would say it failed.
        let mode = |m| std::fs::Permissions::from_mode(m);
        std::fs::set_permissions(home.join("Documents"), mode(0o000)).unwrap();
        let p = Point {
            scope: Scope::Home,
            ..row(
                &["Documents/tool/settings.json", "Documents/*.json"],
                Select(Strict, MCP_SERVERS),
                StartAgent,
                "a tool",
                Never,
                (EVENT, "high", "medium"),
                "",
            )
        };
        let looked = look_all(&p, [(home.as_path(), "")].into_iter());
        let held = holds(&home, &p);
        std::fs::set_permissions(home.join("Documents"), mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&home);
        let l = &looked.look;
        assert_eq!(
            (l.present, l.failed.len(), l.entries.len(), held),
            (0, 0, 0, false)
        );
    }

    #[test]
    fn no_place_of_the_home_folder_in_the_table_is_where_macos_asks_permission() {
        // Nor where a `*` could reach one: the folder before it holds none.
        let home = Path::new("/Users/someone");
        for p in POINTS.iter().filter(|p| p.scope == Scope::Home) {
            for path in p.paths {
                assert!(
                    crate::guarded::folder_of(&home.join(path), home).is_none(),
                    "{path}"
                );
                if let Some((fixed, _)) = path.split_once('*') {
                    let fixed = fixed.rsplit_once('/').map_or("", |(f, _)| f);
                    assert!(
                        crate::guarded::IN_HOME
                            .iter()
                            .all(|g| !Path::new(g).starts_with(fixed)),
                        "{path}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_key_of_every_row_read_by_key_is_an_entry_of_its_triggers_kind() {
        // A row is data: what it lists is what is read, with nothing else to write.
        let dir = std::env::temp_dir().join(format!("soc-autorun-keys-{}", std::process::id()));
        for p in POINTS.iter() {
            let Select(_, keys) = p.part else { continue };
            let _ = std::fs::remove_dir_all(&dir);
            let mut file = Value::Object(Default::default());
            for key in keys {
                let mut at = &mut file;
                for segment in key.trim_start_matches('/').split('/') {
                    let segment = segment.replace('*', "x");
                    at = at
                        .as_object_mut()
                        .unwrap()
                        .entry(segment.clone())
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
        let names: Vec<String> = present(&dir, Scope::Checkout)
            .iter()
            .map(|p| p.name())
            .collect();
        std::fs::remove_file(dir.join("w.code-workspace")).unwrap();
        std::fs::rename(
            dir.join(".venv/lib/python3.12/site-packages/a.pth"),
            dir.join(".venv/lib/python3.12/site-packages/a.txt"),
        )
        .unwrap();
        let after = present(&dir, Scope::Checkout).len();
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
