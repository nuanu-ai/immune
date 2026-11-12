# Reference

What Immune reads on a Mac, where it looks, what it records and when; the vocabulary of facts; the commands; and the files it keeps. [how-it-works.md](how-it-works.md) explains the terms used here.

## When readers run

| Name | Trigger |
|---|---|
| full check | `immune run`; the app starts one every hour while it is open, with a 30-minute limit |
| live | `immune watch`, about a second after FSEvents reports a change in a place it subscribes to |
| sample | `immune watch` every 30 seconds, or `immune sample` |
| events | `immune watch` every 10 seconds, and at every full check |

No reader enters a folder macOS asks permission for, whether a path names it or a symbolic link leads into it: Desktop, Documents, Downloads, iCloud Drive, `~/Library/CloudStorage`, `~/Library/Containers`, `~/Library/Group Containers`, and anything under `/Volumes`. So Immune never makes macOS show a permission dialog. A reader that skipped one writes a reading of the kind `folders macOS asks permission for` naming them, and checkouts already known there are kept with nothing inside them read. `--checkouts-root` can point a full check into such a folder on purpose.

## Readers

The name is what coverage and assertions carry in `reader`.

### On this Mac

| Reader | Where it looks | What it records | Basis | When |
|---|---|---|---|---|
| `checkouts` | The home folder, or the folder given with `--checkouts-root`, up to 5 levels deep. A folder holding `.git` is a checkout and is not searched further. `node_modules`, `target` and `vendor` are never entered, nor `Library`, `Applications`, `Movies`, `Music`, `Pictures` and `Public` directly under the home folder. Only folders are listed; no file is opened | `checkout` entities, `located_on` the machine | observed | full check |
| `agent-folders` | Claude Code's session files, `~/.claude/projects/<folder>/*.jsonl`. Only the `cwd` field of a line is read; the nearest folder above it holding `.git` is the checkout. git is never run | the same as `checkouts`, for checkouts the walk does not reach: temporary folders, hidden worktrees, other volumes | observed | full check |
| `lockfiles` | In every checkout, up to 4 levels deep, skipping `node_modules`, `target`, `vendor` and `.git`: `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`. `yarn.lock`, `uv.lock`, `poetry.lock`, `composer.lock`, `go.sum`, `requirements.txt`, `Package.resolved` and `bun.lock` are named as having no reader | `component` entities `part_of` the checkout, `has_version`. The raw copy is a manifest of paths, sizes and the checkout's commit | declared | full check |
| `brew` | `brew info --json=v2 --installed`, run with `HOMEBREW_NO_AUTO_UPDATE` and `HOMEBREW_NO_ANALYTICS`. Homebrew is looked for where its installer puts it, then on PATH, or at `--brew` | formulae (`brew`) and casks (`brew-cask`) with every installed version. A package Homebrew names no tap for is left out and the reading is partial | observed | full check |
| `integrity` | Application bundles in `/Applications` and `~/Applications` and one folder down; Homebrew kegs and global npm packages under `/opt/homebrew` and `/usr/local`; folders under `~/Library/Application Support` named like an application read here that Apple did not sign | `has_version`, `installed_at`, `signed_by`, `has_seal` (the Security framework's verdict, verified again only when the digest changed), `has_digest` (SHA-256 over every file's path and change time, never content). A folder deeper than 16 levels or with more than 20,000 code files is not recorded, and the reading says so | observed | full check |
| `watched-places` | The places where persistence lives, below, and the rows of what runs by itself that are read | `watched_as` the kind of place, `located_on` the machine or the checkout, `has_content` (a SHA-256, never the content), `links_to` for a symbolic link. Anything that is not a regular file is recorded as what it is, without being opened. A file over 8 MiB is a reading with no reader for it, with that reason | observed | live and full check |
| `indicators` | `indicators.json` next to the store, or `--indicators <file>`; see [threats.md](threats.md#indicators) | `matches_indicator` about a watched file, a lockfile or an editor's task file | observed | full check |
| `events` | The collector's log in `/Library/Application Support/ai.nuanu.immune/event-level/log`; see [event-level.md](event-level.md) | no facts: counts, the level's state, rule matches, and a finding's evidence | | events |
| `processes` | This user's processes and their open internet sockets, through libproc and sysctl, without administrator rights. Other users' processes are counted, not read. No host name is resolved | no facts: `tracked_process` (an interpreter given code on its command line whose parent is launchd or gone, by pid and start time), `matched_connection` (a connection to an address on the indicator list), `last_sample`. Rows gone for a day are deleted. There is no raw copy | | sample |

A command line is read by `processes` only for seven kinds of interpreter (node and bun, deno, python, ruby, perl, the shells, osascript), only to decide whether it was given code on its command line, and it is dropped there. It is never stored, printed or returned.

### About servers

Immune never connects to a server and never runs ssh. These readers find which servers the Mac knows, and read what a sweep the user runs left behind.

| Reader | Where it looks | What it records | Basis | When |
|---|---|---|---|---|
| `ssh-config` | `~/.ssh/config` and the files it pulls in with `Include`, expanded with the system's glob(3), at most 16 deep. Only `Host`, `Match`, `HostName` and `User` are taken; no key file is opened. An alias for code hosting is left out. A `Match` block is not evaluated, so a value it could set first is not recorded and the reading is partial | a `machine` for each literal `Host` alias ssh applies, `known_as` its names | declared | full check |
| `known-hosts` | `~/.ssh/known_hosts`. Only host names are taken, never keys. `[host]:port` keeps its port in its name. Hashed entries, patterns and `@cert-authority` lines make the reading partial with a count | a `machine` per host, `known_as` | observed | full check |
| `tailnet` | `tailscale status --json`, from the app in `/Applications` or `~/Applications`, the Homebrew prefixes, then PATH, or `--tailscale` | each peer's names and addresses (`known_as`), its system as the tailnet names it (`runs_platform`), and `relation_to_owner` for an untagged peer of another user. Tailscale installed but stopped is a failed reading | observed | full check |
| `servers` | The files in `sweep/` next to the store, one `<alias>.txt` per server, written by the probe `scripts/probe.sh` when the user runs `sweep/sweep.sh`. A file is complete only if it reaches `##end` | `runs_os`, `runs_release`, `release_codename`, `runs_kernel`, `runs_kernel_package`, dpkg packages as components with `has_version` and `built_from`, containers with `runs_image`, the server's own names and addresses. Only dpkg is read; rpm, apk and pacman are named | observed | full check |
| `resolver` | the other readers' `known_as` assertions | `same_as` between two machines known by the same full name or public address. Bare names and private addresses link nothing | | full check |

`immune servers` lists the servers this Mac knows and writes `sweep/sweep.sh`. Only servers with a current, explicit way in, a literal alias in the SSH configuration, are offered. An alias listed in `sweep/skip.txt`, or a machine the user said is retired or not theirs, is not visited. A server that wants a password stays known and not read: Immune never stores or types a password.

### Threat data

Read at every full check, not as readers of the Mac: CISA's catalogue and OSV's archives for crates.io and npm. Each attempt is a row in `feed_reading`. See [threats.md](threats.md).

## Watched places

28 rows in `src/watched.rs`. Adding a place is adding a row.

| Kind | Places |
|---|---|
| `autostart item` | every entry in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` |
| `shell profile` | `/etc/zshenv`, `zprofile`, `zshrc`, `zlogin`, `zlogout`, `profile`, `bashrc`; in the home folder `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout`, `.bash_profile`, `.bash_login`, `.profile`, `.bashrc`, `.bash_logout` |
| `ssh access file` | `~/.ssh/config`, `authorized_keys`, `rc`; `/etc/ssh/ssh_config`, `sshd_config` and their `.d` folders |
| `git hook` | every entry in each checkout's `.git/hooks`, except git's `.sample` files |

Never a private key, never known hosts. A checkout whose `.git` is a file, as in a worktree or a submodule, keeps its hooks elsewhere; its hooks reading is partial and says so.

Not read: `core.hooksPath`, `ZDOTDIR`, fish, files pulled in by `Include` in the SSH configuration, cron, the git configuration, launchd jobs with no file on disk.

## What runs by itself

One table of data, `POINTS` in `src/autorun.rs`: one row per known way a file makes a tool run code on a routine action, with where the file is, which part counts, the trigger, the tool, whether the tool asks first, the ATT&CK technique, both levels, and the source the row rests on. There are 41 ways in a project and 11 places in the home folder. Each one present is recorded as `holds_autorun_point` on its checkout, or on the machine for the home folder, whether it is read or not. The ones present and not read are named in the readings `other ways a checkout runs code by itself` and `other places in the home folder where a tool's settings run code by itself`, and the status says how many of the known ways this version reads.

Read in a project (13 of 41):

| File | The part that counts | Rule |
|---|---|---|
| `.vscode/tasks.json` | the whole file, while a `runOn` in it holds `folderOpen` | `autorun.folder-open` |
| `.vscode/settings.json`, `*.code-workspace`, `.devcontainer/devcontainer.json`, `.devcontainer.json` | settings that name an executable or approve tools; a dev container's commands | `autorun.editor-open` |
| `package.json` | the scripts run on install | `autorun.package-install` |
| `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `.cursor/hooks.json`, `.gemini/settings.json` | hooks, MCP servers, tools allowed without asking | `autorun.agent-start` |
| `.git/hooks` | each entry, read as a watched place | `watched.git-hook` |

Read in the home folder (7 of 11): Claude Code's `~/.claude/settings.json` and `~/.claude.json`, Claude Desktop's `claude_desktop_config.json`, Cursor's `~/.cursor/mcp.json` and `~/.cursor/hooks.json`, Gemini CLI's `~/.gemini/settings.json` (all `autorun.agent-settings`), and VS Code's extensions in `~/.vscode/extensions`, each by publisher and name (`autorun.editor-extension`). Named and not read: Claude Code's skills, commands and agents, Continue, Codex, JetBrains plugins.

How a part is taken. In a JSON file, per selected key, the SHA-256 of the canonical value there, kept as `has_content` of `<file>#<JSON pointer>`. Strict JSON is parsed with `serde_json`, JSON with comments with the `jsonc-parser` crate, which keeps every equal key. A file with a byte-order mark, one where equal keys could be read differently at a selected key, or one not in its row's format is hashed whole, and the reading says why. A project file over 1 MiB, a home file over 32 MiB, a file that cannot be read, and a task file that cannot be parsed are failed readings with the reason. The text of a script or command is never kept.

Every row read is watched live, except `~/.claude.json`, which its tool rewrites constantly, and `*.code-workspace`, which has no fixed name; those two are read at each full check. A row's first reading on a Mac is the baseline, and so is a row read for the first time after an upgrade.

## Vocabulary

Types and predicates are rows in the store, not code. A reader cannot create a new kind of fact; a new kind is a new row and a new reader.

| Predicate | Subject → object |
|---|---|
| `located_on` | checkout or container → machine; a watched file → machine, or → its checkout for a git hook; a keg or an application's folder under Application Support → machine |
| `part_of` | component → machine, container or checkout |
| `has_version` | component → version string, exactly as the source gives it. An application's is `CFBundleShortVersionString`, with `CFBundleVersion` in brackets when it differs |
| `installed_at` | application or global npm package → its path |
| `signed_by` | application → `apple`, `app store`, `developer id` or `other certificate`, each with `, team <id>` where the signature names one; `ad hoc, cdhash <hex>`; or `unsigned` |
| `has_seal` | application → `verifies`, or `does not verify: <why>` |
| `has_digest` | application, keg, global npm package, or an application's folder under Application Support → `stat:<64 hex>` |
| `watched_as` | file → the kind of watched place, or the trigger of a way code runs by itself |
| `has_content` | file → `sha256:<64 hex>`, `value sha256:<64 hex>` for a part of a file, `not a regular file: <what>`, or `dangling link` |
| `links_to` | file → the target of a symbolic link |
| `holds_autorun_point` | checkout, or the machine for the home folder → a known way code runs by itself whose file it holds |
| `matches_indicator` | file → the indicator it matches, as a STIX comparison |
| `runs_os` | machine or container → the system's pretty name |
| `runs_release` | machine → `<ID> <VERSION_ID>` from os-release, for example `ubuntu 24.04` |
| `release_codename` | machine → `VERSION_CODENAME`, where the system gives one and a release |
| `runs_kernel` | machine → the running kernel, as `uname -r` gives it |
| `runs_kernel_package` | machine → the package that owns the running kernel's image or modules |
| `built_from` | `deb` component → `<source package> <source version>` |
| `runs_image` | container → its image with the tag |
| `runs_platform` | machine → its system as the tailnet names it |
| `known_as` | machine → a name or address a trace knows it by |
| `same_as` | machine → machine, written only by the resolver |
| `relation_to_owner` | machine → `other user's device`, for an untagged tailnet peer of another user |

Reserved: `copy_of`, `reachable_from`.

## Commands

Every command that takes `--json` prints one envelope with `format`, `operation`, `ok`, `errors` and `result`; an error has a `code`, a `message` and an `example`. Exit codes: 0 answered, 2 a misuse or an unknown id, 3 an unreadable store, 4 a check holding the store (ask again), 5 from `immune watch` when another watcher has the store. `--store <path>` points any command at another store.

| Command | Does |
|---|---|
| `immune run [--json]` | A full check. Flags for tests and special cases: `--machine-name`, `--brew`, `--brew-input`, `--servers-input`, `--checkouts-root`, `--sessions-root`, `--tailscale`, `--threats-input`, `--osv-crates-input`, `--osv-npm-input`, `--curl`, `--system-root`, `--indicators` |
| `immune status [--json]` | What the last finished check left, read-only |
| `immune findings [--all] [--json]` | Open findings, or every one with `--all` |
| `immune finding <id> [--json]` | One finding with what it rests on |
| `immune finding <id> expected --reason <text> [--days <n>] [--via app\|agent]` | Hide it for 30 days or `--days` |
| `immune finding <id> seen [--reason <text>] [--via app\|agent]` | Close it |
| `immune finding <id> reopen [--via app\|agent]` | Take an answer back |
| `immune vulnerabilities [--json]` | Known vulnerabilities that affect packages the lockfiles declare |
| `immune vulnerability <record id or CVE id> [--json]` | The answer for one vulnerability in every project |
| `immune rules [--json]` | The shipped Sigma rules: evaluated in full, in part or not, whether they watch, how often each matched |
| `immune rules --over-log [--system-root <dir>] [--json]` | Evaluates the rules over the log on disk now, without the store |
| `immune servers` | Lists the servers this Mac knows and writes the sweep script |
| `immune owner [<name> retired\|not-mine --reason <text> \| <name> withdraw] [--via app\|agent] [--json]` | A statement that a machine is retired or not the user's, or the list of those that stand |
| `immune view [--no-open] [--if-stale]` | Writes the HTML pages and opens the summary; with `--if-stale`, only when something they show changed or they are an hour old |
| `immune sample [--json]` | One sample of processes and connections |
| `immune watch [--sample-every <s>] [--events-every <s>] [--alive-every <s>]` | Runs until stopped, printing one JSON line per event: `watching`, `read`, `sample`, `program_starts`, `alive`, `problem` |

In JSON output, `title`, `meaning` and `advice` are Immune's fixed words. Anything taken from the machine or a feed is only in a field whose name ends in `_text`.

## Files Immune keeps

Everything lives in `~/Library/Application Support/ai.nuanu.immune/` unless `--store` points elsewhere:

| Path | Holds |
|---|---|
| `store.db` | the store |
| `raw/<run>/` | raw input, copied only when it changed |
| `feeds/` | the latest OSV archive read whole per feed, with its record list |
| `indicators.json` | the indicator list, when the user gives one |
| `sweep/` | `sweep.sh`, `probe.sh`, `skip.txt` and the files the sweep leaves |
| `view.html`, `view/` | the HTML pages |

The collector keeps its own files under `/Library/Application Support/ai.nuanu.immune/event-level`. The app keeps its notification settings under the defaults domain `ai.nuanu.immune`.
