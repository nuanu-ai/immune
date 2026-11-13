# Reference

What Immune reads on a Mac, where it looks, what it records and when; the vocabulary of facts; the commands and the contract; and the files it keeps. [how-it-works.md](how-it-works.md) explains the terms used here.

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
| `agent-folders` | Claude Code's session files, `~/.claude/projects/<folder>/*.jsonl`. Only the `cwd` field of a line is read; the nearest folder above it holding `.git` is the checkout. git is never run. A file that only grew is read on from where the last reading stopped, see below | the same as `checkouts`, for checkouts the walk does not reach: temporary folders, hidden worktrees, other volumes | observed | full check |
| `lockfiles` | In every checkout, up to 4 levels deep, skipping `node_modules`, `target`, `vendor` and `.git`: `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`. `yarn.lock`, `uv.lock`, `poetry.lock`, `composer.lock`, `go.sum`, `requirements.txt`, `Package.resolved` and `bun.lock` are named as having no reader | `component` entities `part_of` the checkout, `has_version`. The raw copy is a manifest of paths, sizes and the checkout's commit | declared | full check |
| `brew` | `brew info --json=v2 --installed`, run with `HOMEBREW_NO_AUTO_UPDATE` and `HOMEBREW_NO_ANALYTICS`. Homebrew is looked for where its installer puts it, then on PATH, or at `--brew` | formulae (`brew`) and casks (`brew-cask`) with every installed version. A package Homebrew names no tap for is left out and the reading is partial | observed | full check |
| `integrity` | Application bundles in `/Applications` and `~/Applications` and one folder down; Homebrew kegs and global npm packages under `/opt/homebrew` and `/usr/local`; folders under `~/Library/Application Support` named like an application read here that Apple did not sign | `has_version`, `installed_at`, `signed_by`, `has_seal` (the Security framework's verdict, verified again only when the digest changed), `has_digest` (SHA-256 over every file's path and change time, never content). A folder deeper than 16 levels or with more than 20,000 code files is not recorded, and the reading says so | observed | full check |
| `watched-places` | The places where persistence lives, below, and the rows of what runs by itself that are read | `watched_as` the kind of place, `located_on` the machine or the checkout, `has_content` (a SHA-256, never the content), `links_to` for a symbolic link. Anything that is not a regular file is recorded as what it is, without being opened. A file over 8 MiB is a reading with no reader for it, with that reason | observed | live and full check |
| `indicators` | `indicators.json` next to the store, or `--indicators <file>`; see [threats.md](threats.md#indicators) | `matches_indicator` about a watched file, a lockfile or an editor's task file | observed | full check |
| `events` | The collector's log in `/Library/Application Support/ai.nuanu.immune/event-level/log`; see [event-level.md](event-level.md) | no facts: counts, the level's state, rule matches, and a finding's evidence | | events |
| `processes` | This user's processes and their open internet sockets, through libproc and sysctl, without administrator rights. Other users' processes are counted, not read. No host name is resolved | no facts: `tracked_process` (an interpreter given code on its command line whose parent is launchd or gone, by pid and start time), `matched_connection` (a connection to an address on the indicator list), `last_sample`. Rows gone for a day are deleted. There is no raw copy | | sample |

For each session file, `agent-folders` keeps in the store's `session_file` table the end of the last whole line it read (the position), the SHA-256 of the bytes before it, the working folders those bytes name, and the file's inode and change time. No other text of a session is kept, and the working folders are never printed. The store keeps at most 64 folders per file, each at most 1024 bytes, and 4 MiB over all files; a file past these bounds is read from its first byte every time. The next reading goes on from the position only when the file has the same inode and either its change time has not moved since a reading taken at least a second after it last changed, or the bytes before the position hash to the digest kept. The first of these, which reads nothing before the position, is used only on APFS and HFS+ volumes, by the type name `statfs` gives. There the kernel moves the change time on a write, a change of size and a change of the modification time, and no program can set it. On any other volume, such as FAT, exFAT, SMB, NFS or FUSE, the bytes before the position are hashed on every reading. Even on APFS and HFS+, changed bytes are not seen until the change time moves in two cases: a write through a shared mapping of the file, until the mapping is synced or unmapped, and a change to the volume while it was not mounted. A program that can do either can also rewrite the session file outright, and a reading from the first byte would see no more. Any other file is read from its first byte, and so is every file the first time a store made by an earlier build is used. A last line without its line break is read, and read again the next time. Deleting the rows of `session_file` makes the next reading start from the first byte of every file.

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

Every row read is watched live, except `~/.claude.json`, which its tool rewrites constantly, and `*.code-workspace`, which has no fixed name; those two are read at each full check. A row's first reading on a Mac is the baseline, and so is a row read for the first time after an upgrade. After that, a part that appears in a checkout is a finding, in a checkout the store held and in one that is new. The exception is a new linked worktree of a repository the store already holds a checkout of. There, a part equal to the one at the same path in that checkout raises nothing; it is recorded, and the journal says which checkout it matched. See [how-it-works.md](how-it-works.md#lifecycle).

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

Every report command that takes `--json` prints one envelope with `format`, `operation`, `ok`, `errors` and `result`; an error has a `code`, a `message` and an `example`. A command of the contract prints its own message instead and uses the envelope only for a failure (see [the contract](#the-contract)). Exit codes: 0 answered, 1 from `immune matches` and `immune rules --over-log` when the event log cannot be read, 2 a misuse or an unknown id, 3 an unreadable store, 4 a check holding the store (ask again), 5 from `immune watch` when another watcher has the store. `--store <path>` points any command at another store.

| Command | Does |
|---|---|
| `immune run [--json]` | A full check. Flags for tests and special cases: `--machine-name`, `--brew`, `--brew-input`, `--servers-input`, `--checkouts-root`, `--sessions-root`, `--tailscale`, `--threats-input`, `--osv-crates-input`, `--osv-npm-input`, `--curl`, `--system-root`, `--indicators` |
| `immune status [--json]` | What the last finished check left, read-only |
| `immune findings [--all] [--json \| --proto]` | Every finding, in every state, as the contract's `Findings` message; for a person, the open findings, or every one with `--all` |
| `immune finding <id> [--json \| --proto]` | One finding whole, as the contract's `Finding` message: its words, where it is, its evidence, the journal entries it rests on and the person's answer; for a person, the same as text |
| `immune finding <id> expected --reason <text> [--days <n>] [--via app\|agent]` | Hide it for 30 days or `--days` |
| `immune finding <id> seen [--reason <text>] [--via app\|agent]` | Close it |
| `immune finding <id> reopen [--via app\|agent]` | Take an answer back |
| `immune vulnerabilities [--json]` | Known vulnerabilities that affect packages the lockfiles declare |
| `immune vulnerability <record id or CVE id> [--json]` | The answer for one vulnerability in every project |
| `immune rules [--json]` | The published rules of the three sets, SigmaHQ's and Elastic's detection rules and behaviour rules translated into Sigma: evaluated in full, in part or not, whether they watch, how often each matched. `sources` says where each set comes from, its name in words (`set`), whether its rules state levels (`states_levels`), its commit, licence, folder, the fields its rules are given and its totals: `shipped` counts the rule files shipped, and `not_taken` the upstream rules a translation did not take, which are also counted under `not_evaluated`. Each rule has its set, `source` by name and `set` in words, its `name`, its set and its id as every command gives it, its `level`, null for a rule whose set states none, and for one in part `never_matches`, each alternative with its `selection_text` (null for one the translation left out), `fields_text` and `left_out_text`. Every Elastic rule the translation did not take is under `not_evaluated` with its `reason` and `detail_text`. Within each group rules are ordered from the most severe level down; the rules of a set that states no level follow as a group of their own, since the order of levels does not include them. The text form gives them their own heading, "Of a set that states no level", with their count, and names each rule by its title and its set. With `--json`, also `catalogue`: every rule of the core's own with its words, the words of a published rule's finding with the sets that raise findings (`raised_by_sets`) and by which levels, the sets whose rules state no level and so raise nothing by themselves (`sets_that_raise_nothing`), and every cause of what is not covered |
| `immune rules --over-log [--system-root <dir>] [--json]` | Evaluates the rules over the log on disk now, without the store. Each rule that matched has its `name`, `source`, `set`, level and count; the most severe first, then the rules of a set that states no level as a group of their own, under their own heading in the text form |
| `immune project <path or id> [--json \| --proto]` | What the store knows of one project, as the contract's `Known` message. The project is a path, absolute or starting with `~/`, which answers for the nearest project that holds it, or an id as the store names it: a project's (`checkout:machine:<name>/<path>`) or a file's (`file:machine:<name>/<path>`), which is the path it names. It reads the store, follows a symbolic link in the path only outside folders macOS asks permission for, and never looks inside the project's folder |
| `immune program <path, name or id> [--json \| --proto]` | The same for one program installed on this Mac: an application bundle, a Homebrew formula, cask or keg, a global npm package. It is a path (the bundle, the keg or the package's folder, or a file inside one), the name the store gives it (a bundle identifier, Homebrew's name, the package's name), or its id. No path is looked at on disk |
| `immune machine [<name or id>] [--json \| --proto]` | The same for this Mac, or for another machine the store knows: a name or address it is known by, as `immune owner` takes one, or its id (`machine:<name>`). A machine known under several ids that the resolver links with `same_as` is answered with what was read under every one of them, whichever name is asked |
| `immune matches [--after <place>] [--limit <n>] [--system-root <dir>] [--json \| --proto]` | Every rule match over the event log, of every level, each with the event it matched, as the contract's `Matches` message, read on from the place an earlier answer gave. It reads the log again and the store only, and writes nothing; without a store it fails |
| `immune servers` | Lists the servers this Mac knows and writes the sweep script |
| `immune owner [<name> retired\|not-mine --reason <text> \| <name> withdraw] [--via app\|agent] [--json]` | A statement that a machine is retired or not the user's, or the list of those that stand |
| `immune view [--no-open] [--if-stale]` | Writes the HTML pages and opens the summary; with `--if-stale`, only when something they show changed or they are an hour old |
| `immune sample [--json]` | One sample of processes and connections |
| `immune watch [--sample-every <s>] [--events-every <s>] [--alive-every <s>]` | Runs until stopped, printing one JSON line per event: `watching`, `read`, `sample`, `program_starts`, `alive`, `problem` |

In JSON output, `title`, `meaning` and `advice` are Immune's fixed words. Anything taken from the machine or a feed is only in a field whose name ends in `_text`.

## The contract

A program that runs Immune, such as the response layer, reads the commands of the contract. Their messages are defined by a protobuf schema in `contract/immune/v1/`, package `immune.v1`. The Rust types are generated from it into `contract/src/immune.v1.rs`, which is committed. A test generates the file again and fails when the two differ, so a build needs neither `protoc` nor a generator.

The types are the crate `immune-contract`, in `contract/`, a member of the same Cargo workspace as the core. The core prints its messages with this crate, and a program in Rust reads them with it. The crate holds the generated types and the code their JSON needs, and nothing of the core. It depends on `prost` and `serde` alone, and re-exports `prost`, so a reader decodes with the same version the types were derived with. It is not published. A program depends on it by a git path at a commit, and brings its own JSON parser:

```toml
[dependencies]
immune-contract = { git = "https://github.com/nuanu-ai/immune", rev = "<commit>" }
serde_json = "1"
```

```rust
use immune_contract::{prost::Message, v1};

let known = v1::Known::decode(out.stdout.as_slice())?;        // immune project <path> --proto
let known: v1::Known = serde_json::from_slice(&out.stdout)?;  // immune project <path> --json
```

The crate's version follows the contract. Its major version is the `format` the messages carry, 1 for package `immune.v1`. Within version 1 the schema is only added to, and each change that adds to it raises the minor version, so a reader built on an older 1.x reads what a newer core prints. A change that leaves the messages as they are, such as a comment in the schema, raises the patch version. Version 2 of the contract is a new package, `immune.v2`, with `format` 2, and major version 2 of the crate.

A command of the contract prints one message on stdout: binary protobuf by default, and the same message as one line of JSON with `--json`. Every command of the contract takes `--proto` too, so a program can always name the form it wants, and naming both is a misuse. `immune findings` and `immune finding <id>` are the exception to the default: without either flag they print the text for a person they printed before. The binary form is standard protobuf, and a program in another language reads that. The JSON is Immune's own and is not protobuf's JSON mapping. The generated types print it. Field names are the schema's, an enum is the name of its value without the enum's prefix and in lower case (`CAUSE_NOT_GIVEN` prints as `not_given`, the store's own word), a 64-bit number is a JSON number, and an absent optional field is null. Times are seconds since the epoch, UTC, in fields ending in `_at`.

A failure to answer is not a message, and a reader checks the exit code before it parses. In binary nothing is printed on stdout. With `--json` the failure envelope is printed without `format`, so a reader that parses it as the message all the same reads format 0 and stops. The exit codes are the ones above.

An enum value a reader does not know, and the value `unspecified`, are read as the unsafe case, which the schema names for each enum: for `Presence` not known, for `Completeness` not full, for `Cause` failed, for `FindingState` open, for a severity and for a rule's level the highest level and for a confidence the lowest, for `AnswerKind` no answer, for `Via` not known who gave it, and for `Change` changed. The generated types read a word they do not know as `unspecified`, so a value added within version 1 does not break an older reader.

Six commands use the contract so far. `immune project`, `immune program` and `immune machine` each print `Known`, about a project, a program or a machine. `immune matches` prints `Matches`. `immune findings` prints `Findings`, and `immune finding <id>` prints `Finding`. The types every message shares are in `common.proto`, and the event a rule matched is in `event.proto`.

Every message carries `store_id`, the id of the store it was read from. A finding's id is unique only within one store: a store deleted and made again can give the same id to another finding, so a reader that keeps a verdict keeps it by the store's id and the finding's id together. The id is 16 random bytes from `getentropy`, written as 32 hexadecimal characters. It is made once, when the store is made, and kept in the store's `meta` table, so it says nothing about the Mac. A store an older build made gets one the next time a command that writes opens it, such as `immune run` or `immune watch`. A command that only reads makes none: until then the field is absent, and nothing tells that store apart from another.

### `immune project`, `immune program` and `immune machine`

| Field | Holds |
|---|---|
| `question` | which question was asked, `project`, `program` or `machine`, so an `unknown` answer says of what kind |
| `presence` | `unknown` when the store has never heard of the thing, `held` when it has facts in force about it or about what is on it, `gone` when it was there and what was read of it is retracted |
| `thing`, `same_as`, `parts` | the thing's entity; the other ids the store knows it by, such as a machine's names the resolver links; and what is inside it with facts in force, one level. For a project: components `part_of` it, files `located_on` it, and files whose path is in its folder. For a machine: what is `part_of` or `located_on` it, such as its containers, packages, checkouts and watched files, without their own parts; `immune project` gives a checkout's. A program has none |
| `facts` | the facts in force about the thing and its parts, each with the assertions it rests on: `reader`, `basis`, `source_ref_text`, `observed_at`, and the reading's scope and kind. A fact whose subject is in `same_as` is about the thing |
| `coverage` | the latest reading of each reader, scope and kind that speaks for the thing: the readings of it and its parts, those that wrote its facts, those that look for things of its kind, for a project the readings of this Mac that read inside every project, and one that names a folder macOS asks permission for that holds it. Each has `completeness`, `reason_text` (whole), `cause` and `observed_at`, and lists what it has no reader for |
| `findings` | the findings in every state, by id, with `rule`, `state`, `severity`, `confidence` and `urgent`: those about the thing, about its parts whether what was read of them is in force or retracted, and for a project about anything whose id lies in its folder. A finding stays in the answer after the file it is about is removed |
| `latest_run_at` | when the latest run that finished ended; absent when none has. A reading older than it was not made again in that run |

Each question answers for one type of entity: `immune project` for a `checkout`, `immune program` for a `component` or a keg's `file` that a reading of installed programs wrote about, and `immune machine` for a `machine`. An id the store holds of another type is refused with `not_a_project`, `not_a_program` or `not_a_machine`, exit code 2. No question answers for a watched file by itself: a `file:` id given to `immune project` or `immune program` is the path it names, and answers for the project or the program that holds it.

The readings that look for things of a kind are, for projects, the walk of the home folder and the reading of agent working folders, given with every project; for programs, the `integrity` readings of application bundles, Homebrew kegs and global npm packages and the `brew` reading; for machines, the `ssh-config`, `known-hosts` and `tailnet` readings. A program or a machine the store has never heard of carries all of its kind. A known one carries those that wrote about it. A project the store knows also carries the readings of this Mac that look inside every project, the ones of the table of ways a project runs code by itself, since one that is not full may be about this project.

A thing the store has never heard of is `unknown`, and its coverage shows which readings looked for it. In a thing that is known and read in full, every reading is `full`. A project in a folder macOS asks permission for keeps what was read there before, and its answer carries the reading `folders macOS asks permission for` with completeness `none`, naming that folder. So does a program path in such a folder. A program whose reading could not read all of it, such as a package whose manifest links into such a folder, carries that reading as `partial`. A server whose sweep did not complete carries its readings as `none`.

Three readings are made by rule rather than read from the store. Each has completeness `none`, cause `not_given` and no `observed_at`, and nothing like them is kept in the store:

- A machine other than this Mac that the server check never visited, under any of the ids the resolver links: `servers`, `sweep visit`.
- A machine the owner set aside as retired or not theirs: `servers`, `sweep of a machine set aside by the owner`. Its reason names what the owner said and the day, and nothing of the owner's reason. `immune owner --json` lists the statements that stand.
- A path that none of the readings looking for things of its kind looks at, answered `unknown`: `immune`, `places the readings that find projects look in` (or programs), scoped to this Mac. For projects that is a path outside the home folder, on another volume, in a hidden folder, in a folder the walk skips, more than 5 levels below the home folder, or in a folder macOS asks permission for: the reading of agent working folders finds a project only where an agent worked. For programs it is a path outside the applications folders (a bundle directly in them or one folder down), Homebrew's Cellars and the global `node_modules` folders; the `brew` reading asks Homebrew by name and looks at no path.

A path inside a project the store knows, held or gone, answers for that project, the nearest one that holds it, with `asked_text` the path as asked. A path that names no project as written is followed through symbolic links one part at a time, and never inside a folder macOS asks permission for; a link into such a folder answers `unknown` with the reading that names it. A path the store knows only under another case is refused with `spelled_otherwise`, exit code 2, and the ids it knows in `ids_text`: the Mac's volumes usually ignore case, so it may be the same folder, and the disk is not asked. A path in another Unicode normal form than the one the store holds is not matched.

`immune program` takes a path to the program whose folder holds it: the path in its `installed_at`, or the path a keg's id names. A program that moved, or one of two copies of it that went away, is still the program at the folder it left, unless another program is there now. A program's id is that program, and a `file:` id of this Mac is the path it names. Anything else is a name, matched against the last part of a program's id, `component:<machine>/<ecosystem>/<name>`. A keg and its Homebrew formula are two programs: no fact links them.

A question that fits more than one thing fails and names each of them. A name that fits two programs, such as a formula and a global npm package called the same, fails with `several_programs`; a name that fits machines not known to be one fails with `several_machines`. Both exit with code 2 and list every id the question fits, whole, in the error's `ids_text`, so each can be asked again.

As in every other answer, text from the Mac is only in fields ending in `_text`. Entity ids are such text, since they hold paths and names from the Mac. An entity id is opaque: compare it whole and never take it apart. In the contract's text a hidden character is written `\u{...}` and so is the backslash itself, `\u{5c}`, so no two texts are shown alike. An id or a path given to a question is read the same way, so every id an answer prints asks back the same thing, and a path with a backslash in it is written with `\u{5c}`. These answers cut no text: an id, the place a fact was read and a coverage reason are given whole, so they can be matched and asked about again.

### `immune findings` and `immune finding <id>`

The response layer gives a verdict about a finding, so it reads one whole. Both answers read the same findings as the status and the pages, in the same order: the most severe first, then the latest seen, then by id. A finding of a rule this build does not have is left out, as it is everywhere else.

`Findings` lists every finding the store holds, in every state, each as its reference (`finding`: `id`, `rule`, `about_text`, `state`, `severity`, `confidence`, `urgent`) with `kind`, `title`, `where_text`, `first_seen_at`, `last_seen_at` and the person's `answer`. `latest_run_at` is absent when no run has finished. `--all` changes only the text for a person; the message carries every state either way.

`Finding` is one finding whole:

| Field | Holds |
|---|---|
| `finding` | its reference, as in the list |
| `kind`, `title`, `meaning`, `advice` | the core's own words, the same for every finding of its rule |
| `technique_text` | the ATT&CK technique its rule names, or the first of a published rule's tags; absent when none fits |
| `where_text` | where the thing is, as a person recognises it |
| `first_seen_at`, `last_seen_at` | when it was first found and when last |
| `answer` | the person's answer: `given` (`expected` or `seen`), `via` (`app`, `agent`, `command`, or `unknown` for one given before this was kept), `given_at`, `reason_text`, `until_at` for `expected`, and `in_force`, whether it hides the finding now. Absent when there is none, including after it was taken back |
| `evidence` | one key, the kind of finding, holding what it rests on beside the journal |
| `rests_on` | the journal entries it rests on, oldest first: `seq`, `recorded_at`, `run_id`, `entry`, `reader`, `kind`, `predicate`, `subject_text`, and the value before and after, `old_value_text` and `new_value_text` |
| `answers_note` | when an agent may answer a finding, the same words as in `immune status --json` and the usage |

The kinds of evidence, by rule:

| Key | Rules | Holds |
|---|---|---|
| `place_changed` | `watched.*`, `autorun.*` | `change`: `new`, `changed`, `gone` or `first_read`. The digests before and after are in `rests_on` as `has_content`, never the content |
| `changed_in_place` | `integrity.*` | `became_text`: what an application's seal or signer became, as the reader wrote it; absent when what changed is a digest, which is in `rests_on` |
| `indicator_matched` | `indicator.match` | `indicators_text`: the indicators the file or the connection matches, as STIX comparisons |
| `detached_process` | `processes.detached-inline-code` | `pid` and `start_micros` of the process the latest sample saw; its program is `about_text`. Its command line is never kept |
| `vulnerable_package` | `lockfiles.*` | `project_text`, `ecosystem`, `package_text`; `releases`, each `version_text` with `at_text`, the lockfile line; `records`, each with `id_text`, `aliases_text`, `source`, `label`, `exploited`, `summary_text` and `fixed_text`. All are from the answers that stand now, so a cleared finding has none |
| `published_rule_matched` | `sigma:<id>` | `rule` as in `Matches`; `matches`, how many events it matched since it was raised; `events`, the latest five at most, newest first, each as `Matches` gives an event; `source` and `licence` |

Text from the Mac or a source is given whole, escaped as in every answer of the contract. A store with no table of findings, which an older build can leave, fails as a store written by an older build, with exit code 3, so an empty list always means that the store holds no finding. An id the store has no finding for is refused with `unknown_finding` and exit code 2.

`immune finding <id> expected`, `seen` and `reopen` are not commands of the contract. With `--json` they print the report's envelope as before, and they take no `--proto`.

### `immune matches`

The response layer looks into what the core is not sure of. `immune matches` gives it every match of every published rule, of every level and with none, each with the event it matched, in the order of the log; events that matched no rule are left out. The store keeps no event and no match, so the command reads the collector's log again and evaluates each event with the same code the core's own reading uses: the two never disagree about what matched.

The caller keeps its place. Each answer prints one in `continue_after`, and `--after` takes it back to read on from there; without `--after` the answer starts at the oldest line kept. A place is the core's own words: a string of lower-case hexadecimal that a reader stores and passes back whole, and never parses or compares. It holds what the core's own reading keeps for itself: for each log file, its identity (the hour its name gives and its inode), how far it was read, and whether its hour was over when it was read to its end, together with the last number `eslogger` gave each kind of event. A place for a day of 25 files is about 530 characters. `--after` takes only a place this build printed, checked character by character and number by number, and refuses anything else as a misuse with exit code 2. A place names no path: a file is only ever looked up among the files the log folder lists.

Reading on from a place works the way the core's own reading works. A file the place holds, with the same inode, is read on from where the place left it. Any other file is read from its start, whatever its name: one the place does not hold, one of the same name with another inode, and one shorter than the place's offset. A file the place holds that is gone or was replaced had lines the place did not read when the collector's note of its deletion says it held more, or, with no note, when the place had not read it to the end of an hour that was over. The answer then says `gone`. Nothing is skipped without the answer saying so. An event may be given twice, after a file was replaced, and is never missed. This holds for a clock set ahead and back, a reinstall within one hour, and a file deleted before it was read.

| Field | Holds |
|---|---|
| `matches` | each match with `position`, `rule` (`name`, `file`, `id_text`, `title_text`, `level`, `techniques_text`, `author_text`, `source`, `set`), `event`, `raised` and `findings`. A match is named by its position and its rule's `name`, its set and its id, `sigma:<id>`, `elastic:<id>` or `elastic-behaviour:<id>`, the same in every command, which a finding of a set that raises carries; `source` and `set` give the set by name and in words; `file` is the path under that set's folder, `rules/sigma/`, `rules/elastic/` or `rules/elastic-behaviour/`. `level` is `not_stated` for a rule whose set states none, Elastic's behaviour rules: a value that is not a severity. A reader built before it was added reads it as a value it does not know, so as the highest level; a rule's level never decides whether the core raised a finding, which `raised` says. A position is an opaque reference to the event's line that includes the log file's inode, so it is never given to another line. Positions are not ordered as text: matches come in the order of the log |
| `event` | one key, the event's kind, holding the event: `program_start` or `file_event`. A program start has `happened_at` with `happened_nanos`, `process` (the process started: `executable_text`, `pid`, `user_id`, `signing_id_text`, `team_id_text`, `platform_binary`), `instigator` (the same process before the `exec`; today only its `executable_text`), `parent_pid`, `args_text` and `working_directory_text`. A file event has the time, `action` (`create` or `rename`), `path_text`, `source_text` for a rename, and `instigator`, the process that did it, today only its `executable_text`. A kind a reader does not know reads as no event |
| `raised` | `below_high` for a rule below high, which raises nothing; `level_not_stated` for a rule whose set states no level, which raises nothing by itself; `finding` with the finding in `findings`, as the core's own reading recorded it, with the finding's state now; `not_read_yet` when the core's own reading has not reached the line; `no_finding` when it read the line and no finding holds the match, as a build without the rule leaves it; `unrecorded` when it read the line before the store kept which finding each match went to |
| `continue_after`, `more` | the place to pass as `--after` next; and whether whole lines are left that the limit stopped short of. There is no place when the collector is not installed |
| `stretch` | what was read after `after`: program starts and file events evaluated, other messages, lines and file events that could not be read, program starts and file events missing from `eslogger`'s numbering, and restarts of the numbering, each a loss of unknown size. `gone` says that lines the place had not read were deleted, or their file replaced, before they were read. `kept_from` is then the position of the first line of the first file kept at or after the hour of those lines |
| `collector` | `state` judged from the log when the answer was made, by the same rule as the core's reading, which speaks for the stretch just read; what `eslogger` or the scripts printed when it is `refused` or `failing`; when the log was last written; whether file events are collected; `status_state` with `status_read_at`, the state `immune status` serves from the core's own latest reading, which speaks for its findings and for `raised`; and `foreign_files`, the files in the log folder that are not the collector's |
| `unevaluated` | the shipped rules that judge nothing here or only part of what they mean, by file, `name`, and its set in `source` and `set`, with the reason: `needs_events`, `needs_fields`, `keyword_search`, `not_parsed`, `in_part`, or `not_collected` for the rules for file events while the collector is not installed or does not record them. Every one of Elastic's detection and behaviour rules for macOS that the translation did not take is here too, by its upstream file and `name`, with the translation's reason, `sequence`, `not_eql`, `needs_events`, `needs_fields`, `backslash_in_wildcard`, `spans_kinds`, `never_true`, `regex`, `unsupported` or `function`, and what the translation said of it in `detail_text`. For a translated rule `in_part`, `fields_text` holds the fields its left-out alternatives need and `detail_text` any pattern the translation could not carry |

An answer with no matches says that nothing matched only when `collector.state` is `running`, the stretch shows nothing lost, unreadable or gone, `collector.file_events_collected` is true, and no rule the reader cares about is in `unevaluated`. A rule listed `in_part` is evaluated, so a match of it is a match, but the absence of one says nothing about the alternatives that need the fields in its `fields_text`. The values of `raised`, `collector.state`, `unevaluated.reason`, `action` and a rule's `level`, and the kinds of event, will grow within version 1. A reader treats a value it does not know as something it cannot judge, and a rule's level it does not know as the highest, which never says whether a finding was raised.

Which finding a high match went to is recorded when the core's own reading reads the line: the line's file, inode and offset, the rule and the finding. Only matches of rules marked high or critical are recorded, since only they raise a finding. A row goes when its log file is no longer there. `not_read_yet` is not a promise: a line deleted before the core's reading reaches it is never read, and no finding holds it. For `not_read_yet`, `no_finding` and `unrecorded` the reader judges the match itself.

A gap in `eslogger`'s numbering at the seam between two answers is counted in the later one, from the last numbers the place holds. Without `--after`, the first event of each kind has nothing before it, as at the start of the log.

One answer holds at most `--limit` matches, 1,000 by default. It also stops once the lines it matched come to 4 MiB, since arguments are never cut and one command line can be a megabyte. On an invented busy hour, 1,000 matches were 892 KB of JSON and 398 KB of binary protobuf; twenty matched starts with half a megabyte of arguments each stopped at 8, about 4.2 MB of JSON.

Text in an event is given whole. No argument or path is cut, each argument is a string of its own, and hidden characters are escaped as elsewhere. The environment is not in the log and not in the answer. On a Mac without the collector, the answer has no matches, the state `not_installed` and the rules for file events in `unevaluated`, and the command exits with 0. Without a store, or with one that cannot be read, the command fails with `store_unreadable` and exit code 3, as the other commands of the contract do: without the store it cannot say what became of a match. A log that cannot be read is a failure with the code `log_unreadable` and exit code 1. With `--json` every failure prints the envelope without `format`, so a reader that takes it for a `Matches` reads format 0 and stops.

The core cannot give these today: a process's start time or its parent's identity beyond the pid, which the collector does not keep; and how many lines a deleted file held, so `gone` says only that lines are gone.

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
