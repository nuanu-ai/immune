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
| `immune findings [--all] [--json]` | Open findings, or every one with `--all` |
| `immune finding <id> [--json]` | One finding with what it rests on |
| `immune finding <id> expected --reason <text> [--days <n>] [--via app\|agent]` | Hide it for 30 days or `--days` |
| `immune finding <id> seen [--reason <text>] [--via app\|agent]` | Close it |
| `immune finding <id> reopen [--via app\|agent]` | Take an answer back |
| `immune vulnerabilities [--json]` | Known vulnerabilities that affect packages the lockfiles declare |
| `immune vulnerability <record id or CVE id> [--json]` | The answer for one vulnerability in every project |
| `immune rules [--json]` | The shipped Sigma rules: evaluated in full, in part or not, whether they watch, how often each matched |
| `immune rules --over-log [--system-root <dir>] [--json]` | Evaluates the rules over the log on disk now, without the store |
| `immune project <path or id> [--json]` | What the store knows of one project, as the contract's `Known` message. The project is a path, absolute or starting with `~/`, which answers for the nearest project that holds it, or an id as the store names it: a project's (`checkout:machine:<name>/<path>`) or a file's (`file:machine:<name>/<path>`), which is the path it names. It reads the store, follows a symbolic link in the path only outside folders macOS asks permission for, and never looks inside the project's folder |
| `immune program <path, name or id> [--json]` | The same for one program installed on this Mac: an application bundle, a Homebrew formula, cask or keg, a global npm package. It is a path (the bundle, the keg or the package's folder, or a file inside one), the name the store gives it (a bundle identifier, Homebrew's name, the package's name), or its id. No path is looked at on disk |
| `immune machine [<name or id>] [--json]` | The same for this Mac, or for another machine the store knows: a name or address it is known by, as `immune owner` takes one, or its id (`machine:<name>`). A machine known under several ids that the resolver links with `same_as` is answered with what was read under every one of them, whichever name is asked |
| `immune matches [--after <position>] [--limit <n>] [--system-root <dir>] [--json]` | Every rule match over the event log, of every level, each with the event it matched, as the contract's `Matches` message. It reads the log again and the store only, and writes nothing |
| `immune servers` | Lists the servers this Mac knows and writes the sweep script |
| `immune owner [<name> retired\|not-mine --reason <text> \| <name> withdraw] [--via app\|agent] [--json]` | A statement that a machine is retired or not the user's, or the list of those that stand |
| `immune view [--no-open] [--if-stale]` | Writes the HTML pages and opens the summary; with `--if-stale`, only when something they show changed or they are an hour old |
| `immune sample [--json]` | One sample of processes and connections |
| `immune watch [--sample-every <s>] [--events-every <s>] [--alive-every <s>]` | Runs until stopped, printing one JSON line per event: `watching`, `read`, `sample`, `program_starts`, `alive`, `problem` |

In JSON output, `title`, `meaning` and `advice` are Immune's fixed words. Anything taken from the machine or a feed is only in a field whose name ends in `_text`.

## The contract

A program that runs Immune, such as the response layer, reads the commands of the contract. Their messages are defined by a protobuf schema in `contract/immune/v1/`, package `immune.v1`. The Rust types are generated from it into `src/contract/immune.v1.rs`, which is committed. A test generates the file again and fails when the two differ, so a build needs neither `protoc` nor a generator.

A command of the contract prints one message on stdout: binary protobuf by default, and the same message as one line of JSON with `--json`. The binary form is standard protobuf, and a program in another language reads that. The JSON is Immune's own and is not protobuf's JSON mapping. The generated types print it. Field names are the schema's, an enum is the name of its value without the enum's prefix and in lower case (`CAUSE_NOT_GIVEN` prints as `not_given`, the store's own word), a 64-bit number is a JSON number, and an absent optional field is null. Times are seconds since the epoch, UTC, in fields ending in `_at`.

A failure to answer is not a message, and a reader checks the exit code before it parses. In binary nothing is printed on stdout. With `--json` the failure envelope is printed, and for `immune project`, `immune program` and `immune machine` it has no `format`, so a reader that parses it as `Known` all the same reads format 0 and stops. The exit codes are the ones above.

An enum value a reader does not know, and the value `unspecified`, are read as the unsafe case, which the schema names for each enum: for `Presence` not known, for `Completeness` not full, for `Cause` failed, for `FindingState` open, for a severity the highest level and for a confidence the lowest. The generated types read a word they do not know as `unspecified`, so a value added within version 1 does not break an older reader.

Four commands use the contract so far. `immune project`, `immune program` and `immune machine` each print `Known`, about a project, a program or a machine. `immune matches` prints `Matches`.

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

### `immune matches`

The response layer looks into what the core is not sure of. `immune matches` gives it every match of every published rule, of every level, each with the event it matched, in the order of the log; events that matched no rule are left out. The store keeps no event and no match, so the command reads the collector's log again and evaluates each event with the same code the core's own reading uses: the two never disagree about what matched.

A position is `<hour>:<offset>`, the hour of the log file in UTC as its name gives it and the byte offset where the line begins, such as `20261004T00:4096`. Log files are only appended to, so a position holds when `eslogger` restarts and its numbering starts again, and across the turn of the hour, until the file is deleted. The caller keeps its place. `--after` reads the lines after the one at that position, and without it the answer starts at the oldest line kept.

| Field | Holds |
|---|---|
| `matches` | each match with `position`, `rule` (`file`, `id_text`, `title_text`, `level`, `techniques_text`, `author_text`), `event`, `raised` and `finding_id`. The position and the rule's file name the match |
| `event` | `kind`, `program_start` or `file_event`, and the one it names. A program start has `happened_at` with `happened_nanos`, `executable_text`, `args_text`, `working_directory_text`, `pid`, `user_id`, `parent_pid`, `parent_executable_text`, `signing_id_text`, `team_id_text` and `platform_binary`. A file event has the time, `action` (`create` or `rename`), `path_text`, `source_text` for a rename, and `executable_text` |
| `raised` | `below_high` for a rule below high, which raises nothing; `finding`, with `finding_id`; `not_read_yet` when the core's own reading has not reached the line; `untold` when the store cannot tell which of the rule's findings it went to |
| `continue_after`, `more` | the position to pass as `--after` next, which is the last line read; and whether whole lines are left that the limit stopped short of |
| `stretch` | what was read after `after`: program starts and file events evaluated, other messages, lines and file events that could not be read, program starts and file events missing from `eslogger`'s numbering, and restarts of the numbering, each a loss of unknown size. `gone` and `kept_from` say that lines after `after` were deleted before they were read |
| `collector` | `state` judged from the log now, by the same rule as the core's reading; what `eslogger` or the scripts printed when it is `refused` or `failing`; when the log was last written; whether file events are collected; and `status_state` with `status_read_at`, the state `immune status` serves from the store |
| `unevaluated` | the shipped rules that judge nothing here or only part of what they mean, by file, with the reason: `needs_events`, `needs_fields`, `keyword_search`, `not_parsed`, `in_part`, or `not_collected` for the rules for file events while the collector does not record them |

Which finding a high match went to is found by time, since no event is stored. A rule raises one finding per Mac and a new one only after the person closes the last, so the findings of a rule follow one another, each last seen at the latest reading that matched it. The reading that read an event came after the event. If only one finding of the rule was last seen at or after the event's second, the match went to it; otherwise `raised` is `untold`. A clock set back between an event and its reading would mislead this.

A gap in `eslogger`'s numbering at the seam between two answers is counted in the later one. Before it reads, the command looks back up to 16 MiB for the last number of each kind of event. When it does not find one there, and the look did not reach the start of the oldest file kept, the gap before the first event of that kind counts as one loss of unknown size.

One answer holds at most `--limit` matches, 1,000 by default. It also stops once the lines it matched come to 4 MiB, since arguments are never cut and one command line can be a megabyte. On an invented busy hour, 1,000 matches were 763 KB of JSON and 342 KB of binary protobuf; twenty matched starts with half a megabyte of arguments each stopped at 8, about 4.2 MB of JSON.

Text in an event is given whole. No argument or path is cut, each argument is a string of its own, and hidden characters are escaped as elsewhere. The environment is not in the log and not in the answer. On a Mac without the collector, the answer has no matches and the state `not_installed`, and the command exits with 0. A log that cannot be read is a failure with the code `log_unreadable` and exit code 1.

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
