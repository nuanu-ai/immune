# Reference

What Immune reads on a Mac, where it looks, what it records and when; the vocabulary of facts; the commands and the contract; and the files it keeps. [how-it-works.md](how-it-works.md) explains the terms used here.

## What is watched

| What | How | When |
|---|---|---|
| Places where persistence lives: launch agents and daemons, login and logout hooks, zsh and bash startup files, `~/.ssh/config`, `authorized_keys` and `rc`, the system's SSH configuration, PAM policies and modules, authorization plugins, git hooks in every project | A checksum of each file, never its content; for login hooks, a checksum of the hook alone | Within seconds while the app is open, otherwise at the hourly check |
| Software changed in place: app bundles, Homebrew kegs, global npm packages, code that apps keep under Application Support | The app's code signature, verified by macOS; for the rest, a digest of file paths and change times | Hourly |
| Files that make a tool run code by itself: install scripts in `package.json`, editor tasks that run when a folder opens, editor and dev container settings, coding agents' settings, hooks and MCP server lists, editor extensions | The part of the file that runs code, as a checksum. 13 of the 41 known ways in a project and 7 of the 11 known places in the home folder are read | Within seconds for most, hourly for the rest |
| Dependencies in `package-lock.json`, `pnpm-lock.yaml` and `Cargo.lock` | Matched against OSV's data for npm and crates.io and against CISA's catalogue | Hourly |
| The user's running programs and their internet connections | Read without administrator rights. An interpreter given code on its command line and left running without a terminal is a finding | Every 30 seconds while the app is open |
| Every program start and every file created or renamed, with the collector | Checked against 198 published rules for macOS: the 75 of SigmaHQ, and 66 of Elastic's detection rules and 57 of its behaviour rules translated into Sigma. 175 are evaluated in full and 23 in part | About every 10 seconds while the app is open, and at every check |
| Indicators from an incident report that the user gives as `indicators.json`: SHA-256 hashes, domains, IPv4 addresses, URLs | Matched against watched files, lockfiles, editor tasks and connections | At every check |

## What this version does not see

`immune status` lists what is not covered, one item per cause, and says who can act on each (see [how-it-works.md](how-it-works.md#coverage)). Today the limits of this version include:

- A connection at the moment it is made, and the name behind an address. Immune samples connections every 30 seconds and sees addresses only; `eslogger` has no network event.
- A file modified in place or removed. The collector records files created and renamed only.
- `fork` and `exit`: a process that forks without starting a new program, and when a process ends.
- One of SigmaHQ's rules, 12 of Elastic's translated detection rules and 10 of its translated behaviour rules have an alternative that needs a field `eslogger` does not give, or that the translation could not carry, so they are evaluated only in part. Of Elastic's other 119 detection rules for macOS, none is evaluated: 30 correlate a sequence of events, 40 are written in KQL or ES|QL, and 49 need events or fields the collector does not record or could not be translated exactly. Of its other 221 behaviour rules, none is evaluated: 109 correlate a sequence of events, and 112 need events or fields the collector does not record or could not be translated exactly. `immune rules` names each with its reason.
- Without the collector: the moment a program starts, its command line, who started it, and which program created a file. The published rules then do not watch.
- Vulnerabilities in installed apps, Homebrew packages, what servers run, and projects in other languages. Lockfiles Immune has no reader for, such as `requirements.txt`, `uv.lock` or `go.sum`, are named in the report.
- Software installed by any package manager other than Homebrew and npm. Immune names a few when it finds them at their installers' default places (MacPorts, Nix, pkgsrc, Fink, conda, and npm under nvm), reads nothing they installed, and does not find the rest. Homebrew and Tailscale installed outside their default places are not found either. One that an earlier check read and this one does not find is reported as not found now, and what was known from it is kept.
- Folders macOS asks permission for: Desktop, Documents, Downloads, iCloud Drive, other cloud storage, other apps' containers and anything under `/Volumes`. Immune never enters them, so macOS never shows a permission dialog because of it. The report names those it met on the way, and the projects page says which folders the search for projects does not enter. A new project kept there is not found; one found there before stays listed as it was.
- Which program changed a watched file in place.
- Stopping anything. Immune reports, and it never blocks, suspends or kills a program.

## When readers run

| Name | Trigger |
|---|---|
| full check | `immune run`; the app starts one every hour while it is open, with a 30-minute limit |
| live | `immune watch`, about a second after FSEvents reports a change in a place it subscribes to: the readings that place belongs to, or every place, see [Watched places](#watched-places) |
| sample | `immune watch` every 30 seconds, or `immune sample` |
| events | `immune watch` every 10 seconds, and at every full check |

No reader enters a folder macOS asks permission for, whether a path names it or a symbolic link leads into it: Desktop, Documents, Downloads, iCloud Drive, `~/Library/CloudStorage`, `~/Library/Containers`, `~/Library/Group Containers`, and anything under `/Volumes`. So Immune never makes macOS show a permission dialog. A reader that skipped one writes a reading of the kind `folders macOS asks permission for` naming them, and checkouts already known there are kept with nothing inside them read. A new project kept in one is not found: the status names the folders under `protected-folders`, and the page's list of projects says they were not looked into, beside what the search for projects does not enter by design, from its own limits: the home folder's Library, which holds iCloud Drive and other cloud storage, hidden folders, links to folders and anything deeper than five folders.

Every list on a page takes its empty text from the coverage of what fills it: it says there is none only when every such reading is full and taken by the latest check; otherwise it names what was not read, why, and when it was last read in full. `--checkouts-root` can point a full check into such a folder on purpose.

## Readers

The name is what coverage and assertions carry in `reader`.

### On this Mac

| Reader | Where it looks | What it records | Basis | When |
|---|---|---|---|---|
| `checkouts` | The home folder, or the folder given with `--checkouts-root`, up to 5 levels deep. A folder holding `.git` is a checkout and is not searched further. `node_modules`, `target` and `vendor` are never entered, nor `Library`, `Applications`, `Movies`, `Music`, `Pictures` and `Public` directly under the home folder. Only folders are listed; no file is opened | `checkout` entities, `located_on` the machine | observed | full check |
| `agent-folders` | Claude Code's session files, `~/.claude/projects/<folder>/*.jsonl`. Only the `cwd` field of a line is read; the nearest folder above it holding `.git` is the checkout. git is never run. A file that only grew is read on from where the last reading stopped, see below | the same as `checkouts`, for checkouts the walk does not reach: temporary folders, hidden worktrees, other volumes | observed | full check |
| `lockfiles` | In every checkout, up to 4 levels deep, skipping `node_modules`, `target`, `vendor` and `.git`: `package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`. `yarn.lock`, `uv.lock`, `poetry.lock`, `composer.lock`, `go.sum`, `requirements.txt`, `Package.resolved` and `bun.lock` are named as having no reader | `component` entities `part_of` the checkout, `has_version`. The raw copy is a manifest of paths, sizes and the checkout's commit | declared | full check |
| `brew` | `brew info --json=v2 --installed`, run with `HOMEBREW_NO_AUTO_UPDATE` and `HOMEBREW_NO_ANALYTICS`. Homebrew is looked for only where its installer puts it, `/opt/homebrew` and `/usr/local`, or at `--brew`; a `brew` anywhere else is neither looked for nor run. Not found there while the store holds what an earlier check read from Homebrew, the reading is `none` with the cause `not_given`, its reason naming the places looked and that it was read before; those facts are kept and told under `read-before-not-found`. Only with nothing from it in the store is it not installed, read in full | formulae (`brew`) and casks (`brew-cask`) with every installed version. A package Homebrew names no tap for is left out and the reading is partial | observed | full check |
| `integrity` | Application bundles in `/Applications` and `~/Applications` and one folder down; Homebrew kegs and global npm packages under `/opt/homebrew` and `/usr/local`; folders under `~/Library/Application Support` named like an application read here that Apple did not sign | `has_version`, `installed_at`, `signed_by`, `has_seal` (the Security framework's verdict, verified again only when the digest changed), `has_digest` (SHA-256 over every file's path and change time, never content). A folder deeper than 16 levels or with more than 20,000 code files is not recorded, and the reading says so. Package managers no reader reads, MacPorts, Nix, pkgsrc, Fink, conda and npm packages installed globally under nvm, are looked for only at their installers' default places, a table in `src/managers.rs` with the source of each place; nothing of the caller's environment, PATH included, decides what is found. Each one found is named in the reading `software of package managers this version does not read`, and nothing of it is read or run. One at a place of its own choosing is not found, a standing limit (`package-managers-elsewhere-not-found`) | observed | full check |
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
| `tailnet` | `tailscale status --json`, from the app in `/Applications` or `~/Applications`, the Homebrew prefixes, never PATH, or `--tailscale`. Not found there while the store holds peers an earlier check read, it is told as `brew` is, under `read-before-not-found`, and the peers are kept | each peer's names and addresses (`known_as`), its system as the tailnet names it (`runs_platform`), and `relation_to_owner` for an untagged peer of another user. Peers are taken only in the state `Running`. `Stopped` is read as `none` with the cause `not_given`, told under `tailnet-switched-off` with `who` `nothing`; `NeedsLogin`, `NeedsMachineAuth` and `InUseOtherUser` the same, told under `tailnet-not-connected` with `who` `you`. Both carry `since`, when the tailnet was last read in full, and the peers known before are kept. `Starting` and `NoState` are failed readings the next check tries again, and so is any other state, named as one this version does not know. A daemon the command cannot reach is a failed reading | observed | full check |
| `servers` | The files in `sweep/` next to the store, one `<alias>.txt` per server, written by the probe `scripts/probe.sh` when the user runs `sweep/sweep.sh`. A file is complete only if it reaches `##end` | `runs_os`, `runs_release`, `release_codename`, `runs_kernel`, `runs_kernel_package`, dpkg packages as components with `has_version` and `built_from`, containers with `runs_image` and their `*_VERSION` variables, the server's own names and addresses. Only dpkg is read; rpm, apk and pacman are named. The probe runs no command inside a container | observed | full check |
| `resolver` | the other readers' `known_as` assertions | `same_as` between two machines known by the same full name or public address. Bare names and private addresses link nothing | | full check |

`immune servers` lists the servers this Mac knows and writes `sweep/sweep.sh`. Only servers with a current, explicit way in, a literal alias in the SSH configuration, are offered. An alias listed in `sweep/skip.txt`, or a machine the user said is retired or not theirs, is not visited. A server that wants a password stays known and not read: Immune never stores or types a password.

### Threat data

Read at every full check, not as readers of the Mac: CISA's catalogue and OSV's archives for crates.io and npm. Each attempt is a row in `feed_reading`. See [threats.md](threats.md).

A download that failed is one item of `not_covered`: since when the data is old, and why, in fixed words for each of curl's documented exit codes (curl(1), EXIT CODES), for the HTTP status, or for a body that was not the data, one case whatever the source. `who` is `you` only when the cause is certainly this Mac's or its network's to fix: a download that could not be written on the disk, a certificate this Mac does not trust (its clock may be wrong, or the network may inspect encrypted traffic), or a proxy that asks for a password or fails its own handshake. Those are `vulnerability-list-not-downloaded-fixable` and `vulnerability-data-not-updated-fixable`. Anything else, such as a refusal by the server or something between, a name that does not resolve or a connection that fails, is `vulnerability-list-not-downloaded` and `vulnerability-data-old`, with `who` `nothing`. What curl said is in `value_text`.

The downloads use a proxy only when the environment names one, as `/usr/bin/curl` does; they do not read the macOS proxy settings, and the app's environment names none. On a network that lets connections out only through a proxy, they fail and are named as failed.

## Watched places

36 rows in `src/watched.rs`. Adding a place is adding a row. Each kind is one reading. After a change, a watcher first reads only the readings whose places the change is in, each whole: one kind of place on this Mac, the hooks of one checkout, or one row of what runs by itself in every checkout. Every other reading keeps its own time in coverage. A watcher reads every place at its start, whatever the store says of an earlier one, after a reading that failed, when it finds new places to watch or a new way into one, after events FSEvents says it dropped or coalesced, for a change at a path in no watched place, and at its next look at what to watch, once a minute, after any reading of some places or when a watched path now leads somewhere else. The place a change names is read within seconds, every other place within about a minute. So what a watcher still owed when it stopped, and what changed while none ran, is read at the next start; on a Mac where nothing changed, that reading's `read` line has `new`, `changed`, `gone` and `opened` at 0. The `watcher` row keeps when every place was last read. Its `event_id` and `volumes` are left empty: an earlier build kept an FSEvents event id there to replay from, and on an empty one it reads every place at its start. A place a later version reads for the first time on a store that already exists is read for the first time: what it holds is its baseline and is told once by `watched.first-read`.

| Kind | Places |
|---|---|
| `autostart item` | every entry in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` |
| `login or logout hook` | the `LoginHook` and `LogoutHook` keys of `/Library/Preferences/com.apple.loginwindow.plist` and `~/Library/Preferences/com.apple.loginwindow.plist`, each as `<file>#/<key>` |
| `shell profile` | `/etc/zshenv`, `zprofile`, `zshrc`, `zlogin`, `zlogout`, `profile`, `bashrc`; in the home folder `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`, `.zlogout`, `.bash_profile`, `.bash_login`, `.profile`, `.bashrc`, `.bash_logout` |
| `ssh access file` | `~/.ssh/config`, `authorized_keys`, `rc`; `/etc/ssh/ssh_config`, `sshd_config` and their `.d` folders |
| `authentication module` | every entry in `/etc/pam.d`, `/usr/local/etc/pam.d`, `/usr/local/lib/pam` and `/Library/Security/SecurityAgentPlugins`; `/etc/pam.conf`, `/usr/local/etc/pam.conf` |
| `git hook` | every entry in each checkout's `.git/hooks`, except git's `.sample` files |

Never a private key, never known hosts. A checkout whose `.git` is a file, as in a worktree or a submodule, keeps its hooks elsewhere; its hooks reading is partial and says so.

Only the hooks count in the login window's preferences, since the rest of the file changes for other reasons. CoreFoundation parses the file, in the XML, binary or old text form. Each hook's value is encoded exactly and its checksum is `has_content` of `<file>#/<key>`: a string by its UTF-16 code units, with no conversion or normalisation, an array or dictionary element by element, any other value as CoreFoundation writes it alone in binary. The file is one unit and its hooks are entries of it. A file with no hook holds no entry. A file that is not a property list, or whose top is not a dictionary, is a failed reading with the reason. A hook whose value cannot be read is named as `<file>#/<key>` with the reason: one nested deeper than 32 levels, or larger than this version reads, more than 10,000 values or 1 MiB encoded, each value counted every time it is referred to. The other hook is still compared, what was known of the unread one is kept, and losing sight of it is judged as the part's own, so that losing sight of the whole file later is found too. The public name adds the part after `#`; the baseline keeps the physical path and part separate. A literal file and a selected part with the same public name can still share an entity ID across readers. A hook, PAM file or plugins folder read before that is there and cannot be read now is a finding of its rule, with the reason, and is never told as removed. The PAM places are where OpenPAM, as Apple builds it, looks for a policy and for a module named without a path (pam.conf(5) and Apple's OpenPAM source). `/usr/lib/pam` and `/usr/share/pam.d` are left out because only an update of macOS can change them. An authorization plugin is a bundle: Immune sees it arrive and go, and does not see a change inside it. The pages say so of each one instead of when it last changed, `immune status` counts such entries per kind (`presence_only`, with `presence_only_note`), and `immune finding <id>` says it of a finding about one. An entry the latest check did not read in full is shown as not read at the last check, with why, never as unchanged.

Not read: `core.hooksPath`, `ZDOTDIR`, fish, files pulled in by `Include` in the SSH configuration, the git configuration. These places of persistence are left out, and `cannot_judge` and `not_covered` name them:

- login and logout hooks in root's preferences, `/var/root/Library/Preferences/com.apple.loginwindow.plist`, where `sudo defaults write` puts them; only root can read the file;
- login and logout hooks in ByHost preferences, `~/Library/Preferences/ByHost/com.apple.loginwindow.<host>.plist`, kept for one Mac;
- login and logout hooks in Managed Preferences, `/Library/Managed Preferences`, which a device management profile writes;
- a PAM policy a device management profile installs, which OpenPAM reads before `/etc/pam.d`;
- the authorization database, which says which authorization plugins run;
- the sudoers file and its folder, which only root can read;
- login items and background items, whose database needs Full Disk Access;
- crontabs, which only root can read. Listing one is a tool's output, and no documentation says that listing it raises no permission dialog;
- launchd jobs with no file on disk, which only launchd itself could list;
- the applications reopened at login, which macOS rewrites at every logout.

StartupItems and periodic scripts are not watched because current macOS no longer runs them: SystemStarter, which ran StartupItems, was removed in OS X 10.10, and `periodic` in macOS 15.

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

Every row read is watched live, except `~/.claude.json`, which its tool rewrites constantly, and `*.code-workspace`, which has no fixed name; those two are read at each full check. What a row finds is judged as the lifecycle says. A part that appears where an earlier reading read or listed is a finding, and so is everything in a checkout new to a folder an earlier walk listed, such as a clone made after the first check. In the store's first full check, what is found is the baseline. A place read for the first time later, such as a project outside the folders the walk enters, becomes its baseline too and is told once, by `watched.first-read`, with how many things it holds. A file read before that is there and cannot be read now is a finding of its row, with the reason. The exception is a new linked worktree of a repository the store already holds a checkout of. There, a part equal to the one at the same path in that checkout raises nothing; it is recorded, and the journal says which checkout it matched. See [how-it-works.md](how-it-works.md#lifecycle).

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

Every command except `immune servers`, `immune view` and `immune watch` answers with one message of the contract, and fails with the message `Failure` (see [the contract](#the-contract)). `immune servers` and `immune view` print text for a person, and `immune watch` prints its own JSON lines. `--store <path>` points any command at another store.

A command that only reads the store opens it read-only and creates nothing next to it. When a check or a watcher was killed in the middle of a write, the first such command rolls that unfinished write back, as SQLite does for any writer, so the store holds what was last committed, and then reads. Where it cannot write in the store's folder it leaves the store as it is and fails with exit 3 until a check or a watcher opens the store.

| Exit | Means |
|---|---|
| 0 | answered |
| 1 | the event log cannot be read: `immune matches`, `immune rules --over-log` and `immune verdict` |
| 2 | a misuse or an unknown id |
| 3 | an unreadable store |
| 4 | a check holds the store; ask again |
| 5 | another watcher has the store: `immune watch` |

| Command | Does |
|---|---|
| `immune run [--json \| --proto]` | A full check, answered with `Status` once it has finished. Flags for tests and special cases: `--machine-name`, `--brew`, `--brew-input`, `--servers-input`, `--checkouts-root`, `--sessions-root`, `--tailscale`, `--threats-input`, `--osv-crates-input`, `--osv-npm-input`, `--curl`, `--system-root`, `--indicators` |
| `immune status [--json \| --proto]` | What the last finished check left, read-only, as the contract's `Status` message (see [`immune status`](#immune-status)) |
| `immune findings [--all] [--json \| --proto]` | Every finding, in every state, as the contract's `Findings` message; its text for a person lists the open findings, or every one with `--all` |
| `immune finding <id> [--json \| --proto]` | One finding whole, as the contract's `Finding` message: its words, where it is, its evidence, the journal entries it rests on and the person's answer |
| `immune finding <id> expected --reason <text> [--days <n>] [--via app\|agent] [--with <id>] [--journal-seq <n>] [--json \| --proto]` | Hide it for 30 days or `--days`; answered with the `Finding` as it left it. `--with` gives the same answer to the other finding of its pair (see [One answer for a pair](#one-answer-for-a-pair)), and `--journal-seq` names the read the answer rests on, required with `--with` or `--via agent` |
| `immune finding <id> seen [--reason <text>] [--via app\|agent] [--with <id>] [--journal-seq <n>] [--json \| --proto]` | Close it, answered the same way |
| `immune finding <id> reopen [--via app\|agent] [--with <id>] [--journal-seq <n>] [--json \| --proto]` | Take an answer back, answered the same way |
| `immune vulnerabilities [--json \| --proto]` | Known vulnerabilities that affect packages the lockfiles declare, as `Vulnerabilities` |
| `immune vulnerability <record id or CVE id> [--json \| --proto]` | The answer for one vulnerability in every project, as `Vulnerability` |
| `immune rules [--json \| --proto]` | As `Rules`: The published rules of the three sets, SigmaHQ's and Elastic's detection rules and behaviour rules translated into Sigma: evaluated in full, in part or not, whether they watch, how often each matched. `sources` says where each set comes from, its name in words (`set`), whether its rules state levels (`states_levels`), its commit, licence, folder, the fields its rules are given and its totals: `shipped` counts the rule files shipped, and `not_taken` the upstream rules a translation did not take, which are also counted under `not_evaluated`. Each rule has its `rule`, the `Rule` every command gives (its `name`, its set and its id, `id_text`, `title_text`, and its `level`, `not_stated` for a rule whose set states none), beside it its set, `source` by name and `set` in words, and for one in part `never_matches`, each alternative with its `selection_text` (null for one the translation left out), `fields_text` and `left_out_text`. Every Elastic rule the translation did not take is under `not_evaluated` with its `reason` and `detail_text`. Within each group rules are ordered from the most severe level down; the rules of a set that states no level follow as a group of their own, since the order of levels does not include them. The text form gives them their own heading, "Of a set that states no level", with their count, and names each rule by its title and its set. The message also carries `catalogue`: every rule of the core's own with its words, the words of a published rule's finding with the sets that raise findings (`raised_by_sets`) and by which levels, the sets whose rules state no level and so raise nothing by themselves (`sets_that_raise_nothing`), and every cause of what is not covered |
| `immune rules --over-log [--system-root <dir>] [--json \| --proto]` | Evaluates the rules over the log on disk now, without the store, as `Replay`; `outcome` is `not_applicable` when no collector is installed. Each rule that matched has its `rule`, its `status` and count; the most severe first, then the rules of a set that states no level as a group of their own, under their own heading in the text form |
| `immune project <path or id> [--json \| --proto]` | What the store knows of one project, as the contract's `Known` message. The project is a path, absolute or starting with `~/`, which answers for the nearest project that holds it, or an id as the store names it: a project's (`checkout:machine:<name>/<path>`) or a file's (`file:machine:<name>/<path>`), which is the path it names. It reads the store, follows a symbolic link in the path only outside folders macOS asks permission for, and never looks inside the project's folder |
| `immune program <path, name or id> [--json \| --proto]` | The same for one program installed on this Mac: an application bundle, a Homebrew formula, cask or keg, a global npm package. It is a path (the bundle, the keg or the package's folder, or a file inside one), the name the store gives it (a bundle identifier, Homebrew's name, the package's name), or its id. No path is looked at on disk |
| `immune machine [<name or id>] [--json \| --proto]` | The same for this Mac, or for another machine the store knows: a name or address it is known by, as `immune owner` takes one, or its id (`machine:<name>`). A machine known under several ids that the resolver links with `same_as` is answered with what was read under every one of them, whichever name is asked |
| `immune matches [--after <place>] [--limit <n>] [--system-root <dir>] [--json \| --proto]` | Every rule match over the event log, of every level, each with the event it matched, as the contract's `Matches` message, read on from the place an earlier answer gave. It reads the log again and the store only, and writes nothing; without a store it fails |
| `immune verdict [--system-root <dir>] (--json \| --proto)` | Records the response layer's verdict about a rule match or a finding: one `Verdict` message on standard input, binary with `--proto` or JSON with `--json`, answered with `VerdictRecorded` in the same form; without a form it is refused. A verdict never writes into a finding the core raised; a `suspicious` one raises a finding of Immune's own rule `verdict.suspicious` |
| `immune servers` | Lists the servers this Mac knows and writes the sweep script |
| `immune owner [<name> retired\|not-mine --reason <text> \| <name> withdraw] [--via app\|agent] [--json \| --proto]` | A statement that a machine is retired or not the user's, answered with `StatementMade`, or the list of those that stand, as `Statements` |
| `immune view [--no-open] [--if-stale]` | Writes the HTML pages and opens the summary; with `--if-stale`, only when something they show changed or they are an hour old |
| `immune sample [--json \| --proto]` | One sample of processes and connections, as `Sample` |
| `immune watch [--sample-every <s>] [--events-every <s>] [--alive-every <s>]` | Runs until stopped, printing one JSON line per event: `watching`, `read`, `sample`, `program_starts`, `alive`, `problem` |

In every answer, `title`, `meaning` and `advice` are Immune's fixed words. Anything taken from the machine or a feed is only in a field whose name ends in `_text`.

A trimmed answer of `immune status --json` from an invented Mac:

```json
{
  "format": 1,
  "this_mac": {
    "state": "watched",
    "fresh": true,
    "stale_reason": null
  },
  "needs_a_look": {
    "items": [
      {
        "finding": {
          "finding": {
            "id": "f89b204373f",
            "rule": "watched.autostart",
            "severity": "medium",
            "confidence": "low",
            "urgent": false
          },
          "title": "A program set to start by itself on this Mac was added, changed or removed.",
          "where_text": "~/Library/LaunchAgents/com.example.updater.plist"
        },
        "technique_text": "T1543"
      }
    ],
    "total": 1,
    "urgent_total": 0
  },
  "not_covered": [
    {
      "id": "vulnerabilities-not-compared",
      "who": "nothing",
      "holds_on": "every_mac",
      "title": "Known vulnerabilities are not yet compared with your installed software, your servers or projects of other kinds."
    }
  ],
  "cannot_judge": [
    "no vulnerability is matched against installed software, servers' packages or ecosystems other than npm and crates.io yet"
  ]
}
```

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

A command of the contract answers with one message, in one of three forms: binary protobuf with `--proto`, the same message as one line of JSON with `--json`, and with neither, text for a person rendered from that message alone, so a person, an agent and a program are given the same thing. Text from a source is set in quotes or a column of its own, escaped as in the message. A program names its form on every call. Naming both flags is a misuse and returns a JSON failure. `immune verdict` reads a message, which is not typed as text, so without a form it is refused. The binary form is standard protobuf, and a program in another language reads that. The JSON is Immune's own and is not protobuf's JSON mapping. The generated types print it. Field names are the schema's, an enum is the name of its value without the enum's prefix and in lower case (`CAUSE_NOT_GIVEN` prints as `not_given`, the store's own word), a 64-bit number is a JSON number, and an absent optional field is null. Times are seconds since the epoch, UTC, in fields ending in `_at`.

A failure to answer is the message `Failure` in `common.proto`, and a reader checks the exit code, the ones above, before it parses. With `--proto` the binary `Failure` is on stdout, with `--json` the same as JSON, and for a person it is on stderr with nothing on stdout. It has `operation`, `ok` (always false) and `errors`, each with a stable `code`, the core's `message`, an `example` of a right call where there is one, `detail_text`, what the failure quotes (null when nothing), and `ids_text`, the ids a question fits when it fits several. `Failure` has no `format`, and its fields are numbered from 1000, which every answer reserves, so one read as any answer, in binary or JSON, reads format 0 and the reader stops.

An enum value a reader does not know, and the value `unspecified`, are read as the unsafe case, which the schema names for each enum: for `Presence` not known, for `Completeness` not full, for `Cause` failed, for `FindingState` open, for a severity and for a rule's level the highest level and for a confidence the lowest, for `AnswerKind` no answer, for `Via` not known who gave it, for `Change` changed, and for `VerdictKind` no verdict. The generated types read a word they do not know as `unspecified`, so a value added within version 1 does not break an older reader.

Every command except `immune servers`, `immune view` and `immune watch` uses the contract. `immune status` and `immune run` print `Status`, and `immune sample` prints `Sample`, in `status.proto`. `immune rules` prints `Rules`, and `immune rules --over-log` prints `Replay`, in `rules.proto`. `immune vulnerabilities` and `immune vulnerability` print `Vulnerabilities` and `Vulnerability`. `immune owner` prints `Statements`, or `StatementMade` for a statement made or withdrawn, in `owner.proto`. `immune project`, `immune program` and `immune machine` each print `Known`, about a project, a program or a machine. `immune matches` prints `Matches`. `immune findings` prints `Findings`; `immune finding <id>` and an answer to it print `Finding`. `immune verdict` reads `Verdict` and prints `VerdictRecorded`, both in `verdict.proto`. The types every message shares are in `common.proto`, and the event a rule matched is in `event.proto`. A map of the report by name is a list of pairs, such as `Count`, a `name` and a `count`.

Every message carries `store_id`, the id of the store it was read from. A finding's id is unique only within one store: a store deleted and made again can give the same id to another finding, so a reader that keeps a verdict keeps it by the store's id and the finding's id together. The id is 16 random bytes from `getentropy`, written as 32 hexadecimal characters. It is made once, when the store is made, and kept in the store's `meta` table, so it says nothing about the Mac. A store an older build made gets one the next time a command that writes opens it, such as `immune run` or `immune watch`. A command that only reads makes none: until then the field is absent, and nothing tells that store apart from another.

### `immune status`

`Status` is what the latest checks left: what needs a look, what is not covered, the collector, and how this Mac is watched.

`needs_a_look` lists open findings, urgent first, then the most severe, then the latest seen. It lists at most 50 of the core's findings and 50 of the response layer's, so neither source can push the other's findings out. `total` counts them all, and `urgent_total` counts the urgent ones among them all, not only those listed. Within each source urgent findings come first, so its cut never drops an urgent finding while it keeps one that is not; when a source has more urgent findings than its 50, `urgent_total` is more than the urgent ones listed. `immune findings` lists every finding.

Each cause in `not_covered` says in `holds_on` where it comes from. `every_mac` is a limit of this version, the same on every Mac, such as a reader it does not have. `this_mac` was raised by a reading on this Mac, such as a failed download, a folder it did not read or software of a package manager it does not read. A cause that holds on every Mac, such as places where something runs by itself that are not read, is `this_mac` when this Mac has something there. `unspecified`, or a value a reader does not know, is read as `this_mac`, so no cause raised here is taken for a limit of the version. The text form follows it: a `nothing` cause that holds on every Mac is told under "Limit of this version", and one of this Mac under "Not judged on this Mac".

Each cause names what it is about in `examples_text`, by name only. `examples` lists the same things in the same order, each with `name_text` and `reason_text`, what its source said about it, such as why a server could not be opened. The secrets the core recognises are cut out of a reason, as in `args_text`, and `reason_text` is absent when the source said nothing. The `reason_text` of `coverage.problems` and `coverage.unreached` is cut the same way. Since 1.8.0.

`this_mac.fresh` says whether the answer rests on a recent check: the latest full check finished within `fresh_for_seconds` (7200) of `answered_at`. When it did not, when its time is ahead of this Mac's clock, or when no full check has finished, `fresh` is false and `stale_reason` says why. A status that is not fresh is never calm, whatever it lists; the app shows it as old, with when the last full check finished. The app also ages a status it holds: one held more than `fresh_for_seconds` after `checked_at` is shown as old in the same way. `this_mac.state` is `watched_in_part` when the collector was refused, from the start or later, failed or fell silent after it ran, and when it runs but lost part of what it was to record over the last day (a gap in its sequence numbers, a restart it cannot account for, log files removed by the cap or left unread), for as long as `rules.judged` is `part`.

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

Four readings are made by rule rather than read from the store. Each has completeness `none` and no `observed_at`, and nothing like them is kept in the store. The first three have the cause `not_given`:

- A machine other than this Mac that the server check never visited, under any of the ids the resolver links: `servers`, `sweep visit`.
- A machine the owner set aside as retired or not theirs: `servers`, `sweep of a machine set aside by the owner`. Its reason names what the owner said and the day, and nothing of the owner's reason. `immune owner --json` lists the statements that stand.
- A path that none of the readings looking for things of its kind looks at, answered `unknown`: `immune`, `places the readings that find projects look in` (or programs), scoped to this Mac. For projects that is a path outside the home folder, on another volume, in a hidden folder, in a folder the walk skips, more than 5 levels below the home folder, or in a folder macOS asks permission for: the reading of agent working folders finds a project only where an agent worked. For programs it is a path outside the applications folders (a bundle directly in them or one folder down), Homebrew's Cellars and the global `node_modules` folders; the `brew` reading asks Homebrew by name and looks at no path.
- A program the store never heard of, answered `unknown` by `immune program`: `immune`, `software of package managers this version does not look for`, cause `no_reader`. Its reason is the limit that a package manager other than Homebrew and npm is not read, and that Homebrew or Tailscale installed outside their default places is not found.

A path inside a project the store knows, held or gone, answers for that project, the nearest one that holds it, with `asked_text` the path as asked. A path that names no project as written is followed through symbolic links one part at a time, and never inside a folder macOS asks permission for; a link into such a folder answers `unknown` with the reading that names it. A path the store knows only under another case is refused with `spelled_otherwise`, exit code 2, and the ids it knows in `ids_text`: the Mac's volumes usually ignore case, so it may be the same folder, and the disk is not asked. A path in another Unicode normal form than the one the store holds is not matched.

`immune program` takes a path to the program whose folder holds it: the path in its `installed_at`, or the path a keg's id names. A program that moved, or one of two copies of it that went away, is still the program at the folder it left, unless another program is there now. A program's id is that program, and a `file:` id of this Mac is the path it names. Anything else is a name, matched against the last part of a program's id, `component:<machine>/<ecosystem>/<name>`. A keg and its Homebrew formula are two programs: no fact links them.

A question that fits more than one thing fails and names each of them. A name that fits two programs, such as a formula and a global npm package called the same, fails with `several_programs`; a name that fits machines not known to be one fails with `several_machines`. Both exit with code 2 and list every id the question fits, whole, in the error's `ids_text`, so each can be asked again.

As in every other answer, text from the Mac is only in fields ending in `_text`. Entity ids are such text, since they hold paths and names from the Mac. An entity id is opaque: compare it whole and never take it apart. In the contract's text a hidden character is written `\u{...}` and so is the backslash itself, `\u{5c}`, so no two texts are shown alike. An id or a path given to a question is read the same way, so every id an answer prints asks back the same thing, and a path with a backslash in it is written with `\u{5c}`. These answers cut no text: an id, the place a fact was read and a coverage reason are given whole, so they can be matched and asked about again.

### `immune findings` and `immune finding <id>`

The response layer gives a verdict about a finding, so it reads one whole. Both answers read the same findings as the status and the pages, in the same order: urgent first, then the most severe, then the latest seen, then by id. A finding of a rule this build does not have is left out, as it is everywhere else.

`Findings` lists every finding the store holds, in every state, each as its reference (`finding`: `id`, `rule`, `about_text`, `state`, `severity`, `confidence`, `urgent`) with `kind`, `kind_title`, `title`, `where_text`, `thing`, `first_seen_at`, `last_seen_at`, the person's `answer` and `verdicts`, what the response layer said about it, counted (see [`immune verdict`](#immune-verdict)). `latest_run_at` is absent when no full check has finished. The text says so and lists any findings already recorded. `--all` changes only the text for a person; the message carries every state either way.

`Finding` is one finding whole:

| Field | Holds |
|---|---|
| `finding` | its reference, as in the list |
| `kind`, `title`, `meaning`, `advice` | the core's own words, the same for every finding of its rule |
| `kind_title` | `kind` as a person reads it, a short title such as `Shell startup file` for `shell profile`, as the pages show it. Match on `kind` |
| `technique_text` | the ATT&CK technique its rule names, or the first of a published rule's tags; absent when none fits |
| `where_text` | where the thing is, as a person recognises it |
| `thing` | what it is about in the core's words, when no name from the Mac says it. Only `watched.first-read` has it: the places its check read for the first time, counted by kind, such as `2 projects and 1 other place`. `where_text` is then the machine |
| `first_seen_at`, `last_seen_at` | when it was first found and when last |
| `answer` | the person's answer: `given` (`expected` or `seen`), `via` (`app`, `agent`, `command`, or `unknown` for one given before this was kept), `given_at`, `reason_text` with the secrets Immune recognises cut out, each a mark (see [Secrets](#secrets-in-what-immune-keeps-and-prints)), `until_at` for `expected`, and `in_force`, whether it hides the finding now. Absent when there is none, including after it was taken back |
| `evidence` | one key, the kind of finding, holding what it rests on beside the journal |
| `rests_on` | the journal entries it rests on, oldest first: `seq`, `recorded_at`, `run_id`, `entry`, `reader`, `kind`, `predicate`, `subject_text`, and the value before and after, `old_value_text` and `new_value_text` |
| `answers_note` | when an agent may answer a finding, the same words as in `immune status --json` and the usage |
| `verdicts` | for a finding of the core, the verdicts that name it, and the `verdict.suspicious` finding of the same rule and thing when one is open or expected; for a `verdict.suspicious` finding, the verdicts of this occurrence. `total`, `suspicious`, and `listed`: the first and the latest 20 at most, oldest first |

The kinds of evidence, by rule:

| Key | Rules | Holds |
|---|---|---|
| `place_changed` | `watched.*`, `autorun.*` | `change`: `new`, `changed`, `gone`, `first_read` or `not_read`. The digests before and after are in `rests_on` as `has_content`, never the content. The `not_read` journal entry gives the reason in `new_value_text`. `presence_only` describes the last retained observation. True means it saw only that the entry was there. False means it read the content the reader checks. The field is null if the store has no such observation. It gives no coverage or freshness for a later reading. For `watched.first-read`, `rests_on` holds a `place_first_read` entry per place, with how many things it holds |
| `changed_in_place` | `integrity.*` | `became_text`: what an application's seal or signer became, as the reader wrote it; absent when what changed is a digest, which is in `rests_on` |
| `indicator_matched` | `indicator.match` | `indicators_text`: the indicators the file or the connection matches, as STIX comparisons |
| `detached_process` | `processes.detached-inline-code` | `pid` and `start_micros` of the process the latest sample saw; its program is `about_text`. Its command line is never kept |
| `vulnerable_package` | `lockfiles.*` | `project_text`, `ecosystem`, `package_text`; `releases`, each `version_text` with `at_text`, the lockfile line; `records`, each with `id_text`, `aliases_text`, `source`, `label`, `exploited`, `summary_text` and `fixed_text`. All are from the answers that stand now, so a cleared finding has none |
| `verdict_given` | `verdict.suspicious` | `rule`, the rule its verdicts are about; `events`, for verdicts about matches, the events at those lines, newest first, five at most |
| `published_rule_matched` | `sigma:<id>`, `elastic:<id>` | `rule` as in `Matches`; `matches`, how many events it matched since it was raised; `events`, the latest five at most, newest first, each as `Matches` gives an event; `source` and `licence`. A finding a verdict raised has the same evidence, and rests on the journal entry `verdict` |

Text from the Mac or a source is given whole, escaped as in every answer of the contract, except for secrets cut out of an event's arguments (see [Secrets](#secrets-in-what-immune-keeps-and-prints)). A store with no table of findings, which an older build can leave, fails as a store written by an older build, with exit code 3, so an empty list always means that the store holds no finding. An id the store has no finding for is refused with `unknown_finding` and exit code 2.

`immune finding <id> expected`, `seen` and `reopen` answer with `Finding`, the finding as the answer left it, in the form asked.

#### One answer for a pair

A rule's finding on this Mac can have a second finding beside it: the response layer's `verdict.suspicious` finding of that rule about the same thing (see [`immune verdict`](#immune-verdict)). `--with <id>` gives one answer to both. It names the other finding of the pair. For a finding of the core that is the `verdict.suspicious` finding of its rule about the same thing, which its `verdicts.verdict_finding` names while one is open or expected. For a `verdict.suspicious` finding it is the core's finding of that rule and thing. The caller always names it. An answer never reaches a finding the command did not name, and a linked finding is never answered by default.

The pair is checked by rule and thing, not by occurrence. Any occurrence of the other finding passes that check, and each answer then refuses a finding it cannot answer: `seen` and `expected` one that is not open or expected, `reopen` one with no answer. An occurrence the command did not name is never changed.

The two answers are one transaction: both are recorded or neither is. Each finding keeps its own answer with the same kind, reason, `--days`, `--via` and time, as if it had been answered alone, so the status, `immune finding`, the pages and taking an answer back all read two ordinary answers. The journal records an entry for each, under one run id. `reopen --with` takes both answers back in the same way, and `reopen` without it takes back only the finding it names. The answer is the `Finding` named first, with `answered_with`, the other finding's reference and its state after the answer (since 1.9.0). It is read in the same transaction before the commit, so a command that is refused has recorded nothing. A third finding about the same thing, of another rule or another occurrence, is never touched. A finding of a rule this build does not have is left out of every answer, and an answer to it is refused as one the store does not hold, with or without `--with`.

A later verdict is not answered in advance. After `seen`, the next `suspicious` verdict about the same rule and thing raises the next occurrence of the response layer's finding, open and urgent by the ordinary rule. After `expected`, that finding stays expected until the mark ends.

An answer is tied to what the caller read, as an HTTP request is with `If-Match`. `Finding`, `Findings` and `Status` carry `journal_seq`, the journal's latest sequence number in the state of the store the answer was read from (since 1.9.0). `--journal-seq <n>` passes it back. The answer is refused with `changed_since_read` when, after that entry, one of these joined a finding it answers: a match of its published rule; a newer reading it rests on, as when a lockfile's finding is found again with newer data; a verdict that went to it, raised it or names it; an answer given to it or taken back; its clearing; or the end of an `expected` mark once a check records it, which the clock alone does not. A rule's finding shows the response layer's `verdict.suspicious` finding of its rule about the same thing inside its own message (`verdicts.verdict_finding`), so the same check covers that finding too, one raised after the read included, and `detail_text` then names it. Nothing else refuses: a newer occurrence of the same rule does not refuse taking back an older one's answer, which quiets nothing. Each of these writes a journal entry in the transaction that makes it, and the journal's numbers only grow, so the check goes by when the store learned of a thing, not when it happened, and misses nothing recorded after the read. Every reading in which a published rule matches writes a `matched` entry with the rule, and the check finds the later ones by the rule; the finding still rests on the one that raised it. What refuses depends on the answer. `seen` says the person looked at what is there, so anything that joined since refuses it. `expected` says more of this is expected, and by its meaning already quiets every later match of the rule until the mark ends. A match of the finding's own rule between the read and the answer is no different from one a second after it, so it does not refuse `expected`. A verdict is another party's statement about the thing and still refuses it, as does everything else in the list. `reopen` is checked as `seen` is. So a finding of a rule that keeps matching can always be marked expected, while `seen` may keep being refused for as long as it matches. One number covers every finding in the store. When the two findings were read in two answers, pass the smaller `journal_seq`. `--journal-seq` is required on `seen` and `expected` given with `--with` or with `--via agent`. From the command line without `--via` and with `--via app` it is optional, and honoured when given. `reopen` needs none, since taking an answer back quiets nothing, but honours one given.

Nothing is recorded when the command is refused. A refusal about the finding named by `--with` quotes its id in `detail_text`:

| Code | Exit | When |
|---|---|---|
| `not_the_pair` | 2 | the finding named by `--with` is not the other finding of the pair: it is of another rule, about another thing, or the same finding twice |
| `unknown_finding` | 2 | the store has no finding with that id that this build shows |
| `finding_closed` | 2 | either finding is not open or expected, so `seen` or `expected` has nothing to answer on it |
| `finding_not_answered` | 2 | either finding has no answer for `reopen` to take back |
| `changed_since_read` | 2 | something joined a finding after the read `--journal-seq` names; `detail_text` is the id of the first that changed. A match of the finding's own rule does not refuse `expected`. Read again, show the person what is new, and answer with the new `journal_seq` |
| `journal_seq_ahead` | 2 | `--journal-seq` names an entry the store's journal has not reached, so it was not read from this store |
| `usage` | 2 | `--with` or `--journal-seq` without an answer, given twice or empty, or `--with` on `seen` or `expected` without `--journal-seq` |

### `immune matches`

The response layer looks into what the core is not sure of. `immune matches` gives it every match of every published rule, of every level and with none, each with the event it matched, in the order of the log; events that matched no rule are left out. The store keeps no event and no match, so the command reads the collector's log again and evaluates each event with the same code the core's own reading uses: the two never disagree about what matched.

The caller keeps its place. Each answer prints one in `continue_after`, and `--after` takes it back to read on from there; without `--after` the answer starts at the oldest line kept. A place is the core's own words: a string of lower-case hexadecimal that a reader stores and passes back whole, and never parses or compares. It holds what the core's own reading keeps for itself: for each log file, its identity (the run and start its name gives, or an earlier collector's hour, and its inode), how far it was read, and whether it was over when it was read to its end, together with the last number `eslogger` gave each kind of event and the filter's markers no gap has taken in yet. A place for a day of 25 files is about 730 characters. `--after` takes this build's places and those of the builds before it, which also held what the lines read said of each group of fields, ignored now, or named files by the hour alone, checked character by character and number by number, and refuses anything else as a misuse with exit code 2. A place names no path: a file is only ever looked up among the files the log folder lists.

Reading on from a place works the way the core's own reading works. A file the place holds, with the same inode, is read on from where the place left it. Any other file is read from its start, whatever its name: one the place does not hold, one of the same name with another inode, and one shorter than the place's offset. A file the place holds that is gone or was replaced had lines the place did not read when the collector's note of its deletion says it held more, or, with no note, when the place had not read it to the end once it was over, that is once a later file had been written to. The answer then says `gone`. Nothing is skipped without the answer saying so. An event may be given twice, after a file was replaced, and is never missed. This holds for a clock set ahead and back, a reinstall within one hour, and a file deleted before it was read.

| Field | Holds |
|---|---|
| `matches` | each match with `position`, `rule` (`name`, `file`, `id_text`, `title_text`, `level`, `techniques_text`, `author_text`, `source`, `set`), `event`, `raised`, `findings` and `verdicts`, the response layer's verdicts about that match, counted and listed as for a finding. After the findings the core's reading recorded, `findings` names the `verdict.suspicious` finding of the latest `suspicious` verdict about the match. A match is named by its position and its rule's `name`, its set and its id, `sigma:<id>`, `elastic:<id>` or `elastic-behaviour:<id>`, the same in every command, which a finding of a set that raises carries; `source` and `set` give the set by name and in words; `file` is the path under that set's folder, `rules/sigma/`, `rules/elastic/` or `rules/elastic-behaviour/`. `level` is `not_stated` for a rule whose set states none, Elastic's behaviour rules: a value that is not a severity. A reader built before it was added reads it as a value it does not know, so as the highest level; a rule's level never decides whether the core raised a finding, which `raised` says. A position is an opaque reference to the event's line that includes the log file's inode, so it is never given to another line. Positions are not ordered as text: matches come in the order of the log |
| `event` | one key, the event's kind, holding the event: `program_start` or `file_event`. A program start has `happened_at` with `happened_nanos`, `process` (the process started: `executable_text`, `pid`, `user_id`, `signing_id_text`, `team_id_text`, `platform_binary`, `pid_version`, `started_at` with `started_nanos`, `codesigning_flags`), `instigator` (the same process before the `exec`: its `executable_text`, `pid`, `pid_version`, `started_at` with `started_nanos` and `codesigning_flags`), `parent_pid`, `parent` (the parent's `pid` and `pid_version` from its audit token), `args_text`, `working_directory_text`, `script_text`, the script an interpreter was started on, and `cuts`, what was cut out of `args_text`, each `argument`, `kind` and `length`. A file event has the time, `action` (`create` or `rename`), `path_text`, `source_text` for a rename, and `instigator`, the process that did it: its `executable_text`, `pid`, `pid_version`, `started_at` with `started_nanos`, and `signing_id_text`. A pid with its `pid_version` names one process while the Mac runs; `started_at` tells two apart across a restart. What a line does not carry is absent, as on every line an earlier collector wrote. A kind a reader does not know reads as no event |
| `raised` | `below_high` for a rule below high, which raises nothing; `level_not_stated` for a rule whose set states no level, which raises nothing by itself; `finding` with the finding in `findings`, as the core's own reading recorded it, with the finding's state now; `not_read_yet` when the core's own reading has not reached the line; `no_finding` when it read the line and no finding holds the match, as a build without the rule leaves it; `unrecorded` when it read the line before the store kept which finding each match went to |
| `continue_after`, `more` | the place to pass as `--after` next; and whether whole lines are left that the limit stopped short of. There is no place when the collector is not installed |
| `stretch` | what was read after `after`: program starts and file events evaluated, other messages, lines and file events that could not be read, program starts and file events missing from `eslogger`'s numbering, and restarts of the numbering, each a loss of unknown size. `gone` says that lines the place had not read were deleted, or their file replaced, before they were read. `kept_from` is then the position of the first line of the first file kept at or after the hour of those lines |
| `collector` | `state` judged from the log when the answer was made, by the same rule as the core's reading, which speaks for the stretch just read; what `eslogger` or the scripts printed when it is `refused` or `failing`; when the log was last written; whether file events are collected; what the core's latest reading stored of each group of fields this version reads, at `status_read_at`, from the lines of the log file being written (`identity`, `script`, `signature`), in five lists: `not_kept`, the latest line of a kind lacks its key, so the collector installed here is an earlier one; `kept_never_filled`, lines carry its key and none a value yet; `not_yet_known`, no line that would carry it has been read; `arriving`, each with `name` and `since`, the time of the first line that gave it a value; and `no_longer_arriving`, each with `name` and `since`, the time of the first of the lines in a row that gave it none, one line for a field every process has and 1,000 program starts for `script` (see [event-level.md](event-level.md#the-states-it-reports)); `status_state` with `status_read_at`, the state `immune status` serves from the core's own latest reading, which speaks for its findings and for `raised`; and `foreign_files`, the files in the log folder that are not the collector's |
| `unevaluated` | the shipped rules that judge nothing here or only part of what they mean, by file, `name`, and its set in `source` and `set`, with the reason: `needs_events`, `needs_fields`, `keyword_search`, `not_parsed`, `in_part`, or `not_collected` for the rules for file events while the collector is not installed or does not record them, and for a rule that reads a group of fields that does not arrive, or that some line of this answer did not give, with those fields in `fields_text` and in `detail_text` which state the core's latest reading stored, or that the lines of this answer did not carry it. A line did not give a group when it lacks the group's key, as an earlier collector's lines do, so the rule was not asked about it; for `identity` and `signature`, which every process has, also when it carries the key with no value. Most program starts run no script, so a start with the script's key and no value is not counted. Every one of Elastic's detection and behaviour rules for macOS that the translation did not take is here too, by its upstream file and `name`, with the translation's reason, `sequence`, `not_eql`, `needs_events`, `needs_fields`, `backslash_in_wildcard`, `spans_kinds`, `never_true`, `regex`, `unsupported` or `function`, and what the translation said of it in `detail_text`. For a translated rule `in_part`, `fields_text` holds the fields its left-out alternatives need and `detail_text` any pattern the translation could not carry |

An answer with no matches says that nothing matched only when `collector.state` is `running`, the stretch shows nothing lost, unreadable or gone, `collector.file_events_collected` is true, and no rule the reader cares about is in `unevaluated`. Quiet rests on `unevaluated`, which covers the lines the answer read, and not on the lists of what arrives in `collector`, which are the core's latest reading and may be older than those lines. A group that only some lines fill by nature, as `script` is, is judged by the core's latest reading alone: one start without a script cannot tell a program that runs none from a field the collector stopped filling. After the collector stops filling such a group, an answer over lines the core has not read yet can stay quiet until the core's reading has counted the group's bound, 1,000 program starts for `script`, and for as long as the core does not read at all. No shipped rule reads such a group. A rule listed `in_part` is evaluated, so a match of it is a match, but the absence of one says nothing about the alternatives that need the fields in its `fields_text`. The values of `raised`, `collector.state`, `unevaluated.reason`, `action` and a rule's `level`, and the kinds of event, will grow within version 1. A reader treats a value it does not know as something it cannot judge, and a rule's level it does not know as the highest, which never says whether a finding was raised.

Which finding a high match went to is recorded when the core's own reading reads the line: the line's file, inode and offset, the rule and the finding. Only matches of rules marked high or critical are recorded, since only they raise a finding. A row goes when its log file is no longer there. `not_read_yet` is not a promise: a line deleted before the core's reading reaches it is never read, and no finding holds it. For `not_read_yet`, `no_finding` and `unrecorded` the reader judges the match itself.

A gap in `eslogger`'s numbering at the seam between two answers is counted in the later one, from the last numbers the place holds. Without `--after`, the first event of each kind has nothing before it, as at the start of the log.

One answer holds at most `--limit` matches, 1,000 by default. It also stops once the lines it matched come to 4 MiB in the log, since one command line can be a megabyte. On an invented busy hour, 1,000 matches were 892 KB of JSON and 398 KB of binary protobuf; twenty matched starts with half a megabyte of arguments each stopped at 8, about 4.2 MB of JSON.

Text in an event is given whole, except for the secrets cut out of its arguments, which `cuts` lists (see [Secrets](#secrets-in-what-immune-keeps-and-prints)). No path is cut, each argument is a string of its own, and hidden characters are escaped as elsewhere. The environment is not in the log and not in the answer. On a Mac without the collector, the answer has no matches, the state `not_installed` and the rules for file events in `unevaluated`, and the command exits with 0. Without a store, or with one that cannot be read, the command fails with `store_unreadable` and exit code 3, as the other commands of the contract do: without the store it cannot say what became of a match. A log that cannot be read is a failure with the code `log_unreadable` and exit code 1. Every failure is the message `Failure`, so a reader that takes it for a `Matches` reads format 0 and stops.

The core cannot give these today: the parent's start time, which `eslogger` does not give in an `exec` message, so `parent` is the pid and pid version alone; and how many lines a deleted file held, so `gone` says only that lines are gone.

### `immune verdict`

The response layer looks into a match or a finding and gives the core a verdict: `suspicious`, a person should see it, or `harmless`. `immune verdict` reads exactly one `Verdict` on standard input, binary protobuf with `--proto` and JSON with `--json`, records it, and prints `VerdictRecorded` in the same form. Standard input that is a terminal is refused: the command asks nothing. A verdict over 65,536 bytes is refused, never cut. What this build does not read is refused in either form: a field the schema does not name, at the top or inside `match` or `finding`, a field given twice, or both `match` and `finding`. A binary verdict must be the encoding this build gives the same message.

| Field of `Verdict` | Holds |
|---|---|
| `format` | 1 |
| `store_id` | the `store_id` of the answer the response layer judged; another store's is refused |
| `match` or `finding` | what it is about: a match by `position` and `rule`, both as `immune matches` printed them, or a finding by `id` |
| `kind` | `suspicious` or `harmless` |
| `reason_text`, `case_text` | the response layer's reason, at most 1,000 Unicode scalar values, and its own reference to its case, at most 200. Each needs a visible character. Longer text is refused, never cut |
| `severity`, `confidence` | on the core's scale: required on a `suspicious` verdict and refused on a `harmless` one; a confidence is `low`, `medium` or `high` |

A verdict never writes into a finding the core raised: not its state, its occurrences, its evidence, when it was last seen, its levels or whether it is urgent.

A `suspicious` verdict is an event of one rule of Immune's own, `verdict.suspicious`, and raises a finding the way any rule that finds an event does. The finding is about the rule the verdict names (the match's rule, or the rule of the finding it names) and the thing that rule's findings are about on this Mac; in the store its rule is `verdict.suspicious:<that rule>`, and in every answer its `rule` is `verdict.suspicious`, its `kind` is `verdict of the response layer`, and `value_text` is the title of the rule it is about. A verdict about a finding and one about a match of the same rule and thing go to the same finding. Open, it stays open as more verdicts come; marked expected, it stays so until the mark ends; marked seen, the next `suspicious` verdict raises its next occurrence. The core never clears it: only the person closes it. Its severity and confidence are the highest any verdict of its occurrence gave, so they only go up, and it is urgent by the ordinary rule. For a verdict about a match, the core reads the line at the position again under `--system-root`, evaluates its event with the same code as its own reading, and the rule must have matched it; the finding keeps that event as a rule's finding keeps events.

A `harmless` verdict is a record: kept, shown beside what it is about, and nothing else.

The same message, equal in what it names, its kind, its reason, its case and both levels, is recorded once while the finding it went to is open, and a `harmless` one is recorded once; the second answer gives the first with `already_recorded` true. After the person answered that finding, the same message is the response layer saying it again and raises the next occurrence. Each verdict is an entry `verdict` in the journal.

Verdicts are not signed, as answers are not. Anyone who can run `immune verdict` as the person can send one, and the core cannot tell the response layer from another program doing so. A verdict about a match names a line of the log under the `--system-root` the command is given, as `immune run` reads the log under its own, and whoever can run Immune as the person can do either. That is why a verdict never writes into the core's findings.

`VerdictRecorded` has `format`, `answered_at`, `store_id`, `recorded` and `already_recorded`. A recorded verdict (`RecordedVerdict`) holds the `verdict` as sent, its text escaped as all text of the contract, `recorded_at`, `finding`, the `verdict.suspicious` finding a `suspicious` one was recorded in (absent for a `harmless` one), `raised`, whether it raised that occurrence, and `reason_cuts`, what was cut out of the reason because it held a secret, each piece with its `kind` and `length` (`argument` is 0). A reason is kept with its secrets cut, so two verdicts whose reasons differ only in a secret are the same message.

What is shown beside a finding is `Verdicts`: `total`, `suspicious`, `listed` and `verdict_finding`. An answer lists at most the first verdict and the latest 20, with the total. In `Findings`, a finding of the core lists none and names its `verdict.suspicious` finding when one is open or expected; a `verdict.suspicious` finding lists the verdict that raised its occurrence. In `immune status --json` an item carries `verdict`: for a finding of the core, `said` (the core's words, such as "2 verdicts from the response layer, 1 suspicious."), `total`, `suspicious` and `finding`, with no text of the response layer's; for a `verdict.suspicious` finding, `said`, then the raising verdict's `reason_text`, `case_text`, `at`, `severity` and `confidence`, and `more`, how many came after it. The text of `immune finding <id>`, the summary page and the app show the core's words first and the response layer's text after them, quoted and whole: a quote character inside it is escaped, and on the page the reason is a block of its own.

`immune status --json` cuts what needs a look per source, in the one order: up to 50 of the core's findings and up to 50 of the response layer's, so that neither source can push the other's findings out of the list. The text form shows the first rows and says how many more there are; `immune findings` lists every one.

A failure is the message `Failure`, in the form named. Without a form the command is refused as a misuse before it reads standard input. Nothing is recorded, and a refused verdict writes nothing to the store: a file that is not a store of this format is not made into one.

| Code | Exit | When |
|---|---|---|
| `usage` | 2 | no form is named, standard input is a terminal, or the command line is wrong |
| `too_large` | 2 | the verdict is over 65,536 bytes |
| `not_a_verdict` | 2 | it is not one `Verdict` of format 1 this build reads: it cannot be read, has a field the schema does not name or a field twice, names neither a match nor a finding or both, has no known kind, has a level that is not on the scale, lacks a level on a `suspicious` verdict, or has one on a `harmless` verdict |
| `empty_reason`, `empty_case` | 2 | `reason_text` or `case_text` has no visible character |
| `reason_too_long`, `case_too_long` | 2 | `reason_text` is over 1,000 Unicode scalar values or `case_text` over 200 |
| `holds_secret` | 2 | a key of the verdict, `case_text`, `store_id` or what it names, holds a secret Immune recognises. `detail_text` names the field and never what it holds. A key is never rewritten: cut, it would name something else. A secret in `reason_text` is cut, never refused |
| `secrets_unchecked` | 1 | the patterns secrets are recognised by did not load, so the verdict cannot be checked |
| `another_store` | 2 | its `store_id` is not this store's |
| `unknown_finding` | 2 | the store has no finding with that id |
| `match_gone` | 2 | the log holds no line at that position: the file it names is not in the log, or another file has its name now |
| `no_such_match` | 2 | the position is not one `immune matches` prints, no event's line begins there, the rule is not shipped, or the event there did not match that rule |
| `log_unreadable` | 1 | the event log could not be read |
| `store_unreadable` | 3 | there is no store, it is not a store of this format, or it cannot be read or written |
| `run_in_progress` | 4 | a run or another writer holds the store; nothing was recorded, and the same verdict can be sent again. `immune finding <id> seen`, `expected` and `reopen` write the same way and fail with the same code |

## Secrets in what Immune keeps and prints

A command line can hold a token or a password, and what Immune keeps and prints reaches the person's agent, which may send it to a model in the cloud. So Immune cuts secrets out of the arguments of a program start before it keeps them as a finding's evidence and again each time it prints an event, in every command and every form. Rules are evaluated on the arguments as the log holds them, in memory, before anything is cut, so a cut never changes what a rule matches. Prose is cut the same way and never refused: what the collector printed (`said_text`), the reason a person or their agent gives with `immune finding <id> expected|seen --reason` or `immune owner … --reason`, and a verdict's `reason_text`. It is kept with its secrets cut, and the answer lists what was cut in `reason_cuts`, each piece with its `kind` and `length` (`argument` is 0), as every later answer that shows the reason does: `Answer`, `Statement` and `Said` since 1.7.0. Cutting always runs, so an empty list means nothing was cut. A value that is a key, such as a verdict's `case_text`, is never rewritten: one that holds a secret is refused. A failure's `message` is Immune's own words and never repeats what it was asked. What it repeats goes in `detail_text`: an argument, a name asked for, a path, a key or a value sent. That field is cut where it is printed, in every form and for every command. An answer that repeats the question cuts it too, in `asked_text` and `id_text`. Paths, the working directory and the script are not searched.

What is recognised:

- gitleaks's published patterns, `config/gitleaks.toml` at commit `5f6ec56cfa6f`, in `rules/secrets/gitleaks/` with its NOTICE: the 217 rules not bound to a file, with their keywords, secret group, entropy threshold and allowlists. Three example values in the allowlists are left out, so no key-shaped string stands in the repository; the NOTICE names them, and without them more is cut. Not taken: the `gitleaks:allow` comment, the decoding passes and the path allowlists.
- The value of a flag or key whose name says it is a secret, from Datadog's word list (`*password*`, `*passwd*`, `*mysql_pwd*`, `*access_token*`, `*auth_token*`, `*api_key*`, `*apikey*`, `*secret*`, `*credentials*`, `stripetoken`) and three words of Immune's own (`token`, `pass`, `passphrase`), whatever its length or entropy. In a name `-`, `_` and `.` are the same character and case does not count. A word without `*` matches the whole name or its last part, so `--password`, `DB_PASSWORD=`, `db.password=` and `--github-token` all match. A name is read at the start of a word and after every `=`, `:`, `&` or `?` in it, so `--from-literal=password=`, `user=a&password=` and `?access_token=` are found too. The value comes after `=` or `:`, whatever it begins with, or as the next word or argument after a flag that has neither, where a word that begins with `-` is the next flag and never taken.
- A password in a URL, by detect-secrets' `BasicAuthDetector`, with an empty user as in `redis://:<password>@host`, up to the last `@` before the host.
- Two forms of Immune's own: an `Authorization` or `Proxy-Authorization` header without quotes, as `eslogger` gives an argument, and a MySQL or MariaDB client's password joined to `-p`.

Where a value ends is decided the same way for every form of Immune's own (a flag's value, an `Authorization` header, `-p`), and when unsure more is cut. When the name begins its argument, as `--password=<value>` or `DB_PASSWORD=<value>` does, the value runs to the end of that argument, spaces and all. When it stands inside a longer text, such as an `sh -c` string, the value is one shell word: quotes and backslash escapes are followed. Names are read from the same words, with their quotes taken off, so `"--password" <value>` and `'--password=<value>'` are found. From the first thing the reader does not follow exactly, no word ends before the end of the argument, and every value after it runs there: a backslash before a character no shell needs escaped, a quote never closed, and in or out of quotes a backtick, `$(`, `${`, `$[`, `$'`, `<(` and `>(`.

A mark is read the same way in every text that is cut: one Immune made, and one a source quotes from what Immune printed, of a kind the patterns cut, bare or with its backslash doubled as JSON writes it. A mark is a value already cut, one piece of a word and never part of a name. It covers only its own bytes and never changes how any other byte is read: the patterns read the text around it once as if the mark were a space and once as if it were not there, and both readings' cuts are taken, so a token glued to a mark is found as it would be beside a space. A value that begins with a mark ends where a real value would: at the end of the argument when its name begins the argument, otherwise at the end of its shell word. Only a value that is the mark alone, with the quotes and closers that end its word, is not cut; anything else in its reach is cut as a real value's would be. `,`, `]` and `}` end no word. A mark a source quoted is kept and shown as the source's text, with its backslash written `\u{5c}`, so it never reads back as one Immune made. A mark of a kind the patterns do not cut is ordinary text. A kind is exempt in the same way, and only where Immune prints it in a list of cuts, as `"kind":"detect-secrets:basic-auth"`; anywhere else, as in `detect-secrets:basic-auth=<value>`, it is read like any other word.

To quote Immune's output in a reason and keep its words, quote it as the text form prints it, or leave a space after each cut value. A mark glued to more text in the same word, as in compact JSON (`"--token \cut{immune:flag-value 11}"],"cuts":`), is read as the start of a value that goes on, and the rest of that word is cut as it would be after a real value. The reason is still recorded, every mark it quoted is kept, and `reason_cuts` lists what was cut.

The lists are data in `rules/secrets/`. Only the secret is replaced, never the program, the flag, the key or the delimiter around it. A cut stays inside one argument, so the arguments keep their count. In the text each cut is a mark, `\cut{<kind> <length>}`: the kind (`gitleaks:<rule id>`, `immune:flag-value`, `detect-secrets:basic-auth`, `immune:authorization`, `immune:mysql-password`) and the length in characters. In the contract a backslash from the source is written `\u{5c}`, so a mark begins with the one bare backslash no source can write. Every printed program start also has `cuts`, one entry per piece cut with its `argument`, `kind` and `length`. That list is what a reader goes by. In the report's JSON, which does not escape a backslash, evidence carries the same `cuts`.

Arguments longer than 64 KiB together are not searched and are withheld whole, each with the kind `immune:too-long`. gitleaks's generic rule compares an allowlist with the whole line for every match, so a line with no newline packed with matches costs the square of its length. Measured in a release build on a loaded machine, such a line of 64 KiB took 29 ms and one of 1 MiB, the most a command line can be, 6.9 s. If the patterns do not load whole (`command-line.json` or gitleaks's file differs from `rules/secrets/SHA256SUMS`, a rule holds a key this build does not read, a pattern does not compile, or a planted invented secret checked at every load is not cut), every argument is withheld whole with the kind `immune:no-patterns` and nothing is printed as it was. A verdict's reason that holds a recognised secret is kept with it cut, and the verdict is recorded; a key of a verdict that holds one is refused (`holds_secret`). A verdict that quotes what Immune printed is always taken, and keeps its words when quoted as above.

What Immune cannot recognise, so it may print it:

- a secret in a path or a working directory;
- a short flag whose meaning depends on the program, such as `sshpass -p x`, `docker login -p x` or `security add-generic-password -w x`, and a program name in capitals before `-p`, such as `MySQL -px`;
- a secret given alone as an argument, such as `ngrok config add-authtoken x` or an AWS secret key, when no pattern knows its shape;
- a value that begins with `-`, such as `--password -x`;
- a header other than `Authorization` whose name holds none of the words, and a bearer token in a form other than a header;
- a name that runs into other text with no boundary of those above, such as npm's `//registry/:_authToken=x`, where `authtoken` is not a word, or `/token=x`, where the name holds a `/`;
- a name written with a character outside ASCII, such as a non-breaking hyphen, or a value after a non-breaking space;
- a secret in a JSON body, such as `-d '{"password":"x"}'`;
- anything inside an encoded value.

A false cut costs only evidence text, since rules see the original.

A store an earlier build kept, of format 4, is cleaned once, by the first build that opens it to write: the arguments of its evidence, what the collector printed, the text of verdicts, and the reasons of answers and of statements about machines, in their rows and in the journal. The cleaning raises the store to format 5, which a build of format 4 refuses as newer, so no earlier build writes uncut text into a cleaned store. Content it overwrites is zeroed, the file is rebuilt with SQLite's `VACUUM`, and the rollback journal is deleted on commit, so no old byte stays in the store's file. The pages made from the store are removed and made again by the next `immune view`. Until then, a command that only reads such a store cuts what it prints all the same: one list of the kinds of kept text that may hold a secret serves both the cleaning and every command that reads them. The store keeps that text with a backslash from the source written `\u{5c}`, as the contract writes it, so a mark is read only where Immune made one, and a mark spelled out by a source is text, cut like any other. Backups and snapshots made before the cleaning, and the collector's own log, are outside it: the log keeps every command line as `eslogger` gave it for up to a day ([event-level.md](event-level.md#who-can-read-the-log)).

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

The store keeps every reading of the 20 runs the changes page lists and of the latest finished run. Of older ones it keeps the first and the last of each run of unchanged readings ([how-it-works.md](how-it-works.md#coverage)). A watcher's reading of the places one change touched keeps its raw copy as `watched-places-touched.txt`, apart from the copy of a reading of every place.

The collector keeps its own files under `/Library/Application Support/ai.nuanu.immune/event-level`. The app keeps its notification settings under the defaults domain `ai.nuanu.immune`.

## Updating and removing

To update, run `git pull`, quit the app from the ⋯ menu of its panel, run `./build` and open the app again. `./build` refuses to run while the app is open.

To remove Immune, quit it, delete `Immune.app` and its data folder, `~/Library/Application Support/ai.nuanu.immune`, and run `defaults delete ai.nuanu.immune` to clear what it remembers about notifications. If the collector is installed, `sudo /bin/sh scripts/event-level/uninstall` removes it with its logs (see [event-level.md](event-level.md)).
