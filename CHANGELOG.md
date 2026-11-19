# Changelog

What changed in Immunity Core that a person who runs it, their agent or a program built on its commands would notice. Everything else is in the Git history.

Immunity Core has no numbered release yet. Entries go by the day a change reached `main`, newest first, and each day names the commit `main` ended on, so a program that pins the core by commit can find its place. Two numbers move on their own: the version of the contract, which is the version of the crate `immunity-contract`, and the format of the store. A build refuses a store of another format and says how to start over.

## Unreleased

### Added

- Projects are also found by the working folders in the sessions of Claude Code's subagents, which it keeps in folders below a project's folder in `~/.claude/projects`, such as `<session>/subagents/agent-<id>.jsonl`. A subagent that works in a worktree of its own, in a hidden folder the search for projects does not enter, states it only there; until now such a project was not found. At most 50,000 folders below the projects' folders are listed; past that the reading of `agent-folders` is partial with the cause `no_reader`.
- Projects are also found by the working folders in Codex CLI's sessions, in `~/.codex/sessions` and `~/.codex/archived_sessions`, read the way Claude Code's are. A session Codex CLI has compressed with zstd, to `.jsonl.zst`, is decoded and read too, once while it is unchanged. One that cannot be decoded is a session file that could not be read, and the reading of `agent-folders` is partial.
- When Gemini CLI, Continue or GitHub Copilot CLI keeps sessions in the home folder, the reading of `agent-folders` is partial with the cause `no_reader` and names that agent in `immunity status`, under `no_reader_for` and in the item `not-understood`. Their sessions are not read. Until now the reading was full, and what was said of the projects as a whole spoke for every project although these agents' working folders were never looked at. It now speaks of the projects found, with the reason.

### Changed

- A session file of Claude Code or Codex CLI that is a link is no longer followed: it is a session file that could not be read, and the reading of `agent-folders` is partial. A named pipe in its place no longer holds the reading. A line of a session longer than 64 MiB is counted as a line that could not be parsed, and the lines after it are read; until now it was held whole and parsed.
- The project is now Immunity Core. Build package `immunity-core` to run `immunity`. The contract crate is `immunity-contract` 1.21.1 and the protobuf package is `immunity.v1`. Message format and field numbers stay at their previous values. The core's own rule set is named `immunity` and its redaction kinds begin with `immunity:`.
- The service and collector use the `ai.nuanu.immunity.core` namespace. This build starts a fresh format 9 store. See [updating and removing](docs/reference.md#updating-and-removing) before updating a running installation.

- The pages `immunity view` writes list what Immunity Core reads. What this version has no reader for is no longer on them: folders macOS protects, files that run code by themselves and are only known by name, lockfiles of other kinds, published rules it cannot check. It stays in [docs/reference.md](docs/reference.md), in `immunity status --json` and in `immunity rules --all`.
- A reading that failed on this Mac is still on the pages. The section "Not judged on this Mac" is now "Could not be read on this Mac". It holds the readings and downloads that failed and is there only while one did. The summary's line and the section page `limits` lead to it.
- What is said of projects speaks of the projects found, and the page says where projects are looked for.
- The rules page lists the rules that are checked, in full or in part. What a rule checked in part goes without is in that rule's details.
- `permissions.allow` in a project's `.claude/settings.local.json` has a rule of its own, `autorun.agent-allowed`, at medium severity and low confidence, so a change to it is not urgent. Claude Code writes an entry there itself each time its user chooses not to be asked again, and each one used to raise an urgent `autorun.agent-start`. This holds only while the value is a list of strings, and only for a change of the list. Any other value there still raises `autorun.agent-start`, and so does a change of where the file leads, such as the file replaced by a link. The other keys of that file, every key of the shared `.claude/settings.json` and the settings in the home folder are judged as before. What is watched on this Mac lists the new kind as "tools your coding agent may use in a project without asking". A store that already holds such an entry moves it to the new kind and raises nothing for it.

### Fixed

- When no project's lockfiles were fully compared with current OSV data and no matches were found, the OSV summary in `immunity status --coverage` and the run report says why. If the store knows of projects, `immunity status` and `immunity run` say their exposure is unknown.
- A project counts as fully compared when the store can establish that a supported lockfile was read and OSV data is current for every applicable ecosystem. A full reading with no package facts can count when both feeds are current. With partial coverage, a report of zero matches applies only to what could be compared.
- A way a project runs code by itself, or a place in the home folder, that has more than one file is named by each of its files where it is not read: Gemini CLI's is `.env` and `.gemini/.env` in `examples_text` of `project-autorun`, in the report of a check and in `immunity status`. Until now its files came as one name, which the report showed as `.env\u{2c} .gemini/.env` and `immunity status --coverage` as one quoted item. These two items now list every name of every way present, as `package-managers-not-read` does, and `count` still counts ways. The comment on `examples_text` in the schema says so; the contract crate is 1.21.3.
- `immunity project` takes a path relative to the folder it is started in, so `immunity project .` answers for the project an agent stands in. It used to exit 2. A word is an id when what comes before its first colon is a type of id the store knows, such as `checkout` or `file`; any other word, `x:y` among them, is a path. `immunity program` still takes a bare word as a program's name.
- The search for projects no longer goes into a folder on another file system than the one it starts on, as `find -xdev` does not. Such a folder is often a container tool's view of its containers, a mounted disk image or a network share; the search used to walk into them, so a container's projects were held as this Mac's and their parts raised urgent findings. The reading of `checkouts` is then partial with the cause `not_given` and names the folder ("on another file system, not walked: …"), as it is for a walk of a given folder, so the status and the answers about projects say not every project was found. Such a folder may hold your own work: a project there is found when a coding agent works in it, or when `--checkouts-root` points into it. A project already found there stays as it was while its folder is there. A folder, or the folder the search starts from, whose device cannot be read is not entered and is named among the folders that could not be listed.
- Matches of the indicator list are now decided file by file. A check that did not read a lockfile or a task file keeps what that file matched when it names the file, or the project the file is in, as not read: the file could not be read or looked at, the lockfile was found and not opened, a folder of the project could not be listed, or the project is held and was not looked into. Until now such a match went while its finding stayed open, and the reading `indicators matched against watched files and texts read in checkouts` said it was full. That reading now names each of these, and the walk for projects when it failed, and is partial with the worst cause. A file the check could have read and found no text in, such as a lockfile replaced by a folder, loses its match. A hash match follows the checksums read in the check, so a watched file that changed loses its match, and its old bytes coming back open a new finding. A file read through an outer project decides its own matches. An indicator taken off the list goes even when its file could not be read.
- The watcher starts on a Mac with more watched places than one FSEvents stream takes. A stream takes 4096 paths, and a Mac with many projects has had more since Git and pnpm hooks are watched in each (#67, #72): `immunity watch` then stopped with `watch_failed`, "FSEvents could not start the stream", each time it started. It now starts as many streams as the places need. A path longer than FSEvents takes, 1023 bytes, used to stop the watcher the same way; it is now refused alone and named as a problem, and the rest are watched.
- `immunity status` no longer says this Mac is watched live while the watcher could not subscribe to a watched place. Such a place was only a `place_not_watched` line on the watcher's output, which goes nowhere under launchd. It is now the watcher failure `places`. The watcher looks at what to watch every minute. While its latest look leaves places unwatched, its lock file says so, and the status goes by that, whatever the store holds. The store says how many places and the first three with why, from the watcher's next use of the store. The failure ends after a look that leaves none, once the watcher has cleared it from the store. The text and the page say the watcher's latest "subscription to some watched places failed". A place whose folder cannot be there now, with a file, a link that leads nowhere or a link in a loop on the way, or a name longer than a file's name can be, is not a failure; it is noticed at the watcher's next look and at the full check, not within seconds. The contract goes to 1.21.2 for the comment that names the kind.

## 2026-11-18

`main` at `b3f3558`. Contract 1.21.0, store format 8.

### Added

- Git hooks are watched in the folder `core.hooksPath` names, as well as in `.git/hooks`. This covers projects that keep their hooks with husky (#72).
- pnpm install hooks in project roots are watched (#67).

### Fixed

- A configured hook folder read for the first time is taken as the baseline, and a hook already watched in another project is not told as new (#75).
- A project found before is closed only where the walk looked (#73).
- Answers about vulnerabilities, and what is said of files that run by themselves in projects, name the projects found when not every project was (#69, #74).
- The background job names the app the core is shipped in (#68).

## 2026-11-17

`main` at `a3f4ac3`.

### Added

- The collector's install can be run by an installer package, and leaves its removal script on the Mac (#63).
- A technique's square in the report says what the technique is (#65).

### Fixed

- `on` stages nothing in a place the core watches (#59).
- A full check is said to be running from its start, its downloads included, and a check that was killed never reads as running while the next one starts (#60, #61).
- A past gap in the collector's log holds this Mac at "watched in part" until the next full check, where it used to hold it for a day (#64).

## 2026-11-16

`main` at `e78c379`.

### Added

- `on` and `off` turn the background checks on and off, and turning them off leaves a trace (#56, #58).
- Every command has a text form made for a terminal (#49, #54).
- A verdict carries an id, and a late `suspicious` one is kept (#50).
- The contract's crate has an example client that runs the core (#51).

### Changed

- The core runs in the background on its own. The menu-bar app is no longer in this repository (#46).

### Fixed

- An answer is about a unit the store holds, and says what it could not tell (#48).
- The lockfiles reader names the lockfiles it did not open (#53).
- A code folder the store holds is read while it is on disk (#52).

## 2026-11-14

`main` at `61de8cb`.

### Added

- Secrets are cut out of what the core keeps and prints (#25, #42, #44).
- Every command answers with one message of the schema (#26).
- The report page shows the state, the findings and what is watched at a glance (#32).
- One answer covers a finding and the response layer's finding about it (#34).
- A finding's row carries its own words: names and the title of its kind (#33).
- The places where code runs by itself are one table, each row with its published source and the macOS it was checked on. The status says which were not checked on the macOS of this Mac (#36, #39).
- A folder for the core's own Sigma rules (#39).
- An event carries the responsible process, the process group, the real user and group ids, and who signed the process that acted (#41, #43).

### Fixed

- A finding the store holds is always shown, also when this version has no rule for it (#38).
- A command that only reads the store answers after a writer was killed (#30).

## 2026-11-13

`main` at `33a61fa`.

### Added

- `verdict` takes the response layer's verdict, which completes version 1 of the contract (#17).
- The contract's types are available as a crate (#11).
- 57 of Elastic's behaviour rules for macOS are evaluated. They state no level (#13).
- Login hooks, PAM policies and modules, and authorization plugins are watched (#19).
- The collector keeps who each process is, and the cap of its log is set at install (#18).
- Agent sessions are read on from where the last reading stopped (#14).

### Changed

- The store stays small, and a check reads only what a change touched (#24).

### Fixed

- A first reading is a baseline, a change, or told once, decided for each file and listing (#15).
- What a Mac unlike the first one showed: Tailscale turned off, other package managers, blocked downloads (#16).
- A finding of a published rule names its set and its licence in words (#9).

## 2026-11-12

`main` at `cb143be`.

### Added

- Program starts, and files created and renamed, are collected with Apple's `eslogger` and read with their losses counted.
- SigmaHQ's rules for macOS are shipped unchanged and checked against every event. A match of a rule marked high is a finding.
- 66 of Elastic's detection rules for macOS are evaluated, translated into Sigma (#8).
- The contract's first messages: `project`, `program`, `machine`, `matches`, `findings` and `finding <id>` (#1, #3, #4, #7).
- The packages of a `pnpm-lock.yaml` are read and matched as npm's are.

### Fixed

- The first check of a Mac finds nothing in what was already there.
- No reader follows a link into a folder macOS asks permission for.
- A worktree of a known project raises nothing for what the project already holds (#2).
- The event log is a buffer of at most 500 MiB.

## 2026-11-11

`main` at `296934c`.

### Added

- The places where persistence lives are watched, and a change between two checks is a finding that stays open until the person answers it.
- The watcher: a change in a watched place is a finding within seconds, and running programs and their connections are sampled.
- Installed software changed in place is a finding.
- Files that make a tool run code when a project is opened are read, and indicators from an incident report are matched.
- Lockfile dependencies are matched against known vulnerabilities.
- A machine-readable status, and a skill for the person's agent.
- The person's agent can answer a finding after the person agreed, and the answer says it came through an agent.
- The HTML pages open on a summary.

## 2026-11-10

`main` at `762fd2a`.

### Added

- The first working whole: the store, the readers of Homebrew packages, servers and lockfiles, and a report.
- Projects and servers are found from traces on the Mac, and one machine known under several names is one machine.
- The person can state that a machine is retired or not theirs.
- CISA's catalogue of exploited vulnerabilities is read at every check.
