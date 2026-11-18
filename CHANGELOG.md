# Changelog

What changed in Immune that a person who runs it, their agent or a program built on its commands would notice. Everything else is in the Git history.

Immune has no numbered release yet. Entries go by the day a change reached `main`, newest first, and each day names the commit `main` ended on, so a program that pins the core by commit can find its place. Two numbers move on their own: the version of the contract, which is the version of the crate `immune-contract`, and the format of the store. A build refuses a store of another format and says how to start over.

## Unreleased

### Changed

- The pages `immune view` writes list what Immune reads. What this version has no reader for is no longer on them: folders macOS protects, files that run code by themselves and are only known by name, lockfiles of other kinds, published rules it cannot check. It stays in [docs/reference.md](docs/reference.md), in `immune status --json` and in `immune rules --all`.
- A reading that failed on this Mac is still on the pages. The section "Not judged on this Mac" is now "Could not be read on this Mac". It holds the readings and downloads that failed and is there only while one did. The summary's line and the section page `limits` lead to it.
- What is said of projects speaks of the projects found, and the page says where projects are looked for.
- The rules page lists the rules that are checked, in full or in part. What a rule checked in part goes without is in that rule's details.

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

- `immune on` stages nothing in a place Immune watches (#59).
- A full check is said to be running from its start, its downloads included, and a check that was killed never reads as running while the next one starts (#60, #61).
- A past gap in the collector's log holds this Mac at "watched in part" until the next full check, where it used to hold it for a day (#64).

## 2026-11-16

`main` at `e78c379`.

### Added

- `immune on` and `immune off` turn the background checks on and off, and turning them off leaves a trace (#56, #58).
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
- A folder for Immune's own Sigma rules, `rules/immune/` (#39).
- An event carries the responsible process, the process group, the real user and group ids, and who signed the process that acted (#41, #43).

### Fixed

- A finding the store holds is always shown, also when this version has no rule for it (#38).
- A command that only reads the store answers after a writer was killed (#30).

## 2026-11-13

`main` at `33a61fa`.

### Added

- `immune verdict` takes the response layer's verdict, which completes version 1 of the contract (#17).
- The contract's types are a crate, `immune-contract` (#11).
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
- The contract's first messages: `immune project`, `immune program`, `immune machine`, `immune matches`, `immune findings` and `immune finding <id>` (#1, #3, #4, #7).
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
