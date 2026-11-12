# How Immune works

Immune is one Rust program, `immune`, with SQLite compiled in, a menu-bar app that shows what the program returns, and an optional collector made of programs that macOS ships. This page describes how the parts fit: what Immune keeps, how a reading becomes a finding, and what a finding, a gap in coverage and an answer mean. [reference.md](reference.md) lists every reader, [threats.md](threats.md) covers vulnerabilities and indicators, and [event-level.md](event-level.md) covers the collector.

## The parts

```
Readers → Store → Rules and matchers → Findings → Store → Commands → App, agent, pages
```

- Readers look at one kind of source each: launch agents, shell profiles, lockfiles, installed applications, the SSH configuration, the collector's log, and so on. A reader writes statements about what it saw and a record of what it looked through.
- The store is one SQLite file, by default `~/Library/Application Support/ai.nuanu.immune/store.db`. Raw input the readers keep, the downloaded vulnerability data and the HTML pages live in the same folder.
- Rules and matchers read the store and write findings into it. Immune's own rules are plain Rust code. Published rules (SigmaHQ's rules for macOS) are shipped unchanged and evaluated by the `sigma-rust` crate. Matchers compare what the readers found with vulnerability data and indicator lists.
- Commands read the store and print what they find, as text or as one JSON envelope with `--json`. A command of the contract with the response layer prints one protobuf message instead, or the same message as JSON. The app, the user's AI agent and the HTML pages all read the same commands.

The store is the one seam between the parts. What a reader saw, what a rule found and what a person answered are all rows in it, and the commands, the app and the pages read nothing else. No other layer or interface sits between the parts. That keeps any one of them replaceable: a collector, for example, can be swapped for another that writes the same facts.

## When things run

A full check, `immune run`, runs every reader once and then every rule. While the app is open it runs one every hour. `immune watch`, which the app keeps running as its child, does the faster work:

- it reads the places where persistence lives about a second after FSEvents reports a change there;
- it samples the user's programs and their internet connections every 30 seconds (`--sample-every`);
- it reads the collector's log every 10 seconds (`--events-every`), when the collector is installed.

Each prints one JSON line per event. Only one watcher may hold a store, and a full check waits up to a minute for a watcher's reading to finish. When the app quits, all of this stops.

## Levels of access

What Immune can see depends on the rights it runs with.

| | Without administrator rights | Apple's `eslogger` as administrator | A signed app with Apple's Endpoint Security entitlement |
|---|---|---|---|
| Status | Built, the default | Built, optional (`scripts/event-level/install`) | Not built |
| Collects | State: files, installed software, lockfiles, configuration; file-system events in watched places; samples of the user's processes and connections | Also every program start with its arguments, and every file created or renamed with the program that did it | Also every connection with its host name |
| Detects | Immune's own rules over state, exact matches of indicators and vulnerabilities | Also the published Sigma rules for macOS | All published rules for macOS |
| Cannot see | The moment a program starts, its command line, who wrote a file | Connections. Apple does not promise `eslogger`'s output as an interface | |

## Entities

An entity is something the user has. Its id is built only from its type and a natural key, so two runs and two readers name the same thing the same way. The types are a closed list kept as rows in the store:

| Type | Natural key | Example id |
|---|---|---|
| `machine` | the name the Mac reports for itself; for a server, the name the user's tools use for it | `machine:<name>` |
| `container` | machine and container name | `container:machine:<name>/<name>` |
| `checkout` | machine and the path of a local repository, from the home folder when it is inside it, otherwise the full path | `checkout:machine:<name>/<path>`, `checkout:machine:<name>//<full path>` |
| `component` | where it is, the ecosystem and the name | `component:machine:<name>/brew/git`, `component:<checkout id>/npm/<name>` |
| `file` | machine and path of a file, or a folder read as one thing | `file:machine:<name>/.zshrc`, `file:machine:<name>//etc/zshrc` |

`repository`, `service`, `account`, `domain`, `key` and `party` are reserved and not used yet.

Ecosystem names follow the vulnerability databases, so matching needs no translation table. Where the databases have no name, Immune's are `brew` for a Homebrew formula, `brew-cask` for a cask and `macos-app` for an application bundle (named by its bundle identifier). A lockfile entry is named by the package it really is, not by an alias it was installed under. Only an entry from the ecosystem's public registry has a bare name; one from git, a path or another registry carries its source in brackets, such as `(git)`, so it is never compared with the registry's package of the same name.

## Facts and their basis

A reader never writes a fact directly. It writes an assertion: one statement from one source.

| Field | Meaning |
|---|---|
| `subject` | an entity id |
| `predicate` | one of a closed list, see [reference.md](reference.md#vocabulary) |
| `object` | an entity id or a literal |
| `reader` | the reader that wrote it |
| `source_ref` | where exactly it was read: a file and line, or a command and section |
| `basis` | how the source knows it |
| `scope`, `kind` | the reading it belongs to, the same pair as in coverage |
| `observed_at` | when the source was first read with this statement, UTC |
| `run_id` | the run that first wrote it |

A fact is the group of assertions with the same subject, predicate and object. Nobody confirms a fact by hand: its assertions show what it rests on.

The basis has three kinds, strongest first, and a reader's kind is fixed in its code:

| Basis | The source is | Example |
|---|---|---|
| `observed` | the thing itself | an installed application, a server's package list |
| `declared` | a description that tooling enforces | a lockfile, the SSH configuration |
| `mentioned` | text | an agent's session, a README |

Text can be written by an attacker. A fact that rests only on `mentioned` assertions is weak and never supports "does not affect me". No reader writes `mentioned` assertions today; the kind exists so that one that reads text cannot pass for a stronger one.

## Coverage

Coverage is a statement about a reading, not about the world. Every reader writes it on every run.

| Field | Meaning |
|---|---|
| `reader`, `run_id`, `observed_at` | as for an assertion |
| `scope` | the entity that was read: a machine, a container, a checkout |
| `kind` | what was looked for there, from a closed list. A kind names exactly what was read, so a reading never claims more than it covered |
| `completeness` | `full`, `partial` or `none` |
| `reason` | required for `partial` and `none`. On `full` it is an optional note |

A reader first finds out whether its source exists on this Mac. A source that is not there, such as Homebrew on a Mac without it, is not applicable: a full reading that found nothing, with that note, and not a failure. A source that is there and cannot be read is a failed reading, `none` with its reason. A source Immune has no reader for, such as a `requirements.txt` beside the lockfiles it does read, is named as having no reader. These three stay apart all the way to the app.

Two rules are invariants, each with its test:

- "Does not affect me, known for certain" needs `full` coverage of that scope and kind, and fresh.
- A missing reading is not evidence of absence. A reader that could not read a scope retracts nothing in it.

`immune status` turns coverage into what a person reads: one item per cause in `not_covered`, never one per machine or file, each saying who can act on it. `you` means the user can, for a server not swept or a file whose permissions keep Immune out. `nothing` means it is a limit of this version or something tried again at every check. A gap in coverage is never counted as something that needs a look. Agents also get the detail in `coverage`, `cannot_judge` and `no_reader_for`.

## Lifecycle

Assertions live in three layers: draft, live and retracted.

- A run writes into draft.
- At the end of the run, for each scope and kind the reader covered in full, draft is compared with live. New assertions become live. Assertions no longer made move to retracted, with the time.
- Under partial coverage new assertions still become live and nothing is retracted. Under no coverage nothing changes.
- Each difference is an event, `added`, `changed` or `removed`, counted per subject and predicate, so a new version of a component is one `changed` event.
- When a checkout or a container is gone, everything read inside it is retracted with it, as one `removed` event.
- Retracted assertions are kept. An investigation looks back.

The first reading of a kind in a scope is a baseline and reports nothing as new. A watched file that could not be read before and now can is named once as read for the first time, since there was nothing to compare it with.

Readers keep their raw input next to the store, copied only when it changed, so that the store can be rebuilt from it. A source that holds secrets keeps only what the reader extracted: the SSH readers keep names and never keys. Homebrew's answer and the vulnerability feeds are kept in reduced form for size. A command that rebuilds the store from raw input is planned. The store carries a format version, now 4, and a build refuses a store of a format it does not know.

## The journal

The journal is an append-only list of what Immune did and decided. Raw events from the collector do not go there. Its entries include `run_started`, `run_finished` and `report` for a run; `added`, `changed` and `removed` for differences between readings; `finding_raised`, `finding_reopened`, `finding_cleared`, `finding_expected` and `finding_seen`; `owner_said` and `owner_withdrew` for statements about a machine; `sampled` for what a sample derived; `matched` for a published rule's match a finding rests on, with the rule and a count; and `threats_first_read`, `threat_added`, `threat_gone` and `advisories_read` for threat data. Each has a sequence number, and a finding refers to the entries it rests on by those numbers (`rests_on`).

A run that died leaves `run_started` without `run_finished`.

## Findings

A finding is one thing a rule or a matcher found, about one entity, with its evidence. How bad it would be (`severity`) and how sure Immune is (`confidence`) are two separate values, named with OCSF's levels: `informational`, `low`, `medium`, `high`, `critical`. A finding is urgent when its severity is high or critical and its confidence medium or high. Only then does the app send a notification; it decides nothing else.

Each of Immune's own rules is plain code with an id, the ATT&CK technique where one fits, both levels, whether it finds an event or a state, and fixed words for a person: `title`, `meaning` and `advice`. Text from the machine or a feed is never put into those words. It goes in fields whose names end in `_text`, so an agent reading the output can treat it as data. Each rule has two samples in the tests: one it must fire on and one it must stay silent on.

| Rule | Fires on | Technique | Severity, confidence |
|---|---|---|---|
| `watched.autostart` | a launch agent or daemon added, changed or removed | T1543 | medium, low |
| `watched.shell-profile` | a zsh or bash startup file added, changed or removed | T1546.004 | medium, low |
| `watched.ssh-access` | `~/.ssh/config`, `authorized_keys`, `rc` or the system's SSH configuration added, changed or removed | | high, low |
| `watched.git-hook` | a git hook in a checkout added, changed or removed | | medium, low |
| `watched.first-read` | a watched file read for the first time | | informational, low |
| `integrity.app-seal` | an application's seal no longer verifies, version unchanged | T1554 | high, medium |
| `integrity.app-signer` | an application signed by someone else, version unchanged | T1554 | high, low |
| `integrity.package-files` | a Homebrew keg or global npm package changed, version unchanged | T1554 | high, medium |
| `integrity.app-code-outside` | code an application keeps under Application Support changed, version unchanged | T1554 | medium, low |
| `autorun.folder-open`, `autorun.editor-open`, `autorun.package-install`, `autorun.agent-start`, `autorun.agent-settings`, `autorun.editor-extension` | a new or changed way a file makes a tool run code by itself, one rule per trigger | from the table of ways, see [reference.md](reference.md#what-runs-by-itself) | from the table |
| `indicator.match` | a file or a connection matches an indicator list | | high, high |
| `processes.detached-inline-code` | an interpreter given code on its command line, left running without a terminal across samples a minute apart | T1059 | high, medium |
| `lockfiles.malicious-package` | a dependency a malicious-package record names | T1195.001 | critical, high |
| `lockfiles.malicious-name-removed` | a dependency whose name the registry replaced with a placeholder | T1195.001 | high, low |
| `lockfiles.exploited-vulnerability` | a dependency with a vulnerability in CISA's catalogue | | critical, medium |
| `sigma:<rule id>` | a published Sigma rule marked high or critical matched a program start or a file event | the rule's | the rule's level; medium for a `stable` rule, low otherwise |

A rule finds either an event or a state. A finding about an event stays open through quiet runs until it is answered; found again, it is the same finding seen later. A finding about a state (the three lockfile rules) is cleared when the state goes, for example when the dependency is removed. A published rule raises one finding per rule on a Mac, and further matches add to its count and its evidence.

The states are `open`, `expected`, `seen` and `cleared`.

## Answers

A finding stays open until someone answers it.

- `immune finding <id> expected --reason <text>` hides it for 30 days, or `--days` from 1 to 3650. If it was found again in the meantime, it opens again when that time ends.
- `immune finding <id> seen` closes it. The next time it is found is a new finding.
- `immune finding <id> reopen` takes an answer back.

An answer records who gave it: `--via app`, `--via agent`, or the command line when neither is given. Answers in force that were not given in the app are listed in the status as `answered_outside_app`, and the app shows them and can take each back. An AI agent may give an answer only after the person has agreed in the conversation, having been told what the finding is and what the options are, and it passes `--via agent` with the reason they agreed to. So an answer is never silent. Answers are not signed. A program running as the user can rewrite the store directly, so the record covers every answer given through Immune and cannot catch one written around it.

The same holds for a statement about a machine. `immune owner <name> retired --reason <text>` or `not-mine` sets a server aside: it is no longer offered for the sweep or counted among the servers, and its facts stay as they were. `immune owner <name> withdraw` takes the statement back. Such a statement never hides a thing seen alive after it: a machine a reader saw later than the statement is listed among the servers again, though still not offered for the sweep. Statements in force that were not given in the app are listed as `statements_outside_app`.

## Is this Mac watched and quiet

`immune status --json` answers this first. What needs a look (`needs_a_look`) is open findings only. Apart from it come:

- this Mac: watched, watched in part when a reading of its own places failed, or not checked; whether a watcher runs; and each kind of thing watched, with its count and how (`live` within seconds, `hourly`, or `sampled`);
- what is not covered, as above;
- known vulnerabilities in the projects' packages (`vulnerabilities`), which are never counted in what needs a look;
- the collector's state (`event_level`).

A watcher whose latest reading or sample failed does not count as watching live until the next success, and the failure is served with what failed, when and what it said.

## Text from a source is data

Files on the Mac, feeds and indicator lists may be written by an attacker, sometimes for an agent to read. Immune takes facts out of them and nothing else:

- no path, command or URL is ever taken from a feed or an indicator list and used;
- nothing from an indicator list is visited, downloaded or run;
- text from a source is returned only in fields ending in `_text`;
- the HTML pages escape it and run no script except one fixed in the program.

## No model

No model runs in collection, detection or the app, so the same input gives the same findings. An agent may investigate a finding through the commands and explain it to the person, but it cannot change a finding, and an answer it gives is recorded as the agent's.

## What comes from the industry and what is Immune's own

Where the industry has a proven name, format or rule set, Immune takes it. Its own design covers only what the industry lacks.

| Part | Taken from |
|---|---|
| Event field names | the Elastic Common Schema, so published rules translate |
| Published rules | SigmaHQ's rules for macOS, unchanged; the Sigma format and its field names |
| Techniques | MITRE ATT&CK for Enterprise, release 20.1 |
| Severity and confidence | OCSF's finding fields and level names |
| Vulnerability answers | OpenVEX's statuses: affected, not affected with a justification, under investigation |
| Vulnerability data | OSV's schema, its ecosystem names and its `IsVulnerable` algorithm; CISA KEV |
| Indicators | STIX 2.1 object paths |
| An answer that hides a finding until an end date, with a reason | the industry's practice for alert exceptions |
| Collector | Apple's `eslogger`, `jq` and `rotatelogs` |

Immune's own:

- the basis of a fact (observed, declared, mentioned), since no standard grades what a statement rests on;
- coverage that an answer depends on, and the rule that a missing reading is not absence;
- "does not affect me, no signs" as an answer apart from "known for certain";
- the map of one person's Mac, projects and servers;
- the table of ways a file makes a tool run code by itself;
- integrity of what is installed: content changed while the version stayed the same, for which no published rule exists;
- one person answering findings, with an agent allowed to answer only after they agree.

## Planned

Not built: grouping related findings into cases, adding up weak rule matches, raising a finding's weight when something is seen on this Mac for the first time, and any reaction that stops or suspends a program. Immune reports and never blocks, suspends or kills anything.

Part of the contract with the response layer is built. Its protobuf schema is in `contract/immune/v1/`, the core's types are generated from it, and one command prints it: `immune project` answers what the store knows of one project (see [reference.md](reference.md#the-contract)). Its message is general, so the questions about a program and a machine will use it unchanged. Those two questions are planned, and so are the queue of rule matches with the event each matched, the count of what was lost and the collector's state, and the verdict that comes back.
