# The event level

Without administrator rights Immune sees state: files, installed software, samples of running programs every 30 seconds. It cannot see the moment a program starts, its command line or who wrote a file, and almost every published detection rule for macOS needs those. The event level is an optional collector that records them, so that published rules for macOS, SigmaHQ's and Elastic's translated into Sigma, can judge every program start and every file created or renamed.

It needs macOS 15 or later, because it uses `/usr/bin/jq`, and an administrator password once:

```sh
sudo /bin/sh scripts/event-level/install
sudo /bin/sh scripts/event-level/uninstall    # removes it, logs included
```

Then `/usr/bin/eslogger` needs Full Disk Access, which the user grants in System Settings, Privacy & Security, Full Disk Access. Without it `eslogger` stops at once and nothing is recorded.

## What runs as root

Three launch daemons, and nothing else:

| Label | Runs | What it does |
|---|---|---|
| `ai.nuanu.immune.eslogger` | `/usr/bin/eslogger exec create rename` | Apple's Endpoint Security logger, subscribed to program starts and to files created and renamed. It writes into a FIFO |
| `ai.nuanu.immune.event-filter` | `/bin/sh collect.sh` | Pipes the FIFO through `/usr/bin/jq` with `filter.jq`, which keeps only the fields Immune reads, into `/usr/sbin/rotatelogs`, which appends to one file per hour |
| `ai.nuanu.immune.event-tidy` | `/bin/sh tidy.sh`, every ten minutes | Deletes old log files and keeps the log under its cap |

Only programs that macOS ships run as root, by absolute path. No compiled code of Immune's runs as root: the root side is a `jq` program and two short shell scripts, and Immune's own reader runs as the user, without rights. A security tool is a target itself, and code of its own running as root would be one more thing an attacker could aim at.

The installer copies the scripts into `/Library/Application Support/ai.nuanu.immune/event-level`, a folder only root can write. Before it writes anything it checks that `/`, `/Library`, `/Library/Application Support`, `/Library/LaunchDaemons` and its own folder can be changed by no account other than root, and stops if one can. Nothing is ever executed from a place the user's account can change. The collector acts on no process, file or connection: it only records.

The installer is idempotent. Run again, it stops what it started, puts every file back and starts it again, keeping the logs. It ends with one line: `RESULT: RUNNING`, `RESULT: RUNNING IN PART` (program starts are recorded, and no file event came in the ten seconds it waited), `RESULT: REFUSED` (Full Disk Access is missing) or `RESULT: INSTALLED, NOT RECORDING YET`.

## What is recorded, and what never is

The filter keeps a list of fields, not a list of what to remove, so a field Apple adds is not written.

For a program start (`exec`):

- `schema_version`, `version`, `seq_num`, `global_seq_num` and `time`;
- the program started (`event.exec.target.executable.path`), its arguments (`event.exec.args`) and its working directory;
- its pid and effective user id from `audit_token`, its parent's pid (`ppid`);
- who signed it: `signing_id`, `team_id`, `is_platform_binary`;
- the image the process ran before the `exec` (`process.executable.path`), which Immune uses as the parent program.

For a file created or renamed (`create`, `rename`):

- `schema_version`, `seq_num` and `time`;
- the program that did it;
- the file's path (`destination`), and for a rename its `source`.

Never written: a program's environment, its file descriptors, the contents of any file. Not collected at all: files changed in place, closed or removed; `fork` and `exit`; connections, since `eslogger` has no network event.

A file event the filter cannot make out, or whose path `eslogger` marks as truncated, is written as its kind with nothing in it, its numbers kept, so the reader counts it as unreadable and never as nothing. A line that is not a JSON object is dropped by `jq`, and the gap it leaves in the sequence numbers is counted as a loss.

## Who can read the log

The log folder and its files belong to root with mode 700 and 600. An access-control entry lets the account that ran the installer through `sudo` list the folder and read the files, and no other account. The installer refuses to run from a root shell, since it needs that account.

The log holds the arguments of every program started on the Mac, by every account, root included, for up to a day. Any program running as the installing account can read it, and `immune matches`, run as that account, prints the whole command line of every program start that matched a rule, whoever started it. On a Mac with one person that is the person's own data. On a shared Mac it is other people's too; the installer says before it starts that it records the program starts of every account.

## The log's life and size

- One file per hour, named by the hour in UTC: `exec-YYYYMMDDTHH.jsonl`. The name dates from when the log held program starts alone; file events go into the same files.
- `rotatelogs` moves to the next hour's file without closing the pipe, so `eslogger` is never restarted to rotate, and its sequence numbers keep counting.
- Every ten minutes `tidy.sh` deletes files not written to for a day, then the oldest files while the log is larger than 500 MiB (524,288,000 bytes), never the file being written. Between two runs the log can pass the cap by what ten minutes add, so it takes at most about 0.6 GB of disk.
- Each deletion is a line in `removed`: when, the file's name, its size, and `age` or `cap`.
- What `eslogger` and the scripts print goes to `eslogger.err` and `scripts.err`. These and `removed` are kept small: a file over 64 KiB is replaced by its last 16 KiB.

The installer's estimate of the cost: about 600 bytes per program start and 350 per file event. A quiet Mac starting 2 programs and creating 20 files a second writes about 700 MB a day; a Mac building software, at 100 starts and 200 files a second, about 11 GB a day, more than the cap, so the oldest hours are deleted first and the log may hold only its last hour or so. The log is a buffer: Immune reads it every ten seconds while the app is open, and what is read is judged and counted.

## How Immune reads it

Immune reads the log at every full check, and every 10 seconds while `immune watch` runs (`--events-every`). A reading that finds nothing new costs a look at the log's files and one row.

- Only a file named exactly as `rotatelogs` names a log file, `exec-YYYYMMDDTHH.jsonl` with an hour of a date, is read. Any other file in the folder is not the collector's and is never read; `immune matches` counts them.
- Lines are read whole, from where the last reading stopped in each file, by the file's name and inode. A line still being written is left for the next reading. A file that is gone is forgotten; one with the same name and a new inode is read from its start.
- A file's hour is over once a file of a later hour has been written to at or after the time the file was last written to. A line without its newline at the end of such a file is never finished, as when a line is split between two hourly files, and is counted as unreadable and skipped. The end of a file whose hour is not over is left for the next reading. That includes a file of an earlier hour written to again after a clock set ahead was put back.
- A line that is not a JSON object is counted as unreadable and skipped.
- A message with an unknown `schema_version`, or without a field the reader needs, means the format changed. The reading fails with the reason and nothing is taken as read, so a build that knows the new format reads the same lines. Today `schema_version` 1 is known. The message `version` alone fails nothing: Apple raises it with macOS releases as it adds fields.

The store keeps no event. It keeps where each file was read up to, counts per reading for two days, the level's state, coverage (one row, replaced at every reading), and per rule how many starts or file events matched, by the hour, for a week. For every match of a rule marked high or critical it keeps which finding the match went to, by the line's file, inode and offset, until the file is no longer there; `immune matches` reads it. The one place arguments enter the store is the evidence of a finding from a published rule: the latest five program starts it matched, or the latest five file events with the file and the program. The environment never does.

Secrets in those arguments are kept as they were. Cutting tokens and passwords out of what Immune keeps and prints, with patterns from a published set, is planned.

## Losses

Every loss is counted, and a loss of unknown size is never counted as zero.

- Endpoint Security drops events for a client that cannot keep up. `seq_num` counts each event type per client, so a gap in it is that many events lost. Immune counts program starts and file events apart.
- A sequence number at or below the last one means `eslogger` started again: after a crash, a reboot or a broken pipe. What was lost across a restart is a gap of unknown size, counted as one.
- Files deleted to stay under the cap held lines younger than a day. Files deleted before Immune read them to their end held lines it never read. Both are counted from `removed`.
- Unreadable lines and unreadable file events are counted.

Coverage of program starts is judged over the last day. After any loss, unreadable line, or hour deleted early or unread, it is partial. The status gives each of these as a caveat with its count: `restarts`, `lost`, `unreadable`, `deleted_early`, `deleted_unread`.

## The states it reports

`immune status --json` serves the level's state as `event_level.state`:

| State | Meaning |
|---|---|
| `not_installed` | The collector's launch daemon is not in `/Library/LaunchDaemons`. A limit the user can lift, not a failure |
| `running` | The log is being written and read |
| `refused` | macOS denies `eslogger` Full Disk Access. What `eslogger` printed is returned as data |
| `failing` | The scripts print errors. What they printed is returned as data |
| `silent` | Nothing was written for 15 minutes. The tidy job's own programs are program starts, so a running level on an awake Mac writes at least every ten minutes; right after waking from sleep this can show once. A log file or launch daemon dated later than now does not count as written: a file's time can be set ahead, and a clock set back leaves the times it wrote ahead of it |
| `failed` | The reading itself failed, with its reason |

File events count as collected only when the installer's record of the collector's arguments, `collects`, names `create` and `rename` and is not older than the installed launch daemon. A collector installed before file events existed writes a log with none in it, which would read the same as a Mac where no file was created. Until the record says otherwise, the five file rules are listed as not watching, with the reason, and `event_level.file_events.collected` is false.

The status also serves the last day's starts by the hour (`program_starts_by_hour`), the last hour by the minute (`program_starts_by_minute`), and the state in words with its caveats (`in_words`). Rules are said to watch only while the state is `running`.

## The rules

Immune ships three sets of rules, all in Sigma's format, compiled into the program and evaluated in memory by the `sigma-rust` crate, loaded once per process:

- SigmaHQ's 75 rules for macOS from commit `d7c9da1`, byte for byte, in `rules/sigma/` with the licence in `rules/sigma/NOTICE`: 70 over program starts and 5 over file events, 13 marked high, 41 medium, 14 low and 7 informational.
- 66 of Elastic's 185 detection rules for macOS from `elastic/detection-rules` at commit `032ac5e`, each translated into Sigma by a program and shipped as the translator wrote it, in `rules/elastic/` with `rules/elastic/NOTICE`: 60 over program starts and 6 over file events, 1 marked critical, 19 high, 38 medium and 8 low. Elastic's severity is the Sigma level of the same name. The other 119 are listed in `rules/elastic/not-taken.tsv` with the reason each was not taken, and `immune rules` names every one of them.
- 57 of Elastic's 278 behaviour rules for macOS from `elastic/protections-artifacts` at commit `a87715d`, translated by the same program and checked the same way, in `rules/elastic-behaviour/` with `rules/elastic-behaviour/NOTICE`: 54 over program starts and 3 over file events. None states a level, as explained below. The other 221 are listed in `rules/elastic-behaviour/not-taken.tsv` with the reason each was not taken.

The set a rule comes from is a property of the loaded rule. It names the rule in findings, `sigma:<id>`, `elastic:<id>` or `elastic-behaviour:<id>` with Elastic's own rule id, and it says under which names an event is given to the rule and whether the rule states a level. A program start is asked only of the process rules and a file event only of the file rules. Before the evaluator is asked, one pass over each field finds the texts a rule needs there, so a rule that cannot match is not asked; a test holds this to the same matches as asking every rule, for every set.

Sigma's taxonomy names no fields for macOS. For SigmaHQ's rules Immune fills the ones `eslogger` can give:

| Sigma field | From `eslogger` | ECS name in evidence |
|---|---|---|
| `Image` | `event.exec.target.executable.path`; for a file event, the program that did it | `process.executable` |
| `CommandLine` | `event.exec.args` joined by single spaces | `process.args` |
| `ParentImage` | `process.executable.path`, the image before the `exec` | `process.parent.executable` |
| `TargetFilename` | the file created, or a rename's destination | `file.path` |

`ParentImage` is the parent's program after a fork or `posix_spawn`, which is how shells, build tools and agents start programs. After an `exec` without a fork it is the wrapper that replaced itself (`nohup`, `env`, `xcrun`), so a rule on `ParentImage` can miss a start one wrapper away. A path under `/private/etc`, `/private/tmp` or `/private/var` is also offered under its short name, since Endpoint Security gives the resolved path and rule authors write `/tmp/...`.

Elastic's translated rules read the Elastic Common Schema's names, filled from the same log. The translation was checked on events built exactly this way:

| Elastic field | From `eslogger` |
|---|---|
| `process.executable`, `process.name` | the program started, and the last part of its path; for a file event, the program that did it |
| `process.args` | `event.exec.args` as one text, each argument preceded by NUL and the last followed by one; absent when there are none |
| `process.args_count` | how many arguments, a number |
| `process.command_line` | the arguments joined by single spaces, as `CommandLine` |
| `process.parent.executable`, `process.parent.name` | the image before the `exec`, as `ParentImage`, and the last part of its path |
| `process.working_directory` | `event.exec.cwd.path` |
| `user.id` | the effective user id, as text |
| `event.type`, `event.action` | `start` and `exec` for a program start; `creation` for both on a file created, `change` and `rename` for one renamed |
| `file.path`, `file.name`, `file.extension` | the file created or a rename's destination, its last part, and what follows the last dot of that |

Every text is also given folded, one character at a time as `sigma-rust` folds, under `immune.folded.` and its name: a translated regular expression that ignores case reads that field, since Sigma's `re` keeps case. Elastic's rules see a path only as Endpoint Security gives it, with no second name through the links into `/private`: the translation was checked that way, and Elastic's rules write `/private/...` where they mean it. A rule's set decides which of these it gets, the short name or the folded copies, through the set's schema in `src/sigma.rs`. `tests/elastic/samples.jsonl` keeps 396 of the translator's invented events with the rules the reference said each matches, three that match and three near misses for every translated rule, and a test holds Immune's evaluation of them to exactly those rules. `tests/elastic-behaviour/samples.jsonl` keeps 341 for the behaviour rules in the same way; one rule matches only 2 of the events made for it, and both are kept.

With file events collected, 175 rules are evaluated in full: 74 of SigmaHQ's, 54 of Elastic's detection rules and 47 of its behaviour rules. 23 are evaluated in part. One of SigmaHQ's reads `OriginalFileName`, a Windows field with no macOS equivalent, in one branch of an OR. Of Elastic's, 9 have an alternative the translation left out because it reads a field the log does not give (`process.parent.code_signature.trusted`, `process.parent.command_line`, `process.Ext.effective_parent.executable` and others), and 3 have one left out because its pattern holds a backslash among wildcards, as in a Windows path. Of the behaviour rules, 10 have an alternative left out for a field the log does not give: the effective parent in 6, whether a signature exists or is trusted in 3, and `process.code_signature.signing_id` in 2, one rule lacking both the effective parent and `signing_id`. A rule that names a field its set's schema does not give is placed the same way as SigmaHQ's, with the field named. `immune rules --json` lists every rule of every set as evaluated in full, in part or not at all, with its set, the reason and how often it matched.

Elastic's behaviour rules state no level. Elastic's sensor sets a behaviour alert's severity when it runs and does not publish which a rule gets, so the translation writes none and Immune gives none of its own. Such a rule is evaluated, and its matches are counted, listed and handed over exactly as those of a rule below high. Where a level is printed, a machine reads `null` in the report commands' JSON and `LEVEL_NOT_STATED` (`"not_stated"` in its JSON) in the contract's `Rule` and `Unevaluated`, a value that is not a severity; a match's `raised` is `below_high`; a person reads "no level stated". Ordered by level, these rules come after `informational`. Upstream, each behaviour rule also stops a process when it matches. The translation records those actions as ignored, and Immune takes no action of any kind.

6 titles are shared by two sets, each pair under different ids. A behaviour rule and a detection rule share Dumping Account Hashes via Built-In Commands, Modification of Safari Settings via Defaults Command, Potential Kerberos Attack via Bifrost, Potential Privacy Control Bypass via Localhost Secure Copy and Unexpected Child Process of macOS Screensaver Engine; a behaviour rule and a SigmaHQ rule share Potential XCSSET Malware Infection. An event that matches both rules of a pair is counted once in each set, and the status and the summary page name each rule's set beside its title. A test counts the pairs from the files.

What a match does:

- Every match of every rule is counted, by the hour, for a week.
- A rule marked high or critical raises one finding per rule on the Mac, `sigma:<rule id>` or `elastic:<rule id>`. A repeated match adds to its count and its evidence and raises nothing new. A rule that states no level raises none.
- Severity is the rule's level. Confidence follows the rule's status: medium for `stable`, low otherwise. None of the shipped rules is `stable` (the translation writes `test` for every Elastic rule), so no published rule is urgent and the app does not notify on one.
- The rule's title, authors, techniques, its set's address and licence travel with the finding as data (`published_rule`), as the Detection Rule License asks. An Elastic rule keeps Elastic's rule id and name as its `id` and `title`.
- Matches of lower rules, and of rules with no level stated, are a quiet count. They never change the headline, the count of findings or the icon. The store keeps nothing else of them; `immune matches` reads them from the log, with their events, for the response layer.

`immune rules --over-log` evaluates the rules over the log on disk without the store and prints per rule its level and count, never a command line. `immune matches` evaluates the log with the same code and prints every match with the event it matched, arguments whole, and for a high match the finding the core's own reading put it in. The caller keeps its place in the log, which holds per file what the core's reading keeps for itself (see [reference.md](reference.md#immune-matches)).

## What published rules need that the level does not give

Counted over SigmaHQ at `d7c9da1`, `elastic/detection-rules` at `032ac5e` and `elastic/protections-artifacts` at `a87715d`, for macOS:

- Connections. `eslogger` has no network event. No Sigma rule for macOS needs one. Of Elastic's 185 detection rules for macOS, 19 of the 145 written in EQL involve the network; of its 278 behaviour rules, 38 do. Seeing every connection needs a network extension signed with Apple's permission.
- A process identity that survives a reused pid (Elastic's `entity_id`), required by 125 of Elastic's rules, mostly as the key of a sequence.
- Whether a signature is trusted (`code_signature.trusted`), which `eslogger` does not give. The signer itself is recorded.
- `fork`, required by 5 of Elastic's behaviour rules.
- Files changed in place, closed or removed.
- Correlations and sequences: `sigma-rust` does not evaluate Sigma correlations, and the shipped Sigma rules have none.

No rule in these sets reads the end of a process or a connection's byte count. Immune has no evaluator of Elastic's query languages, so Elastic's rules are evaluated only as translated into Sigma. What that leaves out of Elastic's 185 detection rules for macOS:

- 30 correlate a sequence of events, and Sigma's rules here judge one event.
- 40 are written in KQL or ES|QL; only EQL rules are translated.
- 23 are about events the collector does not record (files modified, opened or deleted, network events, library loads, configuration changes and others), and 23 cannot do without a field it does not give (`process.parent.args`, `process.code_signature.trusted`, `process.Ext.effective_parent.executable`, `user.name` and others).
- 2 hold a backslash in a wildcard pattern, whose meaning in Elasticsearch is not documented, and 1 is about program starts and file events at once.

Of Elastic's 278 behaviour rules for macOS, 221 are not taken: 109 correlate a sequence of events, 42 are about events the collector does not record and 61 cannot do without a field it does not give, 4 could never be true over the events here, 1 needs a regular expression in EQL's syntax, 2 use a function of EQL's that is not translated, 1 compares one field with another and 1 is about program starts and file events at once.

What the 66 translated rules rest on, beyond the checked translation:

- How Elastic Defend fills `process.name` and `process.command_line` on macOS is not documented. Immune takes the last part of the path and the arguments joined by spaces.
- The image before an `exec` stands for the parent, as for SigmaHQ's `ParentImage`.
- 34 of the 60 rules for program starts do not ask for `event.action == "exec"`, and Elastic may also count a fork as a start. The collector records no fork, so such a rule sees only programs started by `exec`. Three translated rules also ask for an event kind the log does not hold: a fork, a file modified and a file overwritten.
- 15 rules negate a field an event may lack (`process.args`, `process.parent.executable`, `user.id`). They rest on Elasticsearch treating a comparison with a missing field as neither true nor false, so its negation does not hold either: the translation asks for the field to be present wherever it is negated.

What the 57 translated behaviour rules rest on, beyond the checked translation, besides the first two points above:

- 12 do not ask for `event.action == "exec"`, so Elastic would also evaluate them on a fork, which the collector does not record.
- The 3 file rules would also be evaluated on kinds of file event the log does not hold, such as files modified or opened, and one of them also asks for files modified.
- 6 negate a field an event may lack (`process.args`, `process.parent.executable`). Elasticsearch treats a comparison with a field the event does not have as neither true nor false, so its negation does not hold either, and the translation asks for the field to be present wherever it negates it.
- No rule states a level, and no action a rule takes upstream is taken.

## `eslogger` is not a promised interface

Apple's manual page for `eslogger` says it "is NOT API in any sense". Its output has changed between macOS releases while `schema_version` stayed 1: `audit_token` has been an object in some message versions and an eight-element list in another, and Immune reads both. A macOS update may change it again. When that happens, a reading of a format Immune does not know fails with its reason, the state says so, and the rules are not shown as watching until it runs again. The alternative, a collector of Immune's own built on Endpoint Security, needs an entitlement Apple grants to a developer organisation; Immune has none.

## Not yet seen

- A whole day of collection on one Mac, and a real refusal of Full Disk Access after install.
- Whether a line is split at the turn of an hour in practice.
- `eslogger`'s output on macOS 15.
