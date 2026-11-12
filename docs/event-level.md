# The event level

Without administrator rights Immune sees state: files, installed software, samples of running programs every 30 seconds. It cannot see the moment a program starts, its command line or who wrote a file, and almost every published detection rule for macOS needs those. The event level is an optional collector that records them, so that SigmaHQ's rules for macOS can judge every program start and every file created or renamed.

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

The log holds the arguments of every program started on the Mac, by every account, root included, for up to a day. Any program running as the installing account can read it. On a Mac with one person that is the person's own data. On a shared Mac it is other people's too; the installer says before it starts that it records the program starts of every account.

## The log's life and size

- One file per hour, named by the hour in UTC: `exec-YYYYMMDDTHH.jsonl`. The name dates from when the log held program starts alone; file events go into the same files.
- `rotatelogs` moves to the next hour's file without closing the pipe, so `eslogger` is never restarted to rotate, and its sequence numbers keep counting.
- Every ten minutes `tidy.sh` deletes files not written to for a day, then the oldest files while the log is larger than 500 MiB (524,288,000 bytes), never the file being written. Between two runs the log can pass the cap by what ten minutes add, so it takes at most about 0.6 GB of disk.
- Each deletion is a line in `removed`: when, the file's name, its size, and `age` or `cap`.
- What `eslogger` and the scripts print goes to `eslogger.err` and `scripts.err`. These and `removed` are kept small: a file over 64 KiB is replaced by its last 16 KiB.

The installer's estimate of the cost: about 600 bytes per program start and 350 per file event. A quiet Mac starting 2 programs and creating 20 files a second writes about 700 MB a day; a Mac building software, at 100 starts and 200 files a second, about 11 GB a day, more than the cap, so the oldest hours are deleted first and the log may hold only its last hour or so. The log is a buffer: Immune reads it every ten seconds while the app is open, and what is read is judged and counted.

## How Immune reads it

Immune reads the log at every full check, and every 10 seconds while `immune watch` runs (`--events-every`). A reading that finds nothing new costs a look at the log's files and one row.

- Lines are read whole, from where the last reading stopped in each file, by the file's name and inode. A line still being written is left for the next reading. A file that is gone is forgotten; one with the same name and a new inode is read from its start.
- A line that is not a JSON object, such as the two halves of a line split between two hourly files, is counted as unreadable and skipped.
- A message with an unknown `schema_version`, or without a field the reader needs, means the format changed. The reading fails with the reason and nothing is taken as read, so a build that knows the new format reads the same lines. Today `schema_version` 1 is known. The message `version` alone fails nothing: Apple raises it with macOS releases as it adds fields.

The store keeps no event. It keeps where each file was read up to, counts per reading for two days, the level's state, coverage (one row, replaced at every reading), and per rule how many starts or file events matched, by the hour, for a week. The one place arguments enter the store is the evidence of a finding from a published rule: the latest five program starts it matched, or the latest five file events with the file and the program. The environment never does.

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
| `silent` | Nothing was written for 15 minutes. The tidy job's own programs are program starts, so a running level on an awake Mac writes at least every ten minutes; right after waking from sleep this can show once |
| `failed` | The reading itself failed, with its reason |

File events count as collected only when the installer's record of the collector's arguments, `collects`, names `create` and `rename` and is not older than the installed launch daemon. A collector installed before file events existed writes a log with none in it, which would read the same as a Mac where no file was created. Until the record says otherwise, the five file rules are listed as not watching, with the reason, and `event_level.file_events.collected` is false.

The status also serves the last day's starts by the hour (`program_starts_by_hour`), the last hour by the minute (`program_starts_by_minute`), and the state in words with its caveats (`in_words`). Rules are said to watch only while the state is `running`.

## The rules

Immune ships the 75 SigmaHQ rules for macOS from commit `d7c9da1`, byte for byte, in `rules/sigma/` with the licence in `rules/sigma/NOTICE`: 70 over program starts and 5 over file events, 13 marked high, 41 medium, 14 low and 7 informational. They are compiled into the program and evaluated in memory by the `sigma-rust` crate, loaded once per process. A program start is asked only of the process rules and a file event only of the file rules. Before the evaluator is asked, one pass over each field finds the texts a rule needs there, so a rule that cannot match is not asked; a test holds this to the same matches as asking every rule.

Sigma's taxonomy names no fields for macOS. Immune fills the ones `eslogger` can give:

| Sigma field | From `eslogger` | ECS name in evidence |
|---|---|---|
| `Image` | `event.exec.target.executable.path`; for a file event, the program that did it | `process.executable` |
| `CommandLine` | `event.exec.args` joined by single spaces | `process.args` |
| `ParentImage` | `process.executable.path`, the image before the `exec` | `process.parent.executable` |
| `TargetFilename` | the file created, or a rename's destination | `file.path` |

`ParentImage` is the parent's program after a fork or `posix_spawn`, which is how shells, build tools and agents start programs. After an `exec` without a fork it is the wrapper that replaced itself (`nohup`, `env`, `xcrun`), so a rule on `ParentImage` can miss a start one wrapper away. A path under `/private/etc`, `/private/tmp` or `/private/var` is also offered under its short name, since Endpoint Security gives the resolved path and rule authors write `/tmp/...`.

With file events collected, 74 of the 75 rules are evaluated in full. One reads `OriginalFileName`, a Windows field with no macOS equivalent, in one branch of an OR, so it is evaluated in part. `immune rules --json` lists every rule as evaluated in full, in part or not at all, with the reason and how often it matched.

What a match does:

- Every match of every rule is counted, by the hour, for a week.
- A rule marked high or critical raises one finding per rule on the Mac, `sigma:<rule id>`. A repeated match adds to its count and its evidence and raises nothing new.
- Severity is the rule's level. Confidence follows the rule's status: medium for `stable`, low otherwise. None of the shipped rules is `stable`, so no published rule is urgent and the app does not notify on one.
- The rule's title, authors, techniques and licence travel with the finding as data (`published_rule`), as the Detection Rule License asks.
- Matches of lower rules are a quiet count. They never change the headline, the count of findings or the icon.

`immune rules --over-log` evaluates the rules over the log on disk without the store and prints per rule its level and count, never a command line.

## What published rules need that the level does not give

Counted over SigmaHQ at `d7c9da1`, `elastic/detection-rules` at `032ac5e` and `elastic/protections-artifacts` at `a87715d`, for macOS:

- Connections. `eslogger` has no network event. No Sigma rule for macOS needs one. Of Elastic's 100 detection rules for macOS, 11 EQL rules use network events; of its 278 behaviour rules, 38 involve the network. Seeing every connection needs a network extension signed with Apple's permission.
- A process identity that survives a reused pid (Elastic's `entity_id`), required by 125 of Elastic's rules, mostly as the key of a sequence.
- Whether a signature is trusted (`code_signature.trusted`), which `eslogger` does not give. The signer itself is recorded.
- `fork`, required by 5 of Elastic's behaviour rules.
- Files changed in place, closed or removed.
- Correlations and sequences: `sigma-rust` does not evaluate Sigma correlations, and the shipped Sigma rules have none.

No rule in these sets reads the end of a process or a connection's byte count. Elastic's rules are not evaluated at all, since no evaluator of their query languages can be embedded in a Rust program. Translating them into Sigma's format, so that one evaluator runs both, is planned.

## `eslogger` is not a promised interface

Apple's manual page for `eslogger` says it "is NOT API in any sense". Its output has changed between macOS releases while `schema_version` stayed 1: `audit_token` has been an object in some message versions and an eight-element list in another, and Immune reads both. A macOS update may change it again. When that happens, a reading of a format Immune does not know fails with its reason, the state says so, and the rules are not shown as watching until it runs again. The alternative, a collector of Immune's own built on Endpoint Security, needs an entitlement Apple grants to a developer organisation; Immune has none.

## Not yet seen

- A whole day of collection on one Mac, and a real refusal of Full Disk Access after install.
- Whether a line is split at the turn of an hour in practice.
- `eslogger`'s output on macOS 15.
