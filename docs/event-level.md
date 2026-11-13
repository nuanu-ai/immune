# The event level

Without administrator rights Immune sees state: files, installed software, samples of running programs every 30 seconds. It cannot see the moment a program starts, its command line or who wrote a file, and almost every published detection rule for macOS needs those. The event level is an optional collector that records them, so that published rules for macOS, SigmaHQ's and Elastic's translated into Sigma, can judge every program start and every file created or renamed.

It needs macOS 15 or later, because it uses `/usr/bin/jq`, and an administrator password once:

```sh
sudo /bin/sh scripts/event-level/install      # or with --log-gib <n>, the log's cap in GiB
sudo /bin/sh scripts/event-level/uninstall    # removes it, logs included
```

Then `/usr/bin/eslogger` needs Full Disk Access, which the user grants in System Settings, Privacy & Security, Full Disk Access. Without it `eslogger` stops at once and nothing is recorded.

## What runs as root

Three launch daemons, and nothing else:

| Label | Runs | What it does |
|---|---|---|
| `ai.nuanu.immune.eslogger` | `/usr/bin/eslogger exec create rename` | Apple's Endpoint Security logger, subscribed to program starts and to files created and renamed. It writes into a FIFO |
| `ai.nuanu.immune.event-filter` | `/bin/sh collect.sh` | Pipes the FIFO through `/usr/bin/jq` with `filter.jq`, which keeps only the fields Immune reads, into `/usr/sbin/rotatelogs`, which starts a new log file at each hour and at 128 MiB and runs `rotated.sh`, and so `tidy.sh`, each time it does |
| `ai.nuanu.immune.event-tidy` | `/bin/sh tidy.sh`, every ten minutes | Deletes old log files and keeps the log under its cap. Its launch daemon holds the cap |

Only programs that macOS ships run as root, by absolute path. No compiled code of Immune's runs as root: the root side is a `jq` program and three short shell scripts, and Immune's own reader runs as the user, without rights. A security tool is a target itself, and code of its own running as root would be one more thing an attacker could aim at.

The installer copies the scripts into `/Library/Application Support/ai.nuanu.immune/event-level`, a folder only root can write. Before it writes anything it checks that `/`, `/Library`, `/Library/Application Support`, `/Library/LaunchDaemons` and its own folder can be changed by no account other than root, and stops if one can. Once it is installed, nothing is executed from a place the user's account can change. The installer itself runs as root whatever the checkout it is in holds, so run it from a checkout you trust. The collector acts on no process, file or connection: it only records.

The installer is idempotent. Run again, it stops what it started, puts every file back and starts it again, keeping the logs. It makes the folders and the pipe and sets who may read the log before it stops the collector that runs. If a step fails after that, it says what it left: the collector stopped, or partly started, so that nothing is recorded until the installer runs again and succeeds. Immune goes on showing the level as running for up to 15 minutes after the last line was written, and then says it is silent. It ends with one line: `RESULT: RUNNING`, `RESULT: RUNNING IN PART` (program starts are recorded, and no file event came in the ten seconds it waited), `RESULT: REFUSED` (Full Disk Access is missing) or `RESULT: INSTALLED, NOT RECORDING YET`.

## What is recorded, and what never is

The filter keeps a list of fields, not a list of what to remove, so a field Apple adds is not written.

For a program start (`exec`):

- `schema_version`, `version`, `seq_num`, `global_seq_num` and `time`;
- the program started (`event.exec.target.executable.path`), its arguments (`event.exec.args`) and its working directory;
- its pid, effective user id and pid version (`pidversion`) from `audit_token`, its real user (`ruid`) and its effective and real groups (`egid`, `rgid`), and when it started (`start_time`);
- its parent's pid (`ppid`), and the parent's pid and pid version from `parent_audit_token`;
- the pid and pid version of the process macOS holds responsible for it (`responsible_audit_token`), and its process group (`group_id`);
- who signed it: `signing_id`, `team_id`, `is_platform_binary`, and its code-signing flags (`codesigning_flags`);
- the script it runs, `event.exec.script.path`, when the program is an interpreter started on a script file;
- the image the process ran before the `exec` (`process.executable.path`), which Immune uses as the parent program, with that process's pid, pid version, users and groups, its start time, and who signed it: `signing_id`, `team_id`, `is_platform_binary` and `codesigning_flags`.

For a file created or renamed (`create`, `rename`):

- `schema_version`, `seq_num` and `time`;
- the program that did it, with its pid, pid version, users and groups, its start time, and who signed it: `signing_id`, `team_id`, `is_platform_binary` and `codesigning_flags`;
- the file's path (`destination`), and for a rename its `source`.

A pid is reused once its process ends. The pid with its version names one process for as long as the Mac runs, and the start time tells two apart across a restart. `eslogger` has written `audit_token` both as an object and as the eight words of `audit_token_t` (the pid is the sixth, the version the eighth); the filter keeps either.

Every value the filter keeps goes through one of four helpers, each for one shape: a text, a whole number from 0 to 2^53 − 1 (which the reader holds exactly), true or false, or a list of texts. A value of any other shape is written as null. An audit token in another shape is null as a whole, and so is a list of arguments with one that is not text. When the field is one the reader needs, such as the started program's pid or its arguments, a null there fails the reading as a change of format, with the reason. No rule reads the pid or its version: the reader takes them, the start times, the script and the code-signing flags of the program started and of the process before the `exec`, and hands them to the response layer through `immune matches`. The users and groups, the responsible process, the process group and the rest of the signer of the process before an `exec` are on the log for rules Immune cannot evaluate yet (see [what published rules need](#what-published-rules-need-that-the-level-does-not-give)); the reader does not read them today.

Never written: a program's environment, its file descriptors, the contents of any file. Under a field the filter keeps it writes only the keys it names, so nothing else reaches the disk under a kept name. Not collected at all: files changed in place, closed or removed; `fork` and `exit`; connections, since `eslogger` has no network event.

A file event the filter cannot make out, or whose path `eslogger` marks as truncated, is written as its kind with nothing in it, its numbers kept, so the reader counts it as unreadable and never as nothing. A line `jq` cannot read as JSON, such as one with a lone UTF-16 surrogate (`\ud800`) or a raw control character in a string, and a line that is not an object or has no event, is written as the marker `{"unreadable":true}`. The reader counts the marker as a line that could not be read, and the number that message took in `eslogger`'s numbering is not counted again as a loss.

## Who can read the log

The log folder and its files belong to root with mode 700 and 600. An access-control entry lets the account that ran the installer through `sudo` list the folder and read the files, and no other account. The installer refuses to run from a root shell, since it needs that account.

The log holds the arguments of every program started on the Mac, by every account, root included, for up to a day, as `eslogger` gave them: a password or a token typed on a command line is in it as it was typed. Nothing on the root side cuts it, since that would put a matcher of secrets to work as root on text an attacker writes. Any program running as the installing account can read the log, as it can read the arguments of running programs with `/bin/ps`. What the log adds is starts too short to see that way, a day of history, and one file that holds it all. The installer does not exclude the log from backups, so a backup of `/Library/Application Support` holds it too. `immune matches`, run as that account, prints the command line of every program start that matched a rule, whoever started it, with the secrets it recognises cut out ([reference.md](reference.md#secrets-in-what-immune-keeps-and-prints)). On a Mac with one person that is the person's own data. On a shared Mac it is other people's too; the installer says before it starts that it records the program starts of every account.

## The log's life and size

- `rotatelogs` starts a new file at each hour and when the file reaches 128 MiB (`SEGMENT_MIB` in `collect.sh`). A file is named `exec-<run>-<start>.jsonl`, when this run of the filter began and when the file was started, both `YYYYMMDDTHHMMSS` in UTC. The first file of a run and each file started at the hour take the start of the hour; a file started at the size takes the current second. Two files started within the same second share a name, and `rotatelogs` appends to it, so a file passes 128 MiB by more than one write only when more than that arrives within one second. Because the run comes first, a filter started again never reopens a file of an earlier run, and names sort in the order files were written as long as the clock is not set back. No other file reuses a name or an inode. When a write to the log fails, as on a full disk, the writer, `rotatelogs`, empties the file being written and goes on in it; those lines are counted as lost and the day is partial, and they are not told apart from what the kernel dropped. The file then starts with the writer's own message, counted as a line that could not be read.
- Files an earlier collector wrote, `exec-YYYYMMDDTHH.jsonl`, are read before any of these, as they were written before it, and deleted the same way.
- `rotatelogs` moves to the next file without closing the pipe, so `eslogger` is never restarted to rotate, and its sequence numbers keep counting.
- Each time `rotatelogs` starts a file it runs `rotated.sh`, which reads the cap from the tidy job's launch daemon with `plutil` and runs `tidy.sh`. The tidy job also runs it every ten minutes. `tidy.sh` deletes files not written to for a day, then, while the log is larger than its cap, the file written longest ago, never the one written last, which is the one being written. It goes by when each file was last written, so a clock set back does not change what it keeps. Two runs never delete at once: each first makes the folder `tidy.lock` in the log folder with `mkdir`, which only one can make, and removes it when it ends. A run that finds it held deletes nothing and ends without an error, since the run holding it brings the log under the cap and the next new file starts another. A lock older than ten minutes was left by a run that was killed, and is taken over.
- So the log is never larger than its cap, plus the file being written (128 MiB, more only when more than that arrives within one second), plus what is written while `tidy.sh` runs. Heavy writing pushes older lines out before their day is over. Each such file is counted, and Immune then says the day is partial.
- The cap is 2 GiB (2,147,483,648 bytes) unless the installer is given another with `--log-gib <n>`, a whole number of GiB from 1 to 1,048,576. A value that is not one is refused before anything is changed. Without the flag, installing again keeps the cap of the collector already installed when its tidy job holds a whole number of bytes of at least 1 GiB, and uses the default otherwise, so installing again never shrinks the log. The installer says which cap it installs and where it came from. The ceiling is for the shell's arithmetic: above 8,589,934,591 GiB the bytes would wrap.
- The installer writes the cap in bytes into the tidy job's launch daemon, which belongs to root, and nothing else sets it. A cap that a program running as the user could shrink would let that program empty the log. `immune status --json` gives the cap installed as `event_level.log_cap_bytes`, read from that launch daemon with Apple's `plutil`; when it cannot be read, the number is null and `log_cap_reason` says why. Both are absent while no collector is installed.
- Each deletion is a line in `removed`: when, the file's name, its size, and `age` or `cap`. Lines lost when a failed write empties the file being written are not deletions and are not in it.
- `tidy.sh` refuses a cap that is not digits, has a leading zero, has more than 16 digits or is below 1 GiB, the smallest the installer writes, and deletes nothing to keep the log under it; the status reports a cap only in the form `tidy.sh` takes.
- What `eslogger` and the scripts print goes to `eslogger.err` and `scripts.err`. These and `removed` are kept small: a file over 64 KiB is replaced by its last 16 KiB.

The installer's estimate of the cost: about 1,000 bytes per program start and 600 per file event. On invented events a program start takes 966 bytes against 6,482 in `eslogger`'s whole message, and a file event 491 to 553 against 2,404 to 2,838; who each process is and who signed it add about 490 bytes to a start and 230 to a file event. A quiet Mac starting 2 programs and creating 20 files a second writes about 1.2 GB a day, under the default cap, so the log holds its day. A Mac building software, at 100 starts and 200 files a second, writes about 790 MB an hour, so a 128 MiB file lasts about ten minutes. With the default cap the log then holds between about 2.5 and 2.9 hours: right after `tidy.sh` runs it holds the cap less at most the file it just deleted, and before the next new file it holds the cap and the file being written. It takes at most about 2.3 GB of disk, the cap plus the file being written. The installer works these out for the cap it installs. It never says the log holds more than a day, since lines are deleted after one, nor that it takes more disk than a day of the building Mac's writing and one file: with `--log-gib 24` it says the log holds its day and takes at most about 19.1 GB. The log is a buffer: Immune reads it every ten seconds while the app is open, and what is read is judged and counted.

## How Immune reads it

Immune reads the log at every full check, and every 10 seconds while `immune watch` runs (`--events-every`). A reading that finds nothing new costs a look at the log's files and one row.

- Only a file named exactly as a collector names a log file, `exec-<run>-<start>.jsonl` with two seconds of a date or an earlier collector's `exec-YYYYMMDDTHH.jsonl` with an hour of a date, is read. Files are read in the order their names give: an earlier collector's by the hour first, then by run and by start. Any other file in the folder is not the collector's and is never read; `immune matches` counts them.
- Lines are read whole, from where the last reading stopped in each file, by the file's name and inode. A line still being written is left for the next reading. A file that is gone is forgotten; one with the same name and a new inode is read from its start.
- A file is over once a file later in that order has been written to at or after the time the file was last written to. A line without its newline at the end of such a file is never finished, as when a line is split between two files, and is counted as unreadable and skipped. The end of a file that is not over is left for the next reading. That includes an earlier file written to again after a clock set ahead was put back.
- A line that is not a JSON object, and the filter's marker, are counted as unreadable and skipped.
- A message with an unknown `schema_version`, or without a field the reader needs, means the format changed. The reading fails with the reason and nothing is taken as read, so a build that knows the new format reads the same lines. Today `schema_version` 1 is known. The message `version` alone fails nothing: Apple raises it with macOS releases as it adds fields.

The store keeps no event. It keeps where each file was read up to, counts per reading for two days, the level's state, coverage (one row, replaced at every reading), and per rule how many starts or file events matched, by the hour, for a week. For every match of a rule marked high or critical it keeps which finding the match went to, by the line's file, inode and offset, until the file is no longer there; `immune matches` reads it. The one place arguments enter the store is the evidence of a finding from a published rule: the latest five program starts it matched, or the latest five file events with the file and the program. The environment never does.

Those arguments are kept with the secrets Immune recognises cut out, and printed cut again, so a newer set of patterns applies to rows kept before it. The rules are evaluated before anything is cut. What is recognised, the mark a cut leaves and what is not recognised are in [reference.md](reference.md#secrets-in-what-immune-keeps-and-prints).

## Losses

Every loss is counted, and a loss of unknown size is never counted as zero.

- Endpoint Security drops events for a client that cannot keep up. `seq_num` counts each event type per client, so a gap in it is that many events lost. Immune counts program starts and file events apart.
- A sequence number at or below the last one means `eslogger` started again: after a crash, a reboot or a broken pipe. What was lost across a restart is a gap of unknown size, counted as one.
- Files deleted to stay under the cap held lines younger than a day. Files deleted before Immune read them to their end held lines it never read. Both are counted from `removed`.
- When a write to the log fails, as on a full disk, the writer, `rotatelogs`, empties the file being written and goes on in it; those lines are counted as lost and the day is partial, and they are not told apart from what the kernel dropped.
- Unreadable lines and unreadable file events are counted. A marker of the filter stands for a message whose number is missing from the numbering: the next gap takes it in, so it is counted once, as unreadable. A marker does not say which kind its message was, so the gap it is taken from may be the other kind's; the two kinds' losses may then trade one, and their sum is right.

Coverage of program starts is judged over the last day. After any loss, unreadable line, or log file deleted early or unread, it is partial. The status gives each of these as a caveat with its count: `restarts`, `lost`, `unreadable`, `deleted_early`, `deleted_unread`.

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

What the filter keeps beyond the first collector's fields comes in three groups: `identity` (who each process is), `script` (the script a program start runs) and `signature` (code-signing details). Whether the collector keeps one is decided by what its lines carry, and no record is kept of it. Each group is marked in each kind of line by one key: `event.exec.target.start_time`, `event.exec.script` and `event.exec.target.codesigning_flags` in a program start; `process.start_time` and `process.signing_id` in a file event. The last is the field a rule reads. For each kind the reader keeps one of four states, from the lines it has read:

- not kept: the latest line of the kind lacks the key, so an earlier collector wrote it;
- kept, never filled: lines carry the key, and none since the key appeared has given it a value;
- arriving: a line has given it a value, with that line's time;
- no longer arriving: after values arrived, lines in a row carried the key with no value, with the time of the first of them.

How many lines in a row tell that a group no longer arrives depends on how often `eslogger` fills its key. Every process has a start time, an audit token and code-signing flags, and all code that runs natively on Apple silicon is signed at least ad hoc, so it has a signing id. On the first install on a Mac each of these was filled on every line. For them one line without a value is enough: the filter writes null where a macOS update renamed the field or changed its shape. An unsigned Intel program run by Rosetta has no signing id, so a file it creates stops the signer of file events from arriving until the next file event that gives one. The script belongs only to an interpreter started on a script file; on that install 33 of 1,060 program starts gave one, about one in 32. It no longer arrives after 1,000 program starts in a row without one, counted in the file the collector is writing as the core reads it: about thirty times that gap. A Mac that runs no script for that long is told the same, and the rule that reads the script is named as not watching until the next one arrives. The run is kept in the store from one reading to the next, so it does not start again at each reading. A reading that finds new lines in two files, across a new file, counts only the newer file's starts, so a run that crosses the turn of a file can be told up to that file's starts later.

Only the lines of the log file the collector is writing now speak for these states. Lines in other files are read and judged as before and change nothing here. After the earlier collector is installed back, its files are named by the hour and sort before the files the later one wrote, so the later one's older lines are read after the earlier one's new lines. Taking only the file being written keeps those older lines from saying the groups still arrive. A file nobody writes any more holds nothing new, so once the log has been read, the file being written is the only one with new lines, whatever its name and whatever the clock said. When one reading finds new lines in more than one file, as at the first reading or across a new file, the file written last decides, as `tidy.sh` keeps the file written last. A clock set back can make the first reading pick a file that is no longer written. The next reading that finds new lines corrects it.

A group arrives only when it arrives in each kind that marks it, since the later of the two, and no longer arrives since the first of the two that stopped. Before any line of a kind is read, the group is not yet known. `immune status --json` serves the groups in five lists, `event_level.not_kept`, `kept_never_filled`, `not_yet_known`, `arriving` and `no_longer_arriving`, the last two with the time each began to arrive or stopped. `immune matches` gives the same in `collector`, as the core's latest reading stored them, at `status_read_at`, and not yet known while the store holds no reading. A stretch read from a place can stop anywhere in the log, so only the core's reading, which reads every file to its end, can tell which file is being written. While the level runs and a group is not kept, `in_words` says that the collector installed here is an earlier one, names what it does not keep and says that installing the event level again adds it, with the caveat `earlier_collector`. An earlier install wrote a record, `keeps`; the installer removes it.

Lines an earlier collector wrote are read as before. A rule that reads a field of a group watches only while the group arrives. Otherwise it is listed under `rules.not_watching` with the reason `collector_does_not_keep`, `kept_never_filled`, `not_yet_known` or `no_longer_arriving`, and the groups in `not_arriving`, and is not counted in `watching_rules` or `watching_file_rules`. The rules page says it is not watching, and which, instead of saying it found nothing, and `immune matches` lists the rule in `unevaluated` as `not_collected` with the fields it reads and which state in `detail_text`. `immune matches` also lists it when some line it read did not give the group, whatever the core's latest reading says: a line without the group's key, which the rule was not asked about, or, for `identity` and `signature`, a line with the key and no value. That reading can be older than the lines, as after a downgrade while the app is closed, so whether an answer is quiet rests on `unevaluated`. A group that only some lines fill by nature, as `script` is, is judged by the core's latest reading alone: one start without a script cannot tell a program that runs none from a field the collector stopped filling. After the collector stops filling such a group, an answer over lines the core has not read yet can stay quiet until the core's reading has counted the group's bound, 1,000 program starts for `script`, and for as long as the core does not read at all. No shipped rule reads such a group. A row an earlier build stored as arriving is read as not yet known: that build told a group arriving for ever after one value. Today one field of Elastic's needs a group, `process.code_signature.signing_id` on a file event, and no shipped rule reads it, so this silences none of the shipped rules. A line is judged by what it carries itself, so an older line read after a reinstall is still not given to such a rule.

The status also serves the last day's starts by the hour (`program_starts_by_hour`), the last hour by the minute (`program_starts_by_minute`), and the state in words with its caveats (`in_words`). Rules are said to watch only while the state is `running`.

## The rules

Immune ships three sets of rules, all in Sigma's format, compiled into the program and evaluated in memory by the `sigma-rust` crate, loaded once per process:

- SigmaHQ's 75 rules for macOS from commit `d7c9da1`, byte for byte, in `rules/sigma/` with the licence in `rules/sigma/NOTICE`: 70 over program starts and 5 over file events, 13 marked high, 41 medium, 14 low and 7 informational.
- 66 of Elastic's 185 detection rules for macOS from `elastic/detection-rules` at commit `032ac5e`, each translated into Sigma by a program and shipped as the translator wrote it, in `rules/elastic/` with `rules/elastic/NOTICE`: 60 over program starts and 6 over file events, 1 marked critical, 19 high, 38 medium and 8 low. Elastic's severity is the Sigma level of the same name. The other 119 are listed in `rules/elastic/not-taken.tsv` with the reason each was not taken, and `immune rules` names every one of them.
- 57 of Elastic's 278 behaviour rules for macOS from `elastic/protections-artifacts` at commit `a87715d`, translated by the same program and checked the same way, in `rules/elastic-behaviour/` with `rules/elastic-behaviour/NOTICE`: 54 over program starts and 3 over file events. None states a level, as explained below. The other 221 are listed in `rules/elastic-behaviour/not-taken.tsv` with the reason each was not taken.

The set a rule comes from is a property of the loaded rule. A rule's name is its set and its id, `sigma:<id>`, `elastic:<id>` or `elastic-behaviour:<id>` with Elastic's own rule id, the same in every command, and a finding of a set that raises carries that name. The set also says under which names an event is given to the rule and whether the rule states a level. A program start is asked only of the process rules and a file event only of the file rules. Before the evaluator is asked, one pass over each field finds the texts a rule needs there, so a rule that cannot match is not asked; a test holds this to the same matches as asking every rule, for every set.

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
| `process.code_signature.signing_id` | on a file event, the `signing_id` of the program that did it. On a program start it is not given: no translated rule reads it there, and the field is kept for the response layer |

Every text is also given folded, one character at a time as `sigma-rust` folds, under `immune.folded.` and its name: a translated regular expression that ignores case reads that field, since Sigma's `re` keeps case. Elastic's rules see a path only as Endpoint Security gives it, with no second name through the links into `/private`: the translation was checked that way, and Elastic's rules write `/private/...` where they mean it. A rule's set decides which of these it gets, the short name or the folded copies, through the set's schema in `src/sigma.rs`. `tests/elastic/samples.jsonl` keeps 396 of the translator's invented events with the rules the reference said each matches, three that match and three near misses for every translated rule, and a test holds Immune's evaluation of them to exactly those rules. `tests/elastic-behaviour/samples.jsonl` keeps 341 for the behaviour rules in the same way; one rule matches only 2 of the events made for it, and both are kept.

With file events collected, 175 rules are evaluated in full: 74 of SigmaHQ's, 54 of Elastic's detection rules and 47 of its behaviour rules. 23 are evaluated in part. One of SigmaHQ's reads `OriginalFileName`, a Windows field with no macOS equivalent, in one branch of an OR. Of Elastic's, 9 have an alternative the translation left out because it reads a field the log does not give (`process.parent.code_signature.trusted`, `process.parent.command_line`, `process.Ext.effective_parent.executable` and others), and 3 have one left out because its pattern holds a backslash among wildcards, as in a Windows path. Of the behaviour rules, 10 have an alternative left out for a field the log does not give: the effective parent in 6, whether a signature exists or is trusted in 3, and `process.code_signature.signing_id` in 2, one rule lacking both the effective parent and `signing_id`. A rule that names a field its set's schema does not give is placed the same way as SigmaHQ's, with the field named. `immune rules --json` lists every rule of every set as evaluated in full, in part or not at all, with its set, the reason and how often it matched.

Elastic's behaviour rules state no level. Elastic's sensor sets a behaviour alert's severity when it runs and does not publish which a rule gets, so the translation writes none and Immune gives none of its own. Such a rule is evaluated, and its matches are counted, listed and handed over, and raise nothing. Where a level is printed, a machine reads `null` in the report commands' JSON and `LEVEL_NOT_STATED` (`"not_stated"` in its JSON) in the contract's `Rule` and `Unevaluated`, a value that is not a severity; a match's `raised` is `level_not_stated`, a value of its own, so `below_high` keeps its meaning; a person reads "no level stated". No level is not a place on the scale of severity: wherever rules are ordered or cut by level, these rules are a group of their own, "of a set that states no level", with its own heading and count, after the rules with a level and never ranked among them. A file of this set is read only in the shape the translator writes: its top keys among the translator's, the record's keys exactly its, `severity` and `risk_score` null, no `level`, and no YAML merge key `<<` anywhere, so a level in any spelling is refused rather than ignored. The detection rules' files are held to their translator's shape too, with the record's `severity` equal to the rule's `level`. Upstream, each behaviour rule also stops a process when it matches. The translation records those actions as ignored, and Immune takes no action of any kind.

6 titles are shared by two sets among the rules evaluated, and 14 among all the rules listed, taken or not, each pair under different ids. Among the rules evaluated, a behaviour rule and a detection rule share Dumping Account Hashes via Built-In Commands, Modification of Safari Settings via Defaults Command, Potential Kerberos Attack via Bifrost, Potential Privacy Control Bypass via Localhost Secure Copy and Unexpected Child Process of macOS Screensaver Engine; a behaviour rule and a SigmaHQ rule share Potential XCSSET Malware Infection. An event that matches both rules of a pair is counted once in each set. Every listing of rules names each rule's set beside its title, by one function for a person, and in `source` and `set` for a machine. A test counts both numbers from the loaded rules.

What a match does:

- Every match of every rule is counted, by the hour, for a week.
- A rule marked high or critical raises one finding per rule on the Mac, `sigma:<rule id>` or `elastic:<rule id>`. A repeated match adds to its count and its evidence and raises nothing new. A rule that states no level raises none.
- Severity is the rule's level. Confidence follows the rule's status: medium for `stable`, low otherwise. None of the shipped rules is `stable` (the translation writes `test` for every Elastic rule), so no published rule is urgent and the app does not notify on one.
- The rule's title, authors, techniques, its set's address and licence travel with the finding as data (`published_rule`), as the Detection Rule License asks. An Elastic rule keeps Elastic's rule id and name as its `id` and `title`.
- Matches of lower rules, and of rules with no level stated, are a quiet count. They never change the headline, the count of findings or the icon. The store keeps nothing else of them; `immune matches` reads them from the log, with their events, for the response layer.

`immune rules --over-log` evaluates the rules over the log on disk without the store and prints per rule its level and count, never a command line. `immune matches` evaluates the log with the same code and prints every match with the event it matched, its arguments whole except for the secrets cut out of them, and for a high match the finding the core's own reading put it in. The caller keeps its place in the log, which holds per file what the core's reading keeps for itself (see [reference.md](reference.md#immune-matches)).

## What published rules need that the level does not give

Counted over SigmaHQ at `d7c9da1`, `elastic/detection-rules` at `032ac5e` and `elastic/protections-artifacts` at `a87715d`, for macOS:

- Connections. `eslogger` has no network event. No Sigma rule for macOS needs one. Of Elastic's 185 detection rules for macOS, 19 of the 145 written in EQL involve the network; of its 278 behaviour rules, 38 do. Seeing every connection needs a network extension signed with Apple's permission.
- A process identity that survives a reused pid (Elastic's `entity_id`), required by 125 of Elastic's rules, mostly as the key of a sequence. The collector keeps what tells processes apart, the pid with its version and the start time, but Immune evaluates no sequence and gives no rule an `entity_id`.
- Whether a signature is trusted (`code_signature.trusted`), which `eslogger` does not give. The signer and the code-signing flags are recorded. The three of Elastic's rules for macOS that read `code_signature.signing_id` also read `code_signature.trusted`, so keeping the signer of a file event's program opens none of them.
- `fork`, required by 5 of Elastic's behaviour rules.
- Files changed in place, closed or removed.
- Correlations and sequences: `sigma-rust` does not evaluate Sigma correlations, and the shipped Sigma rules have none.

No rule in these sets reads the end of a process or a connection's byte count. Immune has no evaluator of Elastic's query languages, so Elastic's rules are evaluated only as translated into Sigma. What that leaves out of Elastic's 185 detection rules for macOS:

- 30 correlate a sequence of events, and Sigma's rules here judge one event.
- 40 are written in KQL or ES|QL; only EQL rules are translated.
- 23 are about events the collector does not record (files modified, opened or deleted, network events, library loads, configuration changes and others), and 23 cannot do without a field it does not give (`process.parent.args`, `process.code_signature.trusted`, `process.Ext.effective_parent.executable`, `user.name` and others).
- 2 hold a backslash in a wildcard pattern, whose meaning in Elasticsearch is not documented, and 1 is about program starts and file events at once.

Of Elastic's 278 behaviour rules for macOS, 221 are not taken: 109 correlate a sequence of events, 42 are about events the collector does not record and 61 cannot do without a field it does not give, 4 could never be true over the events here, 1 needs a regular expression in EQL's syntax, 2 use a function of EQL's that is not translated, 1 compares one field with another and 1 is about program starts and file events at once.

The fields those 23 wait for, with how many of them name each, and what the log holds toward it. A rule can name more than one.

| Field | Rules | What the log holds |
|---|---|---|
| `process.Ext.effective_parent.executable` | 6 | `responsible_audit_token` of the process started. Its program is on the responsible process's own `exec` line, if that is in the log. That Elastic's effective parent is macOS's responsible process is not documented |
| `process.parent.args` | 6 | the parent's pid and pid version; its arguments are on the parent's own `exec` line, if that is in the log |
| `process.parent.command_line` | 6 | the same |
| `process.code_signature.trusted` | 3 | nothing: `eslogger` gives no verdict on the certificate chain, and the code-signing flags say whether the code is signed and valid, not whether its signer is trusted |
| `process.parent.code_signature.trusted` | 3 | the same |
| `process.parent.code_signature.exists` | 3 | the signer and code-signing flags of the image before the `exec`; each of the 3 also reads `trusted` |
| `process.code_signature.signing_id` | 2 | given, on file events; both also read `trusted` |
| `process.code_signature.exists` | 1 | the code-signing flags of the program started; the rule also reads `trusted` |
| `user.name` | 1 | the effective and real user ids; a name would be looked up when the log is read. The rule asks for `root`, uid 0 |
| `event.outcome` | 1 | nothing to keep: `eslogger` reports a file created or renamed after it happened, so each is a success. The rule also reads files opened and modified, which the collector does not record |
| `process.pe.original_file_name` | 1 | nothing: a field of Windows executables |
| `process.env_vars` | 1 | nothing: the environment is never written |

So no further field from these events would open one of the 23. Giving `user.name` from the user id, and `event.outcome` as `success`, would open 2 of them without collecting anything more.

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
- Whether a line is split at the turn of a file in practice.
- `eslogger`'s output on macOS 15.
- Whether an `exec` changes the process's pid version, and whether the start time of the process before the `exec` ever differs from the target's.
- A Mac where a kept field stops being filled. The first install on a Mac, on its first log file of 1,060 program starts and 483 file events, filled every field of `identity` (the pid version, the start time, the real user and group ids, and the tokens of the parent and of the responsible process) and of `signature` (the signing id and the code-signing flags) on every program start, and for the process that acted on every file event. `script` held a file on 33 of the starts. So the names and shapes taken from invented samples held there, and how many lines in a row tell that a field stopped is set from those counts. A field that comes out null after a later macOS update is told as no longer arriving, and no rule that reads it is said to watch.
- Whether `eslogger` ever writes an escape `jq` cannot read, such as a lone surrogate for bytes of an argument that are not UTF-8. Such a line becomes the filter's marker and is counted.
- A really full disk. When a write to the log fails, as on a full disk, the writer, `rotatelogs`, empties the file being written and goes on in it; those lines are counted as lost and the day is partial, and they are not told apart from what the kernel dropped. This was seen with a write made to fail on purpose, not on a full disk.
- `rotatelogs` with a rotation time and a size together was tried on this version of macOS (Apache 2.4's `rotatelogs`), with `-p` running at each new file; it has not yet run a day on a Mac.
