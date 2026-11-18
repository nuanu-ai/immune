# Attack simulations

How much of a simulated attack Immunity Core notices, measured run by run. The tests are [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s for macOS, with a few controls of Immunity Core's own, run inside a disposable virtual machine with Immunity Core installed. Each run is one table in [`docs/atomic/`](atomic/), and this page keeps the totals, so a change in the collector or in the rules shows as a change in the numbers.

The tests are not part of `./check`, and nobody should run them on a Mac they use. A table holds no command line: a test is named by its ATT&CK technique, its number and its identifier in Atomic Red Team, where the test itself is published.

## How to read a table

One row is one check. `status` is what happened to the test: `executed` when its effect was confirmed, `failed`, `blocked` or `unavailable` when macOS or the image did not let it happen. `outcome` is what Immunity Core made of it:

| Outcome | Meaning |
|---|---|
| `finding` | A finding was raised, the thing a person sees. `finding` names its rule |
| `below_high` | A published rule matched, at a level below high. The match is counted and no finding is raised |
| `not_matched` | The event is in the collector's log and no rule matched it |
| `not_in_log` | The event did not reach the log |
| `not_confirmed` | The test's own effect did not happen, so nothing is measured |

`matched_on` says whether the matches were on the technique's own step, on a `helper` step around it, or `unclear`: the run's results name rules, not events, so this is read from the rules' conditions. `published_matches` lists every published rule that matched with its level. For a check that raised no finding on the technique, `cause` says what stood in the way:

| Cause | Meaning |
|---|---|
| `no_high_rule` | Neither shipped set has a rule marked high for it |
| `high_rule_not_taken` | Elastic has a high rule for it, not taken because the collector lacks a field it reads |
| `high_rule_shipped_since`, `rule_shipped_since` | A rule for it is shipped now and was not in the build that ran |
| `rule_not_taken` | Elastic has a rule for it that was not taken, see `rules/elastic/not-taken.tsv` |
| `rule_too_narrow` | A shipped rule describes the behaviour and names fewer tools or forms than were used |
| `no_rule` | Neither set has a rule for it |
| `collector_down` | The collector was not running |

## Runs

| Run | Build | macOS | Checks | Effect confirmed | Finding | Below high | Not matched | Not in log |
|---|---|---|---:|---:|---:|---:|---:|---:|
| [12 November 2026](atomic/2026-11-12.tsv) | `1f60bf9`, SigmaHQ's 75 rules | 15.7.7 | 74 (70 of Atomic Red Team, 4 controls) | 59 | 9 | 34 | 13 | 3 |

## What the first run showed

- Of the 9 findings, 7 came from Immunity Core's own readers: a launch agent or daemon three times, a shell profile, the ssh access file, a signed app changed in place and an editor task set to run when a folder is opened. Two came from published rules marked high, and one of those matched a helper of the test bench and not the technique.
- 27 confirmed checks were matched on the technique's own step and only below high: the 26 marked `technique` among `below_high`, and the one whose finding came from a helper. For 20 of them neither set has a rule marked high, so more rules would not turn them into findings. For 5 Elastic has a high rule that was not taken, because the collector lacks a field it reads.
- The build held SigmaHQ's rules alone. Elastic's 66 were shipped after it and were not evaluated during the run. Going by the rule files, the remaining 2 of the 27 have a high rule among them.
- The three checks that restarted or shut the machine down are not in the log: the collector went down with it. Immunity Core reported the gap.
- Places where a test left persistence and Immunity Core raised nothing: StartupItems, the login window's preferences and the sudoers file are not watched places, and a launchd job with no file on disk is not read.
- Not recorded by the collector, and behind most of the checks that matched nothing: connections, a file opened, changes of a file's mode, owner or times, account and group changes, and logins.

Test names and identifiers in the tables are Atomic Red Team's; see [`docs/atomic/NOTICE`](atomic/NOTICE).

## Replay of the 12 November logs

The [replay table](atomic/2026-11-12-replay.tsv) uses Immunity Core at `8aa8387`, with 75 SigmaHQ rules, 66 Elastic detection rules and 57 Elastic behaviour rules. The lab confirmed the effects of 55 Atomic Red Team checks. Of those, 52 had a saved event window. Published rules matched in 38 of the 52 windows, Elastic rules matched in 6, and a high or critical rule matched in 2. The 3 restart and shutdown checks had no window because the collector went down.

A window can include preparation, cleanup and unrelated activity. To attribute the following matches, each saved event in those windows was replayed on its own.

| Check | Match on the saved event |
|---|---|
| `T1548.003#3`, `T1548.003#5` | Elastic's medium Sudoers File Activity rule matched a creation and a rename of related files in each case. |
| `T1037.002#1`, `T1547.007#2` | Elastic's medium Persistence via Login or Logout Hook rule matched the step that set the login hook in each case. |
| `T1555.001#1` | Elastic's high Keychain dump rule and SigmaHQ's medium Keychain rule matched the same program start. |
| `T1078.003#4` | The high SigmaHQ match came from a test helper. Elastic and SigmaHQ both matched the root account step at medium. |
| `T1115#3` | SigmaHQ matched clipboard access at medium. The Elastic high rule had no match in this window. |

The four controls are outside the Atomic Red Team totals. The exact-name Axios control had one high match. Both Axios windows had a medium match. The editor and app integrity controls had state findings in the original run and empty match counts in the replay.

The table also gives windows for the 15 checks whose effects were unconfirmed. `window_matches` lists space-separated `set:rule-id/level/count` entries. `none` means the window had zero matches. The `collector_down` rows have blank counts and `not_replayed` in `window_matches`.

The replay covers only saved program starts and file creations and renames. Its loss counts cover gaps within those slices. It cannot measure live collection or state readers, recover events the collector missed, or establish which findings a live run would raise.

### Replaying the lab archive

1. For each check with a saved window, use the final `stage` in the archived `vm-results.tsv`. In `vm-inbox/<stage>/analysis.json`, find the matching `test` under `results` and take the `begin` and `end` entries in `markers`. The two offsets are byte positions in that stage's `log/exec-20261112T17.jsonl`. Check that both offsets fall on line boundaries, then copy the bytes strictly between the marker lines. The slice starts after the newline of `begin` and ends at the byte offset of `end`.
2. In a temporary system root, copy the repository's `scripts/event-level/ai.nuanu.immunity.core.eslogger.plist` to `Library/LaunchDaemons/`. Under `Library/Application Support/ai.nuanu.immunity.core/event-level/`, write the plist's `ProgramArguments` as a JSON array in `collects`, then place the slice in `log/exec-20261112T17.jsonl`. Keep just that window in the log. The files are read as data without loading the daemon.
3. Run `immunity rules --over-log --system-root "$replay_root" --json` for each window. The `Replay` message gives event and loss counts and the published rule IDs, levels and counts. [Command reference](reference.md#commands)
