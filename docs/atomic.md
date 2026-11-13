# Attack simulations

How much of a simulated attack Immune notices, measured run by run. The tests are [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)'s for macOS, with a few controls of Immune's own, run inside a disposable virtual machine with Immune installed. Each run is one table in [`docs/atomic/`](atomic/), and this page keeps the totals, so a change in the collector or in the rules shows as a change in the numbers.

The tests are not part of `./check`, and nobody should run them on a Mac they use. A table holds no command line: a test is named by its ATT&CK technique, its number and its identifier in Atomic Red Team, where the test itself is published.

## How to read a table

One row is one check. `status` is what happened to the test: `executed` when its effect was confirmed, `failed`, `blocked` or `unavailable` when macOS or the image did not let it happen. `outcome` is what Immune made of it:

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

- Of the 9 findings, 7 came from Immune's own readers: a launch agent or daemon three times, a shell profile, the ssh access file, a signed app changed in place and an editor task set to run when a folder is opened. Two came from published rules marked high, and one of those matched a helper of the test bench and not the technique.
- 27 confirmed checks were matched on the technique's own step and only below high: the 26 marked `technique` among `below_high`, and the one whose finding came from a helper. For 20 of them neither set has a rule marked high, so more rules would not turn them into findings. For 5 Elastic has a high rule that was not taken, because the collector lacks a field it reads.
- The build held SigmaHQ's rules alone. Elastic's 66 were shipped after it and were not evaluated over these logs. Going by the rule files, the remaining 2 of the 27 have a high rule among them.
- The three checks that restarted or shut the machine down are not in the log: the collector went down with it. Immune reported the gap.
- Places where a test left persistence and Immune raised nothing: StartupItems, the login window's preferences and the sudoers file are not watched places, and a launchd job with no file on disk is not read.
- Not recorded by the collector, and behind most of the checks that matched nothing: connections, a file opened, changes of a file's mode, owner or times, account and group changes, and logins.

Test names and identifiers in the tables are Atomic Red Team's; see [`docs/atomic/NOTICE`](atomic/NOTICE).
