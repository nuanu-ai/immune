# Writing a rule of Immunity Core's own

Immunity Core evaluates published Sigma rules over the program starts and file events its collector records: SigmaHQ's rules for macOS, and Elastic's rules translated into Sigma. A rule of Immunity Core's own is a Sigma file in this repository, read by the same loader and evaluated by the same evaluator. It is written only where no published rule covers what it detects. Before writing one, check SigmaHQ's rules and Elastic's for the behaviour.

Immunity Core's own rules are compiled into the binary and arrive with a new version of the program. Nothing updates them from outside.

## Where it goes

Put the rule in `rules/immunity/` as `<name>.yml` and list its path in `IMMUNITY_SHIPPED` in `src/sigma.rs`. A test fails while the folder and the list differ. The folder is flat.

A rule is named `immunity:<id>` in `immunity rules`, `immunity matches` and every finding, as a published rule is named by its set and its id. It needs an `id`, a `status`, a `level` and a `logsource` with `product: macos` and the category `process_creation` or `file_event`. Write it to SigmaHQ's conventions.

The level decides what a match does, as for a published rule. A match of a `high` or `critical` rule raises a finding; a match below that is counted and handed over in `immunity matches`. The finding's confidence follows the status: medium for `stable`, low otherwise.

## The two samples

Beside each rule go two samples, each one or more lines as the collector writes them to its log:

- `<name>.fires.jsonl`: the rule must match every line;
- `<name>.silent.jsonl`: the rule must match none, and every line is an event of the rule's kind.

Samples are invented. Use invented names such as `/Users/example/...` and `tool-x`, never a path, host or command line from a real Mac. Never run a command a rule describes in order to make a sample. `tests/immunity-rules/` holds an invented rule with its two samples, which shows the format of a line and is never shipped.

## Running the test

```
cargo test --bin immunity a_rule_of_immunity_s_own
```

The test reads every rule in `rules/immunity/` through the loader every set goes through. It fails for a rule without both samples, for a sample line the rule matches or misses against its name, for a line that is not one the collector writes, and for a rule that is not evaluated in full on the fields below. Such a rule would be shipped as "not evaluated" and would judge nothing. `./check` runs it with every other test.

## Fields

A rule of Immunity Core's own reads an event under SigmaHQ's taxonomy. These are the fields the collector gives. A rule that names any other field is not evaluated in full, and the test refuses it. [event-level.md](event-level.md#the-rules) says how each is taken from the collector's line.

### A program start

| Field | What it holds |
|---|---|
| `Image` | the path of the program started |
| `CommandLine` | its arguments joined by single spaces, the first included, with no quoting |
| `ParentImage` | the program the process ran before this start, which after a fork is the parent's program and after an `exec` without a fork is the wrapper |

### A file created or renamed

| Field | What it holds |
|---|---|
| `TargetFilename` | the path of the file created, or where a renamed file went; under `/private/etc`, `/private/tmp` and `/private/var` the event is also given with the short path through the link |
| `Image` | the path of the program that created or renamed it |
