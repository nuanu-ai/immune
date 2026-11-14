# Immune's own rules

Sigma rules of Immune's own over the event log. A rule is written here only where no published rule, SigmaHQ's or Elastic's, covers what it detects, so the folder may hold none. The rules are compiled into the binary, are named `immune:<id>`, and change only with a new version of the program.

Each rule `<name>.yml` has two samples beside it, invented lines as the collector writes them: `<name>.fires.jsonl`, which the rule must match, and `<name>.silent.jsonl`, an event of its kind that it must not. A test refuses a rule without both, a sample that does not behave as named, and a rule not evaluated in full on the fields the collector gives. [docs/rules.md](../../docs/rules.md) says how to write one and lists those fields.
