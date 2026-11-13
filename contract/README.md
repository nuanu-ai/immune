# immune-contract

The Rust types of Immune's contract, package `immune.v1`: the messages the commands of the contract print, in binary protobuf and in Immune's own JSON. It carries the repository's MIT licence.

The schema in `immune/v1/` is the source. `src/immune.v1.rs` is generated from it and committed, so a build needs no `protoc`. The major version is the contract's `format`; see [the reference](../docs/reference.md#the-contract).

Depend on it by a git path at a commit: `immune-contract = { git = "https://github.com/nuanu-ai/immune", rev = "<commit>" }`.

Read binary output with `immune_contract::prost::Message`, as `v1::Known::decode(stdout.as_slice())`, and JSON output with any serde parser, as `serde_json::from_slice::<v1::Known>(&stdout)`.

## The loop of a program that runs the core

A program that judges what the core found runs four commands. Name the form on every call, `--proto` or `--json`: the default differs between commands today.

1. `immune matches --proto --after <continue_after>` gives the rule matches since the last call, each with the event it matched, its rule and `raised`, what the core did with it. Keep `continue_after` whole and pass it back. A match of a rule whose set states no level has `raised` `level_not_stated`: the core raised nothing and leaves the judgement to the reader.
2. `immune findings --proto` lists the findings, and `immune finding <id> --proto` gives one with its evidence and the person's answer.
3. `immune project`, `immune program` and `immune machine` answer what the store knows of a thing, with coverage.
4. `immune verdict --proto` reads one `Verdict` on standard input and answers with `VerdictRecorded`.

A `Verdict` names what it is about, a match by the `position` and the rule's `name` as `immune matches` printed them, or a finding by its `id`, and carries the `store_id` of the answer it judged. Its `kind` is `suspicious` or `harmless`. `reason_text` and `case_text` are required. `severity` and `confidence` are required on a `suspicious` verdict and refused on a `harmless` one.

A verdict never changes a finding the core raised. A `suspicious` one raises a finding of the rule `verdict.suspicious`, with the verdict's levels, which the person closes. A `harmless` one is kept and shown beside what it is about. The whole of it is in [the reference](../docs/reference.md#immune-verdict).
