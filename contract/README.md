# immune-contract

The Rust types of Immune's contract, package `immune.v1`: the messages the commands of the contract print, in binary protobuf and in Immune's own JSON. It carries the repository's MIT licence.

The schema in `immune/v1/` is the source. `src/immune.v1.rs` is generated from it and committed, so a build needs no `protoc`. The major version is the contract's `format`; see [the reference](../docs/reference.md#the-contract).

Depend on it by a git path at a commit: `immune-contract = { git = "https://github.com/nuanu-ai/immune", rev = "<commit>" }`.

Read binary output with `immune_contract::prost::Message`, as `v1::Known::decode(stdout.as_slice())`, and JSON output with any serde parser, as `serde_json::from_slice::<v1::Known>(&stdout)`.

## Who reads it

[Artificial Immunity](https://immunity.bot) is a closed product from Nuanu AI Lab built on top of Immune. It decides what to do about a finding: triage with a model, response, handing work to an agent. It runs the `immune` binary unchanged and shares no code with it except these types. Immune does not stream every event out. Immune works on its own and does not need Artificial Immunity.

## What the contract covers

The messages of the contract are the answers of `immune matches`, `immune findings`, `immune finding`, `immune project`, `immune program`, `immune machine`, `immune status`, `immune rules`, `immune vulnerabilities`, `immune owner` and `immune sample`, the `Verdict` a program sends to `immune verdict` and the `VerdictRecorded` it gets back, and `Failure`.

Unknown is never zero and never false. A count, a total or a yes-or-no the core could not establish is an optional field that is absent (null in JSON), or it sits inside a message that is absent. A section the core could not give is absent and named in `not_computed` with the reason; a list that is there and empty means there is nothing in it. A reader that takes an absent number as 0 or an absent yes-or-no as `false` reads calm the core did not establish.

## The loop of a program that runs the core

A program that judges what the core found runs four commands. Name the form on every call, `--proto` or `--json`: without one, a command prints text for a person, and `immune verdict` is refused. Check the exit code first: a failure is the message `Failure`, in the form named.

1. `immune matches --proto --after <continue_after>` gives the rule matches since the last call, each with the event it matched, its rule and `raised`, what the core did with it. Keep `continue_after` whole and pass it back. What its `collector` says arrives of the fields a later collector keeps is the core's latest reading, at `status_read_at`, not the stretch. Whether an answer is quiet rests on `unevaluated`, which covers the lines the answer read: a rule that reads a field is listed when that reading says the field does not arrive, and also when some line of the answer did not give it. A group that only some lines fill by nature, as `script` is, is judged by the core's latest reading alone: one start without a script cannot tell a program that runs none from a field the collector stopped filling. After the collector stops filling such a group, an answer over lines the core has not read yet can stay quiet until the core's reading has counted the group's bound, 1,000 program starts for `script`, and for as long as the core does not read at all. No shipped rule reads such a group. A match of a rule whose set states no level has `raised` `level_not_stated`: the core raised nothing and leaves the judgement to the reader.
   A program start's `args_text` has the secrets the core recognises cut out. Each cut is a mark, `\cut{<kind> <length>}`, and the start's `cuts` lists them, one per piece, with `argument`, `kind` and `length`. Go by `cuts`, not by the marks in the text. Since 1.6.0.
2. `immune findings --proto` lists the findings, and `immune finding <id> --proto` gives one with its evidence and the person's answer.
3. `immune project`, `immune program` and `immune machine` answer what the store knows of a thing, with coverage.
4. `immune verdict --proto` reads one `Verdict` on standard input and answers with `VerdictRecorded`.

A `Verdict` names what it is about, a match by the `position` and the rule's `name` as `immune matches` printed them, or a finding by its `id`, and carries the `store_id` of the answer it judged. Its `kind` is `suspicious` or `harmless`. `reason_text` and `case_text` are required. `severity` and `confidence` are required on a `suspicious` verdict and refused on a `harmless` one.

A secret the core recognises in `reason_text` is cut where the reason is kept, and the verdict is recorded: `RecordedVerdict.reason_cuts` lists what was cut. A mark quoted from the core's output, bare or with its backslash doubled as JSON writes it, is a value already cut and is kept as text, so a reason can quote what the core printed. A key holding a secret is refused with `holds_secret` and is never rewritten: `case_text`, `store_id` or what the verdict names. A failure cuts what it repeats of what it was sent. Since 1.6.0.

To keep the words of a quote of the core's output, quote it as the text form prints it, or leave a space after each cut value. A mark glued to more text in its word, as compact JSON writes `"…\cut{immune:flag-value 11}"],"cuts":`, starts a value that goes on, and the rest of that word is cut as after a real value. The reason is still recorded with every mark it quoted, and `reason_cuts` lists the cut.

The person's reasons are cut the same way: an `Answer` in `immune finding` and `immune status`, and a `Statement` or `Said` in `immune owner`, carry `reason_text` cut and `reason_cuts` beside it. Cutting always runs, so an empty `reason_cuts` means nothing was cut. Since 1.7.0.

A verdict never changes a finding the core raised. A `suspicious` one raises a finding of the rule `verdict.suspicious`, with the verdict's levels, which the person closes. A `harmless` one is kept and shown beside what it is about. The whole of it is in [the reference](../docs/reference.md#immune-verdict).
