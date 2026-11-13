# immune-contract

The Rust types of Immune's contract, package `immune.v1`: the messages the commands of the contract print, in binary protobuf and in Immune's own JSON. It carries the repository's MIT licence.

The schema in `immune/v1/` is the source. `src/immune.v1.rs` is generated from it and committed, so a build needs no `protoc`. The major version is the contract's `format`; see [the reference](../docs/reference.md#the-contract).

Depend on it by a git path at a commit: `immune-contract = { git = "https://github.com/nuanu-ai/immune", rev = "<commit>" }`.

Read binary output with `immune_contract::prost::Message`, as `v1::Known::decode(stdout.as_slice())`, and JSON output with any serde parser, as `serde_json::from_slice::<v1::Known>(&stdout)`.
