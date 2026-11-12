# Contributing to Immune

Immune is built and tested only on Apple Silicon with macOS 15 or later. You need Apple's Command Line Tools (`xcode-select --install`) and Rust 1.89 or later.

## Build and check

```sh
./check     # formatting, linter and tests for the program and the app
./build     # the release program and the menu-bar app, in target/app
```

`./check` runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`, then `swift format lint --strict` over the app's sources, and the app's tests through `app/test`. Every commit has to pass it. Changes reach `main` only through a pull request that passed `./check` on a Mac hosted by GitHub.

To try a debug build of the program on its own, run `cargo build` and call `./target/debug/immune` with `--store <path>`, so that it does not touch the store the app uses. Tests run the real binary over a temporary home folder and a temporary system root (`--system-root`), so nothing real is read; `tests/event_level.rs` is a good example to start from.

## Tests

A test pins a promise to someone: an invariant, or behaviour a user or an agent relies on. The test's name says what the promise is. A test that pins no promise is not needed.

Changed code is checked with mutation testing before it is merged. A test that kills no mutant is removed. A mutant that survives means either a test is missing or the code is not needed, and code that is not needed is removed.

Readers are tested on samples of the real formats they read. Content in tests and fixtures is invented. Data copied from another project, such as advisory records or another library's test fixtures, is copied unchanged and carries a NOTICE beside it with its source and licence.

## Dependencies

A security tool is itself a target, so dependencies are a short allowlist, the one in `Cargo.toml`. A new dependency comes in its own commit, with its reason in the commit and in a comment beside it. When something is needed, look in this order: what macOS ships (a system library or tool), then what the allowlist already holds, then a widely used and maintained crate that brings few dependencies of its own.

Where a mistake would be silent, use a tested implementation of someone else's work: transport, parsing a format someone else defines, ordering versions. Our own code is for our own logic: facts, coverage, findings and answers. If no reference implementation exists, our own code is allowed, with the reason stated in the file and tests on the reference's own samples. Cryptographic primitives are never written here.

The menu-bar app is Swift on the frameworks macOS ships, with no third-party packages. It holds no logic of its own and shows what the commands return in JSON.

## Rules and data

Detection rules are taken from published rule sets and are not invented here. The Sigma rules in `rules/sigma/` are SigmaHQ's rules for macOS, copied byte for byte from one commit, with the source and licence in `rules/sigma/NOTICE`. They are not edited here: a change to a rule belongs upstream at https://github.com/SigmaHQ/sigma. ATT&CK data in `rules/attack/` is made from MITRE's published release, as `rules/attack/NOTICE` describes.

A new reader or collector is added when it widens what published detection rules can be evaluated on. Immune's own rules are plain code with an ATT&CK technique where one fits, how bad and how sure as two values, and two samples: one the rule must fire on and one it must stay silent on.

## What a change has to keep

- Nothing tailored to one machine: no personal paths, host names or folder layouts in code or defaults. A reader first finds out whether its source exists. Not present is "not applicable", not a failure; present but unreadable is a failed reading with its reason.
- Nothing tailored to one stack. A reader or a matcher works for a kind of identifier, such as a distribution's packages or an ecosystem's lockfile, never for one product. Where Immune has no reader, it says so by name.
- No "does not affect me" answer without full and fresh coverage.
- Commands keep stable machine-readable names. An answer carries what it rests on and its coverage. Nothing asks an interactive question. Text from a source goes only in a field ending in `_text`, never into prose an agent could read as an instruction.
- The parts of the program talk only through the store. Nothing is sent out, and nothing is taken from the network as a command.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org) and are in English. `Cargo.lock` is committed.

Contributions are under the [MIT licence](LICENSE) of the repository.

To report a vulnerability, see [SECURITY.md](SECURITY.md).
