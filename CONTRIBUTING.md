# Contributing to Immune

Immune is built and tested only on Apple Silicon with macOS 15 or later. You need Apple's Command Line Tools (`xcode-select --install`) and Rust 1.89 or later.

The rules a change has to keep (dependencies, where our own code ends, nothing tailored to one machine or one stack, the one seam, agent first, tests) are in [AGENTS.md](AGENTS.md). Read it before you change code; your coding agent reads it too. How the program is built is in [docs/how-it-works.md](docs/how-it-works.md).

## Build and check

```sh
./check     # formatting, linter and tests for the program and the app
./build     # the release program and the menu-bar app, in target/app
```

`./check` runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`, then `swift format lint --strict` over the app's sources, and the app's tests through `app/test`. Every commit has to pass it. A part can be run by name: `./check lint`, `./check tests`, `./check app`, or one half of the test binaries with `./check tests 1/2` or `./check tests 2/2`. The check on GitHub runs `lint app` and the two halves side by side.

To try a debug build of the program on its own, run `cargo build` and call `./target/debug/immune` with `--store <path>`, so that it does not touch the store the app uses. Tests run the real binary over a temporary home folder and a temporary system root (`--system-root`), so nothing real is read; `tests/event_level.rs` is a good example to start from.

## Rules and data

The Sigma rules in `rules/sigma/` are SigmaHQ's rules for macOS, copied byte for byte from one commit, with the source and licence in `rules/sigma/NOTICE`. They are not edited here: a change to a rule belongs upstream at https://github.com/SigmaHQ/sigma. ATT&CK data in `rules/attack/` is made from MITRE's published release, as `rules/attack/NOTICE` describes.

## Proposing a change

Open an issue first for a new reader, a new collector or a new dependency, so it can be weighed against the rules in AGENTS.md before code is written. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org) and are in English.

A change arrives as a pull request, and `./check` runs on it on a macOS runner. A pull request that changes `check`, `app/test` or anything under `.github/` is read by a maintainer before its result counts: a passing check on a change to the check itself shows nothing.

Contributions are under the [MIT licence](LICENSE) of the repository.

To report a vulnerability, see [SECURITY.md](SECURITY.md).
