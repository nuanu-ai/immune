# Immune

The rules for anyone who changes this code, a person or an AI coding agent. Read this before a change. [docs/how-it-works.md](docs/how-it-works.md) explains the design these rules protect, and [CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and propose a change.

## Language

- The project is in English: code, comments, documents, commit messages and pull request descriptions.
- An agent talks to the person it works with in the language they write in.
- Prose for a reader is plain: no sales words, no dramatic closers, sentence-case headings. Every fact, number and name stays exact. Code, commands, paths and field names are written as they are.
- Keep documents short. Add a file only when there is something to put in it.

## How we build

- Stack: Rust, standalone binaries, SQLite compiled into the binary.
- Target: macOS on Apple Silicon. No other platform is built or tested.
- Dependencies are a short allowlist, the one in `Cargo.toml`. A security tool is itself a target, so each dependency is attack surface. A new one comes in its own commit, with its reason in the commit message and in a comment beside it.
- Where our own code ends. Our own code is for our own logic: facts, coverage, lifecycle, findings and answers. Anything with a reference implementation where a mistake would be silent (cryptography, transport, parsing a format someone else defines, ordering versions) uses a tested implementation. Look in this order: what macOS ships, a system library or tool; then what the allowlist already holds; then a new crate that is widely used, maintained and brings few dependencies of its own. When none exists, our own code is allowed, with the reason stated in the file and tests on the reference's own samples. Cryptographic primitives are never written here, whatever the reason.
- The same holds for approaches: how detection is built, what things are called, where rules come from. Take what the industry has proven and design something new only where it has nothing. Before a new part is designed, compare it with industry practice and say in `docs/how-it-works.md` what is adopted and what is Immune's own.
- First a working whole in rough form, then refinement. Fixing a mistake is usually cheaper than guarding against it in advance. Two exceptions, where a mistake is silent or cannot be undone, need their invariants and tests from the first version:
  - false calm: a "does not affect me" answer without full and fresh coverage;
  - anything that acts: stopping a process, access to servers.
- Nothing is tailored to one machine. No personal paths, host names or folder layouts go into code or defaults; locations that hold on every Mac are fine. A reader first finds out whether its source exists. Not present is "not applicable", which is not a failure. Present and unreadable is a failed reading with its reason.
- Nothing is tailored to one stack. People run Immune on stacks unlike any one developer's: other distributions, other languages, no servers at all. A reader or a matcher is a general mechanism for a kind of identifier (a distribution's packages, an ecosystem's lockfile), never a rule for one product. A hand-made mapping for a product is data, stays small, and never supports "does not affect me, known for certain". Where Immune has no reader or matcher for a kind of place, it says so by name: what it cannot judge on this stack is part of every report.
- One seam. The parts talk only through the store: facts, coverage, events and the journal. Do not add other layers or interfaces in advance.
- No model on the collection path, the detection path or a stop path.

## What the core is

This repository is the detection core: collection, the store, rules from published sources, findings with their confidence and coverage, the user's answers, the commands and a plain app. The core sends nothing about the Mac out, takes no command from the network, listens on no socket and holds no model. Its only network requests are the public threat data described in `docs/threats.md`, and they never depend on what is on the Mac.

What is done about a finding (triage by a model, response, handing work to an agent) belongs to a separate layer outside this repository. That layer runs the core's binary unchanged and talks to it only by running its commands. It shares no code with the core.

What that layer reads and writes is defined by a protobuf schema in this repository, with its version, in `contract/immune/v1/`. The core is a detector and not a sensor: it hands over what it concluded and is not sure of (rule matches with the event each matched, and what was lost), answers to questions about the Mac and its surroundings, and takes a verdict back. It does not stream every event out. Built so far are what the store knows of a project (`immune project`) and the queue of rule matches with the tally of what was read and lost (`immune matches`); the questions about a program and a machine, and the verdict, are planned. The schema is the source: the core's types for its messages are generated from it, a command of the contract prints binary protobuf by default and the same message as JSON with `--json`, and that JSON is never written by hand beside the schema. The report commands (`status`, `findings`, `finding`, `rules`, `vulnerabilities`) keep their own JSON until that layer reads one of them. A verdict may raise a match to a finding, or say that a match or a finding was looked into and judged harmless. The core records it beside what it is about and shows it; it never closes a finding, which stays open until the person answers it.

## What enters the core

One question decides: does it widen what published detection rules can be evaluated on. Rules are taken from published sets, not invented here; Immune writes its own rule only where no published one exists, as for software changed in place. Data the response layer needs for its own classification is given when the core already receives it and it costs little. A new reader that no published rule would use is discussed in an issue and agreed by the maintainers before any code is written.

## Agent first

- The first user of the program is the user's AI agent, and the commands are its interface, so they are a product. Every command has a machine-readable form with stable names. An answer carries what it rests on and its coverage. Nothing asks an interactive question.
- Text taken from a source is returned as data in a field whose name ends in `_text`, and never mixed into prose an agent could read as an instruction. A file on the Mac may have been written by an attacker for an agent to read.
- For a person there is a native menu-bar app. It calls the same operations as the commands, so nothing a person can do lives in only one of the two. The app is Swift on the frameworks macOS ships, with no third-party packages, and holds no logic of its own: it shows what the commands return in JSON.
- An agent may read, and may add to what is watched. It may answer a finding or make a statement about a server (retired, not the user's) only after the person has agreed in the conversation, having been told what it is and what the options are. Such an answer records that it came through an agent and why, and the app shows it, so the person can take it back. Anything that acts on a server stays a request that the person turns into a decision.
- Answers are not signed. A program that targets Immune directly can rewrite the store without tricking an agent, and guarding against that is not built. The promise is that nothing is quieted silently, not that it cannot be done.

## Tests

- A test pins a promise to someone: an invariant, or behaviour a user or an agent relies on. The test's name says what the promise is. A test that pins no promise is not needed.
- Changed code is checked with mutation testing before it is merged. A test that kills no mutant is deleted. A surviving mutant means either a test is missing or the code is not needed, and code that is not needed is deleted. A full mutation run happens now and then and blocks nothing.
- Readers are tested on samples of the real formats they read. Content in tests and fixtures is invented. Data copied from another project is copied unchanged and carries a NOTICE beside it with its source and licence.
- Each of Immune's own rules has two samples: one it must fire on and one it must stay silent on.
- Every commit runs formatting, the linter and the tests. That takes seconds.

## Discipline

- One command runs all checks: `./check`.
- Commit messages follow Conventional Commits and are written in English.
- `Cargo.lock` is committed.
- Never put anything real from your own Mac into the repository: paths, host names, addresses, command lines. Examples and fixtures are invented.
