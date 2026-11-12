# Security policy

Immune is a security tool, so a flaw in it can hide an attack or open a new way in. Please report one privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's Security tab and choose "Report a vulnerability". Only the maintainers see the report. Please do not open a public issue or pull request for it.

Say what you found, which commit you tested, and how to reproduce it on a Mac. Use invented data in your example and leave out anything real from your own machine: paths, host names, addresses, command lines.

There are no releases yet, so reports are taken against the latest commit on the main branch.

## What counts

Anything in this repository: the `immune` program, the menu-bar app, and the collector scripts in `scripts/event-level/`. These matter most:

- Immune says a Mac is quiet, or answers "does not affect me", when it did not read what that answer needs.
- Text from a file on the Mac, a vulnerability feed or an indicator list ends up run as a command, used as a path, or returned outside the fields ending in `_text`.
- The collector, which runs as root, runs anything from a place another account can write, or lets another account read its log.
- Immune sends something about the Mac over the network, or makes a request that depends on what is on it.
- A finding is closed or hidden without the answer being recorded and shown in the app.

Some limits are known and documented in the README, such as answers not being signed, a matched program start's command line kept as evidence with any secret in it, and `eslogger` not being a stable interface. A report that shows one of them is worse than documented is welcome.

A problem in a SigmaHQ rule itself, such as a rule that misses a technique or matches too much, belongs upstream at https://github.com/SigmaHQ/sigma. Immune ships those rules unchanged.
