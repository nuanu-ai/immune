# Background service

The core runs as a launch agent in your macOS login session. The menu-bar app can open or quit independently.

## Install

If you are moving from an earlier bundled build, quit its menu-bar app before installing the service. The earlier app holds the store's watcher lock while it runs.

```sh
core=$(./build)
"$core" install
"$core" status
```

Run `install` as the user being watched, without `sudo`. It copies the binary it was run from to `~/Library/Application Support/ai.nuanu.immune/bin/immune`, the store's folder, and registers that copy with launchd as `~/Library/LaunchAgents/ai.nuanu.immune.watch.plist`. The home folder here is the account's own, read from the user database, and `$HOME` is not used: launchd loads the `LaunchAgents` of that home at login. The job runs `immune watch --background` from the copy, so a rebuild, a switch of branch or a removed checkout does not change the running core. Installing the launch agent can appear as a new watched item in a store that already has a baseline of LaunchAgents.

Only one `install` or `uninstall` runs at a time; a second one fails with `busy` and changes nothing. Before it changes anything, `install` refuses when it runs as root, when the account has no home folder with an absolute path, when launchd has no login session for the user, when a symbolic link stands at the property list, at `bin` or at `bin/immune`, and when the property list there belongs to another job.

`install` then prepares the new property list and the new copy under temporary names and renames them into place, the copy first, while the old job is left alone. The running process keeps the binary it opened and launchd keeps the configuration it loaded, so the job is not stopped; the full checks it starts, and a restart, run the new copy from then on. The installed file is never written in place. Only then does `install` stop the old job, wait until launchd no longer has it, and load the new one. Each failure says what `install` did and did not touch, and what launchd answered:

- The copy cannot be put in place: the installed core, the property list and the job launchd has were not touched.
- The property list cannot be put in place: the property list and the job were not touched; the new core is in place unless `install` was run from the installed copy. Run `install` again.
- launchd still has the old job after the wait, 30 seconds when it took the stop and 2 when it refused it: the core and its property list are in place. Run `install` again.
- Loading the new job fails: the job may be stopped, and the new core and its property list are in place. Run `install` again.

The store is kept in every case. `install` says the job is loaded only after `launchctl print` has found it.

The answer is the contract's `Service` message: the job's label, the paths of the installed core and of the property list, and whether the job is installed, loaded and replaced something. Add `--json` or `--proto` for an agent or a program.

The core starts watching at login. It schedules a full check when it starts and every hour after that. After sleep it starts one overdue check. Two full checks cannot use the same store at once. A background full check can run for up to 30 minutes. A watcher that makes no progress for three minutes exits so launchd can restart it. Status drops live coverage when the last heartbeat is too old.

Check `immune status --json` for `watching`, `last_finished_run` and what has actually been covered. If the job fails to start, `launchctl print "gui/$(id -u)/ai.nuanu.immune.watch"` shows its state and last exit status.

## Update

Build the new core and run its `install`:

```sh
core=$(./build)
"$core" install
```

The new copy replaces the old one by rename, and the job is restarted on it. Running `install` from the installed copy itself registers the job again and leaves the copy as it is.

The optional app is built against the installed copy's path, `app/build "$HOME/Library/Application Support/ai.nuanu.immune/bin/immune"`, so an update of the core does not need a new build of the app.

## Stop and remove the job

```sh
"$HOME/Library/Application Support/ai.nuanu.immune/bin/immune" uninstall
```

Any build of the core can run `uninstall`, the installed copy included. It stops the job, removes its property list and the installed copy, and removes `bin` when nothing else is in it. It keeps the store and everything else in the store's folder, the optional app and the optional event collector. If the stop fails, the property list and the copy are kept. Run where nothing is installed, it says so. To check the Mac once without the service, run `immune run` from a build. To restore continuous coverage, install the service again. Logging out stops the login job until your next login.
