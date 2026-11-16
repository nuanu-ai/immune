# Background service

The core runs as a launch agent in your macOS login session. The menu-bar app can open or quit independently.

## Install

If you are moving from an earlier bundled build, quit its menu-bar app before installing the service. The earlier app holds the store's watcher lock while it runs.

```sh
core=$(./build)
"$core" install
"$core" status
```

Run `install` as the user being watched, without `sudo`. It registers the core with launchd as `~/Library/LaunchAgents/ai.nuanu.immune.watch.plist`, and the job runs `immune watch --background`. The home folder here is the account's own, read from the user database, and `$HOME` is not used: launchd loads the `LaunchAgents` of that home at login. Installing the launch agent can appear as a new watched item in a store that already has a baseline of LaunchAgents.

Which file the job runs depends on whether this account can replace the core `install` was run from. `install` resolves the path's links and looks at the file and every folder above it up to `/`: their owner, group and mode, and the sticky bit, against the account's uid and groups.

- The account can replace it, as it can a build in a checkout. `install` copies it to `~/Library/Application Support/ai.nuanu.immune/bin/immune`, the store's folder, and the job runs the copy, so a rebuild, a switch of branch or a removed checkout does not change the running core.
- The account cannot replace it, as for a core a signed package put in a folder owned by root, such as `/usr/local/bin/immune`. The job runs it where it is and nothing is copied: a copy in the home folder could be replaced by any program of the account, and an update of the package would never reach the job. A copy an earlier install left is removed once the old job has stopped.

The answer's `in_place` says which. The test reads modes only: an access control list that lets the account write a folder owned by root is not seen, and such a core is run where it is, which is no less safe than a copy the account can replace.

Only one `install` or `uninstall` runs at a time; a second one fails with `busy` and changes nothing. Before it changes anything, `install` refuses when it runs as root, when the account has no home folder with an absolute path, when launchd has no login session for the user, when a symbolic link stands at the property list, at `bin` or at `bin/immune`, and when the property list there belongs to another job.

`install` then prepares the new property list and the new copy under temporary names and renames them into place, the copy first, while the old job is left alone. The running process keeps the binary it opened and launchd keeps the configuration it loaded, so the job is not stopped; the full checks it starts, and a restart, run the new copy from then on. The installed file is never written in place. Only then does `install` stop the old job, wait until launchd no longer has it, and load the new one. Each failure says what `install` did and did not touch, and what launchd answered:

- The copy cannot be put in place: the installed core, the property list and the job launchd has were not touched.
- The property list cannot be put in place: the property list and the job were not touched; the new core is in place unless `install` was run from the installed copy. Run `install` again.
- launchd still has the old job after the wait, 30 seconds when it took the stop and 2 when it refused it: the core and its property list are in place. Run `install` again.
- Loading the new job fails: the job may be stopped, and the new core and its property list are in place. Run `install` again.

The store is kept in every case. `install` says the job is loaded only after `launchctl print` has found it.

After launchd loaded the job, `install` waits up to 5 seconds for a watcher to watch the store live, by the same test `immune status` uses. Its answer says one of three things: watching; loaded and not watching yet, with what the status says of the watcher, such as that it has not completed its first reading; or that it cannot tell. The first line of the text carries the mark ✓ only in the first case.

The answer is the contract's `Service` message: the job's label, the paths of the core the job runs and of the property list, whether the job is installed, loaded and replaced something, whether the core is run where it is, and whether a watcher was watching. As text it says that in its first line, then each step with its path or the label, whether an earlier installation was replaced, and the command to run next. `uninstall` lists what is gone and says the store and the event collector were kept. Add `--json` or `--proto` for an agent or a program.

The core starts watching at login. It schedules a full check when it starts and every hour after that. After sleep it starts one overdue check. Two full checks cannot use the same store at once. A background full check can run for up to 30 minutes. A watcher that makes no progress for three minutes exits so launchd can restart it. Status drops live coverage when the last heartbeat is too old.

The watcher the job runs looks at every heartbeat whether the path it was started from still holds the same file, by device and inode. When an update replaced the file, or removed it, the watcher leaves by itself between readings, says why on stderr and in its lock file, and launchd starts it again from the new file. For up to two minutes, until a new watcher holds the store, `immune status` says the watcher is restarting on a new core. A watcher started by hand or by the app is not stopped this way.

Check `immune status --json` for `watching`, `last_finished_run` and what has actually been covered. With no watcher on the store, the status tells a job whose property list is in place, "installed, not running", from one that is not installed, by the file alone. If the job fails to start, `launchctl print "gui/$(id -u)/ai.nuanu.immune.watch"` shows its state and last exit status.

## Update

Build the new core and run its `install`:

```sh
core=$(./build)
"$core" install
```

The new copy replaces the old one by rename, and the job is restarted on it. Running `install` from the installed copy itself registers the job again and leaves the copy as it is. A core run where it is is updated by whatever put it there, such as a new package; the running watcher sees its file replaced and launchd starts the new one, with no `install`.

The optional app is built against the installed copy's path, `app/build "$HOME/Library/Application Support/ai.nuanu.immune/bin/immune"`, so an update of the core does not need a new build of the app.

## Stop and remove the job

```sh
"$HOME/Library/Application Support/ai.nuanu.immune/bin/immune" uninstall
```

Any build of the core can run `uninstall`, the installed copy included. It stops the job, removes its property list and the installed copy, and removes `bin` when nothing else is in it. A core the job ran where it is was not put there by `install`, so `uninstall` leaves it and its answer names where it is. It keeps the store and everything else in the store's folder, the optional app and the optional event collector. If the stop fails, the property list and the copy are kept. Run where nothing is installed, it says so. To check the Mac once without the service, run `immune run` from a build. To restore continuous coverage, install the service again. Logging out stops the login job until your next login.
