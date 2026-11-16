# Background service

The core runs as a launch agent in your macOS login session. The menu-bar app can open or quit independently.

## Turn on

If you are moving from an earlier bundled build, quit its menu-bar app before turning Immune on. The earlier app holds the store's watcher lock while it runs.

```sh
core=$(./build)
"$core" on
"$core" status
```

Run `immune on` as the user being watched, without `sudo`. It registers the core with launchd as `~/Library/LaunchAgents/ai.nuanu.immune.watch.plist`, and the job runs `immune watch --background`. The home folder here is the account's own, read from the user database, and `$HOME` is not used: launchd loads the `LaunchAgents` of that home at login. Registering the launch agent can appear as a new watched item in a store that already has a baseline of LaunchAgents.

Which file the job runs depends on who can replace the core `immune on` was run from. `immune on` resolves the path's links and looks at the file and every folder above it up to `/`: their owner and mode, and the sticky bit. Which account runs it plays no part.

- Only root can replace it: every part is owned by root and writable by neither its group nor others, a sticky folder excepted, as for a core a signed package put in `/usr/local/bin`. The job runs it where it is and nothing is copied: a copy in the home folder could be replaced by any program of the account, and an update of the package would never reach the job. A copy an earlier `immune on` left is removed once the old job has stopped.
- Anyone else can, as for a build in a checkout, a folder owned by another account, or `/Applications`, which the admin group may write. `immune on` copies the core to `~/Library/Application Support/ai.nuanu.immune/bin/immune`, the store's folder, and the job runs the copy, so a rebuild, a switch of branch, a removed checkout or another account does not change the running core.

The answer's `in_place` says which. The test reads modes only; an access control list is not seen.

Only one `immune on` or `immune off` runs at a time; a second one fails with `busy` and changes nothing. Before it changes anything, `immune on` refuses when it runs as root, when the account has no home folder with an absolute path, when launchd has no login session for the user, when a symbolic link stands at the property list, at `bin` or at `bin/immune`, and when the property list there belongs to another job.

`immune on` then prepares the new property list and the new copy under temporary names and renames them into place, the copy first, while the old job is left alone. The running process keeps the binary it opened and launchd keeps the configuration it loaded, so the job is not stopped; the full checks it starts, and a restart, run the new copy from then on. The installed file is never written in place. Only then does `immune on` stop the old job, wait until launchd no longer has it, and load the new one. Each failure says what `immune on` did and did not touch, and what launchd answered:

- The copy cannot be put in place: the installed core, the property list and the job launchd has were not touched.
- The property list cannot be put in place: the property list and the job were not touched; the new core is in place unless `immune on` was run from the installed copy. Run `immune on` again.
- launchd still has the old job after the wait, 30 seconds when it took the stop and 2 when it refused it: the core and its property list are in place. Run `immune on` again.
- Loading the new job fails: the job may be stopped, and the new core and its property list are in place. Run `immune on` again.

The store is kept in every case. `immune on` says the job is loaded only after `launchctl print` has found it.

After launchd loaded the job, `immune on` waits up to 5 seconds and says one of four things. Watching: a watcher watches the store live, by the same test `immune status` uses. Started: the job's watcher holds the store and its heartbeat is fresh, its first check is running, and watching follows; `immune status` says when. Not started: launchd loaded the job and no watcher took the store, with what the status says of it and how to look at the job. Or it cannot tell. The first line of the text carries the mark ✓ only when watching, is a plain success when started, and is red when not started.

The answer is the contract's `Service` message: the job's label, the paths of the core the job runs and of the property list, whether the job is installed, loaded and replaced something, whether the core is run where it is, and whether a watcher was watching. As text it says that in its first line, then each step with its path or the label, whether an earlier job was replaced, and the command to run next. `immune off` lists what is gone and says the store and the event collector were kept. Add `--json` or `--proto` for an agent or a program.

The core starts watching at login. It schedules a full check when it starts and every hour after that. After sleep it starts one overdue check. Two full checks cannot use the same store at once. A background full check can run for up to 30 minutes. A watcher that makes no progress for three minutes exits so launchd can restart it. Status drops live coverage when the last heartbeat is too old.

The watcher the job runs looks at every heartbeat whether the path it was started from still holds the same file, by device and inode. When an update put another file there, the watcher leaves by itself between readings, says why on stderr and in its lock file, and launchd starts it again from the new file. For up to two minutes, until a new watcher holds the store, `immune status` says the watcher is restarting on a new core. A file removed with nothing in its place leaves the watcher running. Only a watcher run with `--background`, as the job runs it, leaves this way, whoever started it; one run without `--background`, by hand or by the app, keeps running on the file it opened.

Check `immune status --json` for `watching`, `last_finished_run` and what has actually been covered. With no watcher on the store, the status tells a job whose property list is in place, "installed, not running", from one that is not installed, by the file alone. `immune on` and `immune off` record in the store's journal when they turned Immune on or off, so a job that is gone though the latest record is `immune on` is said as off and not by `immune off`: something else stopped the job or removed its property list. If the job fails to start, `launchctl print "gui/$(id -u)/ai.nuanu.immune.watch"` shows its state and last exit status.

## Update

Build the new core and run its `on`:

```sh
core=$(./build)
"$core" on
```

The new copy replaces the old one by rename, and the job is restarted on it. Running `immune on` from the installed copy itself registers the job again and leaves the copy as it is. A core run where it is is updated by whatever put it there, such as a new package; the running watcher sees its file replaced and launchd starts the new one, with no `immune on`.

The optional app is built against the installed copy's path, `app/build "$HOME/Library/Application Support/ai.nuanu.immune/bin/immune"`, so an update of the core does not need a new build of the app.

## Turn off

```sh
"$HOME/Library/Application Support/ai.nuanu.immune/bin/immune" off
```

Any build of the core can run `immune off`, the installed copy included. It stops the job, removes its property list and the installed copy, and removes `bin` when nothing else is in it. A core run where it is was not put there by `immune on`, so `immune off` leaves it and says where it is: the core is shared by every account of this Mac. Whether it is run where it is is judged of the core running `immune off`, as `immune on` judges it. The property list, which any program of the account can write, is never read for a path, and no command to remove a file is printed. It keeps the store and everything else in the store's folder, the optional app and the optional event collector. If the stop fails, the property list and the copy are kept. Run when Immune is not on, it says so. To check the Mac once without the service, run `immune run` from a build. To restore continuous coverage, run `immune on` again. Logging out stops the login job until your next login.
