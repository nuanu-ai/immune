# Background service

The core runs as a launch agent in your macOS login session. The menu-bar app can open or quit independently.

## Turn on

If you have a source build with a format 8 store or the 0.2.0 app package, see the [migration note](reference.md#updating-and-removing).

```sh
core=$(./build)
"$core" on
"$core" status
```

Run `immunity on` as the user being watched, without `sudo`. It registers the core with launchd as `~/Library/LaunchAgents/ai.nuanu.immunity.core.watch.plist`, and the job runs `immunity watch --background`. The home folder here is the account's own, read from the user database, and `$HOME` is not used: launchd loads the `LaunchAgents` of that home at login. Registering the launch agent can appear as a new watched item in a store that already has a baseline of LaunchAgents.

Which file the job runs depends on who can replace the core `immunity on` was run from. `immunity on` resolves the path's links and looks at the file and every folder above it up to `/`: their owner and mode, and the sticky bit. Which account runs it plays no part.

- Only root can replace it: every part is owned by root and writable by neither its group nor others, a sticky folder excepted, as for a core a signed package put in `/usr/local/bin`. The job runs it where it is and nothing is copied: a copy in the home folder could be replaced by any program of the account, and an update of the package would never reach the job. A copy an earlier `immunity on` left is removed once the old job has stopped.
- Anyone else can, as for a build in a checkout, a folder owned by another account, or `/Applications`, which the admin group may write. `immunity on` copies the core to `~/Library/Application Support/ai.nuanu.immunity.core/bin/immunity`, the store's folder, and the job runs the copy, so a rebuild, a switch of branch, a removed checkout or another account does not change the running core.

The answer's `in_place` says which. The test reads modes only; an access control list is not seen.

Only one `immunity on` or `immunity off` runs at a time; a second one fails with `busy` and changes nothing. Before it changes anything, `immunity on` refuses when it runs as root, when the account has no home folder with an absolute path, when launchd has no login session for the user, when a symbolic link stands at the property list, at `bin` or at `bin/immunity`, and when the property list there belongs to another job.

`immunity on` then prepares the new property list and the new copy under temporary names and renames them into place, the copy first, while the old job is left alone. The property list is prepared in the store's folder and the copy in `bin`, never in `LaunchAgents`, so the watcher never sees a file of `immunity on`'s come and go among the startup items. The running process keeps the binary it opened and launchd keeps the configuration it loaded, so the job is not stopped; the full checks it starts, and a restart, run the new copy from then on. The installed file is never written in place. Only then does `immunity on` stop the old job, wait until launchd no longer has it, and load the new one. Each failure says what `immunity on` did and did not touch, and what launchd answered:

- The copy cannot be put in place: the installed core, the property list and the job launchd has were not touched.
- The property list cannot be put in place: the property list and the job were not touched; the new core is in place unless `immunity on` was run from the installed copy. Run `immunity on` again.
- launchd still has the old job after the wait, 30 seconds when it took the stop and 2 when it refused it: the core and its property list are in place. Run `immunity on` again.
- Loading the new job fails: the job may be stopped, and the new core and its property list are in place. Run `immunity on` again.

The store is kept in every case. `immunity on` says the job is loaded only after `launchctl print` has found it.

After launchd loaded the job, `immunity on` waits up to 5 seconds and says one of four things. Watching: a watcher watches the store live, by the same test `immunity status` uses. Started: the job's watcher holds the store and its heartbeat is fresh, its first check is running, and watching follows; `immunity status` says when. Not started: launchd loaded the job and no watcher took the store, with what the status says of it and how to look at the job. Or it cannot tell. The first line of the text carries the mark ✓ only when watching, is a plain success when started, and is red when not started.

The answer is the contract's `Service` message: the job's label, the paths of the core the job runs and of the property list, whether the job is installed, loaded and replaced something, whether the core is run where it is, and whether a watcher was watching. As text it says that in its first line, then each step with its path or the label, whether an earlier job was replaced, and the command to run next. `immunity off` lists what is gone and says the store and the event collector were kept. Add `--json` or `--proto` for an agent or a program.

The core starts watching at login. It schedules a full check when it starts and every hour after that. After sleep it starts one overdue check. Two full checks cannot use the same store at once. A background full check can run for up to 30 minutes. A watcher that makes no progress for three minutes exits so launchd can restart it. Status drops live coverage when the last heartbeat is too old.

The watcher the job runs looks at every heartbeat whether the path it was started from still holds the same file, by device and inode. When an update put another file there, the watcher leaves by itself between readings, says why on stderr and in its lock file, and launchd starts it again from the new file. For up to two minutes, until a new watcher holds the store, `immunity status` says the watcher is restarting on a new core. A file removed with nothing in its place leaves the watcher running. Only a watcher run with `--background`, as the job runs it, leaves this way, whoever started it; one run without `--background`, by hand or by the app, keeps running on the file it opened.

Check `immunity status --json` for `watching`, `last_finished_run` and what has actually been covered. With no watcher on the store, the status tells a job whose property list is in place, "installed, not running", from one that is not installed, by the file alone. The job's watcher records in the store's journal that Immunity Core is on, at its first reading after `immunity on`, and `immunity off` records that it turned Immunity Core off, so a job that is gone though the latest record is `immunity on` is said as off and not by `immunity off`: something else stopped the job or removed its property list. If the job fails to start, `launchctl print "gui/$(id -u)/ai.nuanu.immunity.core.watch"` shows its state and last exit status.

## Update

To update a login job already registered as `ai.nuanu.immunity.core.watch`, build the new core and run its `on`.

```sh
core=$(./build)
"$core" on
```

The new copy replaces the old one by rename, and the job is restarted on it. Running `immunity on` from the installed copy itself registers the job again and leaves the copy as it is. A core run where it is is updated by whatever put it there, such as a new package; the running watcher sees its file replaced and launchd starts the new one, with no `immunity on`.

## Turn off

```sh
"$HOME/Library/Application Support/ai.nuanu.immunity.core/bin/immunity" off
```

Run `immunity off` from an Immunity Core build or from the installed copy. It stops `ai.nuanu.immunity.core.watch`, removes its property list and the installed copy, and removes `bin` when nothing else is in it. If the core running `off` is only replaceable by root, it reports that executable's path in `program_path_text` and sets `in_place` to true. This uses the running executable and its parent directories, as for `immunity on`. The property list, which any program of the account can write, is never read for a path, and no command to remove a file is printed. The store and the event collector are kept. If the stop fails, the property list and the copy are kept. Run when Immunity Core is not on, it says so. To check the Mac once without the service, run `immunity run` from a build. To restore continuous coverage, run `immunity on` again. Logging out stops the login job until your next login.
