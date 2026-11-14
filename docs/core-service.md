# Background service

The core runs as a launch agent in your macOS login session. The menu-bar app can open or quit independently.

## Install or update

If you are moving from an earlier bundled build, quit its menu-bar app before installing the service. The earlier app holds the store's watcher lock while it runs.

```sh
core=$(./build)
/bin/sh scripts/core/install "$core"
"$core" status --json
```

Run this from the checkout as the user being watched. The installer registers `~/Library/LaunchAgents/ai.nuanu.immune.watch.plist` with launchd, using the absolute path to the binary. Keep the executable at that path. To upgrade, stop the service, build the new core, and run the installer again. Installing the launch agent can appear as a new watched item in a store that already has a baseline of LaunchAgents.

The core starts watching at login. It schedules a full check when it starts and every hour after that. After sleep it starts one overdue check. Two full checks cannot use the same store at once. A background full check can run for up to 30 minutes. A watcher that makes no progress for three minutes exits so launchd can restart it. Status drops live coverage when the last heartbeat is too old.

Check `immune status --json` for `watching`, `last_finished_run` and what has actually been covered. If the job fails to start, `launchctl print "gui/$(id -u)/ai.nuanu.immune.watch"` shows its state and last exit status.

## Stop and remove the job

```sh
/bin/sh scripts/core/uninstall
```

This stops the core and removes its login job. It keeps the binary, the store, the optional app and the optional event collector. To check the Mac once, run `immune run`. To restore continuous coverage, install the service again. Logging out stops the login job until your next login.
