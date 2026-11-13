#!/bin/sh
# The event level's hook at each new log file, run by Apple's rotatelogs as root (collect.sh
# gives it with -p): rotated.sh <the file just started> [<the file before it>]. It runs tidy.sh
# at once, so the log is brought under its cap each time a file is started, at the hour or at
# 128 MiB, and not only by the tidy job every ten minutes.
#
# The cap has one source, the tidy job's launch daemon, which belongs to root and which only
# the installer writes: its fourth argument, read here with Apple's plutil. Both this script and
# that launch daemon are found from where this script is, in the layout the installer gives
# every Mac: <root>/Library/Application Support/ai.nuanu.immune/event-level/rotated.sh and
# <root>/Library/LaunchDaemons/ai.nuanu.immune.event-tidy.plist, the root being / when installed.
# rotatelogs runs this in the background and goes on writing; what it prints goes to
# scripts.err, with the filter's own messages.
umask 077
here=$0
lib=${here%/*}
case $lib in
*'/Library/Application Support/ai.nuanu.immune/event-level') ;;
*)
    echo "rotated.sh: not run from the installed folder: $here" >&2
    exit 64
    ;;
esac
root=${lib%/Library/Application Support/ai.nuanu.immune/event-level}
# Without the file just started there is no log folder, and tidy.sh refuses to run.
log=${1%/*}
cap=$(/usr/bin/plutil -extract ProgramArguments.3 raw -o - \
    "$root/Library/LaunchDaemons/ai.nuanu.immune.event-tidy.plist") || {
    echo "rotated.sh: the cap could not be read from the tidy job's launch daemon" >&2
    exit 66
}
exec /bin/sh "$lib/tidy.sh" "$log" "$cap"
