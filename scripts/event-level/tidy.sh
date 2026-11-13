# The event level's retention, run as root by launchd every ten minutes
# (ai.nuanu.immune.event-tidy) and by rotated.sh each time rotatelogs starts a new log file:
#   /bin/sh tidy.sh <log folder> <most bytes of log>
# A log file holds at most an hour, or 128 MiB. One not written to for a day holds only lines
# older than a day, and is deleted. Then, while the log files together are larger than the
# cap, the one written longest ago is deleted, never the one written last, which is the one
# being written. So the log is larger than its cap by at most the file being written and what
# is written while this runs. Files are taken in the order they were last written, not by
# name: a clock set back gives a new file an earlier name.
#
# Each deletion is a line in `removed`: when, the file's name, its size, and `age` or `cap`, so
# the reader can say when lines went before it read them or before their day was over. What
# eslogger and these scripts print, and `removed` itself, are kept small: a file of it over
# 64 KiB is replaced by its last 16 KiB, through a new file and a rename. Only files of these
# names in the log folder are touched. The programs this starts are themselves program starts
# eslogger records, so a level that runs writes a line at least every ten minutes on a Mac
# that is awake.
#
# Two runs at once, the job's and the hook's, never both delete: each first makes the folder
# `tidy.lock` in the log folder, which only one can make, and removes it when it ends. A run that
# finds it made deletes nothing and ends without an error: the run that holds it brings the log
# under its cap, and the next new file or the job's next run starts another. A lock older than
# ten minutes was left by a run that was killed, and is taken over. mkdir is the lock because
# every macOS has it, in every version.
umask 077
if [ "$#" -ne 2 ] || [ ! -d "$1" ]; then
    echo "tidy.sh: usage: tidy.sh <log folder> <most bytes of log>" >&2
    exit 64
fi
# The cap: digits, no leading zero, and at most 16 of them, so the shell's 64-bit arithmetic
# compares it as it is. Anything else deletes nothing to keep the log under it.
case $2 in
'' | *[!0-9]* | 0?*)
    echo "tidy.sh: the most bytes of log is a whole number without a leading zero, not $2" >&2
    exit 64
    ;;
esac
if [ "${#2}" -gt 16 ]; then
    echo "tidy.sh: the most bytes of log has more than 16 digits: $2" >&2
    exit 64
fi
# Below the smallest cap the installer writes, 1 GiB, a cap would empty the log of all but the
# file being written: refused like any other, and nothing is deleted.
if [ "$2" -lt 1073741824 ]; then
    echo "tidy.sh: the most bytes of log is below 1 GiB (1073741824): $2" >&2
    exit 64
fi
log=$1
# The cap comes from the tidy job's launch daemon, which belongs to root and which only the
# installer writes, as an argument of the job or read by rotated.sh. No file or setting a
# program running as the user can change sets it: a cap such a program could shrink would let
# it empty the log, and that is quieting.
cap=$2

cd "$log" || exit 66
# The lock. Nothing is printed when it is held: what this prints goes to scripts.err, which
# Immune reads as the scripts failing.
if ! /bin/mkdir tidy.lock 2>/dev/null; then
    [ -n "$(/usr/bin/find tidy.lock -prune -mmin +10 2>/dev/null)" ] || exit 0
    /bin/rmdir tidy.lock 2>/dev/null
    /bin/mkdir tidy.lock 2>/dev/null || exit 0
fi
trap '/bin/rmdir tidy.lock 2>/dev/null' EXIT
trap 'exit 75' HUP INT TERM
now=$(/bin/date +%s)

remove() {
    size=$(/usr/bin/stat -f %z "$1") || return 1
    /bin/rm -f "$1" || return 1
    echo "$now $1 $size $2" >>removed
}

for f in exec-*.jsonl; do
    [ -f "$f" ] || continue
    if [ -n "$(/usr/bin/find "$f" -prune -mmin +1440)" ]; then
        remove "$f" age
    fi
done

# Oldest first by when each was last written, to the nanosecond; the last is the one being
# written. The names hold no space, newline or pattern character, being the collector's own.
files=$(/bin/ls -1tr -- exec-*.jsonl 2>/dev/null)
set -f
total=0
newest=
for f in $files; do
    size=$(/usr/bin/stat -f %z "$f") || continue
    total=$((total + size))
    newest=$f
done
for f in $files; do
    [ "$total" -gt "$cap" ] || break
    [ "$f" != "$newest" ] || break
    size=$(/usr/bin/stat -f %z "$f") || continue
    remove "$f" cap || break
    total=$((total - size))
done

for said in eslogger.err scripts.err removed; do
    [ -f "$said" ] || continue
    size=$(/usr/bin/stat -f %z "$said") || continue
    if [ "$size" -gt 65536 ]; then
        /usr/bin/tail -c 16384 "$said" >"$said.new" && /bin/mv -f "$said.new" "$said"
    fi
done
