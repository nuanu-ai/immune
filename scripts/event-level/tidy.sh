# The event level's retention, run by launchd as root every ten minutes
# (local.personal-soc.event-tidy):
#   /bin/sh tidy.sh <log folder> <most bytes of log>
# A log file holds one hour. One not written to for a day holds only lines older than a day,
# and is deleted. Then, while the log files together are larger than the cap, the oldest is
# deleted, never the one being written, so a busy day cannot fill the disk; between two runs
# the log can pass the cap by what ten minutes add. Each deletion is a line in `removed`:
# when, the file's name, its size, and `age` or `cap`, so the reader can say when lines went
# before it read them or before their day was over. What eslogger and these scripts print,
# and `removed` itself, are kept small: a file of it over 64 KiB is replaced by its last
# 16 KiB, through a new file and a rename. Only files of these names in the log folder are
# touched. The programs this starts are themselves program starts eslogger records, so a
# level that runs writes a line at least every ten minutes on a Mac that is awake.
umask 077
if [ "$#" -ne 2 ] || [ ! -d "$1" ]; then
    echo "tidy.sh: usage: tidy.sh <log folder> <most bytes of log>" >&2
    exit 64
fi
case $2 in
'' | *[!0-9]*)
    echo "tidy.sh: the most bytes of log is a number, not $2" >&2
    exit 64
    ;;
esac
log=$1
cap=$2
now=$(/bin/date +%s)

remove() {
    size=$(/usr/bin/stat -f %z "$1") || return 1
    /bin/rm -f "$1" || return 1
    echo "$now ${1##*/} $size $2" >>"$log/removed"
}

# The log folder's path has a space in it, so each file is looked at by itself.
for f in "$log"/exec-*.jsonl; do
    [ -f "$f" ] || continue
    if [ -n "$(/usr/bin/find "$f" -prune -mmin +1440)" ]; then
        remove "$f" age
    fi
done

total=0
newest=
for f in "$log"/exec-*.jsonl; do
    [ -f "$f" ] || continue
    size=$(/usr/bin/stat -f %z "$f") || continue
    total=$((total + size))
    newest=$f
done
# The names sort by the hour, so the oldest come first.
for f in "$log"/exec-*.jsonl; do
    [ "$total" -gt "$cap" ] || break
    { [ -f "$f" ] && [ "$f" != "$newest" ]; } || break
    size=$(/usr/bin/stat -f %z "$f") || break
    remove "$f" cap || break
    total=$((total - size))
done

for said in "$log/eslogger.err" "$log/scripts.err" "$log/removed"; do
    [ -f "$said" ] || continue
    size=$(/usr/bin/stat -f %z "$said") || continue
    if [ "$size" -gt 65536 ]; then
        /usr/bin/tail -c 16384 "$said" >"$said.new" && /bin/mv -f "$said.new" "$said"
    fi
done
