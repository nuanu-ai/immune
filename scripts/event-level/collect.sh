# The event level's filter, run by launchd as root (ai.nuanu.immune.event-filter):
#   /bin/sh collect.sh <folder of the installed scripts> <events FIFO> <log folder>
# eslogger writes every program start, and every file created or renamed, into the FIFO
# (ai.nuanu.immune.eslogger). Apple's jq keeps of each line only what the reader uses
# (filter.jq), so a program's environment and file descriptors never reach a disk, and Apple's
# rotatelogs appends that to the log. rotatelogs starts a new file at the hour and when the
# file reaches SEGMENT_MIB, and each time it starts one it runs rotated.sh, which runs tidy.sh:
# the log is brought under its cap at every new file, not only every ten minutes.
#
# A file is named by when this run of the filter began and when the file was started, both in
# UTC to the second: exec-<run>-<start>.jsonl. rotatelogs names the first file of a run, and
# each file it starts at the hour, by the start of the hour, and a file it starts at the size by
# the current second. The run comes first so that a run started again never reopens a file of
# an earlier run: names sort in the order files were written, as long as the clock is not set
# back. Two files started within the same second have one name, and rotatelogs appends to it.
# Files named exec-<YYYYMMDDTHH>.jsonl were written by an earlier collector and are read and
# deleted as these are.
#
# rotatelogs moves to the next file without closing the pipe, so eslogger is never restarted
# to rotate and its sequence numbers go on counting what the kernel dropped. Its circular mode
# (-n) is not used: it empties a file and reuses its name and inode, and a reader holding a
# position in that file could not tell. Old files are deleted by tidy.sh.
#
# Only programs macOS ships run here, by absolute path, from files the installer copied into
# a folder only root can write. It only collects: it acts on no process, file or connection.
# When eslogger stops, the pipe ends and so does this script; launchd starts it again, no
# sooner than its ThrottleInterval.
umask 077
# The most a log file holds before rotatelogs starts the next one, in MiB: 128 MiB, about ten
# minutes of a building Mac's writing. The log can pass its cap by about this much.
SEGMENT_MIB=128
if [ "$#" -ne 3 ]; then
    echo "collect.sh: usage: collect.sh <folder of the installed scripts> <events FIFO> <log folder>" >&2
    exit 64
fi
lib=$1
fifo=$2
log=$3
if [ ! -p "$fifo" ]; then
    echo "collect.sh: $fifo is not a FIFO; install the event level again" >&2
    exit 66
fi
if [ ! -d "$log" ]; then
    echo "collect.sh: $log is not a folder; install the event level again" >&2
    exit 66
fi
run=$(/bin/date -u +%Y%m%dT%H%M%S) || exit 70
/usr/bin/jq --raw-input --compact-output --unbuffered -f "$lib/filter.jq" <"$fifo" |
    /usr/sbin/rotatelogs -p "$lib/rotated.sh" "$log/exec-$run-%Y%m%dT%H%M%S.jsonl" 3600 "${SEGMENT_MIB}M"
