# The event level's filter, run by launchd as root (local.personal-soc.event-filter):
#   /bin/sh collect.sh <folder of the installed scripts> <events FIFO> <log folder>
# eslogger writes every program start, and every file created or renamed, into the FIFO
# (local.personal-soc.eslogger). Apple's jq keeps of each line only what the reader uses
# (filter.jq), so a program's environment and file descriptors never reach a disk, and Apple's
# rotatelogs appends that to one file per hour, named by the hour in UTC:
# exec-YYYYMMDDTHH.jsonl, the name it had when it held program starts alone, so that files an
# earlier collector wrote are read and deleted as these are. rotatelogs moves to the next hour's file without closing
# the pipe, so eslogger is never restarted to rotate and its sequence numbers go on counting
# what the kernel dropped; started again within an hour, it appends to that hour's file.
# Its circular mode (-n) is not used: it empties a file and reuses its name and inode, and a
# reader holding a position in that file could not tell. Old files are deleted by tidy.sh.
# Only programs macOS ships run here, by absolute path, from files the installer copied into
# a folder only root can write. It only collects: it acts on no process, file or connection.
# When eslogger stops, the pipe ends and so does this script; launchd starts it again, no
# sooner than its ThrottleInterval.
umask 077
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
/usr/bin/jq --raw-input --compact-output --unbuffered -f "$lib/filter.jq" <"$fifo" |
    /usr/sbin/rotatelogs "$log/exec-%Y%m%dT%H.jsonl" 3600
