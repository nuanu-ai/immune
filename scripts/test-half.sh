#!/bin/sh
# Prints the arguments of `cargo test` that run one share of the test binaries, given as
# N/M (1/2 is the first of two). `./check tests 1/2` runs them, and the check on GitHub runs
# the halves side by side.
#
# The binaries are read from the tree, so a new test file is in a share without being named
# here: every file in tests/*.rs in name order, then the unit tests of the program (`--bins`).
# The package has no library, so these are all that `cargo test` runs. Share N of M takes the
# Nth, the (N+M)th and so on. With the times of a GitHub runner in November 2026 that puts
# verdict and watch, the two slowest, in different halves, and gives about 2m35s of tests to
# the first half and 2m50s to the second.
set -eu
cd "$(dirname "$0")/.."
case "${1-}" in
  [1-9]/[1-9]) ;;
  *)
    echo "usage: $0 N/M, a share N of M, both from 1 to 9" >&2
    exit 2
    ;;
esac
n=${1%/*}
m=${1#*/}
if [ "$n" -gt "$m" ]; then
  echo "$0: share $1 does not exist" >&2
  exit 2
fi
i=0
for target in $(for f in tests/*.rs; do basename "$f" .rs; done | LC_ALL=C sort) --bins; do
  if [ $((i % m + 1)) -eq "$n" ]; then
    case "$target" in
      --bins) echo --bins ;;
      *) echo --test "$target" ;;
    esac
  fi
  i=$((i + 1))
done
