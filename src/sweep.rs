//! The sweep: which servers are offered for it, and the script the owner runs. The program
//! never connects to a server and never runs ssh. It writes the probe and the script next to
//! the store; the owner runs the script, which leaves one file per server for `immune run`.
//!
//! Only servers with a current, explicit way in are offered: literal aliases of `Host`
//! lines as OpenSSH reads them, whose block ssh applies to them, from a reader that has
//! already left code hosting out. A machine the owner said is
//! retired or not theirs is not offered under any alias. An alias listed in `skip.txt`
//! is not offered. A machine known under several aliases is visited once, through the
//! first of them in the order of the ssh configuration that is not in `skip.txt`. The
//! script checks `skip.txt` again when it runs, so an alias added there later is not
//! visited either, and the machine's next alias is used instead.
//!
//! A visit that fails never destroys the reading an earlier one left: it leaves
//! `<alias>.failed` with its time and reason instead, which `immune run` reads.

use std::collections::BTreeSet;
use std::path::Path;

/// The read-only probe that runs on each server.
pub const PROBE: &str = include_str!("../scripts/probe.sh");
/// Aliases the owner does not want visited, one per line, in the sweep folder.
pub const SKIP: &str = "skip.txt";
const SKIP_HEADER: &str =
    "# Aliases the sweep does not visit, one per line. Lines that start with # are ignored.\n";

/// The aliases listed in `skip.txt` in the folder; none when there is no such file.
pub fn skip_list(dir: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(dir.join(SKIP))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Why an alias of the ssh configuration is not offered, or `None` when it is.
pub fn not_offered(alias: &str, skip: &BTreeSet<String>) -> Option<&'static str> {
    if skip.contains(alias) {
        return Some("listed in skip.txt");
    }
    // The alias becomes a file name and a word in the script.
    let safe = alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !safe || alias.starts_with(['-', '.']) {
        return Some("the alias is not safe as a file name");
    }
    None
}

/// How many machines the sweep visits at a time: enough that one slow server does not hold
/// up the rest, few enough that a long list does not open dozens of connections at once.
pub const AT_ONCE: usize = 4;
/// What a failed visit leaves next to the script, `<alias>.failed`: the time in UTC seconds
/// on the first line, then what ssh said.
pub const FAILED: &str = "failed";

/// The script that visits each machine once. `machines` holds each machine's aliases in the
/// order of the ssh configuration. It never stops at a server that fails, and a failed visit
/// never replaces the reading an earlier one left.
pub fn script(machines: &[Vec<String>]) -> String {
    let mut out = String::from(
        "#!/bin/sh
# Written by `immune servers`. Run it yourself: it visits each server below over ssh and
# runs probe.sh there, which only reads. Each server leaves <alias>.txt next to this
# script for `immune run`, replaced only by a complete reading. A visit that fails keeps the
# earlier <alias>.txt, leaves <alias>.failed with its time and what ssh said, and is
# reported while the others go on. A later visit that succeeds removes it.
# Each line below is one machine and its aliases, comma separated. The machine is visited
# once, through the first of them that is not listed in skip.txt next to this script.
# Several machines are visited at a time. Name aliases as arguments to visit only their
# machines; a name this script does not list is never visited.
cd \"$(dirname \"$0\")\" || exit 1
if [ -e skip.txt ] && ! [ -r skip.txt ]; then echo 'skip.txt cannot be read; nothing was visited.'; exit 1; fi
machines='
",
    );
    for aliases in machines {
        out.push_str(&aliases.join(","));
        out.push('\n');
    }
    out.push_str(&format!("'\nat_once={AT_ONCE}\n"));
    out.push_str(
        "skipped() {
  [ -f skip.txt ] && sed 's/^[[:space:]]*//; s/[[:space:]]*$//' skip.txt | grep -qxF -- \"$1\"
}
listed() {
  for m in $machines; do
    for a in $(echo \"$m\" | tr ',' ' '); do
      [ \"$a\" = \"$1\" ] && return 0
    done
  done
  return 1
}
chosen=''
for arg in \"$@\"; do
  if ! listed \"$arg\"; then
    printf 'Not visited: %s is not a server this script visits.\\n' \"$arg\"
  elif skipped \"$arg\"; then
    printf 'Not visited: %s is listed in skip.txt.\\n' \"$arg\"
  else
    chosen=\"$chosen $arg\"
  fi
done
todo=''
names=''
for machine in $machines; do
  named=''
  for alias in $(echo \"$machine\" | tr ',' ' '); do
    for c in $chosen; do [ \"$alias\" = \"$c\" ] && named=yes; done
  done
  if [ $# -gt 0 ] && [ -z \"$named\" ]; then continue; fi
  for alias in $(echo \"$machine\" | tr ',' ' '); do
    if skipped \"$alias\"; then continue; fi
    todo=\"$todo $alias/$machine\"
    names=\"$names $alias\"
    break
  done
done
echo \"Servers to visit:${names:- none}\"
# One visit: the reading goes to a temporary file and replaces <alias>.txt only when it is
# complete. $1 is the alias, $2 every alias of its machine.
visit() {
  ssh -o BatchMode=yes -o ConnectTimeout=12 \"$1\" 'sh -s' < probe.sh > \"$1.txt.part\" 2> \"$1.err\"
  status=$?
  if grep -qx '##end' \"$1.txt.part\" && mv -f \"$1.txt.part\" \"$1.txt\"; then
    for a in $(echo \"$2\" | tr ',' ' '); do rm -f \"$a.failed\"; done
    printf 'ok      %s\\n' \"$1\"
  else
    rm -f \"$1.txt.part\"
    {
      date -u +%s
      if [ -s \"$1.err\" ]; then cat \"$1.err\"
      elif [ \"$status\" -ne 0 ]; then echo \"ssh exited with status $status\"
      else echo 'the probe did not reach its end'
      fi
    } > \"$1.failed\"
    printf 'failed  %s (see %s.failed)\\n' \"$1\" \"$1\"
  fi
}
# Each worker takes the next machine no other worker has taken: mkdir either claims it or
# fails because another worker did. Once the script is stopped the claims are gone, so no
# worker starts another visit.
claims=\".visiting.$$\"
mkdir \"$claims\" || exit 1
trap 'rm -rf \"$claims\"' EXIT
worker() {
  for item in $todo; do
    mkdir \"$claims/${item%%/*}\" 2>/dev/null || continue
    visit \"${item%%/*}\" \"${item#*/}\"
  done
}
n=0
while [ \"$n\" -lt \"$at_once\" ]; do
  worker &
  n=$((n + 1))
done
wait
exit 0
",
    );
    out
}

/// The sentence the owner reads wherever a host key could not be verified. The program
/// never accepts a key on the owner's behalf, and never suggests turning the check off.
const HOST_KEY: &str = "Connect to this server once by hand and check its host key: the sweep never accepts a key for you.";

/// A failed visit as the owner reads it: when, why, and what to do about a host key.
pub fn failed_visit(at: i64, reason: &str) -> String {
    let mut out = format!(
        "the latest visit failed {}: {}.",
        crate::view::utc(at),
        reason.trim_end_matches('.')
    );
    if reason
        .to_ascii_lowercase()
        .contains("host key verification failed")
    {
        out.push(' ');
        out.push_str(HOST_KEY);
    }
    out
}

/// Writes the probe, the script and an empty `skip.txt` when there is none.
pub fn write(dir: &Path, machines: &[Vec<String>]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("probe.sh"), PROBE)?;
    let script_path = dir.join("sweep.sh");
    std::fs::write(&script_path, script(machines))?;
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
    let skip = dir.join(SKIP);
    if !skip.exists() {
        std::fs::write(skip, SKIP_HEADER)?;
    }
    Ok(())
}

/// A path as one word for the shell.
pub fn quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}
