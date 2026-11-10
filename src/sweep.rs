//! The sweep: which servers are offered for it, and the script the owner runs. The program
//! never connects to a server and never runs ssh. It writes the probe and the script next to
//! the store; the owner runs the script, which leaves one file per server for `soc run`.
//!
//! Only servers with a current, explicit way in are offered: plain aliases of the ssh
//! configuration, which has already left code hosting out. A machine the owner said is
//! retired or not theirs is not offered under any alias. An alias listed in `skip.txt`
//! is not offered. A machine known under several aliases is visited once, through the
//! first of them in the order of the ssh configuration that is not in `skip.txt`. The
//! script checks `skip.txt` again when it runs, so an alias added there later is not
//! visited either, and the machine's next alias is used instead.

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

/// The script that visits each machine once. `machines` holds each machine's aliases in the
/// order of the ssh configuration. It never stops at a server that fails.
pub fn script(machines: &[Vec<String>]) -> String {
    let mut out = String::from(
        "#!/bin/sh
# Written by `soc servers`. Run it yourself: it visits each server below over ssh and
# runs probe.sh there, which only reads. Each server leaves <alias>.txt next to this
# script for `soc run`. A server that fails is reported and the others go on.
# Each line below is one machine and its aliases, comma separated. The machine is visited
# once, through the first of them that is not listed in skip.txt next to this script.
cd \"$(dirname \"$0\")\" || exit 1
if [ -e skip.txt ] && ! [ -r skip.txt ]; then echo 'skip.txt cannot be read; nothing was visited.'; exit 1; fi
machines='
",
    );
    for aliases in machines {
        out.push_str(&aliases.join(","));
        out.push('\n');
    }
    out.push_str(
        "'
skipped() {
  [ -f skip.txt ] && sed 's/^[[:space:]]*//; s/[[:space:]]*$//' skip.txt | grep -qxF -- \"$1\"
}
todo=''
for machine in $machines; do
  for alias in $(echo \"$machine\" | tr ',' ' '); do
    if skipped \"$alias\"; then continue; fi
    todo=\"$todo $alias\"
    break
  done
done
echo \"Servers to visit:${todo:- none}\"
for alias in $todo; do
  if ssh -o BatchMode=yes -o ConnectTimeout=12 \"$alias\" 'sh -s' < probe.sh > \"$alias.txt\" 2> \"$alias.err\" \\
    && grep -qx '##end' \"$alias.txt\"; then
    echo \"ok      $alias\"
  else
    echo \"failed  $alias (see $alias.err)\"
  fi
done
exit 0
",
    );
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
