//! The `tailnet` reader: the peers of this machine's tailnet, from `tailscale status
//! --json`. For each peer it takes the host name, the DNS name, the addresses and the
//! operating system, and nothing else: no keys, no user names.
//!
//! A tailnet also holds other people's laptops and phones. A peer without tags that belongs
//! to another user than this machine's is recorded as another user's device, and one that
//! belongs to the same user as the owner's device; the user ids are only compared, never
//! kept. A tagged peer belongs to the tailnet, not to a person, and a peer whose user the
//! status does not give is taken to be nobody's in particular.
//!
//! The system of a peer is what the tailnet says, `runs_platform`: Tailscale's
//! `PeerStatus.OS`, which its client fills from `version.OS()`. That is Go's `GOOS`, except
//! `macOS`, `iOS` and `tvOS` for Apple's systems: `linux`, `windows`, `android`, `freebsd`,
//! `openbsd` and so on. It is not `runs_os`, the release name a server gives itself.
//!
//! Tailscale that is not installed has nothing to read. Tailscale that is installed and
//! answers that it is not connected, stopped or logged out, is in a state the owner chose:
//! its peers are not known while it is off, those seen before stay as they were, and that is
//! not a failure. Tailscale whose command cannot reach the daemon could not be read; the
//! reason names each way that was tried.
//!
//! The command is looked for in the app in `/Applications` and in the user's own
//! `Applications`, and in the Homebrew prefixes, and nowhere else (`crate::tools`). A
//! daemon started by hand may listen on a
//! socket of its own, given to it as `--socket=<path>`: when the command cannot reach the
//! daemon on the default socket, the sockets of running `tailscaled` processes are tried.
//! Of the process list only the value of `--socket` of a `tailscaled` process is taken.

use crate::store::Gap;
use crate::traces::{Extract, Found, Seen, code_hosting, note};
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const READER: &str = "tailnet";
pub const KIND: &str = "tailnet peers";
pub const BASIS: &str = "observed";
pub const NOT_INSTALLED: &str = "Tailscale is not installed on this machine";
/// The one state in which Tailscale is connected and gives its peers.
const RUNNING: &str = "Running";

/// What a state other than `Running` is, in fixed words.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Told {
    /// The reason of the reading.
    pub reason: &'static str,
    /// Not connected, and the person's to fix.
    pub yours: bool,
    /// Not readable this time: a failed reading, which the next check tries again.
    pub retry: bool,
}

/// The states `BackendState` documents (tailscale's `ipn/backend.go`), other than `Running`.
pub const STATES: [(&str, Told); 6] = [
    (
        "Stopped",
        Told {
            reason: "Tailscale is switched off on this Mac",
            yours: false,
            retry: false,
        },
    ),
    (
        "NeedsLogin",
        Told {
            reason: "Tailscale on this Mac waits for you to log in",
            yours: true,
            retry: false,
        },
    ),
    (
        "NeedsMachineAuth",
        Told {
            reason: "Tailscale on this Mac waits for an admin of your tailnet to approve this Mac",
            yours: true,
            retry: false,
        },
    ),
    (
        "InUseOtherUser",
        Told {
            reason: "Tailscale on this Mac is in use by another user of this Mac",
            yours: true,
            retry: false,
        },
    ),
    (
        "Starting",
        Told {
            reason: "Tailscale was starting and gave no list of devices yet; the next check reads it again",
            yours: false,
            retry: true,
        },
    ),
    (
        "NoState",
        Told {
            reason: "Tailscale had not started and gave no list of devices yet; the next check reads it again",
            yours: false,
            retry: true,
        },
    ),
];

/// How the reason begins for a state this version does not know; the state follows, as data.
pub const UNKNOWN_STATE: &str = "Tailscale is in a state this version does not know: ";

/// What the reason of a reading of the tailnet tells, when it is one of the fixed ones.
pub fn told(reason: &str) -> Option<Told> {
    STATES.iter().map(|(_, t)| *t).find(|t| t.reason == reason)
}
/// The `relation_to_owner` of a peer of another user, without tags.
pub const OTHER_USER: &str = "other user's device";
/// The `relation_to_owner` of a peer of the same user as this machine, without tags.
pub const OWN: &str = "owner's device";

/// Systems the server check cannot read at all, as the tailnet names them: phones, tablets,
/// TVs and desktop systems. The probe is a POSIX shell script that reads `/etc/os-release`
/// and a Linux package manager; none of these has either.
pub const DEVICE_SYSTEMS: [&str; 5] = ["iOS", "tvOS", "android", "macOS", "windows"];
/// Systems the server check reads, in full (Linux with dpkg) or in part (a BSD or a Unix
/// with `/etc/os-release` and no Linux package manager), as the tailnet names them.
/// Neither list holds `js`, `plan9`, `aix` or a value a later Tailscale adds: a peer with
/// such a system is not taken for a device, and its system is named as one not known here.
pub const SERVER_SYSTEMS: [&str; 7] = [
    "linux",
    "freebsd",
    "openbsd",
    "netbsd",
    "dragonfly",
    "illumos",
    "solaris",
];

/// What a peer's system, as the tailnet gives it, says about the peer.
#[derive(Debug, PartialEq, Eq)]
pub enum System {
    /// One the server check cannot read at all.
    Device,
    /// One the server check reads.
    Server,
    /// The tailnet gives none.
    NotGiven,
    /// One in neither list.
    NotKnown,
}

pub fn system(platform: Option<&str>) -> System {
    let Some(p) = platform.map(str::trim).filter(|p| !p.is_empty()) else {
        return System::NotGiven;
    };
    if DEVICE_SYSTEMS.iter().any(|d| d.eq_ignore_ascii_case(p)) {
        System::Device
    } else if SERVER_SYSTEMS.iter().any(|d| d.eq_ignore_ascii_case(p)) {
        System::Server
    } else {
        System::NotKnown
    }
}

/// Where the Tailscale app keeps its command, under `/Applications` or the user's own.
const IN_APP: &str = "Applications/Tailscale.app/Contents/MacOS/Tailscale";
/// Where Homebrew puts commands on Apple Silicon and on Intel.
const BREW: [&str; 2] = ["/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale"];
const TIMEOUT: Duration = Duration::from_secs(10);
/// How much of the tool's own error a reason keeps.
const SHORT: usize = 80;

/// `at` is the one place to look for the command instead of the usual ones.
pub fn read(at: Option<&Path>, home: &Path) -> Found {
    let cli = match at {
        Some(at) => at.is_file().then(|| at.to_path_buf()),
        None => {
            let homes = crate::watched::homes(home);
            let homes = [homes[0].as_path(), homes[1].as_path()];
            let found = crate::tools::find(&installed(home), &homes);
            // Found nowhere else, it may be where it was not looked for.
            if let (None, Some(g)) = (&found.at, found.guarded.first()) {
                return Found::Guarded(g.clone());
            }
            found.at
        }
    };
    read_from(cli.as_deref(), processes)
}

/// What a person calls it.
pub const NAME: &str = "Tailscale";

/// The places the command is looked for, as a reason names them, the home folder as `~`.
pub fn places(home: &Path) -> Vec<String> {
    installed(home)
        .iter()
        .map(|p| match p.strip_prefix(home) {
            Ok(rel) => format!("~/{}", rel.display()),
            Err(_) => p.display().to_string(),
        })
        .collect()
}

/// Where Tailscale's installers put the command, in order.
fn installed(home: &Path) -> Vec<PathBuf> {
    [Path::new("/").join(IN_APP), home.join(IN_APP)]
        .into_iter()
        .chain(BREW.map(PathBuf::from))
        .collect()
}

/// The command lines of running processes, or nothing when they cannot be listed.
fn processes() -> String {
    Command::new(crate::tools::PS)
        .args(["-axww", "-o", "args="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// The `--socket` values of `tailscaled` processes, and nothing else of the list.
fn sockets(processes: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in processes.lines() {
        let mut words = line.split_whitespace();
        let program = words.next().unwrap_or("");
        if program.rsplit('/').next() != Some("tailscaled") {
            continue;
        }
        // Go flags: `--socket=<path>`, `-socket=<path>`, or the path as the next word.
        let socket = |flag: &str| flag == "--socket" || flag == "-socket";
        while let Some(word) = words.next() {
            let value = match word.split_once('=') {
                Some((flag, value)) if socket(flag) => Some(value),
                None if socket(word) => words.next(),
                _ => None,
            };
            if let Some(value) = value.filter(|v| !v.is_empty())
                && !out.iter().any(|s| s == value)
            {
                out.push(value.to_string());
            }
        }
    }
    out
}

fn read_from(cli: Option<&Path>, processes: impl Fn() -> String) -> Found {
    let Some(cli) = cli else {
        return Found::Absent(NOT_INSTALLED);
    };
    let mut tried = Vec::new();
    let mut ways = vec![None];
    let mut asked = false;
    while let Some(socket) = ways.pop() {
        match run(cli, socket.as_deref()) {
            Ok((true, stdout, _)) => {
                return match parse(&stdout) {
                    Ok(Answer::Peers(seen)) => Found::Read(seen),
                    Ok(Answer::State(t)) if t.retry => Found::Failed(t.reason.to_string()),
                    Ok(Answer::State(t)) => Found::Off(t.reason.to_string()),
                    Err(e) => Found::Failed(e),
                };
            }
            Ok((false, _, stderr)) => tried.push((socket, short(&stderr))),
            Err(e) => tried.push((socket, e)),
        }
        if !asked {
            asked = true;
            ways = sockets(&processes()).into_iter().rev().map(Some).collect();
        }
    }
    let ways: Vec<String> = tried
        .into_iter()
        .map(|(socket, why)| match socket {
            None => format!("on the default socket ({why})"),
            Some(socket) => format!("on the socket {socket} of a running tailscaled ({why})"),
        })
        .collect();
    Found::Failed(format!(
        "tailscale could not reach its daemon {}",
        ways.join("; nor ")
    ))
}

/// The gist of a tool's error: the last part of its first line, cut short.
fn short(stderr: &str) -> String {
    let first = stderr.lines().map(str::trim).find(|l| !l.is_empty());
    let Some(first) = first else {
        return "no reason given".to_string();
    };
    let gist = first.rsplit(": ").next().unwrap_or(first).trim();
    match gist.char_indices().nth(SHORT) {
        Some((i, _)) => format!("{}…", &gist[..i]),
        None => gist.to_string(),
    }
}

/// Runs `status --json`, on the given socket if any, and gives up after the timeout: a
/// stuck daemon must not stop a run.
fn run(cli: &Path, socket: Option<&str>) -> Result<(bool, String, String), String> {
    let mut command = Command::new(cli);
    if let Some(socket) = socket {
        command.arg(format!("--socket={socket}"));
    }
    let mut child = command
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run it: {e}"))?;
    let pipe = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = pipe(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err = pipe(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("no answer in {} seconds", TIMEOUT.as_secs()));
            }
            Err(e) => return Err(format!("cannot wait for it: {e}")),
        }
    };
    let (out, err) = (
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default(),
    );
    Ok((status.success(), out, err))
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("").trim()
}

/// What `tailscale status --json` answered.
pub enum Answer {
    /// Connected: its peers, in the order of their names.
    Peers(Seen),
    /// Another state Tailscale documents, as `STATES` tells it.
    State(Told),
}

/// The peers in the output of `tailscale status --json`, or the state it is in when it is not
/// connected. Peers are taken only in `Running`, even when another state lists some. A state
/// is matched as Tailscale spells it; any other, or none, is not read.
pub fn parse(json: &str) -> Result<Answer, String> {
    let v: Value = serde_json::from_str(json)
        .map_err(|e| format!("tailscale status gave no readable answer: {e}"))?;
    let state = text(&v, "BackendState");
    if state.is_empty() {
        return Err("tailscale status gave no state".to_string());
    }
    if state != RUNNING {
        return STATES
            .iter()
            .find(|(s, _)| *s == state)
            .map(|(_, t)| Answer::State(*t))
            .ok_or_else(|| format!("{UNKNOWN_STATE}{state}"));
    }
    let mut peers: Vec<&Value> = v
        .get("Peer")
        .and_then(Value::as_object)
        .map(|m| m.values().collect())
        .unwrap_or_default();
    let name = |p: &Value| {
        let host = text(p, "HostName");
        if host.is_empty() {
            text(p, "DNSName")
                .split('.')
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            host.to_string()
        }
    };
    peers.sort_by_key(|p| name(p));
    let me = v.get("Self").and_then(|s| s.get("UserID"));
    // Whose an untagged peer is, when the status gives both users.
    let whose = |p: &Value| match (me, p.get("UserID")) {
        (Some(me), Some(user)) if p.get("Tags").is_none() => {
            Some(if me == user { OWN } else { OTHER_USER })
        }
        _ => None,
    };

    let mut extract = Extract::default();
    let mut hosts = Vec::new();
    let mut third_party = 0;
    // Whose each peer under a name is: two peers may share a host name, and the name is
    // someone's only when every peer under it is theirs.
    let mut owners: Vec<(String, Option<&'static str>, usize)> = Vec::new();
    for peer in peers {
        let host = name(peer);
        if host.is_empty() {
            continue;
        }
        let dns = text(peer, "DNSName");
        if code_hosting(&host) || code_hosting(dns) {
            third_party += 1;
            continue;
        }
        let addresses: Vec<&str> = peer
            .get("TailscaleIPs")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let os = text(peer, "OS");
        let relation = whose(peer);
        let n = extract.add(&format!(
            "{host}\t{dns}\t{}\t{os}\t{}",
            addresses.join(","),
            relation.unwrap_or("")
        ));
        owners.push((host.clone(), relation, n));
        note(&mut hosts, &host, &host, n);
        for value in std::iter::once(dns).chain(addresses) {
            if !value.is_empty() {
                note(&mut hosts, &host, value, n);
            }
        }
        if !os.is_empty()
            && let Some(h) = hosts.iter_mut().find(|h| h.name == host)
            && h.platform.is_none()
        {
            h.platform = Some((os.to_string(), n));
        }
    }
    for host in &mut hosts {
        let mut under = owners.iter().filter(|(name, ..)| *name == host.name);
        let Some((_, first, n)) = under.next() else {
            continue;
        };
        if first.is_some() && under.all(|(_, r, _)| r == first) {
            host.relation = first.map(|r| (r, *n));
        }
    }
    Ok(Answer::Peers(Seen {
        extract: extract.into_text(),
        hosts,
        partial: None,
        gap: Gap::default(),
        third_party,
        guarded: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    //! Tailscale as it is installed in different ways. The command is a fake shell script
    //! and the process list an invented sample: no test asks the real tailscale or reads the
    //! real process list.

    use super::*;

    const PEERS: &str = r#"{ "BackendState": "Running", "Peer": {
        "nodekey:invented": { "HostName": "build-box", "DNSName": "build-box.example-tail.ts.net.",
                              "TailscaleIPs": ["100.64.0.7"], "OS": "linux" } } }"#;

    /// A folder of its own for one test.
    fn folder(tag: &str) -> crate::common::Scratch {
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immune-tailnet-{tag}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fake `tailscale` with this shell body.
    fn command(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("tailscale");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// What the real command says when it finds no daemon on the socket it was given.
    const UNREACHABLE: &str = "echo 'failed to connect to local tailscaled (which appears to be running as tailscaled, pid 4242). Got error: Failed to connect to local Tailscale daemon for /localapi/v0/status; not running? Error: dial unix /var/run/tailscaled.socket: connect: no such file or directory' >&2
echo 'second line of noise' >&2
exit 1";

    #[test]
    fn a_daemon_started_by_hand_on_its_own_socket_is_read() {
        // The owner's tailnet must be read however the daemon was started; a daemon on its
        // own socket looks to plain `tailscale status` like no daemon at all.
        let dir = folder("socket");
        let cli = command(
            &dir,
            &format!(
                "if [ \"$1\" = --socket=/invented/run/tailscaled.sock ]; then cat <<'END'\n{PEERS}\nEND\nexit 0; fi\n{UNREACHABLE}"
            ),
        );
        let ps = "/usr/sbin/invented-daemon --socket=/elsewhere.sock\n\
                  /invented/bin/tailscaled --state=/invented/state/tailscaled.state --socket=/invented/run/tailscaled.sock --port=41641\n";
        let Found::Read(seen) = read_from(Some(&cli), || ps.to_string()) else {
            panic!("the tailnet was not read");
        };
        let names: Vec<&str> = seen.hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["build-box"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_daemon_that_cannot_be_reached_is_a_failed_reading_naming_each_way_tried_in_one_short_line()
    {
        // The reason goes into the one report line. It must say what was tried and why it
        // failed without the tool's whole error, and nothing else from the process list.
        let dir = folder("unreachable");
        let cli = command(&dir, UNREACHABLE);
        let ps = "/invented/bin/tailscaled -socket /invented/a.sock --state=/invented/secret-state\n\
                  /usr/bin/invented-tool --socket=/invented/not-tailscale.sock\n\
                  tailscaled --socket=/invented/b.sock\n\
                  tailscaled --socket=/invented/b.sock\n";
        let Found::Failed(reason) = read_from(Some(&cli), || ps.to_string()) else {
            panic!("an unreachable daemon was not a failed reading");
        };
        assert_eq!(
            reason,
            "tailscale could not reach its daemon on the default socket (no such file or directory); \
             nor on the socket /invented/a.sock of a running tailscaled (no such file or directory); \
             nor on the socket /invented/b.sock of a running tailscaled (no such file or directory)"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_long_error_is_cut_short() {
        // One report line, however much the tool says.
        let long = format!("Error: {}", "x".repeat(200));
        assert_eq!(short(&long), format!("{}…", "x".repeat(SHORT)));
        assert_eq!(short(""), "no reason given");
    }

    #[test]
    fn each_state_tailscale_documents_is_told_as_what_it_is_and_any_other_is_a_reading_that_failed()
    {
        // Switched off is the owner's choice; waiting for a login or an approval is not
        // connected and the owner's to fix; starting is not readable this time. None of them is
        // an empty tailnet, and peers a state other than Running lists are not taken.
        let dir = folder("states");
        let peer =
            "\"nodekey:a\": { \"HostName\": \"new-box\", \"TailscaleIPs\": [\"100.64.0.9\"] }";
        let at = |state: &str| {
            let cli = command(
                &dir,
                &format!("echo '{{ \"BackendState\": \"{state}\", \"Peer\": {{ {peer} }} }}'"),
            );
            read_from(Some(&cli), String::new)
        };
        let off = |state: &str| match at(state) {
            Found::Off(said) => said,
            _ => panic!("{state}: not told as not connected"),
        };
        let failed = |state: &str| match at(state) {
            Found::Failed(said) => said,
            _ => panic!("{state}: not told as a reading that failed"),
        };
        assert_eq!(off("Stopped"), "Tailscale is switched off on this Mac");
        for (state, words) in [
            (
                "NeedsLogin",
                "Tailscale on this Mac waits for you to log in",
            ),
            (
                "NeedsMachineAuth",
                "Tailscale on this Mac waits for an admin of your tailnet to approve this Mac",
            ),
            (
                "InUseOtherUser",
                "Tailscale on this Mac is in use by another user of this Mac",
            ),
        ] {
            assert_eq!(off(state), words);
            assert!(told(words).is_some_and(|t| t.yours && !t.retry), "{state}");
        }
        assert!(told(&off("Stopped")).is_some_and(|t| !t.yours && !t.retry));
        for state in ["Starting", "NoState"] {
            let said = failed(state);
            assert!(said.ends_with("the next check reads it again"), "{said}");
        }
        // Spelled otherwise, or free text, is a state this version does not know.
        for state in ["running", "Stopped. Nothing else to check"] {
            assert_eq!(
                failed(state),
                format!("Tailscale is in a state this version does not know: {state}")
            );
        }
        // An answer that names no state at all is one this reader cannot read.
        let cli = command(&dir, "echo '{ \"Peer\": {} }'");
        let Found::Failed(reason) = read_from(Some(&cli), String::new) else {
            panic!("an answer without a state was taken as one");
        };
        assert_eq!(reason, "tailscale status gave no state");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tailscale_that_is_not_installed_is_not_applicable() {
        // Not installed is not a failure; a running daemon without a command changes nothing.
        let dir = folder("absent");
        let found = read(Some(&dir.join("tailscale")), &dir);
        assert!(matches!(found, Found::Absent(NOT_INSTALLED)));
        let found = read_from(None, || {
            "tailscaled --socket=/invented/a.sock\n".to_string()
        });
        assert!(matches!(found, Found::Absent(NOT_INSTALLED)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_command_is_looked_for_wherever_tailscale_is_installed() {
        // In the app in either Applications folder, or from Homebrew; never on PATH.
        let home = Path::new("/Users/invented");
        assert_eq!(
            installed(home),
            [
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                "/Users/invented/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                "/opt/homebrew/bin/tailscale",
                "/usr/local/bin/tailscale",
            ]
            .map(PathBuf::from)
        );
    }
}
