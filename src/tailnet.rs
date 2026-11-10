//! The `tailnet` reader: the peers of this machine's tailnet, from `tailscale status
//! --json`. For each peer it takes the host name, the DNS name, the addresses and the
//! operating system, and nothing else: no keys, no user names.
//!
//! Tailscale that is not installed has nothing to read. Tailscale that is installed and
//! does not answer, or is logged out, could not be read.

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

/// Where the Tailscale app keeps its command when it is not on PATH.
const IN_APP: &str = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
const TIMEOUT: Duration = Duration::from_secs(10);

/// `at` is the one place to look for the command instead of PATH and the app.
pub fn read(at: Option<&Path>) -> Found {
    let Some(cli) = find(at) else {
        return Found::Absent(NOT_INSTALLED);
    };
    let (status, stdout, stderr) = match run(&cli) {
        Ok(out) => out,
        Err(e) => return Found::Failed(e),
    };
    if !status {
        let first = stderr.lines().next().unwrap_or("").trim().to_string();
        return Found::Failed(format!("tailscale status failed: {first}"));
    }
    match parse(&stdout) {
        Ok(seen) => Found::Read(seen),
        Err(e) => Found::Failed(e),
    }
}

fn find(at: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = at {
        return path.is_file().then(|| path.to_path_buf());
    }
    let on_path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|dir| dir.join("tailscale"))
                .collect()
        })
        .unwrap_or_default();
    on_path
        .into_iter()
        .chain([PathBuf::from(IN_APP)])
        .find(|path| path.is_file())
}

/// Runs `status --json` and gives up after the timeout: a stuck daemon must not stop a run.
fn run(cli: &Path) -> Result<(bool, String, String), String> {
    let mut child = Command::new(cli)
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", cli.display()))?;
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
                return Err(format!(
                    "tailscale status did not answer in {} seconds",
                    TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("tailscale status: {e}")),
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

/// The peers in the output of `tailscale status --json`, in the order of their names.
pub fn parse(json: &str) -> Result<Seen, String> {
    let v: Value = serde_json::from_str(json)
        .map_err(|e| format!("tailscale status gave no readable answer: {e}"))?;
    let state = text(&v, "BackendState");
    if state != "Running" {
        let state = if state.is_empty() { "unknown" } else { state };
        return Err(format!("tailscale is not running, its state is {state}"));
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

    let mut extract = Extract::default();
    let mut hosts = Vec::new();
    let mut third_party = 0;
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
        let n = extract.add(&format!("{host}\t{dns}\t{}\t{os}", addresses.join(",")));
        note(&mut hosts, &host, &host, n);
        for value in std::iter::once(dns).chain(addresses) {
            if !value.is_empty() {
                note(&mut hosts, &host, value, n);
            }
        }
        if !os.is_empty()
            && let Some(h) = hosts.iter_mut().find(|h| h.name == host)
            && h.os.is_none()
        {
            h.os = Some((os.to_string(), n));
        }
    }
    Ok(Seen {
        extract: extract.into_text(),
        hosts,
        partial: None,
        third_party,
    })
}
