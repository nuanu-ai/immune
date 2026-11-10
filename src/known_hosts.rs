//! The `known-hosts` reader: the hosts this machine has connected to, from
//! `~/.ssh/known_hosts`, in the format `sshd(8)` describes under "SSH_KNOWN_HOSTS FILE
//! FORMAT". Each line names one or more hosts, comma separated, and then a key. Only the
//! names are taken: neither a key nor its type is kept anywhere.
//!
//! A host on a port other than 22 is written `[host]:port`, and ssh keys its identity by
//! host and port: machines behind one address with forwarded ports are different
//! machines. So such an entry keeps its port in its name and is a server of its own, not
//! the one on port 22.
//!
//! Some lines say there are hosts without naming them, so a file that has any is read
//! partially, with their count: a hashed line (`|1|...`) hides its name; a pattern with `*`
//! or `?` covers hosts it does not list; a `@cert-authority` line vouches for hosts whose
//! keys ssh then never writes here. A negated pattern names no host to add, and a
//! `@revoked` line names a key that must not be trusted, not a host connected to.

use crate::traces::{Extract, Found, Seen, code_hosting, note};
use std::path::Path;

pub const READER: &str = "known-hosts";
pub const KIND: &str = "known hosts";
pub const BASIS: &str = "observed";
pub const NOT_PRESENT: &str = "there is no known_hosts file on this machine";

pub fn read(home: &Path) -> Found {
    match std::fs::read(home.join(".ssh").join("known_hosts")) {
        Ok(bytes) => Found::Read(parse(&String::from_utf8_lossy(&bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Found::Absent(NOT_PRESENT),
        Err(e) => Found::Failed(format!("cannot read ~/.ssh/known_hosts: {e}")),
    }
}

pub fn parse(text: &str) -> Seen {
    let mut extract = Extract::default();
    let mut hosts = Vec::new();
    let (mut hashed, mut patterns, mut authorities, mut third_party) = (0, 0, 0, 0);
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let field = line.split_whitespace().next().unwrap_or("");
        if field == "@cert-authority" {
            authorities += 1;
            continue;
        }
        if field.starts_with('@') {
            continue;
        }
        if field.starts_with("|1|") {
            hashed += 1;
            continue;
        }
        for name in field.split(',') {
            if name.starts_with('!') {
                continue;
            }
            if name.contains(['*', '?']) {
                patterns += 1;
                continue;
            }
            let (host, port) = split_port(name);
            if host.is_empty() {
                continue;
            }
            if code_hosting(host) {
                third_party += 1;
                continue;
            }
            let name = match port {
                Some(port) => format!("[{host}]:{port}"),
                None => host.to_string(),
            };
            let n = extract.add(&format!("{}\t{name}", i + 1));
            note(&mut hosts, &name, &name, n);
        }
    }
    let mut reasons = Vec::new();
    for (count, one, many) in [
        (
            hashed,
            "hashed entry cannot be read",
            "hashed entries cannot be read",
        ),
        (
            patterns,
            "pattern covers hosts it does not name",
            "patterns cover hosts they do not name",
        ),
        (
            authorities,
            "certificate authority vouches for hosts whose keys are not written here",
            "certificate authorities vouch for hosts whose keys are not written here",
        ),
    ] {
        if count > 0 {
            reasons.push(format!("{count} {}", if count == 1 { one } else { many }));
        }
    }
    Seen {
        extract: extract.into_text(),
        hosts,
        partial: (!reasons.is_empty()).then(|| reasons.join("; ")),
        third_party,
    }
}

/// The host and the port of `[host]:port`; a name without brackets has no port.
fn split_port(name: &str) -> (&str, Option<&str>) {
    match name.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => (rest, None),
        },
        None => (name, None),
    }
}
