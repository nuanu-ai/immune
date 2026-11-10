//! The `known-hosts` reader: the hosts this machine has connected to, from
//! `~/.ssh/known_hosts`. Each line names one or more hosts, comma separated, possibly as
//! `[host]:port`, and then a key. Only the names are taken: neither a key nor its type is
//! kept anywhere.
//!
//! A hashed line (`|1|...`) hides its name and cannot be read, so a file that has any is
//! read partially. Lines for a certificate authority or a revoked key name no host we have.

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
    let (mut hashed, mut third_party) = (0, 0);
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let field = line.split_whitespace().next().unwrap_or("");
        if field.starts_with("|1|") {
            hashed += 1;
            continue;
        }
        for name in field.split(',') {
            // Patterns name no one host.
            if name.contains(['*', '?', '!']) {
                continue;
            }
            let host = match name.strip_prefix('[') {
                Some(rest) => rest.split_once(']').map_or(rest, |(h, _)| h),
                None => name,
            };
            if host.is_empty() {
                continue;
            }
            if code_hosting(host) {
                third_party += 1;
                continue;
            }
            let n = extract.add(&format!("{}\t{host}", i + 1));
            note(&mut hosts, host, host, n);
        }
    }
    Seen {
        extract: extract.into_text(),
        hosts,
        partial: (hashed > 0).then(|| {
            format!(
                "{hashed} hashed {} cannot be read",
                if hashed == 1 { "entry" } else { "entries" }
            )
        }),
        third_party,
    }
}
