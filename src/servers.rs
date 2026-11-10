//! The `servers` reader: what is installed on servers, read from the files the owner's
//! read-only sweep leaves behind. It never connects anywhere; it only reads files.
//!
//! One file per server, `<name>.txt`, made of sections that start with a `##<section>`
//! line, as `scripts/probe.sh` prints them. A file is a complete read only if it reaches
//! `##end`. `##taken_at` is when the probe ran, in UTC seconds. A visit that failed leaves
//! `<name>.failed` next to it, and the earlier `<name>.txt` as it was.

use crate::store::Statement;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const READER: &str = "servers";
pub const BASIS: &str = "observed";
pub const PACKAGES: &str = "system packages";
pub const CONTAINERS: &str = "containers";
/// Every `*_VERSION` variable of a running container: the sweep prints all of them.
pub const VARIABLES: &str = "container version variables";
/// The WordPress core version of a container that runs a WordPress image.
pub const WORDPRESS: &str = "wordpress core version";
/// What is inside a container as a whole. Only the two kinds above are read, so this
/// reading is never full and makes no assertions: nothing may claim a container was read.
pub const CONTENTS: &str = "container contents";
/// The names and addresses the server gives itself. A file from a probe that did not print
/// them has no such reading and links to nothing.
pub const IDENTITY: &str = "own names and addresses";

/// Interfaces of container networks and virtual bridges, by the prefixes Docker, libvirt,
/// LXC, LXD, Podman and Kubernetes give them. Their addresses repeat from server to server,
/// so they name no one machine.
const BRIDGES: [&str; 11] = [
    "docker", "br-", "virbr", "lxcbr", "lxdbr", "podman", "cni", "flannel", "cali", "cilium",
    "kube",
];

pub const NOT_COMPLETE: &str = "the sweep of this server did not complete";
const NO_RIGHTS: &str = "no rights to list containers";
const CONTENTS_PARTIAL: &str = "only version variables and the WordPress core version are read";
/// What the probe prints when docker refused, and when there is no docker.
const REFUSED: &str = "no access";
const NOT_INSTALLED: &str = "docker not installed";

/// The sweep's latest visit to the server: whether it reached the server and the probe
/// completed. The readings of what is on the server keep their own coverage and time; this
/// one says when the latest attempt failed and why, next to them.
pub const VISIT: &str = "sweep visit";

/// What the sweep left for one server: its reading, its failed visit, or both.
pub struct Input {
    pub name: String,
    /// `<name>.txt`, the latest reading. `None` when there is none.
    pub file: Option<File>,
    /// `<name>.failed`, left when the latest visit failed.
    pub failed: Option<Failure>,
}

/// One server file as it was found.
pub struct File {
    /// `None` when the file could not be read.
    pub raw: Option<Vec<u8>>,
    /// When the file was last written, UTC seconds: the time of the reading when the file
    /// does not say when the probe ran.
    pub modified: i64,
}

/// A visit that failed: when, from the file's first line, and why, from the last line ssh
/// printed, which is where it says what went wrong.
pub struct Failure {
    pub at: i64,
    pub reason: String,
}

impl Failure {
    pub fn parse(text: &str, modified: i64) -> Failure {
        let mut lines = text.lines();
        let at = lines.next().and_then(|l| l.trim().parse().ok());
        let reason = lines.map(str::trim).rfind(|l| !l.is_empty());
        Failure {
            at: at.unwrap_or(modified),
            reason: reason.unwrap_or("the visit left no reason").to_string(),
        }
    }
}

/// The failed visit left under this name in the folder, if any.
pub fn failure(dir: &Path, name: &str) -> Option<Failure> {
    let path = dir.join(format!("{name}.{}", crate::sweep::FAILED));
    let meta = std::fs::metadata(&path).ok()?;
    let text = std::fs::read(&path).unwrap_or_default();
    Some(Failure::parse(
        &String::from_utf8_lossy(&text),
        seconds(meta.modified().ok()),
    ))
}

fn seconds(t: Option<std::time::SystemTime>) -> i64 {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

/// Whether a server file is a complete reading.
pub fn complete(text: &str) -> bool {
    sections(text).contains_key("end")
}

/// What one reading of one server, or of one container on it, found.
pub struct Outcome {
    /// The server's or the container's entity id.
    pub scope: String,
    pub kind: &'static str,
    pub completeness: &'static str,
    pub reason: Option<String>,
    pub statements: Vec<Statement>,
}

/// Every server in the folder by name: each `<name>.txt`, except the sweep's own `skip.txt`,
/// and each `<name>.failed`. An error if the folder cannot be listed; a file that cannot be
/// read is still a server we know about.
pub fn inputs(dir: &Path) -> Result<Vec<Input>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let failed = format!(".{}", crate::sweep::FAILED);
    let mut out: BTreeMap<String, Input> = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let (name, txt) = match (
            file_name.strip_suffix(".txt"),
            file_name.strip_suffix(failed.as_str()),
        ) {
            (Some(name), _) => (name, true),
            (_, Some(name)) => (name, false),
            _ => continue,
        };
        if name.is_empty()
            || entry.file_name() == crate::sweep::SKIP
            || !entry.file_type().is_ok_and(|t| t.is_file())
        {
            continue;
        }
        let input = out.entry(name.to_string()).or_insert_with(|| Input {
            name: name.to_string(),
            file: None,
            failed: None,
        });
        if txt {
            input.file = Some(File {
                raw: std::fs::read(&path).ok(),
                modified: seconds(entry.metadata().and_then(|m| m.modified()).ok()),
            });
        } else {
            input.failed = failure(dir, name);
        }
    }
    Ok(out.into_values().collect())
}

/// Lines of each section, with their line numbers, counted from 1.
type Sections<'a> = BTreeMap<&'a str, Vec<(usize, &'a str)>>;

fn sections(text: &str) -> Sections<'_> {
    let mut out = Sections::new();
    let mut current = None;
    for (i, line) in text.lines().enumerate() {
        if let Some(name) = line.strip_prefix("##") {
            let name = name.trim();
            out.entry(name).or_default();
            current = Some(name);
        } else if let Some(name) = current {
            out.entry(name).or_default().push((i + 1, line));
        }
    }
    out
}

/// The non-empty rows of a section, split at the first tab.
fn pairs<'a>(sections: &Sections<'a>, name: &str) -> Vec<(usize, &'a str, &'a str)> {
    let rows = sections.get(name).map(Vec::as_slice).unwrap_or_default();
    rows.iter()
        .filter_map(|(n, line)| {
            let (a, b) = line.split_once('\t')?;
            let (a, b) = (a.trim(), b.trim());
            (!a.is_empty() && !b.is_empty()).then_some((*n, a, b))
        })
        .collect()
}

fn first_line<'a>(sections: &Sections<'a>, name: &str) -> Option<(usize, &'a str)> {
    let (n, line) = sections.get(name)?.first()?;
    let line = line.trim();
    (!line.is_empty()).then_some((*n, line))
}

/// When the probe ran, from `##taken_at`, if the file says.
pub fn taken_at(text: &str) -> Option<i64> {
    first_line(&sections(text), "taken_at").and_then(|(_, t)| t.parse().ok())
}

/// The readings of one server file. `raw_file` is the saved copy, relative to the store's
/// folder. A file that does not reach `##end` is a read that did not happen.
pub fn readings(machine: &str, text: &str, raw_file: &str) -> Vec<Outcome> {
    let s = sections(text);
    if !s.contains_key("end") {
        return nothing_read(machine, NOT_COMPLETE);
    }
    let at = |n: usize| format!("{raw_file}:{n}");
    let say = |out: &mut Vec<Statement>, subject: &str, predicate, object: &str, n| {
        out.push(Statement {
            subject: subject.to_string(),
            predicate,
            object: object.to_string(),
            source_ref: at(n),
        });
    };
    let mut out = Vec::new();

    // The server's own names and addresses. Loopback, link-local and bridge addresses are
    // the same on unrelated servers and are left out: they would join them into one.
    // A name printed twice, as `uname -n` and `hostname -f` often are, is kept once by the
    // lifecycle, which promotes one of the repeated statements.
    if s.contains_key("names") {
        let mut st: Vec<Statement> = Vec::new();
        for (n, line) in s.get("names").map(Vec::as_slice).unwrap_or_default() {
            let line = line.trim();
            if !line.is_empty() {
                say(&mut st, machine, "known_as", line, *n);
            }
        }
        let addresses = pairs(&s, "addresses");
        for (n, interface, address) in &addresses {
            if let Some(address) = own_address(interface, address) {
                say(&mut st, machine, "known_as", &address, *n);
            }
        }
        out.push(if addresses.is_empty() {
            Outcome {
                scope: machine.to_string(),
                kind: IDENTITY,
                completeness: "partial",
                reason: Some("the server's addresses could not be listed".to_string()),
                statements: st,
            }
        } else {
            full(machine, IDENTITY, st)
        });
    }

    // System packages, with the system itself.
    let dpkg = pairs(&s, "dpkg");
    if !s.contains_key("dpkg") {
        out.push(not_read(machine, PACKAGES, "the sweep has no package list"));
    } else if dpkg.is_empty() {
        // An empty list is a missing dpkg, not a server with nothing installed.
        out.push(not_read(machine, PACKAGES, "the package list is empty"));
    } else {
        let mut st = Vec::new();
        if let Some((n, os)) = first_line(&s, "os") {
            say(&mut st, machine, "runs_os", os, n);
        }
        if let Some((n, kernel)) = first_line(&s, "kernel") {
            say(&mut st, machine, "runs_kernel", kernel, n);
        }
        let snap = pairs(&s, "snap");
        let rows = dpkg
            .iter()
            .map(|r| ("deb", r))
            .chain(snap.iter().map(|r| ("snap", r)));
        for (ecosystem, (n, name, version)) in rows {
            let component = format!("component:{machine}/{ecosystem}/{name}");
            say(&mut st, &component, "part_of", machine, *n);
            say(&mut st, &component, "has_version", version, *n);
        }
        out.push(full(machine, PACKAGES, st));
    }

    // Containers. Docker that is not installed has nothing to list: that is a full read.
    let access = first_line(&s, "docker_access").map(|(_, a)| a);
    let mut containers = Vec::new();
    match access {
        None => out.push(not_read(
            machine,
            CONTAINERS,
            "the sweep has no docker section",
        )),
        Some(REFUSED) => out.push(not_read(machine, CONTAINERS, NO_RIGHTS)),
        Some(NOT_INSTALLED) => out.push(full(machine, CONTAINERS, Vec::new())),
        Some(_) if !s.contains_key("docker_ps") => out.push(not_read(
            machine,
            CONTAINERS,
            "the sweep has no container list",
        )),
        Some(_) => {
            let mut st = Vec::new();
            for (n, line) in s.get("docker_ps").map(Vec::as_slice).unwrap_or_default() {
                let mut cols = line.split('\t').map(str::trim);
                let (Some(image), Some(name)) = (cols.next(), cols.next()) else {
                    continue;
                };
                if image.is_empty() || name.is_empty() {
                    continue;
                }
                let container = format!("container:{machine}/{name}");
                say(&mut st, &container, "located_on", machine, *n);
                say(&mut st, &container, "runs_image", image, *n);
                containers.push((container, name));
            }
            out.push(full(machine, CONTAINERS, st));
        }
    }

    // What is inside each running container, one reading per kind and container.
    let variables = s
        .contains_key("container_versions")
        .then(|| pairs(&s, "container_versions"));
    let wordpress = s.get("wp").map(Vec::as_slice).unwrap_or_default();
    for (container, name) in &containers {
        let (container, name) = (container.as_str(), *name);
        match &variables {
            None => out.push(not_read(
                container,
                VARIABLES,
                "the sweep has no version variables",
            )),
            Some(rows) => {
                let mut st = Vec::new();
                for (n, _, var) in rows.iter().filter(|r| r.1.trim_start_matches('/') == name) {
                    let Some((key, value)) = var.split_once('=') else {
                        continue;
                    };
                    let component = key.strip_suffix("_VERSION").unwrap_or("").to_lowercase();
                    if component.is_empty() || value.trim().is_empty() {
                        continue;
                    }
                    let component = format!("component:{container}/container-env/{component}");
                    say(&mut st, &component, "part_of", container, *n);
                    say(&mut st, &component, "has_version", value.trim(), *n);
                }
                out.push(full(container, VARIABLES, st));
            }
        }
        // The probe looks for the WordPress version only in WordPress containers.
        for (n, line) in wordpress {
            let (row, value) = line.split_once('\t').unwrap_or((line, ""));
            if row.trim() != name {
                continue;
            }
            // The probe prints `wp_version=<version>`; a bare version is accepted too.
            let version = value.split_once('=').map_or(value, |(_, v)| v).trim();
            if version.is_empty() {
                out.push(not_read(
                    container,
                    WORDPRESS,
                    "the WordPress version file was not found",
                ));
                continue;
            }
            let component = format!("component:{container}/wordpress-core/wordpress");
            let mut st = Vec::new();
            say(&mut st, &component, "part_of", container, *n);
            say(&mut st, &component, "has_version", version, *n);
            out.push(full(container, WORDPRESS, st));
        }
        out.push(Outcome {
            scope: container.to_string(),
            kind: CONTENTS,
            completeness: "partial",
            reason: Some(CONTENTS_PARTIAL.to_string()),
            statements: Vec::new(),
        });
    }
    out
}

/// An address the server has on one of its interfaces, as the resolver compares it, or
/// `None` when it names no one machine: loopback, link-local, or the address of a
/// container bridge.
fn own_address(interface: &str, address: &str) -> Option<String> {
    if BRIDGES.iter().any(|b| interface.starts_with(b)) {
        return None;
    }
    let address = address.split(['/', '%']).next().unwrap_or(address);
    let ip: std::net::IpAddr = address.parse().ok()?;
    let local = match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    (!local).then(|| ip.to_string())
}

/// The readings of a file that could not be read at all.
pub fn unreadable(machine: &str) -> Vec<Outcome> {
    nothing_read(machine, "the file of this server could not be read")
}

/// The readings of a server with no complete file whose latest visit failed.
pub fn visit_failed(machine: &str, reason: &str) -> Vec<Outcome> {
    nothing_read(machine, &format!("the latest visit failed: {reason}"))
}

fn nothing_read(machine: &str, reason: &str) -> Vec<Outcome> {
    vec![
        not_read(machine, PACKAGES, reason),
        not_read(machine, CONTAINERS, reason),
    ]
}

/// The latest visit: full when it left a complete reading, else none with why it failed.
pub fn visit(machine: &str, failed: Option<&str>) -> Outcome {
    match failed {
        Some(reason) => not_read(machine, VISIT, reason),
        None => full(machine, VISIT, Vec::new()),
    }
}

fn not_read(scope: &str, kind: &'static str, reason: &str) -> Outcome {
    Outcome {
        scope: scope.to_string(),
        kind,
        completeness: "none",
        reason: Some(reason.to_string()),
        statements: Vec::new(),
    }
}

fn full(scope: &str, kind: &'static str, statements: Vec<Statement>) -> Outcome {
    Outcome {
        scope: scope.to_string(),
        kind,
        completeness: "full",
        reason: None,
        statements,
    }
}

#[cfg(test)]
mod tests {
    use super::Failure;

    #[test]
    fn a_failure_record_without_its_time_is_dated_by_the_file_and_one_without_a_reason_says_so() {
        // A record cut short by copying must still be told as a failure, not lost or dated now.
        let cut = Failure::parse("", 1_767_412_800);
        assert_eq!(cut.at, 1_767_412_800);
        assert_eq!(cut.reason, "the visit left no reason");
    }
}
