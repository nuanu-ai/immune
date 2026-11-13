//! The `servers` reader: what is installed on servers, read from the files the owner's
//! read-only sweep leaves behind. It never connects anywhere; it only reads files.
//!
//! One file per server, `<name>.txt`, made of sections that start with a `##<section>`
//! line, as `scripts/probe.sh` prints them. A file is a complete read only if it reaches
//! `##end`. `##taken_at` is when the probe ran, in UTC seconds. A visit that failed leaves
//! `<name>.failed` next to it, and the earlier `<name>.txt` as it was.

use crate::store::{Cause, Gap, Lack, Statement};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const READER: &str = "servers";
pub const BASIS: &str = "observed";
pub const PACKAGES: &str = "system packages";
/// The source package and version each system package was built from.
pub const SOURCES: &str = "system package sources";
/// The distribution and its version as the system gives them in its os-release file.
pub const RELEASE: &str = "system release";
/// The package that owns the running kernel.
pub const KERNEL_PACKAGE: &str = "running kernel package";
pub const CONTAINERS: &str = "containers";
/// Every `*_VERSION` variable of a running container: the sweep prints all of them.
pub const VARIABLES: &str = "container version variables";
/// What is inside a container as a whole. Only the kind above is read, so this reading is
/// never full and makes no assertions: nothing may claim a container was read.
pub const CONTENTS: &str = "container contents";
/// Kinds an earlier version read and this one does not, with why. What an earlier version
/// read of one stays live until a run retracts it, once, with this reason: a fact nothing
/// reads any more must not look as if it were still read.
///
/// The WordPress core version was read from a file inside each container whose image name
/// held `wordpress`, by a command run inside it: a rule for one product, whose result nothing
/// judged. A container of WordPress's own image gives its version as `WORDPRESS_VERSION`, read
/// with every other version variable. What that does not follow is a core updated in place
/// inside the container.
pub const RETIRED: [(&str, &str); 1] = [(
    "wordpress core version",
    "the probe no longer reads WordPress's version file inside a container; a container's WORDPRESS_VERSION variable is read with its other version variables",
)];
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
/// What a file from a probe that did not yet read a kind says about it.
const OLDER_PROBE: &str = "the file came from an older probe, which did not read this";
/// dpkg's list with each package's status and source, and the list an older probe printed.
const DPKG: &str = "dpkg_with_source";
const DPKG_OLD: &str = "dpkg";
const NO_RIGHTS: &str = "no rights to list containers";
const CONTENTS_PARTIAL: &str = "only version variables are read";
/// What the probe prints when docker refused, and when there is no docker.
const REFUSED: &str = "no access";
const NOT_INSTALLED: &str = "docker not installed";

/// The sweep's latest visit to the server: whether it reached the server and the probe
/// completed. The readings of what is on the server keep their own coverage and time; this
/// one says when the latest attempt failed and why, next to them.
pub const VISIT: &str = "sweep visit";
/// What this build has no reader for on a server, in its own words.
pub const PACKAGE_MANAGER: &str = "package manager";
pub const OTHER_MANAGER: &str = "a package manager the probe does not look for";
pub const CONTAINER_CONTENTS: &str = "container contents other than version variables";

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
    /// Why the reading is incomplete, and what this build has no reader for in it.
    pub gap: Gap,
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
            // The probe ran and its section of addresses holds none.
            Outcome {
                scope: machine.to_string(),
                kind: IDENTITY,
                completeness: "partial",
                reason: Some("the server's addresses could not be listed".to_string()),
                gap: Gap::of(Cause::NotGiven),
                statements: st,
            }
        } else {
            full(machine, IDENTITY, st)
        });
    }

    // The release, as the os-release file gives it. Never derived from the pretty name.
    out.push(release(machine, &s, raw_file));

    // System packages, with the system itself, the sources they were built from and the
    // package that owns the running kernel. These three are read only through dpkg.
    let dpkg = debs(&s);
    let managers = s.get("package_managers").map(|rows| {
        rows.iter()
            .map(|(_, l)| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
    });
    let unread = managers.as_deref().map_or(Vec::new(), |m| {
        m.iter().copied().filter(|m| *m != "dpkg").collect()
    });
    let no_reader = managers.as_deref().is_some_and(|m| !m.contains(&"dpkg"));
    // Package managers there that this build has no reader for.
    let lacks: Vec<Lack> = unread
        .iter()
        .map(|m| Lack::new(PACKAGE_MANAGER, Some(m)))
        .collect();
    let failed = if no_reader && unread.is_empty() {
        let lack = vec![Lack::new(OTHER_MANAGER, None)];
        Some((
            Gap {
                cause: Some(Cause::NoReader),
                lacks: lack,
            },
            "the server has none of the package managers the probe looks for".to_string(),
        ))
    } else if no_reader {
        Some((
            Gap {
                cause: Some(Cause::NoReader),
                lacks: lacks.clone(),
            },
            format!(
                "the program has no reader for the package manager this server uses: {}",
                unread.join(", ")
            ),
        ))
    } else if !s.contains_key(DPKG) && !s.contains_key(DPKG_OLD) {
        Some((
            Gap::of(Cause::NotGiven),
            "the sweep has no package list".to_string(),
        ))
    } else if dpkg.is_empty() {
        // An empty list is a missing dpkg, not a server with nothing installed.
        Some((
            Gap::of(Cause::NotGiven),
            "the package list is empty".to_string(),
        ))
    } else {
        None
    };
    if let Some((gap, reason)) = failed {
        for kind in [PACKAGES, SOURCES, KERNEL_PACKAGE] {
            out.push(Outcome {
                gap: gap.clone(),
                ..not_read(machine, kind, Cause::Failed, &reason)
            });
        }
    } else {
        // Packages of another manager next to dpkg are not read: nothing may be retracted
        // for them, and what is read is not all there is.
        let partial = (!unread.is_empty()).then(|| {
            format!(
                "only dpkg is read; packages of {} are not",
                unread.join(", ")
            )
        });
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
            .map(|d| ("deb", d.n, d.name, d.version))
            .chain(snap.iter().map(|(n, a, b)| ("snap", *n, *a, *b)));
        for (ecosystem, n, name, version) in rows {
            let component = format!("component:{machine}/{ecosystem}/{name}");
            say(&mut st, &component, "part_of", machine, n);
            say(&mut st, &component, "has_version", version, n);
        }
        let no_reader = Gap {
            cause: Some(Cause::NoReader),
            lacks,
        };
        let gap = if partial.is_some() {
            no_reader.clone()
        } else {
            Gap::default()
        };
        out.push(reading(machine, PACKAGES, partial.clone(), gap, st));

        if s.contains_key(DPKG) {
            let mut st = Vec::new();
            for d in &dpkg {
                if let Some((source, version)) = d.source {
                    let component = format!("component:{machine}/deb/{}", d.name);
                    say(
                        &mut st,
                        &component,
                        "built_from",
                        &format!("{source} {version}"),
                        d.n,
                    );
                }
            }
            let missing = dpkg.iter().filter(|d| d.source.is_none()).count();
            // Packages of a manager without a reader are worse than packages dpkg gives no
            // source for, and only the worse is said.
            let (reason, gap) = match (&partial, missing) {
                (Some(p), _) => (Some(p.clone()), no_reader),
                (None, 0) => (None, Gap::default()),
                (None, _) => (
                    Some(format!("{missing} of the packages give no source")),
                    Gap::of(Cause::NotGiven),
                ),
            };
            out.push(reading(machine, SOURCES, reason, gap, st));
        } else {
            out.push(not_read(machine, SOURCES, Cause::NotGiven, OLDER_PROBE));
        }

        if s.contains_key("kernel_package") {
            let mut st = Vec::new();
            for (n, package) in kernel_packages(&s) {
                say(&mut st, machine, "runs_kernel_package", package, n);
            }
            out.push(full(machine, KERNEL_PACKAGE, st));
        } else {
            out.push(not_read(
                machine,
                KERNEL_PACKAGE,
                Cause::NotGiven,
                OLDER_PROBE,
            ));
        }
    }

    // Containers. Docker that is not installed has nothing to list: that is a full read.
    let access = first_line(&s, "docker_access").map(|(_, a)| a);
    let mut containers = Vec::new();
    match access {
        None => out.push(not_read(
            machine,
            CONTAINERS,
            Cause::NotGiven,
            "the sweep has no docker section",
        )),
        // Docker refused the probe: it tried and could not.
        Some(REFUSED) => out.push(not_read(machine, CONTAINERS, Cause::Failed, NO_RIGHTS)),
        Some(NOT_INSTALLED) => out.push(full(machine, CONTAINERS, Vec::new())),
        Some(_) if !s.contains_key("docker_ps") => out.push(not_read(
            machine,
            CONTAINERS,
            Cause::NotGiven,
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
    for (container, name) in &containers {
        let (container, name) = (container.as_str(), *name);
        match &variables {
            None => out.push(not_read(
                container,
                VARIABLES,
                Cause::NotGiven,
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
        out.push(Outcome {
            scope: container.to_string(),
            kind: CONTENTS,
            completeness: "partial",
            reason: Some(CONTENTS_PARTIAL.to_string()),
            gap: Gap {
                cause: Some(Cause::NoReader),
                lacks: vec![Lack::new(CONTAINER_CONTENTS, None)],
            },
            statements: Vec::new(),
        });
    }
    out
}

/// One package dpkg lists as present.
struct Deb<'a> {
    n: usize,
    name: &'a str,
    version: &'a str,
    /// The source package and version, `None` in a file from an older probe or when dpkg
    /// did not give them.
    source: Option<(&'a str, &'a str)>,
}

/// The packages whose files are on the server. dpkg also lists a package that was removed
/// and not purged, with only its configuration files left, and one it knows as not
/// installed; neither is a component. An older probe printed only names and versions of
/// whatever dpkg listed.
fn debs<'a>(s: &Sections<'a>) -> Vec<Deb<'a>> {
    if !s.contains_key(DPKG) {
        return pairs(s, DPKG_OLD)
            .into_iter()
            .map(|(n, name, version)| Deb {
                n,
                name,
                version,
                source: None,
            })
            .collect();
    }
    let rows = s.get(DPKG).map(Vec::as_slice).unwrap_or_default();
    rows.iter()
        .filter_map(|(n, line)| {
            let mut cols = line.split('\t').map(str::trim);
            let (status, name, version) = (cols.next()?, cols.next()?, cols.next()?);
            let (source, source_version) = (cols.next(), cols.next());
            // The second letter of `${db:Status-Abbrev}` is the package's state.
            let gone = matches!(status.chars().nth(1), Some('n' | 'c'));
            if gone || name.is_empty() || version.is_empty() {
                return None;
            }
            let source = match (source, source_version) {
                (Some(p), Some(v)) if !p.is_empty() && !v.is_empty() => Some((p, v)),
                _ => None,
            };
            Some(Deb {
                n: *n,
                name,
                version,
                source,
            })
        })
        .collect()
}

/// The packages `dpkg-query -S` says own the running kernel: `<package>, <package>: <path>`.
fn kernel_packages<'a>(s: &Sections<'a>) -> Vec<(usize, &'a str)> {
    let rows = s
        .get("kernel_package")
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut out = Vec::new();
    for (n, line) in rows {
        let Some((packages, _)) = line.split_once(": ") else {
            continue;
        };
        // A package name has no blanks; a diversion line, `diversion by <package> from:`,
        // has them and names no owner.
        for package in packages.split(',').map(str::trim) {
            if !package.is_empty() && !package.contains(char::is_whitespace) {
                out.push((*n, package));
            }
        }
    }
    out
}

/// The release as `<ID> <VERSION_ID>`, and the code name when the system gives one. A
/// system that does not give both is a reading that read nothing, never a guess.
///
/// The probe unquotes a value only when it is one quoted word. A value it left holding a
/// quote, as with text after the closing quote, or holding a blank, which an unquoted shell
/// value cannot, was not read the way the shell reads it: it is taken as not given.
fn release(machine: &str, s: &Sections, raw_file: &str) -> Outcome {
    if !s.contains_key("os_release") {
        return not_read(machine, RELEASE, Cause::NotGiven, OLDER_PROBE);
    }
    let fields = pairs(s, "os_release");
    let plain = |v: &str| !v.contains(['"', '\'']) && !v.contains(char::is_whitespace);
    let field = |key: &str| {
        fields
            .iter()
            .find(|(_, k, _)| *k == key)
            .filter(|r| plain(r.2))
            .map(|r| (r.0, r.2))
    };
    let (id, version, codename) = (field("ID"), field("VERSION_ID"), field("VERSION_CODENAME"));
    let (Some((_, id)), Some((n, version))) = (id, version) else {
        let missing: Vec<&str> = [("ID", id), ("VERSION_ID", version)]
            .into_iter()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k)
            .collect();
        return not_read(
            machine,
            RELEASE,
            Cause::NotGiven,
            &format!("the system does not give {}", missing.join(" or ")),
        );
    };
    let say = |predicate, object: String, n: usize| Statement {
        subject: machine.to_string(),
        predicate,
        object,
        source_ref: format!("{raw_file}:{n}"),
    };
    let mut st = vec![say("runs_release", format!("{id} {version}"), n)];
    if let Some((n, codename)) = codename {
        st.push(say("release_codename", codename.to_string(), n));
    }
    full(machine, RELEASE, st)
}

/// An address the server has on one of its interfaces, in its canonical form, or
/// `None` when it names no one machine: loopback, link-local, or the address of a
/// container bridge.
fn own_address(interface: &str, address: &str) -> Option<String> {
    if BRIDGES.iter().any(|b| interface.starts_with(b)) {
        return None;
    }
    let address = address.split(['/', '%']).next().unwrap_or(address);
    let ip = address.parse::<std::net::IpAddr>().ok()?.to_canonical();
    let local = match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
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

/// The readings of a server whose file could not be read or whose visit failed: the reader
/// tried and could not.
fn nothing_read(machine: &str, reason: &str) -> Vec<Outcome> {
    [PACKAGES, SOURCES, KERNEL_PACKAGE, RELEASE, CONTAINERS]
        .into_iter()
        .map(|kind| not_read(machine, kind, Cause::Failed, reason))
        .collect()
}

/// The latest visit: full when it left a complete reading, else none with why it failed.
pub fn visit(machine: &str, failed: Option<&str>) -> Outcome {
    match failed {
        Some(reason) => not_read(machine, VISIT, Cause::Failed, reason),
        None => full(machine, VISIT, Vec::new()),
    }
}

fn not_read(scope: &str, kind: &'static str, cause: Cause, reason: &str) -> Outcome {
    Outcome {
        scope: scope.to_string(),
        kind,
        completeness: "none",
        reason: Some(reason.to_string()),
        gap: Gap::of(cause),
        statements: Vec::new(),
    }
}

/// Full, or partial for the reason and with the gap given.
fn reading(
    scope: &str,
    kind: &'static str,
    partial: Option<String>,
    gap: Gap,
    statements: Vec<Statement>,
) -> Outcome {
    Outcome {
        scope: scope.to_string(),
        kind,
        completeness: if partial.is_some() { "partial" } else { "full" },
        reason: partial,
        gap,
        statements,
    }
}

fn full(scope: &str, kind: &'static str, statements: Vec<Statement>) -> Outcome {
    Outcome {
        scope: scope.to_string(),
        kind,
        completeness: "full",
        reason: None,
        gap: Gap::default(),
        statements,
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, own_address};

    #[test]
    fn an_address_a_server_gives_itself_is_judged_in_its_canonical_form() {
        // Loopback and link-local addresses are on every server; written as IPv4 mapped into
        // IPv6 they are still those, and would join unrelated servers into one.
        assert_eq!(own_address("eth0", "::ffff:127.0.0.1/104"), None);
        assert_eq!(own_address("eth0", "::ffff:169.254.10.1"), None);
        assert_eq!(own_address("eth0", "fe80::1%eth0"), None);
        assert_eq!(own_address("eth0", "febf::1/64"), None);
        assert_eq!(
            own_address("eth0", "::FFFF:203.0.113.10/96"),
            Some("203.0.113.10".to_string())
        );
        assert_eq!(
            own_address("eth0", "fec0::1/64"),
            Some("fec0::1".to_string())
        );
    }

    #[test]
    fn a_failure_record_without_its_time_is_dated_by_the_file_and_one_without_a_reason_says_so() {
        // A record cut short by copying must still be told as a failure, not lost or dated now.
        let cut = Failure::parse("", 1_767_412_800);
        assert_eq!(cut.at, 1_767_412_800);
        assert_eq!(cut.reason, "the visit left no reason");
    }
}
