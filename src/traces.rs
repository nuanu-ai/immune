//! What the local traces of servers have in common: the ssh configuration, known hosts and
//! the tailnet. Each is its own reader with its own coverage of this machine. Each server a
//! trace names becomes a machine entity with one `known_as` assertion per name or address.
//! Readers never merge entities and never drop one because another trace also has it: the
//! resolver links them afterwards.
//!
//! A trace keeps an extract as its raw input, not the source itself: the sources hold keys
//! and settings that are not ours to copy.

use crate::store::Statement;

/// Code hosting and similar third parties. They are not the owner's machines: no reader
/// makes an entity for them and the sweep never visits them.
const CODE_HOSTING: [&str; 6] = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "ssh.dev.azure.com",
    "sr.ht",
    "codeberg.org",
];

/// Whether a name belongs to code hosting: the domain itself or a name under it.
pub fn code_hosting(name: &str) -> bool {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    CODE_HOSTING
        .iter()
        .any(|d| name == *d || name.ends_with(&format!(".{d}")))
}

/// One server as a trace names it.
pub struct Host {
    /// The name in its entity id, `machine:<name>`.
    pub name: String,
    /// Names and addresses, each with the line of the extract it rests on, counted from 1.
    pub known_as: Vec<(String, usize)>,
    /// The operating system, where the trace gives one.
    pub os: Option<(String, usize)>,
}

/// What reading one trace found.
pub enum Found {
    /// The source is not on this machine: nothing to read, which is not a failure.
    Absent(&'static str),
    Read(Seen),
    /// The source is here and could not be read, with the reason.
    Failed(String),
}

pub struct Seen {
    /// What was taken from the source, one line per thing taken.
    pub extract: String,
    pub hosts: Vec<Host>,
    /// Why the reading is partial; `None` when it is full.
    pub partial: Option<String>,
    /// Entries left out as code hosting.
    pub third_party: usize,
}

impl Seen {
    /// `raw_file` is the saved extract, relative to the store's folder.
    pub fn statements(&self, raw_file: &str) -> Vec<Statement> {
        let mut out = Vec::new();
        for host in &self.hosts {
            let subject = format!("machine:{}", host.name);
            let facts = host
                .known_as
                .iter()
                .map(|(v, n)| ("known_as", v, n))
                .chain(host.os.iter().map(|(v, n)| ("runs_os", v, n)));
            for (predicate, object, n) in facts {
                out.push(Statement {
                    subject: subject.clone(),
                    predicate,
                    object: object.clone(),
                    source_ref: format!("{raw_file}:{n}"),
                });
            }
        }
        out
    }
}

/// The extract a reader builds as it reads.
#[derive(Default)]
pub struct Extract {
    text: String,
    lines: usize,
}

impl Extract {
    /// Adds one line and returns its number, counted from 1. Line breaks inside are dropped.
    pub fn add(&mut self, line: &str) -> usize {
        self.text.push_str(&line.replace(['\n', '\r'], " "));
        self.text.push('\n');
        self.lines += 1;
        self.lines
    }

    pub fn into_text(self) -> String {
        self.text
    }
}

/// Adds a name to a host found by name, or a new host, keeping the order of first sight.
pub fn note(hosts: &mut Vec<Host>, name: &str, known_as: &str, line: usize) {
    let i = match hosts.iter().position(|h| h.name == name) {
        Some(i) => i,
        None => {
            hosts.push(Host {
                name: name.to_string(),
                known_as: Vec::new(),
                os: None,
            });
            hosts.len() - 1
        }
    };
    let host = &mut hosts[i];
    if !host.known_as.iter().any(|(v, _)| v == known_as) {
        host.known_as.push((known_as.to_string(), line));
    }
}
