//! The `ssh-config` reader: the servers this machine has an explicit way into, from
//! `~/.ssh/config` and the files it pulls in with `Include`. It takes only `Host`,
//! `HostName` and `User`. It never opens a key file and keeps no other setting.
//!
//! Every `Host` alias that is a plain name, without `*`, `?` or `!`, is a server. Its
//! `HostName` is another name it is known by. An alias for code hosting, by its name, its
//! `HostName` or `User git`, is left out.

use crate::traces::{Extract, Found, Seen, code_hosting, note};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const READER: &str = "ssh-config";
pub const KIND: &str = "ssh configuration";
pub const BASIS: &str = "declared";
pub const NOT_PRESENT: &str = "there is no ssh configuration on this machine";

/// Includes that include themselves stop here.
const MAX_DEPTH: usize = 16;

pub fn read(home: &Path) -> Found {
    let ssh = home.join(".ssh");
    let text = match std::fs::read(ssh.join("config")) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Found::Absent(NOT_PRESENT),
        Err(e) => return Found::Failed(format!("cannot read ~/.ssh/config: {e}")),
    };
    let mut p = Parser {
        home,
        ssh: &ssh,
        extract: Extract::default(),
        aliases: Vec::new(),
        index: BTreeMap::new(),
        unread: Vec::new(),
    };
    p.file("config", &text, &mut Vec::new(), 0);
    Found::Read(p.finish())
}

struct Alias {
    name: String,
    /// The extract line of the first `Host` line that names it.
    line: usize,
    host_name: Option<(String, usize)>,
    user: Option<String>,
}

struct Parser<'a> {
    home: &'a Path,
    ssh: &'a Path,
    extract: Extract,
    aliases: Vec<Alias>,
    index: BTreeMap<String, usize>,
    /// Included files that are there and could not be read.
    unread: Vec<String>,
}

impl Parser<'_> {
    /// `block` holds the aliases the lines apply to: those of the latest `Host` line.
    fn file(&mut self, label: &str, text: &str, block: &mut Vec<usize>, depth: usize) {
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (keyword, args) = split(line);
            match keyword.to_ascii_lowercase().as_str() {
                "host" => {
                    block.clear();
                    let n =
                        self.extract
                            .add(&format!("{label}:{}\tHost {}", i + 1, args.join(" ")));
                    for name in args.iter().filter(|a| plain(a)) {
                        let k = *self.index.entry(name.clone()).or_insert_with(|| {
                            self.aliases.push(Alias {
                                name: name.clone(),
                                line: n,
                                host_name: None,
                                user: None,
                            });
                            self.aliases.len() - 1
                        });
                        block.push(k);
                    }
                }
                "match" => block.clear(),
                "hostname" if !block.is_empty() => {
                    let Some(value) = args.first() else { continue };
                    let n = self
                        .extract
                        .add(&format!("{label}:{}\tHostName {value}", i + 1));
                    // The first value obtained wins, as in ssh.
                    for &k in block.iter() {
                        let alias = &mut self.aliases[k];
                        if alias.host_name.is_none() {
                            alias.host_name = Some((expand_host(value, &alias.name), n));
                        }
                    }
                }
                "user" => {
                    for &k in block.iter() {
                        let alias = &mut self.aliases[k];
                        if alias.user.is_none() {
                            alias.user = args.first().cloned();
                        }
                    }
                }
                "include" if depth < MAX_DEPTH => {
                    for arg in &args {
                        for path in self.paths(arg) {
                            let label = self.label(&path);
                            match std::fs::read(&path) {
                                Ok(bytes) => {
                                    let text = String::from_utf8_lossy(&bytes).into_owned();
                                    let mut inner = block.clone();
                                    self.file(&label, &text, &mut inner, depth + 1);
                                }
                                // ssh skips an include that is not there.
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                Err(_) => self.unread.push(label),
                            }
                        }
                    }
                }
                "include" => self.unread.push(format!("{label}:{} (too deep)", i + 1)),
                _ => {}
            }
        }
    }

    /// The files an `Include` argument names: relative to `~/.ssh`, with `*` and `?`
    /// allowed in the last part.
    fn paths(&mut self, arg: &str) -> Vec<PathBuf> {
        let path = if let Some(rest) = arg.strip_prefix("~/") {
            self.home.join(rest)
        } else if arg.starts_with('/') {
            PathBuf::from(arg)
        } else {
            self.ssh.join(arg)
        };
        let Some(pattern) = path.file_name().and_then(|n| n.to_str()) else {
            return vec![path];
        };
        if !pattern.contains(['*', '?']) {
            return vec![path];
        }
        let dir = path.parent().unwrap_or(Path::new("/"));
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(_) => {
                let label = self.label(dir);
                self.unread.push(label);
                return Vec::new();
            }
        };
        let mut out: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .filter(|e| e.file_name().to_str().is_some_and(|n| glob(pattern, n)))
            .map(|e| e.path())
            .collect();
        out.sort();
        out
    }

    /// A path as the extract names it: relative to `~/.ssh` or to the home folder.
    fn label(&self, path: &Path) -> String {
        if let Ok(rel) = path.strip_prefix(self.ssh) {
            return rel.to_string_lossy().into_owned();
        }
        if let Ok(rel) = path.strip_prefix(self.home) {
            return format!("~/{}", rel.to_string_lossy());
        }
        path.to_string_lossy().into_owned()
    }

    fn finish(self) -> Seen {
        let mut hosts = Vec::new();
        let mut third_party = 0;
        for alias in &self.aliases {
            let host_name = alias.host_name.as_ref();
            if code_hosting(&alias.name)
                || host_name.is_some_and(|(h, _)| code_hosting(h))
                || alias.user.as_deref() == Some("git")
            {
                third_party += 1;
                continue;
            }
            note(&mut hosts, &alias.name, &alias.name, alias.line);
            if let Some((value, n)) = host_name {
                note(&mut hosts, &alias.name, value, *n);
            }
        }
        let partial =
            (!self.unread.is_empty()).then(|| format!("could not read {}", self.unread.join(", ")));
        Seen {
            extract: self.extract.into_text(),
            hosts,
            partial,
            third_party,
        }
    }
}

/// The keyword and its arguments. A keyword is followed by spaces or by `=`; an argument
/// in double quotes may hold spaces.
fn split(line: &str) -> (&str, Vec<String>) {
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in rest.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    (keyword, args)
}

/// A pattern that names exactly one host.
fn plain(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.contains(['*', '?', '!'])
}

/// `%h` in a `HostName` is the alias; `%%` is a percent sign.
fn expand_host(value: &str, alias: &str) -> String {
    value
        .replace("%%", "\u{0}")
        .replace("%h", alias)
        .replace('\u{0}', "%")
}

/// `*` matches any run of characters, `?` any one.
fn glob(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}
