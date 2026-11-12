//! The `ssh-config` reader: the servers this machine has an explicit way into, from
//! `~/.ssh/config` and the files it pulls in with `Include`. It takes only `Host`, `Match`,
//! `HostName` and `User`. It never opens a key file and keeps no other setting.
//!
//! A server is a literal alias of a `Host` line: a word without `*` or `?` that is not
//! negated with `!`, and whose line ssh applies when it is given that alias. A `Host` line
//! ssh never applies to its own alias, because the alias is also negated on it or because
//! it sits in a file included from a block that does not apply, is not a way in: ssh would
//! look the word up as a host name. Its `HostName` is another name it is known by. An alias
//! for code hosting, by its name, its `HostName` or `User git`, is left out.
//!
//! Why this is our own code: the configuration is OpenSSH's format, and the reference way
//! to resolve it, `ssh -G`, evaluates `Match exec` and so runs commands from the
//! configuration; the program promises never to run ssh. No library reads the format. So
//! the reader follows OpenSSH's own code closely and is tested on its samples:
//!
//! - a line is split into a keyword and words as `readconf.c` does, with a port of
//!   `argv_split` from `misc.c`;
//! - `Include` is expanded by the system's glob(3), as ssh does, from `~/.ssh` for a
//!   relative path, at most 16 files deep;
//! - a `Host` pattern is matched with the system's fnmatch(3), limited to the `*` and `?`
//!   OpenSSH knows, and a negated pattern that matches turns the line off;
//! - the first value obtained wins, from whichever block applies, as in ssh.
//!
//! What is not resolved is said, never guessed. A `Match` block is not evaluated: when one
//! could give an alias its `HostName` or `User` first, that value is not recorded and the
//! reading is partial with the place of the `Match`. An `Include` argument with `%` tokens,
//! `${}` variables or `~user` is not expanded, and the reading is partial naming it. So is
//! one that ssh refuses: an unclosed quote, or includes more than 16 deep.

use crate::store::{Cause, Gap, Lack};
use crate::traces::{Extract, Found, Seen, code_hosting, note};
use std::cell::RefCell;
use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const READER: &str = "ssh-config";
pub const KIND: &str = "ssh configuration";
pub const BASIS: &str = "declared";
pub const NOT_PRESENT: &str = "there is no ssh configuration on this machine";
/// What this build has no reader for in an ssh configuration, in its own words.
pub const MATCH: &str = "ssh Match block, which is not evaluated";
pub const INCLUDE_TOKENS: &str = "ssh Include with % tokens or ${} variables";
pub const INCLUDE_USER: &str = "ssh Include with ~user";

/// How deep includes go: ssh refuses a configuration that includes deeper than this
/// (`READCONF_MAX_DEPTH` in `readconf.c`).
const MAX_DEPTH: usize = 16;

pub fn read(home: &Path) -> Found {
    let ssh = home.join(".ssh");
    let config = match crate::traces::source(home, ".ssh/config", NOT_PRESENT) {
        Ok(path) => path,
        Err(found) => return *found,
    };
    let text = match std::fs::read(config) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Found::Absent(NOT_PRESENT),
        Err(e) => return Found::Failed(format!("cannot read ~/.ssh/config: {e}")),
    };
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut p = Parser {
        home,
        homes: [home, &real_home],
        ssh: &ssh,
        guarded: Vec::new(),
        lines: Vec::new(),
        unread: Vec::new(),
        problems: Vec::new(),
        lacks: Vec::new(),
    };
    p.file("config", &text, 0);
    Found::Read(p.finish())
}

/// A line that matters, in the order ssh reads it, includes spliced in.
enum Line {
    Host {
        at: String,
        patterns: Vec<String>,
    },
    Match {
        at: String,
    },
    HostName {
        at: String,
        value: String,
    },
    User {
        value: String,
    },
    /// An included file starts and ends: ssh restores the block state after it.
    Enter,
    Leave,
}

struct Parser<'a> {
    home: &'a Path,
    /// The home folder by its names, for the folders macOS asks permission for.
    homes: [&'a Path; 2],
    ssh: &'a Path,
    /// Guarded folders an `Include` leads into, not entered.
    guarded: Vec<PathBuf>,
    lines: Vec<Line>,
    /// Files that are there and could not be read.
    unread: Vec<String>,
    /// Other reasons the reading is partial, each with its cause.
    problems: Vec<(Cause, String)>,
    /// What this build has no reader for in the configuration.
    lacks: Vec<Lack>,
}

impl Parser<'_> {
    fn file(&mut self, label: &str, text: &str, depth: usize) {
        for (i, line) in text.lines().enumerate() {
            let at = format!("{label}:{}", i + 1);
            let Some((keyword, rest)) = keyword(line) else {
                continue;
            };
            let Some(args) = argv_split(rest, true) else {
                // ssh itself refuses the configuration: nothing in it can be relied on.
                self.problems.push((
                    Cause::Failed,
                    format!("{at} has an unclosed quote, so ssh refuses the configuration"),
                ));
                continue;
            };
            let first = args.first().cloned();
            match (keyword.to_ascii_lowercase().as_str(), first) {
                ("host", _) => self.lines.push(Line::Host { at, patterns: args }),
                ("match", _) => self.lines.push(Line::Match { at }),
                ("hostname", Some(value)) => self.lines.push(Line::HostName { at, value }),
                ("user", Some(value)) => self.lines.push(Line::User { value }),
                ("include", _) => {
                    for arg in &args {
                        self.include(&at, arg, depth);
                    }
                }
                _ => {}
            }
        }
    }

    /// One `Include` argument: anchored as ssh anchors it and expanded by glob(3).
    fn include(&mut self, at: &str, arg: &str, depth: usize) {
        if arg.contains('%') || arg.contains("${") {
            self.lacks.push(Lack::new(INCLUDE_TOKENS, None));
            self.problems.push((
                Cause::NoReader,
                format!(
                    "{at} Include {arg} was not read: % tokens and ${{}} variables are not expanded"
                ),
            ));
            return;
        }
        let pattern = if let Some(rest) = arg.strip_prefix("~/") {
            format!("{}/{rest}", glob_escape(self.home))
        } else if arg.starts_with('~') {
            self.lacks.push(Lack::new(INCLUDE_USER, None));
            self.problems.push((
                Cause::NoReader,
                format!("{at} Include {arg} was not read: only ~/ is expanded"),
            ));
            return;
        } else if arg.starts_with('/') {
            arg.to_string()
        } else {
            format!("{}/{arg}", glob_escape(self.ssh))
        };
        let (paths, failed) = self.glob_guarded(at, arg, &pattern);
        for dir in failed {
            let label = self.label(&dir);
            self.unread.push(label);
        }
        for path in paths {
            // A file the pattern matched may be a link into a guarded folder.
            if let crate::guarded::Real::Guarded(g) = crate::guarded::real(&path, &self.homes) {
                self.guard(at, arg, g);
                continue;
            }
            // ssh reads a folder as an empty file.
            if path.is_dir() {
                continue;
            }
            let label = self.label(&path);
            if depth >= MAX_DEPTH {
                self.problems.push((
                    Cause::Failed,
                    format!("{at} includes {label} too deep, so ssh refuses the configuration"),
                ));
                continue;
            }
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    self.lines.push(Line::Enter);
                    self.file(&label, &text, depth + 1);
                    self.lines.push(Line::Leave);
                }
                // ssh skips an include that is not there.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.unread.push(label),
            }
        }
    }

    /// What glob(3) gives ssh for an absolute pattern, without passing through a folder that
    /// leads into a guarded one. glob(3) looks at every folder on the way to the pattern's
    /// last part, those its wildcards match included, so it is run one wildcard at a time:
    /// before each run the folder it starts in is made real, and one that leads into a
    /// guarded folder is not looked into, and said. A part that cannot be followed is left
    /// to glob(3), which then finds nothing there. The paths are sorted as one glob(3) sorts
    /// them, by their bytes in the C locale ssh reads it in.
    fn glob_guarded(&mut self, at: &str, arg: &str, pattern: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let parts: Vec<&str> = pattern.split('/').skip(1).collect();
        if parts.is_empty() {
            return (Vec::new(), Vec::new());
        }
        // The pattern in runs, each ending at a wildcard or at the last part. The parts
        // before a run's end hold no wildcard, nor an escape.
        let mut runs: Vec<&[&str]> = Vec::new();
        let mut from = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.contains(['*', '?', '[', '\\']) || i == parts.len() - 1 {
                runs.push(&parts[from..=i]);
                from = i + 1;
            }
        }
        let (mut reached, mut failed) = (vec![PathBuf::from("/")], Vec::new());
        for run in runs {
            let mut next = Vec::new();
            for start in &reached {
                let folder = start.join(run[..run.len() - 1].join("/"));
                if let crate::guarded::Real::Guarded(g) = crate::guarded::real(&folder, &self.homes)
                {
                    self.guard(at, arg, g);
                    continue;
                }
                let start = glob_escape(start);
                let (paths, dirs) = glob(&format!(
                    "{}/{}",
                    start.trim_end_matches('/'),
                    run.join("/")
                ));
                next.extend(paths);
                failed.extend(dirs);
            }
            reached = next;
        }
        reached.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
        (reached, failed)
    }

    /// An `Include` that leads into a guarded folder: not read, and said.
    fn guard(&mut self, at: &str, arg: &str, folder: PathBuf) {
        let said = format!(
            "{at} Include {arg} was not read: {}",
            crate::guarded::leads_into(&folder, self.home)
        );
        if !self.problems.iter().any(|(_, p)| *p == said) {
            self.problems.push((Cause::NotGiven, said));
        }
        if !self.guarded.contains(&folder) {
            self.guarded.push(folder);
        }
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

    fn finish(mut self) -> Seen {
        let mut aliases: Vec<&str> = Vec::new();
        for line in &self.lines {
            if let Line::Host { patterns, .. } = line {
                for p in patterns.iter().filter(|p| literal(p)) {
                    if !aliases.contains(&p.as_str()) {
                        aliases.push(p);
                    }
                }
            }
        }
        let mut extract = Extract::default();
        let mut extracted: Vec<(String, usize)> = Vec::new();
        let mut add = |line: String| match extracted.iter().find(|(l, _)| *l == line) {
            Some((_, n)) => *n,
            None => {
                let n = extract.add(&line);
                extracted.push((line, n));
                n
            }
        };
        let (mut hosts, mut third_party) = (Vec::new(), 0);
        // Each `Match` not applied, with the aliases whose values it could have set.
        let mut not_applied: Vec<(&str, Vec<&str>)> = Vec::new();
        let lines: &[Line] = &self.lines;
        for alias in aliases {
            let r = resolve(lines, alias);
            let host_line = match r.applied {
                Some((State::Yes, at, patterns)) => format!("{at}\tHost {}", patterns.join(" ")),
                Some((State::Maybe(m), ..)) => {
                    depends_on(&mut not_applied, m, alias);
                    continue;
                }
                _ => continue,
            };
            for slot in [&r.host_name, &r.user] {
                if let Value::Unknown(m) = slot {
                    depends_on(&mut not_applied, m, alias);
                }
            }
            let host_name = match &r.host_name {
                Value::Set(value, at) => Some((expand_host(value, alias), *at, *value)),
                _ => None,
            };
            if code_hosting(alias)
                || host_name.as_ref().is_some_and(|(h, ..)| code_hosting(h))
                || matches!(r.user, Value::Set("git", _))
            {
                third_party += 1;
                continue;
            }
            note(&mut hosts, alias, alias, add(host_line));
            if let Some((value, at, raw)) = host_name {
                note(
                    &mut hosts,
                    alias,
                    &value,
                    add(format!("{at}\tHostName {raw}")),
                );
            }
        }
        let mut reasons: Vec<(Cause, String)> = Vec::new();
        if !self.unread.is_empty() {
            let unread = format!("could not read {}", self.unread.join(", "));
            reasons.push((Cause::Failed, unread));
        }
        reasons.append(&mut self.problems);
        for (at, aliases) in not_applied {
            // Evaluating a Match would run its commands: this build has no reader for it.
            self.lacks.push(Lack::new(MATCH, None));
            reasons.push((
                Cause::NoReader,
                format!(
                    "the Match at {at} was not applied; it may decide the HostName or User of {}",
                    aliases.join(", ")
                ),
            ));
        }
        // Several reasons: the reading is as bad as the worst of them.
        let mut lacks = std::mem::take(&mut self.lacks);
        lacks.dedup();
        let gap = Gap {
            cause: Cause::worst(reasons.iter().map(|(c, _)| *c)),
            lacks,
        };
        let reasons: Vec<String> = reasons.into_iter().map(|(_, r)| r).collect();
        Seen {
            extract: extract.into_text(),
            hosts,
            partial: (!reasons.is_empty()).then(|| reasons.join("; ")),
            gap,
            third_party,
            guarded: std::mem::take(&mut self.guarded),
        }
    }
}

/// Notes that what ssh makes of an alias depends on the `Match` at `at`.
fn depends_on<'a>(list: &mut Vec<(&'a str, Vec<&'a str>)>, at: &'a str, alias: &'a str) {
    match list.iter_mut().find(|(m, _)| *m == at) {
        Some((_, aliases)) if !aliases.contains(&alias) => aliases.push(alias),
        Some(_) => {}
        None => list.push((at, vec![alias])),
    }
}

/// Whether a block applies: `Maybe` names the `Match` it depends on.
#[derive(Clone, Copy, PartialEq)]
enum State<'a> {
    No,
    Maybe(&'a str),
    Yes,
}

impl State<'_> {
    fn rank(self) -> u8 {
        match self {
            State::No => 0,
            State::Maybe(_) => 1,
            State::Yes => 2,
        }
    }
}

/// A value of one alias: the first one obtained wins, as in ssh.
enum Value<'a> {
    Unset,
    /// The value and the place it was read.
    Set(&'a str, &'a str),
    /// A `Match` that is not evaluated could have set it first.
    Unknown(&'a str),
}

impl<'a> Value<'a> {
    fn offer(&mut self, value: &'a str, at: &'a str, state: State<'a>) {
        if let Value::Unset = self {
            match state {
                State::Yes => *self = Value::Set(value, at),
                State::Maybe(m) => *self = Value::Unknown(m),
                State::No => {}
            }
        }
    }
}

struct Resolved<'a> {
    /// The strongest state of a `Host` line that names the alias literally, with its place
    /// and patterns.
    applied: Option<(State<'a>, &'a str, &'a [String])>,
    host_name: Value<'a>,
    user: Value<'a>,
}

/// What ssh makes of the configuration when it is given this alias, as `readconf.c` reads
/// it: a `Host` line turns the block on when a pattern matches and no negated one does; a
/// file included while the block is off is read with every block off; after an included
/// file the block is what it was before.
fn resolve<'a>(lines: &'a [Line], alias: &str) -> Resolved<'a> {
    let mut r = Resolved {
        applied: None,
        host_name: Value::Unset,
        user: Value::Unset,
    };
    let (mut active, mut never) = (State::Yes, State::No);
    let mut stack = Vec::new();
    for line in lines {
        match line {
            Line::Host { at, patterns } => {
                let (positive, negative): (Vec<&String>, Vec<&String>) =
                    patterns.iter().partition(|p| !p.starts_with('!'));
                let matched = positive.iter().any(|p| host_matches(alias, p))
                    && !negative.iter().any(|p| host_matches(alias, &p[1..]));
                active = match never {
                    _ if !matched => State::No,
                    State::No => State::Yes,
                    State::Maybe(m) => State::Maybe(m),
                    State::Yes => State::No,
                };
                if positive.iter().any(|p| p.as_str() == alias)
                    && active.rank() > r.applied.map_or(0, |(s, ..)| s.rank())
                {
                    r.applied = Some((active, at.as_str(), patterns.as_slice()));
                }
            }
            Line::Match { at } => {
                active = match never {
                    State::Yes => State::No,
                    _ => State::Maybe(at),
                }
            }
            Line::HostName { at, value } => r.host_name.offer(value, at, active),
            Line::User { value } => r.user.offer(value, "", active),
            Line::Enter => {
                stack.push((active, never));
                never = match (never, active) {
                    (State::Yes, _) | (_, State::No) => State::Yes,
                    (State::Maybe(m), _) | (_, State::Maybe(m)) => State::Maybe(m),
                    _ => State::No,
                };
            }
            Line::Leave => {
                if let Some(saved) = stack.pop() {
                    (active, never) = saved;
                }
            }
        }
    }
    r
}

/// A pattern of a `Host` line that names exactly one host: not negated, no wildcard.
fn literal(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.starts_with('!') && !pattern.contains(['*', '?'])
}

/// Whether a `Host` pattern matches the alias, as OpenSSH's `match_pattern` does: `*` is
/// any run of characters, `?` any one, everything else itself, case counts. fnmatch(3)
/// also knows brackets and escapes, so those are escaped first.
fn host_matches(alias: &str, pattern: &str) -> bool {
    let escaped = pattern.replace('\\', "\\\\").replace('[', "\\[");
    let (Ok(p), Ok(s)) = (CString::new(escaped), CString::new(alias)) else {
        return false;
    };
    // SAFETY: both are NUL-terminated strings that live across the call.
    unsafe { libc::fnmatch(p.as_ptr(), s.as_ptr(), 0) == 0 }
}

/// The keyword and the rest of a configuration line, as `process_config_line_depth` in
/// `readconf.c` takes them with `strdelim`: the keyword ends at whitespace, a quote or one
/// `=`, so `Host web`, `Host=web` and `Host = web` are one line. `None` for an empty line,
/// a comment or a keyword with nothing after it.
fn keyword(line: &str) -> Option<(String, &str)> {
    let line = line.trim_end_matches([' ', '\t', '\r', '\n', '\x0c']);
    let (mut keyword, mut rest) = strdelim(line)?;
    if keyword.is_empty() {
        (keyword, rest) = strdelim(rest?)?;
    }
    if keyword.is_empty() || keyword.starts_with('#') {
        return None;
    }
    let rest = rest?.trim_start_matches(WHITESPACE);
    (!rest.is_empty()).then_some((keyword, rest))
}

const WHITESPACE: [char; 4] = [' ', '\t', '\r', '\n'];

/// One word and what follows it, as `strdelim` in `misc.c` splits them. `None` when a
/// quote is not closed.
fn strdelim(s: &str) -> Option<(String, Option<&str>)> {
    let Some(k) = s.find(|c| WHITESPACE.contains(&c) || c == '"' || c == '=') else {
        return Some((s.to_string(), None));
    };
    if s[k..].starts_with('"') {
        let close = s[k + 1..].find('"')? + k + 1;
        let word = format!("{}{}", &s[..k], &s[k + 1..close]);
        return Some((word, Some(s[close + 1..].trim_start_matches(WHITESPACE))));
    }
    let equals = s[k..].starts_with('=');
    let mut rest = s[k + 1..].trim_start_matches(WHITESPACE);
    if !equals && rest.starts_with('=') {
        rest = rest[1..].trim_start_matches(WHITESPACE);
    }
    Some((s[..k].to_string(), Some(rest)))
}

/// The words of a line, as `argv_split` in OpenSSH's `misc.c` splits them: spaces and tabs
/// separate words, `'` and `"` quote, a backslash escapes a quote, a backslash or (outside
/// quotes) a space, and with `comments` a `#` that starts a word ends the line. `None` when
/// a quote is not closed: ssh then refuses the configuration.
///
/// Ported from OpenSSH (misc.c: Copyright (c) 2005-2020 Damien Miller and others), under
/// its ISC-style licence: permission to use, copy, modify and distribute with the
/// copyright and permission notice kept.
fn argv_split(s: &str, comments: bool) -> Option<Vec<String>> {
    let s = s.as_bytes();
    let mut args = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b' ' || s[i] == b'\t' {
            i += 1;
            continue;
        }
        if comments && s[i] == b'#' {
            break;
        }
        let (mut quote, mut arg) = (0u8, Vec::new());
        while i < s.len() {
            let c = s[i];
            let next = s.get(i + 1).copied();
            if c == b'\\' {
                if matches!(next, Some(b'\'' | b'"' | b'\\')) || (quote == 0 && next == Some(b' '))
                {
                    i += 1;
                    arg.push(s[i]);
                } else {
                    arg.push(c);
                }
            } else if quote == 0 && (c == b' ' || c == b'\t') {
                break;
            } else if quote == 0 && (c == b'"' || c == b'\'') {
                quote = c;
            } else if quote != 0 && c == quote {
                quote = 0;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if quote != 0 {
            return None;
        }
        args.push(String::from_utf8_lossy(&arg).into_owned());
        i += 1;
    }
    Some(args)
}

/// `%h` in a `HostName` is the alias; `%%` is a percent sign.
fn expand_host(value: &str, alias: &str) -> String {
    value
        .replace("%%", "\u{0}")
        .replace("%h", alias)
        .replace('\u{0}', "%")
}

/// A path as a glob(3) pattern that matches only itself.
fn glob_escape(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        if matches!(c, '*' | '?' | '[' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

thread_local! {
    /// Folders glob(3) could not open during the current call.
    static GLOB_FAILED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
}

/// macOS glob(3) reports no folder that is missing or is a file: it matches nothing there,
/// as ssh expects. What it does report is a folder it could not open.
extern "C" fn glob_error(path: *const libc::c_char, _errno: libc::c_int) -> libc::c_int {
    // SAFETY: glob(3) passes a NUL-terminated path.
    let path = unsafe { CStr::from_ptr(path) };
    let path = PathBuf::from(OsStr::from_bytes(path.to_bytes()));
    GLOB_FAILED.with(|f| f.borrow_mut().push(path));
    // Go on, as ssh does.
    0
}

/// The paths a pattern matches, sorted, as glob(3) gives them to ssh, and the folders it
/// could not open on the way.
fn glob(pattern: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let Ok(c) = CString::new(pattern) else {
        return (Vec::new(), Vec::new());
    };
    GLOB_FAILED.with(|f| f.borrow_mut().clear());
    let mut paths = Vec::new();
    // SAFETY: glob_t is a plain C structure that glob(3) fills; zeroed is its empty state,
    // and globfree releases what glob allocated, whatever it returned.
    unsafe {
        let mut g: libc::glob_t = std::mem::zeroed();
        if libc::glob(c.as_ptr(), 0, Some(glob_error), &mut g) == 0 {
            for i in 0..g.gl_pathc {
                let p = CStr::from_ptr(*g.gl_pathv.add(i));
                paths.push(PathBuf::from(OsStr::from_bytes(p.to_bytes())));
            }
        }
        libc::globfree(&mut g);
    }
    (paths, GLOB_FAILED.with(|f| f.take()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_splits_into_the_words_openssh_reads_so_nothing_in_a_comment_becomes_an_alias() {
        // OpenSSH's own vectors, regress/unittests/misc/test_argv.c (public domain), as of
        // openssh-portable 1d28115e. An alias is a word of a Host line, and it becomes a
        // word in the sweep script: a word ssh does not read must never become one.
        let ok: &[(&str, bool, &[&str])] = &[
            ("", false, &[]),
            ("    ", false, &[]),
            ("leamas", false, &["leamas"]),
            ("smiley leamas", false, &["smiley", "leamas"]),
            ("\"smiley\"", false, &["smiley"]),
            ("leamas \" smiley \"", false, &["leamas", " smiley "]),
            ("\"smiley leamas\"", false, &["smiley leamas"]),
            ("smiley\" leamas\" liz", false, &["smiley leamas", "liz"]),
            ("\\\"smiley\\'", false, &["\"smiley'"]),
            ("'\\'smiley\\\"'", false, &["'smiley\""]),
            ("smiley\\'s leamas\\'", false, &["smiley's", "leamas'"]),
            ("leamas\\\\smiley", false, &["leamas\\smiley"]),
            ("leamas\\\\ \\\\smiley", false, &["leamas\\", "\\smiley"]),
            ("smiley\\ leamas", false, &["smiley leamas"]),
            ("'smiley\\ leamas'", false, &["smiley\\ leamas"]),
            ("\"smiley\\ leamas\"", false, &["smiley\\ leamas"]),
            ("# gold", false, &["#", "gold"]),
            ("# gold", true, &[]),
            ("leamas#gold", true, &["leamas#gold"]),
            ("\"leamas # gold\"", true, &["leamas # gold"]),
            ("\"leamas\"#gold", true, &["leamas#gold"]),
        ];
        for (line, comments, words) in ok {
            let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
            assert_eq!(argv_split(line, *comments), Some(words), "{line:?}");
        }
        // ssh refuses a line with an unclosed quote.
        for line in ["\"smiley", "leamas 'smiley"] {
            assert_eq!(argv_split(line, true), None, "{line:?}");
        }
    }

    #[test]
    fn only_a_plain_word_of_a_host_line_is_an_alias() {
        // An alias becomes a word in the sweep script, and ssh connects to it. A pattern, a
        // negation or an empty word is not a server ssh can be sent to by name.
        for (word, alias) in [
            ("web", true),
            ("db-1.example.org", true),
            ("we!b", true),
            ("", false),
            ("!web", false),
            ("web-*", false),
            ("web-?", false),
        ] {
            assert_eq!(literal(word), alias, "{word:?}");
        }
    }

    #[test]
    fn a_keyword_is_read_with_spaces_or_one_equals_sign_as_ssh_reads_it() {
        // readconf.c accepts `Host web`, `Host=web` and `Host = web` alike; a line read
        // differently from ssh names servers ssh does not have.
        for (line, expected) in [
            ("Host web", Some(("Host", "web"))),
            (
                "  Host\tweb # production box",
                Some(("Host", "web # production box")),
            ),
            ("Host=web", Some(("Host", "web"))),
            ("Host = web", Some(("Host", "web"))),
            ("Host =web", Some(("Host", "web"))),
            ("Host==web", Some(("Host", "=web"))),
            ("\"Host\" web", Some(("Host", "web"))),
            ("Host web \x0c", Some(("Host", "web"))),
            ("# Host web", None),
            ("#Host web", None),
            ("Host", None),
            ("Host   ", None),
            ("", None),
            ("\"Host web", None),
        ] {
            let got = keyword(line);
            assert_eq!(
                got.as_ref().map(|(k, r)| (k.as_str(), *r)),
                expected,
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_host_pattern_matches_exactly_what_openssh_matches() {
        // OpenSSH's own vectors for match_pattern, regress/unittests/match/tests.c (public
        // domain), as of openssh-portable 1d28115e, then the characters fnmatch(3) would
        // read differently from OpenSSH. A pattern block that applies, or does not, sets
        // the HostName ssh uses.
        let vectors: &[(&str, &str, bool)] = &[
            ("", "", true),
            ("", "aaa", false),
            ("aaa", "", false),
            ("aaa", "aaaa", false),
            ("aaaa", "aaa", false),
            ("abc", "abc", true),
            ("abc", "abd", false),
            ("abc", "abcd", false),
            ("abcd", "abc", false),
            ("", "*", true),
            ("", "**", true),
            ("", "***", true),
            ("", "?", false),
            ("", "*?", false),
            ("", "?*", false),
            ("", "**a*", false),
            ("a", "?", true),
            ("aa", "a?", true),
            ("a", "*", true),
            ("aa", "a*", true),
            ("aa", "?*", true),
            ("aa", "?a", true),
            ("aa", "*a", true),
            ("ba", "a?", false),
            ("ba", "a*", false),
            ("ab", "?a", false),
            ("ab", "*a", false),
            ("aa", "**", true),
            ("ab", "a***b", true),
            ("axb", "a***b", true),
            ("axxb", "a***b", true),
            ("ax", "a***b", false),
            ("abbb", "a*b*b", true),
            ("abbb", "a*b*c", false),
            ("aaaaaaaaac", "a*a*a*a*b", false),
            ("aaaaaaaaab", "a*a*a*a*b", true),
            ("ab", "*b", true),
            ("ab", "*a*", true),
            ("ab", "*a*b", true),
            ("ab", "*a*c", false),
            ("abc", "a?c", true),
            ("abc", "??c", true),
            ("abc", "???", true),
            ("abc", "a?d", false),
            ("ab", "???", false),
            ("abc", "ab*", true),
            ("ab", "ab*", true),
            ("a", "ab*", false),
            ("abc", "ab?", true),
            ("ab", "ab?", false),
            ("abcd", "ab?", false),
            ("abc", "?bc", true),
            ("abc", "?b*", true),
            ("abc", "?c", false),
            ("abc", "a*?c", true),
            ("ac", "a*?c", false),
            ("abbc", "a*?c", true),
            ("abc", "a?*c", true),
            ("ac", "a?*c", false),
            ("abbc", "a?*c", true),
            ("abc", "a*?*c", true),
            ("ac", "a*?*c", false),
            ("abc", "?*c", true),
            ("ac", "?*c", true),
            ("c", "?*c", false),
            ("abc", "*?c", true),
            ("ac", "*?c", true),
            ("c", "*?c", false),
            ("abc", "a?*", true),
            ("ab", "a?*", true),
            ("a", "a?*", false),
            ("abc", "a*?", true),
            ("ab", "a*?", true),
            ("a", "a*?", false),
            ("abb", "a*b", true),
            ("abbc", "a*b", false),
            // OpenSSH knows no brackets, escapes or case folding.
            ("a", "[a]", false),
            ("[a]", "[a]", true),
            ("a", "\\a", false),
            ("\\a", "\\a", true),
            ("Web", "web", false),
            ("a/b", "a*", true),
            (".a", "*", true),
        ];
        for (input, pattern, expected) in vectors {
            assert_eq!(
                host_matches(input, pattern),
                *expected,
                "{input:?} against {pattern:?}"
            );
        }
    }
}
