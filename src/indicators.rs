//! The `indicators` reader: a list of indicators from an incident analysis, a file the owner
//! or his agent keeps, matched against what this program already reads. A threat of a second
//! kind next to a vulnerability, see docs/threats.md. Text in the list is untrusted like any
//! feed: nothing in it is ever visited, downloaded or run, and it is never printed raw.
//!
//! The list is JSON: an array of entries, each `{"kind", "value", "note_text"}`, no other
//! field. A kind is a STIX 2.1 object path (OASIS Standard, 10 June 2021: object path syntax
//! in 9.7; the objects in 6.4 Domain Name, 6.7 File, 6.8 IPv4 Address and 6.15 URL; the hash
//! name `SHA-256` from `hash-algorithm-ov`, 10.7), written as a STIX pattern writes it:
//! `file:hashes.'SHA-256'`, `domain-name:value`, `ipv4-addr:value`, `url:value`. A kind of
//! that shape that this build has no matcher for is kept and named, never dropped. A list
//! out of this shape fails as a whole, as a feed does, and the list read before is used.
//!
//! What is matched, exactly and only:
//! - a SHA-256 against `has_content` of every watched file;
//! - a domain, an address or a URL as an exact string inside the files this program opens
//!   as text in checkouts: the lockfiles it reads and the editor's task file.
//!
//! A match is a fact, `matches_indicator`, about the file, with the indicator as a STIX
//! comparison; a new one is a finding. An indicator that leaves the list retracts its match
//! and leaves the finding as it is. What a kind is not matched against is named in a reading
//! of its own, with no reader for it.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use rusqlite::Connection;
use serde_json::Value;

use crate::store::Lack;

pub const READER: &str = "indicators";
pub const BASIS: &str = "observed";
/// The list's file name next to the store, and the name of its raw copy.
pub const LIST: &str = "indicators.json";
pub const LIST_KIND: &str = "indicator list given as a file";
pub const MATCH_KIND: &str = "indicators matched against watched files and texts read in checkouts";
pub const UNMATCHED_KIND: &str = "indicators against what this build does not match them with";
/// The rule's kind: what a run saw.
pub const MATCHED: &str = "match of an indicator from the list";
/// What this build has no matcher for: a kind of indicator, by its object path.
pub const NO_MATCHER: &str = "indicator kind with no matcher";
/// What a kind of indicator is not matched against, by kind and place.
pub const NOT_AGAINST: &str = "place indicators are not matched against";
/// A list larger than this is not read, as for the threat catalogue.
pub const CAP: u64 = 8 * 1024 * 1024;

pub const SHA256: &str = "file:hashes.'SHA-256'";
pub const DOMAIN: &str = "domain-name:value";
pub const IPV4: &str = "ipv4-addr:value";
pub const URL: &str = "url:value";
/// An IPv4 indicator that is a block of addresses rather than one, which STIX allows.
pub const IPV4_BLOCK: &str = "ipv4-addr:value given as a CIDR block";

/// One indicator of a kind this build matches, its value in the form it is matched in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Indicator {
    pub kind: &'static str,
    pub value: String,
}

impl Indicator {
    /// The indicator as a STIX comparison expression, the object of `matches_indicator`.
    pub fn literal(&self) -> String {
        let quoted = self.value.replace('\\', "\\\\").replace('\'', "\\'");
        format!("[{} = '{quoted}']", self.kind)
    }
}

/// A list as read: the indicators matched, and the kinds kept without a matcher.
#[derive(Debug, Default, PartialEq)]
pub struct List {
    pub matched: BTreeSet<Indicator>,
    pub unmatched: BTreeSet<String>,
    pub entries: usize,
}

/// Reads a list; an error says which entry is out of shape and how, in the program's words.
pub fn parse(bytes: &[u8]) -> Result<List, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let entries = v.as_array().ok_or("not a list of entries")?;
    let mut list = List {
        entries: entries.len(),
        ..List::default()
    };
    for (i, entry) in entries.iter().enumerate() {
        let at = |why: &str| format!("entry {}: {why}", i + 1);
        let fields = entry.as_object().ok_or_else(|| at("not an object"))?;
        if let Some(other) = fields
            .keys()
            .find(|k| !["kind", "value", "note_text"].contains(&k.as_str()))
        {
            return Err(at(&format!(
                "a field other than kind, value and note_text ({} characters)",
                other.len()
            )));
        }
        let text = |name: &str| fields.get(name).and_then(Value::as_str);
        if fields.get("note_text").is_some_and(|n| !n.is_string()) {
            return Err(at("note_text is not text"));
        }
        let (Some(kind), Some(value)) = (text("kind"), text("value")) else {
            return Err(at("kind and value must both be text"));
        };
        match kind {
            SHA256 => list.matched.insert(Indicator {
                kind: SHA256,
                value: sha256(value).ok_or_else(|| at("not 64 hexadecimal digits"))?,
            }),
            DOMAIN => list.matched.insert(Indicator {
                kind: DOMAIN,
                value: domain(value).ok_or_else(|| at("not a domain name in ASCII"))?,
            }),
            IPV4 => match ipv4(value).ok_or_else(|| at("not an IPv4 address or block"))? {
                Some(address) => list.matched.insert(Indicator {
                    kind: IPV4,
                    value: address,
                }),
                None => list.unmatched.insert(IPV4_BLOCK.to_string()),
            },
            URL => list.matched.insert(Indicator {
                kind: URL,
                value: url(value).ok_or_else(|| at("not a URL"))?,
            }),
            other if object_path(other) => list.unmatched.insert(other.to_string()),
            _ => return Err(at("the kind is not a STIX object path")),
        };
    }
    Ok(list)
}

fn sha256(v: &str) -> Option<String> {
    (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_ascii_lowercase())
}

/// A name of at least two labels of letters, digits, `-` and `_`, compared without case. A
/// name outside ASCII must be given in its ASCII form, as DNS carries it.
fn domain(v: &str) -> Option<String> {
    let v = v.strip_suffix('.').unwrap_or(v);
    let labels: Vec<&str> = v.split('.').collect();
    let good = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    (v.len() <= 253 && labels.len() >= 2 && labels.iter().all(good)).then(|| v.to_ascii_lowercase())
}

/// One address, as the standard library reads dotted decimal, or `None` inside for a block.
fn ipv4(v: &str) -> Option<Option<String>> {
    let (address, prefix) = match v.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok().filter(|p| *p <= 32)?)),
        None => (v, None),
    };
    let address: Ipv4Addr = address.parse().ok()?;
    Some((prefix.unwrap_or(32) == 32).then(|| address.to_string()))
}

/// A scheme and something after it, with no space or control character; kept as written.
fn url(v: &str) -> Option<String> {
    let (scheme, rest) = v.split_once(':')?;
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c));
    let ok =
        scheme_ok && !rest.is_empty() && !v.chars().any(|c| c.is_whitespace() || c.is_control());
    ok.then(|| v.to_string())
}

/// `<object type>:<property path>` as STIX writes it.
fn object_path(kind: &str) -> bool {
    let Some((object, path)) = kind.split_once(':') else {
        return false;
    };
    let lower = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    !object.is_empty()
        && object.chars().all(lower)
        && !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.'[]*-".contains(c))
}

/// Watched files whose content is an indicator's hash, as file id and indicator.
pub fn match_hashes(conn: &Connection, list: &List) -> rusqlite::Result<Vec<(String, Indicator)>> {
    let mut out = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject FROM assertion
         WHERE layer = 'live' AND predicate = 'has_content' AND object = ?1",
    )?;
    for i in list.matched.iter().filter(|i| i.kind == SHA256) {
        for subject in stmt.query_map([format!("sha256:{}", i.value)], |r| r.get(0))? {
            out.push((subject?, i.clone()));
        }
    }
    Ok(out)
}

/// The indicators of the network kinds found in one text as exact strings.
pub fn match_text(text: &str, list: &List) -> Vec<Indicator> {
    let lower = text.to_ascii_lowercase();
    list.matched
        .iter()
        .filter(|i| match i.kind {
            DOMAIN => found(&lower, &i.value, domain_char, true),
            IPV4 => found(text, &i.value, |b| b.is_ascii_digit(), true),
            URL => found(text, &i.value, url_char, false),
            _ => false,
        })
        .cloned()
        .collect()
}

fn domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// What goes on inside a URL. A quote, a bracket, a comma or a space ends one, as it does in
/// the files read here.
fn url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~/?#@!$&*+=%:".contains(&b)
}

/// Whether `needle` is in `hay` as a whole: not continued by a character of its kind on
/// either side, a dot followed by one counting as a continuation. A URL is whole on its left
/// whatever precedes it, since its scheme starts it.
fn found(hay: &str, needle: &str, part: fn(u8) -> bool, check_left: bool) -> bool {
    let bytes = hay.as_bytes();
    hay.match_indices(needle).any(|(at, _)| {
        let end = at + needle.len();
        let left = !check_left || at == 0 || !(part(bytes[at - 1]) || bytes[at - 1] == b'.');
        let right = match bytes.get(end) {
            None => true,
            Some(b'.') => !bytes.get(end + 1).is_some_and(|b| part(*b)),
            Some(b) => !part(*b),
        };
        left && right
    })
}

/// What the kinds in a list are not matched against, by name.
pub fn lacks(list: &List) -> Vec<Lack> {
    let mut out: Vec<Lack> = list
        .unmatched
        .iter()
        .map(|k| Lack::new(NO_MATCHER, Some(k)))
        .collect();
    // An address is matched against the connections a sample sees, `processes.rs`; a name or
    // a URL is not, since a sample has addresses and no name is resolved.
    let kinds: BTreeSet<&str> = list
        .matched
        .iter()
        .map(|i| i.kind)
        .filter(|k| *k != IPV4)
        .collect();
    for kind in kinds {
        let place = if kind == SHA256 {
            "files of checkouts and installed software other than watched files"
        } else {
            "connections"
        };
        out.push(Lack::new(
            NOT_AGAINST,
            Some(&format!("{kind} against {place}")),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &str) -> List {
        parse(entries.as_bytes()).unwrap()
    }

    #[test]
    fn a_list_of_stix_kinds_is_read_with_values_in_the_form_they_are_matched_in() {
        let l = list(
            r#"[
              {"kind": "file:hashes.'SHA-256'", "value": "AA00000000000000000000000000000000000000000000000000000000000000", "note_text": "loader"},
              {"kind": "domain-name:value", "value": "Evil.Example."},
              {"kind": "ipv4-addr:value", "value": "198.51.100.7/32"},
              {"kind": "ipv4-addr:value", "value": "198.51.100.0/24"},
              {"kind": "url:value", "value": "https://evil.example/x?a=1"},
              {"kind": "file:name", "value": "loader.js"}
            ]"#,
        );
        assert_eq!(l.entries, 6);
        let values: Vec<&str> = l.matched.iter().map(|i| i.value.as_str()).collect();
        assert!(
            values.contains(&"aa00000000000000000000000000000000000000000000000000000000000000")
        );
        assert!(values.contains(&"evil.example"));
        assert!(values.contains(&"198.51.100.7"));
        assert!(values.contains(&"https://evil.example/x?a=1"));
        assert_eq!(
            l.unmatched.iter().collect::<Vec<_>>(),
            ["file:name", IPV4_BLOCK]
        );
    }

    #[test]
    fn a_list_out_of_shape_fails_as_a_whole_and_says_which_entry() {
        for bad in [
            "{}",
            "[1]",
            r#"[{"kind": "domain-name:value"}]"#,
            r#"[{"kind": "domain-name:value", "value": "nodot"}]"#,
            r#"[{"kind": "file:hashes.'SHA-256'", "value": "abc"}]"#,
            r#"[{"kind": "ipv4-addr:value", "value": "300.1.1.1"}]"#,
            r#"[{"kind": "url:value", "value": "no scheme here"}]"#,
            r#"[{"kind": "url:value", "value": "://evil.example"}]"#,
            r#"[{"kind": "url:value", "value": "https://evil.example/a b"}]"#,
            r#"[{"kind": "ipv4-addr:value", "value": "10.0.0.0/33"}]"#,
            r#"[{"kind": "file:hashes.'SHA-256'", "value": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}]"#,
            r#"[{"kind": "Domain Name", "value": "evil.example"}]"#,
            r#"[{"kind": "domain-name:value", "value": "evil.example", "note": "x"}]"#,
            r#"[{"kind": "domain-name:value", "value": "evil.example", "note_text": 1}]"#,
        ] {
            let e = parse(bad.as_bytes()).unwrap_err();
            assert!(
                e.starts_with("entry 1") || !bad.starts_with("[{"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn a_network_indicator_matches_only_as_a_whole_string() {
        let l = list(
            r#"[{"kind": "domain-name:value", "value": "evil.example"},
                {"kind": "ipv4-addr:value", "value": "10.0.0.1"},
                {"kind": "url:value", "value": "https://cdn.example/a.js"}]"#,
        );
        let kinds = |t: &str| -> Vec<&str> { match_text(t, &l).iter().map(|i| i.kind).collect() };
        assert_eq!(
            kinds(r#""resolved": "https://EVIL.example/x.tgz""#),
            [DOMAIN]
        );
        assert_eq!(kinds("evil.example."), [DOMAIN]);
        assert!(
            kinds("notevil.example sub.evil.example evil.example.org evil.examples").is_empty()
        );
        assert_eq!(kinds("curl 10.0.0.1:80"), [IPV4]);
        assert!(kinds("110.0.0.1 10.0.0.10 10.0.0.1.5").is_empty());
        assert_eq!(kinds("fetch('https://cdn.example/a.js')"), [URL]);
        assert!(kinds("https://cdn.example/a.json https://CDN.example/a.js").is_empty());
        assert!(kinds("https://cdn.example/a.js/b x-evil.example 1evil.example").is_empty());
        // A URL starts with its scheme, whatever is before it.
        assert_eq!(kinds("/login?next=https://cdn.example/a.js"), [URL]);
    }

    #[test]
    fn an_indicator_is_written_as_a_stix_comparison_with_its_quotes_escaped() {
        let i = Indicator {
            kind: URL,
            value: "https://x.example/a'b\\c".to_string(),
        };
        assert_eq!(i.literal(), r"[url:value = 'https://x.example/a\'b\\c']");
    }
}
