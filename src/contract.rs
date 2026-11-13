//! The contract with a program that runs the core. Its types, generated from the schema in
//! `contract/immune/v1/`, are the crate `immune-contract` (`contract/`), which the response layer
//! depends on too; they are re-exported here, so the core names them as `contract::v1`. What is
//! the core's own is here: how text from a source is shown in the contract and read back.

pub use immune_contract::{v1, value_of};

/// Text from a source as the contract gives it: each character `hidden` names, and the
/// backslash itself, written as `\u{...}`. Escaping the backslash makes the shown form unique:
/// a name holding a hidden character and a name that spells its escape out are shown apart, and
/// `unescape` gives back exactly what was escaped. `hidden` is the core's own test of a character
/// that could hide or rearrange what is shown (`icu::hidden`); it is passed in so that this file
/// needs nothing else of the core.
pub fn escape(s: &str, hidden: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || hidden(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// Text as `escape` shows it, back as it was: every `\u{...}` that names a character becomes
/// that character, and anything else is kept as written. An id the core printed asks back the
/// same thing.
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("\\u{") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 3..];
        // Hex digits alone: `from_str_radix` would also take a sign.
        let named = after.split_once('}').and_then(|(hex, tail)| {
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit())
                .then(|| u32::from_str_radix(hex, 16).ok().and_then(char::from_u32))
                .flatten()
                .map(|c| (c, tail))
        });
        match named {
            Some((c, tail)) => {
                out.push(c);
                rest = tail;
            }
            None => {
                out.push('\\');
                rest = &rest[at + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}
