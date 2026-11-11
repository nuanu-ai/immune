//! JSON with comments, as editors and some coding agents read their settings, read with the
//! `jsonc-parser` crate (dprint). Its tree keeps every property of an object in order, so two
//! equal keys are both seen: what a reader that keeps the last sees is the value here, and
//! where an earlier equal key held something else is said apart, as a doubt. Nothing is
//! stripped by hand.
//!
//! Only comments and, where the tool takes them, trailing commas are allowed: every other
//! extension the crate offers (single quotes, unquoted keys, hexadecimal and other loose
//! numbers, JSON5 escapes, missing commas) is off. VS Code's reader takes none of them, nor
//! does `JSON.parse` after comments are stripped, so a file using one is not read here,
//! never read differently. Where the crate is narrower than a tool (a lone surrogate escape,
//! which `JSON.parse` takes), the file is not read either.

use jsonc_parser::ast;
use jsonc_parser::{CollectOptions, ParseOptions};
use serde_json::Value;

/// What a file says, as a reader that keeps the last of two equal keys reads it.
pub struct Read {
    /// `None` for a file of comments only, or empty.
    pub value: Option<Value>,
    /// JSON pointers where an earlier equal key held another value than the last.
    pub doubts: Vec<String>,
}

/// Reads JSON with comments, with trailing commas when `commas`; else the crate's reason, which
/// says where it stopped and quotes nothing of the file.
pub fn read(bytes: &[u8], commas: bool) -> Result<Read, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    let options = ParseOptions {
        allow_comments: true,
        allow_trailing_commas: commas,
        allow_loose_object_property_names: false,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
        allow_bare_decimal_point_numbers: false,
        allow_non_finite_numbers: false,
        allow_extended_string_escapes: false,
    };
    let parsed = jsonc_parser::parse_to_ast(text, &CollectOptions::default(), &options)
        .map_err(|e| e.to_string())?;
    let mut doubts = Vec::new();
    let value = match parsed.value {
        Some(v) => Some(convert(&v, "", &mut doubts)?),
        None => None,
    };
    Ok(Read { value, doubts })
}

fn convert(v: &ast::Value, at: &str, doubts: &mut Vec<String>) -> Result<Value, String> {
    Ok(match v {
        ast::Value::StringLit(s) => Value::String(s.value.to_string()),
        ast::Value::NumberLit(n) => serde_json::from_str(n.value)
            .map_err(|_| format!("a number serde_json does not read at {at}"))?,
        ast::Value::BooleanLit(b) => Value::Bool(b.value),
        ast::Value::NullKeyword(_) => Value::Null,
        ast::Value::Array(a) => Value::Array(
            a.elements
                .iter()
                .enumerate()
                .map(|(i, e)| convert(e, &format!("{at}/{i}"), doubts))
                .collect::<Result<_, _>>()?,
        ),
        ast::Value::Object(o) => {
            let mut map = serde_json::Map::new();
            for p in &o.properties {
                let name = p.name.as_str().to_string();
                let here = format!("{at}/{}", name.replace('~', "~0").replace('/', "~1"));
                let value = convert(&p.value, &here, doubts)?;
                if let Some(before) = map.insert(name, value.clone())
                    && before != value
                    && !doubts.contains(&here)
                {
                    doubts.push(here);
                }
            }
            Value::Object(map)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_equal_keys_are_both_seen_and_the_last_is_the_value() {
        // The tree keeps both, in order: a reader that keeps the last reads "b", and that an
        // earlier one said "a" is a doubt at its key. Equal keys with equal values are none.
        let r = read(br#"{"x": {"k": "a", "k": "b"}, "y": 1, "y": 1}"#, true).unwrap();
        assert_eq!(r.value, Some(serde_json::json!({"x": {"k": "b"}, "y": 1})));
        assert_eq!(r.doubts, ["/x/k"]);
        // An escaped key is the same key.
        let r = read(br#"{"k": 1, "\u006b": 2}"#, true).unwrap();
        assert_eq!(r.doubts, ["/k"]);
    }

    #[test]
    fn comments_and_trailing_commas_are_read_as_vs_code_reads_them_and_nothing_wider() {
        let file = b"{\n  // a comment\n  \"a\": \"http://x/*y*/\", /* block */\n  \"b\": [1, 2.5, true, null,],\n}";
        let r = read(file, true).unwrap();
        assert_eq!(
            r.value,
            Some(serde_json::json!({"a": "http://x/*y*/", "b": [1, 2.5, true, null]}))
        );
        // Gemini CLI strips comments and then parses strictly: no trailing comma.
        assert!(read(file, false).is_err());
        assert!(read(b"{\"a\": 1} // only a comment after", false).is_ok());
        // What JSON5 adds and VS Code does not take is refused, saying where.
        for wider in [
            &b"{'a': 1}"[..],
            b"{a: 1}",
            b"{\"a\": 0x1F}",
            b"{\"a\": +1}",
            b"{\"a\": .5}",
            b"{\"a\": Infinity}",
            b"{\"a\": \"\\x41\"}",
            b"{\"a\": 1 \"b\": 2}",
        ] {
            let e = read(wider, true).err().unwrap_or_default();
            assert!(
                e.contains("line 1"),
                "{}: {e}",
                String::from_utf8_lossy(wider)
            );
        }
        // Wider than JSON: a raw line break in a string, which VS Code's reader flags and
        // still reads. Narrower: a lone surrogate escape, which `JSON.parse` takes.
        assert!(read(b"{\"a\": \"x\ny\"}", true).is_ok());
        assert!(read(b"{\"a\": \"\\ud800\"}", true).is_err());
        // Comments only, or nothing, say nothing.
        assert_eq!(read(b"// nothing yet\n", true).unwrap().value, None);
        assert_eq!(read(b"", true).unwrap().value, None);
    }
}
