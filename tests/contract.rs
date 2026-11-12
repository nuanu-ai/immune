//! The contract's types are what its schema gives. The schema in `contract/immune/v1/` is the
//! source; `src/contract/immune.v1.rs` is generated from it and committed, so that building the
//! program needs no generator. This test generates it again, with `protox` in place of `protoc`
//! and `prost-build`, and fails when the committed file differs.
//!
//! To regenerate after changing the schema: `IMMUNE_WRITE_CONTRACT=1 cargo test --test contract`.

#[path = "../src/contract.rs"]
#[allow(dead_code)]
mod contract;

use contract::v1;
use prost_types::field_descriptor_proto::{Label, Type};
use std::path::Path;

/// The schema's files, relative to `contract/`.
const SCHEMA: [&str; 2] = ["immune/v1/known.proto", "immune/v1/matches.proto"];
/// The generated file, relative to the crate.
const GENERATED: &str = "src/contract/immune.v1.rs";

/// What heads the generated file, before what prost-build writes.
const HEADER: &str =
    "// @generated from contract/immune/v1/*.proto by prost-build, with the serde attributes that
// tests/contract.rs gives it. Do not edit: the test `the_committed_types_are_what_the_schema_gives`
// generates it again and fails when this file differs. To regenerate:
// IMMUNE_WRITE_CONTRACT=1 cargo test --test contract
";

/// An enum's name as the prefix of its values: `FindingState` is `FINDING_STATE`.
fn screaming(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// The generated Rust for the schema as it stands.
fn generate() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fds = protox::compile(SCHEMA, [root.join("contract")]).expect("the schema compiles");
    let mut config = prost_build::Config::new();
    // Every message and enum derives serde; a message's missing field takes its default, as a
    // missing field does in protobuf.
    config.message_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.message_attribute(".", "#[serde(default)]");
    config.enum_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    for file in &fds.file {
        let package = format!(".{}", file.package());
        for e in &file.enum_type {
            // A value is named in the schema with its enum's name as a prefix, as protobuf's
            // style asks; in JSON it is the rest of the name in lower case, the store's word.
            let prefix = format!("{}_", screaming(e.name()));
            for v in &e.value {
                let word = v.name().strip_prefix(&prefix).unwrap_or_else(|| {
                    panic!(
                        "{}: a value of {} must begin with {prefix}",
                        v.name(),
                        e.name()
                    )
                });
                config.field_attribute(
                    format!("{package}.{}.{}", e.name(), v.name()),
                    format!("#[serde(rename = \"{}\")]", word.to_lowercase()),
                );
            }
        }
        for m in &file.message_type {
            assert!(
                m.nested_type.is_empty() && m.enum_type.is_empty(),
                "{}: the generator configures top-level messages and enums",
                m.name()
            );
            // A one-of prints as an object with one key, the name of its case that is set:
            // `{"program_start": {...}}`. prost keeps it as an enum in a field of its own name,
            // which serde flattens into the message. A case it does not know reads as none. A
            // proto3 `optional` field is a one-of of its own in the descriptor and is left as it
            // is.
            for (i, o) in m.oneof_decl.iter().enumerate() {
                let cases: Vec<_> = m
                    .field
                    .iter()
                    .filter(|f| f.oneof_index == Some(i as i32) && !f.proto3_optional())
                    .collect();
                if cases.is_empty() {
                    continue;
                }
                assert!(
                    cases.iter().all(|f| f.r#type() == Type::Message),
                    "{}.{}: a case of a one-of is a message, so it needs no JSON helper",
                    m.name(),
                    o.name()
                );
                let path = format!("{package}.{}.{}", m.name(), o.name());
                // A path with a leading dot also matches every case of the one-of, as a prefix;
                // without it, it matches the one-of's own field and nothing below it.
                config.field_attribute(&path[1..], "#[serde(flatten)]");
                config.enum_attribute(&path, "#[serde(rename_all = \"snake_case\")]");
            }
            for f in m.field.iter().filter(|f| f.r#type() == Type::Enum) {
                // An enum field is an i32 in prost; it prints as its value's name.
                let rust = f.type_name().rsplit('.').next().unwrap();
                let (ser, de) = if f.proto3_optional() {
                    ("optional_enum_name", "optional_enum_from_name")
                } else {
                    assert!(
                        f.label() != Label::Repeated,
                        "{}.{}: a repeated enum field has no JSON helper",
                        m.name(),
                        f.name()
                    );
                    ("enum_name", "enum_from_name")
                };
                config.field_attribute(
                    format!("{package}.{}.{}", m.name(), f.name()),
                    format!(
                        "#[serde(serialize_with = \"crate::contract::{ser}::<{rust}, _>\", \
                         deserialize_with = \"crate::contract::{de}::<{rust}, _>\")]"
                    ),
                );
            }
        }
    }
    let out = std::env::temp_dir().join(format!(
        "immune-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&out).unwrap();
    config.out_dir(&out);
    config
        .compile_fds(fds)
        .expect("prost-build generates the types");
    let code = std::fs::read_to_string(out.join("immune.v1.rs")).unwrap();
    std::fs::remove_dir_all(&out).unwrap();
    format!("{HEADER}{code}")
}

/// The contract's promise that its types cannot drift from its schema: the committed file is
/// exactly what the schema gives.
#[test]
fn the_committed_types_are_what_the_schema_gives() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GENERATED);
    let fresh = generate();
    if std::env::var_os("IMMUNE_WRITE_CONTRACT").is_some() {
        std::fs::write(&path, &fresh).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == fresh,
        "{GENERATED} is not what the schema gives; regenerate it: IMMUNE_WRITE_CONTRACT=1 cargo test --test contract"
    );
}

/// An enum in the JSON is the name of its value and never a number: a number that names no
/// value is refused, not printed.
#[test]
fn an_enum_prints_as_its_name_and_never_as_a_number() {
    let known = v1::Known {
        presence: v1::Presence::Held as i32,
        ..Default::default()
    };
    let json = serde_json::to_value(&known).unwrap();
    assert_eq!(json["presence"], "held");
    let unnamed = v1::Known {
        presence: 99,
        ..Default::default()
    };
    assert!(serde_json::to_string(&unnamed).is_err());
}
