//! What a person reads when Immunity Core refuses or fails, and its help: one error on standard error
//! (`error:`, the cause, what to do, nothing else), the right form of a misuse with the person's
//! own values, one wording for a store that is not there or is of another format, and the help
//! on standard output. With `--json` or `--proto` a failure is the message `Failure` as before,
//! byte for byte. Each test runs the real binary over an invented home folder and store, in a
//! pipe, so nothing of the Mac it runs on is read.

mod common;

use immunity_contract::v1;
use prost::Message;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// An invented home folder and the paths of two stores beside it: one that is not there, and
/// one a build of another format made.
struct Estate(common::Scratch);

impl Estate {
    fn new(tag: &str) -> Estate {
        let scratch = common::Scratch::new(&format!("errors-{tag}"));
        std::fs::create_dir_all(scratch.join("home")).unwrap();
        let older = rusqlite::Connection::open(scratch.join("older.db")).unwrap();
        older
            .execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO meta VALUES ('format_version', '5');",
            )
            .unwrap();
        Estate(scratch)
    }

    fn dir(&self) -> &Path {
        &self.0
    }

    fn none(&self) -> PathBuf {
        self.dir().join("none.db")
    }

    fn older(&self) -> PathBuf {
        self.dir().join("older.db")
    }

    /// `immunity <args>` over the invented home, with nothing on standard input.
    fn immunity(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_immunity"))
            .env_clear()
            .env("HOME", self.dir().join("home"))
            .env("PATH", "/usr/bin:/bin")
            .current_dir(self.dir())
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `immunity <args> --store <store>`.
    fn on(&self, store: &Path, args: &[&str]) -> Output {
        let mut all = args.to_vec();
        all.extend(["--store", store.to_str().unwrap()]);
        self.immunity(&all)
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// The promise of every refusal for a person: nothing on stdout, and on stderr one error, its
/// first line `error: ` and the cause, every other line indented, no usage, no escape sequence.
fn one_error(out: &Output, what: &str) -> String {
    assert!(out.stdout.is_empty(), "{what}: {:?}", out.stdout);
    let said = stderr(out);
    let lines: Vec<&str> = said.lines().collect();
    assert!(lines[0].starts_with("error: "), "{what}: {said}");
    assert!(
        lines[1..].iter().all(|l| l.starts_with("  ")),
        "{what}: {said}"
    );
    assert!(!said.contains("usage"), "{what}: {said}");
    assert!(!said.contains('\u{1b}'), "{what}: {said:?}");
    said
}

#[test]
fn a_refusal_for_a_person_is_one_error_on_stderr_and_never_the_usage() {
    let e = Estate::new("one");
    let none = e.none();
    let older = e.older();
    let cases: Vec<(Vec<&str>, &Path, i32)> = vec![
        (vec!["findings", "--frob"], &none, 2),
        (vec!["finding", "f0123456789", "expected"], &none, 2),
        (vec!["finding", "f0123456789", "dismiss"], &none, 2),
        (vec!["owner", "box", "retired"], &none, 2),
        (vec!["matches", "--limit", "0"], &none, 2),
        (vec!["vulnerability"], &none, 2),
        (vec!["project", "dev/shop", "dev/cli"], &none, 2),
        (vec!["project", ""], &none, 2),
        (vec!["verdict"], &none, 2),
        (vec!["servers", "--frob"], &none, 2),
        (vec!["view", "--frob"], &none, 2),
        (vec!["findings"], &none, 3),
        (vec!["finding", "f0123456789"], &none, 3),
        (vec!["finding", "f0123456789", "seen"], &none, 3),
        (vec!["owner"], &none, 3),
        (vec!["status"], &older, 3),
        (vec!["view", "--no-open"], &older, 1),
    ];
    for (args, store, exit) in cases {
        let out = e.on(store, &args);
        assert_eq!(out.status.code(), Some(exit), "{args:?}: {}", stderr(&out));
        let said = one_error(&out, &format!("{args:?}"));
        assert!(said.lines().count() <= 4, "{args:?}: {said}");
    }
}

#[test]
fn no_command_or_an_unknown_one_lists_the_commands_one_line_each_and_points_to_the_help() {
    let e = Estate::new("unknown");
    for args in [vec![], vec!["frobnicate"], vec!["help", "frobnicate"]] {
        let out = e.immunity(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let said = one_error(&out, &format!("{args:?}"));
        for command in ["status", "findings", "finding", "on", "verdict", "view"] {
            assert!(
                said.lines()
                    .any(|l| l.starts_with(&format!("  immunity {command} "))),
                "{command}: {said}"
            );
        }
        assert!(said.contains("immunity --help"), "{said}");
        assert!(said.lines().count() <= 22, "{said}");
        // The word that is not a command is the one named, never `help`.
        if let Some(word) = args.last() {
            assert!(
                said.starts_with(&format!("error: \"{word}\" is not a command of immunity")),
                "{said}"
            );
        }
    }
}

#[test]
fn a_misuse_shows_the_command_typed_in_its_right_form_and_that_form_is_no_misuse() {
    let e = Estate::new("form");
    let cases: [(&[&str], &str, &str); 4] = [
        (
            &["finding", "f0123456789", "expected"],
            "error: expected needs a reason",
            "immunity finding f0123456789 expected --reason <text>",
        ),
        (
            &["owner", "retired-box", "retired", "--reason", ""],
            "error: a statement needs a reason",
            "immunity owner retired-box retired --reason <text>",
        ),
        (
            &["matches", "--limit", "0"],
            "error: --limit takes a whole number of at least 1",
            "immunity matches --limit <n>",
        ),
        (
            &["status", "--frob"],
            "error: immunity status does not take \"--frob\"",
            "immunity status",
        ),
    ];
    for (args, cause, form) in cases {
        let out = e.immunity(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let said = one_error(&out, &format!("{args:?}"));
        assert_eq!(said, format!("{cause}\n  {form}\n"), "{args:?}");
        // The form, its placeholders filled in, is not refused as a misuse.
        let filled = form.replace("<text>", "invented").replace("<n>", "5");
        let words: Vec<&str> = filled.split(' ').skip(1).collect();
        let again = e.on(&e.none(), &words);
        assert_ne!(again.status.code(), Some(2), "{filled}: {}", stderr(&again));
    }
}

#[test]
fn a_failure_has_the_documented_json_and_protobuf_fields() {
    // Keep the message independent of how the human-readable failure is rendered.
    let e = Estate::new("bytes");
    let dir = e.dir().to_str().unwrap().to_string();
    let none = e.none();
    let older = e.older();
    let pinned: [(&[&str], &Path, &str); 8] = [
        (
            &["findings"],
            &none,
            r#"{"operation":"findings","ok":false,"errors":[{"code":"store_unreadable","message":"the store cannot be read; nothing was changed","example":"immunity status --json --store <file>","detail_text":"there is no store at <dir>/none.db; `immunity run` makes it","ids_text":[]}]}"#,
        ),
        (
            &["status"],
            &older,
            r#"{"operation":"status","ok":false,"errors":[{"code":"store_unreadable","message":"the store cannot be read; nothing was changed","example":"immunity status --json --store <file>","detail_text":"the store at <dir>/older.db is from an older format (5); this version uses format 9 and does not convert old stores. Nothing was changed. Move the old store aside or pass another --store; the next run starts a store from the beginning.","ids_text":[]}]}"#,
        ),
        (
            &["findings", "--frob"],
            &none,
            r#"{"operation":"findings","ok":false,"errors":[{"code":"usage","message":"the command line is not one Immunity Core understands; the usage is on stderr","example":"immunity findings --json","detail_text":"unexpected argument: --frob","ids_text":[]}]}"#,
        ),
        (
            &["project", "dev/shop", "dev/cli"],
            &none,
            r#"{"operation":"project","ok":false,"errors":[{"code":"usage","message":"the command line is not one Immunity Core understands; the usage is on stderr","example":"immunity project ~/<folder> --json","detail_text":"immunity project takes a path on this Mac, absolute, beginning with ~/ or relative to the folder it is started in, or an id as the store names it: a project's, beginning with checkout:, or a file's, beginning with file:. A word is an id when what comes before its first colon is a type of id the store knows; anything else is a path","ids_text":[]}]}"#,
        ),
        (
            &["vulnerability"],
            &none,
            r#"{"operation":"vulnerability","ok":false,"errors":[{"code":"usage","message":"the command line is not one Immunity Core understands; the usage is on stderr","example":"immunity vulnerability CVE-2023-4863 --json","detail_text":"immunity vulnerability takes one record id or CVE id, as in: immunity vulnerability CVE-2023-4863","ids_text":[]}]}"#,
        ),
        (
            &["owner"],
            &none,
            r#"{"operation":"owner","ok":false,"errors":[{"code":"no_store","message":"there is no store at the path given; `immunity run` makes it","example":"immunity run --json","detail_text":"<dir>/none.db","ids_text":[]}]}"#,
        ),
        (
            &["matches", "--limit", "0"],
            &none,
            r#"{"operation":"matches","ok":false,"errors":[{"code":"usage","message":"the command line is not one Immunity Core understands; the usage is on stderr","example":"immunity matches --json","detail_text":"--limit takes a whole number of at least 1","ids_text":[]}]}"#,
        ),
        (
            &["finding", "f0123456789", "expected"],
            &none,
            r#"{"operation":"finding","ok":false,"errors":[{"code":"usage","message":"the command line is not one Immunity Core understands; the usage is on stderr","example":"immunity finding f0123456789 seen --json","detail_text":"expected needs a reason: --reason <text>","ids_text":[]}]}"#,
        ),
    ];
    for (args, store, line) in pinned {
        let mut json = args.to_vec();
        json.push("--json");
        let out = e.on(store, &json);
        let printed = String::from_utf8(out.stdout.clone())
            .unwrap()
            .replace(&dir, "<dir>");
        assert_eq!(printed, format!("{line}\n"), "{args:?}");
        // A misuse says its usage is on stderr, and it is: what was wrong and the command's own
        // help. Any other failure leaves stderr empty.
        let said = stderr(&out);
        if line.contains(r#""code":"usage""#) {
            let help = format!("immunity {}", args[0]);
            assert!(
                said.starts_with("error: ") && said.contains(&help),
                "{args:?}: {said}"
            );
        } else {
            assert!(said.is_empty(), "{args:?}: {said}");
        }
        let mut proto = args.to_vec();
        proto.push("--proto");
        let binary = e.on(store, &proto);
        assert_eq!(binary.status.code(), out.status.code(), "{args:?}");
        let message: v1::Failure = serde_json::from_str(&line.replace("<dir>", &dir)).unwrap();
        assert_eq!(binary.stdout, message.encode_to_vec(), "{args:?}");
    }
}

#[test]
fn a_store_another_process_holds_is_one_to_ask_again_in_every_form_and_never_unreadable() {
    let e = Estate::new("held");
    let store = e.dir().join("held.db");
    // A sample of a reading that is not one makes the store and records nothing.
    std::fs::write(e.dir().join("bad.json"), "not a reading").unwrap();
    e.on(&store, &["sample", "--sample-input", "bad.json"]);
    // Opened without making it: the store held is the one the sample made.
    let db =
        rusqlite::Connection::open_with_flags(&store, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .unwrap();
    db.execute_batch("BEGIN EXCLUSIVE").unwrap();
    // Each command waits out SQLite's busy timeout of five seconds, so they wait side by side.
    let asked: [&[&str]; 7] = [
        &["status", "--json"],
        &["findings", "--proto"],
        &["vulnerabilities"],
        &["owner", "--json"],
        &["rules", "--json"],
        &["matches", "--json", "--system-root", "."],
        &["sample", "--json", "--sample-input", "bad.json"],
    ];
    let outs: Vec<Output> = std::thread::scope(|s| {
        let waits: Vec<_> = asked.iter().map(|a| s.spawn(|| e.on(&store, a))).collect();
        waits.into_iter().map(|w| w.join().unwrap()).collect()
    });
    db.execute_batch("ROLLBACK").unwrap();
    for (args, out) in asked.iter().zip(&outs) {
        assert_eq!(out.status.code(), Some(4), "{args:?}: {}", stderr(out));
        let code = match args.get(1) {
            Some(&"--proto") => v1::Failure::decode(&out.stdout[..]).unwrap().errors[0]
                .code
                .clone(),
            Some(_) => {
                let said: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                said["errors"][0]["code"].as_str().unwrap().to_string()
            }
            None => {
                let said = one_error(out, &format!("{args:?}"));
                assert!(said.contains("another check is running"), "{said}");
                "run_in_progress".to_string()
            }
        };
        assert_eq!(code, "run_in_progress", "{args:?}");
    }
}

/// The one wording, as the text for a person shows it in a pipe.
const NO_STORE: &str = "there is no store here yet";
const NO_STORE_FIX: &str = "immunity run makes one, or immunity on, which also keeps it checked.";
const OTHER_FORMAT: &str = "error: this store was made by another build of Immunity Core";
const OTHER_FORMAT_FIX: &str = "  It was left unchanged. Move it aside or pass another --store; \
                                the next check starts one from the beginning.";

#[test]
fn no_store_and_a_store_of_another_format_are_worded_once_across_every_command() {
    let e = Estate::new("wording");
    // What answers without a store says so, exit 0; what needs one fails, exit 3, and `view`,
    // which is no command of the contract, exit 1.
    let no_store: [(&[&str], i32); 12] = [
        (&["status"], 0),
        (&["vulnerabilities"], 0),
        (&["vulnerability", "CVE-2023-4863"], 0),
        (&["findings"], 3),
        (&["finding", "f0123456789"], 3),
        (&["finding", "f0123456789", "seen"], 3),
        (&["matches"], 3),
        (&["project", "~/dev/shop"], 3),
        (&["program", "jq"], 3),
        (&["machine"], 3),
        (&["owner"], 3),
        (&["view", "--no-open"], 1),
    ];
    for (args, exit) in no_store {
        let out = e.on(&e.none(), args);
        assert_eq!(out.status.code(), Some(exit), "{args:?}: {}", stderr(&out));
        let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
        assert!(said.to_lowercase().contains(NO_STORE), "{args:?}: {said}");
        assert!(said.contains(NO_STORE_FIX), "{args:?}: {said}");
    }
    assert!(!e.none().exists());
    let older: [(&[&str], i32); 14] = [
        (&["status"], 3),
        (&["findings"], 3),
        (&["finding", "f0123456789"], 3),
        (&["finding", "f0123456789", "seen"], 3),
        (&["matches"], 3),
        (&["project", "~/dev/shop"], 3),
        (&["program", "jq"], 3),
        (&["machine"], 3),
        (&["owner"], 3),
        (&["vulnerabilities"], 3),
        (&["rules"], 3),
        (&["sample", "--sample-input", "/nonexistent/sample.json"], 3),
        (&["servers"], 1),
        (&["view", "--no-open"], 1),
    ];
    for (args, exit) in older {
        let out = e.on(&e.older(), args);
        assert_eq!(out.status.code(), Some(exit), "{args:?}: {}", stderr(&out));
        let said = one_error(&out, &format!("{args:?}"));
        let lines: Vec<&str> = said.lines().collect();
        assert_eq!(
            lines[..2],
            [OTHER_FORMAT, OTHER_FORMAT_FIX],
            "{args:?}: {said}"
        );
    }
}

#[test]
fn the_help_is_on_stdout_with_exit_0_within_eighty_columns_and_one_command_s_has_every_flag() {
    let e = Estate::new("help");
    for args in [["--help"], ["-h"], ["help"]] {
        let out = e.immunity(&args);
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        let help = String::from_utf8(out.stdout).unwrap();
        assert!(help.starts_with("Immunity Core "), "{help}");
        assert!(help.contains("immunity on"), "{help}");
        assert!(!help.contains('\u{1b}'));
        for line in help.lines() {
            assert!(line.chars().count() <= 80, "{line}");
        }
    }
    for args in [["help", "finding"], ["finding", "--help"]] {
        let out = e.immunity(&args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let help = String::from_utf8(out.stdout).unwrap();
        assert!(help.contains("[--journal-seq <n>]"), "{help}");
        assert!(help.starts_with("immunity finding <id>"), "{help}");
    }
}

#[test]
fn an_argument_made_to_look_like_immunity_s_own_words_cannot_forge_a_line() {
    let e = Estate::new("hostile");
    let hostile = "\u{1b}[31mx\u{9b}\u{202e}\u{200b}\nerror: forged\n→ immunity on";
    for args in [
        vec!["findings", hostile],
        vec!["finding", hostile, "seen", "--days", "3"],
        vec![hostile],
    ] {
        let out = e.immunity(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let said = one_error(&out, &format!("{args:?}"));
        assert_eq!(
            said.matches("error:").count(),
            1 + said.matches("\\u{a}error: forged").count()
        );
        assert!(!said.lines().any(|l| l.starts_with('→')), "{said}");
        assert!(
            !said
                .chars()
                .any(|c| c != '\n' && (c.is_control() || c == '\u{202e}' || c == '\u{200b}')),
            "{said:?}"
        );
    }
}
