//! The one rule of forms for the seven commands of the contract, and their one form of failure.
//!
//! A command of the contract answers with one message of the schema, in three projections:
//! `--proto` prints it as binary protobuf, `--json` as one line of JSON, and with neither it is
//! text for a person, rendered from that message alone (`text.rs`). A person, an agent and a
//! program are given the same thing.
//!
//! A failure is the message `Failure` in the same three projections, except that for a person it
//! is on stderr and nothing is on stdout. Its exit code says which kind of failure it is, and a
//! reader checks it first. Every failure of the seven commands goes through `fail`.

use crate::contract::v1;
use crate::{EXIT_RUN_IN_PROGRESS, EXIT_STORE, Stop, known, text};
use prost::Message;
use std::io::Write;
use std::process::ExitCode;

/// The form a command of the contract answers in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// Text for a person, rendered from the message: what is printed when no form is named.
    Text,
    /// The message as one line of JSON, `--json`.
    Json,
    /// The message as binary protobuf, `--proto`.
    Proto,
}

/// The options every command of the contract accepts, including those read on a bad command line.
#[derive(Default)]
pub struct Options {
    store: Option<std::path::PathBuf>,
    named: Option<Form>,
}

impl Options {
    /// The command-specific parser consumes its own operands. Keep reading after the first
    /// error so a later form still applies, but never take an operand for a flag.
    pub fn read<I: Iterator<Item = String>>(
        &mut self,
        mut it: I,
        mut other: impl FnMut(String, &mut I) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut error = None;
        while let Some(arg) = it.next() {
            let result = match arg.as_str() {
                "--store" => {
                    crate::value(&mut it, &arg).map(|value| self.store = Some(value.into()))
                }
                "--json" => self.name(Form::Json),
                "--proto" => self.name(Form::Proto),
                _ => other(arg, &mut it),
            };
            if let Err(e) = result {
                error.get_or_insert(e);
            }
        }
        error.map_or(Ok(()), Err)
    }

    fn name(&mut self, form: Form) -> Result<(), String> {
        if self.named.is_some_and(|named| named != form) {
            // A failure naming both forms is given as JSON in either order.
            self.named = Some(Form::Json);
            Err("--json and --proto each name the form of the answer; give one".to_string())
        } else {
            self.named = Some(form);
            Ok(())
        }
    }

    pub fn form(&self) -> Form {
        self.named.unwrap_or(Form::Text)
    }

    pub fn store(&self) -> Result<std::path::PathBuf, String> {
        self.store.clone().map_or_else(crate::default_store, Ok)
    }
}

/// One reason a command did not answer. `detail` is what the failure quotes, escaped one to one
/// and given whole; empty when it quotes nothing.
pub fn error(code: &str, message: &str, example: &str, detail: &str) -> v1::Error {
    v1::Error {
        code: code.to_string(),
        message: message.to_string(),
        example: (!example.is_empty()).then(|| example.to_string()),
        detail_text: (!detail.is_empty()).then(|| known::whole(detail)),
        ids_text: Vec::new(),
    }
}

/// A store that cannot be read, or that another run holds, with its exit code.
pub fn stopped(e: &Stop, example: &str) -> (v1::Error, u8) {
    match e {
        Stop::Store(detail) => (
            error(
                "store_unreadable",
                "the store cannot be read; nothing was changed",
                example,
                detail,
            ),
            EXIT_STORE,
        ),
        Stop::RunInProgress => (
            error(
                "run_in_progress",
                "another run is in progress on this store; nothing was done",
                example,
                "",
            ),
            EXIT_RUN_IN_PROGRESS,
        ),
    }
}

/// Prints the answer in the form asked: the text for a person is `text` of the same message.
pub fn print<M: Message + serde::Serialize>(
    op: &str,
    form: Form,
    answer: &M,
    text: impl FnOnce(&M) -> String,
) -> ExitCode {
    let written = match form {
        Form::Proto => std::io::stdout().write_all(&answer.encode_to_vec()),
        Form::Json => match serde_json::to_string(answer) {
            Ok(line) => writeln!(std::io::stdout(), "{line}"),
            Err(e) => {
                return fail(
                    op,
                    form,
                    error(
                        "store_unreadable",
                        "the answer holds a value this build cannot print; nothing was changed",
                        "",
                        &e.to_string(),
                    ),
                    EXIT_STORE,
                );
            }
        },
        Form::Text => std::io::stdout().write_all(text(answer).as_bytes()),
    };
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// Every failure of a command of the contract: the message `Failure`, binary or JSON on stdout,
/// or for a person on stderr with nothing on stdout; and the exit code given, which says which
/// kind of failure it is. What its detail repeats of what it was given, an argument, a key or a
/// value a caller sent, is cut here, as it is printed, in every form (`secrets::Text`).
pub fn fail(op: &str, form: Form, mut error: v1::Error, exit: u8) -> ExitCode {
    error.detail_text = error
        .detail_text
        .as_deref()
        .map(|s| crate::secrets::Text::source(&crate::contract::unescape(s)).shown(known::whole));
    let failure = v1::Failure {
        operation: op.to_string(),
        ok: false,
        errors: vec![error],
    };
    match form {
        Form::Proto => {
            let _ = std::io::stdout().write_all(&failure.encode_to_vec());
        }
        // A failure holds no enum, so it always prints.
        Form::Json => {
            if let Ok(line) = serde_json::to_string(&failure) {
                println!("{line}");
            }
        }
        Form::Text => eprint!("{}", text::failure(&failure)),
    }
    ExitCode::from(exit)
}
